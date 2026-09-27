#!/usr/bin/env python3
"""Keep Mailcow's fail2ban whitelist in step with Gatehub trusted ranges.

TLSGate writes Gatehub's dynamic trusted ranges to `trusted_ranges_file`. This
script copies them into Mailcow's Redis hash F2B_WHITELIST so netfilter never
bans a trusted network (for example a home network whose IPv6 prefix changes).

Ownership: only entries this script added are ever removed. Their names are
kept in a state file, because the Mailcow UI rewrites F2B_WHITELIST (with value
1 for every entry) whenever fail2ban settings are saved. Manual entries are
never touched. Run it periodically so entries wiped by a UI save come back.

Safety: a missing ranges file changes nothing. An unparsable file, a range
broader than IPv4 /16 or IPv6 /32, or more than --max-entries ranges aborts
without changes. Active bans that overlap a trusted range are queued for unban.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MIN_PREFIX = {4: 16, 6: 32}


class SyncError(Exception):
    pass


def load_ranges(path, max_entries):
    """Return the validated, canonical trusted ranges, or None if the file is absent."""
    try:
        raw = Path(path).read_text()
    except FileNotFoundError:
        return None
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SyncError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("ranges"), list):
        raise SyncError(f"{path}: expected a version 1 document with a ranges list")
    ranges = set()
    for item in doc["ranges"]:
        if not isinstance(item, str):
            raise SyncError(f"{path}: range {item!r} is not a string")
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise SyncError(f"{path}: invalid range {item!r}: {exc}") from exc
        if net.prefixlen < MIN_PREFIX[net.version]:
            raise SyncError(f"{path}: range {net} is broader than /{MIN_PREFIX[net.version]}; refusing")
        ranges.add(str(net))
    if len(ranges) > max_entries:
        raise SyncError(f"{path}: {len(ranges)} ranges exceed the limit of {max_entries}")
    return ranges


def load_state(path):
    try:
        data = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return set()
    except json.JSONDecodeError as exc:
        raise SyncError(f"{path}: invalid state file: {exc}") from exc
    managed = data.get("managed") if isinstance(data, dict) else None
    if not isinstance(managed, list) or not all(isinstance(m, str) for m in managed):
        raise SyncError(f"{path}: invalid state file")
    return set(managed)


def save_state(path, managed):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.tmp-")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump({"managed": sorted(managed)}, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def overlaps_any(net, ranges):
    try:
        candidate = ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False
    for r in ranges:
        trusted = ipaddress.ip_network(r)
        if candidate.version == trusted.version and candidate.overlaps(trusted):
            return True
    return False


def plan(ranges, whitelist, managed, active_bans):
    """Compute Redis changes. All inputs are sets of CIDR/key strings."""
    add = ranges - whitelist
    remove = (managed - ranges) & whitelist
    new_managed = (managed | add) & ranges
    unban = {b for b in active_bans if overlaps_any(b, ranges)}
    return add, remove, new_managed, unban


class DockerRedis:
    """Minimal redis-cli client through `docker exec` into the Mailcow container."""

    def __init__(self, container, password):
        self.container = container
        self.env = dict(os.environ, REDISCLI_AUTH=password)

    def _run(self, *args):
        cmd = ["docker", "exec", "-e", "REDISCLI_AUTH", self.container, "redis-cli", "--raw", *args]
        proc = subprocess.run(cmd, env=self.env, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0 or proc.stdout.startswith(("ERR", "WRONGTYPE", "NOAUTH")):
            raise SyncError(f"redis-cli {args[0]} failed: {(proc.stderr or proc.stdout).strip()}")
        return proc.stdout

    def hkeys(self, key):
        return {line for line in self._run("HKEYS", key).splitlines() if line}

    def hset(self, key, field, value):
        self._run("HSET", key, field, str(value))

    def hdel(self, key, field):
        self._run("HDEL", key, field)


def redis_password(mailcow_dir):
    conf = Path(mailcow_dir) / "mailcow.conf"
    for line in conf.read_text().splitlines():
        if line.startswith("REDISPASS="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SyncError(f"{conf}: REDISPASS not found")


def sync(redis, ranges, state_path, dry_run=False, log=print):
    managed = load_state(state_path)
    whitelist = redis.hkeys("F2B_WHITELIST")
    active_bans = redis.hkeys("F2B_ACTIVE_BANS")
    add, remove, new_managed, unban = plan(ranges, whitelist, managed, active_bans)
    prefix = "would " if dry_run else ""
    for net in sorted(add):
        log(f"{prefix}add {net} to F2B_WHITELIST")
        if not dry_run:
            redis.hset("F2B_WHITELIST", net, 1)
    for net in sorted(remove):
        log(f"{prefix}remove {net} from F2B_WHITELIST")
        if not dry_run:
            redis.hdel("F2B_WHITELIST", net)
    for net in sorted(unban):
        log(f"{prefix}queue unban of {net} (overlaps a trusted range)")
        if not dry_run:
            redis.hset("F2B_QUEUE_UNBAN", net, 1)
    if not dry_run and new_managed != managed:
        save_state(state_path, new_managed)
    if not (add or remove or unban):
        log(f"no change: {len(ranges)} trusted range(s) already whitelisted")
    return add, remove, unban


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--ranges-file", default="/var/lib/tlsgate/trusted-ranges.json")
    p.add_argument("--state", default="/var/lib/tlsgate/mailcow-f2b-managed.json")
    p.add_argument("--mailcow-dir", default="/opt/mailcow-dockerized")
    p.add_argument("--redis-container", default="mailcowdockerized-redis-mailcow-1")
    p.add_argument("--max-entries", type=int, default=32)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    try:
        ranges = load_ranges(args.ranges_file, args.max_entries)
        if ranges is None:
            print(f"{args.ranges_file} does not exist yet; leaving F2B_WHITELIST unchanged")
            return 0
        redis = DockerRedis(args.redis_container, redis_password(args.mailcow_dir))
        sync(redis, ranges, args.state, dry_run=args.dry_run)
    except (SyncError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
