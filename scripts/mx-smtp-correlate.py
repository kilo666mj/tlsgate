#!/usr/bin/env python3
"""Build bounded SMTP correlation batches and publish atomic reports."""

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

MAX_BYTES = 64 * 1024 * 1024
MAX_LINES = 100_000


def parse_time(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def bounded_lines(paths):
    total_bytes = total_lines = 0
    result = []
    for path, active in paths:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError(f"input is not a regular file: {path}")
            size = st.st_size
            if total_bytes + size > MAX_BYTES:
                raise RuntimeError("input snapshot exceeds 64 MiB; rotate more frequently")
            data = bytearray()
            while len(data) < size:
                chunk = os.read(fd, min(1024 * 1024, size - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            os.close(fd)
        if len(data) != size:
            raise RuntimeError(f"input shrank while being snapshotted: {path}")
        if data and data[-1] != 10:
            if not active:
                raise RuntimeError(f"rotated input has an incomplete final line: {path}")
            cut = data.rfind(b"\n")
            data = data[: cut + 1] if cut >= 0 else bytearray()
        lines = bytes(data).splitlines(keepends=True)
        total_bytes += len(data)
        total_lines += len(lines)
        if total_lines > MAX_LINES:
            raise RuntimeError("input snapshot exceeds 100000 lines; rotate more frequently")
        result.extend(lines)
    return result


def select_events(lines, start, cutoff, instance):
    parsed = []
    sessions = {}
    for line in lines:
        try:
            event = json.loads(line)
            at = parse_time(event["timestamp"])
            key = (event["instance"], event["connection_id"])
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError(f"invalid SMTP event input: {exc}") from exc
        parsed.append((key, at, event, line))
        bounds = sessions.setdefault(key, {})
        if event.get("type") in ("start", "end"):
            bounds[event["type"]] = at
            if event.get("listener"):
                bounds["listener"] = event["listener"]
    eligible = {key for key, b in sessions.items()
                if key[0] == instance
                if b.get("start") is not None and b.get("end") is not None
                and start <= b["start"] <= b["end"] <= cutoff
                and b.get("listener")}
    selected = [line for key, at, event, line in parsed if key in eligible]
    listeners = sorted({sessions[key]["listener"] for key in eligible})
    return selected, listeners


def select_verdicts(lines, start, cutoff):
    selected = []
    for line in lines:
        try:
            record = json.loads(line)
            at = parse_time(record["timestamp"])
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError(f"invalid verdict input: {exc}") from exc
        if start <= at <= cutoff and not str(record.get("queue_id", "")).startswith("TLSGATEPROBE"):
            selected.append(line)
    return selected


def write_batch(path, lines):
    size = sum(map(len, lines))
    if size > MAX_BYTES or len(lines) > MAX_LINES:
        raise RuntimeError(f"filtered batch exceeds collector bounds: {path.name}")
    path.write_bytes(b"".join(lines))


def bounded_command(argv):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data = bytearray()
    assert process.stdout is not None
    while True:
        chunk = process.stdout.read(min(1024 * 1024, MAX_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_BYTES:
            process.kill()
            process.wait()
            raise RuntimeError("journal snapshot exceeds 64 MiB")
    stderr = process.stderr.read() if process.stderr else b""
    if process.wait() != 0:
        raise RuntimeError("journalctl failed: " + stderr.decode(errors="replace").strip())
    lines = bytes(data).splitlines(keepends=True)
    if len(lines) > MAX_LINES:
        raise RuntimeError("journal snapshot exceeds 100000 lines")
    return lines


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--events", default="/var/lib/tlsgate/smtp-events.jsonl")
    p.add_argument("--verdicts", default="/var/lib/docker/volumes/mailcowdockerized_rspamd-vol-1/_data/tlsgate/verdicts.jsonl")
    p.add_argument("--output", default="/var/lib/tlsgate/correlation")
    p.add_argument("--tlsgate", default="/usr/local/bin/tlsgate")
    p.add_argument("--instance", default="mx-public-smtp")
    p.add_argument("--report-gatehub", action="store_true",
                   help="upload each completed report using control-plane credentials")
    p.add_argument("--config", default="/etc/tlsgate/config.json")
    args = p.parse_args()
    output = Path(args.output)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    lock = os.open(output / ".lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)
    start = cutoff - dt.timedelta(hours=24)
    with tempfile.TemporaryDirectory(prefix="run-", dir=output) as work_s:
        work = Path(work_s)
        event_paths = [(args.events + f".{n}", False) for n in range(7, 0, -1)] + [(args.events, True)]
        verdict_paths = [(args.verdicts + f".{n}", False) for n in range(7, 0, -1)] + [(args.verdicts, True)]
        events = bounded_lines(event_paths)
        verdicts = bounded_lines(verdict_paths)
        selected_events, listeners = select_events(events, start, cutoff, args.instance)
        write_batch(work / "events.jsonl", selected_events)
        write_batch(work / "verdicts.jsonl", select_verdicts(verdicts, start, cutoff))
        journal = [line for line in bounded_command([
            "journalctl", "CONTAINER_NAME=mailcowdockerized-postfix-mailcow-1",
            "-o", "short-iso-precise", "--since", start.isoformat(),
            "--until", cutoff.isoformat(), "--no-pager"])
                   if b"TLSGATEPROBE" not in line]
        write_batch(work / "postfix.log", journal)
        generated_at = dt.datetime.now(dt.timezone.utc)
        published = []
        for listener in listeners:
            slug = hashlib.sha256(listener.encode()).hexdigest()[:16]
            report = work / f"latest-{slug}.json"
            with report.open("wb") as out:
                subprocess.run([
                    args.tlsgate, "correlate-smtp", "--events", str(work / "events.jsonl"),
                    "--postfix-log", str(work / "postfix.log"), "--verdicts", str(work / "verdicts.jsonl"),
                    "--instance", args.instance, "--listener", listener,
                    "--db", str(output / "db.sqlite"), "--format", "json"],
                    check=True, stdout=out)
            os.chmod(report, 0o600)
            destination = output / report.name
            if args.report_gatehub:
                subprocess.run([
                    args.tlsgate, "report-smtp", "--config", args.config,
                    "--report", str(report), "--smtp-instance", args.instance,
                    "--listener", listener, "--coverage-start", start.isoformat(),
                    "--coverage-end", cutoff.isoformat(),
                    "--generated-at", generated_at.isoformat()], check=True)
                published.append(listener)
            os.replace(report, destination)
        manifest = work / "latest.json"
        manifest.write_text(json.dumps({"generated_at": generated_at.isoformat(),
                                        "coverage_start": start.isoformat(), "coverage_end": cutoff.isoformat(),
                                        "listeners": [{"listener": x, "report": "latest-" + hashlib.sha256(x.encode()).hexdigest()[:16] + ".json", "gatehub_reported": x in published} for x in listeners]}, separators=(",", ":")) + "\n")
        os.chmod(manifest, 0o600)
        os.replace(manifest, output / "latest.json")


if __name__ == "__main__":
    main()
