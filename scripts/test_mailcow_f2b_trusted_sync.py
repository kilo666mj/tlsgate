import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("f2bsync", HERE / "mailcow-f2b-trusted-sync.py")
f2bsync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f2bsync)

HOME6 = "2001:db8:1860::/64"
HOME4 = "192.0.2.10/32"


class FakeRedis:
    def __init__(self, **hashes):
        self.hashes = {k: dict(v) for k, v in hashes.items()}

    def hkeys(self, key):
        return set(self.hashes.get(key, {}))

    def hset(self, key, field, value):
        self.hashes.setdefault(key, {})[field] = str(value)

    def hdel(self, key, field):
        self.hashes.get(key, {}).pop(field, None)


def write_ranges(d, ranges, version=1):
    path = Path(d) / "trusted-ranges.json"
    path.write_text(json.dumps({"version": version, "source": "gatehub", "ranges": ranges}))
    return path


class LoadRangesTests(unittest.TestCase):
    def test_missing_file_means_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(f2bsync.load_ranges(Path(d) / "absent.json", 32))

    def test_canonicalizes_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_ranges(d, ["2001:db8:1860::5/64", HOME4, HOME4])
            self.assertEqual(f2bsync.load_ranges(path, 32), {HOME6, HOME4})

    def test_empty_list_is_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(f2bsync.load_ranges(write_ranges(d, []), 32), set())

    def test_rejects_broad_ranges(self):
        with tempfile.TemporaryDirectory() as d:
            for bad in ("10.0.0.0/8", "2001:db8::/16", "0.0.0.0/0", "::/0"):
                with self.assertRaisesRegex(f2bsync.SyncError, "broader"):
                    f2bsync.load_ranges(write_ranges(d, [bad]), 32)

    def test_rejects_too_many_and_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            many = [f"192.0.2.{i}/32" for i in range(5)]
            with self.assertRaisesRegex(f2bsync.SyncError, "exceed"):
                f2bsync.load_ranges(write_ranges(d, many), 4)
            with self.assertRaisesRegex(f2bsync.SyncError, "invalid range"):
                f2bsync.load_ranges(write_ranges(d, ["not-a-cidr"]), 32)
            with self.assertRaisesRegex(f2bsync.SyncError, "version 1"):
                f2bsync.load_ranges(write_ranges(d, [HOME4], version=2), 32)
            bad = Path(d) / "bad.json"
            bad.write_text("{")
            with self.assertRaisesRegex(f2bsync.SyncError, "invalid JSON"):
                f2bsync.load_ranges(bad, 32)


class SyncTests(unittest.TestCase):
    def run_sync(self, redis, ranges, state, dry_run=False):
        logs = []
        f2bsync.sync(redis, set(ranges), state, dry_run=dry_run, log=logs.append)
        return logs

    def test_adds_ranges_and_records_ownership(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            redis = FakeRedis(F2B_WHITELIST={"198.51.100.7": "1"})
            self.run_sync(redis, {HOME6, HOME4}, state)
            self.assertEqual(redis.hkeys("F2B_WHITELIST"), {HOME6, HOME4, "198.51.100.7"})
            self.assertEqual(json.loads(state.read_text())["managed"], sorted([HOME4, HOME6]))
            self.assertEqual(oct(state.stat().st_mode & 0o777), "0o600")

    def test_prefix_change_replaces_only_managed_entries(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            redis = FakeRedis(F2B_WHITELIST={"198.51.100.7": "1"})
            self.run_sync(redis, {HOME6}, state)
            new6 = "2001:db8:a64c::/64"
            self.run_sync(redis, {new6}, state)
            self.assertEqual(redis.hkeys("F2B_WHITELIST"), {new6, "198.51.100.7"})
            self.assertEqual(json.loads(state.read_text())["managed"], [new6])

    def test_manual_entry_equal_to_trusted_range_is_never_claimed(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            redis = FakeRedis(F2B_WHITELIST={HOME6: "1"})
            self.run_sync(redis, {HOME6}, state)
            self.run_sync(redis, set(), state)
            self.assertIn(HOME6, redis.hkeys("F2B_WHITELIST"))

    def test_reapplies_after_ui_save_wipes_whitelist(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            redis = FakeRedis()
            self.run_sync(redis, {HOME6}, state)
            redis.hashes["F2B_WHITELIST"] = {"198.51.100.7": "1"}  # UI rewrote the hash
            self.run_sync(redis, {HOME6}, state)
            self.assertEqual(redis.hkeys("F2B_WHITELIST"), {HOME6, "198.51.100.7"})

    def test_empty_trusted_set_removes_managed_entries(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            redis = FakeRedis()
            self.run_sync(redis, {HOME6, HOME4}, state)
            self.run_sync(redis, set(), state)
            self.assertEqual(redis.hkeys("F2B_WHITELIST"), set())

    def test_queues_unban_for_overlapping_bans_only(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            redis = FakeRedis(F2B_ACTIVE_BANS={HOME6: "1790530906", "192.0.2.0/24": "1", "203.0.113.0/24": "1"})
            self.run_sync(redis, {HOME6, HOME4}, state)
            self.assertEqual(redis.hkeys("F2B_QUEUE_UNBAN"), {HOME6, "192.0.2.0/24"})

    def test_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            redis = FakeRedis(F2B_ACTIVE_BANS={HOME6: "1"})
            logs = self.run_sync(redis, {HOME6}, state, dry_run=True)
            self.assertEqual(redis.hkeys("F2B_WHITELIST"), set())
            self.assertEqual(redis.hkeys("F2B_QUEUE_UNBAN"), set())
            self.assertFalse(state.exists())
            self.assertTrue(any(line.startswith("would add") for line in logs))

    def test_no_change_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "state.json"
            redis = FakeRedis()
            self.run_sync(redis, {HOME6}, state)
            logs = self.run_sync(redis, {HOME6}, state)
            self.assertEqual(logs, ["no change: 1 trusted range(s) already whitelisted"])


class MainTests(unittest.TestCase):
    def test_missing_ranges_file_exits_cleanly_without_redis(self):
        with tempfile.TemporaryDirectory() as d:
            rc = f2bsync.main(["--ranges-file", str(Path(d) / "absent.json"), "--mailcow-dir", str(Path(d) / "none")])
            self.assertEqual(rc, 0)

    def test_invalid_ranges_file_fails_before_redis(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_ranges(d, ["0.0.0.0/0"])
            rc = f2bsync.main(["--ranges-file", str(path), "--mailcow-dir", str(Path(d) / "none")])
            self.assertEqual(rc, 1)

    def test_reads_quoted_redis_password(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "mailcow.conf").write_text("# comment\nREDISPASS='s3cret'\nOTHER=1\n")
            self.assertEqual(f2bsync.redis_password(d), "s3cret")


if __name__ == "__main__":
    unittest.main()
