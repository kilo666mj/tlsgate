import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("collector", HERE / "mx-smtp-correlate.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    def test_snapshot_uses_initial_size_and_drops_active_partial_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events"
            path.write_bytes(b'{"a":1}\npartial')
            self.assertEqual(collector.bounded_lines([(str(path), True)]), [b'{"a":1}\n'])

    def test_rotated_partial_line_fails_visible(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events.1"
            path.write_bytes(b'partial')
            with self.assertRaisesRegex(RuntimeError, "incomplete final line"):
                collector.bounded_lines([(str(path), False)])

    def test_only_completed_sessions_inside_window_are_selected(self):
        start = dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)
        cutoff = start + dt.timedelta(days=1)
        def event(kind, cid, at, listener="[::]:25"):
            return (json.dumps({"version": 1, "type": kind, "timestamp": at.isoformat(),
                                "instance": "mx-public-smtp", "connection_id": cid,
                                "listener": listener}) + "\n").encode()
        lines = [event("start", "ok", start), event("fingerprint", "ok", start),
                 event("end", "ok", cutoff), event("start", "open", start)]
        selected, listeners = collector.select_events(lines, start, cutoff, "mx-public-smtp")
        self.assertEqual(len(selected), 3)
        self.assertEqual(listeners, ["[::]:25"])

    def test_verdict_window_is_inclusive(self):
        start = dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)
        cutoff = start + dt.timedelta(hours=1)
        lines = [(json.dumps({"timestamp": x.isoformat(), "queue_id": "Q1"}) + "\n").encode()
                 for x in (start - dt.timedelta(seconds=1), start, cutoff, cutoff + dt.timedelta(seconds=1))]
        self.assertEqual(len(collector.select_verdicts(lines, start, cutoff)), 2)

    def test_probe_verdict_is_excluded(self):
        now = dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)
        line = (json.dumps({"timestamp": now.isoformat(), "queue_id": "TLSGATEPROBE20260908"}) + "\n").encode()
        self.assertEqual(collector.select_verdicts([line], now, now), [])

    def test_upload_failure_still_publishes_local_reports(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            at = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
            events = d / "events.jsonl"
            events.write_text("".join(
                json.dumps({"version": 1, "type": kind, "timestamp": at, "instance": "mx-public-smtp",
                            "connection_id": listener, "listener": listener}) + "\n"
                for listener in ("192.0.2.1:25", "[2001:db8::1]:25") for kind in ("start", "end")))
            bin_dir = d / "bin"
            bin_dir.mkdir()
            (bin_dir / "journalctl").write_text("#!/bin/sh\nexit 0\n")
            # Fake tlsgate: correlation succeeds; only the IPv4 upload fails.
            (bin_dir / "tlsgate").write_text(
                "#!/bin/sh\n"
                "case \"$1\" in correlate-smtp) echo '{}';;\n"
                "report-smtp) case \"$*\" in *192.0.2.1:25*) exit 1;; esac;;\n"
                "esac\n")
            for name in ("journalctl", "tlsgate"):
                os.chmod(bin_dir / name, 0o755)
            output = d / "out"
            argv = ["collector", "--events", str(events), "--verdicts", str(d / "verdicts.jsonl"),
                    "--output", str(output), "--tlsgate", str(bin_dir / "tlsgate"), "--report-gatehub"]
            env = {"PATH": f"{bin_dir}:{os.environ['PATH']}"}
            with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, env):
                with self.assertRaisesRegex(SystemExit, r"192\.0\.2\.1:25"):
                    collector.main()
            manifest = json.loads((output / "latest.json").read_text())
            reported = {x["listener"]: x["gatehub_reported"] for x in manifest["listeners"]}
            self.assertEqual(reported, {"192.0.2.1:25": False, "[2001:db8::1]:25": True})
            for x in manifest["listeners"]:
                self.assertTrue((output / x["report"]).exists())


if __name__ == "__main__":
    unittest.main()
