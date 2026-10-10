#!/usr/bin/env python3
"""Hermetic rolling-upgrade gate oracle tests (#12200)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts" / "rolling_upgrade_oracle.py"
HISTORICAL = ROOT / "docs" / "log" / "10023" / "raw" / "historical" / "iperf.log"
OLD = "a" * 64
NEW = "b" * 64


def healthy_json_stream(duration=12.0, step=0.1, streams=4, dead_stream_after=None):
    sockets = list(range(5, 5 + streams))
    events = [{"event": "start", "data": {"connected": [{"socket": s, "local_port": 40000 + s} for s in sockets]}}]
    t = 0.0
    while t < duration - 1e-9:
        end = min(t + step, duration)
        rows = [
            {"socket": socket, "start": t, "end": end, "bits_per_second": 250_000_000.0,
             "bytes": 3_125_000, "retransmits": 0}
            for socket in sockets
            if socket != 5 or dead_stream_after is None or t < dead_stream_after
        ]
        events.append({"event": "interval", "data": {"streams": rows,
                        "sum": {"start": t, "end": end, "bits_per_second": streams * 250_000_000.0}}})
        t = end
    events.append({"event": "end", "data": {}})
    return "\n".join(json.dumps(event) for event in events) + "\n"


def evidence_files(root, evidence, *, started_at=1000.0, old=OLD, candidate=NEW, samples=None):
    log = root / "iperf.jsonl"
    log.write_text(evidence, encoding="utf-8")
    cuts = root / "cuts.log"
    cuts.write_text(
        "1001.0 event=cut_start node=1\n"
        "1002.0 event=cut_end node=1\n"
        "1006.0 event=cut_start node=0\n"
        "1007.0 event=cut_end node=0\n",
        encoding="utf-8",
    )
    sample_path = root / "versions.log"
    if samples is None:
        samples = [
            (1000.0, old, old),
            (1003.0, candidate, old),
            (1003.2, candidate, old),
            (1008.0, candidate, candidate),
        ]
    sample_path.write_text("".join(f"{t} {sha0} {sha1}\n" for t, sha0, sha1 in samples), encoding="utf-8")
    return log, cuts, sample_path


class RollingUpgradeOracleTests(unittest.TestCase):
    def run_oracle(self, evidence, *, streams=4, started_at=1000.0, old=OLD,
                   candidate=NEW, samples=None, cut_text=None, max_interval_sec=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log, cuts, version_samples = evidence_files(
                root, evidence, started_at=started_at, old=old,
                candidate=candidate, samples=samples,
            )
            if cut_text is not None:
                cuts.write_text(cut_text, encoding="utf-8")
            command = [
                sys.executable, str(ORACLE), "--evidence", str(log), "--cuts", str(cuts),
                "--samples", str(version_samples), "--started-at", str(started_at),
                "--expected-version", candidate, "--streams", str(streams),
            ]
            if max_interval_sec is not None:
                command.extend(["--max-interval-sec", str(max_interval_sec)])
            return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_healthy_two_cut_run_passes_version_and_each_cut_once(self):
        proc = self.run_oracle(healthy_json_stream(), max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.count("CUT 1 PASS"), 1)
        self.assertEqual(proc.stdout.count("CUT 2 PASS"), 1)
        self.assertIn("mixed-version interval observed", proc.stdout)

    def test_stream_that_dies_at_cut_must_not_pass_on_sum_traffic(self):
        proc = self.run_oracle(
            healthy_json_stream(dead_stream_after=2.0), max_interval_sec=0.25
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("CUT 1 FAIL stream 5 did not resume", proc.stdout)
        self.assertIn("CUT 2 FAIL stream 5 has no interval evidence", proc.stdout)

    def test_sampling_blackout_before_cut_is_rejected(self):
        events = [json.loads(line) for line in healthy_json_stream().splitlines()]
        for event in events:
            if event.get("event") == "interval":
                interval_start = event["data"]["sum"]["start"]
                if 0.4 <= interval_start < 1.0:
                    event["data"]["streams"] = []
        evidence = "\n".join(json.dumps(event) for event in events) + "\n"
        proc = self.run_oracle(evidence, max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("CUT 1 FAIL stream 5 interval evidence has a sampling gap", proc.stdout)
        self.assertIn("CUT 2 PASS", proc.stdout)

    def test_noop_drain_same_candidate_sha_fails_version_assertion(self):
        samples = [
            (1000.0, OLD, OLD),
            (1003.0, OLD, OLD),
            (1003.2, OLD, OLD),
            (1008.0, OLD, OLD),
        ]
        proc = self.run_oracle(healthy_json_stream(), old=OLD, candidate=OLD, samples=samples, max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("VERSION FAIL no-op drain", proc.stdout)
        self.assertEqual(proc.stdout.count("CUT 1 PASS"), 1)
        self.assertEqual(proc.stdout.count("CUT 2 PASS"), 1)

    def test_historical_10261_stranded_stream_shape_fails_both_cut_cells(self):
        self.assertTrue(HISTORICAL.is_file())
        historical = HISTORICAL.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log, cuts, samples_path = evidence_files(root, historical, started_at=1000.0)
            cuts.write_text(
                "1015.0 event=cut_start node=1\n1016.0 event=cut_end node=1\n"
                "1028.0 event=cut_start node=0\n1029.0 event=cut_end node=0\n",
                encoding="utf-8",
            )
            samples_path.write_text(
                f"1000.0 {OLD} {OLD}\n1017.0 {NEW} {OLD}\n1017.2 {NEW} {OLD}\n"
                f"1030.0 {NEW} {NEW}\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ORACLE), "--evidence", str(log), "--cuts", str(cuts),
                 "--samples", str(samples_path), "--started-at", "1000.0",
                 "--expected-version", NEW, "--streams", "4"],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.count("CUT 1 FAIL"), 1)
        self.assertEqual(proc.stdout.count("CUT 2 FAIL"), 1)
        self.assertIn("#10261 shape", proc.stdout)

    def test_missing_cut_marker_is_unusable_evidence(self):
        proc = self.run_oracle(healthy_json_stream(), cut_text="1001.0 event=cut_start node=1\n")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("cut trace must contain one start/end pair", proc.stdout)


if __name__ == "__main__":
    unittest.main()
