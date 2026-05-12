#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


MODULE_PATH = Path(__file__).with_name("fairness_multi_sample.py")
SPEC = importlib.util.spec_from_file_location("fairness_multi_sample", MODULE_PATH)
assert SPEC is not None
fairness_multi_sample = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(fairness_multi_sample)


class FairnessMultiSampleTest(unittest.TestCase):
    def test_extract_json_objects_skips_non_json_logs(self) -> None:
        text = 'log {not json}\n{"verdict":"PASS","observed_cov":0.1}\n'
        objects = fairness_multi_sample.extract_json_objects(text)
        self.assertEqual(objects, [{"verdict": "PASS", "observed_cov": 0.1}])

    def test_extract_verdict_objects_ignores_log_json(self) -> None:
        verdict = {
            "verdict": "PASS",
            "observed_cov": 0.1,
            "cstruct": 0.0,
            "gap": 0.0,
            "aggregate_mbps": 1.0,
            "starved_flow_count": 0,
            "failure_reasons": [],
            "distribution_a_i": [1],
            "n_active": 1,
            "saturated": True,
            "a_i_sum_check_ok": True,
        }
        text = (
            'log {"event":"progress","observed_cov":999}\n'
            + json.dumps(verdict)
            + "\n"
        )
        objects = fairness_multi_sample.extract_verdict_objects(text)
        self.assertEqual(objects, [verdict])

    def test_extract_verdict_objects_rejects_schema_incomplete_object(self) -> None:
        # A log object that looks verdict-like but lacks the full fairness-eval
        # schema must not be accepted as a measurement result.
        text = '{"verdict":"PASS","observed_cov":0.01,"failure_reasons":[]}\n'
        objects = fairness_multi_sample.extract_verdict_objects(text)
        self.assertEqual(objects, [])

    def test_numeric_field_rejects_non_finite_negative_and_bool(self) -> None:
        for value in [True, False, math.nan, math.inf, -math.inf, -0.1, "0.1"]:
            with self.subTest(value=value):
                with self.assertRaises(fairness_multi_sample.MultiSampleError):
                    fairness_multi_sample.numeric_field({"observed_cov": value}, "observed_cov")

    def test_sample_record_validates_numeric_summary_fields(self) -> None:
        base_verdict = {
            "verdict": "PASS",
            "observed_cov": 0.1,
            "cstruct": 0.0,
            "gap": 0.0,
            "aggregate_mbps": 1.0,
            "starved_flow_count": 0,
            "failure_reasons": [],
            "distribution_a_i": [1],
            "n_active": 1,
            "saturated": True,
            "a_i_sum_check_ok": True,
        }
        for key, value in [
            ("cstruct", -0.1),
            ("gap", math.nan),
            ("aggregate_mbps", math.inf),
            ("starved_flow_count", -1),
            ("starved_flow_count", 1.5),
            ("starved_flow_count", True),
        ]:
            verdict = dict(base_verdict)
            verdict[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(fairness_multi_sample.MultiSampleError):
                    fairness_multi_sample.sample_record(1, Path("sample-1"), 0, verdict)

    def test_summary_fails_thresholds(self) -> None:
        summary = fairness_multi_sample.summarize(
            [
                {
                    "sample": 1,
                    "verdict": "PASS",
                    "observed_cov": 0.10,
                    "exit_code": 0,
                },
                {
                    "sample": 2,
                    "verdict": "PASS",
                    "observed_cov": 0.30,
                    "exit_code": 0,
                },
            ],
            max_mean_cov=0.15,
            max_stdev_cov=0.03,
            max_run_cov=0.25,
        )
        self.assertEqual(summary["verdict"], "FAIL")
        self.assertGreater(summary["observed_cov"]["mean"], 0.15)
        self.assertGreater(summary["observed_cov"]["sample_stdev"], 0.03)
        self.assertGreater(summary["observed_cov"]["max"], 0.25)

    def test_cli_runs_fake_harness_and_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "fake-harness.sh"
            harness.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -euo pipefail
                    sample=$(basename "$(dirname "${ARTIFACT_DIR}")")
                    case "$sample" in
                      sample-1) cov=0.10 ;;
                      sample-2) cov=0.12 ;;
                      *) cov=0.11 ;;
                    esac
                    echo "harness log line"
                    echo '{"event":"progress","observed_cov":99}'
                    printf '{"verdict":"PASS","observed_cov":%s,"cstruct":0.0,"gap":0.0,"aggregate_mbps":1.0,"starved_flow_count":0,"failure_reasons":[],"distribution_a_i":[1],"n_active":1,"saturated":true,"a_i_sum_check_ok":true}\\n' "$cov"
                    """
                ),
                encoding="utf-8",
            )
            harness.chmod(0o755)
            out_dir = tmp_path / "out"

            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--samples",
                    "2",
                    "--out-dir",
                    str(out_dir),
                    "--harness",
                    str(harness),
                    "--",
                    "target.example",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["verdict"], "PASS")
            self.assertAlmostEqual(summary["observed_cov"]["mean"], 0.11)
            self.assertTrue((out_dir / "sample-1" / "verdict.json").exists())
            self.assertTrue((out_dir / "sample-2" / "artifacts").is_dir())

    def test_cli_rejects_nan_observed_cov(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "fake-harness.sh"
            harness.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    printf '{"verdict":"PASS","observed_cov":NaN,"cstruct":0.0,"gap":0.0,"aggregate_mbps":1.0,"starved_flow_count":0,"failure_reasons":[],"distribution_a_i":[1],"n_active":1,"saturated":true,"a_i_sum_check_ok":true}\\n'
                    """
                ),
                encoding="utf-8",
            )
            harness.chmod(0o755)
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--samples",
                    "2",
                    "--out-dir",
                    str(tmp_path / "out"),
                    "--harness",
                    str(harness),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("not finite", result.stderr)

    def test_cli_times_out_harness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "fake-harness.sh"
            harness.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    sleep 2
                    """
                ),
                encoding="utf-8",
            )
            harness.chmod(0o755)
            out_dir = tmp_path / "out"
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--samples",
                    "2",
                    "--per-run-timeout-sec",
                    "1",
                    "--out-dir",
                    str(out_dir),
                    "--harness",
                    str(harness),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("timed out", result.stderr)
            command = json.loads((out_dir / "sample-1" / "command.json").read_text(encoding="utf-8"))
            self.assertTrue(command["timed_out"])

    def test_cli_timeout_kills_process_group(self) -> None:
        # Verify that process-group kill cleans up descendant processes, not just the shell.
        # The harness spawns a background child that writes a sentinel file after 3 s.
        # With a 1-second timeout the wrapper should kill the whole group before
        # the sentinel is written; the sentinel must be absent after the run.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sentinel = tmp_path / "child_ran"
            harness = tmp_path / "fake-harness.sh"
            harness.write_text(
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env bash
                    (sleep 3 && touch {sentinel}) &
                    sleep 3
                    """
                ),
                encoding="utf-8",
            )
            harness.chmod(0o755)
            out_dir = tmp_path / "out"
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--samples",
                    "2",
                    "--per-run-timeout-sec",
                    "1",
                    "--out-dir",
                    str(out_dir),
                    "--harness",
                    str(harness),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("timed out", result.stderr)
            # Poll for up to 2s to confirm the sentinel is never written.
            # SIGKILL is unblockable so it cannot appear after killpg completes,
            # but poll briefly to catch any kernel-scheduling latency.
            sentinel_written = False
            for _ in range(4):
                if sentinel.exists():
                    sentinel_written = True
                    break
                time.sleep(0.5)
            self.assertFalse(sentinel_written, "descendant child was not killed by process-group kill")

    def test_cli_timeout_after_leader_exit_does_not_hang(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "fake-harness.sh"
            harness.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    (sleep 10 && echo child-still-running) &
                    exit 0
                    """
                ),
                encoding="utf-8",
            )
            harness.chmod(0o755)
            out_dir = tmp_path / "out"
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--samples",
                    "2",
                    "--per-run-timeout-sec",
                    "1",
                    "--out-dir",
                    str(out_dir),
                    "--harness",
                    str(harness),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=4,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("timed out", result.stderr)
            command = json.loads((out_dir / "sample-1" / "command.json").read_text(encoding="utf-8"))
            self.assertTrue(command["timed_out"])

    def test_cli_rejects_samples_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "fake-harness.sh"
            harness.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            harness.chmod(0o755)
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--samples",
                    "1",
                    "--out-dir",
                    str(tmp_path / "out"),
                    "--harness",
                    str(harness),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("--samples must be >= 2", result.stderr)

    def test_cli_rejects_harness_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "fake-harness.sh"
            harness.write_text(
                "#!/usr/bin/env bash\necho before-error\nexit 2\n",
                encoding="utf-8",
            )
            harness.chmod(0o755)
            out_dir = tmp_path / "out"
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--samples",
                    "2",
                    "--out-dir",
                    str(out_dir),
                    "--harness",
                    str(harness),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("harness exited 2", result.stderr)
            self.assertIn(
                "before-error",
                (out_dir / "sample-1" / "stdout.log").read_text(encoding="utf-8"),
            )

    def test_cli_rejects_existing_out_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "fake-harness.sh"
            harness.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            harness.chmod(0o755)
            out_dir = tmp_path / "out"
            out_dir.mkdir()
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--samples",
                    "2",
                    "--out-dir",
                    str(out_dir),
                    "--harness",
                    str(harness),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("--out-dir already exists", result.stderr)


if __name__ == "__main__":
    unittest.main()
