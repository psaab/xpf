#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
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
                    printf '{"verdict":"PASS","observed_cov":%s,"cstruct":0.0,"gap":0.0,"aggregate_mbps":1.0,"starved_flow_count":0,"failure_reasons":[]}\\n' "$cov"
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


if __name__ == "__main__":
    unittest.main()
