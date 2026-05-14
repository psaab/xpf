#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("fairness_multi_sample.py")
EQUAL_FLOW_CAPTURE_PATH = Path(__file__).with_name("fairness_equal_flow_capture.py")
HARNESS_PATH = Path(__file__).with_name("fairness-harness.sh")
CLASS_SWEEP_PATH = Path(__file__).with_name("fairness-cos-class-sweep.sh")
SPEC = importlib.util.spec_from_file_location("fairness_multi_sample", MODULE_PATH)
assert SPEC is not None
fairness_multi_sample = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(fairness_multi_sample)
EQUAL_FLOW_SPEC = importlib.util.spec_from_file_location(
    "fairness_equal_flow_capture",
    EQUAL_FLOW_CAPTURE_PATH,
)
assert EQUAL_FLOW_SPEC is not None
fairness_equal_flow_capture = importlib.util.module_from_spec(EQUAL_FLOW_SPEC)
assert EQUAL_FLOW_SPEC.loader is not None
EQUAL_FLOW_SPEC.loader.exec_module(fairness_equal_flow_capture)


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

    def test_numeric_field_rejects_non_finite_negative_and_bool_by_default(self) -> None:
        for value in [True, False, math.nan, math.inf, -math.inf, -0.1, "0.1"]:
            with self.subTest(value=value):
                with self.assertRaises(fairness_multi_sample.MultiSampleError):
                    fairness_multi_sample.numeric_field({"observed_cov": value}, "observed_cov")

    def test_numeric_field_allows_negative_gap_when_requested(self) -> None:
        self.assertEqual(
            fairness_multi_sample.numeric_field(
                {"gap": -0.25},
                "gap",
                allow_negative=True,
            ),
            -0.25,
        )

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

    def test_sample_record_accepts_negative_gap(self) -> None:
        verdict = {
            "verdict": "PASS",
            "observed_cov": 0.01,
            "cstruct": 0.5,
            "gap": -0.49,
            "aggregate_mbps": 1.0,
            "starved_flow_count": 0,
            "failure_reasons": [],
            "distribution_a_i": [1],
            "n_active": 1,
            "saturated": True,
            "a_i_sum_check_ok": True,
        }

        record = fairness_multi_sample.sample_record(1, Path("sample-1"), 0, verdict)

        self.assertEqual(record["gap"], -0.49)

    def test_summary_defaults_to_cstruct_aware_gap_contract(self) -> None:
        summary = fairness_multi_sample.summarize(
            [
                {
                    "sample": 1,
                    "verdict": "PASS",
                    "observed_cov": 0.30,
                    "cstruct": 0.60,
                    "gap": -0.30,
                    "exit_code": 0,
                },
                {
                    "sample": 2,
                    "verdict": "PASS",
                    "observed_cov": 0.40,
                    "cstruct": 0.50,
                    "gap": -0.10,
                    "exit_code": 0,
                },
            ],
            max_mean_gap=0.05,
            max_run_gap=0.05,
            max_mean_cov=None,
            max_stdev_cov=None,
            max_run_cov=None,
        )
        self.assertEqual(summary["verdict"], "PASS")
        self.assertAlmostEqual(summary["gap"]["mean"], -0.20)
        self.assertAlmostEqual(summary["cstruct"]["mean"], 0.55)
        self.assertIsNone(summary["aggregate_mbps"])

    def test_summary_reports_aggregate_mbps_stats_when_present(self) -> None:
        summary = fairness_multi_sample.summarize(
            [
                {
                    "sample": 1,
                    "verdict": "PASS",
                    "observed_cov": 0.10,
                    "cstruct": 0.50,
                    "gap": -0.40,
                    "aggregate_mbps": 900.0,
                    "exit_code": 0,
                },
                {
                    "sample": 2,
                    "verdict": "PASS",
                    "observed_cov": 0.20,
                    "cstruct": 0.50,
                    "gap": -0.30,
                    "aggregate_mbps": 1100.0,
                    "exit_code": 0,
                },
            ],
            max_mean_gap=0.05,
            max_run_gap=0.05,
            max_mean_cov=None,
            max_stdev_cov=None,
            max_run_cov=None,
        )

        self.assertEqual(summary["verdict"], "PASS")
        self.assertEqual(summary["aggregate_mbps"]["mean"], 1000.0)
        self.assertEqual(summary["aggregate_mbps"]["min"], 900.0)
        self.assertEqual(summary["aggregate_mbps"]["max"], 1100.0)

    def test_summary_fails_gap_thresholds(self) -> None:
        summary = fairness_multi_sample.summarize(
            [
                {
                    "sample": 1,
                    "verdict": "PASS",
                    "observed_cov": 0.20,
                    "cstruct": 0.12,
                    "gap": 0.08,
                    "exit_code": 0,
                },
                {
                    "sample": 2,
                    "verdict": "PASS",
                    "observed_cov": 0.19,
                    "cstruct": 0.12,
                    "gap": 0.07,
                    "exit_code": 0,
                },
            ],
            max_mean_gap=0.05,
            max_run_gap=0.05,
            max_mean_cov=None,
            max_stdev_cov=None,
            max_run_cov=None,
        )
        self.assertEqual(summary["verdict"], "FAIL")
        self.assertGreater(summary["gap"]["mean"], 0.05)
        self.assertGreater(summary["gap"]["max"], 0.05)

    def test_summary_optional_cov_thresholds_fail_when_enabled(self) -> None:
        summary = fairness_multi_sample.summarize(
            [
                {
                    "sample": 1,
                    "verdict": "PASS",
                    "observed_cov": 0.10,
                    "cstruct": 0.50,
                    "gap": -0.40,
                    "exit_code": 0,
                },
                {
                    "sample": 2,
                    "verdict": "PASS",
                    "observed_cov": 0.30,
                    "cstruct": 0.50,
                    "gap": -0.20,
                    "exit_code": 0,
                },
            ],
            max_mean_gap=0.05,
            max_run_gap=0.05,
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

    def test_run_samples_sleeps_between_samples_when_cooldown_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "fake-harness.sh"
            harness.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    printf '{"verdict":"PASS","observed_cov":0.1,"cstruct":0.0,"gap":0.0,"aggregate_mbps":1.0,"starved_flow_count":0,"failure_reasons":[],"distribution_a_i":[1],"n_active":1,"saturated":true,"a_i_sum_check_ok":true}\\n'
                    """
                ),
                encoding="utf-8",
            )
            harness.chmod(0o755)
            out_dir = tmp_path / "out"
            args = fairness_multi_sample.parse_args(
                [
                    "--samples",
                    "3",
                    "--sample-cooldown-sec",
                    "0.25",
                    "--out-dir",
                    str(out_dir),
                    "--harness",
                    str(harness),
                ]
            )

            with mock.patch.object(fairness_multi_sample.time, "sleep") as sleep:
                summary = fairness_multi_sample.run_samples(args)

            self.assertEqual(summary["verdict"], "PASS")
            sleep.assert_has_calls([mock.call(0.25), mock.call(0.25)])
            self.assertEqual(sleep.call_count, 2)
            command = json.loads((out_dir / "sample-2" / "command.json").read_text(encoding="utf-8"))
            self.assertEqual(command["sample_cooldown_sec"], 0.25)

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

    def test_fairness_harness_accepts_scrape_rows_matching_iface_and_cos_queue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            metrics = tmp_path / "metrics.prom"
            metrics.write_text(
                textwrap.dedent(
                    """\
                    xpf_userspace_binding_active_flow_count{binding_slot="0",iface="ge-0-0-2",queue_id="6",worker_id="0"} 1
                    xpf_userspace_cos_active_flow_count{ifindex="5",queue_id="6",worker_id="0"} 1
                    """
                ),
                encoding="utf-8",
            )
            result = self.run_fake_harness_with_metrics(tmp_path, metrics)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"verdict":"PASS"', result.stdout)
            self.assertTrue((tmp_path / "eval-called").exists())

    def test_fairness_harness_empty_reverse_arg_means_forward(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            metrics = tmp_path / "metrics.prom"
            metrics.write_text(
                textwrap.dedent(
                    """\
                    xpf_userspace_binding_active_flow_count{binding_slot="0",iface="ge-0-0-2",queue_id="6",worker_id="0"} 1
                    xpf_userspace_cos_active_flow_count{ifindex="5",queue_id="6",worker_id="0"} 1
                    """
                ),
                encoding="utf-8",
            )
            result = self.run_fake_harness_with_metrics(tmp_path, metrics)

            self.assertEqual(result.returncode, 0, result.stderr)
            iperf_args = (tmp_path / "iperf-argv.txt").read_text(encoding="utf-8").splitlines()
            self.assertNotIn("-R", iperf_args)

    def test_fairness_harness_preserves_raw_sample_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            metrics = tmp_path / "metrics.prom"
            metrics.write_text(
                textwrap.dedent(
                    """\
                    xpf_userspace_binding_active_flow_count{binding_slot="0",iface="ge-0-0-2",queue_id="6",worker_id="0"} 1
                    xpf_userspace_cos_active_flow_count{ifindex="5",queue_id="6",worker_id="0"} 1
                    """
                ),
                encoding="utf-8",
            )
            result = self.run_fake_harness_with_metrics(tmp_path, metrics)

            self.assertEqual(result.returncode, 0, result.stderr)
            artifact_dir = tmp_path / "artifacts"
            self.assertEqual((artifact_dir / "iperf-single.json").read_text(encoding="utf-8"), "{}\n")
            self.assertIn(
                'ge-0-0-2\t1',
                (artifact_dir / "binding-flows.tsv").read_text(encoding="utf-8"),
            )
            self.assertIn(
                '5\t6\t0\t1',
                (artifact_dir / "cos-flows.tsv").read_text(encoding="utf-8"),
            )

    def test_fairness_harness_omitted_reverse_arg_defaults_to_reverse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            metrics = tmp_path / "metrics.prom"
            metrics.write_text(
                textwrap.dedent(
                    """\
                    xpf_userspace_binding_active_flow_count{binding_slot="0",iface="ge-0-0-2",queue_id="6",worker_id="0"} 1
                    xpf_userspace_cos_active_flow_count{ifindex="5",queue_id="6",worker_id="0"} 1
                    """
                ),
                encoding="utf-8",
            )
            result = self.run_fake_harness_with_metrics(
                tmp_path,
                metrics,
                harness_args=["127.0.0.1", "5203", "1", "1"],
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            iperf_args = (tmp_path / "iperf-argv.txt").read_text(encoding="utf-8").splitlines()
            self.assertIn("-R", iperf_args)

    def test_fairness_harness_rejects_scrape_rows_for_wrong_cos_queue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            metrics = tmp_path / "metrics.prom"
            metrics.write_text(
                textwrap.dedent(
                    """\
                    xpf_userspace_binding_active_flow_count{binding_slot="0",iface="ge-0-0-2",queue_id="6",worker_id="0"} 1
                    xpf_userspace_cos_active_flow_count{ifindex="5",queue_id="4",worker_id="0"} 1
                    """
                ),
                encoding="utf-8",
            )
            result = self.run_fake_harness_with_metrics(tmp_path, metrics)

            self.assertEqual(result.returncode, 2)
            self.assertIn(
                "no CoS active-flow metric rows for ifindex 5 queue 6",
                result.stderr,
            )
            self.assertFalse((tmp_path / "eval-called").exists())

    def test_class_sweep_filter_and_rate_utilization_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_wrapper = tmp_path / "fake-wrapper.sh"
            fake_harness = tmp_path / "fake-harness.sh"
            fake_eval = tmp_path / "fake-eval"
            fake_curl = tmp_path / "curl"
            curl_sentinel = tmp_path / "curl-called"
            out_root = tmp_path / "sweep"
            fake_wrapper.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -euo pipefail
                    out_dir=
                    while [[ $# -gt 0 ]]; do
                        case "$1" in
                            --out-dir) out_dir=$2; shift 2 ;;
                            --) shift; break ;;
                            *) shift ;;
                        esac
                    done
                    for _ in {1..100}; do
                        [[ -e "$CURL_SENTINEL" ]] && break
                        sleep 0.02
                    done
                    mkdir -p "$out_dir"
                    cat > "$out_dir/summary.json" <<'JSON'
                    {
                      "verdict": "PASS",
                      "observed_cov": {"mean": 0.1, "max": 0.2, "sample_stdev": 0.01},
                      "cstruct": {"mean": 0.3},
                      "gap": {"mean": -0.2, "max": -0.1},
                      "samples": [
                        {"verdict": "PASS", "aggregate_mbps": 8000.0, "starved_flow_count": 0},
                        {"verdict": "PASS", "aggregate_mbps": 8000.0, "starved_flow_count": 0}
                      ]
                    }
                    JSON
                    """
                ),
                encoding="utf-8",
            )
            fake_harness.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            fake_eval.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            fake_curl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -euo pipefail
                    touch "$CURL_SENTINEL"
                    cat <<'PROM'
                    xpf_fairness_equal_flow_estimate_valid{ifindex="14",queue_id="2"} 1
                    xpf_fairness_equal_flow_sampled_active_workers{ifindex="14",queue_id="2"} 2
                    xpf_fairness_equal_flow_unsampled_active_workers{ifindex="14",queue_id="2"} 0
                    xpf_fairness_equal_flow_target_per_flow_bps{ifindex="14",queue_id="2"} 1000
                    xpf_fairness_equal_flow_observed_bps{ifindex="14",queue_id="2"} 3000
                    xpf_fairness_equal_flow_capped_bps{ifindex="14",queue_id="2"} 2000
                    xpf_fairness_equal_flow_suppressed_bps{ifindex="14",queue_id="2"} 1000
                    xpf_fairness_equal_flow_throughput_loss_ratio{ifindex="14",queue_id="2"} 0.3333333333
                    xpf_fairness_equal_flow_worker_observed_bps{ifindex="14",queue_id="2",worker_id="0"} 1000
                    xpf_fairness_equal_flow_worker_observed_per_flow_bps{ifindex="14",queue_id="2",worker_id="0"} 1000
                    xpf_fairness_equal_flow_worker_cap_bps{ifindex="14",queue_id="2",worker_id="0"} 1000
                    xpf_fairness_equal_flow_worker_suppressed_bps{ifindex="14",queue_id="2",worker_id="0"} 0
                    xpf_fairness_equal_flow_worker_observed_bps{ifindex="14",queue_id="2",worker_id="1"} 2000
                    xpf_fairness_equal_flow_worker_observed_per_flow_bps{ifindex="14",queue_id="2",worker_id="1"} 2000
                    xpf_fairness_equal_flow_worker_cap_bps{ifindex="14",queue_id="2",worker_id="1"} 1000
                    xpf_fairness_equal_flow_worker_suppressed_bps{ifindex="14",queue_id="2",worker_id="1"} 1000
                    PROM
                    """
                ),
                encoding="utf-8",
            )
            for path in (fake_wrapper, fake_harness, fake_eval, fake_curl):
                path.chmod(0o755)

            env = {
                **os.environ,
                "PATH": f"{tmp_path}:{os.environ['PATH']}",
                "ARTIFACT_ROOT": str(out_root),
                "CAPTURE_DATAPLANE": "0",
                "CLASS_FILTER": "q2",
                "COS_IFINDEX": "14",
                "CURL_SENTINEL": str(curl_sentinel),
                "WRAPPER": str(fake_wrapper),
                "HARNESS": str(fake_harness),
                "FAIRNESS_EVAL": str(fake_eval),
            }
            result = subprocess.run(
                [str(CLASS_SWEEP_PATH)],
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=5,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            summary_lines = (out_root / "summary.tsv").read_text(encoding="utf-8").splitlines()
            self.assertIn("avg_rate_utilization", summary_lines[0])
            self.assertEqual(len(summary_lines), 2)
            row = summary_lines[1].split("\t")
            self.assertEqual(row[0], "q2-iperf-e-16g")
            self.assertEqual(row[10], "0.5")
            equal_flow_lines = (
                out_root / "equal-flow-summary.tsv"
            ).read_text(encoding="utf-8").splitlines()
            self.assertIn("target_per_flow_bps_mean", equal_flow_lines[0])
            equal_flow_row = equal_flow_lines[1].split("\t")
            self.assertEqual(equal_flow_row[0], "q2-iperf-e-16g")
            self.assertEqual(equal_flow_row[6], "1")
            self.assertEqual(equal_flow_row[7], "1000.0")
            self.assertTrue((out_root / "q2-iperf-e-16g" / "equal-flow" / "metrics-raw.prom").exists())
            self.assertTrue((out_root / "q2-iperf-e-16g" / "equal-flow" / "summary.tsv").exists())

    def test_equal_flow_capture_reduces_complete_target_rows(self) -> None:
        raw = textwrap.dedent(
            """\
            # xpf_fairness_scrape_begin timestamp=100
            xpf_fairness_equal_flow_estimate_valid{ifindex="5",queue_id="6"} 1
            xpf_fairness_equal_flow_sampled_active_workers{ifindex="5",queue_id="6"} 2
            xpf_fairness_equal_flow_unsampled_active_workers{ifindex="5",queue_id="6"} 0
            xpf_fairness_equal_flow_target_per_flow_bps{ifindex="5",queue_id="6"} 100
            xpf_fairness_equal_flow_observed_bps{ifindex="5",queue_id="6"} 300
            xpf_fairness_equal_flow_capped_bps{ifindex="5",queue_id="6"} 200
            xpf_fairness_equal_flow_suppressed_bps{ifindex="5",queue_id="6"} 100
            xpf_fairness_equal_flow_throughput_loss_ratio{ifindex="5",queue_id="6"} 0.333333
            xpf_fairness_equal_flow_worker_observed_bps{ifindex="5",queue_id="6",worker_id="0"} 100
            xpf_fairness_equal_flow_worker_observed_per_flow_bps{ifindex="5",queue_id="6",worker_id="0"} 100
            xpf_fairness_equal_flow_worker_cap_bps{ifindex="5",queue_id="6",worker_id="0"} 100
            xpf_fairness_equal_flow_worker_suppressed_bps{ifindex="5",queue_id="6",worker_id="0"} 0
            xpf_fairness_equal_flow_worker_observed_bps{ifindex="5",queue_id="6",worker_id="1"} 200
            xpf_fairness_equal_flow_worker_observed_per_flow_bps{ifindex="5",queue_id="6",worker_id="1"} 200
            xpf_fairness_equal_flow_worker_cap_bps{ifindex="5",queue_id="6",worker_id="1"} 100
            xpf_fairness_equal_flow_worker_suppressed_bps{ifindex="5",queue_id="6",worker_id="1"} 100
            # xpf_fairness_scrape_end timestamp=100
            """
        )
        scrapes, empty, errors = fairness_equal_flow_capture.split_scrapes(raw)
        self.assertEqual(empty, [])
        self.assertEqual(errors, [])
        reduced = fairness_equal_flow_capture.reduce_scrapes(scrapes, "5", "6")
        self.assertEqual(reduced["complete_scrape_count"], 1)
        self.assertEqual(reduced["latest"]["worker_count"], 2)
        self.assertEqual(reduced["series"]["suppressed_bps"]["mean"], 100)

    def test_equal_flow_capture_fails_when_target_class_rows_missing(self) -> None:
        raw = textwrap.dedent(
            """\
            # xpf_fairness_scrape_begin timestamp=100
            xpf_fairness_equal_flow_estimate_valid{ifindex="5",queue_id="4"} 1
            # xpf_fairness_scrape_end timestamp=100
            """
        )
        scrapes, _, _ = fairness_equal_flow_capture.split_scrapes(raw)
        with self.assertRaisesRegex(
            fairness_equal_flow_capture.CaptureError,
            "no equal-flow estimator rows for ifindex 5 queue 6",
        ):
            fairness_equal_flow_capture.reduce_scrapes(scrapes, "5", "6")

    def test_equal_flow_capture_fails_when_worker_rows_are_partial(self) -> None:
        raw = textwrap.dedent(
            """\
            # xpf_fairness_scrape_begin timestamp=100
            xpf_fairness_equal_flow_estimate_valid{ifindex="5",queue_id="6"} 1
            xpf_fairness_equal_flow_sampled_active_workers{ifindex="5",queue_id="6"} 2
            xpf_fairness_equal_flow_unsampled_active_workers{ifindex="5",queue_id="6"} 0
            xpf_fairness_equal_flow_target_per_flow_bps{ifindex="5",queue_id="6"} 100
            xpf_fairness_equal_flow_observed_bps{ifindex="5",queue_id="6"} 300
            xpf_fairness_equal_flow_capped_bps{ifindex="5",queue_id="6"} 200
            xpf_fairness_equal_flow_suppressed_bps{ifindex="5",queue_id="6"} 100
            xpf_fairness_equal_flow_throughput_loss_ratio{ifindex="5",queue_id="6"} 0.333333
            xpf_fairness_equal_flow_worker_observed_bps{ifindex="5",queue_id="6",worker_id="0"} 100
            xpf_fairness_equal_flow_worker_observed_per_flow_bps{ifindex="5",queue_id="6",worker_id="0"} 100
            xpf_fairness_equal_flow_worker_cap_bps{ifindex="5",queue_id="6",worker_id="0"} 100
            xpf_fairness_equal_flow_worker_suppressed_bps{ifindex="5",queue_id="6",worker_id="0"} 0
            # xpf_fairness_scrape_end timestamp=100
            """
        )
        scrapes, _, _ = fairness_equal_flow_capture.split_scrapes(raw)
        with self.assertRaisesRegex(
            fairness_equal_flow_capture.CaptureError,
            "worker row count 1 != sampled_active_workers 2",
        ):
            fairness_equal_flow_capture.reduce_scrapes(scrapes, "5", "6")

    def test_equal_flow_capture_reports_empty_scrape_marker(self) -> None:
        raw = textwrap.dedent(
            """\
            # xpf_fairness_scrape_begin timestamp=100
            # xpf_fairness_scrape_empty timestamp=100
            # xpf_fairness_scrape_end timestamp=100
            """
        )
        _scrapes, empty, errors = fairness_equal_flow_capture.split_scrapes(raw)
        self.assertEqual(empty, ["100"])
        self.assertEqual(errors, [])

    def run_fake_harness_with_metrics(
        self,
        tmp_path: Path,
        metrics: Path,
        harness_args: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        sentinel = tmp_path / "curl-called"
        fake_curl = tmp_path / "curl"
        fake_iperf = tmp_path / "fake-iperf"
        fake_eval = tmp_path / "fake-eval"
        fake_curl.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                touch "$CURL_SENTINEL"
                cat "$FAKE_METRICS"
                """
            ),
            encoding="utf-8",
        )
        fake_iperf.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                printf '%s\\n' "$@" > "$IPERF_ARGV_PATH"
                for _ in {1..100}; do
                    [[ -e "$CURL_SENTINEL" ]] && break
                    sleep 0.02
                done
                sleep 0.1
                printf '{}\\n'
                """
            ),
            encoding="utf-8",
        )
        fake_eval.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                touch "$EVAL_SENTINEL"
                printf '{"verdict":"PASS","observed_cov":0.1,"cstruct":0.2,"gap":-0.1,"aggregate_mbps":1.0,"starved_flow_count":0,"failure_reasons":[],"distribution_a_i":[1],"n_active":1,"saturated":true,"a_i_sum_check_ok":true}\\n'
                """
            ),
            encoding="utf-8",
        )
        for path in (fake_curl, fake_iperf, fake_eval):
            path.chmod(0o755)

        env = {
            **os.environ,
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "IPERF_BIN": str(fake_iperf),
            "FAIRNESS_EVAL": str(fake_eval),
            "COS_IFINDEX": "5",
            "COS_QUEUE_ID": "6",
            "CURL_SENTINEL": str(sentinel),
            "EVAL_SENTINEL": str(tmp_path / "eval-called"),
            "FAKE_METRICS": str(metrics),
            "IPERF_ARGV_PATH": str(tmp_path / "iperf-argv.txt"),
            "ARTIFACT_DIR": str(tmp_path / "artifacts"),
        }
        if harness_args is None:
            harness_args = [
                "127.0.0.1",
                "5203",
                "1",
                "1",
                "",
                "http://example.invalid/metrics",
            ]
        return subprocess.run(
            [str(HARNESS_PATH), *harness_args],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=5,
        )

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
