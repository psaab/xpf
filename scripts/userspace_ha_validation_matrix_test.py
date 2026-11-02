#!/usr/bin/env python3
"""Dry-run tests for the userspace HA validation smoke matrix."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = PROJECT_ROOT / "scripts" / "userspace-ha-validation.sh"
IPERF_METRICS = PROJECT_ROOT / "scripts" / "iperf-json-metrics.py"


class UserspaceHASmokeMatrixTests(unittest.TestCase):
    def run_validator(
        self,
        *args: str,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "loss-userspace-cluster.env"
            env_file.write_text(
                textwrap.dedent(
                    """\
                    INCUS_REMOTE=loss
                    VM0=xpf-userspace-fw0
                    VM1=xpf-userspace-fw1
                    IPERF_TARGET4=192.0.2.44
                    LAN_HOST=cluster-userspace-host
                    """
                ),
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update(
                {
                    "RUNS": "1",
                    "DURATION": "1",
                    "PARALLEL": "1",
                    "MIN_GBPS_V4": "1.0",
                    "MIN_GBPS_V6": "1.0",
                }
            )
            if extra_env:
                env.update(extra_env)
            result = subprocess.run(
                [str(VALIDATOR), "--env", str(env_file), "--dry-run-matrix", *args],
                cwd=PROJECT_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        if check and result.returncode != 0:
            self.fail(
                "validator exited "
                f"{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def run_iperf_metrics(self, payload: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "iperf.json"
            json_path.write_text(json.dumps(payload), encoding="utf-8")
            result = subprocess.run(
                ["python3", str(IPERF_METRICS), str(json_path)],
                cwd=PROJECT_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        if result.returncode != 0:
            self.fail(
                "iperf metrics exited "
                f"{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return json.loads(result.stdout)

    def test_full_matrix_lists_all_cos_direction_cells(self) -> None:
        result = self.run_validator("--smoke-matrix")
        plan = [line for line in result.stdout.splitlines() if line.startswith("matrix plan: ")]
        self.assertEqual(
            plan,
            [
                "matrix plan: cos-off-ipv4-push cos=off family=ipv4 direction=push "
                "target=192.0.2.44 port=5201 min_gbps=1.0",
                "matrix plan: cos-off-ipv4-reverse cos=off family=ipv4 direction=reverse "
                "target=192.0.2.44 port=5201 min_gbps=1.0",
                "matrix plan: cos-off-ipv6-push cos=off family=ipv6 direction=push "
                "target=2001:559:8585:80::200 port=5201 min_gbps=1.0",
                "matrix plan: cos-off-ipv6-reverse cos=off family=ipv6 direction=reverse "
                "target=2001:559:8585:80::200 port=5201 min_gbps=1.0",
                "matrix plan: cos-on-ipv4-push cos=on family=ipv4 direction=push "
                "target=192.0.2.44 port=5211 min_gbps=1.0",
                "matrix plan: cos-on-ipv4-reverse cos=on family=ipv4 direction=reverse "
                "target=192.0.2.44 port=5211 min_gbps=1.0",
                "matrix plan: cos-on-ipv6-push cos=on family=ipv6 direction=push "
                "target=2001:559:8585:80::200 port=5211 min_gbps=1.0",
                "matrix plan: cos-on-ipv6-reverse cos=on family=ipv6 direction=reverse "
                "target=2001:559:8585:80::200 port=5211 min_gbps=1.0",
            ],
        )
        self.assertIn(
            "cos-on-ipv4-push run 1: dry-run direction=push port=5211",
            result.stdout,
        )
        self.assertIn("smoke matrix complete: 8/8 cells passed", result.stdout)

    def test_default_fast_mode_is_not_reported_as_full_matrix(self) -> None:
        result = self.run_validator()
        plan = [line for line in result.stdout.splitlines() if line.startswith("matrix plan: ")]
        self.assertEqual(
            plan,
            [
                "matrix plan: fast-current-cos-ipv4-push cos=current-cos family=ipv4 "
                "direction=push target=192.0.2.44 port=5201 min_gbps=1.0",
                "matrix plan: fast-current-cos-ipv6-push cos=current-cos family=ipv6 "
                "direction=push target=2001:559:8585:80::200 port=5201 min_gbps=1.0",
            ],
        )
        self.assertIn(
            "smoke matrix: fast mode runs current-CoS IPv4/IPv6 push only",
            result.stdout,
        )
        self.assertIn("smoke fast complete: 2/2 cells passed", result.stdout)
        self.assertNotIn("smoke matrix complete:", result.stdout)

    def test_dry_run_cell_failure_exits_without_complete_summary(self) -> None:
        result = self.run_validator(
            "--smoke-matrix",
            "--dry-run-fail-cell",
            "cos-on-ipv6-reverse",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dry-run injected failure for cos-on-ipv6-reverse", result.stderr)
        self.assertNotIn("smoke matrix complete:", result.stdout)
        self.assertIn("smoke cell pass: cos-on-ipv6-push", result.stdout)
        self.assertNotIn("smoke cell pass: cos-on-ipv6-reverse", result.stdout)

    def test_matrix_perf_runs_before_cos_on_state(self) -> None:
        result = self.run_validator("--smoke-matrix", "--perf")
        self.assertIn(
            "perf order: before smoke matrix to keep CoS-off baseline clean",
            result.stdout,
        )
        self.assertLess(
            result.stdout.index("cos-off precheck: dry-run"),
            result.stdout.index("perf order: before smoke matrix"),
        )
        self.assertLess(
            result.stdout.index("perf order: before smoke matrix"),
            result.stdout.index("smoke cell start: cos-on-ipv4-push"),
        )
        # Once from the live dry-run stream and once from the final summary.
        self.assertEqual(result.stdout.count("cos-off precheck: dry-run"), 2)

    def test_duration_cli_updates_default_iperf_timeout(self) -> None:
        result = self.run_validator("--smoke-matrix", "--duration", "17")
        self.assertIn(
            "iperf runtime: runs=1 duration=17 parallel=1 timeout=32",
            result.stdout,
        )

    def test_explicit_iperf_timeout_overrides_duration_default(self) -> None:
        result = self.run_validator(
            "--smoke-matrix",
            "--duration",
            "17",
            extra_env={"IPERF_TIMEOUT": "99"},
        )
        self.assertIn(
            "iperf runtime: runs=1 duration=17 parallel=1 timeout=99",
            result.stdout,
        )

    def test_matrix_port_overrides_are_reflected_in_plan(self) -> None:
        result = self.run_validator(
            "--smoke-matrix",
            extra_env={
                "MATRIX_COS_OFF_IPERF_PORT": "5202",
                "MATRIX_COS_ON_IPERF_PORT": "5210",
            },
        )
        self.assertIn(
            "matrix plan: cos-off-ipv4-push cos=off family=ipv4 direction=push "
            "target=192.0.2.44 port=5202 min_gbps=1.0",
            result.stdout,
        )
        self.assertIn(
            "matrix plan: cos-on-ipv4-push cos=on family=ipv4 direction=push "
            "target=192.0.2.44 port=5210 min_gbps=1.0",
            result.stdout,
        )

    def test_rejects_invalid_iperf_port_overrides(self) -> None:
        port_vars = (
            "FAST_IPERF_PORT",
            "MATRIX_COS_OFF_IPERF_PORT",
            "MATRIX_COS_ON_IPERF_PORT",
            "PERF_IPERF_PORT",
        )
        bad_values = ("", "0", "65536", "5211;echo bad")
        for var_name in port_vars:
            for bad_value in bad_values:
                with self.subTest(var_name=var_name, bad_value=bad_value):
                    result = self.run_validator(
                        "--smoke-matrix",
                        check=False,
                        extra_env={var_name: bad_value},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"{var_name} must be a numeric port",
                        result.stderr,
                    )

    def test_rejects_invalid_iperf_runtime_overrides(self) -> None:
        bad_cases = (
            ("DURATION", ""),
            ("DURATION", "5;echo bad"),
            ("PARALLEL", "0"),
            ("PARALLEL", "6;echo bad"),
            ("IPERF_TIMEOUT", "0"),
            ("IPERF_TIMEOUT", "20;echo bad"),
        )
        for var_name, bad_value in bad_cases:
            with self.subTest(var_name=var_name, bad_value=bad_value):
                result = self.run_validator(
                    "--smoke-matrix",
                    check=False,
                    extra_env={var_name: bad_value},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"{var_name} must be a positive integer",
                    result.stderr,
                )

    def test_run_iperf_json_requires_explicit_escaped_port(self) -> None:
        script = VALIDATOR.read_text(encoding="utf-8")
        self.assertNotIn('port="${5:-5201}"', script)
        self.assertIn("run_iperf_json requires an explicit iperf port", script)
        self.assertIn("printf -v port_arg '%q' \"$port\"", script)
        self.assertIn("printf -v target_arg '%q' \"$target\"", script)
        self.assertIn("printf -v outfile_arg '%q' \"$outfile\"", script)
        self.assertIn("printf -v outfile_err_arg '%q' \"${outfile}.err\"", script)
        self.assertIn("printf -v tmpfile_arg '%q' \"$tmpfile\"", script)
        self.assertIn("printf -v timeout_sec_arg '%q' \"$timeout_sec\"", script)
        self.assertIn("printf -v parallel_arg '%q' \"$PARALLEL\"", script)
        self.assertIn("printf -v duration_arg '%q' \"$DURATION\"", script)

    def test_iperf_metrics_prefers_receiver_summary(self) -> None:
        metrics = self.run_iperf_metrics(
            {
                "start": {"test_start": {"protocol": "TCP"}},
                "end": {
                    "sum_sent": {
                        "bits_per_second": 1_000_000,
                        "retransmits": 7,
                        "end": 1.0,
                    },
                    "sum_received": {
                        "bits_per_second": 22_000_000_000,
                        "end": 5.0,
                    },
                },
            }
        )
        self.assertEqual(metrics["avg_gbps"], 22.0)
        self.assertEqual(metrics["retransmits"], 7)
        self.assertEqual(metrics["observed_end_sec"], 5.0)


if __name__ == "__main__":
    unittest.main()
