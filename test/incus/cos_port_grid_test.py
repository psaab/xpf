import pathlib
import os
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
STRICT = (ROOT / "cos-iperf-config.set").read_text()
SAME_CLASS = (ROOT / "cos-iperf-same-class.set").read_text()
SYMMETRIC = (ROOT / "cos-iperf-symmetric.set").read_text()
HARNESS = (ROOT / "fairness-harness.sh").read_text()
SWEEP = (ROOT / "fairness-cos-class-sweep.sh").read_text()
MOUSE = (ROOT / "test-mouse-latency.sh").read_text()
MOUSE_SAME_CLASS = (ROOT / "test-mouse-latency-same-class.sh").read_text()
HEADROOM = ROOT / "fairness-cos-throughput-headroom.sh"


PORT_GRID = [
    (0, "best-effort", "scheduler-be", 5200, 6200, "25000000000", False),
    (1, "iperf-100m", "scheduler-100m", 5201, 6201, "100000000", True),
    (2, "iperf-1g", "scheduler-1g", 5202, 6202, "1000000000", True),
    (3, "iperf-3g", "scheduler-3g", 5203, 6203, "3000000000", True),
    (4, "iperf-6g", "scheduler-6g", 5204, 6204, "6000000000", True),
    (5, "iperf-9g", "scheduler-9g", 5205, 6205, "9000000000", True),
    (6, "iperf-12g", "scheduler-12g", 5206, 6206, "12000000000", True),
    (7, "iperf-15g", "scheduler-15g", 5207, 6207, "15000000000", True),
    (8, "iperf-18g", "scheduler-18g", 5208, 6208, "18000000000", True),
    (9, "iperf-21g", "scheduler-21g", 5209, 6209, "21000000000", True),
    (10, "iperf-24g", "scheduler-24g", 5210, 6210, "24000000000", True),
    (11, "iperf-uncapped", "scheduler-uncapped", 5211, 6211, "25000000000", False),
]


class CoSPortGridTests(unittest.TestCase):
    def test_strict_and_same_class_fixtures_map_520x_and_620x_to_same_class(self):
        for fixture in (STRICT, SAME_CLASS):
            for queue, forwarding_class, scheduler, iperf_port, echo_port, _, exact in PORT_GRID:
                with self.subTest(queue=queue, fixture="strict-or-same"):
                    self.assertIn(
                        f"set class-of-service forwarding-classes queue {queue} {forwarding_class}",
                        fixture,
                    )
                    self.assertIn(
                        f"set class-of-service scheduler-maps bandwidth-limit forwarding-class {forwarding_class} scheduler {scheduler}",
                        fixture,
                    )
                    self.assertIn(
                        f"term {queue} from destination-port {iperf_port}",
                        fixture,
                    )
                    self.assertIn(
                        f"term {queue} from destination-port {echo_port}",
                        fixture,
                    )
                    exact_line = f"set class-of-service schedulers {scheduler} transmit-rate exact"
                    if exact:
                        self.assertIn(exact_line, fixture)
                    else:
                        self.assertNotIn(exact_line, fixture)

    def test_symmetric_fixture_shapes_reverse_source_ports_for_iperf_and_echo(self):
        for queue, forwarding_class, _, iperf_port, echo_port, _, _ in PORT_GRID:
            with self.subTest(queue=queue):
                self.assertIn(
                    f"filter bandwidth-output-reverse term {queue} from source-port {iperf_port}",
                    SYMMETRIC,
                )
                self.assertIn(
                    f"filter bandwidth-output-reverse term {queue} from source-port {echo_port}",
                    SYMMETRIC,
                )
                self.assertIn(
                    f"filter bandwidth-output-reverse term {queue} then forwarding-class {forwarding_class}",
                    SYMMETRIC,
                )

    def test_harness_and_sweep_share_the_canonical_queue_and_rate_map(self):
        for queue, forwarding_class, _, iperf_port, echo_port, rate_bps, _ in PORT_GRID:
            with self.subTest(queue=queue):
                self.assertIn(f"{iperf_port}|{echo_port}) printf '{queue}\\n' ;;", HARNESS)
                self.assertIn(f"{iperf_port}|{echo_port}) printf '{rate_bps}\\n' ;;", HARNESS)
                self.assertIn(f"q{queue}-{forwarding_class}", SWEEP)
                self.assertIn(f" {iperf_port} {queue} {rate_bps}", SWEEP)

    def test_mouse_latency_defaults_use_620x_echo_ports(self):
        self.assertIn('ELEPHANT_PORT="${ELEPHANT_PORT:-5202}"', MOUSE)
        self.assertIn('MOUSE_PORT="${MOUSE_PORT:-6200}"', MOUSE)
        self.assertIn("MOUSE_PORT=6202", MOUSE_SAME_CLASS)
        self.assertIn("MOUSE_CLASS=iperf-1g", MOUSE_SAME_CLASS)

    def test_same_class_fixture_preserves_legacy_port_7_override(self):
        for family in ("inet", "inet6"):
            with self.subTest(family=family):
                self.assertIn(
                    f"set firewall family {family} filter bandwidth-output term 12 from destination-port 7",
                    SAME_CLASS,
                )
                self.assertIn(
                    f"set firewall family {family} filter bandwidth-output term 12 then forwarding-class iperf-1g",
                    SAME_CLASS,
                )
                self.assertIn(
                    f"set firewall family {family} filter bandwidth-output term 12 then count iperf-1g-legacy-mouse",
                    SAME_CLASS,
                )

    def test_headroom_applies_symmetric_fixture_for_reverse_default(self):
        lines = self._run_headroom_and_capture_apply_args({})
        self.assertEqual(
            lines,
            [
                "--symmetric loss:xpf-userspace-fw0",
                "--symmetric --surplus-sharing loss:xpf-userspace-fw0",
                "--symmetric loss:xpf-userspace-fw0",
            ],
        )

    def test_headroom_keeps_forward_fixture_for_explicit_forward(self):
        lines = self._run_headroom_and_capture_apply_args({"REVERSE": ""})
        self.assertEqual(
            lines,
            [
                "loss:xpf-userspace-fw0",
                "--surplus-sharing loss:xpf-userspace-fw0",
                "loss:xpf-userspace-fw0",
            ],
        )

    def _run_headroom_and_capture_apply_args(self, extra_env):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            apply_log = tmp_path / "apply-args.txt"
            fake_apply = tmp_path / "apply-cos-config.sh"
            fake_sweep = tmp_path / "fairness-cos-class-sweep.sh"
            artifact_root = tmp_path / "artifacts"
            fake_apply.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$APPLY_LOG\"\n",
                encoding="utf-8",
            )
            fake_sweep.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -euo pipefail
                    mkdir -p "$ARTIFACT_ROOT"
                    cat > "$ARTIFACT_ROOT/summary.tsv" <<'TSV'
                    class\tport\tqueue_id\trate_bps\texit_status\tverdict\tmean_observed_cov\tmax_observed_cov\tstdev_observed_cov\tavg_mbps\tavg_rate_utilization\tavg_cstruct\tmean_gap\tmax_gap\tstarved_flows\tper_run_verdicts
                    q8-iperf-18g\t5208\t8\t18000000000\t0\tPASS\t0.1\t0.1\t0\t1000\t0.1\t0.1\t0\t0\t0\tPASS
                    TSV
                    """
                ),
                encoding="utf-8",
            )
            fake_apply.chmod(0o755)
            fake_sweep.chmod(0o755)
            env = {
                "PATH": os.environ.get("PATH", ""),
                "APPLY_COS_CONFIG": str(fake_apply),
                "APPLY_LOG": str(apply_log),
                "ARTIFACT_ROOT": str(artifact_root),
                "SWEEP": str(fake_sweep),
            }
            env.update(extra_env)
            result = subprocess.run(
                [str(HEADROOM)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return apply_log.read_text(encoding="utf-8").splitlines()


if __name__ == "__main__":
    unittest.main()
