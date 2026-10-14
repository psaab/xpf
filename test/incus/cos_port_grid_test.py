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
MATRIX = (ROOT / "test-mouse-latency-matrix.sh").read_text()
LIB = (ROOT / "mouse-elephant-lib.sh").read_text()
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

    def test_harness_and_sweep_use_the_shared_schedule_library(self):
        # #13070 (D10-15): the harness and the sweep used to carry their
        # own copies of this queue/rate map, and this test pinned BOTH
        # spellings — which is exactly what let one copy drift unseen.
        # They now source cos-apply-lib.sh, and the VALUES are pinned
        # against the fixture by test_cos_apply_lib.py instead. What
        # remains pinned here is the wiring (#8244 pattern): a script
        # that substitutes the helpers without sourcing the library
        # expands them to EMPTY, which is worse than a wrong number and
        # passes every value assertion.
        for script, marker in (
            (HARNESS, "cos_port_to_rate_bps"),
            (SWEEP, "COS_SCHEDULE_PORTS"),
        ):
            self.assertIn("cos-apply-lib.sh", script)
            self.assertIn(marker, script)

    def test_mouse_latency_defaults_use_620x_echo_ports(self):
        # #8244: the defaults were declared independently in the rep script and
        # the matrix, and this test pinned only one of the two spellings — so a
        # change to the other could not red it. They now live once, in
        # mouse-elephant-lib.sh, and BOTH scripts must reference that.
        for script in (MOUSE, MATRIX):
            self.assertIn('MOUSE_PORT="${MOUSE_PORT:-$MOUSE_DEFAULT_ECHO_PORT}"', script)
            self.assertIn(
                'ELEPHANT_PORT="${ELEPHANT_PORT:-$MOUSE_DEFAULT_IPERF_PORT}"', script
            )
            # A script that substitutes the variable without sourcing the file
            # that defines it expands to EMPTY, which is worse than a wrong
            # port and passes every string pin above.
            self.assertIn('. "${SCRIPT_DIR}/mouse-elephant-lib.sh"', script)
        self.assertIn("MOUSE_PORT=6202", MOUSE_SAME_CLASS)
        self.assertIn("MOUSE_CLASS=iperf-1g", MOUSE_SAME_CLASS)

    def test_the_shared_defaults_AGREE_with_the_port_grid(self):
        """Assert the agreement, not a literal.

        Pinning `6200` in a second file is what let the two copies drift. The
        durable property is that the default IS the grid's best-effort echo
        port — if the grid moves, this follows; if the default drifts off the
        grid, this reds.
        """
        best_effort = next(row for row in PORT_GRID if row[0] == 0)
        _, _, _, iperf_port, echo_port, _, _ = best_effort
        self.assertIn(f"MOUSE_DEFAULT_ECHO_PORT={echo_port}", LIB)
        # The elephant default is the 1 Gbps exact class, not queue 0 — the
        # mice are deliberately best-effort so they share no class with the
        # elephants by default.
        one_gig = next(row for row in PORT_GRID if row[1] == "iperf-1g")
        self.assertIn(f"MOUSE_DEFAULT_IPERF_PORT={one_gig[3]}", LIB)
        self.assertNotEqual(echo_port, iperf_port)

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
        # #13069 (D10-14): TARGET_VM defaults to the DETECTED active
        # primary (fake incus below reports fw1 active, fw0 standby), and
        # the post-surplus restore re-applies the canonical forward-only
        # fixture — no --symmetric — so reverse source-port terms do not
        # leak into later suites.
        lines = self._run_headroom_and_capture_apply_args({})
        self.assertEqual(
            lines,
            [
                "--symmetric loss:xpf-userspace-fw1",
                "--symmetric --surplus-sharing loss:xpf-userspace-fw1",
                "loss:xpf-userspace-fw1",
            ],
        )

    def test_headroom_keeps_forward_fixture_for_explicit_forward(self):
        lines = self._run_headroom_and_capture_apply_args({"REVERSE": ""})
        self.assertEqual(
            lines,
            [
                "loss:xpf-userspace-fw1",
                "--surplus-sharing loss:xpf-userspace-fw1",
                "loss:xpf-userspace-fw1",
            ],
        )

    def _run_headroom_and_capture_apply_args(self, extra_env):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            apply_log = tmp_path / "apply-args.txt"
            fake_apply = tmp_path / "apply-cos-config.sh"
            fake_sweep = tmp_path / "fairness-cos-class-sweep.sh"
            fake_incus = tmp_path / "incus"
            incus_log = tmp_path / "incus-args.txt"
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
            # #13069 (D10-14): the headroom script resolves TARGET_VM by
            # probing the cluster candidates through incus; fw1 answers
            # active so the fakes above must all be aimed at fw1.
            fake_incus.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    printf '%s\\n' "$*" >> "$INCUS_LOG"
                    if [[ "$*" == *"show chassis cluster data-plane statistics"* ]]; then
                        case "$2" in
                            *fw1)
                                printf '%s\\n' \\
                                    'Enabled: true' \\
                                    'Forwarding supported: true' \\
                                    'HA groups: rg1 active=true'
                                ;;
                            *)
                                printf '%s\\n' \\
                                    'Enabled: true' \\
                                    'Forwarding supported: false' \\
                                    'HA groups: rg1 active=false'
                                ;;
                        esac
                    fi
                    """
                ),
                encoding="utf-8",
            )
            fake_apply.chmod(0o755)
            fake_sweep.chmod(0o755)
            fake_incus.chmod(0o755)
            env = {
                "PATH": f"{tmp_path}:{os.environ.get('PATH', '')}",
                "APPLY_COS_CONFIG": str(fake_apply),
                "APPLY_LOG": str(apply_log),
                "ARTIFACT_ROOT": str(artifact_root),
                "INCUS_LOG": str(incus_log),
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
