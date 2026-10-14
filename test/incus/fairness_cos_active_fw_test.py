#!/usr/bin/env python3
"""#13069 (deep-review D10-14): CoS fairness harness cluster-targeting
and capture-cleanup regressions.

Three defects are pinned here:

1. ``fairness-cos-throughput-headroom.sh`` and
   ``fairness-cos-class-sweep.sh`` hardcoded ``loss:xpf-userspace-fw0``,
   so whenever fw1 held the active RG (any failover) CoS was applied to
   — and dataplane telemetry was snapshot from — the STANDBY node. Both
   scripts must now resolve an unset target by probing the cluster
   candidates and fail closed when no active primary answers.
2. ``fairness-cos-class-sweep.sh`` installed no signal traps, so an
   interrupted sweep leaked the background ``/metrics`` scraper loop
   indefinitely (async commands ignore SIGINT/SIGQUIT, so even a
   terminal Ctrl-C on the process group left it alive).
3. The headroom restore path carried the sweep's ``--symmetric``
   direction flags, leaving reverse source-port classification terms
   installed for every later test suite (covered together with the
   active-primary selection in ``cos_port_grid_test.py``).

Every test here runs the REAL shell scripts against fake ``incus`` /
``apply-cos-config.sh`` / wrapper binaries, so each one is red on
pristine master and green only once the mechanisms above are gone.
"""

from __future__ import annotations

import os
import pathlib
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest


HERE = pathlib.Path(__file__).resolve().parent
HEADROOM = HERE / "fairness-cos-throughput-headroom.sh"
CLASS_SWEEP = HERE / "fairness-cos-class-sweep.sh"

_ACTIVE_STATS = "\n".join(
    (
        "Enabled: true",
        "Forwarding supported: true",
        "HA groups: rg1 active=true",
    )
)
_STANDBY_STATS = "\n".join(
    (
        "Enabled: true",
        "Forwarding supported: false",
        "HA groups: rg1 active=false",
    )
)

_GREEN_WRAPPER = textwrap.dedent(
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
    ts=$(($(date +%s) - 5))
    for sample in 1 2; do
        sample_dir="$out_dir/sample-$sample"
        mkdir -p "$sample_dir/artifacts"
        cat > "$sample_dir/artifacts/iperf-single.json" <<JSON
    {"start":{"timestamp":{"timesecs":$ts},"test_start":{"duration":120}}}
    JSON
    done
    cat > "$out_dir/summary.json" <<JSON
    {
      "verdict": "PASS",
      "observed_cov": {"mean": 0.1, "max": 0.2, "sample_stdev": 0.01},
      "cstruct": {"mean": 0.3},
      "gap": {"mean": -0.2, "max": -0.1},
      "samples": [
        {"sample": 1, "sample_dir": "$out_dir/sample-1", "verdict": "PASS", "aggregate_mbps": 500.0, "starved_flow_count": 0},
        {"sample": 2, "sample_dir": "$out_dir/sample-2", "verdict": "PASS", "aggregate_mbps": 500.0, "starved_flow_count": 0}
      ]
    }
    JSON
    """
)

# The interrupted-run wrapper: once the scraper's first curl lands it
# BLOCKS, so the sweep is provably mid-class (scraper live, wrapper
# foreground) when the test delivers its signal.
_BLOCKING_WRAPPER = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    set -euo pipefail
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --) shift; break ;;
            *) shift ;;
        esac
    done
    for _ in {1..500}; do
        [[ -e "$CURL_SENTINEL" ]] && break
        sleep 0.02
    done
    sleep 5
    """
)

_FAKE_CURL = textwrap.dedent(
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
)


def _write_exec(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class FairnessCosActiveFwTests(unittest.TestCase):
    maxDiff = None

    # ---- shared fakes -------------------------------------------------

    def _make_headroom_fakes(self, tmp_path: pathlib.Path) -> dict[str, pathlib.Path]:
        apply_log = tmp_path / "apply-args.txt"
        fake_apply = tmp_path / "apply-cos-config.sh"
        fake_sweep = tmp_path / "fairness-cos-class-sweep.sh"
        artifact_root = tmp_path / "artifacts"
        _write_exec(
            fake_apply,
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$APPLY_LOG\"\n",
        )
        _write_exec(
            fake_sweep,
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
        )
        return {
            "apply_log": apply_log,
            "fake_apply": fake_apply,
            "fake_sweep": fake_sweep,
            "artifact_root": artifact_root,
        }

    def _make_fake_incus_detecting_fw1(
        self, tmp_path: pathlib.Path
    ) -> tuple[pathlib.Path, pathlib.Path]:
        """An incus stub that reports fw1 as the active primary."""
        incus_log = tmp_path / "incus-args.txt"
        fake_incus = tmp_path / "incus"
        _write_exec(
            fake_incus,
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                printf '%s\\n' "$*" >> "$INCUS_LOG"
                case "$*" in
                    *"show chassis cluster data-plane statistics"*)
                        case "$2" in
                            *fw1) printf '%s\\n' '{_ACTIVE_STATS}' ;;
                            *) printf '%s\\n' '{_STANDBY_STATS}' ;;
                        esac
                        ;;
                    *"cat "*) printf '{{}}\\n' ;;
                esac
                """
            ),
        )
        return fake_incus, incus_log

    def _make_fake_incus_failing(
        self, tmp_path: pathlib.Path
    ) -> tuple[pathlib.Path, pathlib.Path]:
        """An incus stub whose ACTIVE-PRIMARY PROBE fails (cluster
        unreachable) while ordinary exec commands still work — isolating
        "cannot tell which node forwards" (must fail closed) from "node
        pinned by the operator" (must run to completion)."""
        incus_log = tmp_path / "incus-args.txt"
        fake_incus = tmp_path / "incus"
        _write_exec(
            fake_incus,
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                printf '%s\\n' "$*" >> "$INCUS_LOG"
                case "$*" in
                    *"sh -lc cli"*) exit 0 ;;
                    *"cli -c show chassis cluster data-plane statistics"*)
                        echo "error: cluster unreachable" >&2
                        exit 1
                        ;;
                    *"cat "*) printf '{}\\n' ;;
                esac
                """
            ),
        )
        return fake_incus, incus_log

    def _make_sweep_fakes(
        self, tmp_path: pathlib.Path, *, wrapper_body: str = _GREEN_WRAPPER
    ) -> dict[str, pathlib.Path]:
        """Wrapper/harness/eval/curl fakes mirroring the green sweep e2e tests."""
        fake_wrapper = tmp_path / "fake-wrapper.sh"
        fake_harness = tmp_path / "fake-harness.sh"
        fake_eval = tmp_path / "fake-eval"
        fake_curl = tmp_path / "curl"
        curl_sentinel = tmp_path / "curl-called"
        out_root = tmp_path / "sweep"
        _write_exec(fake_wrapper, wrapper_body)
        _write_exec(fake_harness, "#!/usr/bin/env bash\nexit 0\n")
        _write_exec(fake_eval, "#!/usr/bin/env bash\nexit 0\n")
        _write_exec(fake_curl, _FAKE_CURL)
        return {
            "fake_wrapper": fake_wrapper,
            "fake_harness": fake_harness,
            "fake_eval": fake_eval,
            "fake_curl": fake_curl,
            "curl_sentinel": curl_sentinel,
            "out_root": out_root,
        }

    def _sweep_env(
        self, tmp_path: pathlib.Path, fakes: dict[str, pathlib.Path], **extra: str
    ) -> dict[str, str]:
        env = {
            **os.environ,
            # #8136: the REAL sweep runs against FAKE targets, so the
            # harness's live target-service precheck is inapplicable here.
            "SKIP_TARGET_PRECHECK": "1",
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "ARTIFACT_ROOT": str(fakes["out_root"]),
            "CLASS_FILTER": "q2",
            "COS_IFINDEX": "14",
            "CURL_SENTINEL": str(fakes["curl_sentinel"]),
            "WRAPPER": str(fakes["fake_wrapper"]),
            "HARNESS": str(fakes["fake_harness"]),
            "FAIRNESS_EVAL": str(fakes["fake_eval"]),
            "WARMUP": "0",
            "EQUAL_FLOW_ESTIMATOR_WINDOW_SECS": "0",
            "FINAL_BURST": "0",
        }
        env.pop("DATAPLANE_VM", None)
        env.pop("TARGET_VM", None)
        env.update(extra)
        return env

    # ---- headroom: active-primary targeting ---------------------------

    def test_headroom_fails_closed_when_no_active_primary_answers(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            fakes = self._make_headroom_fakes(tmp_path)
            fake_incus, incus_log = self._make_fake_incus_failing(tmp_path)
            env = {
                **os.environ,
                "PATH": f"{tmp_path}:{os.environ['PATH']}",
                "APPLY_COS_CONFIG": str(fakes["fake_apply"]),
                "APPLY_LOG": str(fakes["apply_log"]),
                "ARTIFACT_ROOT": str(fakes["artifact_root"]),
                "SWEEP": str(fakes["fake_sweep"]),
                "INCUS_LOG": str(incus_log),
            }
            env.pop("TARGET_VM", None)
            result = subprocess.run(
                [str(HEADROOM)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(
                "unable to detect the active primary firewall", result.stderr
            )
            # Fail-closed means the CoS fixture was never spent: no apply
            # ran against a guessed node.
            self.assertFalse(
                fakes["apply_log"].exists(), "apply ran against a guessed node anyway"
            )

    def test_headroom_explicit_target_vm_skips_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            fakes = self._make_headroom_fakes(tmp_path)
            # No incus on PATH at all: an operator-pinned TARGET_VM must
            # not depend on cluster probing.
            env = {
                **os.environ,
                "APPLY_COS_CONFIG": str(fakes["fake_apply"]),
                "APPLY_LOG": str(fakes["apply_log"]),
                "ARTIFACT_ROOT": str(fakes["artifact_root"]),
                "SWEEP": str(fakes["fake_sweep"]),
                "TARGET_VM": "loss:xpf-userspace-fw9",
            }
            result = subprocess.run(
                [str(HEADROOM)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = fakes["apply_log"].read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                lines,
                [
                    "--symmetric loss:xpf-userspace-fw9",
                    "--symmetric --surplus-sharing loss:xpf-userspace-fw9",
                    "loss:xpf-userspace-fw9",
                ],
            )

    # ---- sweep: active-primary dataplane telemetry ---------------------

    def test_sweep_snapshots_dataplane_from_detected_active_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            fakes = self._make_sweep_fakes(tmp_path)
            fake_incus, incus_log = self._make_fake_incus_detecting_fw1(tmp_path)
            env = self._sweep_env(
                tmp_path,
                fakes,
                CAPTURE_DATAPLANE="1",
                INCUS_LOG=str(incus_log),
            )
            result = subprocess.run(
                [str(CLASS_SWEEP)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            incus_lines = incus_log.read_text(encoding="utf-8").splitlines()
            # Detection probed fw0 first (it answered standby)...
            self.assertIn(
                "exec loss:xpf-userspace-fw0 -- cli -c show chassis cluster "
                "data-plane statistics",
                incus_lines,
            )
            # ...but every dataplane snapshot came from the active primary.
            self.assertTrue(
                any(
                    line.startswith("exec loss:xpf-userspace-fw1 -- sh -lc")
                    for line in incus_lines
                ),
                f"no fw1 dataplane capture in {incus_lines}",
            )
            self.assertFalse(
                any(
                    line.startswith("exec loss:xpf-userspace-fw0 -- sh -lc")
                    for line in incus_lines
                ),
                f"standby fw0 captured dataplane telemetry: {incus_lines}",
            )
            summary_md = (fakes["out_root"] / "summary.md").read_text(encoding="utf-8")
            self.assertIn("loss:xpf-userspace-fw1", summary_md)

    def test_sweep_fails_closed_when_no_active_primary_answers(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            fakes = self._make_sweep_fakes(tmp_path)
            fake_incus, incus_log = self._make_fake_incus_failing(tmp_path)
            env = self._sweep_env(
                tmp_path,
                fakes,
                CAPTURE_DATAPLANE="1",
                INCUS_LOG=str(incus_log),
            )
            result = subprocess.run(
                [str(CLASS_SWEEP)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(
                "unable to detect the active primary firewall for dataplane capture",
                result.stderr,
            )
            # Fail-closed happens before any class work is spent.
            self.assertFalse(
                fakes["curl_sentinel"].exists(), "sweep ran a class despite no primary"
            )

    def test_sweep_explicit_dataplane_vm_skips_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            fakes = self._make_sweep_fakes(tmp_path)
            fake_incus, incus_log = self._make_fake_incus_failing(tmp_path)
            env = self._sweep_env(
                tmp_path,
                fakes,
                CAPTURE_DATAPLANE="1",
                DATAPLANE_VM="loss:xpf-userspace-fw9",
                INCUS_LOG=str(incus_log),
            )
            result = subprocess.run(
                [str(CLASS_SWEEP)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            incus_lines = incus_log.read_text(encoding="utf-8").splitlines()
            self.assertTrue(
                any(
                    line.startswith("exec loss:xpf-userspace-fw9 -- sh -lc")
                    for line in incus_lines
                ),
                f"no fw9 dataplane capture in {incus_lines}",
            )

    # ---- sweep: interrupted runs must not leak the scraper loop --------

    def _find_scraper_pid(self, sweep_pid: int) -> int | None:
        """The background scrape_equal_flow_metrics subshell: a direct
        child of the sweep whose argv is still the sweep script itself
        (the foreground wrapper has its own fake-wrapper.sh argv)."""
        for entry in pathlib.Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = entry.joinpath("stat").read_text(encoding="utf-8")
                ppid = int(stat[stat.rfind(")") + 2 :].split()[1])
                if ppid != sweep_pid:
                    continue
                cmdline = entry.joinpath("cmdline").read_bytes()
                if b"fairness-cos-class-sweep.sh" in cmdline:
                    return int(entry.name)
            except (OSError, ValueError, IndexError):
                continue
        return None

    def _assert_process_gone(self, pid: int, timeout: float = 3.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        self.fail(f"process {pid} (metrics scraper) survived the sweep exit")

    def _run_interrupted_sweep(self, deliver: str) -> tuple[int, int]:
        """Start the sweep with the blocking wrapper, wait until the
        scraper loop is live, deliver a signal, and return the sweep's
        returncode plus the scraper pid (for the liveness check)."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            fakes = self._make_sweep_fakes(
                tmp_path, wrapper_body=_BLOCKING_WRAPPER
            )
            env = self._sweep_env(tmp_path, fakes, CAPTURE_DATAPLANE="0")
            proc = subprocess.Popen(
                [str(CLASS_SWEEP)],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            scraper_pid: int | None = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if fakes["curl_sentinel"].exists():
                        scraper_pid = self._find_scraper_pid(proc.pid)
                        if scraper_pid is not None:
                            break
                    if proc.poll() is not None:
                        self.fail("sweep exited before the scraper started")
                    time.sleep(0.02)
                self.assertIsNotNone(scraper_pid, "scraper subshell never found")
                assert scraper_pid is not None
                if deliver == "term-pid":
                    # `timeout <cmd>`-style kill: TERM to the script only.
                    # Bash defers the trap until the foreground wrapper
                    # finishes (it sleeps 5s), so allow for that here.
                    os.kill(proc.pid, signal.SIGTERM)
                    returncode = proc.wait(timeout=15)
                elif deliver == "int-group":
                    # Terminal Ctrl-C style kill: INT to the whole group.
                    os.killpg(proc.pid, signal.SIGINT)
                    returncode = proc.wait(timeout=15)
                else:
                    raise AssertionError(deliver)
                return returncode, scraper_pid
            finally:
                # Never leak fakes, even when the assertions above fail
                # (pristine master does leak the scraper).
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)

    def test_sweep_sigterm_to_script_stops_metrics_scraper(self):
        returncode, scraper_pid = self._run_interrupted_sweep("term-pid")
        self.assertEqual(returncode, 143)
        self._assert_process_gone(scraper_pid)

    def test_sweep_sigint_to_group_stops_metrics_scraper(self):
        # Async commands ignore SIGINT, so on pristine master the scraper
        # survives the very Ctrl-C that stops the sweep.
        returncode, scraper_pid = self._run_interrupted_sweep("int-group")
        self.assertEqual(returncode, 130)
        self._assert_process_gone(scraper_pid)


if __name__ == "__main__":
    unittest.main()
