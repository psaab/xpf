import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("test-mouse-latency.sh").read_text()
MATRIX_SCRIPT = pathlib.Path(__file__).with_name("test-mouse-latency-matrix.sh").read_text()


class MouseLatencyShellTests(unittest.TestCase):
    def test_surplus_fixture_env_is_validated_and_passed_to_apply(self):
        self.assertIn('MOUSE_COS_SURPLUS_SHARING="${MOUSE_COS_SURPLUS_SHARING:-0}"', SCRIPT)
        self.assertIn('MOUSE_COS_SURPLUS_SHARING=1', SCRIPT)
        self.assertIn("MOUSE_COS_SURPLUS_SHARING='$MOUSE_COS_SURPLUS_SHARING' must be boolean", SCRIPT)

        self.assertRegex(
            SCRIPT,
            re.compile(
                r'if \[\[ "\$MOUSE_COS_SURPLUS_SHARING" -eq 1 \]\]; then\s+'
                r'APPLY_COS_FLAGS\+=\(--surplus-sharing\)\s+fi',
                re.MULTILINE,
            ),
        )

    def test_surplus_fixture_choice_is_written_to_manifest(self):
        self.assertIn(
            'MOUSE_CLASS="$MOUSE_CLASS" MOUSE_COS_SURPLUS_SHARING="$MOUSE_COS_SURPLUS_SHARING"',
            SCRIPT,
        )
        self.assertIn('"cos_surplus_sharing": os.environ["MOUSE_COS_SURPLUS_SHARING"] == "1"', SCRIPT)

    def test_matrix_documents_surplus_fixture_knob(self):
        self.assertIn("Set MOUSE_COS_SURPLUS_SHARING=1", MATRIX_SCRIPT)
        self.assertIn("per-rep manifest records the selected fixture bit", MATRIX_SCRIPT)

    def test_settle_budget_and_diagnostics_are_recorded(self):
        self.assertIn('SETTLE_BUDGET="${MOUSE_LATENCY_SETTLE_BUDGET:-20}"', SCRIPT)
        self.assertIn("MOUSE_LATENCY_SETTLE_BUDGET='$SETTLE_BUDGET' must be a positive integer second count", SCRIPT)
        self.assertIn('settle-diagnostics "${OUT_DIR}/iperf3-settle.txt" "$SHAPER_BPS"', SCRIPT)
        self.assertIn('"settle_budget_s": int(os.environ["SETTLE_BUDGET"])', SCRIPT)
        self.assertIn('"cwnd_settle_elapsed_s": int(os.environ["CWND_SETTLE_ELAPSED"])', SCRIPT)
        self.assertIn('CWND_SETTLE_OK="unknown"', SCRIPT)
        self.assertIn('CWND_SETTLE_OK="false"', SCRIPT)
        self.assertIn('settle_ok = None', SCRIPT)
        self.assertIn('"cwnd_settle_ok": settle_ok', SCRIPT)
        self.assertRegex(
            SCRIPT,
            re.compile(
                r'if \[\[ \$pull_rc -ne 0 \|\| ! -s "\$\{OUT_DIR\}/iperf3-settle\.txt" \]\]; then\s+'
                r'invalidate "iperf3-settle-pull-failed"',
                re.MULTILINE,
            ),
        )
        self.assertIn('"status": "INVALID"', SCRIPT)
        self.assertIn('write_invalid_manifest "$reason"', SCRIPT)

    def test_env_consistency_guard_runs_before_rep(self):
        # #1365: the harness must reject an ELEPHANT_PORT/SHAPER_BPS
        # pairing whose cwnd-settle floor exceeds the class cap, before
        # spending a whole matrix cell on an impossible pairing.
        self.assertIn(
            'check-env-consistency \\\n    "$ELEPHANT_PORT" "$SHAPER_BPS"',
            SCRIPT,
        )
        self.assertIn("unsatisfiable cwnd-settle pairing", SCRIPT)
        # Must fire before the rep does any cluster work (mkdir OUT_DIR is
        # the first post-validation step).
        guard_idx = SCRIPT.index("check-env-consistency")
        mkdir_idx = SCRIPT.index('mkdir -p "$OUT_DIR"')
        self.assertLess(guard_idx, mkdir_idx)

    def test_runtime_cos_and_settle_cpu_artifacts_are_cleared_and_captured(self):
        for artifact in (
            '"/cwnd-settle.json \\',
            '"/mpstat-settle.txt \\',
            '"/cos-interface-pre.txt \\',
            '"/cos-interface-settle.txt \\',
            '"/cos-interface-post.txt \\',
        ):
            self.assertIn(artifact, SCRIPT)
        self.assertIn("show class-of-service interface", SCRIPT)
        # The settle sampler's count is still SETTLE_BUDGET and its
        # remote artifact path is still /tmp/mpstat-settle-<tag>.txt.
        # #8270 moved the launch behind mouse_remote_job_start_cmd, so
        # the assertion moved with it rather than being deleted: the
        # count is pinned here and the path is pinned in
        # RemoteJobArtifactPathTests below, where the library derives it.
        self.assertIn('mouse_remote_job_start_cmd mpstat-settle "$REP_TAG"', SCRIPT)
        self.assertIn('mpstat 1 "$SETTLE_BUDGET"', SCRIPT)


class RemoteJobArtifactPathTests(unittest.TestCase):
    """The library must keep deriving the historical remote paths.

    #8270 replaced three literal launch strings with a derivation. If
    the derivation drifts, every artifact pull in the rep script starts
    missing its file -- and the rep script's own pulls name the old
    paths literally, so the two would disagree silently.
    """

    LIB = pathlib.Path(__file__).with_name("mouse-elephant-lib.sh")

    def _lib_eval(self, expr):
        return subprocess.run(
            ["bash", "-c", f'. "{self.LIB}"; {expr}'],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    def test_remote_paths_match_what_the_rep_script_pulls(self):
        for job, want in (
            ("iperf3", "/tmp/iperf3-TAG.txt"),
            ("mpstat", "/tmp/mpstat-TAG.txt"),
            ("mpstat-settle", "/tmp/mpstat-settle-TAG.txt"),
        ):
            with self.subTest(job=job):
                self.assertEqual(
                    self._lib_eval(f'mouse_remote_job_outfile {job} TAG'), want)
                self.assertEqual(
                    self._lib_eval(f'mouse_remote_job_pidfile {job} TAG'),
                    want[:-len(".txt")] + ".pid")
        # The rep script pulls these literal paths; they must be the
        # same strings the library builds.
        for literal in (
            "/tmp/iperf3-${REP_TAG}.txt",
            "/tmp/mpstat-${REP_TAG}.txt",
            "/tmp/mpstat-settle-${REP_TAG}.txt",
        ):
            self.assertIn(literal, SCRIPT)


class RemoteJobLifecycleWiringTests(unittest.TestCase):
    """#7159/#8270: every BACKGROUNDED REMOTE job must be stopped remotely.

    mouse-elephant-selftest.sh proves the library's start/stop pair
    reaps the leaf process. It cannot see WHICH call sites use it -- and
    the whole defect is a call site: the EXIT trap killed the local
    incus-exec client and believed the remote process had stopped.
    #8268 fixed one of the three and left two with the old shape, which
    is exactly the regression these bind.
    """

    # (local pid var, job name, program name) for every job backgrounded
    # through incus_exec in the rep script.
    REMOTE_JOBS = (
        ("IPERF_PID", "iperf3", "iperf3"),
        ("SETTLE_MPSTAT_PID", "mpstat-settle", "mpstat"),
        ("MPSTAT_PID", "mpstat", "mpstat"),
    )

    def test_rep_script_sources_the_lifecycle_library(self):
        self.assertIn('. "${SCRIPT_DIR}/mouse-elephant-lib.sh"', SCRIPT)

    def test_every_remote_job_is_launched_through_the_library(self):
        # The raw launch strings are what leaked: they left nothing on
        # the remote side that a kill could address.
        # #8259: the elephant target moved from $TARGET_V4 to
        # $ELEPHANT_TARGET_V4 when the single target variable was split, so
        # both raw-launch spellings are now forbidden.
        self.assertNotIn('"iperf3 -c ${TARGET_V4}', SCRIPT)
        self.assertNotIn('"iperf3 -c ${ELEPHANT_TARGET_V4}', SCRIPT)
        self.assertNotIn('"mpstat 1 ${DURATION}', SCRIPT)
        self.assertNotIn('"mpstat 1 ${SETTLE_BUDGET}', SCRIPT)
        self.assertIn(
            'mouse_elephant_start_cmd "$REP_TAG" "$ELEPHANT_TARGET_V4" "$ELEPHANT_PORT"',
            SCRIPT,
        )
        self.assertIn('mouse_remote_job_start_cmd mpstat-settle "$REP_TAG"', SCRIPT)
        self.assertIn('mouse_remote_job_start_cmd mpstat "$REP_TAG" mpstat 1 "$DURATION"', SCRIPT)

    def test_cleanup_stops_every_remote_job_on_the_source_container(self):
        for pid_var, job, prog in self.REMOTE_JOBS:
            with self.subTest(job=job):
                self.assertIn(
                    f'stop_remote_job "${{{pid_var}:-}}" {job} {prog}',
                    SCRIPT,
                    f"{job} is not stopped on the source container: a local "
                    f"kill of {pid_var} only closes the incus-exec client",
                )
        # ... and stop_remote_job must actually reach the container.
        self.assertIn(
            'incus_exec "$SOURCE" sh -c \\\n        "$(mouse_remote_job_kill_cmd "$job" "$REP_TAG" "$prog")"',
            SCRIPT,
        )

    def test_local_subshell_poller_is_not_routed_through_the_remote_stop(self):
        # RG_POLL_PID has the same `kill "$VAR"` spelling and is NOT
        # affected: its $! is a local subshell, so a plain kill is the
        # complete stop. Sending it through stop_remote_job would add a
        # remote round-trip per rep that stops nothing. This is the
        # discriminator that keeps the fix a fix rather than a pattern
        # applied everywhere it matches.
        self.assertNotIn("stop_remote_job \"${RG_POLL_PID", SCRIPT)
        self.assertIn(
            '[[ -n "${RG_POLL_PID:-}" ]] && kill "$RG_POLL_PID" 2>/dev/null || true',
            SCRIPT,
        )

    def test_stale_elephant_guard_runs_before_any_cos_mutation(self):
        self.assertIn("mouse_elephant_stale_check_cmd", SCRIPT)
        self.assertIn('invalidate "stale-elephant-client"', SCRIPT)
        guard_idx = SCRIPT.index("mouse_elephant_stale_check_cmd")
        cos_idx = SCRIPT.index('"${SCRIPT_DIR}/apply-cos-config.sh"')
        self.assertLess(guard_idx, cos_idx)

    def test_every_remote_job_pidfile_is_swept_with_the_stale_artifacts(self):
        for _, job, _ in self.REMOTE_JOBS:
            with self.subTest(job=job):
                self.assertIn("/tmp/%s-${REP_TAG}.pid" % job, SCRIPT)


if __name__ == "__main__":
    unittest.main()


class TargetSplitWiringTests(unittest.TestCase):
    """#8259 — the mouse and elephant targets must be SEPARATELY addressable.

    They were one variable, which is why the gate could never separate
    firewall queueing from target-host service: both flows terminated on the
    same host by construction, not by configuration.

    These pin the WIRING rather than the values. `mouse_latency_aggregate`
    refuses to emit PASS/FAIL when the two are equal, and that check is only
    meaningful if the harness can actually drive them apart — otherwise it is
    permanently true and the gate is permanently void.
    """

    def test_both_targets_are_overridable_and_default_together(self):
        self.assertIn('MOUSE_TARGET_V4="${MOUSE_TARGET_V4:-$TARGET_V4}"', SCRIPT)
        self.assertIn('ELEPHANT_TARGET_V4="${ELEPHANT_TARGET_V4:-$TARGET_V4}"', SCRIPT)

    def test_the_mouse_probe_uses_the_mouse_target(self):
        self.assertIn('--target "$MOUSE_TARGET_V4" --port "$MOUSE_PORT"', SCRIPT)

    def test_the_reachability_preflight_uses_the_mouse_target(self):
        # The preflight opens the ECHO port; checking it on the elephant
        # target would probe a host that need not run an echo daemon at all.
        self.assertIn('exec 3<>/dev/tcp/${MOUSE_TARGET_V4}/${MOUSE_PORT}', SCRIPT)

    def test_both_targets_reach_the_manifest(self):
        # The reducer's void check reads these out of manifest.json. If they
        # are not recorded, the check silently never fires — which is the
        # failure mode this whole change exists to remove.
        self.assertIn('"mouse_target": os.environ["MOUSE_TARGET_V4"]', SCRIPT)
        self.assertIn('"elephant_target": os.environ["ELEPHANT_TARGET_V4"]', SCRIPT)
        # Both the OK and the INVALID manifest builders.
        self.assertEqual(SCRIPT.count('"mouse_target": os.environ["MOUSE_TARGET_V4"]'), 2)

    def test_both_targets_are_exported_to_the_manifest_builders(self):
        # The manifest python runs under an explicit env prefix; a variable
        # missing from it raises KeyError at run time, on the cluster, after
        # the lock is taken.
        self.assertEqual(
            SCRIPT.count('MOUSE_TARGET_V4="$MOUSE_TARGET_V4" ELEPHANT_TARGET_V4="$ELEPHANT_TARGET_V4"'),
            2,
        )


MATRIX = (pathlib.Path(__file__).resolve().parent / "test-mouse-latency-matrix.sh").read_text()


class AbortIsDistinguishableTests(unittest.TestCase):
    """#8244 defect 2 — an abort must not look like a gate failure.

    Every abort path used to `exit 1` and write no summary.json, so the only
    signal was an ABSENCE, and rc=1 is also what a measured gate FAIL returns.
    On #7100 the same rc=1 meant "never ran" (0 JSON files) once and "ran and
    failed" (62 files) the other time, and the run was read as an unprovisioned
    lab when eleven of twelve echo listeners were up.

    Same defect as #8259's void verdict, one layer out: a state the harness
    could not measure, reported as though it had measured it.
    """

    def test_every_abort_path_goes_through_the_helper(self):
        # The usage error is the one legitimate `exit 1`: it fires before $1
        # exists, so there is no out_root to write an artifact into.
        code_lines = [
            ln for ln in MATRIX.splitlines()
            if "exit 1" in ln and not ln.lstrip().startswith("#")
        ]
        self.assertEqual(
            len(code_lines), 1,
            f"every abort but the usage error must call abort_matrix, found: {code_lines}",
        )

    def test_abort_exits_two_not_one(self):
        # 0 = PASS, 1 = measured FAIL, 2 = did not produce a verdict. An abort
        # that exits 1 is the defect; an abort that exits 0 would be worse.
        self.assertIn("    exit 2\n}", MATRIX)

    def test_each_abort_reason_is_distinctly_named(self):
        for code in (
            "ABORTED-LOCK-CONTENTION",
            "ABORTED-TARGET-SERVICES-DOWN",
            "ABORTED-PREFLIGHT-INVALID",
            "ABORTED-PREFLIGHT-NO-PROBE",
            "ABORTED-PREFLIGHT-FAILED",
        ):
            with self.subTest(code=code):
                self.assertIn(code, MATRIX)

    # L on #18738: an assignment can carry a builtin prefix (`export`,
    # `readonly`, `declare -x`, `local`, `typeset`). A pattern anchored on a
    # bare `LOCK_FILE=` did not see `export LOCK_FILE="$TMPDIR/..."`, so a
    # reassignment written that way passed both cells below.
    _LOCK_ASSIGNMENT = re.compile(
        r"^\s*(?:export\s+|readonly\s+|declare(?:\s+-\w+)*\s+|local\s+|typeset\s+)?LOCK_FILE=(.*)$",
        re.MULTILINE,
    )

    def _lock_assignments(self):
        return self._LOCK_ASSIGNMENT.findall(MATRIX)

    def test_the_lock_path_is_assigned_exactly_once(self):
        """Copilot D.1: one per-host mutex, so ONE assignment of LOCK_FILE.

        A later reassignment (for example from TMPDIR) would silently move the
        mutex between invocations.
        """
        assignments = self._lock_assignments()
        self.assertEqual(
            len(assignments), 1,
            f"LOCK_FILE must be assigned exactly once, found {assignments!r}",
        )

    def test_the_lock_path_is_never_environment_derived(self):
        """Copilot D.1: two invocations with different TMPDIR (or any other
        environment) must lock the SAME file, so the value carries no
        expansion at all. This is the property, not a literal path: the next
        correct move of the lock (as #14837 moved it from /tmp to the
        /var/worktrees scratch root) keeps this green.
        """
        for value in self._lock_assignments():
            self.assertNotIn(
                "$", value,
                f"LOCK_FILE={value} expands a variable; the mutex must be a fixed per-host path",
            )

    def test_the_only_lock_opened_is_lock_file(self):
        """The mutex is fd 9 on $LOCK_FILE, and nothing else is opened as a
        lock. An `exec 9>` onto any other path, a TMPDIR-derived one say,
        would bypass the fixed path above.
        """
        # L on #18738: bash also opens a named fd (`exec {fd}>path`), which a
        # digits-only pattern did not see, so a second lock on a TMPDIR path
        # opened that way passed.
        opens = re.findall(r"^\s*exec\s+(?:\{\w+\}|\d+)\s*>\s*(\S+)", MATRIX, re.MULTILINE)
        self.assertEqual(
            opens, ['"$LOCK_FILE"'],
            f"the only exec-opened fd must be the mutex on \"$LOCK_FILE\", found {opens!r}",
        )

    def test_the_only_flock_taken_is_on_the_mutex_fd(self):
        """The fd opened on $LOCK_FILE is 9, and the one flock call must take
        fd 9 and fail fast (-n). A flock on any other fd or path locks
        something other than the fixed mutex, and a blocking flock queues a
        second matrix instead of refusing it.
        """
        calls = [
            c.strip()
            for c in re.findall(r"^[^#\n]*\bflock\b([^|;&\n]*)", MATRIX, re.MULTILINE)
        ]
        self.assertEqual(
            calls, ["-n 9"],
            f"the only flock call must be `flock -n 9` on the mutex fd, found {calls!r}",
        )

    def test_out_root_is_resolved_before_the_mutex(self):
        """A lock-contention abort must be able to write its artifact too.

        That is the purest 'never ran' case, and it used to be the one with
        the least evidence.
        """
        out_root = MATRIX.find('OUT_ROOT="$1"')
        lock = self._LOCK_ASSIGNMENT.search(MATRIX)
        self.assertNotEqual(out_root, -1, 'OUT_ROOT="$1" is not assigned')
        self.assertIsNotNone(lock, "LOCK_FILE is not assigned")
        self.assertLess(out_root, lock.start(), "OUT_ROOT must be resolved before the mutex is taken")

    def test_the_matrix_sources_the_shared_port_defaults(self):
        """#8244 defect 1: the default lived in two files and drifted.

        Without the source line the substitution below expands to EMPTY, which
        is worse than the wrong port — measured before this test existed.
        """
        self.assertIn('. "${SCRIPT_DIR}/mouse-elephant-lib.sh"', MATRIX)
        self.assertIn('MOUSE_PORT="${MOUSE_PORT:-$MOUSE_DEFAULT_ECHO_PORT}"', MATRIX)
        self.assertIn('MOUSE_PORT="${MOUSE_PORT:-$MOUSE_DEFAULT_ECHO_PORT}"', SCRIPT)
        self.assertNotIn('MOUSE_PORT:-6200', MATRIX)
        self.assertNotIn('MOUSE_PORT:-6200', SCRIPT)

    def test_abort_helper_writes_a_readable_artifact(self):
        """FUNCTIONAL, not a string pin: run the helper and parse what it wrote.

        The artifact must match what mouse_latency_aggregate.py emits, so a
        consumer already reading summary.json["verdict"]["verdict"] needs no
        change to see an abort.
        """
        import re as _re
        m = _re.search(r"^abort_matrix\(\) \{.*?^\}$", MATRIX, _re.M | _re.S)
        self.assertIsNotNone(m, "abort_matrix must be a shell function")
        with tempfile.TemporaryDirectory() as tmp:
            script_dir = os.path.join(tmp, "bin")
            os.makedirs(script_dir)
            # Stub the scan so the test is hermetic and its output identifiable.
            stub = os.path.join(script_dir, "target-services.sh")
            with open(stub, "w") as f:
                f.write("#!/bin/sh\necho '6200:closed 6201:OPEN 6202:OPEN'\n")
            os.chmod(stub, 0o755)
            out_root = os.path.join(tmp, "run")
            harness = os.path.join(tmp, "h.sh")
            with open(harness, "w") as f:
                f.write(
                    "set -uo pipefail\n"
                    f'OUT_ROOT="{out_root}"\nSCRIPT_DIR="{script_dir}"\n'
                    + m.group(0)
                    + '\nabort_matrix ABORTED-TARGET-SERVICES-DOWN "echo 6200 down"\n'
                )
            proc = subprocess.run(["bash", harness], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            with open(os.path.join(out_root, "summary.json")) as f:
                doc = json.load(f)
            self.assertEqual(doc["verdict"]["verdict"], "ABORTED-TARGET-SERVICES-DOWN")
            self.assertIn("6200 down", doc["verdict"]["reason"])
            # The scan is the half that turns "the lab is down" into "one port
            # is down" — it must reach the artifact, not just stderr.
            self.assertIn("6201:OPEN", doc["verdict"]["target_services_scan"])
            self.assertEqual(doc["summaries"], {})
