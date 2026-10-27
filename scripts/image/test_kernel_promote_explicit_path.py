#!/usr/bin/env python3
"""Self-test: the #1930 kernel promotion gate runs the xpfd the ARMING recorded.

#6541 / #6601. `scripts/image/xpf-kernel-promote` is the OUTER hop of the A/B
kernel promote/rollback gate: systemd runs it as root on every boot, and on a
candidate boot the exit status of the `xpfd upgrade kernel promote` it invokes
decides promote-vs-rollback. A bare, $PATH-resolved `xpfd` lets any PATH entry
ordered ahead of the real location author that decision — or, with no attacker
at all, lets a stale xpfd from some other directory verify the wrong build
against the candidate kernel.

Six revisions tried to answer "which xpfd is live?" from ambient state — $PATH,
compiled defaults, inode identity, a unit name, then that unit's LoadState — and
each one closed a single stale-authority window and left another. The last broke
concretely: a DISABLED unit still reports LoadState=loaded with MainPID=0, so a
leftover default unit whose drop-in named an OLD version satisfied the arm-time
check and its stale ExecStart was accepted on the candidate boot.

r6 stopped selecting signals. `xpfd upgrade kernel arm` IS an xpfd, so
os.Executable() names the live binary by construction; arming RECORDS that path
and the boot gate READS it. The question changes from "which xpfd is live?"
(unanswerable later) to "which xpfd armed this candidate?" (a fact). So the gate
now has:

    * ONE authority — the arm record;
    * a CROSS-CHECK against the pinned unit (MainPID -> /proc/<pid>/exe, then a
      strictly-parsed ExecStart) which may CONTRADICT the record but never
      replace it;
    * a LOUD refusal on contradiction or on an unusable record;
    * a quiet "nothing to promote" ONLY when the record is absent AND the
      journal agrees nothing is armed (#6601 r7).

Two consequences shape the tests below.

FIRST, the unit hops are still live code, but a wrong answer from them costs
something different now: it no longer hands an impostor the promote decision, it
manufactures a false DISAGREEMENT and REFUSES a healthy promotion. So the
recycled-pid / cgroup / ExecStart-parsing tests assert that the gate still runs
THE RECORDED BINARY — a mutation that loosens one of those guards turns the run
into a refusal and reds the test.

SECOND, the quiet skip is itself an inference, and this issue exists because
every inference eventually met a box that broke it. "Record absent" means
"nothing armed" only because arming writes the record, and losing just ONE of
the two files breaks that: a `/var/lib/xpf` restored from before the arm or
restored partially, a stray cleanup that takes the sidecar and leaves the
journal, or a candidate armed by a build predating the sidecar. A candidate then
goes UNVERIFIED behind a log line that reads like an ordinary boot — the same
laundering the r5 MINOR-1 work removed from the not-found-unit branch — so the
journal is consulted for ONE BIT (is a candidate ARMED) and the divergent state
is loud.

(A non-default `--journal` is NOT one of those cases and must not be cited as
one: Go derives the sidecar from the journal's directory, so that flag moves
BOTH files together and the gate finds neither. It is a real trap — the boot
unit hardcodes this script with no way to pass a journal path, so such a
candidate is structurally unpromotable — but a separate one, closed at the ARM
end by #6631 rather than here.)

FAIL-ON-REVERT: restore `command -v xpfd` / bare `xpfd upgrade kernel promote`,
reintroduce a compiled-default fallback, remove the arm-record check, or make
ARMED-without-record silent again, and this file fails.
"""

import os
import re
import shutil

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "xpf-kernel-promote"

# The two paths a compiled-default fallback used to consult. They are named
# here ONLY so the tests can plant leftovers at them and prove the gate never
# reaches for either: `--sbin-dir` and `--versions-dir` relocate INDEPENDENTLY
# and neither relocation removes what it left behind, so every shape a
# defaults fallback could recognise —
#
#   both usable, DIFFERENT files : one is stale, nothing says which
#   both usable, SAME inode      : the healthy default layout AND a
#                                  both-roots-relocated box's leftovers
#                                  (#6601 r4 Codex MAJOR-1)
#   exactly one usable           : the surviving half of a partial relocation
#
# — has a relocation shape that makes it the stale build.
SBIN = "/usr/local/sbin/xpfd"
# The arm record: written by `xpfd upgrade kernel arm`, read by the gate. Its
# path is asserted against Go by TestPromoteScriptArmRecordPathMatchesGo.
ARM_RECORD = "/var/lib/xpf/kernel-promote-binary"
# The kernel-channel journal. The gate reads ONE BIT out of it (is a candidate
# ARMED) and never a path. Pinned against Go by TestPromoteScriptJournalMatchesGo.
KERNEL_JOURNAL = "/var/lib/xpf/kernel-upgrade.state"
# The durable did-not-run record (#6622). The gate exits 0 on every path and the
# unit is Type=oneshot + RemainAfterExit=yes, so `systemctl status` reads SUCCESS
# even after a refusal; this file is what makes the decline outlive journal
# rotation. Its path is pinned against Go by
# TestPromoteScriptRefusalRecordPathMatchesGo_6622 (pkg/upgrade).
REFUSAL_RECORD = "/var/lib/xpf/kernel-promote-refusal"
VERSIONED = "/var/lib/xpf/versions/current/xpfd"


def script_text() -> str:
    return SCRIPT.read_text()


def shell_function_body(text: str, name: str) -> str:
    """Return the body of `name() { ... }` from a POSIX sh source.

    Used to scope source assertions to one function, so an unrelated query
    elsewhere in the script cannot mask a deletion inside it.
    """
    start = text.index(f"{name}() {{")
    depth, i = 0, start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    raise AssertionError(f"unterminated shell function {name}")


def shell_function_lines(text: str, name: str):
    """1-based (first, last) line numbers of `name() { ... }`."""
    body = shell_function_body(text, name)
    start = text.index(body)
    first = text.count("\n", 0, start) + 1
    return first, first + body.count("\n")


def code_lines():
    """The script's lines with comments stripped."""
    for lineno, line in enumerate(script_text().splitlines(), start=1):
        yield lineno, line.split("#", 1)[0]


class TestNoPathResolution(unittest.TestCase):
    """Static assertions on the script source."""

    def test_script_exists(self):
        # The tracked mode is 0644; debian/rules (install -m 0755) and
        # bake.py (chmod 0755) set the exec bit at install time, so the mode
        # here is deliberately not asserted.
        self.assertTrue(SCRIPT.is_file(), f"{SCRIPT} missing")
        self.assertTrue(
            script_text().startswith("#!/bin/sh"),
            "xpf-kernel-promote must stay a POSIX sh script (early boot)",
        )

    def test_the_arm_record_is_the_authority(self):
        # #6601 r6, the design itself. The EXECUTED path must come out of the
        # record; the unit hops may run, but only to contradict it.
        text = script_text()
        self.assertIn(
            'XPFD="$RECORDED"',
            text,
            "the gate never assigns the executed binary from the arm record; "
            "selection has drifted back to inference (#6601 r6)",
        )
        self.assertIn(
            'same_file "$CROSS" "$RECORDED"',
            text,
            "no record-vs-unit disagreement check; a stale leftover unit could "
            "again select an older binary (#6601 r6 MAJOR)",
        )
        self.assertNotIn(
            '"$CROSS" != "$RECORDED"',
            text,
            "the cross-check compares STRINGS again. The record is a RESOLVED "
            "path (os.Executable -> /proc/self/exe) and the shipped base unit's "
            "ExecStart is the /usr/local/sbin/xpfd SYMLINK until the first cut, "
            "so a string compare refuses a healthy candidate on every never-cut "
            "box (#6601 r8 MAJOR-1)",
        )
        # `same_file` must stay confined to the cross-check: the `-ef` lint
        # exemption above is scoped to its body, so a second caller would be a
        # selection path smuggled past the ban.
        calls = [
            f"{SCRIPT.name}:{lineno}: {code.strip()}"
            for lineno, code in code_lines()
            if "same_file" in code and "same_file()" not in code
        ]
        self.assertEqual(
            len(calls),
            1,
            "same_file must be called ONCE, by the cross-check. Any other "
            f"caller is a filesystem-derived SELECTION (#6601 r8): {calls}",
        )

    def test_discovers_configured_path_from_systemd(self):
        # The CROSS-CHECK must ASK systemd rather than guess. `--versions-dir`
        # and `--sbin-dir` are both real operator options and the cut maintains
        # whatever was configured, so a box that relocated BOTH has a perfectly
        # intact xpfd at a path no hardcoded list contains.
        text = script_text()
        self.assertIn(
            "ExecStart",
            text,
            "the gate never consults systemd's ExecStart for xpfd.service, so a "
            "box with both runtime roots relocated has no cross-check at all "
            "(#6541 fold r3)",
        )
        self.assertIn("xpfd.service", text)
        for call in (
            'try_candidate "$(unit_main_pid_exe)"',
            'try_candidate "$(unit_exec_start)"',
        ):
            self.assertIn(call, text, f"the gate never calls {call} (#6601 r4)")
        # Order matters: the kernel's answer for the LIVE process outranks the
        # declared one.
        self.assertLess(
            text.index('try_candidate "$(unit_main_pid_exe)"'),
            text.index('try_candidate "$(unit_exec_start)"'),
        )

    def test_no_compiled_default_inference_fallback(self):
        # #6601 r5, the class-closing invariant. NO code path may select a
        # binary from an inference that a leftover file can satisfy. The
        # filesystem cannot answer "which of these is the live xpfd" once a
        # root has been relocated — leftovers are indistinguishable from a
        # healthy layout, in EVERY shape (different files, same inode, only one
        # survivor) — so the gate must have no filesystem-derived candidate at
        # all, not a cleverer test over one.
        #
        # The `-ef` ban is scoped to SELECTION (#6601 r8). Its rationale is that
        # a same-inode test cannot decide WHICH of two leftover defaults is the
        # live xpfd — an unanswerable question. Inside `same_file` the question
        # is a different one, and answerable: do these two NAMES denote the same
        # FILE? That is required there, because the record is a resolved path
        # and ExecStart is a symlink before the first cut. The companion
        # assertion below pins `same_file` to the cross-check so the exemption
        # cannot widen into a selection path.
        sf_first, sf_last = shell_function_lines(script_text(), "same_file")
        offenders = []
        for lineno, code in code_lines():
            for lit in (SBIN, VERSIONED):
                if lit in code:
                    offenders.append(f"{SCRIPT.name}:{lineno}: {code.strip()}")
            if re.search(r"(?:^|\s)-ef(?:\s|$)", code) and not (
                sf_first <= lineno <= sf_last
            ):
                offenders.append(
                    f"{SCRIPT.name}:{lineno}: same-inode test OUTSIDE same_file: "
                    f"{code.strip()}"
                )
        self.assertEqual(
            offenders,
            [],
            "the gate reintroduced a compiled-default fallback. A leftover at a "
            "default path is byte-for-byte indistinguishable from a live one, "
            "and `-ef` cannot tell a healthy default layout from a "
            "both-roots-relocated box whose leftover symlink still points at "
            "its leftover runtime (#6601 r4 MAJOR-1). Refuse instead:\n  "
            + "\n  ".join(offenders),
        )

    def test_main_pid_candidate_is_bound_to_the_unit(self):
        # #6601 r4 MAJOR-2. A pid is a number, and a number is not an identity.
        # If xpfd.service exits and the kernel recycles its pid onto an
        # unrelated process, /proc/<pid>/exe names THAT binary — and a basename
        # check only requires the impostor to be called `xpfd`. The pid must be
        # bound back to the unit.
        text = script_text()
        self.assertIn(
            "ControlGroup",
            text,
            "the MainPID hop never checks that the pid belongs to "
            "xpfd.service's own control group, so a recycled pid running an "
            "unrelated binary named `xpfd` can contradict the arm record and "
            "veto a healthy promotion (#6601 r4 MAJOR-2)",
        )
        self.assertIn("/cgroup", text)
        # The pid must be read TWICE and required to be the same: once into the
        # discovery snapshot, and once AGAIN inside unit_main_pid_exe after the
        # readlink, so a recycle DURING the sequence is caught rather than raced
        # past. Since r7 the FIRST read lives in the snapshot (facts and advice
        # must describe the reads the decision was made on), so the count is
        # asserted at both sites rather than twice in one function.
        self.assertIn(
            'SNAP_MAINPID=$(systemctl show --property=MainPID --value "$PROMOTE_UNIT"',
            text,
            "the MainPID discovery read is no longer taken into the snapshot, "
            "so the refusal can report a pid the decision never saw "
            "(#6601 r7 MINOR-3)",
        )
        body = shell_function_body(text, "unit_main_pid_exe")
        self.assertEqual(
            len(re.findall(r"--property=MainPID", body)),
            1,
            "unit_main_pid_exe must RE-READ MainPID exactly once, after the "
            "readlink — that read exists to observe a pid that moved since the "
            "snapshot, so it is the one query that must NOT come from the "
            "snapshot (#6601 r4 MAJOR-2)",
        )
        self.assertIn('pid="$SNAP_MAINPID"', body)
        self.assertIn('[ "$pid2" = "$pid" ]', body)

    def test_execstart_is_parsed_at_systemds_real_field_delimiter(self):
        # MAJOR (#6601 r4). `systemctl show -p ExecStart --value` renders
        #   { path=/x ; argv[]=/x ... ; ignore_errors=no ; ... }
        # and the property printer substitutes the stored path RAW ("path=%s"),
        # with no escaping. systemd PERMITS an executable path containing a
        # space or a ';', so a parser that stops at the first one does not fail
        # to resolve -- it resolves to a SHORTER, DIFFERENT path. Cut at the
        # real field delimiter instead.
        text = script_text()
        self.assertIn(
            " ; argv[]=",
            text,
            "the ExecStart parse does not cut at systemd's real field "
            "delimiter, so a path containing a space or a ';' truncates into a "
            "different executable (#6601 r4 MAJOR-1)",
        )
        self.assertNotIn(
            "[^ ;]",
            text,
            "a `[^ ;]` character class still terminates the ExecStart path at "
            "the first space or semicolon -- both are legal in a systemd "
            "executable path (#6601 r4 MAJOR-1)",
        )

    def test_refusal_facts_come_from_the_discovery_snapshot(self):
        # #6601 r7 MINOR-3. The previous revision suppressed each systemctl
        # failure at the point of use and then RE-QUERIED to build the refusal,
        # so a query that failed during discovery and recovered by the time the
        # message was assembled was reported as "the unit IS known to systemd"
        # and the operator was told to fix an ExecStart that was never
        # consulted. The message must describe the reads the DECISION was made
        # on, which is only structurally true if the reporting path cannot
        # query at all.
        #
        # Scoped to INVOCATION, not to the word: the advice text legitimately
        # tells the operator to run `systemctl show ...` themselves. What must
        # not appear is a command substitution or a systemctl command word.
        text = script_text()
        for fn in ("unit_facts", "set_cause_advice"):
            body = shell_function_body(text, fn)
            why = (
                f"{fn} queries systemctl instead of rendering the discovery "
                "snapshot, so the refusal can describe a system state the "
                "decision was never made on (#6601 r7 MINOR-3)"
            )
            self.assertNotIn("$(systemctl", body, why)
            for line in body.splitlines():
                self.assertIsNone(
                    re.match(r"\s*(?:if\s+|!\s+)?systemctl\b", line),
                    f"{why}: {line.strip()!r}",
                )

    def test_journal_is_read_for_a_boolean_never_for_a_path(self):
        # The journal carries PromoteBinary too, and reading THAT here would put
        # the executed path back inside a JSON value parsed by sh — the exact
        # "a value may legally contain the delimiter" class that MAJOR-1 was
        # about, and the whole reason the one-line sidecar exists.
        text = script_text()
        body = shell_function_body(text, "journal_state")
        self.assertNotIn(
            "promote_binary",
            body,
            "journal_state extracts a PATH out of the JSON journal. The gate is "
            "POSIX sh with no safe JSON parser; the path must come from the "
            "one-line sidecar (#6601 r6/r7)",
        )
        self.assertIn(
            'JOURNAL_ARMED_STATE="ARMED"',
            text,
            "the armed-state token is no longer pinned; ARMED is the verified "
            "trial state (upgrade.IsArmed)",
        )
        self.assertIn(
            'JOURNAL_ARMING_STATE="ARMING"',
            text,
            "the ARMING token is no longer pinned; ARMING *with the arm record "
            "present* is the #16809 unconfirmed-trial shape and must run the "
            "recorded gate, while ARMING without a record stays not-a-trial",
        )
        self.assertIn(
            "ARM_RECORD",
            body,
            "journal_state must consult the arm record to distinguish an "
            "interrupted arm (ARMING, no record) from an unconfirmed trial "
            "(ARMING, record present) (#16809)",
        )

    def test_no_command_v_probe_for_xpfd(self):
        # `command -v xpfd` is a $PATH lookup. The presence check must stat the
        # explicit candidates instead.
        self.assertIsNone(
            re.search(r"command\s+-v\s+xpfd", script_text()),
            "xpf-kernel-promote probes for xpfd via `command -v` ($PATH); "
            "it must test the explicit candidate paths instead (#6541)",
        )

    def test_no_bare_xpfd_invocation(self):
        # Any line that starts a command with a bare `xpfd` word (not a
        # quoted variable, not an absolute path) is the bug.
        for lineno, code in code_lines():
            self.assertIsNone(
                re.search(r"(?:^|[;&|]|\bthen\b|\bdo\b)\s*xpfd\s", code),
                f"{SCRIPT.name}:{lineno} invokes a BARE, $PATH-resolved xpfd "
                f"(#6541): {code.strip()!r}",
            )


class _GateBase(unittest.TestCase):
    """Shared harness: runs the gate against a fake root, hostile xpfd on $PATH.

    Holds setUp and the helpers only -- no test methods, so unittest does not
    collect it. Subclassed by every behavioural class below so the systemctl
    stub, the re-rooting and the $PATH trap are defined ONCE.
    """

    def setUp(self):
        if not shutil.which("sh"):
            self.skipTest("no /bin/sh")
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-promote-6541-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        # A hostile/stale xpfd EARLY on $PATH. Any PATH-resolving
        # implementation finds this one. It records that it ran and exits 0
        # (a false "clean promote").
        self.path_dir = self.tmp / "hostile-path"
        self.path_dir.mkdir()
        self.marker = self.tmp / "hostile-ran"
        self._write_stub(self.path_dir / "xpfd", exit_code=0, marker=self.marker)

        # systemctl stub. `show` answers from env vars the test sets, so unit
        # discovery is exercised hermetically; anything else (reboot) is
        # recorded. systemctl is legitimately $PATH-resolved -- it is a
        # distribution binary, unlike xpfd.
        #
        # MainPID reads are COUNTED so a test can model a pid that changes
        # mid-sequence (the recycle race): with STUB_MAINPID2 set, the second
        # and later reads answer differently from the first. Since r7 the first
        # read is the discovery snapshot's and the second is the re-read inside
        # unit_main_pid_exe, which is exactly the pair the race guard compares.
        self.systemctl_ran = self.tmp / "systemctl.ran"
        self.mainpid_seq = self.tmp / "mainpid.seq"
        (self.path_dir / "systemctl").write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "show" ]; then\n'
            # STUB_SHOW_FAIL models a systemctl that cannot answer at all
            # (missing, erroring, or a query it does not understand).
            '  [ -n "${STUB_SHOW_FAIL-}" ] && exit 1\n'
            '  case "$*" in\n'
            "    *MainPID*)\n"
            f'      n=$(cat "{self.mainpid_seq}" 2>/dev/null || echo 0)\n'
            "      n=$((n + 1))\n"
            f'      echo "$n" > "{self.mainpid_seq}"\n'
            '      if [ "$n" -ge 2 ] && [ -n "${STUB_MAINPID2-}" ]; then\n'
            "        printf '%s\\n' \"$STUB_MAINPID2\"\n"
            "      else\n"
            "        printf '%s\\n' \"${STUB_MAINPID-0}\"\n"
            "      fi\n"
            "      ;;\n"
            '    *ControlGroup*) printf \'%s\\n\' "${STUB_CONTROLGROUP-}" ;;\n'
            '    *ExecStart*) printf \'%s\\n\' "${STUB_EXECSTART-}" ;;\n'
            '    *LoadState*) printf \'%s\\n\' "${STUB_LOADSTATE-not-found}" ;;\n'
            "  esac\n"
            "  exit 0\n"
            "fi\n"
            f'echo "$0 $*" >> "{self.systemctl_ran}"\n'
            "exit 0\n"
        )
        (self.path_dir / "systemctl").chmod(0o755)
        # Default: systemd knows nothing, so nothing cross-checks.
        self.stub_execstart = ""
        self.stub_loadstate = "not-found"
        # Which shell runs the gate. Overridden by the busybox leg (NIT-1); the
        # script is POSIX sh and must behave identically under both.
        self.shell_argv = ["/bin/sh"]
        # The arm record. None => _run() derives it from a well-formed
        # stub_execstart, so a test that models a HEALTHY box expresses
        # "record agrees with the unit" without restating the path. Set it
        # explicitly to model a disagreement, a stale record, or no arming.
        self.armed = None
        self.arm_explicitly_absent = False
        # The kernel journal. None => not written at all (nothing was ever
        # armed here). A string is written verbatim as the journal body.
        self.journal = None
        self.stub_mainpid = "0"
        self.stub_mainpid2 = ""
        self.stub_controlgroup = ""
        self.stub_show_fail = ""
        self._stub_seq = 0

        # A rewritten copy of the script whose absolute state paths — and the
        # HISTORICAL compiled-default paths — are re-rooted into the temp tree.
        # The current gate names neither default, so those two are a no-op for
        # it: they exist so that a revision which reintroduces a defaults
        # fallback is caught HERE, resolving into the fake root, instead of
        # touching the real filesystem.
        self.fake_root = self.tmp / "root"
        self.script_copy = self.tmp / "xpf-kernel-promote"
        text = script_text()
        text = text.replace(VERSIONED, str(self.fake_root) + VERSIONED)
        text = text.replace(SBIN, str(self.fake_root) + SBIN)
        text = text.replace(ARM_RECORD, str(self.fake_root) + ARM_RECORD)
        text = text.replace(KERNEL_JOURNAL, str(self.fake_root) + KERNEL_JOURNAL)
        text = text.replace(REFUSAL_RECORD, str(self.fake_root) + REFUSAL_RECORD)
        self.script_copy.write_text(text)
        self.script_copy.chmod(0o755)

    # ---------------------------------------------------------------- helpers

    def _write_stub(self, path: Path, exit_code: int, marker: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "#!/bin/sh\n"
            f'echo "$0 $*" >> "{marker}"\n'
            f"exit {exit_code}\n"
        )
        path.chmod(0o755)

    def _derive_armed(self):
        """The binary a well-formed ExecStart names, parsed the way the gate does.

        This MUST use the gate's own delimiter rule (` ; argv[]=`), not a
        naive cut at the first space. Parsing it more loosely here arms a
        TRUNCATED path, the gate resolves the correct longer one, and the
        cross-check fires -- which is the harness disagreeing with itself, not
        a finding. (That is exactly what happened when this helper cut at the
        first space: the #6601 r4 space-in-path fixtures started refusing.)
        """
        raw = self.stub_execstart
        cand = ""
        if "\n" in raw.strip():
            return ""   # multi-line render: ambiguous, exactly as the gate treats it
        if "path=" in raw:
            rest = raw.split("path=", 1)[1]
            if rest.count(" ; argv[]=") == 1:
                cand = rest.split(" ; argv[]=", 1)[0]
        elif raw.strip().startswith("/"):
            stripped = raw.strip()
            if not re.search(r"[\s;]", stripped):
                cand = stripped
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
        return ""

    def _run(self):
        if not self.arm_explicitly_absent:
            armed = self.armed if self.armed is not None else self._derive_armed()
            if armed:
                self._arm(armed)
        if self.journal is not None:
            self._write_journal(self.journal)
        env = dict(os.environ)
        env["PATH"] = str(self.path_dir) + os.pathsep + env.get("PATH", "")
        env["STUB_EXECSTART"] = self.stub_execstart
        env["STUB_LOADSTATE"] = self.stub_loadstate
        env["STUB_MAINPID"] = self.stub_mainpid
        env["STUB_MAINPID2"] = self.stub_mainpid2
        env["STUB_CONTROLGROUP"] = self.stub_controlgroup
        env["STUB_SHOW_FAIL"] = self.stub_show_fail
        return subprocess.run(
            self.shell_argv + [str(self.script_copy)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _arm(self, binary) -> Path:
        """Write the arm record the way `xpfd upgrade kernel arm` does."""
        rec = Path(str(self.fake_root) + ARM_RECORD)
        rec.parent.mkdir(parents=True, exist_ok=True)
        rec.write_text(f"{binary}\n")
        return rec

    def _journal_path(self) -> Path:
        return Path(str(self.fake_root) + KERNEL_JOURNAL)

    def _write_journal(self, body: str) -> Path:
        """Write a kernel-channel journal body verbatim.

        Callers pass real `json.MarshalIndent` shapes (see journal_body) so the
        gate's one-bit read is exercised against what Go actually writes.
        """
        j = self._journal_path()
        j.parent.mkdir(parents=True, exist_ok=True)
        j.write_text(body)
        return j

    @staticmethod
    def journal_body(state: str) -> str:
        """A journal as pkg/upgrade writes it: json.MarshalIndent, no trailing \\n."""
        return (
            "{\n"
            '  "candidate_version": "6.18.5-12-generic",\n'
            '  "known_good_version": "6.17.0-1-generic",\n'
            '  "active_slot": "xpf-A",\n'
            '  "inactive_slot": "xpf-B",\n'
            f'  "state": "{state}",\n'
            '  "started_at": "2026-07-31T09:00:00Z",\n'
            '  "boot_id": "Boot0002",\n'
            '  "promote_binary": "/opt/live/xpfd"\n'
            "}"
        )

    def _install(self, rel: str, exit_code: int) -> Path:
        """Install a recording stub at a re-rooted historical default path."""
        marker = self.tmp / (rel.replace("/", "_") + ".ran")
        self._write_stub(Path(str(self.fake_root) + rel), exit_code, marker)
        return marker

    def _install_abs(self, abs_path: Path, exit_code: int = 0) -> Path:
        """Install a recording stub at an ABSOLUTE path outside the fake root."""
        self._stub_seq += 1
        marker = self.tmp / f"stub{self._stub_seq}.ran"
        self._write_stub(abs_path, exit_code, marker)
        return marker

    def _arm_a_live_binary(self):
        """Install a recording stub, record it as the armed xpfd, return both."""
        live = self.tmp / f"recorded{self._stub_seq}" / "xpfd"
        ran = self._install_abs(live)
        self.armed = str(live)
        return live, ran

    def _seed_runtime_layout(self, version: str = "v1"):
        """The layout a NEVER-CUT box actually has, with the record resolved.

        `debian/xpf.postinst` runs `xpfd seed-runtime` on first install, and
        `pkg/upgrade/runtime/seed.go` creates `<SbinDir>/xpfd` as an absolute
        symlink through `versions/current`. No cut has run, so there is no
        `10-xpf-version.conf` drop-in and ExecStart is still the shipped base
        unit's `/usr/local/sbin/xpfd` — while `os.Executable()` in the arming
        process reports the fully-resolved `versions/<ver>/xpfd`.

        `_derive_armed()` cannot express this: it parses the record OUT of
        `stub_execstart`, so record and ExecStart are string-equal by
        construction and the symlink asymmetry is invisible. That is why the
        r8 MAJOR-1 string compare survived a suite that claimed to cover the
        healthy default-rooted box. Callers set `self.armed` from the RESOLVED
        path returned here.

        Returns (resolved_versioned_path, sbin_symlink_path, ran_marker).
        """
        base = str(self.fake_root) + "/var/lib/xpf/versions"
        versioned = Path(base) / version / "xpfd"
        ran = self._install_abs(versioned)
        Path(base + "/current").symlink_to(version)
        sbin = Path(str(self.fake_root) + SBIN)
        sbin.parent.mkdir(parents=True, exist_ok=True)
        sbin.symlink_to(base + "/current/xpfd")
        return versioned, sbin, ran

    def _sbin_symlink_to_versioned(self):
        """The `flip` 6b layout: <SbinDir>/xpfd -> <VersionsDir>/current/xpfd.

        This is what a HEALTHY default-rooted box looks like — and, verbatim,
        what a box that relocated BOTH roots leaves behind (relocation removes
        neither), which is why a same-inode test cannot tell them apart.
        """
        sbin_path = Path(str(self.fake_root) + SBIN)
        sbin_path.parent.mkdir(parents=True, exist_ok=True)
        sbin_path.symlink_to(str(self.fake_root) + VERSIONED)

    # ------------------------------------------------------------- assertions

    def _assert_no_path_fallback(self, res, why: str):
        self.assertFalse(
            self.marker.exists(),
            f"the gate executed the xpfd it found on $PATH ({why}) (#6541): {res.stderr}",
        )

    def _assert_refused(self, res, why: str):
        """A LOUD refusal: the gate had something to promote and would not.

        Deliberately NOT satisfied by the benign "nothing to promote" line. An
        earlier draft of this migration accepted either, and eleven tests then
        passed while never reaching the code they name — the vacuous pass is
        exactly how a guard dies quietly.
        """
        self.assertEqual(
            res.returncode,
            0,
            "the refusal must stay on the non-rebooting infra-error path; a "
            f"non-zero exit trips OnFailure= and reboots: {res.stderr}",
        )
        self.assertIn(
            "REFUSING to promote",
            res.stderr,
            f"the gate did not refuse ({why}); it may have adopted an inferred "
            f"binary, or skipped without reaching the check at all: {res.stderr}",
        )
        self.assertIn("ERROR", res.stderr, f"the refusal was not loud ({why}): {res.stderr}")
        self.assertNotIn(
            "nothing to promote",
            res.stderr,
            f"the refusal was reported as a benign nothing-to-promote ({why}): {res.stderr}",
        )
        self.assertNotIn(
            "promotion gate: clean",
            res.stderr,
            f"the gate reported a CLEAN promotion ({why}) — an inferred binary "
            f"authorized it: {res.stderr}",
        )
        self.assertFalse(
            self.systemctl_ran.exists(),
            f"the refusal rebooted the box ({why})",
        )
        self._assert_no_path_fallback(res, why)

    def _assert_nothing_armed(self, res, why: str):
        """The benign outcome: no record AND a journal that agrees."""
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(
            "nothing to promote",
            res.stderr,
            f"the gate did not report nothing-armed ({why}): {res.stderr}",
        )
        self.assertNotIn("REFUSING to promote", res.stderr)
        self.assertNotIn("promotion gate: using", res.stderr)
        self._assert_no_path_fallback(res, why)

    def _assert_ran(self, res, ran: Path, why: str):
        """The gate executed the recorded binary and did not refuse."""
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn(
            "REFUSING",
            res.stderr,
            f"the gate refused a promotion it should have run ({why}): {res.stderr}",
        )
        self.assertTrue(
            ran.exists(),
            f"the gate did not run the recorded xpfd ({why}): {res.stderr}",
        )
        self._assert_no_path_fallback(res, why)

    def _refusal_path(self) -> Path:
        return Path(str(self.fake_root) + REFUSAL_RECORD)

    def _read_refusal(self) -> dict:
        """Parse the durable did-not-run record the way Go does (#6622).

        Splits on the FIRST '=' only: a systemd ExecStart rendering contains
        several, and a parser that split on every one would mangle the field an
        operator most needs. Returns {} when no record exists.
        """
        p = self._refusal_path()
        if not p.is_file():
            return {}
        out = {}
        for line in p.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
        return out

    def _assert_recorded(self, disposition: str, why: str) -> dict:
        """The did-not-run outcome left a durable, parseable record."""
        rec = self._read_refusal()
        self.assertTrue(
            rec,
            f"no durable record at {self._refusal_path()} ({why}). The gate "
            f"exits 0 and the unit is RemainAfterExit=yes, so `systemctl "
            f"status` reads SUCCESS — without this file the operator has only "
            f"a journald line, which journal rotation takes away (#6622)",
        )
        self.assertEqual(
            rec.get("disposition"),
            disposition,
            f"disposition={rec.get('disposition')!r}, want {disposition!r} "
            f"({why}). A refusal names a condition the operator can fix; an "
            f"indeterminate says the gate could not even tell — folding them "
            f"sends the operator to the wrong subsystem",
        )
        # ONE LINE PER FIELD is the format contract: the shell writes it and Go
        # reads it, so a value carrying a newline would forge extra records.
        raw = self._refusal_path().read_text()
        self.assertEqual(
            len(raw.splitlines()),
            len([k for k in rec]),
            f"the record has lines that are not key=value fields ({why}):\n{raw}",
        )
        return rec

    def _assert_no_record(self, why: str):
        self.assertEqual(
            self._read_refusal(),
            {},
            f"a durable did-not-run record was written ({why}). It is written "
            f"only where the gate never ran xpfd at all; writing it on an "
            f"ordinary boot would rewrite the file every boot and bury the "
            f"signal it exists to carry (#6622)",
        )

    def _spawn_fake_daemon(self, subdir: str, basename: str = "xpfd", unlink: bool = False):
        """Run a real process from a real file; return (proc, path, cgroup)."""
        sleep_bin = shutil.which("sleep")
        if not sleep_bin:
            self.skipTest("no sleep(1) to model a running daemon")
        target = self.tmp / subdir / basename
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sleep_bin, target)
        if not os.access(target, os.X_OK):
            self.skipTest("could not stage an executable copy")
        proc = subprocess.Popen(
            [str(target), "60"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        if unlink:
            # Models a binary REPLACED on disk while the daemon runs: the
            # kernel then renders /proc/<pid>/exe as "<path> (deleted)".
            target.unlink()
        try:
            first = Path(f"/proc/{proc.pid}/cgroup").read_text().splitlines()[0]
        except (OSError, IndexError):
            self.skipTest("no readable /proc/<pid>/cgroup on this kernel")
        # "<hierarchy-id>:<controllers>:<path>" — cgroup v2 renders "0::<path>".
        # The path field is exactly what systemd reports as the unit's
        # ControlGroup for a unit whose main process is this one (verified
        # firsthand against cron/dbus/incus on a live systemd host).
        fields = first.split(":", 2)
        if len(fields) != 3 or not fields[2].startswith("/"):
            self.skipTest(f"unrecognised /proc/<pid>/cgroup rendering: {first!r}")
        return proc, target, fields[2]


class TestRecordIsTheAuthority(_GateBase):
    """The record answers what no inference could, and nothing overrides it."""

    def test_relocated_roots_with_same_inode_leftovers_are_resolved_by_the_record(self):
        # #6601 r4 Codex MAJOR-1, reproduced exactly — and now RESOLVED rather
        # than refused. Both roots relocated, so the LIVE xpfd is at neither
        # default, and relocation removed neither leftover: the old sbin symlink
        # still points at the old versioned runtime, so the two leftovers are
        # ONE INODE, bit-identical to a HEALTHY default-rooted box. `-ef` calls
        # that unambiguous and hands the promotion decision to a STALE build
        # (Codex: live_ran False / stale_ran True).
        #
        # Neither systemd source can rescue it either: the daemon is not running
        # (MainPID 0) and the ExecStart cannot be parsed, because the live path
        # legally contains the literal " ; argv[]=" that is systemd's own field
        # delimiter. `<tmp>/opt/relocated`, where cutting at the FIRST delimiter
        # lands, is itself a real executable, so a parse that gives up on the
        # count rule does not fail to resolve: it resolves to a THIRD binary.
        #
        # This is the box the whole redesign exists for. The arming knew which
        # xpfd it was, so the record names the live binary and the gate runs it.
        live_dir = self.tmp / "opt" / "relocated ; argv[]=x"
        live = live_dir / "xpfd"
        live_ran = self._install_abs(live)
        truncated = self.tmp / "opt" / "relocated"
        truncated_ran = self._install_abs(truncated)

        stale_ran = self._install(VERSIONED, 0)
        self._sbin_symlink_to_versioned()

        self.armed = str(live)
        self.stub_mainpid = "0"
        self.stub_execstart = f"{{ path={live} ; argv[]={live} ; ignore_errors=no }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(
            stale_ran.exists(),
            "the gate executed the STALE leftover left behind by relocating "
            "BOTH roots. Its sbin symlink still points at its versioned "
            "runtime, so the pair is a single inode and looks exactly like a "
            "healthy default layout -- no filesystem test can tell them apart, "
            f"which is why there must be no filesystem fallback at all: {res.stderr}",
        )
        self.assertFalse(
            truncated_ran.exists(),
            "the gate cut the ExecStart at the FIRST field delimiter and "
            f"executed {truncated} -- a shorter, different, and real binary "
            f"(#6601 r4 MAJOR-1): {res.stderr}",
        )
        self._assert_ran(res, live_ran, "both roots relocated, same-inode leftovers")
        self.assertIn(
            "resolved nothing to cross-check against",
            res.stderr,
            "an ExecStart carrying systemd's own field delimiter twice was "
            f"parsed anyway, so it could contradict the record: {res.stderr}",
        )

    def test_disagreeing_leftover_defaults_are_never_executed(self):
        # The `--sbin-dir`-only / `--versions-dir`-only shapes: two usable
        # defaults that are DIFFERENT files. One is stale and nothing on the
        # box says which, so no ranking is right for both. With the recorded
        # binary gone and systemd unable to answer, two perfectly usable
        # candidates are sitting right there — and the gate must still refuse.
        sbin_ran = self._install(SBIN, 0)
        versioned_ran = self._install(VERSIONED, 0)
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_show_fail = "1"  # systemd cannot answer

        res = self._run()
        self.assertFalse(sbin_ran.exists(), f"the gate executed {SBIN}: {res.stderr}")
        self.assertFalse(
            versioned_ran.exists(), f"the gate executed {VERSIONED}: {res.stderr}"
        )
        self._assert_refused(res, "two different usable defaults")

    def test_a_single_surviving_default_is_never_executed(self):
        # The remaining shape a defaults fallback would accept: exactly one
        # default is usable, so "the only usable default" looks decisive. It is
        # not — it is precisely the surviving half of a partial relocation, and
        # relocation leaves the STALE half behind just as readily as the live
        # one.
        versioned_ran = self._install(VERSIONED, 0)
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_show_fail = "1"

        res = self._run()
        self.assertFalse(
            versioned_ran.exists(),
            "the gate executed the ONLY usable compiled default. That is the "
            "surviving leftover of a `--versions-dir`-only relocation just as "
            f"often as it is a live install (#6601 r5): {res.stderr}",
        )
        self._assert_refused(res, "exactly one usable default")

    def test_recorded_binary_that_is_gone_refuses_rather_than_guessing(self):
        # The record is the authority, so an unusable record is a REFUSAL, never
        # a licence to look elsewhere. This is the r6 replacement for the old
        # "nothing resolved" refusal.
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "recorded binary no longer exists")
        self.assertIn(str(self.tmp / "gone" / "xpfd"), res.stderr)

    def test_recorded_relative_path_refuses(self):
        # A record that is present but not an absolute path cannot name an
        # executable unambiguously; "absent" is a definitive statement and must
        # not be reachable by mis-parsing a file that IS present.
        self._arm("not/absolute")
        self.arm_explicitly_absent = True  # do not overwrite the record above
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "record is not an absolute path")
        self.assertIn("not/absolute", res.stderr)

    def test_unit_disagreeing_with_the_record_refuses_rather_than_picking(self):
        # The r6 MAJOR sequence itself: a prior cut leaves a disabled-but-loaded
        # unit whose drop-in still names an OLD version, retention keeps that
        # version executable, and the unit therefore resolves a DIFFERENT binary
        # from the one that armed. Neither side is provably right here, so the
        # gate must refuse rather than pick.
        _live, live_ran = self._arm_a_live_binary()
        stale = self.tmp / "stale-version" / "xpfd"
        stale_ran = self._install_abs(stale)
        self.stub_execstart = f"{{ path={stale} ; argv[]={stale} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "unit contradicts the record")
        self.assertFalse(stale_ran.exists(), f"the gate ran the STALE unit's binary: {res.stderr}")
        self.assertFalse(live_ran.exists(), f"the gate ran a contradicted record: {res.stderr}")


class TestResolutionBehaviour(_GateBase):
    """Cross-check behaviour: it may confirm the record, never replace it."""

    # ---------------------------------------------- anti-over-reach: it works

    def test_never_cut_box_promotes_though_execstart_names_the_sbin_symlink(self):
        # #6601 r8 MAJOR-1, the state EVERY freshly installed or freshly baked
        # appliance is in. The record is the RESOLVED versioned path
        # (os.Executable -> /proc/self/exe) and ExecStart is the sbin SYMLINK
        # the shipped base unit carries until the first cut. One file, two
        # names — a string compare called that a "disagreement" and refused.
        #
        # MainPID=0 is the aggravator that makes it reachable rather than
        # theoretical: it is what the gate sees when xpfd.service is not
        # running, which is the expected outcome of a candidate kernel that
        # breaks the AF_XDP shim (the unit's ExecStartPre runs
        # verify-dataplane). So the refusal landed exactly where the revert
        # guard was supposed to fire, and the box was stranded on a kernel
        # whose dataplane never comes up.
        versioned, sbin, ran = self._seed_runtime_layout()
        self.assertNotEqual(
            str(versioned), str(sbin), "fixture does not model the symlink asymmetry"
        )
        self.assertTrue(sbin.is_symlink() and sbin.resolve() == versioned.resolve())
        self.armed = str(versioned)
        self.stub_execstart = f"{{ path={sbin} ; argv[]={sbin} ; ignore_errors=no }}"
        self.stub_mainpid = "0"  # xpfd.service is NOT running
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, ran, "never-cut box, ExecStart names the sbin symlink")
        self.assertIn(
            "confirmed by",
            res.stderr,
            "the symlink and the resolved path were not recognised as one file: "
            f"{res.stderr}",
        )

    def test_sbin_symlink_to_a_DIFFERENT_version_still_refuses(self):
        # The over-reach guard on the fix above. Comparing FILES must not
        # launder the r6 sequence: a stale drop-in (or a stale sbin symlink)
        # naming an OLDER version names a DIFFERENT file, and identity must
        # still say no.
        _versioned, sbin, ran = self._seed_runtime_layout(version="v1")
        other = Path(str(self.fake_root) + "/var/lib/xpf/versions/v2/xpfd")
        other_ran = self._install_abs(other)
        self.armed = str(other)  # armed by v2; the unit still points at v1
        self.stub_execstart = f"{{ path={sbin} ; argv[]={sbin} }}"
        self.stub_mainpid = "0"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "sbin symlink resolves to a DIFFERENT version")
        self.assertFalse(ran.exists(), f"ran the stale v1 binary: {res.stderr}")
        self.assertFalse(other_ran.exists(), f"ran a contradicted record: {res.stderr}")

    def test_healthy_default_rooted_box_promotes_confirmed_by_execstart(self):
        # ANTI-OVER-REACH. A default-rooted install has not relocated anything,
        # so systemd answers: the shipped base unit carries
        # ExecStart=/usr/local/sbin/xpfd before the first cut, and `flip` 6c
        # templates ExecStart=<VersionsDir>/<ver>/xpfd after every cut. The
        # record names the same binary, reached through the sbin->versioned
        # symlink `flip` 6b leaves, so the unit CONFIRMS the record.
        #
        # MainPID is 0 here, so "confirmed by" can only have come from the
        # ExecStart hop — which is what keeps that parse under test now that it
        # no longer selects the binary.
        versioned_ran = self._install(VERSIONED, 0)
        self._sbin_symlink_to_versioned()
        sbin = str(self.fake_root) + SBIN
        self.stub_execstart = f"{{ path={sbin} ; argv[]={sbin} ; ignore_errors=no }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, versioned_ran, "healthy default-rooted box")
        self.assertIn(
            f"using {sbin} (arm record, confirmed by xpfd.service)",
            res.stderr,
            "the unit did not CONFIRM the record on an ordinary healthy box, so "
            "the ExecStart cross-check is no longer exercised at all: "
            f"{res.stderr}",
        )

    def test_healthy_default_rooted_box_promotes_confirmed_by_main_pid(self):
        # The other half of anti-over-reach, and the ordinary case on a box
        # where the gate runs while xpfd is UP (the unit is After=xpfd.service).
        # Verified firsthand on a live systemd host as root: `systemctl show
        # -p MainPID --value` + `readlink /proc/<pid>/exe` yields the real
        # binary, and `-p ControlGroup --value` is exactly the path field of
        # that pid's /proc/<pid>/cgroup line.
        #
        # ExecStart is empty, so "confirmed by" can only have come from the
        # MainPID -> /proc/<pid>/exe -> cgroup hop.
        proc, target, cgroup = self._spawn_fake_daemon("opt-live")
        self.armed = str(target)
        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = cgroup
        self.stub_loadstate = "loaded"
        stale_sbin = self._install(SBIN, 0)
        stale_versioned = self._install(VERSIONED, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(
            f"using {target} (arm record, confirmed by xpfd.service)",
            res.stderr,
            "the gate did not confirm the record through xpfd.service's MainPID "
            f"and /proc/<pid>/exe: {res.stderr}",
        )
        self.assertFalse(stale_sbin.exists(), f"ran a leftover: {res.stderr}")
        self.assertFalse(stale_versioned.exists(), f"ran a leftover: {res.stderr}")
        self._assert_no_path_fallback(res, "healthy box, daemon up")

    def test_discovers_relocated_roots_via_systemd_execstart(self):
        # MAJOR (fold r3). With `--versions-dir=/opt/xpf/versions
        # --sbin-dir=/usr/sbin`, NEITHER compiled default exists yet the live
        # binary is perfectly intact. Systemd knows where it is, because that
        # is the ExecStart the cut templated (flip step 6c), and it agrees with
        # what the arming recorded.
        relocated = self.tmp / "opt-xpf" / "versions" / "v7" / "xpfd"
        relocated_ran = self.tmp / "relocated.ran"
        self._write_stub(relocated, 0, relocated_ran)

        self.stub_execstart = f"{{ path={relocated} ; argv[]={relocated} ; ignore_errors=no }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, relocated_ran, "both roots relocated, unit agrees")
        self.assertIn("confirmed by", res.stderr)

    def test_leftover_defaults_never_outrank_the_record(self):
        # Leftovers exist and are perfectly usable; the record still decides.
        relocated = self.tmp / "opt-xpf" / "versions" / "v7" / "xpfd"
        relocated_ran = self.tmp / "relocated.ran"
        self._write_stub(relocated, 0, relocated_ran)

        stale_sbin = self._install(SBIN, 0)
        stale_versioned = self._install(VERSIONED, 0)

        self.stub_execstart = f"{{ path={relocated} ; argv[]={relocated} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, relocated_ran, "leftovers present")
        self.assertFalse(stale_sbin.exists(), f"ran the STALE leftover at {SBIN}")
        self.assertFalse(stale_versioned.exists(), f"ran the STALE leftover at {VERSIONED}")

    def test_broken_unit_does_not_veto_a_recorded_promotion(self):
        # A unit whose ExecStart names a path that no longer exists (mid-cut, a
        # GC'd version dir). Earlier revisions fell through to the compiled
        # defaults here. Under the record design there is nothing to fall
        # through TO — and, just as importantly, a unit that resolves NOTHING
        # must not be read as contradicting the record: absence of a
        # cross-check is not evidence against the authority.
        stale_sbin = self._install(SBIN, 0)
        stale_versioned = self._install(VERSIONED, 0)
        _live, live_ran = self._arm_a_live_binary()
        self.stub_execstart = f"{{ path={self.tmp}/gone/xpfd ; argv[]={self.tmp}/gone/xpfd }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(stale_sbin.exists(), f"ran a leftover: {res.stderr}")
        self.assertFalse(stale_versioned.exists(), f"ran a leftover: {res.stderr}")
        self._assert_ran(res, live_ran, "unit ExecStart points at a GC'd path")
        self.assertIn("resolved nothing to cross-check against", res.stderr)

    # ------------------------------------------------- MainPID -> unit binding
    #
    # These four all have the same shape now, and it is worth stating why. The
    # MainPID hop no longer SELECTS the binary, so believing a pid that is not
    # the unit's does not hand an impostor the promote decision — it produces a
    # CROSS that contradicts the record and REFUSES a healthy promotion. Each
    # test therefore arms a good record, feeds the hop something it must not
    # believe, and asserts the gate still promotes. Delete the binding and the
    # gate refuses instead; the test reds.

    def test_main_pid_outside_the_unit_cgroup_is_rejected(self):
        # #6601 r4 MAJOR-2. The recycle race, made concrete: MainPID names a
        # live process running a binary CALLED `xpfd`, but that process is not
        # in xpfd.service's control group — it is an unrelated program that
        # inherited the pid after the daemon exited. The basename guard alone
        # accepts it.
        proc, target, real_cgroup = self._spawn_fake_daemon("impostor")
        unit_cgroup = "/system.slice/xpfd.service"
        if real_cgroup == unit_cgroup or real_cgroup.startswith(unit_cgroup + "/"):
            self.skipTest("test process really is inside /system.slice/xpfd.service")
        _live, live_ran = self._arm_a_live_binary()

        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = unit_cgroup
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            f"using {target} (",
            res.stderr,
            "the gate accepted a process that is NOT a member of "
            "xpfd.service's control group as an answer about the live xpfd "
            f"(#6601 r4 MAJOR-2): {res.stderr}",
        )
        self._assert_ran(res, live_ran, "MainPID outside the unit cgroup")
        self.assertIn("resolved nothing to cross-check against", res.stderr)

    def test_main_pid_that_changes_mid_sequence_is_rejected(self):
        # The narrower half of the same race: the association held when it was
        # first read, but systemd's MainPID moved on while the gate was
        # resolving. Re-read and require the SAME pid.
        proc, target, cgroup = self._spawn_fake_daemon("racing")
        _live, live_ran = self._arm_a_live_binary()
        self.stub_mainpid = str(proc.pid)
        self.stub_mainpid2 = str(proc.pid + 1)
        self.stub_controlgroup = cgroup
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            f"using {target} (",
            res.stderr,
            "the gate believed a MainPID that had already changed by the time "
            "it finished resolving, so /proc/<pid>/exe may name a recycled "
            f"process's binary (#6601 r4 MAJOR-2): {res.stderr}",
        )
        self._assert_ran(res, live_ran, "MainPID changed mid-sequence")

    def test_main_pid_naming_a_non_xpfd_binary_is_rejected(self):
        # The basename guard. Every layout this gate supports names the
        # artifact `xpfd` (the manifest basename), so a MainPID whose
        # /proc/<pid>/exe names something else is not a layout the gate
        # understands — it is an override, a wrapper, or a mis-association.
        proc, target, cgroup = self._spawn_fake_daemon("wrapper", basename="xpfd-wrapper")
        _live, live_ran = self._arm_a_live_binary()
        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = cgroup
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            f"using {target} (",
            res.stderr,
            "the gate accepted a MainPID whose executable is not named `xpfd` "
            f"as an answer about the live xpfd: {res.stderr}",
        )
        self._assert_ran(res, live_ran, "MainPID names a non-xpfd binary")

    def test_main_pid_whose_binary_was_replaced_on_disk_is_rejected(self):
        # A binary replaced (or removed) under a running daemon reads back as
        # "<path> (deleted)". That string is not a path — it cannot be
        # re-executed, and the file it once named is gone — so the MainPID hop
        # must yield nothing. Asserted as an OUTCOME: three independent things
        # reject it (the "(deleted)" case, the basename guard, and the
        # regular-file admission test), so no single one of them is claimed to
        # be the sole rejector (#6601 r4 MINOR).
        proc, target, cgroup = self._spawn_fake_daemon("replaced", unlink=True)
        _live, live_ran = self._arm_a_live_binary()
        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = cgroup
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            str(target),
            res.stderr,
            "the gate adopted a MainPID whose executable was replaced on disk; "
            f'its /proc/<pid>/exe reads "<path> (deleted)": {res.stderr}',
        )
        self._assert_ran(res, live_ran, "MainPID binary deleted on disk")

    def test_prefix_sibling_cgroup_does_not_satisfy_membership(self):
        # The membership test matches the PATH FIELD of a /proc/<pid>/cgroup
        # line, not a substring of the line. A substring test would let a
        # same-prefix sibling stand in for the unit — `/system.slice/xpfd.serv`
        # for `/system.slice/xpfd.service`, or the unit's cgroup for a
        # DIFFERENT unit whose name merely extends it — which is the whole
        # association silently going away again.
        proc, target, real_cgroup = self._spawn_fake_daemon("prefixy")
        if len(real_cgroup) < 2:
            self.skipTest(f"cgroup path too short to truncate: {real_cgroup!r}")
        _live, live_ran = self._arm_a_live_binary()
        # A strict prefix of the real path: contained in the line, but not the
        # path field and not a parent directory of it.
        self.stub_controlgroup = real_cgroup[:-1]
        self.stub_mainpid = str(proc.pid)
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            f"using {target} (",
            res.stderr,
            "a cgroup path that merely OCCURS in the process's "
            "/proc/<pid>/cgroup line was accepted as unit membership "
            f"(#6601 r4 MAJOR-2): {res.stderr}",
        )
        self._assert_ran(res, live_ran, "prefix-sibling cgroup")

    def test_delegated_subgroup_still_satisfies_membership(self):
        # OVER-REACH GUARD on the same matcher, and the one test that requires
        # it to say YES. systemd may place a unit's processes in a subgroup of
        # the unit's own cgroup (delegation), so a process UNDER the reported
        # ControlGroup is still a member. Requiring exact equality would make a
        # legitimately delegated unit resolve NOTHING — which no longer strands
        # the gate, but does silently retire the cross-check on every such box.
        proc, target, real_cgroup = self._spawn_fake_daemon("delegated")
        parent = real_cgroup.rsplit("/", 1)[0]
        if not parent.startswith("/") or parent == real_cgroup:
            self.skipTest(f"cgroup path has no parent to delegate from: {real_cgroup!r}")
        self.armed = str(target)
        self.stub_controlgroup = parent
        self.stub_mainpid = str(proc.pid)
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(
            f"using {target} (arm record, confirmed by xpfd.service)",
            res.stderr,
            "a process in a DELEGATED SUBGROUP of the unit's control group was "
            f"not recognised as a member: {res.stderr}",
        )

    def test_unreported_control_group_yields_nothing_rather_than_a_bad_cross_check(self):
        # OVER-REACH GUARD on the binding: a systemd that cannot report
        # ControlGroup (or a /proc the gate cannot correlate) must not make the
        # MainPID hop guess. It yields nothing and ExecStart gets its turn.
        proc, _target, _cgroup = self._spawn_fake_daemon("live-unbindable")
        declared = self.tmp / "declared" / "xpfd"
        declared_ran = self._install_abs(declared)

        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = ""  # systemd did not answer
        self.stub_execstart = f"{{ path={declared} ; argv[]={declared} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, declared_ran, "unbindable MainPID, ExecStart agrees")
        self.assertIn("confirmed by", res.stderr)

    # ---------------------------------------------------- ExecStart strictness
    #
    # Same inversion as the MainPID block: a mis-parse no longer executes the
    # wrong binary, it fabricates a disagreement. Each test arms a good record
    # and asserts the gate still promotes.

    def test_execstart_path_containing_a_space_is_not_truncated(self):
        # MAJOR (#6601 r4). systemd PERMITS an executable path containing a
        # space, and `systemctl show -p ExecStart` substitutes the stored path
        # RAW into `path=%s` -- there is no escaping. A parse that stops at the
        # first space therefore does not merely fail to resolve: it resolves to
        # a SHORTER, DIFFERENT path. Here `<tmp>/relocated` is itself a valid
        # executable, so the truncated read is ACCEPTED and contradicts the
        # record -- a healthy candidate is then never promoted.
        live = self.tmp / "relocated live" / "xpfd"
        live_ran = self._install_abs(live)
        truncated = self.tmp / "relocated"
        truncated_ran = self._install_abs(truncated)

        self.stub_execstart = (
            f"{{ path={live} ; argv[]={live} ; ignore_errors=no ; "
            "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; "
            "status=0/0 }"
        )
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(
            truncated_ran.exists(),
            f"the gate TRUNCATED systemd's ExecStart at the first space and "
            f"executed {truncated} -- a DIFFERENT binary from the "
            f"{live} systemd actually launches (#6601 r4 MAJOR-1): {res.stderr}",
        )
        self._assert_ran(res, live_ran, "ExecStart path contains a space")
        self.assertIn("confirmed by", res.stderr)

    def test_execstart_path_containing_a_semicolon_is_not_truncated(self):
        # The other half of MAJOR-1: `;` is legal in a path too, and the
        # property printer does not escape it either.
        live = self.tmp / "reloc;ated" / "xpfd"
        live_ran = self._install_abs(live)
        truncated = self.tmp / "reloc"
        truncated_ran = self._install_abs(truncated)

        self.stub_execstart = f"{{ path={live} ; argv[]={live} ; ignore_errors=no }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(
            truncated_ran.exists(),
            f"the gate TRUNCATED systemd's ExecStart at the first ';' and "
            f"executed {truncated} instead of {live} (#6601 r4 MAJOR-1): "
            f"{res.stderr}",
        )
        self._assert_ran(res, live_ran, "ExecStart path contains a semicolon")

    def test_multiple_execstart_entries_are_not_reduced_to_the_first(self):
        # MAJOR-1, second shape. systemd renders one ExecStart entry per LINE
        # (verified against man-db.service). The shipped Type=simple unit cannot
        # validly carry more than one, but an operator-overridden Type=oneshot
        # can -- and its FIRST entry need not be xpfd at all. Taking it
        # unconditionally lets an arbitrary command veto the promotion.
        #
        # NOTE (#6601 r4 MINOR): on a REAL multi-entry render each entry brings
        # its own " ; argv[]=", so the delimiter-COUNT rule already rejects this
        # value; the newline guard is defence in depth here, not the sole
        # rejector. The test below covers what only the newline guard rejects.
        foreign = self.tmp / "prep" / "install"
        self._install_abs(foreign)
        entry = self.tmp / "opt" / "xpfd"
        self._install_abs(entry)
        _live, live_ran = self._arm_a_live_binary()

        self.stub_execstart = (
            f"{{ path={foreign} ; argv[]={foreign} -d ; ignore_errors=no }}\n"
            f"{{ path={entry} ; argv[]={entry} ; ignore_errors=no }}"
        )
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            str(foreign),
            res.stderr,
            f"the gate adopted {foreign}, the FIRST of several ExecStart "
            f"entries, which need not be xpfd (#6601 r4 MAJOR-1): {res.stderr}",
        )
        self._assert_ran(res, live_ran, "multi-entry ExecStart")
        self.assertIn("resolved nothing to cross-check against", res.stderr)

    def test_multiline_execstart_with_one_delimiter_is_rejected(self):
        # The case the newline guard alone rejects, so that guard carries its
        # own weight (#6601 r4 MINOR: the delimiter-count rule subsumes it for
        # ordinary multi-entry renders). One delimiter, several lines: the
        # count rule passes and, without the newline guard, the parse silently
        # adopts the first entry -- a REAL, usable binary here, so the mutation
        # is not merely a failed resolve but a fabricated disagreement.
        first = self.tmp / "first" / "xpfd"
        self._install_abs(first)
        second = self.tmp / "second" / "xpfd"
        self._install_abs(second)
        _live, live_ran = self._arm_a_live_binary()

        self.stub_execstart = f"{{ path={first} ; argv[]={first} }}\n{{ path={second} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            str(first),
            res.stderr,
            "the gate adopted the first of a MULTI-LINE ExecStart render that "
            f"carries only one field delimiter: {res.stderr}",
        )
        self._assert_ran(res, live_ran, "multi-line ExecStart with one delimiter")

    def test_bare_execstart_with_a_tab_is_rejected(self):
        # #6601 r4 audit note. The bare (unstructured) rendering is accepted
        # only when the WHOLE value is one absolute path. Rejecting just spaces
        # and semicolons does not make that true: a tab separates a path from
        # its arguments equally well, and the value here names a real,
        # executable file, so tolerating it fabricates a disagreement rather
        # than merely failing to resolve.
        tabbed = self.tmp / "tabbed" / "xpfd\t--flag"
        self._install_abs(tabbed)
        _live, live_ran = self._arm_a_live_binary()

        self.stub_execstart = str(tabbed)
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            str(tabbed),
            res.stderr,
            "the gate accepted a bare ExecStart rendering containing a TAB. "
            "`path<TAB>--flag` is indistinguishable from a path plus an "
            f"argument, so it is not a whole path (#6601 r4): {res.stderr}",
        )
        self._assert_ran(res, live_ran, "bare ExecStart containing a tab")

    def test_bare_absolute_execstart_is_accepted(self):
        # OVER-REACH GUARD on the whitespace tightening: an ordinary bare
        # rendering (a single absolute path, no arguments) must still resolve,
        # or the cross-check quietly stops cross-checking on such a box.
        plain = self.tmp / "plain" / "xpfd"
        plain_ran = self._install_abs(plain)

        self.stub_execstart = str(plain)
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, plain_ran, "plain absolute bare ExecStart")
        self.assertIn("confirmed by", res.stderr)

    # --------------------------------------------------- admission + refusals

    def test_directory_record_is_not_treated_as_the_binary(self):
        # `test -x` alone is TRUE for a searchable DIRECTORY. The inner hop's
        # validateGateBin rejects a non-regular target, so the outer hop must
        # too — otherwise the two hops' admission tests are not actually
        # symmetric, and the gate execs a directory (rc=126) which then reads
        # as an infra error rather than the refusal it is.
        candidate = self.tmp / "isadir" / "xpfd"
        candidate.mkdir(parents=True)
        self.armed = str(candidate)
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            "infra error",
            res.stderr,
            f"a DIRECTORY named by the arm record was exec'd as the gate binary "
            f"instead of being rejected by the `-f` regular-file test: {res.stderr}",
        )
        self._assert_refused(res, "the record names a directory")

    def test_dangling_symlink_record_is_rejected(self):
        # #2176 leaves a symlink pointing into a removed versions dir.
        dangling = self.tmp / "dangle" / "xpfd"
        dangling.parent.mkdir(parents=True, exist_ok=True)
        dangling.symlink_to(self.tmp / "removed" / "versions" / "v1" / "xpfd")
        self.armed = str(dangling)
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "the record names a dangling symlink")

    def test_unqueryable_systemd_refuses_loudly_rather_than_skipping(self):
        # #6601 r4 audit note. A systemctl that is missing or erroring proves
        # NOTHING about this box -- laundering that into a benign skip lets an
        # ARMED candidate sail past the gate behind a reassuring log line. Here
        # the record is unusable AND systemd cannot be consulted, which is the
        # least-information state the gate can be in, and it must still be loud.
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_show_fail = "1"

        res = self._run()
        self.assertNotIn(
            "skipping promotion gate",
            res.stderr,
            "an unqueryable systemd was treated as proof that xpf is absent "
            f"(#6601 r4): {res.stderr}",
        )
        self._assert_refused(res, "systemctl cannot be consulted")

    def test_unqueryable_systemd_does_not_block_a_recorded_promotion(self):
        # OVER-REACH GUARD on the above. systemd being unqueryable removes the
        # cross-check, not the authority: with a usable record the gate must
        # still promote, or an unrelated systemd hiccup silently costs every
        # armed candidate its promotion.
        _live, live_ran = self._arm_a_live_binary()
        self.stub_show_fail = "1"

        res = self._run()
        self._assert_ran(res, live_ran, "systemctl unqueryable, record usable")
        self.assertIn("resolved nothing to cross-check against", res.stderr)

    def test_refuses_loudly_when_installed_but_the_record_is_unusable(self):
        # FAIL LOUD, not quiet. xpfd.service is installed and a candidate was
        # armed, but the recorded binary is gone: an armed candidate would
        # otherwise sail past unverified with nothing in the journal to say so.
        # The refusal must be explicit AND must stay exit 0 — a non-zero exit
        # trips OnFailure= and reboots the box.
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "installed but the record is unusable")

    def test_skips_rather_than_falling_back_to_path(self):
        # Nothing armed and no journal: the one honest "there is nothing to
        # promote" case. Skip quietly — and never reach for the perfectly good
        # xpfd sitting on $PATH. That last clause is unconditional and survives
        # every redesign: NO state of this gate may resolve xpfd through $PATH.
        res = self._run()
        self._assert_nothing_armed(res, "no record, no journal")
        # The quiet line still has to name what was looked for, so an operator
        # who DID arm something can see which file the gate expected.
        self.assertIn(str(self.fake_root) + ARM_RECORD, res.stderr)

    def test_never_falls_back_to_path_on_a_refusal_either(self):
        # The $PATH invariant is asserted on the REFUSAL path too, not only the
        # quiet one: a refusal is precisely the moment a gate would be tempted
        # to reach for "some xpfd, any xpfd".
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_loadstate = "loaded"
        res = self._run()
        self._assert_refused(res, "unusable record with a good xpfd on $PATH")

    # ------------------------------------------------------ contract preserved

    def test_revert_exit_3_still_reboots(self):
        # OVER-REACH GUARD: the explicit-path change must not disturb the
        # revert contract. An xpfd exiting 3 (REVERT) must still drive the
        # reboot branch. `systemctl` is stubbed on PATH — it is a system
        # binary and is legitimately PATH-resolved.
        live = self.tmp / "live" / "xpfd"
        self._install_abs(live, exit_code=3)
        self.stub_execstart = f"{{ path={live} ; argv[]={live} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("REVERT", res.stderr)
        self.assertTrue(
            self.systemctl_ran.exists(),
            f"exit 3 did not trigger the recovery reboot: {res.stderr}",
        )
        self.assertIn("reboot", self.systemctl_ran.read_text())

    def test_infra_error_does_not_reboot(self):
        # OVER-REACH GUARD: a non-0/non-3 rc stays a non-rebooting infra error.
        live = self.tmp / "live" / "xpfd"
        self._install_abs(live, exit_code=1)
        self.stub_execstart = f"{{ path={live} ; argv[]={live} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("infra error", res.stderr)
        self.assertFalse(self.systemctl_ran.exists(), "an infra error triggered a reboot")


class TestArmedWithoutARecordIsNotLaundered(_GateBase):
    """#6601 r7 — "record absent" is an INFERENCE, and it must be checked.

    The r5 work removed a benign-looking skip from the not-found-unit branch
    because an ARMED candidate could go unverified behind it. The r6 redesign
    then introduced a new branch with exactly that shape: the record is absent,
    so the gate declares "nothing to promote" and exits — a positive claim made
    from the ABSENCE of a file.

    That claim holds only because arming writes the record (before the ARMED
    transition) and clears it with the journal, so no crash ordering can produce
    the divergence. Losing ONE of the two files out of band can:

      * a /var/lib/xpf restored from a backup taken before the arm, or restored
        only partially;
      * a stray cleanup (tmpfiles rule, an operator `rm`, a housekeeping sweep)
        that removes the sidecar and leaves the journal;
      * a candidate armed by a build PREDATING the sidecar and upgraded through
        the #1917 binary channel before the candidate boot — journal ARMED, no
        record ever written.

    A candidate is then armed, the gate silently does not run, and the next
    reboot reverts it.

    Explicitly NOT one of those: `arm --journal <elsewhere>`. Go derives the
    sidecar from the journal's directory, so that flag moves both files together
    and the gate finds neither, taking the quiet branch. It is a separate trap
    (the boot unit hardcodes the script with no journal argument, so such a
    candidate can never be promoted at all), closed at the ARM end by #6631 —
    `KernelRunner.Arm` refuses a non-default journal path — and it must not be
    cited as this check's motivation.

    Not promoting is the SAFE direction, so this is availability and honesty
    rather than security — but a candidate kernel that silently never promotes
    is exactly the laundering the tests above exist to prevent. So the quiet
    exit is conditional on the journal agreeing, and the divergent state is loud.
    """

    def test_armed_journal_without_a_record_refuses_loudly(self):
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "journal says ARMED, record absent")
        for want in ("did NOT run", "UNVERIFIED", "ARMED"):
            self.assertIn(
                want,
                res.stderr,
                f"the divergent-state line does not say {want!r}; an operator "
                f"cannot tell an armed candidate went unverified: {res.stderr}",
            )
        # It must name BOTH files, so the desync is diagnosable without guessing
        # which one the operator should look at.
        self.assertIn(str(self.fake_root) + ARM_RECORD, res.stderr)
        self.assertIn(str(self.fake_root) + KERNEL_JOURNAL, res.stderr)

    def test_armed_journal_without_a_record_never_reaches_for_path(self):
        # The refusal must not become a reason to go looking for an xpfd. This
        # is the state with the strongest pull towards a fallback: something IS
        # armed and there is a perfectly good xpfd on $PATH.
        #
        # The $PATH assertion alone holds on BOTH branches, so it does not bind
        # the refusal — it would stay green under a make-this-silent mutation.
        # Assert the refusal too, so five tests reach this branch and five bind
        # it (#6601 r8 NIT).
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        res = self._run()
        self._assert_no_path_fallback(res, "armed journal, absent record")
        self._assert_refused(res, "armed journal, absent record")

    def test_record_without_a_trailing_newline_is_still_a_path(self):
        # #6601 r8 MINOR-2. `read` returns non-zero at EOF-without-newline
        # AFTER setting the variable, so `|| RECORDED=""` discarded a perfectly
        # good absolute path and then refused with "does not contain an
        # absolute path" — fail-safe, but it misdiagnoses, and it sends the
        # operator after the wrong fault.
        live, ran = self._arm_a_live_binary()
        self.arm_explicitly_absent = True  # write the record by hand, unterminated
        rec = Path(str(self.fake_root) + ARM_RECORD)
        rec.parent.mkdir(parents=True, exist_ok=True)
        rec.write_text(str(live))  # NO trailing newline
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, ran, "arm record with no trailing newline")
        self.assertNotIn("does not contain an absolute path", res.stderr)

    def test_compact_armed_journal_is_still_recognised(self):
        # The gate reads the journal line by line and json.MarshalIndent output
        # has no trailing newline. A compact single-line rendering is therefore
        # the shape most likely to be missed entirely — and missing it puts the
        # silent skip straight back.
        self.arm_explicitly_absent = True
        self.journal = (
            '{"candidate_version":"6.18.5-12-generic","state":"ARMED",'
            '"boot_id":"Boot0002"}'
        )
        res = self._run()
        self._assert_refused(res, "compact single-line ARMED journal")

    def test_arming_state_without_a_record_is_loud_and_durable_17862(self):
        # #17862 CONTRACT CHANGE (this was #16809's over-reach guard: the
        # quiet ordinary boot). Arming now writes the record BEFORE the
        # BootNext mutation, so an ARMING journal with no record from a
        # current-build arm proves the arm died before any NVRAM write. But
        # two shapes still reach this boot with a one-shot possibly QUEUED:
        # a journal written by a pre-#17862 build (record after the
        # readback), and an out-of-band loss of the sidecar. There is no
        # designated binary to gate with either way — the authority design
        # forbids inferring one — so the honest maximum is a durable WARNING
        # naming both files, never the old fold to "not-armed / nothing to
        # promote", which read like an ordinary boot while a candidate may
        # have been running UNVERIFIED with no gate at all.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMING")
        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn(
            "nothing to promote",
            res.stderr,
            "a recordless ARMING journal was folded to not-armed and "
            "reported as a benign nothing-to-promote (#17862): "
            f"{res.stderr}",
        )
        for want in ("WARNING", "did NOT run", "UNVERIFIED", "#17862"):
            self.assertIn(
                want,
                res.stderr,
                f"the unrecorded-arming line does not say {want!r}; an "
                f"operator cannot tell an interrupted arm from a queued "
                f"one-shot they must investigate: {res.stderr}",
            )
        # It must name BOTH files, so the desync is diagnosable without
        # guessing which one the operator should look at.
        self.assertIn(str(self.fake_root) + ARM_RECORD, res.stderr)
        self.assertIn(str(self.fake_root) + KERNEL_JOURNAL, res.stderr)
        rec = self._assert_recorded(
            "unrecorded-arming", "ARMING journal without a record"
        )
        self.assertEqual(
            rec.get("journal_state"),
            "arming-unrecorded",
            "the durable record must distinguish unrecorded-ARMING from the "
            "states folded into not-armed; an operator triaging a "
            "disposition needs the real journal state (#17862)",
        )
        self._assert_no_path_fallback(res, "ARMING journal, absent record")
        # No reboot: exit 0 on the non-rebooting path only.
        self.assertFalse(
            self.systemctl_ran.exists(),
            f"the WARNING rebooted the box ({res.stderr})",
        )

    def test_arming_state_WITH_a_record_runs_the_recorded_gate(self):
        # #16809 DEFECT ROW. The record is written (recordPromoteBinary)
        # BEFORE the verified ARMED transition, so ARMING + record present is
        # the process-death / landed-but-errored-SetBootNext shape: BootNext
        # may have been queued and THIS boot may be the candidate. The gate
        # must RUN the recorded binary — the Go half convicts on BootCurrent +
        # uname -r and gates or no-ops — never refuse it as "not a trial"
        # (the pre-#16809 reading, which left the unverified candidate
        # running with no gate at all) and never take the quiet exit.
        _live, live_ran = self._arm_a_live_binary()
        self.journal = self.journal_body("ARMING")
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, live_ran, "ARMING journal with an arm record")
        self.assertIn("may have been", res.stderr)
        self.assertIn("queued without a verified", res.stderr)
        self.assertIn("#16809", res.stderr)
        self.assertNotIn(
            "nothing to promote",
            res.stderr,
            "an ARMING+record boot was reported as a benign nothing-to-promote "
            f"(#16809): {res.stderr}",
        )

    def test_terminal_journal_states_are_not_a_trial_in_flight(self):
        # Same guard for the other side: a PROMOTED/REVERTED journal that has
        # not been cleared yet (a read-only root, say) is done, not armed.
        for state in ("PROMOTED", "REVERTED", "PREFLIGHT", "INSTALLED"):
            with self.subTest(state):
                self.setUp()
                self.arm_explicitly_absent = True
                self.journal = self.journal_body(state)
                res = self._run()
                self._assert_nothing_armed(res, f"journal at {state}")

    def test_unreadable_journal_warns_rather_than_claiming_nothing_is_armed(self):
        # Absence of evidence is not evidence of absence. A journal that exists
        # but cannot be read as one leaves the gate unable to establish whether
        # a candidate is armed, and the honest report of that is a warning, not
        # the confident "nothing to promote".
        self.arm_explicitly_absent = True
        j = self._journal_path()
        j.parent.mkdir(parents=True, exist_ok=True)
        j.mkdir()  # present, but not a readable regular file

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("WARNING", res.stderr)
        self.assertIn("did NOT run", res.stderr)
        self.assertIn("UNVERIFIED", res.stderr)
        self.assertNotIn(
            "nothing to promote",
            res.stderr,
            "an unreadable journal was reported as proof that nothing is armed "
            f"(#6601 r7): {res.stderr}",
        )
        self._assert_no_path_fallback(res, "unreadable journal")

    def test_armed_journal_WITH_a_usable_record_promotes(self):
        # NEGATIVE CONTROL for the whole branch. The ordinary armed boot — a
        # journal at ARMED and a record naming a live binary — must still
        # promote. A gate that refuses everything is not a fix.
        _live, live_ran = self._arm_a_live_binary()
        self.journal = self.journal_body("ARMED")
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, live_ran, "ordinary armed boot")
        self.assertIn("promotion gate: clean", res.stderr)


class TestRenamedUnitIsSupportedNotLaundered(_GateBase):
    """#6601 r5 MINOR-1, re-expressed for the record design.

    `xpfd upgrade cut --unit myxpf` is a SUPPORTED standalone selector
    (cmd/xpfd/upgrade.go). On such a host flip maintains myxpf.service and the
    deb-installed xpfd.service may have been removed, so the pinned unit reports
    not-found and cannot resolve a binary.

    Under the r5 design that state could not be verified at all: the unit WAS
    the authority, so arming refused the layout up front and the boot gate had
    to say loudly that it did not run. The record removes the dependency — the
    arming knows which xpfd it is regardless of what the unit is called — so a
    renamed-unit box now PROMOTES, and the laundering risk moved to the
    armed-without-record state covered in the class above.

    Both halves are asserted here: the renamed unit must not block a promotion,
    and it must not manufacture a silent one either.
    """

    def test_renamed_unit_does_not_block_a_recorded_promotion(self):
        _live, live_ran = self._arm_a_live_binary()
        self.stub_loadstate = "not-found"
        self.stub_mainpid = "0"
        self.stub_execstart = ""

        res = self._run()
        self._assert_ran(res, live_ran, "unit renamed away, record present")
        self.assertIn(
            "resolved nothing to cross-check against",
            res.stderr,
            "a not-found unit was reported as CONFIRMING the record; absence of "
            f"a cross-check is not a cross-check: {res.stderr}",
        )

    def test_renamed_unit_does_not_read_as_a_benign_skip(self):
        # The whole scenario, with the state that actually launders: the default
        # unit is GONE (renamed to myxpf), a candidate IS armed, the record has
        # desynced, and a perfectly good xpfd is on $PATH for a PATH-resolving
        # gate to find.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        self.stub_loadstate = "not-found"
        self.stub_mainpid = "0"
        self.stub_execstart = ""

        res = self._run()
        self._assert_refused(res, "renamed unit, armed candidate, no record")
        for want in ("did NOT run", "UNVERIFIED"):
            self.assertIn(
                want,
                res.stderr,
                f"the line does not say {want!r}; an operator cannot tell the "
                f"gate silently did not run: {res.stderr}",
            )
        # It must name what it looked for, so the operator can act.
        self.assertIn("LoadState=[not-found]", res.stderr)
        self.assertIn("--unit", res.stderr)


class TestRefusalCarriesFacts(_GateBase):
    """#6601 r5 MINOR-2 / r7 MINOR-3 — the refusal is the only signal.

    exit 0 keeps the unit `active`, so `systemctl status xpf-kernel-promote`
    reads SUCCESS. The journal line is all an operator gets, and policy prose
    without the facts systemd returned is not actionable. Its advice must also
    branch on which cause fired: telling someone to fix ExecStart when systemctl
    could not be consulted points at the wrong system.

    r7 MINOR-3 adds that the facts must be the ones the DECISION was made on.
    The previous revision suppressed query failures during discovery and then
    RE-QUERIED to build this message, so a transient failure that had recovered
    was reported as a unit configuration problem and the operator was told to fix
    a perfectly valid ExecStart.
    """

    def test_refusal_echoes_what_systemd_returned(self):
        self.armed = "/nonexistent/xpfd"
        self.stub_loadstate = "loaded"
        self.stub_mainpid = "0"
        self.stub_execstart = "{ path=/some/other/xpfd ; argv[]=/some/other/xpfd ; ignore_errors=no }"

        res = self._run()
        self._assert_refused(res, "recorded binary is gone")

        for want in (
            "LoadState=[loaded]",
            "MainPID=[0]",
            "ExecStart=[{ path=/some/other/xpfd",
            "/nonexistent/xpfd",
        ):
            self.assertIn(
                want,
                res.stderr,
                f"the refusal omits {want!r}. With exit 0 keeping the unit "
                "active, this line is the ONLY operator signal and it must "
                "carry what systemd actually returned (#6601 r5 MINOR-2)",
            )

    def test_advice_branches_on_the_cause_installed(self):
        # xpf IS installed; the actionable advice names the unit AND the re-arm.
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_loadstate = "loaded"
        self.stub_mainpid = "0"
        self.stub_execstart = "garbage-not-a-path"

        res = self._run()
        self._assert_refused(res, "installed, record unusable")
        self.assertIn("IS known to systemd", res.stderr)
        self.assertIn("Fix xpfd.service", res.stderr)
        self.assertNotIn("systemd-availability problem", res.stderr)

    def test_advice_branches_on_the_cause_systemctl_unreachable(self):
        # systemctl could not be consulted. Telling the operator to fix
        # ExecStart here is actively WRONG -- there is no evidence about the
        # unit at all.
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_show_fail = "1"

        res = self._run()
        self._assert_refused(res, "systemctl unreachable, record unusable")
        self.assertIn("could not be consulted", res.stderr)
        self.assertIn("systemd-availability problem", res.stderr)
        self.assertIn("<systemctl failed>", res.stderr)
        self.assertNotIn(
            "Fix xpfd.service so its ExecStart",
            res.stderr,
            "the refusal tells the operator to fix ExecStart even though "
            "systemctl could not be consulted at all -- that points at the "
            "wrong system (#6601 r5 MINOR-2)",
        )

    def test_advice_branches_on_the_cause_unit_not_found(self):
        # The third cause, new with the record design: the unit is genuinely
        # not-found because this host runs xpfd under another name. Telling the
        # operator to fix an xpfd.service they deliberately do not use is the
        # same wrong-system mistake as the branch above, so the advice is the
        # re-arm that actually rewrites the record.
        self.armed = str(self.tmp / "gone" / "xpfd")
        self.stub_loadstate = "not-found"

        res = self._run()
        self._assert_refused(res, "unit not-found, record unusable")
        self.assertIn("is not-found", res.stderr)
        self.assertIn("xpfd upgrade kernel arm", res.stderr)
        self.assertNotIn("systemd-availability problem", res.stderr)
        self.assertNotIn("Fix xpfd.service so its ExecStart", res.stderr)


class TestRefusalLeavesADurableRecord(_GateBase):
    """#6622 — a did-not-run outcome must survive the boot and journal rotation.

    The gate exits 0 on EVERY path, deliberately: a non-zero exit trips the
    unit's OnFailure= and reboots the box over what may be a transient
    packaging window, and the firmware already cleared BootNext so the next
    plain reboot falls back to known-good on its own. The unit is Type=oneshot
    with RemainAfterExit=yes, so the cost of that correct decision is that
    `systemctl status xpf-kernel-promote` reads SUCCESS and stays active even
    when the gate REFUSED and the armed candidate is running unverified.

    Before this the only signal was a journald line. An operator who armed a
    candidate, rebooted, and came back later saw a box on the old kernel and a
    promote unit reporting success, with nothing saying the gate declined or
    why.

    #6601 is what made it worth closing rather than theoretical: it converted
    "maybe run a stale binary" into "refuse", which is the right trade, but it
    made refusal a REACHABLE outcome. A state that is now reachable needs to be
    observable.

    The record does NOT make the unit fail, and one test below asserts that
    explicitly — the exit-0 contract is load-bearing and this must not erode it.
    """

    def test_a_refusal_leaves_a_durable_record_with_the_facts(self):
        # The strongest refusal: a candidate IS armed and the gate cannot run.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        self.stub_loadstate = "loaded"
        self.stub_mainpid = "0"
        self.stub_execstart = "{ path=/usr/local/sbin/xpfd ; argv[]=/usr/local/sbin/xpfd ; ignore_errors=no }"

        res = self._run()
        self._assert_refused(res, "journal ARMED, record absent")
        rec = self._assert_recorded("refused", "journal ARMED, record absent")

        # The RESOLUTION FACTS, not just "refused" — the issue's central
        # criterion. These are the snapshot values the DECISION was made on, so
        # an operator reading them days later is not looking at a re-query of a
        # system that has since changed.
        self.assertEqual(rec.get("load_state"), "loaded")
        self.assertEqual(rec.get("main_pid"), "0")
        self.assertEqual(rec.get("exec_start"), self.stub_execstart)
        self.assertEqual(rec.get("unit"), "xpfd.service")
        # The journal bit that made this a refusal rather than a quiet skip.
        self.assertEqual(rec.get("journal_state"), "armed")
        # Enough to say WHAT happened and WHAT to do about it.
        self.assertIn("ARMED", rec.get("reason", ""))
        self.assertTrue(rec.get("cause"), f"no cause recorded: {rec}")
        self.assertTrue(rec.get("advice"), f"no advice recorded: {rec}")
        # A wrong early-boot clock must not leave the event unattributable.
        self.assertTrue(rec.get("boot_id"), f"no boot id recorded: {rec}")

    def test_the_record_does_not_make_the_unit_fail(self):
        # The exit-0 contract is why this issue exists at all, and closing the
        # observability gap must not close it by breaking that. Asserted as its
        # own test rather than only inside _assert_refused, because this is the
        # constraint the fix was most likely to violate.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        res = self._run()
        self.assertEqual(
            res.returncode,
            0,
            "the gate exited non-zero after writing the record; that trips the "
            "unit's OnFailure= and reboots the box on the boot path (#6622 "
            "explicitly rules this out as the fix)",
        )
        self.assertTrue(self._read_refusal(), "no record was written")
        self.assertFalse(
            self.systemctl_ran.exists(),
            "the gate rebooted after recording a refusal",
        )

    def test_advice_branch_is_recorded_not_just_logged(self):
        # set_cause_advice BRANCHES: telling an operator to fix an ExecStart
        # when systemctl could not be consulted at all points at the wrong
        # system. The record must preserve WHICH branch was taken, or it
        # reproduces that mistake one rotation later.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        self.stub_show_fail = "1"

        res = self._run()
        self._assert_refused(res, "systemctl unreachable")
        rec = self._assert_recorded("refused", "systemctl unreachable")
        self.assertIn("systemd-availability", rec.get("advice", ""))
        self.assertIn("systemctl could not be consulted", rec.get("cause", ""))
        # And the facts must say the query failed rather than reporting an
        # empty value that reads like "systemd answered, with nothing".
        self.assertEqual(rec.get("load_state"), "<systemctl failed>")

    def test_a_multiline_execstart_cannot_forge_extra_fields(self):
        # systemd renders multiple ExecStart entries one per LINE. The record is
        # one line per field, so an unflattened value would turn a single field
        # into several bogus records -- the same "a value may legally contain
        # the delimiter" class as the ExecStart parse itself, in reverse.
        self.armed = str(self.tmp / "nope" / "xpfd")  # unusable -> refusal
        self.stub_loadstate = "loaded"
        self.stub_execstart = (
            "{ path=/a/xpfd ; argv[]=/a/xpfd ; ignore_errors=no }\n"
            "reason=FORGED\n"
            "{ path=/b/xpfd ; argv[]=/b/xpfd ; ignore_errors=no }"
        )

        res = self._run()
        self._assert_refused(res, "recorded binary missing")
        rec = self._assert_recorded("refused", "recorded binary missing")
        # Assert on the RAW file, not on the parsed dict. The forged line lands
        # BEFORE the real `reason=`, so a last-key-wins parse (which is what
        # both this helper and Go's reader do) silently discards it and a
        # dict-based assertion here could never fire -- it would read as the
        # load-bearing check while being dead. The raw text is where the
        # forgery is visible.
        raw = self._refusal_path().read_text()
        self.assertNotIn(
            "\nreason=FORGED",
            raw,
            "a newline inside ExecStart forged a `reason` field; the value was "
            f"not flattened (#6622):\n{raw}",
        )
        self.assertNotIn(
            "\n",
            rec.get("exec_start", ""),
            "the ExecStart value kept a newline",
        )
        # And the real reason survived intact.
        self.assertIn("not an executable regular file", rec.get("reason", ""))

    def test_an_indeterminate_journal_is_recorded_as_such(self):
        # Not a refusal, but the same operator problem: a candidate may be
        # armed, the gate did not run, and nothing durable said so. Recording
        # it is what makes the record's ABSENCE meaningful -- if only refuse()
        # wrote one, "no record" could not distinguish a clean boot from a boot
        # the gate skipped for this reason.
        self.arm_explicitly_absent = True
        journal = self._journal_path()
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.mkdir()  # a DIRECTORY: present, unreadable as a journal

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("cannot establish whether", res.stderr)
        rec = self._assert_recorded("indeterminate", "journal is a directory")
        self.assertEqual(rec.get("journal_state"), "indeterminate")
        self.assertNotIn("REFUSING", res.stderr)

    def test_an_ordinary_boot_leaves_no_record(self):
        # The ANTI-NOISE control. A file rewritten on every boot is not a
        # signal; and a stale record from a prior candidate would be read as a
        # verdict on the current one.
        self.arm_explicitly_absent = True  # nothing armed, no journal
        res = self._run()
        self._assert_nothing_armed(res, "nothing armed")
        self._assert_no_record("ordinary boot, nothing armed")

    def test_a_successful_promotion_leaves_no_record(self):
        # The gate RAN. From here the Go half owns the durable state (journal,
        # promotion marker, last-roll), so a second writer here would be a
        # second source for the same question.
        self._seed_runtime_layout()
        _live, ran = self._arm_a_live_binary()
        res = self._run()
        self._assert_ran(res, ran, "healthy armed box")
        self._assert_no_record("the gate ran the recorded binary")

    def test_an_unwritable_state_dir_does_not_change_the_exit_path(self):
        # This runs on a candidate boot whose whole problem may be that the
        # filesystem is not what the gate expected. A gate that changed its
        # exit path because it could not write a DIAGNOSTIC would convert an
        # observability gap into an availability one -- it would reboot the box.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        res_dir = Path(str(self.fake_root) + REFUSAL_RECORD).parent
        res_dir.mkdir(parents=True, exist_ok=True)
        # Plant a DIRECTORY where the record goes: mkdir -p succeeds, the
        # rename cannot.
        self._refusal_path().mkdir(parents=True, exist_ok=True)

        res = self._run()
        self._assert_refused(res, "record unwritable")
        self.assertFalse(
            self.systemctl_ran.exists(),
            "an unwritable record rebooted the box",
        )


class TestBusyboxParity(_GateBase):
    """NIT-1 (#6601 r5) — the portability claim was asserted but never bound.

    The `[[:space:]]` note claims dash and busybox both honour the class, and
    the suite only ever ran /bin/sh. Re-run the state matrix under busybox sh so
    the claim is tested rather than trusted. SKIPs when busybox is absent.
    """

    def setUp(self):
        busybox = shutil.which("busybox")
        if not busybox:
            self.skipTest("busybox not installed")
        super().setUp()
        self.shell_argv = [busybox, "sh"]

    def test_parses_and_resolves_under_busybox(self):
        live = self.tmp / "opt" / "versions" / "v9" / "xpfd"
        ran = self._install_abs(live)
        self.stub_loadstate = "loaded"
        self.stub_mainpid = "0"
        self.stub_execstart = f"{{ path={live} ; argv[]={live} ; ignore_errors=no }}"

        res = self._run()
        self._assert_ran(res, ran, "busybox sh")
        self.assertIn("confirmed by", res.stderr)

    def test_whitespace_rejection_holds_under_busybox(self):
        # The bare-rendering branch must reject a TAB as well as a space — the
        # specific claim the `[[:space:]]` comment makes. ExecStart is still
        # parsed (it feeds the cross-check), so the rule still has to hold:
        # each value below names a REAL executable, so tolerating it would
        # contradict the record and refuse a healthy promotion.
        for ws, label in ((" ", "space"), ("\t", "tab")):
            with self.subTest(label):
                self.setUp()
                bad = self.tmp / "bare" / f"xpfd{ws}--flag"
                self._install_abs(bad)
                _live, live_ran = self._arm_a_live_binary()
                self.stub_loadstate = "loaded"
                self.stub_mainpid = "0"
                self.stub_execstart = str(bad)

                res = self._run()
                self.assertNotIn(
                    str(bad),
                    res.stderr,
                    f"busybox sh accepted a bare ExecStart containing a {label}; "
                    "the [[:space:]] portability claim is false there: "
                    f"{res.stderr}",
                )
                self._assert_ran(res, live_ran, f"bare ExecStart with a {label}")

    def test_never_cut_symlink_layout_promotes_under_busybox(self):
        # The r8 MAJOR-1 fix leans on `-ef` (with a `readlink -f` fallback), and
        # neither is in POSIX `test`. busybox sh is the other shell this runs
        # under at early boot, and a `same_file` that silently never matches
        # there would refuse a healthy candidate on every never-cut appliance —
        # the exact regression the fix removes, reintroduced on one platform.
        versioned, sbin, ran = self._seed_runtime_layout()
        self.armed = str(versioned)
        self.stub_execstart = f"{{ path={sbin} ; argv[]={sbin} }}"
        self.stub_mainpid = "0"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_ran(res, ran, "busybox sh, never-cut symlink layout")
        self.assertIn("confirmed by", res.stderr)

    def test_different_files_still_refuse_under_busybox(self):
        # The over-reach half: `same_file` must still say NO under busybox, or
        # the r6 stale-leftover-unit MAJOR is laundered on that platform.
        _versioned, sbin, _ran = self._seed_runtime_layout(version="v1")
        other = Path(str(self.fake_root) + "/var/lib/xpf/versions/v2/xpfd")
        self._install_abs(other)
        self.armed = str(other)
        self.stub_execstart = f"{{ path={sbin} ; argv[]={sbin} }}"
        self.stub_mainpid = "0"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "busybox sh, genuinely different files")

    def test_journal_armed_state_is_recognised_under_busybox(self):
        # The r7 journal read is a `case` glob with an embedded variable and
        # quoted quotes. busybox sh is the other shell this runs under at early
        # boot, and a glob that silently never matches there would restore the
        # silent skip on exactly the platform the appliance boots.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        self.stub_loadstate = "not-found"
        res = self._run()
        self._assert_refused(res, "busybox sh, journal ARMED, record absent")
        self.assertIn("UNVERIFIED", res.stderr)

    def test_refusal_record_is_written_under_busybox(self):
        # The record writer uses `tr`, `date`, `mv` and a redirection into a
        # command group. The busybox leg swaps the SHELL, not the utilities, so
        # what this binds is the SHELL's handling of the group redirect and the
        # command substitutions inside it -- the parts a non-dash sh could
        # differ on. Without it the whole #6622 mechanism is asserted only
        # under /bin/sh, on a script whose entire portability claim is that it
        # runs under both.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMED")
        self.stub_loadstate = "loaded"
        self.stub_execstart = "{ path=/a/xpfd ; argv[]=/a/xpfd ; ignore_errors=no }"

        res = self._run()
        self._assert_refused(res, "busybox, journal ARMED, record absent")
        rec = self._assert_recorded("refused", "busybox")
        self.assertEqual(rec.get("exec_start"), self.stub_execstart)
        self.assertEqual(rec.get("journal_state"), "armed")
        self.assertTrue(rec.get("reason"), f"no reason recorded under busybox: {rec}")

    def test_arming_state_without_a_record_warns_under_busybox(self):
        # The other side of the same glob: recordless ARMING now takes the
        # unrecorded-arming WARNING branch (it must still NOT match the
        # trial glob — nothing may run without a designated binary), and the
        # durable record must be written under busybox sh too, the other
        # early-boot shell.
        self.arm_explicitly_absent = True
        self.journal = self.journal_body("ARMING")
        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("nothing to promote", res.stderr)
        self.assertIn("WARNING", res.stderr)
        self.assertIn("UNVERIFIED", res.stderr)
        self._assert_recorded(
            "unrecorded-arming", "busybox sh, journal ARMING, no record"
        )
        self._assert_no_path_fallback(res, "busybox sh, journal ARMING, no record")

    def test_arming_state_WITH_a_record_runs_the_gate_under_busybox(self):
        # #16809 parity: the ARMING+record -> run-the-gate branch must behave
        # identically under busybox sh, the other early-boot shell.
        _live, live_ran = self._arm_a_live_binary()
        self.journal = self.journal_body("ARMING")
        self.stub_loadstate = "loaded"
        res = self._run()
        self._assert_ran(res, live_ran, "busybox sh, ARMING journal with a record")
        self.assertIn("#16809", res.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1)
