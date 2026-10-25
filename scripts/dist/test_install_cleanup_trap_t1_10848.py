#!/usr/bin/env python3
"""Shell-trap proof for psaab/xpf#10848 T1 (O5 code half).

Extracts only `cleanup_on_fail`, `write_source`, and `write_channel_pin`
from install.sh, then runs them in a shell harness with command stubs. The
stubs log calls and reject mutating paths outside a per-test temporary dir;
install.sh itself is never sourced or executed.
The source-only hook is intentionally avoided: sourcing the full script
loads unrelated installer code and registers its production EXIT trap.
Function extraction keeps this regression scoped to the T1 contract.

Source refs at 4a17e0d29: cleanup_on_fail + EXIT trap (install.sh:85-147),
write_source (:379-397), and write_channel_pin (:402-447).

RED/GREEN: default run is GREEN (the extracted real EXIT trap cleans the
written source and pin). With T1_PROVE_RED=1, the harness omits the trap
registration; only the cleanup-firing assertion fails. The registration test
checks only the harness-generated trap line, not install.sh's registration.

Bounds: shell-trap behavior only. No anti-rollback floor, no Q1-Q4
enforcement, no APT resolver claims (those live in docs only).
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_INSTALLSH = _DIST / "install.sh"
_TRAP_LINE = "trap cleanup_on_fail EXIT"
_FUNCTIONS = ("cleanup_on_fail", "write_source", "write_channel_pin")
_PROVE_RED = os.environ.get("T1_PROVE_RED") == "1"


def _install_source():
    return _INSTALLSH.read_text()


def _extract_function(source, name):
    """Extract one top-level install.sh function, not the whole script."""
    pattern = rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}$"
    match = re.search(pattern, source)
    if match is None:
        raise AssertionError(f"{name}() function missing from install.sh")
    return match.group(0)


def _render_harness(tmpdir, action, trap_enabled):
    """Compose selected real functions with temp-confined command stubs."""
    source = _install_source()
    trap_match = re.search(rf"(?m)^{re.escape(_TRAP_LINE)}$", source)
    if trap_match is None:
        raise AssertionError(f"{_TRAP_LINE!r} missing from install.sh")

    tmp = shlex.quote(str(tmpdir))
    lines = [
        "set -eu",
        f"T1_TMP={tmp}",
        'T1_CALL_LOG="$T1_TMP/calls.log"',
        "t1_log() { printf '%s\\n' \"$*\" >> \"$T1_CALL_LOG\"; }",
        "t1_path_guard() {",
        "    for t1_arg do",
        "        case \"$t1_arg\" in",
        "            -*|0644|0755) ;;",
        '            "$T1_TMP"|"$T1_TMP"/*) ;;',
        "            *) printf 'stub refused unsafe path: %s\\n' \"$t1_arg\" >&2; return 97 ;;",
        "        esac",
        "    done",
        "}",
        # These command stubs log all mutations and guard their operands.
        # The guard's refusal must short-circuit the real command: cleanup_on_fail
        # calls rm as `rm ... || _rc=1` and mv as an `if` condition, and POSIX
        # suppresses `set -e` inside AND-OR lists and `if` conditions (the
        # suppression extends into called function bodies), so a bare
        # `t1_path_guard "$@"; command ...` sequencing would run the real
        # command anyway after a refusal. `|| return 97` refuses for real.
        # The test root exists before the harness starts; install -d is a no-op.
        'install() { t1_log "install $*"; t1_path_guard "$@" || return 97; }',
        'mktemp() { t1_log "mktemp $*"; t1_path_guard "$@" || return 97; command mktemp "$@"; }',
        'chmod() { t1_log "chmod $*"; t1_path_guard "$@" || return 97; command chmod "$@"; }',
        'mv() { t1_log "mv $*"; t1_path_guard "$@" || return 97; command mv "$@"; }',
        'rm() { t1_log "rm $*"; t1_path_guard "$@" || return 97; command rm "$@"; }',
        'info() { printf "xpf-install: %s\\n" "$*"; }',
        'die() { printf "xpf-install ERROR: %s\\n" "$*" >&2; exit 1; }',
        'SRC="$T1_TMP/xpf.sources"',
        'PIN="$T1_TMP/xpf-channel.pref"',
        'KEYRING="$T1_TMP/xpf-archive-keyring.asc"',
        'XPF_APT_BASE_URL="https://example.invalid/apt"',
        'CHANNEL=stable',
        'DRY=0',
        'SRC_WRITTEN=0',
        "SRC_BACKUP=''",
        "SRC_TEMP=''",
        'INSTALL_OK=0',
        'PIN_WRITTEN=0',
        "PIN_BACKUP=''",
        "PIN_TEMP=''",
        'KEYRING_WRITTEN=0',
        "KEYRING_BACKUP=''",
        "KEYRING_TEMP=''",
        "KEYRING_IDENT=''",
        "ARCHIVE_KEY=stub-key",
        "PIN_MARKER='# xpf appliance channel pin; Managed by install.sh (#11133)'",
    ]
    lines.extend(_extract_function(source, name) for name in _FUNCTIONS)
    if trap_enabled:
        # Insert the exact registration line extracted from install.sh.
        lines.append(trap_match.group(0))
    lines.append(action)
    return "\n".join(lines) + "\n"


def _run_harness(tmpdir, action, trap_enabled=True):
    env = dict(os.environ)
    env["TMPDIR"] = str(tmpdir)
    script = _render_harness(tmpdir, action, trap_enabled)
    process = subprocess.run(["sh", "-c", script], capture_output=True,
                             text=True, env=env, timeout=30)
    return process.returncode, (process.stdout or "") + (process.stderr or "")


class TrapTextTests(unittest.TestCase):
    def test_install_sh_has_trap_and_selected_functions(self):
        source = _install_source()
        self.assertRegex(source, rf"(?m)^{re.escape(_TRAP_LINE)}$")
        for name in _FUNCTIONS:
            self.assertIn(f"{name}() {{", source)
        self.assertIn("SRC_WRITTEN=1", source)
        self.assertIn("PIN_WRITTEN=1", source)

    def test_source_backup_restore_is_wired(self):
        source = _install_source()
        self.assertIn("SRC_BACKUP=''", source)
        self.assertIn("SRC_TEMP=''", source)
        self.assertIn("SRC_BACKUP=$(mktemp", source)
        self.assertIn("cp -p \"$SRC\" \"$SRC_BACKUP\"", source)
        self.assertIn("restoring previous $SRC", source)
        self.assertIn('mv -f "$SRC_BACKUP" "$SRC"', source)

    def test_exit_trap_registered_before_main_guard(self):
        source = _install_source()
        trap_lines = re.findall(
            r"(?m)^[ \t]*trap\b[^\n]*\b(?:EXIT|0)\b", source)
        self.assertEqual(trap_lines, [_TRAP_LINE])
        guard = 'if [ "${XPF_INSTALL_SOURCE_ONLY:-}" != "1" ]; then'
        self.assertIn(guard, source)
        self.assertLess(
            source.index(_TRAP_LINE), source.index(guard),
            "EXIT cleanup trap must be registered before the main guard")

    def test_trap_registered_in_harness(self):
        with tempfile.TemporaryDirectory(prefix="t1-10848-trap-") as tmp:
            rc, out = _run_harness(
                Path(tmp), "trap", trap_enabled=not _PROVE_RED)
        self.assertNotIn("stub refused", out)
        self.assertEqual(rc, 0, out[-2000:])
        if _PROVE_RED:
            self.assertNotIn("cleanup_on_fail", out)
        else:
            self.assertIn("cleanup_on_fail", out)


class TrapFiresTests(unittest.TestCase):
    def test_exit_trap_fires_cleanup_on_failure(self):
        with tempfile.TemporaryDirectory(prefix="t1-10848-fire-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            pin = tmpdir / "xpf-channel.pref"
            rc, out = _run_harness(
                tmpdir, "write_source\nwrite_channel_pin\nfalse",
                trap_enabled=not _PROVE_RED)
            calls = (tmpdir / "calls.log").read_text()
            self.assertNotEqual(rc, 0, out[-2000:])
            self.assertNotIn("stub refused", out)
            self.assertIn("writing apt source", out)
            self.assertIn("wrote managed apt channel pin", out)
            # These assertions fail in RED mode if the EXIT trap is absent.
            self.assertIn("install failed", out)
            self.assertIn(f"rm -f {src}", calls)
            self.assertIn(f"rm -f {pin}", calls)
            self.assertFalse(src.exists(), f"stale source left behind: {src}")
            self.assertFalse(pin.exists(), f"stale pin left behind: {pin}")

    def test_without_trap_cleanup_does_not_fire_control(self):
        # Always-unarmed control: writer outputs remain and no cleanup calls
        # are logged, demonstrating that the RED configuration is meaningful.
        with tempfile.TemporaryDirectory(prefix="t1-10848-ctrl-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            pin = tmpdir / "xpf-channel.pref"
            rc, out = _run_harness(
                tmpdir, "write_source\nwrite_channel_pin\nfalse",
                trap_enabled=False)
            calls = (tmpdir / "calls.log").read_text()
            self.assertNotEqual(rc, 0, out[-2000:])
            self.assertNotIn("stub refused", out)
            self.assertIn("writing apt source", out)
            self.assertTrue(src.exists(), "control source missing")
            self.assertTrue(pin.exists(), "control pin missing")
            self.assertNotIn("rm -f", calls)
            self.assertNotIn("install failed", out)

    def test_no_cleanup_on_success(self):
        with tempfile.TemporaryDirectory(prefix="t1-10848-ok-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            pin = tmpdir / "xpf-channel.pref"
            rc, out = _run_harness(
                tmpdir,
                "write_source\nwrite_channel_pin\nINSTALL_OK=1\nexit 0",
                trap_enabled=not _PROVE_RED)
            calls = (tmpdir / "calls.log").read_text()
            self.assertEqual(rc, 0, out[-2000:])
            self.assertNotIn("stub refused", out)
            self.assertTrue(src.exists(), "success run removed source")
            self.assertTrue(pin.exists(), "success run removed pin")
            self.assertNotIn("rm -f", calls)
            self.assertNotIn("install failed", out)

    def test_failed_rerun_restores_preexisting_source_byte_for_byte(self):
        # #16534 defect cell: a re-run (documented channel rebind) overwrites
        # a working source, then the apt step fails. The source must come
        # back byte-for-byte (and keep its mode), not be rm -f'd.
        with tempfile.TemporaryDirectory(prefix="t1-16534-rerun-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            pin = tmpdir / "xpf-channel.pref"
            original = ("# xpf appliance apt source (#1924). Managed by install.sh.\n"
                        "Types: deb\nURIs: https://example.invalid/apt\nSuites: stable\n"
                        "Components: main\nArchitectures: amd64\nSigned-By: /k\n")
            src.write_text(original)
            src.chmod(0o640)
            rc, out = _run_harness(
                tmpdir, "write_source\nwrite_channel_pin\nfalse")
            self.assertNotEqual(rc, 0, out[-2000:])
            self.assertNotIn("stub refused", out)
            self.assertIn("restoring previous %s" % src, out)
            self.assertTrue(src.exists(), "failed re-run deleted pre-existing source")
            self.assertEqual(src.read_text(), original)
            self.assertEqual(src.stat().st_mode & 0o777, 0o640)
            self.assertFalse(pin.exists(), "new pin should still be removed")
            self.assertEqual(
                list(tmpdir.glob(".xpf.sources.*")), [],
                "source temp/backup must not leak")

    def test_successful_rerun_keeps_new_source_and_cleans_backup(self):
        with tempfile.TemporaryDirectory(prefix="t1-16534-ok-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            src.write_text("old source\n")
            rc, out = _run_harness(
                tmpdir, "write_source\nINSTALL_OK=1\nexit 0")
            self.assertEqual(rc, 0, out[-2000:])
            self.assertNotIn("stub refused", out)
            self.assertTrue(src.exists())
            self.assertIn("Suites: stable", src.read_text())
            self.assertNotIn("old source", src.read_text())
            self.assertEqual(
                list(tmpdir.glob(".xpf.sources.*")), [],
                "source temp/backup must not leak on success")

    def test_symlink_source_is_refused_and_preserved(self):
        with tempfile.TemporaryDirectory(prefix="t1-16534-symlink-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            target = tmpdir / "operator-source"
            target.write_text("operator source\n")
            src.symlink_to(target)
            rc, out = _run_harness(tmpdir, "write_source")
            self.assertNotEqual(rc, 0, out[-2000:])
            self.assertIn("refusing to replace symlink", out)
            self.assertTrue(src.is_symlink())
            self.assertEqual(target.read_text(), "operator source\n")
            self.assertEqual(list(tmpdir.glob(".xpf.sources.*")), [])


if __name__ == "__main__":
    unittest.main()
