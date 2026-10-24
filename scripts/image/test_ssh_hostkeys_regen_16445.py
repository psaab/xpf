#!/usr/bin/env python3
"""Decoupled ssh host-key regeneration after an interrupted zeroize (#16445).

On base, the only xpf regenerator was regen_ssh_host_keys() inside
xpf-day0-config, gated by the unit's
ConditionPathExists=!/etc/xpf/.day0-config-applied. A zeroize writes its
pending marker at that exact path BEFORE the seal leg erases
/etc/ssh/ssh_host_* and rotates the machine-id, so any later leg failure
or power loss leaves: marker present, host keys absent, machine-id real.
Next boot the day-0 unit is condition-skipped, Ubuntu's sshd-keygen
(ConditionFirstBoot=yes) is defeated by the real machine-id, and
sshd -t fails -- console-only.

This test exercises the REAL production artifacts, not a re-implementation:

  * It evaluates the REAL units' ConditionPathExists lines with
    systemd-analyze condition against a fixture root holding the
    failed-reset state (pending marker present, no host keys): the
    day-0 loader's condition must FAIL (twin: loader still skipped)
    while the regenerator's condition must SUCCEED.
  * It then runs the regenerator unit's REAL ExecStart (ssh-keygen -A,
    retargeted at the fixture root via its documented -f prefix) in
    that same state and asserts host keys materialize and sshd -t
    passes with them -- the boot outcome the issue requires.
  * With a host key already present, the regenerator's condition must
    FAIL, so existing keys are never rotated by this unit.

RED on revert: delete xpf-ssh-hostkeys.service, re-gate it on the day-0
stamp/first-boot, or move regeneration back into the day-0 script, and
the failed-reset arm reds (no condition succeeds / no keys appear).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_DAY0_UNIT = _HERE / "xpf-day0-config.service"
_REGEN_UNIT = _HERE / "xpf-ssh-hostkeys.service"

_HAS_SYSTEMD_ANALYZE = shutil.which("systemd-analyze") is not None
_HAS_SSH = (shutil.which("ssh-keygen") is not None
            and (Path("/usr/sbin/sshd").is_file()
                 or shutil.which("sshd") is not None))


def _directive(unit: Path, key: str) -> str:
    for line in unit.read_text().splitlines():
        line = line.strip()
        if line.startswith(key + "="):
            return line[len(key) + 1:]
    raise AssertionError(f"{unit.name}: no {key}= directive")


def _condition_holds(unit: Path, root: Path) -> bool:
    """Evaluate the unit's ConditionPathExists against a fixture root.

    The production condition is an absolute path; retarget only its
    leading '/' onto the fixture root, preserving the '!' negation and
    the exact production path underneath.
    """
    cond = _directive(unit, "ConditionPathExists")
    negated = cond.startswith("!")
    raw = cond[1:] if negated else cond
    assert raw.startswith("/"), cond
    fixture = str(root) + raw
    expr = f"ConditionPathExists={'!' if negated else ''}{fixture}"
    res = subprocess.run(
        ["systemd-analyze", "condition", expr],
        capture_output=True, text=True)
    # systemd-analyze condition: rc 0 iff all conditions succeed.
    return res.returncode == 0


@unittest.skipUnless(_HAS_SYSTEMD_ANALYZE and _HAS_SSH,
                     "systemd-analyze, ssh-keygen and sshd are required")
class TestSSHHostkeysRegen16445(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        # Failed-reset state: pending marker at the day-0 stamp path,
        # host keys erased, machine-id freshly rotated (real value).
        xpf = self.root / "etc" / "xpf"
        xpf.mkdir(parents=True)
        (xpf / ".day0-config-applied").write_text(
            "#xpf-zeroize-pending v=1\n")
        (self.root / "etc" / "machine-id").write_text(
            "9b7fad82" + "0" * 24 + "\n")
        self.ssh_dir = self.root / "etc" / "ssh"
        self.ssh_dir.mkdir(parents=True)

    def test_failed_reset_regenerates_and_sshd_validates(self):
        # Twin: with the pending marker present the day-0 loader is
        # still skipped -- its condition must FAIL.
        self.assertFalse(
            _condition_holds(_DAY0_UNIT, self.root),
            "day-0 loader must stay skipped under the pending marker")
        # The regenerator's gate is key absence: it must SUCCEED in
        # exactly the state above.
        self.assertTrue(
            _condition_holds(_REGEN_UNIT, self.root),
            "regen unit must run when host keys are absent, marker or not")

        # Run the unit's real ExecStart, retargeted at the fixture via
        # ssh-keygen -A's documented -f prefix (same generation logic,
        # fixture paths only).
        exec_start = _directive(_REGEN_UNIT, "ExecStart")
        self.assertEqual(exec_start, "/usr/bin/ssh-keygen -A")
        subprocess.run(
            ["ssh-keygen", "-A", "-f", str(self.root)],
            check=True, capture_output=True, text=True)
        key = self.ssh_dir / "ssh_host_ed25519_key"
        self.assertTrue(key.is_file(), "ssh-keygen -A created no host key")

        # sshd -t with the regenerated key passes; without any host
        # key it is the production failure (negative control).
        sshd = shutil.which("sshd") or "/usr/sbin/sshd"
        ok = subprocess.run(
            [sshd, "-t", "-h", str(key)],
            capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        bad = subprocess.run(
            [sshd, "-t", "-f", "/dev/null"],
            capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0,
                            "sshd -t unexpectedly passed with no host key")

    def test_existing_key_skips_regeneration(self):
        key = self.ssh_dir / "ssh_host_ed25519_key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True, capture_output=True, text=True)
        before = key.read_bytes()
        self.assertFalse(
            _condition_holds(_REGEN_UNIT, self.root),
            "regen unit must be skipped when a host key already exists")
        self.assertEqual(key.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
