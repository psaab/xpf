#!/usr/bin/env python3
"""Unit tests for psaab/xpf#12544 — flat build-apt-repo.sh Valid-Until
assertion must not race apt-ftparchive's wall clock.

The flat path pins APT::FTPArchive::Release::Date to NOWSTR and asks
apt-ftparchive to emit Valid-Until with ValidTime, but apt-ftparchive
(apt-utils 3.3.3) derives Valid-Until from time(NULL) and ignores the
pinned Date. A second boundary between reading NOW and apt-ftparchive
sampling the wall clock makes the old exact `NOW + VALID_SECONDS`
assertion fail intermittently (`want epoch ...328, got ...329`) even
though the emitted horizon is valid.

These cells are deterministic: a fake `apt-ftparchive` on PATH emits a
Release whose Valid-Until is exactly one second past
`Date + ValidTime` (the observed race), and a fake `date` pins the
builder's NOW so the race is reproduced on every run, not by luck.
Refusal cells (missing / duplicate / malformed / off-horizon
Valid-Until, duplicate Date) must stay fail-closed.

RED on base: the +1s boundary cell is refused by the exact-epoch
assertion. RED on revert: a wall-clock-independent assertion derived
from the emitted Date accepts exactly Date+ValidTime (+1s wall skew);
dropping the singleton/value checks lets the refusal cells ship.
"""

from __future__ import annotations

import email.utils
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_BUILDER = _DIST / "build-apt-repo.sh"

_FIXED_NOW = 1_700_000_000  # pinned builder NOW (2023-11-14T22:13:20Z)
_REAL_DATE = shutil.which("date") or "/usr/bin/date"

_DATE_SHIM = """\
#!/bin/sh
# Fake date for #12544: pin `date -u +%s` (the builder's NOW) to a fixed
# epoch; delegate every other invocation (formatting/parsing) to real date.
has_d=0
for a in "$@"; do [ "$a" = "-d" ] && has_d=1; done
if [ "$has_d" = "0" ]; then
    for a in "$@"; do
        if [ "$a" = "+%s" ]; then echo "__FIXED_NOW__"; exit 0; fi
    done
fi
exec __REAL_DATE__ "$@"
""".replace("__FIXED_NOW__", str(_FIXED_NOW)).replace("__REAL_DATE__", _REAL_DATE)

_APT_SHIM = """\
#!/bin/sh
# Fake apt-ftparchive for #12544: `packages` emits nothing; `release`
# emits a synthetic Release. Date is the pinned builder Date (fixed
# epoch); Valid-Until is derived per XPF_TEST_VU_MODE from that Date
# plus the ValidTime knob the builder passed via -o (default 365d):
#   boundary-vu  Date+ValidTime+1   (the observed +1s wall-clock race)
#   plus-two-vu  Date+ValidTime+2   (must exceed the narrow allowance)
#   early-vu     Date+ValidTime-1
#   skewed-vu    Date+ValidTime-86400
#   late-vu      Date+ValidTime+3600
#   dup-vu       two boundary lines
#   malformed-vu unparseable value
#   missing-vu   no Valid-Until line
#   dup-date     two Date lines (with boundary-vu)
set -eu
mode="${XPF_TEST_VU_MODE:-boundary-vu}"
case "${1:-}" in
    packages) exit 0 ;;
esac
valid=""
for a in "$@"; do
    case "$a" in
        *ValidTime=*) valid="${a##*ValidTime=}" ;;
    esac
done
[ -n "$valid" ] || valid=31536000
fmt="+%a, %d %b %Y %H:%M:%S UTC"
datestr=$(__REAL_DATE__ -u -d "@__FIXED_NOW__" "$fmt")
vu() { __REAL_DATE__ -u -d "@$((__FIXED_NOW__ + valid + $1))" "$fmt"; }
echo "Origin: xpf"
echo "Label: xpf"
echo "Suite: stable"
echo "Codename: stable"
case "$mode" in
    dup-date) echo "Date: $datestr"; echo "Date: $datestr" ;;
    *) echo "Date: $datestr" ;;
esac
case "$mode" in
    missing-vu) ;;
    dup-vu) echo "Valid-Until: $(vu 1)"; echo "Valid-Until: $(vu 1)" ;;
    malformed-vu) echo "Valid-Until: not-a-date" ;;
    early-vu) echo "Valid-Until: $(vu -1)" ;;
    skewed-vu) echo "Valid-Until: $(vu -86400)" ;;
    plus-two-vu) echo "Valid-Until: $(vu 2)" ;;
    late-vu) echo "Valid-Until: $(vu 3600)" ;;
    *) echo "Valid-Until: $(vu 1)" ;;
esac
echo "Architectures: amd64"
echo "Components: main"
""".replace("__FIXED_NOW__", str(_FIXED_NOW)).replace("__REAL_DATE__", _REAL_DATE)


def _make_deb(path):
    pkgdir = os.path.join(os.path.dirname(path), "pkg")
    debdir = os.path.join(pkgdir, "DEBIAN")
    os.makedirs(debdir, exist_ok=True)
    Path(os.path.join(debdir, "control")).write_text(
        "Package: xpf-appliance\nVersion: 0.0.0-12544\nArchitecture: amd64\n"
        "Maintainer: t <t@x.invalid>\nDescription: 12544 fixture\n")
    subprocess.run(["dpkg-deb", "--build", pkgdir, path], check=True,
                   capture_output=True, timeout=60)


@unittest.skipUnless(shutil.which("dpkg-deb"), "needs dpkg-deb for the deb fixture")
class ShimFlatValidUntilTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-repo12544-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        bindir = os.path.join(self.dir, "bin")
        os.makedirs(bindir)
        for name, text in (("date", _DATE_SHIM), ("apt-ftparchive", _APT_SHIM)):
            shim = os.path.join(bindir, name)
            Path(shim).write_text(text)
            os.chmod(shim, 0o755)
        self.bindir = bindir
        self.deb = os.path.join(self.dir, "xpf-appliance_0.0.0-12544_amd64.deb")
        _make_deb(self.deb)

    def _run(self, mode, days="7"):
        outdir = os.path.join(self.dir, "out-" + mode)
        os.makedirs(outdir, exist_ok=True)
        env = dict(os.environ)
        for var in ("XPF_APT_COMPONENT", "XPF_APT_ARCH", "XPF_APT_ORIGIN",
                    "XPF_APT_SUITE", "XPF_APT_TOOL", "XPF_GPG_KEY",
                    "XPF_APT_VALID_DAYS", "XPF_TEST_VU_MODE"):
            env.pop(var, None)
        env.update({
            "XPF_APT_VALID_DAYS": days,
            "XPF_TEST_VU_MODE": mode,
            "PATH": self.bindir + os.pathsep + env.get("PATH", ""),
        })
        p = subprocess.run(
            ["sh", str(_BUILDER), "--out", outdir, "--suite", "stable",
             "--debs", self.deb],
            capture_output=True, text=True, env=env, timeout=120)
        return outdir, p.returncode, (p.stdout or "") + (p.stderr or "")

    def _release(self, outdir):
        rel = Path(outdir) / "apt" / "dists" / "stable" / "Release"
        self.assertTrue(rel.is_file(), "no Release written")
        return rel.read_text()

    def test_plus_one_second_boundary_accepted(self):
        # apt-ftparchive sampled the wall clock 1s after the pinned Date:
        # Valid-Until == Date + ValidTime + 1 must NOT fail the build.
        outdir, rc, out = self._run("boundary-vu")
        self.assertEqual(rc, 0, out[-800:])
        text = self._release(outdir)
        lines = [ln for ln in text.splitlines() if ln.startswith("Valid-Until:")]
        self.assertEqual(len(lines), 1)
        date_line = next(ln for ln in text.splitlines() if ln.startswith("Date:"))
        vu_epoch = email.utils.parsedate_to_datetime(
            lines[0][len("Valid-Until:"):].strip()).timestamp()
        date_epoch = email.utils.parsedate_to_datetime(
            date_line[len("Date:"):].strip()).timestamp()
        # The fixture's emission is exactly the race: horizon + 1s.
        self.assertEqual(vu_epoch, date_epoch + 7 * 86400 + 1)

    def test_missing_valid_until_refused(self):
        _o, rc, out = self._run("missing-vu")
        self.assertNotEqual(rc, 0, "missing Valid-Until shipped silently")
        self.assertIn("exactly 1", out)

    def test_duplicate_valid_until_refused(self):
        _o, rc, out = self._run("dup-vu")
        self.assertNotEqual(rc, 0, "duplicate Valid-Until shipped silently")
        self.assertIn("exactly 1", out)

    def test_malformed_valid_until_refused(self):
        _o, rc, out = self._run("malformed-vu")
        self.assertNotEqual(rc, 0, "malformed Valid-Until shipped silently")
        self.assertIn("cannot parse", out)

    def test_early_valid_until_refused(self):
        # 1s SHORT of Date+ValidTime: the horizon itself is wrong.
        _o, rc, out = self._run("early-vu")
        self.assertNotEqual(rc, 0, "below-horizon Valid-Until accepted")
        self.assertIn("ValidTime-derived", out)

    def test_skewed_valid_until_refused(self):
        _o, rc, out = self._run("skewed-vu")
        self.assertNotEqual(rc, 0, "day-skewed Valid-Until accepted")
        self.assertIn("ValidTime-derived", out)

    def test_late_valid_until_refused(self):
        # 1h past Date+ValidTime+race: beyond any boundary tolerance.
        _o, rc, out = self._run("late-vu")
        self.assertNotEqual(rc, 0, "hour-late Valid-Until accepted")
        self.assertIn("ValidTime-derived", out)

    def test_plus_two_second_boundary_refused(self):
        # The race permits +1s only; an extra second is outside the window.
        _o, rc, out = self._run("plus-two-vu")
        self.assertNotEqual(rc, 0, "+2s Valid-Until accepted")
        self.assertIn("ValidTime-derived", out)
    def test_duplicate_date_refused(self):
        # Derivation from Date is only unambiguous with exactly one Date.
        _o, rc, out = self._run("dup-date")
        self.assertNotEqual(rc, 0, "duplicate Date shipped silently")
        self.assertIn("exactly 1", out)


if __name__ == "__main__":
    unittest.main()
