#!/usr/bin/env python3
"""Unit tests for psaab/xpf#10123 — build-apt-repo.sh reprepro path must
post-hoc assert the emitted Release carries exactly one Valid-Until equal
to Date + ValidFor.

Follow-up to #9921 item (3): the F-066 flat path pins its Release with a
count==1 + exact-epoch Valid-Until assert, but the reprepro path
(--tool reprepro / XPF_APT_TOOL=reprepro) returned before that assert —
reprepro synthesizes its own Release from its database plus the ValidFor
knob, and nothing post-checked the emitted file.

The assert mirrors the flat one with two legitimate deltas (documented in
the script): the want-epoch derives from the Release's OWN Date (reprepro
generates during includedeb/export, before the check, so a wall-clock
compare would need tolerance — Date-derivation is exact, the same method
as the flat positive cell), and Date itself is pinned to exactly one line
(flat stamps Date via -o; here it is synthesized).

Verified against real reprepro 5.3.1 during development: ValidFor 7d emits
exactly one Valid-Until == Date + 7d to the second; ValidFor 0d emits NO
Valid-Until (fail-closed parity with the flat 0-horizon cell).

Refusal cells use a fake `reprepro` shim on PATH (no reprepro/GPG/deb
needed — the shim synthesizes dists/$SUITE/Release per XPF_TEST_RELEASE_MODE
and the builder's post-hoc assert is what is exercised); the real-binary
class runs the actual reprepro + a throwaway GPG key (selftest.sh section 5
pattern) and is skipped without them.

RED on revert: drop the assert and every refusal cell below exits 0 —
duplicate/missing/skewed Valid-Until ships silently.
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

_HAS_REAL_REPREPRO = bool(shutil.which("reprepro")
                          and shutil.which("gpg")
                          and shutil.which("dpkg-deb"))

_SHIM = """\
#!/bin/sh
# Fake reprepro for #10123 tests: implements
#   reprepro -b $APT includedeb $SUITE $deb
# by writing a synthetic dists/$SUITE/Release. XPF_TEST_RELEASE_MODE picks
# the emission: good | dup-vu | missing-vu | skewed-vu | offbyone-vu |
# dup-date | missing-date | missing-file. XPF_TEST_VALID_DAYS mirrors the
# builder's VALID_DAYS (default 365 both sides).
set -eu
base=""; suite=""
while [ $# -gt 0 ]; do
    case "$1" in
        -b) base="$2"; shift 2 ;;
        includedeb) suite="$2"; shift 2; break ;;
        *) shift ;;
    esac
done
[ -n "$base" ] && [ -n "$suite" ] || { echo "shim: bad argv" >&2; exit 9; }
mode="${XPF_TEST_RELEASE_MODE:-good}"
days="${XPF_TEST_VALID_DAYS:-365}"
[ "$mode" = "missing-file" ] && exit 0
rel="$base/dists/$suite/Release"
mkdir -p "$(dirname "$rel")"
now=$(date -u +%s)
datestr=$(date -u -d "@$now" +"%a, %d %b %Y %H:%M:%S UTC")
goodstr=$(date -u -d "@$((now + days * 86400))" +"%a, %d %b %Y %H:%M:%S UTC")
skewstr=$(date -u -d "@$((now + (days - 1) * 86400))" +"%a, %d %b %Y %H:%M:%S UTC")
offstr=$(date -u -d "@$((now + days * 86400 + 1))" +"%a, %d %b %Y %H:%M:%S UTC")
{
    echo "Origin: xpf"
    echo "Label: xpf"
    echo "Suite: $suite"
    echo "Codename: $suite"
    case "$mode" in
        missing-date) ;;
        dup-date) echo "Date: $datestr"; echo "Date: $datestr" ;;
        *) echo "Date: $datestr" ;;
    esac
    case "$mode" in
        missing-vu) ;;
        dup-vu) echo "Valid-Until: $goodstr"; echo "Valid-Until: $goodstr" ;;
        skewed-vu) echo "Valid-Until: $skewstr" ;;
        offbyone-vu) echo "Valid-Until: $offstr" ;;
        *) echo "Valid-Until: $goodstr" ;;
    esac
    echo "Architectures: amd64"
    echo "Components: main"
} > "$rel"
"""


def _build(outdir, debs, extra_env, path_prefix=None):
    """Run the builder via the reprepro path; return (rc, combined_output)."""
    env = dict(os.environ)
    for var in ("XPF_APT_COMPONENT", "XPF_APT_ARCH", "XPF_APT_ORIGIN",
                "XPF_APT_SUITE", "XPF_APT_TOOL", "XPF_GPG_KEY",
                "XPF_APT_VALID_DAYS", "XPF_TEST_RELEASE_MODE",
                "XPF_TEST_VALID_DAYS"):
        env.pop(var, None)
    env.update(extra_env)
    if path_prefix is not None:
        env["PATH"] = path_prefix + os.pathsep + env.get("PATH", "")
    p = subprocess.run(
        ["sh", str(_BUILDER), "--out", outdir, "--suite", "stable",
         "--debs", debs],
        capture_output=True, text=True, env=env, timeout=180)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _release_text(outdir):
    rel = Path(outdir) / "apt" / "dists" / "stable" / "Release"
    if not rel.is_file():
        return None
    return rel.read_text()


class ShimRepreproTests(unittest.TestCase):
    """Post-hoc assert cells driven by the fake reprepro (run everywhere)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-repo10123-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        bindir = os.path.join(self.dir, "bin")
        os.makedirs(bindir)
        shim = os.path.join(bindir, "reprepro")
        Path(shim).write_text(_SHIM)
        os.chmod(shim, 0o755)
        self.bindir = bindir
        # The shim ignores deb bytes; a missing path proves the assert (not
        # deb handling) is what these cells exercise.
        self.fakedeb = os.path.join(self.dir, "fake.deb")

    def _run(self, mode, days="7"):
        outdir = os.path.join(self.dir, "out-" + mode)
        os.makedirs(outdir, exist_ok=True)
        return outdir, _build(outdir, self.fakedeb, {
            "XPF_APT_TOOL": "reprepro",
            "XPF_GPG_KEY": "TESTKEY10123",
            "XPF_APT_VALID_DAYS": days,
            "XPF_TEST_RELEASE_MODE": mode,
            "XPF_TEST_VALID_DAYS": days,
        }, path_prefix=self.bindir)

    def test_good_emission_accepted(self):
        outdir, (rc, out) = self._run("good")
        self.assertEqual(rc, 0, out[-800:])
        text = _release_text(outdir)
        self.assertIsNotNone(text, "no Release emitted")
        lines = [ln for ln in text.splitlines()
                 if ln.startswith("Valid-Until:")]
        self.assertEqual(len(lines), 1)
        date_line = next(ln for ln in text.splitlines()
                         if ln.startswith("Date:"))
        vu_epoch = email.utils.parsedate_to_datetime(
            lines[0][len("Valid-Until:"):].strip()).timestamp()
        date_epoch = email.utils.parsedate_to_datetime(
            date_line[len("Date:"):].strip()).timestamp()
        self.assertEqual(vu_epoch, date_epoch + 7 * 86400)

    def test_default_horizon_good_emission_accepted(self):
        # Neither knob set: builder defaults to 365d, shim mirrors it.
        outdir = os.path.join(self.dir, "out-default")
        os.makedirs(outdir, exist_ok=True)
        rc, out = _build(outdir, self.fakedeb, {
            "XPF_APT_TOOL": "reprepro",
            "XPF_GPG_KEY": "TESTKEY10123",
        }, path_prefix=self.bindir)
        self.assertEqual(rc, 0, out[-800:])
        text = _release_text(outdir)
        self.assertEqual(sum(1 for ln in text.splitlines()
                             if ln.startswith("Valid-Until:")), 1)

    def test_duplicate_valid_until_refused(self):
        _outdir, (rc, out) = self._run("dup-vu")
        self.assertNotEqual(rc, 0,
                            "duplicate Valid-Until shipped silently (no assert?)")
        self.assertIn("exactly 1", out)

    def test_missing_valid_until_refused(self):
        # Mirrors real reprepro ValidFor 0d behavior (emits no Valid-Until):
        # fail closed, never an unstamped repo.
        _outdir, (rc, out) = self._run("missing-vu")
        self.assertNotEqual(rc, 0,
                            "missing Valid-Until shipped silently (no assert?)")
        self.assertIn("exactly 1", out)

    def test_skewed_valid_until_refused(self):
        # Emitted horizon is a day short of the ValidFor knob.
        _outdir, (rc, out) = self._run("skewed-vu")
        self.assertNotEqual(rc, 0,
                            "skewed Valid-Until shipped silently (no assert?)")
        self.assertIn("ValidFor-derived", out)

    def test_offbyone_valid_until_refused(self):
        # Exactness pin: +1s is not equal — the assert allows no tolerance
        # slop (skew is eliminated by Date-derivation, not absorbed).
        _outdir, (rc, out) = self._run("offbyone-vu")
        self.assertNotEqual(rc, 0, "+1s Valid-Until accepted (tolerance slop?)")
        self.assertIn("ValidFor-derived", out)

    def test_duplicate_date_refused(self):
        _outdir, (rc, out) = self._run("dup-date")
        self.assertNotEqual(rc, 0,
                            "duplicate Date shipped silently (no assert?)")
        self.assertIn("exactly 1", out)

    def test_missing_date_refused(self):
        _outdir, (rc, out) = self._run("missing-date")
        self.assertNotEqual(rc, 0,
                            "missing Date shipped silently (no assert?)")
        self.assertIn("exactly 1", out)

    def test_missing_release_file_refused(self):
        _outdir, (rc, out) = self._run("missing-file")
        self.assertNotEqual(rc, 0,
                            "missing Release shipped silently (no assert?)")
        self.assertIn("emitted no Release", out)


@unittest.skipUnless(_HAS_REAL_REPREPRO,
                     "needs reprepro + gpg + dpkg-deb for a real build")
class RealRepreproTests(unittest.TestCase):
    """End-to-end cells against the real reprepro + throwaway GPG key."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-repo10123real-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.gnupg = os.path.join(self.dir, "gnupg")
        os.makedirs(self.gnupg, mode=0o700)
        env = dict(os.environ, GNUPGHOME=self.gnupg)
        batch = os.path.join(self.dir, "gpg-batch")
        Path(batch).write_text(
            "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
            "Key-Usage: sign\nName-Real: xpf 10123 test\n"
            "Name-Email: test10123@xpf.invalid\nExpire-Date: 0\n%commit\n")
        subprocess.run(["gpg", "--batch", "--gen-key", batch], check=True,
                       capture_output=True, env=env, timeout=120)
        keys = subprocess.run(
            ["gpg", "--batch", "--list-keys", "--with-colons",
             "test10123@xpf.invalid"],
            capture_output=True, text=True, env=env, timeout=60)
        fpr = next((ln.split(":")[9] for ln in keys.stdout.splitlines()
                    if ln.startswith("fpr:")), "")
        self.assertTrue(fpr, "key generation failed")
        self.fpr = fpr
        self.env = env
        # reprepro requires a Section field on the .deb (else it skips it).
        pkgdir = os.path.join(self.dir, "pkg")
        debdir = os.path.join(pkgdir, "DEBIAN")
        os.makedirs(debdir, exist_ok=True)
        Path(os.path.join(debdir, "control")).write_text(
            "Package: xpf-appliance\nVersion: 0.0.0-10123\nSection: admin\n"
            "Priority: optional\nArchitecture: amd64\n"
            "Maintainer: t <t@x.invalid>\nDescription: 10123 fixture\n")
        self.deb = os.path.join(self.dir, "xpf-appliance_0.0.0-10123_amd64.deb")
        subprocess.run(["dpkg-deb", "--build", pkgdir, self.deb], check=True,
                       capture_output=True, timeout=60)

    def _run_real(self, days):
        outdir = os.path.join(self.dir, "out-" + days)
        os.makedirs(outdir, exist_ok=True)
        env = dict(self.env)
        for var in ("XPF_APT_COMPONENT", "XPF_APT_ARCH", "XPF_APT_ORIGIN",
                    "XPF_APT_SUITE", "XPF_APT_TOOL", "XPF_GPG_KEY",
                    "XPF_APT_VALID_DAYS"):
            env.pop(var, None)
        env.update({"XPF_APT_TOOL": "reprepro", "XPF_GPG_KEY": self.fpr,
                    "XPF_APT_VALID_DAYS": days})
        p = subprocess.run(
            ["sh", str(_BUILDER), "--out", outdir, "--suite", "stable",
             "--debs", self.deb],
            capture_output=True, text=True, env=env, timeout=180)
        return outdir, p.returncode, (p.stdout or "") + (p.stderr or "")

    def test_real_reprepro_emission_passes_assert(self):
        outdir, rc, out = self._run_real("7")
        self.assertEqual(rc, 0, out[-800:])
        text = _release_text(outdir)
        self.assertIsNotNone(text, "no Release emitted")
        lines = [ln for ln in text.splitlines()
                 if ln.startswith("Valid-Until:")]
        self.assertEqual(len(lines), 1,
                         f"want exactly one Valid-Until, got {lines}")
        date_line = next(ln for ln in text.splitlines()
                         if ln.startswith("Date:"))
        vu_epoch = email.utils.parsedate_to_datetime(
            lines[0][len("Valid-Until:"):].strip()).timestamp()
        date_epoch = email.utils.parsedate_to_datetime(
            date_line[len("Date:"):].strip()).timestamp()
        self.assertEqual(vu_epoch, date_epoch + 7 * 86400)
        suite_dir = Path(outdir) / "apt" / "dists" / "stable"
        self.assertTrue((suite_dir / "InRelease").is_file(),
                        "reprepro did not sign (no InRelease)")
        self.assertTrue((suite_dir / "Release.gpg").is_file(),
                        "reprepro did not sign (no Release.gpg)")

    def test_real_reprepro_zero_horizon_refused(self):
        # ValidFor 0d: real reprepro emits NO Valid-Until and the count
        # assert refuses — fail-closed parity with the flat 0-horizon cell.
        _outdir, rc, out = self._run_real("0")
        self.assertNotEqual(rc, 0, "unstamped real repo shipped silently")
        self.assertIn("exactly 1", out)


if __name__ == "__main__":
    unittest.main()
