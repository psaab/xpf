#!/usr/bin/env python3
"""Regression tests for psaab/xpf#15277 — publish.gate_apt never read the
signed Valid-Until/Date, so an expired (or imminently expiring) suite in
the dist tree passed the gate and was published, after which apt clients
refused the channel.

RED on base: `publish` has no `_gate_apt_freshness` / margin helper at all
and `gate_apt` accepts an expired signed suite. GREEN after: every suite's
SIGNED cleartext (gpg --decrypt output, never the unsigned on-disk Release)
must carry exactly one parseable Date and Valid-Until, Valid-Until after
Date, Date within the 5-minute future skew, Valid-Until unexpired, and
Valid-Until more than the margin away (default 7 days via
XPF_APT_FRESHNESS_MARGIN_SECONDS; 0 disables only the margin).

Tamper control: rewriting the UNSIGNED on-disk Release to look fresh must
not rescue an expired signed suite — the gate judges verified bytes only.
Fresh control: a freshly built suite passes with the signed bytes intact.
"""

from __future__ import annotations

import email.utils
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_DIST = Path(__file__).resolve().parent
_BUILDER = _DIST / "build-apt-repo.sh"
_SPEC = importlib.util.spec_from_file_location(
    "publish_15277", _DIST / "publish.py")
publish = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(publish)

_HAVE_TOOLS = bool(shutil.which("gpg") and shutil.which("dpkg-deb")
                   and shutil.which("apt-ftparchive"))

DAY = 86400
# Fixed "now" for deterministic unit cells: 2026-01-15T00:00:00Z.
NOW = 1768435200.0


def _fmt(epoch):
    return email.utils.formatdate(epoch, usegmt=True)


def _release(date_epoch, vu_epoch, extra=""):
    return (f"Origin: xpf\nLabel: xpf\nSuite: stable\nCodename: stable\n"
            f"Date: {_fmt(date_epoch)}\n"
            + (f"Valid-Until: {_fmt(vu_epoch)}\n" if vu_epoch is not None else "")
            + extra)


class FreshnessUnitTests(unittest.TestCase):
    """Deterministic cells against _gate_apt_freshness with injected now."""

    def test_fresh_suite_passes(self):
        publish._gate_apt_freshness(
            "stable", _release(NOW - DAY, NOW + 30 * DAY), now=NOW)

    def test_expired_suite_refused(self):
        with self.assertRaisesRegex(SystemExit, "EXPIRED"):
            publish._gate_apt_freshness(
                "stable", _release(NOW - 400 * DAY, NOW - DAY), now=NOW)

    def test_expiring_within_default_margin_refused(self):
        with self.assertRaisesRegex(SystemExit, "freshness margin"):
            publish._gate_apt_freshness(
                "edge", _release(NOW - DAY, NOW + 3 * DAY), now=NOW)

    def test_margin_zero_disables_only_the_margin(self):
        # 0 margin: a suite hours from expiry passes, an expired one refuses.
        publish._gate_apt_freshness(
            "stable", _release(NOW - DAY, NOW + 3600), now=NOW, margin=0)
        with self.assertRaisesRegex(SystemExit, "EXPIRED"):
            publish._gate_apt_freshness(
                "stable", _release(NOW - 2 * DAY, NOW - 1), now=NOW, margin=0)

    def test_custom_margin_boundary(self):
        # Exactly at the margin boundary refuses; one second past passes.
        with self.assertRaisesRegex(SystemExit, "freshness margin"):
            publish._gate_apt_freshness(
                "stable", _release(NOW - DAY, NOW + 100), now=NOW, margin=100)
        publish._gate_apt_freshness(
            "stable", _release(NOW - DAY, NOW + 101), now=NOW, margin=100)

    def test_missing_valid_until_refused(self):
        with self.assertRaisesRegex(SystemExit, "Valid-Until"):
            publish._gate_apt_freshness(
                "stable", _release(NOW - DAY, None), now=NOW)

    def test_missing_date_refused(self):
        text = f"Valid-Until: {_fmt(NOW + 30 * DAY)}\n"
        with self.assertRaisesRegex(SystemExit, "Date"):
            publish._gate_apt_freshness("stable", text, now=NOW)

    def test_duplicate_valid_until_refused(self):
        text = _release(NOW - DAY, NOW + 30 * DAY,
                        extra=f"Valid-Until: {_fmt(NOW + 31 * DAY)}\n")
        with self.assertRaisesRegex(SystemExit, "exactly 1"):
            publish._gate_apt_freshness("stable", text, now=NOW)

    def test_duplicate_date_refused(self):
        text = _release(NOW - DAY, NOW + 30 * DAY,
                        extra=f"Date: {_fmt(NOW - DAY)}\n")
        with self.assertRaisesRegex(SystemExit, "exactly 1"):
            publish._gate_apt_freshness("stable", text, now=NOW)

    def test_malformed_valid_until_refused(self):
        text = _release(NOW - DAY, NOW + 30 * DAY).replace(
            _fmt(NOW + 30 * DAY), "not-a-date")
        with self.assertRaisesRegex(SystemExit, "unparseable"):
            publish._gate_apt_freshness("stable", text, now=NOW)

    def test_valid_until_not_after_date_refused(self):
        with self.assertRaisesRegex(SystemExit, "not after"):
            publish._gate_apt_freshness(
                "stable", _release(NOW - DAY, NOW - DAY), now=NOW)

    def test_future_date_beyond_skew_refused(self):
        with self.assertRaisesRegex(SystemExit, "in the future"):
            publish._gate_apt_freshness(
                "stable", _release(NOW + 3600, NOW + 31 * DAY), now=NOW)

    def test_future_date_within_skew_passes(self):
        publish._gate_apt_freshness(
            "stable", _release(NOW + 240, NOW + 30 * DAY), now=NOW)

    def test_margin_env_parsing(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(publish.APT_FRESHNESS_MARGIN_ENV, None)
            self.assertEqual(publish._apt_freshness_margin(),
                             publish.APT_FRESHNESS_MARGIN_DEFAULT)
        with patch.dict(os.environ,
                        {publish.APT_FRESHNESS_MARGIN_ENV: "0"}):
            self.assertEqual(publish._apt_freshness_margin(), 0)
        with patch.dict(os.environ,
                        {publish.APT_FRESHNESS_MARGIN_ENV: "3600"}):
            self.assertEqual(publish._apt_freshness_margin(), 3600)
        for bad in ("-1", "1.5", "7d", "abc", " 60", str(366 * DAY)):
            with self.subTest(bad=bad):
                with patch.dict(os.environ,
                                {publish.APT_FRESHNESS_MARGIN_ENV: bad}):
                    with self.assertRaises(SystemExit):
                        publish._apt_freshness_margin()


@unittest.skipUnless(_HAVE_TOOLS,
                     "needs gpg + dpkg-deb + apt-ftparchive for signed fixtures")
class GateAptFreshnessTests(unittest.TestCase):
    """End-to-end gate_apt cells over real signed flat suites."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xpf-apt15277-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.gnupg = self.root / "gnupg"
        self.gnupg.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(self.gnupg))
        batch = self.root / "gpg-batch"
        batch.write_text(
            "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
            "Key-Usage: sign\nName-Real: xpf 15277 test\n"
            "Name-Email: test15277@xpf.invalid\nExpire-Date: 0\n%commit\n")
        subprocess.run(["gpg", "--batch", "--gen-key", str(batch)],
                       check=True, capture_output=True, env=env, timeout=120)
        keys = subprocess.run(
            ["gpg", "--batch", "--list-keys", "--with-colons",
             "test15277@xpf.invalid"],
            capture_output=True, text=True, env=env, timeout=60)
        self.fpr = next(ln.split(":")[9] for ln in keys.stdout.splitlines()
                        if ln.startswith("fpr:"))
        self.archive_pub = self.root / "archive.asc"
        self.archive_pub.write_bytes(subprocess.run(
            ["gpg", "--batch", "--armor", "--export", self.fpr],
            capture_output=True, check=True, env=env, timeout=60).stdout)
        self.env = env

    def _deb(self, version="0.0.1+g1527701"):
        pkgdir = self.root / "pkg"
        (pkgdir / "DEBIAN").mkdir(parents=True, exist_ok=True)
        (pkgdir / "DEBIAN" / "control").write_text(
            f"Package: xpf\nVersion: {version}\nArchitecture: amd64\n"
            "Maintainer: t <t@x.invalid>\nDescription: 15277 fixture\n")
        keydir = pkgdir / "usr/share/keyrings"
        keydir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.archive_pub,
                        keydir / "xpf-archive-keyring.asc")
        deb = self.root / f"xpf_{version}_amd64.deb"
        subprocess.run(["dpkg-deb", "--build", str(pkgdir), str(deb)],
                       check=True, capture_output=True, timeout=60)
        return deb

    def _build(self, outdir, suite, valid_days="365"):
        env = dict(self.env)
        env.update({"XPF_GPG_KEY": self.fpr,
                    "XPF_APT_VALID_DAYS": valid_days})
        p = subprocess.run(
            ["sh", str(_BUILDER), "--out", str(outdir), "--suite", suite,
             "--debs", str(self._deb())],
            capture_output=True, text=True, env=env, timeout=180)
        self.assertEqual(p.returncode, 0, (p.stdout or "") + (p.stderr or ""))

    def _resign_suite(self, outdir, suite, date_epoch, vu_epoch):
        """Rewrite a suite's Release dates and re-sign with the test key.

        This is how a stale suite reaches the gate: validly signed, but
        with a Date/Valid-Until in the past. Packages checksums are
        untouched, so only freshness can refuse."""
        suite_dir = Path(outdir) / "apt" / "dists" / suite
        release = suite_dir / "Release"
        lines = []
        for line in release.read_text().splitlines():
            if line.startswith("Date:"):
                line = f"Date: {_fmt(date_epoch)}"
            elif line.startswith("Valid-Until:"):
                line = f"Valid-Until: {_fmt(vu_epoch)}"
            lines.append(line)
        release.write_text("\n".join(lines) + "\n")
        for args, out in (
                (["--clearsign", "-o", str(suite_dir / "InRelease")],
                 None),
                (["-abs", "-o", str(suite_dir / "Release.gpg")], None)):
            subprocess.run(
                ["gpg", "--batch", "--yes", "--local-user", self.fpr,
                 *args, str(release)],
                check=True, capture_output=True, env=self.env, timeout=60)

    def _gate(self, outdir, channel="stable", now=None, env_extra=None):
        env = {"XPF_ARCHIVE_PUBKEY": str(self.archive_pub)}
        env.update(env_extra or {})
        with patch.dict(os.environ, env):
            return publish.gate_apt(str(outdir), channel, None, now=now)

    def test_fresh_signed_suite_passes(self):
        outdir = self.root / "out-fresh"
        self._build(outdir, "stable")
        self._gate(outdir)  # must not raise

    def test_expired_non_target_suite_refused(self):
        # The issue's exact cell: target fresh, a stale NON-target suite
        # in the same tree must refuse the whole publish.
        outdir = self.root / "out-expired-edge"
        self._build(outdir, "stable")
        self._build(outdir, "edge")
        import time as _time
        now = _time.time()
        self._resign_suite(outdir, "edge", now - 400 * DAY, now - DAY)
        with self.assertRaisesRegex(SystemExit, "EXPIRED"):
            self._gate(outdir)

    def test_unsigned_release_tamper_does_not_rescue_expired_suite(self):
        # Attacker/operator edits the UNSIGNED on-disk Release to look
        # fresh; the signed InRelease still says expired -> refused.
        outdir = self.root / "out-tampered"
        self._build(outdir, "stable")
        import time as _time
        now = _time.time()
        self._resign_suite(outdir, "stable", now - 400 * DAY, now - DAY)
        release = Path(outdir) / "apt" / "dists" / "stable" / "Release"
        text = release.read_text()
        lines = []
        for line in text.splitlines():
            if line.startswith("Date:"):
                line = f"Date: {_fmt(now)}"
            elif line.startswith("Valid-Until:"):
                line = f"Valid-Until: {_fmt(now + 365 * DAY)}"
            lines.append(line)
        release.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(SystemExit, "EXPIRED"):
            self._gate(outdir)

    def test_expiring_within_margin_refused_and_margin_zero_allows(self):
        outdir = self.root / "out-margin"
        self._build(outdir, "stable")
        import time as _time
        now = _time.time()
        # Valid-Until 3 days out: inside the 7-day default margin.
        self._resign_suite(outdir, "stable", now - DAY, now + 3 * DAY)
        with self.assertRaisesRegex(SystemExit, "freshness margin"):
            self._gate(outdir, now=now)
        # Margin disabled via env: the same suite passes (not expired).
        self._gate(outdir, now=now,
                   env_extra={publish.APT_FRESHNESS_MARGIN_ENV: "0"})


if __name__ == "__main__":
    unittest.main()
