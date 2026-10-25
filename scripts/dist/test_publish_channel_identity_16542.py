#!/usr/bin/env python3
"""Regression tests for psaab/xpf#16542 — publish gates passed mis-synced
channel identity: _gate_one_latest never checked data["channel"] == channel,
and gate_apt never compared a suite's signed Suite/Codename with dists/<suite>.

A signed edge pointer copied to stable/latest.json (or a signed Release
naming Suite: edge served from dists/stable/) verifies perfectly — the same
key signs every channel — so the gate reported PASSED and uploaded bytes
every client then refuses.

RED on base: wrong-channel and missing-channel pointers pass _gate_one_latest;
wrong/missing/duplicate Suite or Codename pass _gate_apt_suite_identity
(absent on base) and end-to-end gate_apt. GREEN after: both gates refuse,
genuine pointers/suites pass.
"""

from __future__ import annotations

import email.utils
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_DIST = Path(__file__).resolve().parent
_BUILDER = _DIST / "build-apt-repo.sh"
sys.path.insert(0, str(_DIST))
import sign  # noqa: E402

publish = load_subject("publish_16542", _DIST / "publish.py")

_HAVE_MINISIGN = bool(shutil.which("minisign"))
_HAVE_TOOLS = bool(shutil.which("gpg") and shutil.which("dpkg-deb")
                   and shutil.which("apt-ftparchive"))

DAY = 86400


def _fmt(epoch):
    return email.utils.formatdate(epoch, usegmt=True)


def _release(suite_line="Suite: stable", codename_line="Codename: stable"):
    now = time.time()
    lines = ["Origin: xpf", "Label: xpf"]
    if suite_line is not None:
        lines.append(suite_line)
    if codename_line is not None:
        lines.append(codename_line)
    lines.append(f"Date: {_fmt(now - DAY)}")
    lines.append(f"Valid-Until: {_fmt(now + 30 * DAY)}")
    return "\n".join(lines) + "\n"


class SuiteIdentityUnitTests(unittest.TestCase):
    """Deterministic cells against _gate_apt_suite_identity."""

    def test_matching_suite_passes(self):
        publish._gate_apt_suite_identity("stable", _release())

    def test_wrong_suite_refused(self):
        with self.assertRaisesRegex(SystemExit, "Suite is 'edge'"):
            publish._gate_apt_suite_identity(
                "stable", _release(suite_line="Suite: edge"))

    def test_wrong_codename_refused(self):
        with self.assertRaisesRegex(SystemExit, "Codename is 'edge'"):
            publish._gate_apt_suite_identity(
                "stable", _release(codename_line="Codename: edge"))

    def test_missing_suite_refused(self):
        with self.assertRaisesRegex(SystemExit, "0 Suite fields"):
            publish._gate_apt_suite_identity(
                "stable", _release(suite_line=None))

    def test_missing_codename_refused(self):
        with self.assertRaisesRegex(SystemExit, "0 Codename fields"):
            publish._gate_apt_suite_identity(
                "stable", _release(codename_line=None))

    def test_duplicate_suite_refused(self):
        text = _release().replace(
            "Suite: stable\n", "Suite: stable\nSuite: stable\n")
        with self.assertRaisesRegex(SystemExit, "2 Suite fields"):
            publish._gate_apt_suite_identity("stable", text)

    def test_duplicate_codename_refused(self):
        text = _release().replace(
            "Codename: stable\n", "Codename: stable\nCodename: stable\n")
        with self.assertRaisesRegex(SystemExit, "2 Codename fields"):
            publish._gate_apt_suite_identity("stable", text)

    def test_continuation_line_not_a_field(self):
        # A wrapped checksum-style continuation must not be parsed as a
        # second Suite field.
        text = _release() + " Suite: edge\n"
        publish._gate_apt_suite_identity("stable", text)


@unittest.skipUnless(_HAVE_MINISIGN, "needs minisign for signed pointers")
class GateLatestChannelTests(unittest.TestCase):
    """Signed latest.json cells through the real _gate_one_latest."""

    VER = "1.2.3"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-16542-latest-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pub = self.tmp / "image.pub"
        self.sec = self.tmp / "image.sec"
        subprocess.run(
            ["minisign", "-G", "-W", "-p", str(self.pub), "-s", str(self.sec)],
            check=True, capture_output=True)
        self.dist = self.tmp / "dist"
        self.dist.mkdir()

    def _write_pointer(self, served_channel, data):
        cdir = self.dist / served_channel
        cdir.mkdir(parents=True, exist_ok=True)
        latest = cdir / "latest.json"
        latest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        sign.sign_manifest(str(latest), [str(self.sec)])
        return latest

    def _fresh_date(self):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _gate(self, channel, require=None):
        return publish._gate_one_latest(
            str(self.dist), channel, str(self.pub), require)

    def test_genuine_pointer_passes(self):
        self._write_pointer("stable", {
            "channel": "stable", "version": self.VER,
            "manifest": f"xpf-{self.VER}.SHA256SUMS",
            "date": self._fresh_date()})
        self.assertEqual(self._gate("stable", {self.VER}), self.VER)

    def test_wrong_channel_pointer_refused(self):
        # The issue's defect cell: signed edge pointer at stable/.
        self._write_pointer("stable", {
            "channel": "edge", "version": self.VER,
            "manifest": f"xpf-{self.VER}.SHA256SUMS",
            "date": self._fresh_date()})
        with self.assertRaisesRegex(SystemExit, "channel field 'edge'"):
            self._gate("stable", {self.VER})

    def test_missing_channel_pointer_refused(self):
        self._write_pointer("stable", {
            "version": self.VER,
            "manifest": f"xpf-{self.VER}.SHA256SUMS",
            "date": self._fresh_date()})
        with self.assertRaisesRegex(SystemExit, "channel field None"):
            self._gate("stable", {self.VER})

    def test_non_target_wrong_channel_refused_via_gate_latest(self):
        self._write_pointer("stable", {
            "channel": "stable", "version": self.VER,
            "manifest": f"xpf-{self.VER}.SHA256SUMS",
            "date": self._fresh_date()})
        self._write_pointer("edge", {
            "channel": "stable", "version": self.VER,
            "manifest": f"xpf-{self.VER}.SHA256SUMS",
            "date": self._fresh_date()})
        with self.assertRaisesRegex(SystemExit, "channel field 'stable'"):
            publish.gate_latest(str(self.dist), "stable", {self.VER},
                                str(self.pub))


@unittest.skipUnless(_HAVE_TOOLS,
                     "needs gpg + dpkg-deb + apt-ftparchive for signed fixtures")
class GateAptSuiteIdentityTests(unittest.TestCase):
    """End-to-end gate_apt cells over real signed flat suites."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xpf-16542-apt-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.gnupg = self.root / "gnupg"
        self.gnupg.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(self.gnupg))
        batch = self.root / "gpg-batch"
        batch.write_text(
            "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
            "Key-Usage: sign\nName-Real: xpf 16542 test\n"
            "Name-Email: test16542@xpf.invalid\nExpire-Date: 0\n%commit\n")
        subprocess.run(["gpg", "--batch", "--gen-key", str(batch)],
                       check=True, capture_output=True, env=env, timeout=120)
        keys = subprocess.run(
            ["gpg", "--batch", "--list-keys", "--with-colons",
             "test16542@xpf.invalid"],
            capture_output=True, text=True, env=env, timeout=60)
        self.fpr = next(ln.split(":")[9] for ln in keys.stdout.splitlines()
                        if ln.startswith("fpr:"))
        self.archive_pub = self.root / "archive.asc"
        self.archive_pub.write_bytes(subprocess.run(
            ["gpg", "--batch", "--armor", "--export", self.fpr],
            capture_output=True, check=True, env=env, timeout=60).stdout)
        self.env = env

    def _deb(self, version="0.0.1+g1654201"):
        pkgdir = self.root / "pkg"
        (pkgdir / "DEBIAN").mkdir(parents=True, exist_ok=True)
        (pkgdir / "DEBIAN" / "control").write_text(
            f"Package: xpf\nVersion: {version}\nArchitecture: amd64\n"
            "Maintainer: t <t@x.invalid>\nDescription: 16542 fixture\n")
        keydir = pkgdir / "usr/share/keyrings"
        keydir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.archive_pub,
                        keydir / "xpf-archive-keyring.asc")
        deb = self.root / f"xpf_{version}_amd64.deb"
        subprocess.run(["dpkg-deb", "--build", str(pkgdir), str(deb)],
                       check=True, capture_output=True, timeout=60)
        return deb

    def _build(self, outdir, suite):
        env = dict(self.env)
        env.update({"XPF_GPG_KEY": self.fpr, "XPF_APT_VALID_DAYS": "365"})
        p = subprocess.run(
            ["sh", str(_BUILDER), "--out", str(outdir), "--suite", suite,
             "--debs", str(self._deb())],
            capture_output=True, text=True, env=env, timeout=180)
        self.assertEqual(p.returncode, 0, (p.stdout or "") + (p.stderr or ""))

    def _resign_suite_as(self, outdir, served_suite, named_suite):
        """Rewrite served_suite's Release identity to named_suite and re-sign.

        This is how a mis-synced suite reaches the gate: validly signed,
        but naming another suite. Packages checksums are untouched, so
        only the identity check can refuse."""
        suite_dir = Path(outdir) / "apt" / "dists" / served_suite
        release = suite_dir / "Release"
        lines = []
        for line in release.read_text().splitlines():
            if line.startswith("Suite:"):
                line = f"Suite: {named_suite}"
            elif line.startswith("Codename:"):
                line = f"Codename: {named_suite}"
            lines.append(line)
        release.write_text("\n".join(lines) + "\n")
        for args in (["--clearsign", "-o", str(suite_dir / "InRelease")],
                     ["-abs", "-o", str(suite_dir / "Release.gpg")]):
            subprocess.run(
                ["gpg", "--batch", "--yes", "--local-user", self.fpr,
                 *args, str(release)],
                check=True, capture_output=True, env=self.env, timeout=60)

    def _gate(self, outdir, channel="stable"):
        with patch.dict(os.environ,
                        {"XPF_ARCHIVE_PUBKEY": str(self.archive_pub)}):
            return publish.gate_apt(str(outdir), channel, None)

    def test_genuine_suite_passes(self):
        outdir = self.root / "out-genuine"
        self._build(outdir, "stable")
        self._gate(outdir)  # must not raise

    def test_misnamed_target_suite_refused(self):
        # Acceptance cell: dists/stable signed Suite: edge is refused.
        outdir = self.root / "out-misnamed"
        self._build(outdir, "stable")
        self._resign_suite_as(outdir, "stable", "edge")
        with self.assertRaisesRegex(SystemExit, "Suite is 'edge'"):
            self._gate(outdir)

    def test_misnamed_non_target_suite_refused(self):
        outdir = self.root / "out-misnamed-edge"
        self._build(outdir, "stable")
        self._build(outdir, "edge")
        self._resign_suite_as(outdir, "edge", "stable")
        with self.assertRaisesRegex(SystemExit, "Suite is 'stable'"):
            self._gate(outdir)


if __name__ == "__main__":
    unittest.main()
