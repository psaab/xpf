#!/usr/bin/env python3
"""Regressions for persistent APT channel binding (#11133)."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_INSTALLSH = _DIST / "install.sh"
_PIN_MARKER = "# xpf appliance channel pin; Managed by install.sh (#11133)"


def _target(source: Path, suite: str, codename: str) -> str:
    return ("MetaKey: main/binary-amd64/Packages\n"
            f"Sourcesentry: {source}:1\nSuite: {suite}\nCodename: {codename}\n")


class InstallerPinLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xpf-apt-pin-11133-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bindir = self.root / "bin"
        self.bindir.mkdir()
        self.src = self.root / "sources" / "xpf.sources"
        self.pin = self.root / "preferences.d" / "xpf-channel.pref"
        self.targets = self.root / "targets"
        self.calls = self.root / "calls"
        apt_get = self.bindir / "apt-get"
        apt_get.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  update) echo update >> \"$XPF_TEST_CALLS\" ;;\n"
            "  indextargets) echo indextargets >> \"$XPF_TEST_CALLS\"; cat \"$XPF_TEST_TARGETS\" ;;\n"
            "  install)\n"
            "    echo install >> \"$XPF_TEST_CALLS\"\n"
            "    [ -f \"$XPF_TEST_PIN\" ] || { echo 'pin missing before install' >&2; exit 91; }\n"
            "    grep -Fqx \"$XPF_TEST_MARKER\" \"$XPF_TEST_PIN\" || { echo 'pin marker missing before install' >&2; exit 92; }\n"
            "    exit \"$XPF_TEST_INSTALL_RC\" ;;\n"
            "  *) exit 99 ;;\n"
            "esac\n")
        apt_get.chmod(0o755)

    def _run_install(self, suite="stable", codename="stable", install_rc=0):
        self.targets.write_text(_target(self.src, suite, codename))
        env = dict(os.environ)
        env.update({
            "XPF_INSTALL_SOURCE_ONLY": "1",
            "XPF_TEST_TARGETS": str(self.targets),
            "XPF_TEST_CALLS": str(self.calls),
            "XPF_TEST_PIN": str(self.pin),
            "XPF_TEST_MARKER": _PIN_MARKER,
            "XPF_TEST_INSTALL_RC": str(install_rc),
            "PATH": str(self.bindir) + os.pathsep + env.get("PATH", ""),
        })
        script = (
            '. "$1"; CHANNEL=stable; DRY=0; SRC="$2"; PIN="$3"; '
            'do_install; INSTALL_OK=1'
        )
        return subprocess.run(
            ["sh", "-c", script, "sh", str(_INSTALLSH), str(self.src), str(self.pin)],
            capture_output=True, text=True, env=env, timeout=30)

    def test_pin_is_written_after_verification_and_before_install(self):
        result = self._run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls.read_text().splitlines(),
                         ["update", "indextargets", "install"])
        pin = self.pin.read_text()
        self.assertIn(_PIN_MARKER, pin)
        self.assertIn("Pin: release a=stable,n=stable\nPin-Priority: 990", pin)
        self.assertLess(pin.index("Pin-Priority: 990"), pin.index("Pin: release a=*"))
        self.assertLess(pin.index("Pin: release a=*"), pin.index("Pin: release n=*"))
        self.assertEqual(self.pin.stat().st_mode & 0o777, 0o644)
        self.assertEqual(list(self.pin.parent.glob(".xpf-channel.pref.*")), [])

    def test_channel_mismatch_fails_before_pin_or_package_install(self):
        result = self._run_install(suite="edge", codename="edge")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("does not match selected channel", result.stdout + result.stderr)
        self.assertEqual(self.calls.read_text().splitlines(), ["update", "indextargets"])
        self.assertFalse(self.pin.exists())

    def test_unmanaged_preferences_are_preserved_and_block_install(self):
        self.pin.parent.mkdir(parents=True)
        original = "# administrator-owned policy\nPackage: xpf*\nPin-Priority: 700\n"
        self.pin.write_text(original)
        result = self._run_install()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("refusing to replace unmanaged", result.stdout + result.stderr)
        self.assertEqual(self.pin.read_text(), original)
        self.assertEqual(self.calls.read_text().splitlines(), ["update", "indextargets"])

    def test_failed_first_install_removes_new_pin(self):
        result = self._run_install(install_rc=73)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.pin.exists())
        self.assertEqual(self.calls.read_text().splitlines(),
                         ["update", "indextargets", "install"])
        self.assertEqual(list(self.pin.parent.glob(".xpf-channel.pref.*")), [])

    def test_failed_channel_rebind_restores_marked_pin_byte_for_byte(self):
        self.pin.parent.mkdir(parents=True)
        original = (_PIN_MARKER + "\n\nPackage: xpf*\n"
                    "Pin: release a=edge,n=edge\nPin-Priority: 990\n")
        self.pin.write_text(original)
        self.pin.chmod(0o640)
        result = self._run_install(install_rc=73)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.pin.read_text(), original)
        self.assertEqual(self.pin.stat().st_mode & 0o777, 0o640)
        self.assertEqual(list(self.pin.parent.glob(".xpf-channel.pref.*")), [])


class AptCandidatePinningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = [name for name in ("apt-get", "apt-cache", "gpg")
                   if shutil.which(name) is None]
        if missing:
            raise unittest.SkipTest("required local APT fixture tools missing: " + ", ".join(missing))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xpf-apt-repo-11133-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.gnupg = self.root / "gnupg"
        self.gnupg.mkdir(mode=0o700)
        self.env = dict(os.environ, GNUPGHOME=str(self.gnupg))
        self.repo = self.root / "repo"
        self.lists = self.root / "lists"
        self.cache = self.root / "cache"
        self.preferences = self.root / "preferences.d"
        self.sources = self.root / "sources.list"
        self.status = self.root / "status"
        self.empty_status = self.root / "empty-status"
        self.empty_preferences = self.root / "empty.preferences"
        for directory in (self.lists, self.cache / "archives", self.preferences):
            directory.mkdir(parents=True)
        self.status.write_text(self._installed_status())
        self.empty_status.write_text("")
        self.empty_preferences.write_text("")
        self._make_key()
        self.sources.write_text(
            f"deb [arch=amd64 signed-by={self.keyring}] file:{self.repo} stable main\n")

    def _run(self, argv, *, status=None, check=False):
        command = [
            *argv,
            "-c", "/dev/null",
            "-o", "Dir::Etc::main=/dev/null",
            "-o", "Dir::Etc::parts=-",
            "-o", f"Dir::Etc::sourcelist={self.sources}",
            "-o", "Dir::Etc::sourceparts=-",
            "-o", f"Dir::Etc::preferences={self.empty_preferences}",
            "-o", f"Dir::Etc::preferencesparts={self.preferences}",
            "-o", "Dir::Etc::trusted=/dev/null",
            "-o", "Dir::Etc::trustedparts=-",
            "-o", f"Dir::State::status={status or self.status}",
            "-o", f"Dir::State::lists={self.lists}",
            "-o", f"Dir::Cache={self.cache}",
            "-o", f"Dir::Cache::archives={self.cache / 'archives'}",
            "-o", f"Dir::Cache::pkgcache={self.cache / 'pkgcache.bin'}",
            "-o", f"Dir::Cache::srcpkgcache={self.cache / 'srcpkgcache.bin'}",
            "-o", "Debug::NoLocking=1",
            "-o", "APT::Architecture=amd64",
            "-o", "Acquire::Languages=none",
        ]
        return subprocess.run(command, capture_output=True, text=True,
                              env=self.env, timeout=60, check=check)

    def _make_key(self):
        generated = subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-generate-key", "XPF APT pin test <xpf-apt-pin@example.invalid>",
             "rsa2048", "sign", "0"],
            capture_output=True, text=True, env=self.env, timeout=60)
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
        listing = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--list-keys", "xpf-apt-pin@example.invalid"],
            capture_output=True, text=True, env=self.env, timeout=30, check=True)
        fingerprint = next(line.split(":")[9] for line in listing.stdout.splitlines()
                           if line.startswith("fpr:"))
        self.keyring = self.root / "archive.gpg"
        exported = subprocess.run(
            ["gpg", "--batch", "--export", fingerprint],
            capture_output=True, env=self.env, timeout=30, check=True)
        self.keyring.write_bytes(exported.stdout)

    @staticmethod
    def _installed_status():
        return (
            "Package: xpf\nStatus: install ok installed\nPriority: optional\n"
            "Section: net\nArchitecture: amd64\nVersion: 1.0\n"
            "Description: installed XPF fixture\n\n"
            "Package: xpf-appliance\nStatus: install ok installed\nPriority: optional\n"
            "Section: net\nArchitecture: amd64\nVersion: 1.0\nDepends: xpf (= 1.0)\n"
            "Description: installed XPF appliance fixture\n")

    def _packages(self, version):
        records = []
        for name in ("xpf", "xpf-appliance", "debian-pin-probe"):
            depends = f"Depends: xpf (= {version})\n" if name == "xpf-appliance" else ""
            records.append(
                f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
                f"Maintainer: XPF APT test <xpf-apt-pin@example.invalid>\n"
                f"{depends}Filename: pool/main/{name}/{name}_{version}_amd64.deb\n"
                "Size: 1\nSHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
                f"Description: {name} fixture\n")
        return "\n".join(records)

    def _publish(self, suite, codename, version):
        dist = self.repo / "dists" / "stable"
        binary = dist / "main" / "binary-amd64"
        binary.mkdir(parents=True, exist_ok=True)
        packages = self._packages(version).encode()
        package_index = binary / "Packages"
        package_index.write_bytes(packages)
        digest = hashlib.sha256(packages).hexdigest()
        release = [
            "Origin: xpf",
            "Label: xpf",
            "Date: " + datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC"),
        ]
        if suite is not None:
            release.append(f"Suite: {suite}")
        if codename is not None:
            release.append(f"Codename: {codename}")
        release.extend([
            "Architectures: amd64",
            "Components: main",
            "SHA256:",
            f" {digest} {len(packages)} main/binary-amd64/Packages",
            "",
        ])
        release_file = dist / "Release"
        release_file.write_text("\n".join(release))
        inrelease = dist / "InRelease"
        signed = subprocess.run(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
             "--clearsign", "--output", str(inrelease), str(release_file)],
            capture_output=True, text=True, env=self.env, timeout=30)
        self.assertEqual(signed.returncode, 0, signed.stdout + signed.stderr)

    def _clear_lists(self):
        shutil.rmtree(self.lists)
        self.lists.mkdir()

    def _policy(self, package):
        result = self._run(["apt-cache", "policy", package], check=True)
        return result.stdout + result.stderr

    def _generate_pin(self):
        script = (
            '. "$1"; CHANNEL=stable; DRY=0; PIN="$2"; '
            'write_channel_pin; INSTALL_OK=1'
        )
        generated = subprocess.run(
            ["sh", "-c", script, "sh", str(_INSTALLSH),
             str(self.preferences / "xpf-channel.pref")],
            capture_output=True, text=True,
            env=dict(self.env, XPF_INSTALL_SOURCE_ONLY="1"), timeout=30)
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)

    def test_unpinned_upgrade_is_blocked_after_lists_clear_and_bad_codename_fails_closed(self):
        # Counterfactual: reproduce the post-install bypass with a signed edge
        # tree served at the stable path and no persistent preference.
        self._publish("edge", "edge", "99.0~edge")
        update = self._run(["apt-get", "update"])
        self.assertEqual(update.returncode, 0, update.stdout + update.stderr)
        self.assertIn("Conflicting distribution", update.stdout + update.stderr)
        for package in ("xpf", "xpf-appliance"):
            policy = self._policy(package)
            self.assertIn("Candidate: 99.0~edge", policy)
            self.assertRegex(policy, r"(?m)^\s+99\.0~edge\s+500$")
        unpinned_upgrade = self._run(["apt-get", "-s", "upgrade"], check=True)
        self.assertIn("Inst xpf ", unpinned_upgrade.stdout)
        self.assertIn("Inst xpf-appliance ", unpinned_upgrade.stdout)

        self._generate_pin()
        self._clear_lists()
        update = self._run(["apt-get", "update"])
        self.assertEqual(update.returncode, 0, update.stdout + update.stderr)
        for package in ("xpf", "xpf-appliance"):
            policy = self._policy(package)
            self.assertRegex(policy, r"(?m)^\s+99\.0~edge\s+-1$")
        blocked_upgrade = self._run(["apt-get", "-s", "upgrade"], check=True)
        self.assertNotIn("Inst xpf ", blocked_upgrade.stdout)
        self.assertNotIn("Inst xpf-appliance ", blocked_upgrade.stdout)
        unrelated = self._policy("debian-pin-probe")
        self.assertIn("Candidate: 99.0~edge", unrelated)
        self.assertRegex(unrelated, r"(?m)^\s+99\.0~edge\s+500$")

        # A malformed signed Release with no Codename must not miss the old
        # two-field wildcard and fall back to APT's default priority.
        self._publish("edge", None, "99.0~edge")
        self._clear_lists()
        update = self._run(["apt-get", "update"])
        self.assertEqual(update.returncode, 0, update.stdout + update.stderr)
        self.assertIn("Conflicting distribution", update.stdout + update.stderr)
        for package in ("xpf", "xpf-appliance"):
            policy = self._policy(package)
            self.assertRegex(policy, r"(?m)^\s+99\.0~edge\s+-1$")
        no_candidate = self._run(["apt-get", "-s", "install", "xpf-appliance"],
                                 status=self.empty_status)
        self.assertNotEqual(no_candidate.returncode, 0, no_candidate.stdout + no_candidate.stderr)
        self.assertIn("no installation candidate", (no_candidate.stdout + no_candidate.stderr).lower())
        malformed_upgrade = self._run(["apt-get", "-s", "upgrade"], check=True)
        self.assertNotIn("Inst xpf ", malformed_upgrade.stdout)
        self.assertNotIn("Inst xpf-appliance ", malformed_upgrade.stdout)

        # The selected stable pair remains the first-match 990 rule.
        self._publish("stable", "stable", "2.0~stable")
        self._clear_lists()
        stable_update = self._run(["apt-get", "update"])
        self.assertEqual(stable_update.returncode, 0, stable_update.stdout + stable_update.stderr)
        for package in ("xpf", "xpf-appliance"):
            policy = self._policy(package)
            self.assertIn("Candidate: 2.0~stable", policy)
            self.assertRegex(policy, r"(?m)^\s+2\.0~stable\s+990$")
        stable_upgrade = self._run(["apt-get", "-s", "upgrade"], check=True)
        self.assertIn("Inst xpf ", stable_upgrade.stdout)
        self.assertIn("Inst xpf-appliance ", stable_upgrade.stdout)


if __name__ == "__main__":
    unittest.main()
