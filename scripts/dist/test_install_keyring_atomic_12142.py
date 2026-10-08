#!/usr/bin/env python3
"""Regression tests for transactional archive-key installation (#12142)."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_INSTALLSH = _DIST / "install.sh"

# A validly armored PGP PUBLIC KEY BLOCK with correct CRC24, but its payload is
# not an OpenPGP packet. Armor-only/dearmor checks accept it; key parsing must
# reject it before the installer mutates host state.
_NON_KEY_ARMOR = """-----BEGIN PGP PUBLIC KEY BLOCK-----

dGhpcyBpcyBub3QgYW4gT3BlblBHUCBwYWNrZXQsIGp1c3QgZmlsbGVyIGJ5dGVz
LCBub3Qga2V5IGRhdGEuLi4u
=u6TI
-----END PGP PUBLIC KEY BLOCK-----"""


class InstallerKeyringTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gpg = shutil.which("gpg")
        cls.test_key = None
        if cls.gpg:
            cls.gpg_home = tempfile.TemporaryDirectory(prefix="xpf-keyring-gpg-12142-")
            os.chmod(cls.gpg_home.name, 0o700)
            identity = "xpf-12142-test <xpf-12142@example.invalid>"
            subprocess.run(
                [cls.gpg, "--batch", "--homedir", cls.gpg_home.name,
                 "--passphrase", "", "--quick-generate-key", identity,
                 "rsa1024", "sign", "never"],
                check=True, capture_output=True, text=True, timeout=30)
            exported = subprocess.run(
                [cls.gpg, "--batch", "--homedir", cls.gpg_home.name,
                 "--armor", "--export", identity],
                check=True, capture_output=True, text=True, timeout=30)
            cls.test_key = exported.stdout.rstrip("\n")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "gpg_home"):
            cls.gpg_home.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xpf-keyring-12142-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bindir = self.root / "bin"
        self.bindir.mkdir()
        self.keyring_dir = self.root / "keyrings"
        self.keyring_dir.mkdir()
        self.keyring = self.keyring_dir / "xpf-archive-keyring.asc"
        self.source = self.root / "sources" / "xpf.sources"
        self.pin = self.root / "preferences.d" / "xpf-channel.pref"
        self.before = self.root / "keyring.before"
        self.atomic_trace = self.root / "atomic-renames"
        self.atomic_trace.touch()

        self._shim("uname", """#!/bin/sh
case "$1" in
  -m) echo x86_64 ;;
  -r) echo 6.18.0-test ;;
  *) exit 1 ;;
esac
""")
        self._shim("systemctl", "#!/bin/sh\nexit 0\n")
        self._shim("install", """#!/bin/sh
if [ "$1" = "-d" ]; then
    mkdir -p "$XPF_TEST_INSTALL_DIR"
    exit 0
fi
exec /usr/bin/install "$@"
""")
        self._shim("mv", """#!/bin/sh
if [ "$#" -eq 3 ] && [ "$1" = "-f" ] && [ "$3" = "$XPF_TEST_KEYRING" ]; then
    case "$2" in
        "$XPF_TEST_KEYRING_DIR"/.xpf-archive-keyring.asc.tmp.*)
            [ "$(dirname "$2")" = "$(dirname "$3")" ] || exit 90
            [ -f "$2" ] || exit 91
            cmp -s "$3" "$XPF_TEST_BEFORE" || exit 92
            printf '%s\n' "$2" >> "$XPF_TEST_ATOMIC_TRACE"
            ;;
    esac
fi
exec /bin/mv "$@"
""")

    def _shim(self, name: str, body: str):
        path = self.bindir / name
        path.write_text(body)
        path.chmod(0o755)

    def _env(self):
        env = dict(os.environ)
        env.update({
            "XPF_INSTALL_SOURCE_ONLY": "1",
            "XPF_APT_BASE_URL": "https://packages.example.invalid",
            "XPF_TEST_INSTALL_DIR": str(self.keyring_dir),
            "XPF_TEST_KEYRING": str(self.keyring),
            "XPF_TEST_KEYRING_DIR": str(self.keyring_dir),
            "XPF_TEST_BEFORE": str(self.before),
            "XPF_TEST_ATOMIC_TRACE": str(self.atomic_trace),
            "PATH": str(self.bindir) + os.pathsep + env.get("PATH", ""),
        })
        return env

    def _run(self, body: str, *args: str, env=None):
        return subprocess.run(
            ["/bin/dash", "-c", body, "sh", str(_INSTALLSH), *map(str, args)],
            capture_output=True, text=True, env=env or self._env(), timeout=30)

    def _install_setup_args(self):
        return str(self.keyring), str(self.source), str(self.pin)

    def test_non_key_armor_fails_validation_without_touching_old_keyring(self):
        old = b"prior package keyring bytes\x00\xff\n"
        self.keyring.write_bytes(old)
        script = """. \"$1\"
CHANNEL=stable; DRY=1; KEYRING=\"$2\"; SRC=\"$3\"; PIN=\"$4\"; ARCHIVE_KEY=\"$5\"
validate
"""
        result = self._run(script, *self._install_setup_args(), _NON_KEY_ARMOR)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("archive key", (result.stdout + result.stderr).lower())
        self.assertEqual(self.keyring.read_bytes(), old)

    def test_missing_gpg_fails_closed_during_validation(self):
        old = b"prior keyring bytes" + bytes((10,))
        self.keyring.write_bytes(old)
        env = self._env()
        env["PATH"] = str(self.bindir)
        for command in ("cat", "cut", "grep", "tr"):
            (self.bindir / command).symlink_to(shutil.which(command))
        script = """. "$1"
CHANNEL=stable; DRY=1; KEYRING="$2"; SRC="$3"; PIN="$4"; ARCHIVE_KEY="$5"
validate
"""
        result = self._run(script, *self._install_setup_args(), _NON_KEY_ARMOR, env=env)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("gpg is required", (result.stdout + result.stderr).lower())
        self.assertEqual(self.keyring.read_bytes(), old)

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required for public-key parsing")
    def test_valid_public_key_passes_key_validation(self):
        script = ". \"$1\"; ARCHIVE_KEY=\"$2\"; validate_archive_key\n"
        result = self._run(script, self.test_key)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_keyring_replace_is_same_directory_atomic_and_cleans_success_backup(self):
        old = b"prior keyring before atomic replace\n"
        self.keyring.write_bytes(old)
        self.before.write_bytes(old)
        replacement = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnew test key\n-----END PGP PUBLIC KEY BLOCK-----"
        script = """. \"$1\"
DRY=0; KEYRING=\"$2\"; SRC=\"$3\"; PIN=\"$4\"; ARCHIVE_KEY=\"$5\"
install_keyring
INSTALL_OK=1
"""
        result = self._run(script, *self._install_setup_args(), replacement)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.keyring.read_text(), replacement + "\n")
        self.assertEqual(stat.S_IMODE(self.keyring.stat().st_mode), 0o644)
        self.assertEqual(len(self.atomic_trace.read_text().splitlines()), 1,
                         "replacement must use same-directory temp + rename while old path remains intact")
        self.assertEqual(list(self.keyring_dir.glob(".xpf-archive-keyring.asc.*")), [])

    def test_later_install_failure_restores_previous_keyring_byte_for_byte(self):
        old = b"previous signed-by keyring bytes\x00\xff\n"
        self.keyring.write_bytes(old)
        self.before.write_bytes(old)
        old_mode = stat.S_IMODE(self.keyring.stat().st_mode)
        replacement = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnew test key\n-----END PGP PUBLIC KEY BLOCK-----"
        script = """. \"$1\"
DRY=0; KEYRING=\"$2\"; SRC=\"$3\"; PIN=\"$4\"; ARCHIVE_KEY=\"$5\"
install_keyring
false
"""
        result = self._run(script, *self._install_setup_args(), replacement)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.keyring.read_bytes(), old)
        self.assertEqual(stat.S_IMODE(self.keyring.stat().st_mode), old_mode)
        self.assertEqual(len(self.atomic_trace.read_text().splitlines()), 1)
        self.assertEqual(list(self.keyring_dir.glob(".xpf-archive-keyring.asc.*")), [])


if __name__ == "__main__":
    unittest.main()
