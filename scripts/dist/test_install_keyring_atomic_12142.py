#!/usr/bin/env python3
"""Regression tests for transactional archive-key installation (#12142)."""

from __future__ import annotations

import os
import signal
import shutil
import stat
import subprocess
import tempfile
import time
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
        cls.test_secret_key = None
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
                check=True, capture_output=True, timeout=30)
            cls.test_key = exported.stdout.decode().rstrip("\n")
            exported_secret = subprocess.run(
                [cls.gpg, "--batch", "--homedir", cls.gpg_home.name,
                 "--armor", "--export-secret-keys", identity],
                check=True, capture_output=True, timeout=30)
            public_packets = subprocess.run(
                [cls.gpg, "--batch", "--dearmor"], input=exported.stdout,
                check=True, capture_output=True, timeout=30)
            secret_packets = subprocess.run(
                [cls.gpg, "--batch", "--dearmor"], input=exported_secret.stdout,
                check=True, capture_output=True, timeout=30)
            armored_mixed = subprocess.run(
                [cls.gpg, "--batch", "--enarmor"],
                input=public_packets.stdout + secret_packets.stdout,
                check=True, capture_output=True, timeout=30)
            cls.test_secret_public_block = armored_mixed.stdout.replace(
                b"PGP ARMORED FILE", b"PGP PUBLIC KEY BLOCK").decode().rstrip("\n")

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
if [ "$XPF_TEST_FAIL_KEYRING_MV" = "1" ] &&
   [ "$#" -eq 3 ] && [ "$1" = "-f" ] && [ "$3" = "$XPF_TEST_KEYRING" ]; then
    case "$2" in
        "$XPF_TEST_KEYRING_DIR"/.xpf-archive-keyring.asc.tmp.*) exit 93 ;;
    esac
fi
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
            "XPF_TEST_SOURCE": str(self.source),
            "XPF_TEST_PACKAGE_PAYLOAD": "",
            "PATH": str(self.bindir) + os.pathsep + env.get("PATH", ""),
            "XPF_TEST_FAIL_KEYRING_MV": "",
        })
        return env

    def _shim_apt_install_fails_after_unpack(self):
        self._shim("apt-get", """#!/bin/sh
case "$1" in
  update) exit 0 ;;
  indextargets)
    printf 'Sourcesentry: %s:1\\nSuite: stable\\nCodename: stable\\n' "$XPF_TEST_SOURCE"
    exit 0 ;;
  install)
    # Simulate dpkg unpack: rename its .dpkg-new file over the package-owned
    # keyring, then fail as a maintainer script or later package could.
    printf '%s\\n' "$XPF_TEST_PACKAGE_PAYLOAD" > "$XPF_TEST_KEYRING.dpkg-new"
    mv -f "$XPF_TEST_KEYRING.dpkg-new" "$XPF_TEST_KEYRING"
    exit 100 ;;
  *) exit 1 ;;
esac
""")


    def _run(self, body: str, *args: str, env=None):
        return subprocess.run(
            ["/bin/dash", "-c", body, "sh", str(_INSTALLSH), *map(str, args)],
            capture_output=True, text=True, env=env or self._env(), timeout=30)

    def _install_setup_args(self):
        return str(self.keyring), str(self.source), str(self.pin)

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required for public-key parsing")
    def test_non_key_armor_fails_validation_without_touching_old_keyring(self):
        old = b"prior package keyring bytes\x00\xff\n"
        self.keyring.write_bytes(old)
        script = """. "$1"
preflight() { :; }
CHANNEL=stable; DRY=1; KEYRING="$2"; SRC="$3"; PIN="$4"; ARCHIVE_KEY="$5"
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
preflight() { :; }
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

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required for secret-key parsing")
    def test_secret_key_material_is_rejected(self):
        script = """. "$1"; ARCHIVE_KEY="$2"; validate_archive_key
"""
        result = self._run(script, self.test_secret_public_block)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("secret OpenPGP key material", result.stderr)

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

    def _run_apt_unpack_failure(self):
        self.source.parent.mkdir(parents=True, exist_ok=True)
        self.pin.parent.mkdir(parents=True, exist_ok=True)
        payload = "PACKAGE PAYLOAD KEYRING (dpkg-owned, K_new)"
        env = self._env()
        env["XPF_TEST_PACKAGE_PAYLOAD"] = payload
        replacement = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnew test key\n-----END PGP PUBLIC KEY BLOCK-----"
        script = """. "$1"
DRY=0; CHANNEL=stable; KEYRING="$2"; SRC="$3"; PIN="$4"; ARCHIVE_KEY="$5"
install_keyring
write_source
do_install
"""
        result = self._run(script, *self._install_setup_args(), replacement, env=env)
        return result, payload

    def test_apt_install_failure_after_unpack_preserves_dpkg_keyring(self):
        old = b"previous signed-by keyring bytes\x00\xff\n"
        self.keyring.write_bytes(old)
        self.before.write_bytes(old)
        self._shim_apt_install_fails_after_unpack()
        result, payload = self._run_apt_unpack_failure()
        self.assertEqual(result.returncode, 100, result.stdout + result.stderr)
        self.assertEqual(self.keyring.read_bytes(), (payload + "\n").encode())
        self.assertFalse(self.source.exists())
        self.assertFalse(self.pin.exists())
        self.assertEqual(list(self.keyring_dir.glob(".xpf-archive-keyring.asc.*")), [])

    def test_apt_install_failure_after_unpack_first_install_keeps_package_keyring(self):
        self._shim("mv", '#!/bin/sh\nexec /bin/mv "$@"\n')
        self._shim_apt_install_fails_after_unpack()
        result, payload = self._run_apt_unpack_failure()
        self.assertEqual(result.returncode, 100, result.stdout + result.stderr)
        self.assertEqual(self.keyring.read_bytes(), (payload + "\n").encode())
        self.assertEqual(list(self.keyring_dir.glob(".xpf-archive-keyring.asc.*")), [])

    def test_symlink_keyring_is_refused_without_touching_target(self):
        target = self.root / "keyring-target"
        old = b"symlink target bytes\n"
        target.write_bytes(old)
        self.keyring.symlink_to(target)
        script = """. "$1"; DRY=0; KEYRING="$2"; install_keyring
"""
        result = self._run(script, self.keyring)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.keyring.is_symlink())
        self.assertEqual(target.read_bytes(), old)

    def test_non_regular_keyring_is_refused(self):
        self.keyring.mkdir()
        script = """. "$1"; DRY=0; KEYRING="$2"; install_keyring
"""
        result = self._run(script, self.keyring)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.keyring.is_dir())
        self.assertEqual(list(self.keyring_dir.glob(".xpf-archive-keyring.asc.*")), [])

    def test_first_install_failure_removes_bootstrap_keyring(self):
        self.assertFalse(self.keyring.exists())
        replacement = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnew test key\n-----END PGP PUBLIC KEY BLOCK-----"
        script = """. "$1"; DRY=0; KEYRING="$2"; ARCHIVE_KEY="$3"
install_keyring
false
"""
        result = self._run(script, self.keyring, replacement)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.keyring.exists())
        self.assertEqual(list(self.keyring_dir.glob(".xpf-archive-keyring.asc.*")), [])

    def test_failed_atomic_rename_keeps_previous_keyring_and_cleans_files(self):
        old = b"original bytes remain after failed rename\n"
        self.keyring.write_bytes(old)
        self.before.write_bytes(old)
        env = self._env()
        env["XPF_TEST_FAIL_KEYRING_MV"] = "1"
        replacement = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnew test key\n-----END PGP PUBLIC KEY BLOCK-----"
        script = """. "$1"; DRY=0; KEYRING="$2"; ARCHIVE_KEY="$3"
install_keyring
"""
        result = self._run(script, self.keyring, replacement, env=env)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.keyring.read_bytes(), old)
        self.assertEqual(list(self.keyring_dir.glob(".xpf-archive-keyring.asc.*")), [])

    def test_interrupt_signals_run_exit_rollback(self):
        replacement = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnew test key\n-----END PGP PUBLIC KEY BLOCK-----"
        script = """. "$1"; DRY=0; KEYRING="$2"; ARCHIVE_KEY="$3"
install_keyring
sleep 30
"""
        self._shim("sleep", """#!/bin/sh
: > "$XPF_TEST_SLEEP_READY"
exec /bin/sleep "$@"
""")
        env = self._env()
        ready = self.root / "sleep-ready"
        env["XPF_TEST_SLEEP_READY"] = str(ready)

        for sig, status in ((signal.SIGINT, 130), (signal.SIGTERM, 143),
                            (signal.SIGHUP, 129)):
            with self.subTest(signal=sig):
                old = ("keyring before signal %d\n" % sig).encode()
                self.keyring.write_bytes(old)
                self.before.write_bytes(old)
                ready.unlink(missing_ok=True)
                proc = subprocess.Popen(
                    ["/bin/dash", "-c", script, "sh", str(_INSTALLSH),
                     str(self.keyring), replacement],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env=env, start_new_session=True)
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists(), "installer did not reach the interruptible apt stand-in")
                    os.killpg(proc.pid, sig)
                    stdout, stderr = proc.communicate(timeout=10)
                    self.assertEqual(proc.returncode, status, stdout + stderr)
                    self.assertEqual(self.keyring.read_bytes(), old)
                    self.assertEqual(list(self.keyring_dir.glob(".xpf-archive-keyring.asc.*")), [])
                finally:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.communicate(timeout=10)



if __name__ == "__main__":
    unittest.main()
