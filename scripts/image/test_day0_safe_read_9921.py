#!/usr/bin/env python3
"""Unit tests for psaab/xpf#9921 F-147 — xpf-day0-config must open medium
files with O_NOFOLLOW + fstat the fd, with a bounded per-file read.

On base, the `-f`/`! -L` guard and the `head -c` read were separate syscalls
against a medium whose backing store the hypervisor can mutate, so a
mid-probe swap defeated the two-fixed-filenames guard: a symlink redirected
the read to a host-side path and a fifo stalled the copy (bounded only by
the unit's 120 s TimeoutStartSec).

The fix reads every candidate through safe_read_medium (perl O_NOFOLLOW |
O_NONBLOCK sysopen, fstat-is-regular on the fd, capped sysread, timeout
backstop). The helper battery below is the primary red-green anchor (every
cell diverges on base, where the function does not exist); the try_device
legs pin the wiring end-to-end with PATH-stubbed mount/umount/xpfd (6502
pattern). Static-media skip outcomes pass on base too and are kept as
documented regression guards; the perl-stub and function-override legs are
the wiring proofs that diverge on base.

The valid-install case also checks #10735's same-directory staged replacement:
the installed bytes match and the temporary name is consumed by the rename.

RED on revert: helper cells fail (command not found / wrong rc) and the
wiring legs install where they must skip.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
LOADER = _HERE / "xpf-day0-config"

_HAS_BASH = bool(shutil.which("bash"))
_HAS_PERL = bool(shutil.which("perl"))

MOCK_MOUNT = """#!/usr/bin/env bash
# usage (as the loader calls it): mount -o ro,... <dev> <mnt>
args=()
while (( $# )); do
  case "$1" in
    -o) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
dev="${args[0]}"; mnt="${args[1]}"
src="$MOCK_MEDIA/$(basename "$dev")"
[ -d "$src" ] || exit 1
mkdir -p "$mnt"
cp -a "$src"/. "$mnt"/
exit 0
"""

MOCK_UMOUNT = """#!/usr/bin/env bash
exit 0
"""

# install: the loader passes -o root -g root, which a non-root test cannot
# honour. Drop ONLY the ownership flags and forward everything else to the
# real install (6502 pattern).
# #10735's ordering cell also requires node-id to exist before xpf.conf is
# staged, and the success stamp to remain absent until afterward.
MOCK_INSTALL = """#!/usr/bin/env bash
args=()
while (( $# )); do
  case "$1" in
    -o|-g) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
if [ "$MOCK_REQUIRE_NODE_ID" = "1" ] &&
   [[ "${args[-1]}" == "$MOCK_XPF_DIR"/.xpf.conf.* ]]; then
  [ -s "$MOCK_XPF_DIR/node-id" ] || {
    echo "xpf.conf staged before durable node-id" >&2
    exit 1
  }
  [ ! -e "$MOCK_XPF_DIR/.day0-config-applied" ] || {
    echo "day-0 stamp written before xpf.conf" >&2
    exit 1
  }
fi
printf '%s\\n' "${args[-1]}" >> "$MOCK_INSTALLLOG"
exec /usr/bin/install "${args[@]}"
"""

# mktemp: the loader writes its private copy under /run. Redirect a leading
# /run/ to the harness's scratch dir and forward (6502 pattern).
MOCK_MKTEMP = """#!/usr/bin/env bash
args=()
for a in "$@"; do args+=("${a/#\\/run\\//$MOCK_RUN/}"); done
exec /usr/bin/mktemp "${args[@]}"
"""

CONF = "system {{\n    host-name {name};\n}}\n"


@unittest.skipUnless(_HAS_BASH and _HAS_PERL, "needs bash + perl")
class SafeReadHelperTests(unittest.TestCase):
    """safe_read_medium battery — every cell diverges on base."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-day0-9921."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "empty").mkdir()

    def _run(self, *args, path_prefix=None):
        """Call safe_read_medium withargv; return (rc, stdout_bytes, stderr, elapsed)."""
        call = "safe_read_medium " + " ".join(f'"{a}"' for a in args)
        if path_prefix is not None:
            call = f"PATH={path_prefix} {call}"
        script = f'. "{LOADER}"\n{call}\n'
        env = dict(os.environ)
        env["XPF_DAY0_SOURCE_ONLY"] = "1"
        start = time.monotonic()
        p = subprocess.run(["bash", "-c", script], env=env,
                           capture_output=True, timeout=60)
        return p.returncode, p.stdout, p.stderr.decode(errors="replace"), \
            time.monotonic() - start

    def test_regular_file_read_exactly(self):
        f = self.tmp / "regular.conf"
        f.write_bytes(b"host-name ok;\nsecond line\n\x00\xff\xfe binary\n")
        out = self.tmp / "out.bin"
        script = (f'. "{LOADER}"\nsafe_read_medium "{f}" 1024 > "{out}"\n'
                  f'cmp "{f}" "{out}"\n')
        env = dict(os.environ)
        env["XPF_DAY0_SOURCE_ONLY"] = "1"
        p = subprocess.run(["bash", "-c", script], env=env,
                           capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr.decode(errors="replace"))

    def test_symlink_refused_with_eloop(self):
        secret = self.tmp / "secret.conf"
        secret.write_text(CONF.format(name="pwned-via-symlink"))
        link = self.tmp / "link.conf"
        link.symlink_to(secret)
        rc, out, _err, _dt = self._run(str(link), "1024")
        self.assertEqual(rc, 11, f"symlink must fail ELOOP, got rc={rc}")
        self.assertEqual(out, b"")

    def test_dangling_symlink_skipped(self):
        link = self.tmp / "dangling.conf"
        link.symlink_to(self.tmp / "no-such-target")
        rc, out, _err, _dt = self._run(str(link), "1024")
        self.assertIn(rc, (10, 11), f"dangling symlink must skip, got {rc}")
        self.assertEqual(out, b"")

    def test_fifo_refused_instantly(self):
        fifo = self.tmp / "stuck.conf"
        os.mkfifo(fifo)
        rc, out, _err, dt = self._run(str(fifo), "1024")
        self.assertEqual(rc, 12, f"fifo must fail non-regular, got rc={rc}")
        self.assertEqual(out, b"")
        self.assertLess(dt, 8, f"fifo refusal took {dt:.1f}s — not the "
                               "instant fstat path (10 s backstop?)")

    def test_absent_reports_enoent(self):
        rc, out, _err, _dt = self._run(str(self.tmp / "nope.conf"), "1024")
        self.assertEqual(rc, 10)
        self.assertEqual(out, b"")

    def test_directory_refused(self):
        rc, out, _err, _dt = self._run(str(self.tmp), "1024")
        self.assertEqual(rc, 12)
        self.assertEqual(out, b"")

    def test_cap_truncates_without_refusal(self):
        f = self.tmp / "big.conf"
        f.write_bytes(b"A" * 100)
        rc, out, _err, _dt = self._run(str(f), "10")
        self.assertEqual(rc, 0)
        self.assertEqual(out, b"A" * 10)

    def test_missing_args_fail_closed_not_unbound(self):
        script = f'. "{LOADER}"\nsafe_read_medium\n'
        env = dict(os.environ)
        env["XPF_DAY0_SOURCE_ONLY"] = "1"
        p = subprocess.run(["bash", "-c", script], env=env,
                           capture_output=True, timeout=30)
        # 13 = usage error; 127 would be a set -u unbound-variable shell exit.
        self.assertEqual(p.returncode, 13)

    def test_perl_absent_fails_closed(self):
        f = self.tmp / "regular.conf"
        f.write_text("host-name ok;\n")
        rc, _out, _err, _dt = self._run(
            str(f), "1024", path_prefix=str(self.tmp / "empty"))
        self.assertEqual(rc, 14)


@unittest.skipUnless(_HAS_BASH and _HAS_PERL, "needs bash + perl")
class TryDeviceTests(unittest.TestCase):
    """try_device end-to-end with stubbed mount/umount/xpfd (6502 pattern)."""

    def setUp(self):
        self.assertTrue(LOADER.is_file(), f"{LOADER} missing")
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-day0-9921e2e."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.media = self.tmp / "media"
        self.media.mkdir()
        self.run = self.tmp / "run"
        self.run.mkdir()
        self.xpf_dir = self.tmp / "etc-xpf"
        self.mnt = self.tmp / "mnt"
        for name, body in (("mount", MOCK_MOUNT), ("umount", MOCK_UMOUNT),
                           ("install", MOCK_INSTALL), ("mktemp", MOCK_MKTEMP)):
            f = self.bin / name
            f.write_text(body)
            f.chmod(0o755)
        self.xpfd = self.tmp / "xpfd"
        self.xpfd.write_text("#!/bin/sh\nexit 0\n")
        self.xpfd.chmod(0o755)
        self.args_file = self.tmp / "xpfd-args.txt"
        self.installlog = self.tmp / "install.log"
        self.require_node_id_before_config = False

    def _medium(self, dev, files):
        """Create fixture medium for `dev`: {name: bytes} plus {'link:NAME':
        target} symlinks and {'fifo:NAME': None} fifos."""
        d = self.media / os.path.basename(dev)
        d.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            if name.startswith("link:"):
                (d / name[5:]).symlink_to(content)
            elif name.startswith("fifo:"):
                os.mkfifo(d / name[5:])
            else:
                (d / name).write_bytes(content)

    def _env(self):
        env = dict(os.environ)
        env.update({
            "PATH": f"{self.bin}:{env.get('PATH', '')}",
            "MOCK_MEDIA": str(self.media),
            "MOCK_RUN": str(self.run),
            "MOCK_INSTALLLOG": str(self.installlog),
            "MOCK_XPF_DIR": str(self.xpf_dir),
            "MOCK_REQUIRE_NODE_ID": "1" if self.require_node_id_before_config else "0",
            "XPF_DAY0_SOURCE_ONLY": "1",
        })
        return env

    def _try_device(self, dev="/dev/fake0", prelude=""):
        script = (f'. "{LOADER}"\n'
                  f'XPF_DIR="{self.xpf_dir}"\n'
                  f'STAMP="$XPF_DIR/.day0-config-applied"\n'
                  f'REJECT_MARKER="$XPF_DIR/.day0-config-rejected"\n'
                  f'MNT="{self.mnt}"\n'
                  f'XPFD="{self.xpfd}"\n'
                  + prelude +
                  f'try_device "{dev}"\n')
        start = time.monotonic()
        p = subprocess.run(["bash", "-c", script], env=self._env(),
                           capture_output=True, text=True, timeout=120)
        return p.returncode, (p.stdout or "") + (p.stderr or ""), \
            time.monotonic() - start

    def _installed(self):
        f = self.xpf_dir / "xpf.conf"
        return f.read_bytes() if f.is_file() else None

    def test_installs_valid_conf(self):
        self.xpf_dir.mkdir()
        marker = self.xpf_dir / ".day0-config-rejected"
        marker.write_text("commit-check-rejected\n")
        body = CONF.format(name="day0-ok").encode()
        self._medium("/dev/fake0", {"xpf.conf": body})
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual(self._installed(), body)
        self.assertEqual(oct((self.xpf_dir / "xpf.conf").stat().st_mode & 0o777),
                         "0o600")
        # #10735: install stages beside the destination and rename consumes
        # the staging name after replacing xpf.conf.
        staged = Path(self.installlog.read_text().strip())
        self.assertEqual(staged.parent, self.xpf_dir)
        self.assertRegex(staged.name, r"\.xpf\.conf\.[^/]+")
        self.assertFalse(staged.exists(),
                         "successful install did not rename its staged file")
        stamp = (self.xpf_dir / ".day0-config-applied").read_text()
        self.assertIn("/dev/fake0", stamp)
        self.assertFalse(marker.exists(),
                         "a successful install after another medium's REJECT must clear its signal")

    def test_commit_check_reject_leaves_daemon_signal(self):
        self.xpfd.write_text(
            '#!/bin/sh\necho "FAIL bad stanza"\nexit 2\n')
        self._medium("/dev/fake0",
                     {"xpf.conf": CONF.format(name="rejected").encode()})
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 1, out[-600:])
        self.assertIsNone(self._installed(),
                          "a REJECTed config must not be installed")
        marker = self.xpf_dir / ".day0-config-rejected"
        self.assertEqual(marker.read_text(), "commit-check-rejected\n",
                         "xpfd needs a private signal because REJECT installs no xpf.conf")
        self.assertIn("REJECTED by commit-check", out)

    def test_node_id_is_durable_before_config_is_exposed(self):
        body = b"""chassis {
    cluster {
        cluster-id 1;
        node 1;
        reth-count 2;
        authentication-key "bootstrap-psk-10735-long-enough";
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
        }
    }
}
"""
        self.require_node_id_before_config = True
        self._medium("/dev/fake0", {
            "xpf.conf": body,
            "node-id": b"1\n",
        })
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual(
            (self.xpf_dir / "node-id").read_text(), "1\n"
        )
        self.assertEqual(self._installed(), body)
        stamp = (self.xpf_dir / ".day0-config-applied").read_text()
        self.assertIn("/dev/fake0", stamp)

    def test_helper_override_proves_wiring(self):
        # WIRING (diverges on base): overriding safe_read_medium changes
        # try_device's behavior only if try_device actually calls it. (The
        # probe is a file, not stderr: the caller redirects helper stderr
        # to /dev/null.)
        probe = self.tmp / "probe.txt"
        self._medium("/dev/fake0",
                     {"xpf.conf": CONF.format(name="day0-ok").encode()})
        rc, out, _dt = self._try_device(prelude=(
            f'safe_read_medium() {{ echo called >> "{probe}"; return 13; }}\n'))
        self.assertEqual(rc, 1, out[-600:])
        self.assertTrue(probe.is_file(), "override was never called")
        self.assertIsNone(self._installed())

    def test_skips_symlink_conf_even_when_target_is_valid(self):
        # Regression guard (passes on base too — a static symlink never
        # passed the old guard either): kept because it proves end-to-end
        # that the read never follows a symlink to installable bytes.
        self._medium("/dev/fake0", {
            "secret.conf": CONF.format(name="pwned").encode(),
            "link:xpf.conf": self.media / "fake0" / "secret.conf",
        })
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 1, out[-600:])
        self.assertIsNone(self._installed(),
                          "symlink target bytes were installed!")
        self.assertIn("could not be safely read", out)

    def test_skips_fifo_conf_instantly(self):
        # Regression guard (see above): the old code skipped a static fifo
        # at the guard; the new code must refuse it at the fstat — fast.
        self._medium("/dev/fake0", {"fifo:xpf.conf": None})
        rc, out, dt = self._try_device()
        self.assertEqual(rc, 1, out[-600:])
        self.assertIsNone(self._installed())
        self.assertLess(dt, 15, f"fifo medium took {dt:.1f}s")

    def test_broken_perl_skips_valid_conf(self):
        # WIRING (diverges on base, which ignores perl entirely and
        # installs): with no working perl there is no safe primitive, so the
        # device must be skipped with a warning — never read unsafely.
        (self.bin / "perl").write_text("#!/bin/sh\nexit 1\n")
        (self.bin / "perl").chmod(0o755)
        self._medium("/dev/fake0",
                     {"xpf.conf": CONF.format(name="day0-ok").encode()})
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 1, out[-600:])
        self.assertIsNone(self._installed())
        self.assertIn("could not be safely read", out)

    def test_ignores_symlink_node_id(self):
        self._medium("/dev/fake0", {
            "xpf.conf": CONF.format(name="day0-ok").encode(),
            "one.txt": b"1\n",
            "link:node-id": self.media / "fake0" / "one.txt",
        })
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 0, out[-600:])
        self.assertIsNotNone(self._installed())
        self.assertFalse((self.xpf_dir / "node-id").exists(),
                         "symlink node-id was followed!")
        self.assertIn("could not be safely read", out)

    def test_accepts_regular_node_id(self):
        self.xpfd.write_text(
            f'#!/bin/sh\necho "$@" > "{self.args_file}"\nexit 0\n')
        self._medium("/dev/fake0", {
            "xpf.conf": CONF.format(name="day0-ok").encode(),
            "node-id": b"1\n",
        })
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 0, out[-600:])
        self.assertEqual((self.xpf_dir / "node-id").read_text(), "1\n")
        self.assertIn("-node-id 1", self.args_file.read_text())

    def test_ignores_bad_node_id_for_standalone_config(self):
        self._medium("/dev/fake0", {
            "xpf.conf": CONF.format(name="day0-ok").encode(),
            "node-id": b"2\n",
        })
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 0, out[-600:])
        self.assertFalse((self.xpf_dir / "node-id").exists())
        self.assertIn("is not 0 or 1", out)

    def test_absent_node_id_is_fine_for_standalone_config(self):
        self._medium("/dev/fake0",
                     {"xpf.conf": CONF.format(name="day0-ok").encode()})
        rc, out, _dt = self._try_device()
        self.assertEqual(rc, 0, out[-600:])
        self.assertFalse((self.xpf_dir / "node-id").exists())
        self.assertNotIn("node-id", out)


    def test_ha_config_rejected_without_valid_node_id(self):
        # The check-config command rejects cluster configs with no explicit
        # node ID; model that command response and prove the loader does not
        # install or stamp either an absent or invalid ID.
        self.xpfd.write_text(
            '#!/bin/sh\n'
            'case " $* " in\n'
            '  *" -node-id 0 "*|*" -node-id 1 "*) exit 0 ;;\n'
            'esac\n'
            'echo "FAIL HA cluster config requires -node-id 0 or 1"\n'
            'exit 2\n')
        self.xpfd.chmod(0o755)
        cases = (
            ("absent", {}),
            ("invalid", {"node-id": b"2\n"}),
        )
        for index, (name, node_id_file) in enumerate(cases):
            with self.subTest(node_id=name):
                dev = f"/dev/fake{index}"
                files = {"xpf.conf": b"chassis { cluster { cluster-id 1; } }\n"}
                files.update(node_id_file)
                self._medium(dev, files)
                rc, out, _dt = self._try_device(dev)
                self.assertEqual(rc, 1, out[-600:])
                self.assertIn("REJECTED by commit-check", out)
                self.assertIsNone(self._installed())
                self.assertFalse((self.xpf_dir / ".day0-config-applied").exists())

if __name__ == "__main__":
    unittest.main()
