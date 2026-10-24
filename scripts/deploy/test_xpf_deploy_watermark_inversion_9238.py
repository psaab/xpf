#!/usr/bin/env python3
"""Two concurrent fetches must not leave the watermark ahead of the image (#9238).

`cmd_fetch` consults the anti-rollback watermark TWICE with the same comparison
and opposite consequences. The early check (before the download) calls `die`.
The late check (after verification) used the comparison only as the condition
for *writing* the watermark — when it failed, nothing happened at all: no die,
no warning, execution falling straight through to the incus alias import and
the libvirt golden replacement.

That late block re-reads `prev`, so it is the one place in the process holding
correct information about a concurrent advance, and it discarded it:

    start                                      wm=v0   alias=v0
    A verifies v1, passes the early check, stalls
    B verifies v2, advances, publishes         wm=v2   alias=v2
    A resumes, re-reads prev=v2, skips write,
      and PUBLISHES ANYWAY                     wm=v2   alias=v1  <-- inverted

Deploy checks only that the alias/golden EXISTS, so v1 is then consumed as the
channel's stable identity with nothing dissenting. No forged signature and no
--allow-rollback is involved: both images are legitimately signed, and the
ordering does all the work.

The concurrency is modelled by advancing the watermark from inside
`verify_image_artifact` — that is exactly the window the interleaving needs
(after the early check, before the late one), and it makes the race
deterministic instead of hoping two real processes interleave.

Two halves are pinned separately, because neither alone is sufficient:

  1. the late comparison ABORTS instead of falling through, and
  2. the read/compare/publish run under ONE lock, so a second fetch cannot slip
     between the check and the alias import. Without the lock, half 1 only
     narrows the window.

Hermetic: a throwaway minisign keypair, a `file://` base URL, a private
XDG_STATE_HOME, and `incus` stubbed out. No network, no incus, no root.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_ROOT / "scripts" / "dist"))

deploy = load_subject("xpf_deploy", _HERE / "xpf-deploy.py")

import sign  # noqa: E402

V1 = "1.2.3-4-gaaaaaaa"
V2 = "1.2.9-4-gbbbbbbb"


@unittest.skipUnless(shutil.which("minisign") and shutil.which("curl"),
                     "minisign and curl are required")
class WatermarkInversionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-9238."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.pub = self.tmp / "img.pub"
        self.sec = self.tmp / "img.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)

        self.host = self.tmp / "host"
        self.host.mkdir()
        self.base = self.host.as_uri()
        self.out = self.tmp / "out"
        self.state = self.tmp / "state"

        self._env = {}
        for k, v in (("XPF_IMAGE_PUBKEY", str(self.pub)),
                     ("XDG_STATE_HOME", str(self.state))):
            self._env[k] = os.environ.get(k)
            os.environ[k] = v
        self.addCleanup(self._restore_env)

        for v in (V1, V2):
            self._publish_artifacts(v)

        # `incus` must never actually run. Record what the publish attempted so
        # a cell can assert the publish did NOT happen.
        self.incus_calls = []
        self._real_run = deploy.subprocess.run
        deploy.subprocess.run = self._fake_run
        self.addCleanup(self._restore_run)

        self.wm_path = self.state / "xpf" / "image-watermark.json"

    def _restore_env(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _restore_run(self):
        deploy.subprocess.run = self._real_run

    def _fake_run(self, cmd, *a, **kw):
        """Let curl through (it is the file:// transport); stub incus."""
        if cmd and cmd[0] == "incus":
            self.incus_calls.append(list(cmd))
            self.on_incus()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return self._real_run(cmd, *a, **kw)

    def on_incus(self):
        """Hook: overridden by the serialization cell."""

    def _publish_artifacts(self, ver):
        """A signed image set for `ver`, served over file://."""
        names = {
            "qcow2": f"xpf-{ver}.qcow2",
            "metadata": f"xpf-{ver}.incus-metadata.tar.gz",
        }
        for n in names.values():
            (self.host / n).write_bytes(n.encode() * 64)
        man = self.host / f"xpf-{ver}.SHA256SUMS"
        man.write_text("".join(
            f"{sign.sha256_file(str(self.host / n))}  {n}\n"
            for n in names.values()))
        sign.sign_manifest(str(man), str(self.sec), comment="9238 test")

    def _args(self, version, **over):
        ns = argparse.Namespace(
            version=version, image_url=self.base, out=str(self.out),
            alias=None, channel="stable", allow_rollback=False,
            qcow2_only=False, install_libvirt=False, no_import=False,
            dry_run=False)
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _set_watermark(self, ver):
        self.wm_path.parent.mkdir(parents=True, exist_ok=True)
        self.wm_path.write_text(json.dumps({"stable": ver}))

    def _read_watermark(self):
        try:
            return json.loads(self.wm_path.read_text()).get("stable")
        except (OSError, ValueError):
            return None

    def _advance_during_verify(self, to_ver):
        """Model the concurrent fetch: the watermark moves to `to_ver` while
        THIS fetch is verifying — after the early check, before the late one."""
        real = sign.verify_image_artifact
        fired = []

        def hooked(*a, **kw):
            out = real(*a, **kw)
            if not fired:
                fired.append(True)
                self._set_watermark(to_ver)
            return out

        sign.verify_image_artifact = hooked
        self.addCleanup(setattr, sign, "verify_image_artifact", real)
        return fired

    def _imports(self):
        return [c for c in self.incus_calls if c[1:3] == ["image", "import"]]

    # ── half 1: the late comparison is a decision ──

    def test_a_concurrent_advance_aborts_before_publishing(self):
        """THE DEFECT. v1 verifies; v2 lands underneath it; v1 must not be
        published over v2."""
        self._set_watermark(V1)          # nothing newer yet: early check passes
        fired = self._advance_during_verify(V2)

        with self.assertRaises(SystemExit) as ctx:
            deploy.cmd_fetch(self._args(V1))

        self.assertTrue(fired, "the concurrent advance never fired — the cell "
                               "would be vacuous, not passing")
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertEqual(
            self._imports(), [],
            "#9238: the older image was published even though the watermark "
            "had already advanced past it — deploy would consume it as the "
            "channel's stable identity")
        self.assertEqual(self._read_watermark(), V2,
                         "the winner's watermark must survive the loser's abort")

    def test_the_abort_names_both_versions(self):
        """An operator must see a concurrent-fetch collision, not a mystery.
        `die` carries its text as the SystemExit code, so that is where the
        message is read from."""
        self._set_watermark(V1)
        self._advance_during_verify(V2)
        with self.assertRaises(SystemExit) as ctx:
            deploy.cmd_fetch(self._args(V1))
        msg = str(ctx.exception)
        self.assertIn(V1, msg, "the abort must name the version being refused")
        self.assertIn(V2, msg, "the abort must name the version that overtook "
                               "it, or the operator cannot tell a concurrent "
                               "fetch from a corrupt watermark")

    # ── the abort must not fire when there is no inversion ──

    def test_an_ordinary_fetch_still_publishes(self):
        deploy.cmd_fetch(self._args(V2))
        self.assertEqual(len(self._imports()), 1)
        self.assertEqual(self._read_watermark(), V2)

    def test_refetching_the_SAME_version_is_not_an_inversion(self):
        """Equal is allowed — the guard is `<`, not `<=`. A re-fetch of the
        version already recorded is the common case and must not abort."""
        self._set_watermark(V2)
        deploy.cmd_fetch(self._args(V2))
        self.assertEqual(len(self._imports()), 1)

    def test_allow_rollback_still_permits_a_deliberate_downgrade(self):
        self._set_watermark(V1)
        self._advance_during_verify(V2)
        deploy.cmd_fetch(self._args(V1, allow_rollback=True))
        self.assertEqual(len(self._imports()), 1,
                         "--allow-rollback is the documented escape hatch and "
                         "must keep working")

    # ── half 2: the publish happens INSIDE the lock ──

    def test_the_publish_is_serialized_under_the_watermark_lock(self):
        """Half 1 alone leaves check-then-publish as two steps. Assert the
        publish runs while the lock is HELD, which is what makes the read, the
        compare and the publish one transaction."""
        lockpath = self.state / "xpf" / ".image-watermark.lock"
        observed = {}

        def probe():
            # A non-blocking exclusive flock from a SEPARATE fd: it fails
            # exactly when another process would have been made to wait.
            observed["exists"] = lockpath.exists()
            if not observed["exists"]:
                return
            fd = os.open(str(lockpath), os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
                observed["held"] = False
            except OSError:
                observed["held"] = True
            finally:
                os.close(fd)

        self.on_incus = probe
        deploy.cmd_fetch(self._args(V2))

        self.assertEqual(len(self._imports()), 1, "the publish never ran")
        self.assertTrue(observed.get("exists"),
                        "#9238: no watermark lock file was created, so the "
                        "publish cannot have been serialized against a "
                        "concurrent fetch")
        # flock is per-open-file-description, so a second fd in the SAME
        # process still contends — this is a real observation, not a self-hit.
        self.assertTrue(observed.get("held"),
                        "#9238: the incus publish ran with the watermark lock "
                        "NOT held. The check and the publish are two steps, so "
                        "a concurrent fetch can still advance between them and "
                        "leave the watermark ahead of the published image.")


if __name__ == "__main__":
    unittest.main()
