#!/usr/bin/env python3
"""#10852: image-roll binds recreated image bytes to the signed qcow2 digest.

The hook, not the live xpfd reporter, must verify its selected image BEFORE it
tears down the existing node. The driver passes the signed digest and refuses
to continue unless the hook attests those installed bytes. The versioned
sidecar basename selects the expected qcow2 from a signed set that may contain
multiple qcow2 artifacts.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_ROOT / "scripts" / "dist"))

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy_10852", _HERE / "xpf-deploy.py")
deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(deploy)

import sign  # noqa: E402

NEWVER = "2.0.0-newimage"
NEW_MANIFEST = {
    "xpf-version": NEWVER,
    "ha-protocol-version": "3",
    "ha-protocol-min-compat": "2",
    "session-sync-protocol-version": "5",
    "validated": "true",
}
EXPECTED_IMAGE = f"xpf-{NEWVER}.qcow2"
DECOY_IMAGE = "xpf-decoy.qcow2"
EXPECTED_BYTES = b"the signed candidate image bytes"
STALE_BYTES = b"the stale alias image bytes"


def _reported(version):
    values = {
        "xpf-version": version,
        "ha-protocol-version": "3",
        "session-sync-protocol-version": "5",
    }
    return "".join(f"{key}={value}\n" for key, value in values.items())


class _RollBackend:
    def __init__(self):
        self.drained = []
        self.rejoined = []
        self.protocol_nodes = []

    def exec(self, runner, backend, node, argv, check=True):
        if argv[:2] == ["sh", "-c"]:
            return "ACQUIRED\n"
        if argv == ["xpfd", "protocol-versions"]:
            self.protocol_nodes.append(node)
            return _reported(NEWVER)
        if argv == ["cat", "/etc/xpf/node-id"]:
            return "0\n" if node == "fw0" else "1\n"
        if argv[:4] == ["xpfd", "upgrade", "kernel", "drain"]:
            self.drained.append(node)
            return ""
        if argv[:4] == ["xpfd", "upgrade", "kernel", "rejoin"]:
            self.rejoined.append(node)
            return ""
        return ""

    @staticmethod
    def exec_result(runner, backend, node, argv):
        return deploy.NodeExecResult(0, "RENEWED\n", "", True)


class ImageRollDigest10852Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-10852-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pubkey = self.tmp / "test.pub"
        self.pubkey.write_text("test public key\n")
        self._verify_signature = sign.verify_signature
        sign.verify_signature = lambda *args, **kwargs: None
        self._require_minisign = sign.require_minisign
        sign.require_minisign = lambda: "minisign-test-stub"
        self.addCleanup(setattr, sign, "require_minisign",
                        self._require_minisign)
        self.addCleanup(setattr, sign, "verify_signature", self._verify_signature)

    def _signed_image_set(self):
        sidecar = self.tmp / f"xpf-{NEWVER}.manifest"
        sidecar.write_text("xpf_version: " + NEWVER + "\n")
        candidate = self.tmp / EXPECTED_IMAGE
        decoy = self.tmp / DECOY_IMAGE
        candidate.write_bytes(EXPECTED_BYTES)
        decoy.write_bytes(b"different signed artifact sentinel")
        sums = self.tmp / f"xpf-{NEWVER}.SHA256SUMS"
        # Put the decoy first: selection must be by the sidecar's image name,
        # never the first *.qcow2 entry or an unrelated golden alias.
        sign.write_manifest(str(sums), [decoy, sidecar, candidate])
        sig = Path(str(sums) + ".minisig")
        sig.write_text("stub signature\n")
        return sidecar, sums, sig, candidate, decoy

    def test_signed_manifest_selects_matching_qcow2_among_two_sentinels(self):
        sidecar, sums, sig, candidate, decoy = self._signed_image_set()

        name, digest = deploy._verified_expected_qcow2_digest(
            str(sidecar), str(sums), str(sig), str(self.pubkey))

        self.assertEqual(name, EXPECTED_IMAGE)
        self.assertEqual(digest, hashlib.sha256(EXPECTED_BYTES).hexdigest())
        self.assertNotEqual(digest, hashlib.sha256(decoy.read_bytes()).hexdigest())

    def test_hook_must_attest_expected_digest_before_roll_continues(self):
        expected = hashlib.sha256(EXPECTED_BYTES).hexdigest()
        wrong = "0" * 64
        hook = self.tmp / "attest-wrong.sh"
        hook.write_text(
            "#!/bin/sh\nprintf '%s\\n' '" + wrong + "' > \"$XPF_ROLL_ATTESTATION_FILE\"\n")
        hook.chmod(0o755)

        with self.assertRaises(SystemExit) as cm:
            deploy._recreate_node_from_image(
                deploy.Runner(False), "ssh", "fw0",
                type("Args", (), {"recreate_hook": str(hook)})(),
                expect_sha256=expected)

        self.assertIn("did not attest the signed image bytes", str(cm.exception))
        self.assertIn(expected, str(cm.exception))

    def test_stale_alias_with_expected_version_is_rejected_before_destroy(self):
        self._signed_image_set()
        stale = self.tmp / "stale-alias.qcow2"
        stale.write_bytes(STALE_BYTES)
        marker = self.tmp / "destroyed"
        expected_marker = self.tmp / "hook-expected-digest"
        expected = hashlib.sha256(EXPECTED_BYTES).hexdigest()
        hook = self.tmp / "verify-before-destroy.sh"
        hook.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$XPF_ROLL_EXPECT_SHA256\" > \"$EXPECTED_SHA_MARKER\"\n"
            "actual=$(sha256sum \"$STALE_ALIAS_IMAGE\" | cut -d ' ' -f 1)\n"
            "[ \"$actual\" = \"$XPF_ROLL_EXPECT_SHA256\" ] || exit 41\n"
            "printf '%s\\n' \"$actual\" > \"$XPF_ROLL_ATTESTATION_FILE\"\n"
            "touch \"$DESTROY_MARKER\"\n")
        hook.chmod(0o755)
        args = type("Args", (), {
            "dry_run": False, "backend": "ssh", "nodes": ["fw0", "fw1"],
            "node0_id": 0, "node1_id": 1, "recreate_hook": str(hook),
            "manifest": f"xpf-{NEWVER}.manifest", "sha256sums": None,
            "sig": None, "pubkey": None, "lease_ttl": 1800,
            "drain_deadline": 120, "boot_deadline": 40,
            "allow_session_drop": False, "require_daemon_hold": False,
            "allow_unvalidated": False,
        })()
        backend = _RollBackend()
        env = {
            "STALE_ALIAS_IMAGE": str(stale),
            "DESTROY_MARKER": str(marker),
            "EXPECTED_SHA_MARKER": str(expected_marker),
        }
        patches = [
            mock.patch.object(deploy, "_node_exec", backend.exec),
            mock.patch.object(deploy, "_node_exec_result", backend.exec_result),
            mock.patch.object(deploy, "_verified_image_manifest_versions",
                              lambda *a, **k: dict(NEW_MANIFEST)),
            mock.patch.object(deploy, "_verified_expected_qcow2_digest",
                              lambda *a, **k: (EXPECTED_IMAGE, expected)),
            mock.patch.object(deploy.os.path, "isfile", lambda path: True),
        ]
        for patch in patches:
            patch.start()
        try:
            with mock.patch.dict(os.environ, env):
                with self.assertRaises(SystemExit) as cm:
                    deploy.cmd_image_roll(args)
        finally:
            for patch in reversed(patches):
                patch.stop()

        self.assertIn("recreate hook for fw0 failed (rc=41)", str(cm.exception))
        self.assertEqual(expected_marker.read_text().strip(), expected)
        self.assertFalse(marker.exists(), "stale bytes must be rejected before destroy")
        self.assertEqual(backend.drained, ["fw0"])
        self.assertEqual(backend.rejoined, [])

    def test_stale_attestation_is_rejected_despite_expected_version_report(self):
        self._signed_image_set()
        stale = self.tmp / "stale-alias.qcow2"
        stale.write_bytes(STALE_BYTES)
        marker = self.tmp / "installed-stale-image"
        actual_stale_sha = hashlib.sha256(STALE_BYTES).hexdigest()
        expected = hashlib.sha256(EXPECTED_BYTES).hexdigest()
        hook = self.tmp / "install-stale-and-attest.sh"
        hook.write_text(
            "#!/bin/sh\n"
            "actual=$(sha256sum \"$STALE_ALIAS_IMAGE\" | cut -d ' ' -f 1)\n"
            "printf '%s\\n' \"$actual\" > \"$XPF_ROLL_ATTESTATION_FILE\"\n"
            "touch \"$DESTROY_MARKER\"\n")
        hook.chmod(0o755)
        args = type("Args", (), {
            "dry_run": False, "backend": "ssh", "nodes": ["fw0", "fw1"],
            "node0_id": 0, "node1_id": 1, "recreate_hook": str(hook),
            "manifest": f"xpf-{NEWVER}.manifest", "sha256sums": None,
            "sig": None, "pubkey": None, "lease_ttl": 1800,
            "drain_deadline": 120, "boot_deadline": 40,
            "allow_session_drop": False, "require_daemon_hold": False,
            "allow_unvalidated": False,
        })()
        backend = _RollBackend()
        patches = [
            mock.patch.object(deploy, "_node_exec", backend.exec),
            mock.patch.object(deploy, "_node_exec_result", backend.exec_result),
            mock.patch.object(deploy, "_verified_image_manifest_versions",
                              lambda *a, **k: dict(NEW_MANIFEST)),
            mock.patch.object(deploy, "_verified_expected_qcow2_digest",
                              lambda *a, **k: (EXPECTED_IMAGE, expected)),
            mock.patch.object(deploy.os.path, "isfile", lambda path: True),
            mock.patch("time.sleep", lambda seconds: None),
        ]
        for patch in patches:
            patch.start()
        try:
            with mock.patch.dict(os.environ, {
                    "STALE_ALIAS_IMAGE": str(stale),
                    "DESTROY_MARKER": str(marker)}):
                with self.assertRaises(SystemExit) as cm:
                    deploy.cmd_image_roll(args)
        finally:
            for patch in reversed(patches):
                patch.stop()

        self.assertIn(expected, str(cm.exception))
        self.assertIn(actual_stale_sha, str(cm.exception))
        self.assertTrue(marker.exists())
        # The fake node truthfully reports the signed version and expected ID;
        # without the byte-digest gate it would satisfy the existing poll.
        self.assertEqual(backend.protocol_nodes, ["fw1"])
        self.assertEqual(backend.drained, ["fw0"])
        self.assertEqual(backend.rejoined, [])

if __name__ == "__main__":
    unittest.main()
