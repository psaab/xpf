#!/usr/bin/env python3
"""Unit tests for the xpf-deploy.py mixed-base HA safety gate and the core
pure functions the deployer relies on (fable-review-165 H-24).

The deployer is 1348 lines imported/executed by nothing. The single most
load-bearing piece is `_gate_mixed_base` — the LANE-2 Python executor of
the single Go rule `upgrade.GateProtocolCompat` (#17091). That gate
decides whether a LANE-2 HA image roll can preserve sessions across the
failover. The Go and Python bodies are pinned against each other by the
SHARED fixture `mixed_base_gate_fixture.json` in this directory,
consumed by MixedBaseFixture17091Tests here and by
TestMixedBaseGateFixture17091 in pkg/upgrade — the vectors are no longer
retyped per language. RED on any fix-forward that relaxes a leg (drops
the session-sync exact-match, treats an unknown peer as compatible, or
widens the HA window).

Also covers the surrounding pure surface H-24 lists as untested:
`_u16`, `_read_image_manifest_versions` (the manifest key round-trip that
feeds the gate), `_node_protocol_versions` (the peer probe parse),
`expected_name` (the positional naming contract), `memory_mb`, and the
`--nic` spec parser in `cmd_launch`.
"""

from __future__ import annotations

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

xpf_deploy = load_subject("xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))


# The Go parity fixture (imageversions_test.go sampleManifest): a bake
# .manifest speaking HA 2, floor 1, session-sync 3.
_SAMPLE_MANIFEST = """version: 1.2.3
git_commit: abcdef
base_release: 26.04
ha_protocol_version: 2
ha_protocol_min_compat: 1
session_sync_protocol_version: 3
configdb_envelope_version: 1
configdb_min_reader_version: 1
"""

# The Go parity fixture (imageversions_test.go sampleProtoVersions): the
# hyphen/equals namespace `xpfd protocol-versions` emits on a running peer.
_SAMPLE_PROTO = """xpf-version=1.2.3
ha-protocol-version=2
ha-protocol-min-compat=1
session-sync-protocol-version=3
configdb-envelope-version=1
configdb-min-reader-version=1
"""


def _manifest_dict(text=_SAMPLE_MANIFEST):
    """Parse a manifest string through the REAL round-trip helper (writes a
    temp file so `_read_image_manifest_versions` opens it exactly as the
    deployer does)."""
    with tempfile.NamedTemporaryFile("w", suffix=".manifest",
                                     delete=False) as f:
        f.write(text)
        path = f.name
    try:
        return xpf_deploy._read_image_manifest_versions(path)
    finally:
        os.unlink(path)


def _peer(ha, sync):
    """A peer protocol-versions dict as `_node_protocol_versions` would
    return it (string values, hyphenated keys)."""
    return {"ha-protocol-version": str(ha),
            "session-sync-protocol-version": str(sync)}


# ── H-24 primary: the mixed-base HA safety gate (Go-parity vectors) ───────
class MixedBaseGateTests(unittest.TestCase):
    def setUp(self):
        self.img = _manifest_dict()  # HA 2, floor 1, sync 3

    # --- survive legs (must match GateProtocolCompat true cases) ---
    def test_peer_in_window_and_sync_match_survives(self):
        survive, reason = xpf_deploy._gate_mixed_base(self.img, _peer(1, 3))
        self.assertTrue(survive, reason)

    def test_same_version_peer_survives(self):
        survive, reason = xpf_deploy._gate_mixed_base(self.img, _peer(2, 3))
        self.assertTrue(survive, reason)

    # --- fail-closed legs (RED on any relaxation) ---
    def test_unknown_peer_ha_fails_closed(self):
        # peer HA 0 (not advertising) -> drop.
        survive, _ = xpf_deploy._gate_mixed_base(self.img, _peer(0, 3))
        self.assertFalse(survive)

    def test_peer_below_compat_floor_fails_closed(self):
        # New image floor raised to 2, peer still on 1 -> below floor.
        img = _manifest_dict(_SAMPLE_MANIFEST.replace(
            "ha_protocol_min_compat: 1", "ha_protocol_min_compat: 2"))
        survive, _ = xpf_deploy._gate_mixed_base(img, _peer(1, 3))
        self.assertFalse(survive)

    def test_peer_newer_than_image_fails_closed(self):
        # peer HA 3 > new image's 2 (a downgrade is not gated safe) -> drop.
        survive, _ = xpf_deploy._gate_mixed_base(self.img, _peer(3, 3))
        self.assertFalse(survive)

    def test_session_sync_mismatch_fails_closed(self):
        # THE mixed-base hazard: peer HA fine (1) but session-sync differs
        # (peer 4, image 3). A fix-forward that drops this exact-match check
        # (e.g. "just compare HA") would let a mismatched-base HA pair roll
        # and silently corrupt synced sessions at the failover. RED here.
        survive, reason = xpf_deploy._gate_mixed_base(self.img, _peer(1, 4))
        self.assertFalse(survive, reason)
        self.assertIn("session-sync", reason)

    def test_unknown_peer_session_sync_fails_closed(self):
        # peer session-sync 0 (unknown) must NOT be skipped as compatible.
        survive, _ = xpf_deploy._gate_mixed_base(self.img, _peer(1, 0))
        self.assertFalse(survive)

    def test_negative_peer_session_sync_fails_closed(self):
        # A signed value out of uint16 range -> _u16 None -> unparsable peer.
        survive, _ = xpf_deploy._gate_mixed_base(self.img, _peer(1, -1))
        self.assertFalse(survive)

    def test_missing_required_key_fails_closed(self):
        img = dict(self.img)
        del img["session-sync-protocol-version"]
        survive, reason = xpf_deploy._gate_mixed_base(img, _peer(1, 3))
        self.assertFalse(survive)
        self.assertIn("session-sync-protocol-version", reason)

    def test_out_of_range_image_version_fails_closed(self):
        # New image manifest itself carries an out-of-uint16 session-sync.
        img = _manifest_dict(_SAMPLE_MANIFEST.replace(
            "session_sync_protocol_version: 3",
            "session_sync_protocol_version: 70000"))
        survive, _ = xpf_deploy._gate_mixed_base(img, _peer(1, 3))
        self.assertFalse(survive)

# ── #17091: shared cross-language fixture (single source of vectors) ────
class MixedBaseFixture17091Tests(unittest.TestCase):
    """Consumes mixed_base_gate_fixture.json — the SAME file the Go
    TestMixedBaseGateFixture17091 reads — so the Python LANE-2 executor
    (_gate_mixed_base, RefuseUnknownWire) and the Go rule
    (GateProtocolCompat) cannot drift behind retyped tables.

    The Python executor judges from string dicts and has no
    target-error channel: a fixture 'error' row (nil/missing target)
    must surface as (False, reason naming the missing key) here, while
    Go surfaces it as ProtocolCompatVerdict.Err. 'permit' rows are
    LANE-1-only: this executor always refuses an unknown wire, so a
    permit/survive row must REFUSE here — that asymmetry is the one
    deliberate policy difference, pinned explicitly.

    RED on mutation: flip the peer_sync == 0 refusal and
    unknown-wire-refuse-policy fails; drop the exact-match leg and
    sync-mismatch fails; widen the HA window and peer-below-floor /
    peer-newer-than-target fail."""

    _FIXTURE = json.loads(
        (Path(__file__).resolve().parent
         / "mixed_base_gate_fixture.json").read_text())

    def test_shared_fixture_vectors(self):
        cases = self._FIXTURE["cases"]
        self.assertTrue(cases, "fixture has no cases")
        for case in cases:
            with self.subTest(case=case["name"]):
                self._run_case(case)

    def _run_case(self, case):
        target = case["target"]
        if target is None:
            # No target at all: the deployer cannot even build a gate
            # input; an empty image dict is the missing-everything case
            # and must fail closed.
            img = {}
        else:
            img = {"ha-protocol-version": str(target["ha"]),
                   "ha-protocol-min-compat": str(target["floor"]),
                   "session-sync-protocol-version": str(target["sync"])}
            for key in case.get("missing", []):
                del img[key]
        peer = {"ha-protocol-version": str(case["peer_ha"]),
                "session-sync-protocol-version": str(case["peer_wire"])}
        survive, reason = xpf_deploy._gate_mixed_base(img, peer)
        expected = case["expected"]
        if case["policy"] == "permit":
            # LANE-1-only policy: the LANE-2 executor refuses an unknown
            # wire, so permit/survive becomes refuse here. Window/HA
            # refusals agree under either policy.
            if expected == "survive":
                expected = "refuse"
        if expected == "survive":
            self.assertTrue(survive, f"{case['name']}: {reason}")
        else:
            # Both 'refuse' and 'error' fail closed in Python; an
            # 'error' row must additionally name the missing key.
            self.assertFalse(survive,
                             f"{case['name']}: survived ({reason})")
            if expected == "error":
                missing = case.get("missing") or []
                if missing:
                    self.assertIn(missing[0], reason,
                                  f"{case['name']}: {reason}")


# ── manifest key round-trip: _read_image_manifest_versions feeds the gate ──
class ManifestRoundTripTests(unittest.TestCase):
    def test_underscores_become_hyphens(self):
        d = _manifest_dict()
        # The gate reads hyphenated keys; the manifest ships underscores.
        self.assertEqual(d["ha-protocol-version"], "2")
        self.assertEqual(d["ha-protocol-min-compat"], "1")
        self.assertEqual(d["session-sync-protocol-version"], "3")

    def test_comments_and_blank_lines_skipped(self):
        d = _manifest_dict("# a comment\n\nha_protocol_version: 2\n"
                            "ha_protocol_min_compat: 1\n"
                            "session_sync_protocol_version: 3\n")
        self.assertEqual(set(d.keys()),
                         {"ha-protocol-version", "ha-protocol-min-compat",
                          "session-sync-protocol-version"})

    def test_round_trip_output_gates_true(self):
        # End to end: a real manifest file parsed and fed to the gate against
        # a compatible peer must survive — proves the two helpers agree on
        # the key namespace.
        survive, reason = xpf_deploy._gate_mixed_base(_manifest_dict(),
                                                      _peer(1, 3))
        self.assertTrue(survive, reason)


# ── _u16: uint16 bounds mirroring strconv.ParseUint(.,10,16) ──────────────
class U16Tests(unittest.TestCase):
    def test_valid_range(self):
        self.assertEqual(xpf_deploy._u16("0"), 0)
        self.assertEqual(xpf_deploy._u16("65535"), 0xFFFF)
        self.assertEqual(xpf_deploy._u16("2"), 2)

    def test_negative_rejected(self):
        self.assertIsNone(xpf_deploy._u16("-1"))

    def test_over_range_rejected(self):
        self.assertIsNone(xpf_deploy._u16("70000"))
        self.assertIsNone(xpf_deploy._u16("65536"))

    def test_non_numeric_rejected(self):
        self.assertIsNone(xpf_deploy._u16("x"))
        self.assertIsNone(xpf_deploy._u16(""))
        self.assertIsNone(xpf_deploy._u16(None))


# ── _node_protocol_versions: parse the peer probe (key=value) ─────────────
class NodeProtocolVersionsTests(unittest.TestCase):
    def setUp(self):
        self._orig = xpf_deploy._node_exec

    def tearDown(self):
        xpf_deploy._node_exec = self._orig

    def test_parses_key_equals_value(self):
        xpf_deploy._node_exec = lambda *a, **k: _SAMPLE_PROTO
        d = xpf_deploy._node_protocol_versions(None, "incus", "fw0")
        self.assertEqual(d["ha-protocol-version"], "2")
        self.assertEqual(d["session-sync-protocol-version"], "3")
        # And it feeds the gate directly (peer probe -> gate parity).
        survive, reason = xpf_deploy._gate_mixed_base(_manifest_dict(), d)
        self.assertTrue(survive, reason)

    def test_ignores_non_kv_lines(self):
        xpf_deploy._node_exec = lambda *a, **k: (
            "banner line\nha-protocol-version=2\n\n")
        d = xpf_deploy._node_protocol_versions(None, "incus", "fw0")
        self.assertEqual(d, {"ha-protocol-version": "2"})


# ── expected_name: the positional naming contract ─────────────────────────
class ExpectedNameTests(unittest.TestCase):
    def test_position_one_is_fxp0(self):
        self.assertEqual(xpf_deploy.expected_name(0, "standalone", None), "fxp0")
        self.assertEqual(xpf_deploy.expected_name(0, "cluster", 1), "fxp0")

    def test_standalone_ge_naming(self):
        self.assertEqual(xpf_deploy.expected_name(1, "standalone", None), "ge-0/0/0")
        self.assertEqual(xpf_deploy.expected_name(3, "standalone", None), "ge-0/0/2")

    def test_cluster_em0_then_fpc(self):
        self.assertEqual(xpf_deploy.expected_name(1, "cluster", 0), "em0")
        # node 0 uses FPC 0, node 1 uses FPC 7.
        self.assertEqual(xpf_deploy.expected_name(2, "cluster", 0), "ge-0/0/0")
        self.assertEqual(xpf_deploy.expected_name(2, "cluster", 1), "ge-7/0/0")
        self.assertEqual(xpf_deploy.expected_name(3, "cluster", 1), "ge-7/0/1")


# ── memory_mb ─────────────────────────────────────────────────────────────
class MemoryMbTests(unittest.TestCase):
    def test_gigabytes(self):
        self.assertEqual(xpf_deploy.memory_mb("4G"), 4096)
        self.assertEqual(xpf_deploy.memory_mb("2GiB"), 2048)

    def test_megabytes_default(self):
        self.assertEqual(xpf_deploy.memory_mb("512"), 512)
        self.assertEqual(xpf_deploy.memory_mb("512M"), 512)

    def test_unparseable_dies(self):
        with self.assertRaises(SystemExit):
            xpf_deploy.memory_mb("lots")


# ── --nic spec parser (cmd_launch) ────────────────────────────────────────
class NicSpecParserTests(unittest.TestCase):
    class _Args:
        pass

    def _launch_interfaces(self, nics):
        """Drive cmd_launch far enough to capture the parsed interface list
        via a validate_appliance stub, without deploying."""
        captured = {}
        orig_validate = xpf_deploy.validate_appliance
        orig_deploy = xpf_deploy.deploy
        xpf_deploy.validate_appliance = lambda ap, where: captured.update(ap)
        xpf_deploy.deploy = lambda ap, args: None
        try:
            a = self._Args()
            a.nic = nics
            a.name = "fw"
            a.mode = "standalone"
            a.node_id = None
            a.image = "xpf-appliance"
            a.cpu = 2
            a.mem = "4G"
            a.config = None
            xpf_deploy.cmd_launch(a)
        finally:
            xpf_deploy.validate_appliance = orig_validate
            xpf_deploy.deploy = orig_deploy
        return captured["interfaces"]

    def test_backing_prefix_split(self):
        ifs = self._launch_interfaces(
            ["bridge:br-mgmt", "sriov:enp8s0", "pci:0000:09:00.0"])
        self.assertEqual(ifs[0], {"backing": "bridge", "source": "br-mgmt"})
        self.assertEqual(ifs[1], {"backing": "sriov", "source": "enp8s0"})
        # The pci: source keeps its full BDF (only the FIRST ':' splits kind).
        self.assertEqual(ifs[2],
                         {"backing": "pci", "source": "0000:09:00.0"})

    def test_bare_spec_defaults_to_net(self):
        ifs = self._launch_interfaces(["mgmtnet"])
        self.assertEqual(ifs[0], {"backing": "net", "source": "mgmtnet"})

    def test_mac_suffix_extracted(self):
        ifs = self._launch_interfaces(["bridge:br0,mac=02:00:00:00:00:01"])
        self.assertEqual(ifs[0]["mac"], "02:00:00:00:00:01")
        self.assertEqual(ifs[0]["source"], "br0")


# ── #5042: the mixed-base gate input must be SIGNED ───────────────────────
class MixedBaseSignedManifestTests(unittest.TestCase):
    """The protocol sidecar xpf-<ver>.manifest carries the ha-protocol /
    session-sync fields the mixed-base HA session-safety gate reads. Before
    #5042 the deployer parsed it RAW, so tampering ONLY that sidecar — while
    every signed image byte (the qcow2 + the signed SHA256SUMS + its .minisig)
    stayed untouched — could spoof a compatible-window / matching-session-sync
    decision and bypass the session-safety stop.

    _verified_image_manifest_versions now binds the sidecar to the signed
    SHA256SUMS via sign.verify_listed_artifact_bytes. These vectors pin that a
    protocol-field tamper is caught (fail closed). RED on a fix-forward that
    reverts to reading the sidecar raw / drops the checksum binding."""

    def setUp(self):
        here = Path(__file__).resolve().parent
        sys.path.insert(0, str(here.parent / "dist"))
        import sign
        self.sign = sign
        self.tmp = tempfile.mkdtemp(prefix="xpf-5042-test-")
        # A non-placeholder pubkey path so _resolve_pubkey accepts it.
        self.pub = os.path.join(self.tmp, "test.pub")
        with open(self.pub, "w") as f:
            f.write("untrusted-test-key\n")
        # The signed SHA256SUMS + its .minisig are the SIGNED bytes an attacker
        # does NOT touch, so model them as validly signed: neutralize the
        # minisign check and exercise the CHECKSUM binding (pure Python), which
        # is what actually catches a tampered sidecar. A real end-to-end
        # minisign chain is covered separately when the binary is present.
        self._orig_verify_sig = sign.verify_signature
        sign.verify_signature = lambda m, s, p: None

    def tearDown(self):
        self.sign.verify_signature = self._orig_verify_sig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _stage(self, manifest_text, list_manifest=True):
        """Write a sidecar + a signed-manifest covering it (+ a stub .minisig)."""
        manifest = os.path.join(self.tmp, "xpf-1.2.3.manifest")
        with open(manifest, "w") as f:
            f.write(manifest_text)
        sums = os.path.join(self.tmp, "xpf-1.2.3.SHA256SUMS")
        listed = [manifest] if list_manifest else []
        if not listed:
            # a decoy so the manifest is non-empty but does NOT cover the sidecar
            decoy = os.path.join(self.tmp, "decoy.bin")
            with open(decoy, "w") as f:
                f.write("x")
            listed = [decoy]
        self.sign.write_manifest(sums, listed)
        sig = sums + ".minisig"
        with open(sig, "w") as f:
            f.write("stub-signature (verify_signature patched)\n")
        return manifest, sums, sig

    def test_untampered_sidecar_verifies_parses_and_gates(self):
        manifest, sums, sig = self._stage(_SAMPLE_MANIFEST)
        img = xpf_deploy._verified_image_manifest_versions(
            manifest, sums, sig, self.pub)
        self.assertEqual(img["session-sync-protocol-version"], "3")
        survive, reason = xpf_deploy._gate_mixed_base(img, _peer(1, 3))
        self.assertTrue(survive, reason)

    def test_tampered_protocol_field_fails_closed(self):
        manifest, sums, sig = self._stage(_SAMPLE_MANIFEST)
        # Attacker rewrites ONLY the sidecar's session-sync field to spoof a
        # matching-sync decision; the signed SHA256SUMS + .minisig still list
        # the ORIGINAL sidecar hash.
        with open(manifest, "w") as f:
            f.write(_SAMPLE_MANIFEST.replace(
                "session_sync_protocol_version: 3",
                "session_sync_protocol_version: 4"))
        with self.assertRaises(self.sign.SignError):
            xpf_deploy._verified_image_manifest_versions(
                manifest, sums, sig, self.pub)

    def test_sidecar_not_in_signed_manifest_fails_closed(self):
        manifest, sums, sig = self._stage(_SAMPLE_MANIFEST, list_manifest=False)
        with self.assertRaises(self.sign.SignError):
            xpf_deploy._verified_image_manifest_versions(
                manifest, sums, sig, self.pub)

    def test_default_sums_sibling_of_manifest(self):
        self.assertEqual(
            xpf_deploy._default_sums_for_manifest("/d/xpf-1.2.3.manifest"),
            "/d/xpf-1.2.3.SHA256SUMS")
        self.assertIsNone(xpf_deploy._default_sums_for_manifest("/d/weird.txt"))

    def test_real_minisign_end_to_end_tamper(self):
        """Full chain when minisign is installed: real keygen -> sign the
        SHA256SUMS -> verify (pass) -> tamper the sidecar -> verify (fail)."""
        if not shutil.which("minisign"):
            self.skipTest("minisign not installed")
        # Use the REAL signature verification for this leg.
        self.sign.verify_signature = self._orig_verify_sig
        sec = os.path.join(self.tmp, "e2e.key")
        pub = os.path.join(self.tmp, "e2e.pub")
        r = subprocess.run(["minisign", "-G", "-W", "-p", pub, "-s", sec],
                           capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest(f"minisign keygen unavailable (-W): {r.stderr.strip()}")
        manifest = os.path.join(self.tmp, "xpf-9.9.9.manifest")
        with open(manifest, "w") as f:
            f.write(_SAMPLE_MANIFEST)
        sums = os.path.join(self.tmp, "xpf-9.9.9.SHA256SUMS")
        self.sign.write_manifest(sums, [manifest])
        self.sign.sign_manifest(sums, sec)
        sig = sums + ".minisig"
        img = xpf_deploy._verified_image_manifest_versions(manifest, sums, sig, pub)
        self.assertTrue(xpf_deploy._gate_mixed_base(img, _peer(1, 3))[0])
        with open(manifest, "w") as f:
            f.write(_SAMPLE_MANIFEST.replace(
                "session_sync_protocol_version: 3",
                "session_sync_protocol_version: 4"))
        with self.assertRaises(self.sign.SignError):
            xpf_deploy._verified_image_manifest_versions(manifest, sums, sig, pub)


if __name__ == "__main__":
    unittest.main()
