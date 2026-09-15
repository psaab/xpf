#!/usr/bin/env python3
"""Unit tests for #4904 B — the Ubuntu base image is authenticated against a
repo-PINNED SHA256 trust anchor, not just a checksum fetched from the SAME
mirror endpoint as the image.

`scripts/image/bake.py` fetched the cloud image AND its SHA256SUMS from the
same configurable base_url, so a compromised/custom mirror (or a TLS/DNS/CA
compromise) could serve matching malicious bytes+hash and XPF would sign the
result with its release key. The fix pins the expected base-image digest in
reviewed repo metadata (`PINNED_BASE_SHA256`, Canonical-GPG-verified) and
enforces it in `authenticate_base_digest`, and binds the pin-provenance flag
into the signed manifest (`build_manifest_text`).

These tests are hermetic (no network, no libguestfs). On revert (drop the pin
enforcement / return True unconditionally) the mismatch + unpinned tests go RED.
"""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "bake", Path(__file__).with_name("bake.py")
)
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)

# A distinct, syntactically-valid digest that is NOT any real pin.
FAKE = "a" * 64


class _EnvGuard(unittest.TestCase):
    """Isolate the env vars this feature reads so tests never leak state."""

    _KEYS = ("XPF_BASE_SHA256", "XPF_ALLOW_UNPINNED_BASE")

    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in self._KEYS}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class PinnedConstantTests(_EnvGuard):
    """The reviewed repo pin exists for the pinned release and is a real
    sha256. Guards against a truncated/whitespaced pin slipping in."""

    def test_pinned_release_has_a_pin(self):
        pin = bake.PINNED_BASE_SHA256.get(bake.PINNED_BASE_RELEASE)
        self.assertIsNotNone(
            pin, f"no PINNED_BASE_SHA256 entry for the pinned release "
                 f"{bake.PINNED_BASE_RELEASE!r} — the default `make image` base "
                 "would be unauthenticated against a trust anchor (#4904 B).")
        self.assertRegex(pin.lower(), r"^[0-9a-f]{64}$",
                         "the pinned base digest must be a bare sha256 hex.")

    def test_2604_pin_matches_canonical_gpg_verified_value(self):
        # The 26.04 pin is authored by verifying Canonical's SHA256SUMS.gpg
        # against the UEC signing key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81.
        # Current value is Canonical's 2026-08 respin (bumped in bake.py by
        # 5fb53d7a1); re-verified here independently:
        #   gpg: Signature made Tue 04 Aug 2026 01:46:14 PM PDT
        #   gpg:                using RSA key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81
        #   gpg: Good signature from "UEC Image Automatic Signing Key <cdimage@ubuntu.com>"
        # The constant is duplicated here ON PURPOSE: the trust anchor must not
        # be able to move without a reviewer seeing it in a diff. Both places
        # move together, or this test is what says so.
        self.assertEqual(
            bake.PINNED_BASE_SHA256.get("26.04"),
            "9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05")


class ResolveBasePinTests(_EnvGuard):
    def test_repo_constant(self):
        self.assertEqual(bake.resolve_base_pin("26.04"),
                         bake.PINNED_BASE_SHA256["26.04"])

    def test_unpinned_release_is_none(self):
        self.assertIsNone(bake.resolve_base_pin("99.99"))

    def test_env_override_wins_and_is_normalized(self):
        os.environ["XPF_BASE_SHA256"] = "  " + FAKE.upper() + "  "
        # Even for a release with a repo pin, the reviewed env override wins.
        self.assertEqual(bake.resolve_base_pin("26.04"), FAKE)


class AuthenticateBaseDigestTests(_EnvGuard):
    def test_matching_pin_authenticates(self):
        pin = bake.PINNED_BASE_SHA256["26.04"]
        self.assertTrue(bake.authenticate_base_digest("26.04", pin))
        # Case/whitespace-insensitive on the actual side too.
        self.assertTrue(bake.authenticate_base_digest("26.04", pin.upper()))

    def test_mismatch_aborts(self):
        # RED on revert: without pin enforcement this would return True.
        with self.assertRaises(SystemExit) as ctx:
            bake.authenticate_base_digest("26.04", FAKE)
        self.assertNotEqual(ctx.exception.code, 0)

    def test_unpinned_without_escape_hatch_aborts(self):
        with self.assertRaises(SystemExit) as ctx:
            bake.authenticate_base_digest("99.99", FAKE)
        self.assertNotEqual(ctx.exception.code, 0)

    def test_unpinned_with_escape_hatch_returns_false(self):
        os.environ["XPF_ALLOW_UNPINNED_BASE"] = "1"
        # Explicit dev opt-out: proceeds but marks the base UNPINNED.
        self.assertFalse(bake.authenticate_base_digest("99.99", FAKE))

    def test_env_pin_match_and_mismatch(self):
        os.environ["XPF_BASE_SHA256"] = FAKE
        self.assertTrue(bake.authenticate_base_digest("99.99", FAKE))
        with self.assertRaises(SystemExit):
            bake.authenticate_base_digest("99.99", "b" * 64)


class ManifestProvenanceBindingTests(_EnvGuard):
    """#4904 A+B: the signed manifest binds `validated` and the base digest +
    `base_image_pinned` provenance. build_manifest_text is the pure assembler
    main() writes, so we assert the fields without a full bake."""

    def _text(self, *, base_pinned, validated):
        return bake.build_manifest_text(
            ver="9.9.9-test", commit="deadbeef",
            base_url="https://mirror.invalid/rel", base_img="ubuntu.img",
            rel="26.04", base_sha=FAKE, base_pinned=base_pinned,
            validated=validated, bake_date="2026-01-01T00:00:00Z",
            kernel="6.18.0-test", guest_kernel="7.0.0-15-generic")

    def test_base_digest_and_pin_bound(self):
        t = self._text(base_pinned=True, validated=True)
        self.assertIn(f"base_image_sha256: {FAKE}\n", t)
        self.assertIn("base_image_pinned: true\n", t)
        self.assertIn("base_image: https://mirror.invalid/rel/ubuntu.img\n", t)

    def test_guest_kernel_is_bound_and_distinct_from_the_build_host(self):
        # #6500: `bake_host_kernel` is os.uname().release on the BUILD HOST and
        # answers a different question from "what does this image ship". Both
        # must be present and they must not be conflated.
        t = self._text(base_pinned=True, validated=True)
        self.assertIn("guest_kernel: 7.0.0-15-generic\n", t)
        self.assertIn("bake_host_kernel: 6.18.0-test\n", t)

    def test_guest_kernel_is_a_required_keyword(self):
        # Not defaulted: a caller that forgets it must fail at the call site,
        # not ship a manifest the publish gate then refuses three steps later.
        with self.assertRaises(TypeError):
            bake.build_manifest_text(
                ver="9.9.9-test", commit="deadbeef",
                base_url="https://mirror.invalid/rel", base_img="ubuntu.img",
                rel="26.04", base_sha=FAKE, base_pinned=True,
                validated=True, bake_date="2026-01-01T00:00:00Z",
                kernel="6.18.0-test")

    def test_validated_true_and_false(self):
        self.assertIn("validated: true\n",
                      self._text(base_pinned=True, validated=True))
        self.assertIn("validated: false\n",
                      self._text(base_pinned=True, validated=False))
        self.assertIn("base_image_pinned: false\n",
                      self._text(base_pinned=False, validated=True))


class InventoryWiringTests(unittest.TestCase):
    """#6500: the pure pieces are unit-tested, but a bake main() that never
    CALLS them records nothing. main() itself needs libguestfs and a real base
    image, so these pin the call sites in source — deleting one reds here
    instead of silently shipping an image with no traceability record."""

    SRC = Path(__file__).resolve().parent.joinpath("bake.py").read_text(
        encoding="utf-8")

    def test_virt_customize_runs_the_inventory_writer(self):
        self.assertIn("image_inventory.WRITE_CMD", self.SRC)

    def test_the_inventory_is_read_back_offline_with_virt_cat(self):
        # virt-cat, not a boot: the record must be extractable without running
        # the appliance, which is the point of recording it at all.
        self.assertIn('"virt-cat", "-a", work_qcow', self.SRC)
        self.assertIn('("virt-cat", "apt-get install libguestfs-tools")',
                      self.SRC)

    def test_the_pkgs_sidecar_joins_the_SIGNED_checksum_set(self):
        # Outside the signed set it is unauthenticated metadata — exactly the
        # gap #5042 closed for the .manifest sidecar. #9920: the set is the
        # SSOT shared with the strict sign-manifest gate (its four members are
        # pinned in scripts/dist/test_dist_resign_9920.py).
        self.assertIn("sign.write_manifest(", self.SRC)
        self.assertIn("sign.bake_set_basenames(ver)", self.SRC)

    def test_a_bad_inventory_aborts_the_bake(self):
        self.assertIn("image_inventory.InventoryError", self.SRC)

    def test_main_passes_the_guest_kernel_into_the_manifest(self):
        self.assertIn("guest_kernel=guest_kernel", self.SRC)


if __name__ == "__main__":
    unittest.main()
