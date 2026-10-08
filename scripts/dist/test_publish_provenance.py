#!/usr/bin/env python3
"""Unit tests for #4904 A — publish REFUSES a --skip-validate (unvalidated)
image.

A `--skip-validate` bake still produces a fully signed manifest/signature set
that is byte-shape-indistinguishable from a validated release, so the
fail-closed publish gate would ship a dev/emergency image that never booted or
verified the dataplane. bake.py now binds a signed `validated: true|false`
field into the xpf-<ver>.manifest provenance sidecar (covered by the signed
xpf-<ver>.SHA256SUMS); publish.gate_provenance REQUIRES validated: true.

These tests build a real minisign-signed image set with a throwaway key (SKIP
if minisign is absent) and drive publish.gate_provenance directly. On revert
(drop the gate / accept validated:false) the negative cases go RED.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("publish", _DIST / "publish.py")
publish = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(publish)

# sign.py sits beside publish.py; publish already puts _DIST on sys.path.
import image_inventory  # noqa: E402  (#6500 sidecar name)
import sign  # noqa: E402

_HAVE_MINISIGN = shutil.which("minisign") is not None
_HAVE_GPG = shutil.which("gpg") is not None
_IMAGE_TOOLS = ("virt-make-fs", "virt-filesystems", "virt-cat")
_HAVE_IMAGE_TOOLS = all(shutil.which(tool) for tool in _IMAGE_TOOLS)
VER = "0.0.0-provtest"
KVER = "7.0.0-15-generic"


@unittest.skipUnless(_HAVE_MINISIGN and _HAVE_GPG and _HAVE_IMAGE_TOOLS,
                     "minisign, gpg, and libguestfs image tools required")
class GateProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._fixture = tempfile.TemporaryDirectory(prefix="xpf-provtest-image-")
        cls.addClassCleanup(cls._fixture.cleanup)
        home = Path(cls._fixture.name) / "gnupg"
        home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(home))
        batch = Path(cls._fixture.name) / "key.batch"
        batch.write_text(
            "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
            "Key-Usage: sign\nName-Real: provenance test archive\n"
            "Name-Email: provtest@xpf.invalid\nExpire-Date: 0\n%commit\n")
        subprocess.run(["gpg", "--batch", "--gen-key", str(batch)],
                       env=env, check=True, capture_output=True)
        cls._archive_key = Path(cls._fixture.name) / "archive.asc"
        with cls._archive_key.open("wb") as out:
            subprocess.run(
                ["gpg", "--batch", "--armor", "--export",
                 "provtest@xpf.invalid"], env=env, check=True, stdout=out)
        stale_batch = Path(cls._fixture.name) / "stale-key.batch"
        stale_batch.write_text(
            "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
            "Key-Usage: sign\nName-Real: stale provenance test archive\n"
            "Name-Email: stale-provtest@xpf.invalid\n"
            "Expire-Date: 0\n%commit\n")
        subprocess.run(["gpg", "--batch", "--gen-key", str(stale_batch)],
                       env=env, check=True, capture_output=True)
        cls._stale_archive_key = Path(cls._fixture.name) / "stale-archive.asc"
        with cls._stale_archive_key.open("wb") as out:
            subprocess.run(
                ["gpg", "--batch", "--armor", "--export",
                 "stale-provtest@xpf.invalid"], env=env, check=True,
                stdout=out)
        cls._qcow_template = Path(cls._fixture.name) / "keyring.qcow2"
        cls._make_keyring_image(cls._archive_key.read_bytes(),
                                cls._qcow_template)

    @classmethod
    def _make_keyring_image(cls, key_data, output):
        root = Path(cls._fixture.name) / f"guest-{output.stem}"
        key = root / sign.ARCHIVE_KEYRING_GUEST_PATH.lstrip("/")
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_bytes(key_data)
        subprocess.run(
            ["virt-make-fs", "--format=qcow2", "--type=ext4",
             "--partition=mbr", str(root), str(output)],
            check=True, capture_output=True, timeout=60)

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-provtest-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.pub = os.path.join(self.dir, "img.pub")
        self.sec = os.path.join(self.dir, "img.sec")
        subprocess.run(["minisign", "-G", "-W", "-p", self.pub, "-s", self.sec],
                       check=True, capture_output=True)
        self.qcow = os.path.join(self.dir, f"xpf-{VER}.qcow2")
        self.meta = os.path.join(self.dir, f"xpf-{VER}.incus-metadata.tar.gz")
        shutil.copyfile(self._qcow_template, self.qcow)
        Path(self.meta).write_bytes(b"\x00fake-meta\x00")
        self.sidecar = os.path.join(self.dir, f"xpf-{VER}.manifest")
        self.sums = os.path.join(self.dir, f"xpf-{VER}.SHA256SUMS")
        self.pkgs = os.path.join(self.dir, image_inventory.sidecar_name(VER))

    def _sign_set(self, validated, base_pinned=True, guest_kernel=KVER,
                  inventory=KVER, npkgs=60, xpf_version=VER,
                  manifest_version=VER):
        """(Re)write the provenance sidecar + the #6500 inventory sidecar and
        sign a manifest covering qcow + meta + both sidecars (mirrors a bake).

        `base_pinned=None` omits the base_image_pinned line entirely, modelling
        an old/tampered sidecar that never asserts pinning (#5815 fail-closed
        missing-key case). `guest_kernel=None` likewise omits guest_kernel (an
        older bake predating #6500). `inventory=None` writes NO xpf-<ver>.pkgs
        at all; otherwise it is the kernel the inventory records, so a value
        different from `guest_kernel` models two authenticated records that
        disagree. `npkgs` below the floor models a HOLLOW inventory.

        Every DEFAULT is a valid input, so a negative case that varies ONE of
        them is refused for the reason it names — a fixture that left several
        inputs broken at once could not tell which check fired."""
        text = f"version: {manifest_version}\n"
        if base_pinned is not None:
            text += f"base_image_pinned: {'true' if base_pinned else 'false'}\n"
        text += f"validated: {'true' if validated else 'false'}\n"
        if guest_kernel is not None:
            text += f"guest_kernel: {guest_kernel}\n"
        Path(self.sidecar).write_text(text)
        artifacts = [self.qcow, self.meta, self.sidecar]
        if inventory is not None:
            body = ["# xpf appliance image inventory",
                    f"guest_kernel: {inventory}", "packages:"]
            body += [f"pkg{i}=1.0-{i}" for i in range(npkgs)]
            if xpf_version is not None:
                body.append(f"xpf={xpf_version}")
            Path(self.pkgs).write_text("\n".join(body) + "\n")
            artifacts.append(self.pkgs)
        elif os.path.exists(self.pkgs):
            os.remove(self.pkgs)
        sign.write_manifest(self.sums, artifacts)
        sign.sign_manifest(self.sums, self.sec, comment="provtest")

    def _refused(self, needle):
        """gate_provenance must refuse, and its message must name the property
        under test. Asserting only `SystemExit != 0` cannot distinguish WHICH
        check fired, so a reordered or newly-added gate would silently satisfy
        every negative for the wrong reason."""
        with self.assertRaises(SystemExit) as ctx:
            publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn(needle, str(ctx.exception.code))

    def test_validated_true_passes(self):
        # Regression guard: a fully-pinned validated bake still publishes
        # (validated:true AND base_image_pinned:true → no regression).
        self._sign_set(validated=True, base_pinned=True)
        # Should not raise.
        publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)

    def test_base_unpinned_refused(self):
        # #5815: a signed sidecar that is otherwise valid (validated:true) but
        # says base_image_pinned:false (an XPF_ALLOW_UNPINNED_BASE=1 dev bake)
        # must NOT publish. RED on revert: drop the base_image_pinned check ->
        # no SystemExit here.
        self._sign_set(validated=True, base_pinned=False)
        self._refused("base_image_pinned")

    def test_base_pinned_missing_refused(self):
        # #5815 fail-closed: a signed sidecar that never asserts base_image_pinned
        # (old/tampered manifest) is NOT publishable — a sidecar that does not
        # assert pinning must not default-allow.
        self._sign_set(validated=True, base_pinned=None)
        self._refused("base_image_pinned")

    def test_validated_false_refused(self):
        self._sign_set(validated=False)
        # RED on revert: gate_provenance gone -> no SystemExit here.
        self._refused("validated=")

    def test_missing_sidecar_refused(self):
        self._sign_set(validated=True)
        os.remove(self.sidecar)
        self._refused("no provenance sidecar")

    def test_unsigned_tampered_sidecar_refused(self):
        # Sidecar hash-covered by the signed manifest, then swapped on disk to
        # say validated:true — verify_listed_artifact_bytes must reject the
        # hash mismatch (TOCTOU-safe), so a post-sign flip cannot slip through.
        self._sign_set(validated=False)
        Path(self.sidecar).write_text(
            f"version: {VER}\nbase_image_pinned: true\nvalidated: true\n"
            f"guest_kernel: {KVER}\n")
        self._refused("failed verify")


    # ── #6500: the record must say what the image SHIPS ──────────────
    def test_missing_guest_kernel_refused(self):
        # An older bake predating #6500: fully validated and pinned, with a
        # complete inventory sidecar — refused solely for the absent field.
        self._sign_set(validated=True, guest_kernel=None)
        self._refused("no guest_kernel")

    def test_missing_inventory_sidecar_refused(self):
        self._sign_set(validated=True, inventory=None)
        self._refused("no inventory sidecar")

    def test_hollow_inventory_refused(self):
        # Present, signed, and answering nothing. A presence check would pass
        # it — which is why the gate parses rather than stats.
        self._sign_set(validated=True, npkgs=3)
        self._refused("not a usable inventory")

    def test_inventory_without_a_kernel_line_refused(self):
        self._sign_set(validated=True)
        body = Path(self.pkgs).read_text().replace(f"guest_kernel: {KVER}\n", "")
        Path(self.pkgs).write_text(body)
        sign.write_manifest(self.sums, [self.qcow, self.meta, self.sidecar, self.pkgs])
        sign.sign_manifest(self.sums, self.sec, comment="provtest")
        self._refused("not a usable inventory")

    def test_kernel_disagreement_between_the_two_signed_records_refused(self):
        # Both records are inside the SAME signature, so they cannot disagree
        # on an untampered bake — a divergence means the signed set was
        # re-assembled.
        self._sign_set(validated=True, guest_kernel=KVER, inventory="9.9.9-other")
        self._refused("cannot disagree")

    def test_manifest_version_mismatch_refused(self):
        self._sign_set(validated=True, manifest_version="0.0.1+gold")
        self._refused("provenance records version")

    def test_stale_package_version_refused(self):
        self._sign_set(validated=True, xpf_version="0.0.1+gold")
        self._refused("inventory records xpf versions")

    def test_missing_package_version_refused(self):
        self._sign_set(validated=True, xpf_version=None)
        self._refused("inventory records xpf versions")

    def test_unsigned_inventory_sidecar_refused(self):
        # Covered by the signed manifest, then swapped on disk: the hash check
        # must reject it rather than parse whatever is there now.
        self._sign_set(validated=True)
        Path(self.pkgs).write_text(
            "# xpf appliance image inventory\n"
            f"guest_kernel: {KVER}\npackages:\n"
            + "".join(f"evil{i}=1.0\n" for i in range(60)))
        self._refused("failed verify")

    def test_complete_set_publishes(self):
        # The positive control for all of the above: nothing here refuses a
        # good bake.
        self._sign_set(validated=True)
        publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)

    def test_placeholder_keyring_inside_signed_image_is_refused(self):
        placeholder = (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "PLACEHOLDER-xpf-archive-keyring-not-yet-issued\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n").encode()
        bad_image = Path(self.dir) / "placeholder.qcow2"
        self._make_keyring_image(placeholder, bad_image)
        shutil.copyfile(bad_image, self.qcow)
        self._sign_set(validated=True)
        self._refused("PLACEHOLDER archive keyring")

    def test_unparseable_keyring_inside_signed_image_is_refused(self):
        bad_image = Path(self.dir) / "unparseable.qcow2"
        self._make_keyring_image(b"not an OpenPGP public key\n", bad_image)
        shutil.copyfile(bad_image, self.qcow)
        self._sign_set(validated=True)
        self._refused("no valid installed archive keyring")

    def test_image_keyring_must_cover_installer_key(self):
        self._sign_set(validated=True)
        installer = Path(self.dir) / "install.sh"
        installer.write_text(
            "#!/bin/sh\ncat <<'KEY'\n"
            + self._stale_archive_key.read_text()
            + "KEY\n")
        self._refused("does not cover install.sh key")



class ParseManifestFieldsTests(unittest.TestCase):
    def test_parse(self):
        # #9920: the parser lives in sign now (publish imports it); same cases.
        fields = sign.parse_sidecar_fields(
            "version: 1.2.3\n# comment\nvalidated: true\n"
            "base_image_pinned: false\nblank\n\n")
        self.assertEqual(fields["validated"], "true")
        self.assertEqual(fields["base_image_pinned"], "false")
        self.assertEqual(fields["version"], "1.2.3")
        self.assertNotIn("# comment", fields)


if __name__ == "__main__":
    unittest.main()
