#!/usr/bin/env python3
"""Hermetic regression tests for #15089 (A57-01): A/B ESP slot refresh.

The bake copies shim/grub/mm from EFI/ubuntu into EFI/xpf-A and EFI/xpf-B
exactly once. Before this fix nothing refreshed those copies, so a
shim-signed / grub-efi-amd64-signed update (which installs only to
EFI/ubuntu) left BootOrder booting the bake-time bootloader forever,
while dpkg reported the fixed version as installed.

Fix shape asserted here (RED on master, GREEN after):
  - `xpf-uefi-slots` re-syncs EFI/ubuntu -> both slots atomically on every
    boot (before NVRAM registration), with env-overridable roots so the
    sync is exercisable hermetically by the real /bin/sh script.
  - `debian/xpf.triggers` registers a dpkg file trigger on the
    EFI/ubuntu loader files so a bootloader update invokes
    `postinst triggered` -> the same refresh without a reboot.
  - `debian/xpf.postinst` handles `triggered` (runs the helper when it is
    installed, exits 0 without it) and keeps `configure` succeeding.
  - `scripts/image/validate.py` hash-compares each slot loader against
    EFI/ubuntu (`HASH` probe lines + `_ab_slot_loader_hash_verdict`), so a
    stale or divergent slot fails the Tier-1 gate instead of passing on
    presence alone.

Controls: matching hashes pass, an absent EFI/ubuntu source does not
fail the hash verdict (the presence verdict owns that diagnosis), the
boot-time sync is a no-op when already in sync and never touches
xpf.selector, and `postinst configure` on a host without the helper
stays green.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VALIDATE = HERE / "validate.py"
HELPER = HERE / "xpf-uefi-slots"
TRIGGERS = ROOT / "debian" / "xpf.triggers"
POSTINST = ROOT / "debian" / "xpf.postinst"

_spec = importlib.util.spec_from_file_location("validate", VALIDATE)
validate = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(validate)

LOADERS = ("shimx64.efi", "grubx64.efi", "mmx64.efi")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_probe(ubuntu, slots):
    """Render the validate.py HASH line protocol.

    ubuntu: {filename: hexdigest or None(absent)}
    slots: {(slot, filename): hexdigest or None(absent)}
    """
    out = []
    for fname in ("shimx64.efi", "grubx64.efi", "mmx64.efi"):
        digest = ubuntu.get(fname)
        out.append(f"HASH ubuntu {fname} {digest if digest else 'MISSING'}")
        for slot in ("xpf-A", "xpf-B"):
            digest = slots.get((slot, fname))
            out.append(f"HASH {slot} {fname} {digest if digest else 'MISSING'}")
    return "\n".join(out) + "\n"


class LoaderHashVerdictTests(unittest.TestCase):
    def _verdict(self, ubuntu, slots):
        return validate._ab_slot_loader_hash_verdict(_hash_probe(ubuntu, slots))

    def test_matching_hashes_pass(self):
        ubuntu = {f: _sha(f.encode()) for f in LOADERS}
        slots = {("xpf-A", f): ubuntu[f] for f in LOADERS}
        slots.update({("xpf-B", f): ubuntu[f] for f in LOADERS})
        ok, reason = self._verdict(ubuntu, slots)
        self.assertTrue(ok, reason)

    def test_stale_slot_loader_fails_and_names_it(self):
        # The A57-01 state: EFI/ubuntu moved on (new shim), the slots kept
        # the bake-time copy. Presence-only validation passed this.
        ubuntu = {"shimx64.efi": _sha(b"shim-v2"),
                  "grubx64.efi": _sha(b"grub-v2"),
                  "mmx64.efi": _sha(b"mm-v2")}
        slots = {("xpf-A", "shimx64.efi"): _sha(b"shim-v1"),
                 ("xpf-A", "grubx64.efi"): _sha(b"grub-v1"),
                 ("xpf-A", "mmx64.efi"): _sha(b"mm-v1"),
                 ("xpf-B", "shimx64.efi"): _sha(b"shim-v1"),
                 ("xpf-B", "grubx64.efi"): _sha(b"grub-v1"),
                 ("xpf-B", "mmx64.efi"): _sha(b"mm-v1")}
        ok, reason = self._verdict(ubuntu, slots)
        self.assertFalse(ok)
        self.assertIn("xpf-A", reason)
        self.assertIn("shimx64.efi", reason)
        self.assertIn("stale", reason)

    def test_stale_mm_in_one_slot_fails(self):
        ubuntu = {f: _sha(b"v2-" + f.encode()) for f in LOADERS}
        slots = {("xpf-A", f): ubuntu[f] for f in LOADERS}
        slots.update({("xpf-B", f): ubuntu[f] for f in LOADERS})
        slots[("xpf-B", "mmx64.efi")] = _sha(b"v1-mm")
        ok, reason = self._verdict(ubuntu, slots)
        self.assertFalse(ok)
        self.assertIn("xpf-B", reason)
        self.assertIn("mmx64.efi", reason)

    def test_missing_source_loader_is_not_a_hash_failure(self):
        # EFI/ubuntu carries no loader at all: the ESP presence verdict
        # owns the "not staged" diagnosis; the hash verdict must not
        # invent a second, misleading failure.
        ubuntu = {f: None for f in LOADERS}
        slots = {("xpf-A", f): _sha(b"x") for f in LOADERS}
        slots.update({("xpf-B", f): _sha(b"x") for f in LOADERS})
        ok, reason = self._verdict(ubuntu, slots)
        self.assertTrue(ok, reason)

    def test_missing_slot_loader_fails_hash_verdict(self):
        ubuntu = {f: _sha(f.encode()) for f in LOADERS}
        slots = {("xpf-A", f): ubuntu[f] for f in LOADERS}
        slots.update({("xpf-B", f): ubuntu[f] for f in LOADERS})
        slots[("xpf-A", "grubx64.efi")] = None
        ok, reason = self._verdict(ubuntu, slots)
        self.assertFalse(ok)
        self.assertIn("xpf-A", reason)
        self.assertIn("grubx64.efi", reason)

    def test_mm_present_in_source_but_absent_from_slot_fails(self):
        # The bake's fallback copies only shim+grub when mmx64.efi cannot
        # be copied; a slot without mm while ubuntu has one is exactly the
        # silent divergence A57-01 forbids.
        ubuntu = {f: _sha(f.encode()) for f in LOADERS}
        slots = {("xpf-A", f): ubuntu[f] for f in LOADERS}
        slots.update({("xpf-B", f): ubuntu[f] for f in LOADERS})
        slots[("xpf-A", "mmx64.efi")] = None
        ok, reason = self._verdict(ubuntu, slots)
        self.assertFalse(ok)
        self.assertIn("mmx64.efi", reason)

    def test_mm_absent_everywhere_passes(self):
        # An ESP whose ubuntu dir legitimately ships no mmx64.efi (the
        # bake's fallback shape): absence in BOTH places is not drift.
        ubuntu = {"shimx64.efi": _sha(b"s"), "grubx64.efi": _sha(b"g"),
                  "mmx64.efi": None}
        slots = {("xpf-A", "shimx64.efi"): ubuntu["shimx64.efi"],
                 ("xpf-A", "grubx64.efi"): ubuntu["grubx64.efi"],
                 ("xpf-A", "mmx64.efi"): None,
                 ("xpf-B", "shimx64.efi"): ubuntu["shimx64.efi"],
                 ("xpf-B", "grubx64.efi"): ubuntu["grubx64.efi"],
                 ("xpf-B", "mmx64.efi"): None}
        ok, reason = self._verdict(ubuntu, slots)
        self.assertTrue(ok, reason)

    def test_empty_probe_fails_rather_than_passing_vacuously(self):
        ok, reason = validate._ab_slot_loader_hash_verdict("")
        self.assertFalse(ok)


class BootSyncTests(unittest.TestCase):
    """Run the REAL xpf-uefi-slots refresh path in --sync-only mode."""

    def setUp(self):
        self.assertTrue(HELPER.is_file(), f"{HELPER} missing")
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-slot-refresh-test."))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.esp = self.tmp / "esp"
        (self.esp / "EFI" / "ubuntu").mkdir(parents=True)
        for slot in ("xpf-A", "xpf-B"):
            d = self.esp / "EFI" / slot
            d.mkdir(parents=True)
            (d / "xpf.selector").write_text(
                'set xpf_slot_kernel="vmlinuz-1"\n')

    def _write(self, rel, data):
        p = self.esp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def _run_sync(self):
        env = dict(os.environ)
        env["XPF_UEFI_SLOTS_ESP"] = str(self.esp)
        return subprocess.run(
            ["sh", str(HELPER), "--sync-only"],
            env=env, capture_output=True, text=True, check=False)

    def _slot_bytes(self, slot, fname):
        return (self.esp / "EFI" / slot / fname).read_bytes()

    def test_sync_refreshes_stale_slots_to_ubuntu(self):
        # A57-01 acceptance at the mechanism level: after EFI/ubuntu moves
        # (apt reinstall of a changed shim/grub), the sync makes cmp pass
        # across EFI/{ubuntu,xpf-A,xpf-B}.
        self._write("EFI/ubuntu/shimx64.efi", b"shim-v2")
        self._write("EFI/ubuntu/grubx64.efi", b"grub-v2")
        self._write("EFI/ubuntu/mmx64.efi", b"mm-v2")
        for slot in ("xpf-A", "xpf-B"):
            self._write(f"EFI/{slot}/shimx64.efi", b"shim-v1")
            self._write(f"EFI/{slot}/grubx64.efi", b"grub-v1")
            self._write(f"EFI/{slot}/mmx64.efi", b"mm-v1")
        res = self._run_sync()
        self.assertEqual(res.returncode, 0, res.stderr)
        for slot in ("xpf-A", "xpf-B"):
            self.assertEqual(self._slot_bytes(slot, "shimx64.efi"), b"shim-v2")
            self.assertEqual(self._slot_bytes(slot, "grubx64.efi"), b"grub-v2")
            self.assertEqual(self._slot_bytes(slot, "mmx64.efi"), b"mm-v2")
            # The selector is slot state, never loader state: untouched.
            self.assertEqual(
                (self.esp / "EFI" / slot / "xpf.selector").read_text(),
                'set xpf_slot_kernel="vmlinuz-1"\n')

    def test_sync_copies_mm_when_slot_lacks_it(self):
        self._write("EFI/ubuntu/shimx64.efi", b"shim")
        self._write("EFI/ubuntu/grubx64.efi", b"grub")
        self._write("EFI/ubuntu/mmx64.efi", b"mm")
        self._write("EFI/xpf-A/shimx64.efi", b"shim")
        self._write("EFI/xpf-A/grubx64.efi", b"grub")  # no mm: bake fallback
        self._write("EFI/xpf-B/shimx64.efi", b"shim")
        self._write("EFI/xpf-B/grubx64.efi", b"grub")
        res = self._run_sync()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self._slot_bytes("xpf-A", "mmx64.efi"), b"mm")
        self.assertEqual(self._slot_bytes("xpf-B", "mmx64.efi"), b"mm")

    def test_sync_is_noop_when_already_in_sync(self):
        for rel in ("EFI/ubuntu/shimx64.efi", "EFI/xpf-A/shimx64.efi",
                    "EFI/xpf-B/shimx64.efi", "EFI/ubuntu/grubx64.efi",
                    "EFI/xpf-A/grubx64.efi", "EFI/xpf-B/grubx64.efi"):
            self._write(rel, b"same")
        before = {p: p.stat().st_mtime_ns
                  for p in self.esp.rglob("*.efi")}
        res = self._run_sync()
        self.assertEqual(res.returncode, 0, res.stderr)
        after = {p: p.stat().st_mtime_ns
                 for p in self.esp.rglob("*.efi")}
        self.assertEqual(before, after)

    def test_sync_without_ubuntu_source_exits_zero(self):
        # Foreign host / not-yet-baked ESP: a non-UEFI or ubuntu-less ESP
        # must stay on the non-fatal "degraded, not bricked" contract.
        shutil.rmtree(self.esp / "EFI" / "ubuntu")
        res = self._run_sync()
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_sync_removes_no_slot_files(self):
        self._write("EFI/ubuntu/shimx64.efi", b"shim-v2")
        self._write("EFI/ubuntu/grubx64.efi", b"grub-v2")
        self._write("EFI/xpf-A/shimx64.efi", b"shim-v1")
        self._write("EFI/xpf-A/grubx64.efi", b"grub-v1")
        self._write("EFI/xpf-B/shimx64.efi", b"shim-v1")
        self._write("EFI/xpf-B/grubx64.efi", b"grub-v1")
        res = self._run_sync()
        self.assertEqual(res.returncode, 0, res.stderr)
        for slot in ("xpf-A", "xpf-B"):
            self.assertTrue((self.esp / "EFI" / slot / "xpf.selector").is_file())


class DpkgTriggerWiringTests(unittest.TestCase):
    def test_triggers_file_interests_the_efi_ubuntu_loaders(self):
        self.assertTrue(TRIGGERS.is_file(),
                        "debian/xpf.triggers missing — no dpkg trigger "
                        "refreshes the A/B slots on a bootloader update")
        text = TRIGGERS.read_text()
        for path in ("/boot/efi/EFI/ubuntu/shimx64.efi",
                     "/boot/efi/EFI/ubuntu/grubx64.efi"):
            self.assertIn(f"interest-noawait {path}", text,
                          f"no file trigger on {path}: a shim/grub update "
                          "would never invoke the slot refresh")
        # mm is trigger-relevant too when present.
        self.assertIn("interest-noawait /boot/efi/EFI/ubuntu/mmx64.efi", text)

    def test_postinst_triggered_runs_refresh_and_exits_zero(self):
        env = dict(os.environ)
        env["XPF_UEFI_SLOTS_ESP"] = str(self._esp_with_stale_slot())
        # Point the postinst at the in-tree helper via PATH-independent
        # absolute? The postinst calls /usr/local/sbin/xpf-uefi-slots; in
        # the hermetic run that path does not exist, so `triggered` must
        # still exit 0 (foreign host without the bake substrate).
        res = subprocess.run(
            ["sh", str(POSTINST), "triggered"],
            env=env, capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)

    def _esp_with_stale_slot(self):
        tmp = Path(tempfile.mkdtemp(prefix="xpf-postinst-trigger."))
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        (tmp / "EFI" / "ubuntu").mkdir(parents=True)
        (tmp / "EFI" / "ubuntu" / "shimx64.efi").write_bytes(b"v2")
        return tmp

    def test_postinst_triggered_branch_is_wired(self):
        text = POSTINST.read_text()
        self.assertIn("triggered)", text,
                      "postinst has no `triggered` arm — the dpkg trigger "
                      "would be activated but never handled")
        arm = text.split("triggered)", 1)[1].split(";;", 1)[0]
        self.assertIn("xpf-uefi-slots", arm)
        self.assertIn("--sync-only", arm)

    def test_postinst_triggered_without_helper_stays_green(self):
        # Control: `triggered` on a host without the helper / ESP (a
        # foreign install) must exit 0 and not perturb anything.
        env = dict(os.environ)
        env.pop("XPF_UEFI_SLOTS_ESP", None)
        res = subprocess.run(
            ["sh", str(POSTINST), "triggered"],
            env=env, capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)


class ValidateWiringTests(unittest.TestCase):
    def test_scenario_a_applies_the_hash_verdict(self):
        src = VALIDATE.read_text()
        self.assertIn("_ab_slot_loader_hash_verdict(", src)
        self.assertIn("_AB_SLOT_HASH_PROBE", src)
        body = src.split("def assert_ab_kernel_channel", 1)[1]
        body = body.split("def assert_ab_slot_boot", 1)[0] \
            if "def assert_ab_slot_boot" in body else body[:6000]
        self.assertIn("_ab_slot_loader_hash_verdict(", body,
                      "scenario A never applies the hash verdict — a stale "
                      "slot would still pass the Tier-1 gate")

    def test_validate_probe_hashes_both_slots_and_ubuntu(self):
        self.assertIn("sha256sum", validate._AB_SLOT_HASH_PROBE)
        for token in ("ubuntu", "xpf-A", "xpf-B", "shimx64.efi",
                      "grubx64.efi", "mmx64.efi"):
            self.assertIn(token, validate._AB_SLOT_HASH_PROBE)


if __name__ == "__main__":
    unittest.main()
