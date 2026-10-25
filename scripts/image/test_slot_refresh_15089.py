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
  - `debian/xpf.triggers` registers dpkg file triggers on the loader
    payloads dpkg actually unpacks (/usr/lib/shim,
    /usr/lib/grub/x86_64-efi-signed — #16452) so a bootloader update
    invokes `postinst triggered` -> the same refresh without a reboot.
    The ESP paths under /boot/efi/EFI/ubuntu are written by grub-install
    outside dpkg and can never fire a file trigger.
  - `debian/xpf.postinst` handles `triggered` (runs the helper when it is
    installed, exits 0 without it) and keeps `configure` succeeding. The
    helper path defaults to /usr/local/sbin/xpf-uefi-slots and is
    overridable via XPF_UEFI_SLOTS_BIN so the hermetic cell points it at
    the in-tree helper and observes the stale-slot refresh (#16644).
  - `scripts/image/validate.py` hash-compares each slot loader against
    EFI/ubuntu (`HASH` probe lines + `_ab_slot_loader_hash_verdict`), so a
    stale or divergent slot fails the Tier-1 gate instead of passing on
    presence alone.
  - A real-dpkg cell (#16452) builds probe .debs carrying the REAL
    debian/xpf.triggers + the REAL postinst `triggered` arm and a fake
    shim/grub provider, installs/upgrades them with the system dpkg in
    a chrootless sandbox, and asserts "Processing triggers for xpf…"
    plus a byte-equal slot copy with no reboot. On the pre-#16452
    ESP-path interests the provider unpack never fires the trigger and
    the cell is RED.

Controls: matching hashes pass, an absent EFI/ubuntu source does not
fail the hash verdict (the presence verdict owns that diagnosis), the
boot-time sync is a no-op when already in sync and never touches
xpf.selector, and `postinst configure` on a host without the helper
stays green.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VALIDATE = HERE / "validate.py"
HELPER = HERE / "xpf-uefi-slots"
TRIGGERS = ROOT / "debian" / "xpf.triggers"
POSTINST = ROOT / "debian" / "xpf.postinst"

validate = load_subject("validate", VALIDATE)

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


def _dpkg_sandbox_runnable():
    """True when a chrootless dpkg install can run on this host.

    The real-dpkg cell needs dpkg + dpkg-deb and the
    --force-not-root / --force-script-chrootless path (dpkg >= 1.20).
    Probed once; the cell skips (never passes vacuously) without them.
    """
    if not (shutil.which("dpkg") and shutil.which("dpkg-deb")):
        return False
    try:
        out = subprocess.run(["dpkg", "--force-help"], capture_output=True,
                             text=True, check=False).stdout
    except OSError:
        return False
    return "not-root" in out and "script-chrootless" in out


_HAVE_REAL_DPKG = _dpkg_sandbox_runnable()


class DpkgTriggerWiringTests(unittest.TestCase):
    def test_triggers_file_interests_the_unpacked_loader_payloads(self):
        # #16452 (R3-A57-02): the signed providers unpack only /usr/lib
        # payloads; the ESP copies are written by grub-install from
        # their postinsts, outside dpkg. Interests on the ESP paths can
        # never fire. Assert the interests cover what dpkg unpacks and
        # carry no dead ESP interest. The real-dpkg cell below proves
        # the behaviour; this cell pins the declared shape.
        self.assertTrue(TRIGGERS.is_file(),
                        "debian/xpf.triggers missing — no dpkg trigger "
                        "refreshes the A/B slots on a bootloader update")
        interests = []
        for line in TRIGGERS.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            self.assertGreaterEqual(len(parts), 2, line)
            interests.append((parts[0], parts[1]))
        self.assertEqual(
            sorted(interests),
            sorted([("interest-noawait", "/usr/lib/shim"),
                    ("interest-noawait",
                     "/usr/lib/grub/x86_64-efi-signed")]),
            "trigger interests must be exactly the /usr/lib payload "
            "trees the signed shim/grub packages unpack (#16452)")
        for _kind, path in interests:
            self.assertFalse(
                path.startswith("/boot/efi"),
                f"dead ESP interest {path}: no package unpacks there, "
                "grub-install writes it outside dpkg (#16452)")

    def test_postinst_triggered_runs_refresh_and_exits_zero(self):
        # #16644: point the postinst at the REAL in-tree helper via
        # XPF_UEFI_SLOTS_BIN (default is the installed absolute path)
        # and observe the refresh on the stale-slot ESP fixture. A
        # broken/disabled helper invocation in the `triggered` arm
        # leaves both slots on v1 and reds this cell (previously the
        # absolute path was absent on the test host, the arm never ran
        # the helper, and only rc 0 was asserted — the same as the
        # no-helper control below).
        esp = self._esp_with_stale_slot()
        env = dict(os.environ)
        env["XPF_UEFI_SLOTS_ESP"] = str(esp)
        env["XPF_UEFI_SLOTS_BIN"] = str(HELPER)
        res = subprocess.run(
            ["sh", str(POSTINST), "triggered"],
            env=env, capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        for slot in ("xpf-A", "xpf-B"):
            self.assertEqual(
                (esp / "EFI" / slot / "shimx64.efi").read_bytes(), b"shim-v2",
                f"{slot} shim not refreshed by postinst triggered (#16644)")
            self.assertEqual(
                (esp / "EFI" / slot / "grubx64.efi").read_bytes(), b"grub-v2",
                f"{slot} grub not refreshed by postinst triggered (#16644)")
            self.assertEqual(
                (esp / "EFI" / slot / "xpf.selector").read_text(),
                'set xpf_slot_kernel="vmlinuz-1"\n')

    def _esp_with_stale_slot(self):
        tmp = Path(tempfile.mkdtemp(prefix="xpf-postinst-trigger."))
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        (tmp / "EFI" / "ubuntu").mkdir(parents=True)
        (tmp / "EFI" / "ubuntu" / "shimx64.efi").write_bytes(b"shim-v2")
        (tmp / "EFI" / "ubuntu" / "grubx64.efi").write_bytes(b"grub-v2")
        for slot in ("xpf-A", "xpf-B"):
            d = tmp / "EFI" / slot
            d.mkdir(parents=True)
            (d / "shimx64.efi").write_bytes(b"shim-v1")
            (d / "grubx64.efi").write_bytes(b"grub-v1")
            (d / "xpf.selector").write_text(
                'set xpf_slot_kernel="vmlinuz-1"\n')
        return tmp

    def test_postinst_triggered_branch_is_wired(self):
        text = POSTINST.read_text()
        self.assertIn("triggered)", text,
                      "postinst has no `triggered` arm — the dpkg trigger "
                      "would be activated but never handled")
        arm = text.split("triggered)", 1)[1].split(";;", 1)[0]
        self.assertIn("xpf-uefi-slots", arm)
        self.assertIn("--sync-only", arm)
        # Pin the exact production default so renaming it (e.g. to
        # xpf-uefi-slots.disabled) reds even though the hermetic cell
        # overrides the path (#16644 mutant).
        self.assertIn(
            "${XPF_UEFI_SLOTS_BIN:-/usr/local/sbin/xpf-uefi-slots}", arm,
            "triggered arm default helper path is not the installed "
            "/usr/local/sbin/xpf-uefi-slots (#16644)")
        self.assertIn('[ -x "$UEFI_SLOTS_BIN" ]', arm)
        self.assertIn('"$UEFI_SLOTS_BIN" --sync-only', arm)

    def test_postinst_triggered_without_helper_stays_green(self):
        # Control: `triggered` with the helper absent (a foreign
        # install) must exit 0 and not perturb the ESP. The missing
        # path is injected explicitly so the control is hermetic even
        # on a host that has the real helper installed.
        esp = self._esp_with_stale_slot()
        env = dict(os.environ)
        env["XPF_UEFI_SLOTS_ESP"] = str(esp)
        env["XPF_UEFI_SLOTS_BIN"] = str(esp / "no-such-xpf-uefi-slots")
        res = subprocess.run(
            ["sh", str(POSTINST), "triggered"],
            env=env, capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        for slot in ("xpf-A", "xpf-B"):
            self.assertEqual(
                (esp / "EFI" / slot / "shimx64.efi").read_bytes(), b"shim-v1",
                f"{slot} perturbed without a helper")


@unittest.skipUnless(_HAVE_REAL_DPKG,
                     "real dpkg sandbox unavailable (need dpkg + dpkg-deb "
                     "with --force-not-root/--force-script-chrootless)")
class RealDpkgTriggerTests(unittest.TestCase):
    """#16452: drive the REAL dpkg trigger machinery end to end.

    Builds probe packages in a temp dir:
      - `xpf` carrying the REAL debian/xpf.triggers and a postinst whose
        `triggered` arm is extracted verbatim from the REAL
        debian/xpf.postinst (sandbox copy of the REAL xpf-uefi-slots
        injected via XPF_UEFI_SLOTS_BIN, ESP via XPF_UEFI_SLOTS_ESP);
      - `shimprobe` v1/v2 unpacking /usr/lib/shim/shimx64.efi.signed,
        whose postinst mimics the real providers: on configure it
        copies the unpacked payload into EFI/ubuntu (what grub-install
        does outside dpkg);
      - `grubprobe` v1/v2 doing the same for
        /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed -> grubx64.efi.
    Installing the provider v1, then upgrading to v2 with the system
    dpkg (chrootless sandbox: private --root/--admindir, no host dpkg
    state touched), must print "Processing triggers for xpf", run
    `postinst triggered`, and leave both slot copies byte-equal to the
    new loader — the #16452 VM WITNESS, with no reboot. On the
    pre-#16452 ESP-path interests the provider unpack touches no
    interested path, no trigger fires, and this cell is RED.
    """

    def _build_deb(self, build_root, name, version, files, postinst):
        pkg = build_root / f"{name}-{version}"
        (pkg / "DEBIAN").mkdir(parents=True)
        (pkg / "DEBIAN" / "control").write_text(
            f"Package: {name}\nVersion: {version}\n"
            "Architecture: amd64\nMaintainer: xpf test <test@example>\n"
            f"Description: {name} probe for test_slot_refresh_15089\n")
        if postinst is not None:
            p = pkg / "DEBIAN" / "postinst"
            p.write_text(postinst)
            p.chmod(0o755)
        for rel, data in files.items():
            dest = pkg / rel.lstrip("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        deb = build_root / f"{name}_{version}_amd64.deb"
        res = subprocess.run(["dpkg-deb", "--build", str(pkg), str(deb)],
                             capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        return deb

    def _triggered_postinst(self, helper):
        """Extract the real `triggered)` arm, wrapped in a minimal case.

        The arm text is taken verbatim from debian/xpf.postinst, so a
        broken or removed helper invocation in the real arm reds here.
        The sandbox copy of the REAL xpf-uefi-slots is injected via
        the arm's XPF_UEFI_SLOTS_BIN override (set in the dpkg env
        below), not by rewriting the arm text (#16644).
        """
        text = POSTINST.read_text()
        self.assertIn("triggered)", text)
        arm = text.split("triggered)", 1)[1].split(";;", 1)[0]
        self.assertIn(
            "${XPF_UEFI_SLOTS_BIN:-/usr/local/sbin/xpf-uefi-slots}", arm)
        return ("#!/bin/sh\nset -e\ncase \"$1\" in\n"
                f"  triggered){arm};;\n"
                "  configure) ;;\n"
                "  abort-upgrade|abort-remove|abort-deconfigure) ;;\n"
                "  *) echo \"postinst called with unknown argument "
                "\\`$1'\" >&2; exit 1 ;;\n"
                "esac\nexit 0\n")

    def _provider_postinst(self, payload, esp_loader):
        # Mimic shim-signed/grub-efi-amd64-signed: configure re-copies
        # the /usr/lib payload into EFI/ubuntu (grub-install's job).
        # $DPKG_ROOT is set by dpkg for maintainer scripts; in the
        # chrootless sandbox the payload lands under $DPKG_ROOT while
        # the ESP is the test's own tree (env survives chrootless runs).
        return ("#!/bin/sh\nset -e\n"
                "case \"$1\" in\n"
                "  configure)\n"
                f"    cp \"$DPKG_ROOT{payload}\" "
                f"\"$XPF_UEFI_SLOTS_ESP/EFI/ubuntu/{esp_loader}\"\n"
                "    ;;\n"
                "esac\nexit 0\n")

    def test_real_dpkg_provider_upgrade_fires_trigger_and_refreshes(self):
        tmp = Path(tempfile.mkdtemp(prefix="xpf-real-dpkg-trigger."))
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        root = tmp / "root"
        (root / "var" / "lib" / "dpkg").mkdir(parents=True)
        esp = tmp / "esp"
        for slot in ("xpf-A", "xpf-B"):
            d = esp / "EFI" / slot
            d.mkdir(parents=True)
            (d / "shimx64.efi").write_bytes(b"shim-v1")
            (d / "grubx64.efi").write_bytes(b"grub-v1")
            (d / "xpf.selector").write_text(
                'set xpf_slot_kernel="vmlinuz-1"\n')
        (esp / "EFI" / "ubuntu").mkdir(parents=True)
        (esp / "EFI" / "ubuntu" / "shimx64.efi").write_bytes(b"shim-v1")
        (esp / "EFI" / "ubuntu" / "grubx64.efi").write_bytes(b"grub-v1")

        # Sandbox copy of the REAL helper (ESP via the documented env
        # override the hermetic BootSyncTests already use).
        helper = root / "usr" / "local" / "sbin" / "xpf-uefi-slots"
        helper.parent.mkdir(parents=True)
        helper.write_bytes(HELPER.read_bytes())
        helper.chmod(0o755)

        build = tmp / "build"
        build.mkdir()
        xpf_pkg = build / "xpf-1.0"
        xpf_deb = self._build_deb(
            build, "xpf", "1.0", {},
            self._triggered_postinst(helper))
        # The REAL triggers file ships in the probe .deb exactly as
        # dh_installdeb would install debian/xpf.triggers.
        (xpf_pkg / "DEBIAN" / "triggers").write_bytes(
            TRIGGERS.read_bytes())
        res = subprocess.run(
            ["dpkg-deb", "--build", str(xpf_pkg), str(xpf_deb)],
            capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)

        shim_v1 = self._build_deb(
            build, "shimprobe", "1.0",
            {"/usr/lib/shim/shimx64.efi.signed": b"shim-v1"},
            self._provider_postinst("/usr/lib/shim/shimx64.efi.signed",
                                    "shimx64.efi"))
        shim_v2 = self._build_deb(
            build, "shimprobe", "2.0",
            {"/usr/lib/shim/shimx64.efi.signed": b"shim-v2"},
            self._provider_postinst("/usr/lib/shim/shimx64.efi.signed",
                                    "shimx64.efi"))
        grub_v1 = self._build_deb(
            build, "grubprobe", "1.0",
            {"/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed":
             b"grub-v1"},
            self._provider_postinst(
                "/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed",
                "grubx64.efi"))
        grub_v2 = self._build_deb(
            build, "grubprobe", "2.0",
            {"/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed":
             b"grub-v2"},
            self._provider_postinst(
                "/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed",
                "grubx64.efi"))

        env = dict(os.environ)
        env["XPF_UEFI_SLOTS_ESP"] = str(esp)
        env["XPF_UEFI_SLOTS_BIN"] = str(helper)
        # dpkg refuses to run without ldconfig + start-stop-daemon in
        # PATH even chrootless, and it disregards the inherited PATH's
        # non-standard entries — prepend the standard sbin dirs. A host
        # dpkg guarantees both binaries exist there.
        env["PATH"] = ("/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                       "/usr/bin:/sbin:/bin:" + env.get("PATH", ""))
        admindir = root / "var" / "lib" / "dpkg"

        def dpkg_install(*debs):
            cmd = ["dpkg", f"--admindir={admindir}", f"--root={root}",
                   "--force-depends", "--force-not-root",
                   "--force-script-chrootless", "--log=/dev/null",
                   "--install"] + [str(d) for d in debs]
            return subprocess.run(cmd, env=env, capture_output=True,
                                  text=True, check=False)

        res = dpkg_install(xpf_deb)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        res = dpkg_install(shim_v1, grub_v1)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        # Baseline: slots still on v1 (the v1 installs start in sync).
        for slot in ("xpf-A", "xpf-B"):
            self.assertEqual(
                (esp / "EFI" / slot / "shimx64.efi").read_bytes(),
                b"shim-v1")

        # The witness upgrade: provider v2 unpack + configure must fire
        # the xpf file trigger and refresh both slots with no reboot.
        res = dpkg_install(shim_v2, grub_v2)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Processing triggers for xpf", res.stdout,
                      "dpkg never processed the xpf trigger on the "
                      "provider upgrade — the slot refresh did not run "
                      "(#16452):\n" + res.stdout + res.stderr)
        # The provider postinsts refreshed EFI/ubuntu (grub-install's
        # role) ...
        self.assertEqual(
            (esp / "EFI" / "ubuntu" / "shimx64.efi").read_bytes(),
            b"shim-v2")
        self.assertEqual(
            (esp / "EFI" / "ubuntu" / "grubx64.efi").read_bytes(),
            b"grub-v2")
        # ... and the triggered refresh copied the NEW loaders into
        # both slots, byte-equal, in the same dpkg transaction.
        for slot in ("xpf-A", "xpf-B"):
            self.assertEqual(
                (esp / "EFI" / slot / "shimx64.efi").read_bytes(),
                b"shim-v2",
                f"{slot} still boots the stale shim after the dpkg "
                "trigger (#16452)")
            self.assertEqual(
                (esp / "EFI" / slot / "grubx64.efi").read_bytes(),
                b"grub-v2",
                f"{slot} still boots the stale grub after the dpkg "
                "trigger (#16452)")
            self.assertEqual(
                (esp / "EFI" / slot / "xpf.selector").read_text(),
                'set xpf_slot_kernel="vmlinuz-1"\n')


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
