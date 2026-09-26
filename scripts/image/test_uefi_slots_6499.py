#!/usr/bin/env python3
"""Hermetic functional self-test for scripts/image/xpf-uefi-slots (#6499).

`xpf-uefi-slots` MUTATES FIRMWARE NVRAM on every boot of every shipped
appliance: it deletes boot entries, dedups them, and rewrites BootOrder. Until
this file it was covered by `sh -n` and `shellcheck` alone — a parse check and
a style check, neither of which can see that a logic change wipes a customer
box's PXE/recovery entries or undoes a promoted kernel slot.

Three of the guards below exist because a reviewer caught the corresponding
destructive class DURING #1930, so they are regression fixtures, not
hypotheticals:

  * wrong-path deletion — an entry that merely shares the LABEL but points
    somewhere else must be deleted, or the slot chainloads the wrong loader
    and poisons BootNext (r1/r2 Codex High);
  * duplicate dedup — the original label guard was anchored at `$`, missed the
    TAB-then-loader-path shape, and created duplicate slots live. A duplicated
    slot makes BootNext ambiguous;
  * promoted-slot preservation — a self-heal that re-seeded "A first"
    UNDID a promotion to B (r1 Codex High);
  * empty-BootOrder no-write — a reseed built from an unreadable BootOrder
    would emit `--bootorder <A>,<B>`, WIPING every other entry: PXE, recovery,
    the firmware's own (r1 AGY destructive-wipe).

Method: the REAL script, run by a REAL /bin/sh, with PATH shadowed by a mock
`efibootmgr` that models NVRAM as two state files and a mock `findmnt` — the
`test-grow-root.sh` pattern, moved to Python so `run-selftests.sh:139` picks it
up by glob (the shell self-test list at :146-160 is hand-enumerated; #7296).

Non-tautological by construction: every assertion reads the mock's NVRAM state
or its recorded argv AFTER the real script ran. Nothing here re-implements the
script's logic.

`[ -b "$ESP_DISK" ]` is NOT relaxed by a test hook — the mock `findmnt` names a
partition of a REAL host block device, so the script's own device sanity check
is exercised rather than bypassed.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "xpf-uefi-slots"

UBUNTU = "0000|ubuntu|\\EFI\\ubuntu\\shimx64.efi"
PXE = "0001|UEFI PXEv4|PciRoot(0x0)/Pci(0x2,0x0)/MAC(001122334455,1)"

MOCK_EFIBOOTMGR = r"""#!/bin/sh
# Mock efibootmgr modelling NVRAM as $MOCK_NVRAM/{entries,order}.
#   entries: one "ID|LABEL|LOADER" per line
#   order:   a bare comma list
# Every invocation's argv is appended to $MOCK_NVRAM/calls.
NV="$MOCK_NVRAM"
printf '%s\n' "$*" >> "$NV/calls"
[ -n "${MOCK_EFIBOOTMGR_RC:-}" ] && exit "$MOCK_EFIBOOTMGR_RC"

mode=render; del_id=""; label=""; loader=""; neworder=""
while [ $# -gt 0 ]; do
    case "$1" in
    --quiet) ;;
    -b) del_id="$2"; shift ;;
    -B) mode=delete ;;
    --create) mode=create ;;
    --disk|--part) shift ;;
    --label) label="$2"; shift ;;
    --loader) loader="$2"; shift ;;
    --bootorder) mode=order; neworder="$2"; shift ;;
    esac
    shift
done

drop_from_order() {
    o=$(cat "$NV/order" 2>/dev/null)
    printf '%s' "$o" | tr ',' '\n' | grep -vxF "$1" | paste -sd, - > "$NV/order.new"
    mv "$NV/order.new" "$NV/order"
}

case "$mode" in
delete)
    grep -v "^${del_id}|" "$NV/entries" > "$NV/entries.new" 2>/dev/null || true
    mv "$NV/entries.new" "$NV/entries"
    drop_from_order "$del_id"
    ;;
create)
    [ -n "${MOCK_CREATE_RC:-}" ] && exit "$MOCK_CREATE_RC"
    n=$(cat "$NV/nextid" 2>/dev/null || echo 16)
    id=$(printf '%04X' "$n")
    echo "$((n + 1))" > "$NV/nextid"
    printf '%s|%s|%s\n' "$id" "$label" "$loader" >> "$NV/entries"
    # Real efibootmgr PREPENDS a new entry to BootOrder.
    o=$(cat "$NV/order" 2>/dev/null)
    if [ -n "$o" ]; then printf '%s,%s' "$id" "$o" > "$NV/order"
    else printf '%s' "$id" > "$NV/order"; fi
    ;;
order)
    printf '%s' "$neworder" > "$NV/order"
    ;;
render)
    echo "BootCurrent: 0000"
    echo "Timeout: 0 seconds"
    if [ -z "${MOCK_HIDE_BOOTORDER:-}" ]; then
        o=$(cat "$NV/order" 2>/dev/null)
        [ -n "$o" ] && printf 'BootOrder: %s\n' "$o"
    fi
    while IFS='|' read -r id lbl ldr; do
        [ -n "$id" ] || continue
        printf 'Boot%s* %s\t HD(1,GPT,1234)/File(%s)\n' "$id" "$lbl" "$ldr"
    done < "$NV/entries"
    ;;
esac
exit 0
"""

MOCK_FINDMNT = """#!/bin/sh
# Only `findmnt -no SOURCE <esp>` is used by the script.
printf '%s\\n' "${MOCK_ESP_SRC:-}"
"""


def _real_block_device():
    """A REAL host block device, so `[ -b "$ESP_DISK" ]` is exercised for real.

    Returns (esp_src, esp_disk). The partition suffix mirrors the kernel's own
    naming — `p1` when the device name ends in a digit (nvme0n1p1, loop0p1),
    plain `1` otherwise (sda1) — which is exactly the shape the script's
    `s/p?[0-9]+$//` parse handles.
    """
    try:
        names = sorted(os.listdir("/dev"))
    except OSError:
        return None, None
    for name in names:
        p = os.path.join("/dev", name)
        try:
            if not stat.S_ISBLK(os.stat(p).st_mode):
                continue
        except OSError:
            continue
        return p + ("p1" if name[-1].isdigit() else "1"), p
    return None, None


class _SlotsBase(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), f"{SCRIPT} missing")
        esp_src, esp_disk = _real_block_device()
        if not esp_src:
            self.skipTest("no host block device to name as the ESP source")
        self.esp_src, self.esp_disk = esp_src, esp_disk

        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-uefi-slots-test."))
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)]))

        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for name, body in (("efibootmgr", MOCK_EFIBOOTMGR), ("findmnt", MOCK_FINDMNT)):
            f = self.bin / name
            f.write_text(body)
            f.chmod(0o755)

        self.nvram = self.tmp / "nvram"
        self.nvram.mkdir()
        (self.nvram / "entries").write_text("")
        (self.nvram / "order").write_text("")

        # Synthetic efivars dir + ESP. Both slots staged by default; a test
        # that models an unstaged slot removes one.
        self.efivars = self.tmp / "efivars"
        self.efivars.mkdir()
        self.esp = self.tmp / "esp"
        for slot in ("xpf-A", "xpf-B"):
            d = self.esp / "EFI" / slot
            d.mkdir(parents=True)
            (d / "shimx64.efi").write_text("shim")
            (d / "grubx64.efi").write_text("grub")

        self.env_extra = {}

    # ── NVRAM helpers ──
    def seed(self, entries, order):
        (self.nvram / "entries").write_text(
            "".join(e + "\n" for e in entries))
        (self.nvram / "order").write_text(order)

    def entries(self):
        """[(id, label, loader)] currently in the mock NVRAM."""
        out = []
        for line in (self.nvram / "entries").read_text().splitlines():
            if line.strip():
                out.append(tuple(line.split("|", 2)))
        return out

    def order(self):
        return [x for x in (self.nvram / "order").read_text().split(",") if x]

    def ids_for(self, label):
        return [i for i, l, _ in self.entries() if l == label]

    def calls(self):
        p = self.nvram / "calls"
        return p.read_text().splitlines() if p.exists() else []

    def run_slots(self):
        env = dict(os.environ)
        env.update({
            "PATH": f"{self.bin}:{env.get('PATH', '')}",
            "MOCK_NVRAM": str(self.nvram),
            "MOCK_ESP_SRC": self.esp_src,
            "XPF_UEFI_SLOTS_EFIVARS": str(self.efivars),
            "XPF_UEFI_SLOTS_ESP": str(self.esp),
        })
        env.update(self.env_extra)
        res = subprocess.run(["/bin/sh", str(SCRIPT)], env=env,
                             capture_output=True, text=True)
        # The script's whole contract is "degraded, not bricked": it must never
        # fail the boot, on any path.
        self.assertEqual(res.returncode, 0,
                         f"the slot registrar must always exit 0: {res.stderr}")
        return res


class FreshBoxTests(_SlotsBase):
    def test_fresh_box_registers_both_slots_with_their_own_shim(self):
        self.seed([UBUNTU, PXE], "0000,0001")
        self.run_slots()
        got = {l: ldr for _, l, ldr in self.entries()}
        self.assertEqual(got.get("xpf-A"), "\\EFI\\xpf-A\\shimx64.efi")
        self.assertEqual(got.get("xpf-B"), "\\EFI\\xpf-B\\shimx64.efi")

    def test_fresh_box_seeds_a_first_then_b_and_keeps_the_other_entries(self):
        # efibootmgr --create PREPENDS, so creating A then B would leave B in
        # front without the explicit seed (caught live during #1930).
        self.seed([UBUNTU, PXE], "0000,0001")
        self.run_slots()
        a = self.ids_for("xpf-A")[0]
        b = self.ids_for("xpf-B")[0]
        self.assertEqual(self.order()[:2], [a, b])
        # Non-destructive: every pre-existing entry survives, in order.
        self.assertEqual(self.order()[2:], ["0000", "0001"])

    def test_rerun_is_idempotent_and_creates_no_duplicates(self):
        self.seed([UBUNTU, PXE], "0000,0001")
        self.run_slots()
        first = sorted(self.entries())
        self.run_slots()
        self.assertEqual(sorted(self.entries()), first,
                         "a second boot changed NVRAM — the registrar is not "
                         "idempotent")

    def test_unstaged_slot_is_skipped_without_failing_the_boot(self):
        (self.esp / "EFI" / "xpf-B" / "shimx64.efi").unlink()
        self.seed([UBUNTU], "0000")
        res = self.run_slots()
        self.assertEqual(self.ids_for("xpf-B"), [])
        self.assertIn("ESP dir not staged", res.stderr)
        self.assertEqual(len(self.ids_for("xpf-A")), 1)


class WrongPathAndDuplicateTests(_SlotsBase):
    def test_entry_sharing_the_label_but_not_the_loader_is_deleted(self):
        # A stale/foreign label collision would chainload the wrong loader and
        # poison BootNext (r1/r2 Codex High).
        self.seed(["0007|xpf-A|\\EFI\\ubuntu\\shimx64.efi", UBUNTU],
                  "0007,0000")
        res = self.run_slots()
        self.assertIn("deleting WRONG-path entry Boot0007", res.stderr)
        self.assertNotIn("0007", [i for i, _, _ in self.entries()])
        ids = self.ids_for("xpf-A")
        self.assertEqual(len(ids), 1)
        self.assertEqual(
            [ldr for i, l, ldr in self.entries() if i == ids[0]][0],
            "\\EFI\\xpf-A\\shimx64.efi")

    def test_duplicate_correct_entries_are_deduped_to_exactly_one(self):
        # The original label guard was anchored at `$` and missed the
        # TAB-then-path shape, so every boot created another slot.
        self.seed(["0007|xpf-A|\\EFI\\xpf-A\\shimx64.efi",
                   "0008|xpf-A|\\EFI\\xpf-A\\shimx64.efi", UBUNTU],
                  "0007,0008,0000")
        res = self.run_slots()
        self.assertIn("deleting duplicate correct entry", res.stderr)
        self.assertEqual(len(self.ids_for("xpf-A")), 1,
                         "a duplicated slot makes BootNext ambiguous")
        # The FIRST correct one is kept, and no new entry was created for A.
        self.assertEqual(self.ids_for("xpf-A"), ["0007"])

    def test_a_wrong_path_duplicate_pair_leaves_one_correct_entry(self):
        # Both classes at once: one correct, one label-colliding.
        self.seed(["0007|xpf-A|\\EFI\\xpf-A\\shimx64.efi",
                   "0008|xpf-A|\\EFI\\foreign\\shimx64.efi", UBUNTU],
                  "0007,0008,0000")
        self.run_slots()
        self.assertEqual(self.ids_for("xpf-A"), ["0007"])

    def test_loader_path_match_is_case_insensitive(self):
        # efibootmgr renders firmware paths in whatever case the entry holds;
        # the shell guard matches case-insensitively, so an upper-case render
        # must NOT be treated as a wrong-path entry and deleted.
        self.seed(["0007|xpf-A|\\EFI\\XPF-A\\SHIMX64.EFI", UBUNTU], "0007,0000")
        res = self.run_slots()
        self.assertNotIn("deleting WRONG-path entry Boot0007", res.stderr)
        self.assertEqual(self.ids_for("xpf-A"), ["0007"])


class BootOrderTests(_SlotsBase):
    def test_promoted_slot_b_stays_in_front_and_is_not_reseeded_to_a(self):
        # The kernel channel promoted B. A self-heal that forced "A first"
        # would UNDO that promotion (r1 Codex High) — silently, on the next
        # ordinary boot.
        self.seed(["0007|xpf-A|\\EFI\\xpf-A\\shimx64.efi",
                   "0008|xpf-B|\\EFI\\xpf-B\\shimx64.efi", UBUNTU],
                  "0008,0007,0000")
        self.run_slots()
        self.assertEqual(self.order()[0], "0008",
                         "the promoted slot lost the BootOrder front")

    def test_non_xpf_front_preserves_promoted_order(self):
        # An operator may place ubuntu/PXE ahead of the promoted slot. A
        # subsequent boot must preserve that explicit BootOrder rather than
        # treating any non-xpf front as a fresh box and seeding A first.
        self.seed(["0007|xpf-A|\\EFI\\xpf-A\\shimx64.efi",
                   "0008|xpf-B|\\EFI\\xpf-B\\shimx64.efi", UBUNTU, PXE],
                  "0000,0008,0007,0001")
        self.run_slots()
        self.assertEqual(
            self.order(), ["0000", "0008", "0007", "0001"],
            "the registrar overrode the operator's non-xpf BootOrder front")
        self.assertEqual(
            [c for c in self.calls() if "--bootorder" in c], [],
            "the registrar rewrote an existing BootOrder")

        self.run_slots()
        self.assertEqual(
            self.order(), ["0000", "0008", "0007", "0001"],
            "the next boot changed the operator's explicit BootOrder")

    def test_non_xpf_front_survives_missing_slot_registration(self):
        self.seed(["0008|xpf-B|\\EFI\\xpf-B\\shimx64.efi", UBUNTU, PXE],
                  "0000,0008,0001")
        self.run_slots()
        a_ids = self.ids_for("xpf-A")
        self.assertEqual(len(a_ids), 1)
        self.assertEqual(
            self.order(), ["0000", a_ids[0], "0008", "0001"],
            "registering a missing slot displaced the operator's default or "
            "reordered existing entries")

    def test_promoted_b_is_preserved_even_when_slot_a_must_be_recreated(self):
        # B promoted, A's entry lost (a firmware reset that took one entry).
        # The self-heal recreates A — and --create PREPENDS — so the promoted
        # default must be re-asserted, not left wherever the create put it.
        self.seed(["0008|xpf-B|\\EFI\\xpf-B\\shimx64.efi", UBUNTU], "0008,0000")
        self.run_slots()
        self.assertEqual(self.order()[0], "0008")
        self.assertEqual(len(self.ids_for("xpf-A")), 1)

    def test_unreadable_bootorder_writes_no_bootorder_at_all(self):
        # A reseed built from an EMPTY $ORDER would emit `--bootorder <A>,<B>`
        # and WIPE every other entry — PXE, recovery, the firmware's own. The
        # guard must leave NVRAM's order untouched instead.
        self.seed(["0007|xpf-A|\\EFI\\xpf-A\\shimx64.efi",
                   "0008|xpf-B|\\EFI\\xpf-B\\shimx64.efi", UBUNTU, PXE],
                  "0007,0008,0000,0001")
        self.env_extra["MOCK_HIDE_BOOTORDER"] = "1"
        res = self.run_slots()
        self.assertIn("could not read BootOrder", res.stderr)
        self.assertEqual(
            [c for c in self.calls() if "--bootorder" in c], [],
            "the registrar wrote a BootOrder it could not read first — that "
            "reseed wipes PXE/recovery/firmware entries")
        self.assertEqual(self.order(), ["0007", "0008", "0000", "0001"],
                         "the pre-existing BootOrder was not left intact")

    def test_no_xpf_slot_id_leaves_bootorder_unchanged(self):
        # Nothing staged at all: no slot can be registered, so there is no
        # xpf-A id to seed with and BootOrder must be left alone.
        for slot in ("xpf-A", "xpf-B"):
            (self.esp / "EFI" / slot / "shimx64.efi").unlink()
        self.seed([UBUNTU, PXE], "0000,0001")
        res = self.run_slots()
        self.assertIn("no xpf-A slot id", res.stderr)
        self.assertEqual(self.order(), ["0000", "0001"])
        self.assertEqual([c for c in self.calls() if "--bootorder" in c], [])


class NonFatalDegradeTests(_SlotsBase):
    def test_efibootmgr_that_cannot_read_nvram_skips_without_touching_state(self):
        self.seed([UBUNTU, PXE], "0000,0001")
        self.env_extra["MOCK_EFIBOOTMGR_RC"] = "1"
        res = self.run_slots()
        self.assertIn("cannot read NVRAM", res.stderr)
        self.assertEqual(self.entries(), [("0000", "ubuntu", UBUNTU.split("|", 2)[2]),
                                          ("0001", "UEFI PXEv4", PXE.split("|", 2)[2])])
        self.assertEqual(self.order(), ["0000", "0001"])

    def test_no_efivars_directory_skips(self):
        for f in self.efivars.iterdir():
            f.unlink()
        self.efivars.rmdir()
        res = self.run_slots()
        self.assertIn("not a UEFI boot", res.stderr)
        self.assertEqual(self.calls(), [])

    def test_no_esp_mounted_skips(self):
        self.env_extra["MOCK_ESP_SRC"] = ""
        res = self.run_slots()
        self.assertIn("no ESP mounted", res.stderr)

    def test_unparseable_esp_source_skips(self):
        # A source with no trailing partition number, or whose disk half is
        # not a block device, must not reach efibootmgr --create with garbage.
        self.env_extra["MOCK_ESP_SRC"] = "/dev/does-not-exist9"
        res = self.run_slots()
        self.assertIn("could not parse ESP disk/part", res.stderr)
        self.assertEqual([c for c in self.calls() if "--create" in c], [])

    def test_a_failing_create_is_non_fatal_and_does_not_write_bootorder(self):
        self.seed([UBUNTU], "0000")
        self.env_extra["MOCK_CREATE_RC"] = "1"
        res = self.run_slots()
        self.assertIn("failed to register slot", res.stderr)
        self.assertEqual(self.order(), ["0000"])


if __name__ == "__main__":
    unittest.main()
