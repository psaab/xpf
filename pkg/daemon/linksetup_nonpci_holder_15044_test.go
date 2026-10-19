package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #15044 (A33-01): #14595 stopped reporting a USB NIC's xHCI controller
// BDF as the NIC's PCI address, so enumeratePCINICs now skips the USB NIC
// entirely. On a box where a pre-#14595 build had sorted that controller
// ahead of the PCI NICs and named the USB NIC fxp0, the first post-upgrade
// positional pass enumerated only the PCI NICs, assigned fxp0 to the
// first of them, and rewrote 10-xpf-fxp0.link to that NIC's kernel name
// BEFORE the rename EEXISTed against the still-live USB fxp0 (warn-only
// at the boot caller). The next boot then bound fxp0 — management — onto
// the PCI cable. The fix refuses the re-index loudly before any .link
// write or rename whenever a live non-enumerated netdev wears a
// positional name.

// stubLiveNames15044 injects the live-interface list seam and restores it.
func stubLiveNames15044(t *testing.T, names []string, err error) {
	t.Helper()
	old := liveInterfaceNamesFn
	liveInterfaceNamesFn = func() ([]string, error) {
		out := make([]string, len(names))
		copy(out, names)
		return out, err
	}
	t.Cleanup(func() { liveInterfaceNamesFn = old })
}

// TestPositionalUpgradeUSBHolderRefused15044 is the upgrade fixture: the
// live box has the USB NIC wearing fxp0 and one PCI NIC at its kernel
// name; the pre-upgrade fxp0.link records the USB NIC's kernel name. The
// pass must refuse, write no .link, attempt no rename, and leave the
// mapping untouched.
//
// RED on master: renamePositional over the PCI-only enumeration assigns
// fxp0 to the PCI NIC, rewrites 10-xpf-fxp0.link with its kernel name,
// and the rename EEXISTs warn-only.
func TestPositionalUpgradeUSBHolderRefused15044(t *testing.T) {
	dir := withTempLinkDir(t)
	stubLiveNames15044(t, []string{"lo", "fxp0", "enp5s0"}, nil)

	// Pre-#14595 boot state: udev named the USB NIC fxp0 from this file.
	if _, err := writeLinkFile("fxp0", "enx001122334455"); err != nil {
		t.Fatalf("seed fxp0.link: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, linkPrefix+"fxp0.link"))
	if err != nil {
		t.Fatal(err)
	}

	// enumerateAndRenameInterfaces seams: the PCI enumeration sees only
	// the PCI NIC (the USB NIC is skipped under #14595), renames are
	// recorded, reload must never run.
	savedEnum, savedRename, savedReload := enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn
	t.Cleanup(func() {
		enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn = savedEnum, savedRename, savedReload
	})
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"}}, nil
	}
	var renames [][2]string
	renameInterfaceFn = func(from, to string) error {
		renames = append(renames, [2]string{from, to})
		return nil
	}
	networkctlReloadFn = func() error {
		t.Error("reload must not run when the pass refuses")
		return nil
	}

	err = enumerateAndRenameInterfaces(0, false, 0, false, nil)
	if err == nil {
		t.Fatal("positional pass over a live USB fxp0 holder must refuse (#15044)")
	}
	if !strings.Contains(err.Error(), "fxp0") || !strings.Contains(err.Error(), "#15044") {
		t.Fatalf("refusal must name the held positional name and the issue, got: %v", err)
	}
	if len(renames) != 0 {
		t.Fatalf("no rename may be attempted on refusal, got %v", renames)
	}
	after, err := os.ReadFile(filepath.Join(dir, linkPrefix+"fxp0.link"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("10-xpf-fxp0.link must not be rewritten on refusal:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); !os.IsNotExist(err) {
		t.Fatalf("no new .link may be written on refusal, stat err=%v", err)
	}
}

// TestPositionalHolderScanFailureRefused15044: when the live-interface
// scan itself fails, convergence is unknown — the pass must fail closed
// rather than re-index blind (the #7205 readback discipline applied to
// the pre-pass scan).
func TestPositionalHolderScanFailureRefused15044(t *testing.T) {
	withTempLinkDir(t)
	stubLiveNames15044(t, nil, errors.New("injected sysfs read failure"))

	savedEnum, savedRename := enumeratePCINICsFn, renameInterfaceFn
	t.Cleanup(func() { enumeratePCINICsFn, renameInterfaceFn = savedEnum, savedRename })
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"}}, nil
	}
	renameInterfaceFn = func(from, to string) error {
		t.Errorf("no rename may run when the holder scan failed (%s->%s)", from, to)
		return nil
	}

	if err := enumerateAndRenameInterfaces(0, false, 0, false, nil); err == nil {
		t.Fatal("a failed live-interface scan must refuse the positional pass (#15044)")
	}
}

// TestPositionalNoHolderControl15044 is the control: with no live
// non-enumerated positional holder (the USB NIC wears its kernel name),
// the normal first-boot positional pass proceeds and persists exactly as
// before — the holder check must not become an always-refuse.
func TestPositionalNoHolderControl15044(t *testing.T) {
	dir := withTempLinkDir(t)
	// USB NIC present but at its kernel name; nothing holds fxp0.
	stubLiveNames15044(t, []string{"lo", "enx001122334455", "enp5s0", "enp6s0"}, nil)

	savedEnum, savedRename, savedReload := enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn
	t.Cleanup(func() {
		enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn = savedEnum, savedRename, savedReload
	})
	live := []pciNIC{
		{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"},
		{sortKey: 1, busAddr: "0000:06:00.0", name: "enp6s0"},
	}
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		out := make([]pciNIC, len(live))
		copy(out, live)
		return out, nil
	}
	renameInterfaceFn = func(from, to string) error {
		for i := range live {
			if live[i].name == from {
				live[i].name = to
			}
		}
		return nil
	}
	networkctlReloadFn = func() error { return nil }

	if err := enumerateAndRenameInterfaces(0, false, 0, false, nil); err != nil {
		t.Fatalf("no-holder control pass must succeed: %v", err)
	}
	if got := readLinkOriginalName(t, dir, "fxp0"); got != "enp5s0" {
		t.Fatalf("control: fxp0.link OriginalName should be enp5s0, got %q", got)
	}
	if live[0].name != "fxp0" || live[1].name != "ge-0-0-0" {
		t.Fatalf("control: PCI NICs must land on positional names, got %v", live)
	}
}

// TestLivePositionalHolders15044 pins the pure scan: enumerated NICs are
// never holders (even at a positional name), non-positional live names
// are ignored, and cluster em0 counts only in cluster mode.
func TestLivePositionalHolders15044(t *testing.T) {
	nics := []pciNIC{{name: "fxp0"}, {name: "enp5s0"}}
	stubLiveNames15044(t,
		[]string{"lo", "fxp0", "enp5s0", "ge-0-0-2", "em0", "enx001122334455", "ge-0-0-1x"}, nil)

	got, err := livePositionalHolders(nics, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ge-0-0-2" {
		t.Fatalf("standalone holders = %v, want [ge-0-0-2] (fxp0 enumerated, em0 not positional standalone, junk ignored)", got)
	}

	got, err = livePositionalHolders(nics, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "em0" || got[1] != "ge-0-0-2" {
		t.Fatalf("cluster holders = %v, want [em0 ge-0-0-2]", got)
	}
}
