package daemon

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestKnownAbsentPinnedMACRefusesPreflightAndRename10905(t *testing.T) {
	dir := withTempLinkDir(t)

	savedEnum := enumeratePresentNICsFn
	nics := []presentNIC{{Name: "enp9s0", PCIAddr: "0000:09:00.0"}}
	enumeratePresentNICsFn = func() ([]presentNIC, error) { return nics, nil }
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })

	var renameCalls, reloadCalls int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { renameCalls++; return nil }
	t.Cleanup(func() { renameInterfaceFn = savedRename })
	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { reloadCalls++; return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	dm, cfg := macPinnedMapConfig()
	if reason := deviceMapStrandsManagement(cfg, nics, nil, ""); reason == "" ||
		!strings.Contains(reason, "reports no permanent MAC") ||
		!strings.Contains(reason, "remove the MAC pin only if PCI-only binding is intentional") {
		t.Fatalf("preflight refusal = %q, want known-absent-MAC refusal with its specific remedy", reason)
	}

	// Exercise the rename path without the separate management preflight. A
	// refusal must not rename the NIC, persist a .link, or reload networkd.
	if err := enumerateAndRenameMapped(dm, cfg, map[string]bool{}); err != nil {
		t.Fatalf("enumerateAndRenameMapped: %v", err)
	}
	if renameCalls != 0 {
		t.Errorf("rename calls = %d, want 0 for a NIC with no verifiable pinned MAC", renameCalls)
	}
	if reloadCalls != 0 {
		t.Errorf("networkctl reloads = %d, want 0", reloadCalls)
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*.link"))
	if err != nil {
		t.Fatalf("list .link files: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf(".link files = %v, want none for a refused binding", entries)
	}
}
