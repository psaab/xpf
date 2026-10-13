package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestProbe12718DeviceMapDoesNotTreatMACNameAsKernelOriginal is the issue's
// focused probe: a prior MAC-form Name= is not proof that the current name is
// the udev/kernel original, and its claim must be removed before a new owner
// attempts (and can fail) to write that target's .link.
func TestProbe12718DeviceMapDoesNotTreatMACNameAsKernelOriginal(t *testing.T) {
	dir := withTempLinkDir(t)
	macForm := "[Match]\nMACAddress=52:54:00:00:00:02\n\n[Link]\nName=ge-0-0-3\n"
	link := filepath.Join(dir, linkPrefix+"ge-0-0-3.link")
	if err := os.WriteFile(link, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok := deviceMapOriginalNameFor("ge-0-0-3", "ge-0-0-4")
	if ok || got != "" {
		t.Fatalf("MAC-assigned current name is not a known kernel original: got %q, ok=%v", got, ok)
	}
	savedDerive := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { return "enp9s0" }
	t.Cleanup(func() { deriveKernelNameFn = savedDerive })
	if got, ok := deviceMapOriginalNameFor("ge-0-0-3", "ge-0-0-3"); !ok || got != "enp9s0" {
		t.Fatalf("same-target recovery should use derived original, got %q, ok=%v", got, ok)
	}
	if got, ok := deviceMapOriginalNameFor("ens3", "ge-0-0-4"); !ok || got != "ens3" {
		t.Fatalf("fresh name with no .link is its kernel original, got %q, ok=%v", got, ok)
	}

	savedEnum := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{
			{Name: "ge-0-0-3", PCIAddr: "0000:0a:00.0"}, // MAC-form source changes target
			{Name: "enp9s0", PCIAddr: "0000:09:00.0"},   // new owner of ge-0-0-3
		}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error {
		if to == "ge-0-0-4" {
			// Inject a write failure for the new owner's target after the
			// unknown source has been cleaned up.
			if err := os.Mkdir(link, 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(link, "blocker"), []byte("keep directory nonempty"), 0o644)
		}
		return nil
	}
	t.Cleanup(func() { renameInterfaceFn = savedRename })
	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })
	dm := &config.DeviceMapConfig{Entries: []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
		{LogicalName: "ge-0/0/4", PCIAddr: "0000:0a:00.0"},
	}}
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: dm}}
	err := enumerateAndRenameMapped(dm, cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "write .link") {
		t.Fatalf("the injected owner .link write failure must be reported, got %v", err)
	}
	if got, err := os.ReadFile(link); err == nil {
		t.Fatalf("BUG: old MAC-form claim survived the failed owner write: %q", got)
	}
}
