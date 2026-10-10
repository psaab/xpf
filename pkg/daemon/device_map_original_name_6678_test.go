package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #6678. deviceMapOriginalNameFor fell back to the NIC's CURRENT name when the
// kernel-name derivation came back empty. In the recovery branch that matters —
// a NIC already wearing its logical name whose .link was lost — current ==
// logical, so the LOGICAL name was persisted as OriginalName=. udev never
// presents that name, so the .link could not match and boot-time persistence
// failed SILENTLY: the file exists, the name looks plausible, nothing matches.
//
// This is why it was latent rather than obvious: every OTHER consumer of an
// empty derivation treats it as a clean skip (ensureRethLinkOriginalName
// returns without rewriting the RETH .link), so this was the single non-skip
// fallback in the call graph.
//
// The severity comes from what OriginalName= is load-bearing for. RETH members
// are PCI-keyed with OriginalName= precisely BECAUSE their MAC alternates —
// physical at boot, virtual once the daemon programs the RETH virtual MAC — so
// MACAddress= is unreliable for them. A wrong OriginalName= on a RETH member is
// not self-correcting at boot.

// stubMappedSeamsWearingLogicalName points the rename seams at a single NIC
// that ALREADY wears its final logical name (ge-0-0-3), which is the recovery
// branch: current == logical and no .link exists.
func stubMappedSeamsWearingLogicalName(t *testing.T, derived string) (linkDirPath string, renameCalls *int) {
	t.Helper()
	dir := withTempLinkDir(t)

	savedEnum := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		return []presentNIC{{Name: "ge-0-0-3", PCIAddr: "0000:09:00.0"}}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })

	savedDerive := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { return derived }
	t.Cleanup(func() { deriveKernelNameFn = savedDerive })

	var rc int
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { rc++; return nil }
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	return dir, &rc
}

func linkFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".link") {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestDeviceMapOriginalNameForReportsUnderivable_6678 pins the contract change:
// an empty derivation in the recovery branch reports "no name", it does not
// hand back the logical name.
func TestDeviceMapOriginalNameForReportsUnderivable_6678(t *testing.T) {
	withTempLinkDir(t) // empty link dir => recoverOriginalName returns its input
	saved := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { return "" }
	t.Cleanup(func() { deriveKernelNameFn = saved })

	got, ok := deviceMapOriginalNameFor("ge-0-0-3", "ge-0-0-3")
	if ok {
		t.Fatalf("an empty derivation must report NO udev-matchable name, got %q with ok=true", got)
	}
	// Assert what the value BECAME, not merely that ok flipped: the logical
	// name must not be handed back under any guise.
	if got != "" {
		t.Fatalf("underivable must yield the empty string, got %q", got)
	}
	if got == "ge-0-0-3" {
		t.Fatal("the LOGICAL name was returned — udev never presents it")
	}
}

// TestEnumerateAndRenameMappedSkipsLinkWhenOriginalUnderivable_6678 is the
// end-to-end half, driving the real apply path. It also covers the second
// manufacturing site: the write site has its OWN fallback
// (recoverOriginalName), which likewise returns the current name when no .link
// records it — so a fix confined to deviceMapOriginalNameFor would be defeated
// there and this test would still fail.
func TestEnumerateAndRenameMappedSkipsLinkWhenOriginalUnderivable_6678(t *testing.T) {
	dir, _ := stubMappedSeamsWearingLogicalName(t, "") // derivation returns nothing
	dm, cfg := mappedRenameTestConfig()

	err := enumerateAndRenameMapped(dm, cfg, nil)

	if files := linkFilesIn(t, dir); len(files) != 0 {
		for _, f := range files {
			b, _ := os.ReadFile(filepath.Join(dir, f))
			t.Errorf("a .link was written with no derivable OriginalName: %s\n%s", f, b)
		}
	}
	if err == nil {
		t.Fatal("failing to establish boot persistence must be reported, not silent")
	}
	if !strings.Contains(err.Error(), "OriginalName") {
		t.Errorf("the error must name the cause, got %v", err)
	}
}

// TestEnumerateAndRenameMappedWritesLinkWhenOriginalDerivable_6678 is the
// positive control. Without it the test above could pass because this harness
// never writes a .link at all — a green that proves nothing.
func TestEnumerateAndRenameMappedWritesLinkWhenOriginalDerivable_6678(t *testing.T) {
	dir, _ := stubMappedSeamsWearingLogicalName(t, "enp9s0") // derivation succeeds
	dm, cfg := mappedRenameTestConfig()

	if err := enumerateAndRenameMapped(dm, cfg, nil); err != nil {
		t.Fatalf("a derivable OriginalName must apply cleanly, got %v", err)
	}
	files := linkFilesIn(t, dir)
	if len(files) != 1 {
		t.Fatalf("want exactly one .link written, got %v", files)
	}
	b, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(b)
	if !strings.Contains(content, "OriginalName=enp9s0") {
		t.Errorf("the derived kernel name must be recorded, got:\n%s", content)
	}
	if strings.Contains(content, "OriginalName=ge-0-0-3") {
		t.Errorf("the LOGICAL name must never be recorded as OriginalName:\n%s", content)
	}
	if strings.Contains(content, originalNameUnknown) {
		t.Errorf("the sentinel must never reach a .link file:\n%s", content)
	}
}

// TestDeviceMapUnknownSentinelIsNotAnInterfaceName_6678 pins the property that
// makes carrying the sentinel as a map VALUE safe: it can never collide with a
// real interface name, so it cannot be mistaken for one if it ever escapes.
func TestDeviceMapUnknownSentinelIsNotAnInterfaceName_6678(t *testing.T) {
	if !strings.ContainsRune(originalNameUnknown, 0) {
		t.Fatalf("the sentinel must be unrepresentable as an interface name, got %q", originalNameUnknown)
	}
	if len(originalNameUnknown) <= 16 {
		t.Logf("note: sentinel %q is short enough to fit IFNAMSIZ, but the NUL keeps it unrepresentable", originalNameUnknown)
	}
}
