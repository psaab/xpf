package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/devicemap"
)

// withTempLinkDir points linkDir at a temp directory for the duration of a
// test so .link/.network file operations never touch /etc.
func withTempLinkDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := linkDir
	linkDir = dir
	t.Cleanup(func() { linkDir = old })
	return dir
}

// TestWriteLinkFileIdempotent proves operator priority #1 (no churn): a
// second write of an identical .link reports unchanged, so a no-op commit
// never rewrites files or triggers a networkctl reload / link flap.
func TestWriteLinkFileIdempotent(t *testing.T) {
	withTempLinkDir(t)
	if wrote, err := writeLinkFile("ge-0-0-3", "enp9s0"); err != nil || !wrote {
		t.Fatalf("first write should report changed")
	}
	if wrote, err := writeLinkFile("ge-0-0-3", "enp9s0"); err != nil || wrote {
		t.Fatalf("second identical write must report UNCHANGED (no churn)")
	}
	// A different OriginalName is a real change.
	if wrote, err := writeLinkFile("ge-0-0-3", "eth7"); err != nil || !wrote {
		t.Fatalf("changed OriginalName should report changed")
	}
}

// TestScrubStaleDeviceMapLinksNoOpWhenAllDesired proves the scrub leaves
// every still-desired .link untouched (no churn) and removes only orphans.
func TestScrubStaleDeviceMapLinksNoOpWhenAllDesired(t *testing.T) {
	dir := withTempLinkDir(t)
	_, _ = writeLinkFile("ge-0-0-3", "enp9s0")
	_, _ = writeLinkFile("ge-0-0-4", "enp10s0")

	desired := map[string]bool{"ge-0-0-3": true, "ge-0-0-4": true}
	if scrubStaleDeviceMapLinks(desired) {
		t.Fatalf("scrub must be a no-op when all .link targets are still desired")
	}
	// Both files still present.
	for _, n := range []string{"ge-0-0-3", "ge-0-0-4"} {
		if _, err := os.Stat(filepath.Join(dir, linkPrefix+n+".link")); err != nil {
			t.Fatalf("desired .link %s was removed: %v", n, err)
		}
	}

	// Drop ge-0-0-4 from the desired set: only its .link is scrubbed.
	if !scrubStaleDeviceMapLinks(map[string]bool{"ge-0-0-3": true}) {
		t.Fatalf("scrub should remove the now-undesired .link")
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-4.link")); !os.IsNotExist(err) {
		t.Fatalf("stale ge-0-0-4 .link should be gone")
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-3.link")); err != nil {
		t.Fatalf("ge-0-0-3 .link must survive: %v", err)
	}
}

// TestTeardownUnmappedManagedNoOpWhenAllMapped proves V-4 teardown is a
// no-op when every on-disk .link is still a desired binding — zero churn on
// an unrelated commit (operator priority #1). It also never reaches netlink
// in the no-op path (all names desired), so it is safe in the unit sandbox.
func TestTeardownUnmappedManagedNoOpWhenAllMapped(t *testing.T) {
	dir := withTempLinkDir(t)
	_, _ = writeLinkFile("ge-0-0-3", "enp9s0")

	dm := &config.DeviceMapConfig{
		Entries:        []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
		UnmappedPolicy: config.DeviceMapPolicyLeaveAlone,
	}
	teardownUnmappedManaged(dm, nil) // must not panic, must not remove the .link
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-3.link")); err != nil {
		t.Fatalf("teardown removed a still-mapped .link: %v", err)
	}
}

// TestTeardownManageDownIsNoOp proves teardown does nothing under
// manage-down (that mode keeps today's claim-all via the compiler reconcile).
func TestTeardownManageDownIsNoOp(t *testing.T) {
	dir := withTempLinkDir(t)
	_, _ = writeLinkFile("ge-0-0-9", "enp99s0") // not in the map

	dm := &config.DeviceMapConfig{
		Entries:        []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
		UnmappedPolicy: config.DeviceMapPolicyManageDown,
	}
	teardownUnmappedManaged(dm, nil)
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-9.link")); err != nil {
		t.Fatalf("manage-down teardown must not touch .link files: %v", err)
	}
}

// TestDeviceMapLinkOriginalNameRoundTrips proves boot-stability of the
// on-disk record: a written .link for a mapped NIC records the TRUE kernel
// OriginalName=, and a later run recovers exactly that name (so the same
// physical NIC keeps the same logical name across reboots / re-runs).
func TestDeviceMapLinkOriginalNameRoundTrips(t *testing.T) {
	withTempLinkDir(t)
	// First run: enp9s0 -> ge-0-0-3 records OriginalName=enp9s0.
	if wrote, err := writeDeviceMapLinkFile("ge-0-0-3", "enp9s0", nil, nil); err != nil || !wrote {
		t.Fatalf("first .link write should report changed")
	}
	// A subsequent run that sees the NIC already named ge-0-0-3 must recover
	// the original kernel name from the existing .link, not the logical name.
	if got, _, _ := recoverOriginalName("ge-0-0-3"); got != "enp9s0" {
		t.Fatalf("OriginalName round-trip failed: recovered %q, want enp9s0", got)
	}
	// Re-writing the identical .link is a no-op (no churn).
	if wrote, err := writeDeviceMapLinkFile("ge-0-0-3", "enp9s0", nil, nil); err != nil || wrote {
		t.Fatalf("identical .link re-write must be a no-op")
	}
}

// TestDeviceMapOriginalNameFallbackViaDeriveKernelName covers the bug where a
// NIC is already at its final logical name (e.g., second+ boot with device-map)
// but has NO existing .link file (e.g., first device-map activation after
// manual rename, or stale scrub). Without the deriveKernelNameFn fallback the
// code would record OriginalName=ge-0-0-3 (the logical name), which udev would
// never see on next boot, causing the NIC to revert to its predictable kernel
// name (enp9s0) permanently.
func TestDeviceMapOriginalNameFallbackViaDeriveKernelName(t *testing.T) {
	withTempLinkDir(t) // empty — no .link file exists

	// Inject a stub that maps the logical name to the TRUE kernel name.
	old := deriveKernelNameFn
	deriveKernelNameFn = func(name string) string {
		if name == "ge-0-0-3" {
			return "enp9s0"
		}
		return ""
	}
	t.Cleanup(func() { deriveKernelNameFn = old })

	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
	}
	// Simulate: NIC is ALREADY at ge-0-0-3 (current == final); no .link.
	nics := []devicemap.PresentNIC{{Name: "ge-0-0-3", PCIAddr: "0000:09:00.0"}}
	bindings := resolveDeviceMap(entries, nics, nil)
	if len(bindings) != 1 || !bindings[0].Status.Bound() {
		t.Fatalf("expected bound binding, got %+v", bindings)
	}

	// Replicate the originalByCurrent population logic that the fix touches.
	orig, _, _ := recoverOriginalName("ge-0-0-3") // returns "ge-0-0-3" (no .link)
	if orig == "ge-0-0-3" {
		if dk := deriveKernelNameFn("ge-0-0-3"); dk != "" {
			orig = dk
		}
	}
	if orig != "enp9s0" {
		t.Fatalf("OriginalName fallback must yield kernel name %q, got %q", "enp9s0", orig)
	}
	// Prove the .link is written with the TRUE kernel OriginalName, not the logical name.
	changed, _ := writeDeviceMapLinkFile("ge-0-0-3", orig, nil, nil)
	if !changed {
		t.Fatalf("first write should create the .link")
	}
	if got, _, _ := recoverOriginalName("ge-0-0-3"); got != "enp9s0" {
		t.Fatalf("written .link must record OriginalName=enp9s0, recovered %q", got)
	}
}

func TestDeviceMapStrandsManagementSafeWhenMgmtMapped(t *testing.T) {
	// The live mgmt NIC (enp5s0 currently == fxp0) is mapped to its own
	// name => safe.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "fxp0", PCIAddr: "0000:05:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{{Name: "fxp0", PCIAddr: "0000:05:00.0"}}
	protected := map[string]bool{"fxp0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "fxp0"); r != "" {
		t.Fatalf("mapping mgmt NIC to its own name must be safe, got %q", r)
	}
}

func TestDeviceMapStrandsManagementDetectsPortSwap(t *testing.T) {
	// A DIFFERENT physical NIC is mapped to the mgmt logical name fxp0, so
	// the live mgmt NIC (currently fxp0) would lose its name on next boot.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "fxp0", PCIAddr: "0000:09:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "fxp0", PCIAddr: "0000:05:00.0"},   // live mgmt NIC
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // becomes fxp0
	}
	protected := map[string]bool{"fxp0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "fxp0"); r == "" {
		t.Fatalf("expected strand detection when mgmt name moves to another port")
	}
}

func TestDeviceMapStrandsManagementRefuseOnTopologyChange(t *testing.T) {
	// A REFUSED entry (card swapped at a pinned slot) is a hard stop.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: "00:11:22:33:44:55"},
		},
	}}}
	nics := []devicemap.PresentNIC{{Name: "enp9s0", PCIAddr: "0000:09:00.0", PermMAC: "de:ad:be:ef:00:01"}}
	if r := deviceMapStrandsManagement(cfg, nics, nil, ""); r == "" {
		t.Fatalf("expected refusal on topology change (PCI hit, MAC mismatch)")
	}
}

func TestDeviceMapStrandsManagementLifelineRenamedOffStrands(t *testing.T) {
	// The genuine pre-rename strand (Codex HIGH-2 intent, corrected by the
	// unified model): the lifeline NIC (currently enp5s0) is itself mapped to
	// a NON-management name and NO NIC takes a management name -> management
	// becomes unreachable on next boot.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "ge-0/0/0", PCIAddr: "0000:05:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "enp5s0", PCIAddr: "0000:05:00.0"}, // lifeline, mapped to ge-0/0/0
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // not mapped to a mgmt name
	}
	protected := map[string]bool{"fxp0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "enp5s0"); r == "" {
		t.Fatalf("expected strand when the lifeline NIC is renamed off and no NIC takes a mgmt name")
	}
}

func TestDeviceMapStrandsManagementUnmappedLifelineKeepsMgmt(t *testing.T) {
	// Corrected semantics: the lifeline NIC (enp5s0) is left UNMAPPED, so it
	// KEEPS its name and address — management stays reachable. Another NIC
	// taking fxp0 does NOT strand it (no collision; mgmt is on enp5s0).
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "fxp0", PCIAddr: "0000:09:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "enp5s0", PCIAddr: "0000:05:00.0"}, // lifeline, unmapped -> keeps name
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // -> fxp0
	}
	protected := map[string]bool{"fxp0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "enp5s0"); r != "" {
		t.Fatalf("an unmapped lifeline NIC keeps mgmt; must be safe, got %q", r)
	}
}

func TestDeviceMapOriginalNameForFreshKernelName(t *testing.T) {
	// AGY r3 MAJOR: on a fresh first map the NIC wears its real kernel name
	// (ens3) and current != logical, so deviceMapOriginalNameFor must KEEP
	// the kernel name, NOT synthesize an enpXsY via deriveKernelName (which
	// would break the udev match on next boot).
	withTempLinkDir(t) // empty link dir => recoverOriginalName returns input
	called := false
	old := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { called = true; return "enp0s3" }
	t.Cleanup(func() { deriveKernelNameFn = old })

	got, ok := deviceMapOriginalNameFor("ens3", "ge-0-0-3")
	if !ok {
		t.Fatal("a real kernel name is udev-matchable; ok must be true")
	}
	if got != "ens3" {
		t.Fatalf("fresh-box OriginalName must be the real kernel name ens3, got %q", got)
	}
	if called {
		t.Fatalf("deriveKernelName must NOT be consulted when current != logical")
	}
}

func TestDeviceMapOriginalNameForDerivesWhenWearingLogicalName(t *testing.T) {
	// Second+ boot whose .link was lost: the NIC already wears its logical
	// name (ge-0-0-3) and no .link exists, so derive the true kernel name.
	withTempLinkDir(t)
	old := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { return "enp9s0" }
	t.Cleanup(func() { deriveKernelNameFn = old })

	got, ok := deviceMapOriginalNameFor("ge-0-0-3", "ge-0-0-3")
	if !ok {
		t.Fatal("a successful derivation is udev-matchable; ok must be true")
	}
	if got != "enp9s0" {
		t.Fatalf("when wearing the logical name, OriginalName must derive the kernel name, got %q", got)
	}
}

func TestDeviceMapStrandsManagementCaseCCollision(t *testing.T) {
	// AGY r3 MAJOR B.1: a protected name currently held by an unmapped NIC,
	// while a mapped entry assigns that same protected name to a different
	// NIC -> rename collision on next boot -> refuse.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		// enp9s0 -> ge-0/0/3 (a protected name currently held by another NIC).
		Entries: []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "ge-0-0-3", PCIAddr: "0000:0c:00.0"}, // unmapped current holder of the name
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"},   // mapped to ge-0/0/3
	}
	protected := map[string]bool{"ge-0-0-3": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, ""); r == "" {
		t.Fatalf("expected Case C collision rejection")
	}
}

func TestDeviceMapStrandsManagementCaseCAllowsPortSwap(t *testing.T) {
	// AGY r4 CRITICAL: a LEGITIMATE port swap must NOT be flagged by Case C.
	// The current fxp0 holder is re-mapped to ge-0/0/9 (its .link is rewritten
	// away from fxp0, no stale rule) AND a new NIC is mapped to fxp0. No
	// collision on next boot. fxp0 stays protected (mgmt remains on a
	// protected name via the new NIC).
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{
			{LogicalName: "ge-0/0/9", PCIAddr: "0000:05:00.0"}, // old fxp0 NIC -> ge-0-0-9
			{LogicalName: "fxp0", PCIAddr: "0000:09:00.0"},     // new NIC -> fxp0
		},
	}}}
	nics := []devicemap.PresentNIC{
		{Name: "fxp0", PCIAddr: "0000:05:00.0"},   // current fxp0 holder
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"}, // becomes fxp0
	}
	protected := map[string]bool{"fxp0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "fxp0"); r != "" {
		t.Fatalf("legit port swap (fxp0->ge-0-0-9, enp9s0->fxp0) must be allowed, got %q", r)
	}
}

func TestDeviceMapStrandsManagementAllowsLegitMgmtRemap(t *testing.T) {
	// Codex r2 HIGH-A: the live mgmt NIC still wears its kernel name enp5s0,
	// the lifeline resolves it, and BOTH enp5s0 (lifeline current name) and
	// fxp0 (mgmt target) are in the protected set. Mapping enp5s0 -> fxp0 is
	// the LEGITIMATE management mapping and must NOT be flagged.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "fxp0", PCIAddr: "0000:05:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{{Name: "enp5s0", PCIAddr: "0000:05:00.0"}}
	protected := map[string]bool{"fxp0": true, "enp5s0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "enp5s0"); r != "" {
		t.Fatalf("legit mgmt remap enp5s0->fxp0 must be allowed, got %q", r)
	}
}

func TestDeviceMapStrandsManagementMgmtMovedToNonMgmtName(t *testing.T) {
	// The live mgmt NIC mapped to a NON-protected name moves management off
	// it — strand.
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "ge-0/0/9", PCIAddr: "0000:05:00.0"}},
	}}}
	nics := []devicemap.PresentNIC{{Name: "enp5s0", PCIAddr: "0000:05:00.0"}}
	protected := map[string]bool{"fxp0": true, "enp5s0": true}
	if r := deviceMapStrandsManagement(cfg, nics, protected, "enp5s0"); r == "" {
		t.Fatalf("expected strand when mgmt NIC mapped to a non-mgmt name")
	}
}

func TestTeardownSkipsProtectedInterface(t *testing.T) {
	// AGY r2 CRITICAL: an unmapped-but-protected mgmt interface must NOT be
	// torn down (no immediate lockout). The .link survives.
	dir := withTempLinkDir(t)
	_, _ = writeLinkFile("fxp0", "enp5s0") // mgmt NIC currently managed as fxp0
	dm := &config.DeviceMapConfig{
		Entries:        []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
		UnmappedPolicy: config.DeviceMapPolicyLeaveAlone,
	}
	teardownUnmappedManaged(dm, map[string]bool{"fxp0": true})
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"fxp0.link")); err != nil {
		t.Fatalf("teardown removed the protected fxp0 .link (lockout!): %v", err)
	}
}

func TestProtectedForConfigUsesConfigMgmtLeaf(t *testing.T) {
	// AGY HIGH-2: the protected set must come from the SPECIFIC config's
	// management-interface leaf. With no lifeline record, a config that sets
	// `system management-interface em0` protects em0 (and narrows fxp0 out).
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

	cfg := &config.Config{}
	cfg.System.ManagementInterface = "em0"
	got := protectedForConfig(cfg)
	if !got["em0"] {
		t.Fatalf("protectedForConfig must protect the config's mgmt leaf em0; got %v", got)
	}
	if got["fxp0"] {
		t.Fatalf("an explicit non-fxp0 mgmt leaf must narrow fxp0 out; got %v", got)
	}
}

func TestDeviceMapStrandsManagementPositionalIsSafe(t *testing.T) {
	// No device-map => positional mode, never stranded by a (non-existent)
	// map; the #1922 protected set is the backstop.
	cfg := &config.Config{}
	if r := deviceMapStrandsManagement(cfg, nil, map[string]bool{"fxp0": true}, ""); r != "" {
		t.Fatalf("positional mode must never report stranding, got %q", r)
	}
}
