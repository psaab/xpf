package daemon

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// collision_break_premise_7205_test.go — #7205 item 2.
//
// `breakNameCollisions` is phase 1 of the shared two-pass rename. Phase 2's
// stated premise is:
//
//	// Collisions are already broken, so no EEXIST here.
//
// A failed temp rename falsified that premise for exactly one name and then
// `continue`d, leaving the NIC still occupying a desired final name. Phase 2
// went ahead and attempted the rename, which EEXISTs.
//
// #7203 gave both paths an error channel, so that EEXIST is reported rather
// than swallowed — but it names the WRONG CAUSE. It points at the rename, and
// a reader goes looking at udev or the .link file instead of at the collision
// break that did not happen. The correct behaviour is not to report it better;
// it is not to enter phase 2 on a premise that does not hold.
//
// The function is shared by BOTH the positional and device-map callers, so this
// is proven at the shared function AND at each caller. A fix at one call site
// would leave the other with the false premise, and the two paths diverging on
// a shared helper is exactly the drift the helper exists to prevent.

// The shared function must REPORT the name it could not free.
func TestBreakNameCollisionsReportsUnfreedNames_7205(t *testing.T) {
	// enp5s0 wants fxp0; fxp0 is currently worn by the NIC that wants
	// ge-0-0-0. That is a collision: fxp0 must be vacated first.
	currentNames := []string{"enp5s0", "fxp0"}
	desiredNames := map[string]bool{"fxp0": true, "ge-0-0-0": true}
	desiredByCurrent := map[string]string{"enp5s0": "fxp0", "fxp0": "ge-0-0-0"}
	originalByCurrent := map[string]string{"enp5s0": "enp5s0", "fxp0": "enp6s0"}

	// The temp rename fails, so fxp0 stays occupied.
	failTemp := func(from, to string) error {
		return fmt.Errorf("simulated temp-rename failure")
	}

	_, _, unfreed, changed := breakNameCollisions("test", currentNames, desiredNames,
		desiredByCurrent, originalByCurrent, failTemp)

	if !unfreed["fxp0"] {
		t.Error("breakNameCollisions did not report that it could not free \"fxp0\". " +
			"Phase 2 will now attempt a rename onto an occupied name and report an " +
			"EEXIST that names the wrong cause (#7205)")
	}
	if changed {
		t.Error("no rename succeeded, so nothing changed; reporting changed=true would " +
			"trigger a networkctl reload for a pass that moved nothing")
	}
}

// CONTROL. A temp rename that SUCCEEDS frees the name, so nothing is reported
// as unfreed. Without this, an implementation that marked every collision
// unfreed would satisfy the cell above and break every working rename.
func TestBreakNameCollisionsReportsNothingWhenTempRenameSucceeds_7205(t *testing.T) {
	currentNames := []string{"enp5s0", "fxp0"}
	desiredNames := map[string]bool{"fxp0": true, "ge-0-0-0": true}
	desiredByCurrent := map[string]string{"enp5s0": "fxp0", "fxp0": "ge-0-0-0"}
	originalByCurrent := map[string]string{"enp5s0": "enp5s0", "fxp0": "enp6s0"}

	_, _, unfreed, changed := breakNameCollisions("test", currentNames, desiredNames,
		desiredByCurrent, originalByCurrent, func(from, to string) error { return nil })

	if len(unfreed) != 0 {
		t.Errorf("a successful collision break reported %v as unfreed; phase 2 would "+
			"skip renames it is entitled to make", unfreed)
	}
	if !changed {
		t.Error("a successful temp rename must report changed=true so the reload runs")
	}
}

// CALLER 1 — POSITIONAL. The doomed rename must not be attempted, and the error
// must name the collision break rather than an EEXIST.
func TestPositionalDoesNotEnterPhase2OnAFalsePremise_7205(t *testing.T) {
	withTempLinkDir(t)

	savedEnum := enumeratePCINICsFn
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		// Index 0 wants fxp0 but index 1 currently WEARS fxp0 — a collision.
		return []pciNIC{
			{name: "enp5s0", busAddr: "0000:05:00.0"},
			{name: "fxp0", busAddr: "0000:06:00.0"},
		}, nil
	}
	t.Cleanup(func() { enumeratePCINICsFn = savedEnum })

	var attempted []string
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error {
		attempted = append(attempted, from+"->"+to)
		if strings.HasPrefix(to, "xpf-tmp-") {
			return fmt.Errorf("simulated temp-rename failure")
		}
		return nil
	}
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	err := enumerateAndRenameInterfaces(0, false, 0, false, nil)
	if err == nil {
		t.Fatal("a pass that could not free a desired name must not report success")
	}
	if !strings.Contains(err.Error(), "collision break could not free") {
		t.Errorf("the error does not name the collision break as the cause, so a reader "+
			"is sent at the rename instead: %v", err)
	}
	for _, a := range attempted {
		if a == "enp5s0->fxp0" {
			t.Error("phase 2 ATTEMPTED the rename onto the name phase 1 could not free. " +
				"That rename EEXISTs by construction, and its error names the wrong " +
				"cause (#7205)")
		}
	}
}

// CALLER 2 — DEVICE-MAP. Same shared function, same premise, and the fix must
// hold here too or the two paths diverge on shared code.
func TestDeviceMapDoesNotEnterPhase2OnAFalsePremise_7205(t *testing.T) {
	withTempLinkDir(t)

	savedEnum := enumeratePresentNICsFn
	enumeratePresentNICsFn = func() ([]presentNIC, error) {
		// The mapped NIC at 0000:09:00.0 wants ge-0-0-3; another present NIC
		// already WEARS ge-0-0-3.
		return []presentNIC{
			{Name: "enp9s0", PCIAddr: "0000:09:00.0"},
			{Name: "ge-0-0-3", PCIAddr: "0000:0a:00.0"},
		}, nil
	}
	t.Cleanup(func() { enumeratePresentNICsFn = savedEnum })

	var attempted []string
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error {
		attempted = append(attempted, from+"->"+to)
		if strings.HasPrefix(to, "xpf-tmp-") {
			return fmt.Errorf("simulated temp-rename failure")
		}
		return nil
	}
	t.Cleanup(func() { renameInterfaceFn = savedRename })

	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	dm := &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
	}
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: dm}}

	err := enumerateAndRenameMapped(dm, cfg, nil)
	if err == nil {
		t.Fatal("a mapped pass that could not free a desired name must not report success")
	}
	if !strings.Contains(err.Error(), "collision break could not free") {
		t.Errorf("the device-map error does not name the collision break as the cause: %v", err)
	}
	for _, a := range attempted {
		if a == "enp9s0->ge-0-0-3" {
			t.Error("the device-map phase 2 ATTEMPTED the rename onto the name phase 1 " +
				"could not free — the shared fix did not reach this caller (#7205)")
		}
	}
}

// #7205 item 3: the protected set reached the positional branch and was dropped
// in silence, so a reader could not tell a deliberate non-use from an oversight.
//
// This pins the DECISION, not the log text: positional mode must not refuse a
// rename because of the protected set, and it must not pretend to honour one.
// If a strand refusal is ever wanted for positional mode, it needs its own
// issue with a stated failure policy — positional naming claims every NIC, so
// "the lifeline moved" is the normal case there, not an error.
func TestPositionalNamingDoesNotRefuseOnTheProtectedSet_7205(t *testing.T) {
	withTempLinkDir(t)

	savedEnum := enumeratePCINICsFn
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{name: "fxp0", busAddr: "0000:05:00.0"}}, nil
	}
	t.Cleanup(func() { enumeratePCINICsFn = savedEnum })
	savedRename := renameInterfaceFn
	renameInterfaceFn = func(from, to string) error { return nil }
	t.Cleanup(func() { renameInterfaceFn = savedRename })
	savedReload := networkctlReloadFn
	networkctlReloadFn = func() error { return nil }
	t.Cleanup(func() { networkctlReloadFn = savedReload })

	// A protected set naming the very NIC positional mode will claim.
	protected := map[string]bool{"fxp0": true, "enp5s0": true}

	// cfg with no device map => the positional branch.
	cfg := &config.Config{}
	if err := applyStartupNamingPolicy(cfg, 0, false, 0, false, nil, protected); err != nil {
		t.Fatalf("positional naming must not REFUSE on account of the protected set — "+
			"it claims every present NIC by design, so a lifeline move is the normal "+
			"case there and a refusal would strand the box on kernel names: %v", err)
	}
}

// CONTROL: the mapped branch still RECEIVES the set. A "fix" that stopped
// threading protected altogether would satisfy the cell above and silently
// disable device-map's strand refusal — the one place it is load-bearing.
func TestMappedBranchStillReceivesTheProtectedSet_7205(t *testing.T) {
	var got map[string]bool
	saved := enumerateAndRenameMappedFn
	enumerateAndRenameMappedFn = func(dm *config.DeviceMapConfig, cfg *config.Config, protected map[string]bool) error {
		got = protected
		return nil
	}
	t.Cleanup(func() { enumerateAndRenameMappedFn = saved })

	dm := &config.DeviceMapConfig{
		Entries: []config.DeviceMapEntry{{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"}},
	}
	cfg := &config.Config{Chassis: config.ChassisConfig{DeviceMap: dm}}
	protected := map[string]bool{"fxp0": true}

	if err := applyStartupNamingPolicy(cfg, 0, false, 0, false, nil, protected); err != nil {
		t.Fatalf("mapped branch returned an error: %v", err)
	}
	if !got["fxp0"] {
		t.Error("the mapped branch no longer receives the protected set; device-map's " +
			"strand refusal (deviceMapStrandsManagement) is now inert and a boot rename " +
			"can strand management (#7205)")
	}
}
