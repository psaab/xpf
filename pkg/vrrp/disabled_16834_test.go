package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16834: CollectInstances must skip vrrp-groups on a disabled interface
// or unit. #15763/#13149 already drop such a VIP from every host-inbound
// drop scope on the premise that a disabled unit owns no address; without
// this gate the group still ran, claimed MASTER on the down netdev, and
// installed its VIP, so kernel-delivered VIP traffic fell through the
// nft input chain to policy accept (fail-open).
//
// FAIL-ON-REVERT: drop the ifc.Disable / unit.Disable gates in
// CollectInstances and the disabled rows below collect 1 instance
// instead of 0.

func disabled16834Cfg(ifDisable, unit3Disable bool) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name:        "ge-0/0/0",
					Disable:     ifDisable,
					VlanTagging: true,
					Units: map[int]*config.InterfaceUnit{
						0: {
							Number: 0,
							VRRPGroups: map[string]*config.VRRPGroup{
								"10.0.20.1/24_grp20": {
									ID:               20,
									Priority:         100,
									VirtualAddresses: []string{"10.0.20.254/24"},
								},
							},
						},
						3: {
							Number:  3,
							VlanID:  30,
							Disable: unit3Disable,
							VRRPGroups: map[string]*config.VRRPGroup{
								"10.0.30.1/24_grp30": {
									ID:               30,
									Priority:         100,
									VirtualAddresses: []string{"10.0.30.254/24"},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestCollectInstancesDisabledUnit16834(t *testing.T) {
	// Disabled unit 3: only the enabled unit 0 group survives.
	insts := CollectInstances(disabled16834Cfg(false, true))
	if len(insts) != 1 {
		t.Fatalf("disabled unit: got %d instances %+v, want 1 (unit 0 only)", len(insts), insts)
	}
	if insts[0].GroupID != 20 || insts[0].Interface != "ge-0-0-0" {
		t.Fatalf("disabled unit: surviving instance = %+v, want VRID 20 on ge-0-0-0", insts[0])
	}
	for _, in := range insts {
		for _, vip := range in.VirtualAddresses {
			if vip == "10.0.30.254/24" {
				t.Fatalf("disabled unit VIP 10.0.30.254/24 collected: %+v", in)
			}
		}
	}

	// Enabled twin (positive control): both groups collect, unchanged.
	insts = CollectInstances(disabled16834Cfg(false, false))
	if len(insts) != 2 {
		t.Fatalf("enabled control: got %d instances %+v, want 2", len(insts), insts)
	}
	seen := map[int]bool{}
	for _, in := range insts {
		seen[in.GroupID] = true
	}
	if !seen[20] || !seen[30] {
		t.Fatalf("enabled control: VRIDs = %v, want {20,30}", seen)
	}
}

func TestCollectInstancesDisabledInterface16834(t *testing.T) {
	// Whole-interface disable: no group on any unit runs.
	if insts := CollectInstances(disabled16834Cfg(true, false)); len(insts) != 0 {
		t.Fatalf("disabled interface: got %d instances %+v, want 0", len(insts), insts)
	}
	// Re-enabling restores both instances (no sticky state in the
	// collector; the same config with Disable cleared collects again).
	if insts := CollectInstances(disabled16834Cfg(false, false)); len(insts) != 2 {
		t.Fatalf("re-enabled control: got %d instances, want 2", len(insts))
	}
}

// The manager reconcile is the second half of the acceptance: once the
// collector stops emitting a disabled unit's group, UpdateInstances must
// stop the previously running instance (its run loop then withdraws the
// VIP via becomeBackup/stop). Re-enabling re-creates it.
//
// FAIL-ON-REVERT: with the collector gates dropped, the disable step
// below still collects the instance, so the manager keeps 1 instance
// after UpdateInstances and this test fails at the collector length
// assertion before reaching the manager.
func TestManagerUpdateInstancesDisabledUnitWithdraws16834(t *testing.T) {
	m := vrrpFamilyManager()
	defer stopManagerForTest(m)

	enabled := CollectInstances(disabled16834Cfg(false, true))
	// Unit 3 is disabled from the start here so only VRID 20 runs; the
	// disabled-then-enabled toggle is exercised on that single group by
	// flipping the interface gate in the second config below.
	if len(enabled) != 1 {
		t.Fatalf("setup: got %d instances, want 1", len(enabled))
	}
	if err := m.UpdateInstances(enabled); err != nil {
		t.Fatalf("UpdateInstances(enabled): %v", err)
	}
	m.mu.RLock()
	n := len(m.instances)
	m.mu.RUnlock()
	if n != 1 {
		t.Fatalf("after enable: manager holds %d instances, want 1", n)
	}

	// Disable the whole interface: collector emits nothing, reconcile
	// must remove (stop) the running instance.
	disabled := CollectInstances(disabled16834Cfg(true, false))
	if len(disabled) != 0 {
		t.Fatalf("disabled interface collected %d instances, want 0", len(disabled))
	}
	if err := m.UpdateInstances(disabled); err != nil {
		t.Fatalf("UpdateInstances(disabled): %v", err)
	}
	m.mu.RLock()
	n = len(m.instances)
	m.mu.RUnlock()
	if n != 0 {
		t.Fatalf("after disable: manager holds %d instances, want 0 (instance stopped, VIP withdrawn by run loop)", n)
	}

	// Re-enable: the instance is restored.
	if err := m.UpdateInstances(CollectInstances(disabled16834Cfg(false, false))); err != nil {
		t.Fatalf("UpdateInstances(re-enabled): %v", err)
	}
	m.mu.RLock()
	n = len(m.instances)
	m.mu.RUnlock()
	if n != 2 {
		t.Fatalf("after re-enable: manager holds %d instances, want 2", n)
	}
}
