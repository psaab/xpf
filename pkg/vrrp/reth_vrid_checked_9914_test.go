package vrrp

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9914 F-121, manager half: an out-of-range VRID is SKIPPED with a Warn
// (correct — a wrapped VRID would join the wrong virtual router), but the
// refusal left zero manager state: the guard `continue`s before desiredMap,
// so the key never reaches unbuiltDesired and RGVRRPReady can only report the
// generic "no instance" reason. The refusal must be recorded and the RG
// reported not-ready with a reason that names it.
//
// FAIL-ON-REVERT: remove the refusal recording in UpdateInstances (or the
// checked constructor at the RGVRRPReady arm) and unbuiltDesired is empty
// again while the reason degrades to "no instance".
func TestVRIDRefusalRecordedAndRGNotReady_9914(t *testing.T) {
	m, _ := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	// What CollectRethInstances synthesizes for RG 156 (100+156=256): a RETH
	// key (empty family) whose VRID is one past the RFC 5798 byte.
	desired := []*Instance{
		{Interface: "reth0", GroupID: 256, VirtualAddresses: []string{"10.0.61.1/24"}},
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	m.mu.RLock()
	reason, recorded := m.unbuiltDesired[instanceKey{iface: "reth0", groupID: 256}]
	m.mu.RUnlock()
	if !recorded {
		t.Fatal("VRID-256 desired key absent from unbuiltDesired: the refusal " +
			"left no manager state (want the key recorded with its reason)")
	}
	if !strings.Contains(reason, "out of range") {
		t.Errorf("unbuiltDesired reason %q does not name the VRID refusal "+
			"(want it to say \"out of range\")", reason)
	}

	ready, reasons := m.RGVRRPReady(156, true)
	if ready {
		t.Fatal("RGVRRPReady(156) = true with the only instance refused: " +
			"manager state and VIP reality diverge")
	}
	if len(reasons) == 0 {
		t.Fatal("RGVRRPReady(156) not-ready with no reasons: the refusal is unnamed")
	}
	for _, r := range reasons {
		if !strings.Contains(r, "out of range") {
			t.Errorf("RGVRRPReady reason %q does not name the VRID refusal "+
				"(want it to say \"out of range\")", r)
		}
	}
}

// #9914 F-121, collector half: the RETH collector must not synthesize an
// instance it knows the manager will refuse. RG 156 derives VRID 256, outside
// 1..255; only the in-range RG may produce an instance.
//
// FAIL-ON-REVERT: restore the unchecked `100 + rgID` in CollectRethInstances
// and the out-of-range RG emits an instance again.
func TestCollectRethInstancesSkipsOutOfRangeVRID_9914(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 156, // 100+156 = 256: out of range
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.1.1/24"}},
					},
				},
				"reth1": {
					Name:            "reth1",
					RedundancyGroup: 1, // 100+1 = 101: the control
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"172.16.0.1/24"}},
					},
				},
			},
		},
	}
	insts := CollectRethInstances(cfg, map[int]int{156: 200, 1: 200})
	if len(insts) != 1 {
		var got []int
		for _, in := range insts {
			got = append(got, in.GroupID)
		}
		t.Fatalf("expected 1 instance (RG 1 only), got %d with GroupIDs %v",
			len(insts), got)
	}
	if insts[0].GroupID != 101 {
		t.Errorf("surviving instance GroupID = %d, want 101 (RG 1 control)", insts[0].GroupID)
	}
}
