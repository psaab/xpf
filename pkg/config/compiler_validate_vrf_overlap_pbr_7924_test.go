package config

import (
	"strings"
	"testing"
)

// #7924: overlapping L3 across routing-instances is only a LIVE cross-tenant
// bypass when a PBR `then routing-instance` term is steering. The established-
// session fast path short-circuits before `ingress_route_table_override`, so a
// second flow sharing a 5-tuple inherits the first flow's cached egress, NAT and
// POLICY decision across the tenant boundary — but nothing re-homes a flow's
// table without that term.
//
// So the rejection is NARROW, and this table is what proves it is narrow rather
// than broad. The MIDDLE ROW is the whole point: overlap with NO PBR must still
// commit. Delete the PBR half of the condition and only that row reds — without
// it a broad reject passes as a narrow one, and a broad reject would break the
// overlapping-address-space designs VRFs exist to serve.
func TestVRFOverlapRejectedOnlyWithPBRSteering_7924(t *testing.T) {
	const (
		ifA = "set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24"
		ifB = "set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24"
		// Non-overlapping sibling for the third row.
		ifC   = "set interfaces ge-0/0/2 unit 0 family inet address 192.168.7.2/24"
		riA   = "set routing-instances RI-A instance-type virtual-router"
		riAif = "set routing-instances RI-A interface ge-0/0/1.0"
		riB   = "set routing-instances RI-B instance-type virtual-router"
		riBif = "set routing-instances RI-B interface ge-0/0/2.0"
		pbr   = "set firewall family inet filter fbf term t1 then routing-instance RI-B"
		pbrIf = "set interfaces ge-0/0/3 unit 0 family inet filter input fbf"
		ifD   = "set interfaces ge-0/0/3 unit 0 family inet address 192.168.7.1/24"
	)

	for _, tc := range []struct {
		name       string
		cmds       []string
		wantReject bool
		why        string
	}{
		{
			// overlap YES, PBR YES -> reject.
			name:       "overlap_and_pbr_steering",
			cmds:       []string{ifA, ifB, riA, riAif, riB, riBif, pbr, ifD, pbrIf},
			wantReject: true,
			why: "this is the live cross-tenant policy bypass: the fast path skips " +
				"the PBR table override, so a colliding 5-tuple inherits the other " +
				"tenant's cached policy decision",
		},
		{
			// THE MIDDLE ROW. overlap YES, PBR NO -> commits, warning unchanged.
			name:       "overlap_without_pbr_still_commits",
			cmds:       []string{ifA, ifB, riA, riAif, riB, riBif},
			wantReject: false,
			why: "overlapping address space is the primary reason VRFs exist. With " +
				"no `then routing-instance` term nothing re-homes a flow's table " +
				"mid-path, so the collision is not reachable and rejecting would " +
				"break a design that works correctly today",
		},
		{
			// overlap NO, PBR YES -> commits clean.
			name:       "pbr_steering_without_overlap",
			cmds:       []string{ifA, ifC, riA, riAif, riB, riBif, pbr, ifD, pbrIf},
			wantReject: false,
			why: "PBR steering into a VRF whose address space is disjoint cannot " +
				"produce a 5-tuple collision at all",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			_, err := CompileConfig(tree)
			if tc.wantReject && err == nil {
				t.Fatalf("want a commit REJECTION — %s", tc.why)
			}
			if !tc.wantReject && err != nil {
				t.Fatalf("want the config to COMMIT — %s; got: %v", tc.why, err)
			}
			if tc.wantReject && !strings.Contains(err.Error(), "#7924") {
				t.Errorf("the rejection must cite #7924 so an operator can find the "+
					"limitation and its tracking issue; got: %v", err)
			}
			if tc.wantReject && !strings.Contains(err.Error(), "#7160") {
				t.Errorf("the rejection must cite #7160, the real fix, so this "+
					"workaround does not read as the end state; got: %v", err)
			}
		})
	}
}

// TestVRFOverlapPBRRejectionIsLenientDowngraded_7924 pins the #1960 no-brick
// half. A hard reject on the tolerant load / HA peer-sync path would refuse to
// boot a node on a configuration its PEER already accepted and is forwarding —
// strictly worse than the collision this gate exists to prevent, because it
// takes the node down entirely rather than mis-forwarding some flows.
//
// The warning must survive the downgrade, or the lenient path reports nothing at
// all and the operator loses the pre-#7924 advisory too.
func TestVRFOverlapPBRRejectionIsLenientDowngraded_7924(t *testing.T) {
	cmds := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
		"set firewall family inet filter fbf term t1 then routing-instance RI-B",
		"set interfaces ge-0/0/3 unit 0 family inet address 192.168.7.1/24",
		"set interfaces ge-0/0/3 unit 0 family inet filter input fbf",
	}
	tree := buildTree(t, cmds)

	// Strict: rejected. This is the precondition — without it the lenient
	// assertion below could pass because the config was never rejectable.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("precondition: the strict path must reject this config")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant / peer-sync path must still BOOT this config "+
			"(#1960 no-brick): refusing it would take a node down on a "+
			"configuration its peer already accepted; got: %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "overlapping L3 across routing-instances") {
			found = true
		}
	}
	if !found {
		t.Error("the lenient path must still carry the overlap WARNING — a silent " +
			"downgrade loses the pre-#7924 advisory as well as the rejection")
	}
}
