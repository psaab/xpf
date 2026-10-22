package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #4626 L01, REST half. sessionEntryV4/V6 resolved PolicyName by indexing
// view.policyNames directly, and `policy_id` 0 is BOTH the first configured
// policy's id and the value stamped on every session no policy admitted
// (host-inbound, neighbor-seed, fabric, tunnel, pre-#3056, and every session
// synced from an older HA peer mid-rolling-upgrade). The JSON surface therefore
// told automation that a specific policy admitted traffic that policy never
// saw — and unlike the CLI there was no numeric fallback here, so the name was
// emitted unconditionally.
//
// These drive the real entry builders. Re-inlining `view.policyNames[val.PolicyID]`
// at either site turns them RED.

// policyNamesWithFirstPolicy is the fixture that matters: id 0 is OCCUPIED by a
// real policy, exactly as compilePolicies emits it. A fixture without an entry
// at 0 would pass against the unfixed code.
func policyNamesWithFirstPolicy() map[uint32]string {
	return map[uint32]string{
		0:                                 "trust-to-untrust/allow-web",
		1:                                 "trust-to-untrust/allow-dns",
		dataplane.DefaultPolicySentinelID: dataplane.DefaultPolicyName,
	}
}

func testSessionView() sessionView {
	return sessionView{
		zoneNames:    map[uint16]string{1: "trust", 2: "untrust"},
		policyNames:  policyNamesWithFirstPolicy(),
		appNames:     map[config.AssignedAppID]string{},
		zoneIfaces:   map[uint16][]string{},
		egressIfaces: map[sessionEgressKey]string{},
	}
}

func TestSessionEntryV4PolicyIDZeroNotFirstPolicy_4626(t *testing.T) {
	view := testSessionView()
	val := dataplane.SessionValue{
		State:       1,
		PolicyID:    0, // host-inbound / fabric / tunnel / older-peer session
		IngressZone: 1,
		EgressZone:  2,
		Created:     100,
		LastSeen:    100,
	}

	se := sessionEntryV4(dataplane.SessionKey{Protocol: 6}, val, 200, view)

	if se.PolicyName == view.policyNames[0] {
		t.Fatalf("REST session entry reports policy_name=%q for a policy_id 0 session — "+
			"that is the FIRST configured policy, which never admitted it. Automation "+
			"reading this attributes host-inbound/fabric/tunnel/older-peer traffic to a "+
			"real rule (#4626)", se.PolicyName)
	}
	if se.PolicyName != dataplane.UnattributedPolicyName {
		t.Errorf("policy_name = %q, want %q", se.PolicyName, dataplane.UnattributedPolicyName)
	}
	// The numeric id is still carried, so nothing is hidden by the substitution.
	if se.PolicyID != 0 {
		t.Errorf("policy_id = %d, want 0 — the raw wire value must still be surfaced", se.PolicyID)
	}
}

func TestSessionEntryV6PolicyIDZeroNotFirstPolicy_4626(t *testing.T) {
	view := testSessionView()
	val := dataplane.SessionValueV6{
		State:       1,
		PolicyID:    0,
		IngressZone: 1,
		EgressZone:  2,
		Created:     100,
		LastSeen:    100,
	}

	se := sessionEntryV6(dataplane.SessionKeyV6{Protocol: 6}, val, 200, view)

	if se.PolicyName == view.policyNames[0] {
		t.Fatalf("REST IPv6 session entry reports policy_name=%q for a policy_id 0 session "+
			"— the first configured policy never admitted it (#4626)", se.PolicyName)
	}
	if se.PolicyName != dataplane.UnattributedPolicyName {
		t.Errorf("policy_name = %q, want %q", se.PolicyName, dataplane.UnattributedPolicyName)
	}
}

// Over-rejection guard: a session a real policy DID admit must keep reporting
// that policy, on both families. A fix that blanked every name would satisfy
// the tests above and destroy the surface's actual purpose.
func TestSessionEntryRealPolicyStillResolves_4626(t *testing.T) {
	view := testSessionView()

	se4 := sessionEntryV4(dataplane.SessionKey{Protocol: 6},
		dataplane.SessionValue{State: 1, PolicyID: 1, Created: 100, LastSeen: 100}, 200, view)
	if want := view.policyNames[1]; se4.PolicyName != want {
		t.Errorf("v4 policy_name = %q, want %q — an admitted session must still name its "+
			"policy", se4.PolicyName, want)
	}

	se6 := sessionEntryV6(dataplane.SessionKeyV6{Protocol: 6},
		dataplane.SessionValueV6{State: 1, PolicyID: 1, Created: 100, LastSeen: 100}, 200, view)
	if want := view.policyNames[1]; se6.PolicyName != want {
		t.Errorf("v6 policy_name = %q, want %q", se6.PolicyName, want)
	}

	// The implicit default-policy sentinel keeps its #3057 rendering.
	seDef := sessionEntryV4(dataplane.SessionKey{Protocol: 6},
		dataplane.SessionValue{State: 1, PolicyID: dataplane.DefaultPolicySentinelID,
			Created: 100, LastSeen: 100}, 200, view)
	if seDef.PolicyName != dataplane.DefaultPolicyName {
		t.Errorf("default-sentinel policy_name = %q, want %q (#3057 must not regress)",
			seDef.PolicyName, dataplane.DefaultPolicyName)
	}
}
