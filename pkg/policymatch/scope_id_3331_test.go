package policymatch

import (
	"net"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestMatchResultCarriesZonePairScopeAndID pins #3331: a zone-pair match must
// report the matched policy's from-zone/to-zone scope, that it is NOT global,
// and the stable runtime policy ID (the SSOT RuntimePolicyIDs namespace) so a
// verdict can be mapped back to the runtime policy / session-table / audit
// record. RED on revert: before #3331 Result carried only PolicyName/Action.
func TestMatchResultCarriesZonePairScopeAndID(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		// Two zone pairs that share a duplicate policy NAME "allow" — legal in
		// Junos and exactly the collision that made a name-only verdict
		// ambiguous before #3331.
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application any",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies from-zone untrust to-zone trust policy allow match source-address any",
		"set security policies from-zone untrust to-zone trust policy allow match destination-address any",
		"set security policies from-zone untrust to-zone trust policy allow match application any",
		"set security policies from-zone untrust to-zone trust policy allow then deny",
		"set security policies default-policy deny-all",
	}
	cfg := compileFromSet(t, cmds)

	res := Match(cfg, Query{
		FromZone: "untrust", ToZone: "trust",
		SrcIP: net.ParseIP("10.0.2.5"), DstIP: net.ParseIP("10.0.1.5"),
	})
	if !res.Matched {
		t.Fatalf("expected a match, got Matched=false")
	}
	if res.Global {
		t.Errorf("Global = true, want false for a zone-pair policy")
	}
	if res.FromZone != "untrust" || res.ToZone != "trust" {
		t.Errorf("scope = %s->%s, want untrust->trust", res.FromZone, res.ToZone)
	}
	if res.PolicyName != "allow" {
		t.Errorf("PolicyName = %q, want allow", res.PolicyName)
	}

	// The reported PolicyID must equal the SSOT runtime ID for THIS policy
	// (the untrust->trust set's "allow"), NOT the same-named trust->untrust
	// policy — that is the disambiguation #3331 delivers.
	ids := dpuserspace.RuntimePolicyIDs(cfg)
	var untrustSetIdx int
	for i, zpp := range cfg.Security.Policies {
		if zpp != nil && zpp.FromZone == "untrust" && zpp.ToZone == "trust" {
			untrustSetIdx = i
		}
	}
	wantID := ids[[2]uint32{uint32(untrustSetIdx), 0}]
	if res.PolicyID != wantID {
		t.Errorf("PolicyID = %d, want %d (untrust->trust runtime ID)", res.PolicyID, wantID)
	}
	// Sanity: the duplicate-named trust->untrust policy has a DIFFERENT runtime
	// ID, so the ID truly disambiguates.
	var trustSetIdx int
	for i, zpp := range cfg.Security.Policies {
		if zpp != nil && zpp.FromZone == "trust" && zpp.ToZone == "untrust" {
			trustSetIdx = i
		}
	}
	if otherID := ids[[2]uint32{uint32(trustSetIdx), 0}]; otherID == res.PolicyID {
		t.Errorf("trust->untrust ID %d collides with untrust->trust ID %d; scope/id cannot disambiguate", otherID, res.PolicyID)
	}
}

// TestMatchResultCarriesGlobalScopeAndID pins #3331 for the global tier: a
// global-policy match must report Global=true, the policy's match from-zone/
// to-zone scope (#3148, empty == all zones), and the runtime policy ID drawn
// from the global policy set (policySetID == len(cfg.Security.Policies)).
func TestMatchResultCarriesGlobalScopeAndID(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies global policy g-allow match source-address any",
		"set security policies global policy g-allow match destination-address any",
		"set security policies global policy g-allow match application any",
		"set security policies global policy g-allow match from-zone trust",
		"set security policies global policy g-allow then permit",
		"set security policies default-policy deny-all",
	}
	cfg := compileFromSet(t, cmds)

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
	})
	if !res.Matched || !res.Global {
		t.Fatalf("expected global match, got Matched=%v Global=%v", res.Matched, res.Global)
	}
	if res.FromZone != "trust" {
		t.Errorf("global scope from-zone = %q, want trust", res.FromZone)
	}
	if res.ToZone != "" {
		t.Errorf("global scope to-zone = %q, want \"\" (any)", res.ToZone)
	}
	if res.PolicyName != "g-allow" {
		t.Errorf("PolicyName = %q, want g-allow", res.PolicyName)
	}
	ids := dpuserspace.RuntimePolicyIDs(cfg)
	wantID := ids[[2]uint32{uint32(len(cfg.Security.Policies)), 0}]
	if res.PolicyID != wantID {
		t.Errorf("PolicyID = %d, want %d (global set runtime ID)", res.PolicyID, wantID)
	}
}

// TestMatchResultRuntimeIDMatchesShowPolicies pins that a multi-application
// policy's reported match-policies PolicyID equals its span-accumulated runtime
// ID — i.e. it advances past an earlier multi-application policy's expansion
// exactly like the `show policies` Index column (#3063), not the raw ordinal.
// This is the property that lets the diagnostic cross-reference the audit log.
func TestMatchResultRuntimeIDMatchesShowPolicies(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		// First policy matches an application-set so its runtime span > 1,
		// pushing the second policy's runtime ID past the raw ordinal.
		"set applications application-set webset application junos-http",
		"set applications application-set webset application junos-https",
		"set security policies from-zone trust to-zone untrust policy first match source-address any",
		"set security policies from-zone trust to-zone untrust policy first match destination-address any",
		"set security policies from-zone trust to-zone untrust policy first match application webset",
		"set security policies from-zone trust to-zone untrust policy first then permit",
		"set security policies from-zone trust to-zone untrust policy second match source-address any",
		"set security policies from-zone trust to-zone untrust policy second match destination-address any",
		"set security policies from-zone trust to-zone untrust policy second match application any",
		"set security policies from-zone trust to-zone untrust policy second then deny",
		"set security policies default-policy deny-all",
	}
	cfg := compileFromSet(t, cmds)

	// A non-web flow falls through "first" (web-only) to "second".
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		Protocol: "udp", DstPort: PortPtr(9999),
	})
	if !res.Matched || res.PolicyName != "second" {
		t.Fatalf("expected match on second, got Matched=%v name=%q", res.Matched, res.PolicyName)
	}
	ids := dpuserspace.RuntimePolicyIDs(cfg)
	wantID := ids[[2]uint32{0, 1}] // set 0, slice index 1 (second policy)
	if res.PolicyID != wantID {
		t.Errorf("PolicyID = %d, want %d (SSOT span-accumulated runtime ID)", res.PolicyID, wantID)
	}
	// The span-accumulated ID must NOT equal the raw ordinal (set*256 + 1 == 1
	// here); "first" expanded to 2 slots, so "second" sits at runtime ID 2.
	if res.PolicyID == 1 {
		t.Errorf("PolicyID = 1 looks like the raw ordinal, not the span-accumulated runtime ID")
	}
}
