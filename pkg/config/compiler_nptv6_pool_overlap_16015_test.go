package config

import (
	"strings"
	"testing"
)

// #16015: pool/interface members inside an NPTv6 external prefix.
//
// NPTv6 publishes its external (match) prefix statelessly with the
// source port unchanged, so it owns no occupancy bit a pool mint could
// consult. The strict gate natPoolOverlapOwners had pools+NAT64+
// interface only, and validateStaticNATPoolOverlapStrict explicitly
// skips IsNPTv6 rules — so a referenced v6 pool (or v6 interface
// egress) inside the external prefix committed clean and the runtime
// pool mint checked peer/iface/static only.
//
// FAIL-ON-REVERT: neutralizing validateNPTv6PoolOverlapStrict (or
// dropping its tail-gate dispatch) turns every "must reject" cell
// GREEN. Zone, scope-drop, unreferenced, and outside-prefix controls
// must stay GREEN both ways.

// nptv6Ext builds an installed NPTv6 rule (from zone = fromZone):
// internal fd00:1::/48 -> external 2001:db8:1::/48.
func nptv6Ext16015(fromZone string) []string {
	return []string{
		"set security nat static rule-set NPTV6 from zone " + fromZone,
		"set security nat static rule-set NPTV6 rule N1 match destination-address 2001:db8:1::/48",
		"set security nat static rule-set NPTV6 rule N1 then static-nat nptv6-prefix fd00:1::/48",
	}
}

func assertNPTv6PoolRejected16015(t *testing.T, want string, cmds ...string) {
	t.Helper()
	if _, err := CompileConfig(natOverlapTree(t, cmds...)); err == nil {
		t.Fatalf("strict commit must reject the NPTv6/pool overlap (want %q)", want)
	} else {
		msg := err.Error()
		if !strings.Contains(msg, "#16015") {
			t.Fatalf("strict error must cite #16015, got: %v", err)
		}
		if !strings.Contains(msg, want) {
			t.Fatalf("strict error %q does not contain %q", msg, want)
		}
	}
	cfg, err := CompileConfigLenient(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient compile must not brick: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16015") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a #16015 warning; warnings = %v", cfg.Warnings)
	}
}

func TestPoolMemberInsideNPTv6ExternalRejected16015(t *testing.T) {
	// V6 pool host inside the /48 external prefix; source rule egresses
	// to the NPTv6 from-zone (untrust).
	cmds := []string{"set security nat source pool P6 address 2001:db8:1::10"}
	cmds = append(cmds, srcRuleV6("RS1", "R1", "P6")...)
	cmds = append(cmds, nptv6Ext16015("untrust")...)
	assertNPTv6PoolRejected16015(t, `nptv6 external prefix "2001:db8:1::/48"`, cmds...)
}

func TestPoolCIDRInsideNPTv6ExternalRejected16015(t *testing.T) {
	cmds := []string{"set security nat source pool P6 address 2001:db8:1:5::/120"}
	cmds = append(cmds, srcRuleV6("RS1", "R1", "P6")...)
	cmds = append(cmds, nptv6Ext16015("untrust")...)
	assertNPTv6PoolRejected16015(t, `nptv6 external prefix`, cmds...)
}

func TestPoolMemberOutsideNPTv6ExternalAccepted16015(t *testing.T) {
	cmds := []string{"set security nat source pool P6 address 2001:db8:2::10"}
	cmds = append(cmds, srcRuleV6("RS1", "R1", "P6")...)
	cmds = append(cmds, nptv6Ext16015("untrust")...)
	assertNATOverlapAccepted(t, cmds...)
}

func TestUnreferencedPoolInsideNPTv6Accepted16015(t *testing.T) {
	// No source rule references the pool: it builds no allocator.
	cmds := []string{"set security nat source pool P6 address 2001:db8:1::10"}
	cmds = append(cmds, nptv6Ext16015("untrust")...)
	assertNATOverlapAccepted(t, cmds...)
}

func TestNPTv6DisjointZonePoolAccepted16015(t *testing.T) {
	// Source rule egresses dmz; NPTv6 is scoped to untrust. A packet
	// carries one egress zone, so the two can never publish for the
	// same flow direction.
	cmds := []string{"set security nat source pool P6 address 2001:db8:1::10"}
	cmds = append(cmds,
		"set security nat source rule-set RSD from zone trust",
		"set security nat source rule-set RSD to zone dmz",
		"set security nat source rule-set RSD rule R1 match source-address 2001:db8:ffff::/64",
		"set security nat source rule-set RSD rule R1 then source-nat pool P6",
	)
	cmds = append(cmds, nptv6Ext16015("untrust")...)
	assertNATOverlapAccepted(t, cmds...)
}

func TestNPTv6ScopedDroppedRuleDoesNotRejectPool16015(t *testing.T) {
	// A scope-carrying NPTv6 rule is dropped by the snapshot builder
	// (#5818) and never installs; its prefix must not quarantine the
	// pool. (The scoped rule itself is rejected by its own gate, so
	// assert the NPTv6/pool gate alone stays silent.)
	cfg := &Config{}
	cfg.Security.NAT.SourcePools = map[string]*NATPool{
		"P6": {Name: "P6", Address: "2001:db8:1::10"},
	}
	cfg.Security.NAT.Source = []*NATRuleSet{{
		Name: "RS1", FromZone: "trust", ToZone: "untrust",
		Rules: []*NATRule{{Name: "R1", Then: NATThen{PoolName: "P6"}}},
	}}
	cfg.Security.NAT.Static = []*StaticNATRuleSet{{
		Name: "NPTV6", FromZone: "untrust",
		Rules: []*StaticNATRule{{
			Name: "N1", Match: "2001:db8:1::/48", Then: "fd00:1::/48",
			IsNPTv6: true, SourceAddresses: []string{"fd00:9::/48"},
		}},
	}}
	if _, err := validateNPTv6PoolOverlapStrict(cfg, false); err != nil {
		t.Fatalf("scope-dropped NPTv6 rule must not reject the pool: %v", err)
	}
}

func TestNPTv6PoolGateNilAndEmpty16015(t *testing.T) {
	if _, err := validateNPTv6PoolOverlapStrict(nil, false); err != nil {
		t.Fatalf("nil cfg: %v", err)
	}
	cfg := &Config{}
	cfg.Security.NAT.SourcePools = map[string]*NATPool{
		"P6": {Name: "P6", Address: "2001:db8:1::10"},
	}
	cfg.Security.NAT.Source = []*NATRuleSet{{
		Name: "RS1", FromZone: "trust", ToZone: "untrust",
		Rules: []*NATRule{{Name: "R1", Then: NATThen{PoolName: "P6"}}},
	}}
	if _, err := validateNPTv6PoolOverlapStrict(cfg, false); err != nil {
		t.Fatalf("no NPTv6 rules must not reject: %v", err)
	}
}
