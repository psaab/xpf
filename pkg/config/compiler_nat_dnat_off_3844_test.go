package config

import "testing"

// TestDNATDestinationOffCompilesExemption verifies #3844: a DNAT rule
// `then destination-nat off` compiles to a real no-translate EXEMPTION
// (Then.Type == NATDestination, Then.Off == true), not the empty Then
// (Type == 0, Off == false, PoolName == "") that the pre-#3844 parser produced
// and the snapshot builder silently dropped. A normal `then destination-nat
// pool <p>` rule in the same rule-set still compiles to a translate rule.
//
// RED on revert: reverting the compiler_nat.go then-parser change leaves the
// off rule as an empty Then (Type == 0 / NATSource, Off == false), so both the
// Then.Off and Then.Type assertions fail.
func TestDNATDestinationOffCompilesExemption(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat destination pool p1 address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	// The token is a valid config leaf (it was already accepted at commit; the
	// bug was that it compiled to nothing, not that it was rejected).
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected `then destination-nat off`: %v", err)
	}
	if len(cfg.Security.NAT.Destination.RuleSets) != 1 {
		t.Fatalf("expected 1 DNAT rule-set, got %d", len(cfg.Security.NAT.Destination.RuleSets))
	}
	var exempt, dnat *NATRule
	for _, r := range cfg.Security.NAT.Destination.RuleSets[0].Rules {
		switch r.Name {
		case "r-exempt":
			exempt = r
		case "r-dnat":
			dnat = r
		}
	}
	if exempt == nil || dnat == nil {
		t.Fatalf("missing rules: exempt=%v dnat=%v", exempt, dnat)
	}
	if exempt.Then.Type != NATDestination {
		t.Errorf("off rule Then.Type = %d, want NATDestination (%d)", exempt.Then.Type, NATDestination)
	}
	if !exempt.Then.Off {
		t.Errorf("off rule Then.Off = false, want true (the #3844 exemption flag)")
	}
	if exempt.Then.PoolName != "" {
		t.Errorf("off rule Then.PoolName = %q, want empty", exempt.Then.PoolName)
	}
	// The sibling translate rule is unaffected.
	if dnat.Then.Type != NATDestination || dnat.Then.Off || dnat.Then.PoolName != "p1" {
		t.Errorf("translate rule = {Type:%d Off:%v Pool:%q}, want {NATDestination false \"p1\"}",
			dnat.Then.Type, dnat.Then.Off, dnat.Then.PoolName)
	}
}
