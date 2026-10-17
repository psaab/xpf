package config

import "testing"

// DR14-H2 (#14415): a NAT rule whose `match` is PACKED onto the rule line —
//
//	rule r1 match source-address 10.0.0.0/24 { then { source-nat interface; } }
//
// — parses as ONE rule node with Keys=[rule r1 match source-address
// 10.0.0.0/24] and Children=[then{...}]. The compilers read the match only
// via FindChildren("match"), which scans Children, so the packed match was
// never seen: matchAuthored stayed false (disarming the #8430 empty-match
// gate and the #9874 lenient fail-closed marker), and the rule compiled
// unconstrained (SNAT: translates every source in scope) or vanished
// (DNAT: no destination key, so the snapshot builder publishes no entry —
// an `off` exemption silently deleted, letting later translate rules fire).
//
// These cells use the hierarchical text path (NewParser via compileText),
// NOT flat `set`, because SetPath nests each segment and never produces
// the packed shape.

const dr14h2SNATPacked = `security { nat { source { rule-set rs1 { from zone trust; to zone untrust; rule r1 match source-address 10.0.0.0/24 { then { source-nat interface; } } } } } }`
const dr14h2SNATBraced = `security { nat { source { rule-set rs1 { from zone trust; to zone untrust; rule r1 { match { source-address 10.0.0.0/24; } then { source-nat interface; } } } } } }`

func dr14h2SNATRule(t *testing.T, cfg *Config) *NATRule {
	t.Helper()
	for _, rs := range cfg.Security.NAT.Source {
		for _, r := range rs.Rules {
			if r.Name == "r1" {
				return r
			}
		}
	}
	t.Fatalf("SNAT rule r1 not found in %+v", cfg.Security.NAT.Source)
	return nil
}

func TestSNATPackedMatchCompilesConstrained14415(t *testing.T) {
	cfg := compileText(t, dr14h2SNATPacked)
	if cfg == nil {
		t.Fatal("packed SNAT config must compile")
	}
	r := dr14h2SNATRule(t, cfg)
	if got := r.Match.SourceAddresses; len(got) != 1 || got[0] != "10.0.0.0/24" {
		t.Errorf("packed match SourceAddresses = %v, want [10.0.0.0/24] (the rule must not compile unconstrained)", got)
	}
	if !r.matchAuthored {
		t.Error("packed match must set matchAuthored=true so the #8430/#9874 gates see it as authored")
	}
	if r.LenientMatchDropped {
		t.Error("packed match that constrains must not be marked LenientMatchDropped")
	}
	// Braced control must agree.
	braced := compileText(t, dr14h2SNATBraced)
	if braced == nil {
		t.Fatal("braced SNAT control must compile")
	}
	br := dr14h2SNATRule(t, braced)
	if len(br.Match.SourceAddresses) != 1 || br.Match.SourceAddresses[0] != "10.0.0.0/24" || !br.matchAuthored {
		t.Fatalf("braced control broken: src=%v authored=%v", br.Match.SourceAddresses, br.matchAuthored)
	}
}

const dr14h2DNATOffPacked = `security { nat { destination { pool p1 { address 192.168.1.10/32; } rule-set rs1 { from zone untrust; rule r1 match destination-address 203.0.113.10/32 { then { destination-nat off; } } rule r2 { match { destination-address 203.0.113.0/24; } then { destination-nat pool p1; } } } } } }`
const dr14h2DNATOffBraced = `security { nat { destination { pool p1 { address 192.168.1.10/32; } rule-set rs1 { from zone untrust; rule r1 { match { destination-address 203.0.113.10/32; } then { destination-nat off; } } rule r2 { match { destination-address 203.0.113.0/24; } then { destination-nat pool p1; } } } } } }`
const dr14h2DNATPoolPacked = `security { nat { destination { pool p1 { address 192.168.1.10/32; } rule-set rs1 { from zone untrust; rule r1 match destination-address 203.0.113.10/32 { then { destination-nat pool p1; } } } } } }`

func dr14h2DNATRule(t *testing.T, cfg *Config, name string) *NATRule {
	t.Helper()
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("no DNAT config compiled")
	}
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, r := range rs.Rules {
			if r.Name == name {
				return r
			}
		}
	}
	t.Fatalf("DNAT rule %s not found", name)
	return nil
}

func TestDNATPackedMatchOffExemptionCompiles14415(t *testing.T) {
	for label, text := range map[string]string{"packed": dr14h2DNATOffPacked, "braced": dr14h2DNATOffBraced} {
		cfg := compileText(t, text)
		if cfg == nil {
			t.Fatalf("%s: DNAT off config must compile", label)
		}
		r1 := dr14h2DNATRule(t, cfg, "r1")
		if got := r1.Match.DestinationAddresses; len(got) != 1 || got[0] != "203.0.113.10/32" {
			t.Errorf("%s: off rule DestinationAddresses = %v, want [203.0.113.10/32]", label, got)
		}
		if !r1.matchAuthored {
			t.Errorf("%s: off rule matchAuthored = false, want true", label)
		}
		if !r1.Then.Off || r1.Then.Type != NATDestination {
			t.Errorf("%s: off rule Then = %+v, want NATDestination+Off", label, r1.Then)
		}
		// Installed means: no exclusion reason. The userspace snapshot
		// builder (pkg/dataplane/userspace) installs exactly the rules
		// for which this predicate is empty and destAddrs is non-empty;
		// an empty destination here is what made the exemption vanish.
		if reason := DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, r1); reason != "" {
			t.Errorf("%s: off rule excluded (%q) — the exemption would not install", label, reason)
		}
		r2 := dr14h2DNATRule(t, cfg, "r2")
		if r2.Then.PoolName != "p1" {
			t.Errorf("%s: translate rule PoolName = %q, want p1", label, r2.Then.PoolName)
		}
	}
}

func TestDNATPackedMatchPoolRuleCompiles14415(t *testing.T) {
	cfg := compileText(t, dr14h2DNATPoolPacked)
	if cfg == nil {
		t.Fatal("packed DNAT pool config must compile")
	}
	r := dr14h2DNATRule(t, cfg, "r1")
	if got := r.Match.DestinationAddresses; len(got) != 1 || got[0] != "203.0.113.10/32" {
		t.Errorf("packed DNAT pool rule DestinationAddresses = %v, want [203.0.113.10/32] (currently publishes no entry)", got)
	}
	if !r.matchAuthored {
		t.Error("packed DNAT pool rule matchAuthored = false, want true")
	}
	if reason := DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, r); reason != "" {
		t.Errorf("packed DNAT pool rule excluded (%q) — it would publish no entry", reason)
	}
}

// Scope-only control: a rule with NO match at all is legitimate and must
// stay unconstrained and unmarked — the fix must not invent a match.
func TestNATScopeOnlyRuleStaysLegitimate14415(t *testing.T) {
	cfg := compileText(t, `security { nat { source { rule-set rs1 { from zone trust; to zone untrust; rule r1 { then { source-nat interface; } } } } } }`)
	if cfg == nil {
		t.Fatal("scope-only SNAT rule must compile")
	}
	r := dr14h2SNATRule(t, cfg)
	if r.matchAuthored {
		t.Error("scope-only rule must keep matchAuthored=false")
	}
	if r.LenientMatchDropped {
		t.Error("scope-only rule must not be poisoned as LenientMatchDropped")
	}
	if len(r.Match.SourceAddresses) != 0 {
		t.Errorf("scope-only rule gained sources %v", r.Match.SourceAddresses)
	}
}

// Fully-packed shape: `rule r1 match ... then ...;` with NO braced body.
// packedBodyChildren expands it into match+then siblings, so it now
// compiles to the same constrained rule as the braced spelling — the
// pre-fix zero-action rejection was a consequence of the same dropped
// match, not a deliberate gate on this spelling. What must NOT happen
// is the pre-fix outcome for the braced-body shape (unconstrained /
// vanished); this cell pins the fully-packed spelling to the braced
// result instead.
func TestNATFullyPackedMatchThenCompilesConstrained14415(t *testing.T) {
	cfg := compileText(t, `security { nat { source { rule-set rs1 { from zone trust; to zone untrust; rule r1 match source-address 10.0.0.0/24 then source-nat interface; } } } }`)
	if cfg == nil {
		t.Fatal("fully-packed SNAT rule must compile via lenient path")
	}
	r := dr14h2SNATRule(t, cfg)
	if len(r.Match.SourceAddresses) != 1 || r.Match.SourceAddresses[0] != "10.0.0.0/24" {
		t.Errorf("fully-packed SourceAddresses = %v, want [10.0.0.0/24]", r.Match.SourceAddresses)
	}
	if !r.Then.Interface {
		t.Errorf("fully-packed Then = %+v, want interface SNAT", r.Then)
	}

}
