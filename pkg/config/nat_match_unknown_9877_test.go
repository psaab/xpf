package config

import (
	"reflect"
	"strings"
	"testing"
)

// Unknown NAT `match` leaves — #9877 cells.
//
// A typo'd match leaf beside a valid one was silently dropped on the tolerant
// path and the rule compiled constrained on the surviving dimensions, with no
// operator-facing warning. These cells pin the record (UnknownMatchLeaves),
// the strict-reject / lenient-warn gate, the #8430 suppression, the exclusion
// predicates, and the #6812 walk placement. The snapshot skips themselves are
// pinned in pkg/dataplane/userspace (nat_unknown_match_9877_test.go) and the
// show annotations in pkg/natshow — this file stays on the compile side.

// lenientNAT9877 compiles set-lines on the tolerant load / peer-sync path.
func lenientNAT9877(t *testing.T, lines []string) *Config {
	t.Helper()
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func sourceRule9877(t *testing.T, cfg *Config, ruleSet, rule string) *NATRule {
	t.Helper()
	for _, rs := range cfg.Security.NAT.Source {
		if rs != nil && rs.Name == ruleSet {
			for _, r := range rs.Rules {
				if r != nil && r.Name == rule {
					return r
				}
			}
		}
	}
	t.Fatalf("source rule %s/%s missing after compile", ruleSet, rule)
	return nil
}

// TestNATUnknownMatchLeavesLenientWarnsSource9877 is the issue's core cell: a
// valid leaf plus a typo'd one must record the drop and warn naming it — not
// compile as surviving-dimension-only in silence.
func TestNATUnknownMatchLeavesLenientWarnsSource9877(t *testing.T) {
	cfg := lenientNAT9877(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	})
	r := sourceRule9877(t, cfg, "rs1", "r1")
	if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownMatchLeaves = %v, want %v (the typo was dropped silently)", got, want)
	}
	all := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(all, "soruce-address") {
		t.Fatalf("no lenient warning names the dropped leaf; warnings: %q", cfg.Warnings)
	}
	if strings.Contains(all, "constrains nothing") {
		t.Fatalf("the #8430 generic warning fired alongside the precise one (one mistake must yield one warning); warnings: %q", cfg.Warnings)
	}
	if reason := SourceNATRuleExcludedReason(r); reason == "" {
		t.Fatal("the marked rule reports no exclusion reason — the builder would install it as surviving-dimension-only")
	} else if !strings.Contains(reason, "soruce-address") {
		t.Fatalf("exclusion reason %q does not name the dropped leaf", reason)
	}
}

// TestNATUnknownMatchLeavesStrictRejects9877 pins both strict channels for the
// same tree: SchemaValidate (closedWorld) and direct CompileConfig (the #9877
// gate — the defense-in-depth branch for callers that skip schema).
func TestNATUnknownMatchLeavesStrictRejects9877(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
	tree := buildTree(t, lines)
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("SchemaValidate accepted a typo'd NAT match leaf; want closed-world rejection")
	} else if !strings.Contains(err.Error(), "soruce-address") {
		t.Fatalf("SchemaValidate error %q does not name the typo", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted a rule with a dropped match leaf; want #9877 rejection")
	} else if !strings.Contains(err.Error(), "soruce-address") || !strings.Contains(err.Error(), "#9877") {
		t.Fatalf("CompileConfig error %q must name the leaf and the issue", err)
	}
}

// TestNATUnknownMatchLeavesDestStatic9877 covers the destination and static
// siblings: same record, same warn, same strict reject.
func TestNATUnknownMatchLeavesDestStatic9877(t *testing.T) {
	t.Run("destination", func(t *testing.T) {
		lines := []string{
			"set security zones security-zone trust",
			"set security nat destination pool p1 address 192.0.2.5",
			"set security nat destination rule-set rs1 from zone trust",
			"set security nat destination rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat destination rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool p1",
		}
		cfg := lenientNAT9877(t, lines)
		var r *NATRule
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			for _, cand := range rs.Rules {
				if cand.Name == "r1" {
					r = cand
				}
			}
		}
		if r == nil {
			t.Fatal("destination rule r1 missing after compile")
		}
		if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
		}
		if all := strings.Join(cfg.Warnings, "\n"); !strings.Contains(all, "soruce-address") {
			t.Fatalf("no lenient warning names the dropped leaf; warnings: %q", cfg.Warnings)
		}
		if _, err := CompileConfig(buildTree(t, lines)); err == nil {
			t.Fatal("CompileConfig accepted a destination rule with a dropped match leaf")
		} else if !strings.Contains(err.Error(), "soruce-address") {
			t.Fatalf("strict error %q must name the leaf", err)
		}
	})
	t.Run("static", func(t *testing.T) {
		lines := []string{
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security nat static rule-set rs1 from zone untrust",
			"set security nat static rule-set rs1 rule r1 match destination-address 198.51.100.10/32",
			"set security nat static rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
			"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
		}
		cfg := lenientNAT9877(t, lines)
		if len(cfg.Security.NAT.Static) == 0 || len(cfg.Security.NAT.Static[0].Rules) == 0 {
			t.Fatal("static rule missing after compile")
		}
		r := cfg.Security.NAT.Static[0].Rules[0]
		if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
		}
		if all := strings.Join(cfg.Warnings, "\n"); !strings.Contains(all, "soruce-address") {
			t.Fatalf("no lenient warning names the dropped leaf; warnings: %q", cfg.Warnings)
		}
		if _, err := CompileConfig(buildTree(t, lines)); err == nil {
			t.Fatal("CompileConfig accepted a static rule with a dropped match leaf")
		} else if !strings.Contains(err.Error(), "soruce-address") {
			t.Fatalf("strict error %q must name the leaf", err)
		}
	})
}

// TestNATUnknownMatchLeavesTypoOnlySingleWarning9877: a typo-ONLY match is both
// unknown-leaf and unconstrained — the precise diagnosis must win alone, and
// it must state the unconstrained consequence so the #8430 suppression loses
// no information.
func TestNATUnknownMatchLeavesTypoOnlySingleWarning9877(t *testing.T) {
	cfg := lenientNAT9877(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	})
	r := sourceRule9877(t, cfg, "rs1", "r1")
	if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
	}
	if len(cfg.Warnings) != 1 {
		t.Fatalf("want exactly one warning for one mistake, got %d: %q", len(cfg.Warnings), cfg.Warnings)
	}
	w := cfg.Warnings[0]
	if !strings.Contains(w, "soruce-address") {
		t.Fatalf("the single warning %q does not name the typo", w)
	}
	if !strings.Contains(w, "constrains nothing") {
		t.Fatalf("the single warning %q hides the unconstrained consequence of the typo-only match", w)
	}
	if strings.Contains(w, "EVERY packet") {
		t.Fatalf("the #8430 generic text leaked into the warning %q (suppression failed)", w)
	}
}

// TestNATUnknownMatchLeavesCombinedValueless9877: a valueless known leaf plus a
// typo is still one mistake for warning purposes — the named typo plus the
// stated unconstrained consequence.
func TestNATUnknownMatchLeavesCombinedValueless9877(t *testing.T) {
	cfgText := `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match {
                        source-address;
                        soruce-address 192.168.0.0/16;
                    }
                    then {
                        source-nat interface;
                    }
                }
            }
        }
    }
}
`
	tree := mustParse(t, cfgText)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	r := sourceRule9877(t, cfg, "rs1", "r1")
	if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
	}
	if len(cfg.Warnings) != 1 {
		t.Fatalf("want exactly one warning, got %d: %q", len(cfg.Warnings), cfg.Warnings)
	}
	if w := cfg.Warnings[0]; !strings.Contains(w, "soruce-address") || !strings.Contains(w, "constrains nothing") {
		t.Fatalf("combined-shape warning %q must name the typo and state the consequence", w)
	}
}

// TestNATUnknownMatchLeavesDeduped9877: a repeated unknown leaf (and a typo in
// a second #3850 match block) records once — the warning must not list it
// twice.
func TestNATUnknownMatchLeavesDeduped9877(t *testing.T) {
	t.Run("repeated flat-set", func(t *testing.T) {
		cfg := lenientNAT9877(t, []string{
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set rs1 rule r1 match soruce-address 10.0.0.0/8",
			"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
			"set security nat source rule-set rs1 rule r1 then source-nat interface",
		})
		r := sourceRule9877(t, cfg, "rs1", "r1")
		if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("UnknownMatchLeaves = %v, want %v (dedupe failed)", got, want)
		}
	})
	t.Run("second match block", func(t *testing.T) {
		cfgText := `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match {
                        source-address 10.0.0.0/8;
                    }
                    match {
                        soruce-address 192.168.0.0/16;
                    }
                    then {
                        source-nat interface;
                    }
                }
            }
        }
    }
}
`
		tree := mustParse(t, cfgText)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient: %v", err)
		}
		r := sourceRule9877(t, cfg, "rs1", "r1")
		if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("UnknownMatchLeaves = %v, want %v (second match block not recorded)", got, want)
		}
	})
}

// TestNATUnknownMatchLeavesGateDirect9877 units the validator against
// hand-built configs: the strict-via-set-lines path rejects at schema first,
// so this is what pins the gate's own verdict per direction.
func TestNATUnknownMatchLeavesGateDirect9877(t *testing.T) {
	marked := &NATRule{Name: "r1", UnknownMatchLeaves: []string{"soruce-address"}}
	marked.Match.SourceAddresses = []string{"10.0.0.0/8"}
	clean := &NATRule{Name: "r2"}
	clean.Match.SourceAddresses = []string{"10.0.0.0/8"}

	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{{Name: "rs1", Rules: []*NATRule{clean}}}
	if err := validateNATUnknownMatchLeavesStrict(cfg); err != nil {
		t.Fatalf("clean source rule rejected: %v", err)
	}
	cfg.Security.NAT.Source[0].Rules = []*NATRule{marked}
	if err := validateNATUnknownMatchLeavesStrict(cfg); err == nil {
		t.Fatal("marked source rule accepted")
	} else if !strings.Contains(err.Error(), "soruce-address") {
		t.Fatalf("source error %q must name the leaf", err)
	}

	cfg = &Config{}
	cfg.Security.NAT.Destination = &DestinationNATConfig{
		RuleSets: []*NATRuleSet{{Name: "rs1", Rules: []*NATRule{marked}}},
	}
	if err := validateNATUnknownMatchLeavesStrict(cfg); err == nil {
		t.Fatal("marked destination rule accepted")
	}

	cfg = &Config{}
	cfg.Security.NAT.Static = []*StaticNATRuleSet{{
		Name: "rs1",
		Rules: []*StaticNATRule{{
			Name: "r1", Match: "198.51.100.10",
			UnknownMatchLeaves: []string{"soruce-address"},
		}},
	}}
	if err := validateNATUnknownMatchLeavesStrict(cfg); err == nil {
		t.Fatal("marked static rule accepted")
	}

	if err := validateNATUnknownMatchLeavesStrict(nil); err != nil {
		t.Fatalf("nil config rejected: %v", err)
	}
	if err := validateNATUnknownMatchLeavesStrict(&Config{}); err != nil {
		t.Fatalf("empty config rejected: %v", err)
	}
}

// TestNATUnknownMatchLeavesExemptionMessage9877: exemptions install (keyable),
// so their warning must say the exemption installs widened — not the
// not-installed disposition.
func TestNATUnknownMatchLeavesExemptionMessage9877(t *testing.T) {
	cfg := lenientNAT9877(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat off",
	})
	r := sourceRule9877(t, cfg, "rs1", "r1")
	if !r.Then.Off {
		t.Fatal("premise broken: rule is not an exemption")
	}
	all := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(all, "soruce-address") || !strings.Contains(all, "exemption") {
		t.Fatalf("exemption warning %q must name the leaf and the exemption disposition", cfg.Warnings)
	}
	if strings.Contains(all, "not installed") {
		t.Fatalf("exemption warning %q claims not-installed, but keyable exemptions install", cfg.Warnings)
	}
	if reason := SourceNATRuleExcludedReason(r); reason != "" {
		t.Fatalf("exemption reports exclusion reason %q — exemptions install, never skip", reason)
	}
}

// TestNATUnknownMatchLeavesControls9877: clean shapes stay byte-quiet — no
// record, no #9877 warning.
func TestNATUnknownMatchLeavesControls9877(t *testing.T) {
	cfg := lenientNAT9877(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security applications application app-a protocol tcp",
		"set security applications application app-a destination-port 80",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule clean match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule clean match destination-port 443",
		"set security nat source rule-set rs1 rule clean match application app-a",
		"set security nat source rule-set rs1 rule clean then source-nat interface",
		"set security nat source rule-set rs1 rule catchall match source-address 0.0.0.0/0",
		"set security nat source rule-set rs1 rule catchall then source-nat interface",
		"set security nat source rule-set rs1 rule scopeless then source-nat interface",
	})
	for _, name := range []string{"clean", "catchall", "scopeless"} {
		if got := sourceRule9877(t, cfg, "rs1", name).UnknownMatchLeaves; len(got) != 0 {
			t.Fatalf("control rule %q recorded %v; want no record", name, got)
		}
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "unknown leaves") {
			t.Fatalf("control config raised a #9877 warning: %q (all warnings: %q)", w, cfg.Warnings)
		}
	}
}

// TestSourceNATRuleExcludedReason9877 pins the source predicate's truth table.
func TestSourceNATRuleExcludedReason9877(t *testing.T) {
	if got := SourceNATRuleExcludedReason(nil); got != "" {
		t.Fatalf("nil rule reports %q", got)
	}
	clean := &NATRule{Name: "clean"}
	clean.Match.SourceAddresses = []string{"10.0.0.0/8"}
	clean.Then.PoolName = "p1"
	if got := SourceNATRuleExcludedReason(clean); got != "" {
		t.Fatalf("clean pool rule reports %q", got)
	}
	clean.Then.PoolName = ""
	clean.Then.Interface = true
	if got := SourceNATRuleExcludedReason(clean); got != "" {
		t.Fatalf("clean interface rule reports %q", got)
	}
	marked := &NATRule{Name: "marked", UnknownMatchLeaves: []string{"soruce-address"}}
	marked.Match.SourceAddresses = []string{"10.0.0.0/8"}
	marked.Then.PoolName = "p1"
	if got := SourceNATRuleExcludedReason(marked); !strings.Contains(got, "soruce-address") {
		t.Fatalf("marked pool rule reports %q; must name the leaf", got)
	}
	marked.Then.PoolName = ""
	marked.Then.Interface = true
	if got := SourceNATRuleExcludedReason(marked); !strings.Contains(got, "soruce-address") {
		t.Fatalf("marked interface rule reports %q; must name the leaf", got)
	}
	marked.Then.Interface = false
	marked.Then.Off = true
	if got := SourceNATRuleExcludedReason(marked); got != "" {
		t.Fatalf("marked exemption reports %q; exemptions install, never skip", got)
	}
	// Disarm-wins (parent ruling): both markers → no exclusion; the #9874
	// tombstone ships instead.
	marked.Then.Off = false
	marked.Then.PoolName = "p1"
	marked.LenientMatchDropped = true
	if got := SourceNATRuleExcludedReason(marked); got != "" {
		t.Fatalf("both-markers rule reports %q; disarm must win over skip", got)
	}
}

// TestDestinationNATRuleExcludedReason9877 pins the destination predicate,
// including the unkeyable-exemption arm.
func TestDestinationNATRuleExcludedReason9877(t *testing.T) {
	dnat := &DestinationNATConfig{}
	if got := DestinationNATRuleExcludedReason(nil, &NATRule{}); got != "" {
		t.Fatalf("nil DNAT config reports %q", got)
	}
	if got := DestinationNATRuleExcludedReason(dnat, nil); got != "" {
		t.Fatalf("nil rule reports %q", got)
	}
	marked := &NATRule{Name: "marked", UnknownMatchLeaves: []string{"soruce-address"}}
	marked.Match.SourceAddresses = []string{"10.0.0.0/8"}
	marked.Match.DestinationAddresses = []string{"203.0.113.0/24"}
	marked.Then.PoolName = "p1"
	if got := DestinationNATRuleExcludedReason(dnat, marked); !strings.Contains(got, "soruce-address") {
		t.Fatalf("marked rule reports %q; must name the leaf", got)
	}
	// Keyable exemption (destination survives): installs.
	off := &NATRule{Name: "off", UnknownMatchLeaves: []string{"soruce-address"}}
	off.Match.SourceAddresses = []string{"10.0.0.0/8"}
	off.Match.DestinationAddresses = []string{"203.0.113.0/24"}
	off.Then.Type = NATDestination
	off.Then.Off = true
	if got := DestinationNATRuleExcludedReason(dnat, off); got != "" {
		t.Fatalf("keyable exemption reports %q; it installs", got)
	}
	// Unkeyable exemption (destination was the dropped dimension): reported.
	off.Match.DestinationAddresses = nil
	if got := DestinationNATRuleExcludedReason(dnat, off); !strings.Contains(got, "no destination key") {
		t.Fatalf("unkeyable exemption reports %q; must report the missing key", got)
	}
	// Pre-existing shape: unkeyable exemption with NO typo stays silent here
	// (that lie class is not this issue's).
	plain := &NATRule{Name: "plain"}
	plain.Match.SourceAddresses = []string{"10.0.0.0/8"}
	plain.Then.Type = NATDestination
	plain.Then.Off = true
	if got := DestinationNATRuleExcludedReason(dnat, plain); got != "" {
		t.Fatalf("unmarked keyless exemption reports %q; out of scope", got)
	}
}

// TestStaticNATRuleExcludedReason9877 pins the static predicate, including the
// NPTv6 unknown-leaf clause and the plain-only shielding below it.
func TestStaticNATRuleExcludedReason9877(t *testing.T) {
	if got := StaticNATRuleExcludedReason(nil); got != "" {
		t.Fatalf("nil rule reports %q", got)
	}
	clean := &StaticNATRule{Name: "clean", Match: "198.51.100.10"}
	if got := StaticNATRuleExcludedReason(clean); got != "" {
		t.Fatalf("clean rule reports %q", got)
	}
	marked := &StaticNATRule{Name: "marked", Match: "198.51.100.10", UnknownMatchLeaves: []string{"soruce-address"}}
	if got := StaticNATRuleExcludedReason(marked); !strings.Contains(got, "soruce-address") {
		t.Fatalf("marked rule reports %q; must name the leaf", got)
	}
	// NPTv6: unknown leaves disarm (the #5818-evasion hole); anything else
	// stays with NPTv6ScopeUnsupported.
	nptv6 := &StaticNATRule{Name: "nptv6", Match: "2001:db8:1::/48", IsNPTv6: true, UnknownMatchLeaves: []string{"soruce-address"}}
	if got := StaticNATRuleExcludedReason(nptv6); !strings.Contains(got, "soruce-address") {
		t.Fatalf("marked NPTv6 rule reports %q; must name the leaf", got)
	}
	scoped := &StaticNATRule{Name: "scoped", Match: "2001:db8:1::/48", IsNPTv6: true}
	scoped.SourceAddresses = []string{"2001:db8:9::/48"}
	if got := StaticNATRuleExcludedReason(scoped); got != "" {
		t.Fatalf("scoped NPTv6 rule reports %q here; scope stays with NPTv6ScopeUnsupported", got)
	}
	if !NPTv6ScopeUnsupported(&StaticNATRuleSet{Name: "rs"}, scoped) {
		t.Fatal("premise broken: the scoped NPTv6 rule must still trip NPTv6ScopeUnsupported")
	}
}

// TestSourceNATRuleNotInstalledReason9877 pins the shared composition: the
// rule verdict precedes the pool-mode gate (interface-mode skips annotate)
// and precedes the pool verdict (match cause reads first).
func TestSourceNATRuleNotInstalledReason9877(t *testing.T) {
	cfg := &Config{}
	iface := &NATRule{Name: "iface", UnknownMatchLeaves: []string{"soruce-address"}}
	iface.Match.SourceAddresses = []string{"10.0.0.0/8"}
	iface.Then.Interface = true
	if got := SourceNATRuleNotInstalledReason(cfg, iface); !strings.Contains(got, "soruce-address") {
		t.Fatalf("marked interface rule reports %q; must name the leaf", got)
	}
	cleanIface := &NATRule{Name: "clean"}
	cleanIface.Match.SourceAddresses = []string{"10.0.0.0/8"}
	cleanIface.Then.Interface = true
	if got := SourceNATRuleNotInstalledReason(cfg, cleanIface); got != "" {
		t.Fatalf("clean interface rule reports %q; must stay armed", got)
	}
	missing := &NATRule{Name: "missing", UnknownMatchLeaves: []string{"soruce-address"}}
	missing.Match.SourceAddresses = []string{"10.0.0.0/8"}
	missing.Then.PoolName = "no-such-pool"
	if got := SourceNATRuleNotInstalledReason(cfg, missing); !strings.Contains(got, "soruce-address") {
		t.Fatalf("marked rule with missing pool reports %q; match cause must win", got)
	}
	unmarked := &NATRule{Name: "unmarked"}
	unmarked.Match.SourceAddresses = []string{"10.0.0.0/8"}
	unmarked.Then.PoolName = "no-such-pool"
	if got := SourceNATRuleNotInstalledReason(cfg, unmarked); got != "missing_pool" {
		t.Fatalf("unmarked rule with missing pool reports %q; want missing_pool (#8329 preserved)", got)
	}
	// Both markers on interface mode: no NOT INSTALLED reason — the tombstone
	// ships and the ADMITTED note (natshow's branch) carries the verdict.
	tombstoned := &NATRule{Name: "tombstoned", UnknownMatchLeaves: []string{"soruce-address"}, LenientMatchDropped: true}
	tombstoned.Then.Interface = true
	if got := SourceNATRuleNotInstalledReason(cfg, tombstoned); got != "" {
		t.Fatalf("both-markers interface rule reports %q; want no NOT INSTALLED verdict", got)
	}
	// The rule verdict is Go-side prose; the token expander must echo it
	// verbatim so the text surfaces print it as-is.
	prose := SourceNATRuleNotInstalledReason(cfg, iface)
	if got := SourceNATDisarmReasonText(prose); got != prose {
		t.Fatalf("prose reason %q did not echo verbatim (got %q); interface-mode skips would render empty", prose, got)
	}
}

// TestNATUnknownMatchLeavesWalkExcludesSkipped9877 pins the #6812 walk
// placement: a dropped rule's pool charges only via a surviving reference,
// and the skip lands BEFORE the seen-marking.
func TestNATUnknownMatchLeavesWalkExcludesSkipped9877(t *testing.T) {
	cfg := lenientNAT9877(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool shared address 198.51.100.1/32",
		"set security nat source pool dropped-only address 198.51.100.2/32",
		"set security nat source pool tombstoned address 198.51.100.3/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat pool shared",
		"set security nat source rule-set rs1 rule r2 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r2 then source-nat pool shared",
		"set security nat source rule-set rs1 rule r3 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r3 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r3 then source-nat pool dropped-only",
		"set security nat source rule-set rs1 rule r4 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r4 then source-nat pool tombstoned",
	})
	if got := sourceRule9877(t, cfg, "rs1", "r1").UnknownMatchLeaves; len(got) == 0 {
		t.Fatal("premise broken: r1 carries no unknown-leaf record")
	}
	charges := sourceNATAggregateReferencedCharges(cfg)
	names := make([]string, len(charges))
	for i, c := range charges {
		names[i] = c.name
	}
	// shared is referenced by dropped r1 AND healthy r2: r1 must not mark it
	// seen-without-charge, or r2's reference charges nothing (under-charge).
	found := 0
	for _, n := range names {
		if n == "shared" {
			found++
		}
		if n == "dropped-only" {
			t.Fatalf("pool %q is referenced only by a dropped rule but was charged %v", n, names)
		}
		if n == "tombstoned" {
			t.Fatalf("pool %q is referenced only by a tombstoned rule but was charged %v", n, names)
		}
	}
	if found != 1 {
		t.Fatalf("pool %q charged %d times, want once (charges: %v)", "shared", found, names)
	}
}

// TestNATUnknownMatchLeavesBothMarkersSingleWarning9874_9877 pins the overlap
// contract with #9874 (second-lander cell): a typo-only match is BOTH
// unknown-leaf (#9877) and unconstrained (#9874). Both markers set; exactly
// one warning, naming the typo (the #9877 gate runs first, #8430 suppressed;
// the #9874 setter is gate-independent so its marker still sets).
func TestNATUnknownMatchLeavesBothMarkersSingleWarning9874_9877(t *testing.T) {
	cfg := lenientNAT9877(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	})
	r := sourceRule9877(t, cfg, "rs1", "r1")
	if !r.LenientMatchDropped {
		t.Fatal("premise broken: typo-only rule lacks the #9874 marker")
	}
	if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
	}
	if len(cfg.Warnings) != 1 {
		t.Fatalf("want exactly one warning, got %d: %q", len(cfg.Warnings), cfg.Warnings)
	}
	if w := cfg.Warnings[0]; !strings.Contains(w, "soruce-address") || !strings.Contains(w, "#9877") {
		t.Fatalf("single warning %q must be the #9877 typo diagnosis", w)
	}
	// Disarm-wins disposition: the rule ships as a drop tombstone, so the
	// warning must report the drop — never "not installed".
	if w := cfg.Warnings[0]; !strings.Contains(w, "fail-closed drop") || strings.Contains(w, "not installed") {
		t.Fatalf("both-markers warning %q must report the drop disposition", w)
	}
}

// TestNATMatchLeafKnown9877 units the schema-backed compact check: exactly the
// modeled leaves per direction (the same map the normalizer consults), with
// DNAT-only `protocol` correctly unknown under source.
func TestNATMatchLeafKnown9877(t *testing.T) {
	for _, tc := range []struct {
		dir, head string
		want      bool
	}{
		{"source", "source-address", true},
		{"source", "destination-port", true},
		{"source", "application", true},
		{"source", "soruce-address", false},
		{"source", "protocol", false},
		{"destination", "protocol", true},
		{"destination", "source-address", true},
		{"destination", "soruce-address", false},
		{"static", "destination-address", true},
		{"static", "destination-port", true},
		{"static", "application", false},
		{"static", "soruce-address", false},
		{"bogus-direction", "source-address", false},
		{"source", "", false},
	} {
		if got := natMatchLeafKnown(tc.dir, tc.head); got != tc.want {
			t.Errorf("natMatchLeafKnown(%q, %q) = %v, want %v", tc.dir, tc.head, got, tc.want)
		}
	}
}

// compactVsBraced9877 compiles the same rule twice — once with the typo in
// brace-elided (compact) form beside a surviving valid braced block, once
// fully braced — and requires identical record, warning and verdict.
func compactVsBraced9877(t *testing.T, compactText, bracedText string, check func(t *testing.T, cfg *Config)) {
	t.Helper()
	compactTree := mustParse(t, compactText)
	compactCfg, err := CompileConfigLenient(compactTree)
	if err != nil {
		t.Fatalf("compact CompileConfigLenient: %v", err)
	}
	bracedTree := mustParse(t, bracedText)
	bracedCfg, err := CompileConfigLenient(bracedTree)
	if err != nil {
		t.Fatalf("braced CompileConfigLenient: %v", err)
	}
	if a, b := compactCfg.Warnings, bracedCfg.Warnings; !reflect.DeepEqual(a, b) {
		t.Fatalf("warnings diverge:\ncompact: %q\nbraced:  %q", a, b)
	}
	check(t, compactCfg)
	check(t, bracedCfg)
}

// TestNATUnknownMatchCompactSpellingEquivalence9877: a compact typo beside a
// surviving valid block records, warns and verdicts exactly like the braced
// spelling. Before the compact capture this compiled silent and constrained.
func TestNATUnknownMatchCompactSpellingEquivalence9877(t *testing.T) {
	zones := `
    zones {
        security-zone trust;
        security-zone untrust;
    }`
	t.Run("source", func(t *testing.T) {
		rule := func(match string) string {
			return `security {` + zones + `
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    ` + match + `
                    then { source-nat interface; }
                }
            }
        }
    }
}`
		}
		compactVsBraced9877(t,
			rule("match { source-address 10.0.0.0/8; } match soruce-address 192.168.0.0/16;"),
			rule("match { source-address 10.0.0.0/8; soruce-address 192.168.0.0/16; }"),
			func(t *testing.T, cfg *Config) {
				r := sourceRule9877(t, cfg, "rs1", "r1")
				if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
					t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
				}
				if got := SourceNATRuleExcludedReason(r); !strings.Contains(got, "soruce-address") {
					t.Fatalf("exclusion reason %q must name the leaf", got)
				}
			})
	})
	t.Run("destination", func(t *testing.T) {
		rule := func(match string) string {
			return `security {` + zones + `
    nat {
        destination {
            pool p1 { address 192.0.2.5; }
            rule-set rs1 {
                from zone trust;
                rule r1 {
                    ` + match + `
                    then { destination-nat pool p1; }
                }
            }
        }
    }
}`
		}
		compactVsBraced9877(t,
			rule("match { destination-address 203.0.113.0/24; } match soruce-address 10.0.0.0/8;"),
			rule("match { destination-address 203.0.113.0/24; soruce-address 10.0.0.0/8; }"),
			func(t *testing.T, cfg *Config) {
				rules := cfg.Security.NAT.Destination.RuleSets[0].Rules
				if len(rules) != 1 {
					t.Fatalf("want 1 rule, got %d", len(rules))
				}
				if got, want := rules[0].UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
					t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
				}
				if got := DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, rules[0]); !strings.Contains(got, "soruce-address") {
					t.Fatalf("exclusion reason %q must name the leaf", got)
				}
			})
	})
	t.Run("static", func(t *testing.T) {
		rule := func(match string) string {
			return `security {` + zones + `
    nat {
        static {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    ` + match + `
                    then { static-nat prefix 10.0.0.5/32; }
                }
            }
        }
    }
}`
		}
		compactVsBraced9877(t,
			rule("match { destination-address 198.51.100.10/32; } match soruce-address 10.0.0.0/8;"),
			rule("match { destination-address 198.51.100.10/32; soruce-address 10.0.0.0/8; }"),
			func(t *testing.T, cfg *Config) {
				r := cfg.Security.NAT.Static[0].Rules[0]
				if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
					t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
				}
				if got := StaticNATRuleExcludedReason(r); !strings.Contains(got, "soruce-address") {
					t.Fatalf("exclusion reason %q must name the leaf", got)
				}
			})
	})
}

// TestNATUnknownMatchCompactTypoOnly9877: a compact typo-only match records
// like the braced spelling — both markers, one precise warning (not the
// generic #8430 text it drew before the capture).
func TestNATUnknownMatchCompactTypoOnly9877(t *testing.T) {
	cfgText := `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match soruce-address 192.168.0.0/16;
                    then { source-nat interface; }
                }
            }
        }
    }
}
`
	tree := mustParse(t, cfgText)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	r := sourceRule9877(t, cfg, "rs1", "r1")
	if !r.LenientMatchDropped {
		t.Fatal("premise broken: compact typo-only rule lacks the #9874 marker")
	}
	if got, want := r.UnknownMatchLeaves, []string{"soruce-address"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownMatchLeaves = %v, want %v", got, want)
	}
	if len(cfg.Warnings) != 1 {
		t.Fatalf("want exactly one warning, got %d: %q", len(cfg.Warnings), cfg.Warnings)
	}
	if w := cfg.Warnings[0]; !strings.Contains(w, "soruce-address") || !strings.Contains(w, "#9877") {
		t.Fatalf("single warning %q must be the #9877 typo diagnosis", w)
	}
}

// TestNATUnknownMatchLenientEnumerates9877: two marked rules with DISTINCT
// dropped keywords warn once EACH on the tolerant path (a first-error-only
// gate would leave the second — here a widened exemption — silent), while
// strict keeps the first error.
func TestNATUnknownMatchLenientEnumerates9877(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
		"set security nat source rule-set rs1 rule r2 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r2 match destination-addres 203.0.113.0/24",
		"set security nat source rule-set rs1 rule r2 then source-nat off",
	}
	cfg := lenientNAT9877(t, lines)
	if len(cfg.Warnings) != 2 {
		t.Fatalf("want one warning per marked rule (2), got %d: %q", len(cfg.Warnings), cfg.Warnings)
	}
	all := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(all, "soruce-address") || !strings.Contains(all, "destination-addres") {
		t.Fatalf("warnings %q must name BOTH dropped keywords", cfg.Warnings)
	}
	if !strings.Contains(all, "exemption") {
		t.Fatalf("warnings %q must flag the widened exemption r2", cfg.Warnings)
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("strict CompileConfig accepted marked rules; want first-error rejection")
	} else if !strings.Contains(err.Error(), "soruce-address") || strings.Contains(err.Error(), "destination-addres") {
		t.Fatalf("strict error %q must be the FIRST offender only", err)
	}
}

// TestNATUnknownMatchLenientDedupesExpansions9877: scope expansion shares rule
// pointers across expanded rule-sets — one authored rule warns once, not once
// per expansion.
func TestNATUnknownMatchLenientDedupesExpansions9877(t *testing.T) {
	cfg := lenientNAT9877(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone dmz",
		"set security zones security-zone untrust",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 from zone dmz",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match soruce-address 192.168.0.0/16",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	})
	if n := len(cfg.Security.NAT.Source); n != 2 {
		t.Fatalf("premise broken: want 2 expanded rule-sets, got %d", n)
	}
	if cfg.Security.NAT.Source[0].Rules[0] != cfg.Security.NAT.Source[1].Rules[0] {
		t.Fatal("premise broken: expansions do not share the rule pointer")
	}
	named := 0
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "soruce-address") {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("want exactly one warning for the shared rule, got %d: %q", named, cfg.Warnings)
	}
}

// TestNATUnknownMatchDestOffUnkeyableMessage9877: a destination exemption whose
// destination key was dropped does NOT install — the warning must report the
// unkeyable disposition, never the installs-widened text.
func TestNATUnknownMatchDestOffUnkeyableMessage9877(t *testing.T) {
	cfg := lenientNAT9877(t, []string{
		"set security zones security-zone trust",
		"set security nat destination pool p1 address 192.0.2.5",
		"set security nat destination rule-set rs1 from zone trust",
		"set security nat destination rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat destination rule-set rs1 rule r1 match destination-addres 203.0.113.0/24",
		"set security nat destination rule-set rs1 rule r1 then destination-nat off",
	})
	all := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(all, "destination-addres") || !strings.Contains(all, "cannot be keyed") {
		t.Fatalf("unkeyable-exemption warning %q must name the leaf and the missing key", cfg.Warnings)
	}
	if strings.Contains(all, "installs matching only") {
		t.Fatalf("unkeyable-exemption warning %q claims it installs", cfg.Warnings)
	}
}
