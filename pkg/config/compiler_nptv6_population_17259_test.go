package config

import (
	"strings"
	"testing"
)

func nptv6RuleSet17259(name, zone string, rules ...*StaticNATRule) *StaticNATRuleSet {
	return &StaticNATRuleSet{Name: name, FromZone: zone, Rules: rules}
}

func nptv6Rule17259(name, match, then string) *StaticNATRule {
	return &StaticNATRule{Name: name, IsNPTv6: true, Match: match, Then: then}
}

// The single population distinguishes NPTv6 membership from installability:
// malformed rules still reach compile-time validation, while excluded/scoped/
// undefined-zone entries cannot reach the helper.
func TestNPTv6RulesCentralizeMembership17259(t *testing.T) {
	plain := &StaticNATRule{Name: "plain", Match: "2001:db8:1::/48", Then: "fd00:1::/48"}
	installed := nptv6Rule17259("installed", "2001:db8:2::/48", "fd00:2::/48")
	scoped := nptv6Rule17259("scoped", "2001:db8:3::/48", "fd00:3::/48")
	scoped.SourceAddresses = []string{"2001:db8:90::/48"}
	excluded := nptv6Rule17259("excluded", "2001:db8:4::/48", "fd00:4::/48")
	excluded.UnknownMatchLeaves = []string{"soruce-address"}
	dropped := nptv6Rule17259("dropped", "2001:db8:5::/48", "fd00:5::/48")
	malformed := nptv6Rule17259("malformed", "::/0", "fd00::/0")

	cfg := &Config{}
	cfg.Security.NAT.Static = []*StaticNATRuleSet{
		nptv6RuleSet17259("plain", "untrust", plain),
		nptv6RuleSet17259("installed", "untrust", installed),
		nptv6RuleSet17259("scoped", "untrust", scoped),
		nptv6RuleSet17259("excluded", "untrust", excluded),
		nptv6RuleSet17259("dropped", "untrust", dropped),
		nptv6RuleSet17259("malformed", "untrust", malformed),
	}
	cfg.LenientNATUndefinedZoneRuleSets = map[NATRuleSetRef]bool{
		{Kind: "static", Name: "dropped"}: true,
	}

	got := NPTv6Rules(cfg)
	if len(got) != 5 {
		t.Fatalf("NPTv6 population has %d rows, want 5 (ordinary static NAT excluded): %+v", len(got), got)
	}
	wantNames := []string{"installed", "scoped", "excluded", "dropped", "malformed"}
	wantInstalled := []bool{true, false, false, false, true}
	for i, member := range got {
		if member.RuleSet.Name != wantNames[i] || member.Index != i {
			t.Errorf("row %d identity/index = %q/%d, want %q/%d", i, member.RuleSet.Name, member.Index, wantNames[i], i)
		}
		if member.Installed != wantInstalled[i] {
			t.Errorf("row %q installed=%v, want %v", member.Rule.Name, member.Installed, wantInstalled[i])
		}
	}
	if !got[1].ScopeUnsupported || got[2].ExcludedReason == "" || !got[3].UndefinedZone {
		t.Fatalf("membership dispositions missing: scoped=%+v excluded=%+v dropped=%+v", got[1], got[2], got[3])
	}
}

// RED-before at 99cb6b34ec: the lenient strict validator included a tolerated
// undefined-zone set in its overlap lists, while the builder/pre-pass dropped
// the entire set. Both must now derive overlap membership from NPTv6Rules.
func TestNPTv6DroppedUndefinedZoneDoesNotWarnOverlap17259(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Static = []*StaticNATRuleSet{
		nptv6RuleSet17259("dropped", "untrust", nptv6Rule17259("d", "2001:db8:1::/48", "fd00:1::/48")),
		nptv6RuleSet17259("healthy", "untrust", nptv6Rule17259("h", "2001:db8:1::/48", "fd00:2::/48")),
	}
	cfg.LenientNATUndefinedZoneRuleSets = map[NATRuleSetRef]bool{
		{Kind: "static", Name: "dropped"}: true,
	}
	warnings, err := validateNPTv6Strict(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "overlaps rule-set") {
			t.Fatalf("dropped rule-set caused a false overlap warning: %q", warning)
		}
	}
	if conflict := NPTv6OverlapConflict(cfg); conflict != "" {
		t.Fatalf("dropped rule-set caused a helper overlap conflict: %q", conflict)
	}
	if prefixes := nptv6ExternalPrefixes(cfg); len(prefixes) != 1 || prefixes[0].ruleSet != "healthy" {
		t.Fatalf("external-prefix population = %+v, want only healthy rule", prefixes)
	}
}

// RED-before at 99cb6b34ec: strict's same-(rule-set,rule) self-skip accepted
// duplicate snapshots while the helper rejected their identical prefixes.
// The builder emits each population row, so exact duplicate rows fail closed.
func TestNPTv6DuplicateIdentityMatchesHelper17259(t *testing.T) {
	rule := nptv6Rule17259("r1", "2001:db8:2::/48", "fd00:2::/48")
	cfg := &Config{}
	cfg.Security.NAT.Static = []*StaticNATRuleSet{
		nptv6RuleSet17259("rs", "untrust", rule, rule),
	}
	_, strictErr := validateNPTv6Strict(cfg, false)
	conflict := NPTv6OverlapConflict(cfg)
	if strictErr == nil || conflict == "" {
		t.Fatalf("duplicate helper entries must be rejected by strict and pre-pass: strict=%v conflict=%q", strictErr, conflict)
	}
	if !strings.Contains(strictErr.Error(), `rule-set "rs" rule "r1"`) || !strings.Contains(conflict, `rule-set "rs" rule "r1"`) {
		t.Fatalf("diagnostics must retain same-identity context: strict=%v conflict=%q", strictErr, conflict)
	}
}

func TestNPTv6OverlapWordBoundaries17259(t *testing.T) {
	cases := []struct {
		name       string
		first      string
		second     string
		firstThen  string
		secondThen string
		conflict   bool
	}{
		{"nested /64 at /48 boundary", "2001:db8:1::/48", "2001:db8:1:ffff::/64", "fd00:1::/48", "fd00:2::/64", true},
		{"adjacent /64s", "2001:db8:1:0::/64", "2001:db8:1:1::/64", "fd00:1::/64", "fd00:2::/64", false},
		{"adjacent /48s", "2001:db8:1::/48", "2001:db8:2::/48", "fd00:1::/48", "fd00:2::/48", false},
		{"zero prefix rejected", "::/0", "::/0", "fd00::/0", "fd01::/0", false},
		{"non-word /63 rejected", "2001:db8:1::/63", "2001:db8:1::/63", "fd00:1::/63", "fd00:2::/63", false},
		{"non-word /65 rejected", "2001:db8:1::/65", "2001:db8:1::/65", "fd00:1::/65", "fd00:2::/65", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Security.NAT.Static = []*StaticNATRuleSet{
				nptv6RuleSet17259("a", "untrust", nptv6Rule17259("a", tc.first, tc.firstThen)),
				nptv6RuleSet17259("b", "untrust", nptv6Rule17259("b", tc.second, tc.secondThen)),
			}
			findings := NPTv6OverlapFindings(NPTv6Rules(cfg))
			if got := len(findings) != 0; got != tc.conflict {
				t.Fatalf("overlap findings=%+v, conflict=%v; want %v", findings, got, tc.conflict)
			}
		})
	}
}

func TestNPTv6ExternalPoolPopulationExcludesHostBits17259(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Static = []*StaticNATRuleSet{
		nptv6RuleSet17259("host-bits", "untrust", nptv6Rule17259("bad", "2001:db8:1:2::/48", "fd00:1::/48")),
	}
	if got := nptv6ExternalPrefixes(cfg); len(got) != 0 {
		t.Fatalf("helper-rejected host-bit prefix entered pool-overlap population: %+v", got)
	}
}
