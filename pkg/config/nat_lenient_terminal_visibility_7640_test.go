package config

// nat_lenient_terminal_visibility_7640_test.go — #7640.
//
// The strict terminal-action cardinality gate (#5628) rejects a NAT rule whose
// `then` carries anything other than exactly one translation action. The
// tolerant load / peer-sync / rollback path downgrades that to a cfg.Warnings
// entry (#1960 no-brick) — correctly, since the alternative is a brick.
//
// But cfg.Warnings reaches an operator only through the commit RESPONSE
// (pkg/api, pkg/grpcapi) and an apply-time log line (pkg/daemon), and a
// tolerant LOAD has no commit response. Boot, peer-sync and rollback are
// exactly the paths on which such a rule survives, so the node then runs
// indefinitely carrying a rule a commit would refuse, with no live signal.
//
// These cells bind the record the gauge and the operator annotation read.

import (
	"strings"
	"testing"
)

// actionlessSourceRuleSet builds a rule-set whose rule carries NO terminal
// action — the shape a pre-#5628 config can still carry through a tolerant
// load.
func actionlessSourceRuleSet7640(rsName, ruleName string) *NATRuleSet {
	return &NATRuleSet{
		Name:  rsName,
		Rules: []*NATRule{{Name: ruleName}}, // Then zero-valued: no action at all
	}
}

// TestLenientPathRecordsTheAdmittedRule7640 is the core: a rule the strict gate
// rejects, admitted by the tolerant path, must leave a durable record on the
// compiled config — not only a warning string.
//
// FAIL-ON-REVERT: drop the LenientNATTerminalActionRules assignment in
// compiler_uniformgates_firewall_nat2.go and the record is empty while the
// warning still fires, which is precisely the pre-#7640 invisibility.
func TestLenientPathRecordsTheAdmittedRule7640(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{actionlessSourceRuleSet7640("rs1", "actionless")}

	opts := compileOpts{lenientNATTerminalAction: true}
	if err := runUniformGatesFirewallNAT2(nil, cfg, opts); err != nil {
		t.Fatalf("the tolerant path must not reject: %v", err)
	}

	// Precondition: the warning fired, so this cell is about the RECORD being
	// missing rather than about the gate not firing at all.
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "NAT terminal-action cardinality") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the tolerant path did not warn, so the fixture never reached "+
			"the downgrade this cell is about: %v", cfg.Warnings)
	}

	if len(cfg.LenientNATTerminalActionRules) != 1 {
		t.Fatalf("LenientNATTerminalActionRules = %v, want exactly the one "+
			"admitted rule — without the record the surviving rule is invisible "+
			"to the gauge and to `show ... rule detail`, and a tolerant load has "+
			"no commit response to carry the warning (#7640)",
			cfg.LenientNATTerminalActionRules)
	}
	got := cfg.LenientNATTerminalActionRules[0]
	if got.Reason != LenientNATTerminalActionReasonActionless ||
		got.Kind != "source" || got.RuleSet != "rs1" || got.Rule != "actionless" || got.Actions != 0 {
		t.Fatalf("recorded rule = %+v, want actionless {source rs1 actionless 0} — the "+
			"identity must be enough to find the stanza", got)
	}
	if s := got.String(); !strings.Contains(s, "rs1") || !strings.Contains(s, "actionless") {
		t.Fatalf("String() = %q, must name the rule-set and rule", s)
	}
}

// TestStrictPathRecordsNothing7640 is the PAIRED control. The record means
// "admitted leniently"; on the strict path the config is REJECTED, so a
// recorded rule there would make the gauge report a violation on a node that
// refused to run one.
func TestStrictPathRecordsNothing7640(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{actionlessSourceRuleSet7640("rs1", "actionless")}

	if err := runUniformGatesFirewallNAT2(nil, cfg, compileOpts{}); err == nil {
		t.Fatal("the strict path must REJECT an actionless rule (#5628)")
	}
	if len(cfg.LenientNATTerminalActionRules) != 0 {
		t.Fatalf("the strict path recorded %v — the record must mean "+
			"'admitted leniently', and a rejected config admitted nothing",
			cfg.LenientNATTerminalActionRules)
	}
}

// TestHealthyConfigRecordsNothing7640 is the other half of the pairing: a
// well-formed rule must leave the record empty, or the gauge reports a
// violation on every node and the alert is worthless.
func TestHealthyConfigRecordsNothing7640(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{{
		Name:  "rs1",
		Rules: []*NATRule{{Name: "ok", Then: NATThen{Interface: true}}},
	}}
	if err := runUniformGatesFirewallNAT2(nil, cfg, compileOpts{lenientNATTerminalAction: true}); err != nil {
		t.Fatalf("a well-formed rule must compile: %v", err)
	}
	if len(cfg.LenientNATTerminalActionRules) != 0 {
		t.Fatalf("a healthy config recorded %v", cfg.LenientNATTerminalActionRules)
	}
}

// TestLenientNATOffendersMatchTheGate_7640 binds the strict error, tolerant
// record, and enumerator projection on real compiled configs. A hand-built
// NATRule cannot carry thenAuthored, so such a fixture cannot exercise #7013's
// duplicate-pool finding.
//
// FAIL-ON-REVERT: dropping duplicate-pool findings from the tolerant projection
// leaves the strict gate red but makes the compiled duplicate-pool row vanish
// from LenientNATTerminalActionRules.
func TestLenientNATOffendersMatchTheGate_7640(t *testing.T) {
	duplicatePools := `security {
  zones { security-zone untrust; }
  nat { destination {
    pool PD { address 10.0.0.5; }
    pool PD2 { address 10.0.0.6; }
    rule-set RD { from zone untrust;
      rule R1 {
        match { destination-address 203.0.113.10/32; }
        then { destination-nat { pool PD; pool PD2; } }
      }
    }
  } }
}`
	for _, tc := range []struct {
		name    string
		text    string
		reason  LenientNATTerminalActionReason
		actions int
	}{
		{"actionless", snat7033(""), LenientNATTerminalActionReasonActionless, 0},
		{"interface-only", snat7033("then { source-nat interface; }"), "", 0},
		{"resolved-multi-action", snat7033("then { source-nat { interface; pool P; } }"), LenientNATTerminalActionReasonMultiAction, 2},
		{"packed-contradiction", snat7033("then { source-nat pool P off; }"), LenientNATTerminalActionReasonPackedContradiction, 2},
		{"duplicate-pools", duplicatePools, LenientNATTerminalActionReasonDuplicatePools, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, parseErr := NewParser(tc.text).Parse()
			if len(parseErr) != 0 {
				t.Fatalf("fixture did not parse: %v", parseErr)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile failed: %v", err)
			}

			var cardinalityWarnings int
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "NAT terminal-action cardinality") {
					cardinalityWarnings++
				}
			}
			gateErr := validateNATTerminalActionCardinalityStrict(cfg)
			wantOffender := tc.reason != ""
			if (gateErr != nil) != wantOffender {
				t.Fatalf("strict gate rejects = %v, want %v (err=%v)", gateErr != nil, wantOffender, gateErr)
			}
			wantWarnings := 0
			if wantOffender {
				wantWarnings = 1
			}
			if cardinalityWarnings != wantWarnings {
				t.Fatalf("cardinality warnings = %d, want %d: %v", cardinalityWarnings, wantWarnings, cfg.Warnings)
			}

			enumerated := natTerminalActionCardinalityOffenders(cfg)
			if len(enumerated) != wantWarnings {
				t.Fatalf("enumerator found %d records, want %d: %v", len(enumerated), wantWarnings, enumerated)
			}
			if len(cfg.LenientNATTerminalActionRules) != wantWarnings {
				t.Fatalf("compiled LenientNATTerminalActionRules = %v, want %d records",
					cfg.LenientNATTerminalActionRules, wantWarnings)
			}
			if wantOffender {
				got := cfg.LenientNATTerminalActionRules[0]
				if got.Reason != tc.reason || got.Actions != tc.actions {
					t.Fatalf("compiled finding = %+v, want reason %q and count %d", got, tc.reason, tc.actions)
				}
				if enumerated[0] != got {
					t.Fatalf("compiled record %+v differs from enumerator projection %+v", got, enumerated[0])
				}
				if got.Reason == LenientNATTerminalActionReasonPackedContradiction {
					resolvedActions := natThenTerminalActionCount(cfg.Security.NAT.Source[0].Rules[0].Then)
					if got.Actions != 2 || resolvedActions != 1 {
						t.Fatalf("packed record has %d authored modes but resolves to %d actions; want 2 and 1",
							got.Actions, resolvedActions)
					}
				}
			}
		})
	}
}

// TestOffendersCoverBothKinds7640 pins that destination NAT is walked too. The
// gate checks both kinds; an enumerator that walked only source would report a
// healthy node for a config whose destination rules a commit would refuse.
func TestOffendersCoverBothKinds7640(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Source = []*NATRuleSet{actionlessSourceRuleSet7640("srs", "s-actionless")}
	cfg.Security.NAT.Destination = &DestinationNATConfig{
		RuleSets: []*NATRuleSet{actionlessSourceRuleSet7640("drs", "d-actionless")},
	}
	got := natTerminalActionCardinalityOffenders(cfg)
	if len(got) != 2 {
		t.Fatalf("offenders = %v, want one source and one destination", got)
	}
	kinds := map[string]bool{}
	for _, r := range got {
		kinds[r.Kind] = true
	}
	if !kinds["source"] || !kinds["destination"] {
		t.Fatalf("offenders cover only %v; the gate checks BOTH kinds", kinds)
	}
}
