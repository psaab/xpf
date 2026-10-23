package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6673 / #6659: static-NAT `match destination-address` selection must stay
// LAST-SIBLING-WINS on the tolerant load path.
//
// #6659 widened this leaf to read every value (`MatchAddresses`) so a malformed
// prefix in any slot but the first could no longer escape validation. In doing
// so it also changed which value lands in the scalar `rule.Match` — from
// `nodeVal(m)` assigned once per sibling child (LAST wins) to
// `MatchAddresses[0]` (FIRST wins).
//
// That is invisible for the BRACKET form (`[ a b ]`), which is one node with its
// values on Keys[1:]/Children, so the two selections agree — and every test the
// widening shipped with used the bracket form, which is why all of them stayed
// green. The REPEATED-`set` form produces two sibling `destination-address`
// nodes and is the shape that flipped. It had no coverage at all.
//
// The consequence is not cosmetic. `rule.Match` lowers to
// StaticNATRuleSnapshot.ExternalIP, so the published service on the last-authored
// address silently stops being translated, while an address that was never a NAT
// target starts DNAT'ing inbound traffic to the internal host. The strict commit
// gate does not save the tolerant path: this is the restart / peer-sync route for
// an ALREADY-PERSISTED config, and `tree.Format()` renders both sibling lines
// verbatim, so the divergence survives a persistence round trip.
//
// Fail-on-revert: replace `rule.Match = nodeVal(m)` in compiler_nat_static.go
// with `rule.Match = rule.MatchAddresses[0]` and ExternalIP below flips from
// 198.51.100.1/32 to 192.0.2.1/32.
func repeatedMatchTree6673(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		// #16008: define the from-zone, else the tolerant undefined-zone
		// record drops this rule-set before selection is observable.
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		// The shape with no coverage: two sibling destination-address nodes,
		// NOT a bracket list.
		"set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32",
		"set security nat static rule-set rs1 rule r1 match destination-address 198.51.100.1/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func TestStaticNATRepeatedMatchKeepsLastSibling6673(t *testing.T) {
	tree := repeatedMatchTree6673(t)

	// The TOLERANT path — restart / peer-sync of an already-persisted config.
	// Strict commit is not what runs here, so its multi-value rejection cannot
	// mask a wrong selection.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}

	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("expected exactly 1 static-NAT snapshot, got %d: %+v", len(snaps), snaps)
	}
	const wantExternal = "198.51.100.1/32"
	if snaps[0].ExternalIP != wantExternal {
		t.Fatalf("ExternalIP = %q, want %q.\n"+
			"Static-NAT destination-address selection is LAST-SIBLING-WINS; taking MatchAddresses[0] "+
			"picks the FIRST instead, so the published service on %s silently stops being translated "+
			"and %s — never a NAT target — starts DNAT'ing to the internal host.",
			snaps[0].ExternalIP, wantExternal, wantExternal, snaps[0].ExternalIP)
	}

	// The widening this PR exists for must still hold: BOTH prefixes are read,
	// so neither escapes validation.
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if len(rule.MatchAddresses) != 2 {
		t.Fatalf("MatchAddresses = %v, want both prefixes read (the #6659 widening)", rule.MatchAddresses)
	}
}

// The divergence must not be an artefact of one in-memory parse: it has to
// survive the persistence round trip, because the tolerant path is reached by
// re-loading a formatted config.
func TestStaticNATRepeatedMatchSurvivesFormatRoundTrip6673(t *testing.T) {
	formatted := repeatedMatchTree6673(t).Format()
	if !strings.Contains(formatted, "192.0.2.1/32") || !strings.Contains(formatted, "198.51.100.1/32") {
		t.Fatalf("Format() dropped a sibling destination-address; both must round-trip:\n%s", formatted)
	}

	// Re-parse the rendered config exactly as a restart would.
	//
	// #6673 round 9: this must reparse the SAME rendering persistence writes.
	// configstore's writeActive does `data := s.active.Format()`
	// (pkg/configstore/store_persist.go:784, and :941 for the boot snapshot), so
	// the on-disk artefact is Format() output and the restart path re-parses it
	// with the hierarchical parser. Rendering with Format() and then reparsing
	// FormatSet() through ParseSetCommand exercised a DIFFERENT round trip from
	// the one the comment above claims — and flat-set reparsing is precisely the
	// route that cannot reproduce this bug's shape, because SetPath merges the
	// two statements differently.
	reparsed, perrs := config.NewParser(formatted).Parse()
	if len(perrs) != 0 {
		t.Fatalf("re-parsing the persisted Format() rendering failed: %v\n%s", perrs, formatted)
	}
	cfg, err := config.CompileConfigLenient(reparsed)
	if err != nil {
		t.Fatalf("CompileConfigLenient after round trip: %v", err)
	}
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot after the round trip, got %d: %+v", len(snaps), snaps)
	}
	if snaps[0].ExternalIP != "198.51.100.1/32" {
		t.Fatalf("ExternalIP after a persistence round trip = %q, want 198.51.100.1/32", snaps[0].ExternalIP)
	}
}
