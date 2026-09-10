package config

import (
	"strings"
	"testing"
)

// #9571 — the tolerant #8752 duplicate-policy fold must never turn a statement's
// deny into a permit.
//
// Channel: CompileConfigLenient and CompileConfigForNodeLenient, the compile
// Store.Load, Store.SyncApply and upgrade use. Strict CompileConfig rejects every
// duplicate below (#3473) and is asserted unchanged. The fixtures are
// hierarchical text through NewParser on purpose: a flat `set` merges at SetPath
// and never reaches the fold.

const zones9571 = `zones { security-zone trust; security-zone untrust; }`
const anyMatch9571 = `match { source-address any; destination-address any; application any; }`

func zonePairText9571(body string) string {
	return `security { ` + zones9571 + ` policies { from-zone trust to-zone untrust { ` + body + ` } } }`
}

func globalText9571(body string) string {
	return `security { ` + zones9571 + ` policies { global { ` + body + ` } } }`
}

func parse9571(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v", errs)
	}
	return tree
}

func policies9571(cfg *Config) []*Policy {
	var out []*Policy
	for _, z := range cfg.Security.Policies {
		if z != nil {
			out = append(out, z.Policies...)
		}
	}
	return append(out, cfg.Security.GlobalPolicies...)
}

func hasWarning9571(cfg *Config, subs ...string) bool {
	for _, w := range cfg.Warnings {
		all := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

var lenientEntries9571 = []struct {
	label   string
	compile func(*ConfigTree) (*Config, error)
}{
	{"CompileConfigLenient", CompileConfigLenient},
	{"CompileConfigForNodeLenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
}

// TestFoldNeverTurnsAStatementsDenyIntoAPermit9571 is the defect. Measured at
// a475b3ea4 before the fix: every row compiled to ONE permit policy with no
// poison, and the union row permitted 10.0.1.5, a source only the DENY statement
// named. Both compile entry points run the fold, so both are asserted: a mutant
// that removes the marking at either call site reds its own sub-case.
func TestFoldNeverTurnsAStatementsDenyIntoAPermit9571(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"zone-pair deny then permit, both match any", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { deny; } } policy p1 { ` + anyMatch9571 + ` then { permit; } }`)},
		{"global deny then permit", globalText9571(
			`policy p1 { ` + anyMatch9571 + ` then { deny; } } policy p1 { ` + anyMatch9571 + ` then { permit; } }`)},
		{"union: deny one half, permit the other", zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { source-address 10.0.1.128/25; destination-address any; application any; } then { permit; } }`)},
		{"deny then a permit fragment", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { deny; } } policy p1 { then { permit; } }`)},
		{"reject then permit", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { reject; } } policy p1 { ` + anyMatch9571 + ` then { permit; } }`)},
		{"permit, deny fragment, permit fragment", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { permit; } } policy p1 { then { deny; } } policy p1 { then { permit; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(parse9571(t, tc.text)); err == nil {
				t.Fatal("strict commit accepted a duplicate policy name; #9571 must leave the #3473 gate unchanged")
			}
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parse9571(t, tc.text))
				if err != nil {
					t.Fatalf("%s must accept the config (#1960 no-brick): %v", entry.label, err)
				}
				pols := policies9571(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want the duplicate still FOLDED into 1 policy (#8752), got %d", entry.label, len(pols))
				}
				if pols[0].Action != PolicyPermit {
					t.Fatalf("%s: fixture premise broken: the merged action is %v, not permit, so this row "+
						"no longer measures a widening", entry.label, pols[0].Action)
				}
				if !pols[0].LenientContentDropped {
					t.Errorf("%s: #9571: the fold turned a statement's deny into a PERMIT over the union of "+
						"the statements' match criteria, and nothing poisons it, so the helper enforces it", entry.label)
				}
				if LenientDroppedPolicyLocator(cfg) == "" {
					t.Errorf("%s: the #6707 commit-confirmed preflight cannot see the poison", entry.label)
				}
				if !hasWarning9571(cfg, "duplicate policy name", "#9571") {
					t.Errorf("%s: the refusal is silent; warnings=%v", entry.label, cfg.Warnings)
				}
			}
		})
	}
}

// TestFoldControlsStillMergeWithoutPoison9571 is the load-bearing half. A fix
// that poisoned every duplicate would pass the cell above and regress #8752,
// whose fixture (permit then a deny fragment) is the first row here. None of
// these admits traffic a statement denied, so none may be poisoned or warned.
func TestFoldControlsStillMergeWithoutPoison9571(t *testing.T) {
	for _, tc := range []struct {
		name    string
		text    string
		want    PolicyAction
		objects int
	}{
		{"#8752 fixture: permit then a deny fragment", zonePairText9571(
			`policy p1 { match { source-address 10.0.0.0/8; destination-address any; application any; } then { permit; } } policy p1 { then { deny; } }`),
			PolicyDeny, 1},
		{"global: permit then deny", globalText9571(
			`policy g1 { ` + anyMatch9571 + ` then { permit; } } policy g1 { then { deny; } }`), PolicyDeny, 1},
		{"permit and permit", zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.128/25; destination-address any; application any; } then { permit; } }`),
			PolicyPermit, 1},
		{"deny and deny", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { deny; } } policy p1 { ` + anyMatch9571 + ` then { deny; } }`), PolicyDeny, 1},
		{"deny then reject", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { deny; } } policy p1 { ` + anyMatch9571 + ` then { reject; } }`), PolicyReject, 1},
		{"match-only statement then a permit fragment", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` } policy p1 { then { permit; } }`), PolicyPermit, 1},
		{"deny, permit fragment, deny fragment: ends restrictive", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { deny; } } policy p1 { then { permit; } } policy p1 { then { deny; } }`),
			PolicyDeny, 1},
		{"distinct names, deny first", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { deny; } } policy p2 { ` + anyMatch9571 + ` then { permit; } }`),
			PolicyDeny, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parse9571(t, tc.text))
				if err != nil {
					t.Fatalf("%s: %v", entry.label, err)
				}
				pols := policies9571(cfg)
				if len(pols) != tc.objects {
					t.Fatalf("%s: want %d policy object(s), got %d", entry.label, tc.objects, len(pols))
				}
				if pols[0].Action != tc.want {
					t.Errorf("%s: first policy action = %v, want %v", entry.label, pols[0].Action, tc.want)
				}
				for _, p := range pols {
					if p.LenientContentDropped {
						t.Errorf("%s: #9571 OVER-REJECTION: policy %q was poisoned, so the whole snapshot is "+
							"refused for a config that admits nothing a statement denied", entry.label, p.Name)
					}
				}
				if hasWarning9571(cfg, "#9571") {
					t.Errorf("%s: a #9571 refusal warning fired for a non-widening config: %v", entry.label, cfg.Warnings)
				}
			}
		})
	}
}
