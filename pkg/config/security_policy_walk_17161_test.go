package config

import (
	"strings"
	"testing"
)

// #17161 (R4-Q50-06): the eight strict security-policy gates used to each
// paste their own security -> policies -> global / from-zone pair walk.
// The #12782 keyed-context arm (`len(tzNode.Keys) >= 2`) was pinned only
// for the four gates its test named (#3044, #6526, #3113, #3114); deleting
// it in any other copy let a keyed
// `from-zone { A { to-zone B { ... } } }` policy carrying the gated
// construct commit strict while every test stayed green. The walk now
// lives once in forEachSecurityPolicy (security_policy_walk.go) and every
// gate passes only its checkPolicy.
//
// This table runs EVERY gate over four zone-pair shapes:
//
//   - flat:      hierarchical combined spelling
//     `from-zone A to-zone B { policy ... }` (the walker's
//     Keys >= 4 hierarchical arm);
//   - keyed:     `from-zone { A { to-zone B { policy ... } } }` (the
//     #12782 keyed arm — a keyed to-zone carries the pair body itself);
//   - nested-container: `from-zone { A { to-zone { B { policy ... } } } }`
//     (keyless to-zone enumerating destination-named child containers);
//   - duplicate-root: the flat spelling inside a SECOND top-level
//     `security {}` block after a benign zones-only first block (the
//     #3562 every-root iteration).
//
// Each cell carries a policy body gated by exactly that gate plus an
// otherwise-valid match/then, so on the strict path the ONLY possible
// rejection is that gate reaching the policy through the shared walker.
// Mutating the shared walker — disabling the keyed arm
// (`len(tzNode.Keys) >= 2` -> `>= 99`), the hierarchical arm, the
// keyless-container arm, or the every-root iteration — turns the matching
// shape column RED for every gate subtest, instead of the pre-#17161 state
// where five of the eight copies could lose the arm with all tests green.
func TestSecurityPolicyWalkEveryGateEveryShape17161(t *testing.T) {
	match := `match { source-address any; destination-address any; application any; }`
	gates := []struct {
		name string
		body string // policy body (beside match) carrying the gated construct
		want string // stable substring of that gate's strict rejection
	}{
		{"match-leaves-3113", match + ` then { permit; } extra-match`, "#3113"},
		{"required-match-3044-6526", `then { permit; }`, "#3044"},
		{"then-permit-3114", match + ` then { permit application-services; }`, "#3114"},
		{"then-reject-3115", match + ` then { reject profile strict-web; }`, "#3115"},
		{"then-count-alarm-11342", match + ` then { permit; count { alarm { per-minute-threshold 100; } } }`, "#11342"},
		{"then-deny-3141-3374", match + ` then { deny session-init; }`, "#3374"},
		{"then-siblings-11013", match + ` then { permit; next term; }`, "#11013"},
		{"enforcement-subtrees-12634", match + ` then { permit; } term nested { then { deny; } }`, "#11014"},
	}
	// The match-leaves cell needs its unsupported leaf INSIDE match, not
	// beside it; fix that cell's body construction below by special-casing.
	gates[0].body = `match { source-address any; destination-address any; application any; dynamic-application foo; } then { permit; }`

	shapes := []struct {
		name string
		wrap func(policy string) string // full config text around `policy d { ... }`
	}{
		{
			name: "flat",
			wrap: func(policy string) string {
				return `security { zones { security-zone A; security-zone B; } policies { from-zone A to-zone B { ` + policy + ` } } }`
			},
		},
		{
			name: "keyed",
			wrap: func(policy string) string {
				return `security { zones { security-zone A; security-zone B; } policies { from-zone { A { to-zone B { ` + policy + ` } } } } }`
			},
		},
		{
			name: "nested-container",
			wrap: func(policy string) string {
				return `security { zones { security-zone A; security-zone B; } policies { from-zone { A { to-zone { B { ` + policy + ` } } } } } }`
			},
		},
		{
			name: "duplicate-root",
			wrap: func(policy string) string {
				return `security { zones { security-zone A; security-zone B; } } ` +
					`security { policies { from-zone A to-zone B { ` + policy + ` } } }`
			},
		},
	}

	for _, gate := range gates {
		for _, shape := range shapes {
			t.Run(gate.name+"/"+shape.name, func(t *testing.T) {
				text := shape.wrap(`policy d { ` + gate.body + ` }`)
				tree, parseErrs := NewParser(text).Parse()
				if len(parseErrs) != 0 {
					t.Fatalf("parse: %v", parseErrs[0])
				}
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("strict compile committed gated construct via %s shape; shared walker did not deliver the policy to gate %s (want %s rejection)", shape.name, gate.name, gate.want)
				}
				if !strings.Contains(err.Error(), gate.want) {
					t.Fatalf("strict error = %v, want gate %s marker %q", err, gate.name, gate.want)
				}
				if !strings.Contains(err.Error(), `policy "d"`) {
					t.Fatalf("strict error = %v, want it to name policy \"d\" (walker scope/name delivery)", err)
				}
			})
		}
	}

	// Control: the same four shapes with a fully valid policy must commit
	// and compile exactly one A->B pair carrying policy d — the walker's
	// superset enumeration must not invent or drop pairs.
	for _, shape := range shapes {
		t.Run("valid/"+shape.name, func(t *testing.T) {
			text := shape.wrap(`policy d { ` + match + ` then { permit; } }`)
			tree, parseErrs := NewParser(text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse: %v", parseErrs[0])
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile of valid %s policy: %v", shape.name, err)
			}
			if len(cfg.Security.Policies) != 1 || cfg.Security.Policies[0].FromZone != "A" ||
				cfg.Security.Policies[0].ToZone != "B" || len(cfg.Security.Policies[0].Policies) != 1 ||
				cfg.Security.Policies[0].Policies[0].Name != "d" {
				t.Fatalf("valid %s shape compiled pairs = %+v, want one A->B pair with policy d", shape.name, cfg.Security.Policies)
			}
		})
	}
}
