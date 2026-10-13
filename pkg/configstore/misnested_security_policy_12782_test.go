package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12782: a misspelled policy child under a keyed `to-zone` was consumed as a
// second-level zone name, leaving the deny uncompiled and no quarantine record.
// The valid keyed destination must remain a real pair, while its unknown
// policy-shaped child is quarantined with the actual pair context.
func TestSyncApplyQuarantinesKeyedToZoneInContainerFromZone12782(t *testing.T) {
	match := `match { source-address any; destination-address any; application any; }`
	cases := []struct {
		name, text string
		unknowns   []string
	}{
		{
			name:     "keyed to-zone misspelled policy deny",
			text:     `security { policies { default-policy permit-all; from-zone { A { to-zone B { polcy d { ` + match + ` then { deny; } } } } } } }`,
			unknowns: []string{`from-zone "A" to-zone "B" polcy`},
		},
		{
			name:     "keyed to-zone misspelled policy match only",
			text:     `security { policies { default-policy permit-all; from-zone { A { to-zone B { polcy d { ` + match + ` } } } } } }`,
			unknowns: []string{`from-zone "A" to-zone "B" polcy`},
		},
		{
			name:     "keyed to-zone misspelled policy sibling of good policy",
			text:     `security { policies { default-policy permit-all; from-zone { A { to-zone B { policy good { ` + match + ` then { permit; } } polcy d { ` + match + ` then { deny; } } } } } } }`,
			unknowns: []string{`from-zone "A" to-zone "B" polcy`},
		},
		{
			name:     "keyed to-zone mismatch records concrete source zones",
			text:     `security { policies { default-policy permit-all; from-zone { A { to-zone B { polcy d { ` + match + ` then { deny; } } } } C { to-zone B { polcy d { ` + match + ` then { deny; } } } } } } }`,
			unknowns: []string{`from-zone "A" to-zone "B" polcy`, `from-zone "C" to-zone "B" polcy`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			compiled, err := store.SyncApply(tc.text, nil)
			if err != nil {
				t.Fatalf("SyncApply: %v", err)
			}
			if got := config.LenientDroppedPolicyLocator(compiled); got != `global policy "xpf-unknown-policies-child-poison"` {
				t.Fatalf("dropped policy-shaped child locator = %q, want the #12217 quarantine carrier", got)
			}
			for _, pair := range compiled.Security.Policies {
				if pair.ToZone == "polcy" || pair.ToZone == "policy" {
					t.Fatalf("phantom zone pair compiled from policy keyword: %+v", pair)
				}
			}
			joined := strings.Join(compiled.Warnings, "\n")
			if !strings.Contains(joined, "polcy") || !strings.Contains(joined, "snapshot is refused") {
				t.Fatalf("SyncApply warning did not identify and quarantine skipped child: %v", compiled.Warnings)
			}
			if len(compiled.Security.MalformedZonePairs) != 0 {
				t.Fatalf("correct keyed shape acquired a mixed-shape diagnostic: %q", compiled.Security.MalformedZonePairs)
			}
			for _, want := range tc.unknowns {
				found := false
				for _, got := range compiled.Security.UnknownPoliciesChildren {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("exact quarantine record %q missing from %q", want, compiled.Security.UnknownPoliciesChildren)
				}
			}
			tree, parseErrs := config.NewParser(tc.text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse strict control: %v", parseErrs[0])
			}
			if _, strictErr := store.compileTree(tree); strictErr == nil || !strings.Contains(strictErr.Error(), tc.unknowns[0][strings.LastIndex(tc.unknowns[0], " ")+1:]) {
				t.Fatalf("strict compileTree error = %v, want rejection naming skipped keyword", strictErr)
			}
		})
	}
}

// Keyed `to-zone` children in a container `from-zone` are compiled from their
// key and must pass strict validation. Invalid policy-shaped siblings remain
// quarantined through the same tolerant path.
func TestStrictKeyedToZoneInContainerFromZone12788(t *testing.T) {
	match := `match { source-address any; destination-address any; application any; }`
	text := `security { zones { security-zone A; security-zone B; } policies { from-zone { A { to-zone B { policy d { ` + match + ` then { deny; } } } } } } }`
	store := newTestStore(t)
	tree, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse: %v", parseErrs[0])
	}
	cfg, err := store.compileTree(tree)
	if err != nil {
		t.Fatalf("strict keyed zone-pair commit: %v", err)
	}
	if len(cfg.Security.Policies) != 1 || cfg.Security.Policies[0].FromZone != "A" ||
		cfg.Security.Policies[0].ToZone != "B" || len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("keyed zone pair was not compiled from its key: %+v", cfg.Security.Policies)
	}
}

func TestStrictKeyedToZonePolicyWarningsInContainerFromZone12788(t *testing.T) {
	match := `match { source-address any; destination-address any; application any; }`
	for _, tc := range []struct {
		name, policy, want string
	}{
		{"missing match", `policy d { then { permit; } }`, "#3044"},
		{"valueless match dimension", `policy d { match { source-address; destination-address any; application any; } then { permit; } }`, "#6526"},
		{"unsupported match leaf", `policy d { match { source-address any; destination-address any; application any; dynamic-application foo; } then { permit; } }`, "#3113"},
		{"unsupported then permit", `policy d { ` + match + ` then { permit application-services; } }`, "#3114"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := `security { zones { security-zone A; security-zone B; } policies { from-zone { A { to-zone B { ` + tc.policy + ` } } } } }`
			store := newTestStore(t)
			tree, parseErrs := config.NewParser(text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse: %v", parseErrs[0])
			}
			_, strictErr := store.compileTree(tree)
			if strictErr == nil {
				t.Fatal("strict keyed policy unexpectedly committed")
			}
			if (tc.want == "#3044" || tc.want == "#3114") && !strings.Contains(strictErr.Error(), tc.want) {
				t.Fatalf("strict keyed policy error = %v, want %s gate", strictErr, tc.want)
			}
			compiled, err := store.SyncApply(text, nil)
			if err != nil {
				t.Fatalf("tolerant keyed compile: %v", err)
			}
			if !strings.Contains(strings.Join(compiled.Warnings, "\n"), tc.want) {
				t.Fatalf("tolerant keyed warning = %v, want %s", compiled.Warnings, tc.want)
			}
		})
	}
}

func TestSyncApplyKeepsSupportedToZoneContexts12782(t *testing.T) {
	match := `match { source-address any; destination-address any; application any; }`
	cases := []struct {
		name, text, wantTo string
	}{
		{
			name:   "keyed to-zone in container",
			text:   `security { policies { default-policy permit-all; from-zone { A { to-zone B { policy d { ` + match + ` then { deny; } } } } } } }`,
			wantTo: "B",
		},
		{
			name:   "keyed to-zone any in container",
			text:   `security { policies { default-policy permit-all; from-zone { A { to-zone any { policy d { ` + match + ` then { deny; } } } } } } }`,
			wantTo: "any",
		},
		{
			name:   "fully nested container to-zone deny",
			text:   `security { policies { default-policy permit-all; from-zone { A { to-zone { B { policy d { ` + match + ` then { deny; } } } } } } } }`,
			wantTo: "B",
		},
		{
			name:   "fully keyed to-zone deny",
			text:   `security { policies { default-policy permit-all; from-zone A to-zone B { policy d { ` + match + ` then { deny; } } } } }`,
			wantTo: "B",
		},
		{
			name:   "fully keyed to-zone any deny",
			text:   `security { policies { default-policy permit-all; from-zone A to-zone any { policy d { ` + match + ` then { deny; } } } } }`,
			wantTo: "any",
		},
		{
			name:   "fully keyed to-zone permit",
			text:   `security { policies { default-policy permit-all; from-zone A to-zone B { policy d { ` + match + ` then { permit; } } } } }`,
			wantTo: "B",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			compiled, err := store.SyncApply(tc.text, nil)
			if err != nil {
				t.Fatalf("SyncApply: %v", err)
			}
			if got := config.LenientDroppedPolicyLocator(compiled); got != "" {
				t.Fatalf("correct policy context was quarantined at %q", got)
			}
			found := false
			for _, pair := range compiled.Security.Policies {
				if pair.FromZone != "A" || pair.ToZone != tc.wantTo {
					t.Fatalf("unexpected zone pair %q -> %q", pair.FromZone, pair.ToZone)
				}
				for _, policy := range pair.Policies {
					if policy != nil && policy.Name == "d" {
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("policy d was not compiled into pair A->%s: %+v", tc.wantTo, compiled.Security.Policies)
			}
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, "#11346") {
					t.Fatalf("supported keyed context emitted the obsolete mixed-shape warning: %q", warning)
				}
				if strings.Contains(warning, "snapshot is refused") {
					t.Fatalf("correct policy context emitted quarantine warning: %q", warning)
				}
			}
		})
	}
}
