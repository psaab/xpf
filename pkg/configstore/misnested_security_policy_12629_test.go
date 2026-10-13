package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSyncApplyQuarantinesMisnestedSecurityPolicyDeny12629(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			name: "global policy keyword",
			text: `security { policies { default-policy permit-all; global { polcy d { match { source-address any; destination-address any; application any; } then { deny; } } } } }`,
			want: `polcy`,
		},
		{
			name: "keyed from-zone policy keyword",
			text: `security { policies { default-policy permit-all; from-zone A to-zone B { polcy d { match { source-address any; destination-address any; application any; } then { deny; } } } } }`,
			want: `polcy`,
		},
		{
			name: "nested to-zone keyword",
			text: `security { policies { default-policy permit-all; from-zone A { to-zon B { policy d { match { source-address any; destination-address any; application any; } then { deny; } } } } } }`,
			want: `to-zon`,
		},
		{
			name: "keyed from-zone nested to-zone keyword",
			text: `security { policies { default-policy permit-all; from-zone A to-zone B { to-zon C { policy d { match { source-address any; destination-address any; application any; } then { deny; } } } } } }`,
			want: `to-zon`,
		},
		{
			name: "fully nested policy keyword",
			text: `security { policies { default-policy permit-all; from-zone { A { to-zone { B { polcy d { match { source-address any; destination-address any; application any; } then { deny; } } } } } } } }`,
			want: `polcy`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			compiled, err := store.SyncApply(tc.text, nil)
			if err != nil {
				t.Fatalf("SyncApply: %v", err)
			}
			if got := config.LenientDroppedPolicyLocator(compiled); got == "" {
				t.Fatal("dropped deny produced no LenientContentDropped locator; with permit-all default the omitted rule can fail open")
			}
			joined := strings.Join(compiled.Warnings, "\n")
			if !strings.Contains(joined, tc.want) || !strings.Contains(joined, "snapshot is refused") {
				t.Fatalf("SyncApply warning does not identify %q and quarantine the snapshot: %v", tc.want, compiled.Warnings)
			}
			tree, parseErrs := config.NewParser(tc.text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse strict control: %v", parseErrs[0])
			}
			if _, strictErr := store.compileTree(tree); strictErr == nil || !strings.Contains(strictErr.Error(), tc.want) {
				t.Fatalf("strict compileTree error = %v, want rejection naming %q", strictErr, tc.want)
			}
		})
	}
}

func TestSyncApplyKeepsCorrectSecurityPolicyContexts12629(t *testing.T) {
	text := `security {
 zones { security-zone A; security-zone B; }
 policies {
  default-policy permit-all;
  global {
   apply-macro GOOD { key value; }
   policy global-deny { match { source-address any; destination-address any; application any; } then { deny; } }
  }
  from-zone A to-zone B {
   apply-macro GOOD { key value; }
   policy pair-deny { match { source-address any; destination-address any; application any; } then { deny; } }
  }
  from-zone C { apply-macro GOOD { key value; } }
 }
}`
	store := newTestStore(t)
	compiled, err := store.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply correct policy contexts: %v", err)
	}
	if got := config.LenientDroppedPolicyLocator(compiled); got != "" {
		t.Fatalf("correct policy contexts were quarantined at %q", got)
	}
	var globalFound, pairFound bool
	for _, policy := range compiled.Security.GlobalPolicies {
		if policy != nil && policy.Name == "global-deny" {
			globalFound = true
		}
	}
	for _, pair := range compiled.Security.Policies {
		if pair == nil || pair.FromZone != "A" || pair.ToZone != "B" {
			continue
		}
		for _, policy := range pair.Policies {
			if policy != nil && policy.Name == "pair-deny" {
				pairFound = true
			}
		}
	}
	if !globalFound || !pairFound {
		t.Fatalf("correct policy contexts were not compiled: global=%t pair=%t", globalFound, pairFound)
	}
	for _, warning := range compiled.Warnings {
		if strings.Contains(warning, "snapshot is refused") {
			t.Fatalf("correct policy contexts emitted quarantine warning: %q", warning)
		}
	}
}
