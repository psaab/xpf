package configstore

import (
	"strings"
	"testing"
)

func TestGroupInheritedValidRouteFilterTrailerRemainsAccepted12687(t *testing.T) {
	const text = `groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto /24; } } } }
policy-options { apply-groups G; policy-statement P { term T then accept; } }`
	store := newTestStore(t)
	cfg, err := store.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected valid inherited route-filter: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if term.Action != "accept" || len(term.RouteFilters) != 1 ||
		term.RouteFilters[0].Prefix != "10.0.0.0/8" ||
		term.RouteFilters[0].MatchType != "upto" || term.RouteFilters[0].UptoLen != 24 {
		t.Fatalf("valid inherited term = %+v, want accept with 10.0.0.0/8 upto /24", term)
	}
}

func TestTolerantSyncGroupInheritedValidThroughNotQuarantined12687(t *testing.T) {
	const text = `groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 through 10.0.0.0/24; } } } }
policy-options { apply-groups G; policy-statement P { term T then accept; } }`
	store := newTestStore(t)
	cfg, err := store.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected valid inherited through operand: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if term.Action != "accept" || len(term.RouteFilters) != 1 ||
		term.RouteFilters[0].MatchType != "through" {
		t.Fatalf("valid inherited through term = %+v, want historical tolerant behavior", term)
	}
}

func TestTolerantSyncGroupInheritedInvalidRouteFilterRejects12687(t *testing.T) {
	cases := []struct {
		name, trailer string
	}{
		{"malformed upto", "upto /bogus"},
		{"malformed prefix-length-range", "prefix-length-range /24-/abc"},
		{"unsupported through operand", "through bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := "groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 " +
				tc.trailer + "; } } } } policy-options { apply-groups G; policy-statement P { term T then accept; } }"
			store := newTestStore(t)
			cfg, err := store.SyncApply(text, nil)
			if err != nil {
				t.Fatalf("SyncApply rejected tolerant input: %v", err)
			}
			if cfg == nil {
				t.Fatal("SyncApply returned nil config")
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if term.Action != "reject" {
				t.Fatalf("tolerant inherited term action = %q, want reject; term=%+v", term.Action, term)
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "route-filter match-type") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("SyncApply emitted no route-filter warning: %v", cfg.Warnings)
			}
		})
	}
}
