package configstore

import (
	"testing"
)

func TestLoadOverrideCommitRetainsInheritedRouteFilter12529(t *testing.T) {
	store := newTestStore(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer store.ExitConfigure()

	const text = `groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto /24; } } } }
policy-options { apply-groups G; policy-statement P { term T then accept; } }`
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	committed, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	statement := committed.PolicyOptions.PolicyStatements["P"]
	if statement == nil || len(statement.Terms) != 1 {
		t.Fatalf("committed policy P terms = %+v, want one term", statement)
	}
	term := statement.Terms[0]
	if len(term.RouteFilters) != 1 || term.RouteFilters[0] == nil ||
		term.RouteFilters[0].Prefix != "10.0.0.0/8" ||
		term.RouteFilters[0].MatchType != "upto" ||
		term.RouteFilters[0].UptoLen != 24 {
		t.Fatalf("committed RouteFilters = %+v, want 10.0.0.0/8 upto /24", term.RouteFilters)
	}
}
