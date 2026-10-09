package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func rejectRouteFilterTextAndStore12067(t *testing.T, text, want string) {
	t.Helper()
	if _, err := CheckText(text, 0); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("CheckText error = %v, want rejection naming %q", err, want)
	}

	store := newTestStore(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.CommitCheck(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("CommitCheck error = %v, want rejection naming %q", err, want)
	}
	if _, err := store.Commit(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Commit error = %v, want rejection naming %q", err, want)
	}
}

func TestTermLineRouteFilterWideningsRejected_12067(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"bare route-filter", `policy-options { policy-statement P { term T from route-filter; term T then accept; } }`, "route-filter"},
		{"upto missing length", `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto; term T then accept; } }`, "upto"},
		{"upto then accept packed", `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto then accept; } }`, "upto"},
		{"then first", `policy-options { policy-statement P { term T then accept from route-filter 10.0.0.0/8 upto; } }`, "upto"},
		{"term body", `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 upto; then accept; } } }`, "upto"},
		{"with protocol", `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto protocol static; term T then accept; } }`, "upto"},
		{"with community", `policy-options { community C1 members 65000:1; policy-statement P { term T from route-filter 10.0.0.0/8 upto community C1; term T then accept; } }`, "upto"},
		{"apply-groups", `groups { G { policy-options { policy-statement P { term T from route-filter; } } } } policy-options { apply-groups G; policy-statement P { term T then accept; } }`, "route-filter"},
		{"apply-groups upto", `groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto; } } } } policy-options { apply-groups G; policy-statement P { term T then accept; } }`, "upto"},
		{"policy-statement packing", `policy-options { policy-statement P term T from route-filter; policy-statement P term T then accept; }`, "route-filter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rejectRouteFilterTextAndStore12067(t, tc.text, tc.want)
		})
	}
}

func TestTermLineUpto24RemainsValid_12067(t *testing.T) {
	const text = `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto /24; term T then accept; } }`
	cfg, err := CheckText(text, 0)
	if err != nil {
		t.Fatalf("CheckText rejected a valid term-line upto /24: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.RouteFilters) != 1 || term.RouteFilters[0].UptoLen != 24 {
		t.Fatalf("route-filters = %+v, want one upto /24", term.RouteFilters)
	}
	store := newTestStore(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	committed, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit rejected a valid term-line upto /24: %v", err)
	}
	term = committed.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.RouteFilters) != 1 || term.RouteFilters[0].UptoLen != 24 {
		t.Fatalf("committed route-filters = %+v, want one upto /24", term.RouteFilters)
	}
}

func TestPackedRouteFilterValueReferencesRemainValid_12067(t *testing.T) {
	cases := []struct {
		name, definition, from, leaf string
	}{
		{"prefix-list", `prefix-list route-filter { 10.0.0.0/8; }`, `route-filter 10.0.0.0/8 exact prefix-list route-filter`, "prefix-list"},
		{"community", `community route-filter members 65000:1;`, `route-filter 10.0.0.0/8 exact community route-filter`, "community"},
		{"as-path", `as-path route-filter ".*";`, `route-filter 10.0.0.0/8 exact as-path route-filter`, "as-path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `policy-options { ` + tc.definition + ` policy-statement P { term T { from ` + tc.from + `; then accept; } } }`
			compiled, err := CheckText(text, 0)
			if err != nil {
				t.Fatalf("CheckText rejected valid %s value named route-filter: %v", tc.leaf, err)
			}
			assertPackedRouteFilterValue12067(t, compiled, tc.leaf)

			store := newTestStore(t)
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := store.LoadOverride(text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			committed, err := store.Commit()
			if err != nil {
				t.Fatalf("Commit rejected valid %s value named route-filter: %v", tc.leaf, err)
			}
			assertPackedRouteFilterValue12067(t, committed, tc.leaf)
		})
	}
}
func TestPackedRouteFilterValueControlsRemainValid_12067(t *testing.T) {
	cases := []struct{ name, text string }{
		{"braced from", `policy-options { prefix-list route-filter { 10.0.0.0/8; } policy-statement P { term T { from { route-filter 10.0.0.0/8 exact; prefix-list route-filter; } then accept; } } }`},
		{"quoted value", `policy-options { prefix-list route-filter { 10.0.0.0/8; } policy-statement P { term T { from route-filter 10.0.0.0/8 exact prefix-list "route-filter"; then accept; } } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := CheckText(tc.text, 0)
			if err != nil {
				t.Fatalf("CheckText rejected valid control: %v", err)
			}
			assertPackedRouteFilterValue12067(t, compiled, "prefix-list")

			store := newTestStore(t)
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := store.LoadOverride(tc.text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			committed, err := store.Commit()
			if err != nil {
				t.Fatalf("Commit rejected valid control: %v", err)
			}
			assertPackedRouteFilterValue12067(t, committed, "prefix-list")
		})
	}
}


func assertPackedRouteFilterValue12067(t *testing.T, cfg *config.Config, leaf string) {
	t.Helper()
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if len(term.RouteFilters) != 1 || term.RouteFilters[0].Prefix != "10.0.0.0/8" || term.RouteFilters[0].MatchType != "exact" {
		t.Fatalf("route-filters = %+v, want one exact filter", term.RouteFilters)
	}
	var got []string
	switch leaf {
	case "prefix-list":
		got = term.PrefixList
	case "community":
		got = term.FromCommunity
	case "as-path":
		got = term.FromASPath
	}
	if len(got) != 1 || got[0] != "route-filter" {
		t.Fatalf("%s values = %v, want [route-filter]", leaf, got)
	}
}

func TestQuotedRouteFilterHeadDoesNotHidePackedTail_12067(t *testing.T) {
	cases := []struct{ name, from, want string }{
		{"protocol", `"route-filter" 10.0.0.0/8 orlonger protocol static`, "protocol"},
		{"community", `"route-filter" 10.0.0.0/8 upto /24 community C1`, "community"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `policy-options { community C1 members 65000:1; policy-statement P { term T { from ` +
				tc.from + `; then accept; } } }`
			if _, err := CheckText(text, 0); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CheckText error = %v, want rejection naming %q", err, tc.want)
			}
		})
	}
}

func TestRouteFilterValueProvenanceDoesNotHideTail_12067(t *testing.T) {
	cases := []struct{ name, tail string }{
		{"quoted", `"protocol"`},
		{"bracketed", `[ protocol ]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `policy-options { policy-statement P { term T { from { route-filter 10.0.0.0/8 orlonger ` + tc.tail + `; } then accept; } } }`
			if _, err := CheckText(text, 0); err == nil || !strings.Contains(err.Error(), "protocol") {
				t.Fatalf("CheckText error = %v, want unconsumed route-filter token protocol", err)
			}
		})
	}
}
