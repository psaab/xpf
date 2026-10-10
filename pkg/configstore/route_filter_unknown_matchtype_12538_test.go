package configstore

import (
	"strings"
	"testing"
)

func TestCompactAndTermLineRouteFilterUnknownMatchTypeRejected_12538(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "compact orlongerr",
			text: `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 orlongerr; then accept; } } }`,
		},
		{
			name: "compact exactt",
			text: `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 exactt; then accept; } } }`,
		},
		{
			name: "compact bogus match-type",
			text: `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 bogus; then accept; } } }`,
		},
		{
			name: "term-line orlongerr",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 orlongerr; term T then accept; } }`,
		},
		{
			name: "term-line exactt",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 exactt; term T then accept; } }`,
		},
		{
			name: "term-line bogus match-type",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 bogus; term T then accept; } }`,
		},
		{
			name: "term-line packed then",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 orlongerr then accept; } }`,
		},
		{
			name: "term-line then first",
			text: `policy-options { policy-statement P { term T then accept from route-filter 10.0.0.0/8 orlongerr; } }`,
		},
		{
			name: "term-line with protocol",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 orlongerr protocol static; term T then accept; } }`,
		},
		{
			name: "policy-statement packing",
			text: `policy-options { policy-statement P term T from route-filter 10.0.0.0/8 orlongerr; policy-statement P term T then accept; }`,
		},
		{
			name: "apply-groups compact",
			text: `groups { G { policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 orlongerr; } } } } } policy-options { apply-groups G; policy-statement P { term T then accept; } }`,
		},
		{
			name: "apply-groups term-line",
			text: `groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 orlongerr; } } } } policy-options { apply-groups G; policy-statement P { term T then accept; } }`,
		},
		{
			name: "compact ipv6 unknown match-type",
			text: `policy-options { policy-statement P { term T { from route-filter 2001:db8::/32 orlongerr; then accept; } } }`,
		},
		{
			name: "term-line ipv6 unknown match-type",
			text: `policy-options { policy-statement P { term T from route-filter 2001:db8::/32 orlongerr; term T then accept; } }`,
		},
		{
			name: "compact second filter unknown",
			text: `policy-options { policy-statement P { term T { from route-filter 10.0.0.0/8 exact route-filter 192.168.0.0/16 orlongerr; then accept; } } }`,
		},
		{
			name: "term-line second filter unknown",
			text: `policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 exact route-filter 192.168.0.0/16 orlongerr; term T then accept; } }`,
		},
	}

	const want = "not a valid route-filter match-type"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rejectRouteFilterTextAndStore12067(t, tc.text, want)
		})
	}
}

func TestTolerantSyncUnknownMatchTypeWarning_12538(t *testing.T) {
	const text = `policy-options {
policy-statement P {
    term T from route-filter 10.0.0.0/8 orlongerr;
    term T then accept;
}
}`
	store := newTestStore(t)
	cfg, err := store.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply failed on tolerant path: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned nil config")
	}

	foundWarning := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "route-filter match-type") && strings.Contains(w, "not a valid route-filter match-type") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("expected warning for route-filter match-type on tolerant path, got warnings: %v", cfg.Warnings)
	}
}
