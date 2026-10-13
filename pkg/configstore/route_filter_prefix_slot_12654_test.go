package configstore

import (
	"strings"
	"testing"
)

func TestTolerantSyncInvalidRouteFilterPrefixWarning12654(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "compact keyword in prefix slot",
			text: `policy-options { policy-statement P { term T { from route-filter longer exact; then accept; } } }`,
		},
		{
			name: "compact garbage prefix",
			text: `policy-options { policy-statement P { term T { from route-filter garbage exact; then accept; } } }`,
		},
		{
			name: "term-line invalid IPv6 prefix",
			text: `policy-options { policy-statement P { term T from route-filter 2001:db8::/129 exact; term T then accept; } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			cfg, err := store.SyncApply(tc.text, nil)
			if err != nil {
				t.Fatalf("SyncApply failed on tolerant path: %v", err)
			}
			if cfg == nil {
				t.Fatal("SyncApply returned nil config")
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "route-filter match-type") &&
					strings.Contains(warning, "route-filter prefix") {
					return
				}
			}
			t.Fatalf("expected tolerant warning for invalid route-filter prefix, got %v", cfg.Warnings)
		})
	}
}
