package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14132: a positive (non-except) prefix-list reference that does not resolve
// on the lenient / peer-sync path must refuse the whole candidate snapshot
// via FromUnrepresentable, exactly like the unresolved-except case (#11451).
// Pre-fix only `except` refs set the marker: a discard/reject term over a
// single unresolved positive list matched nothing and fell through to the
// filter's implicit accept, and a deny over an OR of a resolved plus an
// unresolved list silently narrowed to the resolved members only.
// FAIL-ON-REVERT: restoring the except-only helper makes every discard /
// reject / destination / partial-OR assertion below go RED.
func TestBuildFirewallFilterSnapshotsUnresolvedPositiveFailsClosed14132(t *testing.T) {
	cases := []struct {
		name  string
		term  *config.FirewallFilterTerm
		lists map[string]*config.PrefixList
	}{
		{
			name: "discard single unresolved source",
			term: &config.FirewallFilterTerm{
				Name:              "t",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
				Action:            "discard",
			},
		},
		{
			name: "reject single unresolved source",
			term: &config.FirewallFilterTerm{
				Name:              "t",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
				Action:            "reject",
			},
		},
		{
			name: "discard single unresolved destination",
			term: &config.FirewallFilterTerm{
				Name:            "t",
				DestPrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
				Action:          "discard",
			},
		},
		{
			name: "accept single unresolved source",
			term: &config.FirewallFilterTerm{
				Name:              "t",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
				Action:            "accept",
			},
		},
		{
			name: "discard partial OR resolved plus unresolved",
			term: &config.FirewallFilterTerm{
				Name: "t",
				SourcePrefixLists: []config.PrefixListRef{
					{Name: "known"},
					{Name: "TYPO"},
				},
				Action: "discard",
			},
			lists: map[string]*config.PrefixList{
				"known": {Name: "known", Prefixes: []string{"10.0.0.0/8"}},
			},
		},
		{
			name: "reject unresolved alongside literal",
			term: &config.FirewallFilterTerm{
				Name:              "t",
				SourceAddresses:   []string{"192.0.2.0/24"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO"}},
				Action:            "reject",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.PolicyOptions.PrefixLists = tc.lists
			cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
				"edge": {Name: "edge", Terms: []*config.FirewallFilterTerm{tc.term}},
			}
			snaps := BuildFirewallFilterSnapshots(cfg)
			if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
				t.Fatalf("snapshot terms = %+v, want one filter term", snaps)
			}
			term := snaps[0].Terms[0]
			if !term.FromUnrepresentable {
				t.Fatalf("an unresolved positive prefix-list must refuse the candidate snapshot (#14132), got %+v", term)
			}
		})
	}
}

// A defined (even defined-empty) positive prefix-list is representable and
// must NOT trigger the unresolved-reference refusal: the matcher already
// fails closed on the constrained empty set without discarding prior-good
// state for a legitimate config.
func TestBuildFirewallFilterSnapshotsDefinedPositiveKeepsRepresentable14132(t *testing.T) {
	for _, tc := range []struct {
		name     string
		prefixes []string
	}{
		{name: "defined with prefixes", prefixes: []string{"10.0.0.0/8"}},
		{name: "defined empty", prefixes: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{
				"known": {Name: "known", Prefixes: tc.prefixes},
			}
			cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
				"edge": {
					Name: "edge",
					Terms: []*config.FirewallFilterTerm{{
						Name:              "t",
						SourcePrefixLists: []config.PrefixListRef{{Name: "known"}},
						Action:            "discard",
					}},
				},
			}
			snaps := BuildFirewallFilterSnapshots(cfg)
			term := snaps[0].Terms[0]
			if term.FromUnrepresentable {
				t.Fatal("a defined positive prefix-list is representable and must not refuse the snapshot (#14132)")
			}
			if !term.SourceConstrained {
				t.Fatalf("defined positive prefix-list must stay constrained, got %+v", term)
			}
		})
	}
}
