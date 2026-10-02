package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11451: the tolerant builder must not send an unresolved `except` as the
// empty-set complement (match-all). FromUnrepresentable refuses the candidate
// snapshot, preserving the prior good filter state rather than widening it.
func TestBuildFirewallFilterSnapshotsUnresolvedExceptFailsClosed11451(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {
			Name: "edge",
			Terms: []*config.FirewallFilterTerm{{
				Name:              "t",
				SourcePrefixLists: []config.PrefixListRef{{Name: "TYPO", Except: true}},
				Action:            "accept",
			}},
		},
	}

	snaps := BuildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("snapshot terms = %+v, want one filter term", snaps)
	}
	term := snaps[0].Terms[0]
	if !term.FromUnrepresentable {
		t.Fatal("an unresolved except reference must refuse the candidate snapshot (#11451), not encode match-all")
	}
}

// A defined-but-empty except list remains representable and preserves Junos
// match-all semantics; it must not trigger the unresolved-reference refusal.
func TestBuildFirewallFilterSnapshotsDefinedEmptyExceptKeepsMatchAll11451(t *testing.T) {
	cfg := &config.Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*config.PrefixList{"none": {Name: "none"}}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {
			Name: "edge",
			Terms: []*config.FirewallFilterTerm{{
				Name:              "t",
				SourcePrefixLists: []config.PrefixListRef{{Name: "none", Except: true}},
				Action:            "accept",
			}},
		},
	}

	snaps := BuildFirewallFilterSnapshots(cfg)
	term := snaps[0].Terms[0]
	if term.FromUnrepresentable {
		t.Fatal("a defined-empty except list is representable and must not refuse the snapshot")
	}
	if !term.SourceExcept || !term.SourceConstrained || len(term.SourceAddresses) != 0 {
		t.Fatalf("defined-empty except must encode constrained match-all, got %+v", term)
	}
}
