package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestNATAddressNameCollisionQuarantined12216(t *testing.T) {
	ab := &config.AddressBook{
		Addresses: map[string]*config.Address{
			"blocked": {Name: "blocked", Value: "10.0.0.0/8"},
			"other":   {Name: "other", Value: "192.0.2.1/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"blocked": {Name: "blocked", Addresses: []string{"other"}},
		},
		CollidingNames: map[string]struct{}{"blocked": {}},
	}
	cfg := &config.Config{}
	cfg.Security.AddressBook = ab

	if got := resolveNATAddressNamePrefixes(cfg, nil, "blocked"); len(got) != 0 {
		t.Fatalf("NAT-only colliding name published a winner subset: %v", got)
	}

	if got := resolveNATAddressNamePrefixes(cfg, map[string][]string{
		"blocked": {"198.51.100.0/24"},
	}, "blocked"); len(got) != 0 {
		t.Fatalf("feed overlay must not bypass collision quarantine, got %v", got)
	}
	if got := appendNATSourceAddressName(cfg, nil, nil, "blocked"); len(got) != 1 || got[0] != "blocked" {
		t.Fatalf("colliding NAT source must use the unmatchable raw-name fallback, got %v", got)
	}
	if nameRepresentable(ab, nil, nil, "blocked", map[string]bool{}) {
		t.Fatal("policy-path control accepted the same colliding reference")
	}
}

func TestNATAddressSetDanglingMemberQuarantined12216(t *testing.T) {
	ab := &config.AddressBook{
		Addresses: map[string]*config.Address{
			"good": {Name: "good", Value: "10.20.0.0/16"},
		},
		AddressSets: map[string]*config.AddressSet{
			"mixed": {Name: "mixed", Addresses: []string{"good", "ghost"}},
		},
	}
	cfg := &config.Config{}
	cfg.Security.AddressBook = ab

	if got := resolveNATAddressNamePrefixes(cfg, nil, "mixed"); len(got) != 0 {
		t.Fatalf("NAT-only dangling set published the static subset: %v", got)
	}
	if nameRepresentable(ab, nil, nil, "mixed", map[string]bool{}) {
		t.Fatal("policy-path control accepted the same dangling set")
	}
}

func TestNATAddressSetUnreadyFeedPoisonsStaticAlias12216(t *testing.T) {
	ab := &config.AddressBook{
		Addresses: map[string]*config.Address{
			"good":   {Name: "good", Value: "10.20.0.0/16"},
			"feed-a": {Name: "feed-a", Value: "10.30.0.0/16"},
		},
		AddressSets: map[string]*config.AddressSet{
			"mixed": {Name: "mixed", Addresses: []string{"good", "feed-a"}},
		},
	}
	cfg := &config.Config{}
	cfg.Security.AddressBook = ab
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"feed-a": {Name: "feed-a", FeedNames: []string{"threat"}},
	}

	if got := resolveNATAddressNamePrefixes(cfg, nil, "mixed"); len(got) != 0 {
		t.Fatalf("NAT-only set published static alias while declared feed was unready: %v", got)
	}
	if nameRepresentable(ab, nil, cfg.Security.DynamicAddress.AddressBindings, "mixed", map[string]bool{}) {
		t.Fatal("policy-path control accepted a set with a declared but unready feed")
	}

	live := map[string][]string{"feed-a": {"198.51.100.0/24"}}
	got := resolveNATAddressNamePrefixes(cfg, live, "mixed")
	if !contains(got, "10.20.0.0/16") || !contains(got, "198.51.100.0/24") {
		t.Fatalf("ready feed and static member must both resolve, got %v", got)
	}
	if !nameRepresentable(ab, live, cfg.Security.DynamicAddress.AddressBindings, "mixed", map[string]bool{}) {
		t.Fatal("policy-path control rejected the same set after the feed became ready")
	}
}

func TestNATReadyFeedWithEmptySameNameSetStillResolves12216(t *testing.T) {
	ab := &config.AddressBook{
		AddressSets: map[string]*config.AddressSet{
			"feed-only": {Name: "feed-only"},
		},
	}
	cfg := &config.Config{}
	cfg.Security.AddressBook = ab
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"feed-only": {Name: "feed-only", FeedNames: []string{"threat"}},
	}
	overlay := map[string][]string{"feed-only": {"198.51.100.0/24"}}

	got := resolveNATAddressNamePrefixes(cfg, overlay, "feed-only")
	if len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("ready feed bound to an empty same-name set must resolve, got %v", got)
	}
	if !nameRepresentable(ab, overlay, cfg.Security.DynamicAddress.AddressBindings, "feed-only", map[string]bool{}) {
		t.Fatal("policy-path control rejected the same ready feed")
	}
}
