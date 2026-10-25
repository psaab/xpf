package configstore

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16606: PublishRefreshedDNS swaps the compiled active config to the
// refreshed clone only while base is still active, and publishes a new
// generation. A stale base must not overwrite a newer generation.
//
// FAIL-ON-REVERT: dropping the base check (or the publishActiveLocked
// call) makes the stale-swap or generation asserts RED.

func TestPublishRefreshedDNS16606(t *testing.T) {
	s := snapshotPublishStore9905(t, "a")
	base := s.ActiveConfig()
	g1, _ := s.ActiveSnapshot()

	refreshed := base.CloneForDNSRefresh()
	// CloneForDNSRefresh on a dns-less config shares everything; give the
	// clone a distinguishable runtime answer by installing a dns entry
	// copy (production clones are made before RefreshDNSAddressBooks).
	if !s.PublishRefreshedDNS(base, refreshed) {
		t.Fatal("PublishRefreshedDNS(base, refreshed) = false, want true")
	}
	if s.ActiveConfig() != refreshed {
		t.Fatal("ActiveConfig not swapped to refreshed clone")
	}
	g2, snap := s.ActiveSnapshot()
	if g2 <= g1 || snap != refreshed {
		t.Fatalf("ActiveSnapshot = (%d,%p), want (> %d, refreshed)", g2, snap, g1)
	}
	// Operator-tree identity is untouched (DNS is runtime state).
	if s.ActiveConfigGeneration() == "" {
		t.Fatal("ActiveConfigGeneration empty after DNS publish")
	}

	// Stale base: base is no longer active, must not swap.
	stale := &config.Config{}
	if s.PublishRefreshedDNS(base, stale) {
		t.Fatal("PublishRefreshedDNS(stale base) = true, want false")
	}
	if s.ActiveConfig() != refreshed {
		t.Fatal("stale PublishRefreshedDNS overwrote the active config")
	}
	// Nil guards.
	if s.PublishRefreshedDNS(nil, refreshed) || s.PublishRefreshedDNS(refreshed, nil) {
		t.Fatal("PublishRefreshedDNS nil guard failed")
	}
}
