package userspace

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16730: the mapper must name fabric and unpublished-snapshot blockers
// with their own vocabulary entries, never drop them, and never mislabel
// the unpublished-generation reason as forwarding_unsupported. Every
// blocker the mapper returns must be a member of the shared vocabulary
// the Prometheus emitter renders — this is the guard that fails if a
// future takeoverReadyLocked reason is added without extending the vocab.

func TestHATakeoverReadinessFabricBlockersInVocab16730(t *testing.T) {
	installable := FabricSnapshot{Name: "fab1", ParentIfindex: 21, PeerAddress: peerV4_15918, LocalMAC: localMAC_15918, PeerMAC: peerMAC_15918}

	t.Run("peer unresolved", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{{Name: "fab1", ParentIfindex: 21, PeerAddress: peerV4_15918, LocalMAC: localMAC_15918, PeerMAC: ""}})
		s := m.HATakeoverReadiness()
		if !slices.Contains(s.Blockers, HATakeoverBlockerFabricPeerUnresolved) {
			t.Fatalf("Blockers=%v, want fabric_peer_unresolved", s.Blockers)
		}
		assertBlockersInVocab16730(t, s.Blockers)
	})

	t.Run("not converged", func(t *testing.T) {
		m := healthyFabricManager15918(t, []FabricSnapshot{installable})
		m.partialOutcomeUnknown = partialFabrics
		s := m.HATakeoverReadiness()
		if !slices.Contains(s.Blockers, HATakeoverBlockerFabricNotConverged) {
			t.Fatalf("Blockers=%v, want fabric_not_converged", s.Blockers)
		}
		assertBlockersInVocab16730(t, s.Blockers)
	})
}

func TestHATakeoverReadinessUnpublishedSnapshotNotForwarding16730(t *testing.T) {
	snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 9, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	m := healthyTakeoverManager12235(t)
	m.lastSnapshot = snap
	m.publishedSnapshot = 8
	m.pendingFullSnapshotMetadata = true
	s := m.HATakeoverReadiness()
	if slices.Contains(s.Blockers, HATakeoverBlockerForwardingUnsupported) {
		t.Fatalf("Blockers=%v: unpublished generation mislabelled forwarding_unsupported", s.Blockers)
	}
	if !slices.Contains(s.Blockers, HATakeoverBlockerSnapshotUnpublished) {
		t.Fatalf("Blockers=%v, want snapshot_unpublished", s.Blockers)
	}
	assertBlockersInVocab16730(t, s.Blockers)
}

func TestHATakeoverReadinessSnapshotRetryDebtNotUnpublished16730(t *testing.T) {
	// Control: retry-debt keeps its own name and is not collapsed into
	// snapshot_unpublished or forwarding_unsupported.
	snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 9, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	m := healthyTakeoverManager12235(t)
	m.lastSnapshot = snap
	m.publishedSnapshot = 8
	m.applySnapshotOutcomeUnknown = true
	s := m.HATakeoverReadiness()
	if !slices.Contains(s.Blockers, HATakeoverBlockerSnapshotRetryDebt) {
		t.Fatalf("Blockers=%v, want snapshot_retry_debt", s.Blockers)
	}
	if slices.Contains(s.Blockers, HATakeoverBlockerSnapshotUnpublished) ||
		slices.Contains(s.Blockers, HATakeoverBlockerForwardingUnsupported) {
		t.Fatalf("Blockers=%v: retry debt mislabelled", s.Blockers)
	}
	assertBlockersInVocab16730(t, s.Blockers)
}

func TestMapHATakeoverBlocker16730(t *testing.T) {
	cases := []struct {
		reason string
		want   HATakeoverBlocker
	}{
		{"userspace helper not running", HATakeoverBlockerHelperDown},
		{"userspace helper not enabled", HATakeoverBlockerNotEnabled},
		{"userspace forwarding unsupported", HATakeoverBlockerForwardingUnsupported},
		{"userspace three-color policers require color-blind mode and a supported then action", HATakeoverBlockerForwardingUnsupported},
		{"userspace forwarding not armed", HATakeoverBlockerNotArmed},
		{"userspace dataplane not active", HATakeoverBlockerNotActive},
		{"userspace XSK liveness failed", HATakeoverBlockerXSKLivenessFailed},
		{"userspace XSK liveness not proven", HATakeoverBlockerXSKUnproven},
		{"userspace session mirror unhealthy: dial timeout", HATakeoverBlockerSessionMirrorFailed},
		{"userspace worker-session repair overflow; full session inventory replay required: x", HATakeoverBlockerRepairOverflow},
		{"userspace session inventory not reconciled for helper generation 7", HATakeoverBlockerInventoryDebtOwed},
		{"userspace snapshot retry debt outstanding (generation 9 unpublished)", HATakeoverBlockerSnapshotRetryDebt},
		{"userspace snapshot generation 9 unpublished", HATakeoverBlockerSnapshotUnpublished},
		{"userspace HA state clear pending", HATakeoverBlockerPendingHAClear},
		{"userspace HA state replay pending", HATakeoverBlockerPendingHAReplay},
		{"userspace event stream listener not bound", HATakeoverBlockerEventStreamUnbound},
		{"userspace fabric state not converged (update_fabrics outcome unknown)", HATakeoverBlockerFabricNotConverged},
		{"userspace fabric peer unresolved (no installable fabric link)", HATakeoverBlockerFabricPeerUnresolved},
		{"some future reason nobody mapped yet", HATakeoverBlockerOther},
		{"", HATakeoverBlockerOther},
	}
	for _, tc := range cases {
		if got := MapHATakeoverBlocker(tc.reason); got != tc.want {
			t.Errorf("MapHATakeoverBlocker(%q) = %q, want %q", tc.reason, got, tc.want)
		}
	}
	// Vocabulary hygiene: no duplicates, non-empty, includes other+fabric+unpublished.
	seen := map[string]bool{}
	for _, b := range HATakeoverBlockers {
		if b == "" || seen[b] {
			t.Fatalf("HATakeoverBlockers has empty/duplicate %q: %v", b, HATakeoverBlockers)
		}
		seen[b] = true
	}
	for _, want := range []HATakeoverBlocker{HATakeoverBlockerOther, HATakeoverBlockerFabricNotConverged, HATakeoverBlockerFabricPeerUnresolved, HATakeoverBlockerSnapshotUnpublished} {
		if !seen[want] {
			t.Fatalf("HATakeoverBlockers missing %q: %v", want, HATakeoverBlockers)
		}
	}
}

func assertBlockersInVocab16730(t *testing.T, blockers []string) {
	t.Helper()
	for _, b := range blockers {
		if !IsHATakeoverBlocker(b) {
			t.Fatalf("blocker %q not in shared vocabulary %v (all blockers %v)", b, HATakeoverBlockers, blockers)
		}
	}
}
