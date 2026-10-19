package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #14965 — the scoped singular delete must reach the helper wire with the
// caller's routing domain and PurgeTunnelVariants intact, without probing
// the BPF mirror (newSyncOnlyManager9146 has no loaded shim; a mirror probe
// would error/behave differently — the wire request is the evidence).
// Pre-fix Manager had no DeleteSessionScoped at all: the store's per-key
// retry fell back to bare DeleteSession, which re-derives scope from the
// surviving mirror row and never sets the purge flag.
func TestDeleteSessionScopedCarriesDomainAndPurge14965(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	key := key9146()
	key.Protocol = 47
	sk := dataplane.ScopedSessionKey{Key: key, RoutingDomain: 100007, PurgeTunnelVariants: true}
	if err := m.DeleteSessionScoped(sk); err != nil {
		t.Fatalf("DeleteSessionScoped: %v", err)
	}
	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(got))
	}
	if got[0].RoutingDomain != 100007 {
		t.Errorf("wire routing_domain = %d, want 100007 (caller scope, not a mirror probe)", got[0].RoutingDomain)
	}
	if !got[0].PurgeTunnelVariants {
		t.Error("wire request lost PurgeTunnelVariants; helper exact-matches and the GRE0 row leaks")
	}
	if got[0].Operation != "mirror_delete" {
		t.Errorf("operation = %q, want mirror_delete", got[0].Operation)
	}
}

// Control: an unflagged default-instance scoped delete stays bit-identical
// to the bare delete (domain 0, no purge widening).
func TestDeleteSessionScopedDefaultInstanceStaysBare14965(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	sk := dataplane.ScopedSessionKey{Key: key9146()}
	if err := m.DeleteSessionScoped(sk); err != nil {
		t.Fatalf("DeleteSessionScoped: %v", err)
	}
	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(got))
	}
	if got[0].RoutingDomain != 0 || got[0].PurgeTunnelVariants {
		t.Errorf("default delete = {domain:%d purge:%v}, want {0 false} — must not invent scope or widen to a wildcard",
			got[0].RoutingDomain, got[0].PurgeTunnelVariants)
	}
}

// V6 twin: V6 has its own builder and could drift independently.
func TestDeleteSessionScopedV6CarriesDomainAndPurge14965(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	key := dataplane.SessionKeyV6{Protocol: 47, SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(443)}
	sk := dataplane.ScopedSessionKeyV6{Key: key, RoutingDomain: 100008, PurgeTunnelVariants: true}
	if err := m.DeleteSessionScopedV6(sk); err != nil {
		t.Fatalf("DeleteSessionScopedV6: %v", err)
	}
	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("recorded %d V6 requests, want 1", len(got))
	}
	if got[0].RoutingDomain != 100008 {
		t.Errorf("V6 wire routing_domain = %d, want 100008", got[0].RoutingDomain)
	}
	if !got[0].PurgeTunnelVariants {
		t.Error("V6 wire request lost PurgeTunnelVariants")
	}
}
