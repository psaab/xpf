package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9364 — the BATCH session-delete path stripped the routing domain, so the
// conntrack GC's deletes went out as bare 5-tuples and hit #8636's
// ambiguous-routing-domain refusal on a standby.
//
// #9146 fixed the SINGULAR delete. This is the half that matters more: the batch
// path is what retires sessions continuously on every running box
// (`pkg/conntrack/gc.go` expiry, `pkg/daemon/daemon_policy_invalidate.go`), while
// the singular path serves the operator clears. So the fix that landed covered
// the operator paths and left the steady-state one bare.
//
// The consequence is worse on a standby than the #8636 acceptance assumed. #8636
// accepted refusing an ambiguous delete because "a refused delete leaks for ONE
// PACKET, not until idle timeout" — #8356 re-derives zone policy on the
// established-session hit path. That reasoning needs a caller that RECEIVES
// packets. A synced session on a standby receives none and nothing re-judges it,
// so it leaks to idle timeout and is promoted on failover.
//
// THESE CELLS RUN WITHOUT CAP_BPF, deliberately. Every BPF-backed harness in this
// package skips when `RemoveMemlock` is denied (#9337: 42 registered guards, and
// the privileged CI leg they defer to does not exist), and a cell that SKIPS
// scores every mutation as SURVIVED — the reading that argues for deleting a
// guard doing its job. `newSyncOnlyManager9146` touches no map, and the wire
// contract is the whole of this issue, so these observe the real requests.

func scopedKeys9364(domain uint32, ports ...uint16) []dataplane.ScopedSessionKey {
	out := make([]dataplane.ScopedSessionKey, 0, len(ports))
	for _, p := range ports {
		k := key9146()
		k.SrcPort = hostToNetwork16(p)
		out = append(out, dataplane.ScopedSessionKey{Key: k, RoutingDomain: domain})
	}
	return out
}

// THE ACCEPTANCE CRITERION: a batch delete for tenant sessions names the domain.
func TestBatchDeleteNamesTheInstalledRoutingDomain9364(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	const tenant = uint32(100007)

	if err := m.deleteHelperSessionsScopedV4(scopedKeys9364(tenant, 1234, 1235, 1236)); err != nil {
		t.Fatalf("deleteHelperSessionsScopedV4: %v", err)
	}

	got := rec.all()
	if len(got) != 3 {
		t.Fatalf("FIXTURE FAILED: recorded %d delete requests, want 3 — the cell cannot "+
			"observe the domain if the requests never reached the socket", len(got))
	}
	for i, req := range got {
		if req.Operation != "delete" {
			t.Errorf("request %d operation = %q, want delete", i, req.Operation)
		}
		if req.RoutingDomain != tenant {
			t.Errorf("#9364: batch delete %d carried routing_domain=%d, want %d. A bare "+
				"delete makes the helper PROBE every routing instance for the 5-tuple, and "+
				"two tenants sharing that tuple make it REFUSE (#8636) — on a standby the "+
				"session then leaks to idle timeout and is promoted on failover",
				i, req.RoutingDomain, tenant)
		}
	}
}

// LOAD-BEARING CONTROL #1 — the delete that must still SUCCEED.
//
// "Name a domain on every batch delete" is satisfiable by always sending some
// non-zero value, which would break every non-VRF deployment: the helper would
// look for a row in a routing instance that does not hold it and the delete would
// land nowhere. A default-instance batch must still carry 0.
func TestDefaultInstanceBatchDeleteStillCarriesDomainZero9364(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)

	if err := m.deleteHelperSessionsScopedV4(scopedKeys9364(0, 1234, 1235)); err != nil {
		t.Fatalf("deleteHelperSessionsScopedV4: %v", err)
	}

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("FIXTURE FAILED: recorded %d requests, want 2", len(got))
	}
	for i, req := range got {
		if req.RoutingDomain != 0 {
			t.Errorf("#9364: a default-instance batch delete carried routing_domain=%d, "+
				"want 0 — request %d is now addressed to an instance that does not hold "+
				"the row, so the delete lands nowhere", req.RoutingDomain, i)
		}
	}
}

// LOAD-BEARING CONTROL #2 — `ClearAllSessions` must STAY bare.
//
// It has no values by construction and is exactly the caller #8636's refusal was
// designed for: an operator `clear security flow session all` that names an
// ambiguous tuple should be refused rather than guessed at. The bare
// `deleteHelperSessionsV4` entry point is what that path uses, and it must keep
// producing domain-0 requests even though it now shares one chunking
// implementation with the scoped form.
func TestBareHelperDeletePathStillSendsDomainZero9364(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)

	k1, k2 := key9146(), key9146()
	k2.SrcPort = hostToNetwork16(9999)
	if err := m.deleteHelperSessionsV4([]dataplane.SessionKey{k1, k2}); err != nil {
		t.Fatalf("deleteHelperSessionsV4: %v", err)
	}

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("FIXTURE FAILED: recorded %d requests, want 2", len(got))
	}
	for i, req := range got {
		if req.RoutingDomain != 0 {
			t.Errorf("#9364: the BARE delete path (ClearAllSessions) carried "+
				"routing_domain=%d on request %d, want 0. That path has no values to "+
				"derive a domain from, and inventing one would address the delete to an "+
				"instance nobody asked for", req.RoutingDomain, i)
		}
	}
}

// The V6 twin of the acceptance criterion. Not a copy for symmetry's sake: V6 has
// its own `deleteScopeValV6` derivation and its own request builder, and #9146
// wrote its V6 scope inline rather than through a shared helper — so the two
// families could drift.
func TestBatchDeleteNamesTheRoutingDomainV6_9364(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	const tenant = uint32(100008)

	k := dataplane.SessionKeyV6{Protocol: 6, SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(443)}
	k.SrcIP[0], k.DstIP[0] = 0x20, 0x20
	scoped := []dataplane.ScopedSessionKeyV6{{Key: k, RoutingDomain: tenant}}

	if err := m.deleteHelperSessionsScopedV6(scoped); err != nil {
		t.Fatalf("deleteHelperSessionsScopedV6: %v", err)
	}

	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("FIXTURE FAILED: recorded %d requests, want 1", len(got))
	}
	if got[0].RoutingDomain != tenant {
		t.Errorf("#9364 V6: batch delete carried routing_domain=%d, want %d",
			got[0].RoutingDomain, tenant)
	}
}

// The two scope derivations must agree. `deleteScopeVal` and `deleteScopeValV6`
// are separate functions over separate value types, and #9364 gave the V6 side a
// named helper precisely because it had been written inline; a cell keeps them
// from drifting apart on the one rule that matters — nil at 0, domain otherwise.
func TestBothScopeDerivationsAgree9364(t *testing.T) {
	if deleteScopeVal(0) != nil {
		t.Error("deleteScopeVal(0) must be nil, so the request is built exactly as it was " +
			"before #9146 for a deployment with no routing-instance membership")
	}
	if deleteScopeValV6(0) != nil {
		t.Error("deleteScopeValV6(0) must be nil, for the same reason")
	}
	if v := deleteScopeVal(7); v == nil || v.RoutingDomain != 7 {
		t.Errorf("deleteScopeVal(7) = %+v, want a value naming domain 7", v)
	}
	if v := deleteScopeValV6(7); v == nil || v.RoutingDomain != 7 {
		t.Errorf("deleteScopeValV6(7) = %+v, want a value naming domain 7", v)
	}
}
