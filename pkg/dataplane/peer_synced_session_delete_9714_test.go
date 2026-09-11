package dataplane

import (
	"testing"

	"github.com/cilium/ebpf"
)

// #9714 — BIND THE WIRING at the store, the way the #9364 cells do: drive the
// entry points the cluster apply calls and record what reaches the dataplane.
//
// A cluster-stale delete (the peer's delete and the #6368 install rollback) must
// reach the dataplane through the PEER capability, so the helper request is
// marked and the helper can refuse it for a live local session. Every other
// reason must keep today's path. A capability miss falls back silently, so the
// negative arms matter as much as the positive ones.

// peerRecorderDP implements the optional peer capability and records every
// delete path the store can take.
type peerRecorderDP struct {
	DataPlane
	peerBatchV4  []ScopedSessionKey
	peerBatchV6  []ScopedSessionKeyV6
	scopedV4     []ScopedSessionKey
	scopedV6     []ScopedSessionKeyV6
	peerSingleV4 []SessionKey
	singleV4     []SessionKey
}

func (d *peerRecorderDP) BatchDeletePeerSyncedSessionsScoped(s []ScopedSessionKey) (int, error) {
	d.peerBatchV4 = append(d.peerBatchV4, s...)
	return len(s), nil
}

func (d *peerRecorderDP) BatchDeletePeerSyncedSessionsScopedV6(s []ScopedSessionKeyV6) (int, error) {
	d.peerBatchV6 = append(d.peerBatchV6, s...)
	return len(s), nil
}

func (d *peerRecorderDP) DeletePeerSyncedSession(k SessionKey) error {
	d.peerSingleV4 = append(d.peerSingleV4, k)
	return nil
}

func (d *peerRecorderDP) DeletePeerSyncedSessionV6(SessionKeyV6) error { return nil }

func (d *peerRecorderDP) BatchDeleteSessionsScoped(s []ScopedSessionKey) (int, error) {
	d.scopedV4 = append(d.scopedV4, s...)
	return len(s), nil
}

func (d *peerRecorderDP) BatchDeleteSessionsScopedV6(s []ScopedSessionKeyV6) (int, error) {
	d.scopedV6 = append(d.scopedV6, s...)
	return len(s), nil
}

func (d *peerRecorderDP) DeleteSession(k SessionKey) error {
	d.singleV4 = append(d.singleV4, k)
	return nil
}

func (d *peerRecorderDP) GetSessionV4(SessionKey) (SessionValue, error) {
	return SessionValue{}, ebpf.ErrKeyNotExist
}

func (d *peerRecorderDP) DeleteDNATEntry(DNATKey) error     { return nil }
func (d *peerRecorderDP) DeleteDNATEntryV6(DNATKeyV6) error { return nil }

func knownEntry9714() []SessionEntryV4 {
	return []SessionEntryV4{{
		Key:   key9364(1234),
		Value: SessionValue{RoutingDomain: 100007, ReverseKey: key9364(4321)},
	}}
}

// THE ACCEPTANCE CRITERION at the store: a cluster-stale delete of a known entry
// reaches the dataplane only through the peer capability, forward AND reverse.
func TestAClusterStaleDeleteIsMarkedAsAPeerDelete9714(t *testing.T) {
	dp := &peerRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	if _, err := store.DeleteBatchKnownV4(knownEntry9714(), DeleteReasonClusterStale); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp.peerBatchV4) != 2 {
		t.Errorf("a cluster-stale delete must reach the dataplane as a PEER delete for the forward key "+
			"and its reverse companion; peer batch got %d keys", len(dp.peerBatchV4))
	}
	if len(dp.scopedV4) != 0 {
		t.Errorf("a cluster-stale delete also took the unmarked scoped path (%d keys); the helper then "+
			"cannot tell it from an operator clear", len(dp.scopedV4))
	}
}

// Every other reason keeps today's unmarked path.
func TestAGCExpiryDeleteStaysUnmarked9714(t *testing.T) {
	dp := &peerRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	if _, err := store.DeleteBatchKnownV4(knownEntry9714(), DeleteReasonGCExpired); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp.peerBatchV4) != 0 {
		t.Errorf("a GC-expiry delete was marked as a peer delete (%d keys); the helper would refuse a "+
			"local delete it must perform", len(dp.peerBatchV4))
	}
	if len(dp.scopedV4) != 2 {
		t.Errorf("a GC-expiry delete must keep the scoped path; got %d keys", len(dp.scopedV4))
	}
}

// The not-found fallback carries the mark too, and only for cluster-stale.
func TestTheNotFoundFallbackIsMarkedOnlyForClusterStale9714(t *testing.T) {
	dp := &peerRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	if err := store.DeleteWithCompanionsV4(key9364(1234), DeleteReasonClusterStale); err != nil {
		t.Fatalf("DeleteWithCompanionsV4 cluster-stale: %v", err)
	}
	if len(dp.peerSingleV4) != 1 || len(dp.singleV4) != 0 {
		t.Errorf("a cluster-stale delete of a key the mirror no longer holds must use the peer single-key "+
			"delete; peer=%d unmarked=%d", len(dp.peerSingleV4), len(dp.singleV4))
	}
	if err := store.DeleteWithCompanionsV4(key9364(1235), DeleteReasonGCExpired); err != nil {
		t.Fatalf("DeleteWithCompanionsV4 gc: %v", err)
	}
	if len(dp.peerSingleV4) != 1 || len(dp.singleV4) != 1 {
		t.Errorf("a GC delete of a missing key must use the unmarked single-key delete; peer=%d unmarked=%d",
			len(dp.peerSingleV4), len(dp.singleV4))
	}
}

// The IPv6 batch path carries the mark the same way.
func TestAClusterStaleV6DeleteIsMarkedAsAPeerDelete9714(t *testing.T) {
	dp := &peerRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	entries := []SessionEntryV6{{
		Key:   SessionKeyV6{SrcPort: 1234, DstPort: 443, Protocol: 6},
		Value: SessionValueV6{RoutingDomain: 100007, ReverseKey: SessionKeyV6{SrcPort: 443, DstPort: 1234, Protocol: 6}},
	}}
	if _, err := store.DeleteBatchKnownV6(entries, DeleteReasonClusterStale); err != nil {
		t.Fatalf("DeleteBatchKnownV6: %v", err)
	}
	if len(dp.peerBatchV6) != 2 || len(dp.scopedV6) != 0 {
		t.Errorf("a cluster-stale IPv6 delete must be a peer delete for both halves; peer=%d unmarked=%d",
			len(dp.peerBatchV6), len(dp.scopedV6))
	}
}

// Control: a dataplane WITHOUT the capability still deletes on cluster-stale
// (today's scoped path), so the capability never makes a delete disappear.
func TestADataplaneWithoutThePeerCapabilityStillDeletes9714(t *testing.T) {
	dp := &domainRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	if _, err := store.DeleteBatchKnownV4(knownEntry9714(), DeleteReasonClusterStale); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp.scopedV4) != 2 {
		t.Errorf("without the peer capability a cluster-stale delete must fall back to the scoped path; got %d keys",
			len(dp.scopedV4))
	}
}
