package dataplane

import (
	"slices"
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
	dnatV4       []DNATKey
	// #9752 round 3: the forward-only mark each helper batch/single carried.
	peerBatchMarks  []bool
	peerSingleMarks []bool
	// refuseV4 names the keys the "helper" refuses as peer deletes; absentV4/V6
	// model helper-applied rows whose mirror disappeared concurrently. events
	// records the order of peer deletes and DNAT deletes; iterV4 is what a bulk
	// sweep sees.
	refuseV4 map[ScopedSessionKey]bool
	absentV4 map[ScopedSessionKey]bool
	absentV6 map[ScopedSessionKeyV6]bool
	events   []string
	iterV4   []SessionEntryV4
	// #10512: scoped single-key peer deletes received (key + domain + id).
	peerScopedV4 []scopedPeerCallV4
	peerScopedV6 []scopedPeerCallV6
}

type scopedPeerCallV4 struct {
	key    SessionKey
	domain uint32
	id     uint64
}

type scopedPeerCallV6 struct {
	key    SessionKeyV6
	domain uint32
	id     uint64
}

func (d *peerRecorderDP) BatchDeletePeerSyncedSessionsScoped(s []ScopedSessionKey, forwardOnly bool) (int, []ScopedSessionKey, error) {
	d.peerBatchV4 = append(d.peerBatchV4, s...)
	d.peerBatchMarks = append(d.peerBatchMarks, forwardOnly)
	var refused []ScopedSessionKey
	for _, k := range s {
		d.events = append(d.events, "peer-delete")
		if d.refuseV4[k] {
			refused = append(refused, k)
		}
	}
	return len(s) - len(refused), refused, nil
}

func (d *peerRecorderDP) BatchDeletePeerSyncedSessionsScopedV6(s []ScopedSessionKeyV6, forwardOnly bool) (int, []ScopedSessionKeyV6, error) {
	d.peerBatchV6 = append(d.peerBatchV6, s...)
	return len(s), nil, nil
}
func (d *peerRecorderDP) BatchDeletePeerSyncedSessionsExactScoped(s []ScopedSessionKey, forwardOnly bool) ([]ScopedSessionKey, []ScopedSessionKey, error) {
	d.peerBatchV4 = append(d.peerBatchV4, s...)
	d.peerBatchMarks = append(d.peerBatchMarks, forwardOnly)
	var deleted, applied []ScopedSessionKey
	for _, k := range s {
		d.events = append(d.events, "peer-delete")
		if d.refuseV4[k] {
			continue
		}
		applied = append(applied, k)
		if !d.absentV4[k] {
			deleted = append(deleted, k)
		}
	}
	return deleted, applied, nil
}

func (d *peerRecorderDP) BatchDeletePeerSyncedSessionsExactScopedV6(s []ScopedSessionKeyV6, forwardOnly bool) ([]ScopedSessionKeyV6, []ScopedSessionKeyV6, error) {
	d.peerBatchV6 = append(d.peerBatchV6, s...)
	applied := append([]ScopedSessionKeyV6(nil), s...)
	deleted := make([]ScopedSessionKeyV6, 0, len(s))
	for _, k := range s {
		if !d.absentV6[k] {
			deleted = append(deleted, k)
		}
	}
	return deleted, applied, nil
}

func (d *peerRecorderDP) DeletePeerSyncedSession(k SessionKey, forwardOnly bool) (bool, error) {
	d.peerSingleV4 = append(d.peerSingleV4, k)
	d.peerSingleMarks = append(d.peerSingleMarks, forwardOnly)
	return false, nil
}

func (d *peerRecorderDP) DeletePeerSyncedSessionV6(SessionKeyV6, bool) (bool, error) {
	return false, nil
}

func (d *peerRecorderDP) DeletePeerSyncedSessionScoped(k SessionKey, domain uint32, expectedID uint64) (bool, error) {
	d.peerScopedV4 = append(d.peerScopedV4, scopedPeerCallV4{key: k, domain: domain, id: expectedID})
	return false, nil
}

func (d *peerRecorderDP) DeletePeerSyncedSessionScopedV6(k SessionKeyV6, domain uint32, expectedID uint64) (bool, error) {
	d.peerScopedV6 = append(d.peerScopedV6, scopedPeerCallV6{key: k, domain: domain, id: expectedID})
	return false, nil
}

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

func (d *peerRecorderDP) GetPersistentNAT() *PersistentNATTable { return nil }

func (d *peerRecorderDP) DeleteDNATEntry(k DNATKey) error {
	d.dnatV4 = append(d.dnatV4, k)
	d.events = append(d.events, "dnat-delete")
	return nil
}

func (d *peerRecorderDP) BatchIterateSessions(fn func(SessionKey, SessionValue) bool) error {
	for _, entry := range d.iterV4 {
		if !fn(entry.Key, entry.Value) {
			break
		}
	}
	return nil
}

func (d *peerRecorderDP) BatchIterateSessionsV6(func(SessionKeyV6, SessionValueV6) bool) error {
	return nil
}

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
	if _, err := store.DeleteBatchKnownV4(knownEntry9714(), DeleteReasonClusterStale, false); err != nil {
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

// TestExactPeerDeleteExcludesAbsentMirrorRowsKeepsAppliedCompanions pins the
// distinction between a helper-applied forward and a mirror row that was
// already absent (#10598). The absent forward is still helper-applied, so its
// reverse companion must be retired, but only the actually deleted mirror key
// belongs in the outward exact set.
func TestExactPeerDeleteExcludesAbsentMirrorRowsKeepsAppliedCompanions(t *testing.T) {
	forward0, forward1 := key9364(1234), key9364(1235)
	reverse0, reverse1 := key9364(4321), key9364(4322)
	entries := []SessionEntryV4{
		{Key: forward0, Value: SessionValue{RoutingDomain: 100007, ReverseKey: reverse0}},
		{Key: forward1, Value: SessionValue{RoutingDomain: 100007, ReverseKey: reverse1}},
	}
	dp := &peerRecorderDP{
		absentV4: map[ScopedSessionKey]bool{{
			Key:           forward1,
			RoutingDomain: 100007,
		}: true},
	}
	store := dataPlaneSessionStore{dp: dp}
	exact, err := store.DeleteBatchKnownExactV4(entries, DeleteReasonClusterStale, false)
	if err != nil {
		t.Fatalf("DeleteBatchKnownExactV4: %v", err)
	}
	if len(exact) != 1 || exact[0] != forward0 {
		t.Fatalf("exact keys = %+v, want [%+v]", exact, forward0)
	}
	if len(dp.peerBatchV4) != 4 {
		t.Fatalf("peer batch keys = %+v, want two forwards plus two applied companions", dp.peerBatchV4)
	}
	if dp.peerBatchV4[2].Key != reverse0 || dp.peerBatchV4[3].Key != reverse1 {
		t.Fatalf("companion batch keys = %+v, want [%+v %+v]", dp.peerBatchV4[2:], reverse0, reverse1)
	}
}

// TestExactPeerDeleteExcludesAbsentMirrorRowsKeepsAppliedCompanionsV6 is the
// IPv6 twin of the absent-vs-applied companion regression.
func TestExactPeerDeleteExcludesAbsentMirrorRowsKeepsAppliedCompanionsV6(t *testing.T) {
	forward0 := SessionKeyV6{SrcIP: [16]byte{0x20, 1}, DstIP: [16]byte{0x30, 1}, SrcPort: 1234, DstPort: 80, Protocol: 6}
	forward1 := SessionKeyV6{SrcIP: [16]byte{0x20, 2}, DstIP: [16]byte{0x30, 2}, SrcPort: 1235, DstPort: 80, Protocol: 6}
	reverse0 := SessionKeyV6{SrcIP: [16]byte{0x30, 1}, DstIP: [16]byte{0x20, 1}, SrcPort: 80, DstPort: 1234, Protocol: 6}
	reverse1 := SessionKeyV6{SrcIP: [16]byte{0x30, 2}, DstIP: [16]byte{0x20, 2}, SrcPort: 80, DstPort: 1235, Protocol: 6}
	entries := []SessionEntryV6{
		{Key: forward0, Value: SessionValueV6{RoutingDomain: 100007, ReverseKey: reverse0}},
		{Key: forward1, Value: SessionValueV6{RoutingDomain: 100007, ReverseKey: reverse1}},
	}
	dp := &peerRecorderDP{
		absentV6: map[ScopedSessionKeyV6]bool{{
			Key:           forward1,
			RoutingDomain: 100007,
		}: true},
	}
	store := dataPlaneSessionStore{dp: dp}
	exact, err := store.DeleteBatchKnownExactV6(entries, DeleteReasonClusterStale, false)
	if err != nil {
		t.Fatalf("DeleteBatchKnownExactV6: %v", err)
	}
	if len(exact) != 1 || exact[0] != forward0 {
		t.Fatalf("exact v6 keys = %+v, want [%+v]", exact, forward0)
	}
	if len(dp.peerBatchV6) != 4 {
		t.Fatalf("v6 peer batch keys = %+v, want two forwards plus two applied companions", dp.peerBatchV6)
	}
	if dp.peerBatchV6[2].Key != reverse0 || dp.peerBatchV6[3].Key != reverse1 {
		t.Fatalf("v6 companion batch keys = %+v, want [%+v %+v]", dp.peerBatchV6[2:], reverse0, reverse1)
	}
}

// Every other reason keeps today's unmarked path.
func TestAGCExpiryDeleteStaysUnmarked9714(t *testing.T) {
	dp := &peerRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	if _, err := store.DeleteBatchKnownV4(knownEntry9714(), DeleteReasonGCExpired, false); err != nil {
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
	if err := store.DeleteWithCompanionsV4(key9364(1234), DeleteReasonClusterStale, false); err != nil {
		t.Fatalf("DeleteWithCompanionsV4 cluster-stale: %v", err)
	}
	if len(dp.peerSingleV4) != 1 || len(dp.singleV4) != 0 {
		t.Errorf("a cluster-stale delete of a key the mirror no longer holds must use the peer single-key "+
			"delete; peer=%d unmarked=%d", len(dp.peerSingleV4), len(dp.singleV4))
	}
	if err := store.DeleteWithCompanionsV4(key9364(1235), DeleteReasonGCExpired, false); err != nil {
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
	if _, err := store.DeleteBatchKnownV6(entries, DeleteReasonClusterStale, false); err != nil {
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
	if _, err := store.DeleteBatchKnownV4(knownEntry9714(), DeleteReasonClusterStale, false); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp.scopedV4) != 2 {
		t.Errorf("without the peer capability a cluster-stale delete must fall back to the scoped path; got %d keys",
			len(dp.scopedV4))
	}
}

func snatEntry9714() []SessionEntryV4 {
	return []SessionEntryV4{{
		Key: key9364(1234),
		Value: SessionValue{
			RoutingDomain: 100007,
			ReverseKey:    key9364(4321),
			Flags:         SessFlagSNAT,
		},
	}}
}

// #9714 review F1: a forward key the helper refuses keeps everything this node holds
// for it. Its reverse companion is not deleted, and neither is its reverse-SNAT DNAT
// row, which the unmarked path deletes before the helper is ever asked.
func TestARefusedPeerDeleteKeepsItsReverseAndDNATRow9714(t *testing.T) {
	entries := snatEntry9714()
	forward := ScopedSessionKey{Key: entries[0].Key, RoutingDomain: entries[0].Value.RoutingDomain}
	dp := &peerRecorderDP{refuseV4: map[ScopedSessionKey]bool{forward: true}}
	store := dataPlaneSessionStore{dp: dp}

	if _, err := store.DeleteBatchKnownV4(entries, DeleteReasonClusterStale, false); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	if len(dp.peerBatchV4) != 1 || dp.peerBatchV4[0] != forward {
		t.Errorf("a refused forward still had its reverse companion deleted: peer deletes %v", dp.peerBatchV4)
	}
	if len(dp.dnatV4) != 0 {
		t.Errorf("a refused peer delete still deleted the flow's reverse-SNAT DNAT row %v; its replies lose "+
			"their steering while the helper keeps the session (#9714)", dp.dnatV4)
	}
}

// #9714 review F1: an applied peer delete removes the DNAT row only AFTER the helper
// applied the forward and reverse deletes.
func TestAnAppliedPeerDeleteDeletesTheDNATRowAfterTheHelper9714(t *testing.T) {
	dp := &peerRecorderDP{}
	store := dataPlaneSessionStore{dp: dp}
	if _, err := store.DeleteBatchKnownV4(snatEntry9714(), DeleteReasonClusterStale, false); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}
	want := []string{"peer-delete", "peer-delete", "dnat-delete"}
	if !slices.Equal(dp.events, want) {
		t.Errorf("events %v, want %v: the DNAT row must go only after the helper applied the forward and "+
			"reverse deletes (#9714)", dp.events, want)
	}
}

// #9714 review F7: bulk stale reconciliation deletes on the PEER's authority too, and
// ReconcileClusterBulk defaults an empty reason to cluster-stale.
func TestABulkReconcileDeletesAsAPeer9714(t *testing.T) {
	dp := &peerRecorderDP{iterV4: knownEntry9714()}
	store := dataPlaneSessionStore{dp: dp}
	result, err := store.ReconcileClusterBulk(ClusterBulkReconcileInput{
		ReceivedV4:     map[SessionKey]struct{}{},
		ReceivedV6:     map[SessionKeyV6]struct{}{},
		ShouldSyncZone: func(uint16) bool { return false },
	})
	if err != nil {
		t.Fatalf("ReconcileClusterBulk: %v", err)
	}
	if result.StaleV4 != 1 {
		t.Fatalf("FIXTURE: stale v4 = %d, want 1", result.StaleV4)
	}
	if len(dp.peerBatchV4) == 0 || len(dp.scopedV4) != 0 {
		t.Errorf("a bulk-reconcile delete did not reach the dataplane as a PEER delete: peer=%v unmarked=%v",
			dp.peerBatchV4, dp.scopedV4)
	}
}
