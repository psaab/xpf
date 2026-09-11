package userspace

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #9714 — the helper requests must carry PeerDelete exactly when the caller is
// the peer path. These run without CAP_BPF against the real session socket
// (newSyncOnlyManager9146), so they observe the wire, not a hook.

func TestAPeerBatchDeleteMarksEveryHelperRequest9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	const tenant = uint32(100007)
	_, _, _ = m.BatchDeletePeerSyncedSessionsScoped(scopedKeys9364(tenant, 1234, 1235))

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("FIXTURE: recorded %d delete requests, want 2", len(got))
	}
	for i, req := range got {
		if !req.PeerDelete {
			t.Errorf("request %d is not marked PeerDelete; the helper cannot refuse a peer delete of a "+
				"live local session", i)
		}
		if req.RoutingDomain != tenant {
			t.Errorf("request %d lost its routing domain (%d)", i, req.RoutingDomain)
		}
	}
}

func TestAnOrdinaryBatchDeleteStaysUnmarked9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	_, _ = m.BatchDeleteSessionsScoped(scopedKeys9364(100007, 1234, 1235))

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("FIXTURE: recorded %d delete requests, want 2", len(got))
	}
	for i, req := range got {
		if req.PeerDelete {
			t.Errorf("request %d of an ordinary delete (GC, clear) is marked PeerDelete; the helper would "+
				"refuse a delete it must perform", i)
		}
	}
}

func TestAMarkedSingleDeleteMarksBothHalves9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	k := key9146()
	rev := dataplane.SessionKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol}
	val := dataplane.SessionValue{RoutingDomain: 100007, ReverseKey: rev}

	m.mu.Lock()
	m.syncDeleteV4LockedMarked(k, val, true, true)
	m.mu.Unlock()
	marked := rec.all()
	if len(marked) != 2 {
		t.Fatalf("FIXTURE: recorded %d requests for a marked delete, want 2 (key + reverse)", len(marked))
	}
	for i, req := range marked {
		if !req.PeerDelete {
			t.Errorf("half %d of a peer single-key delete is not marked", i)
		}
	}

	m.mu.Lock()
	m.syncDeleteV4Locked(k, val, true)
	m.mu.Unlock()
	all := rec.all()
	if len(all) != 4 {
		t.Fatalf("FIXTURE: recorded %d requests after the unmarked delete, want 4", len(all))
	}
	for i, req := range all[2:] {
		if req.PeerDelete {
			t.Errorf("half %d of an ordinary single-key delete is marked PeerDelete", i)
		}
	}
}

func TestAPeerV6BatchDeleteMarksEveryHelperRequest9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	scoped := []dataplane.ScopedSessionKeyV6{
		{Key: dataplane.SessionKeyV6{SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(443), Protocol: 6}, RoutingDomain: 100007},
	}
	_, _, _ = m.BatchDeletePeerSyncedSessionsScopedV6(scoped)

	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("FIXTURE: recorded %d delete requests, want 1", len(got))
	}
	if !got[0].PeerDelete {
		t.Errorf("the IPv6 peer batch delete is not marked PeerDelete")
	}
}

// #9714 review F1: the helper's in-band refusal reaches the caller by key, so the
// store can keep that flow's DNAT row and the Manager its mirror row.
func TestARefusedPeerBatchDeleteIsReportedByKey9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst(peerDeleteRefusedLocalOwned)
	keys := scopedKeys9364(100007, 1234, 1235)

	_, refused, _ := m.BatchDeletePeerSyncedSessionsScoped(keys)

	if got := len(rec.all()); got != 2 {
		t.Fatalf("FIXTURE: recorded %d helper requests, want 2", got)
	}
	if len(refused) != 1 || refused[0] != keys[0] {
		t.Errorf("refused = %v, want exactly the first key: the store would delete the DNAT row of a flow "+
			"the helper kept, or keep one it removed (#9714)", refused)
	}
}

// #9714 review F1: a refused single-key peer delete does not go on to delete the
// reverse companion of the flow the helper kept.
func TestARefusedPeerSingleDeleteKeepsTheReverse9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst(peerDeleteRefusedLocalOwned)
	k := key9146()
	rev := dataplane.SessionKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol}

	m.mu.Lock()
	refused := m.syncDeleteV4LockedMarked(k, dataplane.SessionValue{RoutingDomain: 100007, ReverseKey: rev}, true, true)
	m.mu.Unlock()

	if !refused {
		t.Errorf("the helper refused the marked delete but the Manager did not report it (#9714)")
	}
	if got := len(rec.all()); got != 1 {
		t.Errorf("recorded %d helper requests, want 1: a refused forward must keep its reverse half", got)
	}
}

// #9714: an UNMARKED delete never reads an in-band answer as a peer refusal, even the
// same text, so an operator clear always goes on to the reverse half.
func TestAnUnmarkedDeleteNeverReadsAPeerRefusal9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst(peerDeleteRefusedLocalOwned)
	k := key9146()
	rev := dataplane.SessionKey{SrcIP: k.DstIP, DstIP: k.SrcIP, SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol}

	m.mu.Lock()
	refused := m.syncDeleteV4LockedMarked(k, dataplane.SessionValue{RoutingDomain: 100007, ReverseKey: rev}, true, false)
	m.mu.Unlock()

	if refused {
		t.Errorf("an unmarked delete reported a peer refusal")
	}
	if got := len(rec.all()); got != 2 {
		t.Errorf("recorded %d helper requests, want 2: an unmarked delete must still send the reverse half", got)
	}
}

// #9714 review F1: a key the helper refused keeps its BPF mirror row, and a row that
// is already gone neither counts as deleted nor stops the rest.
func TestARefusedKeyKeepsItsMirrorRow9714(t *testing.T) {
	keys := scopedKeys9364(100007, 1234, 1235, 1236)
	var attempted []dataplane.ScopedSessionKey
	deleted, err := deleteUnrefusedMirrorRows(keys, keys[:1], func(sk dataplane.ScopedSessionKey) error {
		attempted = append(attempted, sk)
		if sk == keys[1] {
			return ebpf.ErrKeyNotExist
		}
		return nil
	})
	if err != nil {
		t.Fatalf("a missing mirror row is not an error: %v", err)
	}
	if slices.Contains(attempted, keys[0]) {
		t.Errorf("the refused key's BPF mirror row was deleted; bulk export would then drop a flow the helper " +
			"kept (#9714)")
	}
	if len(attempted) != 2 || deleted != 1 {
		t.Errorf("attempted %d rows and counted %d deleted, want 2 and 1: a missing row must neither count nor "+
			"stop the rest", len(attempted), deleted)
	}
}

// #9714: only the peer-delete refusal token is a kept flow. Another in-band refusal of
// a marked delete (an ambiguous routing domain) must not be reported as one.
func TestAnAmbiguousRefusalIsNotAPeerRefusal9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	rec.refuseFirst("synced-delete-refused:ambiguous-routing-domain (5-tuple matches 2 routing instances)")

	_, refused, _ := m.BatchDeletePeerSyncedSessionsScoped(scopedKeys9364(100007, 1234))

	if len(refused) != 0 {
		t.Errorf("an ambiguous-routing-domain refusal was read as a peer refusal: %v", refused)
	}
}

// #9714 review F3: the single-key peer delete asks the helper even when the BPF mirror
// holds no row for the key, which is exactly when the store falls back to it.
func TestAPeerSingleDeleteAsksTheHelperWithoutAMirrorRow9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)

	_, _ = m.DeletePeerSyncedSession(key9146())

	got := rec.all()
	if len(got) != 1 || !got[0].PeerDelete {
		t.Errorf("recorded %d helper requests (%v): the helper must be asked, marked, even though the mirror "+
			"holds nothing for the key (#9714)", len(got), got)
	}
}
