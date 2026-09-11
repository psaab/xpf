package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9714 — the helper requests must carry PeerDelete exactly when the caller is
// the peer path. These run without CAP_BPF against the real session socket
// (newSyncOnlyManager9146), so they observe the wire, not a hook.

func TestAPeerBatchDeleteMarksEveryHelperRequest9714(t *testing.T) {
	m, rec := newSyncOnlyManager9146(t)
	const tenant = uint32(100007)
	_, _ = m.BatchDeletePeerSyncedSessionsScoped(scopedKeys9364(tenant, 1234, 1235))

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
	_, _ = m.BatchDeletePeerSyncedSessionsScopedV6(scoped)

	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("FIXTURE: recorded %d delete requests, want 1", len(got))
	}
	if !got[0].PeerDelete {
		t.Errorf("the IPv6 peer batch delete is not marked PeerDelete")
	}
}
