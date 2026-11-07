package daemon

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #12160 wiring pin (Opus F2, #9482 class): the published userspace runtime
// must satisfy BOTH anonymous inventory interfaces the session-sync wiring
// asserts, and the wiring must actually install a requester on it. Promoted
// from the reviewer probe C. Kills M7 (reconciler assertion dropped) and M8
// (requester never installed).
type inventoryWiringSpy12160 struct {
	dataplane.RuntimeDataPlane
	installed  func(uint64, uint64) bool
	requested  [][2]uint64
	reconciled [][2]uint64
}

func (p *inventoryWiringSpy12160) SetSessionInventoryRequester(f func(uint64, uint64) bool) {
	p.installed = func(generation, requestToken uint64) bool {
		p.requested = append(p.requested, [2]uint64{generation, requestToken})
		return f(generation, requestToken)
	}
}

func (p *inventoryWiringSpy12160) MarkSessionInventoryReconciled(generation, requestToken uint64) bool {
	p.reconciled = append(p.reconciled, [2]uint64{generation, requestToken})
	return true
}

func TestSessionInventoryWiringBound12160(t *testing.T) {
	var published dataplane.RuntimeDataPlane = dpuserspace.Boot()
	if _, ok := published.(interface {
		SetSessionInventoryRequester(func(uint64, uint64) bool)
	}); !ok {
		t.Errorf("published %T does not satisfy the requester assertion", published)
	}
	if _, ok := published.(interface {
		MarkSessionInventoryReconciled(uint64, uint64) bool
	}); !ok {
		t.Errorf("published %T does not satisfy the reconciler assertion", published)
	}

	d := newWiringTestDaemon()
	spy := &inventoryWiringSpy12160{RuntimeDataPlane: published}
	d.setDataplane(spy)
	ss := cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	d.sessionSync = ss
	d.wireSessionSyncPeerCallbacks(ss)
	if spy.installed == nil {
		t.Fatal("wiring did not install a requester on the published runtime")
	}
	if spy.installed(7, 11) {
		t.Error("requester reported success on a disconnected SessionSync")
	}

	// Exercise the installed closure against a connected, queue-only
	// SessionSync so its token/generation ordering is observable.
	localConn, peerConn := net.Pipe()
	ss.InstallUnauthenticatedConnForTest(localConn)
	ss.SetConnectedForTesting(true)
	t.Cleanup(func() {
		_ = localConn.Close()
		_ = peerConn.Close()
	})
	if !spy.installed(7, 11) {
		t.Error("requester failed to forward a valid generation/token pair")
	}
	if spy.installed(7, 10) {
		t.Error("requester accepted an older token for the same generation")
	}
	if !spy.installed(7, 12) {
		t.Error("requester failed to forward a newer token for the same generation")
	}
	if !spy.installed(8, 1) {
		t.Error("requester failed to forward a newer generation")
	}
	if spy.installed(7, 13) {
		t.Error("requester accepted an older generation despite its higher token")
	}
	wantRequests := [][2]uint64{{7, 11}, {7, 11}, {7, 10}, {7, 12}, {8, 1}, {7, 13}}
	if len(spy.requested) != len(wantRequests) {
		t.Errorf("requester received %d pair(s), want %d: %v", len(spy.requested), len(wantRequests), spy.requested)
	} else {
		for i, want := range wantRequests {
			if spy.requested[i] != want {
				t.Errorf("requester pair %d = %v, want %v", i, spy.requested[i], want)
			}
		}
	}
	ss.OnSessionInventoryBulkReceived(9, 13)
	if len(spy.reconciled) != 1 || spy.reconciled[0] != ([2]uint64{9, 13}) {
		t.Errorf("completion pair did not reach the runtime: %v", spy.reconciled)
	}
	// A superseded SessionSync must not complete even with its captured pair.
	d.sessionSync = cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	ss.OnSessionInventoryBulkReceived(10, 14)
	if len(spy.reconciled) != 1 {
		t.Errorf("stale SessionSync completion reached the runtime: %v", spy.reconciled)
	}
	if spy.installed(8, 14) {
		t.Error("stale SessionSync requester reached the retired connection")
	}
}
