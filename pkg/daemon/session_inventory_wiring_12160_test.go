package daemon

import (
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
	installed func(uint64) bool
	marked    []uint64
}

func (p *inventoryWiringSpy12160) SetSessionInventoryRequester(f func(uint64) bool) {
	p.installed = f
}

func (p *inventoryWiringSpy12160) MarkSessionInventoryReconciled(g uint64) bool {
	p.marked = append(p.marked, g)
	return true
}

func TestSessionInventoryWiringBound12160(t *testing.T) {
	var published dataplane.RuntimeDataPlane = dpuserspace.Boot()
	if _, ok := published.(interface {
		SetSessionInventoryRequester(func(uint64) bool)
	}); !ok {
		t.Errorf("published %T does not satisfy the requester assertion", published)
	}
	if _, ok := published.(interface {
		MarkSessionInventoryReconciled(uint64) bool
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
	if spy.installed(7) {
		t.Error("requester reported success on a disconnected SessionSync")
	}
	ss.OnSessionInventoryBulkReceived(9)
	if len(spy.marked) != 1 || spy.marked[0] != 9 {
		t.Errorf("completion did not reach the runtime: %v", spy.marked)
	}
	// A superseded SessionSync must not complete (request-fencing via
	// rewiring is intentionally not pinned here — the closure is replaced).
	d.sessionSync = cluster.NewSessionSync("127.0.0.1:4785", "127.0.0.1:4785", nil)
	ss.OnSessionInventoryBulkReceived(10)
	if len(spy.marked) != 1 {
		t.Errorf("stale SessionSync completion reached the runtime: %v", spy.marked)
	}
}
