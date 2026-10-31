package daemon

import (
	"testing"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18620 (review of #18638, seat T): the userspace manager's release hook
// fires when an acknowledged helper inventory drops an RG from the
// connected-row hold. The daemon must wire it, and it must republish the
// routes-only snapshot so the RG's connected rows leave the helper FIB. That
// covers the paths that schedule no republish of their own, such as the
// reconcile retry of a failed rg_active=false write.
func TestHelperReleaseHookRepublishesConnectedRows18620(t *testing.T) {
	dp := &fakeOverlayDP{callsChanged: make(chan struct{}, 2)}
	d := routeListenerBumpDaemon11565(t, dp)
	mgr := dpuserspace.New()
	d.wireUserspaceRGRouteHooks(mgr)

	mgr.ReleaseHeldRGsForTesting([]int{1})

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for range 2 {
		select {
		case <-dp.callsChanged:
		case <-timer.C:
			t.Fatalf("the release hook did not republish; calls = %v", dp.callsSnapshot())
		}
	}
	requireRouteListenerCalls11565(t, dp.callsSnapshot(), "publish", "bump")
}
