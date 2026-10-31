package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
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

// Review of #18638 (seat T): the apply-time wiring site must install the
// release hook too. A userspace manager recreated by an apply would otherwise
// come back without it, and a released RG's connected rows would stay until
// some unrelated publish. The site is inside applyDataplaneAndHACore, which no
// cell can drive to a real userspace manager, so this pins it the way
// TestDeferredPublishFailureCallbackIsWired12235 pins its neighbour: the
// function body must call d.wireUserspaceRGRouteHooks(mgr). The helper's own
// behaviour is pinned by TestHelperReleaseHookRepublishesConnectedRows18620.
func TestApplyTimeWiringInstallsReleaseHook18620(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon_apply_dataplane.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_apply_dataplane.go: %v", err)
	}
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "applyDataplaneAndHACore" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "wireUserspaceRGRouteHooks" {
				return true
			}
			if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == "d" {
				found = true
			}
			return true
		})
	}
	if !found {
		t.Fatal("applyDataplaneAndHACore does not call d.wireUserspaceRGRouteHooks: an apply-recreated " +
			"userspace manager would come back without the #18620 release hook")
	}
}
