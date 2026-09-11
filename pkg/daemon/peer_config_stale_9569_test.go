package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #9569: the daemon wires the session-sync nack state into the cluster Manager,
// so the untargeted failover, the batch form and ForceSecondary can refuse a
// config-stale peer.

// With no session sync there is no push that could have failed.
func TestPeerConfigStaleWithoutSessionSyncIsNotStale_9569(t *testing.T) {
	d := &Daemon{}
	if stale, reason := d.peerConfigStale(); stale || reason != "" {
		t.Errorf("a daemon with no session sync reported a stale peer (%q)", reason)
	}
}

// The comms wiring registers the predicate beside the transfer-readiness
// callback. Without it the Manager's gate never fires in production.
func TestCommsWiringRegistersPeerConfigStale_9569(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon_ha_comms_wiring.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_ha_comms_wiring.go: %v", err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "SetPeerConfigStaleFunc" || len(call.Args) != 1 {
			return true
		}
		if arg, ok := call.Args[0].(*ast.SelectorExpr); ok && arg.Sel.Name == "peerConfigStale" {
			found = true
		}
		return true
	})
	if !found {
		t.Errorf("the comms wiring does not call cluster.SetPeerConfigStaleFunc(d.peerConfigStale), so no " +
			"untargeted failover or ForceSecondary ever consults the peer's config-apply nack")
	}
}
