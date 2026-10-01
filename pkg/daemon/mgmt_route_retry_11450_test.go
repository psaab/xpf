package daemon

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestMgmtRouteFailureRetriesWithoutNewEvents11450(t *testing.T) {
	d := daemonWithActiveConfig9693(t)

	policyRuns := 0
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevVRF, prevMgmt := vrfMissTerminatorReconcileFn, mgmtVRFRouteReconcileFn
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error {
		policyRuns++
		return nil
	}
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error { return nil }
	vrfMissTerminatorReconcileFn = func(*Daemon) error { return nil }
	attempts := 0
	transient := errors.New("injected RouteReplace/list failure")
	mgmtVRFRouteReconcileFn = func(*Daemon) error {
		attempts++
		if attempts == 1 {
			return transient
		}
		return nil
	}
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		vrfMissTerminatorReconcileFn, mgmtVRFRouteReconcileFn = prevVRF, prevMgmt
	})

	// This is the management-only DHCP/boot failure: no later lease or config
	// event occurs to happen to retry it.
	d.noteMgmtRouteReconcileResult(transient)
	if owed, failures, last := d.RoutingReconcileDebt(); !owed || failures != 1 || last == "" {
		t.Fatalf("initial failure must latch management route debt: owed=%v failures=%d last=%q", owed, failures, last)
	}

	d.reassertRoutingReconcileOnce(context.Background())
	if attempts != 1 {
		t.Fatalf("the 30s routing retry owner did not retry the failed management routes: attempts=%d", attempts)
	}
	if owed, failures, last := d.RoutingReconcileDebt(); !owed || failures != 2 || last == "" {
		t.Fatalf("a failed retry must retain debt and count the failure: owed=%v failures=%d last=%q", owed, failures, last)
	}
	if policyRuns != 0 {
		t.Fatalf("management-route debt must not rewrite unrelated policy-routing state (runs=%d)", policyRuns)
	}

	d.reassertRoutingReconcileOnce(context.Background())
	if attempts != 2 {
		t.Fatalf("the owner did not retry management routes after the transient failure: attempts=%d", attempts)
	}
	if owed, failures, _ := d.RoutingReconcileDebt(); owed || failures != 2 {
		t.Fatalf("a successful retry must discharge only the management debt: owed=%v failures=%d", owed, failures)
	}
	d.reassertRoutingReconcileOnce(context.Background())
	if attempts != 2 || policyRuns != 0 {
		t.Fatalf("the owner kept doing work after route debt cleared: attempts=%d policy-runs=%d", attempts, policyRuns)
	}
}

func TestMgmtRouteDebtDoesNotDischargeOtherRoutingDebt11450(t *testing.T) {
	d := &Daemon{}
	routingErr := errors.New("policy-routing failure")
	mgmtRouteErr := errors.New("management-route failure")
	d.noteRoutingReconcileResult(routingErr)
	d.noteMgmtRouteReconcileResult(mgmtRouteErr)
	if owed, failures, last := d.RoutingReconcileDebt(); !owed || failures != 2 || last != mgmtRouteErr.Error() {
		t.Fatalf("latest owed error must be reported: owed=%v failures=%d last=%q", owed, failures, last)
	}

	d.noteMgmtRouteReconcileResult(nil)
	if owed, failures, last := d.RoutingReconcileDebt(); !owed || failures != 2 || last != routingErr.Error() {
		t.Fatalf("clearing management routes must retain generic routing debt: owed=%v failures=%d last=%q",
			owed, failures, last)
	}
	d.noteRoutingReconcileResult(nil)
	if owed, failures, last := d.RoutingReconcileDebt(); owed || failures != 2 || last != "" {
		t.Fatalf("clearing generic routes must discharge aggregate debt: owed=%v failures=%d last=%q",
			owed, failures, last)
	}
}

func TestMgmtRouteRetryWiring11450(t *testing.T) {
	calls := func(file, function string) map[string][]token.Pos {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		out := make(map[string][]token.Pos)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != function || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch callee := call.Fun.(type) {
				case *ast.SelectorExpr:
					out[callee.Sel.Name] = append(out[callee.Sel.Name], call.Pos())
				case *ast.Ident:
					out[callee.Name] = append(out[callee.Name], call.Pos())
				}
				return true
			})
		}
		return out
	}
	requireBefore := func(calls map[string][]token.Pos, before, after, context string) {
		t.Helper()
		if len(calls[before]) == 0 || len(calls[after]) == 0 ||
			calls[before][0] >= calls[after][0] {
			t.Errorf("%s must call %s before %s", context, before, after)
		}
	}

	apply := calls("daemon_apply.go", "applyConfigLocked")
	requireBefore(apply, "applyMgmtVRFRoutes", "noteMgmtRouteReconcileResult",
		"full config apply")

	dhcp := calls("daemon_dhcp.go", "onDHCPAddressChange")
	if len(dhcp["applyMgmtVRFRoutes"]) == 0 || len(dhcp["noteMgmtRouteReconcileResult"]) == 0 {
		t.Error("management-only DHCP refresh must latch failed management-route applies")
	}

	rebind := calls("daemon_apply_dataplane.go", "applyDataplaneAndHACore")
	requireBefore(rebind, "rebindManagementVRFIfaces", "mgmtVRFRouteReconcileFn",
		"post-networkd management-VRF path")
	if len(rebind["noteMgmtRouteReconcileResult"]) == 0 {
		t.Error("post-networkd management-route result must update retry debt")
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon_apply_dataplane.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_apply_dataplane.go: %v", err)
	}
	var postRebindRouteErrorReturned bool
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "applyDataplaneAndHACore" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) == 0 ||
				len(assign.Rhs) != 1 || assign.Pos() <= rebind["mgmtVRFRouteReconcileFn"][0] {
				return true
			}
			lhs, ok := assign.Lhs[0].(*ast.Ident)
			if !ok || lhs.Name != "networkdErr" {
				return true
			}
			ast.Inspect(assign.Rhs[0], func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "Errorf" {
					postRebindRouteErrorReturned = true
				}
				return true
			})
			return true
		})
	}
	if !postRebindRouteErrorReturned {
		t.Error("post-networkd management-route failure must be returned in networkd commit errors")
	}
}
