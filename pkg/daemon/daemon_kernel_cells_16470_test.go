package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// daemonKernelCells16470 is the registry of pkg/daemon top-level cells
// that enter a private netns through enterPrivateNetns9813, directly or
// through a same-package helper (newBackupKernelEnv12583). The
// test/daemon/selftest-daemon-kernel_15241.sh forcing leg runs exactly
// this set plus the six #15241 host-inbound cells, and pins every name.
//
// The list is deliberately explicit: TestDaemonKernelCellRegistry16470
// derives the same set from the AST and fails on any drift, so a new
// helper caller cannot silently run in no gate (#16470). Subtests are
// not listed here; the leg rejects any indented --- SKIP record, which
// covers the subtests these cells spawn (5 in
// TestMgmtStaticRouteResolvedGatewayAliasesInstallInKernel_12084, 2 in
// TestBareCrossSpelledMemberEnslavesVLANChildrenInKernel10174, and the
// DHCP probe subtests under the three 12127 parents).
var daemonKernelCells16470 = []string{
	"TestBackupRouterFollowsGatewayMoveOnKernel12583",
	"TestBackupRouterLeavesNonManagementLinkOnKernel12583",
	"TestBackupRouterRemovedOnKernel14972",
	"TestBackupRouterSteadyStateOnKernel12583",
	"TestBackupRouterUnreachableGatewayFailsClosedOnKernel12583",
	"TestBareCrossSpelledMemberEnslavesVLANChildrenInKernel10174",
	"TestBareRIMemberEnslavesItsVLANChildren9754",
	"TestDashMemberEnslavesVLANChildInKernel9815",
	// #18573: the direct-VIP IFA_PROTO stamp round trip and the
	// renumber + snapshot SNAT-source cell.
	"TestDirectVIPRenumberOnKernel18573",
	"TestDirectVIPStampRoundTripsThroughTheKernel18573",
	"TestHostInboundDHCPManagementVRFColdBootProductionFence12127",
	"TestHostInboundDHCPManagementVRFDelivery12127",
	"TestHostInboundDHCPManagementVRFGapDelivery12127",
	"TestHostInputFenceLiveReadbackAndRestore9506",
	"TestMgmtDNSRulesSteerOnlyDefaultContextHostLookups11385",
	"TestMgmtStaticECMPLifecycleInKernel12539",
	"TestMgmtStaticRouteAliasDeduplicationInstallsInKernel12084",
	"TestMgmtStaticRouteResolvedGatewayAliasesInstallInKernel_12084",
	"TestMgmtStaticRouteTolerantNoInstallActionInstallsGateway_12084",
	"TestMgmtVRFReassertRepairsOutOfBandUnbindInKernel11448",
	"TestReassertBindsTheFabricOverlayInTheKernel_9813",
	"TestRIMemberIsReBoundInTheKernel_9813",
	"TestRethRIMemberBindsLocalPhysicalInKernel12059",
}

// daemonKernelCellViolations16470 scans the *_test.go files in dir and
// returns every top-level Test function that reaches
// enterPrivateNetns9813 (transitively through same-file helpers, e.g.
// newBackupKernelEnv12583) but is not in daemonKernelCells16470, plus
// every registered name that no longer reaches the helper.
func daemonKernelCellViolations16470(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	// First pass: helpers (non-Test funcs) whose body calls the helper
	// directly or calls another reaching helper. Iterate to a fixpoint
	// so helper->helper chains resolve regardless of file order.
	type funcBody struct {
		name string
		body *ast.BlockStmt
	}
	var bodies []funcBody
	reaches := map[string]bool{"enterPrivateNetns9813": true}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			bodies = append(bodies, funcBody{name: fn.Name.Name, body: fn.Body})
		}
	}
	callsOf := func(body *ast.BlockStmt) map[string]bool {
		calls := map[string]bool{}
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok {
				calls[id.Name] = true
			}
			return true
		})
		return calls
	}
	for changed := true; changed; {
		changed = false
		for _, fb := range bodies {
			if reaches[fb.name] {
				continue
			}
			for callee := range callsOf(fb.body) {
				if reaches[callee] {
					reaches[fb.name] = true
					changed = true
					break
				}
			}
		}
	}
	registered := map[string]bool{}
	for _, name := range daemonKernelCells16470 {
		registered[name] = true
	}
	var violations []string
	seen := map[string]bool{}
	for _, fb := range bodies {
		if !strings.HasPrefix(fb.name, "Test") {
			continue
		}
		hit := false
		for callee := range callsOf(fb.body) {
			if reaches[callee] {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		seen[fb.name] = true
		if !registered[fb.name] {
			violations = append(violations, fb.name+" reaches enterPrivateNetns9813 but is not in daemonKernelCells16470 (add it and extend the daemon-kernel forcing leg)")
		}
	}
	for _, name := range daemonKernelCells16470 {
		if !seen[name] {
			violations = append(violations, name+" is registered in daemonKernelCells16470 but no longer reaches enterPrivateNetns9813 (remove it or restore the kernel cell)")
		}
	}
	sort.Strings(violations)
	return violations
}

func TestDaemonKernelCellRegistry16470(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	if violations := daemonKernelCellViolations16470(t, filepath.Dir(file)); len(violations) > 0 {
		t.Fatalf("daemon kernel-cell registry drift (#16470):\n%s", strings.Join(violations, "\n"))
	}
}
