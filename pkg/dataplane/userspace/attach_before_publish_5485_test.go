// #5485: Compile attaches the XDP shim to the new candidate set and then
// DETACHES XDP/TC from every ifindex the new snapshot no longer adjudicates.
// Both ran BEFORE apply_snapshot, and m.lastSnapshot — the authority every
// fail-closed path promises is "retained" — advances only on a successful
// publish. So every failure in between left the KERNEL on the new interface set
// while the control plane still reported the OLD one.
//
// The detach half is the sharp edge. Both pre-publish failure modes drive the
// shim to ctrl.Enabled=0, and a disabled ctrl DROPS transit on every interface
// that still carries the shim (degraded_ctrl_disabled_action runs before the
// ingress-map test in userspace-xdp/src/lib.rs). An interface that has already
// been detached has no XDP program at all, so with ip_forward=1 its traffic
// goes straight into the Linux stack, unadjudicated — a policy bypass on an
// interface the retained snapshot still lists as protected.
//
// The fix re-sequences: syncInterfaceAttachments runs only after the snapshot
// has been ACCEPTED as the retained authority (published, or deliberately
// deferred with m.lastSnapshot advanced).
//
// FAIL-ON-REVERT: re-inserting a single `m.syncInterfaceAttachments(result,
// snap)` immediately after `defer m.mu.Unlock()` in applyCompiledSnapshot (the
// pre-fix ordering) makes TestAttachmentsNotDetachedBeforePublish_5485 go RED on
// its "XDP link for ifindex 4242 was detached" assertion, and
// TestDetachOnlyAfterSnapshotAccepted_5485 go RED on the un-dominated call site.
package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// shimLink5485 stands in for a live bpf_link. link.Link carries an unexported
// marker so it cannot be implemented from outside cilium/ebpf; embedding the
// interface and overriding exactly the two methods DetachXDP/DetachTC invoke
// (Unpin, Close) is the pattern pkg/dataplane's armedGateFakeLink already uses.
type shimLink5485 struct {
	link.Link
	unpinned bool
	closed   bool
}

func (l *shimLink5485) Unpin() error { l.unpinned = true; return nil }
func (l *shimLink5485) Close() error { l.closed = true; return nil }

// protectedIfindex5485 is the interface the RETAINED snapshot adjudicates and
// the NEW config drops — the population syncInterfaceAttachments detaches.
const protectedIfindex5485 = 4242

// TestAttachmentsNotDetachedBeforePublish_5485 drives the real apply path with a
// snapshot the helper never accepts and asserts the kernel attachment state
// still matches the RETAINED snapshot.
//
// The injected failure is programBootstrapMapsLocked's "userspace_ctrl map not
// loaded" — a genuine, production-reachable failure that lands in exactly the
// window the issue names (after the old detach site, before apply_snapshot).
// It needs no BPF map fixture, so this test RUNS unprivileged rather than
// skipping; assertNotSkipped5485 pins that.
func TestAttachmentsNotDetachedBeforePublish_5485(t *testing.T) {
	m := New()

	retained := &ConfigSnapshot{
		Generation: 7,
		Interfaces: []InterfaceSnapshot{{
			Ifindex:   protectedIfindex5485,
			LinuxName: "ge-0-0-9",
			Name:      "ge-0/0/9",
			Zone:      "trust",
		}},
	}
	// Premise: the retained snapshot really does adjudicate this ifindex, so
	// detaching it really does strip a protected ingress. Without this the test
	// could pass over a snapshot that never protected anything.
	if got := buildUserspaceIngressIfindexes(retained); len(got) != 1 || got[0] != protectedIfindex5485 {
		t.Fatalf("premise broken: retained snapshot ingress set = %v, want [%d] — "+
			"the interface under test must be one the retained snapshot protects",
			got, protectedIfindex5485)
	}
	// The new snapshot drops it, so the allowed set is empty and the detach
	// loop would take the link.
	next := &ConfigSnapshot{Generation: 8}
	if got := buildUserspaceIngressIfindexes(next); len(got) != 0 {
		t.Fatalf("premise broken: new snapshot ingress set = %v, want empty — "+
			"the new config must DROP the interface for the detach to be reached", got)
	}

	xdpLink := &shimLink5485{}
	tcLink := &shimLink5485{}
	m.bpfShim.XDPLinks()[protectedIfindex5485] = xdpLink
	m.bpfShim.TCLinks()[protectedIfindex5485] = tcLink

	m.mu.Lock()
	m.lastSnapshot = retained
	m.mu.Unlock()

	cfg := &config.Config{}
	result := &dataplane.CompileResult{}
	ran := false
	_, err := func() (*dataplane.CompileResult, error) {
		defer func() { ran = true }()
		return m.applyCompiledSnapshot(cfg, result, next, deriveUserspaceConfig(cfg), deriveUserspaceCapabilities(cfg))
	}()
	assertNotSkipped5485(t, ran)

	if err == nil {
		t.Fatal("premise broken: the apply must FAIL before apply_snapshot — " +
			"with no BPF maps injected programBootstrapMapsLocked cannot succeed")
	}
	if !strings.Contains(err.Error(), "userspace_ctrl map not loaded") {
		t.Fatalf("premise broken: apply failed with %v, want the pre-publish "+
			"programBootstrapMapsLocked failure — the assertions below only bind "+
			"the window between the detach site and apply_snapshot", err)
	}

	m.mu.Lock()
	authority := m.lastSnapshot
	published := m.publishedSnapshot
	m.mu.Unlock()
	if authority != retained {
		t.Fatalf("premise broken: m.lastSnapshot advanced past the retained snapshot "+
			"on a failed apply (generation %d) — the fail-closed contract is that it does not",
			authority.Generation)
	}
	if published != 0 {
		t.Fatalf("premise broken: publishedSnapshot = %d, want 0 — nothing was published", published)
	}

	// THE ASSERTION. The retained snapshot still lists ifindex 4242 as a
	// protected ingress, so it must still carry the shim: with ctrl disabled the
	// shim drops its transit, where a detached interface would forward it
	// through the Linux stack with no xpf adjudication at all.
	if _, ok := m.bpfShim.XDPLinks()[protectedIfindex5485]; !ok {
		t.Errorf("XDP link for ifindex %d was detached by a FAILED apply — the retained "+
			"snapshot still adjudicates it, so it now has no XDP program while the control "+
			"plane reports the previous-good snapshot as enforced (#5485 policy bypass)",
			protectedIfindex5485)
	}
	if xdpLink.closed || xdpLink.unpinned {
		t.Errorf("XDP link handle for ifindex %d was closed/unpinned by a FAILED apply "+
			"(closed=%v unpinned=%v)", protectedIfindex5485, xdpLink.closed, xdpLink.unpinned)
	}
	if _, ok := m.bpfShim.TCLinks()[protectedIfindex5485]; !ok {
		t.Errorf("TC link for ifindex %d was detached by a FAILED apply — the egress half "+
			"of the same divergence (#5485)", protectedIfindex5485)
	}
	if tcLink.closed || tcLink.unpinned {
		t.Errorf("TC link handle for ifindex %d was closed/unpinned by a FAILED apply "+
			"(closed=%v unpinned=%v)", protectedIfindex5485, tcLink.closed, tcLink.unpinned)
	}
}

// assertNotSkipped5485 fails when the body under test never executed. The
// sibling fail-closed tests in this package gate on rlimit.RemoveMemlock and
// t.Skip when unprivileged; this one deliberately needs no BPF fixture, and a
// silent skip would turn the whole #5485 proof vacuous.
func assertNotSkipped5485(t *testing.T, ran bool) {
	t.Helper()
	if !ran {
		t.Fatal("the apply under test did not run — this test must never skip; " +
			"it needs no privileged BPF map fixture")
	}
}

// TestDetachOnlyAfterSnapshotAccepted_5485 binds the half the behavioral test
// above cannot see. That test proves the detach does not happen on a FAILED
// apply; deleting syncInterfaceAttachments outright would satisfy it too, and
// silently retire the obsolete-attachment cleanup. This asserts the call still
// exists AND that every call site is dominated by the snapshot becoming the
// retained authority (`m.lastSnapshot = snap`) in its own block — which is what
// "only after acceptance" means as a program property, on both acceptance paths
// (published, and deferred-during-XSK-startup).
func TestDetachOnlyAfterSnapshotAccepted_5485(t *testing.T) {
	t.Parallel()

	const path = "manager_compile.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "applyCompiledSnapshot" {
			fn = d
			break
		}
	}
	if fn == nil {
		t.Fatal("applyCompiledSnapshot not found in manager_compile.go — the apply " +
			"path was renamed or re-inlined; retarget this guard rather than deleting it")
	}

	calls := 0
	dominated := 0
	ast.Inspect(fn, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		accepted := false
		for _, stmt := range block.List {
			if assignsRetainedAuthority5485(stmt) {
				accepted = true
			}
			if !callsSyncInterfaceAttachments5485(stmt) {
				continue
			}
			calls++
			if accepted {
				dominated++
				continue
			}
			t.Errorf("syncInterfaceAttachments is called at %s with no preceding "+
				"`m.lastSnapshot = snap` in its block — the detach must happen only "+
				"after the new snapshot has become the retained authority, or a later "+
				"failure leaves a protected ingress with no XDP program (#5485)",
				fset.Position(stmt.Pos()))
		}
		return true
	})

	if calls == 0 {
		t.Fatal("applyCompiledSnapshot no longer calls syncInterfaceAttachments — " +
			"the obsolete-attachment cleanup was deleted, not re-sequenced (#5485)")
	}
	// Both acceptance points must reconcile: the published path and the
	// deferred-publish path, which also advances m.lastSnapshot and returns nil.
	if calls != 2 || dominated != 2 {
		t.Errorf("applyCompiledSnapshot has %d syncInterfaceAttachments call(s), %d of them "+
			"dominated by the retained-authority assignment; want 2 and 2 (the published "+
			"path and the deferred-publish path both advance m.lastSnapshot and must both "+
			"reconcile the attachment set)", calls, dominated)
	}
}

// assignsRetainedAuthority5485 reports whether stmt is `m.lastSnapshot = snap`,
// the single statement that makes the freshly built snapshot the authority every
// other reader enforces.
func assignsRetainedAuthority5485(stmt ast.Stmt) bool {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return false
	}
	sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "lastSnapshot" {
		return false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok || recv.Name != "m" {
		return false
	}
	rhs, ok := assign.Rhs[0].(*ast.Ident)
	return ok && rhs.Name == "snap"
}

// callsSyncInterfaceAttachments5485 reports whether stmt is a bare
// `m.syncInterfaceAttachments(...)` expression statement.
func callsSyncInterfaceAttachments5485(stmt ast.Stmt) bool {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "syncInterfaceAttachments"
}
