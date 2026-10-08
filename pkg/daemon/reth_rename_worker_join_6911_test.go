package daemon

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// #6911: renameRethMember performs a setDown -> setName -> setUp cycle on a RETH
// member. That is the same hazard #5103 fixed in programRethMAC — AF_XDP worker
// threads live across the link DOWN and touch UMEM pages the NIC unmaps as it
// tears down its queues — so this site needs the same beforeCycle join.
//
// The hazard is LATENT today (renameRethMember runs only when the target name
// does not resolve, so no binding can exist), which is exactly why these guards
// matter: the reachability argument rests on three properties of unrelated code
// and none of them is asserted. These tests assert the ORDERING and the ABORT,
// so a future change that makes the site reachable cannot silently reopen #5103.

// TestRenameRethMemberJoinsWorkersBeforeLinkDown pins the ordering: the join
// must run strictly BEFORE the first mutation of the link.
//
// RED-on-revert: moving the beforeCycle call below ops.setDown leaves
// opsAtJoin == ["down"], because the fake records every netlink op in order.
// A test that only asserted "the hook ran" would stay green under that move —
// which is the whole defect, since a join after the DOWN is no join at all.
func TestRenameRethMemberJoinsWorkersBeforeLinkDown(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)

	joinRan := false
	var opsAtJoin []string
	join := func() error {
		joinRan = true
		opsAtJoin = append([]string(nil), ops...)
		return nil
	}

	oldName, cycled, err := renameRethMember("ge-0-0-1", mac, mac, nil, join)
	if err != nil || !cycled || oldName != "enp8s0" {
		t.Fatalf("renameRethMember returned (%q, %v, %v), want (enp8s0, true, nil)", oldName, cycled, err)
	}
	if !joinRan {
		t.Fatal("the beforeCycle worker join never ran on the rename path (#6911)")
	}
	if len(opsAtJoin) != 0 {
		t.Fatalf("worker join ran AFTER the link was already touched: ops at join = %v.\n"+
			"The join must precede setDown — workers live across the link DOWN and touch\n"+
			"UMEM pages the NIC unmaps during queue teardown (#5103, #6911).", opsAtJoin)
	}
	// The rename must still complete normally when the join succeeds.
	if link.attrs.Name != "ge-0-0-1" {
		t.Fatalf("link not renamed after a successful join: %q", link.attrs.Name)
	}
	if !adminUp {
		t.Fatal("link left administratively DOWN after a successful rename (#3920)")
	}
}

// TestRenameRethMemberAbortsWithoutTouchingLinkWhenJoinFails is the paired cell:
// on a join error the link must be left EXACTLY as found.
//
// RED-on-revert: dropping the `return ""` in the error arm lets the rename
// proceed, so ops becomes ["down", "name:ge-0-0-1", "up"] instead of empty.
// Asserting the empty-op sequence rather than just the "" return value is what
// makes this catch a fall-through — a fall-through that then failed for an
// unrelated reason would also return "".
func TestRenameRethMemberAbortsWithoutTouchingLinkWhenJoinFails(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)

	join := func() error { return errors.New("worker join refused") }

	oldName, cycled, err := renameRethMember("ge-0-0-1", mac, mac, nil, join)
	if oldName != "" || cycled || err == nil {
		t.Fatalf("renameRethMember returned (%q, %v, %v) on a failed join, want empty name, no cycle, error",
			oldName, cycled, err)
	}
	if len(ops) != 0 {
		t.Fatalf("link was mutated after the worker join failed: ops = %v.\n"+
			"A cycle with the workers in an unknown state is precisely the #5103\n"+
			"hazard this hook exists to avoid — the abort must touch nothing.", ops)
	}
	if link.attrs.Name != "enp8s0" {
		t.Fatalf("link renamed despite a failed join: %q", link.attrs.Name)
	}
	if !adminUp {
		t.Fatal("link left DOWN after an aborted rename — the abort must not touch admin state")
	}
}

// TestRenameRethMemberNilHookStillRenames keeps the nil-hook contract explicit,
// matching programRethMAC's: a nil beforeCycle means "no join needed" and must
// not change the rename behaviour. Without this, a fix that made the hook
// mandatory would break every caller with no live dataplane.
func TestRenameRethMemberNilHookStillRenames(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)

	oldName, cycled, err := renameRethMember("ge-0-0-1", mac, mac, nil, nil)
	if err != nil || !cycled || oldName != "enp8s0" {
		t.Fatalf("renameRethMember with a nil hook returned (%q, %v, %v), want (enp8s0, true, nil)",
			oldName, cycled, err)
	}
	if link.attrs.Name != "ge-0-0-1" {
		t.Fatalf("link not renamed with a nil hook: %q", link.attrs.Name)
	}
}

// TestDaemonPassesRenameRethMemberBeforeCycleHook_6911 binds the WIRING, not the
// function.
//
// The behavioural cells above drive renameRethMember directly, so they bind what
// happens INSIDE it. They do not bind the daemon's call TO it: replacing the
// hook argument with a literal `nil` at the apply site compiles, keeps all three
// of them green, and restores the #6911 defect exactly. I measured that — a
// mutation passing nil at the call site produced ZERO failures across the whole
// pkg/daemon suite before this test existed.
//
// Structured as an AST walk rather than a grep for the same reason as its #5103
// sibling: a source scan keyed on text can be satisfied by a comment quoting the
// pattern it looks for, and can silently sweep nothing. packageGoFiles fatals
// when it finds no non-test files, so a broken sweep fails loudly instead of
// counting zero call sites and passing.
func TestDaemonPassesRenameRethMemberBeforeCycleHook_6911(t *testing.T) {
	fset := token.NewFileSet()
	calls := 0
	for _, file := range packageGoFiles(t) {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != "renameRethMember" {
				return true
			}
			calls++
			if len(call.Args) != 5 {
				t.Errorf("%s:%d: renameRethMember called with %d args, want 5 — the fifth "+
					"is the beforeCycle worker-join hook (#6911)",
					file, fset.Position(call.Pos()).Line, len(call.Args))
				return true
			}
			if arg, ok := call.Args[4].(*ast.Ident); ok && arg.Name == "nil" {
				t.Errorf("%s:%d: the daemon passes a nil beforeCycle hook to renameRethMember, "+
					"so AF_XDP workers are never joined before the rename link cycle — the "+
					"#6911 defect, restored with every producer-side test still green",
					file, fset.Position(call.Pos()).Line)
			}
			return true
		})
	}
	if calls != 1 {
		t.Errorf("found %d production renameRethMember call sites, want exactly 1. "+
			"A second call site would need its own hook, and zero means this canary "+
			"is watching a function the daemon no longer calls.", calls)
	}
}

// TestRenameRethMemberHookRunsOnTheCallersGoroutine_6911 is the behavioural
// proof that the #6871 acquisition-site allowlist requires for this call site.
//
// The daemon's renameJoin hook takes a link-cycle lease, and the ONLY thing
// bounding that lease is applyDataplaneAndHACore's deferred
// abandonLinkCycleLease. The hook is written as a func literal, so no AST fact
// establishes that it runs inside that defer's extent — being inside it is a
// property of renameRethMember invoking the callback SYNCHRONOUSLY. A hook that
// outlived the renameRethMember call could take the lease after the defer has
// run, and since #6871 round 8 the lease renews itself, so that would suppress
// the 1 Hz reconcile for the life of the process rather than for one TTL.
//
// This is the same obligation, and the same proof, as
// TestRethMACHookRunsOnTheCallersGoroutine_6871 carries for programRethMAC.
func TestRenameRethMemberHookRunsOnTheCallersGoroutine_6911(t *testing.T) {
	mac, err := net.ParseMAC("02:bf:72:01:01:00")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: mac}}
	adminUp := true
	var ops []string
	installFakeRethLinkOps(t, link, &adminUp, &ops, false)

	caller := goIDFromStack()
	if caller == 0 {
		t.Fatal("fixture: could not read the test goroutine's id from the runtime.Stack " +
			"header, so the identity comparison below would compare 0 against 0")
	}

	ran := false
	var hookGoID uint64
	oldName, cycled, err := renameRethMember("ge-0-0-1", mac, mac, nil, func() error {
		ran = true
		hookGoID = goIDFromStack()
		return nil
	})
	if err != nil || !cycled || oldName != "enp8s0" {
		t.Fatalf("renameRethMember returned (%q, %v, %v); on any other path the hook is not "+
			"invoked at all and this test would assert nothing", oldName, cycled, err)
	}
	if !ran {
		t.Fatal("the beforeCycle hook never ran on the rename path")
	}
	if hookGoID != caller {
		t.Fatalf("beforeCycle ran on goroutine %d but renameRethMember was called from %d.\n"+
			"The daemon takes its link-cycle lease inside this hook, and the only thing "+
			"bounding that lease is applyDataplaneAndHACore's deferred "+
			"abandonLinkCycleLease. A hook that does not complete within the "+
			"renameRethMember call can take the lease after that defer has run, and "+
			"since #6871 round 8 the lease renews itself — so it would suppress the "+
			"1 Hz reconcile for the life of the process (#6911)", hookGoID, caller)
	}
}
