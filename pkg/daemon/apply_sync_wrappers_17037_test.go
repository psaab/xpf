package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17037: the nil-argument convenience wrappers for the commit/sync
// apply pipeline were production-compiled but production-dead: no
// production caller used applyAndSyncCommitted or syncAndApply, yet
// the former carried the #4034 pipeline doc that falsely claimed
// commitAndApply and commitConfirmedAndApply shared it (both call
// applyAndSyncCommittedWithPeerSnapshotAuthorization directly).
// The wrappers now live here, test-only, named …ForTest.

func (d *Daemon) applyAndSyncCommittedForTest(oldActive, compiled *config.Config, syncPeer peerSyncPolicy) (*config.Config, error) {
	return d.applyAndSyncCommittedWithPeerSnapshotAuthorization(oldActive, compiled, syncPeer, nil)
}

func (d *Daemon) syncAndApplyForTest(
	ctx context.Context,
	configText string,
	chassisPreserve func(*config.ConfigTree),
) (compiled *config.Config, retErr error) {
	return d.syncAndApplyWithAncestry(ctx, configText, chassisPreserve, nil)
}

// TestNoProductionDeadApplySyncWrappers17037 pins the #17037 cleanup:
// daemon_apply_commit.go must not declare the production-dead wrappers,
// the #4034 doc must sit on the production function, and both
// production entries must call the live functions directly.
//
// RED pre-fix: daemon_apply_commit.go declares both wrappers and the
// doc above applyAndSyncCommitted claims it is "Shared by
// commitAndApply and commitConfirmedAndApply", so the first checks
// fail. Control: the live functions and their direct production
// callers exist both before and after the fix.
func TestNoProductionDeadApplySyncWrappers17037(t *testing.T) {
	const file = "daemon_apply_commit.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	declared := map[string]*ast.FuncDecl{}
	calls := map[string]map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		declared[fn.Name.Name] = fn
		calls[fn.Name.Name] = map[string]int{}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			calls[fn.Name.Name][sel.Sel.Name]++
			return true
		})
	}
	for _, dead := range []string{"applyAndSyncCommitted", "syncAndApply"} {
		if _, ok := declared[dead]; ok {
			t.Errorf("#17037: %s is still declared in %s; the production-dead "+
				"wrapper must live only as %sForTest in a _test.go file", dead, file, dead)
		}
	}
	live, ok := declared["applyAndSyncCommittedWithPeerSnapshotAuthorization"]
	if !ok {
		t.Fatalf("#17037: production function applyAndSyncCommittedWithPeerSnapshotAuthorization missing from %s", file)
	}
	if live.Doc == nil {
		t.Fatalf("#17037: applyAndSyncCommittedWithPeerSnapshotAuthorization has no doc comment; " +
			"the #4034 pipeline doc must sit on the production function")
	}
	doc := live.Doc.Text()
	for _, want := range []string{"#4034", "commitAndApply", "commitConfirmedAndApply"} {
		if !strings.Contains(doc, want) {
			t.Errorf("#17037: production function doc must mention %q (the #4034 doc moved here); doc:\n%s", want, doc)
		}
	}
	if _, ok := declared["syncAndApplyWithAncestry"]; !ok {
		t.Fatalf("#17037: production function syncAndApplyWithAncestry missing from %s", file)
	}
	for _, caller := range []string{"commitAndApply", "commitConfirmedAndApply"} {
		if calls[caller]["applyAndSyncCommittedWithPeerSnapshotAuthorization"] == 0 {
			t.Errorf("#17037: %s must call applyAndSyncCommittedWithPeerSnapshotAuthorization directly; calls=%v", caller, calls[caller])
		}
	}
}
