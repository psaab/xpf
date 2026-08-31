package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7441 constraint (2), bound directly rather than argued: an admitted
// session-sync peer must not be able to disarm — or arm — the posture through
// config-sync.
//
// The vector is real and was verified at HEAD: readAuthed()
// (pkg/cluster/sync_conn_read.go) gates trailer VERIFICATION only, so an
// unauthenticated stream's frames reach handleConfigPayload; and
// handleConfigSync (daemon_ha_sync.go) refuses a push only on the RG0 primary,
// so a STANDBY accepts one. A posture flag carried in synced config would be
// clearable by exactly the connection it exists to evict.

func treeWithPosture7441(t *testing.T, set bool) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	// A minimal but REAL chassis-cluster stanza: the preserve hook edits the
	// incoming tree in place, so it has to be given the shape a peer pushes.
	if err := tree.SetPath([]string{"chassis", "cluster", "cluster-id", "22"}); err != nil {
		t.Fatalf("SetPath cluster-id: %v", err)
	}
	if set {
		if err := tree.SetPath([]string{"chassis", "cluster", "strict-session-auth"}); err != nil {
			t.Fatalf("SetPath strict-session-auth: %v", err)
		}
	}
	if got := chassisClusterFlagSet(tree, "strict-session-auth"); got != set {
		t.Fatalf("fixture tree posture = %v, want %v — the fixture does not construct "+
			"the state it names", got, set)
	}
	return tree
}

// TestPeerPushCannotClearTheNodeLocalPosture7441 is the security cell.
//
// A hostile admitted stream pushes a config whose chassis stanza simply omits
// the leaf. Nothing about that push is malformed — omission IS how the leaf is
// cleared — so no validator can reject it. The preserve hook has to put it back.
func TestPeerPushCannotClearTheNodeLocalPosture7441(t *testing.T) {
	local := treeWithPosture7441(t, true)
	incoming := treeWithPosture7441(t, false)

	preserveNodeLocalChassis(local)(incoming)

	if !chassisClusterFlagSet(incoming, "strict-session-auth") {
		t.Fatal("a peer push cleared this node's strict-session-auth posture. The " +
			"connection that pushed it may be the very one the posture exists to " +
			"evict — this is #5078's re-arming constraint, and it is why the leaf " +
			"is node-local rather than synced")
	}
	// The rest of the peer's tree must still apply: preserving one leaf must
	// not turn config-sync into a no-op, or a standby strands on a stale
	// cluster topology.
	if incoming.FindChild("chassis") == nil {
		t.Fatal("the preserve hook destroyed the incoming tree")
	}
}

// TestPeerPushCannotSetTheNodeLocalPosture7441 is the other direction, and it
// is not symmetric window-dressing.
//
// "The peer may turn my security posture ON" is not harmless: it drops THIS
// node's session sync whenever the peer is the end that cannot answer the
// upgrade. Preserving in only one direction would leave that as a lever.
func TestPeerPushCannotSetTheNodeLocalPosture7441(t *testing.T) {
	local := treeWithPosture7441(t, false)
	incoming := treeWithPosture7441(t, true)

	preserveNodeLocalChassis(local)(incoming)

	if chassisClusterFlagSet(incoming, "strict-session-auth") {
		t.Fatal("a peer push SET a posture this node never declared; the peer can then " +
			"drop this node's session sync by declaring a posture it cannot itself satisfy")
	}
}

// TestPreserveIsANoOpWhenBothAgree7441 is the control: the hook must not edit a
// tree that already matches, or every peer push rewrites the stanza.
func TestPreserveIsANoOpWhenBothAgree7441(t *testing.T) {
	for _, set := range []bool{true, false} {
		local := treeWithPosture7441(t, set)
		incoming := treeWithPosture7441(t, set)
		before := incoming.FormatSet()
		preserveNodeLocalChassis(local)(incoming)
		if got := incoming.FormatSet(); got != before {
			t.Errorf("posture=%v: the hook rewrote an already-matching tree:\n--- before ---\n%s\n--- after ---\n%s",
				set, before, got)
		}
		if got := chassisClusterFlagSet(incoming, "strict-session-auth"); got != set {
			t.Errorf("posture=%v: hook changed the value to %v", set, got)
		}
	}
}

// TestNilLocalTreePreservesNothing7441: a node that has never committed has no
// posture to defend. This pins that a nil local is HANDLED rather than
// nil-dereferenced, and that the leaf is stripped for that reason.
func TestNilLocalTreePreservesNothing7441(t *testing.T) {
	incoming := treeWithPosture7441(t, true)
	preserveNodeLocalChassis(nil)(incoming)
	if chassisClusterFlagSet(incoming, "strict-session-auth") {
		t.Error("a node with no committed config kept a pushed posture; with no local " +
			"value there is nothing to preserve and the leaf should be stripped")
	}
	if incoming.FindChild("chassis") == nil {
		t.Fatal("nil local tree destroyed the incoming tree")
	}
}

// TestHandleConfigSyncInstallsThePreserveHook7441 is the WIRING cell.
//
// The cells above test the hook. This one tests that the peer-sync apply path
// passes it. handleConfigSync used to call syncAndApply with a literal nil for
// chassisPreserve; restoring that nil leaves every cell above green while the
// posture becomes clearable by the peer again — the exact defect, with a
// passing suite.
//
// A source scan rather than an execution because reaching handleConfigSync's
// apply needs a live store, a cluster manager reporting non-primary and a
// dataplane; the wiring is one call argument and the scan sees it directly.
func TestHandleConfigSyncInstallsThePreserveHook7441(t *testing.T) {
	const src = "daemon_ha_sync.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	var scanned, found bool
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Name.Name != "handleConfigSync" {
			continue
		}
		scanned = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == "preserveNodeLocalChassis" {
				found = true
			}
			return true
		})
	}
	// Non-vacuity: a renamed or moved handleConfigSync would otherwise leave
	// this cell asserting nothing while reporting green.
	if !scanned {
		t.Fatalf("handleConfigSync not found in %s; this cell is scanning the wrong "+
			"subject and would pass over an empty set", src)
	}
	if !found {
		t.Fatal("handleConfigSync does not call preserveNodeLocalChassis. The peer-sync " +
			"apply passes no chassisPreserve hook, so an admitted hostile stream can " +
			"push a config that clears the strict-session-auth posture on a standby " +
			"(handleConfigSync refuses a push only on the RG0 primary).")
	}
}

// TestNodeLocalLeafListIsTheContract7441 pins the list itself. Widening it to
// the whole chassis stanza would strand a standby on a stale cluster topology;
// dropping the entry re-opens the vector. Both should be deliberate edits.
func TestNodeLocalLeafListIsTheContract7441(t *testing.T) {
	if len(nodeLocalChassisLeaves) == 0 {
		t.Fatal("nodeLocalChassisLeaves is empty; config-sync now carries every chassis " +
			"leaf and the #7441 posture is clearable by the peer")
	}
	var found bool
	for _, l := range nodeLocalChassisLeaves {
		if l == "strict-session-auth" {
			found = true
		}
	}
	if !found {
		t.Errorf("strict-session-auth is no longer node-local: %v", nodeLocalChassisLeaves)
	}
	if strings.Join(chassisClusterPath, " ") != "chassis cluster" {
		t.Errorf("chassisClusterPath = %v, want [chassis cluster]", chassisClusterPath)
	}
}
