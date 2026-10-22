package config

// #6706 review r11 F4: bind the NODE-AWARE `LoginDroppedByPacking` assignment.
//
// The flag is assigned at two places in compiler.go: once in the generic
// `compileTree` (CompileConfig / CompileConfigLenient) and once in
// `compileTree node branch` (CompileConfigForNode /
// CompileConfigForNodeLenient). Every pre-existing true-flag assertion reaches
// the GENERIC one; the node-aware assignment had no test that could fire.
//
// Measured before writing this: reverting ONLY the node-aware line and running
// `./pkg/config/... ./pkg/configstore/... ./pkg/daemon/... ./pkg/cli/...
// ./pkg/osident/... ./cmd/cli/...` came back rc=0, every package `ok`. That is
// the "guard unable to fire" bar.
//
// It is not academic which constructor is covered. `pkg/configstore/store.go`
// uses the node-aware TOLERANT constructor on the load/sync path, so a node
// booting from its own persisted config, or ingesting a peer's, goes through
// line 550 and not line 370. With that line reverted, node 1 tolerantly
// compiles a packed `system login user alice class ops;` to nil Login with the
// flag FALSE, `applyCLILoginClass` takes its legacy early return, and the shell
// runs unrestricted — the exact #6706 fail-open, reopened on the one path an
// HA node actually boots through.
//
// TWO ARMS ARE REQUIRED, and one fixture binds one arm. A single-node fixture
// cannot distinguish "the flag is computed per node" from "the flag is computed
// once and shared": both produce the same answer when only one node is driven.
// The pair below differs in exactly the node id and asserts opposite outcomes,
// so the per-node dimension is what is pinned.

import "testing"

// haLoginNodeSplitConfig puts the packed login stanza in node1's group ONLY.
// node0's group carries an unrelated statement, so the two node views differ in
// exactly the property under test.
const haLoginNodeSplitConfig = `groups {
  node0 { system { host-name fw0; } }
  node1 { system login user alice class ops; }
}
apply-groups "${node}";
`

func TestLoginDroppedFlagIsPerNodeView_6706(t *testing.T) {
	tree, perrs := NewParser(haLoginNodeSplitConfig).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}

	for _, tc := range []struct {
		node        int
		wantDropped bool
		why         string
	}{
		{
			node:        0,
			wantDropped: false,
			why: "node 0's view has no `login` token at all — its group carries only " +
				"host-name — so nothing was packed and nothing was dropped. A flag set " +
				"here would deny every non-root operator on a node whose config never " +
				"mentioned RBAC, which is the lockout half of the boundary",
		},
		{
			node:        1,
			wantDropped: true,
			why: "node 1's view packs `user alice class ops` onto the system line, so a " +
				"configured RBAC stanza WAS dropped and the daemon must refuse the " +
				"legacy unset-class mode. A flag left false here reopens the #6706 " +
				"fail-open on the node-aware tolerant path configstore actually boots " +
				"through",
		},
	} {
		t.Run(nodeName(tc.node), func(t *testing.T) {
			cfg, err := CompileConfigForNodeLenient(tree, tc.node)
			if err != nil {
				t.Fatalf("node %d lenient compile: %v", tc.node, err)
			}
			// Precondition: both views must compile the stanza AWAY, or the flag
			// is not the thing deciding the outcome and the assertion below
			// would be about something else.
			if cfg.System.Login != nil {
				t.Fatalf("node %d: precondition failed, System.Login is non-nil — this "+
					"fixture no longer exercises the dropped-login path", tc.node)
			}
			if got := cfg.System.LoginDroppedByPacking; got != tc.wantDropped {
				t.Errorf("node %d: LoginDroppedByPacking = %v, want %v.\n%s",
					tc.node, got, tc.wantDropped, tc.why)
			}
		})
	}
}

// TestLoginDroppedFlagNodeViewsDisagree_6706 states the discrimination the two
// arms above exist to provide, as one assertion rather than two independent
// ones: the SAME config must produce DIFFERENT flags for the two node views.
//
// A per-node computation replaced by a whole-tree one — the natural way to
// "simplify" the two assignment sites into one — collapses both views onto the
// same answer and is RED here, while each single-node arm above could still be
// satisfied by whichever answer that collapse happened to pick.
func TestLoginDroppedFlagNodeViewsDisagree_6706(t *testing.T) {
	tree, perrs := NewParser(haLoginNodeSplitConfig).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	node0, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil {
		t.Fatalf("node 0: %v", err)
	}
	node1, err := CompileConfigForNodeLenient(tree, 1)
	if err != nil {
		t.Fatalf("node 1: %v", err)
	}
	if node0.System.LoginDroppedByPacking == node1.System.LoginDroppedByPacking {
		t.Fatalf("both node views report LoginDroppedByPacking = %v for a config whose "+
			"packed `system login` exists ONLY in node1's group. The flag is being "+
			"computed from something other than the per-node effective view, so one "+
			"of the two nodes is getting the other's answer: either node 0 denies "+
			"over a config it never had, or node 1 fails open on a stanza it did",
			node0.System.LoginDroppedByPacking)
	}
}

func nodeName(n int) string {
	if n == 0 {
		return "node0"
	}
	return "node1"
}
