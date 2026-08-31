package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// Node-local chassis-cluster settings, preserved across a peer config push
// (#7441; the hook is shared with #6629's eventual node-local posture).
//
// WHY THIS EXISTS AT ALL. `chassis cluster strict-session-auth` is the posture
// that lets a keyed node evict a session-sync connection which was admitted
// before the key was committed and never authenticated. If it were carried in
// ordinary synced config it would be clearable by exactly the connection it
// exists to evict, and here is the full path, verified at HEAD rather than
// assumed:
//
//  1. an unauthenticated session-sync stream's frames reach
//     handleConfigPayload. readAuthed() (pkg/cluster/sync_conn_read.go) gates
//     whether a per-frame trailer is VERIFIED; an unauthenticated connection is
//     a pass-through, not a rejection;
//  2. handleConfigSync (daemon_ha_sync.go) refuses a push only when this node
//     is the RG0 primary. A STANDBY accepts;
//  3. so a hostile admitted stream on a standby can push a configuration whose
//     chassis-cluster stanza omits the leaf, and the posture disarms itself.
//
// That is #5078's "an admitted peer must not be able to re-arm the window"
// constraint, which is why the leaf is node-local instead of synced.
//
// WHAT IS PRESERVED IS THE LOCAL STATE, IN BOTH DIRECTIONS. A push cannot set
// the leaf either, not only clear it. Preserving in one direction would leave
// the other as a lever, and "the peer may turn my security posture ON" is not
// obviously harmless: it drops this node's session sync if the peer is the one
// that cannot answer. The rule is simply that this leaf is not the peer's
// business.
//
// SCOPE. Deliberately ONE leaf, not "the chassis stanza". Everything else
// under `chassis cluster` — the redundancy groups, the interfaces, the PSK
// itself — is cluster-wide state that config-sync exists to converge, and
// blanket-preserving it would strand a standby on a stale cluster topology.
// #6629's node-local posture will join this list; the list is the contract.

// preserveNodeLocalChassis returns the Store.SyncApply chassisPreserve hook: it
// rewrites the INCOMING peer tree so every node-local leaf keeps this node's
// committed value.
//
// local is this node's currently-active tree. A nil local (nothing committed
// yet) means there is no local value to preserve, and the incoming tree is left
// exactly as pushed — a node with no committed config has no posture to defend,
// and the leaf is inert until it does.
func preserveNodeLocalChassis(local *config.ConfigTree) func(*config.ConfigTree) {
	return func(incoming *config.ConfigTree) {
		if incoming == nil {
			return
		}
		for _, leaf := range nodeLocalChassisLeaves {
			localSet := chassisClusterFlagSet(local, leaf)
			incomingSet := chassisClusterFlagSet(incoming, leaf)
			if localSet == incomingSet {
				continue
			}
			path := append(append([]string(nil), chassisClusterPath...), leaf)
			if localSet {
				if err := incoming.SetPath(path); err != nil {
					// Fail CLOSED for the posture: if the leaf cannot be
					// restored into the peer's tree, the apply would disarm
					// it. Log loudly — this is a security-relevant edit that
					// did not happen — and leave the rest of the sync alone;
					// the runtime posture in pkg/cluster is published from the
					// COMPILED local config on the next apply, so a failure
					// here does not silently flip the live rule.
					slog.Error("cluster: could not preserve the node-local chassis leaf on a "+
						"peer config push; the pushed tree omits it (#7441)",
						"leaf", leaf, "err", err)
				}
				continue
			}
			if err := incoming.DeletePath(path); err != nil {
				slog.Error("cluster: could not strip a node-local chassis leaf a peer pushed; "+
					"this node does not have it set locally (#7441)",
					"leaf", leaf, "err", err)
			}
		}
	}
}

// chassisClusterPath is the container every node-local leaf below hangs off.
var chassisClusterPath = []string{"chassis", "cluster"}

// nodeLocalChassisLeaves is the CONTRACT: the `chassis cluster` flag leaves
// config-sync must never carry. Adding one here is the whole of making it
// node-local, and it is deliberately an explicit list rather than a predicate
// so that a new leaf is node-local only by a reviewed decision.
var nodeLocalChassisLeaves = []string{"strict-session-auth"}

// chassisClusterFlagSet reports whether a bare flag leaf is present under
// `chassis cluster` in tree. A nil tree reports false, which is what makes a
// not-yet-committed node preserve nothing.
func chassisClusterFlagSet(tree *config.ConfigTree, leaf string) bool {
	if tree == nil {
		return false
	}
	chassis := tree.FindChild("chassis")
	if chassis == nil {
		return false
	}
	cluster := chassis.FindChild("cluster")
	if cluster == nil {
		return false
	}
	return cluster.FindChild(leaf) != nil
}
