package configstore

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// validatePeerStrictPipeline runs the strict commit pipeline — the same steps
// compileTreeStrict runs for the submitting node — against the PEER node's
// effective view of a chassis-cluster candidate (#9619).
//
// A shared commit is strict-checked on one node only, and what config-sync
// carries to the other node is the raw group tree, which that node ingests on
// the tolerant path (Store.SyncApply -> compileTreeLenient), where every strict
// gate is a warning. So a value that only the peer's `${node}` expansion
// selects — `groups node1 system dataplane ring-entries 16385`, or
// `groups node1 chassis cluster reth-advertise-interval 40960` — committed
// green on node0 and installed on node1 with nothing refusing it, although
// node1's own commit rejects the identical value. The #5876/#4785 registry
// (config.ValidatePeerEffectiveStrict) closed that for two named subjects; every
// other strict gate stayed open, and each new gate added anywhere in pkg/config
// was another peer-only hole. Running the pipeline itself on the peer view
// closes the class rather than the next member of it.
//
// peerTree must be the tree the peer will compile: compileTreeStrict hands in
// its clone with rewriteRetiredDataplaneType already applied (#6861 F2), the
// same rewrite SyncApply performs before compileTreeLenient.
//
// Every step is the local one, unchanged, so the peer is refused exactly what
// its own commit would refuse:
//   - schemaValidateExpandedTreeForNode: typed-leaf ranges and references on the
//     peer's apply-groups expansion (both #9619 witnesses fail here);
//   - config.CompileConfigForNode: every compiler-side strict gate;
//   - crossCheckRAIntervals: the #4525 min/max ratio on the peer's view.
//   - crossCheckLoginIdleTimeout10828: unsupported login-class deadlines.
//
// crossCheckNodeID is the one step NOT run for the peer. It compares the
// compiled `chassis cluster node` leaf with the node-id file of the host doing
// the check, and the origin holds no such file for the peer. A config authored
// for one node with a literal `node 0` leaf is an accepted check-config and
// commit input on that node (TestCheckTextNodeIDMismatchRejected,
// TestCheckTextAcceptsKeyedCluster_6611, the #8444 fabric cells), and the same
// text evaluated for node1 would always "mismatch". The case where that literal
// leaf does reach node1 by config-sync is the #4185 review Finding 2 warning on
// the tolerant ingress; refusing it at the origin would change what day-0
// check-config accepts, which is a separate decision from this gap.
//
// The error names the peer node and wraps the underlying gate's error, so the
// operator sees which node would receive the value and which rule it breaks.
//
// Standalone (nodeID < 0) and any id without a two-node peer are a no-op. The
// tolerant ingresses do not call this, so a config already on disk that is
// invalid for this node still loads with its warnings (#1960).
func validatePeerStrictPipeline(peerTree *config.ConfigTree, nodeID int) error {
	return validatePeerStrictPipelineWithCurrent(peerTree, nodeID, nil)
}

// validatePeerStrictPipelineWithCurrent is validatePeerStrictPipeline
// with the peer's own persisted/current compiled config supplied for the
// #16025 fold-3 staged-rotation gate. The peer view uses the same shared
// candidate tree, but the exception's "existing primary" proof must be
// the peer's persisted primary, not the local node's: both nodes hold
// the same persisted primary in a synced cluster, yet the gate derives
// it per-view so a peer whose persisted primary differs (or is absent)
// does not inherit the local node's migration state. Callers without
// persisted state pass nil, keeping the exception closed for the peer
// exactly as fold 2 keeps it closed locally.
func validatePeerStrictPipelineWithCurrent(peerTree *config.ConfigTree, nodeID int, peerCurrent *config.Config) error {
	return validatePeerStrictPipelineJudged(peerTree, nodeID, peerCurrent, peerCurrent != nil)
}

// validatePeerStrictPipelineJudged runs the peer view with the same #18744
// placeholder decision as the local view, so a shared commit cannot pass on
// one node's view and be refused on the other's.
func validatePeerStrictPipelineJudged(peerTree *config.ConfigTree, nodeID int, peerCurrent *config.Config, judgePlaceholders bool) error {
	peerID, ok := config.PeerNodeID(nodeID)
	if peerTree == nil || !ok {
		return nil
	}
	if err := schemaValidateExpandedTreeForNode(peerTree, peerID); err != nil {
		return peerStrictError(peerID, err)
	}
	peerCompiled, err := config.CompileConfigForNodeJudgingPlaceholders(peerTree, peerID, peerCurrent, judgePlaceholders)
	if err != nil {
		return peerStrictError(peerID, err)
	}
	if err := crossCheckRAIntervals(peerCompiled); err != nil {
		return peerStrictError(peerID, err)
	}
	if err := crossCheckLoginIdleTimeout10828(peerCompiled); err != nil {
		return peerStrictError(peerID, err)
	}
	return nil
}

func peerStrictError(peerID int, err error) error {
	return fmt.Errorf("chassis cluster peer node%d: the shared commit is invalid on node%d's "+
		"effective configuration, and config-sync would install it there (#9619): %w",
		peerID, peerID, err)
}
