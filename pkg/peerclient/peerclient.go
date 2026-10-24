// Package peerclient holds the transport-neutral peer-proxy
// reconciliation shared by the CLI and gRPC peer-proxy frontends
// (#16154).
//
// The two frontends dial differently and must stay different:
//   - pkg/cli's dialPeer tries fab0 then fab1 behind a background TCP
//     reachability probe and returns nil when no fabric address is
//     reachable;
//   - pkg/grpcapi's Server.dialPeer is ctx-bound and probes liveness
//     with an RPC/GetStatus call, where a ResourceExhausted response
//     still means the peer is alive (#8597).
//
// Unifying those dialers would flip wedged-server reachability and
// could change fabric-auth / signed-request metadata handling, so
// only the pure reconciliation table is shared here: the proxy
// timeout sizing (TimeoutFor), deadline classification (IsDeadline),
// and the post-deadline ownership reconciliation (Reconcile). Each
// frontend keeps its own dialer, its own RPC deadline construction,
// and its own fabric-auth credential/token construction.
package peerclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/clusterfailover"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultTimeout is the historical budget for an ordinary forwarded
// SystemAction. Only a node-targeted cluster failover gets the
// larger cluster-budget sizing (see TimeoutFor).
const DefaultTimeout = 5 * time.Second

// TimeoutFor sizes the deadline for a forwarded SystemAction.
// Ordinary actions keep the historical 5s budget; a forwarded
// node-targeted cluster failover (#15081) runs the peer's full
// RequestPeerFailover sequence (ACK + settle + commit, each bounded
// well above 5s), so it uses the cluster-budget sizing
// (clusterfailover.ProxyFailoverTimeout).
func TimeoutFor(action string) time.Duration {
	if clusterfailover.IsFailoverActionString(action) {
		return clusterfailover.ProxyFailoverTimeout
	}
	return DefaultTimeout
}

// IsDeadline reports whether err is a context/gRPC deadline outcome:
// the local context expired (context.DeadlineExceeded) or the peer
// returned codes.DeadlineExceeded.
func IsDeadline(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return status.Code(err) == codes.DeadlineExceeded
}

// Ownership is transport-neutral snapshot of peer RG ownership used
// to reconcile a timed-out forwarded failover. It is satisfied by
// *cluster.Manager; both frontends pass their manager directly, so
// no per-surface adapter code is required.
type Ownership interface {
	// IsPeerPrimary reports whether the peer is primary for rg.
	IsPeerPrimary(rg int) bool
	// PeerAlive reports whether the peer is currently reachable.
	PeerAlive() bool
	// PeerPrimaryRGs returns the data redundancy groups the peer
	// currently owns as primary, and whether the peer is alive.
	PeerPrimaryRGs() (rgs []int, peerAlive bool)
	// DataGroupIDs returns the configured non-control redundancy
	// groups in ascending order.
	DataGroupIDs() []int
}

// Outcome is the machine-readable verdict of a post-deadline
// reconciliation (#15081, #16432). It lets a status-checking client
// distinguish a committed transfer from an unknown one without
// parsing the human-readable message.
type Outcome int

const (
	// OutcomeNone means Reconcile did not reconcile the error: the
	// caller relays the original error unchanged.
	OutcomeNone Outcome = iota
	// OutcomeCommitted means ownership moved as requested (peer
	// primary for the RG, or for every data RG).
	OutcomeCommitted
	// OutcomeUnknown means the proxy leg timed out and ownership did
	// not move as requested, or the peer is unreachable: the transfer
	// may still commit later, so the operator must verify ownership
	// before retrying or proceeding.
	OutcomeUnknown
)

// Reconcile reconciles a forwarded failover whose proxy leg hit a
// deadline against current RG ownership (#15081): the peer may have
// committed after the proxy gave up, so a bare DeadlineExceeded must
// never reach the operator for this path.
//
// It returns (message, OutcomeCommitted) when ownership moved as
// requested, (message, OutcomeUnknown) when ownership did not move
// or the peer is unreachable, and ("", OutcomeNone) otherwise (the
// caller relays the original error). view may be nil (standalone /
// no cluster view), in which case it returns ("", OutcomeNone).
//
//	outcome for a targeted failover after a deadline:
//	  - ownership moved as requested (peer primary for the RG, or for
//	    every data RG): OutcomeCommitted ("transfer committed");
//	  - peer reachable but ownership did not move: OutcomeUnknown
//	    with the peer's current primary set;
//	  - peer unreachable / no cluster view: OutcomeUnknown
//	    (or OutcomeNone when there is no view at all, matching the
//	    CLI's existing nil-cluster gate).
func Reconcile(view Ownership, op clusterfailover.Op, err error) (string, Outcome) {
	if err == nil || view == nil {
		return "", OutcomeNone
	}
	if !IsDeadline(err) {
		return "", OutcomeNone
	}
	if !op.Targeted() {
		return "", OutcomeNone
	}
	switch op.Kind {
	case clusterfailover.KindRGFailoverNode:
		if view.IsPeerPrimary(op.RG) {
			return fmt.Sprintf("Manual failover completed for redundancy group %d (transfer committed on node %d; proxy response timed out after the peer committed)", op.RG, op.Node), OutcomeCommitted
		}
		if !view.PeerAlive() {
			return fmt.Sprintf("Cluster failover outcome unknown for redundancy group %d: forwarded request to node %d timed out and the peer is unreachable; verify redundancy group %d ownership before retrying", op.RG, op.Node, op.RG), OutcomeUnknown
		}
		return fmt.Sprintf("Cluster failover outcome unknown for redundancy group %d: forwarded request to node %d timed out; redundancy group %d is not primary on node %d — verify ownership before retrying", op.RG, op.Node, op.RG, op.Node), OutcomeUnknown
	case clusterfailover.KindDataFailover:
		peerRGs, peerAlive := view.PeerPrimaryRGs()
		if !peerAlive {
			return fmt.Sprintf("Data failover outcome unknown: forwarded request to node %d timed out and the peer is unreachable; verify redundancy group ownership before retrying", op.Node), OutcomeUnknown
		}
		// The peer-side handler moves exactly the data RGs not already
		// primary on the target; "committed" means every data RG is now
		// primary on the peer. A partial set is reported as unknown.
		if dataRGs := view.DataGroupIDs(); len(dataRGs) > 0 && len(peerRGs) == len(dataRGs) {
			committed := true
			for _, rgID := range dataRGs {
				found := false
				for _, prg := range peerRGs {
					if prg == rgID {
						found = true
						break
					}
				}
				if !found {
					committed = false
					break
				}
			}
			if committed {
				return fmt.Sprintf("Manual failover completed for data redundancy groups %v (transfer committed on node %d; proxy response timed out after the peer committed)", dataRGs, op.Node), OutcomeCommitted
			}
		}
		return fmt.Sprintf("Data failover outcome unknown: forwarded request to node %d timed out; data redundancy groups now primary on node %d: %v — verify ownership before retrying", op.Node, op.Node, peerRGs), OutcomeUnknown
	}
	return "", OutcomeNone
}
