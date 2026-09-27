package daemon

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// ErrPeerSnapshotProtocolIncompatible reports that a connected cluster peer
// cannot represent the active multi-zone policy shape without narrowing it.
// The preflight returns it before promotion; if the learned protocol becomes
// incompatible later, the daemon returns it while withholding the queue write
// and retaining a deferred-config alarm.
var ErrPeerSnapshotProtocolIncompatible = errors.New("cluster peer cannot represent this config")

// ErrPeerSnapshotProtocolAuthorizationStale reports that the peer incarnation
// or its learned protocol changed after a config snapshot was authorized.
var ErrPeerSnapshotProtocolAuthorizationStale = errors.New("cluster peer snapshot authorization became stale")

// peerSnapshotProtocolAuthorization binds the decision to the capability
// observation and daemon connection epoch that produced it.
type peerSnapshotProtocolAuthorization struct {
	session       *cluster.SessionSync
	state         cluster.PeerSnapshotState
	peerConnEpoch uint64
}

// peerSnapshotProtocolCommitPreflight refuses a candidate that a connected
// peer cannot represent and returns the capability/epoch token required by the
// later queue boundary. A disconnected peer remains a liveness exception.
func (d *Daemon) peerSnapshotProtocolCommitPreflight(
	cand *config.Config,
) (*peerSnapshotProtocolAuthorization, error) {
	return d.peerSnapshotProtocolAuthorizationForConfig(cand)
}

func (d *Daemon) peerSnapshotProtocolAuthorizationForConfig(
	cand *config.Config,
) (*peerSnapshotProtocolAuthorization, error) {
	if d == nil || cand == nil {
		return nil, nil
	}
	clustered := d.cluster != nil && cand.Chassis.Cluster != nil && cand.Chassis.Cluster.ConfigSync
	if !clustered || !userspace.ConfigHasMultiZoneScopedPolicy(cand) {
		return nil, nil
	}
	ss := d.getSessionSync()
	state := cluster.PeerSnapshotState{}
	if ss != nil {
		state = ss.SnapshotPeerSnapshotProtocol()
	}
	auth := &peerSnapshotProtocolAuthorization{
		session:       ss,
		state:         state,
		peerConnEpoch: d.syncPeerConnEpoch.Load(),
	}
	err := peerSnapshotProtocolDecision(true, state.Connected, true, state.Version)
	return auth, err
}

// revalidatePeerSnapshotAuthorization is the daemon-side pre-queue check. The
// SessionSync queue repeats this atomically with its final socket write; this
// check also protects the test seam and provides an operator-facing reason.
func (d *Daemon) revalidatePeerSnapshotAuthorization(
	auth *peerSnapshotProtocolAuthorization,
	configText string,
) (bool, error) {
	if auth == nil {
		return true, nil
	}
	ss := d.getSessionSync()
	currentEpoch := d.syncPeerConnEpoch.Load()
	current := cluster.PeerSnapshotState{}
	if ss != nil {
		current = ss.SnapshotPeerSnapshotProtocol()
	}
	if ss != auth.session || currentEpoch != auth.peerConnEpoch || current != auth.state {
		if current.Connected && current.Version < userspace.MinProtocolMultiZoneScopedPolicy {
			err := peerSnapshotProtocolDecision(true, true, true, current.Version)
			d.reportPeerSnapshotConfigSyncDeferred(configText, currentEpoch, err.Error())
			return false, err
		}
		reason := "peer connection or snapshot capability changed after commit preflight; config sync is deferred until reconciliation"
		d.reportPeerSnapshotConfigSyncDeferred(configText, currentEpoch, reason)
		return false, fmt.Errorf("%w: %s", ErrPeerSnapshotProtocolAuthorizationStale, reason)
	}
	if !current.Connected {
		return false, nil
	}
	if current.Version < userspace.MinProtocolMultiZoneScopedPolicy {
		err := peerSnapshotProtocolDecision(true, true, true, current.Version)
		d.reportPeerSnapshotConfigSyncDeferred(configText, currentEpoch, err.Error())
		return false, err
	}
	return true, nil
}

// peerSnapshotProtocolDecision is the gate's whole decision, split out from the
// Daemon so every combination is directly testable. A *SessionSync cannot be
// driven into the "connected, advertising v3" state from outside pkg/cluster —
// its connection state is unexported — so a method-only gate would be testable
// mainly in the arms that return nil, which is the half that proves least.
func peerSnapshotProtocolDecision(clustered, peerConnected, hasMultiZone bool, peerProto uint16) error {
	if !clustered || !peerConnected || !hasMultiZone {
		return nil
	}
	if peerProto >= userspace.MinProtocolMultiZoneScopedPolicy {
		return nil
	}
	// peerProto == 0 is a CONNECTED peer that advertised nothing, i.e. a build
	// predating #6650 — which necessarily predates v4 too. Say so explicitly
	// rather than printing "version 0", which reads like a decode bug.
	peerDesc := fmt.Sprintf("%d", peerProto)
	if peerProto == 0 {
		peerDesc = "pre-#6650 (advertises no version)"
	}
	return fmt.Errorf(
		"%w: this config contains a multi-zone scoped policy, which needs config-snapshot "+
			"protocol %d; the cluster peer is at %s and would read only the first zone of the "+
			"scope, silently NARROWING the policy on that node. Upgrade the peer, then re-commit "+
			"(or express the policy as one rule per zone, which both nodes represent identically)",
		ErrPeerSnapshotProtocolIncompatible,
		userspace.MinProtocolMultiZoneScopedPolicy,
		peerDesc,
	)
}
