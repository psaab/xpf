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
// observation and daemon connection epoch that produced it. minProtocol
// is the STRICTEST per-feature floor the authorized config needs
// (multi-zone scoped policy v4 and/or NAT64 multi-RI v64), so the
// queue boundary revalidates against the same requirement.
type peerSnapshotProtocolAuthorization struct {
	session       *cluster.SessionSync
	state         cluster.PeerSnapshotState
	peerConnEpoch uint64
	minProtocol   uint16
	// nat64RI / multiZone mark which feature(s) the config carries,
	// for the operator-facing refusal reason.
	nat64RI   bool
	multiZone bool
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
	hasMultiZone := clustered && userspace.ConfigHasMultiZoneScopedPolicy(cand)
	hasNAT64RI := clustered && userspace.ConfigHasMultiRoutingInstanceNAT64(cand)
	if !hasMultiZone && !hasNAT64RI {
		return nil, nil
	}
	ss := d.getSessionSync()
	state := cluster.PeerSnapshotState{}
	if ss != nil {
		state = ss.SnapshotPeerSnapshotProtocol()
	}
	minProtocol := uint16(0)
	if hasMultiZone {
		minProtocol = userspace.MinProtocolMultiZoneScopedPolicy
	}
	if hasNAT64RI && uint16(userspace.MinProtocolNAT64RoutingInstanceList) > minProtocol {
		minProtocol = uint16(userspace.MinProtocolNAT64RoutingInstanceList)
	}
	auth := &peerSnapshotProtocolAuthorization{
		session:       ss,
		state:         state,
		peerConnEpoch: d.syncPeerConnEpoch.Load(),
		minProtocol:   minProtocol,
		nat64RI:       hasNAT64RI,
		multiZone:     hasMultiZone,
	}
	err := peerSnapshotProtocolDecision(true, state.Connected, hasMultiZone, hasNAT64RI, state.Version)
	return auth, err
}

// currentPeerSnapshotObservation captures the daemon epoch and selected
// SessionSync capability for a deferral attempt. The report path compares both
// again under its alarm lock and discards stale observations.
func (d *Daemon) currentPeerSnapshotObservation() (uint64, cluster.PeerSnapshotState) {
	if d == nil {
		return 0, cluster.PeerSnapshotState{}
	}
	epoch := d.syncPeerConnEpoch.Load()
	state := cluster.PeerSnapshotState{}
	if ss := d.getSessionSync(); ss != nil {
		state = ss.SnapshotPeerSnapshotProtocol()
	}
	return epoch, state
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
		if current.Connected && current.Version < auth.minProtocol {
			err := peerSnapshotProtocolDecisionForAuth(auth, current.Version)
			d.reportPeerSnapshotConfigSyncDeferred(configText, currentEpoch, current, err.Error())
			return false, err
		}
		if !current.Connected {
			return false, nil
		}
		reason := "peer connection or snapshot capability changed after commit preflight; reconciliation will retry against the current peer state"
		return false, fmt.Errorf("%w: %s", ErrPeerSnapshotProtocolAuthorizationStale, reason)
	}
	if !current.Connected {
		return false, nil
	}
	if current.Version < auth.minProtocol {
		err := peerSnapshotProtocolDecisionForAuth(auth, current.Version)
		d.reportPeerSnapshotConfigSyncDeferred(configText, currentEpoch, current, err.Error())
		return false, err
	}
	return true, nil
}

// peerSnapshotProtocolDecisionForAuth renders the refusal for the
// feature(s) the authorized config actually carries. A NAT64-RI auth
// captured the v64 floor; a multi-zone-only auth captured v4. When
func peerSnapshotProtocolDecisionForAuth(auth *peerSnapshotProtocolAuthorization, peerProto uint16) error {
	if auth == nil {
		return nil
	}
	return peerSnapshotProtocolDecision(true, true, auth.multiZone, auth.nat64RI, peerProto)
}

// peerSnapshotProtocolDecision is the gate's whole decision, split out from the
// Daemon so every combination is directly testable. A *SessionSync cannot be
// driven into the "connected, advertising v3" state from outside pkg/cluster —
// its connection state is unexported — so a method-only gate would be testable
// mainly in the arms that return nil, which is the half that proves least.
// hasNAT64RI (#16049) arms the v64 NAT64 multi-RI floor alongside the
// v4 multi-zone floor; the strictest applicable floor governs.
func peerSnapshotProtocolDecision(clustered, peerConnected, hasMultiZone, hasNAT64RI bool, peerProto uint16) error {
	if !clustered || !peerConnected || (!hasMultiZone && !hasNAT64RI) {
		return nil
	}
	// peerProto == 0 is a CONNECTED peer that advertised nothing, i.e. a build
	// predating #6650 — which necessarily predates every floor too. Say so
	// explicitly rather than printing "version 0", which reads like a decode bug.
	peerDesc := fmt.Sprintf("%d", peerProto)
	if peerProto == 0 {
		peerDesc = "pre-#6650 (advertises no version)"
	}
	if hasNAT64RI && peerProto < uint16(userspace.MinProtocolNAT64RoutingInstanceList) {
		return fmt.Errorf(
			"%w: this config contains a NAT64 rule-set scoped to multiple routing-instances, which needs config-snapshot "+
				"protocol %d; the cluster peer is at %s and would recompile the config text with last-routing-instance-wins, "+
				"silently TRUNCATING the NAT64 scope on that node. Upgrade the peer, then re-commit "+
				"(or scope each NAT64 rule-set to a single routing-instance, which both nodes represent identically)",
			ErrPeerSnapshotProtocolIncompatible,
			userspace.MinProtocolNAT64RoutingInstanceList,
			peerDesc,
		)
	}
	if hasMultiZone && peerProto < userspace.MinProtocolMultiZoneScopedPolicy {
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
	return nil
}
