package cluster

import "time"

// HAState is the typed cluster HA state behind GetClusterHAState and the
// rolling / kernel-drain safety predicates (#17095).
//
// Before #17095 every predicate scraped `show chassis cluster
// information|status` text; a present-but-garbled value collapsed to 0
// and permitted a drain (#14991), and any operator-facing rewording
// could abort or permit a roll. The text renderers in status.go keep
// their operator formatting, but the machine contract is THIS struct:
// presence is explicit (PeerHAProtocol / PeerSessionSyncWire are nil
// when absent, which proto3 `optional` carries on the wire), malformed
// is unrepresentable, and a zero version is never confused with an
// absent one. Adding a gate input is now a field addition here plus a
// renderer line — never a new text parser.
type HAState struct {
	LocalNodeID int
	ClusterID   int
	PeerAlive   bool
	PeerNodeID  int // meaningful only when PeerAlive

	// SyncEstablished mirrors the text predicate: peer alive AND the
	// session/fabric sync link is up.
	SyncEstablished bool
	// BulkPrimed is the inbound bulk session snapshot for the current
	// sync epoch (#10261; never timeout-released).
	BulkPrimed bool

	// LocalHAProtocol is this node's HA protocol version (always set).
	LocalHAProtocol uint16
	// PeerHAProtocol is nil when the peer is not alive.
	PeerHAProtocol *uint16
	// LocalSessionSyncWire is this node's session-sync wire version.
	LocalSessionSyncWire uint16
	// PeerSessionSyncWirePresent mirrors the text render: the peer wire
	// line is rendered whenever the peer is alive, so this is true
	// exactly when PeerAlive. It preserves the #7990 distinction
	// between "line absent" (instrument unreadable — refuse) and
	// "unknown" (peer predates #7990 — permit).
	PeerSessionSyncWirePresent bool
	// PeerSessionSyncWire is nil when the peer advertises nothing
	// (predates #7990); non-nil otherwise. Malformed is impossible.
	PeerSessionSyncWire *uint16

	Groups []HARGState
}

// HARGState is one redundancy group's typed state (#17095). States use
// the cluster NodeState values; an absent peer group is represented by
// PeerStateKnown=false rather than a fabricated state.
type HARGState struct {
	ID              int
	LocalState      NodeState
	PeerState       NodeState
	PeerStateKnown  bool // false when peer not alive / group unadvertised
	TakeoverReady   bool // folds the takeover-hold window, like the text render
	TakeoverReasons []string
	TransferReady   bool
	TransferReasons []string
	Weight          int // local effective weight (0 = ForceSecondary drain)
	FailoverCount   int
	LocalPriority   int
	PeerPriority    int
	MonitorFailures []string
}

// HAState snapshots the typed HA state from the manager. It is the
// single source the gRPC GetClusterHAState handler serves; the text
// renderers keep their own operator formatting over the same manager
// fields, and the parity test in status_ha_state_17095_test.go pins
// them to agree on every gate input.
func (m *Manager) HAState() HAState {
	states := m.GroupStates()

	m.mu.RLock()
	peerAlive := m.peerAlive
	peerNodeID := m.peerNodeID
	localProtocol := normalizeHAProtocolVersion(m.localHAProtocolVersion)
	var peerProtocol *uint16
	if peerAlive {
		v := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
		peerProtocol = &v
	}
	bulkPrimed := m.syncBulkPrimed
	peerGroups := make(map[int]PeerGroupState, len(m.peerGroups))
	for k, v := range m.peerGroups {
		peerGroups[k] = v
	}
	hold := m.takeoverHoldTime
	m.mu.RUnlock()

	st := HAState{
		LocalNodeID:                m.nodeID,
		ClusterID:                  m.clusterID,
		PeerAlive:                  peerAlive,
		PeerNodeID:                 peerNodeID,
		BulkPrimed:                 bulkPrimed,
		LocalHAProtocol:            localProtocol,
		PeerHAProtocol:             peerProtocol,
		LocalSessionSyncWire:       SessionSyncWireVersion,
		PeerSessionSyncWirePresent: peerAlive,
	}
	if peerAlive {
		if pw := m.PeerSessionSyncWireVersion(); pw != 0 {
			v := pw
			st.PeerSessionSyncWire = &v
		}
	}
	st.SyncEstablished = peerAlive && m.IsSyncConnected()

	st.Groups = make([]HARGState, 0, len(states))
	for _, rg := range states {
		g := HARGState{
			ID:              rg.GroupID,
			LocalState:      rg.State,
			Weight:          rg.Weight,
			FailoverCount:   rg.FailoverCount,
			LocalPriority:   rg.LocalPriority,
			PeerPriority:    rg.PeerPriority,
			MonitorFailures: append([]string(nil), rg.MonitorFails...),
			TransferReady:   rg.TransferReady,
			TransferReasons: append([]string(nil), rg.TransferReadinessReasons...),
		}
		// Takeover readiness folds the hold window exactly like both
		// text renders (FormatStatus / FormatInformation): Ready inside
		// the hold window is NOT takeover-ready.
		if !rg.Ready {
			g.TakeoverReasons = append([]string(nil), rg.ReadinessReasons...)
		} else if rem := rg.TakeoverHoldRemaining(hold); rem > 0 {
			g.TakeoverReasons = []string{"takeover hold: " + rem.Round(time.Millisecond).String() + " remaining"}
		} else {
			g.TakeoverReady = true
		}
		if pg, ok := peerGroups[rg.GroupID]; peerAlive && ok {
			g.PeerState = pg.State
			g.PeerStateKnown = true
		}
		st.Groups = append(st.Groups, g)
	}
	return st
}
