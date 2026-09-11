package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrHeartbeatStartSuperseded reports that a StartHeartbeat was overtaken by a
// StopHeartbeat while it was creating its sockets, so it declined to publish
// (#7257). It is a lifecycle outcome, not a failure: the caller asked for a
// heartbeat that the cluster has since torn down. A bind-retry loop must treat
// it as terminal — retrying would race the same teardown again, and on success
// would resurrect a heartbeat the teardown exists to remove.
var ErrHeartbeatStartSuperseded = errors.New("cluster: heartbeat start superseded by teardown")

// heartbeatUDPNetwork returns the UDP network string ("udp4" or "udp6") for a
// literal control-link IP so the heartbeat sockets follow the configured
// address family. A v4 (or v4-mapped) literal yields "udp4"; a v6 literal
// yields "udp6". An address that is not a parseable literal falls back to
// "udp4" — the historical default — so a malformed value fails the same way
// it always did. The daemon may hand StartHeartbeat an IPv6 control-link
// address (selectClusterBindAddr honours an IPv6 peer via
// globalIPv6Candidates), so hardcoding "udp4" made an IPv6 control link
// unusable (#4549 F9); deriving the family here keeps v4 bit-identical while
// letting a v6 control link bind.
func heartbeatUDPNetwork(addr string) string {
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return "udp6"
	}
	return "udp4"
}

// StartHeartbeat launches heartbeat sender and receiver goroutines.
// localAddr is the local control link IP, peerAddr is the peer control link IP.
// vrfDevice is optional — if non-empty, sockets bind to that VRF device so
// packets route through the correct table.
//
// StartHeartbeat is idempotent: a heartbeat that is already running is torn
// down (cancel + join) BEFORE the new sender/receiver are installed, so
// exactly one heartbeat goroutine set exists at a time. Without this a second
// StartHeartbeat (e.g. a comms restart, or the daemon's bind-retry goroutine
// racing RestartHeartbeat) would overwrite m.hbSender/m.hbReceiver and leak
// the previous goroutines — their stopCh is never closed, so N restarts leak
// N heartbeat goroutines and duplicate the on-wire heartbeat rate (#4033).
func (m *Manager) StartHeartbeat(localAddr, peerAddr, vrfDevice, controlIface string) error {
	// Serialize the whole stop-previous + create + install sequence so
	// concurrent callers cannot interleave and both install a heartbeat.
	// hbStartMu is distinct from m.mu: StopHeartbeat below takes m.mu and
	// joins goroutines that also take m.mu.
	m.hbStartMu.Lock()
	defer m.hbStartMu.Unlock()

	// Stop any heartbeat that is already running before installing a new one.
	// Safe to call unconditionally — it is a no-op when nothing is running.
	m.StopHeartbeat()

	// #7257: the lifecycle tenure this start belongs to.
	//
	// Captured HERE, deliberately — after the #4033 idempotent teardown above,
	// not at function entry. That teardown is a StopHeartbeat, so it bumps
	// hbEpoch too; an entry-time capture would compare against a value this
	// call had itself invalidated and every start would refuse to publish.
	// The window that actually needs guarding is exactly the one that opens
	// now: socket creation is unbounded in time (two binds, possibly against a
	// VRF that is still settling), and an EXTERNAL StopHeartbeat landing in it
	// must supersede us.
	m.mu.RLock()
	startEpoch := m.hbEpoch
	hook := m.hbStartInWindowHook
	m.mu.RUnlock()
	// Test seam: land a concurrent teardown inside the guarded window. nil in
	// production. Called with no lock held — the hook takes m.mu itself.
	if hook != nil {
		hook()
	}

	m.mu.Lock()
	interval := m.hbInterval
	threshold := m.hbThreshold
	m.mu.Unlock()

	// #6169: kick this node's boot-epoch resolution. This MUST NOT BLOCK —
	// StopHeartbeat() above has already torn the heartbeat down, so any wait
	// here is a window with no frames going out at all, which a peer cannot
	// tell apart from a dead node. An earlier revision waited up to 2s for the
	// persisted value and measured 2.005s/2.012s/2.011s against a 500ms
	// dead-peer threshold under a wedged store. It buys nothing now: the
	// wall-clock epoch is published synchronously before any I/O, so the frame
	// already carries one and persistence catches up off-path.
	m.initHeartbeatEpochState()

	// Select the UDP network from the control-link address family so a v6
	// control link binds; v4 stays "udp4". net.JoinHostPort brackets a v6
	// literal (fd00::1 -> [fd00::1]:port) — plain "%s:%d" would produce an
	// unparseable address for IPv6.
	network := heartbeatUDPNetwork(localAddr)
	portStr := strconv.Itoa(HeartbeatPort)

	// Resolve peer address.
	peer, err := net.ResolveUDPAddr(network, net.JoinHostPort(peerAddr, portStr))
	if err != nil {
		return fmt.Errorf("resolve peer addr: %w", err)
	}

	// Bind receiver to local address.
	local, err := net.ResolveUDPAddr(network, net.JoinHostPort(localAddr, portStr))
	if err != nil {
		return fmt.Errorf("resolve local addr: %w", err)
	}

	lc := vrfListenConfig(vrfDevice)

	recvPkt, err := lc.ListenPacket(context.Background(), network, local.String())
	if err != nil {
		return fmt.Errorf("listen heartbeat: %w", err)
	}
	recvConn := recvPkt.(*net.UDPConn)

	// Create sender socket (bound to local address).
	sendAddr := net.JoinHostPort(localAddr, "0")
	sendPkt, err := lc.ListenPacket(context.Background(), network, sendAddr)
	if err != nil {
		recvConn.Close()
		return fmt.Errorf("sender socket: %w", err)
	}
	sendConn := sendPkt.(*net.UDPConn)

	m.mu.Lock()
	// #7257: refuse a start that a teardown superseded. StopHeartbeat bumps
	// hbEpoch under this same lock, so comparing the entry epoch HERE — in the
	// critical section that publishes — makes "was I superseded?" and "publish"
	// atomic with respect to it. Socket creation above is unbounded in time (two
	// binds, possibly against a VRF that is still settling), so a stop landing in
	// that gap is not theoretical.
	if m.hbEpoch != startEpoch {
		m.mu.Unlock()
		recvConn.Close()
		sendConn.Close()
		slog.Info("cluster: heartbeat start superseded by a teardown, not publishing",
			"local", localAddr, "peer", peerAddr)
		return ErrHeartbeatStartSuperseded
	}
	sender := newHeartbeatSender(m, sendConn, peer, interval)
	receiver := newHeartbeatReceiver(m, recvConn, threshold, interval, peer)
	m.hbSender = sender
	m.hbReceiver = receiver
	m.hbLocalAddr = localAddr
	m.hbPeerAddr = peerAddr
	m.hbVRFDevice = vrfDevice
	m.hbControlIface = controlIface
	// Start the LOCALS, and start them INSIDE the critical section (#7257).
	// Locals because the pre-#7257 code re-read m.hbReceiver/m.hbSender after
	// unlocking, which raced StopHeartbeat nilling them — a nil-deref panic if
	// the stop won. Inside because publishing and starting must be one step: a
	// stop that interleaves between them would capture the handles and stop
	// goroutines that had not been spawned yet, and the spawns would then run
	// with nothing able to stop them. start() only spawns (`go run()` /
	// `go readLoop()` + `go timeoutLoop()`), so it cannot block on this lock.
	receiver.start()
	sender.start()
	m.mu.Unlock()

	slog.Info("cluster: heartbeat started",
		"local", localAddr, "peer", peerAddr,
		"interval", interval, "threshold", threshold)
	return nil
}

// vrfListenConfig returns a net.ListenConfig that binds sockets to a VRF device
// via SO_BINDTODEVICE with SO_REUSEADDR+SO_REUSEPORT to allow immediate rebind
// after a restart (even if old sockets linger from a killed process).
// If vrfDevice is empty, only SO_REUSEADDR+SO_REUSEPORT are set.
func vrfListenConfig(vrfDevice string) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				// Allow immediate rebind after restart — the kernel may
				// still hold the old socket briefly after process death.
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					unix.SO_REUSEADDR, 1)
				_ = unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					unix.SO_REUSEPORT, 1)
				if vrfDevice != "" {
					err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET,
						syscall.SO_BINDTODEVICE, vrfDevice)
				}
			})
			return err
		},
	}
}

// HeartbeatRunning reports whether a heartbeat sender or receiver is currently
// installed. Used by status reporting and to assert the idempotent
// start/stop discipline (#4033).
func (m *Manager) HeartbeatRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hbSender != nil || m.hbReceiver != nil
}

// StopHeartbeat halts heartbeat sender and receiver goroutines.
func (m *Manager) StopHeartbeat() {
	m.mu.Lock()
	sender := m.hbSender
	receiver := m.hbReceiver
	m.hbSender = nil
	m.hbReceiver = nil
	// #7257: supersede any StartHeartbeat that is mid-flight. It captured the
	// previous epoch on entry and compares it under this lock before publishing,
	// so from here on it cannot install a pair this Stop would never see.
	// RestartHeartbeat is unaffected: it stops first, and the StartHeartbeat it
	// then calls captures the POST-bump epoch on its own entry.
	m.hbEpoch++
	m.mu.Unlock()

	if sender != nil {
		sender.stop()
	}
	if receiver != nil {
		receiver.stop()
	}
}

// ApplyCommittedHeartbeatTiming restarts the heartbeat when the COMMITTED
// interval/threshold differ from what the RUNNING heartbeat is actually using,
// and reports whether it restarted.
//
// #7164: StartHeartbeat snapshots m.hbInterval/m.hbThreshold into the sender and
// receiver; UpdateConfig rewrites those manager fields on every commit; and
// RestartHeartbeat had exactly ONE production caller, the VRF-rebind path. So
// `set chassis cluster heartbeat-interval` (or `heartbeat-threshold`) updated
// the manager and never reached the wire: the sender kept the old cadence and
// the receiver kept declaring the peer dead at the old threshold*interval until
// something unrelated — a VRF rebind, a transport-key change — happened to
// rebuild it. Peers could declare death too early or too late relative to the
// committed configuration, indefinitely.
//
// #5081 made that divergence CORRECT-BY-CONSTRUCTION wherever it is consumed
// (every derived duration is sized from liveHeartbeatTimingLocked) and VISIBLE
// to the operator (the `Heartbeat pending restart:` status line). It
// deliberately did not make the commit take effect. This does, and it reuses
// #5081's own predicate rather than adding a second notion of "diverged" that
// could disagree with the line the operator is reading.
//
// The restart window is safe by an existing mechanism, not by luck:
// RestartHeartbeat invokes m.hbRestartNotifyFn, which the daemon wires to
// SessionSync.SendLivenessKeepalive so the peer's heartbeat-timeout suppression
// guard keeps observing fresh sync traffic while this node's UDP heartbeats are
// silent (#1792). That is the same protection the VRF-rebind path has always
// relied on.
//
// "Not running" is checked EXPLICITLY rather than inferred from the comparison.
// liveHeartbeatTimingLocked falls back to the desired values when no receiver
// exists, so live == desired holds both when the timing is already correct and
// when there is no heartbeat at all — two states a bare comparison cannot tell
// apart. Depending on that coincidence would make this silently wrong if the
// fallback ever changed.
func (m *Manager) ApplyCommittedHeartbeatTiming() bool {
	// The decision is heartbeatTimingDivergedLocked's, called rather than
	// restated: a second copy of the condition here could disagree with the one
	// the table in heartbeat_timing_apply_7164_test.go asserts, and then the
	// tests would pass while production restarted on the wrong commits.
	if !m.heartbeatTimingDivergedLocked() {
		return false
	}
	m.mu.RLock()
	liveInterval, liveThreshold := m.liveHeartbeatTimingLocked()
	wantInterval, wantThreshold := m.hbInterval, m.hbThreshold
	m.mu.RUnlock()
	slog.Info("cluster: heartbeat timing changed by commit, restarting heartbeat",
		"live_interval", liveInterval, "committed_interval", wantInterval,
		"live_threshold", liveThreshold, "committed_threshold", wantThreshold)
	return m.RestartHeartbeat()
}

// heartbeatTimingDivergedLocked is the DECISION half of
// ApplyCommittedHeartbeatTiming, split out so it can be asserted without
// standing up a real heartbeat.
//
// The split is deliberate: the restart MECHANISM is already covered by the
// VRF-rebind path's tests, and binding a socket in a unit test to observe a
// comparison would make the cell a bind-race rather than a statement about the
// predicate. What #7164 changed is which commits decide to restart, so that is
// what gets its own name and its own table.
func (m *Manager) heartbeatTimingDivergedLocked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.hbReceiver == nil {
		return false
	}
	liveInterval, liveThreshold := m.liveHeartbeatTimingLocked()
	return liveInterval != m.hbInterval || liveThreshold != m.hbThreshold
}

// RestartHeartbeat stops and restarts the heartbeat with the same parameters.
// This is needed when the control interface's VRF binding changes (e.g. during
// DHCP-triggered recompile) which invalidates the existing UDP sockets.
// Retries up to 5 times with 1s delay if the bind fails (address may briefly
// disappear during VRF rebind). Returns false if heartbeat was not running.
//
// The restart window (worst case ~5s of bind retries) is longer than the
// peer's default timeout (5 x 100ms), so two protections wrap it (#1792):
//
//   - Peer side: hbRestartNotifyFn fires before teardown and after each
//     failed bind retry. The daemon wires it to
//     SessionSync.SendLivenessKeepalive, which refreshes the peer's
//     LastPeerReceiveAge — the signal its heartbeat-timeout suppression
//     guard (shouldSuppressPeerHeartbeatTimeout, 2s recency window) checks
//     before fencing/electing. Suppression on the peer is bounded by its
//     existing 5s continuous-suppression cap and self-clearing (it derives
//     purely from message recency — no sticky state), so a node that dies
//     mid-restart still fails over.
//
//   - Local side: lastSeen carries over to the replacement receiver (same
//     CLOCK_MONOTONIC domain, same process) so a peer that dies while our
//     sockets are down is still detected once the post-restart 30s startup
//     grace expires. Without the seed the new receiver starts at
//     lastSeen=0, whose timeout path only invokes handlePeerNeverSeen — a
//     no-op once peerEverSeen is set — and a peer death during the restart
//     window would never be detected.
func (m *Manager) RestartHeartbeat() bool {
	m.mu.RLock()
	running := m.hbSender != nil || m.hbReceiver != nil
	localAddr := m.hbLocalAddr
	peerAddr := m.hbPeerAddr
	vrfDevice := m.hbVRFDevice
	controlIface := m.hbControlIface
	notify := m.hbRestartNotifyFn
	receiver := m.hbReceiver
	m.mu.RUnlock()

	if !running || localAddr == "" {
		return false
	}

	// Preserve the old receiver's last-seen heartbeat timestamp
	// (CLOCK_MONOTONIC nanos — comparable across an in-process restart).
	var lastSeenSeed int64
	if receiver != nil {
		lastSeenSeed = receiver.lastSeen.Load()
	}

	slog.Info("cluster: restarting heartbeat after VRF rebind",
		"local", localAddr, "peer", peerAddr, "vrf", vrfDevice)

	// Freshen the peer's sync-recency suppression guard before our UDP
	// heartbeats go silent.
	if notify != nil {
		notify()
	}

	m.StopHeartbeat()

	for i := 0; i < 5; i++ {
		if err := m.StartHeartbeat(localAddr, peerAddr, vrfDevice, controlIface); err != nil {
			slog.Warn("cluster: heartbeat restart bind failed, retrying",
				"err", err, "attempt", i+1)
			// Keep the peer's suppression guard fed (2s recency window)
			// through each 1s retry interval.
			if notify != nil {
				notify()
			}
			time.Sleep(1 * time.Second)
			continue
		}
		// Seed the replacement receiver with the pre-restart timestamp
		// unless it has already seen a live heartbeat.
		if lastSeenSeed != 0 {
			m.mu.RLock()
			newReceiver := m.hbReceiver
			m.mu.RUnlock()
			if newReceiver != nil {
				newReceiver.lastSeen.CompareAndSwap(0, lastSeenSeed)
			}
		}
		return true
	}
	slog.Error("cluster: heartbeat restart failed after retries")
	return false
}

// buildHeartbeat creates a heartbeat packet from current state.
func (m *Manager) buildHeartbeat() *HeartbeatPacket {
	m.mu.RLock()
	mon := m.monitor
	m.mu.RUnlock()

	// Collect local interface statuses outside the lock (monitor has its own).
	var localStatuses []InterfaceMonitorInfo
	if mon != nil {
		localStatuses = mon.LocalInterfaceStatuses()
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	pkt := &HeartbeatPacket{
		NodeID:            uint8(m.nodeID),
		ClusterID:         uint16(m.clusterID),
		SoftwareVersion:   m.localSoftwareVersion,
		HAProtocolVersion: m.localHAProtocolVersion,
	}
	for _, rg := range m.groups {
		pkt.Groups = append(pkt.Groups, HeartbeatGroup{
			GroupID:  wireRGID(rg.GroupID),
			Priority: clampWirePriority(rg.LocalPriority),
			Weight:   clampWireWeight(rg.Weight),
			State:    uint8(rg.State),
		})
	}

	// Include local interface monitor statuses.
	for _, ls := range localStatuses {
		pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
			RGID:      wireRGID(ls.RedundancyGroup),
			Weight:    clampWireWeight(ls.Weight),
			Up:        ls.Up,
			Interface: ls.Interface,
		})
	}
	return pkt
}

// wireRGID narrows a redundancy-group id onto the single-byte heartbeat RG
// fields (`HeartbeatGroup.GroupID`, `HeartbeatMonitor.RGID`).
//
// #8337: SATURATING, like its neighbour clampWireWeight, and for a sharper
// reason than a wrong number. A bare `uint8(id)` wraps, and the peer-group map
// is keyed by whatever byte arrives while every reader looks the map up by the
// RAW config id (election.go, status.go, failover.go, upgrade_drain.go,
// group_state.go). For any id whose low byte differs, those keys never meet,
// and `election.go` turns a missing entry into `peerAlive && peerGroup == nil
// -> electLocalPrimary, "Peer has no RG info"`. A node that is receiving and
// parsing its peer's heartbeats concludes the peer has no RG info and elects
// itself primary — a SECOND primary, not a display glitch.
//
// Saturation is deliberately not a refusal. Declining to advertise the group
// would leave the peer with no entry for it, which is the same
// `peerGroup == nil` the wrap produces — the fix would reproduce the bug.
//
// Two config ids above the ceiling collapse onto 255 and become
// indistinguishable on the wire. That is inherent to a single-byte field, not
// introduced here, and it is unreachable from a strict commit: `MaxRedundancyGroups`
// bounds an operator-typed config to 16. It is reachable through
// `Store.Load` / `Store.SyncApply`, which compile leniently — a strict gate
// bounds what an operator can TYPE, not what the runtime can hold.
func wireRGID(id int) uint8 {
	if id < 0 {
		return 0
	}
	if id > 255 {
		return 255
	}
	return uint8(id)
}

// localRGIDForWireByte maps a received wire RG byte back to the LOCAL config's
// redundancy-group id.
//
// #8337: this is what makes the peer-group map agree with its readers BY
// CONSTRUCTION rather than by a comment claiming it does. Every consumer of
// `m.peerGroups` indexes it with a raw config id; keying it by the wire byte
// was the disagreement. Resolving here — at the single producer — fixes all of
// them at once and leaves the ~8 call sites untouched, because they were
// already right.
//
// The two directions share one function: an entry matches when
// `wireRGID(local id) == received byte`, which is exactly what the sender
// computed. Nothing can drift between them without changing `wireRGID` itself.
//
// Falls back to `int(b)` when no local group matches, preserving today's
// behaviour for a group this node does not configure.
//
// #9723: the answer must not depend on map order. Several local ids can
// saturate onto one byte (every negative id onto 0, every id above 255 onto
// 255), and ranging over `m.groups` returned whichever came first, so a node
// holding RG0 and RG -1 attributed the peer's RG0 entry to either group. A local
// group whose id EQUALS the byte always wins; among saturating ids the smallest
// wins. The config's tolerant path also drops negative ids now, so RG0 cannot
// meet one through a loaded config; this keeps the lookup deterministic for any
// state that reaches the manager.
func (m *Manager) localRGIDForWireByte(b uint8) int {
	if _, ok := m.groups[int(b)]; ok {
		return int(b)
	}
	var matches []int
	for id := range m.groups {
		if wireRGID(id) == b {
			matches = append(matches, id)
		}
	}
	if len(matches) > 0 {
		sort.Ints(matches)
		return matches[0]
	}
	return int(b)
}

// clampWirePriority narrows a redundancy-group node priority onto the uint16
// heartbeat priority field by SATURATING instead of truncating (#8597, K17).
//
// Like clampWireWeight, this is the last belt and not the fix. The domain is
// closed upstream by clampNodePriority (group_state.go), so every value that
// reaches here is already in [1,254] and this is an identity today.
//
// What a bare `uint16(p)` did, and why it is a dual-primary vector rather than
// a wrong number: the wire carried the truncated value while election.go
// compared the RAW local int. A local priority of 65700 advertised as 164
// (65700 - 65536). Against a peer at 200, the local node compared 65700 > 200
// and elected itself; the peer compared 200 > 164 and elected ITSELF. Both
// nodes primary, duplicate VIPs and duplicate RETH virtual MAC on the LAN —
// the second half of the #4880 gate's own threat model, which had a strict
// commit gate and no runtime belt.
//
// Saturating rather than wrapping means a future writer who bypasses
// clampNodePriority degrades to a bounded, MONOTONIC priority. That property is
// what the election needs: two nodes can disagree about the exact number and
// still agree about the winner, but they cannot agree about the winner if one
// side's value wrapped past the other's.
func clampWirePriority(p int) uint16 {
	if p < 0 {
		return 0
	}
	if p > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(p)
}

// clampWireWeight narrows a weight onto the single-byte heartbeat weight field
// by SATURATING instead of truncating (#6549).
//
// This is the last belt, not the fix. `uint8(w)` wraps — 355 leaves as 99 —
// which is what let a node's local weight and its advertised weight disagree
// and put two primaries on the LAN. The fix is that the weight domain is closed
// upstream (rgWeightFromDebt for rg.Weight, config.ClampInterfaceMonitorWeight
// for the per-monitor weight), so every value that reaches here is already in
// [0,255] and this is an identity. Saturating rather than wrapping means a
// future writer that bypasses those helpers degrades to a bounded, monotonic
// weight instead of silently aliasing to an unrelated one.
func clampWireWeight(w int) uint8 {
	if w < 0 {
		return 0
	}
	if w > maxRedundancyGroupWeight {
		return maxRedundancyGroupWeight
	}
	return uint8(w)
}

// handlePeerHeartbeat processes an incoming peer heartbeat.
func (m *Manager) handlePeerHeartbeat(pkt *HeartbeatPacket) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	wasAlive := m.peerAlive
	m.peerAlive = true
	m.peerEverSeen = true
	m.peerNodeID = int(pkt.NodeID)
	m.peerSoftwareVersion = pkt.SoftwareVersion
	m.peerHAProtocolVersion = normalizeHAProtocolVersion(pkt.HAProtocolVersion)

	// Rebuild peer group states from scratch — prunes stale RGs that
	// the peer no longer reports (fix #92).
	newPeerGroups := make(map[int]PeerGroupState, len(pkt.Groups))
	for _, g := range pkt.Groups {
		// #8337: key by the LOCAL config id the wire byte resolves to, which is
		// how every reader of m.peerGroups indexes it.
		localID := m.localRGIDForWireByte(g.GroupID)
		newPeerGroups[localID] = PeerGroupState{
			GroupID:  localID,
			Priority: int(g.Priority),
			Weight:   int(g.Weight),
			State:    NodeState(g.State),
		}
	}
	// Apply pending transfer-commit overrides + expire transfer-grace
	// windows. The body is owned by failover.go so that the entire
	// transfer-commit state machine (override map + grace windows +
	// expiry) lives in a single file alongside
	// commitRequestedPeerFailover / notePeerTransferCommitted /
	// FinalizePeerTransferOut. handlePeerHeartbeat is just the caller
	// — heartbeat orchestration does not own transfer-commit state.
	m.applyTransferCommitOverridesOnPeerStateLocked(newPeerGroups, now)
	m.peerGroups = newPeerGroups

	// Update peer interface monitor statuses.
	if len(pkt.Monitors) > 0 {
		m.peerMonitors = make([]InterfaceMonitorInfo, len(pkt.Monitors))
		for i, mon := range pkt.Monitors {
			m.peerMonitors[i] = InterfaceMonitorInfo{
				Interface:       mon.Interface,
				Weight:          int(mon.Weight),
				Up:              mon.Up,
				RedundancyGroup: m.localRGIDForWireByte(mon.RGID),
			}
		}
	} else {
		m.peerMonitors = nil
	}

	// Update PeerPriority on local RG state for display.
	for _, rg := range m.groups {
		if pg, ok := m.peerGroups[rg.GroupID]; ok {
			rg.PeerPriority = pg.Priority
		}
	}

	if !wasAlive {
		slog.Info("cluster: peer heartbeat received",
			"peer_node", pkt.NodeID, "groups", len(pkt.Groups))
		m.history.Record(EventHeartbeat, -1, fmt.Sprintf("Peer alive (node%d)", pkt.NodeID))
	}

	m.runElection()
}

// handlePeerTimeout is called when the peer heartbeat timeout expires.
func (m *Manager) handlePeerTimeout() {
	m.mu.Lock()
	if !m.peerAlive {
		m.mu.Unlock()
		return // already marked lost
	}
	if suppress, reason := m.suppressPeerTimeoutForTransferCommitLocked(time.Now()); suppress {
		m.mu.Unlock()
		slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
		return
	}
	guard := m.peerTimeoutGuardFn
	m.mu.Unlock()

	if guard != nil {
		if suppress, reason := guard(); suppress {
			slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
			return
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerAlive {
		return // already marked lost while guard ran
	}
	// Re-check heartbeat STALENESS, not just peerAlive. m.mu is released
	// across the guard call above, so the receiver read path can run
	// handlePeerHeartbeat — setting peerAlive and advancing lastSeen — for
	// ANY guard duration, not only a slow guard fn (a configured slow guard
	// merely widens the window). peerAlive is essentially always true here
	// (it was true on entry and a fresh heartbeat only keeps it true), so
	// checking it cannot detect that a heartbeat landed during the window —
	// re-reading lastSeen against the live clock can. If the heartbeat is
	// fresh again, the peer is not lost: abort to avoid a spurious peer-loss
	// and the unnecessary failover churn that follows (#2080).
	if m.peerHeartbeatFreshLocked() {
		slog.Debug("cluster: aborting peer heartbeat timeout, fresh heartbeat arrived during guard window")
		return
	}
	if suppress, reason := m.suppressPeerTimeoutForTransferCommitLocked(time.Now()); suppress {
		slog.Debug("cluster: suppressing peer heartbeat timeout", "reason", reason)
		return
	}

	m.peerAlive = false
	m.peerGroups = make(map[int]PeerGroupState)
	m.peerMonitors = nil
	m.peerSoftwareVersion = ""
	m.peerHAProtocolVersion = 0
	slog.Warn("cluster: peer heartbeat timeout, marking peer lost")
	m.history.Record(EventHeartbeat, -1, "Peer heartbeat timeout")

	// Clear ManualFailover on all RGs: the peer is dead, so the surviving
	// node MUST be able to take over. Without this, a previous manual
	// transfer-out would keep the local node parked in secondary-hold even
	// though there is no longer a peer to hand ownership to.
	//
	// #9640: restore the weight WITHOUT electing, with the helper electRG uses
	// when it clears a manual failover for the same reason. recalcWeight runs
	// electSingleNode (peerAlive is already false), which promoted every group
	// BEFORE the disable-rg-confirmed fence below asked the peer to relinquish
	// them. The single electSingleNode after the fence elects every group. Under
	// disable-rg and no fencing that election still precedes any fence, so their
	// events and end state are unchanged
	// (TestPeerLossWithManualFailoverKeepsTodaysOutcome9640).
	for _, rg := range m.groups {
		if rg.ManualFailover {
			slog.Info("cluster: clearing manual failover (peer lost)", "rg", rg.GroupID)
			rg.ManualFailover = false
			rg.ManualFailoverAt = time.Time{}
			m.manualFailoverRestoreWeightLocked(rg)
		}
	}

	// #6656: drop the peer-transfer-out override too. It is the OTHER half of
	// "a previous manual transfer-out" the loop above clears — that half parks
	// the LOCAL node, this half forces our view of the PEER to secondary-hold —
	// and it was the only half that survived peer loss.
	//
	// Why that matters more than a stale field. Unlike ManualFailover and the
	// commit grace window, this override has NO expiry: it is re-applied to
	// every rebuilt peer-group map on EVERY heartbeat
	// (applyTransferCommitOverridesOnPeerStateLocked), and it feeds BOTH the
	// election AND the operator-facing status render, because FormatStatus
	// prints the post-override m.peerGroups. So an override that outlives the
	// peer incarnation it was granted against means: the peer reconnects — a
	// reboot, a rolling deploy, or simply a new process — and from the first
	// heartbeat onward this node forces it to secondary-hold, electRG takes its
	// "Peer transfer out" arm, and this node self-elects primary for that RG
	// regardless of what the peer actually reports. Two nodes then believe they
	// are primary, and the one that is NOT forwarding shows a healthy primary
	// row with an empty session table.
	//
	// The authority the override carries is scoped to the peer that
	// acknowledged the transfer. Peer loss ends that peer's incarnation, so the
	// authority ends with it — the same argument the ManualFailover clear above
	// already makes, and the same incarnation-scoping the sync layer applies to
	// clockSynced and peerHeartbeatAckEver.
	//
	// Ordering: this runs AFTER suppressPeerTimeoutForTransferCommitLocked has
	// been consulted (twice) and declined, so an in-flight commit still gets
	// its suppression window. The time-bounded maps
	// (peerTransferCommitGraceUntil / localTransferOutHoldUntil) are left alone
	// deliberately — they expire on their own, and clearing them here would
	// shorten a window a live transfer may still be inside.
	for rgID := range m.peerTransferOutOverride {
		slog.Info("cluster: clearing peer transfer-out override (peer lost)", "rg", rgID)
		m.clearPeerTransferOutOverrideLocked(rgID)
	}

	// #7147: under `disable-rg-confirmed` the fence runs BEFORE the election
	// and this node waits, bounded, for the peer to confirm it relinquished
	// its redundancy groups. That ordering is the entire point of the policy —
	// see awaitPeerFenceLocked for why it cannot stall a takeover.
	if m.peerFencing == PeerFencingDisableRGConfirmed {
		m.awaitPeerFenceLocked()
	}

	// Peer lost: re-run single-node election.
	m.electSingleNode()

	// Attempt peer fencing if configured.
	//
	// Ordering note (#72): under `disable-rg` the election above runs BEFORE
	// the fence, and the fence is never a precondition for ownership. That is
	// deliberate: SendFence (sync_failover.go) writes syncMsgFence and returns
	// without waiting, so a `sent to peer` result means the write reached the
	// socket, not that the peer disabled anything. Gating takeover on the send
	// SUCCEEDING would be worse than useless: the send fails precisely when
	// the peer is unreachable, which is the split-brain case fencing exists
	// to cover, so it would convert a dead peer into a total outage.
	//
	// #7147 added the acknowledged alternative rather than changing this one.
	// An operator who wants ownership gated on a confirmed fence selects
	// `disable-rg-confirmed` above; `disable-rg` behaves exactly as it always
	// has, so no existing config changes behaviour.
	//
	// Every attempt and its result is recorded to the EventFence history and
	// rendered by FormatInformation's "Peer fencing:" block.
	if m.peerFencing == PeerFencingDisableRG {
		fn := m.peerFenceFn
		if fn != nil {
			// Release lock for the network call.
			m.mu.Unlock()
			err := fn()
			m.mu.Lock()
			if err != nil {
				slog.Warn("cluster: fence: peer unreachable, relying on heartbeat-driven failover", "err", err)
				m.history.Record(EventFence, -1, fmt.Sprintf("Fence failed: %v", err))
			} else {
				slog.Info("cluster: fence: disable-rg sent to peer")
				m.history.Record(EventFence, -1, "Fence disable-rg sent to peer")
			}
		} else {
			slog.Warn("cluster: fence: sync not available, peer unreachable")
			m.history.Record(EventFence, -1, "Fence skipped: sync not available")
		}
	}
}

// handlePeerNeverSeen is called when the heartbeat timeout expires and no
// peer heartbeat has ever been received. This confirms the peer is truly
// absent (not just a fresh boot race). Sets peerEverSeen so non-preempt
// nodes can claim primary via electSingleNode.
func (m *Manager) handlePeerNeverSeen() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.peerEverSeen {
		return // already handled
	}
	m.peerEverSeen = true // no longer "never seen" — now "confirmed absent"
	slog.Info("cluster: peer never seen after heartbeat timeout, proceeding with election")
	m.history.Record(EventHeartbeat, -1, "Peer never seen (timeout)")
	m.electSingleNode()
}

// HeartbeatStats returns current heartbeat counters.
//
// The SCOPES here differ, and reporting them off the same nil check was a
// defect. Sent/Received/error counts belong to the goroutine currently
// installed, so they are correctly gated on a live sender/receiver. The #6169
// epoch state does NOT: the downgrade latch and its counters live on
// Manager.hbAuth precisely so a heartbeat restart or a VRF rebind cannot reset
// them (#5086/#6642), and the receiver merely holds a pointer to it.
//
// Gating them on `receiver != nil` therefore reported the latch as CLEAR during
// every window in which no receiver is installed — StopHeartbeat, and the whole
// bind-retry span of a failed RestartHeartbeat, which is up to ~5s of retries
// and is exactly when an operator is looking at the status output. The
// underlying state was armed the entire time. Read it from the Manager, which
// owns it, so the report tracks the process state rather than the goroutine's.
func (m *Manager) HeartbeatStats() HeartbeatStats {
	m.mu.RLock()
	sender := m.hbSender
	receiver := m.hbReceiver
	m.mu.RUnlock()

	var s HeartbeatStats
	if sender != nil {
		s.Sent = sender.sent.Load()
		s.SendErrors = sender.sendErrors.Load()
	}
	if receiver != nil {
		s.Received = receiver.received.Load()
		s.RecvErrors = receiver.recvErrors.Load()
		s.ForeignSrcDropped = receiver.foreignSrc.Load()
	}
	// Process-scoped, not receiver-scoped: valid with no receiver installed.
	s.EpochlessAdmitted = m.hbAuth.epochlessAdmitted.Load()
	s.EpochDowngradeRejected = m.hbAuth.epochDowngradeRejected.Load()
	s.EpochOutOfBandRejected = m.hbAuth.epochOutOfBandRejected.Load()
	s.EpochRaiseDeclinedAheadOfClock = m.hbAuth.epochRaiseDeclinedAheadOfClock.Load()
	s.EpochSessionCollision = m.hbAuth.epochSessionCollision.Load()
	s.PeerEpochLatched = m.hbAuth.peerEpochLatched()
	return s
}

// PeerBootEpoch reports the peer's across-reboot boot-epoch floor and whether
// the peer has proved it emits boot epochs, as one coherent snapshot (#7762).
//
// PROMOTION FROM DIAGNOSTIC TO CLASSIFICATION INPUT. The underlying accessors
// are documented "Diagnostics and tests only", which is a statement about who
// consumes them, not a ceiling. What a correctness consumer needs is that the
// UPDATE path be safe for one, and it is:
//
//   - Both writes (`epochSeen = true`, `highEpoch = epoch`) happen inside
//     admitAuthed under s.mu, and the read takes the same mutex — so no torn or
//     half-updated pair is observable.
//   - The floor is monotonically non-decreasing: the sole assignment is guarded
//     by `epoch > s.highEpoch`, and the `epoch < s.highEpoch` case is a refusal
//     arm that writes nothing. A classifier can never see the floor go
//     backwards.
//   - The latch is one-way: `epochSeen = true` is the only production
//     assignment, nothing sets it false, and hbAuth is an embedded value on
//     Manager that survives heartbeat restart, VRF rebind and UpdateConfig.
//
// NOT promoted: `peerEpochLatched`'s own doc warns it is "A FACT ABOUT THIS
// STATE, NOT ABOUT CURRENT ENFORCEMENT" — it does not mean epochless frames are
// being refused right now, because a cleared PSK decouples the two. This
// accessor's consumer uses it only as a VALIDITY flag for the floor, which is
// the fact it does assert.
func (m *Manager) PeerBootEpoch() (uint64, bool) {
	return m.hbAuth.peerBootEpoch()
}

// HeartbeatStats holds heartbeat send/receive counters.
type HeartbeatStats struct {
	Sent       uint64
	Received   uint64
	SendErrors uint64
	RecvErrors uint64
	// ForeignSrcDropped counts heartbeat datagrams dropped by the #6888 peer
	// pin — read from the control-link port but sourced from something other
	// than the configured peer. Surfaced rather than kept internal because the
	// condition it reports (a third node misconfigured onto this cluster's
	// control link) is otherwise invisible: such frames were previously read,
	// MAC-checked and discarded with no signal anywhere.
	ForeignSrcDropped uint64

	// EpochlessAdmitted counts authenticated heartbeats admitted WITHOUT a
	// #6169 boot epoch, and EpochDowngradeRejected counts those refused because
	// the peer had already proved it emits them.
	//
	// EpochlessAdmitted is the exposure meter. A frame with no epoch is
	// governed by the bounded session ring alone, which is the mechanism that
	// stops working past heartbeatReplaySessions captures — so a non-zero and
	// still-climbing value after BOTH nodes are upgraded means either a node is
	// still on a pre-#6169 build or someone is replaying pre-upgrade captures.
	// Rotating the control-link PSK is what retires an attacker's archive; see
	// "Operating the control-link PSK" in pkg/cluster/README.md. Without this
	// counter that residual is invisible to an operator.
	EpochlessAdmitted      uint64
	EpochDowngradeRejected uint64

	// EpochSessionCollision counts frames refused because they claimed the
	// FLOOR epoch beyond the bound on how many sessions may be admitted at one
	// epoch value (heartbeatAuthState.highEpochSessions,
	// heartbeatEpochSessionsPerEpoch slots).
	//
	// It is the meter for the one case the floor's own value cannot order: two
	// peer incarnations advertising the SAME epoch. Distinct sessions at one
	// epoch are what let a replay churn the bounded ring, so past the bound they
	// are refused — and a non-zero value says which of the two causes is in
	// play.
	//
	// CLIMBING ALONGSIDE A PEER THAT KEEPS BEING DECLARED DEAD is a SENDER
	// emitting one constant epoch across its own incarnations, and the first
	// thing to check is a NON-WRITABLE /var on that node — a full filesystem, a
	// quota, or a read-only remount. refineBootEpoch chains to persisted+1,
	// which is a pure function of the file, so a store that READS but cannot
	// WRITE hands every restart the identical value. `df` and a test write under
	// /var/lib/xpf find it.
	//
	// IT TAKES THE FILE AS WELL AS THE STORE FAULT, and an earlier revision of
	// this note said the clock was "irrelevant to this and usually perfectly
	// correct". The chain only engages when `prev+1 > epoch`, and `epoch` is
	// this incarnation's WALL-CLOCK seed, so an unwritable /var holding a value
	// BEHIND the current clock changes nothing — each restart simply publishes
	// its own, higher, seed. Measured on the fixture in
	// TestEqualEpochSuccessorIsAdmitted_6669 at both polarities: a file 30
	// minutes behind `now` gives two incarnations 1786141172292358650 and
	// 1786141172295059255 (different), the same file 30 minutes AHEAD gives both
	// 1786142972295695676 (equal). So the regime is an unwritable store holding a
	// value at or above the wall-clock seed — an RTC that ran fast and was
	// corrected back, or a clock that stepped backwards. Look at both, not just
	// `df`. The degenerate third cause — a clock at or before the Unix epoch,
	// which makes bootEpochSeed return the literal 1 for every incarnation — is
	// worth checking only after the store is ruled out. Either way the sender
	// recovers once its epoch can move again; see pkg/cluster/README.md.
	//
	// CLIMBING WHILE PEER LIVENESS IS STILL HEALTHY is an attacker replaying a
	// captured set that shares an epoch. Read that as "not yet affected" rather
	// than "harmless": an earlier revision of this note said liveness is
	// UNAFFECTED, and it is not. Each replayed session spends one of the epoch
	// value's slots, so the peer's NEXT restart at that same value finds the slot
	// it needs already taken and is refused — the same lockout the first cause
	// produces, deferred until the peer happens to restart. Investigate a
	// climbing count even while the peer is up.
	//
	// Neither cause is visible in the other two counters: such a frame carries an
	// epoch (so it is not EpochlessAdmitted) and is not a downgrade (so it is not
	// EpochDowngradeRejected).
	EpochSessionCollision uint64

	// EpochOutOfBandRejected and EpochRaiseDeclinedAheadOfClock are the two epoch
	// refusals that are NOT replays, split out so the operator action differs
	// from the one "stale nonce (replay)" implies.
	//
	// A non-zero EpochOutOfBandRejected means the PEER is emitting an epoch of 0
	// or past the year-2200 horizon. A conforming #6169 build cannot do that
	// (refineBootEpoch declines to chain to such a value, clock-independently),
	// so this points at the peer's state file or at the peer running something
	// that is not this build — never at this node's clock.
	//
	// A non-zero EpochRaiseDeclinedAheadOfClock is a CLOCK fault and usually a
	// perfectly healthy peer: its epoch is more than bootEpochMaxSkew (one hour)
	// ahead of THIS node's clock, so either the peer runs fast or this node runs
	// slow. Check NTP on both nodes. It gates only the RAISE path, so a peer
	// already at the floor keeps being admitted — which is why this can climb
	// while peer liveness stays healthy, and why reading it as an attack wastes
	// an incident. It self-clears once the clocks agree; no restart is needed.
	// #6969 F5: from an established receiver the frame itself is ADMITTED with
	// the raise declined (the floor is held, liveness is not lost); from a fresh
	// one it is still refused. The name says "declined" rather than "rejected"
	// for that reason — the common case no longer drops the frame.
	EpochOutOfBandRejected         uint64
	EpochRaiseDeclinedAheadOfClock uint64

	// PeerEpochLatched is the DOWNGRADE LATCH itself (heartbeatAuthState.
	// epochSeen): an epoch-bearing frame has been accepted from this peer.
	//
	// THAT IS A FACT ABOUT THIS NODE'S STATE, NOT ABOUT WHAT IS ENFORCED, and an
	// earlier revision of this comment said "so an epoch-less frame from it is
	// refused from now on". admitAuthed does refuse one while this is
	// true, but it is not the outermost gate: heartbeatAuthDecision
	// short-circuits to dual-accept whenever no local control-link key is
	// configured, and UpdateConfig clears controlAuthKey WITHOUT resetting
	// hbAuth. So a latched node admits epoch-less frames unverified for as long
	// as the key is absent. Renderers must report the fact — see
	// epochlessExposureNote and peerEpochLatched.
	//
	// This is the state, not a proxy for it. EpochDowngradeRejected was used as
	// one and is not equivalent: it only moves when a LATER epoch-less frame
	// arrives and is refused, so between the frame that arms the latch and the
	// next epoch-less frame — which may never come — the counter is still 0
	// while the latch is armed. Reporting live exposure off the counter told
	// the operator "replay protection is ring-only" at a moment when it was
	// not. epochlessExposureNote reads this instead.
	PeerEpochLatched bool
}
