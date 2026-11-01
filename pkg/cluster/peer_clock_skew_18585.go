package cluster

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Peer wall-clock offset, measured over the authenticated heartbeat (#18585).
//
// Cross-node fabric RPC authenticates with a 30 s wall-clock token window
// (pkg/grpcapi/fabric_auth.go, accept band current ±1): under 30 s of skew it
// always works, 30–60 s depends on alignment, 60 s or more always fails.
// Nothing compared the two nodes' clocks while they still worked —
// pkg/clockskew samples the LOCAL NTP reference only, and the #6708 skew
// report exists only after a fabric RPC has been rejected. On loss
// (2026-10-31) fw1 was 72 s behind fw0, `show chassis cluster status` looked
// healthy, and every cross-node failover failed.
//
// Each heartbeat now carries the sender's wall clock (the `XPFT` body
// section, heartbeat_wire.go). The receiver takes peer-minus-local at the
// moment it ADMITS the frame. One-way control-link delay (sub-millisecond) is
// folded in and ignored: the alarm is at 10 s.
//
// This is VISIBILITY ONLY. The fabric verifier's accept band and the time a
// client signs at are unchanged, so the replay horizon is unchanged (#7487
// records why signing at now+offset is a different, riskier change). The
// reading only drives a display line, an alarm, and an early, clearer refusal
// of a cross-node RPC that is certain to fail.
const (
	// PeerClockSkewRaise raises the alarm: a third of the 30 s window, so an
	// operator sees it long before fabric RPC can fail.
	PeerClockSkewRaise = 10 * time.Second
	// PeerClockSkewClear clears it (hysteresis, so a clock hovering near
	// 10 s does not flap).
	PeerClockSkewClear = 5 * time.Second
	// PeerClockFabricBreak is the skew at which fabric RPC authentication
	// always fails (two full 30 s windows; clockskew.AuthBreakSkewSecs).
	PeerClockFabricBreak = 60 * time.Second
	// peerClockFreshFor bounds how old a sample may be before it is shown as
	// stale and no longer acted on (25 heartbeats at the 200 ms lab interval).
	peerClockFreshFor = 5 * time.Second
)

// Plausibility band for a peer's declared clock. A reading outside it is not
// a clock (an older sender's epoch marker matching the section magic, or
// garbage) and is discarded rather than displayed.
var (
	peerClockPlausibleMin = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	peerClockPlausibleMax = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
)

type peerClockState struct {
	mu sync.Mutex
	// alarmHook receives raise/clear transitions (the daemon forwards them to
	// syslog as RT_SYSTEM CLOCK_SKEW_ALARM_* like the local reference alarm).
	alarmHook func(raised bool, offset time.Duration)
	have      bool
	offset    time.Duration // peer wall clock minus local wall clock
	at        time.Time     // local receive time (carries monotonic reading)
	raised    bool
	raisedAt  time.Time
}

// notePeerWallClock records one admitted heartbeat's clock sample. It runs on
// the heartbeat receive path (~5/s): it logs only on alarm transitions.
func (m *Manager) notePeerWallClock(peerUnixNano int64, now time.Time) {
	if m == nil || peerUnixNano < peerClockPlausibleMin || peerUnixNano > peerClockPlausibleMax {
		return
	}
	offset := time.Duration(peerUnixNano - now.UnixNano())
	pc := &m.peerClock
	pc.mu.Lock()
	pc.have, pc.offset, pc.at = true, offset, now
	mag := offset
	if mag < 0 {
		mag = -mag
	}
	var transition string
	switch {
	case !pc.raised && mag >= PeerClockSkewRaise:
		pc.raised, pc.raisedAt = true, now
		transition = "raise"
	case pc.raised && mag < PeerClockSkewClear:
		pc.raised = false
		transition = "clear"
	}
	hook := pc.alarmHook
	pc.mu.Unlock()
	if hook != nil && transition != "" {
		hook(transition == "raise", offset)
	}
	switch transition {
	case "raise":
		slog.Warn("cluster: peer wall clock skew alarm raised",
			"peer_minus_local", offset.Round(10*time.Millisecond).String(),
			"alarm_at", PeerClockSkewRaise.String(),
			"fabric_auth_breaks_at", PeerClockFabricBreak.String())
	case "clear":
		slog.Info("cluster: peer wall clock skew alarm cleared",
			"peer_minus_local", offset.Round(10*time.Millisecond).String())
	}
}

// SetPeerClockAlarmHook installs the raise/clear transition callback. It is
// called outside every Manager lock, once per transition (never per
// heartbeat), so it may do I/O.
func (m *Manager) SetPeerClockAlarmHook(fn func(raised bool, offset time.Duration)) {
	if m == nil {
		return
	}
	m.peerClock.mu.Lock()
	m.peerClock.alarmHook = fn
	m.peerClock.mu.Unlock()
}

// PeerClockOffset returns the last measured peer-minus-local wall-clock
// offset and the sample's age. ok is false when no admitted heartbeat has
// carried a clock (an older peer, or no peer yet).
func (m *Manager) PeerClockOffset() (offset, age time.Duration, ok bool) {
	if m == nil {
		return 0, 0, false
	}
	pc := &m.peerClock
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if !pc.have {
		return 0, 0, false
	}
	return pc.offset, time.Since(pc.at), true
}

// PeerClockSkewAlarm reports the raised alarm: the last offset and when it was
// raised. raised is false when the alarm is clear, or when the sample is stale
// (the peer stopped sending clocks — peer loss is its own alarm).
func (m *Manager) PeerClockSkewAlarm() (offset time.Duration, raisedAt time.Time, raised bool) {
	if m == nil {
		return 0, time.Time{}, false
	}
	pc := &m.peerClock
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if !pc.raised || time.Since(pc.at) > peerClockFreshFor {
		return 0, time.Time{}, false
	}
	return pc.offset, pc.raisedAt, true
}

// CrossNodeFabricClockError returns a non-nil error when a FRESH measurement
// says the peer's wall clock is at least PeerClockFabricBreak away, so a
// cross-node fabric RPC cannot authenticate whatever window alignment. It
// lets `request chassis cluster failover ... node <peer>` refuse with the
// measured number and a remedy instead of a token error. Below the break, or
// with no fresh sample, it returns nil and the RPC is attempted as before.
func (m *Manager) CrossNodeFabricClockError(peerNode int) error {
	offset, age, ok := m.PeerClockOffset()
	if !ok || age > peerClockFreshFor {
		return nil
	}
	mag, dir := offset, "ahead of"
	if mag < 0 {
		mag, dir = -mag, "behind"
	}
	if mag < PeerClockFabricBreak {
		return nil
	}
	return fmt.Errorf("cross-node request not sent: node%d's wall clock is %s %s this node "+
		"(measured %s ago over authenticated heartbeats), and fabric RPC authentication fails "+
		"past %s of skew; fix time sync on both nodes (`set system ntp server <address> "+
		"routing-instance mgmt`), or run this command on node%d, where moving a redundancy "+
		"group to itself needs no fabric RPC",
		peerNode, mag.Round(100*time.Millisecond), dir, age.Round(100*time.Millisecond),
		PeerClockFabricBreak, peerNode)
}

// formatPeerClockLine renders the status line, or "" when nothing is known.
func (m *Manager) formatPeerClockLine() string {
	offset, age, ok := m.PeerClockOffset()
	if !ok {
		return ""
	}
	mag, dir := offset, "ahead of"
	if mag < 0 {
		mag, dir = -mag, "behind"
	}
	line := fmt.Sprintf("Peer clock offset: %+.1fs (peer %s this node; measured %s ago)",
		offset.Seconds(), dir, age.Round(100*time.Millisecond))
	if age > peerClockFreshFor {
		line += " [stale]"
	} else if _, _, raised := m.PeerClockSkewAlarm(); raised {
		line += fmt.Sprintf(" [ALARM at %gs: fabric RPC fails past 30-%gs]", PeerClockSkewRaise.Seconds(), PeerClockFabricBreak.Seconds())
	}
	return line
}
