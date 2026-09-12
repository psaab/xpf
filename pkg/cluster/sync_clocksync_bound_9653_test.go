package cluster

import (
	"encoding/binary"
	"math"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9653: a ClockSync frame stored an unbounded peer clock offset, and the
// offset was global. One frame on any session-sync connection therefore
// rebased the Created/LastSeen of every later synced install, to 0 (aged out
// on the standby) or into the future (never aged).

func clockSyncPayload9653(peerMono uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, peerMono)
	return b
}

type clockEnv9653 struct {
	t     *testing.T
	s     *SessionSync
	dp    *mockSweepDP
	conns [2]net.Conn
	port  uint16
}

// newClockEnv9653 is a SessionSync with a session store and a connection on
// each fabric, wrapped the way handleNewConnection wraps them.
func newClockEnv9653(t *testing.T) *clockEnv9653 {
	t.Helper()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}
	e := &clockEnv9653{t: t, s: NewSessionSync(":0", "10.0.0.2:4785", dp), dp: dp, port: 1000}
	for i := range e.conns {
		local, remote := net.Pipe()
		t.Cleanup(func() { local.Close(); remote.Close() })
		ac := &authConn{Conn: local}
		e.s.installConn(i, ac)
		e.conns[i] = ac
	}
	return e
}

func (e *clockEnv9653) clockSync(fabric int, peerMono uint64) {
	e.s.handleMessage(e.conns[fabric], syncMsgClockSync, clockSyncPayload9653(peerMono))
}

func (e *clockEnv9653) connOffset(fabric int) (int64, bool) {
	ac := e.conns[fabric].(*authConn)
	return ac.clockOffset.Load(), ac.clockSynced.Load()
}

// install sends one session on fabric, stamped in the peer's clock, and returns
// what the store holds.
func (e *clockEnv9653) install(fabric int, created, lastSeen uint64) dataplane.SessionValue {
	e.t.Helper()
	e.port++
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 9}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: e.port, DstPort: 443}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Created: created, LastSeen: lastSeen}
	e.s.handleMessage(e.conns[fabric], syncMsgSessionV4, encodeSessionV4Payload(key, val))
	got, ok := e.dp.v4sessions[key]
	if !ok {
		e.t.Fatalf("setup: the session sent on fabric %d was not installed", fabric)
	}
	return got
}

// The acceptance: a reading no running peer can send leaves the stored offset
// unchanged and is counted, on either fabric, and a session installed afterwards
// on either fabric keeps the honest offset.
func TestClockSyncWithAnImpossiblePeerClockIsRefused_9653(t *testing.T) {
	for _, tc := range []struct {
		name     string
		peerMono uint64
	}{
		{"int64 max", math.MaxInt64},
		{"uint64 max", math.MaxUint64},
		{"zero against a long local uptime", 0},
		{"one second past a century", maxPeerMonoSeconds + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newClockEnv9653(t)
			e.clockSync(0, monotonicSeconds()/2)
			want, synced := e.connOffset(0)
			if !synced || e.s.peerClockOffset.Load() != want {
				t.Fatalf("setup: the honest clock sync was not stored (fabric 0 synced=%v offset=%d, global=%d)",
					synced, want, e.s.peerClockOffset.Load())
			}

			e.clockSync(0, tc.peerMono)
			e.clockSync(1, tc.peerMono)

			if got := e.s.stats.ClockSyncsRefused.Load(); got != 2 {
				t.Errorf("ClockSyncsRefused = %d, want 2 (one per fabric)", got)
			}
			if got := e.s.Stats().ClockSyncsRefused; got != 2 {
				t.Errorf("Stats().ClockSyncsRefused = %d, want 2: the refusal must reach the snapshot cluster status renders", got)
			}
			if got := e.s.peerClockOffset.Load(); got != want {
				t.Errorf("the stored offset moved from %d to %d on peer clock %d", want, got, tc.peerMono)
			}
			if got, _ := e.connOffset(0); got != want {
				t.Errorf("fabric 0's offset moved from %d to %d on peer clock %d", want, got, tc.peerMono)
			}
			if _, synced := e.connOffset(1); synced {
				t.Errorf("fabric 1 adopted the refused peer clock %d", tc.peerMono)
			}
			for fabric := 0; fabric < 2; fabric++ {
				got := e.install(fabric, 100, 200)
				if got.Created != rebaseTimestamp(100, want) || got.LastSeen != rebaseTimestamp(200, want) {
					t.Errorf("a session installed on fabric %d after the refused clock sync has Created=%d LastSeen=%d, "+
						"want %d and %d (the honest offset %d)", fabric, got.Created, got.LastSeen,
						rebaseTimestamp(100, want), rebaseTimestamp(200, want), want)
				}
			}
		})
	}
}

// Honest readings on both sides of the local uptime still apply: a peer that
// booted after this node (a positive offset), and one that has been up a month
// longer (a negative offset that a recent timestamp must not be clamped by).
func TestHonestClockSyncsStillApply_9653(t *testing.T) {
	e := newClockEnv9653(t)
	local := monotonicSeconds()
	later := local / 2
	longer := local + 30*24*3600
	e.clockSync(0, later)
	e.clockSync(1, longer)

	o0, s0 := e.connOffset(0)
	o1, s1 := e.connOffset(1)
	if !s0 || !s1 || o0 <= 0 || o1 >= 0 {
		t.Fatalf("honest clock syncs were not applied: fabric 0 synced=%v offset=%d (want > 0), fabric 1 synced=%v offset=%d (want < 0)",
			s0, o0, s1, o1)
	}
	if got := e.s.stats.ClockSyncsRefused.Load(); got != 0 {
		t.Errorf("ClockSyncsRefused = %d for two honest readings, want 0", got)
	}
	if got := e.install(0, later-10, later-1); got.LastSeen != rebaseTimestamp(later-1, o0) {
		t.Errorf("fabric 0 session LastSeen = %d, want %d", got.LastSeen, rebaseTimestamp(later-1, o0))
	}
	got := e.install(1, longer-10, longer-1)
	if got.LastSeen == 0 || got.LastSeen != rebaseTimestamp(longer-1, o1) {
		t.Errorf("a recent session from a longer-running peer has LastSeen = %d, want %d (non-zero)",
			got.LastSeen, rebaseTimestamp(longer-1, o1))
	}
}

// The bound cannot tell a plausible false reading from a true one. What keeps
// such a reading from corrupting the real peer's sessions is that the offset
// belongs to the connection that carried it.
func TestClockSyncRebasesOnlyTheSessionsItsOwnConnectionCarries_9653(t *testing.T) {
	e := newClockEnv9653(t)
	local := monotonicSeconds()
	peer := local / 2
	e.clockSync(0, peer)
	o0, _ := e.connOffset(0)

	// A reading inside the bound but false: a decade of uptime, on fabric 1.
	e.clockSync(1, local+10*365*24*3600)
	o1, synced := e.connOffset(1)
	if !synced || o1 >= 0 {
		t.Fatalf("setup: fabric 1's in-bound reading was not applied to fabric 1 (synced=%v offset=%d)", synced, o1)
	}

	got := e.install(0, peer-10, peer-1)
	if got.LastSeen == 0 || got.LastSeen != rebaseTimestamp(peer-1, o0) {
		t.Errorf("the real peer's session on fabric 0 has LastSeen = %d, want %d: it was rebased by the clock sync "+
			"another connection sent, so one frame rewrote the timestamps of every session the peer carries",
			got.LastSeen, rebaseTimestamp(peer-1, o0))
	}
	if lie := e.install(1, peer-10, peer-1); lie.LastSeen != rebaseTimestamp(peer-1, o1) {
		t.Errorf("fabric 1's own session has LastSeen = %d, want %d (fabric 1's offset)", lie.LastSeen, rebaseTimestamp(peer-1, o1))
	}

	// The IPv6 install site rebases through the same per-connection offset.
	key6 := gen2170KeyV6()
	val6 := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, Created: peer - 10, LastSeen: peer - 1}
	e.s.handleMessage(e.conns[0], syncMsgSessionV6, encodeSessionV6Payload(key6, val6))
	got6, ok := e.dp.v6sessions[key6]
	if !ok {
		t.Fatalf("setup: the v6 session sent on fabric 0 was not installed")
	}
	if got6.LastSeen == 0 || got6.LastSeen != rebaseTimestamp(peer-1, o0) {
		t.Errorf("the real peer's v6 session on fabric 0 has LastSeen = %d, want %d: the v6 install rebased it by "+
			"the clock sync another connection sent", got6.LastSeen, rebaseTimestamp(peer-1, o0))
	}
}
