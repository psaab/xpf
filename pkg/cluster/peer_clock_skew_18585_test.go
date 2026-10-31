package cluster

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

var clock18585 = time.Date(2026, 10, 31, 3, 0, 0, 0, time.UTC)

func clockPkt18585(wall int64, echo bool) *HeartbeatPacket {
	p := samplePkt()
	if echo {
		p.HeartbeatSession, p.HeartbeatSequence = 0xA11CE, 7
		p.PeerHeartbeatSession, p.PeerHeartbeatSequence = 0xB0B, 6
	}
	p.WallClockUnixNano = wall
	return p
}

// #18585 wire: the clock section round-trips with and without the echo
// section, and a frame WITHOUT it is byte-identical to the pre-#18585
// encoding (the golden vectors pin that exactly) and decodes as "absent".
func TestHeartbeatClockSectionRoundTrip18585(t *testing.T) {
	wall := clock18585.UnixNano()
	for _, echo := range []bool{true, false} {
		got, err := UnmarshalHeartbeat(MarshalHeartbeat(clockPkt18585(wall, echo)))
		if err != nil {
			t.Fatalf("echo=%v: unmarshal: %v", echo, err)
		}
		if got.WallClockUnixNano != wall {
			t.Fatalf("echo=%v: WallClockUnixNano = %d, want %d", echo, got.WallClockUnixNano, wall)
		}
		if echo && (got.HeartbeatSession != 0xA11CE || got.PeerHeartbeatSequence != 6) {
			t.Fatalf("echo section damaged by the clock section: %+v", got)
		}
		absent, err := UnmarshalHeartbeat(MarshalHeartbeat(clockPkt18585(0, echo)))
		if err != nil || absent.WallClockUnixNano != 0 {
			t.Fatalf("echo=%v: a frame without the section must decode as absent: %+v, %v", echo, absent, err)
		}
	}
}

// #18585 old-reader property: the new section is APPENDED to the body, so the
// pre-#18585 body is a strict prefix of the new one — an older reader, which
// stops after the echo section, reads exactly what it read before.
func TestHeartbeatClockSectionIsAnAppendedSuffix18585(t *testing.T) {
	for _, echo := range []bool{true, false} {
		old := MarshalHeartbeat(clockPkt18585(0, echo))
		neu := MarshalHeartbeat(clockPkt18585(clock18585.UnixNano(), echo))
		if !bytes.HasPrefix(neu, old) || len(neu) != len(old)+heartbeatClockTrailerSize {
			t.Fatalf("echo=%v: new body must be old body + %d bytes; old=%d new=%d", echo, heartbeatClockTrailerSize, len(old), len(neu))
		}
		if string(neu[len(old):len(old)+4]) != heartbeatClockMagic {
			t.Fatalf("echo=%v: section magic missing", echo)
		}
	}
}

// #18585 keyed frames: the clock section sits INSIDE the signed body, so the
// fixed-tail epoch and auth trailers stay where deployed readers index them
// (the #7487 dual-primary trap), the MAC verifies, and the epoch reads back.
func TestHeartbeatClockSectionKeepsFixedTailTrailers18585(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	const epoch = uint64(1793410000)
	frame := marshalHeartbeatAuthEpoch(clockPkt18585(clock18585.UnixNano(), true), key, 0xA11CE, 7, epoch)
	if _, _, present := heartbeatAuthTrailer(frame); !present {
		t.Fatal("auth trailer not at the fixed tail")
	}
	if !verifyHeartbeatMAC(frame, key) {
		t.Fatal("MAC must cover the clock section and verify")
	}
	if got, ok := heartbeatFrameEpoch(frame, key); !ok || got != epoch {
		t.Fatalf("epoch at the fixed slot = (%d, %v), want (%d, true)", got, ok, epoch)
	}
	pkt, err := UnmarshalHeartbeat(frame)
	if err != nil || pkt.WallClockUnixNano != clock18585.UnixNano() {
		t.Fatalf("clock through a keyed frame: %+v, %v", pkt, err)
	}
	// Tampering with the clock bytes breaks the MAC: the reading is
	// authenticated on a keyed cluster.
	i := bytes.Index(frame, []byte(heartbeatClockMagic))
	frame[i+5] ^= 0xff
	if verifyHeartbeatMAC(frame, key) {
		t.Fatal("a modified clock section must fail the MAC")
	}
}

// #18585: a maximal frame still fits and stays signed — the section is
// reserved before best-effort monitors are truncated.
//
// Swept over monitor-name lengths so the slack left after the last whole
// monitor takes every value: with one fixed length the slack can happen to
// exceed the section and hide an unreserved write.
func TestHeartbeatClockSectionReservedBeforeMonitors18585(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for n := 0; n < 96; n++ {
		nameLen := n%48 + 1
		p := clockPkt18585(clock18585.UnixNano(), true)
		if n >= 48 {
			p.SoftwareVersion = "" // the reserve has a separate branch for no version
		}
		for i := 0; i < 250; i++ {
			p.Monitors = append(p.Monitors, HeartbeatMonitor{RGID: 1, Weight: 1, Up: true, Interface: strings.Repeat("x", nameLen)})
		}
		for _, keyed := range []bool{true, false} {
			var frame []byte
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("nameLen=%d keyed=%v: marshal panicked: %v", nameLen, keyed, r)
					}
				}()
				if keyed {
					frame = marshalHeartbeatAuthEpoch(p, key, 1, 1, 1793410000)
				} else {
					frame = MarshalHeartbeat(p)
				}
			}()
			if len(frame) > maxHeartbeatSize {
				t.Fatalf("nameLen=%d keyed=%v: frame %d bytes > cap %d", nameLen, keyed, len(frame), maxHeartbeatSize)
			}
			pkt, err := UnmarshalHeartbeat(frame)
			if err != nil || pkt.WallClockUnixNano != p.WallClockUnixNano {
				t.Fatalf("nameLen=%d keyed=%v: maximal frame lost the clock: %v", nameLen, keyed, err)
			}
			if keyed && !verifyHeartbeatMAC(frame, key) {
				t.Fatalf("nameLen=%d: maximal keyed frame lost its MAC", nameLen)
			}
		}
	}
}

// #18585: only an ADMITTED frame updates the measured offset. A replay of a
// genuine frame (rejected by the anti-replay gate) must not move it.
func TestPeerClockOnlyFromAdmittedFrames18585(t *testing.T) {
	m := epochGateManager()
	key := m.controlLinkAuthKey()
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	feed := func(frame []byte) bool {
		t.Helper()
		pkt, err := UnmarshalHeartbeat(frame)
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return r.admitFrame(frame, pkt)
	}
	skewed := time.Now().Add(-72 * time.Second).UnixNano()
	first := MarshalHeartbeatAuth(clockPkt18585(skewed, false), key, 0xA11CE, 1)
	if !feed(first) {
		t.Fatal("genuine frame must be admitted")
	}
	off, _, ok := m.PeerClockOffset()
	if !ok || off > -71*time.Second || off < -73*time.Second {
		t.Fatalf("offset after admitted frame = %v, %v; want about -72s", off, ok)
	}
	// A FORGED frame (wrong key) claiming a sane clock is rejected and moves
	// nothing.
	forged := MarshalHeartbeatAuth(clockPkt18585(time.Now().UnixNano(), false), []byte("not-the-key-not-the-key-not-the!"), 0xBAD, 2)
	if feed(forged) {
		t.Fatal("forged frame must be rejected")
	}
	if off2, _, _ := m.PeerClockOffset(); off2 > -71*time.Second {
		t.Fatalf("a rejected frame moved the offset to %v", off2)
	}
}

func noteAt18585(m *Manager, peerMinusLocal time.Duration) {
	now := time.Now()
	m.notePeerWallClock(now.Add(peerMinusLocal).UnixNano(), now)
}

// #18585 alarm: raised at 10 s in either direction, held above 5 s
// (hysteresis), cleared below; implausible readings are discarded.
func TestPeerClockSkewAlarmHysteresis18585(t *testing.T) {
	m := NewManager(0, 1)
	if _, _, ok := m.PeerClockOffset(); ok {
		t.Fatal("no sample yet must read as unknown")
	}
	steps := []struct {
		off    time.Duration
		raised bool
	}{
		{2 * time.Second, false},
		{9 * time.Second, false},
		{-10 * time.Second, true},
		{7 * time.Second, true}, // between clear and raise: held
		{-4 * time.Second, false},
		{11 * time.Second, true},
	}
	for i, st := range steps {
		noteAt18585(m, st.off)
		if _, _, raised := m.PeerClockSkewAlarm(); raised != st.raised {
			t.Fatalf("step %d (offset %v): raised=%v, want %v", i, st.off, raised, st.raised)
		}
	}
	m.notePeerWallClock(12345, time.Now()) // 1970: not a clock
	if off, _, _ := m.PeerClockOffset(); off < 10*time.Second {
		t.Fatalf("an implausible reading must be discarded; offset now %v", off)
	}
}

// #18585 fail-fast: a cross-node request is refused only on a FRESH reading
// at or past the guaranteed-break bound, and the refusal names the number and
// both remedies. Below it, or with no reading, the RPC is attempted as before.
func TestCrossNodeFabricClockError18585(t *testing.T) {
	m := NewManager(0, 1)
	if err := m.CrossNodeFabricClockError(1); err != nil {
		t.Fatalf("no reading: must attempt the RPC, got %v", err)
	}
	for _, off := range []time.Duration{-59 * time.Second, 30 * time.Second, 0} {
		noteAt18585(m, off)
		if err := m.CrossNodeFabricClockError(1); err != nil {
			t.Fatalf("offset %v is below the break: must attempt, got %v", off, err)
		}
	}
	for _, off := range []time.Duration{-72 * time.Second, 61 * time.Second} {
		noteAt18585(m, off)
		err := m.CrossNodeFabricClockError(1)
		if err == nil {
			t.Fatalf("offset %v is past the break: must refuse", off)
		}
		for _, want := range []string{"node1", "routing-instance mgmt", "run this command on node1"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("refusal %q must name %q", err, want)
			}
		}
	}
	// A stale reading is not acted on.
	m.peerClock.mu.Lock()
	m.peerClock.at = time.Now().Add(-2 * peerClockFreshFor)
	m.peerClock.mu.Unlock()
	if err := m.CrossNodeFabricClockError(1); err != nil {
		t.Fatalf("a stale reading must not refuse: %v", err)
	}
	if _, _, raised := m.PeerClockSkewAlarm(); raised {
		t.Fatal("a stale reading must not hold the alarm")
	}
}

// #18585 status surfaces: the measured offset is shown when known, absent
// otherwise (byte-identical status for an older peer).
func TestPeerClockStatusLine18585(t *testing.T) {
	m := NewManager(0, 1)
	m.mu.Lock()
	m.peerAlive = true
	m.mu.Unlock()
	if strings.Contains(m.FormatStatus(), "Peer clock offset") {
		t.Fatal("no reading: the line must be absent")
	}
	noteAt18585(m, -72*time.Second)
	st := m.FormatStatus()
	if !strings.Contains(st, "Peer clock offset: -72.0s (peer behind this node") || !strings.Contains(st, "ALARM") {
		t.Fatalf("status must show the offset and the alarm:\n%s", st)
	}
	if !strings.Contains(m.FormatInformation(), "Peer clock offset: -72.0s") {
		t.Fatalf("information must show the offset:\n%s", m.FormatInformation())
	}
	noteAt18585(m, 300*time.Millisecond)
	if st := m.FormatStatus(); !strings.Contains(st, "Peer clock offset: +0.3s (peer ahead of this node") || strings.Contains(st, "ALARM") {
		t.Fatalf("a small offset is shown without an alarm:\n%s", st)
	}
}

// #18585 sender: production heartbeats carry this node's wall clock.
func TestBuildHeartbeatCarriesWallClock18585(t *testing.T) {
	m := NewManager(0, 1)
	before := time.Now().UnixNano()
	pkt := m.buildHeartbeat()
	if pkt.WallClockUnixNano < before || pkt.WallClockUnixNano > time.Now().UnixNano() {
		t.Fatalf("WallClockUnixNano = %d, want now", pkt.WallClockUnixNano)
	}
}
