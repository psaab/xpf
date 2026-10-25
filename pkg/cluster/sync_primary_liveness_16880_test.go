package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

func TestBusyPrimarySessionIsResyncedAcrossTenTimeouts16880(t *testing.T) {
	for _, tc := range []struct {
		name       string
		timeout    uint32
		appTimeout uint32
		period     uint32
	}{
		{name: "default timeout", timeout: 30, period: 30},
		{name: "one-second application timeout", timeout: 300, appTimeout: 1, period: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runBusyPrimaryLiveness16880(t, tc.timeout, tc.appTimeout, tc.period)
		})
	}
}

func runBusyPrimaryLiveness16880(t *testing.T, timeout, appTimeout, period uint32) {
	t.Helper()
	const base = uint64(1_000)
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: 6,
	}
	value := dataplane.SessionValue{
		State:   dataplane.SessStateEstablished,
		Created: base, LastSeen: base, Timeout: timeout, AppTimeout: appTimeout, SessionID: 42,
	}
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{key: value},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base
	ss.lastPrimaryLivenessSweepTime = base
	now := base
	ss.testSweepNow = func() uint64 { return now }

	livenessFrames := 0
	drain := func() {
		for len(ss.sendCh) > 0 {
			frame := <-ss.sendCh
			if len(frame) < syncHeaderSize {
				t.Fatalf("queued frame is shorter than its sync header: len=%d", len(frame))
			}
			if frame[4] != syncMsgSessionV4 {
				t.Fatalf("unexpected session frame type=%d", frame[4])
			}
			_, sentValue, ok := decodeSessionV4Payload(frame[syncHeaderSize:])
			if !ok {
				t.Fatal("could not decode queued v4 session frame")
			}
			if sentValue.PrimaryLiveness {
				livenessFrames++
			}
		}
	}

	if sent := ss.syncSweep(); sent != 1 {
		t.Fatalf("initial session sync sent %d entries, want 1", sent)
	}
	drain()
	// Keep the primary row present while its LastSeen mirror remains stale:
	// Rust writes that field to the BPF map only on a budgeted multi-second
	// cadence, so row presence—not the mirror timestamp—is liveness evidence.
	for elapsed := uint64(1); elapsed <= 10*uint64(period); elapsed++ {
		now = base + elapsed
		ss.syncSweep()
		drain()
	}

	if livenessFrames < 8 {
		t.Fatalf("busy primary session emitted %d primary-liveness refreshes across 10 timeout intervals; want at least 8", livenessFrames)
	}
}

func TestStartSyncSweepKeepsShortTimeoutLivenessCadence16880(t *testing.T) {
	const base = uint64(10_000)
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: 6,
	}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {
				State:      dataplane.SessStateEstablished,
				Created:    base - 10,
				LastSeen:   base - 10,
				Timeout:    2,
				AppTimeout: 2,
				SessionID:  0,
			},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
	ss.IsPrimaryFn = func() bool { return true }

	var sweepCalls uint64
	ss.testSweepNow = func() uint64 {
		sweepCalls++
		if sweepCalls == 1 {
			// Make the test independent of the process's monotonic-second
			// phase while keeping StartSyncSweep's real one-second timer.
			ss.lastSweepTime = base
			ss.lastPrimaryLivenessSweepTime = base
		}
		return base + sweepCalls
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		ss.wg.Wait()
	}()
	ss.StartSyncSweep(ctx)

	timeout := time.NewTimer(2900 * time.Millisecond)
	defer timeout.Stop()
	for {
		select {
		case frame := <-ss.sendCh:
			if len(frame) < syncHeaderSize {
				t.Fatalf("unexpected short sync frame: len=%d", len(frame))
			}
			if frame[4] != syncMsgSessionV4 {
				t.Fatalf("unexpected sync frame type: %d", frame[4])
			}
			_, value, ok := decodeSessionV4Payload(frame[syncHeaderSize:])
			if !ok {
				t.Fatal("could not decode timer-driven session frame")
			}
			if value.PrimaryLiveness {
				return
			}
		case <-timeout.C:
			t.Fatal("idle short-timeout session received no timer-driven primary-liveness refresh within 2.9s")
		}
	}
}

type livenessSweepProfileSource16880 struct{}

func (livenessSweepProfileSource16880) DrainSessionDeltas(uint32) (dpruntime.SessionDeltaSnapshot, error) {
	return dpruntime.SessionDeltaSnapshot{}, nil
}

func (livenessSweepProfileSource16880) ExportOwnerRGSessions([]int, uint32) (dpruntime.SessionDeltaSnapshot, error) {
	return dpruntime.SessionDeltaSnapshot{}, nil
}

func (livenessSweepProfileSource16880) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	return true, 15 * time.Second, 60 * time.Second
}

type livenessProfiledSessionStore16880 struct {
	dataplane.SessionStore
	source dpruntime.SessionDeltaSource
}

func (s livenessProfiledSessionStore16880) SessionDeltas() dpruntime.SessionDeltaSource {
	return s.source
}

func TestStartSyncSweepWakesWhenLivenessCapabilityDiscovered16880(t *testing.T) {
	const base = uint64(10_000)
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: 6,
	}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {
				State:      dataplane.SessStateEstablished,
				Created:    base - 10,
				LastSeen:   base - 10,
				Timeout:    2,
				AppTimeout: 2,
			},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.sessions = livenessProfiledSessionStore16880{
		SessionStore: ss.sessions,
		source:       livenessSweepProfileSource16880{},
	}
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }

	var sweepCalls uint64
	ss.testSweepNow = func() uint64 {
		sweepCalls++
		if sweepCalls == 1 {
			ss.lastSweepTime = base
			ss.lastPrimaryLivenessSweepTime = base
		}
		return base + sweepCalls
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		ss.wg.Wait()
	}()
	ss.StartSyncSweep(ctx)

	// Userspace starts at a 15s interval. Learning liveness support after that
	// timer was armed must wake it so the primary begins its 1s refresh cadence.
	payload := capabilityFrame9714(t, 0)
	payload = append(payload, make([]byte, 5+bootIncarnationLen+8+8+1-len(payload))...)
	payload[len(payload)-1] = capFlag2PrimaryLiveness
	ss.handleMessage(nil, syncMsgPeerCapabilities, payload)

	timeout := time.NewTimer(2900 * time.Millisecond)
	defer timeout.Stop()
	for {
		select {
		case frame := <-ss.sendCh:
			if len(frame) < syncHeaderSize {
				t.Fatalf("unexpected short sync frame: len=%d", len(frame))
			}
			if frame[4] != syncMsgSessionV4 {
				t.Fatalf("unexpected sync frame type: %d", frame[4])
			}
			_, value, ok := decodeSessionV4Payload(frame[syncHeaderSize:])
			if !ok {
				t.Fatal("could not decode timer-driven session frame")
			}
			if value.PrimaryLiveness {
				return
			}
		case <-timeout.C:
			t.Fatal("discovering primary-liveness capability did not wake the 15s userspace sweep timer")
		}
	}
}

func TestPrimaryLivenessCapabilityAndWireRoundTrip16880(t *testing.T) {
	if localCapabilityFlags2&capFlag2PrimaryLiveness == 0 {
		t.Fatal("local capability advertisement omits primary-liveness session refreshes")
	}

	key4 := dataplane.SessionKey{Protocol: 6}
	val4 := dataplane.SessionValue{PrimaryLiveness: true}
	_, got4, ok := decodeSessionV4Payload(encodeSessionV4Payload(key4, val4))
	if !ok || !got4.PrimaryLiveness {
		t.Fatalf("v4 liveness marker decoded as ok=%t primary_liveness=%t", ok, got4.PrimaryLiveness)
	}

	key6 := dataplane.SessionKeyV6{Protocol: 6}
	val6 := dataplane.SessionValueV6{PrimaryLiveness: true}
	_, got6, ok := decodeSessionV6Payload(encodeSessionV6Payload(key6, val6))
	if !ok || !got6.PrimaryLiveness {
		t.Fatalf("v6 liveness marker decoded as ok=%t primary_liveness=%t", ok, got6.PrimaryLiveness)
	}
}

func TestSecondCapabilityByteIndependentBits16880(t *testing.T) {
	if capFlag2PrimaryLiveness == capFlag2PersistentNatLeaseProvenance {
		t.Fatal("primary-liveness and persistent-NAT provenance share a capability bit")
	}
	for _, bit := range []uint8{capFlag2PrimaryLiveness, capFlag2PersistentNatLeaseProvenance} {
		if localCapabilityFlags2&bit == 0 {
			t.Fatalf("local capability advertisement omits bit %#x", bit)
		}
	}

	tests := []struct {
		name        string
		flags       uint8
		wantLive    bool
		wantNatProv bool
	}{
		{name: "neither"},
		{name: "provenance only", flags: capFlag2PersistentNatLeaseProvenance, wantNatProv: true},
		{name: "liveness only", flags: capFlag2PrimaryLiveness, wantLive: true},
		{name: "both", flags: capFlag2PrimaryLiveness | capFlag2PersistentNatLeaseProvenance, wantLive: true, wantNatProv: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
			payload := capabilityFrame14161(t, 8, localCapabilityFlags, SessionSyncWireVersion)
			payload = append(payload, make([]byte, bootIncarnationLen+8+8)...)
			payload = append(payload, tc.flags)
			ss.handleMessage(nil, syncMsgPeerCapabilities, payload)

			if got := ss.PrimaryLivenessCapable(); got != tc.wantLive {
				t.Errorf("PrimaryLivenessCapable() = %t, want %t", got, tc.wantLive)
			}
			if got := ss.PersistentNatLeaseProvenanceCapable(); got != tc.wantNatProv {
				t.Errorf("PersistentNatLeaseProvenanceCapable() = %t, want %t", got, tc.wantNatProv)
			}
		})
	}
}
