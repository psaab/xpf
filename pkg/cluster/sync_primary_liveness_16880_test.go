package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	"golang.org/x/sys/unix"
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

func primaryLivenessSwept16880(t *testing.T, protocol uint8, value dataplane.SessionValue, now, previous uint64) bool {
	t.Helper()
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: protocol,
	}
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{key: value},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = value.Created + 1
	ss.lastPrimaryLivenessSweepTime = previous
	ss.testSweepNow = func() uint64 { return now }

	ss.syncSweep()
	for len(ss.sendCh) > 0 {
		frame := <-ss.sendCh
		if len(frame) < syncHeaderSize || frame[4] != syncMsgSessionV4 {
			t.Fatalf("unexpected primary-liveness frame: len=%d", len(frame))
		}
		_, sentValue, ok := decodeSessionV4Payload(frame[syncHeaderSize:])
		if !ok {
			t.Fatal("could not decode primary-liveness sweep frame")
		}
		if sentValue.PrimaryLiveness {
			return true
		}
	}
	return false
}

func TestPrimaryLivenessCadenceUsesReceiverTimeout16880(t *testing.T) {
	const (
		created = uint64(1000)
		long    = uint32(3600)
	)
	for _, tc := range []struct {
		name            string
		protocol        uint8
		receiverTimeout uint32
	}{
		{
			name:            "udp promoted app override",
			protocol:        unix.IPPROTO_UDP,
			receiverTimeout: config.DataplaneUDPSessionTimeoutSecs,
		},
		{
			name:            "icmp promoted app override",
			protocol:        unix.IPPROTO_ICMP,
			receiverTimeout: config.DataplaneICMPSessionTimeoutSecs,
		},
		{
			name:            "ospf app override",
			protocol:        primaryLivenessOSPFProtocol,
			receiverTimeout: config.DataplaneOSPFSessionTimeoutSecs,
		},
		{
			name:            "other protocol app override",
			protocol:        47, // GRE uses the other-protocol default.
			receiverTimeout: config.DataplaneOtherSessionTimeoutSecs,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			promoted := dataplane.SessionValue{
				State: dataplane.SessStateEstablished, Created: created,
				Timeout: long, AppTimeout: long, RevPackets: 1,
			}
			before := created + uint64(tc.receiverTimeout) - 1
			if primaryLivenessSwept16880(t, tc.protocol, promoted, before, before-1) {
				t.Fatalf("promoted app override refreshed before the receiver's %ds timeout", tc.receiverTimeout)
			}
			due := created + uint64(tc.receiverTimeout)
			if !primaryLivenessSwept16880(t, tc.protocol, promoted, due, due-1) {
				t.Fatalf("long app override did not refresh by the receiver's %ds timeout", tc.receiverTimeout)
			}
			promotedShort := promoted
			promotedShort.Timeout = tc.receiverTimeout
			promotedShort.AppTimeout = 10
			if primaryLivenessSwept16880(t, tc.protocol, promotedShort, created+9, created+8) {
				t.Fatal("replied datagram refreshed before its promoted app timeout")
			}
			if !primaryLivenessSwept16880(t, tc.protocol, promotedShort, created+10, created+9) {
				t.Fatal("replied datagram did not use its promoted app timeout")
			}

			// App-timeout promotion on the primary remains gated by observed
			// reply traffic. An unreplied row retains its shorter global window.
			unreplied := promoted
			unreplied.Timeout = 20
			unreplied.RevPackets = 0
			if primaryLivenessSwept16880(t, tc.protocol, unreplied, created+19, created+18) {
				t.Fatal("unreplied datagram refreshed before its global timeout")
			}
			if !primaryLivenessSwept16880(t, tc.protocol, unreplied, created+20, created+19) {
				t.Fatal("unreplied datagram did not use its global timeout cadence")
			}
		})
	}
}

func TestPrimaryLivenessCadenceRespectsTCPStates16880(t *testing.T) {
	const (
		created = uint64(2000)
		longApp = uint32(3600)
	)
	for _, tc := range []struct {
		name           string
		timeout        uint32
		cadenceTimeout uint32
		handshakeState uint8
		closeClass     uint8
	}{
		{
			name:           "opening caps no-entry fallback",
			timeout:        config.DataplaneTCPEstablishedWindowSecs,
			cadenceTimeout: config.DataplaneTCPOpeningWindowSecs,
			handshakeState: dataplane.TCPHandshakeStateOpening,
		},
		{
			name:           "opening honors shorter configured window",
			timeout:        10,
			cadenceTimeout: 10,
			handshakeState: dataplane.TCPHandshakeStateOpening,
		},
		{
			name:           "closing caps no-entry fallback",
			timeout:        config.DataplaneTCPEstablishedWindowSecs,
			cadenceTimeout: config.DataplaneTCPClosingWindowSecs,
			handshakeState: dataplane.TCPHandshakeStateEstablished,
			closeClass:     1,
		},
		{
			name:           "reset keeps short close window",
			timeout:        config.DataplaneTCPEstablishedWindowSecs,
			cadenceTimeout: config.DataplaneTCPRSTWindowSecs,
			handshakeState: dataplane.TCPHandshakeStateEstablished,
			closeClass:     3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := dataplane.SessionValue{
				State: dataplane.SessStateEstablished, Created: created,
				Timeout: tc.timeout, AppTimeout: longApp,
				TCPHandshakeState: tc.handshakeState, TCPCloseClass: tc.closeClass,
			}
			if primaryLivenessSwept16880(t, unix.IPPROTO_TCP, value,
				created+uint64(tc.cadenceTimeout)-1, created+uint64(tc.cadenceTimeout)-2) {
				t.Fatalf("TCP state refreshed before its %ds timeout", tc.cadenceTimeout)
			}
			if !primaryLivenessSwept16880(t, unix.IPPROTO_TCP, value,
				created+uint64(tc.cadenceTimeout), created+uint64(tc.cadenceTimeout)-1) {
				t.Fatalf("TCP state did not refresh by its %ds timeout", tc.cadenceTimeout)
			}
		})
	}
}

type completedSweepSessionStore16880 struct {
	dataplane.SessionStore
	completed chan struct{}
}

func (s completedSweepSessionStore16880) ForEachV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	err := s.SessionStore.ForEachV6(fn)
	select {
	case s.completed <- struct{}{}:
	default:
	}
	return err
}

func TestQueuedShortTimeoutWakesLivenessSweep16880(t *testing.T) {
	const base = uint64(20_000)
	longKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: unix.IPPROTO_TCP,
	}
	shortKey := longKey
	shortKey.SrcPort++
	longValue := dataplane.SessionValue{
		State: dataplane.SessStateEstablished, Created: base, LastSeen: base,
		Timeout: 3600, AppTimeout: 3600,
	}
	shortValue := dataplane.SessionValue{
		State: dataplane.SessStateEstablished, Created: base + 1, LastSeen: base + 1,
		Timeout: 1, AppTimeout: 1,
	}
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{longKey: longValue},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
	ss.IsPrimaryFn = func() bool { return true }
	completed := make(chan struct{}, 4)
	ss.sessions = completedSweepSessionStore16880{
		SessionStore: livenessProfiledSessionStore16880{
			SessionStore: ss.sessions,
			source:       livenessSweepProfileSource16880{},
		},
		completed: completed,
	}

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

	// The long-lived row establishes the 10s liveness scan cap and leaves the
	// profiled 15s active interval armed at 10s before the short row is queued.
	select {
	case <-completed:
	case <-time.After(3 * time.Second):
		t.Fatal("initial sweep did not complete")
	}
	time.Sleep(50 * time.Millisecond)
	for len(ss.sendCh) > 0 {
		<-ss.sendCh
	}

	// Queue a new one-second row after the long timer is armed. Its liveness
	// marker can only arrive promptly if this queue event re-arms that timer.
	dp.v4sessions[shortKey] = shortValue
	dp.sessionCounter = 2
	ss.QueueSessionV4(shortKey, shortValue)
	for len(ss.sendCh) > 0 {
		<-ss.sendCh
	}

	timeout := time.NewTimer(2900 * time.Millisecond)
	defer timeout.Stop()
	for {
		select {
		case frame := <-ss.sendCh:
			if len(frame) < syncHeaderSize {
				t.Fatalf("unexpected short queued frame: len=%d", len(frame))
			}
			if frame[4] != syncMsgSessionV4 {
				t.Fatalf("unexpected queued frame type=%d", frame[4])
			}
			_, sentValue, ok := decodeSessionV4Payload(frame[syncHeaderSize:])
			if !ok {
				t.Fatal("could not decode timer-driven session frame")
			}
			if sentValue.PrimaryLiveness {
				return
			}
		case <-timeout.C:
			t.Fatal("new one-second row did not wake the armed idle sweep in time for a liveness refresh")
		}
	}
}
