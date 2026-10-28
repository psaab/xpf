package cluster

import (
	"context"
	"net"
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
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
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
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
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

type livenessPublishBarrierStore16880 struct {
	dataplane.SessionStore
	enumerated chan struct{}
	release    chan struct{}
}

func (s livenessPublishBarrierStore16880) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	err := s.SessionStore.ForEachV4(fn)
	close(s.enumerated)
	<-s.release
	return err
}

func TestQueuedShortTimeoutSurvivesConcurrentSweepPublish16880(t *testing.T) {
	const base = uint64(12_000)
	existingKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: unix.IPPROTO_UDP,
	}
	newKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 3}, DstIP: [4]byte{10, 0, 0, 4},
		SrcPort: 12346, DstPort: 443, Protocol: unix.IPPROTO_UDP,
	}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			existingKey: {
				State: dataplane.SessStateEstablished, Created: base - 1,
				Timeout: 30, AppTimeout: 30, SessionID: 1,
			},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	barrier := livenessPublishBarrierStore16880{
		SessionStore: ss.sessions,
		enumerated:   make(chan struct{}),
		release:      make(chan struct{}),
	}
	ss.sessions = barrier
	ss.stats.Connected.Store(true)
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base
	ss.lastPrimaryLivenessSweepTime = base
	ss.primaryLivenessScanIntervalSeconds.Store(10)
	ss.testSweepNow = func() uint64 { return base + 1 }

	done := make(chan int, 1)
	go func() { done <- ss.syncSweep() }()
	select {
	case <-barrier.enumerated:
	case <-time.After(time.Second):
		close(barrier.release)
		t.Fatal("sweep did not reach the post-enumeration barrier")
	}

	// The new row is visible to the next sweep, but arrives after this scan's
	// V4 enumeration and before it publishes the old 10s minimum.
	newValue := dataplane.SessionValue{
		State: dataplane.SessStateEstablished, Created: base + 1,
		Timeout: 2, AppTimeout: 2, SessionID: 2,
	}
	dp.v4sessions[newKey] = newValue
	ss.QueueSessionV4(newKey, newValue)
	close(barrier.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sweep did not finish after releasing the enumeration barrier")
	}

	if got := ss.primaryLivenessScanIntervalSeconds.Load(); got != 1 {
		t.Fatalf("concurrent sweep publish overwrote queued 1s cadence: got %ds", got)
	}
}
func TestQueuedEqualCadenceRegistrationSurvivesPublication16880(t *testing.T) {
	const base = uint64(13_000)
	existingKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: unix.IPPROTO_UDP,
	}
	queuedKey := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 3}, DstIP: [4]byte{10, 0, 0, 4},
		SrcPort: 12346, DstPort: 443, Protocol: unix.IPPROTO_UDP,
	}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			existingKey: {
				State: dataplane.SessStateEstablished, Created: base - 1,
				Timeout: 30, AppTimeout: 30, SessionID: 1,
			},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	barrier := livenessPublishBarrierStore16880{
		SessionStore: ss.sessions,
		enumerated:   make(chan struct{}),
		release:      make(chan struct{}),
	}
	ss.sessions = barrier
	ss.stats.Connected.Store(true)
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base
	ss.lastPrimaryLivenessSweepTime = base
	ss.primaryLivenessScanIntervalSeconds.Store(1)
	now := base + 1
	ss.testSweepNow = func() uint64 { return now }

	// The first short request has the same cadence as the published interval.
	// The second request lands after enumeration; publication must not consume
	// the pending registration before a later scan can observe its row.
	ss.wakeSweepForQueuedSession(unix.IPPROTO_UDP, 2, 2, 0, 0, 0)
	done := make(chan int, 1)
	go func() { done <- ss.syncSweep() }()
	select {
	case <-barrier.enumerated:
	case <-time.After(time.Second):
		close(barrier.release)
		t.Fatal("sweep did not reach the post-enumeration barrier")
	}

	queuedValue := dataplane.SessionValue{
		State: dataplane.SessStateEstablished, Created: base - 1,
		Timeout: 2, AppTimeout: 2, SessionID: 2,
	}
	ss.QueueSessionV4(queuedKey, queuedValue)
	for len(ss.sendCh) > 0 {
		<-ss.sendCh
	}
	close(barrier.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sweep did not finish after releasing the enumeration barrier")
	}
	ss.primaryLivenessScanIntervalMu.Lock()
	pending := ss.pendingPrimaryLivenessScanIntervalSeconds
	ss.primaryLivenessScanIntervalMu.Unlock()
	if pending != 1 {
		t.Fatalf("post-enumeration registration was consumed before a scan saw its row: pending=%d, want 1", pending)
	}

	// Model one additional stale mirror batch: the registration must keep the
	// next publication at one second even when that scan still misses the row.
	ss.sessions = barrier.SessionStore
	now = base + 2
	ss.syncSweep()
	if got := ss.primaryLivenessScanIntervalSeconds.Load(); got != 1 {
		t.Fatalf("lagged scan raised liveness cadence to %ds, want 1s", got)
	}

	dp.v4sessions[queuedKey] = queuedValue
	now = base + 3
	ss.syncSweep()
	for len(ss.sendCh) > 0 {
		frame := <-ss.sendCh
		if len(frame) < syncHeaderSize || frame[4] != syncMsgSessionV4 {
			continue
		}
		gotKey, gotValue, ok := decodeSessionV4Payload(frame[syncHeaderSize:])
		if ok && gotKey == queuedKey && gotValue.PrimaryLiveness {
			return
		}
	}
	t.Fatal("row was not refreshed after becoming visible to the liveness scan")
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
	return primaryLivenessSweptWithProfile16880(t, protocol, value, now, previous, ReceiverSessionTimeoutProfile{})
}

func primaryLivenessSweptWithProfile16880(t *testing.T, protocol uint8, value dataplane.SessionValue, now, previous uint64, profile ReceiverSessionTimeoutProfile) bool {
	t.Helper()
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: protocol,
	}
	handshakeState := value.TCPHandshakeState
	closeClass := value.TCPCloseClass
	if protocol == unix.IPPROTO_TCP {
		if value.SessionID == 0 {
			value.SessionID = 42
		}
		value.TCPHandshakeState = 0
		value.TCPCloseClass = 0
	}
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{key: value},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	if profile != (ReceiverSessionTimeoutProfile{}) {
		ss.SetReceiverSessionTimeoutProfile(profile)
	}
	if protocol == unix.IPPROTO_TCP {
		ss.genState.genSentMu.Lock()
		ss.genState.tcpHandshakeSentV4[key] = sentTCPHandshakeState{sessionID: value.SessionID, state: handshakeState}
		ss.genState.closeClassSentV4[key] = sentCloseClass{sessionID: value.SessionID, class: closeClass}
		ss.genState.genSentMu.Unlock()
	}
	ss.stats.Connected.Store(true)
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
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

func TestPrimaryLivenessUsesConfiguredReceiverUDPTimeout16880(t *testing.T) {
	const base = uint64(15_000)
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 12345, DstPort: 443, Protocol: unix.IPPROTO_UDP,
	}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {
				State: dataplane.SessStateEstablished, Created: base,
				Timeout: 3600, AppTimeout: 3600, RevPackets: 1, SessionID: 10,
			},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.SetReceiverSessionTimeoutProfile(ReceiverSessionTimeoutProfile{UDPSessionSeconds: 10})
	ss.stats.Connected.Store(true)
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = base + 1
	ss.lastPrimaryLivenessSweepTime = base + 9
	ss.testSweepNow = func() uint64 { return base + 10 }

	if sent := ss.syncSweep(); sent != 1 {
		t.Fatalf("configured 10s UDP receiver timeout sent %d rows at its deadline, want 1", sent)
	}
	frame := <-ss.sendCh
	if len(frame) < syncHeaderSize || frame[4] != syncMsgSessionV4 {
		t.Fatalf("unexpected configured-timeout frame: len=%d", len(frame))
	}
	_, value, ok := decodeSessionV4Payload(frame[syncHeaderSize:])
	if !ok || !value.PrimaryLiveness {
		t.Fatalf("configured 10s UDP receiver timeout did not refresh at its deadline: ok=%t primary_liveness=%t", ok, value.PrimaryLiveness)
	}
}

func TestPrimaryLivenessUsesConfiguredTCPWindows16880(t *testing.T) {
	const (
		created = uint64(18_000)
		long    = uint32(config.DataplaneTCPEstablishedWindowSecs)
	)
	for _, tc := range []struct {
		name    string
		timeout uint64
		value   dataplane.SessionValue
		profile ReceiverSessionTimeoutProfile
	}{
		{
			name:    "opening",
			timeout: 10,
			value: dataplane.SessionValue{
				Timeout: long, SessionID: 10,
				TCPHandshakeState: dataplane.TCPHandshakeStateOpening,
			},
			profile: ReceiverSessionTimeoutProfile{TCPOpeningSeconds: 10},
		},
		{
			name:    "established honors configured window without app override",
			timeout: 10,
			value: dataplane.SessionValue{
				Timeout: long, SessionID: 10,
				TCPHandshakeState: dataplane.TCPHandshakeStateEstablished,
			},
			profile: ReceiverSessionTimeoutProfile{TCPEstablishedSeconds: 10},
		},
		{
			name:    "established zero-timeout mirror uses configured window",
			timeout: 10,
			value: dataplane.SessionValue{
				Timeout: 0, SessionID: 10,
				TCPHandshakeState: dataplane.TCPHandshakeStateEstablished,
			},
			profile: ReceiverSessionTimeoutProfile{TCPEstablishedSeconds: 10},
		},
		{
			name:    "closing",
			timeout: 12,
			value: dataplane.SessionValue{
				Timeout: long, SessionID: 12,
				TCPHandshakeState: dataplane.TCPHandshakeStateEstablished, TCPCloseClass: 1,
			},
			profile: ReceiverSessionTimeoutProfile{TCPClosingSeconds: 12},
		},
		{
			name:    "time-wait",
			timeout: 14,
			value: dataplane.SessionValue{
				Timeout: long, SessionID: 14,
				TCPHandshakeState: dataplane.TCPHandshakeStateEstablished, TCPCloseClass: 2,
			},
			profile: ReceiverSessionTimeoutProfile{TCPTimeWaitSeconds: 14},
		},
		{
			name:    "time-wait window also governs half-closed",
			timeout: 16,
			value: dataplane.SessionValue{
				Timeout: long, SessionID: 16,
				TCPHandshakeState: dataplane.TCPHandshakeStateEstablished, TCPCloseClass: 1,
			},
			profile: ReceiverSessionTimeoutProfile{
				TCPTimeWaitSeconds: 16, TCPTimeWaitApplyToHalfClosed: true,
			},
		},
		{
			name:    "time-wait ageout uses established window",
			timeout: 11,
			value: dataplane.SessionValue{
				Timeout: long, SessionID: 11,
				TCPHandshakeState: dataplane.TCPHandshakeStateEstablished, TCPCloseClass: 2,
			},
			profile: ReceiverSessionTimeoutProfile{
				TCPEstablishedSeconds: 11, TCPTimeWaitSeconds: 16,
				TCPTimeWaitSessionAgeout: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.value.State = dataplane.SessStateEstablished
			tc.value.Created = created
			if primaryLivenessSweptWithProfile16880(t, unix.IPPROTO_TCP, tc.value,
				created+tc.timeout-1, created+tc.timeout-2, tc.profile) {
				t.Fatalf("configured TCP receiver window refreshed before %ds", tc.timeout)
			}
			if !primaryLivenessSweptWithProfile16880(t, unix.IPPROTO_TCP, tc.value,
				created+tc.timeout, created+tc.timeout-1, tc.profile) {
				t.Fatalf("configured TCP receiver window did not refresh by %ds", tc.timeout)
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
				SessionID:         uint64(tc.cadenceTimeout),
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
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
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

func TestNewDualSessionSyncWakesForShortTimeout16880(t *testing.T) {
	ss := NewDualSessionSync(":0", "10.0.0.2:4785", ":0", "10.0.0.3:4785", nil)
	if !ss.IsDualFabric() {
		t.Fatal("fixture did not construct dual-fabric session sync")
	}
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
	ss.primaryLivenessScanIntervalSeconds.Store(10)

	ss.wakeSweepForQueuedSession(unix.IPPROTO_UDP, 2, 2, 0, 0, 0)
	select {
	case <-ss.sweepWakeCh:
	default:
		t.Fatal("dual-fabric SessionSync has no wake channel for a newly queued short-timeout row")
	}
	if got := ss.sweepWakeScanIntervalSeconds.Load(); got != 1 {
		t.Fatalf("dual-fabric queued scan request = %ds, want 1s", got)
	}
}

func TestPrimaryLivenessMarkerRequiresPeerCapability16880(t *testing.T) {
	key4 := dataplane.SessionKey{SrcPort: 1000, DstPort: 443, Protocol: 6}
	val4 := dataplane.SessionValue{PrimaryLiveness: true}
	key6 := dataplane.SessionKeyV6{SrcPort: 1000, DstPort: 443, Protocol: 6}
	val6 := dataplane.SessionValueV6{PrimaryLiveness: true}

	for _, tc := range []struct {
		name string
		ss   *SessionSync
		want bool
	}{
		{name: "unknown peer", ss: &SessionSync{}},
		{name: "capable peer", ss: func() *SessionSync {
			ss := &SessionSync{}
			ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness))
			return ss
		}(), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, got4, ok4 := decodeSessionV4Payload(tc.ss.encodeSessionV4PayloadForPeer(key4, val4))
			_, got6, ok6 := decodeSessionV6Payload(tc.ss.encodeSessionV6PayloadForPeer(key6, val6))
			if !ok4 || !ok6 {
				t.Fatalf("peer-aware session encoding failed: v4=%v v6=%v", ok4, ok6)
			}
			if got4.PrimaryLiveness != tc.want || got6.PrimaryLiveness != tc.want {
				t.Fatalf("primary-liveness markers v4/v6 = %v/%v, want %v",
					got4.PrimaryLiveness, got6.PrimaryLiveness, tc.want)
			}
		})
	}
}

func TestQueuedPrimaryLivenessFrameRechecksPeerAfterDowngrade16880(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	localConn, peerConn := net.Pipe()
	defer localConn.Close()
	defer peerConn.Close()
	ss.mu.Lock()
	ss.conn0 = localConn
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)
	ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PrimaryLiveness | capFlag2PersistentNatLeaseProvenance))

	key := dataplane.SessionKey{SrcPort: 12345, DstPort: 443, Protocol: 6}
	value := dataplane.SessionValue{PrimaryLiveness: true}
	msg := ss.encodeSessionV4ForPeer(key, value)
	_, queuedValue, ok := decodeSessionV4Payload(msg[syncHeaderSize:])
	if !ok || !queuedValue.PrimaryLiveness {
		t.Fatal("fixture did not queue a liveness-marked frame for the capable peer")
	}
	// The frame was encoded for a peer advertising both capabilities; the
	// reconnect then advertises provenance alone before queued bytes are written.
	ss.testBeforeQueuedWrite = func() {
		ss.peerIncarnationState().peerCapabilityFlags2.Store(uint32(capFlag2PersistentNatLeaseProvenance))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ss.sendLoop(ctx)
	}()
	ss.sendCh <- msg

	msgType, payload := readFrame(t, peerConn)
	if msgType != syncMsgSessionV4 {
		t.Fatalf("reconnected peer received frame type %d, want session v4", msgType)
	}
	_, got, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("reconnected peer received a malformed session frame")
	}
	if got.PrimaryLiveness {
		t.Fatal("peer advertising only provenance received the stale liveness marker")
	}
	cancel()
	<-done
}
