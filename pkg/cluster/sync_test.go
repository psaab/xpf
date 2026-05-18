package cluster

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

func readSyncMessage(t *testing.T, conn net.Conn) (uint8, []byte) {
	t.Helper()

	var hdr [syncHeaderSize]byte
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read sync header: %v", err)
	}
	if string(hdr[0:4]) != "BPSY" {
		t.Fatalf("bad sync magic: %q", hdr[0:4])
	}
	payloadLen := binary.LittleEndian.Uint32(hdr[8:12])
	if payloadLen > 1<<20 {
		t.Fatalf("unexpected sync payload length: %d", payloadLen)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read sync payload: %v", err)
	}
	return hdr[4], payload
}

func TestSyncHeaderEncoding(t *testing.T) {
	// Test that writeMsg produces valid headers
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 1},
		DstIP:    [4]byte{10, 0, 2, 1},
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}

	msg := encodeDeleteV4(key)

	// Check header
	if string(msg[0:4]) != "BPSY" {
		t.Fatalf("bad magic: %q", msg[0:4])
	}
	if msg[4] != syncMsgDeleteV4 {
		t.Fatalf("bad type: %d", msg[4])
	}
	length := binary.LittleEndian.Uint32(msg[8:12])
	if length != 16 {
		t.Fatalf("bad length: %d", length)
	}

	// Check payload
	payload := msg[syncHeaderSize:]
	if payload[0] != 10 || payload[1] != 0 || payload[2] != 1 || payload[3] != 1 {
		t.Fatalf("bad src IP in payload")
	}
	if payload[4] != 10 || payload[5] != 0 || payload[6] != 2 || payload[7] != 1 {
		t.Fatalf("bad dst IP in payload")
	}
	port := binary.LittleEndian.Uint16(payload[8:10])
	if port != 12345 {
		t.Fatalf("bad src port: %d", port)
	}
}

func TestEncodeSessionV4(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{192, 168, 1, 1},
		DstIP:    [4]byte{10, 0, 0, 1},
		SrcPort:  1024,
		DstPort:  443,
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		State:       dataplane.SessStateEstablished,
		Flags:       dataplane.SessFlagSNAT,
		Created:     1000,
		LastSeen:    2000,
		Timeout:     3600,
		PolicyID:    1,
		IngressZone: 1,
		EgressZone:  2,
		NATSrcIP:    0x0100000a, // 10.0.0.1 in native endian
		FwdPackets:  100,
		FwdBytes:    50000,
	}

	msg := encodeSessionV4(key, val)

	// Verify magic and type
	if string(msg[0:4]) != "BPSY" {
		t.Fatalf("bad magic: %q", msg[0:4])
	}
	if msg[4] != syncMsgSessionV4 {
		t.Fatalf("bad type: %d", msg[4])
	}

	// Verify payload has correct key at start
	payload := msg[syncHeaderSize:]
	if payload[0] != 192 || payload[1] != 168 {
		t.Fatalf("bad src IP start in payload")
	}
}

func TestEncodeDeleteV6(t *testing.T) {
	key := dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		SrcPort:  8080,
		DstPort:  443,
		Protocol: 6,
	}

	msg := encodeDeleteV6(key)

	if string(msg[0:4]) != "BPSY" {
		t.Fatalf("bad magic")
	}
	if msg[4] != syncMsgDeleteV6 {
		t.Fatalf("bad type: %d", msg[4])
	}
	length := binary.LittleEndian.Uint32(msg[8:12])
	if length != 40 {
		t.Fatalf("bad length: %d", length)
	}
}

func TestEncodeSessionV6(t *testing.T) {
	key := dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		SrcPort:  9090,
		DstPort:  80,
		Protocol: 6,
	}
	val := dataplane.SessionValueV6{
		State:   dataplane.SessStateEstablished,
		Created: 5000,
		Timeout: 1800,
	}

	msg := encodeSessionV6(key, val)

	if string(msg[0:4]) != "BPSY" {
		t.Fatalf("bad magic")
	}
	if msg[4] != syncMsgSessionV6 {
		t.Fatalf("bad type: %d", msg[4])
	}
}

func TestPeerRecentlyActive(t *testing.T) {
	s := &SessionSync{}
	if s.PeerRecentlyActive(time.Second) {
		t.Fatal("expected false without peer activity")
	}

	s.lastPeerRxUnix.Store(time.Now().Add(-500 * time.Millisecond).UnixNano())
	if !s.PeerRecentlyActive(time.Second) {
		t.Fatal("expected recent peer activity to be reported")
	}
	if s.PeerRecentlyActive(100 * time.Millisecond) {
		t.Fatal("expected stale peer activity for tight window")
	}
}

func TestPeerHealthyRequiresRecentInboundAfterHeartbeatAckCapability(t *testing.T) {
	s := &SessionSync{}
	if s.PeerHealthy() {
		t.Fatal("expected disconnected session sync to be unhealthy")
	}

	s.stats.Connected.Store(true)
	if !s.PeerHealthy() {
		t.Fatal("expected connected pre-capability session sync to be healthy")
	}

	s.peerHeartbeatAckEver.Store(true)
	s.lastPeerRxUnix.Store(time.Now().UnixNano())
	if !s.PeerHealthy() {
		t.Fatal("expected recent peer activity to be healthy")
	}

	s.lastPeerRxUnix.Store(time.Now().Add(-2 * syncPeerSilenceTimeout).UnixNano())
	if s.PeerHealthy() {
		t.Fatal("expected stale peer activity to be unhealthy")
	}
}

func TestForwardSessionInstalledCallbackFiresOnlyForForwardSessions(t *testing.T) {
	dp := &mockSweepDP{}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	calls := 0
	ss.OnForwardSessionInstalled = func() {
		calls++
	}

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  12345,
		DstPort:  5201,
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		State:       dataplane.SessStateEstablished,
		IngressZone: 1,
		EgressZone:  2,
	}

	ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4(key, val)[syncHeaderSize:])
	if got := calls; got != 1 {
		t.Fatalf("forward callback calls = %d, want 1", got)
	}

	val.IsReverse = 1
	ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4(key, val)[syncHeaderSize:])
	if got := calls; got != 1 {
		t.Fatalf("reverse callback calls = %d, want 1", got)
	}
}

func TestSyncStatsInit(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	stats := ss.Stats()
	if stats.Connected {
		t.Fatal("should not be connected initially")
	}
	if stats.SessionsSent != 0 {
		t.Fatal("sessions sent should be 0")
	}
}

func TestQueueWithoutConnection(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	// Should not panic with no connection
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{}
	ss.QueueSessionV4(key, val)
	// Message should be dropped since not connected
	if ss.stats.SessionsSent.Load() != 0 {
		t.Fatal("should not count sent when not connected")
	}
}

func TestFormatStats(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	ss.stats.SessionsSent.Store(100)
	ss.stats.SessionsReceived.Store(50)
	out := ss.FormatStats()
	if out == "" {
		t.Fatal("format stats should produce output")
	}
}

func TestValidateFailoverBatchRGCount(t *testing.T) {
	okRGs := make([]int, maxFailoverBatchRGCount)
	if err := validateFailoverBatchRGCount(okRGs); err != nil {
		t.Fatalf("validateFailoverBatchRGCount(%d) error = %v", len(okRGs), err)
	}

	tooManyRGs := make([]int, maxFailoverBatchRGCount+1)
	if err := validateFailoverBatchRGCount(tooManyRGs); err == nil {
		t.Fatalf("validateFailoverBatchRGCount(%d) unexpectedly succeeded", len(tooManyRGs))
	}
}

func TestDecodeSessionV4RoundTrip(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{192, 168, 1, 1},
		DstIP:    [4]byte{10, 0, 0, 1},
		SrcPort:  1024,
		DstPort:  443,
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		State:       dataplane.SessStateEstablished,
		Flags:       dataplane.SessFlagSNAT,
		TCPState:    3,
		Created:     1000,
		LastSeen:    2000,
		Timeout:     3600,
		PolicyID:    42,
		IngressZone: 1,
		EgressZone:  2,
		NATSrcIP:    0x0100000a,
		NATDstIP:    0x0200000a,
		NATSrcPort:  5000,
		NATDstPort:  80,
		FwdPackets:  100,
		FwdBytes:    50000,
		RevPackets:  80,
		RevBytes:    40000,
		ReverseKey: dataplane.SessionKey{
			SrcIP:    [4]byte{10, 0, 0, 1},
			DstIP:    [4]byte{192, 168, 1, 1},
			SrcPort:  443,
			DstPort:  1024,
			Protocol: 6,
		},
		ALGType:    1,
		LogFlags:   2,
		FibIfindex: 586,
		FibVlanID:  80,
		FibDmac:    [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		FibSmac:    [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08},
		FibGen:     7,
	}

	payload := encodeSessionV4Payload(key, val)
	dKey, dVal, ok := decodeSessionV4Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}

	if dKey != key {
		t.Fatalf("key mismatch: got %+v, want %+v", dKey, key)
	}
	if dVal.State != val.State {
		t.Fatalf("State mismatch: %d vs %d", dVal.State, val.State)
	}
	if dVal.Flags != val.Flags {
		t.Fatalf("Flags mismatch: %d vs %d", dVal.Flags, val.Flags)
	}
	if dVal.TCPState != val.TCPState {
		t.Fatalf("TCPState mismatch")
	}
	if dVal.Created != val.Created || dVal.LastSeen != val.LastSeen {
		t.Fatalf("timestamps mismatch")
	}
	if dVal.Timeout != val.Timeout || dVal.PolicyID != val.PolicyID {
		t.Fatalf("timeout/policy mismatch")
	}
	if dVal.IngressZone != val.IngressZone || dVal.EgressZone != val.EgressZone {
		t.Fatalf("zone mismatch")
	}
	if dVal.NATSrcIP != val.NATSrcIP || dVal.NATDstIP != val.NATDstIP {
		t.Fatalf("NAT IP mismatch")
	}
	if dVal.NATSrcPort != val.NATSrcPort || dVal.NATDstPort != val.NATDstPort {
		t.Fatalf("NAT port mismatch")
	}
	if dVal.FwdPackets != val.FwdPackets || dVal.FwdBytes != val.FwdBytes {
		t.Fatalf("fwd counter mismatch")
	}
	if dVal.RevPackets != val.RevPackets || dVal.RevBytes != val.RevBytes {
		t.Fatalf("rev counter mismatch")
	}
	if dVal.ReverseKey != val.ReverseKey {
		t.Fatalf("reverse key mismatch: got %+v", dVal.ReverseKey)
	}
	if dVal.ALGType != val.ALGType || dVal.LogFlags != val.LogFlags {
		t.Fatalf("ALG/log mismatch")
	}
	if dVal.FibIfindex != val.FibIfindex || dVal.FibVlanID != val.FibVlanID {
		t.Fatalf("fib ifindex/vlan mismatch")
	}
	if dVal.FibDmac != val.FibDmac || dVal.FibSmac != val.FibSmac || dVal.FibGen != val.FibGen {
		t.Fatalf("fib metadata mismatch")
	}
}

func TestDecodeSessionV6RoundTrip(t *testing.T) {
	key := dataplane.SessionKeyV6{
		SrcIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:    [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		SrcPort:  9090,
		DstPort:  80,
		Protocol: 6,
	}
	val := dataplane.SessionValueV6{
		State:       dataplane.SessStateEstablished,
		Flags:       dataplane.SessFlagDNAT,
		TCPState:    2,
		Created:     5000,
		LastSeen:    6000,
		Timeout:     1800,
		PolicyID:    10,
		IngressZone: 3,
		EgressZone:  4,
		NATSrcIP:    [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		NATSrcPort:  4000,
		FwdPackets:  200,
		FwdBytes:    100000,
		ALGType:     2,
		FibIfindex:  586,
		FibVlanID:   80,
		FibDmac:     [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		FibSmac:     [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08},
		FibGen:      9,
	}

	payload := encodeSessionV6Payload(key, val)
	dKey, dVal, ok := decodeSessionV6Payload(payload)
	if !ok {
		t.Fatal("decode failed")
	}

	if dKey != key {
		t.Fatalf("key mismatch: got %+v, want %+v", dKey, key)
	}
	if dVal.State != val.State {
		t.Fatalf("State mismatch")
	}
	if dVal.Flags != val.Flags {
		t.Fatalf("Flags mismatch")
	}
	if dVal.Created != val.Created || dVal.Timeout != val.Timeout {
		t.Fatalf("timestamps mismatch")
	}
	if dVal.NATSrcIP != val.NATSrcIP {
		t.Fatalf("NAT src IP mismatch")
	}
	if dVal.NATSrcPort != val.NATSrcPort {
		t.Fatalf("NAT src port mismatch")
	}
	if dVal.FwdPackets != val.FwdPackets || dVal.FwdBytes != val.FwdBytes {
		t.Fatalf("fwd counter mismatch")
	}
	if dVal.FibIfindex != val.FibIfindex || dVal.FibVlanID != val.FibVlanID {
		t.Fatalf("fib ifindex/vlan mismatch")
	}
	if dVal.FibDmac != val.FibDmac || dVal.FibSmac != val.FibSmac || dVal.FibGen != val.FibGen {
		t.Fatalf("fib metadata mismatch")
	}
}

func TestDecodeSessionV4Short(t *testing.T) {
	// Too short for even a key
	_, _, ok := decodeSessionV4Payload([]byte{1, 2, 3})
	if ok {
		t.Fatal("should fail on short payload")
	}
}

func TestDecodeSessionV6Short(t *testing.T) {
	_, _, ok := decodeSessionV6Payload([]byte{1, 2, 3})
	if ok {
		t.Fatal("should fail on short payload")
	}
}

func TestIPsecSAPayloadRoundTrip(t *testing.T) {
	names := []string{"vpn-site-a", "vpn-site-b", "tunnel-corp"}
	payload := encodeIPsecSAPayload(names)
	decoded := decodeIPsecSAPayload(payload)

	if len(decoded) != len(names) {
		t.Fatalf("count mismatch: got %d, want %d", len(decoded), len(names))
	}
	for i, name := range names {
		if decoded[i] != name {
			t.Fatalf("name[%d] mismatch: got %q, want %q", i, decoded[i], name)
		}
	}
}

func TestIPsecSAPayloadEmpty(t *testing.T) {
	payload := encodeIPsecSAPayload(nil)
	decoded := decodeIPsecSAPayload(payload)
	if len(decoded) != 0 {
		t.Fatalf("expected empty, got %d", len(decoded))
	}
}

func TestPeerIPsecSAs(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)

	// Initially empty
	if names := ss.PeerIPsecSAs(); len(names) != 0 {
		t.Fatal("should be empty initially")
	}

	// Simulate receiving IPsec SA list
	ss.handleMessage(nil, syncMsgIPsecSA, encodeIPsecSAPayload([]string{"vpn-a", "vpn-b"}))

	names := ss.PeerIPsecSAs()
	if len(names) != 2 {
		t.Fatalf("got %d names, want 2", len(names))
	}
	if names[0] != "vpn-a" || names[1] != "vpn-b" {
		t.Fatalf("unexpected names: %v", names)
	}
}

func TestSetDataPlane(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	if ss.sessions != nil {
		t.Fatal("session store should be nil initially")
	}

	// Simulate handleMessage without dp — should not crash
	key := dataplane.SessionKey{Protocol: 6, SrcIP: [4]byte{1, 2, 3, 4}, DstIP: [4]byte{5, 6, 7, 8}}
	val := dataplane.SessionValue{State: 1}
	payload := encodeSessionV4Payload(key, val)
	ss.handleMessage(nil, syncMsgSessionV4, payload)

	if ss.stats.SessionsReceived.Load() != 1 {
		t.Fatal("should count received")
	}
	if ss.stats.SessionsInstalled.Load() != 0 {
		t.Fatal("should not install without dp")
	}
}

func TestHandleMessageDeleteV4(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	// Without dp, should not crash
	key := dataplane.SessionKey{Protocol: 6}
	msg := encodeDeleteV4(key)
	ss.handleMessage(nil, syncMsgDeleteV4, msg[syncHeaderSize:])
	if ss.stats.DeletesReceived.Load() != 1 {
		t.Fatal("should count delete received")
	}
}

// --- Sync sweep tests ---

// mockSweepDP is a minimal mock for testing sync sweep.
// Embeds DataPlane interface; only IterateSessions/V6 are implemented.
type mockSweepDP struct {
	dataplane.DataPlane
	v4sessions     map[dataplane.SessionKey]dataplane.SessionValue
	v6sessions     map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	sessionCounter uint64
	deletedDNATV4  []dataplane.DNATKey
	deletedDNATV6  []dataplane.DNATKeyV6
}

func (m *mockSweepDP) ReadGlobalCounter(index uint32) (uint64, error) {
	return m.sessionCounter, nil
}

func (m *mockSweepDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range m.v4sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (m *mockSweepDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for k, v := range m.v6sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (m *mockSweepDP) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return m.IterateSessions(fn)
}

func (m *mockSweepDP) BatchIterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return m.IterateSessionsV6(fn)
}

func (m *mockSweepDP) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	if v, ok := m.v4sessions[key]; ok {
		return v, nil
	}
	return dataplane.SessionValue{}, ebpf.ErrKeyNotExist
}

func (m *mockSweepDP) GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	if v, ok := m.v6sessions[key]; ok {
		return v, nil
	}
	return dataplane.SessionValueV6{}, ebpf.ErrKeyNotExist
}

func (m *mockSweepDP) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	if m.v4sessions == nil {
		m.v4sessions = make(map[dataplane.SessionKey]dataplane.SessionValue)
	}
	m.v4sessions[key] = val
	return nil
}

func (m *mockSweepDP) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	if m.v6sessions == nil {
		m.v6sessions = make(map[dataplane.SessionKeyV6]dataplane.SessionValueV6)
	}
	m.v6sessions[key] = val
	return nil
}

func (m *mockSweepDP) DeleteSession(key dataplane.SessionKey) error {
	delete(m.v4sessions, key)
	return nil
}

func (m *mockSweepDP) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	delete(m.v6sessions, key)
	return nil
}

func (m *mockSweepDP) DeleteDNATEntry(key dataplane.DNATKey) error {
	m.deletedDNATV4 = append(m.deletedDNATV4, key)
	return nil
}

func (m *mockSweepDP) DeleteDNATEntryV6(key dataplane.DNATKeyV6) error {
	m.deletedDNATV6 = append(m.deletedDNATV6, key)
	return nil
}

func (m *mockSweepDP) GetPersistentNAT() *dataplane.PersistentNATTable { return nil }

func (m *mockSweepDP) SetDNATEntry(key dataplane.DNATKey, val dataplane.DNATValue) error {
	return nil
}

func (m *mockSweepDP) SetDNATEntryV6(key dataplane.DNATKeyV6, val dataplane.DNATValueV6) error {
	return nil
}

func TestSyncSweepNewSessions(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				State: dataplane.SessStateEstablished, Created: now, IsReverse: 0,
			},
			{SrcIP: [4]byte{10, 0, 1, 2}, DstIP: [4]byte{10, 0, 2, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}: {
				State: dataplane.SessStateEstablished, Created: now - 100, IsReverse: 0, // old session
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now // only sessions created at or after 'now' should sync

	ss.syncSweep()

	// Should have synced exactly 1 session (the one with Created == now)
	if ss.stats.SessionsSent.Load() != 1 {
		t.Fatalf("expected 1 session sent, got %d", ss.stats.SessionsSent.Load())
	}
}

func TestSyncSweepPausedSkipsIncrementalReplay(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{
				SrcIP:    [4]byte{10, 0, 0, 1},
				DstIP:    [4]byte{10, 0, 0, 2},
				SrcPort:  1234,
				DstPort:  80,
				Protocol: 6,
			}: {
				Created:     now,
				LastSeen:    now,
				IngressZone: 1,
			},
		},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":4785", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now - 1

	ss.PauseIncrementalSync("test")
	if got := ss.syncSweep(); got != 0 {
		t.Fatalf("expected paused sweep to queue 0 sessions, got %d", got)
	}
	if len(ss.sendCh) != 0 {
		t.Fatalf("expected paused sweep to leave send queue empty, got len=%d", len(ss.sendCh))
	}
	if ss.lastSweepTime != now-1 {
		t.Fatalf("expected paused sweep to preserve lastSweepTime, got %d", ss.lastSweepTime)
	}

	ss.ResumeIncrementalSync("test")
	if got := ss.syncSweep(); got != 1 {
		t.Fatalf("expected resumed sweep to queue 1 session, got %d", got)
	}
	if len(ss.sendCh) != 1 {
		t.Fatalf("expected resumed sweep to queue one message, got len=%d", len(ss.sendCh))
	}
}

func TestSyncSweepSkipsReverse(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6}: {
				Created: now, IsReverse: 1, // reverse entry
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 0 {
		t.Fatal("should not sync reverse entries")
	}
}

func TestSyncSweepSkipsWhenNotPrimary(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{Protocol: 6}: {Created: now, IsReverse: 0},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return false }
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 0 {
		t.Fatal("should not sync when not primary")
	}
}

func TestSyncSweepSkipsWhenDisconnected(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{Protocol: 6}: {Created: now, IsReverse: 0},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(false)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 0 {
		t.Fatal("should not sync when disconnected")
	}
}

func TestBulkEndTriggersCallback(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)

	called := make(chan struct{}, 1)
	ss.OnBulkSyncReceived = func() {
		called <- struct{}{}
	}

	// Simulate receiving BulkEnd message.
	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	select {
	case <-called:
		// OK
	case <-time.After(time.Second):
		t.Fatal("OnBulkSyncReceived callback not called within 1s")
	}
}

func TestBulkEndWithoutCallback(t *testing.T) {
	ss := NewSessionSync(":4785", "10.0.0.2:4785", nil)
	// Should not panic when callback is nil.
	ss.handleMessage(nil, syncMsgBulkEnd, nil)
}

func TestSyncSweepV6(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			{SrcIP: [16]byte{0x20, 0x01}, Protocol: 6}: {
				Created: now, IsReverse: 0,
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return true }
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 1 {
		t.Fatalf("expected 1 v6 session sent, got %d", ss.stats.SessionsSent.Load())
	}
}

func TestShouldSyncZoneFallback(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.IsPrimaryFn = func() bool { return true }

	// No IsPrimaryForRGFn or zoneRGMap — should fall back to IsPrimaryFn.
	if !ss.ShouldSyncZone(1) {
		t.Fatal("expected ShouldSyncZone to return true via fallback")
	}

	ss.IsPrimaryFn = func() bool { return false }
	if ss.ShouldSyncZone(1) {
		t.Fatal("expected ShouldSyncZone to return false via fallback")
	}
}

func TestShouldSyncZonePerRG(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.IsPrimaryFn = func() bool { return false } // not primary for RG 0
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1 // primary for RG 1 only
	}
	ss.SetZoneRGMap(map[uint16]int{
		1: 1, // zone 1 → RG 1
		2: 2, // zone 2 → RG 2
	})

	// Zone 1 → RG 1 (primary) → should sync
	if !ss.ShouldSyncZone(1) {
		t.Fatal("zone 1 should sync (RG 1 is primary)")
	}

	// Zone 2 → RG 2 (not primary) → should not sync
	if ss.ShouldSyncZone(2) {
		t.Fatal("zone 2 should not sync (RG 2 is not primary)")
	}

	// Zone 3 → not in map → falls back to IsPrimaryFn (false)
	if ss.ShouldSyncZone(3) {
		t.Fatal("zone 3 should not sync (fallback to IsPrimaryFn=false)")
	}
}

func TestSyncSweepPerRG(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			// Session in zone 1 (RG 1 — primary)
			{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				State: dataplane.SessStateEstablished, Created: now, IsReverse: 0, IngressZone: 1,
			},
			// Session in zone 2 (RG 2 — not primary)
			{SrcIP: [4]byte{10, 0, 3, 1}, DstIP: [4]byte{10, 0, 4, 1}, Protocol: 6, SrcPort: 2000, DstPort: 443}: {
				State: dataplane.SessStateEstablished, Created: now, IsReverse: 0, IngressZone: 2,
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1 // primary for RG 1 only
	}
	ss.SetZoneRGMap(map[uint16]int{
		1: 1, // zone 1 → RG 1
		2: 2, // zone 2 → RG 2
	})
	ss.lastSweepTime = now

	ss.syncSweep()

	// Only the session in zone 1 (RG 1) should be synced
	if ss.stats.SessionsSent.Load() != 1 {
		t.Fatalf("expected 1 session synced (zone 1/RG 1), got %d", ss.stats.SessionsSent.Load())
	}
}

func TestSyncSweepPerRGV6(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			// Session in zone 1 (RG 1 — primary)
			{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Protocol: 6}: {
				Created: now, IsReverse: 0, IngressZone: 1,
			},
			// Session in zone 2 (RG 2 — not primary)
			{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, Protocol: 6}: {
				Created: now, IsReverse: 0, IngressZone: 2,
			},
		},
		sessionCounter: 1,
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.stats.Connected.Store(true)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})
	ss.lastSweepTime = now

	ss.syncSweep()

	if ss.stats.SessionsSent.Load() != 1 {
		t.Fatalf("expected 1 v6 session synced, got %d", ss.stats.SessionsSent.Load())
	}
}

// shortWriteConn is a mock net.Conn that returns short writes (1 byte at a time).
type shortWriteConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (c *shortWriteConn) SetDeadline(time.Time) error {
	return nil
}

func (c *shortWriteConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *shortWriteConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *shortWriteConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	// Only write 1 byte at a time to simulate short writes.
	c.buf = append(c.buf, b[0])
	return 1, nil
}

func (c *shortWriteConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

func TestWriteFullShortWrites(t *testing.T) {
	sw := &shortWriteConn{}

	// Use writeMsg which calls writeFull internally.
	payload := []byte("hello world")
	err := writeMsg(sw, syncMsgConfig, payload)
	if err != nil {
		t.Fatalf("writeMsg failed: %v", err)
	}

	got := sw.bytes()
	expected := syncHeaderSize + len(payload)
	if len(got) != expected {
		t.Fatalf("expected %d bytes, got %d", expected, len(got))
	}

	// Verify header.
	if string(got[0:4]) != "BPSY" {
		t.Fatalf("bad magic: %q", got[0:4])
	}
	if got[4] != syncMsgConfig {
		t.Fatalf("bad msg type: %d", got[4])
	}
	pLen := binary.LittleEndian.Uint32(got[8:12])
	if int(pLen) != len(payload) {
		t.Fatalf("bad payload length: %d", pLen)
	}

	// Verify payload.
	if string(got[syncHeaderSize:]) != "hello world" {
		t.Fatalf("bad payload: %q", got[syncHeaderSize:])
	}
}

func TestWriteFullDirectShortWrites(t *testing.T) {
	sw := &shortWriteConn{}

	// Write a pre-encoded session message through writeFull directly.
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 1},
		DstIP:    [4]byte{10, 0, 2, 1},
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished}
	msg := encodeSessionV4(key, val)

	err := writeFull(sw, msg)
	if err != nil {
		t.Fatalf("writeFull failed: %v", err)
	}

	got := sw.bytes()
	if len(got) != len(msg) {
		t.Fatalf("expected %d bytes, got %d", len(msg), len(got))
	}

	// Verify byte-for-byte match.
	for i := range msg {
		if got[i] != msg[i] {
			t.Fatalf("byte mismatch at offset %d: got %02x, want %02x", i, got[i], msg[i])
		}
	}
}

func TestShouldInitiateFabricDial(t *testing.T) {
	tests := []struct {
		name     string
		local    string
		peer     string
		expected bool
	}{
		{name: "lower address dials", local: "10.99.12.1:4785", peer: "10.99.12.2:4785", expected: true},
		{name: "higher address listens", local: "10.99.12.2:4785", peer: "10.99.12.1:4785", expected: false},
		{name: "lower port dials when ip same", local: "10.99.12.1:4784", peer: "10.99.12.1:4785", expected: true},
		{name: "unparsable local preserves legacy dial", local: ":4785", peer: "10.99.12.2:4785", expected: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldInitiateFabricDial(tc.local, tc.peer); got != tc.expected {
				t.Fatalf("shouldInitiateFabricDial(%q, %q)=%t want %t", tc.local, tc.peer, got, tc.expected)
			}
		})
	}
}

// msgCapture wraps a net.Conn and records message types in order.
type msgCapture struct {
	net.Conn
	mu       sync.Mutex
	msgTypes []uint8
}

func (c *msgCapture) SetDeadline(time.Time) error {
	return nil
}

func (c *msgCapture) SetReadDeadline(time.Time) error {
	return nil
}

func (c *msgCapture) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *msgCapture) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(b) >= syncHeaderSize && string(b[0:4]) == "BPSY" {
		c.msgTypes = append(c.msgTypes, b[4])
	}
	return len(b), nil
}

func (c *msgCapture) types() []uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]uint8, len(c.msgTypes))
	copy(cp, c.msgTypes)
	return cp
}

func TestBulkSyncSerialization(t *testing.T) {
	// Verify that two concurrent BulkSync() calls are serialized:
	// the message stream should never interleave BulkStart/BulkEnd
	// from different epochs.
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				IsReverse: 0, IngressZone: 1,
			},
		},
	}

	mc := &msgCapture{}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }
	ss.mu.Lock()
	ss.conn0 = mc
	ss.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ss.BulkSync()
		}()
	}
	wg.Wait()

	// Check that BulkStart/BulkEnd messages are always paired (never interleaved).
	types := mc.types()
	depth := 0
	for i, mt := range types {
		if mt == syncMsgBulkStart {
			depth++
			if depth > 1 {
				t.Fatalf("interleaved BulkStart at msg index %d (depth %d)", i, depth)
			}
		}
		if mt == syncMsgBulkEnd {
			if depth != 1 {
				t.Fatalf("BulkEnd without matching BulkStart at msg index %d", i)
			}
			depth--
		}
	}
	if depth != 0 {
		t.Fatalf("unmatched BulkStart remaining (depth %d)", depth)
	}
}

func TestBulkSyncWriteFailureClearsActiveConnection(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				IsReverse: 0, IngressZone: 1,
			},
		},
	}

	local, peer := net.Pipe()
	peer.Close()

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }
	ss.mu.Lock()
	ss.conn0 = local
	ss.mu.Unlock()

	if err := ss.BulkSync(); err == nil {
		t.Fatal("BulkSync() unexpectedly succeeded on broken connection")
	}
	if ss.getActiveConn() != nil {
		t.Fatal("BulkSync() write failure should clear the active connection")
	}
	if ss.IsConnected() {
		t.Fatal("BulkSync() write failure should mark sync disconnected")
	}
}

func TestBulkEpochMismatchIgnored(t *testing.T) {
	// BulkEnd with mismatched epoch should be ignored (no reconciliation, no callback).
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6}: {IsReverse: 0, IngressZone: 2},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return false }
	ss.SetZoneRGMap(map[uint16]int{2: 2})

	called := false
	ss.OnBulkSyncReceived = func() { called = true }

	// BulkStart with epoch 5
	var startBuf [8]byte
	binary.LittleEndian.PutUint64(startBuf[:], 5)
	ss.handleMessage(nil, syncMsgBulkStart, startBuf[:])

	// BulkEnd with epoch 99 (mismatch)
	var endBuf [8]byte
	binary.LittleEndian.PutUint64(endBuf[:], 99)
	ss.handleMessage(nil, syncMsgBulkEnd, endBuf[:])

	// Callback should NOT have been invoked
	time.Sleep(50 * time.Millisecond)
	if called {
		t.Fatal("OnBulkSyncReceived should not be called on epoch mismatch")
	}

	// Session should NOT be reconciled (deleted)
	if _, ok := dp.v4sessions[dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6}]; !ok {
		t.Fatal("session should not be deleted on epoch mismatch")
	}

	// Now send matching BulkEnd — should trigger callback + reconciliation
	var matchBuf [8]byte
	binary.LittleEndian.PutUint64(matchBuf[:], 5)
	ss.handleMessage(nil, syncMsgBulkEnd, matchBuf[:])

	time.Sleep(50 * time.Millisecond)
	if !called {
		t.Fatal("OnBulkSyncReceived should be called on matching epoch")
	}
}

func TestReconcileUsesSnapshotNotLive(t *testing.T) {
	// When IsPrimaryForRGFn flips between BulkStart and BulkEnd,
	// reconciliation should use the snapshot taken at BulkStart time.
	//
	// Scenario: at BulkStart we're secondary for RG 2 (zone 2 owned by peer).
	// Peer sends bulk with sessionA in zone 2. We also have staleB in zone 2.
	// Between BulkStart and BulkEnd, we become primary for RG 2.
	// With the snapshot, reconciliation still sees zone 2 as peer-owned →
	// staleB gets deleted. Without snapshot, it would skip zone 2 and keep staleB.

	freshKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	staleKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}

	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			freshKey: {IsReverse: 0, IngressZone: 2},
			staleKey: {IsReverse: 0, IngressZone: 2},
		},
	}

	primaryForRG2 := false // starts as secondary for RG 2
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		if rgID == 2 {
			return primaryForRG2
		}
		return rgID == 1
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})

	// BulkStart — snapshot sees us as secondary for RG 2
	ss.handleMessage(nil, syncMsgBulkStart, nil)

	// Peer sends freshKey
	payload := encodeSessionV4Payload(freshKey, dataplane.SessionValue{IsReverse: 0, IngressZone: 2})
	ss.handleMessage(nil, syncMsgSessionV4, payload)

	// FLIP: we become primary for RG 2 mid-bulk
	primaryForRG2 = true

	// BulkEnd — reconciliation should use snapshot (secondary for RG 2)
	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	// freshKey should remain
	if _, ok := dp.v4sessions[freshKey]; !ok {
		t.Fatal("freshKey should not be deleted")
	}
	// staleKey should be deleted (snapshot says zone 2 is peer-owned)
	if _, ok := dp.v4sessions[staleKey]; ok {
		t.Fatal("staleKey should be deleted — snapshot should see zone 2 as peer-owned")
	}
}

// countingWriter wraps a net.Conn and counts sync messages written.
type countingWriter struct {
	net.Conn
	sessionMsgs int
}

func (c *countingWriter) SetDeadline(time.Time) error {
	return nil
}

func (c *countingWriter) SetReadDeadline(time.Time) error {
	return nil
}

func (c *countingWriter) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *countingWriter) Write(b []byte) (int, error) {
	// Count session messages by checking the magic + type in headers.
	if len(b) >= syncHeaderSize && string(b[0:4]) == "BPSY" {
		if b[4] == syncMsgSessionV4 || b[4] == syncMsgSessionV6 {
			c.sessionMsgs++
		}
	}
	return len(b), nil // discard
}

func TestBulkSyncRGFiltering(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			// Forward session in zone 1 (RG 1 — primary) — should sync
			{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 1,
			},
			// Reverse session in zone 1 — should be skipped (reverse)
			{SrcIP: [4]byte{10, 0, 2, 1}, DstIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}: {
				State: dataplane.SessStateEstablished, IsReverse: 1, IngressZone: 1,
			},
			// Forward session in zone 2 (RG 2 — not primary) — should skip
			{SrcIP: [4]byte{10, 0, 3, 1}, DstIP: [4]byte{10, 0, 4, 1}, Protocol: 6, SrcPort: 2000, DstPort: 443}: {
				State: dataplane.SessStateEstablished, IsReverse: 0, IngressZone: 2,
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			// Forward v6 session in zone 1 (RG 1 — primary) — should sync
			{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Protocol: 6}: {
				IsReverse: 0, IngressZone: 1,
			},
			// Reverse v6 session — should be skipped
			{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, Protocol: 6}: {
				IsReverse: 1, IngressZone: 1,
			},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1 // primary for RG 1 only
	}
	ss.SetZoneRGMap(map[uint16]int{
		1: 1, // zone 1 → RG 1
		2: 2, // zone 2 → RG 2
	})

	cw := &countingWriter{}
	ss.mu.Lock()
	ss.conn0 = cw
	ss.mu.Unlock()

	err := ss.BulkSync()
	if err != nil {
		t.Fatalf("BulkSync failed: %v", err)
	}

	// Should only sync 2 sessions: 1 v4 forward in zone 1 + 1 v6 forward in zone 1
	if cw.sessionMsgs != 2 {
		t.Fatalf("expected 2 session messages (1 v4 + 1 v6 in owned RG), got %d", cw.sessionMsgs)
	}
}

func TestBulkSyncSkipsReverseEntries(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}: {
				IsReverse: 0, IngressZone: 1,
			},
			{SrcIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}: {
				IsReverse: 1, IngressZone: 1,
			},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }

	cw := &countingWriter{}
	ss.mu.Lock()
	ss.conn0 = cw
	ss.mu.Unlock()

	err := ss.BulkSync()
	if err != nil {
		t.Fatalf("BulkSync failed: %v", err)
	}

	// Only forward entry should be sent
	if cw.sessionMsgs != 1 {
		t.Fatalf("expected 1 session message (forward only), got %d", cw.sessionMsgs)
	}
}

func TestReconcileStaleSessions(t *testing.T) {
	// Simulate: we're secondary for zone 2 (RG 2 owned by peer).
	// We have 3 sessions in zone 2: sessionA, sessionB, sessionC.
	// Peer sends bulk with only sessionA — sessionB and sessionC are stale.
	staleKeyB := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 2}, DstIP: [4]byte{10, 0, 4, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}
	staleKeyC := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 3}, DstIP: [4]byte{10, 0, 4, 3}, Protocol: 6, SrcPort: 3000, DstPort: 80}
	freshKeyA := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 1}, DstIP: [4]byte{10, 0, 4, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	// Session in zone 1 (locally owned) — should NOT be deleted.
	localKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 5000, DstPort: 22}

	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			freshKeyA: {IsReverse: 0, IngressZone: 2},
			staleKeyB: {IsReverse: 0, IngressZone: 2},
			staleKeyC: {IsReverse: 0, IngressZone: 2},
			localKey:  {IsReverse: 0, IngressZone: 1},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool {
		return rgID == 1 // we're primary for RG 1 (zone 1), peer owns RG 2 (zone 2)
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})

	// Simulate bulk receive: BulkStart → sessionA → BulkEnd.
	ss.handleMessage(nil, syncMsgBulkStart, nil)

	// Send freshKeyA as a session message.
	payload := encodeSessionV4Payload(freshKeyA, dataplane.SessionValue{IsReverse: 0, IngressZone: 2})
	ss.handleMessage(nil, syncMsgSessionV4, payload)

	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	// freshKeyA should remain.
	if _, ok := dp.v4sessions[freshKeyA]; !ok {
		t.Fatal("freshKeyA should not be deleted")
	}

	// staleKeyB and staleKeyC should be deleted.
	if _, ok := dp.v4sessions[staleKeyB]; ok {
		t.Fatal("staleKeyB should be deleted (not in bulk)")
	}
	if _, ok := dp.v4sessions[staleKeyC]; ok {
		t.Fatal("staleKeyC should be deleted (not in bulk)")
	}

	// localKey (zone 1, our RG) should NOT be touched.
	if _, ok := dp.v4sessions[localKey]; !ok {
		t.Fatal("localKey should not be deleted (our RG)")
	}
}

func TestReconcileStaleSessionsV6(t *testing.T) {
	staleKey := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, Protocol: 6, SrcPort: 2000, DstPort: 80}
	freshKey := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}

	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			freshKey: {IsReverse: 0, IngressZone: 2},
			staleKey: {IsReverse: 0, IngressZone: 2},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})

	ss.handleMessage(nil, syncMsgBulkStart, nil)
	payload := encodeSessionV6Payload(freshKey, dataplane.SessionValueV6{IsReverse: 0, IngressZone: 2})
	ss.handleMessage(nil, syncMsgSessionV6, payload)
	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	if _, ok := dp.v6sessions[freshKey]; !ok {
		t.Fatal("freshKey should remain")
	}
	if _, ok := dp.v6sessions[staleKey]; ok {
		t.Fatal("staleKey should be deleted")
	}
}

func TestReconcileStaleSessionsUsesSessionStoreCompanionDeleteV4(t *testing.T) {
	freshKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 1}, DstIP: [4]byte{10, 0, 4, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	staleKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 3, 2}, DstIP: [4]byte{10, 0, 4, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}
	reverseKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 4, 2}, DstIP: [4]byte{10, 0, 3, 2}, Protocol: 6, SrcPort: 443, DstPort: 2000}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			freshKey: {IsReverse: 0, IngressZone: 2},
			staleKey: {
				IsReverse:   0,
				IngressZone: 2,
				ReverseKey:  reverseKey,
				Flags:       dataplane.SessFlagSNAT,
				NATSrcIP:    0x2c0200c0,
				NATSrcPort:  40443,
			},
			reverseKey: {IsReverse: 1, IngressZone: 2},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})

	ss.handleMessage(nil, syncMsgBulkStart, nil)
	ss.handleMessage(nil, syncMsgSessionV4, encodeSessionV4Payload(freshKey, dataplane.SessionValue{IsReverse: 0, IngressZone: 2}))
	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	if _, ok := dp.v4sessions[staleKey]; ok {
		t.Fatal("stale forward session should be deleted")
	}
	if _, ok := dp.v4sessions[reverseKey]; ok {
		t.Fatal("stale reverse session should be deleted")
	}
	wantDNAT := dataplane.DNATKey{Protocol: 6, DstIP: 0x2c0200c0, DstPort: 40443}
	if len(dp.deletedDNATV4) != 1 || dp.deletedDNATV4[0] != wantDNAT {
		t.Fatalf("deleted DNAT = %+v, want [%+v]", dp.deletedDNATV4, wantDNAT)
	}
}

func TestReconcileStaleSessionsUsesSessionStoreCompanionDeleteV6(t *testing.T) {
	freshKey := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 1000, DstPort: 80}
	freshKey.SrcIP[15] = 1
	freshKey.DstIP[15] = 2
	staleKey := dataplane.SessionKeyV6{Protocol: 17, SrcPort: 2000, DstPort: 53}
	staleKey.SrcIP[15] = 3
	staleKey.DstIP[15] = 4
	reverseKey := dataplane.SessionKeyV6{Protocol: 17, SrcPort: 53, DstPort: 2000}
	reverseKey.SrcIP[15] = 4
	reverseKey.DstIP[15] = 3
	natIP := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99}
	dp := &mockSweepDP{
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			freshKey: {IsReverse: 0, IngressZone: 2},
			staleKey: {
				IsReverse:   0,
				IngressZone: 2,
				ReverseKey:  reverseKey,
				Flags:       dataplane.SessFlagSNAT,
				NATSrcIP:    natIP,
				NATSrcPort:  53000,
			},
			reverseKey: {IsReverse: 1, IngressZone: 2},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})

	ss.handleMessage(nil, syncMsgBulkStart, nil)
	ss.handleMessage(nil, syncMsgSessionV6, encodeSessionV6Payload(freshKey, dataplane.SessionValueV6{IsReverse: 0, IngressZone: 2}))
	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	if _, ok := dp.v6sessions[staleKey]; ok {
		t.Fatal("stale forward session should be deleted")
	}
	if _, ok := dp.v6sessions[reverseKey]; ok {
		t.Fatal("stale reverse session should be deleted")
	}
	wantDNAT := dataplane.DNATKeyV6{Protocol: 17, DstIP: natIP, DstPort: 53000}
	if len(dp.deletedDNATV6) != 1 || dp.deletedDNATV6[0] != wantDNAT {
		t.Fatalf("deleted DNATv6 = %+v, want [%+v]", dp.deletedDNATV6, wantDNAT)
	}
}

func TestReconcileStaleSessionsHasNoLocalDNATCleanup(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "sync.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse sync.go: %v", err)
	}
	var reconcile ast.Node
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "reconcileStaleSessions" {
			reconcile = fn.Body
			break
		}
	}
	if reconcile == nil {
		t.Fatal("reconcileStaleSessions not found")
	}
	ast.Inspect(reconcile, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "DeleteDNATEntry", "DeleteDNATEntryV6":
			t.Fatalf("reconcileStaleSessions still owns local %s cleanup; use SessionStore companion delete", sel.Sel.Name)
		}
		return true
	})
}

func TestReconcileNoBulkInProgress(t *testing.T) {
	// If no bulk was in progress, reconciliation should be a no-op.
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6}
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			key: {IsReverse: 0, IngressZone: 2},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return false }
	ss.SetZoneRGMap(map[uint16]int{2: 2})

	// Call BulkEnd WITHOUT BulkStart — reconciliation should not run.
	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	if _, ok := dp.v4sessions[key]; !ok {
		t.Fatal("session should not be deleted when no bulk was in progress")
	}
}

func TestReconcileSkipsEmptyBulk(t *testing.T) {
	peerOwnedKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 9, 1}, Protocol: 6, SrcPort: 1234, DstPort: 80}
	localOwnedKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 9, 2}, Protocol: 6, SrcPort: 2345, DstPort: 443}

	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			peerOwnedKey:  {IsReverse: 0, IngressZone: 2},
			localOwnedKey: {IsReverse: 0, IngressZone: 1},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetZoneRGMap(map[uint16]int{1: 1, 2: 2})

	ss.handleMessage(nil, syncMsgBulkStart, nil)
	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	if _, ok := dp.v4sessions[peerOwnedKey]; !ok {
		t.Fatal("peer-owned session should not be deleted on empty bulk")
	}
	if _, ok := dp.v4sessions[localOwnedKey]; !ok {
		t.Fatal("local-owned session should remain on empty bulk")
	}
}

func TestReconcileSkipsNonEmptyBulkWithoutZoneSnapshot(t *testing.T) {
	freshKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 7, 1}, Protocol: 6, SrcPort: 1111, DstPort: 80}
	stalePeerKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 7, 2}, Protocol: 6, SrcPort: 2222, DstPort: 443}

	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			freshKey:     {IsReverse: 0, IngressZone: 2},
			stalePeerKey: {IsReverse: 0, IngressZone: 2},
		},
	}

	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	// Intentionally do not install any zone->RG mapping. BulkStart will take an
	// empty snapshot, which should suppress stale reconciliation for this bulk.

	ss.handleMessage(nil, syncMsgBulkStart, nil)
	payload := encodeSessionV4Payload(freshKey, dataplane.SessionValue{IsReverse: 0, IngressZone: 2})
	ss.handleMessage(nil, syncMsgSessionV4, payload)
	ss.handleMessage(nil, syncMsgBulkEnd, nil)

	if _, ok := dp.v4sessions[freshKey]; !ok {
		t.Fatal("freshKey should remain")
	}
	if _, ok := dp.v4sessions[stalePeerKey]; !ok {
		t.Fatal("stalePeerKey should remain when zone snapshot is missing")
	}
}

func TestHandleDisconnectStaleConn(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	// Create two pipe connections to simulate conn A and conn B.
	connA1, connA2 := net.Pipe()
	defer connA1.Close()
	defer connA2.Close()
	connB1, connB2 := net.Pipe()
	defer connB1.Close()
	defer connB2.Close()

	// Set conn A as the active connection.
	ss.mu.Lock()
	ss.conn0 = connA1
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	// Replace conn A with conn B (simulates accept/connect race).
	ss.mu.Lock()
	ss.conn0 = connB1
	ss.mu.Unlock()

	// Conn A's goroutine calls handleDisconnect with stale conn A.
	// This should NOT close conn B.
	ss.handleDisconnect(connA1)

	ss.mu.Lock()
	currentConn := ss.conn0
	ss.mu.Unlock()

	if currentConn != connB1 {
		t.Fatal("handleDisconnect(staleConn) should not replace the active connection")
	}
	if !ss.stats.Connected.Load() {
		t.Fatal("handleDisconnect(staleConn) should not mark as disconnected")
	}

	// Now disconnect with the actual conn B — should work.
	ss.handleDisconnect(connB1)

	ss.mu.Lock()
	currentConn = ss.conn0
	ss.mu.Unlock()

	if currentConn != nil {
		t.Fatal("handleDisconnect(activeConn) should clear s.conn0")
	}
	if ss.stats.Connected.Load() {
		t.Fatal("handleDisconnect(activeConn) should mark as disconnected")
	}
}

func TestHandleDisconnectAlreadyNil(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	connA1, connA2 := net.Pipe()
	defer connA1.Close()
	defer connA2.Close()

	// conn is nil, calling handleDisconnect should not panic.
	ss.handleDisconnect(connA1)

	if ss.stats.Connected.Load() {
		t.Fatal("should remain disconnected")
	}
}

func TestSetZoneRGMap(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	// Set map
	m := map[uint16]int{1: 1, 2: 2, 3: 0}
	ss.SetZoneRGMap(m)

	// Verify internal state
	ss.zoneRGMu.RLock()
	if len(ss.zoneRGMap) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(ss.zoneRGMap))
	}
	if ss.zoneRGMap[1] != 1 {
		t.Fatalf("zone 1 should map to RG 1")
	}
	ss.zoneRGMu.RUnlock()

	// Replace map
	ss.SetZoneRGMap(map[uint16]int{5: 3})
	ss.zoneRGMu.RLock()
	if len(ss.zoneRGMap) != 1 {
		t.Fatalf("expected 1 entry after replace, got %d", len(ss.zoneRGMap))
	}
	ss.zoneRGMu.RUnlock()
}

func TestConcurrentSyncWriters(t *testing.T) {
	// Verify that concurrent writers cannot produce corrupted/interleaved messages.
	// 5 goroutines write sessions via sendCh, 5 write control messages via writeMsg.
	// Receiver verifies every message has valid framing (magic + correct length).

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.mu.Lock()
	ss.conn0 = clientConn
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	const writersPerType = 5
	const msgsPerWriter = 50
	totalExpected := writersPerType * msgsPerWriter * 2 // session + control

	// Receiver: read all messages and verify framing.
	type result struct {
		count int
		err   error
	}
	recvDone := make(chan result, 1)
	go func() {
		hdr := make([]byte, syncHeaderSize)
		count := 0
		for count < totalExpected {
			if _, err := io.ReadFull(serverConn, hdr); err != nil {
				recvDone <- result{count, fmt.Errorf("read header #%d: %w", count, err)}
				return
			}
			if string(hdr[0:4]) != "BPSY" {
				recvDone <- result{count, fmt.Errorf("bad magic at msg #%d: %x", count, hdr[0:4])}
				return
			}
			pLen := binary.LittleEndian.Uint32(hdr[8:12])
			if pLen > 1<<20 {
				recvDone <- result{count, fmt.Errorf("unreasonable length at msg #%d: %d", count, pLen)}
				return
			}
			if pLen > 0 {
				payload := make([]byte, pLen)
				if _, err := io.ReadFull(serverConn, payload); err != nil {
					recvDone <- result{count, fmt.Errorf("read payload #%d: %w", count, err)}
					return
				}
			}
			count++
		}
		recvDone <- result{count, nil}
	}()

	// Spawn writers.
	var wg sync.WaitGroup

	// Session writers: pre-encode and push to sendCh.
	for i := 0; i < writersPerType; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := dataplane.SessionKey{Protocol: 6, SrcPort: 1000, DstPort: 80}
			val := dataplane.SessionValue{State: dataplane.SessStateEstablished}
			for j := 0; j < msgsPerWriter; j++ {
				msg := encodeSessionV4(key, val)
				ss.sendCh <- msg
			}
		}()
	}

	// Control writers: write config/failover/fence directly.
	for i := 0; i < writersPerType; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < msgsPerWriter; j++ {
				var err error
				switch id % 3 {
				case 0:
					ss.writeMu.Lock()
					err = writeMsg(clientConn, syncMsgConfig, []byte("test config data"))
					ss.writeMu.Unlock()
				case 1:
					ss.writeMu.Lock()
					err = writeMsg(clientConn, syncMsgFailover, []byte{0})
					ss.writeMu.Unlock()
				case 2:
					ss.writeMu.Lock()
					err = writeMsg(clientConn, syncMsgFence, nil)
					ss.writeMu.Unlock()
				}
				if err != nil {
					t.Errorf("write error: %v", err)
					return
				}
			}
		}(i)
	}

	// Drain sendCh via sendLoop-like logic (read from channel, write under writeMu).
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		sent := 0
		for sent < writersPerType*msgsPerWriter {
			msg := <-ss.sendCh
			ss.writeMu.Lock()
			_, err := clientConn.Write(msg)
			ss.writeMu.Unlock()
			if err != nil {
				t.Errorf("drain write error: %v", err)
				return
			}
			sent++
		}
	}()

	wg.Wait()
	<-drainDone

	select {
	case r := <-recvDone:
		if r.err != nil {
			t.Fatalf("receiver error after %d messages: %v", r.count, r.err)
		}
		if r.count != totalExpected {
			t.Fatalf("expected %d messages, got %d", totalExpected, r.count)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("receiver timed out")
	}
}

func TestDeleteJournalBasic(t *testing.T) {
	// Deletes while disconnected should be journaled and flushed on reconnect.
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	// Not connected — queueMessage will fail.

	key1 := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	key2 := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 2}, Protocol: 6, SrcPort: 2000, DstPort: 443}
	key3v6 := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01}, Protocol: 6, SrcPort: 3000, DstPort: 80}

	ss.QueueDeleteV4(key1)
	ss.QueueDeleteV4(key2)
	ss.QueueDeleteV6(key3v6)

	// Journal should have 3 entries.
	ss.deleteJournalMu.Lock()
	if len(ss.deleteJournal) != 3 {
		t.Fatalf("expected 3 journal entries, got %d", len(ss.deleteJournal))
	}
	ss.deleteJournalMu.Unlock()

	// No sends should have happened.
	if ss.stats.DeletesSent.Load() != 0 {
		t.Fatal("should not count sent when disconnected")
	}

	// Now "connect" and flush.
	ss.stats.Connected.Store(true)
	ss.flushDeleteJournal()

	// All 3 should be flushed to sendCh.
	if ss.stats.DeletesSent.Load() != 3 {
		t.Fatalf("expected 3 deletes sent after flush, got %d", ss.stats.DeletesSent.Load())
	}

	// Journal should be empty.
	ss.deleteJournalMu.Lock()
	if len(ss.deleteJournal) != 0 {
		t.Fatalf("journal should be empty after flush, got %d", len(ss.deleteJournal))
	}
	ss.deleteJournalMu.Unlock()
}

func TestDeleteJournalOverflow(t *testing.T) {
	// When journal is full, oldest entries are evicted and DeletesDropped incremented.
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.deleteJournalCap = 5 // small cap for testing

	// Queue 8 deletes while disconnected — first 3 should be evicted.
	for i := 0; i < 8; i++ {
		key := dataplane.SessionKey{
			SrcIP:    [4]byte{10, 0, 1, byte(i)},
			Protocol: 6,
			SrcPort:  uint16(1000 + i),
			DstPort:  80,
		}
		ss.QueueDeleteV4(key)
	}

	ss.deleteJournalMu.Lock()
	if len(ss.deleteJournal) != 5 {
		t.Fatalf("journal should be capped at 5, got %d", len(ss.deleteJournal))
	}
	ss.deleteJournalMu.Unlock()

	if ss.stats.DeletesDropped.Load() != 3 {
		t.Fatalf("expected 3 dropped deletes, got %d", ss.stats.DeletesDropped.Load())
	}
}

func TestDeleteJournalFlushNoEntries(t *testing.T) {
	// Flushing an empty journal should be a no-op.
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.stats.Connected.Store(true)
	ss.flushDeleteJournal()
	if ss.stats.DeletesSent.Load() != 0 {
		t.Fatal("should not send anything on empty journal")
	}
}

func TestDeleteJournalReconnectConvergence(t *testing.T) {
	// End-to-end: disconnect→deletes→reconnect→verify deletes arrive on peer.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	// Start disconnected.

	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	ss.QueueDeleteV4(key)
	ss.QueueDeleteV4(key) // journal 2 deletes

	// Simulate reconnect: set conn and connected.
	ss.mu.Lock()
	ss.conn0 = clientConn
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	// Flush in background (will write to clientConn via sendCh).
	ss.flushDeleteJournal()

	// Drain sendCh and write to conn.
	go func() {
		for i := 0; i < 2; i++ {
			msg := <-ss.sendCh
			ss.writeMu.Lock()
			writeFull(clientConn, msg)
			ss.writeMu.Unlock()
		}
	}()

	// Read 2 messages from server side.
	hdr := make([]byte, syncHeaderSize)
	for i := 0; i < 2; i++ {
		if _, err := io.ReadFull(serverConn, hdr); err != nil {
			t.Fatalf("read header %d: %v", i, err)
		}
		if string(hdr[0:4]) != "BPSY" {
			t.Fatalf("bad magic at msg %d", i)
		}
		if hdr[4] != syncMsgDeleteV4 {
			t.Fatalf("expected delete msg, got type %d at msg %d", hdr[4], i)
		}
		pLen := binary.LittleEndian.Uint32(hdr[8:12])
		payload := make([]byte, pLen)
		if _, err := io.ReadFull(serverConn, payload); err != nil {
			t.Fatalf("read payload %d: %v", i, err)
		}
	}

	if ss.stats.DeletesSent.Load() != 2 {
		t.Fatalf("expected 2 deletes sent, got %d", ss.stats.DeletesSent.Load())
	}
}

func TestSessionQueueDoesNotJournal(t *testing.T) {
	// Session updates (not deletes) should NOT be journaled — they get replayed by sweep.
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	// Disconnected.

	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{State: 1}
	ss.QueueSessionV4(key, val)

	ss.deleteJournalMu.Lock()
	if len(ss.deleteJournal) != 0 {
		t.Fatal("session updates should not be journaled")
	}
	ss.deleteJournalMu.Unlock()
}

func TestWaitForPeerBarrierRequiresConnection(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	if err := ss.WaitForPeerBarrier(10 * time.Millisecond); err == nil {
		t.Fatal("expected barrier wait to fail while disconnected")
	}
}

func TestWaitForPeerBarrierCompletesOnAck(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	localConn, peerConn := net.Pipe()
	defer localConn.Close()
	defer peerConn.Close()
	ss.mu.Lock()
	ss.conn0 = localConn
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)

	// Start sendLoop so barrier messages queued to sendCh are written to
	// the connection.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ss.sendLoop(ctx)

	done := make(chan error, 1)
	go func() {
		msg := make([]byte, syncHeaderSize+8)
		if _, err := io.ReadFull(peerConn, msg); err != nil {
			done <- fmt.Errorf("read barrier message: %w", err)
			return
		}
		if len(msg) < syncHeaderSize+8 {
			done <- fmt.Errorf("barrier message too short: %d", len(msg))
			return
		}
		if msg[4] != syncMsgBarrier {
			done <- fmt.Errorf("unexpected message type %d", msg[4])
			return
		}
		var ack [24]byte
		copy(ack[:8], msg[syncHeaderSize:])
		binary.LittleEndian.PutUint64(ack[8:16], 12)
		binary.LittleEndian.PutUint64(ack[16:24], 9)
		ss.handleMessage(nil, syncMsgBarrierAck, ack[:])
		done <- nil
	}()

	if err := ss.WaitForPeerBarrier(2 * time.Second); err != nil {
		t.Fatalf("WaitForPeerBarrier returned error: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("barrier helper failed: %v", err)
	}
}

func TestWaitForPeerBarrierPreservesQueuedSessionOrdering(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	localConn, peerConn := net.Pipe()
	defer localConn.Close()
	defer peerConn.Close()
	ss.mu.Lock()
	ss.conn0 = localConn
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 2},
		SrcPort:  1234,
		DstPort:  80,
		Protocol: 6,
	}
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished}
	ss.sendCh <- encodeSessionV4(key, val)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ss.sendLoop(ctx)

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- ss.WaitForPeerBarrier(2 * time.Second)
	}()

	msgType, _ := readSyncMessage(t, peerConn)
	if msgType != syncMsgSessionV4 {
		t.Fatalf("first message type = %d, want %d", msgType, syncMsgSessionV4)
	}

	msgType, payload := readSyncMessage(t, peerConn)
	if msgType != syncMsgBarrier {
		t.Fatalf("second message type = %d, want %d", msgType, syncMsgBarrier)
	}
	var ack [24]byte
	copy(ack[:8], payload[:8])
	binary.LittleEndian.PutUint64(ack[8:16], 1)
	binary.LittleEndian.PutUint64(ack[16:24], 1)
	ss.handleMessage(nil, syncMsgBarrierAck, ack[:])

	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("WaitForPeerBarrier returned error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("WaitForPeerBarrier did not complete")
	}
}

func TestPendingBulkAckTracksNewestOutboundEpoch(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80, Protocol: 6}: {
				IngressZone: 1,
			},
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }
	localConn, peerConn := net.Pipe()
	defer localConn.Close()
	defer peerConn.Close()
	ss.conn0 = localConn
	ss.stats.Connected.Store(true)

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 8192)
		for {
			if _, err := peerConn.Read(buf); err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "closed pipe") {
					readDone <- nil
					return
				}
				readDone <- err
				return
			}
		}
	}()

	if err := ss.BulkSync(); err != nil {
		t.Fatalf("BulkSync() error = %v", err)
	}
	epoch, age, ok := ss.PendingBulkAck()
	if !ok {
		t.Fatal("expected pending bulk ack after BulkSync")
	}
	if epoch != 1 {
		t.Fatalf("pending bulk epoch = %d, want 1", epoch)
	}
	if age < 0 {
		t.Fatalf("pending bulk age = %v, want >= 0", age)
	}
	ss.handleMessage(nil, syncMsgBulkAck, func() []byte {
		var payload [8]byte
		binary.LittleEndian.PutUint64(payload[:], epoch)
		return payload[:]
	}())
	if _, _, ok := ss.PendingBulkAck(); ok {
		t.Fatal("expected pending bulk ack to clear after matching ack")
	}
	peerConn.Close()
	if err := <-readDone; err != nil {
		t.Fatalf("peer drain failed: %v", err)
	}
}

func TestPendingBulkAckClearedOnDisconnect(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	localConn, peerConn := net.Pipe()
	defer peerConn.Close()
	ss.conn0 = localConn
	ss.stats.Connected.Store(true)
	ss.pendingBulkAckEpoch.Store(7)
	ss.pendingBulkAckSince.Store(time.Now().UnixNano())

	ss.handleDisconnect(localConn)

	if _, _, ok := ss.PendingBulkAck(); ok {
		t.Fatal("expected pending bulk ack to clear on disconnect")
	}
}

func TestTransferReadinessReportsPendingBulkAckAndBulkReceive(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.stats.Connected.Store(true)
	ss.pendingBulkAckEpoch.Store(9)
	ss.pendingBulkAckSince.Store(time.Now().Add(-1500 * time.Millisecond).UnixNano())
	ss.bulkMu.Lock()
	ss.bulkInProgress = true
	ss.bulkRecvEpoch = 4
	ss.bulkRecvV4 = map[dataplane.SessionKey]struct{}{
		{}: {},
	}
	ss.bulkRecvV6 = map[dataplane.SessionKeyV6]struct{}{
		{}: {},
	}
	ss.bulkMu.Unlock()

	state := ss.TransferReadiness()
	if !state.Connected {
		t.Fatal("expected connected transfer state")
	}
	if state.PendingBulkAckEpoch != 9 {
		t.Fatalf("pending bulk ack epoch = %d, want 9", state.PendingBulkAckEpoch)
	}
	if state.PendingBulkAckAge <= 0 {
		t.Fatalf("pending bulk ack age = %v, want > 0", state.PendingBulkAckAge)
	}
	if !state.BulkReceiveInProgress {
		t.Fatal("expected bulk receive in progress")
	}
	if state.BulkReceiveEpoch != 4 {
		t.Fatalf("bulk receive epoch = %d, want 4", state.BulkReceiveEpoch)
	}
	if state.BulkReceiveSessions != 2 {
		t.Fatalf("bulk receive sessions = %d, want 2", state.BulkReceiveSessions)
	}
	if state.ReadyForManualFailover() {
		t.Fatal("expected transfer state to block manual failover")
	}
	if got := state.Reason(); !strings.Contains(got, "peer still receiving outbound bulk epoch=9") {
		t.Fatalf("unexpected reason: %q", got)
	}
}

// TestHandleNewConnectionSkipsBulkSyncOnActiveFabricChange verifies that an
// active-fabric flip does NOT trigger a bulk sync (#466). Sessions are already
// synced; incremental sync resumes on the new transport.
func TestHandleNewConnectionSkipsBulkSyncOnActiveFabricChange(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80, Protocol: 6}: {
				IngressZone: 1,
			},
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }
	oldLocal, oldPeer := net.Pipe()
	newLocal, newPeer := net.Pipe()
	defer oldPeer.Close()
	defer newPeer.Close()
	ss.conn1 = oldLocal
	ss.stats.Connected.Store(true)

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 8192)
		for {
			if _, err := newPeer.Read(buf); err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "closed pipe") {
					readDone <- nil
					return
				}
				readDone <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	ss.handleNewConnection(ctx, 0, newLocal)

	// Active fabric changed from 1→0 but this should NOT trigger bulk sync.
	_, _, ok := ss.PendingBulkAck()
	if ok {
		t.Fatal("active fabric change should NOT trigger bulk sync (#466)")
	}

	cancel()
	newLocal.Close()
	oldLocal.Close()
	if err := <-readDone; err != nil {
		t.Fatalf("peer drain failed: %v", err)
	}
}

func TestHandleNewConnectionDoesNotBulkSyncForNonActiveRedundantPath(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80, Protocol: 6}: {
				IngressZone: 1,
			},
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }
	activeLocal, activePeer := net.Pipe()
	redundantLocal, redundantPeer := net.Pipe()
	defer activePeer.Close()
	defer redundantPeer.Close()
	ss.conn0 = activeLocal
	ss.stats.Connected.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	ss.handleNewConnection(ctx, 1, redundantLocal)
	if _, _, ok := ss.PendingBulkAck(); ok {
		t.Fatal("did not expect pending bulk ack when adding non-active redundant connection")
	}

	cancel()
	redundantLocal.Close()
	activeLocal.Close()
}

func TestWaitForIdleCompletesWhenCountersStabilize(t *testing.T) {
	s := NewSessionSync(":0", "127.0.0.1:1", nil)
	s.sendCh = make(chan []byte, 16)
	s.stats.SessionsSent.Store(10)
	s.stats.DeletesSent.Store(2)
	if err := s.WaitForIdle(500*time.Millisecond, 2, 10*time.Millisecond); err != nil {
		t.Fatalf("WaitForIdle() error = %v", err)
	}
}

func TestWaitForIdleTimesOutWhileQueueAdvances(t *testing.T) {
	s := NewSessionSync(":0", "127.0.0.1:1", nil)
	s.sendCh = make(chan []byte, 16)
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		defer close(done)
		var sent uint64
		for i := 0; i < 20; i++ {
			<-ticker.C
			sent++
			s.stats.SessionsSent.Store(sent)
		}
	}()
	err := s.WaitForIdle(60*time.Millisecond, 2, 5*time.Millisecond)
	<-done
	if err == nil {
		t.Fatal("WaitForIdle() unexpectedly succeeded")
	}
}

func TestWaitForPeerBarriersDrainedCompletesAfterAck(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.barrierSeq.Store(2)

	go func() {
		time.Sleep(20 * time.Millisecond)
		ss.barrierAckSeq.Store(2)
	}()

	if err := ss.WaitForPeerBarriersDrained(100 * time.Millisecond); err != nil {
		t.Fatalf("WaitForPeerBarriersDrained returned error: %v", err)
	}
}

func TestWaitForPeerBarriersDrainedTimesOutWhenUnacked(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.barrierSeq.Store(3)
	ss.barrierAckSeq.Store(1)
	ss.barrierWaitMu.Lock()
	ss.barrierWaiters = map[uint64]chan struct{}{
		3: make(chan struct{}),
	}
	ss.barrierWaitMu.Unlock()

	if err := ss.WaitForPeerBarriersDrained(20 * time.Millisecond); err == nil {
		t.Fatal("expected WaitForPeerBarriersDrained to time out")
	}
}

func TestWaitForPeerBarriersDrainedIgnoresTimedOutBarrierSeqWithoutWaiter(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.barrierSeq.Store(3)
	ss.barrierAckSeq.Store(0)
	// Simulate an earlier timeout that removed the waiter but left the sequence
	// counters behind. Retries should be allowed to queue a fresh barrier.
	if err := ss.WaitForPeerBarriersDrained(20 * time.Millisecond); err != nil {
		t.Fatalf("WaitForPeerBarriersDrained() with no active waiters = %v", err)
	}
}

func TestHandleDisconnectClearsBarrierWaitersWithoutResettingBarrierCounters(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)
	ss.barrierSeq.Store(3)
	ss.barrierAckSeq.Store(1)
	waiterCh := make(chan struct{})
	ss.barrierWaitMu.Lock()
	ss.barrierWaiters = map[uint64]chan struct{}{
		2: waiterCh,
	}
	ss.barrierWaitMu.Unlock()

	ss.handleDisconnect(local)

	// barrierSeq must NOT reset — monotonic counter prevents seq
	// collisions between stale goroutines and new barriers (#458).
	if ss.barrierSeq.Load() != 3 {
		t.Fatalf("barrierSeq = %d, want 3 (must not reset)", ss.barrierSeq.Load())
	}
	// barrierAckSeq must remain monotonic too. Resetting it to 0 can cause a
	// just-completed barrier to be misclassified as a disconnect if a waiter
	// checks after handleDisconnect runs.
	if ss.barrierAckSeq.Load() != 1 {
		t.Fatalf("barrierAckSeq = %d, want 1 (must not reset)", ss.barrierAckSeq.Load())
	}
	if err := ss.WaitForPeerBarriersDrained(20 * time.Millisecond); err != nil {
		t.Fatalf("WaitForPeerBarriersDrained() after disconnect = %v", err)
	}
	ss.barrierWaitMu.Lock()
	if len(ss.barrierWaiters) != 0 {
		ss.barrierWaitMu.Unlock()
		t.Fatalf("barrier waiters not cleared: %d", len(ss.barrierWaiters))
	}
	ss.barrierWaitMu.Unlock()

	// Verify the waiter channel was closed so blocked goroutines wake up.
	select {
	case <-waiterCh:
		// ok — channel was closed
	default:
		t.Fatal("waiter channel not closed on disconnect")
	}
}

// TestBarrierSeqNoCollisionAcrossReconnect verifies that a stale
// WaitForPeerBarrier goroutine from connection cycle 1 cannot corrupt
// the barrier waiter map used by connection cycle 2 (#458).
func TestBarrierSeqNoCollisionAcrossReconnect(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)

	// Simulate cycle 1: barrier seq=1 is pending.
	local1, peer1 := net.Pipe()
	defer peer1.Close()
	ss.mu.Lock()
	ss.conn0 = local1
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)

	cycle1Waiter := make(chan struct{})
	ss.barrierWaitMu.Lock()
	ss.barrierWaiters = map[uint64]chan struct{}{1: cycle1Waiter}
	ss.barrierWaitMu.Unlock()
	ss.barrierSeq.Store(1)

	// Disconnect — simulates failback.
	ss.handleDisconnect(local1)

	// Cycle 1 waiter channel must be closed.
	select {
	case <-cycle1Waiter:
	default:
		t.Fatal("cycle 1 waiter not closed on disconnect")
	}

	// barrierSeq must NOT have been reset: the current counter value
	// remains 1, so the next sequence allocated by barrierSeq.Add(1)
	// will be 2, not 1 (which would collide with cycle 1).
	currentSeq := ss.barrierSeq.Load()
	if currentSeq != 1 {
		t.Fatalf("barrierSeq after disconnect = %d, want 1", currentSeq)
	}

	// Reconnect — cycle 2 barrier gets seq=2 (barrierSeq.Add(1)).
	local2, peer2 := net.Pipe()
	defer peer2.Close()
	ss.mu.Lock()
	ss.conn0 = local2
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)

	cycle2Waiter := make(chan struct{})
	seq2 := ss.barrierSeq.Add(1) // seq=2
	ss.barrierWaitMu.Lock()
	ss.barrierWaiters = map[uint64]chan struct{}{seq2: cycle2Waiter}
	ss.barrierWaitMu.Unlock()

	// Verify no collision: seq2 must be 2, not 1.
	if seq2 == 1 {
		t.Fatal("seq collision: cycle 2 reused seq=1 from cycle 1")
	}

	// Simulate ack for seq=2.
	ss.barrierAckSeq.Store(seq2)
	ss.completeBarrierWait(seq2)

	select {
	case <-cycle2Waiter:
		// ok
	default:
		t.Fatal("cycle 2 waiter not completed")
	}
}

// TestWaitForPeerBarrierReturnsErrorOnDisconnect verifies that
// WaitForPeerBarrier returns an error (not nil) when the connection
// drops while waiting for the barrier ack.
func TestWaitForPeerBarrierReturnsErrorOnDisconnect(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer peer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.mu.Lock()
	ss.conn0 = local
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)

	// Start sendLoop so the barrier message can be consumed from sendCh.
	go ss.sendLoop(ctx)

	errCh := make(chan error, 1)
	go func() {
		errCh <- ss.WaitForPeerBarrier(5 * time.Second)
	}()

	// Give WaitForPeerBarrier time to queue the barrier.
	time.Sleep(50 * time.Millisecond)

	// Disconnect — closes the waiter channel.
	ss.handleDisconnect(local)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("WaitForPeerBarrier returned nil after disconnect, want error")
		}
		t.Logf("got expected error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForPeerBarrier did not return after disconnect")
	}
}

func TestHandleMessageFailoverDoesNotBlockReceiveLoop(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	started := make(chan int, 1)
	release := make(chan struct{})
	ss.OnRemoteFailover = func(rgID int) error {
		started <- rgID
		<-release
		return nil
	}

	done := make(chan struct{})
	go func() {
		payload := make([]byte, 9)
		payload[0] = 7
		binary.LittleEndian.PutUint64(payload[1:9], 11)
		ss.handleMessage(nil, syncMsgFailover, payload)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("handleMessage blocked on remote failover callback")
	}

	select {
	case rgID := <-started:
		if rgID != 7 {
			t.Fatalf("unexpected rgID %d", rgID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("remote failover callback did not run")
	}

	close(release)
}

func TestSendFailoverWaitsForAck(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	type failoverResult struct {
		reqID uint64
		err   error
	}
	done := make(chan failoverResult, 1)
	go func() {
		reqID, err := ss.SendFailover(7)
		done <- failoverResult{reqID: reqID, err: err}
	}()

	var hdrBuf [syncHeaderSize]byte
	if _, err := io.ReadFull(peer, hdrBuf[:]); err != nil {
		t.Fatalf("read failover header: %v", err)
	}
	if hdrBuf[4] != syncMsgFailover {
		t.Fatalf("msg type = %d, want %d", hdrBuf[4], syncMsgFailover)
	}
	payloadLen := binary.LittleEndian.Uint32(hdrBuf[8:12])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read failover payload: %v", err)
	}
	if len(payload) != 9 || payload[0] != 7 {
		t.Fatalf("payload = %v, want rg=7 with req_id", payload)
	}
	reqID := binary.LittleEndian.Uint64(payload[1:9])

	ack := make([]byte, 10)
	ack[0] = 7
	ack[1] = failoverAckApplied
	binary.LittleEndian.PutUint64(ack[2:10], reqID)
	ss.handleMessage(local, syncMsgFailoverAck, ack)

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("SendFailover() error = %v", result.err)
		}
		if result.reqID != reqID {
			t.Fatalf("SendFailover() reqID = %d, want %d", result.reqID, reqID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendFailover did not complete after ack")
	}
}

func TestSendFailoverBatchWaitsForAck(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	type failoverResult struct {
		reqID uint64
		err   error
	}
	done := make(chan failoverResult, 1)
	go func() {
		reqID, err := ss.SendFailoverBatch([]int{2, 1})
		done <- failoverResult{reqID: reqID, err: err}
	}()

	var hdrBuf [syncHeaderSize]byte
	if _, err := io.ReadFull(peer, hdrBuf[:]); err != nil {
		t.Fatalf("read batch failover header: %v", err)
	}
	if hdrBuf[4] != syncMsgFailoverBatch {
		t.Fatalf("msg type = %d, want %d", hdrBuf[4], syncMsgFailoverBatch)
	}
	payloadLen := binary.LittleEndian.Uint32(hdrBuf[8:12])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read batch failover payload: %v", err)
	}
	rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
	if err != nil {
		t.Fatalf("decodeFailoverBatchRequestPayload() error = %v", err)
	}
	if len(rgIDs) != 2 || rgIDs[0] != 1 || rgIDs[1] != 2 {
		t.Fatalf("rgIDs = %v, want [1 2]", rgIDs)
	}

	ss.handleMessage(local, syncMsgFailoverBatchAck, encodeFailoverBatchAckPayload(rgIDs, failoverAckApplied, reqID, ""))

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("SendFailoverBatch() error = %v", result.err)
		}
		if result.reqID != reqID {
			t.Fatalf("SendFailoverBatch() reqID = %d, want %d", result.reqID, reqID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendFailoverBatch did not complete after ack")
	}
}

func TestSendFailoverPropagatesPeerRejection(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := ss.SendFailover(3)
		done <- err
	}()

	var hdrBuf [syncHeaderSize]byte
	if _, err := io.ReadFull(peer, hdrBuf[:]); err != nil {
		t.Fatalf("read failover header: %v", err)
	}
	payloadLen := binary.LittleEndian.Uint32(hdrBuf[8:12])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read failover payload: %v", err)
	}
	if len(payload) != 9 || payload[0] != 3 {
		t.Fatalf("payload = %v, want rg=3 with req_id", payload)
	}
	reqID := binary.LittleEndian.Uint64(payload[1:9])

	reason := "remote failover rejected: redundancy group 3"
	ack := make([]byte, 10+len(reason))
	ack[0] = 3
	ack[1] = failoverAckRejected
	binary.LittleEndian.PutUint64(ack[2:10], reqID)
	copy(ack[10:], reason)
	ss.handleMessage(local, syncMsgFailoverAck, ack)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected SendFailover() error")
		}
		if !strings.Contains(err.Error(), reason) {
			t.Fatalf("SendFailover() error = %v, want contains %q", err, reason)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendFailover did not complete after rejection")
	}
}

func TestSendFailoverDisconnectReleasesWaiter(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := ss.SendFailover(4)
		done <- err
	}()

	var hdrBuf [syncHeaderSize]byte
	if _, err := io.ReadFull(peer, hdrBuf[:]); err != nil {
		t.Fatalf("read failover header: %v", err)
	}
	payloadLen := binary.LittleEndian.Uint32(hdrBuf[8:12])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read failover payload: %v", err)
	}
	if len(payload) != 9 || payload[0] != 4 {
		t.Fatalf("payload = %v, want rg=4 with req_id", payload)
	}
	go ss.handleDisconnect(local)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected SendFailover() disconnect error")
		}
		if !strings.Contains(err.Error(), "peer disconnected") && !strings.Contains(err.Error(), "aborted") {
			t.Fatalf("SendFailover() error = %v, want disconnect-style error", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendFailover did not complete after disconnect")
	}
}

func TestSendFailoverRejectsOutOfRangeRGID(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	if _, err := ss.SendFailover(256); err == nil {
		t.Fatal("expected out-of-range RG error")
	}
}

func TestSendFailoverIgnoresStaleAckForEarlierRequest(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	done1 := make(chan error, 1)
	go func() {
		_, err := ss.SendFailover(9)
		done1 <- err
	}()

	var hdrBuf [syncHeaderSize]byte
	if _, err := io.ReadFull(peer, hdrBuf[:]); err != nil {
		t.Fatalf("read first failover header: %v", err)
	}
	payloadLen := binary.LittleEndian.Uint32(hdrBuf[8:12])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read first failover payload: %v", err)
	}
	firstReqID := binary.LittleEndian.Uint64(payload[1:9])

	ss.failoverWaitMu.Lock()
	delete(ss.failoverWaiters, 9)
	ss.failoverWaitMu.Unlock()

	done2 := make(chan error, 1)
	go func() {
		_, err := ss.SendFailover(9)
		done2 <- err
	}()

	if _, err := io.ReadFull(peer, hdrBuf[:]); err != nil {
		t.Fatalf("read second failover header: %v", err)
	}
	payloadLen = binary.LittleEndian.Uint32(hdrBuf[8:12])
	payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read second failover payload: %v", err)
	}
	secondReqID := binary.LittleEndian.Uint64(payload[1:9])
	if secondReqID == firstReqID {
		t.Fatalf("second reqID = %d, want different from first reqID %d", secondReqID, firstReqID)
	}

	staleAck := make([]byte, 10)
	staleAck[0] = 9
	staleAck[1] = failoverAckApplied
	binary.LittleEndian.PutUint64(staleAck[2:10], firstReqID)
	ss.handleMessage(local, syncMsgFailoverAck, staleAck)

	select {
	case err := <-done2:
		t.Fatalf("second SendFailover() completed early from stale ack: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	freshAck := make([]byte, 10)
	freshAck[0] = 9
	freshAck[1] = failoverAckApplied
	binary.LittleEndian.PutUint64(freshAck[2:10], secondReqID)
	ss.handleMessage(local, syncMsgFailoverAck, freshAck)

	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("second SendFailover() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("second SendFailover did not complete after fresh ack")
	}
}

func TestSendFailoverCommitWaitsForAck(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- ss.SendFailoverCommit(7, 41)
	}()

	var hdrBuf [syncHeaderSize]byte
	if _, err := io.ReadFull(peer, hdrBuf[:]); err != nil {
		t.Fatalf("read failover commit header: %v", err)
	}
	if hdrBuf[4] != syncMsgFailoverCommit {
		t.Fatalf("msg type = %d, want %d", hdrBuf[4], syncMsgFailoverCommit)
	}
	payloadLen := binary.LittleEndian.Uint32(hdrBuf[8:12])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read failover commit payload: %v", err)
	}
	if len(payload) != 9 || payload[0] != 7 {
		t.Fatalf("payload = %v, want rg=7 with req_id", payload)
	}
	if gotReqID := binary.LittleEndian.Uint64(payload[1:9]); gotReqID != 41 {
		t.Fatalf("reqID = %d, want 41", gotReqID)
	}

	ack := make([]byte, 10)
	ack[0] = 7
	ack[1] = failoverAckApplied
	binary.LittleEndian.PutUint64(ack[2:10], 41)
	ss.handleMessage(local, syncMsgFailoverCommitAck, ack)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendFailoverCommit() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendFailoverCommit did not complete after ack")
	}
}

func TestHandleRemoteFailoverCommitInvokesCallback(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	done := make(chan int, 1)
	ss.OnRemoteFailoverCommit = func(rgID int) error {
		done <- rgID
		return nil
	}

	payload := make([]byte, 9)
	payload[0] = 5
	binary.LittleEndian.PutUint64(payload[1:9], 99)
	ss.handleMessage(nil, syncMsgFailoverCommit, payload)

	select {
	case rgID := <-done:
		if rgID != 5 {
			t.Fatalf("callback rgID = %d, want 5", rgID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("remote failover commit callback did not run")
	}
}

func TestHandleRemoteFailoverBatchInvokesCallback(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	done := make(chan []int, 1)
	ss.OnRemoteFailoverBatch = func(rgIDs []int) error {
		done <- append([]int(nil), rgIDs...)
		return nil
	}

	ss.handleMessage(nil, syncMsgFailoverBatch, encodeFailoverBatchRequestPayload([]int{2, 1}, 99))

	select {
	case rgIDs := <-done:
		if len(rgIDs) != 2 || rgIDs[0] != 1 || rgIDs[1] != 2 {
			t.Fatalf("callback rgIDs = %v, want [1 2]", rgIDs)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("remote batch failover callback did not run")
	}
}

func TestSendFailoverCommitBatchWaitsForAck(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- ss.SendFailoverCommitBatch([]int{2, 1}, 41)
	}()

	var hdrBuf [syncHeaderSize]byte
	if _, err := io.ReadFull(peer, hdrBuf[:]); err != nil {
		t.Fatalf("read batch failover commit header: %v", err)
	}
	if hdrBuf[4] != syncMsgFailoverBatchCommit {
		t.Fatalf("msg type = %d, want %d", hdrBuf[4], syncMsgFailoverBatchCommit)
	}
	payloadLen := binary.LittleEndian.Uint32(hdrBuf[8:12])
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatalf("read batch failover commit payload: %v", err)
	}
	rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
	if err != nil {
		t.Fatalf("decodeFailoverBatchRequestPayload() error = %v", err)
	}
	if reqID != 41 {
		t.Fatalf("reqID = %d, want 41", reqID)
	}

	ss.handleMessage(local, syncMsgFailoverBatchCommitAck, encodeFailoverBatchAckPayload(rgIDs, failoverAckApplied, reqID, ""))

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendFailoverCommitBatch() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendFailoverCommitBatch did not complete after ack")
	}
}

func TestSendLoopRetainsQueuedMessageUntilConnectionAvailable(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.stats.Connected.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ss.sendLoop(ctx)

	done := make(chan error, 1)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	go func() {
		msg := make([]byte, syncHeaderSize+8)
		if _, err := io.ReadFull(peer, msg); err != nil {
			done <- fmt.Errorf("read queued barrier: %w", err)
			return
		}
		if msg[4] != syncMsgBarrier {
			done <- fmt.Errorf("unexpected queued type %d", msg[4])
			return
		}
		done <- nil
	}()

	var payload [8]byte
	binary.LittleEndian.PutUint64(payload[:], 42)
	msg := encodeRawMessage(syncMsgBarrier, payload[:])

	ss.sendCh <- msg
	time.Sleep(20 * time.Millisecond)

	ss.mu.Lock()
	ss.conn0 = local
	ss.mu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for queued barrier delivery")
	}
}

type mockSweepProfilerDP struct {
	active time.Duration
	idle   time.Duration
}

func (m mockSweepProfilerDP) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	return true, m.active, m.idle
}

func TestSweepIntervalsDefault(t *testing.T) {
	active, idle := sweepIntervalsForDataPlane(nil)
	if active != time.Second {
		t.Fatalf("active interval = %v, want %v", active, time.Second)
	}
	if idle != 10*time.Second {
		t.Fatalf("idle interval = %v, want %v", idle, 10*time.Second)
	}
}

func TestSweepIntervalsDataplaneOverride(t *testing.T) {
	active, idle := sweepIntervalsForDataPlane(mockSweepProfilerDP{
		active: 15 * time.Second,
		idle:   60 * time.Second,
	})
	if active != 15*time.Second {
		t.Fatalf("active interval = %v, want %v", active, 15*time.Second)
	}
	if idle != 60*time.Second {
		t.Fatalf("idle interval = %v, want %v", idle, 60*time.Second)
	}
}

func TestSweepIntervalsClampIdleToActive(t *testing.T) {
	active, idle := sweepIntervalsForDataPlane(mockSweepProfilerDP{
		active: 20 * time.Second,
		idle:   5 * time.Second,
	})
	if active != 20*time.Second {
		t.Fatalf("active interval = %v, want %v", active, 20*time.Second)
	}
	if idle != 20*time.Second {
		t.Fatalf("idle interval = %v, want %v", idle, 20*time.Second)
	}
}

// TestHandleNewConnectionColdStartTriggersBulkSync verifies that the first
// connection on a fresh daemon start triggers a bulk sync (#466).
func TestHandleNewConnectionColdStartTriggersBulkSync(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80, Protocol: 6}: {
				IngressZone: 1,
			},
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }

	if ss.BulkEverCompleted() {
		t.Fatal("fresh SessionSync should not be bulk-ever-completed")
	}

	local, peer := net.Pipe()
	defer peer.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 8192)
		for {
			if _, err := peer.Read(buf); err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "closed pipe") {
					readDone <- nil
					return
				}
				readDone <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	ss.handleNewConnection(ctx, 0, local)

	// Cold start: bulkEverCompleted is false, so bulk should fire.
	epoch, _, ok := ss.PendingBulkAck()
	if !ok {
		t.Fatal("expected bulk sync on cold start connection")
	}
	if epoch != 1 {
		t.Fatalf("pending bulk epoch = %d, want 1", epoch)
	}

	cancel()
	local.Close()
	if err := <-readDone; err != nil {
		t.Fatalf("peer drain failed: %v", err)
	}
}

// TestHandleNewConnectionReconnectSkipsBulkSync verifies that a reconnect
// after a prior bulk exchange does NOT trigger bulk sync (#466).
func TestHandleNewConnectionReconnectSkipsBulkSync(t *testing.T) {
	dp := &mockSweepDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: 1234, DstPort: 80, Protocol: 6}: {
				IngressZone: 1,
			},
		},
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }

	// Simulate a prior bulk exchange completing.
	ss.bulkEverCompleted.Store(true)

	local, peer := net.Pipe()
	defer peer.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 8192)
		for {
			if _, err := peer.Read(buf); err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "closed pipe") {
					readDone <- nil
					return
				}
				readDone <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	// wasDisconnected=true (no existing connections), but bulkEverCompleted
	// is true so bulk should be skipped.
	ss.handleNewConnection(ctx, 0, local)

	_, _, ok := ss.PendingBulkAck()
	if ok {
		t.Fatal("reconnect after prior bulk exchange should NOT trigger bulk sync (#466)")
	}

	cancel()
	local.Close()
	if err := <-readDone; err != nil {
		t.Fatalf("peer drain failed: %v", err)
	}
}

// TestBulkEverCompletedDefaultsFalse verifies that a fresh SessionSync
// has bulkEverCompleted=false.
func TestBulkEverCompletedDefaultsFalse(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	if ss.BulkEverCompleted() {
		t.Fatal("bulkEverCompleted should start false on a new SessionSync")
	}
}

// TestBulkEverCompletedSurvivesDisconnect verifies that bulkEverCompleted
// persists across disconnect/reconnect cycles.
func TestBulkEverCompletedSurvivesDisconnect(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	ss.bulkEverCompleted.Store(true)

	// Simulate a disconnect.
	local, peer := net.Pipe()
	defer peer.Close()
	ss.conn0 = local
	ss.stats.Connected.Store(true)
	ss.handleDisconnect(local)

	if !ss.BulkEverCompleted() {
		t.Fatal("bulkEverCompleted should survive disconnect")
	}
}

func TestReceiveLoopClosesSilentConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverConnCh := make(chan net.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case err := <-serverErrCh:
		t.Fatalf("accept: %v", err)
	case serverConn = <-serverConnCh:
	}
	defer serverConn.Close()

	heartbeatAcked := make(chan struct{}, 1)
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		for {
			var hdr [syncHeaderSize]byte
			if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				serverDone <- err
				return
			}
			if _, err := io.ReadFull(serverConn, hdr[:]); err != nil {
				serverDone <- err
				return
			}
			if string(hdr[0:4]) != "BPSY" {
				serverDone <- fmt.Errorf("bad sync magic: %q", hdr[0:4])
				return
			}
			payloadLen := binary.LittleEndian.Uint32(hdr[8:12])
			if payloadLen > 0 {
				payload := make([]byte, payloadLen)
				if _, err := io.ReadFull(serverConn, payload); err != nil {
					serverDone <- err
					return
				}
			}
			if hdr[4] != syncMsgHeartbeat {
				continue
			}
			if err := writeMsg(serverConn, syncMsgHeartbeatAck, nil); err != nil {
				serverDone <- err
				return
			}
			heartbeatAcked <- struct{}{}
			<-time.After(time.Second)
			return
		}
	}()

	ss := NewSessionSync(":0", ln.Addr().String(), nil)
	ss.bulkEverCompleted.Store(true)
	ss.readDeadline = 100 * time.Millisecond
	ss.peerSilenceLimit = 300 * time.Millisecond

	disconnected := make(chan struct{}, 1)
	ss.OnPeerDisconnected = func() {
		select {
		case disconnected <- struct{}{}:
		default:
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.handleNewConnection(ctx, 0, clientConn)

	select {
	case <-heartbeatAcked:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for heartbeat ack exchange")
	}

	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for silent connection disconnect")
	}

	if ss.IsConnected() {
		t.Fatal("expected sync to be marked disconnected after silent timeout")
	}
	if ss.PeerHealthy() {
		t.Fatal("expected peer health to be false after silent timeout")
	}
	if got := ss.getActiveConn(); got != nil {
		t.Fatalf("expected active conn to be cleared, got %v", got)
	}
	if err := <-serverDone; err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
		t.Fatalf("server loop failed: %v", err)
	}
}

func TestReceiveLoopKeepsConnectionAliveWithoutHeartbeatAckSupport(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverConnCh := make(chan net.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case err := <-serverErrCh:
		t.Fatalf("accept: %v", err)
	case serverConn = <-serverConnCh:
	}
	defer serverConn.Close()

	heartbeatSeen := make(chan struct{}, 1)
	serverDone := make(chan error, 1)
	go func() {
		for {
			var hdr [syncHeaderSize]byte
			if err := serverConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				serverDone <- err
				return
			}
			if _, err := io.ReadFull(serverConn, hdr[:]); err != nil {
				serverDone <- err
				return
			}
			if string(hdr[0:4]) != "BPSY" {
				serverDone <- fmt.Errorf("bad sync magic: %q", hdr[0:4])
				return
			}
			payloadLen := binary.LittleEndian.Uint32(hdr[8:12])
			if payloadLen > 0 {
				payload := make([]byte, payloadLen)
				if _, err := io.ReadFull(serverConn, payload); err != nil {
					serverDone <- err
					return
				}
			}
			if hdr[4] == syncMsgHeartbeat {
				select {
				case heartbeatSeen <- struct{}{}:
				default:
				}
			}
		}
	}()

	ss := NewSessionSync(":0", ln.Addr().String(), nil)
	ss.bulkEverCompleted.Store(true)
	ss.readDeadline = 100 * time.Millisecond
	ss.peerSilenceLimit = 300 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.handleNewConnection(ctx, 0, clientConn)

	select {
	case <-heartbeatSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for legacy heartbeat request")
	}

	time.Sleep(350 * time.Millisecond)

	if !ss.IsConnected() {
		t.Fatal("expected legacy peer without heartbeat ack to remain connected")
	}
	if !ss.PeerHealthy() {
		t.Fatal("expected legacy peer without heartbeat ack to remain healthy")
	}
	if got := ss.getActiveConn(); got == nil {
		t.Fatal("expected active conn to remain installed")
	}

	cancel()
	serverConn.Close()
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") && !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("server loop failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server loop to exit")
	}
}

func TestReceiveLoopDisconnectsSilentConnectionAfterAckCapableReconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverConnCh := make(chan net.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case err := <-serverErrCh:
		t.Fatalf("accept: %v", err)
	case serverConn = <-serverConnCh:
	}
	defer serverConn.Close()

	heartbeatSeen := make(chan struct{}, 1)
	serverDone := make(chan error, 1)
	go func() {
		for {
			var hdr [syncHeaderSize]byte
			if err := serverConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				serverDone <- err
				return
			}
			if _, err := io.ReadFull(serverConn, hdr[:]); err != nil {
				serverDone <- err
				return
			}
			if string(hdr[0:4]) != "BPSY" {
				serverDone <- fmt.Errorf("bad sync magic: %q", hdr[0:4])
				return
			}
			payloadLen := binary.LittleEndian.Uint32(hdr[8:12])
			if payloadLen > 0 {
				payload := make([]byte, payloadLen)
				if _, err := io.ReadFull(serverConn, payload); err != nil {
					serverDone <- err
					return
				}
			}
			if hdr[4] == syncMsgHeartbeat {
				select {
				case heartbeatSeen <- struct{}{}:
				default:
				}
			}
		}
	}()

	ss := NewSessionSync(":0", ln.Addr().String(), nil)
	ss.bulkEverCompleted.Store(true)
	ss.readDeadline = 100 * time.Millisecond
	ss.peerSilenceLimit = 300 * time.Millisecond
	ss.peerHeartbeatAckEver.Store(true)

	disconnected := make(chan struct{}, 1)
	ss.OnPeerDisconnected = func() {
		select {
		case disconnected <- struct{}{}:
		default:
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.handleNewConnection(ctx, 0, clientConn)

	select {
	case <-heartbeatSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for heartbeat request")
	}

	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for silent reconnect disconnect")
	}

	if ss.IsConnected() {
		t.Fatal("expected ack-capable silent reconnect to be marked disconnected")
	}
	if ss.PeerHealthy() {
		t.Fatal("expected peer health to be false after silent reconnect disconnect")
	}
	if got := ss.getActiveConn(); got != nil {
		t.Fatalf("expected active conn to be cleared, got %v", got)
	}
	if err := <-serverDone; err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("server loop failed: %v", err)
	}
}

func TestReceiveLoopKeepsConnectionAliveWithHeartbeatAck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverConnCh := make(chan net.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case err := <-serverErrCh:
		t.Fatalf("accept: %v", err)
	case serverConn = <-serverConnCh:
	}
	defer serverConn.Close()

	heartbeatSeen := make(chan struct{}, 1)
	serverDone := make(chan error, 1)
	go func() {
		for {
			var hdr [syncHeaderSize]byte
			if err := serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				serverDone <- err
				return
			}
			if _, err := io.ReadFull(serverConn, hdr[:]); err != nil {
				serverDone <- err
				return
			}
			if string(hdr[0:4]) != "BPSY" {
				serverDone <- fmt.Errorf("bad sync magic: %q", hdr[0:4])
				return
			}
			msgType := hdr[4]
			payloadLen := binary.LittleEndian.Uint32(hdr[8:12])
			if payloadLen > 0 {
				payload := make([]byte, payloadLen)
				if _, err := io.ReadFull(serverConn, payload); err != nil {
					serverDone <- err
					return
				}
			}
			if msgType == syncMsgHeartbeat {
				select {
				case heartbeatSeen <- struct{}{}:
				default:
				}
				if err := writeMsg(serverConn, syncMsgHeartbeatAck, nil); err != nil {
					serverDone <- err
					return
				}
			}
		}
	}()

	ss := NewSessionSync(":0", ln.Addr().String(), nil)
	ss.bulkEverCompleted.Store(true)
	ss.readDeadline = 100 * time.Millisecond
	ss.peerSilenceLimit = 300 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.handleNewConnection(ctx, 0, clientConn)

	select {
	case <-heartbeatSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for heartbeat request")
	}

	time.Sleep(100 * time.Millisecond)

	if !ss.IsConnected() {
		t.Fatal("expected heartbeat ack to keep sync connected")
	}
	if !ss.PeerHealthy() {
		t.Fatal("expected heartbeat ack to keep peer healthy")
	}
	if got := ss.getActiveConn(); got == nil {
		t.Fatal("expected active conn to remain installed")
	}

	cancel()
	serverConn.Close()
	if err := <-serverDone; err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("server loop failed: %v", err)
	}
}
