package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type fixedEventStreamProvider struct {
	es *dpuserspace.EventStream
}

const maxEventFramePayloadForWiringTest = 1 << 20

func (p fixedEventStreamProvider) EventStream() *dpuserspace.EventStream { return p.es }

// eventStreamCellBackend is a publishable RuntimeDataPlane that also
// implements userspaceEventStreamProvider, so the wiring loop can resolve
// it out of the daemon's #2114 cell (r6-F4).
type eventStreamCellBackend struct {
	*dataplane.Manager
	es *dpuserspace.EventStream
}

func (b *eventStreamCellBackend) EventStream() *dpuserspace.EventStream { return b.es }

// buildSessionOpenFrameV4PayloadForWiringTest builds a v4 SessionOpen payload
// in the #2467 widened wire layout consumed by
// pkg/dataplane/userspace.decodeSessionEvent:
//
//	[0]     AddrFamily (4)
//	[1]     Protocol
//	[2:4]   SrcPort        [4:6]   DstPort
//	[6:8]   NATSrcPort     [8:10]  NATDstPort
//	[10:14] OwnerRGID (int32 LE)      — #2467: widened from int16
//	[14:18] EgressIfindex (int32 LE)  — #2467: widened from int16
//	[18:22] TXIfindex (int32 LE)      — #2467: widened from int16
//	[22:24] TunnelEndpointID  [24:26] TXVLANID
//	[26] Flags [27:29] IngressZone u16 [29:31] EgressZone u16 [31] Disposition
//	[32..]  src/dst/nat_src/nat_dst IPs (4 bytes each, v4)
//	[N..]   NeighborMAC(6) SrcMAC(6) NextHop(4)
//
// Total v4 size: 32 + 4*4 + 6 + 6 + 4 = 64 bytes (#3075: zone fields widened
// u8->u16, +2). The three identity fields are seeded with 40000 (> int16 max
// 32767) so the full daemon wire+ack path round-trips a high ifindex per the
// #2467 intent — a revert to the old 24-byte/int16 layout makes this payload
// undersized (decodeSessionEvent rejects it, no ACK is sent, the test times
// out).
func buildSessionOpenFrameV4PayloadForWiringTest() []byte {
	buf := make([]byte, 64)
	buf[0] = 4
	buf[1] = 6
	binary.LittleEndian.PutUint16(buf[2:4], 12345)
	binary.LittleEndian.PutUint16(buf[4:6], 443)
	binary.LittleEndian.PutUint32(buf[10:14], 40000) // OwnerRGID (>int16)
	binary.LittleEndian.PutUint32(buf[14:18], 40001) // EgressIfindex
	binary.LittleEndian.PutUint32(buf[18:22], 40002) // TXIfindex
	binary.LittleEndian.PutUint16(buf[27:29], 1)     // IngressZone u16 (#3075)
	binary.LittleEndian.PutUint16(buf[29:31], 2)     // EgressZone u16 (#3075)
	copy(buf[32:36], []byte{10, 0, 1, 2})            // SrcIP
	copy(buf[36:40], []byte{172, 16, 0, 1})          // DstIP
	return buf
}

func writeEventFrameForWiringTest(t *testing.T, conn net.Conn, typ uint8, seq uint64, payload []byte) {
	t.Helper()
	var hdr [dpuserspace.EventFrameHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	hdr[4] = typ
	binary.LittleEndian.PutUint64(hdr[8:16], seq)
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatalf("write frame header: %v", err)
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write frame payload: %v", err)
		}
	}
}

// wiringTestDeadline returns a generous absolute deadline for the event-stream
// wiring poll loops (socket connect, then the per-seq ACK wait). Those loops
// already gate on the actual completion event — a successful connect, then an
// ACK frame with seq >= want — so this cap is only a backstop against a genuine
// hang, NOT the mechanism that decides success. It is deliberately large so it
// never fires from mere goroutine-scheduling latency under concurrent
// build/test load.
//
// #6038: the previous fixed 2s cap left only ~1.8s of headroom over the ~0.2s
// happy path (each ACK is flushed by the eventstream ackLoop's 100ms ticker, so
// the two ACKs cost ~200ms). On a loaded box the ackLoop / acceptLoop / readLoop
// goroutines starve, the flush slips past 2s, and the loop tripped a spurious
// 2.01s timeout — non-monotonic across commits, the signature of a load-racing
// deadline rather than a product regression. Gating on the actual ACK with a
// generous cap removes the wall-clock race without weakening any assertion.
//
// When `go test -timeout` is in effect (the default is 10m) the cap tracks that
// deadline less a small margin, so a real hang fails HERE with a precise message
// just before the whole test binary is killed; with `-timeout 0` it falls back
// to a fixed generous window.
func wiringTestDeadline(t *testing.T) time.Time {
	t.Helper()
	const (
		fallback = 30 * time.Second
		margin   = 5 * time.Second
	)
	if d, ok := t.Deadline(); ok {
		if capped := d.Add(-margin); capped.After(time.Now()) {
			return capped
		}
	}
	return time.Now().Add(fallback)
}

func waitForAckSeqForWiringTest(t *testing.T, conn net.Conn, want uint64) {
	t.Helper()
	deadline := wiringTestDeadline(t)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		var hdr [dpuserspace.EventFrameHeaderSize]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read ack frame: %v", err)
		}
		payloadLen := binary.LittleEndian.Uint32(hdr[0:4])
		typ := hdr[4]
		seq := binary.LittleEndian.Uint64(hdr[8:16])
		if payloadLen > maxEventFramePayloadForWiringTest {
			t.Fatalf("unexpected frame payload length: %d", payloadLen)
		}
		if payloadLen > 0 {
			// Ack/control frames in this helper are header-only; drain any payload
			// to keep stream framing aligned for subsequent reads.
			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(conn, payload); err != nil {
				t.Fatalf("read frame payload: %v", err)
			}
		}
		if typ == dpuserspace.EventTypeAck && seq >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for ack seq >= %d", want)
		}
	}
}

type fakeUserspaceDeltaDrainer struct {
	batches [][]dpuserspace.SessionDeltaInfo
	calls   int
}

func (f *fakeUserspaceDeltaDrainer) DrainSessionDeltas(max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	f.calls++
	if len(f.batches) == 0 {
		return nil, dpuserspace.ProcessStatus{}, nil
	}
	batch := f.batches[0]
	f.batches = f.batches[1:]
	return batch, dpuserspace.ProcessStatus{}, nil
}

type fakeUserspaceSessionExporter struct {
	deltas []dpuserspace.SessionDeltaInfo
	calls  int
}

func (f *fakeUserspaceSessionExporter) ExportOwnerRGSessionsPaged(rgIDs []int) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error) {
	f.calls++
	return append([]dpuserspace.SessionDeltaInfo(nil), f.deltas...), dpuserspace.ProcessStatus{}, nil
}

// TestUserspaceSessionFromDeltaCarriesRTFlowSessionID5212 verifies the delta ->
// SessionValue conversion stamps the originating node's stable RT_FLOW session
// id (delta.RTFlowSessionID) onto SessionValue{,V6}.RTFlowSessionID (distinct
// from the BPF-ABI SessionID) so it rides the cluster sync wire and the peer
// adopts it. Reverting the stamp leaves it 0 and this fails RED.
func TestUserspaceSessionFromDeltaCarriesRTFlowSessionID5212(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	wantID := uint64(7)<<48 | 0x1234_5678

	deltaV4 := dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: 2, Protocol: 6,
		SrcIP: "10.0.61.102", DstIP: "172.16.80.200", SrcPort: 12345, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", EgressIfindex: 12,
		RTFlowSessionID: wantID,
	}
	_, valV4, ok := userspaceSessionFromDeltaV4(deltaV4, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	if valV4.RTFlowSessionID != wantID {
		t.Fatalf("v4 RTFlowSessionID = %#x, want %#x", valV4.RTFlowSessionID, wantID)
	}
	// #6666 REVERSED THIS ASSERTION, and the reversal is the decision rather
	// than a concession. It used to require the BPF-ABI SessionID be DISTINCT
	// from the cross-node id -- which is exactly the divergence that made the
	// displayed id flip between the control plane's value and the helper's, and
	// made #5213's "identical to the id RT_FLOW emits" promise false for every
	// peer-synced session. The mirror now ADOPTS the peer's id when it sent one.
	if valV4.SessionID != wantID {
		t.Fatalf("v4 SessionID = %#x, want the ADOPTED cross-node id %#x — the session views "+
			"and RT_FLOW must render one id for one session (#6666)", valV4.SessionID, wantID)
	}

	deltaV6 := dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: 10, Protocol: 6,
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 12345, DstPort: 5201,
		IngressZone: "lan", EgressZone: "wan", EgressIfindex: 12,
		RTFlowSessionID: wantID,
	}
	_, valV6, ok := userspaceSessionFromDeltaV6(deltaV6, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	if valV6.RTFlowSessionID != wantID {
		t.Fatalf("v6 RTFlowSessionID = %#x, want %#x", valV6.RTFlowSessionID, wantID)
	}
}

func TestUserspaceSessionFromDeltaV4(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:         "open",
		AddrFamily:    2,
		Protocol:      6,
		SrcIP:         "10.0.61.102",
		DstIP:         "172.16.80.200",
		SrcPort:       12345,
		DstPort:       5201,
		IngressZone:   "lan",
		EgressZone:    "wan",
		OwnerRGID:     1,
		EgressIfindex: 12,
		TXIfindex:     11,
		TXVLANID:      80,
		NeighborMAC:   "aa:bb:cc:dd:ee:ff",
		SrcMAC:        "02:bf:72:00:50:08",
		NATSrcIP:      "172.16.80.8",
		NATSrcPort:    40000,
		FabricIngress: true,
	}

	key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	if userspaceNetworkToHost16(key.SrcPort) != 12345 || userspaceNetworkToHost16(key.DstPort) != 5201 {
		t.Fatalf("unexpected key ports: %+v", key)
	}
	if val.IngressZone != 1 || val.EgressZone != 2 {
		t.Fatalf("unexpected zones: %+v", val)
	}
	if val.Flags == 0 {
		t.Fatalf("expected NAT/session flags to be set")
	}
	if got := val.NATSrcIP; got != binary.NativeEndian.Uint32([]byte{172, 16, 80, 8}) {
		t.Fatalf("unexpected nat src ip: %08x", got)
	}
	if userspaceNetworkToHost16(val.NATSrcPort) != 40000 {
		t.Fatalf("unexpected nat src port: %d", val.NATSrcPort)
	}
	if val.FibIfindex != 11 || val.FibVlanID != 80 {
		t.Fatalf("unexpected fib egress metadata: ifindex=%d vlan=%d", val.FibIfindex, val.FibVlanID)
	}
	if val.FibDmac != [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Fatalf("unexpected fib dmac: %v", val.FibDmac)
	}
	if val.FibSmac != [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08} {
		t.Fatalf("unexpected fib smac: %v", val.FibSmac)
	}
	if userspaceNetworkToHost16(val.ReverseKey.DstPort) != 40000 {
		t.Fatalf("unexpected reverse dst port: %d", val.ReverseKey.DstPort)
	}
	if val.LogFlags&dataplane.LogFlagUserspaceFabricIngress == 0 {
		t.Fatalf("expected fabric ingress marker in log flags: %#x", val.LogFlags)
	}
}

func TestWrapUserspaceManualFailoverPrepareErrorMarksRetryableSyncErrors(t *testing.T) {
	err := wrapUserspaceManualFailoverPrepareError(
		errors.New("session sync peer not quiescent before demotion: timed out"),
	)
	var retryable *cluster.RetryablePreFailoverError
	if !errors.As(err, &retryable) {
		t.Fatalf("expected retryable pre-failover error, got %T", err)
	}
}

func TestWrapUserspaceManualFailoverPrepareErrorLeavesFatalErrors(t *testing.T) {
	src := errors.New("prepare failed")
	err := wrapUserspaceManualFailoverPrepareError(src)
	if err != src {
		t.Fatalf("expected original error to be preserved, got %v", err)
	}
}

func TestWrapUserspaceManualFailoverPrepareErrorMarksRetryableBulkSyncNotReady(t *testing.T) {
	err := wrapUserspaceManualFailoverPrepareError(
		errors.New("session sync not ready before demotion: peer not responding to barrier: timed out"),
	)
	var retryable *cluster.RetryablePreFailoverError
	if !errors.As(err, &retryable) {
		t.Fatalf("expected retryable pre-failover error, got %T", err)
	}
}

func TestWrapUserspaceManualFailoverPrepareErrorLeavesTransferNotReadyFatal(t *testing.T) {
	src := errors.New("session sync transfer not ready before demotion: peer still receiving outbound bulk epoch=4 age=3s")
	err := wrapUserspaceManualFailoverPrepareError(
		src,
	)
	if err != src {
		t.Fatalf("expected original fatal error to be preserved, got %v", err)
	}
}

func TestUserspaceManualFailoverTransferReadinessErrorPendingBulkAck(t *testing.T) {
	err := userspaceManualFailoverTransferReadinessError(cluster.TransferReadinessSnapshot{
		Connected:           true,
		PendingBulkAckEpoch: 4,
		PendingBulkAckAge:   3 * time.Second,
	})
	if err == nil {
		t.Fatal("expected transfer readiness error")
	}
	if got := err.Error(); got != "session sync transfer not ready before demotion: peer still receiving outbound bulk epoch=4 age=3s" {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestUserspaceManualFailoverTransferReadinessErrorBulkReceive(t *testing.T) {
	err := userspaceManualFailoverTransferReadinessError(cluster.TransferReadinessSnapshot{
		Connected:             true,
		BulkReceiveInProgress: true,
		BulkReceiveEpoch:      7,
		BulkReceiveSessions:   128,
	})
	if err == nil {
		t.Fatal("expected transfer readiness error")
	}
	if got := err.Error(); got != "session sync transfer not ready before demotion: local bulk receive still in progress epoch=7 sessions=128" {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestUserspaceTransferReadinessDisconnected(t *testing.T) {
	d := &Daemon{}
	ready, reasons := d.userspaceTransferReadiness(0)
	if ready {
		t.Fatal("expected disconnected transfer readiness to be false")
	}
	if len(reasons) != 1 || reasons[0] != "session sync disconnected" {
		t.Fatalf("unexpected reasons: %v", reasons)
	}
}

type fakeUserspaceTransferReadinessProvider struct {
	connected bool
	healthy   bool
	state     cluster.TransferReadinessSnapshot
}

func (f fakeUserspaceTransferReadinessProvider) IsConnected() bool {
	return f.connected
}

func (f fakeUserspaceTransferReadinessProvider) PeerHealthy() bool {
	return f.healthy
}

func (f fakeUserspaceTransferReadinessProvider) TransferReadiness() cluster.TransferReadinessSnapshot {
	return f.state
}

func TestComputeUserspaceTransferReadinessRequiresHealthyPeer(t *testing.T) {
	ready, reasons := computeUserspaceTransferReadiness(fakeUserspaceTransferReadinessProvider{
		connected: true,
		healthy:   false,
		state: cluster.TransferReadinessSnapshot{
			Connected: true,
		},
	}, true)
	if ready {
		t.Fatal("expected unhealthy peer transfer readiness to be false")
	}
	if len(reasons) != 1 || reasons[0] != "session sync disconnected" {
		t.Fatalf("unexpected reasons: %v", reasons)
	}
}

func TestComputeUserspaceTransferReadinessReady(t *testing.T) {
	ready, reasons := computeUserspaceTransferReadiness(fakeUserspaceTransferReadinessProvider{
		connected: true,
		healthy:   true,
		state: cluster.TransferReadinessSnapshot{
			Connected: true,
		},
	}, true)
	if !ready {
		t.Fatalf("expected ready transfer readiness, got reasons=%v", reasons)
	}
	if reasons != nil {
		t.Fatalf("expected nil reasons, got %v", reasons)
	}
}

type fakeUserspaceHAProtocolMismatchProvider struct {
	mismatch bool
	local    uint16
	peer     uint16
}

func (f fakeUserspaceHAProtocolMismatchProvider) HAProtocolVersionMismatch() (bool, uint16, uint16) {
	return f.mismatch, f.local, f.peer
}

func TestUserspaceHAProtocolMismatchReason(t *testing.T) {
	reasons := userspaceHAProtocolMismatchReason(fakeUserspaceHAProtocolMismatchProvider{
		mismatch: true,
		local:    1,
		peer:     2,
	})
	if len(reasons) != 1 || reasons[0] != `ha protocol mismatch local=1 peer=2` {
		t.Fatalf("unexpected reasons: %v", reasons)
	}
}

func TestUserspaceSessionFromDeltaV4CarriesTunnelEndpointMetadata(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "sfmix": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:            "open",
		AddrFamily:       2,
		Protocol:         1,
		SrcIP:            "10.0.61.102",
		DstIP:            "10.255.192.41",
		SrcPort:          4459,
		DstPort:          4459,
		IngressZone:      "lan",
		EgressZone:       "sfmix",
		EgressIfindex:    586,
		TXIfindex:        24,
		TunnelEndpointID: 3,
		TXVLANID:         80,
		NeighborMAC:      "aa:bb:cc:dd:ee:ff",
		SrcMAC:           "02:bf:72:00:50:08",
		NATSrcIP:         "10.255.192.42",
	}

	_, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 tunnel delta to convert")
	}
	if val.FibIfindex != 0 {
		t.Fatalf("unexpected fib ifindex: %d", val.FibIfindex)
	}
	if val.FibGen != 3 {
		t.Fatalf("unexpected fib gen tunnel id: %d", val.FibGen)
	}
	if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint == 0 {
		t.Fatalf("expected tunnel endpoint marker in log flags: %#x", val.LogFlags)
	}
}

func TestUserspaceForwardWireAliasFromDeltaV4UsesNATTuple(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  dataplane.AFInet,
		Protocol:    6,
		SrcIP:       "10.0.61.102",
		DstIP:       "172.16.80.200",
		SrcPort:     39906,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "172.16.80.8",
		NATSrcPort:  39906,
	}

	baseKey, baseVal, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	key, _, ok := userspaceForwardWireAliasV4(baseKey, baseVal, delta)
	if !ok {
		t.Fatal("expected v4 forward-wire alias")
	}
	if got := key.SrcIP; got != [4]byte{172, 16, 80, 8} {
		t.Fatalf("unexpected forward-wire src ip: %v", got)
	}
	if got := userspaceNetworkToHost16(key.SrcPort); got != 39906 {
		t.Fatalf("unexpected forward-wire src port: %d", got)
	}
}

func TestUserspaceSessionFromDeltaV6(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:         "open",
		AddrFamily:    10,
		Protocol:      17,
		SrcIP:         "2001:559:8585:ef00::100",
		DstIP:         "2001:559:8585:80::200",
		SrcPort:       5555,
		DstPort:       53,
		IngressZone:   "lan",
		EgressZone:    "wan",
		OwnerRGID:     1,
		EgressIfindex: 12,
		TXIfindex:     11,
		TXVLANID:      80,
		NeighborMAC:   "00:11:22:33:44:55",
		SrcMAC:        "02:bf:72:00:50:08",
		NATSrcIP:      "2001:559:8585:80::8",
		NATSrcPort:    40000,
		FabricIngress: true,
	}

	key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	if userspaceNetworkToHost16(key.SrcPort) != 5555 || userspaceNetworkToHost16(key.DstPort) != 53 {
		t.Fatalf("unexpected key ports: %+v", key)
	}
	if val.IngressZone != 1 || val.EgressZone != 2 {
		t.Fatalf("unexpected zones: %+v", val)
	}
	if val.Flags == 0 {
		t.Fatalf("expected NAT/session flags to be set")
	}
	if val.NATSrcIP == [16]byte{} {
		t.Fatalf("expected NAT src v6 address to be set")
	}
	if userspaceNetworkToHost16(val.NATSrcPort) != 40000 {
		t.Fatalf("unexpected nat src port: %d", val.NATSrcPort)
	}
	if val.FibIfindex != 11 || val.FibVlanID != 80 {
		t.Fatalf("unexpected fib egress metadata: ifindex=%d vlan=%d", val.FibIfindex, val.FibVlanID)
	}
	if val.FibDmac != [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55} {
		t.Fatalf("unexpected fib dmac: %v", val.FibDmac)
	}
	if val.FibSmac != [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08} {
		t.Fatalf("unexpected fib smac: %v", val.FibSmac)
	}
	if userspaceNetworkToHost16(val.ReverseKey.DstPort) != 40000 {
		t.Fatalf("unexpected reverse dst port: %d", val.ReverseKey.DstPort)
	}
	if val.LogFlags&dataplane.LogFlagUserspaceFabricIngress == 0 {
		t.Fatalf("expected fabric ingress marker in log flags: %#x", val.LogFlags)
	}
}

func TestUserspaceSessionFromDeltaV6CarriesTunnelEndpointMetadata(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "sfmix": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:            "open",
		AddrFamily:       10,
		Protocol:         17,
		SrcIP:            "2001:559:8585:ef00::100",
		DstIP:            "2001:db8::1",
		SrcPort:          5555,
		DstPort:          53,
		IngressZone:      "lan",
		EgressZone:       "sfmix",
		EgressIfindex:    586,
		TXIfindex:        24,
		TunnelEndpointID: 7,
		TXVLANID:         80,
		NeighborMAC:      "00:11:22:33:44:55",
		SrcMAC:           "02:bf:72:00:50:08",
		NATSrcIP:         "2001:db8::2",
	}

	_, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 tunnel delta to convert")
	}
	if val.FibIfindex != 0 {
		t.Fatalf("unexpected fib ifindex: %d", val.FibIfindex)
	}
	if val.FibGen != 7 {
		t.Fatalf("unexpected fib gen tunnel id: %d", val.FibGen)
	}
	if val.LogFlags&dataplane.LogFlagUserspaceTunnelEndpoint == 0 {
		t.Fatalf("expected tunnel endpoint marker in log flags: %#x", val.LogFlags)
	}
}

func TestUserspaceForwardWireAliasFromDeltaV6UsesNATTuple(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  dataplane.AFInet6,
		Protocol:    6,
		SrcIP:       "2001:559:8585:ef00::100",
		DstIP:       "2001:559:8585:80::200",
		SrcPort:     50952,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "2001:559:8585:80::8",
		NATSrcPort:  50952,
	}

	baseKey, baseVal, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	key, _, ok := userspaceForwardWireAliasV6(baseKey, baseVal, delta)
	if !ok {
		t.Fatal("expected v6 forward-wire alias")
	}
	if got := userspaceNetworkToHost16(key.SrcPort); got != 50952 {
		t.Fatalf("unexpected forward-wire src port: %d", got)
	}
	if key.SrcIP == [16]byte{} {
		t.Fatal("expected forward-wire src ip to be rewritten")
	}
}

func TestUserspaceSessionFromDeltaUsesNetworkByteOrderPorts(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  2,
		Protocol:    6,
		SrcIP:       "10.0.61.102",
		DstIP:       "172.16.80.200",
		SrcPort:     50952,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "172.16.80.8",
	}

	key, _, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	if key.SrcPort == delta.SrcPort || key.DstPort == delta.DstPort {
		t.Fatalf("ports were not converted to network order: %+v", key)
	}
	if got := userspaceNetworkToHost16(key.SrcPort); got != delta.SrcPort {
		t.Fatalf("src port roundtrip = %d, want %d", got, delta.SrcPort)
	}
	if got := userspaceNetworkToHost16(key.DstPort); got != delta.DstPort {
		t.Fatalf("dst port roundtrip = %d, want %d", got, delta.DstPort)
	}
}

func TestUserspaceSessionFromDeltaV4PreservesPortForAddressOnlySNAT(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  2,
		Protocol:    6,
		SrcIP:       "10.0.61.102",
		DstIP:       "172.16.80.200",
		SrcPort:     50952,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "172.16.80.8",
	}

	_, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v4 delta to convert")
	}
	if got := userspaceNetworkToHost16(val.NATSrcPort); got != delta.SrcPort {
		t.Fatalf("nat src port roundtrip = %d, want %d", got, delta.SrcPort)
	}
}

func TestUserspaceSessionFromDeltaV6PreservesPortForAddressOnlySNAT(t *testing.T) {
	zoneIDs := map[string]uint16{"lan": 1, "wan": 2}
	delta := dpuserspace.SessionDeltaInfo{
		Event:       "open",
		AddrFamily:  10,
		Protocol:    6,
		SrcIP:       "2001:559:8585:ef00::100",
		DstIP:       "2001:559:8585:80::200",
		SrcPort:     50952,
		DstPort:     5201,
		IngressZone: "lan",
		EgressZone:  "wan",
		NATSrcIP:    "2001:559:8585:80::8",
	}

	_, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		t.Fatal("expected v6 delta to convert")
	}
	if got := userspaceNetworkToHost16(val.NATSrcPort); got != delta.SrcPort {
		t.Fatalf("nat src port roundtrip = %d, want %d", got, delta.SrcPort)
	}
}

func TestShouldSyncUserspaceDeltaPrefersOwnerRG(t *testing.T) {
	d := &Daemon{
		sessionSync: &cluster.SessionSync{
			IsPrimaryFn:      func() bool { return false },
			IsPrimaryForRGFn: func(rgID int) bool { return rgID == 2 },
		},
	}
	if !d.shouldSyncUserspaceDelta(d.sessionSync, dpuserspace.SessionDeltaInfo{OwnerRGID: 2}, 1) {
		t.Fatal("expected owner RG primary to allow sync")
	}
	if d.shouldSyncUserspaceDelta(d.sessionSync, dpuserspace.SessionDeltaInfo{OwnerRGID: 1}, 1) {
		t.Fatal("expected non-primary owner RG to block sync")
	}
}

func TestShouldSyncUserspaceDeltaFallsBackToZone(t *testing.T) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return false },
		IsPrimaryForRGFn: func(rgID int) bool { return false },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1})
	d := &Daemon{sessionSync: ss}
	if d.shouldSyncUserspaceDelta(d.sessionSync, dpuserspace.SessionDeltaInfo{}, 1) {
		t.Fatal("expected fallback zone sync to be false when RG 1 is not local primary")
	}
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	if !d.shouldSyncUserspaceDelta(d.sessionSync, dpuserspace.SessionDeltaInfo{}, 1) {
		t.Fatal("expected fallback zone sync to use ShouldSyncZone")
	}
}

func TestShouldSyncUserspaceDeltaSkipsLocalDelivery(t *testing.T) {
	d := &Daemon{
		sessionSync: &cluster.SessionSync{
			IsPrimaryFn:      func() bool { return true },
			IsPrimaryForRGFn: func(rgID int) bool { return true },
		},
	}
	if d.shouldSyncUserspaceDelta(d.sessionSync, dpuserspace.SessionDeltaInfo{Disposition: "local_delivery"}, 1) {
		t.Fatal("expected helper local-delivery deltas to stay out of session sync")
	}
}

// EVERY transient-local-seed origin must stay out of session sync, and the
// control leg is what makes that mean something.
//
// The helper suppresses these at install, so a green here proves only that the
// belt matches the suspenders — which is the point: #6599 measured that a
// FabricRedirect-disposition Open delta reaching the peer overwrites the
// owner's authoritative session family under latest-generation-wins, and a
// #7770 punt seed has that disposition and is NAT-free. The list is driven
// rather than spelled out per-origin so a member added to
// `transientLocalSeedOrigins` without a test cannot slip through.
//
// The non-seed control leg is load-bearing: without it a filter that refused
// EVERY delta would satisfy every assertion above it.
func TestShouldSyncUserspaceDeltaSkipsTransientLocalSeeds(t *testing.T) {
	d := &Daemon{
		sessionSync: &cluster.SessionSync{
			IsPrimaryFn:      func() bool { return true },
			IsPrimaryForRGFn: func(rgID int) bool { return true },
		},
	}
	if len(transientLocalSeedOrigins) == 0 {
		t.Fatal("transientLocalSeedOrigins is empty, so this test asserts nothing")
	}
	for _, origin := range transientLocalSeedOrigins {
		if d.shouldSyncUserspaceDelta(d.sessionSync, dpuserspace.SessionDeltaInfo{Origin: origin}, 1) {
			t.Errorf("transient local seed origin %q was queued for session sync; "+
				"the authoritative session for such a flow lives on the OTHER node, "+
				"and a FabricRedirect-disposition Open delta overwrites it there "+
				"under latest-generation-wins (#6599/#7770)", origin)
		}
	}
	// Control: an ORDINARY local forward session must still sync, or the loop
	// above is measuring a filter that refuses everything.
	if !d.shouldSyncUserspaceDelta(d.sessionSync, dpuserspace.SessionDeltaInfo{Origin: "forward_flow"}, 1) {
		t.Fatal("an ordinary forward_flow delta was filtered — the seed filter is " +
			"refusing traffic it must pass, so the assertions above are not about seeds")
	}
}

// The property this pins is that the OWNER-RG gate must not block a
// fabric-redirect handoff: a fabric redirect exists precisely because the peer
// owns the flow's egress RG, so delta.OwnerRGID always names an RG this node is
// not primary for.
//
// #6599 retargeted the fixture. It used to make the node primary for NOTHING —
// which also made it not primary for the RG owning the flow's INGRESS zone, so
// the test asserted that a node owning neither side of the flow may still push
// an Open to the peer. That is the identity-less-Open emission channel, not the
// handoff property. The node is now primary for RG 2 and the flow ingresses on
// a zone that lives on RG 2, so it legitimately owns the traffic it hands off
// while its owner RG (1) is still the peer's.
func TestShouldSyncUserspaceDeltaAllowsStaleOwnerFabricRedirect(t *testing.T) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return false },
		IsPrimaryForRGFn: func(rgID int) bool { return rgID == 2 },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 2})
	d := &Daemon{sessionSync: ss}
	delta := dpuserspace.SessionDeltaInfo{
		OwnerRGID:      1,
		FabricRedirect: true,
		FabricIngress:  false,
		IngressZone:    "lan",
		EgressZone:     "wan",
		EgressIfindex:  3,
		TXIfindex:      3,
		NeighborMAC:    "aa:bb:cc:dd:ee:ff",
		SrcMAC:         "02:bf:72:aa:00:01",
	}
	if !d.shouldSyncUserspaceDelta(d.sessionSync, delta, 1) {
		t.Fatal("expected stale-owner fabric redirect delta to be synced")
	}
}

func TestShouldSyncUserspaceDeltaDoesNotBypassFabricIngress(t *testing.T) {
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return false },
		IsPrimaryForRGFn: func(rgID int) bool { return false },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1})
	d := &Daemon{sessionSync: ss}
	delta := dpuserspace.SessionDeltaInfo{
		OwnerRGID:      1,
		FabricRedirect: true,
		FabricIngress:  true,
	}
	if d.shouldSyncUserspaceDelta(d.sessionSync, delta, 1) {
		t.Fatal("expected fabric-ingress delta to remain blocked on standby")
	}
}

func TestDrainUserspaceSessionDeltasWithConfigDrainsPreparedBatches(t *testing.T) {
	buildDelta := func(srcPort uint16) dpuserspace.SessionDeltaInfo {
		return dpuserspace.SessionDeltaInfo{
			Event:         "open",
			AddrFamily:    dataplane.AFInet,
			Protocol:      6,
			SrcIP:         "10.0.61.102",
			DstIP:         "172.16.80.200",
			SrcPort:       srcPort,
			DstPort:       5201,
			IngressZone:   "lan",
			EgressZone:    "wan",
			OwnerRGID:     1,
			EgressIfindex: 12,
			TXIfindex:     11,
			TXVLANID:      80,
			NeighborMAC:   "aa:bb:cc:dd:ee:ff",
			SrcMAC:        "02:bf:72:00:50:08",
			NATSrcIP:      "172.16.80.8",
			NATSrcPort:    40000 + srcPort,
		}
	}

	firstBatch := make([]dpuserspace.SessionDeltaInfo, 256)
	for i := range firstBatch {
		firstBatch[i] = buildDelta(uint16(10000 + i))
	}
	secondBatch := []dpuserspace.SessionDeltaInfo{buildDelta(20001)}
	drainer := &fakeUserspaceDeltaDrainer{
		batches: [][]dpuserspace.SessionDeltaInfo{firstBatch, secondBatch},
	}
	d := &Daemon{
		sessionSync: &cluster.SessionSync{
			IsPrimaryFn:      func() bool { return true },
			IsPrimaryForRGFn: func(rgID int) bool { return rgID == 1 },
		},
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"},
		"wan": {Name: "wan"},
	}

	queued, err := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 8)
	if err != nil {
		t.Fatalf("drainUserspaceSessionDeltasWithConfig() error = %v", err)
	}
	if queued != 257 {
		t.Fatalf("queued = %d, want 257", queued)
	}
	if drainer.calls != 2 {
		t.Fatalf("drain calls = %d, want 2", drainer.calls)
	}
}

func TestExportUserspaceOwnerRGSessionsWithConfigQueuesForwardWireAlias(t *testing.T) {
	exporter := &fakeUserspaceSessionExporter{
		deltas: []dpuserspace.SessionDeltaInfo{{
			Event:          "open",
			AddrFamily:     dataplane.AFInet,
			Protocol:       6,
			SrcIP:          "10.0.61.102",
			DstIP:          "172.16.80.200",
			SrcPort:        39906,
			DstPort:        5201,
			IngressZone:    "lan",
			EgressZone:     "wan",
			OwnerRGID:      1,
			EgressIfindex:  12,
			TXIfindex:      11,
			TXVLANID:       80,
			NeighborMAC:    "aa:bb:cc:dd:ee:ff",
			SrcMAC:         "02:bf:72:00:50:08",
			NATSrcIP:       "172.16.80.8",
			NATSrcPort:     39906,
			FabricRedirect: true,
		}},
	}
	// #9767: the count is what reached the send queue, so the sync must read
	// connected. A disconnected one admits nothing, and the export says so.
	ss := cluster.NewSessionSync("127.0.0.1:0", "127.0.0.1:1", nil)
	ss.IsPrimaryFn = func() bool { return true }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	ss.SetConnectedForTesting(true)
	d := &Daemon{sessionSync: ss}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"},
		"wan": {Name: "wan"},
	}

	queued, err := d.exportUserspaceOwnerRGSessionsWithConfig(exporter, cfg, []int{1})
	if err != nil {
		t.Fatalf("exportUserspaceOwnerRGSessionsWithConfig() error = %v", err)
	}
	if queued != 2 {
		t.Fatalf("queued = %d, want 2", queued)
	}
	if exporter.calls != 1 {
		t.Fatalf("export calls = %d, want 1", exporter.calls)
	}
	for i := 0; i < 2; i++ {
		if typ, ok := ss.TakeQueuedMessageTypeForTesting(0); !ok || typ != "session_v4" {
			t.Fatalf("send-queue message %d = %q (present=%v), want session_v4 for the session and its forward-wire alias",
				i, typ, ok)
		}
	}
}

func TestUserspaceRGDemotionPrepLeaseCanBeReleasedAfterFailure(t *testing.T) {
	d := &Daemon{
		userspaceDemotionPrepUntil: make(map[int]time.Time),
	}
	if !d.acquireUserspaceRGDemotionPrep(1, time.Second) {
		t.Fatal("expected first lease acquisition")
	}
	d.releaseUserspaceRGDemotionPrep(1)
	if !d.acquireUserspaceRGDemotionPrep(1, time.Second) {
		t.Fatal("expected lease acquisition after release")
	}
}

// TestHandleEventStreamDeltaSkipsWhenNoCluster verifies that permanent
// non-owner/no-cluster paths ACK and ignore events instead of asking the helper
// to replay forever.
func TestHandleEventStreamDeltaSkipsWhenNoCluster(t *testing.T) {
	d := &Daemon{}
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
		SrcIP:      "10.0.1.102",
		DstIP:      "172.16.80.200",
		SrcPort:    12345,
		DstPort:    443,
	}
	if !d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
		t.Fatal("delta without cluster/sessionSync should be permanently ignored and ACKed")
	}
	backup := &Daemon{
		cluster:     newClusterManager(false),
		sessionSync: &cluster.SessionSync{},
	}
	if !backup.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta) {
		t.Fatal("delta on a backup should be permanently ignored and ACKed")
	}
}

// TestHandleEventStreamDeltaMapsEventTypes verifies event type to string mapping
// doesn't panic for all supported types.
func TestHandleEventStreamDeltaMapsEventTypes(t *testing.T) {
	d := &Daemon{} // nil cluster = early return
	delta := dpuserspace.SessionDeltaInfo{
		AddrFamily: dataplane.AFInet,
		Protocol:   6,
	}
	d.handleEventStreamDelta(dpuserspace.EventTypeSessionOpen, delta)
	d.handleEventStreamDelta(dpuserspace.EventTypeSessionClose, delta)
	d.handleEventStreamDelta(dpuserspace.EventTypeSessionUpdate, delta)
}

func TestHandleEventStreamFullResyncRequiresHAReady(t *testing.T) {
	if !(&Daemon{}).handleEventStreamFullResync() {
		t.Fatal("full resync without cluster/sessionSync should be permanently ignored and ACKed")
	}
	backup := &Daemon{
		cluster:     newClusterManager(false),
		sessionSync: &cluster.SessionSync{},
	}
	if !backup.handleEventStreamFullResync() {
		t.Fatal("full resync on a backup should be permanently ignored and ACKed")
	}
	d := &Daemon{
		cluster:     newClusterManager(true),
		sessionSync: &cluster.SessionSync{},
	}
	if d.handleEventStreamFullResync() {
		t.Fatal("full resync with disconnected sessionSync should withhold ACK")
	}
}

// clusterManagerPrimaryForRGs builds a standalone cluster.Manager (no control
// interface) that elects the local node primary for every listed RG id. With no
// control interface, electSingleNode() promotes every weight>0 RG immediately,
// so IsLocalPrimary(id) is true for each configured id.
func clusterManagerPrimaryForRGs(ids ...int) *cluster.Manager {
	m := cluster.NewManager(0, 1)
	rgs := make([]*config.RedundancyGroup, 0, len(ids))
	for _, id := range ids {
		rgs = append(rgs, &config.RedundancyGroup{
			ID:             id,
			NodePriorities: map[int]int{0: 200},
			Preempt:        true,
		})
	}
	m.UpdateConfig(&config.ClusterConfig{RethCount: 1, RedundancyGroups: rgs})
	return m
}

// TestPrimaryOwnerRGIDsIncludesHighID is the #4028 RED-on-revert guard: the
// full-resync RG enumeration must follow the configured redundancy-group set,
// not a hardcoded 0..15 range. A cluster with an RG id >= 16 must have that RG
// enumerated so its sessions are re-exported to the standby on a full resync.
// Reverting primaryOwnerRGIDs to the old `for rgID := 0; rgID < 16` loop drops
// RG 20 here and turns this test RED.
func TestPrimaryOwnerRGIDsIncludesHighID(t *testing.T) {
	d := &Daemon{cluster: clusterManagerPrimaryForRGs(0, 1, 20)}
	// Sanity: the manager must actually consider the node primary for RG 20.
	if !d.cluster.IsLocalPrimary(20) {
		t.Fatal("test setup: node should be primary for RG 20")
	}

	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0}, {ID: 1}, {ID: 20},
		},
	}

	got := d.primaryOwnerRGIDs(cfg)
	want := map[int]bool{0: true, 1: true, 20: true}
	if len(got) != len(want) {
		t.Fatalf("primaryOwnerRGIDs() = %v, want ids %v", got, want)
	}
	for _, id := range got {
		if !want[id] {
			t.Fatalf("primaryOwnerRGIDs() returned unexpected RG %d (got %v)", id, got)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("primaryOwnerRGIDs() missing RGs %v (got %v) — RG >= 16 skipped?", want, got)
	}
}

// TestPrimaryOwnerRGIDsFollowsConfigAndOwnership verifies the enumeration only
// returns configured RGs the node owns, skips nil entries (#3494), and returns
// nil when there is no cluster or no cluster config.
func TestPrimaryOwnerRGIDsFollowsConfigAndOwnership(t *testing.T) {
	// Node owns RG 0 and 20, but the config only lists 0 and 5. RG 5 is not
	// owned, RG 20 is owned but not configured — neither should appear.
	d := &Daemon{cluster: clusterManagerPrimaryForRGs(0, 20)}
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0},
			nil, // #3494: nil RG entry must not panic and must be skipped
			{ID: 5},
		},
	}
	got := d.primaryOwnerRGIDs(cfg)
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("primaryOwnerRGIDs() = %v, want [0]", got)
	}

	// No cluster manager → nil.
	if ids := (&Daemon{}).primaryOwnerRGIDs(cfg); ids != nil {
		t.Fatalf("primaryOwnerRGIDs() with nil cluster = %v, want nil", ids)
	}
	// No cluster config → nil.
	if ids := d.primaryOwnerRGIDs(&config.Config{}); ids != nil {
		t.Fatalf("primaryOwnerRGIDs() with no cluster config = %v, want nil", ids)
	}
}

func TestWireUserspaceEventStreamCallbacksStandaloneWiresSessionAndFullResync(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	es := dpuserspace.NewEventStream(socketPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Start binds the Unix listener synchronously before launching the accept
	// loop, so a successful return means the socket is connectable. #6038: check
	// the error instead of discarding it — a silent bind failure would otherwise
	// surface only as a confusing dial-loop timeout below.
	if err := es.Start(ctx); err != nil {
		t.Fatalf("start event stream: %v", err)
	}
	defer es.Close()

	// #6743 r6-F4: the wiring resolves the provider from the #2114 cell
	// per poll rather than taking one as an argument, so the fake is
	// PUBLISHED here. That is the production shape: a provider handed in
	// by the caller could be a backend the daemon has already disowned.
	d := &Daemon{}
	d.setDataplane(&eventStreamCellBackend{
		Manager: dataplane.New(),
		es:      es,
	})
	if d.wireUserspaceEventStreamCallbacks(ctx) == nil {
		t.Fatal("expected callback wiring to succeed")
	}

	var conn net.Conn
	var err error
	// #6038: gate on a successful connect with a generous cap (see
	// wiringTestDeadline) instead of a fixed 2s wall-clock that races the
	// listener under load.
	dialDeadline := wiringTestDeadline(t)
	for time.Now().Before(dialDeadline) {
		conn, err = net.Dial("unix", socketPath)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial event stream socket: %v", err)
	}
	defer conn.Close()

	writeEventFrameForWiringTest(t, conn, dpuserspace.EventTypeSessionOpen, 1, buildSessionOpenFrameV4PayloadForWiringTest())
	waitForAckSeqForWiringTest(t, conn, 1)

	writeEventFrameForWiringTest(t, conn, dpuserspace.EventTypeFullResync, 2, nil)
	waitForAckSeqForWiringTest(t, conn, 2)
}

// TestUserspaceManagerImplementsEventStreamExporter verifies that the userspace
// Manager satisfies the userspaceEventStreamExporter interface used by
// bulkSyncViaEventStreamOrFallback.
func TestUserspaceManagerImplementsEventStreamExporter(t *testing.T) {
	var mgr interface{} = &dpuserspace.Manager{}
	if _, ok := mgr.(userspaceEventStreamExporter); !ok {
		t.Fatal("userspace.Manager does not implement userspaceEventStreamExporter")
	}
}

// TestBulkSyncFallbackWhenDPIsNil verifies that bulkSyncViaEventStreamOrFallback
// returns an error when the dataplane is nil (no event stream support) and
// session sync is also nil.
func TestBulkSyncFallbackWhenDPIsNil(t *testing.T) {
	d := &Daemon{}
	err := d.bulkSyncViaEventStreamOrFallback(nil)
	if err == nil {
		t.Fatal("expected error from nil session sync fallback")
	}
}

// captureDeltaSink records every session the delta walk admits, so a test can
// assert on BOTH the canonical open and the forward-wire alias the
// fabric-redirect branch emits alongside it.
type captureDeltaSink struct {
	opensV4   []dataplane.SessionKey
	opensV6   []dataplane.SessionKeyV6
	deletesV4 []dataplane.SessionKey
	deletesV6 []dataplane.SessionKeyV6
}

func (c *captureDeltaSink) openV4(key dataplane.SessionKey, _ dataplane.SessionValue) {
	c.opensV4 = append(c.opensV4, key)
}

func (c *captureDeltaSink) openV6(key dataplane.SessionKeyV6, _ dataplane.SessionValueV6) {
	c.opensV6 = append(c.opensV6, key)
}

// #7188: the delete arms take the converted VALUE too, because two RFC 2890 GRE
// tunnels between one pair of outer endpoints share a dataplane.SessionKey and
// differ only in val.TunnelDiscriminator. This capture sink records keys only —
// its subject is the eligibility filter, not identity — so it discards the value.
func (c *captureDeltaSink) deleteV4(key dataplane.SessionKey, _ dataplane.SessionValue) {
	c.deletesV4 = append(c.deletesV4, key)
}

func (c *captureDeltaSink) deleteV6(key dataplane.SessionKeyV6, _ dataplane.SessionValueV6) {
	c.deletesV6 = append(c.deletesV6, key)
}

// #6599: the fabric-redirect carve-out must still require that THIS node owns
// the RG the flow's INGRESS zone belongs to.
//
// A fabric redirect means "the peer owns the EGRESS side", so judging the delta
// by delta.OwnerRGID would refuse every legitimate split-RG handoff — that is
// what the carve-out exists for. But bypassing ownership ENTIRELY lets a node
// that owns neither side emit an Open for a session it fabricated on a
// peer-owned tuple: the transient-purge re-entry class. The ingress-zone RG is
// the predicate that keeps the handoff and drops the fabrication.
func TestShouldSyncUserspaceDeltaFabricRedirectRequiresIngressOwnership6599(t *testing.T) {
	ss := &cluster.SessionSync{
		IsPrimaryFn: func() bool { return false },
		// Split-RG: this node is primary for RG 2 only. RG 1 is the peer's.
		IsPrimaryForRGFn: func(rgID int) bool { return rgID == 2 },
	}
	// Zone 1 lives on RG 1 (peer-owned); zone 5 lives on RG 2 (locally owned).
	ss.SetZoneRGMap(map[uint16]int{1: 1, 5: 2})
	d := &Daemon{sessionSync: ss}

	peerIngress := dpuserspace.SessionDeltaInfo{
		OwnerRGID:      1,
		FabricRedirect: true,
		FabricIngress:  false,
		IngressZone:    "wan",
		EgressZone:     "lan",
	}
	if d.shouldSyncUserspaceDelta(d.sessionSync, peerIngress, 1) {
		t.Fatal("expected a fabric-redirect delta whose INGRESS RG is peer-owned to be refused (#6599)")
	}

	// Positive control: the legitimate split-RG handoff. The session's owner RG
	// is the peer's (that is why it is a fabric redirect at all), but the flow
	// ingressed on an RG this node owns, so the handoff must still sync.
	localIngress := peerIngress
	if !d.shouldSyncUserspaceDelta(d.sessionSync, localIngress, 5) {
		t.Fatal("expected a fabric-redirect handoff from a locally-owned ingress RG to sync")
	}
}

// #6599: the gate is what the WALK consults, and the fabric-redirect branch
// emits TWO sessions per admitted delta (the canonical key and the forward-wire
// alias). Bind the walk, not just the predicate: an unowned-ingress delta must
// contribute ZERO sessions, alias included.
func TestWalkUserspaceSessionDeltasDropsUnownedFabricRedirect6599(t *testing.T) {
	zoneIDs := map[string]uint16{"wan": 1, "lan": 5}
	ss := &cluster.SessionSync{
		IsPrimaryFn:      func() bool { return false },
		IsPrimaryForRGFn: func(rgID int) bool { return rgID == 2 },
	}
	ss.SetZoneRGMap(map[uint16]int{1: 1, 5: 2})
	d := &Daemon{sessionSync: ss}

	// The spoofed re-entry: a session the standby fabricated on the peer-owned
	// flow's translated tuple. It ingressed on the WAN zone, whose RG the peer
	// owns, and its resolution is a fabric redirect because this node is not
	// the RG owner — exactly the condition that fired the transient purge.
	spoofed := dpuserspace.SessionDeltaInfo{
		Event:          "open",
		AddrFamily:     dataplane.AFInet,
		Protocol:       6,
		SrcIP:          "172.16.80.8",
		DstIP:          "172.16.80.200",
		SrcPort:        39906,
		DstPort:        5201,
		IngressZone:    "wan",
		EgressZone:     "lan",
		OwnerRGID:      1,
		NATSrcIP:       "172.16.80.9",
		NATSrcPort:     39906,
		FabricRedirect: true,
		FabricIngress:  false,
	}
	var sink captureDeltaSink
	n := d.walkUserspaceSessionDeltas(ss, zoneIDs, []dpuserspace.SessionDeltaInfo{spoofed}, &sink)
	if n != 0 || len(sink.opensV4) != 0 {
		t.Fatalf("expected the unowned-ingress fabric-redirect open AND its forward-wire alias to be dropped (#6599); got n=%d opens=%v", n, sink.opensV4)
	}

	// Positive control: the same delta ingressing on a locally-owned RG still
	// emits BOTH the canonical session and its forward-wire alias.
	handoff := spoofed
	handoff.IngressZone = "lan"
	handoff.EgressZone = "wan"
	var okSink captureDeltaSink
	n = d.walkUserspaceSessionDeltas(ss, zoneIDs, []dpuserspace.SessionDeltaInfo{handoff}, &okSink)
	if n != 2 || len(okSink.opensV4) != 2 {
		t.Fatalf("expected the owned-ingress handoff to emit the session and its alias; got n=%d opens=%v", n, okSink.opensV4)
	}
}
