package userspace

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// EventStream manages the daemon-side event socket for receiving session events
// from the Rust helper over a persistent binary-framed Unix stream.
//
// The daemon creates the listener socket before spawning the helper. The helper
// dials on startup. A single connection is active at a time. If the helper
// disconnects, the accept loop waits for reconnection.
type EventStream struct {
	socketPath string
	listener   net.Listener

	mu   sync.Mutex
	conn net.Conn // current helper connection; nil when disconnected

	connected atomic.Bool
	paused    atomic.Bool

	// Sequence tracking.
	lastRecvSeq    atomic.Uint64
	lastAppliedSeq atomic.Uint64 // advanced only after onEvent() completes
	lastAckSeq     atomic.Uint64
	ackBatch       atomic.Uint64 // events since last ack

	// Callbacks — set before Start(), called on the reader goroutine.
	onEvent             func(eventType uint8, seq uint64, delta SessionDeltaInfo)
	onDataplaneEvent    func(seq uint64, rec logging.EventRecord)
	onRawDataplaneEvent func(seq uint64, payload []byte)
	onFullResync        func()

	// DrainComplete signaling for demotion prep.
	drainCompleteMu sync.Mutex
	drainCompleteCh chan uint64

	// Stats.
	FramesRead        atomic.Uint64
	FramesWritten     atomic.Uint64
	DecodeErrors      atomic.Uint64
	SeqGaps           atomic.Uint64
	PolicyDenyEvents  atomic.Uint64
	ScreenDropEvents  atomic.Uint64
	FilterLogEvents   atomic.Uint64
	PolicyDenyDrops   atomic.Uint64
	ScreenDropDrops   atomic.Uint64
	FilterLogDrops    atomic.Uint64
	UnknownFrameDrops atomic.Uint64
}

// NewEventStream creates an EventStream for the given Unix socket path.
// Call Start() to begin listening.
func NewEventStream(socketPath string) *EventStream {
	return &EventStream{
		socketPath:      socketPath,
		drainCompleteCh: make(chan uint64, 1),
	}
}

// SetOnEvent sets the callback for session events. Must be called before Start().
func (es *EventStream) SetOnEvent(fn func(eventType uint8, seq uint64, delta SessionDeltaInfo)) {
	es.onEvent = fn
}

// SetOnDataplaneEvent sets the callback for RT_FLOW-style dataplane events.
// Must be called before Start().
func (es *EventStream) SetOnDataplaneEvent(fn func(seq uint64, rec logging.EventRecord)) {
	es.onDataplaneEvent = fn
}

// SetOnRawDataplaneEvent sets the callback for raw RT_FLOW dataplane events.
// It is preferred when the receiver can process the canonical dataplane.Event
// payload itself, because it preserves name resolution and syslog fanout.
func (es *EventStream) SetOnRawDataplaneEvent(fn func(seq uint64, payload []byte)) {
	es.onRawDataplaneEvent = fn
}

// SetOnFullResync sets the callback for full resync requests. Must be called before Start().
func (es *EventStream) SetOnFullResync(fn func()) {
	es.onFullResync = fn
}

// Start creates the Unix socket listener and launches the accept loop.
func (es *EventStream) Start(ctx context.Context) {
	_ = os.Remove(es.socketPath)
	ln, err := net.Listen("unix", es.socketPath)
	if err != nil {
		slog.Error("event stream: failed to listen", "path", es.socketPath, "err", err)
		return
	}
	es.listener = ln
	slog.Info("event stream: listening", "path", es.socketPath)
	go es.acceptLoop(ctx)
}

// Close shuts down the listener and any active connection.
func (es *EventStream) Close() {
	if es.listener != nil {
		es.listener.Close()
	}
	es.mu.Lock()
	if es.conn != nil {
		es.conn.Close()
		es.conn = nil
	}
	es.connected.Store(false)
	es.mu.Unlock()
	_ = os.Remove(es.socketPath)
}

// IsConnected returns true if the helper is currently connected.
func (es *EventStream) IsConnected() bool {
	return es.connected.Load()
}

// SendPause sends a Pause frame to the helper, requesting it to buffer events.
func (es *EventStream) SendPause() error {
	es.paused.Store(true)
	return es.writeFrame(EventTypePause, 0, nil)
}

// SendResume sends a Resume frame to the helper, requesting it to flush buffered events.
func (es *EventStream) SendResume() error {
	es.paused.Store(false)
	return es.writeFrame(EventTypeResume, 0, nil)
}

// SendDrainRequest sends a DrainRequest frame and blocks until DrainComplete
// arrives or the context expires. Returns the drain-complete sequence number.
func (es *EventStream) SendDrainRequest(ctx context.Context) (uint64, error) {
	// Drain any stale DrainComplete signal.
	es.drainCompleteMu.Lock()
	select {
	case <-es.drainCompleteCh:
	default:
	}
	es.drainCompleteMu.Unlock()

	// Fence to the last sequence whose callback has completed, so the
	// helper knows exactly which events have been fully applied.
	targetSeq := es.lastAppliedSeq.Load()
	if err := es.writeFrame(EventTypeDrainRequest, targetSeq, nil); err != nil {
		return 0, fmt.Errorf("write drain request: %w", err)
	}

	select {
	case seq := <-es.drainCompleteCh:
		return seq, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// LastAckedSequence returns the last sequence number acknowledged to the helper.
func (es *EventStream) LastAckedSequence() uint64 {
	return es.lastAckSeq.Load()
}

func (es *EventStream) Status() EventStreamStatus {
	return EventStreamStatus{
		FramesRead:        es.FramesRead.Load(),
		FramesWritten:     es.FramesWritten.Load(),
		DecodeErrors:      es.DecodeErrors.Load(),
		SeqGaps:           es.SeqGaps.Load(),
		PolicyDenyEvents:  es.PolicyDenyEvents.Load(),
		ScreenDropEvents:  es.ScreenDropEvents.Load(),
		FilterLogEvents:   es.FilterLogEvents.Load(),
		PolicyDenyDrops:   es.PolicyDenyDrops.Load(),
		ScreenDropDrops:   es.ScreenDropDrops.Load(),
		FilterLogDrops:    es.FilterLogDrops.Load(),
		UnknownFrameDrops: es.UnknownFrameDrops.Load(),
	}
}

// acceptLoop listens for helper connections. Only one is active at a time.
func (es *EventStream) acceptLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := es.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Debug("event stream: accept error", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		slog.Info("event stream: helper connected")
		es.mu.Lock()
		// Close any previous connection.
		if es.conn != nil {
			es.conn.Close()
		}
		es.conn = conn
		es.connected.Store(true)
		es.ackBatch.Store(0)
		// Reset sequence tracking for the new connection so stale
		// watermarks from a previous helper don't cause gaps (#280).
		es.lastRecvSeq.Store(0)
		es.lastAppliedSeq.Store(0)
		es.lastAckSeq.Store(0)
		es.mu.Unlock()

		// Run the reader and ack loops for this connection.
		connCtx, connCancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			es.ackLoop(connCtx)
			close(done)
		}()

		es.readLoop(connCtx)

		// readLoop returned — connection lost.
		connCancel()
		<-done // wait for ackLoop to exit

		es.mu.Lock()
		if es.conn == conn {
			es.conn.Close()
			es.conn = nil
			es.connected.Store(false)
		}
		es.mu.Unlock()
		slog.Info("event stream: helper disconnected")
	}
}

// readLoop reads binary frames from the helper and dispatches events.
func (es *EventStream) readLoop(ctx context.Context) {
	var hdr [EventFrameHeaderSize]byte
	prevSeq := es.lastRecvSeq.Load()

	for {
		if ctx.Err() != nil {
			return
		}

		es.mu.Lock()
		conn := es.conn
		es.mu.Unlock()
		if conn == nil {
			return
		}

		// Set a read deadline so we can check ctx cancellation periodically.
		// If the deadline fires with no data (idle helper), just loop back.
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read frame header.
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			if ctx.Err() != nil {
				return
			}
			// Timeout with no data is normal when the helper is idle.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			slog.Debug("event stream: read header error", "err", err)
			return
		}

		length := binary.LittleEndian.Uint32(hdr[0:4])
		typ := hdr[4]
		seq := binary.LittleEndian.Uint64(hdr[8:16])

		// Sanity check payload length (max 256 bytes for session events).
		if length > 1024 {
			slog.Warn("event stream: oversized frame", "length", length, "type", typ)
			es.DecodeErrors.Add(1)
			return
		}

		// Read payload.
		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				if ctx.Err() == nil {
					slog.Debug("event stream: read payload error", "err", err)
				}
				return
			}
		}

		es.FramesRead.Add(1)

		switch typ {
		case EventTypeSessionOpen, EventTypeSessionUpdate:
			delta, ok := decodeSessionEvent(payload)
			if !ok {
				es.DecodeErrors.Add(1)
				continue
			}
			if typ == EventTypeSessionOpen {
				delta.Event = "open"
			} else {
				delta.Event = "open" // updates treated as opens for sync
			}
			// Track sequence gaps.
			if seq > prevSeq+1 && prevSeq > 0 {
				es.SeqGaps.Add(1)
				slog.Debug("event stream: sequence gap", "expected", prevSeq+1, "got", seq)
			}
			prevSeq = seq
			es.lastRecvSeq.Store(seq)
			es.ackBatch.Add(1)
			if es.onEvent != nil {
				es.onEvent(typ, seq, delta)
			}
			es.lastAppliedSeq.Store(seq)

		case EventTypeSessionClose:
			delta, ok := decodeSessionCloseEvent(payload)
			if !ok {
				es.DecodeErrors.Add(1)
				continue
			}
			delta.Event = "close"
			if seq > prevSeq+1 && prevSeq > 0 {
				es.SeqGaps.Add(1)
			}
			prevSeq = seq
			es.lastRecvSeq.Store(seq)
			es.ackBatch.Add(1)
			if es.onEvent != nil {
				es.onEvent(typ, seq, delta)
			}
			es.lastAppliedSeq.Store(seq)

		case EventTypeDrainComplete:
			select {
			case es.drainCompleteCh <- seq:
			default:
			}

		case EventTypeFullResync:
			slog.Warn("event stream: full resync requested by helper")
			if es.onFullResync != nil {
				es.onFullResync()
			}

		case EventTypeKeepalive:
			// Idle heartbeat from helper — no action needed, just keeps
			// the connection alive to prevent read-deadline disconnect.

		case EventTypePolicyDeny, EventTypeScreenDrop, EventTypeFilterLog:
			if !dataplaneEventPayloadMatchesFrame(typ, payload) {
				es.DecodeErrors.Add(1)
				es.recordDataplaneEventDrop(typ)
				es.markDroppedFrameApplied(seq, &prevSeq)
				continue
			}
			rec, ok := decodeDataplaneEventPayload(payload)
			if !ok {
				es.DecodeErrors.Add(1)
				es.recordDataplaneEventDrop(typ)
				es.markDroppedFrameApplied(seq, &prevSeq)
				continue
			}
			if seq > prevSeq+1 && prevSeq > 0 {
				es.SeqGaps.Add(1)
				slog.Debug("event stream: sequence gap", "expected", prevSeq+1, "got", seq)
			}
			prevSeq = seq
			es.lastRecvSeq.Store(seq)
			es.ackBatch.Add(1)
			if es.onRawDataplaneEvent != nil {
				es.onRawDataplaneEvent(seq, payload)
			} else if es.onDataplaneEvent != nil {
				es.onDataplaneEvent(seq, rec)
			}
			es.recordDataplaneEvent(typ)
			es.lastAppliedSeq.Store(seq)

		default:
			es.UnknownFrameDrops.Add(1)
			es.markDroppedFrameApplied(seq, &prevSeq)
			slog.Debug("event stream: dropped unknown frame type", "type", typ, "seq", seq)
		}
	}
}

func (es *EventStream) markDroppedFrameApplied(seq uint64, prevSeq *uint64) {
	if seq > *prevSeq+1 && *prevSeq > 0 {
		es.SeqGaps.Add(1)
	}
	*prevSeq = seq
	es.lastRecvSeq.Store(seq)
	es.ackBatch.Add(1)
	es.lastAppliedSeq.Store(seq)
}

func (es *EventStream) recordDataplaneEvent(typ uint8) {
	switch typ {
	case EventTypePolicyDeny:
		es.PolicyDenyEvents.Add(1)
	case EventTypeScreenDrop:
		es.ScreenDropEvents.Add(1)
	case EventTypeFilterLog:
		es.FilterLogEvents.Add(1)
	}
}

func (es *EventStream) recordDataplaneEventDrop(typ uint8) {
	switch typ {
	case EventTypePolicyDeny:
		es.PolicyDenyDrops.Add(1)
	case EventTypeScreenDrop:
		es.ScreenDropDrops.Add(1)
	case EventTypeFilterLog:
		es.FilterLogDrops.Add(1)
	default:
		es.UnknownFrameDrops.Add(1)
	}
}

// ackLoop periodically sends Ack frames to the helper with the highest
// consumed sequence number.
func (es *EventStream) ackLoop(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		es.sendAckIfNeeded()
	}
}

// sendAckIfNeeded sends an Ack if new events have been received since the last ack.
func (es *EventStream) sendAckIfNeeded() {
	applied := es.lastAppliedSeq.Load()
	acked := es.lastAckSeq.Load()
	if applied <= acked {
		return
	}
	if err := es.writeFrame(EventTypeAck, applied, nil); err != nil {
		slog.Debug("event stream: ack write error", "err", err)
		return
	}
	es.lastAckSeq.Store(applied)
	es.ackBatch.Store(0)
}

// writeFrame writes a single binary frame to the helper connection.
func (es *EventStream) writeFrame(typ uint8, seq uint64, payload []byte) error {
	es.mu.Lock()
	conn := es.conn
	es.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("event stream not connected")
	}

	var hdr [EventFrameHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	hdr[4] = typ
	// hdr[5:8] reserved, zero
	binary.LittleEndian.PutUint64(hdr[8:16], seq)

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))

	if len(payload) == 0 {
		_, err := conn.Write(hdr[:])
		if err == nil {
			es.FramesWritten.Add(1)
		}
		return err
	}

	// Write header + payload together to minimize syscalls.
	buf := make([]byte, EventFrameHeaderSize+len(payload))
	copy(buf, hdr[:])
	copy(buf[EventFrameHeaderSize:], payload)
	_, err := conn.Write(buf)
	if err == nil {
		es.FramesWritten.Add(1)
	}
	return err
}

// ---------------------------------------------------------------------------
// Binary payload decoders
// ---------------------------------------------------------------------------

// decodeSessionEvent decodes a SessionOpen or SessionUpdate binary payload
// into a SessionDeltaInfo.
//
// Wire layout (v4, 56 bytes):
//
//	[0]     AddrFamily (4=v4, 6=v6)
//	[1]     Protocol
//	[2:4]   SrcPort (uint16 LE)
//	[4:6]   DstPort (uint16 LE)
//	[6:8]   NATSrcPort (uint16 LE)
//	[8:10]  NATDstPort (uint16 LE)
//	[10:12] OwnerRGID (int16 LE)
//	[12:14] EgressIfindex (int16 LE)
//	[14:16] TXIfindex (int16 LE)
//	[16:18] TunnelEndpointID (uint16 LE)
//	[18:20] TXVLANID (uint16 LE)
//	[20]    Flags
//	[21]    IngressZoneID
//	[22]    EgressZoneID
//	[23]    Disposition
//	[24..]  IPs (4 bytes each for v4, 16 each for v6): src, dst, nat_src, nat_dst
//	[N..]   NeighborMAC (6 bytes)
//	[N+6..] SrcMAC (6 bytes)
//	[N+12..]NextHop (4 or 16 bytes)
//
// wireAFToDataplane maps the 1-byte wire encoding (4 = IPv4, 6 = IPv6
// — chosen by the Rust codec to match the protocol number; see
// userspace-dp/src/event_stream/codec.rs:88) to the Linux dataplane
// constants used throughout the Go side (`AFInet` = 2, `AFInet6` = 10).
// Returns 0 for unknown values; callers reject 0.
func wireAFToDataplane(wire uint8) uint8 {
	switch wire {
	case 4:
		return dataplane.AFInet
	case 6:
		return dataplane.AFInet6
	}
	return 0
}

func decodeSessionEvent(payload []byte) (SessionDeltaInfo, bool) {
	if len(payload) < 24 {
		return SessionDeltaInfo{}, false
	}

	af := payload[0]
	var addrSize int
	switch af {
	case 4:
		addrSize = 4
	case 6:
		addrSize = 16
	default:
		return SessionDeltaInfo{}, false
	}

	// Fixed header (24 bytes) + 4*addrSize + 6+6 + addrSize = 24 + 5*addrSize + 12
	minLen := 24 + 5*addrSize + 12
	if len(payload) < minLen {
		return SessionDeltaInfo{}, false
	}

	flags := payload[20]

	// #919/#922: normalise the wire AF (4/6) to the dataplane AF
	// constants (2/10) consumed by daemon_ha_userspace.go's switch.
	dpAF := wireAFToDataplane(af)
	if dpAF == 0 {
		return SessionDeltaInfo{}, false
	}

	d := SessionDeltaInfo{
		AddrFamily:       dpAF,
		Protocol:         payload[1],
		SrcPort:          binary.LittleEndian.Uint16(payload[2:4]),
		DstPort:          binary.LittleEndian.Uint16(payload[4:6]),
		NATSrcPort:       binary.LittleEndian.Uint16(payload[6:8]),
		NATDstPort:       binary.LittleEndian.Uint16(payload[8:10]),
		OwnerRGID:        int(int16(binary.LittleEndian.Uint16(payload[10:12]))),
		EgressIfindex:    int(int16(binary.LittleEndian.Uint16(payload[12:14]))),
		TXIfindex:        int(int16(binary.LittleEndian.Uint16(payload[14:16]))),
		TunnelEndpointID: binary.LittleEndian.Uint16(payload[16:18]),
		TXVLANID:         binary.LittleEndian.Uint16(payload[18:20]),
		// #919/#922: bytes [21]/[22] are u8 ingress/egress zone IDs
		// written by the Rust codec at event_stream/codec.rs:144-156.
		// Promote to uint16 for symmetry with SessionSyncRequest.
		IngressZoneID:  uint16(payload[21]),
		EgressZoneID:   uint16(payload[22]),
		FabricRedirect: flags&SessionEventFlagFabricRedirect != 0,
		FabricIngress:  flags&SessionEventFlagFabricIngress != 0,
	}

	// Disposition mapping: 0=Accept, 1=LocalDelivery
	switch payload[23] {
	case 1:
		d.Disposition = "local_delivery"
	}

	// IP addresses start at offset 24.
	off := 24
	d.SrcIP = formatIP(payload[off:off+addrSize], af)
	off += addrSize
	d.DstIP = formatIP(payload[off:off+addrSize], af)
	off += addrSize
	d.NATSrcIP = formatIP(payload[off:off+addrSize], af)
	off += addrSize
	d.NATDstIP = formatIP(payload[off:off+addrSize], af)
	off += addrSize

	// MACs.
	d.NeighborMAC = formatMAC(payload[off : off+6])
	off += 6
	d.SrcMAC = formatMAC(payload[off : off+6])
	off += 6

	// NextHop.
	d.NextHop = formatIP(payload[off:off+addrSize], af)

	return d, true
}

// decodeSessionCloseEvent decodes a SessionClose binary payload.
//
// Wire layout (v4):
//
//	[0]     AddrFamily
//	[1]     Protocol
//	[2:4]   SrcPort
//	[4:6]   DstPort
//	[6..]   SrcIP (4 or 16 bytes)
//	[N..]   DstIP (4 or 16 bytes)
//	[M:M+2] OwnerRGID (int16 LE)
//	[M+2]   Flags
func decodeSessionCloseEvent(payload []byte) (SessionDeltaInfo, bool) {
	if len(payload) < 6 {
		return SessionDeltaInfo{}, false
	}

	af := payload[0]
	var addrSize int
	switch af {
	case 4:
		addrSize = 4
	case 6:
		addrSize = 16
	default:
		return SessionDeltaInfo{}, false
	}

	// Legacy minimum: 6 (fixed) + 2*addrSize + 2 (OwnerRGID) + 1 (Flags).
	// New helpers append +2 (ZoneIDs); accept both for rolling upgrade.
	legacyMin := 6 + 2*addrSize + 3
	if len(payload) < legacyMin {
		return SessionDeltaInfo{}, false
	}

	dpAF := wireAFToDataplane(af)
	if dpAF == 0 {
		return SessionDeltaInfo{}, false
	}

	d := SessionDeltaInfo{
		AddrFamily: dpAF,
		Protocol:   payload[1],
		SrcPort:    binary.LittleEndian.Uint16(payload[2:4]),
		DstPort:    binary.LittleEndian.Uint16(payload[4:6]),
	}

	off := 6
	d.SrcIP = formatIP(payload[off:off+addrSize], af)
	off += addrSize
	d.DstIP = formatIP(payload[off:off+addrSize], af)
	off += addrSize
	d.OwnerRGID = int(int16(binary.LittleEndian.Uint16(payload[off : off+2])))
	off += 2
	flags := payload[off]
	off++
	d.FabricRedirect = flags&SessionEventFlagFabricRedirect != 0
	d.FabricIngress = flags&SessionEventFlagFabricIngress != 0
	// #919/#922: zone IDs are present iff the helper sent the +2-byte
	// trailer. Older helpers leave them as 0 and the daemon falls back
	// to the legacy zone-name string (empty for close events, which
	// drops the close, matching pre-#919 behavior on a malformed close).
	if len(payload) >= off+2 {
		d.IngressZoneID = uint16(payload[off])
		d.EgressZoneID = uint16(payload[off+1])
	}

	return d, true
}

// decodeDataplaneEventPayload decodes the canonical dataplane.Event RT_FLOW
// payload. Userspace-dp carries these bytes over event-stream frame types 11-13,
// but the payload itself is the same shape consumed by pkg/logging/ringbuf.go.
func decodeDataplaneEventPayload(payload []byte) (logging.EventRecord, bool) {
	return logging.DecodeRawEventRecord(payload)
}

func dataplaneEventPayloadMatchesFrame(typ uint8, payload []byte) bool {
	if len(payload) <= 52 {
		return false
	}
	var want uint8
	switch typ {
	case EventTypePolicyDeny:
		want = dataplane.EventTypePolicyDeny
	case EventTypeScreenDrop:
		want = dataplane.EventTypeScreenDrop
	case EventTypeFilterLog:
		want = dataplane.EventTypeFilterLog
	default:
		return false
	}
	return payload[52] == want
}

// formatIP converts raw IP bytes to a string representation.
func formatIP(b []byte, af uint8) string {
	if af == 4 {
		if len(b) < 4 {
			return ""
		}
		// Check if zero.
		if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
			return ""
		}
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	if len(b) < 16 {
		return ""
	}
	// Check if all zero.
	allZero := true
	for _, v := range b[:16] {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	ip := make(net.IP, 16)
	copy(ip, b[:16])
	return ip.String()
}

// formatMAC converts 6 raw bytes to a MAC address string, or "" if all zero.
func formatMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
