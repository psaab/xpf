package userspace

import (
	"context"
	"encoding/binary"
	"errors"
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
	"golang.org/x/sys/unix"
)

const pendingCallbackFramesLimit = 4096

// pendingDroppedMarkerType is the frame-type byte stamped on a #6558 dropped
// marker. Markers are dispatched by their `dropped` flag, never by type, so
// this only has to be a value that is NOT a live protocol frame type — a
// marker stamped with the refused frame's own type would look dispatchable in
// a log or a debugger. Zero is outside the allocated range (protocol_events.go
// starts at 1) and TestDroppedMarkerTypeIsNotALiveFrameType6558 keeps it that
// way: if 0 were ever allocated, a marker reaching the flush's type switch
// would be dispatched as real traffic.
const pendingDroppedMarkerType uint8 = 0
const callbackNotReadyBackoff = 100 * time.Millisecond

type pendingCallbackFrame struct {
	typ              uint8
	seq              uint64
	sessionDelta     SessionDeltaInfo
	dataplanePayload []byte
	dataplaneRecord  logging.EventRecord

	// dropped marks a frame that will never be applied — an undecodable,
	// oversized or unknown-type frame the reader refused (#6130/#6132/#6160).
	// It carries no callback; the flush simply advances the watermark past it
	// IN ORDER (#6558). See markDroppedFrameApplied for why a refused frame
	// has to enter the queue at all.
	dropped bool
}

// EventStream manages the daemon-side event socket for receiving session events
// from the Rust helper over a persistent binary-framed Unix stream.
//
// The daemon creates the listener socket before spawning the helper. The helper
// dials on startup. A single connection is active at a time. If the helper
// disconnects, the accept loop waits for reconnection.
type EventStream struct {
	socketPath string

	lifecycleMu sync.Mutex
	listener    net.Listener
	socketLock  *os.File
	ownsSocket  bool

	mu   sync.Mutex
	conn net.Conn // current helper connection; nil when disconnected

	// writeMu serializes the SetWriteDeadline+Write pair inside writeFrame so
	// two concurrent frame writers (ackLoop's 100ms ticker vs a SendPause /
	// SendResume / SendDrainRequest transition) cannot interleave their
	// deadline set and write on the same conn (#4835). It is deliberately a
	// SEPARATE lock from mu: mu guards connection lifecycle (Close, the
	// acceptLoop conn swap, readLoop's conn read) and must NOT be held across
	// a potentially slow/blocked socket write, so widening mu to cover the
	// write is not an option.
	writeMu sync.Mutex

	// listening is TRUE once net.Listen on the event socket succeeded in
	// Start(), and FALSE again after Close(). It records whether the daemon
	// can ACCEPT session deltas from a helper — the local listener is bound —
	// which is distinct from `connected` below (a helper has dialed in). HA
	// takeover-readiness gates on this: a node whose delta channel never bound
	// must not advertise itself able to feed a standby after failover (#5273).
	listening atomic.Bool

	connected atomic.Bool
	paused    atomic.Bool

	// Sequence tracking.
	lastRecvSeq    atomic.Uint64
	lastAppliedSeq atomic.Uint64 // advanced only after onEvent() completes
	lastAckSeq     atomic.Uint64
	ackBatch       atomic.Uint64 // events since last ack

	// Callbacks are invoked on the reader goroutine and may be updated
	// dynamically by control-plane code.
	callbackMu          sync.RWMutex
	onEvent             func(eventType uint8, seq uint64, delta SessionDeltaInfo) bool
	onDataplaneEvent    func(seq uint64, rec logging.EventRecord)
	onRawDataplaneEvent func(seq uint64, payload []byte)
	onFullResync        func() bool

	pendingFlushMu        sync.Mutex
	pendingMu             sync.Mutex
	pendingCallbackFrames []pendingCallbackFrame

	// DrainComplete signaling for demotion prep.
	drainCompleteMu sync.Mutex
	drainCompleteCh chan uint64

	// Stats.
	FramesRead    atomic.Uint64
	FramesWritten atomic.Uint64
	DecodeErrors  atomic.Uint64
	SeqGaps       atomic.Uint64
	// SessionSyncResyncs counts how many times a full bulk re-export was forced
	// by a correctness-critical session-sync frame (open/close/update): either a
	// sequence gap (#2874) or a COMPLETE-but-undecodable frame (#5483/#6130).
	// Distinct from SeqGaps, which also counts benign gaps on telemetry frames
	// (which do NOT force a resync). A growing value means the helper's lossy
	// producer is dropping session deltas under channel backpressure, or its
	// encoder is emitting frames this daemon cannot decode (a codec bug /
	// version-skewed helper).
	SessionSyncResyncs atomic.Uint64
	// DecodeResyncSuppressed counts undecodable SESSION frames whose watermark
	// was advanced past (loop-break, #6130) but whose full-resync trigger was
	// rate-limited (a prior decode-failure resync fired within
	// decodeFailureResyncInterval). A large value alongside SessionSyncResyncs
	// staying small is the signature of a PERSISTENTLY-undecodable stream that
	// the rate-limiter is throttling — the resync/reconnect loop the naive
	// #5483 fix would have produced, now bounded.
	DecodeResyncSuppressed atomic.Uint64
	// lastDecodeResyncNanos is the wall-clock nanosecond timestamp of the last
	// FIRED decode-failure resync. It rate-limits both the onFullResync trigger
	// (shared control socket — must not be hammered, per CLAUDE.md) and the WARN
	// log so a persistently-undecodable stream cannot flood either. The watermark
	// advance in handleSessionDecodeFailure is NOT gated by it — advancing on
	// every undecodable frame is what breaks the loop (#6130).
	lastDecodeResyncNanos atomic.Int64
	PolicyDenyEvents      atomic.Uint64
	ScreenDropEvents      atomic.Uint64
	ScreenAlarmEvents     atomic.Uint64 // screen event with action=PERMIT (#2298)
	FilterLogEvents       atomic.Uint64
	SessionCloseEvents    atomic.Uint64 // #2460: RT_FLOW SESSION_CLOSE frames
	SessionCreateEvents   atomic.Uint64 // #2508: RT_FLOW SESSION_CREATE frames
	PolicyDenyDrops       atomic.Uint64
	ScreenDropDrops       atomic.Uint64
	FilterLogDrops        atomic.Uint64
	SessionCloseDrops     atomic.Uint64 // #2460
	SessionCreateDrops    atomic.Uint64 // #2508
	UnknownFrameDrops     atomic.Uint64
}

// NewEventStream creates an EventStream for the given Unix socket path.
// Call Start() to begin listening.
func NewEventStream(socketPath string) *EventStream {
	return &EventStream{
		socketPath:      socketPath,
		drainCompleteCh: make(chan uint64, 1),
	}
}

// SetOnEvent sets the callback for session events. The callback returns true
// only after the delta is durably handled; false withholds ACK so the helper can
// replay instead of losing an event during readiness transitions.
func (es *EventStream) SetOnEvent(fn func(eventType uint8, seq uint64, delta SessionDeltaInfo) bool) {
	es.callbackMu.Lock()
	es.onEvent = fn
	es.callbackMu.Unlock()
	es.flushPendingCallbackFrames()
}

// SetOnDataplaneEvent sets the callback for RT_FLOW-style dataplane events.
func (es *EventStream) SetOnDataplaneEvent(fn func(seq uint64, rec logging.EventRecord)) {
	es.callbackMu.Lock()
	es.onDataplaneEvent = fn
	es.callbackMu.Unlock()
	es.flushPendingCallbackFrames()
}

// SetOnRawDataplaneEvent sets the callback for raw RT_FLOW dataplane events.
// It is preferred when the receiver can process the canonical dataplane.Event
// payload itself, because it preserves name resolution and syslog fanout.
func (es *EventStream) SetOnRawDataplaneEvent(fn func(seq uint64, payload []byte)) {
	es.callbackMu.Lock()
	es.onRawDataplaneEvent = fn
	es.callbackMu.Unlock()
	es.flushPendingCallbackFrames()
}

// SetOnFullResync sets the callback for full resync requests. The callback
// returns true only after the resync request has been acted on.
func (es *EventStream) SetOnFullResync(fn func() bool) {
	es.callbackMu.Lock()
	es.onFullResync = fn
	es.callbackMu.Unlock()
	es.flushPendingCallbackFrames()
}

func (es *EventStream) dataplaneCallbacks() (func(uint64, []byte), func(uint64, logging.EventRecord)) {
	es.callbackMu.RLock()
	defer es.callbackMu.RUnlock()
	raw := es.onRawDataplaneEvent
	decoded := es.onDataplaneEvent
	return raw, decoded
}

// Start creates the Unix socket listener and launches the accept loop.
//
// It returns an error when listener ownership or net.Listen fails
// (path-too-long, an active owner, permission, missing directory). A sidecar
// flock serializes owners; while holding it, Start removes only a socket whose
// kernel socket-table check proves it is a stale crash artifact. The failure is NOT
// swallowed: the event socket is the primary push channel over which the local
// helper streams
// post-bootstrap session open/close/update deltas to the daemon. Although the
// daemon can poll DrainSessionDeltas while the stream is disconnected, a node
// must not silently start in that degraded fallback state. The caller therefore
// treats a Start error as a failed bring-up rather than storing a
// non-nil-but-dead stream (#5273).
func (es *EventStream) Start(ctx context.Context) error {
	es.lifecycleMu.Lock()
	defer es.lifecycleMu.Unlock()
	if es.listener != nil || es.ownsSocket {
		return errors.New("event stream listener already started")
	}

	lockFile, err := acquireEventStreamSocketLock(es.socketPath)
	if err != nil {
		return err
	}
	releaseLock := true
	defer func() {
		if releaseLock {
			releaseEventStreamSocketLock(lockFile)
		}
	}()
	if err := removeStaleUnixSocket(socketKindEventStream, es.socketPath); err != nil {
		return err
	}

	ln, err := net.Listen("unix", es.socketPath)
	if err != nil {
		slog.Error("event stream: failed to listen", "path", es.socketPath, "err", err)
		return fmt.Errorf("event stream listen on %s: %w", es.socketPath, err)
	}
	// #9003: 0600 on the bound socket. Before this the mode was
	// 0777 &^ umask — an inherited value no code, unit file or test asserted, so
	// a `UMask=0000` in the unit (or any operator-set umask) silently made this
	// socket connectable by every local user with no signal anywhere. The
	// accept-side SO_PEERCRED gate below is the authoritative check; this is the
	// cheap layer that stops an unprivileged process from reaching it at all.
	if err := os.Chmod(es.socketPath, 0o600); err != nil {
		_ = ln.Close()
		slog.Error("event stream: failed to restrict socket mode", "path", es.socketPath, "err", err)
		return fmt.Errorf("event stream chmod %s: %w", es.socketPath, err)
	}
	es.listener = ln
	es.socketLock = lockFile
	es.ownsSocket = true
	releaseLock = false
	es.listening.Store(true)
	slog.Info("event stream: listening", "path", es.socketPath)
	go es.acceptLoop(ctx, ln)
	return nil
}

func acquireEventStreamSocketLock(socketPath string) (*os.File, error) {
	lockPath := socketPath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open event stream ownership lock %s: %w", lockPath, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire event stream ownership lock %s: %w", lockPath, err)
	}
	return f, nil
}

func releaseEventStreamSocketLock(f *os.File) {
	if f == nil {
		return
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}

// ListenerBound reports whether the event-stream listener socket successfully
// bound (net.Listen in Start() succeeded and Close() has not run). It is TRUE
// as soon as the daemon can receive the local helper's session deltas,
// independent of whether that helper has dialed in (that is IsConnected). HA
// takeover-readiness gates on ListenerBound, not IsConnected: transient stream
// disconnects use the DrainSessionDeltas polling fallback, while a listener
// that never bound is a failed dependency rather than an accepted startup
// state (#5273).
func (es *EventStream) ListenerBound() bool {
	return es.listening.Load()
}

// Close shuts down the listener and any active connection.
func (es *EventStream) Close() {
	es.lifecycleMu.Lock()
	es.listening.Store(false)
	if es.listener != nil {
		_ = es.listener.Close()
		es.listener = nil
	}
	es.mu.Lock()
	if es.conn != nil {
		_ = es.conn.Close()
		es.conn = nil
	}
	es.connected.Store(false)
	es.mu.Unlock()
	if es.ownsSocket {
		// Exempt from removeStaleUnixSocket (#5839): ownsSocket is set only
		// after THIS EventStream bound the path under the sidecar flock, so
		// ownership is already established and the liveness probe would be
		// meaningless — the listener it would find is the one just closed
		// above. The failure is reported rather than discarded so a socket
		// left behind is diagnosable at the next bring-up, which refuses to
		// unlink what it cannot prove stale.
		if err := os.Remove(es.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("event stream: removing own socket failed",
				"path", es.socketPath, "err", err)
		}
		es.ownsSocket = false
	}
	releaseEventStreamSocketLock(es.socketLock)
	es.socketLock = nil
	es.lifecycleMu.Unlock()
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
//
// RESERVED / DORMANT: this method has no production caller. The live graceful
// demotion path (Daemon.prepareUserspaceRGDemotionWithTimeout) synchronizes via
// SessionSync.WaitForPeerBarrier plus the continuous lossless event stream;
// bulk republish on loss-of-sync uses ExportOwnerRGSessions(rgIDs, 0) (an
// unbounded ground-truth snapshot) triggered by an event-stream FullResync, not
// by this seq-fenced drain. The pair is retained — fully tested and hardened by
// #2876/#2920 — for a possible future fenced-drain use. See
// docs/session-sync-architecture.md ("DrainRequest fence — RESERVED / DORMANT").
//
// The drain is only reported successful when the helper's DrainComplete seq has
// reached the target fence (the last fully-applied sequence at demotion time).
// A DrainComplete carrying seq < targetSeq means the helper timed out below the
// fence (#2876): the events after the fence have NOT been flushed to the peer,
// so demotion must NOT proceed. That case is returned as a hard error rather
// than silently accepted as success, which would cause HA session loss on the
// subsequent failover. A context expiry (helper never replied, or never reached
// the fence and so withheld DrainComplete) is likewise an error.
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
		if seq < targetSeq {
			// Fence not reached: the helper drained below the target
			// (timeout below fence). Treat as failure so demotion does
			// not proceed past an unflushed fence.
			return seq, fmt.Errorf("drain incomplete: helper acked seq %d below target %d", seq, targetSeq)
		}
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
		FramesRead:             es.FramesRead.Load(),
		FramesWritten:          es.FramesWritten.Load(),
		DecodeErrors:           es.DecodeErrors.Load(),
		SeqGaps:                es.SeqGaps.Load(),
		SessionSyncResyncs:     es.SessionSyncResyncs.Load(),
		DecodeResyncSuppressed: es.DecodeResyncSuppressed.Load(),
		PolicyDenyEvents:       es.PolicyDenyEvents.Load(),
		ScreenDropEvents:       es.ScreenDropEvents.Load(),
		ScreenAlarmEvents:      es.ScreenAlarmEvents.Load(),
		FilterLogEvents:        es.FilterLogEvents.Load(),
		SessionCloseEvents:     es.SessionCloseEvents.Load(),
		SessionCreateEvents:    es.SessionCreateEvents.Load(),
		PolicyDenyDrops:        es.PolicyDenyDrops.Load(),
		ScreenDropDrops:        es.ScreenDropDrops.Load(),
		FilterLogDrops:         es.FilterLogDrops.Load(),
		SessionCloseDrops:      es.SessionCloseDrops.Load(),
		SessionCreateDrops:     es.SessionCreateDrops.Load(),
		UnknownFrameDrops:      es.UnknownFrameDrops.Load(),
	}
}

// acceptLoop listens for helper connections. Only one is active at a time.
func (es *EventStream) acceptLoop(ctx context.Context, listener net.Listener) {
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Debug("event stream: accept error", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// #9003: prove the peer before letting it DISPLACE the current helper.
		// The block below closes es.conn and installs this connection as the
		// event source, so an unprivileged local process that connected here
		// disconnected the real helper AND became the thing feeding session
		// events into the control plane. Refuse and keep serving the old
		// connection.
		if err := verifyUnixPeerIsPrivileged("event stream socket", es.socketPath, conn); err != nil {
			slog.Error("event stream: refusing connection from an unprivileged peer",
				"path", es.socketPath, "err", err)
			_ = conn.Close()
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
		es.clearPendingCallbackFrames()
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

		// Sanity check payload length (max 256 bytes for session events). An
		// oversized declared length is a corrupt / framing-desynced frame. Do NOT
		// drop the connection forever (the pre-#6132 bare `return`): the helper's
		// Rust replay buffer re-sends a PRESENT frame verbatim on reconnect with no
		// gap self-heal barrier, so a persistently-oversized frame produced the same
		// drop -> reconnect -> replay storm #6130 fixed for the undecodable-decode
		// path. handleOversizedFrame recovers via a rate-limited resync instead.
		if length > 1024 {
			if !es.handleOversizedFrame(conn, length, typ, seq, &prevSeq) {
				return
			}
			continue
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
				// #5483/#6130: a COMPLETE but semantically undecodable
				// session-sync frame carries session state the standby needs,
				// so it forces a full resync — but UNLIKE a #2874 gap the frame
				// is PRESENT on the wire, so the watermark is advanced past it
				// (loop-break) and the connection kept alive. See
				// handleSessionDecodeFailure.
				if !es.handleSessionDecodeFailure(seq, &prevSeq) {
					es.backoffCallbackNotReady(ctx)
					return
				}
				continue
			}
			if typ == EventTypeSessionOpen {
				delta.Event = "open"
			} else {
				delta.Event = "open" // updates treated as opens for sync
			}
			// #2874: a gap on a correctness-critical session-sync frame is a
			// HARD sync break — the helper's lossy producer dropped a session
			// open/close (or the replay window was trimmed), so the peer's
			// session view may have silently diverged. Force a full bulk
			// re-export and reconnect from the last CONTIGUOUS ack instead of
			// dispatching this frame and cumulatively ACKing past the hole.
			if seq > prevSeq+1 && prevSeq > 0 {
				es.handleSessionSyncGap(prevSeq+1, seq)
				return
			}
			prevSeq = seq
			es.lastRecvSeq.Store(seq)
			if !es.dispatchOrQueueSessionFrame(typ, seq, delta) {
				es.backoffCallbackNotReady(ctx)
				return
			}

		case EventTypeSessionClose:
			delta, ok := decodeSessionCloseEvent(payload)
			if !ok {
				// #5483/#6130: see the SessionOpen/Update case — an undecodable
				// session CLOSE frame forces a resync and advances the watermark
				// past the present-but-undecodable frame (loop-break).
				if !es.handleSessionDecodeFailure(seq, &prevSeq) {
					es.backoffCallbackNotReady(ctx)
					return
				}
				continue
			}
			delta.Event = "close"
			// #2874: see the SessionOpen/Update case — a session-sync gap forces
			// a resync rather than ACKing past the missing close.
			if seq > prevSeq+1 && prevSeq > 0 {
				es.handleSessionSyncGap(prevSeq+1, seq)
				return
			}
			prevSeq = seq
			es.lastRecvSeq.Store(seq)
			if !es.dispatchOrQueueSessionFrame(typ, seq, delta) {
				es.backoffCallbackNotReady(ctx)
				return
			}

		case EventTypeDrainComplete:
			select {
			case es.drainCompleteCh <- seq:
			default:
			}

		case EventTypeFullResync:
			slog.Warn("event stream: full resync requested by helper")
			if !es.dispatchOrQueueFullResyncFrame(seq) {
				es.backoffCallbackNotReady(ctx)
				return
			}
			// #5362: the FullResync(S) barrier re-baselines the sequence — the
			// producer emits it in wire==seq order (#5361) and the next live
			// delta is S+1. Advance prevSeq (and the persistent watermark) so
			// that S+1 is contiguous and does NOT trip the session-sync gap
			// check (seq > prevSeq+1), which would otherwise force one spurious
			// reconnect on the active-traffic recovery path. This mirrors the
			// delta cases' prevSeq/lastRecvSeq advance; markFrameApplied already
			// ran inside dispatchOrQueueFullResyncFrame. Only the successful-
			// dispatch path advances here — the drop paths use
			// markDroppedFrameApplied, which advances prevSeq itself.
			prevSeq = seq
			es.lastRecvSeq.Store(seq)

		case EventTypeKeepalive:
			// Idle heartbeat from helper — no action needed, just keeps
			// the connection alive to prevent read-deadline disconnect.
			continue

		case EventFrameTypePolicyDeny, EventFrameTypeScreenDrop, EventFrameTypeFilterLog,
			EventFrameTypeSessionClose, EventFrameTypeSessionCreate:
			if !dataplaneEventPayloadMatchesFrame(typ, payload) {
				es.DecodeErrors.Add(1)
				es.recordDataplaneEventDrop(typ)
				if !es.markDroppedFrameApplied(seq, &prevSeq) {
					es.backoffCallbackNotReady(ctx)
					return
				}
				continue
			}
			rec, ok := decodeDataplaneEventPayload(payload)
			if !ok {
				es.DecodeErrors.Add(1)
				es.recordDataplaneEventDrop(typ)
				if !es.markDroppedFrameApplied(seq, &prevSeq) {
					es.backoffCallbackNotReady(ctx)
					return
				}
				continue
			}
			onRawDataplaneEvent, onDataplaneEvent := es.dataplaneCallbacks()
			if seq > prevSeq+1 && prevSeq > 0 {
				es.SeqGaps.Add(1)
				slog.Debug("event stream: sequence gap", "expected", prevSeq+1, "got", seq)
			}
			prevSeq = seq
			es.lastRecvSeq.Store(seq)
			if !es.dispatchOrQueueDataplaneFrame(typ, seq, payload, rec, onRawDataplaneEvent, onDataplaneEvent) {
				es.backoffCallbackNotReady(ctx)
				return
			}

		default:
			es.UnknownFrameDrops.Add(1)
			if !es.markDroppedFrameApplied(seq, &prevSeq) {
				es.backoffCallbackNotReady(ctx)
				return
			}
			slog.Debug("event stream: dropped unknown frame type", "type", typ, "seq", seq)
		}
	}
}

// markDroppedFrameApplied performs the LOOP-BREAK for a frame the reader
// refused: it advances the receive watermark past the frame so the gap detector
// does not re-fire on it and the helper is not asked to replay something that
// would only be refused again (#6130/#6132/#6160).
//
// #6558: the ACK watermark is a DURABILITY claim, and it must not overtake the
// pending-apply queue. `dispatchOrQueue*` returns true after a successful
// ENQUEUE, so the reader keeps reading with frames still queued unapplied. A
// refused frame arriving behind them used to call markFrameApplied directly,
// which advanced lastAppliedSeq — and therefore the cumulative ACK — PAST
// deltas that had not been applied. The helper trims its replay buffer on
// `front.seq <= acked` and the daemon discards its pending queue on the next
// accept, so those deltas were unrecoverable. The three prior refusal fixes each
// reasoned about the refused frame ITSELF and were correct for it; none of them
// reasoned about frames still queued BEHIND it, because the queue did not exist
// yet when the first was written.
//
// So a refusal that lands while the queue is non-empty ENTERS the queue as a
// dropped marker and its watermark advance happens in FIFO order, exactly like
// an applied frame. The loop-break is unaffected — prevSeq and lastRecvSeq still
// move immediately, so nothing re-fires the gap detector and nothing is
// re-requested.
//
// Returns false only when the queue is full, matching the dispatchOrQueue*
// contract: the caller closes the stream so the helper replays from a watermark
// that is still honest.
func (es *EventStream) markDroppedFrameApplied(seq uint64, prevSeq *uint64) bool {
	if seq > *prevSeq+1 && *prevSeq > 0 {
		es.SeqGaps.Add(1)
	}
	*prevSeq = seq
	es.lastRecvSeq.Store(seq)

	return es.applyRefusedFrameInOrder(seq)
}

// applyRefusedFrameInOrder advances the ACK watermark past a frame the reader
// refused, BEHIND anything still queued unapplied (#6558).
//
// It is deliberately separate from the loop-break bookkeeping each caller does
// (prevSeq / lastRecvSeq / SeqGaps): those differ per refusal site — the
// session-decode path does not count a gap where the telemetry path does — and
// folding them together here would silently change the gap accounting on two of
// the three sites. This helper owns exactly one property: the ACK watermark
// moves in FIFO order.
//
// Returns false only when the pending queue is full, matching the
// dispatchOrQueue* contract: the caller closes the stream so the helper replays
// from a watermark that is still honest.
func (es *EventStream) applyRefusedFrameInOrder(seq uint64) bool {
	if es.hasPendingCallbackFrames() {
		if !es.enqueuePendingCallbackFrame(pendingCallbackFrame{
			typ:     pendingDroppedMarkerType,
			seq:     seq,
			dropped: true,
		}) {
			return false
		}
		es.flushPendingCallbackFrames()
		return true
	}
	es.markFrameApplied(seq)
	return true
}

// markFrameApplied advances the cumulative applied watermark.
//
// #6558: the advance is MONOTONIC. It was a bare Store, which let a later
// in-order flush REWIND the watermark below a value a drop path had already
// jumped it to — and a rewound lastAppliedSeq is silently swallowed by
// sendAckIfNeeded's `applied <= acked` guard and can regress
// SendDrainRequest's fence. Frames are applied in order on one goroutine, so
// the CAS is uncontended in practice; it is here so no future caller can
// reintroduce a rewind.
func (es *EventStream) markFrameApplied(seq uint64) {
	es.ackBatch.Add(1)
	for {
		cur := es.lastAppliedSeq.Load()
		if seq <= cur {
			return
		}
		if es.lastAppliedSeq.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// handleSessionSyncGap responds to a detected sequence gap on a
// correctness-critical session-sync frame (open/close/update) — the #2874 HA
// data-loss fix.
//
// A gap on the session-sync stream means the helper's lossy producer dropped a
// session open/close delta under channel backpressure (or the helper's replay
// window was trimmed), so the standby's session view may have silently
// diverged from the primary's table truth. This must NOT be treated like a
// telemetry gap (which is merely counted and the stream continues): doing so
// and then cumulatively ACKing `lastAppliedSeq` past the hole trims the
// helper's replay buffer over the missing delta, making it permanently
// unrecoverable until an unrelated full-sync runs.
//
// Recovery has two halves, both performed here:
//   - Trigger a full bulk re-export (onFullResync → handleEventStreamFullResync)
//     so the peer re-derives a complete session snapshot — the only path that
//     recovers a delta the producer dropped (it never entered the replay
//     buffer, so a plain replay cannot resend it).
//   - Do NOT advance lastAppliedSeq past the hole, and return to the caller so
//     the reader loop drops the connection. On reconnect the helper replays
//     from the last CONTIGUOUS ack and the sequence tracking resets cleanly.
//     The cumulative ACK therefore never moves past the missing sequence.
func (es *EventStream) handleSessionSyncGap(expected, got uint64) {
	es.SeqGaps.Add(1)
	es.SessionSyncResyncs.Add(1)
	slog.Warn("event stream: session-sync sequence gap; forcing full resync",
		"expected", expected, "got", got, "last_applied", es.lastAppliedSeq.Load())
	es.callbackMu.RLock()
	onFullResync := es.onFullResync
	es.callbackMu.RUnlock()
	if onFullResync != nil {
		// Best-effort: the reconnect below is the backstop. The helper's own
		// replay_buffered() also re-issues a FullResync when its window cannot
		// cover acked+1, so a missed trigger here still self-heals.
		onFullResync()
	}
}

// decodeFailureResyncInterval rate-limits BOTH the full-resync trigger and the
// WARN log emitted for a run of COMPLETE-but-undecodable SESSION frames. Under a
// persistent codec bug / version-skewed helper EVERY session frame is
// undecodable, so an un-throttled per-frame onFullResync would hammer the shared
// control socket (which CLAUDE.md forbids at >1/s) and flood the log. Kept
// comfortably above 1s. The watermark advance is NOT throttled by this.
const decodeFailureResyncInterval = 2 * time.Second

// handleSessionDecodeFailure responds to a COMPLETE but semantically
// undecodable session-sync frame (open/close/update) at seq — the #5483 HA
// data-loss fix, corrected for the #6130 resync/reconnect loop.
//
// A session frame whose length prefix was read in full but that the typed
// decoder rejects (short/malformed payload, unknown address family) still
// carries session state the standby needs. The pre-#5483 code skipped it with
// `es.DecodeErrors.Add(1); continue`, leaving prevSeq/lastAppliedSeq BELOW the
// hole; a subsequent lossy TELEMETRY frame then advanced the cumulative ACK
// PAST the undecodable session seq, the Rust replay buffer trimmed the
// never-applied frame, and the standby silently diverged.
//
// #5483 (b9cb3eb34) closed that by forcing a resync and NOT advancing the
// watermark — but that WEDGED the stream on a PERSISTENTLY-undecodable frame.
// The frame is PRESENT on the wire, not a #2874 gap: the Rust replay buffer
// (userspace-dp/src/event_stream/mod.rs) stores encoded frames and re-sends
// them VERBATIM. `replay_buffered` only parks a re-baselining FullResync barrier
// when a seq is ABSENT (`has_gap` == oldest_buffered > acked+1); a
// present-but-undecodable frame has NO such backstop. So withholding the ACK
// made the helper re-send the same frame on every reconnect: reconnect → replay
// N → decode fail → resync → drop → reconnect, an unbounded busy-loop hammering
// the control socket and flooding the log (worst case on a STANDBY, whose
// onFullResync is a corrective no-op — pure churn).
//
// #6130 breaks the loop by ADVANCING the watermark PAST the undecodable frame
// (markFrameApplied + prevSeq), unconditionally, on every undecodable frame.
// sendAckIfNeeded then ACKs past seq, the helper trims it (`front.seq <=
// acked`), and it is NEVER re-sent. The connection is KEPT (the caller
// `continue`s, mirroring the helper-initiated FullResync path #5362) because
// there is nothing to replay.
//
// Anti-divergence — why advancing past seq does NOT reintroduce the #5483 bug:
// we advance ONLY as part of triggering a FullResync that re-baselines the peer
// from TABLE TRUTH (onFullResync → handleEventStreamFullResync →
// ExportOwnerRGSessions, an UNBOUNDED ground-truth snapshot). For an undecodable
// OPEN the session is still in the helper's table, so the snapshot re-derives it
// — a strict superset of the lost frame's state. For an undecodable CLOSE the
// export cannot convey a delete (docs/session-sync-architecture.md #2880), so it
// degrades to the pre-existing "missed close → idle-GC self-heal" bounded
// staleness — NOT a permanent divergence. This is fundamentally unlike the
// pre-#5483 silent skip, which advanced past seq with NO resync at all.
//
// The resync trigger + log are RATE-LIMITED (decodeFailureResyncInterval). A
// single bad frame fires exactly one resync (the realistic non-catastrophic
// case). A persistent-skew stream fires at most one resync per interval and
// counts the rest in DecodeResyncSuppressed; each fired resync is a full
// snapshot, so the peer is re-baselined at ≤1 interval of staleness. A
// suppressed frame's session, if still live, is re-derived by the next fired
// resync (or its own subsequent decodable UPDATE, treated as an open). The fire
// is best-effort: the watermark advances even if onFullResync returns false or
// there is no callback, because breaking the loop is the hard guarantee and the
// periodic sweep reconcile + reconnect bulk sync are independent resync
// backstops.
//
// STANDBY: handleEventStreamFullResync early-returns "not primary" (a cheap
// no-op — it never reaches the control socket), so a standby that reads an
// undecodable session frame from its OWN helper still advances + rate-limits
// here and cannot spin. Advancing is divergence-safe on a standby anyway: a
// decoded session delta is itself a no-op there (handleEventStreamDelta drops it
// for a non-primary), so nothing is lost by skipping the undecodable one.
//
// Scope: SESSION frames ONLY. A decode failure on a lossy TELEMETRY/stats frame
// stays tolerable to skip (DecodeErrors + drop-counter + markDroppedFrameApplied)
// — telemetry carries no HA session state.
func (es *EventStream) handleSessionDecodeFailure(seq uint64, prevSeq *uint64) bool {
	es.DecodeErrors.Add(1)

	// Rate-limited resync trigger + WARN. Fire BEFORE advancing the watermark so
	// the table-truth snapshot is triggered while lastAppliedSeq still sits below
	// the hole — the ACK only moves past seq after this returns.
	es.triggerRateLimitedResync("undecodable session-sync frame", seq)

	// Loop-break (#6130): advance PAST the present-but-undecodable frame
	// unconditionally so the cumulative ACK trims it from the helper's replay
	// buffer and it is never re-sent. Byte-identical to the pre-#6558 lines —
	// this path deliberately does NOT count a SeqGap, and routing it through
	// markDroppedFrameApplied (which does) would have changed that.
	*prevSeq = seq
	es.lastRecvSeq.Store(seq)

	// #6558: the watermark advance goes behind anything still queued unapplied.
	// Returns false only on a full queue, which the caller turns into a stream
	// close so the helper replays from an honest watermark.
	return es.applyRefusedFrameInOrder(seq)
}

// triggerRateLimitedResync fires a full resync (onFullResync) plus a WARN for a
// REFUSED correctness-critical session-sync frame — an undecodable frame
// (#6130) or an oversized/framing-desynced frame (#6132). The trigger and log
// are rate-limited by decodeFailureResyncInterval off the shared
// lastDecodeResyncNanos timestamp so a persistently-bad stream cannot hammer the
// shared control socket (CLAUDE.md forbids >1/s) or flood the log: a fired call
// bumps SessionSyncResyncs and re-baselines the peer from table truth; a
// suppressed call bumps DecodeResyncSuppressed. The caller is responsible for
// the loop-break (advancing the watermark past the refused frame) — this only
// performs the shared, rate-limited resync side.
func (es *EventStream) triggerRateLimitedResync(reason string, seq uint64) {
	nowNanos := time.Now().UnixNano()
	last := es.lastDecodeResyncNanos.Load()
	if last == 0 || nowNanos-last >= int64(decodeFailureResyncInterval) {
		es.lastDecodeResyncNanos.Store(nowNanos)
		es.SessionSyncResyncs.Add(1)
		slog.Warn("event stream: "+reason+"; forcing rate-limited full resync",
			"seq", seq, "last_applied", es.lastAppliedSeq.Load())
		es.callbackMu.RLock()
		onFullResync := es.onFullResync
		es.callbackMu.RUnlock()
		if onFullResync != nil {
			onFullResync()
		}
	} else {
		es.DecodeResyncSuppressed.Add(1)
	}
}

// maxDiscardableOversizedFrameBytes bounds how many payload bytes the reader will
// read-and-discard to skip past an oversized-but-well-framed frame and re-align
// on the next header (#6132). The helper writes atomic, correctly-length-
// prefixed frames whose largest legitimate payload is a session event (<=256B),
// so the 1024 guard already flags anything larger as corrupt / over-max. A
// declared length still within this ceiling is trusted as a real frame boundary
// (a version-skewed / buggy encoder emitting an over-max but correctly-prefixed
// frame): the reader discards exactly that many bytes on the live connection.
// A declared length ABOVE this ceiling is NOT trusted to re-align the byte stream
// (draining it could block the reader on a desynced / pathologically-large
// length), so the reader drops the connection to re-establish framing on
// reconnect rather than discarding blindly.
const maxDiscardableOversizedFrameBytes = 64 * 1024

// handleOversizedFrame recovers from an oversized / framing-desynced frame
// (declared length > the 1024 sanity bound) WITHOUT the pre-#6132
// drop-the-connection-forever replay loop — the framing-path analog of the
// #6130 undecodable-decode fix.
//
// The pre-#6132 guard did a bare `return`, dropping the connection on any
// declared length > 1024. Because the helper's Rust replay buffer re-sends a
// PRESENT frame verbatim on reconnect (no `has_gap` self-heal barrier for a
// present-but-corrupt frame — the exact pathology #6130 fixed for the
// undecodable path), a persistently-oversized / framing-corrupt frame at seq N
// produced a deterministic drop -> reconnect -> replay -> drop storm that
// hammered the shared control socket and flooded the log.
//
// The helper writes whole `[header|payload]` frames and the reader consumes
// exactly `length` payload bytes per frame, so the header (and thus this frame's
// `seq`/`typ`) stays aligned frame-to-frame and is trustworthy; only the payload
// SIZE is anomalous. Recovery mirrors #6130 and preserves the security posture —
// the corrupt frame is NEVER decoded or applied, it is REFUSED and superseded by
// a resync:
//   - Trigger a rate-limited full resync so the peer is re-baselined from table
//     truth (onFullResync -> ExportOwnerRGSessions, an unbounded ground-truth
//     snapshot), superseding whatever the refused frame carried.
//   - Advance the sequence watermark PAST this frame so the helper's cumulative
//     ACK trims it and it is NOT re-sent verbatim — the loop-break.
//
// The byte-stream re-alignment differs by trust in the LENGTH:
//   - length <= maxDiscardableOversizedFrameBytes: the frame boundary is trusted;
//     discard exactly `length` bytes to land on the next header and KEEP the
//     connection (returns true -> caller `continue`s). No drop.
//   - length above the ceiling, or a failed drain (short / desynced stream): the
//     length is not trusted to re-align the byte stream, so flush the advanced
//     ACK (so the helper trims the frame) and drop the connection (returns false
//     -> caller returns) to re-establish framing cleanly on reconnect. The
//     advance + flushed ACK make the drop bounded — the frame is trimmed, not
//     replayed into another drop.
func (es *EventStream) handleOversizedFrame(conn net.Conn, length uint32, typ uint8, seq uint64, prevSeq *uint64) bool {
	slog.Warn("event stream: oversized frame", "length", length, "type", typ, "seq", seq)
	es.DecodeErrors.Add(1)
	es.triggerRateLimitedResync("oversized/framing-desync frame", seq)

	// LOOP-BREAK (#6160): advance the watermark PAST this frame so the helper
	// trims it and never re-sends it verbatim. Without the advance the helper
	// never trims, re-sends on reconnect, and the reader drops again — a
	// permanent reconnect with no forward progress. That is why the advance is
	// unconditional, and `Test_oversized_session_frame_over_ceiling_drops_and_
	// flushes_ack_6160` pins it deliberately rather than incidentally.
	//
	// WHERE THE SAFETY ACTUALLY COMES FROM (#8597 K80). This comment used to
	// justify the advance as "its aligned-header seq is trustworthy". That
	// claim is FALSE on one of the two paths below: the branch that finds
	// `length > maxDiscardableOversizedFrameBytes` has, by its own reasoning,
	// just concluded the byte stream is DESYNCED — and a desynced stream's
	// "header" is not a header, so its seq is whatever the payload bytes
	// happened to be. The advance is safe anyway, but for a reason that lives
	// in another component and another language, which is why the local claim
	// was worth removing rather than repairing:
	//
	//   - The HELPER validates every ACK before acting on it (#2959,
	//     `userspace-dp/src/event_stream/control.rs`). A sequence outside
	//     [acked_seq, next_seq] — which a garbage seq overwhelmingly is —
	//     is IGNORED, the replay buffer is left intact, and it is counted on
	//     `frames_invalid_acks`. A poisoned watermark does not trim anything.
	//   - The daemon-side effect on `lastRecvSeq` is absorbed by the
	//     rate-limited full resync triggered above, which re-baselines from
	//     table truth rather than from the sequence space.
	//
	// THE RESIDUAL, stated so nobody has to rediscover it: a garbage seq that
	// happens to land INSIDE the live [acked_seq, next_seq] window is honoured
	// and trims frames the daemon has not applied. Narrow, not impossible, and
	// strictly smaller than the reconnect loop that removing the advance would
	// create — which is why #8597 K80 was refuted rather than fixed.
	//
	// If that residual is ever worth closing, the remedy is NEITHER "always
	// trust" nor "never trust" but a PLAUSIBILITY BOUND: a desynced seq is
	// arbitrary while a real one is adjacent to `prevSeq`, so advancing only on
	// a near-contiguous seq keeps #6160's loop-break and drops the poisoned
	// path. That changes a protocol liveness property and is a decision to be
	// taken deliberately, not a tidy-up to fold into an unrelated change.
	*prevSeq = seq
	es.lastRecvSeq.Store(seq)
	// #6558: the advance goes behind anything still queued unapplied, so the
	// ACK this function flushes on its drop path (below) cannot trim the
	// helper's replay buffer over a delta the daemon has not applied. A full
	// queue means the drop cannot be recorded in order at all, so drop the
	// connection WITHOUT flushing an ACK — the helper then replays from a
	// watermark that is still honest, which is the whole point.
	if !es.applyRefusedFrameInOrder(seq) {
		return false
	}

	// Oversized-but-well-framed: the declared length is a trusted frame boundary
	// (within the discard ceiling). Drain exactly that many bytes to re-align on
	// the next header and KEEP the connection.
	if length <= maxDiscardableOversizedFrameBytes {
		if _, err := io.CopyN(io.Discard, conn, int64(length)); err == nil {
			return true
		}
		// Drain failed (short / desynced stream) — fall through to the drop path
		// below to re-establish framing on reconnect.
	}

	// Genuine framing desync (untrusted length, or a failed drain): re-establish
	// framing by dropping the connection. Flush the advanced ACK first so the
	// helper trims the frame — the drop is bounded, not a replay loop.
	es.sendAckIfNeeded()
	return false
}

func (es *EventStream) backoffCallbackNotReady(ctx context.Context) {
	timer := time.NewTimer(callbackNotReadyBackoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (es *EventStream) dispatchOrQueueSessionFrame(typ uint8, seq uint64, delta SessionDeltaInfo) bool {
	es.callbackMu.RLock()
	onEvent := es.onEvent
	es.callbackMu.RUnlock()
	if onEvent == nil || es.hasPendingCallbackFrames() {
		if !es.enqueuePendingCallbackFrame(pendingCallbackFrame{
			typ:          typ,
			seq:          seq,
			sessionDelta: delta,
		}) {
			return false
		}
		es.flushPendingCallbackFrames()
		return true
	}
	if !onEvent(typ, seq, delta) {
		return es.enqueuePendingCallbackFrame(pendingCallbackFrame{
			typ:          typ,
			seq:          seq,
			sessionDelta: delta,
		})
	}
	es.markFrameApplied(seq)
	return true
}

func (es *EventStream) dispatchOrQueueFullResyncFrame(seq uint64) bool {
	es.callbackMu.RLock()
	onFullResync := es.onFullResync
	es.callbackMu.RUnlock()
	if onFullResync == nil || es.hasPendingCallbackFrames() {
		if !es.enqueuePendingCallbackFrame(pendingCallbackFrame{
			typ: EventTypeFullResync,
			seq: seq,
		}) {
			return false
		}
		es.flushPendingCallbackFrames()
		return true
	}
	if !onFullResync() {
		return es.enqueuePendingCallbackFrame(pendingCallbackFrame{
			typ: EventTypeFullResync,
			seq: seq,
		})
	}
	es.markFrameApplied(seq)
	return true
}

func (es *EventStream) dispatchOrQueueDataplaneFrame(
	typ uint8,
	seq uint64,
	payload []byte,
	rec logging.EventRecord,
	onRawDataplaneEvent func(uint64, []byte),
	onDataplaneEvent func(uint64, logging.EventRecord),
) bool {
	if onRawDataplaneEvent == nil && onDataplaneEvent == nil || es.hasPendingCallbackFrames() {
		if !es.enqueuePendingCallbackFrame(pendingCallbackFrame{
			typ:              typ,
			seq:              seq,
			dataplanePayload: append([]byte(nil), payload...),
			dataplaneRecord:  rec,
		}) {
			return false
		}
		es.flushPendingCallbackFrames()
		return true
	}
	if onRawDataplaneEvent != nil {
		onRawDataplaneEvent(seq, payload)
	} else {
		onDataplaneEvent(seq, rec)
	}
	es.recordDataplaneEvent(typ, dataplaneEventAction(payload))
	es.markFrameApplied(seq)
	return true
}

func (es *EventStream) hasPendingCallbackFrames() bool {
	es.pendingMu.Lock()
	defer es.pendingMu.Unlock()
	return len(es.pendingCallbackFrames) > 0
}

func (es *EventStream) enqueuePendingCallbackFrame(frame pendingCallbackFrame) bool {
	es.pendingMu.Lock()
	defer es.pendingMu.Unlock()
	if len(es.pendingCallbackFrames) >= pendingCallbackFramesLimit {
		slog.Error("event stream: pending callback queue full; closing helper stream to force replay",
			"limit", pendingCallbackFramesLimit, "type", frame.typ, "seq", frame.seq)
		return false
	}
	es.pendingCallbackFrames = append(es.pendingCallbackFrames, frame)
	return true
}

func (es *EventStream) clearPendingCallbackFrames() {
	es.pendingFlushMu.Lock()
	defer es.pendingFlushMu.Unlock()
	es.pendingMu.Lock()
	es.pendingCallbackFrames = nil
	es.pendingMu.Unlock()
}

func (es *EventStream) flushPendingCallbackFrames() {
	es.pendingFlushMu.Lock()
	defer es.pendingFlushMu.Unlock()

	for {
		es.pendingMu.Lock()
		if len(es.pendingCallbackFrames) == 0 {
			es.pendingMu.Unlock()
			return
		}
		frame := es.pendingCallbackFrames[0]
		es.pendingMu.Unlock()

		// #6558: a dropped marker has no callback. It exists only to hold the
		// ACK watermark's place in FIFO order, so it "applies" unconditionally
		// — including when no callback is wired, which is exactly the state
		// that queued the frames ahead of it.
		if frame.dropped {
			es.markFrameApplied(frame.seq)
			es.pendingMu.Lock()
			if len(es.pendingCallbackFrames) > 0 && es.pendingCallbackFrames[0].seq == frame.seq {
				copy(es.pendingCallbackFrames, es.pendingCallbackFrames[1:])
				es.pendingCallbackFrames = es.pendingCallbackFrames[:len(es.pendingCallbackFrames)-1]
			}
			es.pendingMu.Unlock()
			continue
		}

		switch frame.typ {
		case EventTypeSessionOpen, EventTypeSessionUpdate, EventTypeSessionClose:
			es.callbackMu.RLock()
			onEvent := es.onEvent
			es.callbackMu.RUnlock()
			if onEvent == nil {
				return
			}
			if !onEvent(frame.typ, frame.seq, frame.sessionDelta) {
				return
			}
		case EventTypeFullResync:
			es.callbackMu.RLock()
			onFullResync := es.onFullResync
			es.callbackMu.RUnlock()
			if onFullResync == nil {
				return
			}
			if !onFullResync() {
				return
			}
		case EventFrameTypePolicyDeny, EventFrameTypeScreenDrop, EventFrameTypeFilterLog,
			EventFrameTypeSessionClose, EventFrameTypeSessionCreate:
			onRawDataplaneEvent, onDataplaneEvent := es.dataplaneCallbacks()
			if onRawDataplaneEvent == nil && onDataplaneEvent == nil {
				return
			}
			if onRawDataplaneEvent != nil {
				onRawDataplaneEvent(frame.seq, frame.dataplanePayload)
			} else {
				onDataplaneEvent(frame.seq, frame.dataplaneRecord)
			}
			es.recordDataplaneEvent(frame.typ, dataplaneEventAction(frame.dataplanePayload))
		default:
			slog.Warn("event stream: dropping unsupported pending callback frame",
				"type", frame.typ, "seq", frame.seq)
		}

		es.markFrameApplied(frame.seq)
		es.pendingMu.Lock()
		if len(es.pendingCallbackFrames) > 0 && es.pendingCallbackFrames[0].seq == frame.seq {
			copy(es.pendingCallbackFrames, es.pendingCallbackFrames[1:])
			es.pendingCallbackFrames = es.pendingCallbackFrames[:len(es.pendingCallbackFrames)-1]
		}
		es.pendingMu.Unlock()
	}
}

// recordDataplaneEvent accounts a successfully decoded dataplane event.
//
// Screen events are classified by BOTH frame type and action (#2298): the
// scan-table-pressure saturation alarm (#2234) is a screen event with
// action=PERMIT — the packet still forwards. It must NOT inflate the
// screen-DROP counter (that would mask real screen drops under exactly the
// condition the alarm fires) — it is accounted separately as a screen alarm.
// Only a screen event that actually dropped (action=DENY/REJECT) bumps
// ScreenDropEvents.
func (es *EventStream) recordDataplaneEvent(typ, action uint8) {
	switch typ {
	case EventFrameTypePolicyDeny:
		es.PolicyDenyEvents.Add(1)
	case EventFrameTypeScreenDrop:
		if action == dataplane.ActionPermit {
			es.ScreenAlarmEvents.Add(1)
		} else {
			es.ScreenDropEvents.Add(1)
		}
	case EventFrameTypeFilterLog:
		es.FilterLogEvents.Add(1)
	case EventFrameTypeSessionClose:
		es.SessionCloseEvents.Add(1)
	case EventFrameTypeSessionCreate:
		es.SessionCreateEvents.Add(1)
	}
}

func (es *EventStream) recordDataplaneEventDrop(typ uint8) {
	switch typ {
	case EventFrameTypePolicyDeny:
		es.PolicyDenyDrops.Add(1)
	case EventFrameTypeScreenDrop:
		es.ScreenDropDrops.Add(1)
	case EventFrameTypeFilterLog:
		es.FilterLogDrops.Add(1)
	case EventFrameTypeSessionClose:
		es.SessionCloseDrops.Add(1)
	case EventFrameTypeSessionCreate:
		es.SessionCreateDrops.Add(1)
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
		es.flushPendingCallbackFrames()
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

	// Build the complete frame before taking the write lock so no shared
	// state (only stack-local buf) is touched under it.
	var buf []byte
	if len(payload) == 0 {
		buf = hdr[:]
	} else {
		// Header + payload together to minimize syscalls.
		buf = make([]byte, EventFrameHeaderSize+len(payload))
		copy(buf, hdr[:])
		copy(buf[EventFrameHeaderSize:], payload)
	}

	// Serialize SetWriteDeadline+Write as one atomic unit per frame. Without
	// this, two concurrent writeFrame callers (ackLoop's ticker vs a Send*
	// state transition) could interleave their deadline set + write on the
	// same conn — a data race on the connection's write/deadline state and,
	// for a future per-call variable deadline, a "wrong deadline wins"
	// hazard (#4835). writeMu is held ONLY across the deadline+write, not
	// es.mu, so a slow write never stalls connection-lifecycle work.
	es.writeMu.Lock()
	defer es.writeMu.Unlock()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
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
// Wire layout (v4, 62 bytes):
//
//	[0]     AddrFamily (4=v4, 6=v6)
//	[1]     Protocol
//	[2:4]   SrcPort (uint16 LE)
//	[4:6]   DstPort (uint16 LE)
//	[6:8]   NATSrcPort (uint16 LE)
//	[8:10]  NATDstPort (uint16 LE)
//	[10:14] OwnerRGID (int32 LE)      — #2467: widened from int16
//	[14:18] EgressIfindex (int32 LE)  — #2467: widened from int16
//	[18:22] TXIfindex (int32 LE)      — #2467: widened from int16
//	[22:24] TunnelEndpointID (uint16 LE)
//	[24:26] TXVLANID (uint16 LE)
//	[26]    Flags
//	[27:29] IngressZoneID (uint16 LE)  — #3075: widened from u8
//	[29:31] EgressZoneID (uint16 LE)   — #3075: widened from u8
//	[31]    Disposition
//	[32..]  IPs (4 bytes each for v4, 16 each for v6): src, dst, nat_src, nat_dst
//	[N..]   NeighborMAC (6 bytes)
//	[N+6..] SrcMAC (6 bytes)
//	[N+12..]NextHop (4 or 16 bytes)
//	#3301 trailing firewall metadata (length-gated; absent on old helpers):
//	[+0:+4]  policy_id u32 LE          (#3056)
//	[+4:+8]  policy_counter_idx u32 LE (#3073)
//	[+8:+12] inactivity_timeout secs u32 LE (#3227 -> AppTimeout)
//
// #2467: the three identity fields at [10:22] were widened from signed
// 16-bit to signed 32-bit. Linux ifindexes are a full `int`; with the old
// i16 encoding an ifindex above 32767 wrapped negative. This is a breaking
// wire-format change — the Rust encoder (event_stream/codec.rs) and this
// decoder must be deployed together (they always are: one binary set).
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
	// #2467: fixed header was 30 bytes after widening the three identity fields
	// at [10:22] from int16 to int32. #3075: now 32 bytes after widening the two
	// zone fields at [27]/[28] from u8 to u16 (Disposition moved [29]->[31]).
	if len(payload) < 32 {
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

	// Fixed header (32 bytes, #3075) + 4*addrSize + 6+6 + addrSize
	// = 32 + 5*addrSize + 12.
	minLen := 32 + 5*addrSize + 12
	if len(payload) < minLen {
		return SessionDeltaInfo{}, false
	}

	flags := payload[26]

	// #919/#922: normalise the wire AF (4/6) to the dataplane AF
	// constants (2/10) consumed by daemon_ha_userspace.go's switch.
	dpAF := wireAFToDataplane(af)
	if dpAF == 0 {
		return SessionDeltaInfo{}, false
	}

	d := SessionDeltaInfo{
		AddrFamily: dpAF,
		Protocol:   payload[1],
		SrcPort:    binary.LittleEndian.Uint16(payload[2:4]),
		DstPort:    binary.LittleEndian.Uint16(payload[4:6]),
		NATSrcPort: binary.LittleEndian.Uint16(payload[6:8]),
		NATDstPort: binary.LittleEndian.Uint16(payload[8:10]),
		// #2467: int32 LE (was int16) — ifindexes are a full Linux int.
		OwnerRGID:        int(int32(binary.LittleEndian.Uint32(payload[10:14]))),
		EgressIfindex:    int(int32(binary.LittleEndian.Uint32(payload[14:18]))),
		TXIfindex:        int(int32(binary.LittleEndian.Uint32(payload[18:22]))),
		TunnelEndpointID: binary.LittleEndian.Uint16(payload[22:24]),
		TXVLANID:         binary.LittleEndian.Uint16(payload[24:26]),
		// #3075: bytes [27:29]/[29:31] are u16 LE ingress/egress zone IDs
		// written by the Rust codec (widened from the u8 [27]/[28] of #919/#922
		// so a stable name-hash zone id > 255 round-trips).
		IngressZoneID:  binary.LittleEndian.Uint16(payload[27:29]),
		EgressZoneID:   binary.LittleEndian.Uint16(payload[29:31]),
		FabricRedirect: flags&SessionEventFlagFabricRedirect != 0,
		FabricIngress:  flags&SessionEventFlagFabricIngress != 0,
		// #2785: per-policy log selection from the open-frame flags byte.
		LogSessionInit:  flags&SessionEventFlagLogSessionInit != 0,
		LogSessionClose: flags&SessionEventFlagLogSessionClose != 0,
		// #4565: NAT64 cross-family marker; drives the reverse-BIB rebuild on
		// the peer-promoted session (see the trailing snat_v4 decode below).
		Nat64: flags&SessionEventFlagNat64 != 0,
	}

	// Disposition mapping: 0=Accept, 1=LocalDelivery. #3075: moved [29]->[31].
	switch payload[31] {
	case 1:
		d.Disposition = "local_delivery"
	}

	// IP addresses start at offset 32 (#3075: was 30 before the u16 zone widen).
	off := 32
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
	off += addrSize

	// #3301: trailing firewall-metadata fields (length-gated; absent on an
	// old helper => 0, the legitimate "unattributed / no per-rule counter /
	// use-global-timeout" value). Each is an independent gate so a
	// partially-extended frame still decodes what it carries.
	//   [off:off+4]   policy_id u32 LE        (#3056)
	//   [off+4:off+8] policy_counter_idx u32  (#3073)
	//   [off+8:off+12] inactivity_timeout secs u32 (#3227 -> AppTimeout)
	if off+4 <= len(payload) {
		d.PolicyID = binary.LittleEndian.Uint32(payload[off : off+4])
		off += 4
	}
	if off+4 <= len(payload) {
		d.PolicyCounterIdx = binary.LittleEndian.Uint32(payload[off : off+4])
		off += 4
	}
	if off+4 <= len(payload) {
		d.AppTimeout = binary.LittleEndian.Uint32(payload[off : off+4])
		off += 4
	}
	// #4565: trailing NAT64 pool source (4 raw IPv4 octets), length-gated. Only
	// meaningful when the FLAG_NAT64 bit is set; an old helper omits it (=> 0,
	// Nat64=false). Carried so a peer-PROMOTED NAT64 session can rebuild its
	// reverse (v4->v6) BIB after failover — the pool source is the one datum the
	// standby cannot reconstruct from the synced forward v6 key.
	if off+4 <= len(payload) {
		if d.Nat64 && (payload[off] != 0 || payload[off+1] != 0 || payload[off+2] != 0 || payload[off+3] != 0) {
			d.Nat64SnatV4 = net.IP(payload[off : off+4]).String()
		}
		off += 4
	}
	// #5212: trailing stable RT_FLOW session id (u64 LE), length-gated. Carried so
	// a peer-synced session adopts the originating node's id, making its
	// SESSION_CREATE/CLOSE RT_FLOW records correlatable across HA nodes. An old
	// helper omits it (=> 0, the standby allocs a fresh local id — pre-#5212).
	if off+8 <= len(payload) {
		d.RTFlowSessionID = binary.LittleEndian.Uint64(payload[off : off+8])
		off += 8
	}
	// #7188: trailing tunnel discriminator (u64 LE), length-gated. The one field
	// on the record that tells two RFC 2890 GRE tunnels between the same outer
	// endpoints apart — protocol 47 has no ports, so their 5-tuples are equal.
	// Opaque to Go: the tag is defined by the helper's
	// TunnelDiscriminator::to_wire. An old helper omits it (=> 0, the RESERVED
	// "not carried" tag, on which the peer helper withholds a protocol-47
	// session rather than importing it aliased).
	if off+8 <= len(payload) {
		d.TunnelDiscriminator = binary.LittleEndian.Uint64(payload[off : off+8])
		off += 8
	}
	// #7239: trailing routing domain (u32 LE), length-gated. The domain the
	// flow's ingress interface belonged to AT INSTALL, so the peer keys the
	// session where it actually arrived rather than re-deriving it from an
	// ingress fold that a later ifindex recycle can point at a sibling. An old
	// helper omits it => 0, the default routing instance, which is both a legal
	// value and the pre-#7160 behaviour.
	if off+4 <= len(payload) {
		d.RoutingDomain = binary.LittleEndian.Uint32(payload[off : off+4])
		off += 4
	}
	// #9412: trailing close class (u8), length-gated after the routing domain.
	// The helper writes it on every open and close-state update frame: 0 = not
	// carried or not closing, 1 = CLOSING, 2 = TIME_WAIT, 3 = RST. An old
	// helper omits it => 0, and the session syncs exactly as before.
	if off+1 <= len(payload) {
		d.TCPCloseClass = payload[off]
		off++
	}

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
//	[M:M+4]   OwnerRGID (int32 LE)  — #2467: widened from int16
//	[M+4]     Flags
//	[M+5:M+7] IngressZoneID (uint16 LE)  — #3075: widened from u8
//	[M+7:M+9] EgressZoneID (uint16 LE)   — #3075: widened from u8
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

	// Minimum: 6 (fixed) + 2*addrSize + 4 (OwnerRGID int32, #2467) + 1 (Flags).
	// Helpers append +4 (u16 ZoneIDs, #3075) after that; accept both lengths.
	minLen := 6 + 2*addrSize + 5
	if len(payload) < minLen {
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
	// #2467: int32 LE (was int16).
	d.OwnerRGID = int(int32(binary.LittleEndian.Uint32(payload[off : off+4])))
	off += 4
	flags := payload[off]
	off++
	d.FabricRedirect = flags&SessionEventFlagFabricRedirect != 0
	d.FabricIngress = flags&SessionEventFlagFabricIngress != 0
	// #3075: zone IDs are u16 LE present iff the helper sent the +4-byte trailer
	// (widened from the +2-byte u8 trailer of #919/#922). A frame without the
	// trailer leaves them 0 and the daemon falls back to the legacy zone-name
	// string (empty for close events, which drops the close).
	if len(payload) >= off+4 {
		d.IngressZoneID = binary.LittleEndian.Uint16(payload[off : off+2])
		d.EgressZoneID = binary.LittleEndian.Uint16(payload[off+2 : off+4])
		off += 4
	}
	// #7188: trailing tunnel discriminator (u64 LE), length-gated. A close names
	// the session to RETRACT, and for protocol 47 the 5-tuple names two tunnels
	// at once, so the retraction needs the same discriminator the open carried.
	if len(payload) >= off+8 {
		d.TunnelDiscriminator = binary.LittleEndian.Uint64(payload[off : off+8])
		off += 8
	}
	// #7239: trailing routing domain (u32 LE), length-gated. A close names the
	// session to RETRACT, and two routing instances sharing a 5-tuple are two
	// sessions — so the retraction needs the same domain the open carried, for
	// the same reason #7188 needed the discriminator here.
	if len(payload) >= off+4 {
		d.RoutingDomain = binary.LittleEndian.Uint32(payload[off : off+4])
		off += 4
	}

	return d, true
}

// decodeDataplaneEventPayload decodes the canonical dataplane.Event RT_FLOW
// payload. Userspace-dp carries these bytes over event-stream frame types 11-15
// (#2460 added the SESSION_CLOSE frame; #2508 the SESSION_CREATE frame), but the
// payload itself is the same shape consumed by pkg/logging/ringbuf.go.
func decodeDataplaneEventPayload(payload []byte) (logging.EventRecord, bool) {
	return logging.DecodeRawEventRecord(payload)
}

func dataplaneEventPayloadMatchesFrame(typ uint8, payload []byte) bool {
	if len(payload) <= 52 {
		return false
	}
	var want uint8
	switch typ {
	case EventFrameTypePolicyDeny:
		want = dataplane.EventTypePolicyDeny
	case EventFrameTypeScreenDrop:
		want = dataplane.EventTypeScreenDrop
	case EventFrameTypeFilterLog:
		want = dataplane.EventTypeFilterLog
	case EventFrameTypeSessionClose:
		want = dataplane.EventTypeSessionClose
	case EventFrameTypeSessionCreate:
		want = dataplane.EventTypeSessionOpen
	default:
		return false
	}
	return payload[52] == want
}

// dataplaneEventActionOffset is the byte offset of the RT_FLOW action field in
// the canonical dataplane.Event wire payload (mirrors ringbuf.DecodeRawEventRecord
// at data[54], and the C struct field order in bpf/headers/xpf_common.h). A
// screen event with action=PERMIT is the #2234 saturation alarm — it must be
// counted as a screen alarm, not a screen drop (#2298).
const dataplaneEventActionOffset = 54

// dataplaneEventAction returns the RT_FLOW action byte from a decoded-OK event
// payload. The caller has already validated the payload via
// dataplaneEventPayloadMatchesFrame (len > 52) and decodeDataplaneEventPayload,
// but the bound is rechecked defensively; a short payload reports ActionDeny so
// it is never misclassified as a permit alarm.
func dataplaneEventAction(payload []byte) uint8 {
	if len(payload) <= dataplaneEventActionOffset {
		return dataplane.ActionDeny
	}
	return payload[dataplaneEventActionOffset]
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
