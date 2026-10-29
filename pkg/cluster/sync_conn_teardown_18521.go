package cluster

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// #18521: a session-sync connection could stay half-open for ~56 s after the
// peer had torn it down, and nothing on either node said why.
//
// The mechanism, from the code:
//
//  1. receiveLoop reads the next frame only after handleMessage returns, and
//     handleMessage runs session installs/deletes synchronously through the
//     dataplane (installClusterSyncedV4 -> PutClusterSyncedV4 -> the userspace
//     Manager's global mutex and a helper control-socket round trip, whose
//     deadline can reach controlMaxDeadline). A receive loop that is slower
//     than its peer's writer, or stalled outright, stops draining the socket.
//  2. Once the 256 KiB buffers fill, the peer's next write cannot complete,
//     its syncWriteDeadline (2 s) fires, and the writer calls handleDisconnect,
//     which closes the socket. sendLoop logged that error only at Debug, so the
//     peer's journal showed "fabric N disconnected" with nothing before it.
//  3. A graceful close queues the FIN BEHIND the unsent bytes still in the
//     closer's send buffer. With the slow side's window closed the FIN cannot
//     be transmitted, so the slow side's kernel keeps the socket ESTABLISHED
//     and its receive loop learns of the close only after it has consumed the
//     whole backlog (both buffers, ~1 MB) — tens of seconds at helper-install
//     speed. Measured on loopback: graceful close leaves the reader
//     ESTABLISHED with ~990 KB to drain; an abortive close (SO_LINGER 0)
//     moves it to TCP_CLOSE at once with only its own receive queue left.
//  4. The accept side never dials (shouldInitiateFabricDial), so the pair can
//     only heal when the dial side notices — the half-open shape.
//
// The fixes here are the ones that are correct regardless of WHICH handler was
// slow: every teardown is abortive (abortSyncConn) so the peer's kernel learns
// immediately; a per-connection watchdog tears the connection down as soon as
// the kernel reports the peer reset it while unread frames are still queued
// (draining a dead connection's backlog only installs stale state that the
// reconnect's cold-prime bulk re-sends anyway); and the next occurrence names
// itself — every disconnect logs its cause, every receive-loop exit logs once
// with its reason and a per-connection summary, and a handler that keeps the
// loop off the socket for syncHandlerSlowThreshold is logged with its message
// type, both while it is still blocked and when it returns.

// syncHandlerSlowThreshold is how long one handleMessage call may keep the
// receive loop off the socket before it is reported. Half the peer's
// syncWriteDeadline: at the full deadline the peer's writer gives up and drops
// the connection, so a handler this slow is already close to costing the link.
const syncHandlerSlowThreshold = syncWriteDeadline / 2

// syncConnWatchInterval is how often the per-connection watchdog samples the
// in-flight handler and the kernel TCP state. One getsockopt + one ioctl per
// connection per tick; at most two connections exist.
const syncConnWatchInterval = time.Second

// linuxTCPStateClose is TCP_CLOSE in include/net/tcp_states.h. An open socket
// reports it after the peer's RST (or a local kernel abort such as a
// retransmission timeout): the connection is dead and only the already-queued
// receive bytes remain readable.
const linuxTCPStateClose = 7

// syncConnDiag is the per-connection teardown diagnostics carried on every
// *authConn (#18521). The receive-side counters and the in-flight handler are
// written only by the connection's single receiveLoop goroutine and read by the
// watchdog and by handleDisconnect, hence atomics. The drop reason is
// first-writer-wins: the FIRST path that decided to tear the connection down is
// the cause; later callers (the receive loop waking on the closed socket, a
// second writer) are consequences.
type syncConnDiag struct {
	installedMono atomic.Int64

	framesRead      atomic.Uint64
	bytesRead       atomic.Uint64
	handlerNanos    atomic.Int64
	maxHandlerNanos atomic.Int64
	maxHandlerType  atomic.Uint32

	// handlerStartMono is the MonotonicNanos at which the in-flight
	// handleMessage call started, 0 while the loop is not in a handler.
	handlerStartMono   atomic.Int64
	handlerType        atomic.Uint32
	handlerStallWarned atomic.Bool

	dropMu     sync.Mutex
	dropReason string
	dropErr    error
}

func syncConnDiagFor(conn net.Conn) *syncConnDiag {
	if ac, ok := conn.(*authConn); ok && ac != nil {
		return &ac.diag
	}
	return nil
}

// noteDrop records why the connection is being torn down, keeping the first
// reason.
func (d *syncConnDiag) noteDrop(reason string, err error) {
	if d == nil || reason == "" {
		return
	}
	d.dropMu.Lock()
	if d.dropReason == "" {
		d.dropReason = reason
		d.dropErr = err
	}
	d.dropMu.Unlock()
}

func (d *syncConnDiag) drop() (string, error) {
	if d == nil {
		return "", nil
	}
	d.dropMu.Lock()
	defer d.dropMu.Unlock()
	return d.dropReason, d.dropErr
}

// beginHandler / endHandler bracket one handleMessage call. endHandler returns
// the call's duration and whether the watchdog already reported it as stalled.
func (d *syncConnDiag) beginHandler(msgType uint8, startMono int64) {
	d.handlerType.Store(uint32(msgType))
	d.handlerStallWarned.Store(false)
	d.handlerStartMono.Store(startMono)
}

func (d *syncConnDiag) endHandler(msgType uint8, startMono int64) (time.Duration, bool) {
	elapsed := MonotonicNanos() - startMono
	d.handlerStartMono.Store(0)
	d.handlerNanos.Add(elapsed)
	if elapsed > d.maxHandlerNanos.Load() {
		d.maxHandlerNanos.Store(elapsed)
		d.maxHandlerType.Store(uint32(msgType))
	}
	return time.Duration(elapsed), d.handlerStallWarned.Load()
}

// summaryAttrs is the per-connection summary appended to the disconnect and
// receive-loop-exit lines: how old the connection was and how much the receive
// loop did, which is what distinguishes a slow consumer (many frames, handler
// time close to the connection's age) from a single stuck call (large max).
func (d *syncConnDiag) summaryAttrs() []any {
	if d == nil {
		return nil
	}
	attrs := make([]any, 0, 12)
	if inst := d.installedMono.Load(); inst != 0 {
		attrs = append(attrs, "conn_age", time.Duration(MonotonicNanos()-inst).Round(time.Millisecond).String())
	}
	attrs = append(attrs,
		"frames_read", d.framesRead.Load(),
		"bytes_read", d.bytesRead.Load(),
		"handler_time", time.Duration(d.handlerNanos.Load()).Round(time.Millisecond).String(),
		"handler_max", time.Duration(d.maxHandlerNanos.Load()).Round(time.Millisecond).String(),
		"handler_max_type", syncMsgName(uint8(d.maxHandlerType.Load())),
	)
	return attrs
}

// disconnectAttrs is the attribute set of the "fabric N disconnected" line.
func disconnectAttrs(conn net.Conn) []any {
	d := syncConnDiagFor(conn)
	reason, err := d.drop()
	if reason == "" {
		reason = "unspecified"
	}
	attrs := []any{"reason", reason}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	attrs = append(attrs, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
	return append(attrs, d.summaryAttrs()...)
}

// disconnectConn records why conn is being torn down and runs handleDisconnect.
// Every production teardown goes through here so the disconnect line names its
// cause; handleDisconnect alone (tests, legacy callers) logs "unspecified".
func (s *SessionSync) disconnectConn(conn net.Conn, reason string, err error) {
	syncConnDiagFor(conn).noteDrop(reason, err)
	s.handleDisconnect(conn)
}

// syncTCPConn returns the TCP socket under a session-sync connection, or nil
// for a non-TCP transport (net.Pipe in tests).
func syncTCPConn(conn net.Conn) *net.TCPConn {
	switch c := conn.(type) {
	case *net.TCPConn:
		return c
	case *authConn:
		if c == nil {
			return nil
		}
		if tc, ok := c.Conn.(*net.TCPConn); ok {
			return tc
		}
	}
	return nil
}

// abortSyncConn closes a session-sync connection ABORTIVELY (SO_LINGER 0, so
// the kernel sends RST and discards the unsent send queue). Every teardown in
// this package is a decision that the stream is unusable — a write that timed
// out mid-frame has already desynced it — so delivering the queued bytes first
// gains nothing, and a graceful FIN can sit behind up to the whole send buffer
// for as long as the peer's window stays closed. An RST is not subject to the
// window: the peer's kernel moves the socket to TCP_CLOSE on receipt, which is
// what the peer's watchdog keys on.
func abortSyncConn(conn net.Conn) {
	if conn == nil {
		return
	}
	if tc := syncTCPConn(conn); tc != nil {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}

// tcpConnKernelState samples the kernel TCP state and the unread receive-queue
// byte count. ok is false once the socket is closed locally.
func tcpConnKernelState(tc *net.TCPConn) (state uint8, unread int, ok bool) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var infoErr error
	ctlErr := rc.Control(func(fd uintptr) {
		var info *unix.TCPInfo
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if infoErr == nil {
			state = info.State
		}
		if n, qerr := unix.IoctlGetInt(int(fd), unix.SIOCINQ); qerr == nil {
			unread = n
		}
	})
	if ctlErr != nil || infoErr != nil {
		return 0, 0, false
	}
	return state, unread, true
}

func (s *SessionSync) slowHandlerThreshold() time.Duration {
	if s != nil && s.testSlowHandlerThreshold > 0 {
		return s.testSlowHandlerThreshold
	}
	return syncHandlerSlowThreshold
}

func (s *SessionSync) connWatchInterval() time.Duration {
	if s != nil && s.testConnWatchInterval > 0 {
		return s.testConnWatchInterval
	}
	return syncConnWatchInterval
}

// startConnWatch runs the per-connection watchdog until done closes or ctx is
// cancelled. The caller (receiveLoop) holds a wg token, so Add here is safe.
func (s *SessionSync) startConnWatch(ctx context.Context, conn net.Conn, done <-chan struct{}) {
	d := syncConnDiagFor(conn)
	tc := syncTCPConn(conn)
	if d == nil && tc == nil {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.watchConn(ctx, conn, d, tc, done)
	}()
}

// watchConn is the watchdog. It does two things the receive loop cannot do for
// itself while a handler holds it:
//
//   - reports a handler that has kept the loop off the socket for the slow
//     threshold, ONCE per call, while it is still running (the loop's own
//     report only fires when the call returns, which a stuck call never does);
//   - tears the connection down as soon as the kernel says the peer reset it
//     while this loop is behind (unread bytes queued, or a handler in flight).
//     Without this the loop drains the dead connection's backlog first, and
//     the dial side — the only side that redials — keeps the slot occupied for
//     as long as that takes.
func (s *SessionSync) watchConn(ctx context.Context, conn net.Conn, d *syncConnDiag, tc *net.TCPConn, done <-chan struct{}) {
	threshold := s.slowHandlerThreshold()
	ticker := time.NewTicker(s.connWatchInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
		}
		inHandler := false
		if d != nil {
			if start := d.handlerStartMono.Load(); start != 0 {
				inHandler = true
				blocked := time.Duration(MonotonicNanos() - start)
				if blocked >= threshold && d.handlerStallWarned.CompareAndSwap(false, true) {
					slog.Warn("cluster sync: receive loop blocked in a message handler; nothing reads the "+
						"socket meanwhile, so the peer's writes stall behind it and time out at its write deadline (#18521)",
						"msg_type", syncMsgName(uint8(d.handlerType.Load())),
						"blocked_for", blocked.Round(time.Millisecond).String(),
						"peer_write_deadline", syncWriteDeadline.String(),
						"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
				}
			}
		}
		if tc == nil {
			continue
		}
		state, unread, ok := tcpConnKernelState(tc)
		if !ok {
			return
		}
		if state == linuxTCPStateClose && (unread > 0 || inHandler) {
			slog.Warn("cluster sync: peer reset the session-sync connection while the receive loop "+
				"was behind; tearing it down now instead of draining the dead connection's backlog (#18521)",
				"unread_bytes", unread, "in_handler", inHandler,
				"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
			s.disconnectConn(conn, "peer reset while receive loop behind", nil)
			return
		}
	}
}

// recvExit is why receiveLoop returned. reason is a short fixed phrase; err is
// the transport/protocol error when there was one.
type recvExit struct {
	reason string
	err    error
}

// classifyRecvReadErr names a non-timeout read error.
func classifyRecvReadErr(what string, err error) recvExit {
	switch {
	case errors.Is(err, net.ErrClosed):
		return recvExit{reason: what + ": connection closed locally", err: err}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return recvExit{reason: what + ": peer closed the connection", err: err}
	case errors.Is(err, syscall.ECONNRESET):
		return recvExit{reason: what + ": peer reset the connection", err: err}
	default:
		return recvExit{reason: what + ": read error", err: err}
	}
}

// logReceiveLoopExit is the once-per-connection receive-loop exit line. A loop
// that woke on a socket another path already closed (ctx cancel, a writer's
// teardown, the watchdog) logs at Info — that path logged the cause — and every
// exit the loop itself detected logs at Warn.
func (s *SessionSync) logReceiveLoopExit(conn net.Conn, exit recvExit) {
	attrs := []any{"reason", exit.reason}
	if exit.err != nil {
		attrs = append(attrs, "err", exit.err.Error())
	}
	attrs = append(attrs, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
	attrs = append(attrs, syncConnDiagFor(conn).summaryAttrs()...)
	if exit.reason == recvExitContextDone || errors.Is(exit.err, net.ErrClosed) {
		slog.Info("cluster sync: receive loop exited", attrs...)
		return
	}
	slog.Warn("cluster sync: receive loop exited", attrs...)
}

const recvExitContextDone = "session sync stopping"

// syncMsgName names a wire message type for diagnostics. Its case labels must
// stay the same set as handleMessage's dispatch
// (TestSyncMsgNameCoversHandleMessage18521 compares the two by AST).
func syncMsgName(t uint8) string {
	switch t {
	case syncMsgSessionV4:
		return "session_v4"
	case syncMsgSessionV6:
		return "session_v6"
	case syncMsgDeleteV4:
		return "delete_v4"
	case syncMsgDeleteV6:
		return "delete_v6"
	case syncMsgBulkRequest:
		return "bulk_request"
	case syncMsgBulkStart:
		return "bulk_start"
	case syncMsgBulkEnd:
		return "bulk_end"
	case syncMsgBulkAck:
		return "bulk_ack"
	case syncMsgConfigApplyNack:
		return "config_apply_nack"
	case syncMsgConfigApplyAck:
		return "config_apply_ack"
	case syncMsgHeartbeat:
		return "heartbeat"
	case syncMsgHeartbeatAck:
		return "heartbeat_ack"
	case syncMsgConfig:
		return "config"
	case syncMsgConfigEncrypted:
		return "config_encrypted"
	case syncMsgConfigKeyExchange:
		return "config_key_exchange"
	case syncMsgAuthUpgradeRequest:
		return "auth_upgrade_request"
	case syncMsgAuthUpgradeHello:
		return "auth_upgrade_hello"
	case syncMsgAuthUpgradeProof:
		return "auth_upgrade_proof"
	case syncMsgAuthUpgradeConfirm:
		return "auth_upgrade_confirm"
	case syncMsgIPsecSA:
		return "ipsec_sa"
	case syncMsgIPsecSAChunk:
		return "ipsec_sa_chunk"
	case syncMsgPersistentNatLease:
		return "persistent_nat_lease"
	case syncMsgPersistentNatLeaseScoped:
		return "persistent_nat_lease_scoped"
	case syncMsgPersistentNatLeaseGeneration:
		return "persistent_nat_lease_generation"
	case syncMsgPersistentNatLeaseDeterministic:
		return "persistent_nat_lease_deterministic"
	case syncMsgPersistentNatLeaseProvenance:
		return "persistent_nat_lease_provenance"
	case syncMsgPersistentNatLeaseDeterministicProvenance:
		return "persistent_nat_lease_deterministic_provenance"
	case syncMsgPersistentNatLeaseTypedPool:
		return "persistent_nat_lease_typed_pool"
	case syncMsgPersistentNatLeaseDeterministicTypedPool:
		return "persistent_nat_lease_deterministic_typed_pool"
	case syncMsgDHCPLeaseV4:
		return "dhcp_lease_v4"
	case syncMsgDHCPLeaseV6:
		return "dhcp_lease_v6"
	case syncMsgDHCPLeaseV4Chunk:
		return "dhcp_lease_v4_chunk"
	case syncMsgDHCPLeaseV6Chunk:
		return "dhcp_lease_v6_chunk"
	case syncMsgFailover:
		return "failover"
	case syncMsgFailoverAck:
		return "failover_ack"
	case syncMsgFailoverCommit:
		return "failover_commit"
	case syncMsgFailoverCommitAck:
		return "failover_commit_ack"
	case syncMsgFailoverBatch:
		return "failover_batch"
	case syncMsgFailoverBatchAck:
		return "failover_batch_ack"
	case syncMsgFailoverBatchCommit:
		return "failover_batch_commit"
	case syncMsgFailoverBatchCommitAck:
		return "failover_batch_commit_ack"
	case syncMsgFailoverAbort:
		return "failover_abort"
	case syncMsgFailoverBatchAbort:
		return "failover_batch_abort"
	case syncMsgFence:
		return "fence"
	case syncMsgFenceAck:
		return "fence_ack"
	case syncMsgPeerCapabilities:
		return "peer_capabilities"
	case syncMsgClockSync:
		return "clock_sync"
	case syncMsgBarrier:
		return "barrier"
	case syncMsgBarrierAck:
		return "barrier_ack"
	}
	return "unknown"
}
