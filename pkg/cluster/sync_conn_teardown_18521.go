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
// slow:
//
//   - a teardown of a connection judged DEAD (a write that timed out, an
//     eviction, a supersede, a protocol error) is abortive (abortSyncConn), so
//     the peer's kernel learns immediately;
//   - a GRACEFUL stop is not such a judgment: Stop flushes what it already
//     wrote, bounded by syncStopFlushTimeout, and aborts only a peer that did
//     not take the bytes in time (review of #18525 round 2 — an abortive Stop
//     discarded the stopping primary's newest session deltas, which nothing
//     re-sends because nothing reconnects);
//   - a per-connection watchdog notices the kernel's report that the peer
//     reset the connection. The bytes already in the receive queue are what
//     the peer sent before it reset — its newest state, and possibly a
//     failover commit/abort, config ACK or fence the cold-prime bulk never
//     re-sends — so a receive loop that is still making progress drains them.
//     Meanwhile the slot is redialable, writers stop using the connection,
//     and its frames earn no peer liveness. Only a loop that makes NO
//     progress (a handler stuck for syncWriteDeadline, the same bound the
//     peer's writer uses to judge us) is torn down under its backlog;
//   - the next occurrence names itself — every disconnect logs its cause,
//     every receive-loop exit logs once with its reason and a per-connection
//     summary, and slow handlers are reported, rate-limited per connection.

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

// linuxTCPStateCloseWait is TCP_CLOSE_WAIT: the peer's FIN has arrived, so it
// will send nothing more, and the queued bytes end in EOF.
const linuxTCPStateCloseWait = 8

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

	// Slow-handler reporting (#18521 review round 2): slowCalls counts every
	// completed call over the slow threshold for the per-connection summary;
	// the two limiters hold the in-flight and completion reports to one line
	// each per syncSlowHandlerLogInterval, the rest counted and reported on
	// the next line. Without them a helper whose every install takes over the
	// threshold turned the reports into a per-session Warn stream.
	slowCalls      atomic.Uint64
	slowInFlightLg slowLogLimiter
	slowDoneLg     slowLogLimiter

	// peerClosed is set by the watchdog once the kernel reports the peer
	// closed this connection — an RST (#18521 review round 2) or a FIN
	// (round 3) — while the receive loop still had frames to handle. From
	// then on the loop drains what the peer already delivered and owns the
	// teardown: writers skip the connection (getActiveConn), a writer's
	// failed write does not tear it down (disconnectConn), the dial side may
	// redial its slot (fabricSlotNeedsDialLocked; the redial retires it,
	// retirePeerClosedSlot), and its frames earn no peer liveness. Frames
	// read between the close and the next watchdog tick still do — at most
	// one syncConnWatchInterval of them.
	peerClosed atomic.Bool
	// writesDeferred counts writer teardowns ignored while draining.
	writesDeferred atomic.Uint64

	// stopFlush marks a connection whose close Stop owns while it flushes
	// (see flushOnStop); abortSyncConn leaves it alone meanwhile.
	stopFlush atomic.Bool

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

func (d *syncConnDiag) endHandler(msgType uint8, startMono, nowMono int64) (time.Duration, bool) {
	elapsed := nowMono - startMono
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
		"slow_calls", d.slowCalls.Load(),
	)
	if d.peerClosed.Load() {
		attrs = append(attrs, "drained_after_peer_close", true, "writes_deferred", d.writesDeferred.Load())
	}
	return attrs
}

// syncSlowHandlerLogInterval is the per-connection, per-kind spacing of
// slow-handler reports. The count and maximum of the calls in between ride on
// the next report and in the receive-loop exit summary (slow_calls).
const syncSlowHandlerLogInterval = 10 * time.Second

// slowLogLimiter admits one report per interval; the reports it refuses are
// counted, with their maximum duration, for the next admitted one.
type slowLogLimiter struct {
	lastMono   atomic.Int64
	suppressed atomic.Uint64
	maxNanos   atomic.Int64
}

func (l *slowLogLimiter) admit(nowMono int64, interval, elapsed time.Duration) (ok bool, suppressed uint64, suppressedMax time.Duration) {
	last := l.lastMono.Load()
	if (last != 0 && nowMono-last < int64(interval)) || !l.lastMono.CompareAndSwap(last, nowMono) {
		l.suppressed.Add(1)
		for {
			m := l.maxNanos.Load()
			if int64(elapsed) <= m || l.maxNanos.CompareAndSwap(m, int64(elapsed)) {
				break
			}
		}
		return false, 0, 0
	}
	return true, l.suppressed.Swap(0), time.Duration(l.maxNanos.Swap(0))
}

// noteSlowHandler reports one slow handler call, rate-limited per connection:
// inFlight is the watchdog's report of a call that is still running, the
// other kind is the receive loop's report when a slow call returns.
func (s *SessionSync) noteSlowHandler(conn net.Conn, d *syncConnDiag, msgType uint8, elapsed time.Duration, inFlight, reportedWhileBlocked bool) {
	lim := &d.slowDoneLg
	if inFlight {
		lim = &d.slowInFlightLg
	}
	ok, suppressed, suppressedMax := lim.admit(s.nowMono(), syncSlowHandlerLogInterval, elapsed)
	if !ok {
		return
	}
	attrs := []any{"msg_type", syncMsgName(msgType)}
	if inFlight {
		attrs = append(attrs, "blocked_for", elapsed.Round(time.Millisecond).String())
	} else {
		attrs = append(attrs, "elapsed", elapsed.Round(time.Millisecond).String(),
			"reported_while_blocked", reportedWhileBlocked)
	}
	attrs = append(attrs, "peer_write_deadline", syncWriteDeadline.String())
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed,
			"suppressed_max", suppressedMax.Round(time.Millisecond).String(),
			"suppressed_over", syncSlowHandlerLogInterval.String())
	}
	attrs = append(attrs, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
	if inFlight {
		slog.Warn("cluster sync: receive loop blocked in a message handler; nothing reads the "+
			"socket meanwhile, so the peer's writes stall behind it and time out at its write deadline (#18521)",
			attrs...)
		return
	}
	slog.Warn("cluster sync: slow message handler held the receive loop off the socket (#18521)", attrs...)
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

// disconnectConn is the WRITER's teardown: a write on conn failed. It
// records why conn is being torn down and runs handleDisconnect, so the
// disconnect line names its cause; handleDisconnect alone (tests, legacy
// callers) logs "unspecified".
//
// A connection the peer already reset is the exception (#18521 review round
// 2): every write to it fails, so the failure says nothing new, and tearing it
// down here would discard the frames its receive loop is still draining. Its
// reader owns the teardown (disconnectConnNow), and writers no longer select
// it (getActiveConn).
func (s *SessionSync) disconnectConn(conn net.Conn, reason string, err error) {
	if d := syncConnDiagFor(conn); d != nil && d.peerClosed.Load() {
		d.writesDeferred.Add(1)
		slog.Debug("cluster sync: write failed on a connection the peer reset; its receive loop "+
			"is draining what the peer delivered and owns the teardown",
			"reason", reason, "err", err, "remote", connRemoteAddrString(conn))
		return
	}
	s.disconnectConnNow(conn, reason, err)
}

// disconnectConnNow tears conn down unconditionally: the receive loop's own
// exit, the watchdog's no-progress judgment, and policy teardowns (retired
// peer identity, strict session authentication).
func (s *SessionSync) disconnectConnNow(conn net.Conn, reason string, err error) {
	syncConnDiagFor(conn).noteDrop(reason, err)
	s.handleDisconnect(conn)
}

// retirePeerClosedSlot runs before installConn takes its locks (#18521 review
// round 3). When the slot about to be filled holds a connection the peer
// closed that is still draining, it is retired through handleDisconnect — the
// path the watchdog's teardown took before the drain existed — so the install
// lands in an EMPTY slot. A SUPERSESSION of a current-incarnation connection is
// installConn's evidence of a new peer process: it advances the incarnation,
// runs the #17097 retirement reset and evicts the same-process connection in
// the other slot. The peer closing its own connection is not that evidence,
// and on a dual-fabric pair the eviction took down the healthy fabric-1
// connection every writer had just moved to. A genuine restart behind the
// redial is still caught by its raised boot epoch and the #9818 identity
// check. A single-fabric retirement is a full disconnect, so its
// OnPeerDisconnected precedes the redial's OnPeerConnected — dispatchPeerEvent
// keeps that order.
func (s *SessionSync) retirePeerClosedSlot(fabricIdx int, incoming net.Conn) {
	s.mu.Lock()
	old := s.conn0
	if fabricIdx == 1 {
		old = s.conn1
	}
	s.mu.Unlock()
	if old == nil || old == incoming || !connPeerClosed(old) {
		return
	}
	s.disconnectConnNow(old, "superseded by a redial after the peer closed it", nil)
}

// dispatchPeerEvent runs a peer connect/disconnect callback on its own
// goroutine, after every callback dispatched before it has returned (#18521
// review round 3). Separate goroutines alone do not keep their order: the Go
// scheduler runs the most recently spawned goroutine first, so a redial that
// follows a full disconnect within microseconds could run OnPeerConnected
// before OnPeerDisconnected and leave the daemon believing the peer is gone
// while it is connected. Not tracked by s.wg, like the bare dispatch it
// replaces.
func (s *SessionSync) dispatchPeerEvent(fn func()) {
	if fn == nil {
		return
	}
	s.peerEventMu.Lock()
	prev := s.peerEventTail
	done := make(chan struct{})
	s.peerEventTail = done
	s.peerEventMu.Unlock()
	go func() {
		defer close(done)
		if prev != nil {
			<-prev
		}
		fn()
	}()
}

// connPeerClosed reports whether the watchdog marked conn as closed by the
// peer (an RST, or a FIN, observed while its receive loop was behind).
func connPeerClosed(conn net.Conn) bool {
	d := syncConnDiagFor(conn)
	return d != nil && d.peerClosed.Load()
}

// fabricSlotNeedsDialLocked reports whether fabricConnectLoop should dial
// fabric idx: the slot is empty, or it holds a connection the peer reset that
// is only being drained. A live peer then answers the dial and the new
// connection supersedes the drained one (installConn), exactly as the accept
// side's supersede does; a peer that is gone refuses it and the drain
// completes. Caller holds s.mu.
func (s *SessionSync) fabricSlotNeedsDialLocked(fabricIdx int) bool {
	c := s.conn0
	if fabricIdx == 1 {
		c = s.conn1
	}
	return c == nil || connPeerClosed(c)
}

// writableConnLocked is the connection writers use: the preferred active
// connection, unless the peer reset it (then the other fabric's connection if
// it is usable, else none). The cold-prime and stream-identity decisions keep
// using activeConnLocked, which is unchanged. Caller holds s.mu.
func (s *SessionSync) writableConnLocked() net.Conn {
	c := s.activeConnLocked()
	if c == nil || !connPeerClosed(c) {
		return c
	}
	for _, alt := range []net.Conn{s.conn0, s.conn1} {
		if alt != nil && alt != c && !connPeerClosed(alt) {
			return alt
		}
	}
	return nil
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
	if d := syncConnDiagFor(conn); d != nil && d.stopFlush.Load() {
		// Stop is flushing this socket and closes it itself (flushOnStop).
		return
	}
	if tc := syncTCPConn(conn); tc != nil {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}

// syncStopFlushTimeout bounds Stop's graceful flush of each connection. Half
// the peer's write deadline: short enough that the peer's writer, which this
// stopping node no longer reads for, does not hit its own write deadline and
// reset the connection under the flush, and well inside systemd's
// TimeoutStopSec=20 (Stop is at most this flush plus its own 5s goroutine
// wait). It does NOT cover a peer that is reading below line rate — the
// #18521 slow-install state: at ~50 session installs/s the peer's window opens
// by about 50 frames in this second, so up to the rest of the send queue
// (~520 KB, ~2,000 session frames measured on loopback) is still discarded by
// the abort (review of #18525 round 3). The receive half of that state — what
// the peer already holds — is kept by its drain.
const syncStopFlushTimeout = syncWriteDeadline / 2

// The flush must stay below the peer's write deadline (above). Fails to
// compile otherwise: the constant would overflow uint64.
const _ = uint64(syncWriteDeadline - syncStopFlushTimeout - 1)

func (s *SessionSync) stopFlushTimeout() time.Duration {
	if s != nil && s.testStopFlushTimeout > 0 {
		return s.testStopFlushTimeout
	}
	return syncStopFlushTimeout
}

// tcpConnSendQueue returns the bytes this socket has written that the peer's
// kernel has not yet acknowledged (SIOCOUTQ). ok is false once the socket is
// closed.
func tcpConnSendQueue(tc *net.TCPConn) (outq int, ok bool) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var qerr error
	if cerr := rc.Control(func(fd uintptr) {
		outq, qerr = unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
	}); cerr != nil || qerr != nil {
		return 0, false
	}
	return outq, true
}

// beginStopFlushLocked hands conn's close to Stop's flush when it is a TCP
// session-sync connection (other transports are aborted at once, as before).
// Caller holds s.mu.
func beginStopFlushLocked(conn net.Conn) bool {
	d := syncConnDiagFor(conn)
	d.noteDrop("session sync stopping", nil)
	if d == nil || syncTCPConn(conn) == nil || d.peerClosed.Load() {
		abortSyncConn(conn)
		return false
	}
	d.stopFlush.Store(true)
	return true
}

// flushOnStop is Stop's graceful close (#18521 review round 2). Stop is not a
// judgment that the stream is dead: every byte already written is addressed
// to a live peer that would process it, and when the primary stops for good
// nothing reconnects to re-send them. So each connection waits until the
// peer's kernel has acknowledged everything written (SIOCOUTQ == 0) and then
// closes normally. The wait is bounded by stopFlushTimeout; a peer that has
// not taken the bytes by then is stalled, and the close is abortive (RST) so
// its kernel learns at once instead of waiting behind the unsent tail — the
// #18521 half-open concern. Either way the bytes the peer DID take are in its
// receive queue, and its watchdog lets a progressing receive loop drain them.
func (s *SessionSync) flushOnStop(conns []net.Conn) {
	if len(conns) == 0 {
		return
	}
	timeout := s.stopFlushTimeout()
	deadline := time.Now().Add(timeout)
	if hook := s.testOnStopFlush; hook != nil {
		hook()
	}
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			d := syncConnDiagFor(conn)
			tc := syncTCPConn(conn)
			outq, ok := tcpConnSendQueue(tc)
			start := outq
			for ok && outq > 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
				outq, ok = tcpConnSendQueue(tc)
			}
			d.stopFlush.Store(false)
			if ok && outq == 0 {
				_ = conn.Close()
				slog.Info("cluster sync: stop flushed the session-sync connection and closed it",
					"flushed_bytes", start, "remote", connRemoteAddrString(conn))
				return
			}
			abortSyncConn(conn)
			slog.Warn("cluster sync: stop could not flush the session-sync connection in time; "+
				"the peer was not taking bytes at line rate, aborting (it keeps what it already received)",
				"unsent_bytes", outq, "flush_timeout", timeout.String(),
				"remote", connRemoteAddrString(conn))
		}(conn)
	}
	wg.Wait()
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

// stuckHandlerThreshold is how long one handler call may run, once the peer
// has reset the connection, before the watchdog judges the receive loop to be
// making no progress and tears the connection down under its backlog. Twice
// the slow threshold, i.e. syncWriteDeadline in production: the same bound
// the peer's writer uses to judge THIS loop dead.
func (s *SessionSync) stuckHandlerThreshold() time.Duration {
	return 2 * s.slowHandlerThreshold()
}

// watchConn is the watchdog. It does what the receive loop cannot do for
// itself while a handler holds it:
//
//   - reports a handler that has kept the loop off the socket for the slow
//     threshold while it is still running (the loop's own report only fires
//     when the call returns, which a stuck call never does), rate-limited per
//     connection with the completion reports (noteSlowHandler);
//   - notices the kernel's report that the peer closed the connection — an
//     RST (TCP_CLOSE) or a FIN (TCP_CLOSE_WAIT) — while this loop is behind
//     (unread bytes queued, or a handler in flight). If the loop is still
//     making progress, the connection is marked peerClosed and the loop
//     drains what the peer delivered (see syncConnDiag.peerClosed for what
//     the mark changes); it ends at the kernel's ECONNRESET or EOF once the
//     queue is empty, or earlier if a redial retires it. If the peer RESET
//     the connection and the loop makes NO progress — one handler call
//     running for stuckHandlerThreshold — the connection is torn down now, as
//     before: the dial side, the only side that redials, would otherwise keep
//     the slot for as long as the stuck call lasts. A FIN never tears down
//     (the peer closed gracefully; the mark already makes the slot
//     redialable). A loop outside a handler is reading, and reaches the end
//     of the queue by itself.
func (s *SessionSync) watchConn(ctx context.Context, conn net.Conn, d *syncConnDiag, tc *net.TCPConn, done <-chan struct{}) {
	threshold := s.slowHandlerThreshold()
	stuckAfter := s.stuckHandlerThreshold()
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
		if hook := s.testOnWatchTick; hook != nil {
			hook()
		}
		inHandler := false
		var blocked time.Duration
		if d != nil {
			if start := d.handlerStartMono.Load(); start != 0 {
				inHandler = true
				blocked = time.Duration(s.nowMono() - start)
				if blocked >= threshold && d.handlerStallWarned.CompareAndSwap(false, true) {
					s.noteSlowHandler(conn, d, uint8(d.handlerType.Load()), blocked, true, true)
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
		closed := state == linuxTCPStateClose || state == linuxTCPStateCloseWait
		if !closed || (unread == 0 && !inHandler) {
			continue
		}
		if state == linuxTCPStateClose && (d == nil || (inHandler && blocked >= stuckAfter)) {
			slog.Warn("cluster sync: peer reset the session-sync connection while the receive loop "+
				"was behind and making no progress; tearing it down now (#18521)",
				"unread_bytes", unread, "in_handler", inHandler,
				"blocked_for", blocked.Round(time.Millisecond).String(),
				"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
			s.disconnectConnNow(conn, "peer reset while receive loop made no progress", nil)
			return
		}
		if d == nil {
			continue
		}
		if d.peerClosed.CompareAndSwap(false, true) {
			how := "reset"
			if state == linuxTCPStateCloseWait {
				how = "fin"
			}
			slog.Info("cluster sync: peer closed the session-sync connection; the receive loop "+
				"drains what the peer already delivered (the slot is redialable, writers skip it "+
				"and its frames earn no peer liveness meanwhile) (#18521)",
				"peer_close", how, "unread_bytes", unread, "in_handler", inHandler,
				"local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		}
	}
}

// setConnSlotLocked is the ONLY production writer of s.conn0 / s.conn1
// (TestConnSlotWritesGoThroughTheSetter18525 enforces it). Replacing an
// installed connection — by nil or by a new one — advances connSlotRemovals,
// the generation the Manager binds a remote transfer-out lease to: a commit or
// abort queued on a removed connection is lost, so the owner's leased hold
// must not outlive it (#18521 review round 2). Filling an empty slot removes
// nothing and does not advance it. Caller holds s.mu.
func (s *SessionSync) setConnSlotLocked(fabricIdx int, conn net.Conn) {
	slot := &s.conn0
	if fabricIdx == 1 {
		slot = &s.conn1
	}
	if old := *slot; old != nil && old != conn {
		s.connSlotRemovals.Add(1)
	}
	*slot = conn
}

// TransferChannelGen returns the connection-slot removal generation. See
// setConnSlotLocked. Lock-free.
func (s *SessionSync) TransferChannelGen() uint64 {
	return s.connSlotRemovals.Load()
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
