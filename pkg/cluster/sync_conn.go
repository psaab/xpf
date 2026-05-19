package cluster

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *SessionSync) noteHelperMirrorResult(af string, warned *atomic.Bool, err error) {
	if err == nil {
		warned.Store(false)
		return
	}
	s.stats.Errors.Add(1)
	if warned.CompareAndSwap(false, true) {
		slog.Warn("cluster sync: failed to mirror synced session into dataplane helper", "af", af, "err", err)
		return
	}
	slog.Debug("cluster sync: repeated synced-session helper mirror failure", "af", af, "err", err)
}

func (s *SessionSync) installClusterSyncedV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	if s.sessions == nil {
		return
	}
	if err := s.sessions.PutClusterSyncedV4(key, val); err == nil {
		s.stats.SessionsInstalled.Add(1)
		s.noteHelperMirrorResult("v4", &s.sessionMirrorWarnedV4, nil)
		if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
			s.OnForwardSessionInstalled()
		}
	} else {
		s.noteHelperMirrorResult("v4", &s.sessionMirrorWarnedV4, err)
	}
}

func (s *SessionSync) installClusterSyncedV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	if s.sessions == nil {
		return
	}
	if err := s.sessions.PutClusterSyncedV6(key, val); err == nil {
		s.stats.SessionsInstalled.Add(1)
		s.noteHelperMirrorResult("v6", &s.sessionMirrorWarnedV6, nil)
		if val.IsReverse == 0 && s.OnForwardSessionInstalled != nil {
			s.OnForwardSessionInstalled()
		}
	} else {
		s.noteHelperMirrorResult("v6", &s.sessionMirrorWarnedV6, err)
	}
}

func (s *SessionSync) deleteClusterSyncedV4(key dataplane.SessionKey) {
	if s.sessions == nil {
		return
	}
	if err := s.sessions.DeleteWithCompanionsV4(key, dataplane.DeleteReasonClusterStale); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete v4 session", "err", err)
	}
}

func (s *SessionSync) deleteClusterSyncedV6(key dataplane.SessionKeyV6) {
	if s.sessions == nil {
		return
	}
	if err := s.sessions.DeleteWithCompanionsV6(key, dataplane.DeleteReasonClusterStale); err != nil {
		s.stats.Errors.Add(1)
		slog.Warn("cluster sync: failed to delete v6 session", "err", err)
	}
}

func shouldInitiateFabricDial(localAddr, peerAddr string) bool {
	local, err := netip.ParseAddrPort(localAddr)
	if err != nil {
		return true
	}
	peer, err := netip.ParseAddrPort(peerAddr)
	if err != nil {
		return true
	}
	if cmp := local.Addr().Compare(peer.Addr()); cmp != 0 {
		return cmp < 0
	}
	return local.Port() < peer.Port()
}

// activeConnLocked returns the preferred active connection. fab0 is preferred;
// fab1 is used only when fab0 is down. The caller must hold s.mu.
func (s *SessionSync) activeConnLocked() net.Conn {
	if s.conn0 != nil {
		return s.conn0
	}
	return s.conn1
}

// getActiveConn returns the active connection while taking s.mu.
func (s *SessionSync) getActiveConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeConnLocked()
}
func connRemoteAddrString(conn net.Conn) (remote string) {
	if conn == nil {
		return "<nil>"
	}
	defer func() {
		if recover() != nil {
			remote = "<unavailable>"
		}
	}()
	addr := conn.RemoteAddr()
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}
func connLocalAddrString(conn net.Conn) (local string) {
	if conn == nil {
		return "<nil>"
	}
	defer func() {
		if recover() != nil {
			local = "<unavailable>"
		}
	}()
	addr := conn.LocalAddr()
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}
func configureSessionSyncConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcpConn.SetNoDelay(true); err != nil {
		slog.Warn("cluster sync: failed to enable TCP_NODELAY", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "err", err)
	}
	if err := tcpConn.SetWriteBuffer(256 * 1024); err != nil {
		slog.Warn("cluster sync: failed to set write buffer", "local", connLocalAddrString(conn), "err", err)
	}
	if err := tcpConn.SetReadBuffer(256 * 1024); err != nil {
		slog.Warn("cluster sync: failed to set read buffer", "local", connLocalAddrString(conn), "err", err)
	}
}

func (s *SessionSync) handleNewConnection(ctx context.Context, fabricIdx int, conn net.Conn) {
	configureSessionSyncConn(conn)
	s.mu.Lock()
	wasDisconnected := s.conn0 == nil && s.conn1 == nil
	activeBefore := -1
	if s.conn0 != nil {
		activeBefore = 0
	} else if s.conn1 != nil {
		activeBefore = 1
	}
	hadConn0 := s.conn0 != nil
	hadConn1 := s.conn1 != nil
	switch fabricIdx {
	case 0:
		if s.conn0 != nil {
			s.conn0.Close()
		}
		s.conn0 = conn
	case 1:
		if s.conn1 != nil {
			s.conn1.Close()
		}
		s.conn1 = conn
	}
	activeAfter := -1
	if s.conn0 != nil {
		activeAfter = 0
	} else if s.conn1 != nil {
		activeAfter = 1
	}
	s.stats.Connected.Store(true)
	s.lastPeerRxUnix.Store(time.Now().UnixNano())
	s.mu.Unlock()
	becameActive := activeAfter == fabricIdx
	slog.Info("cluster sync: handling new connection", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "was_disconnected", wasDisconnected, "active_before", activeBefore, "active_after", activeAfter, "became_active", becameActive, "had_conn0", hadConn0, "had_conn1", hadConn1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.receiveLoop(ctx, conn)
	}()
	s.sendClockSync(conn)
	coldStart := !s.bulkEverCompleted.Load()
	if wasDisconnected {
		slog.Info("cluster sync: first connection after disconnect", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "cold_start", coldStart)
		s.flushDeleteJournal()
		if s.OnPeerConnected != nil {
			slog.Info("cluster sync: scheduling OnPeerConnected callback", "fabric", fabricIdx)
			go s.OnPeerConnected()
		}
		if coldStart {
			slog.Info("cluster sync: starting bulk sync on cold start", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
			if err := s.doBulkSync(); err != nil {
				slog.Warn("cluster sync: bulk sync failed", "err", err, "fabric", fabricIdx)
			}
		} else {
			slog.Info("cluster sync: skipping bulk sync on reconnect (already primed)", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
		}
	} else if becameActive {
		slog.Info("cluster sync: active fabric changed, resuming incremental sync", "fabric", fabricIdx, "remote", connRemoteAddrString(conn), "active_before", activeBefore, "active_after", activeAfter)
	} else {
		slog.Info("cluster sync: connection added without bulk sync", "fabric", fabricIdx, "remote", connRemoteAddrString(conn))
	}
}

func (s *SessionSync) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)
	lc := vrfListenConfig(s.vrfDevice)
	ln, err := lc.Listen(ctx, "tcp", s.localAddr)
	if err != nil {
		return fmt.Errorf("sync listen: %w", err)
	}
	s.listener = ln
	slog.Info("cluster sync: listening", "addr", s.localAddr)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, ln, 0)
	}()
	if s.localAddr1 != "" {
		lc1 := vrfListenConfig(s.vrfDevice)
		ln1, err := lc1.Listen(ctx, "tcp", s.localAddr1)
		if err != nil {
			slog.Warn("cluster sync: secondary fabric listen failed, using primary only", "addr", s.localAddr1, "err", err)
		} else {
			s.listener1 = ln1
			slog.Info("cluster sync: listening on secondary fabric", "addr", s.localAddr1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.acceptLoop(ctx, ln1, 1)
			}()
		}
	}
	if shouldInitiateFabricDial(s.localAddr, s.peerAddr) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.fabricConnectLoop(ctx, 0, s.peerAddr)
		}()
	}
	if s.peerAddr1 != "" && shouldInitiateFabricDial(s.localAddr1, s.peerAddr1) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.fabricConnectLoop(ctx, 1, s.peerAddr1)
		}()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sendLoop(ctx)
	}()
	return nil
}

func (s *SessionSync) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if s.listener1 != nil {
		s.listener1.Close()
	}
	s.mu.Lock()
	if s.conn0 != nil {
		s.conn0.Close()
	}
	if s.conn1 != nil {
		s.conn1.Close()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("cluster sync: Stop timed out waiting for goroutines, proceeding with shutdown")
	}
}

func (s *SessionSync) StartSyncSweep(ctx context.Context) {
	s.lastSweepTime = monotonicSeconds()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		activeInterval, idleInterval := s.sweepIntervals()
		interval := activeInterval
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				activeInterval, idleInterval = s.sweepIntervals()
				synced := s.syncSweep()
				if synced > 0 || s.syncBackfillNeeded.Load() {
					interval = activeInterval
				} else {
					interval = min(interval*2, idleInterval)
				}
				timer.Reset(interval)
			}
		}
	}()
	slog.Info("cluster sync: sweep started")
}
func (s *SessionSync) sweepIntervals() (time.Duration, time.Duration) {
	if s.sessions != nil {
		if source := s.sessions.SessionDeltas(); source != nil {
			return sweepIntervalsForDataPlane(source)
		}
	}
	return sweepIntervalsForDataPlane(nil)
}
func sweepIntervalsForDataPlane(dp any) (time.Duration, time.Duration) {
	activeInterval := time.Second
	idleInterval := 10 * time.Second
	if profiler, ok := dp.(sessionSyncSweepProfiler); ok {
		if enabled, active, idle := profiler.SessionSyncSweepProfile(); enabled {
			if active > 0 {
				activeInterval = active
			}
			if idle > 0 {
				idleInterval = idle
			}
		}
	}
	if idleInterval < activeInterval {
		idleInterval = activeInterval
	}
	return activeInterval, idleInterval
}

func (s *SessionSync) ShouldSyncZone(zoneID uint16) bool {
	if s.IsPrimaryForRGFn != nil {
		s.zoneRGMu.RLock()
		rgID, ok := s.zoneRGMap[zoneID]
		s.zoneRGMu.RUnlock()
		if ok {
			return s.IsPrimaryForRGFn(rgID)
		}
	}
	if s.IsPrimaryFn != nil {
		return s.IsPrimaryFn()
	}
	return false
}
func (s *SessionSync) syncSweep() int {
	if s.IsPrimaryFn == nil && s.IsPrimaryForRGFn == nil {
		return 0
	}
	if s.incrementalPauseDepth.Load() > 0 {
		return 0
	}
	if !s.stats.Connected.Load() {
		return 0
	}
	if s.sessions == nil {
		return 0
	}
	if s.lastSweepEmpty && !s.syncBackfillNeeded.Load() {
		if s.telemetry != nil {
			newCtr, err1 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
			closedCtr, err2 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
			if err1 == nil && err2 == nil && newCtr == s.lastNewCounter && closedCtr == s.lastClosedCounter {
				s.lastSweepTime = monotonicSeconds()
				return 0
			}
			s.lastNewCounter = newCtr
			s.lastClosedCounter = closedCtr
		}
	}
	threshold := s.lastSweepTime
	now := monotonicSeconds()
	var count int
	var overflow bool
	replaying := s.syncBackfillNeeded.Load()
	if err := s.sessions.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created >= threshold && s.ShouldSyncZone(val.IngressZone) {
			msg := encodeSessionV4(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v4") {
				count++
			} else {
				overflow = true
			}
		}
		return true
	}); err != nil {
		slog.Warn("cluster sync: sweep v4 iteration failed", "err", err)
		s.stats.Errors.Add(1)
		return count
	}
	if err := s.sessions.ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if val.Created >= threshold && s.ShouldSyncZone(val.IngressZone) {
			msg := encodeSessionV6(key, val)
			if s.queueMessage(msg, &s.stats.SessionsSent, "sweep_v6") {
				count++
			} else {
				overflow = true
			}
		}
		return true
	}); err != nil {
		slog.Warn("cluster sync: sweep v6 iteration failed", "err", err)
		s.stats.Errors.Add(1)
		return count
	}
	if overflow {
		s.syncBackfillNeeded.Store(true)
		slog.Warn("cluster sync: sweep queue overflow, replaying previous window", "threshold", threshold, "queued", count, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		return count
	}
	if replaying {
		s.syncBackfillNeeded.Store(false)
		slog.Info("cluster sync: sweep replay recovered", "queued", count, "threshold", threshold)
	}
	s.lastSweepTime = now
	s.lastSweepEmpty = (count == 0)
	if count == 0 && s.telemetry != nil {
		newCtr, err1 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsNew)
		closedCtr, err2 := s.telemetry.GlobalCounter(dataplane.GlobalCtrSessionsClosed)
		if err1 == nil && err2 == nil {
			s.lastNewCounter = newCtr
			s.lastClosedCounter = closedCtr
		}
	}
	if count > 0 {
		slog.Info("cluster sync: sweep synced sessions", "count", count)
	}
	return count
}

// PauseIncrementalSync temporarily disables background sweep-driven session
// replication. Explicit sync producers may continue queueing messages.
func (s *SessionSync) PauseIncrementalSync(reason string) {
	depth := s.incrementalPauseDepth.Add(1)
	if depth == 1 {
		stats := s.Stats()
		slog.Info("cluster sync: incremental sync paused", "reason", reason, "depth", depth, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	}
}

// ResumeIncrementalSync releases a previous PauseIncrementalSync call.
func (s *SessionSync) ResumeIncrementalSync(reason string) {
	depth := s.incrementalPauseDepth.Add(-1)
	if depth < 0 {
		s.incrementalPauseDepth.Store(0)
		depth = 0
	}
	if depth == 0 {
		stats := s.Stats()
		slog.Info("cluster sync: incremental sync resumed", "reason", reason, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
	}
}
func (s *SessionSync) queueMessage(msg []byte, sentCounter *atomic.Uint64, source string) bool {
	if !s.stats.Connected.Load() {
		return false
	}
	select {
	case s.sendCh <- msg:
		sentCounter.Add(1)
		return true
	default:
		s.stats.Errors.Add(1)
		if s.syncBackfillNeeded.CompareAndSwap(false, true) {
			slog.Warn("cluster sync: send queue full, enabling sweep replay", "source", source, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		}
		return false
	}
}

// QueueSessionV4 queues a v4 session for synchronization to the peer.
func (s *SessionSync) QueueSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	msg := encodeSessionV4(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v4")
}

// QueueSessionV6 queues a v6 session for synchronization to the peer.
func (s *SessionSync) QueueSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	msg := encodeSessionV6(key, val)
	s.queueMessage(msg, &s.stats.SessionsSent, "session_v6")
}

// QueueDeleteV4 queues a v4 session deletion for synchronization. If the peer
// is disconnected, the delete is journaled for replay on reconnect.
func (s *SessionSync) QueueDeleteV4(key dataplane.SessionKey) {
	msg := encodeDeleteV4(key)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v4") {
		s.journalDelete(msg)
	}
}

// QueueDeleteV6 queues a v6 session deletion for synchronization. If the peer
// is disconnected, the delete is journaled for replay on reconnect.
func (s *SessionSync) QueueDeleteV6(key dataplane.SessionKeyV6) {
	msg := encodeDeleteV6(key)
	if !s.queueMessage(msg, &s.stats.DeletesSent, "delete_v6") {
		s.journalDelete(msg)
	}
}

// journalDelete stores a delete message in the bounded ring buffer for replay
// on reconnect. If the journal is full, the oldest entry is evicted and
// DeletesDropped is incremented.
func (s *SessionSync) journalDelete(msg []byte) {
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()
	cap := s.deleteJournalCap
	if cap <= 0 {
		cap = deleteJournalDefaultCap
	}
	if len(s.deleteJournal) >= cap {
		s.deleteJournal = s.deleteJournal[1:]
		s.stats.DeletesDropped.Add(1)
	}
	s.deleteJournal = append(s.deleteJournal, msg)
}

func (s *SessionSync) flushDeleteJournal() {
	s.deleteJournalMu.Lock()
	journal := s.deleteJournal
	s.deleteJournal = nil
	s.deleteJournalMu.Unlock()
	if len(journal) == 0 {
		return
	}
	var flushed int
	// Replay journaled delete messages before normal sync resumes.
	for _, msg := range journal {
		if s.queueMessage(msg, &s.stats.DeletesSent, "journal_flush") {
			flushed++
		}
	}
	slog.Info("cluster sync: flushed delete journal", "total", len(journal), "sent", flushed)
}

// QueueConfig sends the full config text to the peer for configuration synchronization.
func (s *SessionSync) QueueConfig(configText string) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	payload := []byte(configText)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgConfig, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: config send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	s.stats.ConfigsSent.Add(1)
	slog.Info("cluster sync: config sent to peer", "size", len(payload))
}

// sendClockSync exchanges the local monotonic clock over the sync channel.
func (s *SessionSync) sendClockSync(conn net.Conn) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], monotonicSeconds())
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgClockSync, buf[:])
	s.writeMu.Unlock()
	if err != nil {
		s.handleDisconnect(conn)
		slog.Warn("cluster sync: failed to send clock sync", "err", err)
	}
}
func (s *SessionSync) acceptLoop(ctx context.Context, ln net.Listener, fabricIdx int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Warn("cluster sync: accept error", "err", err)
				time.Sleep(time.Second)
				continue
			}
		}
		slog.Info("cluster sync: peer connected", "remote", conn.RemoteAddr(), "fabric", fabricIdx)
		s.handleNewConnection(ctx, fabricIdx, conn)
	}
}

func (s *SessionSync) fabricConnectLoop(ctx context.Context, fabricIdx int, peerAddr string) {
	for first := true; ; // fabricConnectLoop retries outbound connection on a single fabric link.
	// Each fabric gets its own loop so fab0 reconnects independently of fab1.
	first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
		s.mu.Lock()
		var connected bool
		if fabricIdx == 0 {
			connected = s.conn0 != nil
		} else {
			connected = s.conn1 != nil
		}
		s.mu.Unlock()
		if connected {
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}
		dialer := net.Dialer{Timeout: 3 * time.Second}
		if s.vrfDevice != "" {
			dialer.Control = vrfListenConfig(s.vrfDevice).Control
		}
		conn, err := dialer.DialContext(ctx, "tcp", peerAddr)
		if err != nil {
			continue
		}
		slog.Info("cluster sync: connected to peer", "addr", peerAddr, "fabric", fabricIdx)
		s.handleNewConnection(ctx, fabricIdx, conn)
	}
}
func (s *SessionSync) sendLoop(ctx context.Context) {
	sendOne := func(msg []byte) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn := s.getActiveConn()
			if conn == nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.writeMu.Lock()
			err := writeFull(conn, msg)
			s.writeMu.Unlock()
			if err != nil {
				slog.Debug("cluster sync: send error", "err", err)
				s.stats.Errors.Add(1)
				s.handleDisconnect(conn)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-s.sendCh:
			sendOne(msg)
		}
	}
}
func (s *SessionSync) receiveLoop(ctx context.Context, conn net.Conn) {
	defer func() {
		s.handleDisconnect(conn)
	}()
	hdrBuf := make([]byte, syncHeaderSize)
	readDeadline := s.readDeadlineDuration()
	missedHeartbeats := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(readDeadline))
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if s.peerHeartbeatAckEver.Load() {
					missedHeartbeats++
				}
				if missedHeartbeats >= 2 {
					slog.Warn("cluster sync: heartbeat ack timeout, closing stale connection", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "missed_heartbeats", missedHeartbeats)
					return
				}
				s.writeMu.Lock()
				err := writeMsg(conn, syncMsgHeartbeat, nil)
				s.writeMu.Unlock()
				if err != nil {
					return
				}
				continue
			}
			slog.Debug("cluster sync: read header error", "err", err)
			return
		}
		var hdr syncHeader
		copy(hdr.Magic[:], hdrBuf[:4])
		hdr.Type = hdrBuf[4]
		hdr.Length = binary.LittleEndian.Uint32(hdrBuf[8:12])
		if hdr.Magic != syncMagic {
			slog.Warn("cluster sync: bad magic")
			s.stats.Errors.Add(1)
			return
		}
		var payload []byte
		if hdr.Length > 0 {
			if hdr.Length > 16*1024*1024 {
				slog.Warn("cluster sync: payload too large", "len", hdr.Length)
				return
			}
			payload = make([]byte, hdr.Length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}
		missedHeartbeats = 0
		s.lastPeerRxUnix.Store(time.Now().UnixNano())
		s.handleMessage(conn, hdr.Type, payload)
	}
}
func (s *SessionSync) handleMessage(conn net.Conn, msgType uint8, payload []byte) {
	switch msgType {
	case syncMsgSessionV4:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			count := s.stats.BulkSyncSessions.Add(1)
			if count == 1 || count%64 == 0 {
				s.bulkMu.Lock()
				epoch := s.bulkRecvEpoch
				s.bulkMu.Unlock()
				slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", "v4", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
			}
		}
		if s.sessions != nil {
			if key, val, ok := decodeSessionV4Payload(payload); ok {
				if val.IsReverse == 0 {
					s.bulkMu.Lock()
					if s.bulkInProgress {
						s.bulkRecvV4[key] = struct{}{}
					}
					s.bulkMu.Unlock()
				}
				offset := s.peerClockOffset.Load()
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
				s.installClusterSyncedV4(key, val)
			}
		}
	case syncMsgSessionV6:
		s.stats.SessionsReceived.Add(1)
		if s.stats.BulkSyncStartTime.Load() > 0 && s.stats.BulkSyncEndTime.Load() == 0 {
			count := s.stats.BulkSyncSessions.Add(1)
			if count == 1 || count%64 == 0 {
				s.bulkMu.Lock()
				epoch := s.bulkRecvEpoch
				s.bulkMu.Unlock()
				slog.Info("cluster sync: bulk receive progress", "epoch", epoch, "sessions", count, "type", "v6", "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
			}
		}
		if s.sessions != nil {
			if key, val, ok := decodeSessionV6Payload(payload); ok {
				if val.IsReverse == 0 {
					s.bulkMu.Lock()
					if s.bulkInProgress {
						s.bulkRecvV6[key] = struct{}{}
					}
					s.bulkMu.Unlock()
				}
				offset := s.peerClockOffset.Load()
				val.Created = rebaseTimestamp(val.Created, offset)
				val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
				s.installClusterSyncedV6(key, val)
			}
		}
	case syncMsgDeleteV4:
		s.stats.DeletesReceived.Add(1)
		if s.sessions != nil && len(payload) >= 16 {
			var key dataplane.SessionKey
			copy(key.SrcIP[:], payload[0:4])
			copy(key.DstIP[:], payload[4:8])
			key.SrcPort = binary.LittleEndian.Uint16(payload[8:10])
			key.DstPort = binary.LittleEndian.Uint16(payload[10:12])
			key.Protocol = payload[12]
			s.deleteClusterSyncedV4(key)
		}
	case syncMsgDeleteV6:
		s.stats.DeletesReceived.Add(1)
		if s.sessions != nil && len(payload) >= 40 {
			var key dataplane.SessionKeyV6
			copy(key.SrcIP[:], payload[0:16])
			copy(key.DstIP[:], payload[16:32])
			key.SrcPort = binary.LittleEndian.Uint16(payload[32:34])
			key.DstPort = binary.LittleEndian.Uint16(payload[34:36])
			key.Protocol = payload[36]
			s.deleteClusterSyncedV6(key)
		}
	case syncMsgBulkStart:
		var epoch uint64
		if len(payload) >= 8 {
			epoch = binary.LittleEndian.Uint64(payload[:8])
		}
		s.stats.BulkSyncStartTime.Store(time.Now().UnixNano())
		s.stats.BulkSyncEndTime.Store(0)
		s.stats.BulkSyncSessions.Store(0)
		zoneSnap := s.snapshotZoneOwnership()
		s.bulkMu.Lock()
		s.bulkInProgress = true
		s.bulkRecvEpoch = epoch
		s.bulkRecvV4 = make(map[dataplane.SessionKey]struct{})
		s.bulkRecvV6 = make(map[dataplane.SessionKeyV6]struct{})
		s.bulkZoneSnapshot = zoneSnap
		s.bulkMu.Unlock()
		slog.Info("cluster sync: bulk transfer starting", "epoch", epoch, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
	case syncMsgBulkEnd:
		var epoch uint64
		if len(payload) >= 8 {
			epoch = binary.LittleEndian.Uint64(payload[:8])
		}
		s.bulkMu.Lock()
		if s.bulkInProgress && s.bulkRecvEpoch != epoch {
			s.bulkMu.Unlock()
			slog.Warn("cluster sync: ignoring BulkEnd with mismatched epoch", "expected", s.bulkRecvEpoch, "got", epoch)
			break
		}
		s.bulkMu.Unlock()
		s.stats.BulkSyncEndTime.Store(time.Now().UnixNano())
		s.reconcileStaleSessions()
		slog.Info("cluster sync: bulk transfer complete", "epoch", epoch, "sessions", s.stats.BulkSyncSessions.Load(), "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn))
		s.sendBulkAck(conn, epoch)
		s.bulkEverCompleted.Store(true)
		if s.OnBulkSyncReceived != nil {
			go s.OnBulkSyncReceived()
		}
	case syncMsgBulkAck:
		if len(payload) < 8 {
			slog.Warn("cluster sync: bulk ack message too short")
			return
		}
		epoch := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		slog.Info("cluster sync: bulk ack received", "epoch", epoch, "local", connLocalAddrString(conn), "remote", connRemoteAddrString(conn), "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		if pending := s.pendingBulkAckEpoch.Load(); pending != 0 && epoch >= pending {
			s.pendingBulkAckEpoch.Store(0)
			s.pendingBulkAckSince.Store(0)
		}
		s.bulkEverCompleted.Store(true)
		if s.OnBulkSyncAckReceived != nil {
			go s.OnBulkSyncAckReceived()
		}
	case syncMsgHeartbeat:
		if conn == nil {
			return
		}
		s.writeMu.Lock()
		err := writeMsg(conn, syncMsgHeartbeatAck, nil)
		s.writeMu.Unlock()
		if err != nil {
			slog.Debug("cluster sync: heartbeat ack send error", "err", err)
			s.stats.Errors.Add(1)
			s.handleDisconnect(conn)
		}
	case syncMsgHeartbeatAck:
		s.peerHeartbeatAckEver.Store(true)
	case syncMsgConfig:
		s.stats.ConfigsReceived.Add(1)
		s.stats.LastConfigSyncTime.Store(time.Now().UnixNano())
		s.stats.LastConfigSyncSize.Store(uint64(len(payload)))
		if s.OnConfigReceived != nil {
			configText := string(payload)
			slog.Info("cluster sync: config received from peer", "size", len(payload))
			go s.OnConfigReceived(configText)
		}
	case syncMsgIPsecSA:
		s.stats.IPsecSAReceived.Add(1)
		names := decodeIPsecSAPayload(payload)
		s.peerIPsecSAsMu.Lock()
		s.peerIPsecSAs = names
		s.peerIPsecSAsMu.Unlock()
		slog.Debug("cluster sync: received IPsec SA list", "count", len(names))
		if s.OnIPsecSAReceived != nil {
			s.OnIPsecSAReceived(names)
		}
	case syncMsgFailover:
		if len(payload) < 9 {
			slog.Warn("cluster sync: failover message too short")
			return
		}
		rgID := int(payload[0])
		reqID := binary.LittleEndian.Uint64(payload[1:9])
		slog.Info("cluster sync: remote failover request received", "rg", rgID, "req_id", reqID)
		go s.handleRemoteFailover(conn, rgID, reqID)
	case syncMsgFailoverAck:
		if len(payload) < 10 {
			slog.Warn("cluster sync: failover ack message too short")
			return
		}
		rgID := int(payload[0])
		status := payload[1]
		reqID := binary.LittleEndian.Uint64(payload[2:10])
		detail := string(payload[10:])
		slog.Info("cluster sync: failover ack received", "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverWait(rgID, reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverCommit:
		if len(payload) < 9 {
			slog.Warn("cluster sync: failover commit message too short")
			return
		}
		rgID := int(payload[0])
		reqID := binary.LittleEndian.Uint64(payload[1:9])
		slog.Info("cluster sync: remote failover commit received", "rg", rgID, "req_id", reqID)
		go s.handleRemoteFailoverCommit(conn, rgID, reqID)
	case syncMsgFailoverCommitAck:
		if len(payload) < 10 {
			slog.Warn("cluster sync: failover commit ack message too short")
			return
		}
		rgID := int(payload[0])
		status := payload[1]
		reqID := binary.LittleEndian.Uint64(payload[2:10])
		detail := string(payload[10:])
		slog.Info("cluster sync: failover commit ack received", "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverCommitWait(rgID, reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverBatch:
		rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover message decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: remote batch failover request received", "rgs", rgIDs, "req_id", reqID)
		go s.handleRemoteFailoverBatch(conn, rgIDs, reqID)
	case syncMsgFailoverBatchAck:
		rgIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover ack decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: batch failover ack received", "rgs", rgIDs, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverBatchWait(failoverBatchKey(rgIDs), reqID, failoverAck{status: status, detail: detail})
	case syncMsgFailoverBatchCommit:
		rgIDs, reqID, err := decodeFailoverBatchRequestPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover commit message decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: remote batch failover commit received", "rgs", rgIDs, "req_id", reqID)
		go s.handleRemoteFailoverCommitBatch(conn, rgIDs, reqID)
	case syncMsgFailoverBatchCommitAck:
		rgIDs, status, reqID, detail, err := decodeFailoverBatchAckPayload(payload)
		if err != nil {
			slog.Warn("cluster sync: batch failover commit ack decode failed", "err", err)
			return
		}
		slog.Info("cluster sync: batch failover commit ack received", "rgs", rgIDs, "req_id", reqID, "status", status, "detail", detail)
		s.completeFailoverBatchCommitWait(failoverBatchKey(rgIDs), reqID, failoverAck{status: status, detail: detail})
	case syncMsgFence:
		s.stats.FencesReceived.Add(1)
		slog.Warn("cluster sync: fence received from peer — disabling all RGs")
		if s.OnFenceReceived != nil {
			s.OnFenceReceived()
		}
	case syncMsgClockSync:
		if len(payload) < 8 {
			slog.Warn("cluster sync: clock sync message too short")
			return
		}
		peerMono := binary.LittleEndian.Uint64(payload[:8])
		localMono := monotonicSeconds()
		offset := int64(localMono) - int64(peerMono)
		s.peerClockOffset.Store(offset)
		s.clockSynced.Store(true)
		slog.Info("cluster sync: clock synced with peer", "peer_mono", peerMono, "local_mono", localMono, "offset", offset)
	case syncMsgPrepareActivation:
		if len(payload) < 1 {
			slog.Warn("cluster sync: prepare_activation message too short")
			return
		}
		rgID := int(payload[0])
		slog.Info("cluster sync: prepare_activation received from demoting peer", "rg", rgID)
		if s.OnPrepareActivation != nil {
			go s.OnPrepareActivation(rgID)
		}
	case syncMsgBarrier:
		if len(payload) < 8 {
			slog.Warn("cluster sync: barrier message too short")
			return
		}
		seq := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		slog.Info("cluster sync: barrier received", "seq", seq, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		s.sendBarrierAck(conn, seq)
	case syncMsgBarrierAck:
		if len(payload) < 8 {
			slog.Warn("cluster sync: barrier ack message too short")
			return
		}
		seq := binary.LittleEndian.Uint64(payload[:8])
		stats := s.Stats()
		peerSessionsReceived := uint64(0)
		peerSessionsInstalled := uint64(0)
		if len(payload) >= 24 {
			peerSessionsReceived = binary.LittleEndian.Uint64(payload[8:16])
			peerSessionsInstalled = binary.LittleEndian.Uint64(payload[16:24])
		}
		slog.Info("cluster sync: barrier ack received", "seq", seq, "sessions_sent", stats.SessionsSent, "sessions_received", stats.SessionsReceived, "sessions_installed", stats.SessionsInstalled, "peer_sessions_received", peerSessionsReceived, "peer_sessions_installed", peerSessionsInstalled, "queue_len", len(s.sendCh), "queue_cap", cap(s.sendCh))
		for {
			current := s.barrierAckSeq.Load()
			if seq <= current || s.barrierAckSeq.CompareAndSwap(current, seq) {
				break
			}
		}
		s.stats.LastFenceAckAt.Store(time.Now().UnixNano())
		s.completeBarrierWait(seq)
	}
}
func (s *SessionSync) handleDisconnect(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.conn0 != nil && s.conn0 == conn:
		s.conn0.Close()
		s.conn0 = nil
		slog.Info("cluster sync: fabric 0 disconnected")
	case s.conn1 != nil && s.conn1 == conn:
		s.conn1.Close()
		s.conn1 = nil
		slog.Info("cluster sync: fabric 1 disconnected")
	default:
		slog.Debug("cluster sync: ignoring stale disconnect", "stale", fmt.Sprintf("%p", conn))
		return
	}
	connected := s.conn0 != nil || s.conn1 != nil
	s.stats.Connected.Store(connected)
	if !connected {
		pendingBarriers := s.barrierSeq.Load()
		ackedBarriers := s.barrierAckSeq.Load()
		s.barrierWaitMu.Lock()
		clearedWaiters := len(s.barrierWaiters)
		staleWaiters := s.barrierWaiters
		s.barrierWaiters = nil
		s.barrierWaitMu.Unlock()
		for _, ch := range staleWaiters {
			close(ch)
		}
		s.failoverWaitMu.Lock()
		failoverWaiters := s.failoverWaiters
		failoverCommitWaiters := s.failoverCommitWaiters
		failoverBatchWaiters := s.failoverBatchWaiters
		failoverBatchCommitWaiters := s.failoverBatchCommitWaiters
		clearedFailoverWaiters := len(failoverWaiters)
		clearedFailoverCommitWaiters := len(failoverCommitWaiters)
		clearedFailoverBatchWaiters := len(failoverBatchWaiters)
		clearedFailoverBatchCommitWaiters := len(failoverBatchCommitWaiters)
		s.failoverWaiters = make(map[int]failoverWaiter)
		s.failoverCommitWaiters = make(map[int]failoverWaiter)
		s.failoverBatchWaiters = make(map[string]failoverWaiter)
		s.failoverBatchCommitWaiters = make(map[string]failoverWaiter)
		s.failoverWaitMu.Unlock()
		for _, waiter := range failoverWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverCommitWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverBatchWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		for _, waiter := range failoverBatchCommitWaiters {
			select {
			case waiter.ch <- failoverAck{status: failoverAckDisconnected, detail: "peer disconnected"}:
			default:
			}
			close(waiter.ch)
		}
		s.clockSynced.Store(false)
		s.pendingBulkAckEpoch.Store(0)
		s.pendingBulkAckSince.Store(0)
		s.bulkMu.Lock()
		hadBulkInProgress := s.bulkInProgress
		s.bulkInProgress = false
		s.bulkRecvEpoch = 0
		s.bulkRecvV4 = nil
		s.bulkRecvV6 = nil
		s.bulkZoneSnapshot = nil
		s.bulkMu.Unlock()
		if hadBulkInProgress {
			slog.Info("cluster sync: reset in-progress bulk receive on disconnect")
		}
		slog.Info("cluster sync: peer disconnected (all fabrics down)")
		if pendingBarriers != 0 || ackedBarriers != 0 || clearedWaiters != 0 || clearedFailoverWaiters != 0 || clearedFailoverCommitWaiters != 0 || clearedFailoverBatchWaiters != 0 || clearedFailoverBatchCommitWaiters != 0 {
			slog.Info("cluster sync: reset barrier state after disconnect", "pending_seq", pendingBarriers, "acked_seq", ackedBarriers, "cleared_waiters", clearedWaiters, "cleared_failover_waiters", clearedFailoverWaiters, "cleared_failover_commit_waiters", clearedFailoverCommitWaiters, "cleared_failover_batch_waiters", clearedFailoverBatchWaiters, "cleared_failover_batch_commit_waiters", clearedFailoverBatchCommitWaiters)
		}
		if s.OnPeerDisconnected != nil {
			go s.OnPeerDisconnected()
		}
	}
}
