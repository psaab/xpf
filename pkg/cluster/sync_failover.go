package cluster

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

func validateFailoverBatchRGCount(rgIDs []int) error {
	if len(rgIDs) > maxFailoverBatchRGCount {
		return fmt.Errorf("too many redundancy groups in failover batch: %d > %d", len(rgIDs), maxFailoverBatchRGCount)
	}
	return nil
}
func rgSetOverlap(a, b []int) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[int]struct{}, len(a))
	for _, rgID := range a {
		set[rgID] = struct{}{}
	}
	for _, rgID := range b {
		if _, ok := set[rgID]; ok {
			return true
		}
	}
	return false
}
func validateFailoverProtocolRGID(rgID int) error {
	if rgID < 0 || rgID > 255 {
		return fmt.Errorf("redundancy group %d out of failover protocol range 0..255", rgID)
	}
	return nil
}
func validateFailoverProtocolRGIDs(rgIDs []int) error {
	for _, rgID := range rgIDs {
		if err := validateFailoverProtocolRGID(rgID); err != nil {
			return err
		}
	}
	return nil
}
func (s *SessionSync) failoverRGInUseLocked(rgIDs []int) bool {
	for _, rgID := range rgIDs {
		if _, exists := s.failoverWaiters[rgID]; exists {
			return true
		}
		if _, exists := s.failoverCommitWaiters[rgID]; exists {
			return true
		}
	}
	for _, waiter := range s.failoverBatchWaiters {
		if rgSetOverlap(waiter.rgIDs, rgIDs) {
			return true
		}
	}
	for _, waiter := range s.failoverBatchCommitWaiters {
		if rgSetOverlap(waiter.rgIDs, rgIDs) {
			return true
		}
	}
	return false
}

// SendFailover sends a remote failover request to the peer and waits for an
// explicit applied or rejected acknowledgement.
func (s *SessionSync) SendFailover(rgID int) (uint64, error) {
	if err := validateFailoverProtocolRGID(rgID); err != nil {
		return 0, err
	}
	conn := s.getActiveConn()
	if conn == nil {
		return 0, fmt.Errorf("peer not connected")
	}
	waitCh := make(chan failoverAck, 1)
	reqID := s.failoverSeq.Add(1)
	s.failoverWaitMu.Lock()
	if _, exists := s.failoverWaiters[rgID]; exists {
		s.failoverWaitMu.Unlock()
		return 0, fmt.Errorf("failover request already in flight for redundancy group %d", rgID)
	}
	if s.failoverRGInUseLocked([]int{rgID}) {
		s.failoverWaitMu.Unlock()
		return 0, fmt.Errorf("failover request already in flight for redundancy group %d", rgID)
	}
	s.failoverWaiters[rgID] = failoverWaiter{reqID: reqID, ch: waitCh, rgIDs: []int{rgID}}
	s.failoverWaitMu.Unlock()
	payload := make([]byte, 9)
	payload[0] = byte(rgID)
	binary.LittleEndian.PutUint64(payload[1:9], reqID)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgFailover, payload)
	s.writeMu.Unlock()
	if err != nil {
		s.completeFailoverWait(rgID, reqID, failoverAck{status: failoverAckDisconnected, detail: "send failed"})
		slog.Warn("cluster sync: failover send error", "err", err, "rg", rgID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return 0, fmt.Errorf("failed to send failover request: %w", err)
	}
	slog.Info("cluster sync: failover request sent to peer", "rg", rgID)
	timer := time.NewTimer(failoverAckTimeout)
	defer timer.Stop()
	select {
	case ack := <-waitCh:
		return reqID, failoverAckError([]int{rgID}, ack)
	case <-timer.C:
		select {
		case ack := <-waitCh:
			return reqID, failoverAckError([]int{rgID}, ack)
		default:
		}
		s.failoverWaitMu.Lock()
		if current, ok := s.failoverWaiters[rgID]; ok && current.reqID == reqID && current.ch == waitCh {
			delete(s.failoverWaiters, rgID)
		}
		s.failoverWaitMu.Unlock()
		return 0, fmt.Errorf("timed out waiting for peer failover ack for redundancy group %d", rgID)
	}
}

// SendFailoverBatch sends a remote failover request for multiple RGs and waits
// for an explicit applied or rejected acknowledgement.
func (s *SessionSync) SendFailoverBatch(rgIDs []int) (uint64, error) {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return 0, err
	}
	if len(ids) == 1 {
		return s.SendFailover(ids[0])
	}
	if err := validateFailoverProtocolRGIDs(ids); err != nil {
		return 0, err
	}
	if err := validateFailoverBatchRGCount(ids); err != nil {
		return 0, err
	}
	conn := s.getActiveConn()
	if conn == nil {
		return 0, fmt.Errorf("peer not connected")
	}
	waitCh := make(chan failoverAck, 1)
	reqID := s.failoverSeq.Add(1)
	key := failoverBatchKey(ids)
	s.failoverWaitMu.Lock()
	if _, exists := s.failoverBatchWaiters[key]; exists || s.failoverRGInUseLocked(ids) {
		s.failoverWaitMu.Unlock()
		return 0, fmt.Errorf("failover request already in flight for redundancy groups %v", ids)
	}
	s.failoverBatchWaiters[key] = failoverWaiter{reqID: reqID, ch: waitCh, rgIDs: append([]int(nil), ids...)}
	s.failoverWaitMu.Unlock()
	payload := encodeFailoverBatchRequestPayload(ids, reqID)
	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgFailoverBatch, payload)
	s.writeMu.Unlock()
	if err != nil {
		s.completeFailoverBatchWait(key, reqID, failoverAck{status: failoverAckDisconnected, detail: "send failed"})
		slog.Warn("cluster sync: batch failover send error", "err", err, "rgs", ids)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return 0, fmt.Errorf("failed to send batch failover request: %w", err)
	}
	slog.Info("cluster sync: batch failover request sent to peer", "rgs", ids)
	timer := time.NewTimer(failoverAckTimeout)
	defer timer.Stop()
	select {
	case ack := <-waitCh:
		if err := failoverAckError(ids, ack); err != nil {
			return 0, err
		}
		return reqID, nil
	case <-timer.C:
		select {
		case ack := <-waitCh:
			if err := failoverAckError(ids, ack); err != nil {
				return 0, err
			}
			return reqID, nil
		default:
		}
		s.failoverWaitMu.Lock()
		if current, ok := s.failoverBatchWaiters[key]; ok && current.reqID == reqID && current.ch == waitCh {
			delete(s.failoverBatchWaiters, key)
		}
		s.failoverWaitMu.Unlock()
		return 0, fmt.Errorf("timed out waiting for peer failover ack for redundancy groups %v", ids)
	}
}
func failoverAckError(rgIDs []int, ack failoverAck) error {
	label := fmt.Sprintf("redundancy groups %v", rgIDs)
	if len(rgIDs) == 1 {
		label = fmt.Sprintf("redundancy group %d", rgIDs[0])
	}
	switch ack.status {
	case failoverAckApplied:
		return nil
	case failoverAckRejected:
		if ack.detail != "" {
			return fmt.Errorf("peer rejected failover request for %s: %s", label, ack.detail)
		}
		return fmt.Errorf("peer rejected failover request for %s", label)
	case failoverAckFailed:
		if ack.detail != "" {
			return fmt.Errorf("peer failed failover request for %s: %s", label, ack.detail)
		}
		return fmt.Errorf("peer failed failover request for %s", label)
	default:
		if ack.detail != "" {
			return fmt.Errorf("failover request for %s aborted: %s", label, ack.detail)
		}
		return fmt.Errorf("failover request for %s aborted", label)
	}
}

// SendFailoverCommit sends the final ownership-commit step for a previously
// acknowledged failover request and waits for the peer to finalize transfer-out.
func (s *SessionSync) SendFailoverCommit(rgID int, reqID uint64) error {
	if err := validateFailoverProtocolRGID(rgID); err != nil {
		return err
	}
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("peer not connected")
	}
	waitCh := make(chan failoverAck, 1)
	s.failoverWaitMu.Lock()
	if _, exists := s.failoverCommitWaiters[rgID]; exists {
		s.failoverWaitMu.Unlock()
		return fmt.Errorf("failover commit already in flight for redundancy group %d", rgID)
	}
	if s.failoverRGInUseLocked([]int{rgID}) {
		s.failoverWaitMu.Unlock()
		return fmt.Errorf("failover commit already in flight for redundancy group %d", rgID)
	}
	s.failoverCommitWaiters[rgID] = failoverWaiter{reqID: reqID, ch: waitCh, rgIDs: []int{rgID}}
	s.failoverWaitMu.Unlock()
	payload := make([]byte, 9)
	payload[0] = byte(rgID)
	binary.LittleEndian.PutUint64(payload[1:9], reqID)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgFailoverCommit, payload)
	s.writeMu.Unlock()
	if err != nil {
		s.completeFailoverCommitWait(rgID, reqID, failoverAck{status: failoverAckDisconnected, detail: "send failed"})
		slog.Warn("cluster sync: failover commit send error", "err", err, "rg", rgID, "req_id", reqID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send failover commit: %w", err)
	}
	slog.Info("cluster sync: failover commit sent to peer", "rg", rgID, "req_id", reqID)
	timer := time.NewTimer(failoverAckTimeout)
	defer timer.Stop()
	select {
	case ack := <-waitCh:
		return failoverCommitAckError(rgID, ack)
	case <-timer.C:
		select {
		case ack := <-waitCh:
			return failoverCommitAckError(rgID, ack)
		default:
		}
		s.failoverWaitMu.Lock()
		if current, ok := s.failoverCommitWaiters[rgID]; ok && current.reqID == reqID && current.ch == waitCh {
			delete(s.failoverCommitWaiters, rgID)
		}
		s.failoverWaitMu.Unlock()
		return fmt.Errorf("timed out waiting for peer failover commit ack for redundancy group %d", rgID)
	}
}

// SendFailoverCommitBatch sends the final ownership-commit step for a
// previously acknowledged multi-RG failover request.
func (s *SessionSync) SendFailoverCommitBatch(rgIDs []int, reqID uint64) error {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return s.SendFailoverCommit(ids[0], reqID)
	}
	if err := validateFailoverProtocolRGIDs(ids); err != nil {
		return err
	}
	if err := validateFailoverBatchRGCount(ids); err != nil {
		return err
	}
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("peer not connected")
	}
	waitCh := make(chan failoverAck, 1)
	key := failoverBatchKey(ids)
	s.failoverWaitMu.Lock()
	if _, exists := s.failoverBatchCommitWaiters[key]; exists || s.failoverRGInUseLocked(ids) {
		s.failoverWaitMu.Unlock()
		return fmt.Errorf("failover commit already in flight for redundancy groups %v", ids)
	}
	s.failoverBatchCommitWaiters[key] = failoverWaiter{reqID: reqID, ch: waitCh, rgIDs: append([]int(nil), ids...)}
	s.failoverWaitMu.Unlock()
	payload := encodeFailoverBatchRequestPayload(ids, reqID)
	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgFailoverBatchCommit, payload)
	s.writeMu.Unlock()
	if err != nil {
		s.completeFailoverBatchCommitWait(key, reqID, failoverAck{status: failoverAckDisconnected, detail: "send failed"})
		slog.Warn("cluster sync: batch failover commit send error", "err", err, "rgs", ids, "req_id", reqID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send batch failover commit: %w", err)
	}
	slog.Info("cluster sync: batch failover commit sent to peer", "rgs", ids, "req_id", reqID)
	timer := time.NewTimer(failoverAckTimeout)
	defer timer.Stop()
	select {
	case ack := <-waitCh:
		return failoverCommitAckBatchError(ids, ack)
	case <-timer.C:
		select {
		case ack := <-waitCh:
			return failoverCommitAckBatchError(ids, ack)
		default:
		}
		s.failoverWaitMu.Lock()
		if current, ok := s.failoverBatchCommitWaiters[key]; ok && current.reqID == reqID && current.ch == waitCh {
			delete(s.failoverBatchCommitWaiters, key)
		}
		s.failoverWaitMu.Unlock()
		return fmt.Errorf("timed out waiting for peer failover commit ack for redundancy groups %v", ids)
	}
}
func failoverCommitAckBatchError(rgIDs []int, ack failoverAck) error {
	label := fmt.Sprintf("redundancy groups %v", rgIDs)
	switch ack.status {
	case failoverAckApplied:
		return nil
	case failoverAckRejected:
		if ack.detail != "" {
			return fmt.Errorf("peer rejected failover commit for %s: %s", label, ack.detail)
		}
		return fmt.Errorf("peer rejected failover commit for %s", label)
	case failoverAckFailed:
		if ack.detail != "" {
			return fmt.Errorf("peer failed failover commit for %s: %s", label, ack.detail)
		}
		return fmt.Errorf("peer failed failover commit for %s", label)
	default:
		if ack.detail != "" {
			return fmt.Errorf("failover commit for %s aborted: %s", label, ack.detail)
		}
		return fmt.Errorf("failover commit for %s aborted", label)
	}
}
func failoverCommitAckError(rgID int, ack failoverAck) error {
	switch ack.status {
	case failoverAckApplied:
		return nil
	case failoverAckRejected:
		if ack.detail != "" {
			return fmt.Errorf("peer rejected failover commit for redundancy group %d: %s", rgID, ack.detail)
		}
		return fmt.Errorf("peer rejected failover commit for redundancy group %d", rgID)
	case failoverAckFailed:
		if ack.detail != "" {
			return fmt.Errorf("peer failed failover commit for redundancy group %d: %s", rgID, ack.detail)
		}
		return fmt.Errorf("peer failed failover commit for redundancy group %d", rgID)
	default:
		if ack.detail != "" {
			return fmt.Errorf("failover commit for redundancy group %d aborted: %s", rgID, ack.detail)
		}
		return fmt.Errorf("failover commit for redundancy group %d aborted", rgID)
	}
}

// SendFence sends a fence message to the peer, requesting it to disable all
// redundancy groups as a best-effort operation.
func (s *SessionSync) SendFence() error {
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("peer not connected")
	}
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgFence, nil)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: fence send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send fence message: %w", err)
	}
	s.stats.FencesSent.Add(1)
	slog.Info("cluster sync: fence message sent to peer")
	return nil
}

func (s *SessionSync) handleRemoteFailover(conn net.Conn, rgID int, reqID uint64) {
	if s.OnRemoteFailover == nil {
		s.sendFailoverResult(conn, syncMsgFailoverAck, rgID, reqID, failoverAckFailed, "no remote failover handler")
		return
	}
	if err := s.OnRemoteFailover(rgID, reqID); err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		s.sendFailoverResult(conn, syncMsgFailoverAck, rgID, reqID, status, err.Error())
		return
	}
	// #5640: OnRemoteFailover only ENQUEUES the async demotion event; the old
	// owner is not fenced (VRRP resigned / VIPs removed) until the daemon's
	// event consumer actuates it. Acking applied here let the peer promote
	// while this node still owned the RG → a two-owner window. Gate the
	// applied-ack on the fence-completion barrier; if the fence does not
	// actuate within the bounded timeout, downgrade to failed so the peer
	// holds rather than joining a split-brain.
	if s.WaitFailoverApplied != nil {
		if err := s.WaitFailoverApplied(rgID, reqID); err != nil {
			slog.Warn("cluster sync: remote failover fence barrier failed", "rg", rgID, "req_id", reqID, "err", err)
			s.sendFailoverResult(conn, syncMsgFailoverAck, rgID, reqID, failoverAckFailed, err.Error())
			return
		}
	}
	s.sendFailoverResult(conn, syncMsgFailoverAck, rgID, reqID, failoverAckApplied, "")
}
func (s *SessionSync) handleRemoteFailoverBatch(conn net.Conn, rgIDs []int, reqID uint64) {
	if s.OnRemoteFailoverBatch == nil {
		s.sendFailoverBatchResult(conn, syncMsgFailoverBatchAck, rgIDs, reqID, failoverAckFailed, "no remote batch failover handler")
		return
	}
	if err := s.OnRemoteFailoverBatch(rgIDs, reqID); err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		s.sendFailoverBatchResult(conn, syncMsgFailoverBatchAck, rgIDs, reqID, status, err.Error())
		return
	}
	// #5640: gate the batch applied-ack on every RG being fenced. See
	// handleRemoteFailover for the two-owner rationale — a batch handoff that
	// acks before actuation opens the same window across the whole set.
	if s.WaitFailoverAppliedBatch != nil {
		if err := s.WaitFailoverAppliedBatch(rgIDs, reqID); err != nil {
			slog.Warn("cluster sync: remote batch failover fence barrier failed", "rgs", rgIDs, "req_id", reqID, "err", err)
			s.sendFailoverBatchResult(conn, syncMsgFailoverBatchAck, rgIDs, reqID, failoverAckFailed, err.Error())
			return
		}
	}
	s.sendFailoverBatchResult(conn, syncMsgFailoverBatchAck, rgIDs, reqID, failoverAckApplied, "")
}
func (s *SessionSync) handleRemoteFailoverCommit(conn net.Conn, rgID int, reqID uint64) {
	if s.OnRemoteFailoverCommit == nil {
		s.sendFailoverResult(conn, syncMsgFailoverCommitAck, rgID, reqID, failoverAckFailed, "no remote failover commit handler")
		return
	}
	if err := s.OnRemoteFailoverCommit(rgID, reqID); err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		s.sendFailoverResult(conn, syncMsgFailoverCommitAck, rgID, reqID, status, err.Error())
		return
	}
	s.sendFailoverResult(conn, syncMsgFailoverCommitAck, rgID, reqID, failoverAckApplied, "")
}
func (s *SessionSync) handleRemoteFailoverCommitBatch(conn net.Conn, rgIDs []int, reqID uint64) {
	if s.OnRemoteFailoverCommitBatch == nil {
		s.sendFailoverBatchResult(conn, syncMsgFailoverBatchCommitAck, rgIDs, reqID, failoverAckFailed, "no remote batch failover commit handler")
		return
	}
	if err := s.OnRemoteFailoverCommitBatch(rgIDs, reqID); err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		s.sendFailoverBatchResult(conn, syncMsgFailoverBatchCommitAck, rgIDs, reqID, status, err.Error())
		return
	}
	s.sendFailoverBatchResult(conn, syncMsgFailoverBatchCommitAck, rgIDs, reqID, failoverAckApplied, "")
}
func (s *SessionSync) sendFailoverResult(conn net.Conn, msgType uint8, rgID int, reqID uint64, status uint8, detail string) {
	ackConn := s.getActiveConn()
	if ackConn == nil {
		ackConn = conn
	}
	if ackConn == nil {
		return
	}
	payload := make([]byte, 10+len(detail))
	payload[0] = byte(rgID)
	payload[1] = status
	binary.LittleEndian.PutUint64(payload[2:10], reqID)
	copy(payload[10:], detail)
	s.writeMu.Lock()
	err := writeMsg(ackConn, msgType, payload)
	firstErr := err
	if err != nil && conn != nil && ackConn != conn {
		err = writeMsg(conn, msgType, payload)
	}
	s.writeMu.Unlock()
	if firstErr != nil && ackConn != nil && ackConn != conn {
		s.handleDisconnect(ackConn)
	}
	if err != nil {
		slog.Warn("cluster sync: failover result send error", "err", err, "msg_type", msgType, "rg", rgID, "req_id", reqID, "status", status)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	slog.Info("cluster sync: failover result sent", "msg_type", msgType, "rg", rgID, "req_id", reqID, "status", status, "detail", detail)
}
func (s *SessionSync) completeFailoverWait(rgID int, reqID uint64, ack failoverAck) {
	s.failoverWaitMu.Lock()
	waiter := s.failoverWaiters[rgID]
	if waiter.reqID == reqID {
		delete(s.failoverWaiters, rgID)
	}
	s.failoverWaitMu.Unlock()
	if waiter.ch == nil || waiter.reqID != reqID {
		return
	}
	select {
	case waiter.ch <- ack:
	default:
	}
}
func (s *SessionSync) completeFailoverBatchWait(key string, reqID uint64, ack failoverAck) {
	s.failoverWaitMu.Lock()
	waiter, ok := s.failoverBatchWaiters[key]
	if ok && waiter.reqID == reqID {
		delete(s.failoverBatchWaiters, key)
	}
	s.failoverWaitMu.Unlock()
	if !ok || waiter.ch == nil || waiter.reqID != reqID {
		return
	}
	select {
	case waiter.ch <- ack:
	default:
	}
}
func (s *SessionSync) sendFailoverBatchResult(conn net.Conn, msgType uint8, rgIDs []int, reqID uint64, status uint8, detail string) {
	if err := validateFailoverBatchRGCount(rgIDs); err != nil {
		slog.Warn("cluster sync: refusing to send oversized batch failover result", "err", err, "msg_type", msgType, "rgs", rgIDs, "req_id", reqID, "status", status)
		return
	}
	ackConn := s.getActiveConn()
	if ackConn == nil {
		ackConn = conn
	}
	if ackConn == nil {
		return
	}
	payload := encodeFailoverBatchAckPayload(rgIDs, status, reqID, detail)
	s.writeMu.Lock()
	err := writeMsg(ackConn, msgType, payload)
	firstErr := err
	if err != nil && conn != nil && ackConn != conn {
		err = writeMsg(conn, msgType, payload)
	}
	s.writeMu.Unlock()
	if firstErr != nil && ackConn != nil && ackConn != conn {
		s.handleDisconnect(ackConn)
	}
	if err != nil {
		if firstErr != nil && conn != nil && ackConn != conn {
			slog.Warn("cluster sync: batch failover result send error on active conn", "err", firstErr, "msg_type", msgType, "rgs", rgIDs, "req_id", reqID, "status", status)
		}
		slog.Warn("cluster sync: batch failover result send error", "err", err, "msg_type", msgType, "rgs", rgIDs, "req_id", reqID, "status", status)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
}
func (s *SessionSync) completeFailoverCommitWait(rgID int, reqID uint64, ack failoverAck) {
	s.failoverWaitMu.Lock()
	waiter := s.failoverCommitWaiters[rgID]
	if waiter.reqID == reqID {
		delete(s.failoverCommitWaiters, rgID)
	}
	s.failoverWaitMu.Unlock()
	if waiter.ch == nil || waiter.reqID != reqID {
		return
	}
	select {
	case waiter.ch <- ack:
	default:
	}
}
func (s *SessionSync) completeFailoverBatchCommitWait(key string, reqID uint64, ack failoverAck) {
	s.failoverWaitMu.Lock()
	waiter, ok := s.failoverBatchCommitWaiters[key]
	if ok && waiter.reqID == reqID {
		delete(s.failoverBatchCommitWaiters, key)
	}
	s.failoverWaitMu.Unlock()
	if !ok || waiter.ch == nil || waiter.reqID != reqID {
		return
	}
	select {
	case waiter.ch <- ack:
	default:
	}
}
