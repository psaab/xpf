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

// failoverWaitPartition separates the request and commit phases so an
// acknowledged request never completes a commit waiter (or vice versa).
type failoverWaitPartition int

const (
	failoverWaitRequest failoverWaitPartition = iota
	failoverWaitCommit
)

// failoverWaitKey is the canonical registry key: a phase plus the sorted
// normalised RG set, rendered like failoverBatchKey for readability. The
// single flag records whether the registration came from a single-RG call so
// handleDisconnect can keep its per-shape cleared counts.
type failoverWaitKey struct {
	partition failoverWaitPartition
	key       string
	single    bool
}

// failoverWaiterRegistry is the single waiter map (#17102). One
// declaration replaces the four hand-copied maps (single/batch x
// request/commit); every entry records its RG set so overlapping
// registrations are refused across phases and shapes.
type failoverWaiterRegistry map[failoverWaitKey]failoverWaiter

func newFailoverWaiterRegistry() failoverWaiterRegistry {
	return make(failoverWaiterRegistry)
}

func (s *SessionSync) ensureFailoverRegistryLocked() {
	if s.failoverWaiters == nil {
		s.failoverWaiters = newFailoverWaiterRegistry()
	}
}

// failoverWaiterFor builds the canonical key + waiter entry for an RG set.
// single is true only for single-RG calls (payload shape [rg]), false for
// batch calls that carry the batch-normalised set.
func failoverWaiterFor(partition failoverWaitPartition, rgIDs []int, reqID uint64, ch chan failoverAck, single bool) (failoverWaitKey, failoverWaiter) {
	copied := append([]int(nil), rgIDs...)
	return failoverWaitKey{partition: partition, key: failoverBatchKey(rgIDs), single: single},
		failoverWaiter{reqID: reqID, ch: ch, rgIDs: copied}
}

func (s *SessionSync) completeFailoverWait(key failoverWaitKey, reqID uint64, ack failoverAck) bool {
	s.failoverWaitMu.Lock()
	s.ensureFailoverRegistryLocked()
	waiter, ok := s.failoverWaiters[key]
	if ok && waiter.reqID == reqID {
		delete(s.failoverWaiters, key)
	}
	s.failoverWaitMu.Unlock()
	if !ok || waiter.ch == nil || waiter.reqID != reqID {
		return false
	}
	select {
	case waiter.ch <- ack:
	default:
	}
	return true
}

// registerFailoverWaitForTest inserts a waiter directly (test fixture only).
func (s *SessionSync) registerFailoverWaitForTest(partition failoverWaitPartition, rgIDs []int, reqID uint64, ch chan failoverAck) {
	single := partition == failoverWaitRequest && len(rgIDs) == 1
	key, _ := failoverWaiterFor(partition, rgIDs, reqID, ch, single)
	s.failoverWaitMu.Lock()
	defer s.failoverWaitMu.Unlock()
	s.ensureFailoverRegistryLocked()
	s.failoverWaiters[key] = failoverWaiter{reqID: reqID, ch: ch, rgIDs: append([]int(nil), rgIDs...)}
}

func (s *SessionSync) removeFailoverWait(key failoverWaitKey, reqID uint64, ch chan failoverAck) {
	s.failoverWaitMu.Lock()
	defer s.failoverWaitMu.Unlock()
	s.ensureFailoverRegistryLocked()
	if current, ok := s.failoverWaiters[key]; ok && current.reqID == reqID && current.ch == ch {
		delete(s.failoverWaiters, key)
	}
}

// drainAllFailoverWaits swaps out every waiter and returns them for
// disconnect delivery. Delivery (send + close) stays with the caller.
func (s *SessionSync) drainAllFailoverWaits() (map[failoverWaitKey]failoverWaiter, [4]int) {
	s.failoverWaitMu.Lock()
	defer s.failoverWaitMu.Unlock()
	s.ensureFailoverRegistryLocked()
	drained := s.failoverWaiters
	counts := [4]int{}
	for key := range drained {
		switch key.partition {
		case failoverWaitRequest:
			if key.single {
				counts[0]++
			} else {
				counts[2]++
			}
		case failoverWaitCommit:
			if key.single {
				counts[1]++
			} else {
				counts[3]++
			}
		}
	}
	s.failoverWaiters = newFailoverWaiterRegistry()
	return drained, counts
}

func (s *SessionSync) failoverRGInUseLocked(rgIDs []int) bool {
	for _, waiter := range s.failoverWaiters {
		if rgSetOverlap(waiter.rgIDs, rgIDs) {
			return true
		}
	}
	return false
}

// failoverTripOutcome names the three terminal shapes of failoverRoundTrip
// so callers never have to string-match an error (#17102).
type failoverTripOutcome int

const (
	failoverTripAcked failoverTripOutcome = iota
	failoverTripRejected
	failoverTripSendFailed
	failoverTripTimedOut
)

// failoverRoundTrip is the single failover request/commit skeleton (#17102):
// register one waiter, write one frame, drain the ack or the timeout, and
// mirror the send-error arm. Payload encoding and ack interpretation stay
// with the caller, so nothing here knows the single/batch wire shapes.
//
// The returned reqID mirrors SendFailover's contract (#16592): non-zero
// whenever the request was sent (including ack failure/timeout), zero on
// local rejection or failed send. Commit callers discard it.
func (s *SessionSync) failoverRoundTrip(msgType uint8, rgIDs []int, single bool, reqID uint64, genReqID bool, payload []byte, payloadFor func(reqID uint64) []byte) (failoverAck, uint64, failoverTripOutcome, error) {
	conn := s.getActiveConn()
	if conn == nil {
		return failoverAck{}, 0, failoverTripRejected, fmt.Errorf("peer not connected")
	}
	if genReqID {
		reqID = s.failoverSeq.Add(1)
	}
	partition := failoverWaitRequest
	if msgType == syncMsgFailoverCommit || msgType == syncMsgFailoverBatchCommit {
		partition = failoverWaitCommit
	}
	waitCh := make(chan failoverAck, 1)
	key, _ := failoverWaiterFor(partition, rgIDs, reqID, waitCh, single)
	s.failoverWaitMu.Lock()
	s.ensureFailoverRegistryLocked()
	if _, exists := s.failoverWaiters[key]; exists || s.failoverRGInUseLocked(rgIDs) {
		s.failoverWaitMu.Unlock()
		if partition == failoverWaitCommit {
			return failoverAck{}, 0, failoverTripRejected, fmt.Errorf("failover commit already in flight for %s", failoverRGLabel(rgIDs))
		}
		return failoverAck{}, 0, failoverTripRejected, fmt.Errorf("failover request already in flight for %s", failoverRGLabel(rgIDs))
	}
	s.failoverWaiters[key] = failoverWaiter{reqID: reqID, ch: waitCh, rgIDs: append([]int(nil), rgIDs...)}
	s.failoverWaitMu.Unlock()
	if payloadFor != nil {
		payload = payloadFor(reqID)
	}
	s.writeMu.Lock()
	err := writeMsg(conn, msgType, payload)
	s.writeMu.Unlock()
	if err != nil {
		s.completeFailoverWait(key, reqID, failoverAck{status: failoverAckDisconnected, detail: "send failed"})
		return failoverAck{}, 0, failoverTripSendFailed, err
	}
	timer := time.NewTimer(failoverAckTimeout)
	defer timer.Stop()
	select {
	case ack := <-waitCh:
		return ack, reqID, failoverTripAcked, nil
	case <-timer.C:
		select {
		case ack := <-waitCh:
			return ack, reqID, failoverTripAcked, nil
		default:
		}
		s.removeFailoverWait(key, reqID, waitCh)
		return failoverAck{}, reqID, failoverTripTimedOut, errFailoverTimeoutFor(msgType, rgIDs)
	}
}

// errFailoverTimeoutFor builds the legacy timeout string: request vs commit.
func errFailoverTimeoutFor(msgType uint8, rgIDs []int) error {
	if msgType == syncMsgFailoverCommit || msgType == syncMsgFailoverBatchCommit {
		return fmt.Errorf("timed out waiting for peer failover commit ack for %s", failoverRGLabel(rgIDs))
	}
	return fmt.Errorf("timed out waiting for peer failover ack for %s", failoverRGLabel(rgIDs))
}

func failoverRGLabel(rgIDs []int) string {
	if len(rgIDs) == 1 {
		return fmt.Sprintf("redundancy group %d", rgIDs[0])
	}
	return fmt.Sprintf("redundancy groups %v", rgIDs)
}

func encodeFailoverSingleReqPayload(rgID int, reqID uint64) []byte {
	payload := make([]byte, 9)
	payload[0] = byte(rgID)
	binary.LittleEndian.PutUint64(payload[1:9], reqID)
	return payload
}

// SendFailover sends a remote failover request to the peer and waits for an
// explicit applied or rejected acknowledgement. The returned reqID is
// non-zero whenever the request was sent (including on an ack failure or
// ack timeout), so the caller can bind a reqID-scoped abort to it (#16592);
// it is zero on local rejection or a failed send.
func (s *SessionSync) SendFailover(rgID int) (uint64, error) {
	if err := validateFailoverProtocolRGID(rgID); err != nil {
		return 0, err
	}
	conn := s.getActiveConn()
	if conn == nil {
		return 0, fmt.Errorf("peer not connected")
	}
	ack, reqID, outcome, err := s.failoverRoundTrip(syncMsgFailover, []int{rgID}, true, 0, true, nil,
		func(reqID uint64) []byte { return encodeFailoverSingleReqPayload(rgID, reqID) })
	switch outcome {
	case failoverTripAcked:
		slog.Info("cluster sync: failover request sent to peer", "rg", rgID)
		return reqID, failoverAckError([]int{rgID}, ack)
	case failoverTripSendFailed:
		slog.Warn("cluster sync: failover send error", "err", err, "rg", rgID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return 0, fmt.Errorf("failed to send failover request: %w", err)
	case failoverTripTimedOut:
		slog.Info("cluster sync: failover request sent to peer", "rg", rgID)
		return reqID, err
	default:
		return 0, err
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
	ack, reqID, outcome, err := s.failoverRoundTrip(syncMsgFailoverBatch, ids, false, 0, true, nil,
		func(reqID uint64) []byte { return encodeFailoverBatchRequestPayload(ids, reqID) })
	switch outcome {
	case failoverTripAcked:
		slog.Info("cluster sync: batch failover request sent to peer", "rgs", ids)
		return reqID, failoverAckError(ids, ack)
	case failoverTripSendFailed:
		slog.Warn("cluster sync: batch failover send error", "err", err, "rgs", ids)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return 0, fmt.Errorf("failed to send batch failover request: %w", err)
	case failoverTripTimedOut:
		slog.Info("cluster sync: batch failover request sent to peer", "rgs", ids)
		return reqID, err
	default:
		return 0, err
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
	payload := encodeFailoverSingleReqPayload(rgID, reqID)
	ack, _, outcome, err := s.failoverRoundTrip(syncMsgFailoverCommit, []int{rgID}, true, reqID, false, payload, nil)
	switch outcome {
	case failoverTripAcked:
		slog.Info("cluster sync: failover commit sent to peer", "rg", rgID, "req_id", reqID)
		return failoverCommitAckError(rgID, ack)
	case failoverTripSendFailed:
		slog.Warn("cluster sync: failover commit send error", "err", err, "rg", rgID, "req_id", reqID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send failover commit: %w", err)
	case failoverTripTimedOut:
		slog.Info("cluster sync: failover commit sent to peer", "rg", rgID, "req_id", reqID)
		return err
	default:
		return err
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
	payload := encodeFailoverBatchRequestPayload(ids, reqID)
	ack, _, outcome, err := s.failoverRoundTrip(syncMsgFailoverBatchCommit, ids, false, reqID, false, payload, nil)
	switch outcome {
	case failoverTripAcked:
		slog.Info("cluster sync: batch failover commit sent to peer", "rgs", ids, "req_id", reqID)
		return failoverCommitAckBatchError(ids, ack)
	case failoverTripSendFailed:
		slog.Warn("cluster sync: batch failover commit send error", "err", err, "rgs", ids, "req_id", reqID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send batch failover commit: %w", err)
	case failoverTripTimedOut:
		slog.Info("cluster sync: batch failover commit sent to peer", "rgs", ids, "req_id", reqID)
		return err
	default:
		return err
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
		s.sendFailoverAckFrame(conn, syncMsgFailoverAck, []int{rgID}, reqID, failoverAckFailed, "no remote failover handler")
		return
	}
	if err := s.OnRemoteFailover(rgID, reqID); err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		s.sendFailoverAckFrame(conn, syncMsgFailoverAck, []int{rgID}, reqID, status, err.Error())
		return
	}
	// #5640: OnRemoteFailover only ENQUEUES the async demotion event; the old
	// owner is not fenced (VRRP resigned / VIPs removed) until the daemon's
	// event consumer actuates it. Acking applied here let the peer promote
	// while this node still owned the RG → a two-owner window. Gate the
	// applied-ack on the fence-completion barrier; if the fence does not
	// actuate within the bounded timeout, downgrade to failed. #16592: a
	// failed ack alone does NOT hold the requester — its election promotes
	// on our secondary-hold heartbeat — so also restore this owner
	// (reqID-bound, best-effort) before replying, making failure symmetric:
	// the requester records the abort and this node becomes primary again.
	if s.WaitFailoverApplied != nil {
		if err := s.WaitFailoverApplied(rgID, reqID); err != nil {
			slog.Warn("cluster sync: remote failover fence barrier failed", "rg", rgID, "req_id", reqID, "err", err)
			if s.OnRemoteFailoverAbort != nil {
				if aerr := s.OnRemoteFailoverAbort(rgID, reqID); aerr != nil {
					slog.Warn("cluster sync: restore after failed fence failed; lease remains as fallback", "rg", rgID, "req_id", reqID, "err", aerr)
				}
			}
			s.sendFailoverAckFrame(conn, syncMsgFailoverAck, []int{rgID}, reqID, failoverAckFailed, err.Error())
			return
		}
	}
	s.sendFailoverAckFrame(conn, syncMsgFailoverAck, []int{rgID}, reqID, failoverAckApplied, "")
}
func (s *SessionSync) handleRemoteFailoverBatch(conn net.Conn, rgIDs []int, reqID uint64) {
	if s.OnRemoteFailoverBatch == nil {
		s.sendFailoverAckFrame(conn, syncMsgFailoverBatchAck, rgIDs, reqID, failoverAckFailed, "no remote batch failover handler")
		return
	}
	if err := s.OnRemoteFailoverBatch(rgIDs, reqID); err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		s.sendFailoverAckFrame(conn, syncMsgFailoverBatchAck, rgIDs, reqID, status, err.Error())
		return
	}
	// #5640: gate the batch applied-ack on every RG being fenced. See
	// handleRemoteFailover for the two-owner rationale — a batch handoff that
	// acks before actuation opens the same window across the whole set.
	if s.WaitFailoverAppliedBatch != nil {
		if err := s.WaitFailoverAppliedBatch(rgIDs, reqID); err != nil {
			slog.Warn("cluster sync: remote batch failover fence barrier failed", "rgs", rgIDs, "req_id", reqID, "err", err)
			if s.OnRemoteFailoverAbortBatch != nil {
				if aerr := s.OnRemoteFailoverAbortBatch(rgIDs, reqID); aerr != nil {
					slog.Warn("cluster sync: batch restore after failed fence failed; lease remains as fallback", "rgs", rgIDs, "req_id", reqID, "err", aerr)
				}
			}
			s.sendFailoverAckFrame(conn, syncMsgFailoverBatchAck, rgIDs, reqID, failoverAckFailed, err.Error())
			return
		}
	}
	s.sendFailoverAckFrame(conn, syncMsgFailoverBatchAck, rgIDs, reqID, failoverAckApplied, "")
}
func (s *SessionSync) handleRemoteFailoverCommit(conn net.Conn, rgID int, reqID uint64) {
	if s.OnRemoteFailoverCommit == nil {
		s.sendFailoverAckFrame(conn, syncMsgFailoverCommitAck, []int{rgID}, reqID, failoverAckFailed, "no remote failover commit handler")
		return
	}
	if err := s.OnRemoteFailoverCommit(rgID, reqID); err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		s.sendFailoverAckFrame(conn, syncMsgFailoverCommitAck, []int{rgID}, reqID, status, err.Error())
		return
	}
	s.sendFailoverAckFrame(conn, syncMsgFailoverCommitAck, []int{rgID}, reqID, failoverAckApplied, "")
}
func (s *SessionSync) handleRemoteFailoverCommitBatch(conn net.Conn, rgIDs []int, reqID uint64) {
	if s.OnRemoteFailoverCommitBatch == nil {
		s.sendFailoverAckFrame(conn, syncMsgFailoverBatchCommitAck, rgIDs, reqID, failoverAckFailed, "no remote batch failover commit handler")
		return
	}
	if err := s.OnRemoteFailoverCommitBatch(rgIDs, reqID); err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		s.sendFailoverAckFrame(conn, syncMsgFailoverBatchCommitAck, rgIDs, reqID, status, err.Error())
		return
	}
	s.sendFailoverAckFrame(conn, syncMsgFailoverBatchCommitAck, rgIDs, reqID, failoverAckApplied, "")
}

// SendFailoverAbort notifies the owner that a requested transfer-out is
// abandoned (#15164/#16592). Fire-and-forget: there is no abort
// ack, and the owner's #5079 lease restores it if this frame is lost.
func (s *SessionSync) SendFailoverAbort(rgID int, reqID uint64) error {
	if err := validateFailoverProtocolRGID(rgID); err != nil {
		return err
	}
	conn := s.getActiveConn()
	if conn == nil {
		return fmt.Errorf("peer not connected")
	}
	payload := encodeFailoverSingleReqPayload(rgID, reqID)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgFailoverAbort, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: failover abort send error", "err", err, "rg", rgID, "req_id", reqID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send failover abort: %w", err)
	}
	slog.Info("cluster sync: failover abort sent to peer", "rg", rgID, "req_id", reqID)
	return nil
}

// SendFailoverAbortBatch is the multi-RG form of SendFailoverAbort.
func (s *SessionSync) SendFailoverAbortBatch(rgIDs []int, reqID uint64) error {
	ids, err := normalizeFailoverRGIDs(rgIDs)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return s.SendFailoverAbort(ids[0], reqID)
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
	payload := encodeFailoverBatchRequestPayload(ids, reqID)
	s.writeMu.Lock()
	err = writeMsg(conn, syncMsgFailoverBatchAbort, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: batch failover abort send error", "err", err, "rgs", ids, "req_id", reqID)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return fmt.Errorf("failed to send batch failover abort: %w", err)
	}
	slog.Info("cluster sync: batch failover abort sent to peer", "rgs", ids, "req_id", reqID)
	return nil
}

func (s *SessionSync) handleRemoteFailoverAbort(rgID int, reqID uint64) {
	if s.OnRemoteFailoverAbort == nil {
		return
	}
	if err := s.OnRemoteFailoverAbort(rgID, reqID); err != nil {
		slog.Warn("cluster sync: remote failover abort failed", "rg", rgID, "req_id", reqID, "err", err)
	}
}

func (s *SessionSync) handleRemoteFailoverAbortBatch(rgIDs []int, reqID uint64) {
	if s.OnRemoteFailoverAbortBatch == nil {
		return
	}
	if err := s.OnRemoteFailoverAbortBatch(rgIDs, reqID); err != nil {
		slog.Warn("cluster sync: remote batch failover abort failed", "rgs", rgIDs, "req_id", reqID, "err", err)
	}
}

// sendFailoverAckFrame is the single result sender (#17102): it builds the
// single or batch ack payload for rgIDs and owns the #14160 two-conn write
// protocol — a broken active conn is disconnected even when the fallback
// delivers, and on dual failure both conns are disconnected with one error
// counted. The single path's success Info log is preserved only for single
// frames; the batch path never logged success.
func (s *SessionSync) sendFailoverAckFrame(conn net.Conn, msgType uint8, rgIDs []int, reqID uint64, status uint8, detail string) {
	single := len(rgIDs) == 1
	if !single {
		if err := validateFailoverBatchRGCount(rgIDs); err != nil {
			slog.Warn("cluster sync: refusing to send oversized batch failover result", "err", err, "msg_type", msgType, "rgs", rgIDs, "req_id", reqID, "status", status)
			return
		}
	}
	ackConn := s.getActiveConn()
	if ackConn == nil {
		ackConn = conn
	}
	if ackConn == nil {
		return
	}
	var payload []byte
	if single {
		payload = make([]byte, 10+len(detail))
		payload[0] = byte(rgIDs[0])
		payload[1] = status
		binary.LittleEndian.PutUint64(payload[2:10], reqID)
		copy(payload[10:], detail)
	} else {
		payload = encodeFailoverBatchAckPayload(rgIDs, status, reqID, detail)
	}
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
		if single {
			slog.Warn("cluster sync: failover result send error", "err", err, "msg_type", msgType, "rg", rgIDs[0], "req_id", reqID, "status", status)
		} else {
			if firstErr != nil && conn != nil && ackConn != conn {
				slog.Warn("cluster sync: batch failover result send error on active conn", "err", firstErr, "msg_type", msgType, "rgs", rgIDs, "req_id", reqID, "status", status)
			}
			slog.Warn("cluster sync: batch failover result send error", "err", err, "msg_type", msgType, "rgs", rgIDs, "req_id", reqID, "status", status)
		}
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	if single {
		slog.Info("cluster sync: failover result sent", "msg_type", msgType, "rg", rgIDs[0], "req_id", reqID, "status", status, "detail", detail)
	}
}
