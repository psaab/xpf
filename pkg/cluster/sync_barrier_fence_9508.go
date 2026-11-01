package cluster

import (
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
)

// #9508: the session-sync readiness barrier claims something about ONE ordered
// stream: the peer processed every delta queued before the marker. A BarrierAck
// proves that only for the connection the marker travelled on, and
// barrierAckSeq is global. sendLoop writes each message on whatever connection
// is active at that instant, so the stream can move between fabric connections
// (a partial drop, or a preferred fabric connecting) while frames written on the
// old connection are still unprocessed or already lost. An ACK on the new
// connection says nothing about them, and readiness would permit a demotion that
// loses those sessions.
//
// The fence closes that. The first ordered-stream write on a DIFFERENT
// connection bumps epoch BEFORE it writes, so no ACK for a frame on the new
// connection can be observed without the bump. A barrier pending across a bump
// fails. Every later barrier is refused until a bulk is ACKed that captured the
// current epoch BEFORE reading its session source: a snapshot read after the
// move holds every delta written before it, on whichever connection.
type barrierFence struct {
	// streamConn is the connection the ordered stream was last noted on.
	// Guarded by writeMu; compared by identity only.
	streamConn net.Conn
	// epoch counts stream moves; cleared is the highest epoch an ACKed bulk
	// discharged. The fence is armed while they differ.
	epoch   atomic.Uint64
	cleared atomic.Uint64
	// pendingBulk is the capture (epoch+1; 0 = cannot discharge) of the bulk
	// pendingBulkAckEpoch names. The writer stores pendingBulkAckEpoch FIRST
	// and this second; the BulkAck reader loads this FIRST and the epoch
	// second. An ACK can then never pair one bulk's epoch with a newer bulk's
	// capture: a newer epoch stored in between fails the epoch match.
	pendingBulk atomic.Uint64
	// reprimeInFlight single-flights the re-prime goroutine.
	reprimeInFlight atomic.Bool
}

// noteStreamConnLocked records that an ordered-stream write is about to go on
// conn, and reports whether the stream moved, having bumped the epoch first.
// Caller holds writeMu, and calls onStreamMoved after releasing it when this
// returns true.
func (s *SessionSync) noteStreamConnLocked(conn net.Conn) bool {
	prev := s.fence.streamConn
	s.fence.streamConn = conn
	if prev == nil || prev == conn {
		return false
	}
	s.fence.epoch.Add(1)
	return true
}

// barrierFenced reports whether readiness barriers are currently refused.
func (s *SessionSync) barrierFenced() bool {
	return s.fence.epoch.Load() != s.fence.cleared.Load()
}

// onStreamMoved releases every pending barrier waiter (each observes the epoch
// change and fails) and, when scheduleReprime is set, starts the re-prime that
// discharges the fence. A bulk that noted the move itself passes false: it may
// be that re-prime, and a refused barrier re-kicks one if it is not.
func (s *SessionSync) onStreamMoved(scheduleReprime bool) {
	s.barrierWaitMu.Lock()
	waiters := s.barrierWaiters
	s.barrierWaiters = nil
	// #9822: mark BEFORE closing, under the same mutex the waiter reads it
	// under, so a barrier released here is told it was fenced rather than left
	// to infer it from an epoch it may have captured after the bump.
	for _, w := range waiters {
		w.fenced = true
	}
	s.barrierWaitMu.Unlock()
	for _, w := range waiters {
		close(w.ch)
	}
	slog.Warn("cluster sync: ordered stream moved to another fabric connection; readiness barriers are fenced until a re-prime is acked",
		"fence_epoch", s.fence.epoch.Load(), "released_barrier_waiters", len(waiters))
	if scheduleReprime {
		s.scheduleBarrierFenceReprime("stream moved")
	}
}

// scheduleBarrierFenceReprime runs one bulk to discharge the fence, unless one
// is already running. The daemon cannot be relied on for it: it restarts its
// own prime-retry loop after a failed barrier only while the peer is unprimed,
// and a primed peer is the normal case, so without this the fence would refuse
// every later demotion.
func (s *SessionSync) scheduleBarrierFenceReprime(reason string) {
	if !s.barrierFenced() {
		return
	}
	// #18521 (C): at most ONE discharge-capable re-prime outstanding. The
	// in-flight flag below only covers WRITING the bulk; the fence is
	// discharged by the peer's BulkAck, which arrives after the peer has
	// INSTALLED the whole table — seconds later at helper-install speed. A
	// manual-failover admission retries its barrier every 0.5s, so each
	// refusal used to start a fresh full bulk the moment the previous one
	// finished writing. Every new bulk overwrote pendingBulkAckEpoch, so the
	// ack the peer eventually sent was for an epoch no longer pending and was
	// dropped (#9177 V053's exact-match rule): the fence could never
	// discharge, and each bulk added a full table to a receiver that was
	// already behind (the backlog that ends in the half-open teardown above).
	// A pending bulk that captured the CURRENT epoch will discharge it when
	// acked; until BulkAckPendingRetryAfter says that ack is lost, wait for it.
	if s.fenceDischargeAwaited() {
		slog.Debug("cluster sync: barrier fence re-prime already awaiting the peer's ack",
			"reason", reason, "fence_epoch", s.fence.epoch.Load(),
			"pending_epoch", s.pendingBulkAckEpoch.Load())
		return
	}
	if !s.fence.reprimeInFlight.CompareAndSwap(false, true) {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.fence.reprimeInFlight.Store(false)
		if !s.barrierFenced() || !s.stats.Connected.Load() || s.fenceDischargeAwaited() {
			return
		}
		slog.Info("cluster sync: re-priming the peer to discharge the barrier fence",
			"reason", reason, "fence_epoch", s.fence.epoch.Load())
		if err := s.doBulkSync(); err != nil {
			slog.Warn("cluster sync: barrier-fence re-prime failed; the next refused barrier retries it", "err", err)
		}
	}()
}

// fenceDischargeAwaited reports whether an outbound bulk that can discharge the
// CURRENT fence epoch is still awaiting its BulkAck inside
// BulkAckPendingRetryAfter (#18521). The capture is loaded before the pending
// epoch, mirroring handleBulkAck's order (see barrierFence.pendingBulk), so a
// newer bulk stored in between can only make this report a bulk pending, never
// pair an old capture with a cleared epoch.
func (s *SessionSync) fenceDischargeAwaited() bool {
	capture := s.fence.pendingBulk.Load()
	if capture == 0 || capture-1 < s.fence.epoch.Load() {
		return false
	}
	_, age, ok := s.PendingBulkAck()
	return ok && age < BulkAckPendingRetryAfter
}

// captureBarrierFenceForBulk notes the connection a bulk is about to use and
// returns the capture it may discharge (epoch+1; 0 = none). It MUST run before
// the bulk reads its session source.
func (s *SessionSync) captureBarrierFenceForBulk() uint64 {
	conn := s.getActiveConn()
	if conn == nil {
		return 0
	}
	s.writeMu.Lock()
	moved := s.noteStreamConnLocked(conn)
	capture := s.fence.epoch.Load() + 1
	s.writeMu.Unlock()
	if moved {
		s.onStreamMoved(false)
	}
	return capture
}

// dischargeBarrierFence advances cleared to an ACKed bulk's capture. A stale
// capture (the stream moved after it) leaves the fence armed.
func (s *SessionSync) dischargeBarrierFence(capture uint64) {
	if capture == 0 {
		return
	}
	epoch := capture - 1
	for {
		cur := s.fence.cleared.Load()
		if epoch <= cur {
			return
		}
		if s.fence.cleared.CompareAndSwap(cur, epoch) {
			slog.Info("cluster sync: barrier fence discharged by an acked bulk",
				"discharged_epoch", epoch, "fence_epoch", s.fence.epoch.Load())
			return
		}
	}
}

func barrierFencedError(seq uint64) error {
	return fmt.Errorf("session sync barrier fenced seq=%d: the ordered stream moved to another fabric connection and no re-prime has been acked on it yet", seq)
}
