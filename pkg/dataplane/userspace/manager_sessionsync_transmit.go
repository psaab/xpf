package userspace

// Session-sync transmit for the userspace dataplane, and the single owner of
// its lock discipline: every path here drops m.mu for the socket I/O and
// reacquires it, takes m.sessionMu once per request, and fast-fails a batch on
// a transport failure (#5380).
//
// #8015 removed the contiguous PAIR transmit (one m.sessionMu hold across a
// forward and its explicitly built reverse companion, #5698). The local session
// mirror now sends ONE upsert and the helper synthesizes the companion itself,
// so there is no group whose members must not be split — and with nothing left
// to keep contiguous, sessionPairMaxRequests and the per-half sessionPairResult
// went with it.

import (
	"errors"
	"log/slog"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (m *Manager) syncSessionV4Locked(op string, key dataplane.SessionKey, val *dataplane.SessionValue) error {
	if m.proc == nil {
		return nil
	}
	req := m.buildSessionSyncRequestV4(op, key, val)
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) syncSessionV6Locked(op string, key dataplane.SessionKeyV6, val *dataplane.SessionValueV6) error {
	if m.proc == nil {
		return nil
	}
	req := m.buildSessionSyncRequestV6(op, key, val)
	return m.syncSessionRequestLocked(req)
}

func (m *Manager) syncSessionRequestLocked(req SessionSyncRequest) error {
	// Build the control request under mu (for data access), then release mu
	// before the socket I/O so snapshot publishes aren't blocked.
	ctrlReq := ControlRequest{
		Type:           "sync_session",
		SuppressStatus: true,
		SessionSync:    &req,
	}
	m.mu.Unlock()
	err := m.requestSessionSync(ctrlReq)
	m.mu.Lock()
	if err != nil {
		slog.Debug("userspace session sync mirror failed", "operation", req.Operation, "err", err)
	}
	return err
}

// sendSessionSyncBatch transmits reqs through send, which performs one
// session-socket round trip per request. It stays a named function with one
// caller (syncSessionRequestsLocked) because the #5380 contract below is the
// thing being described, not the loop.
//
// It attempts every request as long as the helper keeps answering — an
// APPLICATION-level rejection of one request (helper alive, resp.OK=false) does
// not stop the loop, so a bulk revocation drops as many helper sessions as it
// can. It returns the FIRST helper IPC error encountered, or nil if all
// succeeded.
//
// #5380: if a request fails at the TRANSPORT layer (dial/write/read wrapped
// with errSessionHelperUnreachable), the helper is down or hung and every
// remaining request would pay the full per-request deadline too. A bulk delete
// chunk is up to sessionHelperDeleteChunk (256) requests, so looping on would
// stall bulk session ops — and repeatedly hold sessionMu, starving live session
// installs — for ~256 * sessionSyncRoundtripDeadline (~13 min). So the batch
// fast-fails: it stops after the first transport failure and returns it. The
// mirror is best-effort — the periodic sweep retries once the helper is healthy
// again.
func sendSessionSyncBatch(reqs []SessionSyncRequest, send func(ControlRequest) error) error {
	for _, err := range sendSessionSyncBatchOutcomes(reqs, send) {
		if err != nil {
			return err
		}
	}
	return nil
}

// errSessionSyncNotAttempted marks a request the batch NEVER SENT (#9714 review
// round 2, finding 1).
//
// It is not a failure OF the request — it is the ABSENCE of an answer, and on the
// delete path that distinction decides whether a live session survives. The three
// states a caller must tell apart are:
//   - nil            the helper APPLIED it; the caller may drop its BPF mirror row;
//   - a refusal      the helper KEPT the session; the row must stay;
//   - not attempted  the caller knows NOTHING; the row must stay.
//
// Collapsing the third into the first is not recoverable later: the mirror is not
// self-healing, because the refresh path writes with BPF_EXIST precisely so it
// "avoid[s] recreating deleted entries". A row deleted on a guess is gone until
// the session is rebuilt.
var errSessionSyncNotAttempted = errors.New("session sync request not attempted")

// sendSessionSyncBatchOutcomes is sendSessionSyncBatch keeping every request's
// result (#9714): outcomes[i] is reqs[i]'s error, nil if the helper applied it.
// It stops at the first transport failure exactly as sendSessionSyncBatch does
// (#5380), and every request after that one reports errSessionSyncNotAttempted.
//
// That tail used to report nil, i.e. "applied". A chunk is up to
// sessionHelperDeleteChunk (256) requests, so an unreachable helper on request 1
// manufactured up to 255 phantom successes, and BatchDeletePeerSyncedSessions*
// then deleted 255 BPF mirror rows for sessions the helper still holds — the
// failure direction this whole path exists to prevent, reached by an instrument
// that could not distinguish silence from assent.
func sendSessionSyncBatchOutcomes(reqs []SessionSyncRequest, send func(ControlRequest) error) []error {
	outcomes := make([]error, len(reqs))
	for i := range reqs {
		ctrlReq := ControlRequest{
			Type:           "sync_session",
			SuppressStatus: true,
			SessionSync:    &reqs[i],
		}
		if err := send(ctrlReq); err != nil {
			slog.Debug("userspace session sync mirror failed", "operation", reqs[i].Operation, "err", err)
			outcomes[i] = err
			// Helper unreachable/hung: abort the batch instead of paying the
			// per-request deadline once per remaining request (#5380).
			if errors.Is(err, errSessionHelperUnreachable) {
				// Mark the unsent tail EXPLICITLY. A zero-valued `error` is
				// indistinguishable from a success the helper actually gave,
				// so the absence of an answer has to be written down rather
				// than left as the zero value.
				for j := i + 1; j < len(reqs); j++ {
					outcomes[j] = errSessionSyncNotAttempted
				}
				break
			}
		}
	}
	return outcomes
}

// syncSessionRequestOutcomesLocked is syncSessionRequestsLocked keeping every
// request's result (#9714); see sendSessionSyncBatchOutcomes. The m.mu discipline
// is the same: one unlock around the socket I/O, reacquired before returning.
func (m *Manager) syncSessionRequestOutcomesLocked(reqs ...SessionSyncRequest) []error {
	if len(reqs) == 0 {
		return nil
	}
	m.mu.Unlock()
	outcomes := sendSessionSyncBatchOutcomes(reqs, m.requestSessionSync)
	m.mu.Lock()
	return outcomes
}

// syncSessionRequestsLocked transmits one or more PRE-BUILT session-sync
// requests to the Rust helper over the session socket. Like
// syncSessionRequestLocked it drops m.mu once for the socket I/O (so snapshot
// publishes are not blocked by a session install) and reacquires it before
// returning; the caller keeps the lock across the call. It performs NO
// snapshot reads — callers MUST have built every request under a single,
// uninterrupted prior m.mu hold so a forward/reverse companion pair is
// resolved against one consistent snapshot (#5007).
//
// The single m.mu unlock buys exactly two things and NOTHING more: the
// deliberate "socket I/O must not block snapshot publishes" property, and the
// #5007 one-snapshot build (every request was resolved before the lock was
// dropped). It does NOT make the transmit contiguous. This path acquires and
// releases m.sessionMu once PER request (requestSessionSync), so m.sessionMu is
// free between consecutive requests and an unrelated session-socket mutation —
// an operator clear, a policy invalidation, a GC delete, a stale-session
// reconciliation — can land between them (#5698). That interleaving is the
// CORRECT behaviour here: a bulk caller passes up to sessionHelperDeleteChunk
// (256) requests, and holding sessionMu across a chunk that large would starve
// live session installs for minutes — the exact harm the #5380 fast-fail
// exists to avoid. Since #8015 there is no group that must not be split: the
// local session mirror sends ONE upsert and the helper synthesizes the reverse
// companion itself, so the contiguous pair transmit that used to sit alongside
// this path is gone.
//
// It returns the FIRST helper IPC error encountered, or nil if all succeeded.
// Best-effort mirror callers (batch delete) discard the result; the
// authoritative clear-all path (#5881) propagates it so a failed helper
// revocation is reported instead of masquerading as success.
func (m *Manager) syncSessionRequestsLocked(reqs ...SessionSyncRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	m.mu.Unlock()
	err := sendSessionSyncBatch(reqs, m.requestSessionSync)
	m.mu.Lock()
	return err
}
