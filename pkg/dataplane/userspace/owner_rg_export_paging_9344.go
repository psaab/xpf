package userspace

import (
	"errors"
	"fmt"
)

// #9344: the owner-RG session export had no terminating bound.
//
// `export_owner_rg_sessions` is asked with a ~60-byte request and answered with
// the UNBOUNDED owner-RG session set, because `max=0` was the only safe request
// a caller could make. `MaxControlRequestBytes` bounds the ASK; the ANSWER is
// bounded only by `MaxControlResponseBytes` (64 MiB), and crossing that is a
// truncation, which `doBulkSync` turns into a failed cold prime — permanently,
// on every attempt, on a busy cluster.
//
// Why "raise the cap" is not the fix. A worst-case `SessionDeltaInfo` is 1424
// bytes of JSON (every string field a full-width IPv6 literal, every numeric at
// its maximum), and the theoretical maximum answer is
// `workers * DEFAULT_MAX_SESSIONS(131072) * 1424`:
//
//	workers   theoretical max     vs 64 MiB cap   cap crossed at
//	      1       178 MiB              2.8x          47,127 sessions/worker
//	      4       712 MiB               11x          11,781
//	      6      1068 MiB               16x           7,854   <- loss cluster
//	      8      1424 MiB               22x           5,890
//	     16      2848 MiB               44x           2,945
//
// That is not a number, it is a number PER BOX, and the only source for the
// worker count is `ProcessStatus.Workers` — reported by the helper. Sizing an
// allocation bound from a value the bounded party supplies is not a bound, and
// any fixed constant large enough for a 16-worker box (>= 2.8 GiB) reopens the
// unbounded-allocation case #9003 closed.
//
// So the export is PAGED. The pieces were already there: the helper's
// `drain_session_deltas_fair` computes the "there is more" bit and the owner-RG
// call site discarded it into `_overflow`, and #5290 already threads a fair
// drain cursor across batches.

const (
	// MinProtocolOwnerRGExportPaging is the ProcessStatus paging-contract
	// version at which a helper honours SessionExportRequest.Continuation and
	// reports ControlResponse.SessionExportMore.
	MinProtocolOwnerRGExportPaging = 1

	// ownerRGExportPageDeltas is the per-page cap.
	//
	// Derived from the response cap, not chosen: a worst-case delta is 1424
	// bytes of JSON, so 8192 deltas is 11.1 MiB against MaxControlResponseBytes
	// (64 MiB) — a 5.7x margin that covers the rest of the response (the status
	// block, which is the only other large member) and JSON framing without
	// needing either side to agree on an exact per-delta size.
	//
	// It is deliberately far below the 47,127 deltas that would exactly fill
	// the cap at worst case. A page that is merely correct at worst case is a
	// page that fails the first time the worst case is underestimated, and the
	// cost of a smaller page is one extra round trip on a socket that is
	// already serialized.
	ownerRGExportPageDeltas = 8192

	// maxOwnerRGExportPages bounds the paging loop.
	//
	// A runaway loop is the same defect this file exists to fix wearing a
	// different hat: "the answer is unbounded" is no better when the
	// unboundedness is a page count instead of a byte count. 256 pages x 8192
	// deltas = 2,097,152, which is one COMPLETELY full session table on a
	// 16-worker box (16 x DEFAULT_MAX_SESSIONS). A window larger than every
	// session the largest shipped box can hold is not a window, it is a helper
	// that is not terminating, and the caller fails CLOSED on it — doBulkSync
	// frames no window rather than a partial one.
	maxOwnerRGExportPages = 256
)

// ErrOwnerRGExportUnterminated is returned when the helper keeps reporting more
// pages past maxOwnerRGExportPages. It is a FAILURE, never a partial answer:
// #5085's receiver reconciles authoritatively against the delimited window and
// deletes every eligible session missing from it, so handing back the pages we
// did collect would delete the rest on the peer.
var ErrOwnerRGExportUnterminated = errors.New("owner-RG session export did not terminate")

// ExportOwnerRGSessionsPaged collects ONE owner-RG export window, paging when
// the helper supports it.
//
// The manager lock is held across every page ON PURPOSE. The per-binding delta
// buffers this export drains are the SAME buffers the incremental
// `drain_session_deltas` verb drains, so an interleaved incremental drain
// between two pages would steal part of the window — and a window missing
// sessions is exactly what makes the peer delete live ones. Serializing the
// whole sequence is what makes the pages add up to the single-shot answer;
// holding the lock for one round trip and releasing it between pages would not.
func (m *Manager) ExportOwnerRGSessionsPaged(rgIDs []int) ([]SessionDeltaInfo, ProcessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.proc == nil {
		return nil, ProcessStatus{}, errors.New("userspace dataplane helper not running")
	}

	// A helper that predates the paging contract honours Max by TRUNCATING and
	// reports no more-bit, so paging it would silently lose the remainder. Ask
	// it for the unbounded set instead: identical to the pre-#9344 caller,
	// including the 64 MiB failure, which #9322 made diagnosable rather than
	// mistakable for a helper rejection.
	if m.lastStatus.SessionExportPagingProtocolVersion < MinProtocolOwnerRGExportPaging {
		return m.exportOwnerRGSessionsUnpagedLocked(rgIDs)
	}

	var all []SessionDeltaInfo
	var status ProcessStatus
	for page := 0; page < maxOwnerRGExportPages; page++ {
		resp, err := m.requestDetailedLocked(ControlRequest{
			Type: "export_owner_rg_sessions",
			SessionExport: &SessionExportRequest{
				OwnerRGs: rgIDs,
				Max:      ownerRGExportPageDeltas,
				// Every page after the first continues the window the first
				// page opened. A non-continuation would run phase 1 again and
				// stack a second full set from a different instant onto the
				// remainder of this one.
				Continuation: page > 0,
			},
		})
		if err != nil {
			return nil, ProcessStatus{}, err
		}
		all = append(all, resp.SessionDeltas...)
		if resp.Status != nil {
			status = *resp.Status
			if err := m.applyHelperStatusLocked(&status); err != nil {
				// #9699: one complete window or an error, never both. The
				// pages collected so far are a partial window, and #5085's
				// receiver deletes every session missing from a window.
				return nil, status, err
			}
		}
		if !resp.SessionExportMore {
			return all, status, nil
		}
	}
	return nil, status, fmt.Errorf("%w: still reporting more after %d pages of %d deltas (%d collected)",
		ErrOwnerRGExportUnterminated, maxOwnerRGExportPages, ownerRGExportPageDeltas, len(all))
}

// exportOwnerRGSessionsUnpagedLocked is the pre-#9344 single request. It is the
// fallback for a helper with no paging contract, and it is byte-identical to
// what ExportOwnerRGSessions has always sent.
func (m *Manager) exportOwnerRGSessionsUnpagedLocked(rgIDs []int) ([]SessionDeltaInfo, ProcessStatus, error) {
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type: "export_owner_rg_sessions",
		SessionExport: &SessionExportRequest{
			OwnerRGs: rgIDs,
			Max:      0,
		},
	})
	if err != nil {
		return nil, ProcessStatus{}, err
	}
	var status ProcessStatus
	if resp.Status != nil {
		status = *resp.Status
		if err := m.applyHelperStatusLocked(&status); err != nil {
			// #9699: never deltas together with an error (see the paged loop).
			return nil, status, err
		}
	}
	return resp.SessionDeltas, status, nil
}
