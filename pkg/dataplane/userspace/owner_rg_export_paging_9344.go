package userspace

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
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
// Why "raise the cap" is not the fix. A worst-case `SessionDeltaInfo` measures
// 1688 bytes of JSON in the current wire schema (every string field a full-width
// IPv6 literal, every numeric at its maximum), and the theoretical maximum
// answer is `workers * DEFAULT_MAX_SESSIONS(131072) * 1688`. That is roughly
// 211 MiB per worker before response framing, so even one worker can exceed the
// 64 MiB response cap; sizing from a helper-supplied worker count would still
// make the allocation bound untrusted.
//
// That is not a number, it is a number PER BOX, and the worker count is
// supplied by the helper. A fixed response cap therefore cannot safely become
// an allocation bound by multiplying it by that untrusted count.
//
// So the export is PAGED. The pieces were already there: the helper's
// `drain_session_deltas_fair` computes the "there is more" bit and the owner-RG
// call site discarded it into `_overflow`, and #5290 already threads a fair
// drain cursor across batches.

const (
	// MinProtocolOwnerRGExportPaging is the v2 fail-closed owner-RG
	// export contract. v1 helpers silently truncate at Max and are refused.
	MinProtocolOwnerRGExportPaging = 2

	// ownerRGExportPageDeltas is the per-page cap.
	ownerRGExportPageDeltas = 8192

	// ownerRGExportEstimatedDeltaBytes conservatively mirrors the measured
	// worst-case JSON sizing (the test reflects the current wire schema). It
	// sizes ONE page against MaxControlResponseBytes; it must NOT be charged
	// against retained deltas (#15161/#16515), because retained form is no
	// longer []SessionDeltaInfo at all.
	ownerRGExportEstimatedDeltaBytes = 1863 // #11064 ICMP, #11070 ingress/rule-ID, #12187 source-NAT provenance; reflected worst-case 1863 (TestOwnerRGExportPageFitsTheResponseCap9344)
	// maxOwnerRGExportDataPages is the structural data-page bound. Each
	// kick-visible session can produce one open plus one terminal tombstone
	// while the window drains: 16 workers * DEFAULT_MAX_SESSIONS * 2 /
	// 8192 deltas = 512 pages.
	maxOwnerRGExportDataPages = 512
	// One additional request is reserved for the terminal probe when the
	// final data page filled exactly while the worker ACK still lagged.
	maxOwnerRGExportPages = maxOwnerRGExportDataPages + 1
)

// ownerRGExportLease serializes paged windows without holding a Manager's
// general mutex across every control round trip.
var ownerRGExportLease sync.Mutex

// ErrOwnerRGExportUnterminated is returned when the helper keeps reporting more
// pages past maxOwnerRGExportPages.
var ErrOwnerRGExportUnterminated = errors.New("owner-RG session export did not terminate")

// ErrOwnerRGExportIncomplete is returned when a v2 helper reports a dropped
// delta or an invalid/restarted export token. It is a failure, never a partial
// answer, because the authoritative receiver deletes sessions missing from a
// supposedly complete window.
var ErrOwnerRGExportIncomplete = errors.New("owner-RG session export incomplete")

// OwnerRGExportPageSink receives each decoded page of an owner-RG export
// window (#16515). The slice is caller-owned only for the call; it is reused
// for the next page, so a sink must convert/copy what it retains. Returning
// an error aborts the window with that error (wrapped by the caller).
type OwnerRGExportPageSink interface {
	OnOwnerRGExportPage(deltas []SessionDeltaInfo) error
}

// OwnerRGExportPageFunc adapts a function to OwnerRGExportPageSink.
type OwnerRGExportPageFunc func(deltas []SessionDeltaInfo) error

func (f OwnerRGExportPageFunc) OnOwnerRGExportPage(deltas []SessionDeltaInfo) error {
	return f(deltas)
}

// ExportOwnerRGSessionsPagedStream collects ONE owner-RG export window,
// paging when the helper supports it and streaming each page to sink.
//
// The dedicated per-worker export buffers are distinct from the incremental
// buffers, so the export lease can release the Manager mutex between pages.
// ownerRGExportLease still serializes windows: a second export must not start
// while the first one is carrying a continuation token.
//
// #16518: every page request sets SuppressStatus and the pager never applies
// an attached page status. The pager drops m.mu for each RPC; a disarm that
// queues behind the page on controlReqMu can apply a fresh DISARMED status
// before the pager re-locks, and the page's older ARMED status would then
// overwrite it (ctrl=1 / ForwardingArmed=true into a disarmed helper) until
// the next page or poll. Both production callers discard the returned
// status, and helper truth keeps flowing through the 1 Hz poll and the
// explicit state verbs, so suppressing the per-page status loses nothing
// and keeps applyHelperStatusLocked the single writer in RPC order.
//
// #16515: no window-wide []SessionDeltaInfo is retained. Only one decoded
// page (<=8192 deltas) lives at a time; the sink converts each page into its
// own compact form (cluster rows / queued installs) before the next request.
// The structural bound is maxOwnerRGExportDataPages (512 pages = 16 workers
// x DEFAULT_MAX_SESSIONS x 2 records), not a byte budget: a 16-worker
// realistic window (~1M forward deltas) previously exceeded any fixed
// 256 MiB retention bound at the 520-byte struct floor alone.
//
// On any error the window is incomplete: sink may already have consumed
// earlier pages, so callers must discard/abort any derived state and must
// not frame or acknowledge a window. ExportOwnerRGSessionsPaged wraps this
// for callers that still need the whole slice.
func (m *Manager) ExportOwnerRGSessionsPagedStream(rgIDs []int, sink OwnerRGExportPageSink) (_ ProcessStatus, _ int, retErr error) {
	if sink == nil {
		return ProcessStatus{}, 0, fmt.Errorf("%w: nil page sink", ErrOwnerRGExportIncomplete)
	}
	ownerRGExportLease.Lock()
	defer ownerRGExportLease.Unlock()
	// #18752: a window this call opened and then abandoned on an error must be
	// closed on the helper NOW. Otherwise the helper keeps it open until its
	// 60 s idle expiry and answers every fresh kick BUSY in the meantime: the
	// HA cold prime then cannot be paid, ColdPrimeOwedWithoutPendingBulk stays
	// true, and every manual failback in that minute is refused. The helper
	// closes a window itself on a terminal page and on its own error paths,
	// so this only matters when the abort is decided HERE (a helper/config
	// generation change between pages, a dropped-delta or token report, a
	// sink error, an oversized page) or when page 1's response never arrived
	// (lost or timed out) although the helper opened the window. The window is
	// named by the client's own id, chosen before page 1 is sent, plus the
	// helper's token once known. Best effort and lease-held, so no new window
	// can start before it lands; the idle expiry stays the backstop.
	clientWindow := nextOwnerRGExportClientWindow()
	var windowMayBeOpen bool
	var openIncarnation, openSequence uint64
	var openSocket string
	defer func() {
		if retErr != nil && windowMayBeOpen {
			m.abandonOwnerRGExportWindow(openSocket, clientWindow, openIncarnation, openSequence, retErr)
		}
	}()
	m.mu.Lock()
	if m.proc == nil {
		status := m.lastStatus
		m.mu.Unlock()
		return status, 0, errors.New("userspace dataplane helper not running")
	}
	status := m.lastStatus
	protocol := status.SessionExportPagingProtocolVersion
	controlSocket := m.cfg.ControlSocket
	exportProcGen := m.procGen
	exportConfigGen := m.generation
	m.mu.Unlock()
	if len(rgIDs) == 0 {
		return status, 0, nil
	}
	if protocol < MinProtocolOwnerRGExportPaging {
		return status, 0, fmt.Errorf(
			"%w: helper advertises paging protocol %d, want %d",
			ErrOwnerRGExportIncomplete,
			protocol,
			MinProtocolOwnerRGExportPaging,
		)
	}

	collected := 0
	expectedStatusIncarnation := status.SessionExportIncarnation
	var incarnation, sequence uint64
	for page := range maxOwnerRGExportPages {
		probe := page == maxOwnerRGExportDataPages
		req := SessionExportRequest{
			OwnerRGs:        rgIDs,
			Max:             ownerRGExportPageDeltas,
			ProtocolVersion: MinProtocolOwnerRGExportPaging,
			Continuation:    page > 0,
		}
		if page > 0 {
			req.ContinuationIncarnation = incarnation
			req.ContinuationSequence = sequence
		} else {
			req.ClientWindow = clientWindow
		}
		m.mu.Lock()
		if m.proc == nil ||
			m.procGen != exportProcGen ||
			m.generation != exportConfigGen ||
			m.cfg.ControlSocket != controlSocket {
			status = m.lastStatus
			m.mu.Unlock()
			return status, collected, fmt.Errorf(
				"%w: helper/config generation changed during export window",
				ErrOwnerRGExportIncomplete,
			)
		}
		m.mu.Unlock()
		// #16518: SuppressStatus — see the doc comment above. Without it the
		// helper attaches its status at page-answer time, and applying that
		// snapshot after re-locking can undo a newer disarm that landed
		// while this page's RPC was in flight.
		resp, err := m.requestDetailedAtSocket(ControlRequest{
			Type:           "export_owner_rg_sessions",
			SuppressStatus: true,
			SessionExport:  &req,
		}, controlSocket)
		// #18752: record whether the helper may now hold a window open,
		// BEFORE any check below can abort. Page 1 was sent, so unless a
		// response proves otherwise the helper may have opened it — even if
		// the response was lost (err != nil). A page that reports more keeps
		// it open; a terminal page closed it.
		if page == 0 {
			windowMayBeOpen, openSocket = true, controlSocket
		}
		if err == nil {
			if resp.SessionExportMore && resp.SessionExportSeq != 0 {
				if page == 0 {
					openIncarnation, openSequence = resp.SessionExportIncarnation, resp.SessionExportSeq
				}
			} else {
				windowMayBeOpen = false
			}
		}
		m.mu.Lock()
		if m.proc == nil ||
			m.procGen != exportProcGen ||
			m.generation != exportConfigGen ||
			m.cfg.ControlSocket != controlSocket {
			status = m.lastStatus
			m.mu.Unlock()
			return status, collected, fmt.Errorf(
				"%w: helper/config generation changed during export window",
				ErrOwnerRGExportIncomplete,
			)
		}
		status = m.lastStatus
		m.mu.Unlock()
		if err != nil {
			return ProcessStatus{}, collected, err
		}

		if resp.SessionExportDropped != 0 {
			return status, collected, fmt.Errorf(
				"%w: helper reported %d dropped delta(s) for seq=%d",
				ErrOwnerRGExportIncomplete,
				resp.SessionExportDropped,
				resp.SessionExportSeq,
			)
		}
		if resp.SessionExportIncarnation == 0 || resp.SessionExportSeq == 0 {
			return status, collected, fmt.Errorf(
				"%w: helper omitted nonzero incarnation/sequence on page %d",
				ErrOwnerRGExportIncomplete,
				page+1,
			)
		}
		if page == 0 {
			incarnation = resp.SessionExportIncarnation
			sequence = resp.SessionExportSeq
			if expectedStatusIncarnation != 0 &&
				incarnation != expectedStatusIncarnation {
				return status, collected, fmt.Errorf(
					"%w: helper incarnation %d differs from status %d",
					ErrOwnerRGExportIncomplete,
					incarnation,
					expectedStatusIncarnation,
				)
			}
		} else if resp.SessionExportIncarnation != incarnation || resp.SessionExportSeq != sequence {
			return status, collected, fmt.Errorf(
				"%w: continuation token changed from (%d,%d) to (%d,%d)",
				ErrOwnerRGExportIncomplete,
				incarnation,
				sequence,
				resp.SessionExportIncarnation,
				resp.SessionExportSeq,
			)
		}
		if !probe && len(resp.SessionDeltas) > ownerRGExportPageDeltas {
			return status, collected, fmt.Errorf(
				"%w: helper returned %d deltas on page %d, max %d",
				ErrOwnerRGExportIncomplete,
				len(resp.SessionDeltas),
				page+1,
				ownerRGExportPageDeltas,
			)
		}
		if probe {
			if len(resp.SessionDeltas) != 0 || resp.SessionExportMore {
				return status, collected, fmt.Errorf(
					"%w: terminal probe returned %d delta(s), more=%t",
					ErrOwnerRGExportUnterminated,
					len(resp.SessionDeltas),
					resp.SessionExportMore,
				)
			}
			return status, collected, nil
		}
		if err := sink.OnOwnerRGExportPage(resp.SessionDeltas); err != nil {
			return status, collected, err
		}
		collected += len(resp.SessionDeltas)
		if !resp.SessionExportMore {
			return status, collected, nil
		}
	}
	return status, collected, fmt.Errorf(
		"%w: still reporting more after %d data pages and a terminal probe of %d deltas (%d collected)",
		ErrOwnerRGExportUnterminated,
		maxOwnerRGExportDataPages,
		ownerRGExportPageDeltas,
		collected,
	)
}

// abandonOwnerRGExportWindow asks the helper to close the owner-RG export
// window (incarnation, sequence) that an aborted paged export left open
// (#18752). The helper clears it only if that token still names its open
// window, so a late or duplicate abandon can never close a newer window. A
// helper without the verb answers "unknown request type"; the window then
// stays until the helper's idle expiry, which is the pre-#18752 behaviour.
// Called with ownerRGExportLease held and m.mu NOT held.
func (m *Manager) abandonOwnerRGExportWindow(controlSocket string, clientWindow, incarnation, sequence uint64, cause error) {
	resp, err := m.requestDetailedAtSocket(ControlRequest{
		Type:           "abandon_owner_rg_export",
		SuppressStatus: true,
		SessionExport: &SessionExportRequest{
			ProtocolVersion:         MinProtocolOwnerRGExportPaging,
			ClientWindow:            clientWindow,
			ContinuationIncarnation: incarnation,
			ContinuationSequence:    sequence,
		},
	}, controlSocket)
	if err != nil {
		if isUnknownVerbError(err) {
			// A helper without the verb (older build). Say so once per helper
			// generation, then quietly: every abort would otherwise repeat it,
			// and the idle expiry still closes the window.
			m.mu.Lock()
			first := !m.abandonUnsupportedWarned || m.abandonUnsupportedGen != m.procGen
			m.abandonUnsupportedWarned, m.abandonUnsupportedGen = true, m.procGen
			m.mu.Unlock()
			if first {
				slog.Warn("userspace: helper does not support abandon_owner_rg_export; aborted owner-RG export windows stay open until the helper's 60 s idle expiry (#18752)",
					"client_window", clientWindow, "sequence", sequence, "cause", cause)
			} else {
				slog.Debug("userspace: helper does not support abandon_owner_rg_export (#18752)",
					"client_window", clientWindow, "sequence", sequence)
			}
			return
		}
		slog.Warn("userspace: could not abandon the aborted owner-RG export window; the helper keeps it until its idle expiry (#18752)",
			"client_window", clientWindow, "sequence", sequence, "cause", cause, "err", err)
		return
	}
	if resp.SessionExportAbandoned {
		slog.Info("userspace: abandoned aborted owner-RG export window (#18752)",
			"client_window", clientWindow, "sequence", sequence, "cause", cause)
		return
	}
	// Nothing matched: the window had already closed (a helper-side error
	// path, or page 1 was refused BUSY and never opened ours). Routine on
	// every re-drive after a BUSY, so not at Info.
	slog.Debug("userspace: owner-RG export abandon matched no open window (#18752)",
		"client_window", clientWindow, "sequence", sequence, "cause", cause)
}

// ownerRGExportClientWindowSeq numbers the pager's export windows (#18752).
// Seeded at random so a restarted daemon does not reuse a live helper's ids
// (the helper outlives nothing here, but a seed costs nothing and keeps ids
// distinct across Manager instances in one process too).
var ownerRGExportClientWindowSeq = func() *atomic.Uint64 {
	var v atomic.Uint64
	var b [8]byte
	if _, err := crand.Read(b[:]); err == nil {
		v.Store(binary.LittleEndian.Uint64(b[:]) >> 1)
	}
	return &v
}()

// nextOwnerRGExportClientWindow returns a nonzero client window id.
func nextOwnerRGExportClientWindow() uint64 {
	for {
		if id := ownerRGExportClientWindowSeq.Add(1); id != 0 {
			return id
		}
	}
}

// ExportOwnerRGSessionsPaged collects ONE complete window into a slice.
// Retained for callers/tests that need the whole window; production bulk
// and FullResync paths stream via ExportOwnerRGSessionsPagedStream so a
// 16-worker window is not retained as []SessionDeltaInfo (#16515).
func (m *Manager) ExportOwnerRGSessionsPaged(rgIDs []int) ([]SessionDeltaInfo, ProcessStatus, error) {
	var all []SessionDeltaInfo
	// Empty RG set: preserve the no-request fast path (stream validates
	// the sink before the empty check, so handle it here too).
	if len(rgIDs) == 0 {
		m.mu.Lock()
		status := m.lastStatus
		running := m.proc != nil
		m.mu.Unlock()
		if !running {
			return nil, status, errors.New("userspace dataplane helper not running")
		}
		return nil, status, nil
	}
	status, _, err := m.ExportOwnerRGSessionsPagedStream(rgIDs, OwnerRGExportPageFunc(func(deltas []SessionDeltaInfo) error {
		all = append(all, deltas...)
		return nil
	}))
	if err != nil {
		return nil, status, err
	}
	return all, status, nil
}
