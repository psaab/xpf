package userspace

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
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
	// against every retained delta (#15161), because typical decoded deltas
	// are an order of magnitude smaller and the charge capped a complete
	// window at 17 pages (~139k-144k deltas).
	ownerRGExportEstimatedDeltaBytes = 1863 // #11064 ICMP, #11070 ingress/rule-ID, #12187 source-NAT provenance; reflected worst-case 1863 (TestOwnerRGExportPageFitsTheResponseCap9344)
	ownerRGExportMaxAccumulatorBytes = 256 * 1024 * 1024
	// maxOwnerRGExportDataPages is the structural data-page bound. Each
	// kick-visible session can produce one open plus one terminal tombstone
	// while the window drains: 16 workers * DEFAULT_MAX_SESSIONS * 2 /
	// 8192 deltas = 512 pages.
	maxOwnerRGExportDataPages = 512
	// One additional request is reserved for the terminal probe when the
	// final data page filled exactly while the worker ACK still lagged.
	maxOwnerRGExportPages = maxOwnerRGExportDataPages + 1
	// maxOwnerRGExportAccumulatorPages was the old worst-case retained-slice
	// budget in full pages (256 MiB / (8192 * 1863) = 17). It is no longer a
	// collector budget: #15161 charges actual decoded retention instead and
	// bounds the window by maxOwnerRGExportDataPages, the same structural
	// ceiling the helper asserts. Kept only so existing references and the
	// history of the 17-page cap stay nameable.
	maxOwnerRGExportAccumulatorPages = ownerRGExportMaxAccumulatorBytes /
		(ownerRGExportPageDeltas * ownerRGExportEstimatedDeltaBytes)
)

// ownerRGExportActualDeltaBytes is the #15161 actual decoded retention for
// one delta: the fixed-size struct plus every heap string payload it points
// at. The [16]byte/[6]byte/json:"-" legs live inside the struct and are
// already counted by unsafe.Sizeof. This replaces charging the 1863-byte
// worst-case JSON size for every delta, which capped a complete window at
// 17 pages regardless of the real decoded size. The accumulator still fails
// closed at ownerRGExportMaxAccumulatorBytes, so a window of genuinely
// wide deltas (full-width IPv6 literals on every string field) is refused
// rather than retained without bound.
func ownerRGExportActualDeltaBytes(d *SessionDeltaInfo) int {
	n := int(unsafe.Sizeof(*d))
	n += len(d.Interface) + len(d.Event) + len(d.SrcIP) + len(d.DstIP) +
		len(d.IngressZone) + len(d.EgressZone) + len(d.Disposition) +
		len(d.Origin) + len(d.NextHop) + len(d.NeighborMAC) + len(d.SrcMAC) +
		len(d.NATSrcIP) + len(d.NATDstIP) + len(d.PolicyRuleID) +
		len(d.Nat64SnatV4)
	return n
}

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

// ExportOwnerRGSessionsPaged collects ONE owner-RG export window, paging when
// the helper supports it.
//
// The dedicated per-worker export buffers are distinct from the incremental
// buffers, so the export lease can release the Manager mutex between pages.
// ownerRGExportLease still serializes windows: a second export must not start
// while the first one is carrying a continuation token.
func (m *Manager) ExportOwnerRGSessionsPaged(rgIDs []int) ([]SessionDeltaInfo, ProcessStatus, error) {
	ownerRGExportLease.Lock()
	defer ownerRGExportLease.Unlock()

	m.mu.Lock()
	if m.proc == nil {
		status := m.lastStatus
		m.mu.Unlock()
		return nil, status, errors.New("userspace dataplane helper not running")
	}
	status := m.lastStatus
	protocol := status.SessionExportPagingProtocolVersion
	controlSocket := m.cfg.ControlSocket
	exportProcGen := m.procGen
	exportConfigGen := m.generation
	m.mu.Unlock()
	if len(rgIDs) == 0 {
		return nil, status, nil
	}
	if protocol < MinProtocolOwnerRGExportPaging {
		return nil, status, fmt.Errorf(
			"%w: helper advertises paging protocol %d, want %d",
			ErrOwnerRGExportIncomplete,
			protocol,
			MinProtocolOwnerRGExportPaging,
		)
	}

	var all []SessionDeltaInfo
	var retainedBytes int
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
		}
		m.mu.Lock()
		if m.proc == nil ||
			m.procGen != exportProcGen ||
			m.generation != exportConfigGen ||
			m.cfg.ControlSocket != controlSocket {
			status = m.lastStatus
			m.mu.Unlock()
			return nil, status, fmt.Errorf(
				"%w: helper/config generation changed during export window",
				ErrOwnerRGExportIncomplete,
			)
		}
		m.mu.Unlock()
		resp, err := m.requestDetailedAtSocket(ControlRequest{
			Type:          "export_owner_rg_sessions",
			SessionExport: &req,
		}, controlSocket)
		m.mu.Lock()
		if m.proc == nil ||
			m.procGen != exportProcGen ||
			m.generation != exportConfigGen ||
			m.cfg.ControlSocket != controlSocket {
			status = m.lastStatus
			m.mu.Unlock()
			return nil, status, fmt.Errorf(
				"%w: helper/config generation changed during export window",
				ErrOwnerRGExportIncomplete,
			)
		}
		var statusErr error
		if err == nil && resp.Status != nil {
			status = *resp.Status
			statusErr = m.applyHelperStatusLocked(&status)
		}
		m.mu.Unlock()
		if err != nil {
			return nil, ProcessStatus{}, err
		}
		if statusErr != nil {
			return nil, status, statusErr
		}
		if resp.SessionExportDropped != 0 {
			return nil, status, fmt.Errorf(
				"%w: helper reported %d dropped delta(s) for seq=%d",
				ErrOwnerRGExportIncomplete,
				resp.SessionExportDropped,
				resp.SessionExportSeq,
			)
		}
		if resp.SessionExportIncarnation == 0 || resp.SessionExportSeq == 0 {
			return nil, status, fmt.Errorf(
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
				return nil, status, fmt.Errorf(
					"%w: helper incarnation %d differs from status %d",
					ErrOwnerRGExportIncomplete,
					incarnation,
					expectedStatusIncarnation,
				)
			}
		} else if resp.SessionExportIncarnation != incarnation || resp.SessionExportSeq != sequence {
			return nil, status, fmt.Errorf(
				"%w: continuation token changed from (%d,%d) to (%d,%d)",
				ErrOwnerRGExportIncomplete,
				incarnation,
				sequence,
				resp.SessionExportIncarnation,
				resp.SessionExportSeq,
			)
		}
		if !probe && len(resp.SessionDeltas) > ownerRGExportPageDeltas {
			return nil, status, fmt.Errorf(
				"%w: helper returned %d deltas on page %d, max %d",
				ErrOwnerRGExportIncomplete,
				len(resp.SessionDeltas),
				page+1,
				ownerRGExportPageDeltas,
			)
		}
		if probe {
			// The probe is not another data page: it only gives a worker whose
			// final push preceded its ACK a chance to publish more=false.
			if len(resp.SessionDeltas) != 0 || resp.SessionExportMore {
				return nil, status, fmt.Errorf(
					"%w: terminal probe returned %d delta(s), more=%t",
					ErrOwnerRGExportUnterminated,
					len(resp.SessionDeltas),
					resp.SessionExportMore,
				)
			}
			return all, status, nil
		}
		// #15161: charge ACTUAL decoded retention, not the 1863-byte
		// worst-case JSON size. The old charge capped a complete window at
		// 17 pages (~139k-144k deltas) even when every delta decoded to a
		// few hundred bytes, so cold prime / FullResync failed closed on
		// any owner holding more than that. The byte bound is unchanged:
		// a window whose deltas really are wide still fails closed here,
		// and maxOwnerRGExportDataPages (512) remains the structural cap.
		var pageBytes int
		for i := range resp.SessionDeltas {
			pageBytes += ownerRGExportActualDeltaBytes(&resp.SessionDeltas[i])
		}
		if pageBytes > ownerRGExportMaxAccumulatorBytes ||
			retainedBytes > ownerRGExportMaxAccumulatorBytes-pageBytes {
			return nil, status, fmt.Errorf(
				"%w: export accumulator exceeds %d-byte bound",
				ErrOwnerRGExportIncomplete,
				ownerRGExportMaxAccumulatorBytes,
			)
		}
		retainedBytes += pageBytes
		all = append(all, resp.SessionDeltas...)
		if !resp.SessionExportMore {
			return all, status, nil
		}
	}
	return nil, status, fmt.Errorf(
		"%w: still reporting more after %d data pages and a terminal probe of %d deltas (%d collected)",
		ErrOwnerRGExportUnterminated,
		maxOwnerRGExportDataPages,
		ownerRGExportPageDeltas,
		len(all),
	)
}
