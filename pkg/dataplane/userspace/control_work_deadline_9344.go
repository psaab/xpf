package userspace

import "time"

// #9344 (the adjacent finding): controlRoundtripDeadline sizes the
// control-socket round trip off the REQUEST BODY, which is the wrong axis for a
// verb whose cost is WORK rather than bytes.
//
// `export_owner_rg_sessions` is asked with a ~60-byte request, so it lands
// under the 1 MiB threshold and gets controlBaseDeadline — 3 s. The helper's
// phase 2 waits up to OWNER_RG_EXPORT_ACK_WAIT (15 s, userspace-dp
// afxdp/ha/export.rs) for every worker to ack the export sequence BEFORE it
// drains a single delta or writes a single byte. So the caller can abandon a
// round trip the helper is still legitimately performing, and report a failed
// cold prime for a helper that was working.
//
// That is #4036's failure shape — "Go timed out and reported the apply FAILED
// while the dataplane had applied it live" — moved from the request-size axis
// to the work axis, and #4036's per-mebibyte fix does not reach it because
// there are no mebibytes to scale on.
//
// It matters more with paging than without: paging makes the export succeed at
// any session count, and an export that reliably times out at 3 s is not an
// export. Fixing the size bound while leaving the time bound would have shipped
// a fix that cannot run.
//
// SCOPE, deliberately: this raises a FLOOR for named verbs, it does not raise
// controlMaxDeadline. The #7675 reachable bound (controlBaseDeadline + 64 s =
// 67 s, from a 64 MiB apply) is unchanged and still the largest hold any stop
// analysis must budget for, because every floor here is far below it. The #8526
// shutdown census is likewise unaffected: armControlIO is still the single site
// and controlShutdownCeiling still clamps a stop in progress.
var controlVerbDeadlineFloors9344 = map[string]time.Duration{
	// 30 s is the absolute budget for the helper-owned policy READ and all
	// continuation pages in one capture. Individual pages remain bounded by
	// this floor; the manager enforces the same deadline across the sequence.
	"list_sessions_by_policy": 30 * time.Second,
	// 15 s of worker ack-wait, plus the drain, JSON serialization and write of
	// a page. The margin is 3 s — the same base a small request gets — rather
	// than a round number, so the helper's own bound and one ordinary round trip
	// fit without changing the global control deadline.
	"export_owner_rg_sessions": ownerRGExportAckWait + controlBaseDeadline,
	// #11840: fib_dump is requested with ~60 bytes but may return a full
	// MAX_CONTROL_RESPONSE_BYTES JSON body. Budget five response-sized
	// passes: route-row size measurement, response-cap counting, response
	// encoding, socket write, and Go response decode/framing. Estimate this
	// work at a pessimistic 10 MiB/s, then add one ordinary round trip as
	// margin. This covers the helper's and caller's full-response work
	// without raising the #7675 reachable bound or slowing unrelated verbs.
	"fib_dump": fibDumpWorstCaseResponseWork11840 + controlBaseDeadline,
}

// ownerRGExportAckWait mirrors OWNER_RG_EXPORT_ACK_WAIT in
// userspace-dp/src/afxdp/ha/export.rs.
//
// The two must agree, and TestOwnerRGExportAckWaitMatchesTheHelper9344 asserts
// the AGREEMENT by READING the Rust constant rather than pinning either side to
// a literal — the same shape as the syncedImportRefusedPrefix agreement test.
// A number restated in two languages with a comment saying "keep these in sync"
// is a number that will drift.
const ownerRGExportAckWait = 15 * time.Second
const (
	// Two helper-side JSON traversals (per-route sizing and full-response
	// cap counting), response encoding/write, and Go response
	// decode/framing account for five full-response-sized work passes.
	// The agreement test reads the Rust cap that sizes this budget.
	fibDumpWorstCaseResponseBytesPerSecond11840 = 10 * 1024 * 1024
	fibDumpWorstCaseResponseWorkPasses11840     = 5
	fibDumpWorstCaseResponseWork11840           = time.Duration((MaxControlResponseBytes*fibDumpWorstCaseResponseWorkPasses11840+
		fibDumpWorstCaseResponseBytesPerSecond11840-1)/fibDumpWorstCaseResponseBytesPerSecond11840) * time.Second
)

// controlWorkDeadline returns the round-trip deadline for a request: the
// body-sized deadline, raised to the verb's floor when it has one.
//
// It is a MAXIMUM of the two, never a replacement. A verb with a work floor can
// still carry a large body — nothing stops a future caller sending one — and
// taking the floor alone would silently shrink the budget the #4036 sizing
// grants it.
func controlWorkDeadline(reqType string, bodyLen int) time.Duration {
	d := controlRoundtripDeadline(bodyLen)
	if floor, ok := controlVerbDeadlineFloors9344[reqType]; ok && floor > d {
		d = floor
	}
	if d > controlMaxDeadline {
		d = controlMaxDeadline
	}
	return d
}
