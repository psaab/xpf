package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// A FullResync frame is acknowledged to the helper when
// handleEventStreamFullResync returns true, and the helper then trims its
// replay buffer past the barrier. The export behind it is one transaction with
// two obligations:
//
//   - #9767: it succeeds only if the whole export reached the session-sync send
//     queue. It used to go through the incremental producers' lossy queue: a
//     batch the #7194 schema gate withheld, or installs a full send queue
//     dropped, still reported success, and the standby never received those
//     sessions. The background sweep does not repair that, because it re-sends
//     only sessions whose timestamps moved, and a resync exports old ones.
//   - #9766: nothing else may queue a delta between the export's snapshot and
//     its queueing. The fallback loop's reconciliation drain and the event
//     stream callback can run on other goroutines, so both take
//     userspaceDeltaSyncMu. A close in that window therefore cannot reach the
//     peer ahead of the export's stale install. The paced repayment export is
//     ordered by this lock but is intentionally not an authoritative
//     reconciliation window; cold-start bulk remains broader and reconciles
//     stale receiver entries.
const (
	// fullResyncInstallWait bounds how long one export install waits for room
	// in the send queue. The writer drains thousands of messages a second, so a
	// wait this long means the link is stalled, not busy. Once one install has
	// timed out the rest of the batch is queued without waiting: a stalled link
	// costs the event-stream reader one wait, not one per session.
	fullResyncInstallWait = 2 * time.Second

	// fullResyncRetryBackoff holds off the export after an attempt that failed.
	// The event stream retries a withheld FullResync on every later frame and on
	// its 100 ms ACK tick, and each retry would otherwise re-run the synchronous
	// helper export.
	fullResyncRetryBackoff = time.Second
)

var errUserspaceDeltaSchemaWithheld = errors.New(
	"the helper's session-delta schema differs from this binary, so the batch was withheld (#7194)")

func (d *Daemon) fullResyncInstallWait() time.Duration {
	if d.fullResyncInstallWaitForTest > 0 {
		return d.fullResyncInstallWaitForTest
	}
	return fullResyncInstallWait
}

// fullResyncHeldOff reports whether a failed attempt's backoff is still running.
func (d *Daemon) fullResyncHeldOff(now time.Time) bool {
	return now.UnixNano() < d.fullResyncRetryAt.Load()
}

func (d *Daemon) holdOffFullResync(now time.Time) {
	d.fullResyncRetryAt.Store(now.Add(fullResyncRetryBackoff).UnixNano())
}

// drainUserspaceSessionDeltasLocked runs one fallback-loop drain batch under
// userspaceDeltaSyncMu, which a FullResync holds across its export and its
// queueing (#9766).
func (d *Daemon) drainUserspaceSessionDeltasLocked(drainer userspaceSessionDeltaDrainer, cfg *config.Config) (int, error) {
	d.userspaceDeltaSyncMu.Lock()
	defer d.userspaceDeltaSyncMu.Unlock()
	return d.drainUserspaceSessionDeltasWithConfigLocked(drainer, cfg, 1)
}

// discardUserspaceSessionDeltasLocked (#16627) runs one drain batch under
// userspaceDeltaSyncMu and discards ONLY the drained deltas the event
// stream has already applied: those whose StreamSeq is non-zero and at
// or below appliedSeq (the stream's LastAppliedSequence watermark from
// eventstream.go). It is the connected-arm counterpart of
// drainUserspaceSessionDeltasLocked. Queueing an already-streamed copy
// re-stamps it with a fresh generation, so a replayed open resurrects a
// session the stream already closed and a replayed close transiently
// deletes a live same-tuple successor. Deltas the stream never carried
// (StreamSeq 0: stream-down production, CommandExport, a failed lossless
// enqueue, or an older helper) and deltas ahead of the watermark are
// NOT duplicates — they are queued through the normal locked path, so
// discarding never happens on mere connectedness. The drain still runs
// so any covered backlog is cleared instead of being replayed minutes
// later after a disconnect. It returns the number of DISCARDED deltas.
//
// The helper's delta-schema fingerprint is recorded ONLY on a valid
// status (err == nil): a status that arrived with an error may be
// partial or zero, and recording it could clear a real mismatch (0 is
// "unknown") or invent one.
func (d *Daemon) discardUserspaceSessionDeltasLocked(drainer userspaceSessionDeltaDrainer, cfg *config.Config, appliedSeq uint64) (int, error) {
	d.userspaceDeltaSyncMu.Lock()
	defer d.userspaceDeltaSyncMu.Unlock()
	if drainer == nil || cfg == nil {
		return 0, nil
	}
	deltas, status, err := drainer.DrainSessionDeltas(256)
	if err == nil {
		d.recordUserspaceDeltaSchema(status.SessionDeltaSchemaFingerprint)
	}
	var keep []dpuserspace.SessionDeltaInfo
	discarded := 0
	for _, delta := range deltas {
		if delta.StreamSeq != 0 && delta.StreamSeq <= appliedSeq {
			discarded++
			continue
		}
		keep = append(keep, delta)
	}
	if len(keep) > 0 {
		d.queueUserspaceSessionDeltasLocked(buildZoneIDs(cfg), keep)
	}
	if err != nil {
		if len(deltas) == 0 {
			return 0, err
		}
		// The batch was destructively popped by the helper (#15217 shape):
		// the covered part is discarded and the rest queued above, but
		// the status error must still surface (counted + propagated)
		// rather than being silently swallowed with the deltas.
		errTotal := d.userspaceDeltaDrainStatusErrors.Add(1)
		if emit, suppressed := d.userspaceDeltaDrainStatusWarn.shouldLog(time.Now(), userspaceDeltaDrainStatusWarnInterval); emit {
			slog.Warn("userspace: session-delta discard-drain handled deltas despite helper status-apply error",
				"err", err, "deltas_in_batch", len(deltas), "discarded", discarded,
				"error_total", errTotal, "suppressed_since_last", suppressed)
		}
		return discarded, err
	}
	return discarded, nil
}

// queueUserspaceSessionDeltasComplete queues deltas through the same schema
// gate and the same walk as queueUserspaceSessionDeltasLocked, but paces each
// install against the send queue. It returns an error unless the gate admitted
// the batch and every install reached the queue.
func (d *Daemon) queueUserspaceSessionDeltasComplete(
	zoneIDs map[string]uint16,
	deltas []dpuserspace.SessionDeltaInfo,
	installWait time.Duration,
) (int, error) {
	ss := d.getSessionSync()
	if ss == nil {
		return 0, errors.New("session sync not ready")
	}
	if !d.userspaceDeltaSchemaAdmits(len(deltas)) {
		return 0, errUserspaceDeltaSchemaWithheld
	}
	sink := &pacedQueueDeltaSink{ss: ss, wait: installWait}
	n := d.walkUserspaceSessionDeltas(ss, zoneIDs, deltas, sink)
	if sink.missed > 0 {
		return n - sink.missed, fmt.Errorf("%d of %d session installs did not reach the session-sync send queue",
			sink.missed, sink.installs)
	}
	return n, nil
}

// queueUserspaceSessionDeltasCompleteStream is the streaming form: produce
// invokes the paged export, whose pages walk into the shared paced sink via
// walkPageIntoPacedSink. The #7194 schema gate is applied inside that walk
// for the first page only (before any install of the window): checking
// per page would flood the withheld counter/log dampener, and admitting
// early pages then withholding later ones would partially queue the window.
// If the gate withholds, the sink is flagged and this returns
// errUserspaceDeltaSchemaWithheld. On a mid-stream export error the caller
// discards the result; installs already queued from earlier pages ride the
// incremental stream, never a framed bulk window.
func (d *Daemon) queueUserspaceSessionDeltasCompleteStream(
	installWait time.Duration,
	produce func(*pacedQueueDeltaSink) error,
) (int, error) {
	ss := d.getSessionSync()
	if ss == nil {
		return 0, errors.New("session sync not ready")
	}
	sink := &pacedQueueDeltaSink{ss: ss, wait: installWait}
	if err := produce(sink); err != nil {
		if sink.schemaWithheld {
			return 0, errUserspaceDeltaSchemaWithheld
		}
		return 0, err
	}
	if sink.missed > 0 {
		return sink.installs - sink.missed, fmt.Errorf("%d of %d session installs did not reach the session-sync send queue",
			sink.missed, sink.installs)
	}
	return sink.installs - sink.missed, nil
}

// walkPageIntoPacedSink walks one streamed page into the paced sink. The
// first page carries the #7194 schema gate for the whole window (see
// queueUserspaceSessionDeltasCompleteStream); missed-install accounting
// lives on the sink itself.
func (d *Daemon) walkPageIntoPacedSink(sink *pacedQueueDeltaSink, zoneIDs map[string]uint16, deltas []dpuserspace.SessionDeltaInfo) error {
	ss := d.getSessionSync()
	if ss == nil {
		return errors.New("session sync not ready")
	}
	if !sink.gateChecked {
		sink.gateChecked = true
		if !d.userspaceDeltaSchemaAdmits(len(deltas)) {
			sink.schemaWithheld = true
			return errUserspaceDeltaSchemaWithheld
		}
	}
	if sink.schemaWithheld {
		return errUserspaceDeltaSchemaWithheld
	}
	d.walkUserspaceSessionDeltas(ss, zoneIDs, deltas, sink)
	return nil
}
