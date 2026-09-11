package daemon

import (
	"errors"
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
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
//     its queueing. The fallback loop's reconciliation drain runs on its own
//     goroutine. A close it drained in that window reached the peer ahead of
//     the export's stale install of the same session, and the install's fresher
//     generation resurrected the session on the standby.

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
	return d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
}

// queueUserspaceSessionDeltasComplete queues deltas through the same schema
// gate and the same walk as queueUserspaceSessionDeltas, but paces each install
// against the send queue. It returns an error unless the gate admitted the
// batch and every install reached the queue.
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

// pacedQueueDeltaSink is queueDeltaSink for the FullResync export. Each install
// waits for room in the send queue, and the sink counts the installs that did
// not reach it. A delete is queued as queueDeltaSink queues it: one that finds
// the queue full is journaled, and the next connected sweep flushes the journal
// (#3926), so it is not lost.
type pacedQueueDeltaSink struct {
	ss       *cluster.SessionSync
	wait     time.Duration
	installs int
	missed   int
}

// installWait is the next install's wait: none once an install has timed out.
func (p *pacedQueueDeltaSink) installWait() time.Duration {
	if p.missed > 0 {
		return 0
	}
	return p.wait
}

func (p *pacedQueueDeltaSink) openV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	p.installs++
	if !p.ss.QueueSessionV4Paced(key, val, p.installWait()) {
		p.missed++
	}
}

func (p *pacedQueueDeltaSink) openV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	p.installs++
	if !p.ss.QueueSessionV6Paced(key, val, p.installWait()) {
		p.missed++
	}
}

func (p *pacedQueueDeltaSink) deleteV4(key dataplane.SessionKey, _ dataplane.SessionValue) {
	p.ss.QueueDeleteV4(key)
}

func (p *pacedQueueDeltaSink) deleteV6(key dataplane.SessionKeyV6, _ dataplane.SessionValueV6) {
	p.ss.QueueDeleteV6(key)
}
