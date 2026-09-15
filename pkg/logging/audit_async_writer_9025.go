package logging

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Audit-log disk writes must not run on the EventStream reader goroutine
// (#9025).
//
// TraceWriter.HandleEvent and LocalLogWriter's callback did a synchronous
// `WriteString` on a raw *os.File — no bufio — and called rotate() inline when
// the size cap tripped, all from inside ringbuf's synchronous callback loop
// (`for _, cb := range cbs { cb(rec, data) }`). One `write(2)` per logged event
// on a SHARED goroutine.
//
// That goroutine is not a logging goroutine. The same EventStream switch loop
// also handles EventTypeSessionOpen/Update/Close (HA SESSION SYNC),
// EventTypeDrainComplete (the ISSU drain signal) and EventTypeFullResync. Under
// disk distress — writeback stall, dirty-page throttling, a full or hung device
// — the reader parks and HA session-sync deltas and the ISSU drain signal park
// with it.
//
// The contract is already stated in-tree and it names this collateral by name.
// pkg/flowexport/routemask.go (#3743) moved FIB lookups off this exact path
// because they "stall the event reader and every other callback behind it
// (including the trace writer)". That precedent moved a different blocking
// call; the trace writer it named as a victim was itself still blocking.
//
// Volume backpressure already existed (#3478 counts dropped and erroring
// writes). LATENCY backpressure did not, and a hung write never returns to be
// counted — which is why the fix is a queue rather than more counters.
//
// SHAPE: bounded queue, one dedicated writer goroutine, DROP AND COUNT on
// overflow — the shape #3478 established for volume, reused rather than
// reinvented. Dropping is correct here and blocking is not: blocking on a full
// queue would reintroduce exactly the stall this removes, just one buffer
// later.

// auditQueueDepth bounds the in-flight audit lines per writer.
//
// Sized so an ordinary burst is absorbed while a genuinely stalled disk is
// bounded in MEMORY as well as in latency: at ~200 bytes a line this is a few
// hundred KB per writer, and a writer that stays behind is losing telemetry
// either way — the queue's job is to absorb a burst, not to hide a stall. A
// deeper queue would delay the drop signal without preventing it, which is the
// worse trade for an audit surface: the operator needs to learn early.
const auditQueueDepth = 4096

// auditItem is either a LINE to write or a SYNC BARRIER. One channel carries
// both so the barrier is ordered behind every line already queued — FIFO is
// what makes `syncForTest` sound rather than a sleep in disguise.
type auditItem struct {
	// severity is carried alongside the text because LocalLogWriter formats
	// its line INSIDE Send (the RFC 5424 envelope needs the priority), so the
	// writer goroutine has to re-enter Send rather than being handed a
	// finished string. TraceWriter formats before enqueueing and ignores it.
	severity int
	line     string
	ack      chan struct{} // non-nil: a barrier, nothing to write
}

// asyncAuditWriter is the shared queue+goroutine for the two audit-log writers.
// ONE implementation rather than a copy in each: TraceWriter and LocalLogWriter
// had the same synchronous shape and the same #3478 drop accounting, and a
// second copy of a concurrency handoff is where two callers silently acquire
// different semantics.
type asyncAuditWriter struct {
	items chan auditItem
	// write performs the actual (locked) disk write. Supplied by the owner so
	// this type carries no knowledge of rotation or file handles.
	write func(auditItem)

	// mu serializes the retire check against the send (#9916 F-132): enqueue's
	// stopped-check-plus-send and stop's stopped-store-plus-done-close run under
	// it, so a send that passes the check happens-before the worker's final
	// drain observes the close. The hot receive path (worker) never takes it;
	// every critical section is a non-blocking channel op with no I/O (except
	// the test-only beforeSendFn pause below), so an EventStream-reader enqueue
	// blocks for microseconds at most.
	mu        sync.Mutex
	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
	// stopped makes a post-Close enqueue FAIL rather than silently filling a
	// channel nobody drains. Without it a retired writer swallowed every
	// later event with no drop counted — strictly worse than the
	// pre-#9025 behaviour, which counted them as nil-file drops, and
	// invisible because the queue had room.
	stopped atomic.Bool
	done    chan struct{}
	// drained closes once the writer goroutine has exited, so stop() can wait
	// for the queue to be flushed rather than truncating the audit tail.
	drained chan struct{}

	// dropped counts lines lost to a FULL queue. Distinct from #3478's
	// write-failure drops because the cause and the remedy differ: a full queue
	// means the disk is not keeping up; a write failure means it refused. The
	// owner folds this into its existing DroppedWrites so an operator watching
	// that one signal still sees the loss.
	dropped      atomic.Uint64
	lastWarnMu   sync.Mutex
	lastWarnTime time.Time
	// afterDrainFn is a test-only seam (#9916 F-132), mirroring #5062's. When
	// non-nil, the worker invokes it exactly once per retire, after observing
	// an empty queue in the final drain and before returning, so a test can
	// deterministically land a send in the drain-to-exit window. Nil in
	// production; a single nil-check on the retire path only.
	afterDrainFn func()
	// beforeSendFn is the second half of the F-132 test pair (parent-review
	// follow-up): when non-nil, enqueue invokes it after the stopped check
	// passes and before the send, WHILE HOLDING mu. A test pauses here, runs
	// stop() (which blocks on mu until the pause releases), then resumes — so
	// the send provably lands before the worker's drain and is handled exactly
	// once. On unfixed code (no mu) the same pause lets stop complete first and
	// the resumed send orphans. Nil in production (one nil-check on the enqueue
	// path); must not call back into enqueue/stop.
	beforeSendFn func()
}

func newAsyncAuditWriter(write func(auditItem)) *asyncAuditWriter {
	a := &asyncAuditWriter{
		items:   make(chan auditItem, auditQueueDepth),
		write:   write,
		done:    make(chan struct{}),
		drained: make(chan struct{}),
	}
	a.start()
	return a
}

func (a *asyncAuditWriter) start() {
	a.startOnce.Do(func() {
		a.started.Store(true)
		go func() {
			defer close(a.drained)
			for {
				select {
				case it := <-a.items:
					a.handle(it)
				case <-a.done:
					// Drain what is already queued before exiting. These lines
					// were ACCEPTED, and discarding them on shutdown loses
					// exactly the records around whatever caused the shutdown.
					for {
						select {
						case it := <-a.items:
							a.handle(it)
						default:
							if a.afterDrainFn != nil {
								a.afterDrainFn()
							}
							return
						}
					}
				}
			}
		}()
	})
}

func (a *asyncAuditWriter) handle(it auditItem) {
	if it.ack != nil {
		close(it.ack)
		return
	}
	a.write(it)
}

// enqueue offers a line to the writer WITHOUT BLOCKING. False means the queue
// was full and the caller must count a drop.
//
// The non-blocking send is the whole point: this runs on the EventStream reader
// goroutine, and a blocking send would put the stall back one buffer later.
// Dropping is correct for an audit surface under disk distress; blocking is
// not, because the goroutine being blocked also carries HA session sync and the
// ISSU drain signal.
func (a *asyncAuditWriter) enqueue(it auditItem) bool {
	a.mu.Lock()
	if a.stopped.Load() {
		// Retired: the goroutine is gone, so anything accepted here would never
		// be written. Refuse so the caller counts the loss.
		a.mu.Unlock()
		return false
	}
	if a.beforeSendFn != nil {
		a.beforeSendFn()
	}
	select {
	case a.items <- it:
		a.mu.Unlock()
		return true
	default:
		a.dropped.Add(1)
		a.mu.Unlock()
		// Rate-limited warn OUTSIDE mu: slog.Warn can re-enter the syslog send
		// path, and holding the retire lock across it would stall concurrent
		// enqueues on logging I/O.
		a.warnRateLimited()
		return false
	}
}

func (a *asyncAuditWriter) warnRateLimited() {
	a.lastWarnMu.Lock()
	defer a.lastWarnMu.Unlock()
	if time.Since(a.lastWarnTime) < time.Second {
		return
	}
	a.lastWarnTime = time.Now()
	slog.Warn("audit log write queue full; lines dropped (disk not keeping up)",
		"dropped_total", a.dropped.Load(), "depth", auditQueueDepth)
}

// Dropped reports lines lost to a full queue.
func (a *asyncAuditWriter) Dropped() uint64 { return a.dropped.Load() }

// stop signals the writer to drain and exit, then waits for it. Idempotent.
func (a *asyncAuditWriter) stop() {
	a.stopOnce.Do(func() {
		a.mu.Lock()
		a.stopped.Store(true)
		close(a.done)
		a.mu.Unlock()
	})
	if a.started.Load() {
		<-a.drained
		// Re-drain (#9916 F-132): collect anything that landed after the
		// worker's final empty-observation but before THIS mu acquisition — in
		// practice the mu-bypassing syncForTest barrier (mu already closes the
		// window for enqueue itself). NARROWLY SCOPED: a direct send landing
		// after this re-drain releases mu still orphans. That is acceptable
		// only because production has no mu-bypassers (every live send routes
		// through enqueue); the sole bypasser is syncForTest's test-only direct
		// send, whose post-stop case is benign (its waiter already returned via
		// the drained arm; at most one leaked barrier in a retired channel).
		// Collected under mu (non-blocking receives only), handled OUTSIDE it:
		// handle does disk I/O, and holding mu across a stalled write would
		// stall EventStream-reader enqueues on the disk.
		a.mu.Lock()
		var rest []auditItem
		for {
			select {
			case it := <-a.items:
				rest = append(rest, it)
			default:
				a.mu.Unlock()
				for _, it := range rest {
					a.handle(it)
				}
				return
			}
		}
	}
}

// syncForTest blocks until every line queued BEFORE the call has been written.
//
// It is not a production flush and production never needs one: the writer
// goroutine is always draining and stop() waits for it. It exists so a cell can
// assert on file contents without sleeping.
//
// It cannot pass by doing nothing. The barrier travels through the SAME FIFO
// channel as the lines, so the ack cannot fire until the writer has drained
// everything ahead of it — a no-op implementation would return early and the
// assertions after it would fail.
func (a *asyncAuditWriter) syncForTest() {
	ack := make(chan struct{})
	select {
	case a.items <- auditItem{ack: ack}:
	case <-a.drained:
		return
	}
	select {
	case <-ack:
	case <-a.drained:
	case <-time.After(5 * time.Second):
	}
}
