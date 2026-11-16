package cluster

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

// #19115: an owed cold-prime debt with no bulk in flight must be re-driven
// well inside the manual-failover admission window.
//
// ISSU drain and manual failover go through runPreHook, which retries a
// retryable pre-hook refusal for DefaultPreManualFailoverRetryTimeout (5s).
// The userspace pre-hook refuses at once while ColdPrimeOwedWithoutPendingBulk
// holds, and does nothing about the debt. On a live connection, the only thing
// that re-drives the debt is the sweep's owed re-drive branch, and the sweep
// runs only on its timer. Under the userspace dataplane that timer is
// SessionSyncSweepProfile's 15s active / 60s idle (#7842), and a re-drive that
// syncs no rows backs the interval off toward 60s. So a debt with nothing in
// flight outlives every admission window that starts inside it.
//
// Each property below has two subtests on the same fixture:
//
//   - control-fast-sweep: a 50ms/100ms sweep profile. It passes at master and
//     proves the fixture CAN observe a re-drive, so a red production subtest is
//     about cadence, not a broken harness.
//   - userspace-sweep-profile: the production 15s/60s profile. RED at master
//     05b4645749 (the re-drive waits for a sweep tick at least 15s away).

const (
	// owedRedriveBound19115 is how soon after the debt becomes undriven the
	// re-drive must have COMPLETED. It sits inside the admission window with
	// room left for the peer's ack round trip.
	owedRedriveBound19115 = 3 * time.Second
	// twoFailureRedriveBound19115 covers one failed re-drive followed by a
	// successful one.
	twoFailureRedriveBound19115 = 4 * time.Second
)

// errExportGenChanged19115 is the transient that failed the first owed bulk in
// the field (pkg/dataplane/userspace/owner_rg_export_paging_9344.go).
var errExportGenChanged19115 = errors.New("owner-RG export incomplete: helper/config generation changed during export window")

type sweepProfile19115 struct {
	name         string
	active, idle time.Duration
}

var sweepProfiles19115 = []sweepProfile19115{
	{name: "control-fast-sweep", active: 50 * time.Millisecond, idle: 100 * time.Millisecond},
	// pkg/dataplane/userspace/manager.go SessionSyncSweepProfile.
	{name: "userspace-sweep-profile", active: 15 * time.Second, idle: 60 * time.Second},
}

type sweepProfileSource19115 struct{ active, idle time.Duration }

func (sweepProfileSource19115) DrainSessionDeltas(uint32) (dpruntime.SessionDeltaSnapshot, error) {
	return dpruntime.SessionDeltaSnapshot{}, nil
}

func (sweepProfileSource19115) ExportOwnerRGSessions([]int, uint32) (dpruntime.SessionDeltaSnapshot, error) {
	return dpruntime.SessionDeltaSnapshot{}, nil
}

func (p sweepProfileSource19115) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	return true, p.active, p.idle
}

// flakySnapshot19115 is a table-truth source that fails its first `failures`
// reads the way the field's export did, then succeeds with an empty table.
type flakySnapshot19115 struct {
	failures atomic.Int32
	calls    atomic.Int32
	mu       sync.Mutex
	at       []time.Time
}

func (f *flakySnapshot19115) read() (BulkSnapshot, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.at = append(f.at, time.Now())
	f.mu.Unlock()
	for {
		left := f.failures.Load()
		if left <= 0 {
			return BulkSnapshot{}, nil
		}
		if f.failures.CompareAndSwap(left, left-1) {
			return BulkSnapshot{}, errExportGenChanged19115
		}
	}
}

// times returns when each read happened.
func (f *flakySnapshot19115) times() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.at...)
}

// fixture19115 observes the sweep loop: every timer (re)arm, with its delay,
// and every sweep that reached the incremental scan.
type fixture19115 struct {
	arms   chan time.Duration
	sweeps atomic.Int64
}

var fixtures19115 sync.Map // *SessionSync -> *fixture19115

func fx19115(ss *SessionSync) *fixture19115 {
	v, _ := fixtures19115.Load(ss)
	return v.(*fixture19115)
}

// drainArms19115 empties the arm stream and returns what was in it.
func drainArms19115(fx *fixture19115) []time.Duration {
	var out []time.Duration
	for {
		select {
		case d := <-fx.arms:
			out = append(out, d)
		default:
			return out
		}
	}
}

// primarySync19115 is a primary whose runtime is wired with the given sweep
// profile and whose sweep loop is ALREADY running, as in production: the
// daemon starts the sweep at bring-up, long before a peer reconnects.
//
// It returns only once the loop has armed its first, long timer (Codex P2-5
// on the design: without that, a trigger could land before the loop runs and
// a missing wake would be masked by startup scheduling).
func primarySync19115(t *testing.T, ctx context.Context, p sweepProfile19115, src func() (BulkSnapshot, error)) *SessionSync {
	t.Helper()
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.sessions = livenessProfiledSessionStore16880{
		SessionStore: ss.sessions,
		source:       sweepProfileSource19115{active: p.active, idle: p.idle},
	}
	if active, idle := ss.sweepIntervals(); active != p.active || idle != p.idle {
		t.Fatalf("FIXTURE: sweep profile not adopted: got %v/%v, want %v/%v", active, idle, p.active, p.idle)
	}
	ss.IsPrimaryFn = func() bool { return true }
	ss.BulkSnapshotSource = src
	fx := &fixture19115{arms: make(chan time.Duration, 256)}
	fixtures19115.Store(ss, fx)
	t.Cleanup(func() { fixtures19115.Delete(ss) })
	ss.testSweepTimerArmed = func(d time.Duration) {
		select {
		case fx.arms <- d:
		default:
		}
	}
	ss.testSweepNow = func() uint64 {
		fx.sweeps.Add(1)
		return monotonicSeconds()
	}
	ss.StartSyncSweep(ctx)
	select {
	case d := <-fx.arms:
		if d < p.active {
			t.Fatalf("FIXTURE: the first sweep timer was armed at %v, below the profile's %v", d, p.active)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FIXTURE: the sweep loop never armed its timer")
	}
	return ss
}

// connectWithFailedColdPrime19115 connects a peer, which drives the owed cold
// prime in installConn; the snapshot source fails it.
func connectWithFailedColdPrime19115(t *testing.T, ctx context.Context, ss *SessionSync, snap *flakySnapshot19115) *bulkCaptureConn {
	t.Helper()
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	if got := snap.calls.Load(); got != 1 {
		t.Fatalf("FIXTURE: the connect must have attempted exactly one cold-prime bulk, got %d snapshot reads", got)
	}
	if got := ss.stats.BulkSyncs.Load(); got != 0 {
		t.Fatalf("FIXTURE: the first cold-prime bulk must have failed, got %d completed bulks", got)
	}
	if !ss.ColdPrimeOwedWithoutPendingBulk() {
		t.Fatal("FIXTURE: the failed cold prime must leave the debt owed with no bulk pending")
	}
	return conn
}

// waitForBulkSyncs19115 polls until `want` bulks have completed or `bound`
// elapses, and returns how long it took.
func waitForBulkSyncs19115(ss *SessionSync, want uint64, bound time.Duration) (time.Duration, bool) {
	start := time.Now()
	for {
		if ss.stats.BulkSyncs.Load() >= want {
			return time.Since(start), true
		}
		if time.Since(start) >= bound {
			return time.Since(start), false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOwedRedriveBoundFitsTheAdmissionWindow19115(t *testing.T) {
	if owedRedriveBound19115 >= DefaultPreManualFailoverRetryTimeout ||
		twoFailureRedriveBound19115 >= DefaultPreManualFailoverRetryTimeout {
		t.Fatalf("the #19115 re-drive bounds (%v, %v) must sit inside the %v admission window, "+
			"or the cells below no longer say anything about admission",
			owedRedriveBound19115, twoFailureRedriveBound19115, DefaultPreManualFailoverRetryTimeout)
	}
}

// TestFailedOwedColdPrimeIsRedrivenPromptly19115 is the field shape: the
// connect-time cold prime fails once on a transient export error, and the
// connection stays up.
//
// After the re-drive it also pins the rest of the cycle: no second bulk while
// the ack is awaited (#9626), and the peer's ack discharges the debt.
func TestFailedOwedColdPrimeIsRedrivenPromptly19115(t *testing.T) {
	for _, p := range sweepProfiles19115 {
		t.Run(p.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			snap := &flakySnapshot19115{}
			snap.failures.Store(1)
			ss := primarySync19115(t, ctx, p, snap.read)
			conn := connectWithFailedColdPrime19115(t, ctx, ss, snap)

			took, ok := waitForBulkSyncs19115(ss, 1, owedRedriveBound19115)
			if !ok {
				t.Fatalf("#19115: the owed cold prime was not re-driven within %v of its failure "+
					"(sweep profile %v/%v; %d snapshot reads). A manual failover or ISSU drain "+
					"started now is refused for the whole %v admission window.",
					owedRedriveBound19115, p.active, p.idle, snap.calls.Load(), DefaultPreManualFailoverRetryTimeout)
			}
			t.Logf("owed cold prime re-driven %v after its failure", took.Round(time.Millisecond))

			// #9626: while the ack is awaited, nothing re-sends the bulk.
			time.Sleep(1200 * time.Millisecond)
			if got := ss.stats.BulkSyncs.Load(); got != 1 {
				t.Fatalf("#19115/#9626: want exactly one completed bulk while its ack is awaited, got %d", got)
			}
			epoch, _, pending := ss.PendingBulkAck()
			if !pending || !ss.needColdPrime.Load() {
				t.Fatalf("#9626: after the re-drive, want a pending ack and a still-owed debt, got pending=%v owed=%v",
					pending, ss.needColdPrime.Load())
			}
			// #18752: a successful send resets the RETRY schedule only; the
			// owed age and the last failure stay until the peer acks.
			if detail := ss.ColdPrimeDebtDetail(); !strings.Contains(detail, errExportGenChanged19115.Error()) {
				t.Errorf("#18752: before the ack, the debt detail must still name the last failure, got %q", detail)
			}
			ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch))
			if ss.needColdPrime.Load() {
				t.Fatal("#9626: the peer's ack for the re-driven bulk did not discharge the debt")
			}
		})
	}
}

// TestRepeatedlyFailingOwedColdPrimeKeepsRetryingPromptly19115: the first
// RE-DRIVE fails too. The retry after it must be prompt as well; at master a
// failed re-drive syncs no rows, so the sweep backs off toward its idle
// interval.
func TestRepeatedlyFailingOwedColdPrimeKeepsRetryingPromptly19115(t *testing.T) {
	for _, p := range sweepProfiles19115 {
		t.Run(p.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			snap := &flakySnapshot19115{}
			snap.failures.Store(2)
			ss := primarySync19115(t, ctx, p, snap.read)
			connectWithFailedColdPrime19115(t, ctx, ss, snap)

			took, ok := waitForBulkSyncs19115(ss, 1, twoFailureRedriveBound19115)
			if !ok {
				t.Fatalf("#19115: with one failed re-drive, the owed cold prime was not delivered within %v "+
					"(sweep profile %v/%v; %d snapshot reads, want 3)",
					twoFailureRedriveBound19115, p.active, p.idle, snap.calls.Load())
			}
			if got := snap.calls.Load(); got != 3 {
				t.Fatalf("#19115: want exactly 3 snapshot reads (failed connect, failed re-drive, success), got %d", got)
			}
			t.Logf("owed cold prime delivered %v after the connect failure", took.Round(time.Millisecond))
		})
	}
}

// TestSweepWakesDoNotPostponeAnOwedColdPrime19115: sweep wakes keep arriving
// while the debt is owed (the capability exchange wakes the sweep on every
// reconnect, sync_fence_ack_7147.go). At master the wake case RESETS the timer
// to the current interval, so each wake moves the sweep later. A wake may
// bring a re-drive forward; it must never push it back.
func TestSweepWakesDoNotPostponeAnOwedColdPrime19115(t *testing.T) {
	for _, p := range sweepProfiles19115 {
		t.Run(p.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			snap := &flakySnapshot19115{}
			snap.failures.Store(1)
			ss := primarySync19115(t, ctx, p, snap.read)
			connectWithFailedColdPrime19115(t, ctx, ss, snap)

			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				tick := time.NewTicker(100 * time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-stop:
						return
					case <-tick.C:
						ss.wakeSyncSweep()
					}
				}
			}()
			took, ok := waitForBulkSyncs19115(ss, 1, owedRedriveBound19115)
			close(stop)
			<-done
			if !ok {
				t.Fatalf("#19115: under a stream of sweep wakes, the owed cold prime was not re-driven within %v "+
					"(sweep profile %v/%v; %d snapshot reads)",
					owedRedriveBound19115, p.active, p.idle, snap.calls.Load())
			}
			t.Logf("owed cold prime re-driven %v after its failure, under wakes", took.Round(time.Millisecond))
		})
	}
}

// TestPeerRebootArmedColdPrimeIsDrivenPromptly19115: a debt can be armed with
// NO bulk attempt at all. When the restarted peer's priming BulkStart arrives
// on the alternate fabric slot carrying a new boot id, classifyPrimeLocked
// switches the incarnation and arms the debt (sync_conn.go, #6910/#7762), and
// leaves it to the sweep's re-drive. A fix that schedules a retry only where a
// bulk FAILS never sees this debt.
//
// The classifier is a changed peer OS boot id (/proc/sys/kernel/random/boot_id,
// sync_boot_incarnation.go) on a priming BulkStart: a VM or host REBOOT of the
// peer, whether its old connection lingers here or left before the BulkStart
// (sync_bootid_reboot_coldprime_9618_test.go). A clean xpfd restart keeps the
// boot id and never takes this edge. (An earlier revision said the edge needs
// a no-FIN "corpse"; that was wrong, Codex P3 on the design.)
func TestPeerRebootArmedColdPrimeIsDrivenPromptly19115(t *testing.T) {
	for _, p := range sweepProfiles19115 {
		t.Run(p.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			snap := &flakySnapshot19115{}
			ss := primarySync19115(t, ctx, p, snap.read)

			// The old peer process primed on fabric 0.
			corpse := newBulkCaptureConn()
			t.Cleanup(func() { corpse.Close() })
			ss.installConn(0, corpse)
			ss.noteConnBootIncarnation(corpse, incarnation6910(0xA1))
			ss.notePeerBootIncarnation(incarnation6910(0xA1))
			// Its table was primed and acknowledged before it restarted.
			ss.DischargeColdPrimeForTesting()
			// The replacement connects into the empty alternate slot.
			repl := newBulkCaptureConn()
			t.Cleanup(func() { repl.Close() })
			ss.installConn(1, repl)
			ss.DischargeColdPrimeForTesting()
			if ss.needColdPrime.Load() {
				t.Fatal("FIXTURE: the debt must be discharged before the reboot is observed")
			}
			if got := snap.calls.Load(); got != 0 {
				t.Fatalf("FIXTURE: no bulk may have been attempted yet, got %d snapshot reads", got)
			}

			// The replacement primes us with a NEW boot id.
			ss.handleMessage(repl, syncMsgBulkStart, bulkStartPayload6910(7, incarnation6910(0xB2)))
			if !ss.ColdPrimeOwedWithoutPendingBulk() {
				t.Fatal("FIXTURE: the peer's reboot must arm a cold-prime debt with no bulk pending")
			}

			took, ok := waitForBulkSyncs19115(ss, 1, owedRedriveBound19115)
			if !ok {
				t.Fatalf("#19115: a cold prime armed by the peer's reboot was not driven within %v "+
					"(sweep profile %v/%v; %d snapshot reads)",
					owedRedriveBound19115, p.active, p.idle, snap.calls.Load())
			}
			t.Logf("reboot-armed cold prime driven %v after the arm", took.Round(time.Millisecond))
		})
	}
}

// TestRedriveDoesNotStackOnAnInFlightColdPrime19115 is a GUARD for the fix,
// GREEN at master: a prompt re-drive must not start a second bulk while the
// connect-time cold prime is still running.
//
// While that bulk runs, nothing marks it in flight: the pending ack is
// published only after BulkEnd, so the debt reads "owed without pending" for
// the bulk's whole duration, and bulkRedriveInFlight covers re-drives only. A
// re-drive that passes its predicate there blocks on bulkSendMu and then sends
// a second full bulk. At master the 15s sweep hides that behind any bulk
// shorter than 15s; a retry delay of about a second would not.
func TestRedriveDoesNotStackOnAnInFlightColdPrime19115(t *testing.T) {
	p := sweepProfiles19115[1]
	if p.name != "userspace-sweep-profile" {
		t.Fatalf("FIXTURE: want the production profile, got %q", p.name)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	ss := primarySync19115(t, ctx, p, func() (BulkSnapshot, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release // a long table-truth export
		}
		return BulkSnapshot{}, nil
	})

	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	connected := make(chan struct{})
	go func() {
		defer close(connected)
		ss.handleNewConnection(ctx, 0, conn, true)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("FIXTURE: the connect-time cold prime never reached its snapshot read")
	}
	// Longer than any prompt-retry delay a fix would choose.
	time.Sleep(2500 * time.Millisecond)
	close(release)
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("FIXTURE: the connect-time cold prime did not finish after its export was released")
	}
	time.Sleep(1200 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("#19115: a second bulk was started on top of the in-flight connect-time cold prime "+
			"(%d snapshot reads, want 1)", got)
	}
	if got := ss.stats.BulkSyncs.Load(); got != 1 {
		t.Fatalf("#19115: want exactly one completed bulk, got %d", got)
	}
}

// ── design v3 cells (#19115, Codex review of the design) ─────────────────

// TestOwedRetryBacksOffUnderAFastSweep19115 (Codex P1-1): the backoff is a
// deadline the re-drive checks, not a timer cap. Under a sweep that ticks
// every 50-100 ms (the fast profile; negotiated liveness or session work
// speed the production sweep up the same way), a persistently failing export
// must still be attempted about 1 s, then 2 s, then 4 s after each failure
// (these failures are instantaneous, so that is also the start-to-start gap;
// TestOwedRetryBackoffRunsFromTheFailedAttemptsEnd19115 separates the two),
// not on every tick. (A first revision negotiated primary liveness for the fast sweep; its
// scan interval adapts upward with no rows, so the sweep was not actually fast
// and the cell did not see a missing deadline check.)
func TestOwedRetryBacksOffUnderAFastSweep19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	snap.failures.Store(1 << 20)
	ss := primarySync19115(t, ctx, sweepProfiles19115[0], snap.read)
	connectWithFailedColdPrime19115(t, ctx, ss, snap)
	time.Sleep(11500 * time.Millisecond)
	at := snap.times()
	if len(at) < 4 {
		t.Fatalf("#19115: want the connect attempt and three retries within 11.5 s, got %d attempts", len(at))
	}
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		gap := at[i+1].Sub(at[i])
		if gap < want-150*time.Millisecond {
			t.Errorf("#19115 (Codex P1-1): retry %d came %v after the previous attempt, want at least %v; the fast sweep bypassed the backoff",
				i+1, gap.Round(time.Millisecond), want)
		}
		if gap > want+1500*time.Millisecond {
			t.Errorf("#19115: retry %d came %v after the previous attempt, want about %v", i+1, gap.Round(time.Millisecond), want)
		}
	}
}

// TestOwedRetryBackoffRunsFromTheFailedAttemptsEnd19115 (Codex findings 7
// and 20 on design v4): the backoff runs from the END of a failed attempt, so
// the failed attempt's own duration adds to the start-to-start gap, and under
// the production 15 s / 60 s profile the sweep timer is armed exactly at each
// deadline, the 4 s step included. Every failed export takes 400 ms. A backoff
// measured from the attempt's START comes 400 ms early; a timer that rounds a
// deadline up (or waits for the profile) comes late.
func TestOwedRetryBackoffRunsFromTheFailedAttemptsEnd19115(t *testing.T) {
	const exportTakes = 400 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var mu sync.Mutex
	var starts, ends []time.Time
	var failuresLeft atomic.Int32
	failuresLeft.Store(3) // the connect attempt and two re-drives fail
	src := func() (BulkSnapshot, error) {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		if failuresLeft.Add(-1) < 0 {
			return BulkSnapshot{}, nil
		}
		time.Sleep(exportTakes)
		mu.Lock()
		ends = append(ends, time.Now())
		mu.Unlock()
		return BulkSnapshot{}, errExportGenChanged19115
	}
	ss := primarySync19115(t, ctx, sweepProfiles19115[1], src)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	if _, ok := waitForBulkSyncs19115(ss, 1, 11*time.Second); !ok {
		t.Fatalf("#19115: the owed debt was not delivered within 11 s (want failures ending at about 0.4 s, 1.8 s and 4.2 s, then a success at about 8.2 s)")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(starts) != 4 || len(ends) != 3 {
		t.Fatalf("FIXTURE: want 4 attempts and 3 failures, got %d and %d", len(starts), len(ends))
	}
	for i, backoff := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		fromEnd := starts[i+1].Sub(ends[i])
		if fromEnd < backoff-30*time.Millisecond {
			t.Errorf("#19115 (Codex finding 20): retry %d started %v after the failed attempt ENDED, want at least %v; "+
				"the backoff ran from the attempt's start", i+1, fromEnd.Round(time.Millisecond), backoff)
		}
		if fromEnd > backoff+400*time.Millisecond {
			t.Errorf("#19115 (Codex findings 7, 13): retry %d started %v after the failed attempt ended, want about %v; "+
				"the sweep timer was not armed at the deadline", i+1, fromEnd.Round(time.Millisecond), backoff)
		}
		t.Logf("retry %d: %v after the failure ended, %v after the failed attempt started",
			i+1, fromEnd.Round(time.Millisecond), starts[i+1].Sub(starts[i]).Round(time.Millisecond))
	}
	if gap := starts[3].Sub(starts[2]); gap < 4*time.Second+exportTakes-30*time.Millisecond {
		t.Errorf("#19115 (Codex finding 7): at the 4 s step the start-to-start gap is %v, want at least 4 s plus the failed export's %v",
			gap.Round(time.Millisecond), exportTakes)
	}
}

// TestOwedRetryBackoffHasALongTail19115 (the user's decision of
// 2026-11-15): the first three consecutive failures of an owed episode back
// off 1 s, 2 s and 4 s, the admission phase that wins a 5 s drain window; a
// failure after those grows the backoff to 8 s, 16 s and then a 30 s cap,
// so a persistently failing export costs one attempt per 30 s, not per 4 s.
// A successful send and a new debt generation restart the schedule, and the
// sweep timer is armed at the full tail deadline. Driven with a fake
// monotonic clock, so the exact deadlines are read, not waited for.
func TestOwedRetryBackoffHasALongTail19115(t *testing.T) {
	ss := bareSync19115((&flakySnapshot19115{}).read)
	now := int64(1_000_000_000_000)
	ss.nowMonoFn = func() int64 { return now }
	fail := func(n int) []time.Duration {
		var got []time.Duration
		for range n {
			ss.noteBulkRetryResult(errExportGenChanged19115)
			got = append(got, time.Duration(ss.bulkRetryNotBeforeNs()-now))
			now += int64(time.Minute) // the next failure ends well after this deadline
		}
		return got
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	got := fail(len(want))
	for i := range want {
		switch {
		case i < 3 && got[i] != want[i]:
			t.Errorf("#19115 admission phase: failure %d backed off %v, want %v; growing before the third failure loses the retries that win a 5 s drain window",
				i+1, got[i], want[i])
		case got[i] != want[i]:
			t.Errorf("#19115 long tail: failure %d backed off %v, want %v (8 s, 16 s, then a 30 s cap)", i+1, got[i], want[i])
		}
	}

	// In the tail, an owed debt's sweep timer is armed at the full deadline,
	// not at a profile interval.
	ss.mu.Lock()
	ss.armColdPrimeLocked()
	ss.mu.Unlock()
	fail(len(coldPrimeRetrySchedule))
	now -= int64(time.Minute) // back to the moment the last failure ended
	if d := ss.nextSweepDelay(time.Minute); d != 30*time.Second {
		t.Errorf("#19115: with the backoff at its 30 s cap the sweep timer is %v, want exactly 30 s", d)
	}
	now += int64(time.Minute)

	// A successful send restarts the schedule.
	ss.noteBulkRetryResult(nil)
	if got := fail(1)[0]; got != time.Second {
		t.Errorf("#19115: after a successful send the next failure backed off %v, want 1 s", got)
	}
	// So does a new debt generation, from deep in the tail.
	fail(len(coldPrimeRetrySchedule))
	ss.mu.Lock()
	ss.armColdPrimeLocked()
	ss.mu.Unlock()
	if got := fail(1)[0]; got != time.Second {
		t.Errorf("#19115: after a new debt generation the next failure backed off %v, want 1 s", got)
	}
}

// TestDebtFreeSweepKeepsItsProfileCadence19115: with no debt owed the sweep
// is not accelerated. After the cold prime is acknowledged, no sweep runs and
// no timer below the profile interval is armed for 3 s.
func TestDebtFreeSweepKeepsItsProfileCadence19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	p := sweepProfiles19115[1]
	ss := primarySync19115(t, ctx, p, snap.read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	epoch, _, pending := ss.PendingBulkAck()
	if !pending || ss.stats.BulkSyncs.Load() != 1 {
		t.Fatalf("FIXTURE: want the cold prime sent and pending, got pending=%v bulks=%d", pending, ss.stats.BulkSyncs.Load())
	}
	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch))
	if ss.needColdPrime.Load() {
		t.Fatal("FIXTURE: the ack did not discharge the debt")
	}
	fx := fx19115(ss)
	drainArms19115(fx)
	before := fx.sweeps.Load()
	time.Sleep(3 * time.Second)
	// The timer the connect-time arm lowered to the 1 s floor may still fire
	// once; every timer armed from here on must be the profile's.
	for _, d := range drainArms19115(fx) {
		if d < p.active {
			t.Errorf("#19115: with no debt owed the sweep timer was armed at %v, below the profile's %v", d, p.active)
		}
	}
	if n := fx.sweeps.Load() - before; n > 1 {
		t.Errorf("#19115: %d sweeps ran in 3 s with no debt owed (profile %v); at most the one already armed may", n, p.active)
	}
}

// TestFencedDebtWaitsForCapableDiscovery19115 (Codex P1-3): while the bulk is
// fenced for an incapable peer, the owed debt is not retried and does not
// speed the sweep up; a capable discovery makes the SAME debt (no new
// generation) eligible and wakes the sweep, which re-drives it promptly.
func TestFencedDebtWaitsForCapableDiscovery19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	snap.failures.Store(1)
	ss := primarySync19115(t, ctx, sweepProfiles19115[1], snap.read)
	connectWithFailedColdPrime19115(t, ctx, ss, snap)
	// The window the next retry would open hits the install fence.
	ss.peerIncarnationState().bulkFencedForPeer.Store(true)
	if ss.bulkFenceNow() == nil {
		t.Fatal("FIXTURE: the bulk is not fenced")
	}
	// A bulk run outside the sweep (a daemon prime, a peer request) is refused
	// at the fence BEFORE its table-truth read (design v3 C).
	if err := ss.DoBulkSync(); !errors.Is(err, errBulkFencedForPeer) {
		t.Fatalf("FIXTURE: a fenced bulk returned %v, want errBulkFencedForPeer", err)
	}
	if got := snap.calls.Load(); got != 1 {
		t.Fatalf("#19115 (Codex P1-3): a fenced bulk read the table-truth snapshot (%d reads, want 1)", got)
	}
	gen := ss.coldPrimeGen.Load()
	fx := fx19115(ss)
	before := fx.sweeps.Load()
	time.Sleep(3 * time.Second)
	if got := snap.calls.Load(); got != 1 {
		t.Errorf("#19115 (Codex P1-3): a fenced debt was retried: %d snapshot reads, want 1", got)
	}
	if n := fx.sweeps.Load() - before; n > 1 {
		t.Errorf("#19115 (Codex P1-3): a fenced debt kept the sweep at the retry cadence: %d sweeps in 3 s", n)
	}
	// nil is handlePeerCapabilities' unit-test seam (it stores for the
	// current incarnation unconditionally), as in the #9752 cells.
	ss.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity))
	if ss.bulkFenceNow() != nil {
		t.Fatal("FIXTURE: the capability frame did not lift the fence")
	}
	took, ok := waitForBulkSyncs19115(ss, 1, owedRedriveBound19115)
	if !ok {
		t.Fatalf("#19115 (Codex P1-3): capable discovery did not get the fenced debt re-driven within %v", owedRedriveBound19115)
	}
	if got := ss.coldPrimeGen.Load(); got != gen {
		t.Errorf("#19115: capable discovery armed a new debt generation (%d -> %d) instead of waking the owed one", gen, got)
	}
	t.Logf("fenced debt re-driven %v after capable discovery", took.Round(time.Millisecond))
}

// TestDebtArmedDuringABulkIsSentAfterIt19115 (Codex P1-2 on design v3,
// finding 15 on v4): a debt generation armed AFTER a bulk captured its
// generation is a newer debt, which that bulk does not pay (#9626). The
// sender is HELD at its BulkStart write: after the window captured the
// generation it pays, before it publishes its pending ack. The newer
// generation is armed there, and only then is the sender released. The held
// bulk must publish the OLDER generation (so its ack cannot discharge the
// newer debt), and the newer debt must then be sent promptly by a second bulk
// that carries it.
func TestDebtArmedDuringABulkIsSentAfterIt19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ss := primarySync19115(t, ctx, sweepProfiles19115[1], (&flakySnapshot19115{}).read)
	conn := &holdAtBulkStartConn19115{
		bulkCaptureConn: newBulkCaptureConn(),
		ss:              ss,
		held:            make(chan struct{}),
		release:         make(chan struct{}),
	}
	t.Cleanup(func() {
		conn.releaseOnce.Do(func() { close(conn.release) })
		conn.Close()
	})
	connected := make(chan struct{})
	go func() {
		defer close(connected)
		ss.handleNewConnection(ctx, 0, conn, true)
	}()
	select {
	case <-conn.held:
	case <-time.After(5 * time.Second):
		t.Fatal("FIXTURE: the connect-time bulk never wrote its BulkStart")
	}
	// The sender is between its generation capture and its pending
	// publication. The generation it captured is the current one: nothing has
	// armed since.
	ss.mu.Lock()
	captured := ss.coldPrimeGen.Load()
	ss.armColdPrimeLocked()
	newer := ss.coldPrimeGen.Load()
	ss.mu.Unlock()
	if newer == captured {
		t.Fatal("FIXTURE: the arm did not make a newer generation")
	}
	conn.releaseOnce.Do(func() { close(conn.release) })
	<-connected
	if got := conn.firstPublished.Load(); got != captured {
		t.Fatalf("#9626 (Codex finding 15): the held bulk published generation %d, want the %d it captured before the arm "+
			"(the newer %d is not this bulk's to pay)", got, captured, newer)
	}
	took, ok := waitForBulkSyncs19115(ss, 2, owedRedriveBound19115)
	if !ok {
		t.Fatalf("#19115 (Codex P1-2): the debt armed during a bulk was not sent within %v of that bulk (%d bulks)",
			owedRedriveBound19115, ss.stats.BulkSyncs.Load())
	}
	if got := ss.pendingBulkOwed.Load(); got != newer {
		t.Errorf("#19115: the bulk sent after the held one carries generation %d, want the newer %d", got, newer)
	}
	t.Logf("newer debt sent %v after the held bulk ended", took.Round(time.Millisecond))
}

// holdAtBulkStartConn19115 holds the FIRST BulkStart write until release is
// closed (held is closed when it is reached), and records the pending
// generation the first bulk published when that bulk writes its BulkEnd: the
// window publishes the pending stamp before it writes BulkEnd.
type holdAtBulkStartConn19115 struct {
	*bulkCaptureConn
	ss             *SessionSync
	held, release  chan struct{}
	startOnce      sync.Once
	endOnce        sync.Once
	releaseOnce    sync.Once
	firstPublished atomic.Uint64
}

func (c *holdAtBulkStartConn19115) Write(b []byte) (int, error) {
	if len(b) > 4 && b[4] == syncMsgBulkStart {
		c.startOnce.Do(func() {
			close(c.held)
			<-c.release
		})
	}
	if len(b) > 4 && b[4] == syncMsgBulkEnd {
		c.endOnce.Do(func() { c.firstPublished.Store(c.ss.pendingBulkOwed.Load()) })
	}
	return c.bulkCaptureConn.Write(b)
}

// TestAgedAckIsRetriedAtItsExpiry19115 (Codex P1-2): a young ack suppresses
// retries (#9626) without speeding the sweep up, and its BulkAckPendingRetryAfter
// expiry is part of the debt's due time: an ack aged to 34.5 s is retried at
// about 35 s, not at the next 15 s / 60 s profile tick.
func TestAgedAckIsRetriedAtItsExpiry19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ss := primarySync19115(t, ctx, sweepProfiles19115[1], (&flakySnapshot19115{}).read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	if _, _, pending := ss.PendingBulkAck(); !pending || ss.stats.BulkSyncs.Load() != 1 {
		t.Fatal("FIXTURE: want the cold prime sent and its ack pending")
	}
	fx := fx19115(ss)
	drainArms19115(fx)
	time.Sleep(1500 * time.Millisecond)
	if got := ss.stats.BulkSyncs.Load(); got != 1 {
		t.Fatalf("#9626: a young ack was not respected: %d bulks", got)
	}
	// While only a young ack is awaited, the debt is due at the ack's expiry,
	// so no timer below the profile is armed (the one the connect-time arm
	// lowered may still fire once and is re-armed at the profile).
	for _, d := range drainArms19115(fx) {
		if d < sweepProfiles19115[1].active {
			t.Errorf("#19115: while only a young ack was awaited the sweep timer was armed at %v", d)
		}
	}
	// The ack is now about to expire; the due time must include that expiry.
	ss.pendingBulkAckSince.Store(ss.nowMono() - int64(34500*time.Millisecond))
	ss.wakeSyncSweep()
	took, ok := waitForBulkSyncs19115(ss, 2, owedRedriveBound19115)
	if !ok {
		t.Fatalf("#19115 (Codex P1-2): an ack past BulkAckPendingRetryAfter was not retried within %v", owedRedriveBound19115)
	}
	t.Logf("aged ack retried %v after it neared expiry", took.Round(time.Millisecond))
}

// TestNewDebtGenerationIsDueAtOnce19115: a new debt generation is not held to
// an older one's backoff. After three failed attempts the next retry is 4 s
// out; a new arm (the peer-reboot edge, a capable discovery) is re-driven at
// the 1 s floor instead.
func TestNewDebtGenerationIsDueAtOnce19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	snap.failures.Store(3)
	ss := primarySync19115(t, ctx, sweepProfiles19115[1], snap.read)
	connectWithFailedColdPrime19115(t, ctx, ss, snap)
	deadline := time.Now().Add(6 * time.Second)
	for snap.calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("FIXTURE: want three failed attempts (connect, +1 s, +2 s), got %d", snap.calls.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	ss.mu.Lock()
	ss.armColdPrimeLocked()
	ss.mu.Unlock()
	took, ok := waitForBulkSyncs19115(ss, 1, 2500*time.Millisecond)
	if !ok {
		t.Fatalf("#19115: a new debt generation was held to the older one's 4 s backoff (not sent within 2.5 s)")
	}
	t.Logf("new debt generation sent %v after its arm", took.Round(time.Millisecond))
}

// TestOutOfSweepBulkFailureWakesTheRetry19115 (Codex P1-2): a bulk that runs
// outside the sweep and FAILS while the sweep timer is long must get the owed
// debt retried promptly. Here a pending bulk is abandoned and replaced under
// bulkSendMu (the survivor re-drive's shape, #10387) and the replacement
// fails: only that bulk's completion can tell the sweep the debt is due.
func TestOutOfSweepBulkFailureWakesTheRetry19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	p := sweepProfiles19115[1]
	ss := primarySync19115(t, ctx, p, snap.read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	if _, _, pending := ss.PendingBulkAck(); !pending {
		t.Fatal("FIXTURE: want the cold prime sent and pending")
	}
	// Put the sweep on a long timer. The connect-time arm may have lowered it
	// to the 1 s floor (if its wake was seen before the bulk published its
	// pending ack); that timer fires within 1.5 s and re-arms from state,
	// which is now the young ack's due time, so the profile's.
	fx := fx19115(ss)
	time.Sleep(1500 * time.Millisecond)
	if arms := drainArms19115(fx); len(arms) > 0 && arms[len(arms)-1] < p.active {
		t.Fatalf("FIXTURE: the sweep is still on a short timer (%v) while only a young ack is awaited", arms[len(arms)-1])
	}
	snap.failures.Store(1)
	ss.bulkSendMu.Lock()
	ss.clearPendingBulkAck()
	err := ss.doBulkSyncWithBulkSend(true)
	ss.bulkSendMu.Unlock()
	if err == nil {
		t.Fatal("FIXTURE: the replacement bulk must fail")
	}
	took, ok := waitForBulkSyncs19115(ss, 2, owedRedriveBound19115)
	if !ok {
		t.Fatalf("#19115 (Codex P1-2): a failed out-of-sweep bulk left the owed debt on the %v profile timer (not retried within %v)",
			p.active, owedRedriveBound19115)
	}
	t.Logf("debt retried %v after the out-of-sweep failure", took.Round(time.Millisecond))
}

// ── design v4 cells (#19115, Codex review of design v3) ──────────────────

// bareSync19115 is a connected-ready primary with NO sweep loop, for cells
// that drive syncSweep or a re-drive directly.
func bareSync19115(src func() (BulkSnapshot, error)) *SessionSync {
	dp := &mockSweepDP{
		v4sessions:     map[dataplane.SessionKey]dataplane.SessionValue{},
		sessionCounter: 1,
	}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return true }
	ss.BulkSnapshotSource = src
	return ss
}

// TestSweepWakesDoNotPostponeTheSweep19115: a wake only moves the loop's
// deadline EARLIER. With a 1 s profile and a wake every 100 ms, the sweep
// still runs about once a second; a loop whose wakes reset the timer would
// never run it.
func TestSweepWakesDoNotPostponeTheSweep19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := sweepProfile19115{name: "one-second", active: time.Second, idle: time.Second}
	ss := primarySync19115(t, ctx, p, (&flakySnapshot19115{}).read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	epoch, _, pending := ss.PendingBulkAck()
	if !pending {
		t.Fatal("FIXTURE: want the cold prime sent and pending")
	}
	ss.handleMessage(conn, syncMsgBulkAck, epochPayload9626(epoch))
	fx := fx19115(ss)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				ss.wakeSyncSweep()
			}
		}
	}()
	before := fx.sweeps.Load()
	time.Sleep(3500 * time.Millisecond)
	close(stop)
	<-done
	if n := fx.sweeps.Load() - before; n < 2 {
		t.Fatalf("#19115: under a wake every 100 ms a 1 s sweep ran %d time(s) in 3.5 s; the wakes postponed it", n)
	}
}

// TestForcedResyncKeepsItsCadence19115 (removed): it pinned #19115's narrowed
// scope, in which a forced resync re-armed after a failure kept its
// no-backoff cadence. #19135 holds it to the ONE retry backoff, with its
// deadline scheduled; that contract is pinned by
// TestForcedResyncWaitsForTheBackoffAndFiresAtItsDeadline19135 and
// TestHeldBackRetryIsScheduledExactlyAtItsDeadline19135
// (sync_bulk_retry_backoff_19135_test.go).

// TestIneligibleOwedRetryDoesNotFallThroughToAgedRetry19115 (Codex finding
// 1): while a debt is owed it governs every sweep retry. An owed debt inside
// its backoff must not be re-sent by the aged-ack branch on its behalf.
func TestIneligibleOwedRetryDoesNotFallThroughToAgedRetry19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	snap.failures.Store(1 << 20)
	ss := bareSync19115(snap.read)
	connectWithFailedColdPrime19115(t, ctx, ss, snap) // owed, backoff 1 s
	ss.bulkAckRetryOwed.Store(true)                   // left by an earlier aged retry
	reads := snap.calls.Load()
	for range 5 {
		ss.syncSweep()
	}
	if got := snap.calls.Load(); got != reads {
		t.Fatalf("#19115 (Codex finding 1): inside the owed debt's backoff a sweep re-sent the bulk through another branch (%d snapshot reads, want %d)", got, reads)
	}
}

// TestIpsecFenceNeedsLearnedCapabilities19115 (Codex finding 3): the IPsec
// fence is lifted only when the peer's capabilities are LEARNED and it is
// discriminator capable, the bulk window's exact conjunction. The capability
// bit alone does not make a fenced debt eligible, and a bulk is refused before
// its table-truth read.
func TestIpsecFenceNeedsLearnedCapabilities19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	snap.failures.Store(1)
	ss := bareSync19115(snap.read)
	connectWithFailedColdPrime19115(t, ctx, ss, snap)
	ss.peerIncarnationState().bulkFencedForIpsecPeer.Store(true)
	ss.peerIncarnationState().peerCapabilityFlags.Store(uint32(capFlagIpsecTunnelDiscriminator))
	if ss.peerCapabilitiesLearned() || !ss.IpsecTunnelDiscriminatorCapable() {
		t.Fatal("FIXTURE: want the discriminator bit set with the capabilities NOT learned")
	}
	ss.bulkRetryReset() // the backoff is not what keeps it ineligible
	if err := ss.bulkFenceNow(); !errors.Is(err, errBulkFencedForIpsecPeer) {
		t.Fatalf("#19115 (Codex finding 3): the IPsec fence reads %v with unlearned capabilities, want errBulkFencedForIpsecPeer", err)
	}
	if ss.owedColdPrimeRetryEligible() {
		t.Error("#19115 (Codex finding 3): a debt fenced for IPsec is eligible on the capability bit alone")
	}
	reads := snap.calls.Load()
	if err := ss.DoBulkSync(); !errors.Is(err, errBulkFencedForIpsecPeer) || snap.calls.Load() != reads {
		t.Errorf("#19115: a bulk fenced for IPsec returned %v after %d table-truth read(s), want the fence before any read",
			err, snap.calls.Load()-reads)
	}
}

// TestConnectTimeBulkSkipsWhenTheSweepAlreadyPrimed19115 (Codex finding 4 on
// design v3, the reverse ordering): installConn decides the connect-time cold
// prime, then the connection setup writes run. If they are slow, the sweep's
// owed re-drive sends the qualifying bulk first. The connect path must then
// recheck its own obligation under bulkSendMu and NOT send a second snapshot.
// The connect path is held just before its admission
// (testBeforeConnectColdPrime) while the sweep's re-drive runs to completion.
func TestConnectTimeBulkSkipsWhenTheSweepAlreadyPrimed19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	ss := bareSync19115(snap.read)
	held := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ss.testBeforeConnectColdPrime = func() {
		once.Do(func() {
			close(held)
			<-release
		})
	}
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	connected := make(chan struct{})
	go func() {
		defer close(connected)
		ss.handleNewConnection(ctx, 0, conn, true)
	}()
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("FIXTURE: the connect path never reached its cold prime")
	}
	if !ss.owedColdPrimeRetryEligible() {
		close(release)
		t.Fatal("FIXTURE: the connect-armed debt is not eligible for the sweep's re-drive")
	}
	if ss.bulkRedriveInFlight.CompareAndSwap(false, true) {
		ss.redriveOwedColdPrime()
	}
	if got := snap.calls.Load(); got != 1 {
		close(release)
		t.Fatalf("FIXTURE: the sweep's re-drive did not send the cold prime (%d reads)", got)
	}
	close(release)
	<-connected
	if got := snap.calls.Load(); got != 1 {
		t.Fatalf("#19115 (Codex finding 4): the connect-time cold prime sent a second snapshot after the sweep had primed the same debt (%d reads, want 1)", got)
	}
	if got := ss.stats.BulkSyncs.Load(); got != 1 {
		t.Errorf("#19115: want exactly one completed bulk, got %d", got)
	}
}

// TestRetryWaitingBehindAFailedBulkSeesItsOutcome19115 (Codex finding 12 on
// design v3): a retry that waits for bulkSendMu behind a FAILED bulk must see
// that failure's advanced deadline when it is admitted. The outcome is held
// at the start of noteBulkResult; the bulk's admission lock must still be held
// there, so the waiting retry cannot read the old deadline and export again.
func TestRetryWaitingBehindAFailedBulkSeesItsOutcome19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	snap.failures.Store(1)
	ss := bareSync19115(snap.read)
	atResult := make(chan struct{})
	releaseResult := make(chan struct{})
	var once sync.Once
	ss.testBeforeBulkResult = func(err error) {
		if err != nil {
			once.Do(func() {
				close(atResult)
				<-releaseResult
			})
		}
	}
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	connected := make(chan struct{})
	go func() {
		defer close(connected)
		ss.handleNewConnection(ctx, 0, conn, true)
	}()
	select {
	case <-atResult:
	case <-time.After(5 * time.Second):
		close(releaseResult)
		t.Fatal("FIXTURE: the connect-time cold prime never reached its result")
	}
	retried := make(chan struct{})
	go func() {
		defer close(retried)
		if ss.bulkRedriveInFlight.CompareAndSwap(false, true) {
			ss.redriveOwedColdPrime()
		}
	}()
	time.Sleep(200 * time.Millisecond)
	whileHeld := snap.calls.Load()
	close(releaseResult)
	<-retried
	<-connected
	if whileHeld != 1 || snap.calls.Load() != 1 {
		t.Fatalf("#19115 (Codex finding 12): a retry admitted behind a failed bulk exported again before the failure's backoff was published (%d reads while the outcome was held, %d after; want 1 and 1)",
			whileHeld, snap.calls.Load())
	}
}

// TestSkippedRetriesReleaseTheRedriveGuard19115 (Codex finding 4): a re-drive
// that its own recheck skips releases bulkRedriveInFlight, or every later
// re-drive, survivor and aged-ack included, is locked out.
func TestSkippedRetriesReleaseTheRedriveGuard19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	snap.failures.Store(1 << 20)
	ss := bareSync19115(snap.read)
	connectWithFailedColdPrime19115(t, ctx, ss, snap) // owed, inside its backoff
	ss.bulkRedriveInFlight.Store(true)
	ss.redriveOwedColdPrime()
	if ss.bulkRedriveInFlight.Load() {
		t.Error("#19115: an owed re-drive skipped by its recheck kept bulkRedriveInFlight")
	}
	ss.bulkRedriveInFlight.Store(true)
	ss.redriveAgedBulk() // a debt is owed: not this branch's obligation
	if ss.bulkRedriveInFlight.Load() {
		t.Error("#19115: an aged-ack re-drive skipped by its recheck kept bulkRedriveInFlight")
	}
	if got := snap.calls.Load(); got != 1 {
		t.Errorf("#19115: a skipped re-drive read the snapshot (%d reads, want 1)", got)
	}
}

// TestArmDuringTheSnapshotReadIsPaidByThatBulk19115 (Codex finding 15): an
// arm that lands while the table-truth snapshot is being read, BEFORE the
// window captures its generation, is paid by that same bulk: it carries the
// new generation, and no second bulk is sent for it.
func TestArmDuringTheSnapshotReadIsPaidByThatBulk19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	ss := primarySync19115(t, ctx, sweepProfiles19115[1], func() (BulkSnapshot, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return BulkSnapshot{}, nil
	})
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	connected := make(chan struct{})
	go func() {
		defer close(connected)
		ss.handleNewConnection(ctx, 0, conn, true)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("FIXTURE: the connect-time cold prime never reached its snapshot read")
	}
	ss.mu.Lock()
	ss.armColdPrimeLocked()
	gen := ss.coldPrimeGen.Load()
	ss.mu.Unlock()
	close(release)
	<-connected
	if got := ss.pendingBulkOwed.Load(); got != gen {
		t.Fatalf("#9626: a bulk whose generation capture followed the arm carries %d, want the new generation %d", got, gen)
	}
	time.Sleep(1500 * time.Millisecond)
	if got := ss.stats.BulkSyncs.Load(); got != 1 {
		t.Errorf("#19115: the arm already paid by the in-flight bulk was sent again (%d bulks, want 1)", got)
	}
}

// TestFencedStreamRefusesAPendingBulkPromptly19115 (Codex finding 16): a
// qualifying pending bulk ends the cold-prime refusal, but it does not by
// itself admit the drain. After an ordered-stream move the barrier fence stays
// armed until that bulk's ack discharges it, and the barrier is refused at once
// (no 60 s wait). That is the intended safe refusal; #19115 promises the
// first, not the second.
func TestFencedStreamRefusesAPendingBulkPromptly19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ss := bareSync19115((&flakySnapshot19115{}).read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	if ss.ColdPrimeOwedWithoutPendingBulk() {
		t.Fatal("FIXTURE: want the debt covered by a qualifying pending bulk")
	}
	ss.fence.epoch.Store(ss.fence.cleared.Load() + 1)
	ss.fence.pendingBulk.Store(ss.fence.epoch.Load() + 1) // that bulk will discharge it
	if !ss.barrierFenced() || !ss.fenceDischargeAwaited() {
		t.Fatal("FIXTURE: want the barrier fenced, awaiting the pending bulk's ack")
	}
	start := time.Now()
	err := ss.WaitForPeerBarrierAfterColdPrimeGate(60 * time.Second)
	if err == nil || !strings.Contains(err.Error(), "barrier fenced") {
		t.Fatalf("#19115 (Codex finding 16): a fenced stream with a pending bulk returned %v, want the barrier-fence refusal", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("#19115 (Codex finding 16): the fence refusal took %v, want it at once", took)
	}
}

// TestDaemonPrimeSkipsWhileABulkIsPending19115 (Codex finding 4): the
// daemon's bulk-prime retry rechecks its own obligation under bulkSendMu: a
// bulk sent since it decided to retry, still young, makes it a no-op.
func TestDaemonPrimeSkipsWhileABulkIsPending19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ss := bareSync19115((&flakySnapshot19115{}).read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	if sent, err := ss.DoPrimeBulkSync(); sent || err != nil {
		t.Fatalf("#19115: the daemon prime sent=%v err=%v with a young bulk pending, want a skip", sent, err)
	}
	if got := ss.stats.BulkSyncs.Load(); got != 1 {
		t.Fatalf("#19115: want one bulk, got %d", got)
	}
	ss.pendingBulkAckSince.Store(ss.nowMono() - int64(BulkAckPendingRetryAfter) - int64(time.Second))
	if sent, err := ss.DoPrimeBulkSync(); !sent || err != nil {
		t.Fatalf("#19115: the daemon prime sent=%v err=%v once the pending bulk aged out, want a send", sent, err)
	}
}

// TestBarrierReprimeRechecksItsObligation19115 (Codex finding 4): the barrier
// fence re-prime rechecks its own obligation under bulkSendMu. If a bulk
// admitted ahead of it captured the fence epoch and is now awaiting the ack
// that discharges the fence, the re-prime sends nothing.
func TestBarrierReprimeRechecksItsObligation19115(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	snap := &flakySnapshot19115{}
	ss := bareSync19115(snap.read)
	conn := newBulkCaptureConn()
	t.Cleanup(func() { conn.Close() })
	ss.handleNewConnection(ctx, 0, conn, true)
	ss.fence.epoch.Store(ss.fence.cleared.Load() + 1)
	ss.fence.pendingBulk.Store(0)
	if !ss.barrierFenced() || ss.fenceDischargeAwaited() {
		t.Fatal("FIXTURE: want the barrier fenced with no discharge-capable bulk pending")
	}
	reads := snap.calls.Load()
	ss.bulkSendMu.Lock() // another bulk holds admission
	ss.scheduleBarrierFenceReprime("19115-cell")
	time.Sleep(100 * time.Millisecond)
	ss.fence.pendingBulk.Store(ss.fence.epoch.Load() + 1)
	ss.pendingBulkAckSince.Store(ss.nowMono())
	ss.bulkSendMu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for ss.fence.reprimeInFlight.Load() {
		if time.Now().After(deadline) {
			t.Fatal("FIXTURE: the re-prime never finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := snap.calls.Load(); got != reads {
		t.Fatalf("#19115 (Codex finding 4): the barrier re-prime exported (%d reads, want %d) although the bulk admitted ahead of it already awaits the fence-discharging ack",
			got, reads)
	}
}
