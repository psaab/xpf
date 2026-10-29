package cluster

import (
	"errors"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// #7257 — StartHeartbeat published m.hbSender/m.hbReceiver under m.mu, RELEASED
// the lock, and then dereferenced the fields it had just written:
//
//	m.mu.Unlock()
//	m.hbReceiver.start()   // unlocked read
//	m.hbSender.start()     // unlocked read
//
// while StopHeartbeat nils both under the lock. Two outcomes, both live:
//
//  1. nil-deref panic, if the stop lands in that gap;
//  2. a sender/receiver pair started AFTER a stop already captured and nilled
//     the handles — running with nothing able to stop it, on a torn-down
//     cluster. That one is worse than the panic: it is silent.
//
// Reachable because the daemon's startHeartbeatWithRetryForEpoch runs on a bare
// `go` goroutine outside the current epoch's constructor and fabric-populate
// join groups, so stopClusterComms does not join it; it only cancels the
// context and calls StopHeartbeat.
//
// CI has no path to it: make test-go's race gate (test-race-dp) runs -race
// under a fixed -run filter and nothing in that set drives startClusterComms
// with a control-link endpoint, so the heartbeat path is never raced.

// TestStartHeartbeatDoesNotRaceStopHeartbeat7257 is the race probe.
//
// WARNING (#7663): this probe currently observes NOTHING, and the change below
// does not fix that — it only stops the degeneracy floor firing spuriously
// under load (#7650). Measured at de6b8c85d on an idle machine, with the #7257
// production fix reverted, `-race` reports ZERO data races, both with and
// without the #7650 change. That contract was false as written; it is now
// stated below as the measured RATE it actually is, with its run counts.
//
// The cause is structural, not timing: StartHeartbeat re-checks its entry epoch
// before publishing, StopHeartbeat bumps that epoch, and this probe runs an
// UNBOUNDED teardown loop. Instrumenting the epoch check gives
// `publish-window entered=0 superseded=60` against 39300 stops — every start is
// superseded long before it reaches the derefs that carry the race. The
// `stops >= starts` floor below is satisfied by exactly the condition that
// guarantees the vacuity, so it cannot detect it.
//
// #7663 carries the fix (pace the teardown; assert the publish window was
// entered). Do not read a green here as evidence the #7257 regression is
// guarded.
//
// The BOUNDED side is the expensive one. StartHeartbeat creates two UDP
// sockets; StopHeartbeat is nearly free. A first draft bounded the stops and
// looped the starts "until done", and the logged rate gave it away immediately:
// 1 start against 200 stops — the cheap loop ran to completion inside the
// expensive loop's first pass, so the window was raced approximately once.
// Bounding the starts and looping the stops until they signal done is what
// makes every start contend.
//
// The count is logged rather than assumed, so a future change that makes
// StartHeartbeat slower turns a degenerate probe into a visible one instead of
// a quiet pass.
//
// The assertion is the race detector, so this is only meaningful under -race.
//
// RED ON REVERT (#7663) — a measured RATE, deliberately not stated as a
// contract. The exact revert, in StartHeartbeat — written as before/after
// rather than as a unified diff, because gofmt reformats a leading `-`/`+`
// inside an indented comment into a godoc list and rewrites `+` to `-`, which
// would silently turn the additions below into deletions and make this
// instruction wrong:
//
//	BEFORE (fixed, as shipped):     AFTER (reverted, reproduces the race):
//	    receiver.start()                m.mu.Unlock()
//	    sender.start()                  m.hbReceiver.start()
//	    m.mu.Unlock()                   m.hbSender.start()
//
// Both halves matter: the start() calls move AFTER the Unlock, AND they read
// the FIELDS rather than the locals. That unlocked read of fields StopHeartbeat
// nils under the lock is #7257's actual defect. Disarming the `m.hbEpoch !=
// startEpoch` supersede guard instead does NOT reproduce it — that leaves the
// publish and both start() calls inside the critical section, so there is no
// unsynchronised access for the detector to find. (Recorded because a reviewer
// read "restore the unlocked pair" that way, reasonably, and measured 0 races.)
//
// With that revert applied, `go test -race -run
// TestStartHeartbeatDoesNotRaceStopHeartbeat7257 ./pkg/cluster/` reported
// WARNING: DATA RACE naming StartHeartbeat and StopHeartbeat in:
//
//	12 of 12 runs at startAttempts = 240   (this file)
//	10 of 12 runs at startAttempts = 60    (the previous value)
//
// It is a rate and not a guarantee, and 12/12 does not upgrade it to one — the
// misses are governed by REACH, and a run whose contention happens to collapse
// reach (one miss logged `4 published / 56 superseded`) has fewer chances to
// catch it. Before #7663 the rate was 0 of N: the probe could not distinguish a
// fixed tree from a reverted one at all.
// waitForTeardownProgress blocks until the teardown goroutine has completed at
// least one stop, so the start loop is issued into a window that is provably
// being contended (#7650).
//
// Only ONE edge, and only before the contended region. A per-start handshake
// would be deterministic but would also establish happens-before between each
// teardown and the start it races, which is exactly what the race detector
// looks for the absence of — the probe would go quiet against the very bug it
// exists to catch.
// teardownProgressBudget bounds the wait for the teardown goroutine's first
// stop. It is deliberately generous, and 5s was not.
//
// #7679: at 5s this test made master RED under `go test ./...` — twice. The
// bound is not a timing assertion about the heartbeat code; its only job is to
// turn "the goroutine was never scheduled at all" into a named failure instead
// of a silent degenerate probe or a hang. Under `./...` the runner starts many
// package binaries concurrently, each with GOMAXPROCS equal to the core count,
// so the machine is heavily oversubscribed and a cheap goroutine can wait a
// long time for a P.
//
// #7970 CORRECTION. The sentence that stood here — "raising it costs nothing…
// a goroutine that is genuinely never scheduled stays unscheduled for 30s just
// as surely as for 5s" — is FALSE, and it was the sentence that would have sent
// the next person to raise the bound a third time. The test then red at exactly
// 30.00s under `go test ./...`, so the goroutine was not "genuinely never
// scheduled": the bound was a wall-clock sample after all, just a later one.
//
// The cause was not the machine. It was THIS TEST. The teardown loop used to
// spin with no pacing, burning ~73k stop iterations per run; under `./...` the
// runner already oversubscribes every core, so the probe was both the
// contributor to and the victim of the contention it then waited 30s on. It
// starved itself. #7663's vacuity and #7970's flake were one knob seen from two
// ends, and pacing the loop (see the teardown goroutine) removed both.
//
// The bound is kept at 30s and is NOT a timing assertion: its only job is to
// turn a hang into a named failure. It is deliberately left generous rather than
// lowered to match the now-much-lower contention, because lowering it would be a
// fresh unmeasured claim about scheduling latency — the exact kind of claim this
// comment previously got wrong.
// startCostMicros is the measured cost of one `StartHeartbeat` on this path,
// in microseconds, and it is what the teardown pacing is scaled against.
//
// Measured rather than guessed (#7663): 60 uncontended starts averaged 60.95us
// each (two socket binds dominate) against 226ns for a stop — a ratio of ~270.
// That ratio IS the vacuity: an unpaced teardown loop lands ~270 stops inside
// every start's entry-to-epoch-recheck window, so every start is superseded.
//
// It does not need to be exact. It sets the ORDER OF MAGNITUDE of the gap the
// teardown leaves, and the randomisation spans it; being wrong by 2x changes
// how often starts publish, not whether they can.
const startCostMicros = 61

// measureStartCost is what actually paces the teardown loop, and it exists
// because `startCostMicros` above is calibrated on an IDLE box (#8207/#8345).
//
// The const's own comment reasons that "being wrong by 2x changes how often
// starts publish, not whether they can". That is true at 2x and false at the
// factor a full `go test ./...` run produces. Under oversubscription a start
// costs far more than 61us — two socket binds while several times the core
// count of goroutines compete — while the teardown's sleep stays pinned to
// 61us, so the stop:start ratio climbs back toward the unpaced regime and every
// start is superseded again. That is exactly the failure both issues report:
// `240 of 240 starts were SUPERSEDED before publishing`, on a machine where the
// probe passes 8/8 in isolation.
//
// Raising the const would be widening a margin against an unbounded quantity.
// Measuring it removes the assumption instead: if the box is 10x slower, the
// observed cost is 10x larger, the gap the teardown leaves grows with it, and
// the publish rate is preserved. The probe becomes scale-invariant rather than
// calibrated.
//
// The calibration is UNCONTENDED on purpose — it runs before the two goroutines
// start — so it measures the cost of a start on this machine right now, which
// is the quantity the pacing needs. It is not a happens-before edge with
// anything in the contended phase and cannot order the race the probe detects.
func measureStartCost(t *testing.T, samples int) time.Duration {
	t.Helper()
	m := NewManager(0, 1)
	// One warm-up pair, discarded: the first bind on this path pays lazy
	// runtime initialisation that no later start repeats, and folding it into
	// the mean biases the pacing high — the safe direction for publishing, but
	// it would make the measurement a claim about startup rather than about
	// steady-state cost.
	_ = m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0")
	m.StopHeartbeat()

	start := time.Now()
	for i := 0; i < samples; i++ {
		if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
			t.Fatalf("calibration start %d failed: %v — the pacing below cannot "+
				"be derived and the probe would silently fall back to an "+
				"idle-box constant", i, err)
		}
		m.StopHeartbeat()
	}
	per := time.Since(start) / time.Duration(samples)

	// Floor at the idle-box constant. The calibration can only ever report a
	// cost this low on a machine at least as fast as the one the const was
	// measured on, and a pacing gap SHORTER than the const is the regime that
	// produced the original vacuity. There is no corresponding ceiling: a large
	// observed cost is the signal this function exists to carry.
	if floor := startCostMicros * time.Microsecond; per < floor {
		per = floor
	}
	return per
}

// heartbeatProbeAttempts bounds how many times the race probe is re-run when it
// comes back degenerate.
//
// Calibration measures the load at calibration time, and a full-suite run's
// load is not stationary — another package's test can start between the
// calibration and the contended phase. A retry costs one more attempt; the
// alternative is a red gate whose named cause is a timing artifact, which
// trains re-running a red reflexively until it goes green (#8345). That habit
// is the actual cost, because a genuine intermittent regression here would be
// waved through by the same reflex.
//
// It does NOT hide a structural degeneracy: a probe that cannot reach its
// window by construction reaches it zero times on every attempt, and the test
// still fails with the same message. The retry only distinguishes "this machine
// was busy" from "this probe is broken", which is the distinction the single
// attempt could not make.
const heartbeatProbeAttempts = 3

const teardownProgressBudget = 30 * time.Second

func waitForTeardownProgress(t *testing.T, stops *atomic.Int64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for stops.Load() == 0 {
		if time.Now().After(deadline) {
			// #7970: DUMP, do not diagnose. The message this replaced asserted
			// "it was never scheduled" as fact — a conclusion this wait cannot
			// support and, measured, one of at least two possibilities:
			//
			//   - the goroutine is RUNNABLE but has not been given a P (genuine
			//     starvation under `./...` oversubscription), or
			//   - it is BLOCKED inside StopHeartbeat — which now tears down real
			//     senders/receivers, since #7663's pacing means starts actually
			//     publish, and both stop() paths join goroutines via wg.Wait().
			//
			// The deadline cannot tell those apart and neither can "still
			// running"; the stack can, immediately. Anyone who hits this should
			// read the dump rather than re-run, because the two have completely
			// different fixes and only one of them is about the machine.
			// ALL goroutines (the `true`), and GROWN until the dump fits.
			// runtime.Stack truncates silently when the buffer is short — it
			// just returns fewer bytes — so a fixed size would produce a dump
			// that looks complete and has lost exactly the goroutine the
			// blocked one is waiting on. Under a full `./...` run there are
			// many. Growing until n < len(buf) is the standard idiom and the
			// only way to know the dump is whole.
			buf := make([]byte, 1<<20)
			var n int
			for {
				n = runtime.Stack(buf, true)
				if n < len(buf) {
					break
				}
				buf = make([]byte, 2*len(buf))
			}
			t.Fatalf("the teardown goroutine completed no stops in %s. This is a "+
				"HANG, not a slow machine, and the goroutine dump below says which "+
				"kind: look for the goroutine in StopHeartbeat. If it is blocked in "+
				"wg.Wait() the defect is a stop that cannot complete; if it is "+
				"absent or runnable the defect is scheduling starvation under "+
				"`go test ./...` (#7970/#7650).\n\n=== goroutine dump ===\n%s",
				within, buf[:n])
		}
		time.Sleep(time.Millisecond)
	}
}

// heartbeatProbeResult reports what one attempt of the race probe reached.
type heartbeatProbeResult struct {
	published, superseded, starts, stops int64
	pacing                               time.Duration
}

// TestStartHeartbeatDoesNotRaceStopHeartbeat7257 is the race probe. The
// contended run lives in runHeartbeatRaceProbe7257; this wrapper only decides
// what a degenerate attempt MEANS (see heartbeatProbeAttempts).
func TestStartHeartbeatDoesNotRaceStopHeartbeat7257(t *testing.T) {
	var attempts []heartbeatProbeResult
	for i := 0; i < heartbeatProbeAttempts; i++ {
		res := runHeartbeatRaceProbe7257(t)
		attempts = append(attempts, res)
		if res.published > 0 {
			t.Logf("#7257 race probe (attempt %d/%d, pacing %v): %d published / "+
				"%d superseded of %d starts, %d stops",
				i+1, heartbeatProbeAttempts, res.pacing, res.published,
				res.superseded, res.starts, res.stops)
			return
		}
		t.Logf("#7257 race probe attempt %d/%d was DEGENERATE (pacing %v): "+
			"0 published, %d superseded, %d stops — retrying",
			i+1, heartbeatProbeAttempts, res.pacing, res.superseded, res.stops)
	}
	// #7663: the precondition is REACH, not stop volume. Every attempt failed
	// to reach it, so this is not a busy machine — see heartbeatProbeAttempts.
	t.Fatalf("#7257 probe is degenerate on all %d attempts: no start ever "+
		"reached the publish window. `StartHeartbeat` returns nil only after it "+
		"publishes m.hbSender/m.hbReceiver, so zero published starts means the "+
		"race this probe exists to detect was never executed — a green here "+
		"would be vacuous, not evidence (#7663). Per-attempt: %+v",
		heartbeatProbeAttempts, attempts)
}

func runHeartbeatRaceProbe7257(t *testing.T) heartbeatProbeResult {
	t.Helper()
	m := NewManager(0, 1)

	// #8207/#8345: paced against the cost measured on THIS machine under THIS
	// load, not against the idle-box constant. See measureStartCost.
	startCost := measureStartCost(t, 20)

	const startAttempts = 240
	var stops, starts, published, superseded atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// BOUNDED, expensive side: a fixed number of starts.
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < startAttempts; i++ {
			// Loopback both ways: the bind succeeds without a cluster peer.
			//
			// #7663: the two outcomes are counted SEPARATELY, because they are
			// not equivalent for this probe. `StartHeartbeat` returns nil only
			// after it has published `m.hbSender`/`m.hbReceiver` — the single
			// `return nil` sits below the publish — so `published` is an exact,
			// production-instrumentation-free measure of how many starts
			// reached the window the race lives in. A superseded start returned
			// before the publish and carries no race to detect. Lumping them
			// into one counter is what let this probe report 60 healthy starts
			// while reaching the publish ZERO times.
			err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0")
			switch {
			case err == nil:
				published.Add(1)
				starts.Add(1)
			case errors.Is(err, ErrHeartbeatStartSuperseded):
				superseded.Add(1)
				starts.Add(1)
			}
		}
	}()
	// UNBOUNDED, cheap side: keep tearing down until the starts are finished,
	// so each start is contended rather than running alone.
	go func() {
		defer wg.Done()
		for {
			m.StopHeartbeat()
			stops.Add(1)
			// #7663/#7970: yield a gap on the order of a START's own duration.
			//
			// A tight spin here is what made this probe vacuous AND flaky. A
			// stop costs ~226ns and a start ~61us (measured), so an unpaced
			// loop lands ~270 stops inside every start's entry-to-epoch-recheck
			// window and supersedes all of them: 0 of 60 starts ever reached the
			// publish. The same spin burned ~73k iterations per run, which under
			// `go test ./...` oversubscription is what left this test's own
			// teardown goroutine waiting on a P for 30s (#7970).
			//
			// Randomised, and NOT a fixed interval: a fixed gap phase-locks
			// against the start loop and samples one alignment. Randomising
			// samples the whole window, including gaps short enough to land
			// inside a post-publish deref.
			//
			// This is still UNORDERED with respect to any particular start —
			// no channel, no handshake, no happens-before edge — so the race
			// detector still sees unsynchronised accesses. That is the property;
			// pacing changes only how often the probe reaches it.
			time.Sleep(time.Duration(rand.Int63n(int64(2 * startCost))))
			// #7970 RETRO-EXPLANATION. This mechanism accounts for every
			// symptom the flake showed, which is how you tell it is THE cause
			// rather than a cause:
			//
			//   - it red at exactly 30.00s, never a jittery value, because the
			//     awaited event was IMPOSSIBLE rather than late — the full
			//     budget was paid every time;
			//   - #7679 raising the bound 5s -> 30s did not help and could not
			//     have: a larger bound only buys a longer wait for an event
			//     that will never arrive;
			//   - it passed in 0.010s in isolation, because on an idle box this
			//     goroutine wins the first-schedule race trivially;
			//   - it SURVIVED the #7663 pacing fix, because pacing changes how
			//     often starts reach the publish window and touches the
			//     first-schedule race not at all. (That is also why linking the
			//     two issues as one defect was wrong.)
			//
			// #7970: the `done` check is at the END, so this goroutine always
			// completes AT LEAST ONE stop before it can exit.
			//
			// It used to be at the TOP, and that is the whole of #7970. `done`
			// is closed by the start goroutine's `defer` once its 60 starts are
			// finished — about 3.7ms of work. If this goroutine lost the
			// first-schedule race by that much (routine under `go test ./...`
			// oversubscription) it observed `done` already closed on its very
			// first iteration and returned having done NOTHING. waitForTeardown-
			// Progress then waited the full 30s for a stop that could never
			// arrive, because the only thing that produces stops had exited.
			//
			// So the red was never starvation and never a slow machine: it was a
			// wait on an IMPOSSIBLE event, and the bound only set how long the
			// suite paid to discover that. Raising it could not have helped —
			// which is why raising it 5s -> 30s (#7679) did not.
			//
			// Verified by construction: with a 50ms sleep inserted before the old
			// top-of-loop check, the failure reproduced deterministically at
			// exactly 30.00s with zero stops. Confirmed against the captured
			// goroutine dump from a real `./...` red, in which NEITHER probe
			// goroutine appears — both had already exited, so nothing was blocked
			// and nothing was runnable-but-starved.
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	// #7650: wait until the teardown side is provably RUNNING before the
	// starts begin.
	//
	// The degeneracy floor below is `stops >= starts`, and it fired on a loaded
	// machine with 0 stops against 60 starts — not because the window was
	// uncontended by design, but because the cheap goroutine had not been
	// scheduled at all while the expensive one ran to completion. The floor was
	// reading the machine.
	//
	// This wait is deliberately placed BEFORE the start loop and creates a
	// happens-before edge only with stops that precede every start. It must not
	// become a per-start handshake: an edge between a stop and the start it
	// contends would ORDER the unlocked publish against the teardown's read and
	// suppress the very data race this probe exists to detect. The teardown
	// goroutine keeps running freely for the whole start loop, so each start
	// still overlaps unordered teardowns.
	waitForTeardownProgress(t, &stops, teardownProgressBudget)
	wg.Wait()
	m.StopHeartbeat()

	if got := starts.Load(); got < startAttempts {
		t.Fatalf("only %d of %d starts completed — the probe under-exercised its window", got, startAttempts)
	}
	// #7663: the precondition is REACH, not stop volume.
	//
	// This replaces a `stops >= starts` floor that was not merely unhelpful, it
	// enforced the vacuity: satisfying it required the teardown side to out-run
	// the start side, which is precisely the condition under which every start
	// is superseded before publishing. Measured both ways on this file —
	//
	//	spin teardown  : published 0/60,  1223 stops/start, floor PASSES
	//	paced teardown : published 59/60, 0.08 stops/start, floor FAILS
	//
	// — so the old floor and the property were in strict opposition, and the
	// floor won every time. A probe that cannot reach the window it probes is
	// degenerate no matter how contended it is.
	// The degeneracy verdict is the CALLER's, because a single degenerate
	// attempt no longer means the probe is broken — see heartbeatProbeAttempts.
	return heartbeatProbeResult{
		published:  published.Load(),
		superseded: superseded.Load(),
		starts:     starts.Load(),
		stops:      stops.Load(),
		pacing:     startCost,
	}
}

// TestStartHeartbeatSupersededByStopDoesNotPublish7257 is the deterministic
// half. The race detector is probabilistic and only runs under -race, so the
// start-after-stop outcome needs an assertion that depends on neither.
//
// A start that a teardown overtook must not install a heartbeat. Before #7257
// it did: StopHeartbeat captured and nilled the handles, the in-flight start
// then wrote its own pair into the freshly-nilled fields and spawned their
// goroutines, and nothing held a handle to stop them. Silent, and on a cluster
// that has been torn down.
//
// The teardown is landed through hbStartInWindowHook rather than with a sleep.
// The first version of this test slept 2 ms and hoped the stop would land
// during socket creation; it did not, and the test PASSED against a build with
// the epoch guard removed — vacuous by exactly the margin the sleep was wrong
// by. The hook fires inside the guarded window by construction, so there is no
// timing to get right.
//
// RED on revert: drop the `m.hbEpoch != startEpoch` check from StartHeartbeat's
// publish critical section and both assertions fire.
func TestStartHeartbeatSupersededByStopDoesNotPublish7257(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.StopHeartbeat)

	var fired atomic.Int64
	m.mu.Lock()
	m.hbStartInWindowHook = func() {
		// Only the first start is superseded; a hook that fired forever would
		// make the negative control below unreachable.
		if fired.Add(1) == 1 {
			m.StopHeartbeat()
		}
	}
	m.mu.Unlock()

	err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0")
	if fired.Load() == 0 {
		t.Fatal("setup: the in-window hook never fired, so no teardown was landed in the window")
	}
	if !errors.Is(err, ErrHeartbeatStartSuperseded) {
		t.Fatalf("#7257: StartHeartbeat = %v, want ErrHeartbeatStartSuperseded — a start the "+
			"teardown overtook must decline to publish", err)
	}
	if m.HeartbeatRunning() {
		t.Fatal("#7257: a heartbeat is running after the teardown that superseded its start — " +
			"the pair was published into the nilled fields and nothing holds a handle to stop it")
	}
}

// TestStartHeartbeatStillPublishesWithoutAContendingStop7257 is the negative
// control. The epoch guard must refuse ONLY a superseded start; an ordinary one
// must still install a heartbeat, or the fix would be a heartbeat that never
// starts — which no other test in this package would catch, because they all
// call StartHeartbeat and check its error rather than the resulting state.
func TestStartHeartbeatStillPublishesWithoutAContendingStop7257(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.StopHeartbeat)

	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("StartHeartbeat() = %v, want nil with no contending teardown", err)
	}
	if !m.HeartbeatRunning() {
		t.Fatal("an uncontended StartHeartbeat must leave a heartbeat running")
	}
}

// TestRestartHeartbeatSurvivesTheEpochGuard7257 pins the trap the epoch capture
// had to be placed around. StartHeartbeat performs its OWN idempotent teardown
// (#4033) before creating sockets, and that teardown bumps the tenure too.
// Capturing the tenure at function ENTRY would compare against a value the call
// had itself invalidated, so every start — including every restart — would
// refuse to publish and the heartbeat would silently never come up.
//
// RestartHeartbeat is the caller that makes this concrete: it stops, then
// starts, in one call.
//
// RED on revert: move the `startEpoch` capture above the internal
// `m.StopHeartbeat()` and this fails on the running assertion.
func TestRestartHeartbeatSurvivesTheEpochGuard7257(t *testing.T) {
	m := NewManager(0, 1)
	t.Cleanup(m.StopHeartbeat)

	if err := m.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("setup StartHeartbeat: %v", err)
	}
	if !m.RestartHeartbeat() {
		t.Fatal("RestartHeartbeat reported nothing running after a successful start")
	}
	if !m.HeartbeatRunning() {
		t.Fatal("#7257: the heartbeat is not running after a restart — the epoch guard " +
			"refused a start that its own idempotent teardown superseded")
	}
}
