package userspace

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// #18685: decide that the helper is wedged on TIME, measured across every
// control round trip, not on a count of status polls.
//
// The #9651 detector counted 30 consecutive unanswered STATUS polls and assumed
// they arrive once a second. They do not when it matters. Every control round
// trip serialises on controlReqMu with at least a 3 s deadline, and when the
// helper stops answering, each queued caller (HA sync, NAT-lease export,
// neighbour regeneration, ...) burns its full deadline before the status poll
// gets a turn. On loss (#18658) polls then landed about every 90 s: 26 failures
// in 37 minutes and no kill, with transit dead and the node still primary.
//
// So the evidence is taken at the single round-trip site
// (requestDetailedAtSocket), for EVERY verb:
//   - an answer (a decoded reply or an in-band refusal) clears the silence;
//   - an undecodable reply (#18293: the helper wrote bytes) neither advances
//     nor clears it;
//   - anything else (a deadline, an EOF with no bytes, a full backlog, a
//     reset) is SILENCE, the same conservative rule #9651 used. The silence
//     starts at the START of the first such round trip after the last answer,
//     because the helper has answered nothing since then.
//
// Two verdicts come out of it, and neither needs m.mu or controlReqMu:
//   - wedge SUSPECTED (cheap, reversible): two silent round trips spanning at
//     least helperWedgeDemoteSpan, or a worker whose heartbeat has not moved
//     for helperWorkerFrozenAfter. The daemon turns it into election debt so a
//     healthy peer takes the data RGs (see HelperWedgeSuspected).
//   - kill DUE (irreversible): two silent round trips spanning at least
//     helperWedgeMinSpan (30 s), outside the RG-activation grace. A per-
//     generation watchdog goroutine checks it every second and SIGKILLs the
//     generation's own process handle, so a caller blocked in a round trip
//     while holding m.mu cannot delay the kill. The #5838 supervisor reaps
//     and restarts it.
//
// Bounds, from the measured healthy population (#18658 cells, 2026-11-01): the
// helper status round trip stayed under 31 ms on udp and tcp through 16k-
// session bursts, including during the #18655 convoy, on every build measured.
// A silent round trip needs > 3 s (the base deadline), so two of them spanning
// 5 s are more than two orders of magnitude outside healthy behaviour. Worker
// heartbeats are published about once a second; in the #18655 convoy the oldest
// reached 16-22 s while transit was dead and the control thread still answered
// in 2 ms, which is exactly the state that must demote.
const (
	// helperWedgeDemoteSpan is the minimum silence span that raises the
	// suspected verdict (with at least helperWedgeMinSilentTrips).
	helperWedgeDemoteSpan = 5 * time.Second
	// helperWedgeMinSilentTrips is how many silent round trips either verdict
	// needs. One timeout alone is not a wedge.
	helperWedgeMinSilentTrips = 2
	// helperWorkerFrozenAfter is how long a worker heartbeat may stay unchanged
	// across answered polls before the worker counts as frozen.
	helperWorkerFrozenAfter = 10 * time.Second
	// helperWedgeClearAfter is how long the helper must look healthy (answering,
	// no frozen worker) before a suspected verdict clears, and helperWedgeClear
	// Trips how many answers that span must contain. Without it a helper that
	// answers every other round trip would flap the RGs.
	helperWedgeClearAfter = 5 * time.Second
	helperWedgeClearTrips = 3
	// helperWorkerFrozenKillAfter is how long a worker may stay frozen, with
	// the control thread still answering, before the helper is killed. A
	// frozen worker alone first only DEMOTES (reversible): the #18655 busy
	// convoy froze heartbeats for 16-22 s and then cleared by itself, and a
	// kill throws away every session. Two minutes is several times the longest
	// convoy measured; a worker frozen that long is not coming back.
	helperWorkerFrozenKillAfter = 2 * time.Minute
	// helperWatchdogTick is the watchdog goroutine's cadence.
	helperWatchdogTick = time.Second
)

// helperLivenessTracker holds the round-trip and heartbeat evidence for ONE
// helper generation. Its mutex is a leaf: nothing else is locked under it.
type helperLivenessTracker struct {
	mu  sync.Mutex
	gen uint64

	lastAnswer     time.Time
	silentSince    time.Time
	silentTrips    int
	lastRGActivate time.Time

	// heartbeat freeze, from answered statuses. Freeze is judged against the
	// time of the latest answered status, never the wall clock, so a stretch
	// with no polls at all (a RETH MAC link cycle skips the status loop and
	// parks the workers) can never age a worker into "frozen".
	hbLast       []time.Time
	hbChanged    []time.Time
	lastStatusAt time.Time

	// suspected verdict with hysteresis
	suspected      bool
	suspectedSince time.Time
	healthySince   time.Time
	healthyTrips   int
	// inherited is set on a generation started after an UNEXPECTED exit (a
	// crash, or a wedge kill): the verdict stays raised until the new helper
	// reports ForwardingArmed and then looks healthy, so the RGs do not come
	// back to a helper that is not yet forwarding (#18697).
	inherited bool
	armedSeen bool

	kills atomic.Uint64
}

// reset starts a new generation. inheritNotReady carries a raised verdict
// across an unexpected exit.
func (t *helperLivenessTracker) reset(gen uint64, now time.Time, inheritNotReady bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gen = gen
	t.lastAnswer = now
	t.silentSince = time.Time{}
	t.silentTrips = 0
	t.hbLast, t.hbChanged, t.lastStatusAt = nil, nil, time.Time{}
	t.inherited = inheritNotReady
	t.armedSeen = false
	t.suspected = inheritNotReady
	t.suspectedSince = time.Time{}
	if inheritNotReady {
		t.suspectedSince = now
	}
	t.healthySince, t.healthyTrips = time.Time{}, 0
}

func (t *helperLivenessTracker) generation() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gen
}

// noteRGActivate records an update_ha_state; kills wait out helperWedgeRGGrace
// after it, so a failover's own control-socket load is never a restart.
func (t *helperLivenessTracker) noteRGActivate(now time.Time) {
	t.mu.Lock()
	t.lastRGActivate = now
	t.mu.Unlock()
}

// noteAnswered records a round trip the helper answered, ended at end.
func (t *helperLivenessTracker) noteAnswered(gen uint64, end time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if gen != t.gen {
		return
	}
	t.lastAnswer = end
	t.silentSince = time.Time{}
	t.silentTrips = 0
	if t.healthySince.IsZero() {
		t.healthySince = end
	}
	t.healthyTrips++
	t.evaluateLocked(end)
}

// noteSilent records a round trip that got no answer, started at start.
func (t *helperLivenessTracker) noteSilent(gen uint64, start, end time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if gen != t.gen {
		return
	}
	if t.silentSince.IsZero() {
		t.silentSince = start
	}
	t.silentTrips++
	t.healthySince, t.healthyTrips = time.Time{}, 0
	t.evaluateLocked(end)
}

// noteRoundTrip classifies one control round trip and records it.
func (t *helperLivenessTracker) noteRoundTrip(gen uint64, start, end time.Time, err error, receivedBytes bool) {
	switch answered, silent := classifyControlRoundTrip(err, receivedBytes); {
	case answered:
		t.noteAnswered(gen, end)
	case silent:
		t.noteSilent(gen, start, end)
	}
}

// noteStatus records an answered status: worker heartbeats and arm state.
func (t *helperLivenessTracker) noteStatus(gen uint64, now time.Time, heartbeats []time.Time, forwardingArmed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if gen != t.gen {
		return
	}
	if forwardingArmed && !t.armedSeen {
		t.armedSeen = true
		if t.inherited {
			// The hysteresis for an inherited verdict is measured from the
			// arm, not from answers the unarmed helper gave before it.
			t.healthySince, t.healthyTrips = now, 0
		}
	}
	t.lastStatusAt = now
	if len(heartbeats) != len(t.hbLast) {
		t.hbLast = append([]time.Time(nil), heartbeats...)
		t.hbChanged = make([]time.Time, len(heartbeats))
		for i := range t.hbChanged {
			t.hbChanged[i] = now
		}
	} else {
		for i, hb := range heartbeats {
			if !hb.Equal(t.hbLast[i]) {
				t.hbLast[i] = hb
				t.hbChanged[i] = now
			}
		}
	}
	if t.frozenWorkerLocked() >= 0 {
		t.healthySince, t.healthyTrips = time.Time{}, 0
	}
	t.evaluateLocked(now)
}

// frozenWorkerLocked returns the index of a worker whose heartbeat had not
// moved for helperWorkerFrozenAfter as of the latest answered status, or -1.
// A zero heartbeat (not yet published) never counts.
func (t *helperLivenessTracker) frozenWorkerLocked() int {
	for i, hb := range t.hbLast {
		if hb.IsZero() {
			continue
		}
		if t.lastStatusAt.Sub(t.hbChanged[i]) >= helperWorkerFrozenAfter {
			return i
		}
	}
	return -1
}

func (t *helperLivenessTracker) silenceSpanLocked(now time.Time) time.Duration {
	if t.silentSince.IsZero() || t.silentTrips < helperWedgeMinSilentTrips {
		return 0
	}
	return now.Sub(t.silentSince)
}

// evaluateLocked raises or clears the suspected verdict.
func (t *helperLivenessTracker) evaluateLocked(now time.Time) {
	raise := t.silenceSpanLocked(now) >= helperWedgeDemoteSpan || t.frozenWorkerLocked() >= 0
	if raise {
		if !t.suspected {
			t.suspected = true
			t.suspectedSince = now
		}
		return
	}
	if !t.suspected {
		return
	}
	if t.inherited && !t.armedSeen {
		return
	}
	if !t.silentSince.IsZero() || t.healthySince.IsZero() {
		return
	}
	if now.Sub(t.healthySince) >= helperWedgeClearAfter && t.healthyTrips >= helperWedgeClearTrips {
		t.suspected = false
		t.inherited = false
	}
}

// wedgeSuspected reports the suspected verdict, re-evaluated at now so a
// silence that is not followed by another round trip still ages into it.
func (t *helperLivenessTracker) wedgeSuspected(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.evaluateLocked(now)
	return t.suspected
}

// killDue reports whether the generation has answered nothing for
// helperWedgeMinSpan, or kept a worker frozen for helperWorkerFrozenKillAfter,
// outside the RG-activation grace. The duration returned is the longer of the
// two, for the log line.
func (t *helperLivenessTracker) killDue(now time.Time) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	span := t.silenceSpanLocked(now)
	frozen := time.Duration(0)
	if i := t.frozenWorkerLocked(); i >= 0 {
		frozen = t.lastStatusAt.Sub(t.hbChanged[i])
	}
	if span < helperWedgeMinSpan && frozen < helperWorkerFrozenKillAfter {
		return false, max(span, frozen)
	}
	span = max(span, frozen)
	if !t.lastRGActivate.IsZero() && now.Sub(t.lastRGActivate) < helperWedgeRGGrace {
		return false, span
	}
	return true, span
}

// answerAge is the time since the generation's last answered round trip.
func (t *helperLivenessTracker) answerAge(now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastAnswer.IsZero() {
		return 0
	}
	return now.Sub(t.lastAnswer)
}

// classifyControlRoundTrip maps a requestDetailedAtSocket outcome onto the
// tracker, in the same order requestDetailedAtSocket classifies its own errors
// (#18293):
//   - answered: the helper replied (success or in-band refusal);
//   - neither: the request was provably never sent (encode, size, no socket
//     configured);
//   - silent: a deadline expiry or an EOF, EVEN after a partial prefix: a
//     helper that wrote "{" and stalled has not answered;
//   - neither: any other failure after bytes arrived (an undecodable or
//     over-cap reply: the helper answered);
//   - silent: everything else, the same conservative rule #9651 used (a full
//     backlog, a reset, a refused connect).
func classifyControlRoundTrip(err error, receivedBytes bool) (answered, silent bool) {
	if err == nil || errors.Is(err, errHelperRejected) || errors.Is(err, errHelperPostTeardown) {
		return true, false
	}
	var unsent *knownUnsentError
	if errors.As(err, &unsent) {
		return false, false
	}
	if isStatusReadTimeout(err) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false, true
	}
	if receivedBytes || errors.Is(err, errStatusDecode) {
		return false, false
	}
	return false, true
}

// HelperWedgeSuspected reports whether the current helper looks wedged or not
// forwarding (#18685), or is the first generation after an unexpected exit and
// has not yet armed and looked healthy (#18697). It never takes m.mu.
func (m *Manager) HelperWedgeSuspected() bool {
	if m == nil {
		return false
	}
	return m.liveTrack.wedgeSuspected(time.Now())
}

// HelperElectionNotReady reports that this node's helper must not hold the RGs
// at full weight (#18697, #18685): it exited unexpectedly and has not come back,
// or it is back but not yet armed and healthy, or it is running but wedged.
// An intentional stop or respawn (a plan-key change, an operator stop) is NOT
// reported: that keeps the F2 rule, so a config commit does not move the RGs.
// It never takes m.mu, so the daemon's transit tick can read it while a caller
// is blocked in a control round trip holding m.mu.
func (m *Manager) HelperElectionNotReady() bool {
	if m == nil {
		return false
	}
	return m.helperDownUnexpected.Load() || m.liveTrack.wedgeSuspected(time.Now())
}

// HelperAnswerAge is the time since the helper last answered any control
// round trip (#18685), for the status-age gauge.
func (m *Manager) HelperAnswerAge() time.Duration {
	if m == nil {
		return 0
	}
	return m.liveTrack.answerAge(time.Now())
}

// HelperWedgeKills counts helpers the #18685 watchdog killed.
func (m *Manager) HelperWedgeKills() uint64 {
	if m == nil {
		return 0
	}
	return m.liveTrack.kills.Load()
}

// watchHelperLiveness is the per-generation watchdog. It runs until the
// generation exits and kills the generation's own process once killDue holds.
// It takes neither m.mu nor controlReqMu, so a caller blocked in a round trip
// while holding m.mu cannot delay it.
func (m *Manager) watchHelperLiveness(g *helperGeneration, tick time.Duration) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-g.exited:
			return
		case now := <-ticker.C:
			if m.liveTrack.generation() != g.gen {
				return
			}
			due, span := m.liveTrack.killDue(now)
			if !due {
				continue
			}
			if g.cmd == nil || g.cmd.Process == nil {
				return
			}
			if m.wedgeKilledGen.Swap(g.gen+1) == g.gen+1 {
				return // the status-loop path already killed this generation
			}
			m.liveTrack.kills.Add(1)
			slog.Error("userspace dataplane helper answered no control request; killing it so the supervisor fails closed and restarts it (#18685)",
				"unanswered_for", span.Round(time.Second).String(),
				"pid", g.cmd.Process.Pid, "generation", g.gen)
			_ = g.cmd.Process.Kill()
			return
		}
	}
}
