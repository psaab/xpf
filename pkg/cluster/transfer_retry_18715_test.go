package cluster

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

// #18715: an aborted transfer whose old owner never re-promotes must not leave
// the RG with no primary. The requester retries through the ordinary request
// sequence; the owner (a #18715 build) accepts a request for an RG it does not
// own only when the RG is ownerless from its own fresh view, and acks only
// after it confirmed its dataplane inactive. These cells drive two real
// Managers; the owner's daemon (OnRemoteFailover + the sync layer's
// fence wait) is simulated by retryPair18715.request.

// retryPair18715 wires a requester to an owner. fence is the owner daemon's
// verdict for each request: nil means the fence actuated (the ordinary path)
// or the ownerless confirm succeeded; an error fails the ack.
type retryPair18715 struct {
	t        *testing.T
	owner    *Manager
	req      *Manager
	nextReq  uint64
	oldOwner bool // a pre-#18715 owner: a request for an RG it does not own is rejected
	fence    func(attempt int, ownerWasPrimary bool) error
	attempts int
	attemptT []time.Time
	pending  []func()
	commits  int
	aborts   int
	// inFlight runs inside a request, after the owner parked the RG and
	// before the ack returns (an operator action racing the attempt).
	inFlight func(attempt int)
}

func newRetryPair18715(t *testing.T, owner, req *Manager) *retryPair18715 {
	t.Helper()
	p := &retryPair18715{t: t, owner: owner, req: req}
	req.SetPeerFailoverFunc(p.request)
	req.SetPeerFailoverCommitFunc(func(rgID int, reqID uint64) error {
		p.commits++
		if err := owner.FinalizePeerTransferOut(rgID); err != nil {
			return err
		}
		owner.ClearRemoteTransferOutLease(rgID, reqID)
		return nil
	})
	req.SetPeerFailoverAbortFunc(func(rgID int, reqID uint64) error {
		p.aborts++
		return owner.AbortRemoteTransferOut(rgID, reqID)
	})
	req.mu.Lock()
	req.abortedTransferRetryLaunchFn = func(fn func()) { p.pending = append(p.pending, fn) }
	req.mu.Unlock()
	return p
}

func (p *retryPair18715) request(rgID int) (uint64, error) {
	p.nextReq++
	reqID := p.nextReq
	p.attempts++
	p.attemptT = append(p.attemptT, time.Now())
	attempt := p.attempts
	ownerWasPrimary := p.owner.IsLocalPrimary(rgID)
	var err error
	switch {
	case ownerWasPrimary:
		_, err = p.owner.ManualFailover(rgID)
	case p.oldOwner:
		err = fmt.Errorf("%w: redundancy group %d", ErrRemoteFailoverRejected, rgID)
	default:
		_, err = p.owner.ManualFailoverOwnerless(rgID)
	}
	if err != nil {
		status := failoverAckFailed
		if errors.Is(err, ErrRemoteFailoverRejected) {
			status = failoverAckRejected
		}
		return reqID, failoverAckError([]int{rgID}, failoverAck{status: status, detail: err.Error()})
	}
	p.owner.ArmRemoteTransferOutLease([]int{rgID}, reqID)
	// The owner's hold heartbeat reaches the requester before the ack.
	p.req.handlePeerHeartbeat(p.owner.buildHeartbeat())
	if p.inFlight != nil {
		p.inFlight(attempt)
	}
	if ferr := p.fence(attempt, ownerWasPrimary); ferr != nil {
		// handleRemoteFailover restores the owner after a failed fence.
		_ = p.owner.AbortRemoteTransferOut(rgID, reqID)
		return reqID, failoverAckError([]int{rgID}, failoverAck{status: failoverAckFailed, detail: ferr.Error()})
	}
	return reqID, nil
}

type roles18715 struct{ owner, req bool }

// round exchanges one heartbeat each way, runs any retry attempt the
// requester launched, and reports who is primary afterwards.
func (p *retryPair18715) round() roles18715 {
	p.owner.handlePeerHeartbeat(p.req.buildHeartbeat())
	p.req.handlePeerHeartbeat(p.owner.buildHeartbeat())
	for len(p.pending) > 0 {
		fn := p.pending[0]
		p.pending = p.pending[1:]
		fn()
	}
	return roles18715{p.owner.IsLocalPrimary(1), p.req.IsLocalPrimary(1)}
}

func (p *retryPair18715) marker() bool {
	p.req.mu.RLock()
	defer p.req.mu.RUnlock()
	_, ok := p.req.abortedPeerTransferReqID[1]
	return ok
}

func (p *retryPair18715) chain() *abortedTransferRetry {
	p.req.mu.RLock()
	defer p.req.mu.RUnlock()
	return p.req.abortedTransferRetries[1]
}

// fastRetry18715 shrinks the quiet period and the backoff for a test.
func fastRetry18715(t *testing.T, quiet, minB, maxB time.Duration) {
	t.Helper()
	oq, omin, omax := abortedTransferRetryQuietOverride, abortedTransferRetryBackoffMin, abortedTransferRetryBackoffMax
	abortedTransferRetryQuietOverride, abortedTransferRetryBackoffMin, abortedTransferRetryBackoffMax = quiet, minB, maxB
	t.Cleanup(func() {
		abortedTransferRetryQuietOverride, abortedTransferRetryBackoffMin, abortedTransferRetryBackoffMax = oq, omin, omax
	})
}

// trapArmDebt18715 reproduces the L-review trap on f660678c93: the operator
// asks the healthy node (node1) for RG1; the owner's helper wedges during the
// request (arm debt lands) and its fence fails; the owner is restored but
// yields at the arm-debt floor, and the requester is fenced. Neither is primary.
func trapArmDebt18715(t *testing.T, fence func(attempt int, ownerWasPrimary bool) error) *retryPair18715 {
	t.Helper()
	owner, req := armDebtPair12164(t)
	p := newRetryPair18715(t, owner, req)
	p.fence = func(attempt int, ownerWasPrimary bool) error {
		if attempt == 1 {
			owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
			return errors.New("rg_active=false refused by the helper")
		}
		return fence(attempt, ownerWasPrimary)
	}
	if err := req.RequestPeerFailover(1); err == nil {
		t.Fatal("setup: the operator request must fail on the failed fence")
	}
	if got := (roles18715{owner.IsLocalPrimary(1), req.IsLocalPrimary(1)}); got.owner || got.req || !p.marker() {
		t.Fatalf("setup: want the ownerless trap (neither primary, requester fenced), got %+v marker=%v", got, p.marker())
	}
	return p
}

// runRounds18715 drives rounds until stop returns true (or max), then keeps
// going for at least `after` rounds, counting dual-primary rounds and ownership
// transitions over the whole run.
func runRounds18715(p *retryPair18715, max, after int, stop func(roles18715) bool) (last roles18715, rounds, dual, transitions int, stopped bool) {
	prev := roles18715{p.owner.IsLocalPrimary(1), p.req.IsLocalPrimary(1)}
	extra := -1
	for rounds < max {
		now := p.round()
		rounds++
		if now.owner && now.req {
			dual++
		}
		if now != prev {
			transitions++
		}
		prev = now
		if extra < 0 && stop(now) {
			stopped = true
			extra = 0
		}
		if extra >= 0 {
			if extra >= after {
				break
			}
			extra++
		}
		time.Sleep(2 * time.Millisecond)
	}
	return prev, rounds, dual, transitions, stopped
}

// TestAbortedTransferRetryConverges18715 is the L BLOCKING cell. From the
// ownerless trap, the requester retries until the owner confirms its dataplane
// inactive, then commits; exactly one node owns RG1 afterwards and no round
// has two. Each row is a different way the owner's confirm resolves mid-retry.
func TestAbortedTransferRetryConverges18715(t *testing.T) {
	fastRetry18715(t, 20*time.Millisecond, 10*time.Millisecond, 40*time.Millisecond)
	ok := func(int, bool) error { return nil }
	for _, tc := range []struct {
		name      string
		fence     func(attempt int, ownerWasPrimary bool) error
		wantOwner string // "req" or "owner"
		recover   bool   // the owner's helper re-arms after the second attempt
	}{
		// The refused write lands late (the reconcile loop's retry): the
		// first retry's fresh write succeeds.
		{"late-write-lands", ok, "req", false},
		// A slow write: the fresh write keeps timing out for two attempts.
		{"slow-write", func(a int, _ bool) error {
			if a <= 3 {
				return errors.New("fresh rg_active=false write timed out")
			}
			return nil
		}, "req", false},
		// The watchdog kills the wedged helper: the fresh write fails while it
		// is gone, then succeeds once the respawned helper answers (its
		// rg_active starts false). Arm debt stays until it re-arms.
		{"watchdog-kill-restart", func(a int, _ bool) error {
			if a <= 3 {
				return errors.New("no helper running")
			}
			return nil
		}, "req", false},
		// The helper answers again and re-arms between attempts: the owner's
		// arm debt clears, it out-ranks the requester and re-promotes, which
		// resolves the fence; the chain stops.
		{"helper-answers-again", func(a int, _ bool) error {
			return errors.New("fresh rg_active=false write timed out")
		}, "owner", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := trapArmDebt18715(t, tc.fence)
			stop := func(r roles18715) bool {
				if tc.recover && p.attempts >= 2 {
					p.owner.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
				}
				return r.owner != r.req
			}
			last, rounds, dual, _, stopped := runRounds18715(p, 2000, 40, stop)
			if !stopped {
				t.Fatalf("RG1 still has no primary after %d rounds (%d retry attempts): the trap did not converge", rounds, p.attempts)
			}
			if dual != 0 {
				t.Fatalf("%d of %d rounds had two primaries", dual, rounds)
			}
			if rounds < 40 {
				t.Fatalf("ran %d rounds, want at least 40", rounds)
			}
			want := roles18715{owner: tc.wantOwner == "owner", req: tc.wantOwner == "req"}
			if last != want {
				t.Fatalf("final roles %+v, want %+v (attempts %d, commits %d)", last, want, p.attempts, p.commits)
			}
			if p.chain() != nil {
				t.Fatalf("the retry chain outlived convergence: %+v", p.chain())
			}
			if tc.wantOwner == "req" && p.commits != 1 {
				t.Fatalf("commits = %d, want exactly 1", p.commits)
			}
			if tc.wantOwner == "owner" && p.commits != 0 {
				t.Fatalf("commits = %d, want none (the owner re-promoted)", p.commits)
			}
		})
	}
}

// TestAbortedTransferRetryOldOwnerKeepsRetrying18715: a pre-#18715 owner
// rejects every retry (it does not own the RG). The requester keeps retrying
// with growing backoff, never gives up, and never creates a second primary.
// The RG stays ownerless, exactly as it was before #18715.
func TestAbortedTransferRetryOldOwnerKeepsRetrying18715(t *testing.T) {
	fastRetry18715(t, 10*time.Millisecond, 5*time.Millisecond, 20*time.Millisecond)
	p := trapArmDebt18715(t, func(int, bool) error { return nil })
	p.oldOwner = true
	start := time.Now()
	dual := 0
	for time.Since(start) < 400*time.Millisecond {
		if r := p.round(); r.owner && r.req {
			dual++
		}
		time.Sleep(2 * time.Millisecond)
	}
	if dual != 0 {
		t.Fatalf("%d dual-primary rounds against an old owner", dual)
	}
	if p.attempts < 5 {
		t.Fatalf("only %d attempts in 400 ms: the retry gave up or stalled", p.attempts)
	}
	c := p.chain()
	if c == nil || c.backoff != abortedTransferRetryBackoffMax {
		t.Fatalf("chain %+v: want it alive with backoff at the %s cap", c, abortedTransferRetryBackoffMax)
	}
	if p.commits != 0 || p.owner.IsLocalPrimary(1) || p.req.IsLocalPrimary(1) {
		t.Fatalf("an old owner's rejections must change nothing: commits=%d", p.commits)
	}
}

// TestHigherPriorityRequesterTrapConverges18715: the #17713 shape without any
// arm debt. A requester that out-ranks the owner is fenced after a failed
// fence while the restored owner stays secondary
// (TestFailedFenceRestorationKeepsHigherPriorityRequesterFenced17713 pins that
// step). The retry now converges it.
func TestHigherPriorityRequesterTrapConverges18715(t *testing.T) {
	fastRetry18715(t, 20*time.Millisecond, 10*time.Millisecond, 40*time.Millisecond)
	req, owner := ackWireManagers16592(t, []int{1}, true)
	p := newRetryPair18715(t, owner, req)
	p.fence = func(attempt int, _ bool) error {
		if attempt == 1 {
			return errors.New("fence did not actuate")
		}
		return nil
	}
	if err := req.RequestPeerFailover(1); err == nil {
		t.Fatal("setup: the failed fence must fail the request")
	}
	if owner.IsLocalPrimary(1) || req.IsLocalPrimary(1) || !p.marker() {
		t.Fatal("setup: want the #17713 ownerless shape")
	}
	last, rounds, dual, _, stopped := runRounds18715(p, 2000, 40, func(r roles18715) bool { return r.owner != r.req })
	if !stopped || dual != 0 || last != (roles18715{req: true}) {
		t.Fatalf("stopped=%v dual=%d final=%+v after %d rounds: want the requester as the only primary", stopped, dual, last, rounds)
	}
}

// TestAbortedTransferRetryWithoutRetryStaysOwnerless18715 is the control: the
// same trap with the retry disabled (the requester never launches an attempt)
// stays ownerless. It is the mutant "drop the retry" run as a cell, so the
// convergence cells above are known to depend on the retry.
func TestAbortedTransferRetryWithoutRetryStaysOwnerless18715(t *testing.T) {
	fastRetry18715(t, 10*time.Millisecond, 5*time.Millisecond, 20*time.Millisecond)
	p := trapArmDebt18715(t, func(int, bool) error { return nil })
	p.req.mu.Lock()
	p.req.abortedTransferRetryLaunchFn = func(func()) {} // attempts are dropped
	p.req.mu.Unlock()
	for range 60 {
		if r := p.round(); r.owner || r.req {
			t.Fatalf("roles %+v: without the retry the trap must persist (control)", r)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestPendingRetryNeverOverridesTheOperator18715 (coordinator cell 3): while a
// retry is pending, an operator decision for the RG ends the chain. "Back to
// the sick node" reaches the requester as the peer's transfer request, served
// by ManualFailoverOwnerless; a local failover or reset are the other entry
// points. The stale chain must not fire.
func TestPendingRetryNeverOverridesTheOperator18715(t *testing.T) {
	const quiet = 60 * time.Millisecond
	fastRetry18715(t, quiet, 10*time.Millisecond, 40*time.Millisecond)
	for _, tc := range []struct {
		name string
		act  func(p *retryPair18715)
	}{
		{"back-to-sick-node", func(p *retryPair18715) {
			if _, err := p.req.ManualFailoverOwnerless(1); err != nil {
				p.t.Fatalf("ManualFailoverOwnerless: %v", err)
			}
		}},
		{"local-failover", func(p *retryPair18715) {
			if _, err := p.req.ManualFailover(1); err != nil {
				p.t.Fatalf("ManualFailover: %v", err)
			}
		}},
		{"reset", func(p *retryPair18715) {
			if err := p.req.ResetFailover(1); err != nil {
				p.t.Fatalf("ResetFailover: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := trapArmDebt18715(t, func(int, bool) error { return nil })
			p.round() // the chain starts
			if p.chain() == nil {
				t.Fatal("setup: no pending retry chain")
			}
			before := p.attempts
			tc.act(p)
			deadline := time.Now().Add(3 * quiet)
			for time.Now().Before(deadline) {
				if r := p.round(); r.owner && r.req {
					t.Fatal("dual primary")
				}
				time.Sleep(2 * time.Millisecond)
			}
			if p.attempts != before {
				t.Fatalf("%d retry attempt(s) fired after the operator acted", p.attempts-before)
			}
		})
	}
}

// TestOperatorActionRestartsTheRetryEpoch18715: an operator action that fails
// without changing any role still ends the old chain (the operator epoch moved),
// so the next attempt waits a full quiet period from the operator's action, not
// the old chain's schedule. This is the cell where the epoch is the only guard.
func TestOperatorActionRestartsTheRetryEpoch18715(t *testing.T) {
	const quiet = 80 * time.Millisecond
	fastRetry18715(t, quiet, 10*time.Millisecond, 40*time.Millisecond)
	p := trapArmDebt18715(t, func(int, bool) error { return nil })
	p.round()
	if p.chain() == nil {
		t.Fatal("setup: no pending retry chain")
	}
	time.Sleep(quiet / 2)
	p.req.SetPreManualFailoverHook(func(int) error { return errors.New("barrier refused") })
	opAt := time.Now()
	if _, err := p.req.ManualFailover(1); err == nil {
		t.Fatal("setup: the operator's failover must fail in its pre-hook")
	}
	p.req.SetPreManualFailoverHook(nil)
	for p.attempts < 2 && time.Since(opAt) < 2*time.Second {
		p.round()
		time.Sleep(2 * time.Millisecond)
	}
	if p.attempts < 2 {
		t.Fatal("no retry after the operator action")
	}
	if first := p.attemptT[1]; first.Sub(opAt) < quiet {
		t.Fatalf("the retry fired %s after the operator action, before a full quiet period (%s): the stale chain's schedule survived",
			first.Sub(opAt), quiet)
	}
}

// TestInFlightRetryDoesNotCommitAfterAReset18715: an operator reset that lands
// while an attempt is in flight ends its epoch. The owner's applied ack then
// arrives, but the commit's admission check refuses it: no commit is sent, the
// owner is told to abort, and the RG converges under the reset's normal
// election with one primary.
func TestInFlightRetryDoesNotCommitAfterAReset18715(t *testing.T) {
	fastRetry18715(t, 10*time.Millisecond, 10*time.Millisecond, 40*time.Millisecond)
	p := trapArmDebt18715(t, func(int, bool) error { return nil })
	p.inFlight = func(attempt int) {
		if attempt == 2 {
			if err := p.req.ResetFailover(1); err != nil {
				p.t.Fatalf("ResetFailover: %v", err)
			}
		}
	}
	abortsBefore := p.aborts
	last, rounds, dual, _, stopped := runRounds18715(p, 2000, 40, func(r roles18715) bool { return r.owner != r.req })
	if p.attempts < 2 {
		t.Fatal("setup: the retry never fired")
	}
	if p.commits != 0 {
		t.Fatalf("an attempt whose epoch a reset ended was committed (%d commits)", p.commits)
	}
	if p.aborts == abortsBefore {
		t.Fatal("the stale attempt did not send the owner an abort")
	}
	if !stopped || dual != 0 || last != (roles18715{req: true}) {
		t.Fatalf("stopped=%v dual=%d final=%+v after %d rounds: want one primary under normal election", stopped, dual, last, rounds)
	}
}

// ownerlessOwner18715 builds an owner whose RG1 is ownerless from its view: it
// is secondary and its peer reports secondary over a fresh heartbeat.
func ownerlessOwner18715(t *testing.T) *Manager {
	t.Helper()
	owner, peer := armDebtPair12164(t)
	_ = peer
	owner.SetGroupStateForTesting(1, StateSecondary)
	owner.SetPeerGroupStateForTesting(1, StateSecondary)
	return owner
}

// TestOwnerlessAcceptRequiresAFreshOwnerlessView18715 (coordinator 2): the
// owner-side exception accepts only on a fresh view showing the peer not
// primary. A delayed request from an old epoch that arrives after the peer
// promoted must be rejected, with no hold installed.
func TestOwnerlessAcceptRequiresAFreshOwnerlessView18715(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(m *Manager)
		accept bool
	}{
		{"fresh-ownerless", func(*Manager) {}, true},
		{"peer-primary-fresh", func(m *Manager) { m.SetPeerGroupStateForTesting(1, StatePrimary) }, false},
		// The peer promoted, but this node's latest frame from it is older
		// than two heartbeat intervals and still says secondary.
		{"stale-view-shows-secondary", func(m *Manager) { m.SetPeerHeartbeatAgeForTesting(time.Second) }, false},
		{"local-primary", func(m *Manager) { m.SetGroupStateForTesting(1, StatePrimary) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := ownerlessOwner18715(t)
			tc.setup(m)
			_, err := m.ManualFailoverOwnerless(1)
			m.mu.RLock()
			held := m.groups[1].ManualFailover
			m.mu.RUnlock()
			if tc.accept {
				if err != nil || !held {
					t.Fatalf("err=%v held=%v: want accepted with the hold installed", err, held)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrRemoteFailoverRejected) {
				t.Fatalf("err=%v: want a rejection (ErrRemoteFailoverRejected)", err)
			}
			if held && tc.name != "local-primary" {
				t.Fatal("a rejected request installed a hold")
			}
		})
	}
}

// TestOwnerlessAcceptChecksUnderTheHoldLock18715 (coordinator 1): the
// predicate is re-evaluated in the critical section that installs the hold.
// A change during the unlocked pre-hook (the peer promotes, or this node does)
// must refuse the hold.
func TestOwnerlessAcceptChecksUnderTheHoldLock18715(t *testing.T) {
	for _, tc := range []struct {
		name string
		flip func(m *Manager)
	}{
		{"peer-promotes-mid-prehook", func(m *Manager) { m.SetPeerGroupStateForTesting(1, StatePrimary) }},
		{"local-promotes-mid-prehook", func(m *Manager) { m.SetGroupStateForTesting(1, StatePrimary) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := ownerlessOwner18715(t)
			m.SetPreManualFailoverHook(func(int) error { tc.flip(m); return nil })
			_, err := m.ManualFailoverOwnerless(1)
			if !errors.Is(err, ErrRemoteFailoverRejected) {
				t.Fatalf("err=%v: a change during the pre-hook must refuse the hold", err)
			}
			m.mu.RLock()
			st, held := m.groups[1].State, m.groups[1].ManualFailover
			m.mu.RUnlock()
			if held || st == StateSecondaryHold {
				t.Fatalf("state=%s held=%v: the hold was installed after the predicate stopped holding", st, held)
			}
		})
	}
}

// TestRequesterDropsAnAckForAnotherRequest18715 (coordinator 2): the residual
// window of the freshness check is a request from an old epoch that the owner
// accepts on a fresh-but-not-yet-updated view. Its applied ack carries the old
// reqID, and the requester must drop it: only the request it is waiting on can
// complete. This pins completeFailoverWait's reqID match.
func TestRequesterDropsAnAckForAnotherRequest18715(t *testing.T) {
	ss := &SessionSync{}
	ch := make(chan failoverAck, 1)
	ss.registerFailoverWaitForTest(failoverWaitRequest, []int{1}, 42, ch)
	ack := func(reqID uint64) []byte {
		b := make([]byte, 10)
		b[0], b[1] = 1, failoverAckApplied
		binary.LittleEndian.PutUint64(b[2:10], reqID)
		return b
	}
	if ss.handleFailoverAck(nil, ack(41)) {
		t.Fatal("an applied ack for request 41 completed the wait for request 42")
	}
	select {
	case a := <-ch:
		t.Fatalf("the waiter for request 42 received %+v from request 41's ack", a)
	default:
	}
	if !ss.handleFailoverAck(nil, ack(42)) {
		t.Fatal("the matching ack was not delivered (control)")
	}
	if a := <-ch; a.status != failoverAckApplied {
		t.Fatalf("delivered %+v, want applied", a)
	}
}

// TestTransferRetryShowsInStatus18715 (coordinator 5): the operator's request
// returned an error and the RG moves later on its own, so a pending retry is
// visible in `show chassis cluster status`, below the node row (#8206).
func TestTransferRetryShowsInStatus18715(t *testing.T) {
	fastRetry18715(t, time.Hour, time.Hour, time.Hour)
	p := trapArmDebt18715(t, func(int, bool) error { return nil })
	p.round()
	out := p.req.FormatStatus()
	if !containsLine18715(out, "  Transfer retry: pending (transfer ") {
		t.Fatalf("no pending-retry line in the status render:\n%s", out)
	}
	if v := statusLayoutViolations(out); len(v) > 0 {
		t.Fatalf("the retry line broke the #8206 layout contract: %v\n%s", v, out)
	}
}

func containsLine18715(out, prefix string) bool {
	for _, l := range splitLines18715(out) {
		if len(l) >= len(prefix) && l[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func splitLines18715(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// TestBothNodesSickNoRetry18715 (coordinator 1): a requester that is itself in
// arm debt is not eligible to take the RG, so it does not retry: when both
// nodes are sick a retry achieves nothing. The requester out-ranks the owner
// here, so with both at the arm-debt floor the owner stays secondary and the
// requester's own eligibility is the only thing holding the retry back. Once
// the requester re-arms, the retry resumes and converges.
func TestBothNodesSickNoRetry18715(t *testing.T) {
	const quiet = 20 * time.Millisecond
	fastRetry18715(t, quiet, 10*time.Millisecond, 40*time.Millisecond)
	req, owner := ackWireManagers16592(t, []int{1}, true)
	p := newRetryPair18715(t, owner, req)
	p.fence = func(attempt int, _ bool) error {
		if attempt == 1 {
			owner.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
			req.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
			return errors.New("fence did not actuate")
		}
		return nil
	}
	if err := req.RequestPeerFailover(1); err == nil {
		t.Fatal("setup: the failed fence must fail the request")
	}
	before := p.attempts
	for range 40 {
		r := p.round()
		if p.attempts != before {
			t.Fatalf("a requester in arm debt retried (%d attempts; roles %+v)", p.attempts-before, r)
		}
		if r.owner || r.req {
			t.Fatalf("setup: roles %+v, want both secondary with both nodes at the arm-debt floor", r)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if p.attempts != before || p.chain() != nil {
		t.Fatalf("a requester in arm debt retried (%d attempts, chain %+v)", p.attempts-before, p.chain())
	}
	req.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	last, _, dual, _, stopped := runRounds18715(p, 2000, 40, func(r roles18715) bool { return r.owner != r.req })
	if !stopped || dual != 0 || last != (roles18715{req: true}) {
		t.Fatalf("stopped=%v dual=%d final=%+v: the retry must resume once the requester re-arms", stopped, dual, last)
	}
}

// TestAbortedTransferRetryOnItsOwnGoroutine18715 runs the production launch
// (each attempt on its own goroutine, racing the heartbeat loop) so the race
// detector sees the real concurrency. Only Manager state is read here: the
// pair's counters belong to the attempt goroutine.
func TestAbortedTransferRetryOnItsOwnGoroutine18715(t *testing.T) {
	fastRetry18715(t, 20*time.Millisecond, 10*time.Millisecond, 40*time.Millisecond)
	p := trapArmDebt18715(t, func(int, bool) error { return nil })
	p.req.mu.Lock()
	p.req.abortedTransferRetryLaunchFn = nil
	p.req.mu.Unlock()
	dual, converged := 0, 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && converged < 40 {
		r := p.round()
		if r.owner && r.req {
			dual++
		}
		if r.req && !r.owner && p.chain() == nil {
			converged++
		}
		time.Sleep(2 * time.Millisecond)
	}
	if dual != 0 || converged < 40 {
		t.Fatalf("dual=%d converged-rounds=%d: want the requester as the only primary for 40 rounds", dual, converged)
	}
}
