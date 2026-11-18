package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #19140: peer-driven takeover. The owner only CARRIES its member-shim debt
// (a reserved heartbeat marker, no weight). A healthy secondary that sees
// the marker requests the RG through the ordinary transfer protocol, on its own
// readiness at the moment it acts. These cells drive two real Managers wired
// both ways through the #18715 transfer harness (retryPair18715), so either
// node can request and every request runs requestPeerFailover end to end.

// shimPair19140 is node 0 (a, the initial owner at the higher priority) and
// node 1 (b). ab carries b's requests to a; ba carries a's requests to b.
type shimPair19140 struct {
	t      *testing.T
	a, b   *Manager
	ab, ba *retryPair18715
	// stripAMarker drops a's member-shim marker from the frames b receives:
	// an owner that predates #19140.
	stripAMarker bool
}

func memberShimPair19140(t *testing.T, preempt bool, aPri, bPri int) (a, b *Manager) {
	t.Helper()
	cfg := &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 1, Preempt: preempt, NodePriorities: map[int]int{0: aPri, 1: bPri},
		}},
	}
	a, b = NewManager(0, 1), NewManager(1, 1)
	a.UpdateConfig(cfg)
	b.UpdateConfig(cfg)
	a.takeoverHoldTime, b.takeoverHoldTime = 0, 0
	a.SetRGReady(1, true, nil)
	b.SetRGReady(1, true, nil)
	a.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	b.SetMonitorWeight(1, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)
	t.Cleanup(func() { a.Stop(); b.Stop() })
	return a, b
}

func newShimPair19140(t *testing.T, preempt bool) *shimPair19140 {
	t.Helper()
	a, b := memberShimPair19140(t, preempt, 200, 100)
	p := &shimPair19140{t: t, a: a, b: b}
	ok := func(int, bool) error { return nil }
	p.ab = newRetryPair18715(t, a, b)
	p.ab.fence = ok
	p.ba = newRetryPair18715(t, b, a)
	p.ba.fence = ok
	b.mu.Lock()
	b.memberShimTakeoverLaunchFn = func(fn func()) { p.ab.pending = append(p.ab.pending, fn) }
	b.mu.Unlock()
	a.mu.Lock()
	a.memberShimTakeoverLaunchFn = func(fn func()) { p.ba.pending = append(p.ba.pending, fn) }
	a.mu.Unlock()
	exchangeElection12164(a, b)
	if !a.IsLocalPrimary(1) || b.IsLocalPrimary(1) {
		t.Fatal("precondition: a primary, b secondary")
	}
	return p
}

// fastShim19140 shrinks the quiet period and the backoff for a test.
func fastShim19140(t *testing.T, quiet, minB, maxB time.Duration) {
	t.Helper()
	oq, omin, omax := memberShimTakeoverQuietOverride, memberShimTakeoverBackoffMin, memberShimTakeoverBackoffMax
	memberShimTakeoverQuietOverride, memberShimTakeoverBackoffMin, memberShimTakeoverBackoffMax = quiet, minB, maxB
	t.Cleanup(func() {
		memberShimTakeoverQuietOverride, memberShimTakeoverBackoffMin, memberShimTakeoverBackoffMax = oq, omin, omax
	})
}

func chargeMemberShim19140(m *Manager, on bool) {
	m.SetMonitorWeight(1, RethMemberShimMonitorIface, on, RethMemberShimMonitorCost)
}

func (p *shimPair19140) frameFromA() *HeartbeatPacket {
	pkt := p.a.buildHeartbeat()
	if p.stripAMarker {
		kept := pkt.Monitors[:0]
		for _, mon := range pkt.Monitors {
			if mon.Interface != RethMemberShimMonitorIface {
				kept = append(kept, mon)
			}
		}
		pkt.Monitors = kept
	}
	return pkt
}

// exchange delivers one heartbeat each way, launching (not running) any
// attempt either node starts.
func (p *shimPair19140) exchange() {
	p.a.handlePeerHeartbeat(p.b.buildHeartbeat())
	p.b.handlePeerHeartbeat(p.frameFromA())
}

// runPending runs every launched attempt, in order.
func (p *shimPair19140) runPending() {
	for _, q := range []*retryPair18715{p.ab, p.ba} {
		for len(q.pending) > 0 {
			fn := q.pending[0]
			q.pending = q.pending[1:]
			fn()
		}
	}
}

// rounds runs n exchange+run rounds, 2 ms apart, counting ownership
// transitions and dual-primary rounds.
func (p *shimPair19140) rounds(n int) (transitions, dual int) {
	last := [2]bool{p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1)}
	for range n {
		p.exchange()
		p.runPending()
		now := [2]bool{p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1)}
		if now != last {
			transitions++
		}
		if now[0] && now[1] {
			dual++
		}
		last = now
		time.Sleep(2 * time.Millisecond)
	}
	return transitions, dual
}

// roundsFor runs rounds for at least d.
func (p *shimPair19140) roundsFor(d time.Duration) (transitions, dual int) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		tr, du := p.rounds(1)
		transitions += tr
		dual += du
	}
	return transitions, dual
}

func (p *shimPair19140) chainAttempts(m *Manager) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if c := m.memberShimTakeovers[1]; c != nil {
		return c.attempts
	}
	return 0
}

func modes19140() []struct {
	name    string
	preempt bool
} {
	return []struct {
		name    string
		preempt bool
	}{{"preempt", true}, {"non-preempt", false}}
}

// P1: a healthy secondary requests the RG of an owner carrying member-shim
// debt, through ONE transfer (a request the owner served, then a commit), and
// the RG then stays put: no second request either way, no preempt back.
func TestHealthyPeerRequestsAShimlessOwnersRG19140(t *testing.T) {
	for _, mode := range modes19140() {
		t.Run(mode.name, func(t *testing.T) {
			fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
			p := newShimPair19140(t, mode.preempt)
			chargeMemberShim19140(p.a, true)
			if got := rgWeight9842(t, p.a, 1).Weight; got != 255 {
				t.Fatalf("charged owner weight = %d, want 255: the debt is a marker, not weight", got)
			}
			tr, dual := p.rounds(10)
			if p.a.IsLocalPrimary(1) || !p.b.IsLocalPrimary(1) || tr != 1 || dual != 0 {
				t.Fatalf("a=%v b=%v transitions=%d dual=%d: the healthy peer must take the RG once",
					p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1), tr, dual)
			}
			if p.ab.attempts != 1 || p.ab.commits != 1 {
				t.Fatalf("requests=%d commits=%d: the takeover must be one ordinary transfer", p.ab.attempts, p.ab.commits)
			}
			tr, dual = p.rounds(30)
			if p.a.IsLocalPrimary(1) || !p.b.IsLocalPrimary(1) || tr != 0 || dual != 0 ||
				p.ab.attempts != 1 || p.ba.attempts != 0 {
				t.Fatalf("a=%v b=%v transitions=%d dual=%d requests b->a=%d a->b=%d: the RG must stay with the healthy node",
					p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1), tr, dual, p.ab.attempts, p.ba.attempts)
			}
		})
	}
}

// P2: the owner never yields on its own debt. A peer that does not run the
// trigger (a build that predates #19140) never requests, so the owner keeps
// the RG: the conservative default. And a new requester facing
// an owner that sends no marker never requests either.
func TestOwnerKeepsTheRGWithoutAPeerRequest19140(t *testing.T) {
	for _, mode := range modes19140() {
		t.Run(mode.name+"/old-requester", func(t *testing.T) {
			fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
			p := newShimPair19140(t, mode.preempt)
			p.b.mu.Lock()
			p.b.memberShimTakeoverLaunchFn = func(func()) {} // never acts
			p.b.mu.Unlock()
			chargeMemberShim19140(p.a, true)
			tr, dual := p.rounds(30)
			if !p.a.IsLocalPrimary(1) || p.b.IsLocalPrimary(1) || tr != 0 || dual != 0 {
				t.Fatalf("a=%v b=%v transitions=%d dual=%d: without a peer request the owner must keep the RG",
					p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1), tr, dual)
			}
		})
		t.Run(mode.name+"/old-owner", func(t *testing.T) {
			fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
			p := newShimPair19140(t, mode.preempt)
			p.stripAMarker = true
			chargeMemberShim19140(p.a, true)
			tr, _ := p.rounds(30)
			if !p.a.IsLocalPrimary(1) || tr != 0 || p.ab.attempts != 0 || p.chainAttempts(p.b) != 0 {
				t.Fatalf("a=%v transitions=%d requests=%d: no marker must mean no request",
					p.a.IsLocalPrimary(1), tr, p.ab.attempts)
			}
		})
	}
}

// P3: a requester with floor debt of its own never requests: two equally
// broken nodes leave the RG where it is, with no request and no ping-pong.
func TestChargedRequesterNeverRequests19140(t *testing.T) {
	debts := []struct {
		name  string
		apply func(m *Manager)
	}{
		{"member-shim", func(m *Manager) { chargeMemberShim19140(m, true) }},
		{"dataplane-arm", func(m *Manager) {
			m.SetMonitorWeight(1, DataplaneArmMonitorIface, true, DataplaneArmMonitorCost)
		}},
	}
	for _, mode := range modes19140() {
		for _, d := range debts {
			t.Run(mode.name+"/"+d.name, func(t *testing.T) {
				fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
				p := newShimPair19140(t, mode.preempt)
				d.apply(p.b)
				chargeMemberShim19140(p.a, true)
				tr, dual := p.rounds(30)
				if !p.a.IsLocalPrimary(1) || p.b.IsLocalPrimary(1) || tr != 0 || dual != 0 ||
					p.ab.attempts != 0 || p.ba.attempts != 0 || p.chainAttempts(p.b) != 0 {
					t.Fatalf("a=%v b=%v transitions=%d dual=%d requests=%d/%d attempts=%d: a charged requester must not request",
						p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1), tr, dual, p.ab.attempts, p.ba.attempts, p.chainAttempts(p.b))
				}
			})
		}
	}
}

// P4: the requester's own readiness gates every attempt.
//   - not-ready: an unready requester starts no attempt at all, so the moment
//     it becomes ready the takeover follows within the quiet period, not after
//     a backoff a refused attempt would have armed;
//   - live-refusal: the live transfer-readiness callback refuses at the
//     reservation, nothing reaches the owner, and the owner keeps the RG;
//   - lapse-after-ack: readiness lapses after the owner fenced and acked. The
//     commit's re-check refuses, the transfer aborts, and the owner is restored
//     with no dual-primary round.
func TestRequesterReadinessGatesTheTakeover19140(t *testing.T) {
	t.Run("not-ready", func(t *testing.T) {
		fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
		p := newShimPair19140(t, false)
		p.b.SetRGReady(1, false, []string{"userspace data interface ge-7-0-2 has no XDP shim attached (not-attached)"})
		chargeMemberShim19140(p.a, true)
		p.rounds(20)
		if !p.a.IsLocalPrimary(1) || p.chainAttempts(p.b) != 0 || p.ab.attempts != 0 {
			t.Fatalf("a=%v attempts=%d requests=%d: an unready requester must not start an attempt",
				p.a.IsLocalPrimary(1), p.chainAttempts(p.b), p.ab.attempts)
		}
		p.b.SetRGReady(1, true, nil)
		p.rounds(5)
		if p.a.IsLocalPrimary(1) || !p.b.IsLocalPrimary(1) {
			t.Fatalf("a=%v b=%v: once ready, the requester must take the RG without a backoff",
				p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1))
		}
	})
	t.Run("live-refusal", func(t *testing.T) {
		fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
		p := newShimPair19140(t, false)
		p.b.SetTransferReadinessFunc(func(int) (bool, []string) {
			return false, []string{"helper not serving the RG"}
		})
		chargeMemberShim19140(p.a, true)
		tr, dual := p.rounds(20)
		if !p.a.IsLocalPrimary(1) || p.b.IsLocalPrimary(1) || tr != 0 || dual != 0 || p.ab.attempts != 0 {
			t.Fatalf("a=%v b=%v transitions=%d dual=%d requests=%d: a live-unready requester must send nothing",
				p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1), tr, dual, p.ab.attempts)
		}
	})
	t.Run("lapse-after-ack", func(t *testing.T) {
		fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
		p := newShimPair19140(t, false)
		p.ab.inFlight = func(int) {
			p.b.SetRGReady(1, false, []string{"userspace data interface ge-7-0-2 has no XDP shim attached (not-attached)"})
		}
		chargeMemberShim19140(p.a, true)
		_, dual := p.rounds(20)
		if !p.a.IsLocalPrimary(1) || p.b.IsLocalPrimary(1) || dual != 0 || p.ab.attempts != 1 || p.ab.commits != 0 {
			t.Fatalf("a=%v b=%v dual=%d requests=%d commits=%d: a lapse after the ack must abort and restore the owner",
				p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1), dual, p.ab.attempts, p.ab.commits)
		}
	})
}

// P5: the owner's debt clears after the requester launched an attempt but
// before its reservation. The attempt is abandoned with nothing sent and the
// owner keeps the RG.
func TestOwnerRecoversBeforeTheRequest19140(t *testing.T) {
	fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
	p := newShimPair19140(t, false)
	chargeMemberShim19140(p.a, true)
	for range 10 {
		p.exchange()
		if len(p.ab.pending) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if len(p.ab.pending) != 1 {
		t.Fatalf("setup: the requester launched %d attempts, want 1", len(p.ab.pending))
	}
	chargeMemberShim19140(p.a, false)
	p.b.handlePeerHeartbeat(p.frameFromA())
	p.runPending()
	if !p.a.IsLocalPrimary(1) || p.b.IsLocalPrimary(1) || p.ab.attempts != 0 {
		t.Fatalf("a=%v b=%v requests=%d: a recovered owner must receive no request",
			p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1), p.ab.attempts)
	}
	tr, _ := p.rounds(20)
	if tr != 0 || p.ab.attempts != 0 {
		t.Fatalf("transitions=%d requests=%d after the owner recovered", tr, p.ab.attempts)
	}
}

// P6: throttling. Every request is refused by the owner's fence. One attempt
// is in flight at a time, the next waits out the backoff, and a requester
// whose own readiness flaps between attempts does not reset that backoff.
func TestMemberShimTakeoverBacksOff19140(t *testing.T) {
	fastShim19140(t, time.Millisecond, 400*time.Millisecond, 400*time.Millisecond)
	p := newShimPair19140(t, false)
	p.ab.fence = func(int, bool) error { return errors.New("rg_active=false refused by the helper") }
	chargeMemberShim19140(p.a, true)
	p.roundsFor(100 * time.Millisecond)
	if p.ab.attempts != 1 {
		t.Fatalf("requests=%d in the first 100 ms, want exactly 1", p.ab.attempts)
	}
	p.b.SetRGReady(1, false, []string{"flap"})
	p.rounds(2)
	p.b.SetRGReady(1, true, nil)
	p.roundsFor(150 * time.Millisecond)
	if p.ab.attempts != 1 {
		t.Fatalf("requests=%d inside the backoff after a readiness flap, want still 1", p.ab.attempts)
	}
	p.roundsFor(400 * time.Millisecond)
	if p.ab.attempts != 2 {
		t.Fatalf("requests=%d after the backoff, want 2", p.ab.attempts)
	}
	if !p.a.IsLocalPrimary(1) || p.b.IsLocalPrimary(1) {
		t.Fatalf("a=%v b=%v: refused requests must leave the owner in place", p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1))
	}
}

// P7: after the takeover, the new owner is charged in turn and the old owner
// has recovered. The takeover runs the other way through the same protocol,
// so the commit pin never strands the RG on a charged node.
func TestTakeoverRunsTheOtherWay19140(t *testing.T) {
	fastShim19140(t, time.Millisecond, time.Hour, time.Hour)
	p := newShimPair19140(t, true)
	chargeMemberShim19140(p.a, true)
	p.rounds(10)
	if p.a.IsLocalPrimary(1) || !p.b.IsLocalPrimary(1) {
		t.Fatal("precondition: b took the RG")
	}
	chargeMemberShim19140(p.a, false)
	chargeMemberShim19140(p.b, true)
	tr, dual := p.rounds(10)
	if !p.a.IsLocalPrimary(1) || p.b.IsLocalPrimary(1) || tr != 1 || dual != 0 || p.ba.attempts != 1 || p.ba.commits != 1 {
		t.Fatalf("a=%v b=%v transitions=%d dual=%d requests=%d commits=%d: the recovered node must take the RG back",
			p.a.IsLocalPrimary(1), p.b.IsLocalPrimary(1), tr, dual, p.ba.attempts, p.ba.commits)
	}
}

// P8: a lone owner keeps the RG, at its weight.
func TestMemberShimDebtLoneOwnerKeepsRG19140(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{{
		ID: 1, NodePriorities: map[int]int{0: 200},
	}}})
	t.Cleanup(m.Stop)
	if !m.IsLocalPrimary(1) {
		t.Fatal("precondition: a standalone node is primary")
	}
	chargeMemberShim19140(m, true)
	if !m.IsLocalPrimary(1) {
		t.Fatal("a lone owner with member-shim debt resigned the RG; it must keep it")
	}
	if got := rgWeight9842(t, m, 1).Weight; got != 255 {
		t.Fatalf("lone owner weight = %d, want 255", got)
	}
}

// P9: the member-shim debt is listed with the RG's monitor failures (and so
// in `show chassis cluster status`) but monitorDebtTotalLocked ignores it: it
// moves no weight, alone or beside other debt. At the arm floor it would
// inherit the election paths that promote a peer at that floor whatever its
// readiness (P4 lapse-after-ack is the end-to-end form of that defect).
func TestMemberShimDebtMovesNoWeight19140(t *testing.T) {
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{{
		ID: 1, NodePriorities: map[int]int{0: 200},
	}}})
	t.Cleanup(m.Stop)
	chargeMemberShim19140(m, true)
	m.mu.RLock()
	total := m.monitorDebtTotalLocked(m.groups[1])
	m.mu.RUnlock()
	if total != 0 {
		t.Fatalf("monitorDebtTotalLocked = %d with only member-shim debt, want 0", total)
	}
	if out := m.FormatStatus(); !strings.Contains(out, RethMemberShimMonitorIface) {
		t.Fatalf("show chassis cluster status does not list %s:\n%s", RethMemberShimMonitorIface, out)
	}
	rg := rgWeight9842(t, m, 1)
	if rg.Weight != 255 {
		t.Fatalf("member-shim alone: weight = %d, want 255", rg.Weight)
	}
	listed := false
	for _, f := range rg.MonitorFails {
		listed = listed || f == RethMemberShimMonitorIface
	}
	if !listed {
		t.Fatalf("monitor failures %v: the debt must stay visible", rg.MonitorFails)
	}
	m.SetMonitorWeight(1, "ge-0-0-1", true, 100)
	if got := rgWeight9842(t, m, 1).Weight; got != 155 {
		t.Fatalf("member-shim + 100 interface debt: weight = %d, want 155", got)
	}
}
