package routing

import (
	"testing"
)

// #16582: an external writer (the dataplane zone compile, an operator
// `ip link set up`) re-ups a keepalive-down tunnel while state.Up
// stays false. The old down edge (`state.Up && Failures>=MaxRetries`)
// never fired again, so the dead tunnel stayed admin UP for the rest
// of the outage. A dead tick at/past threshold must now re-down a
// link OBSERVED admin UP, and must stay silent when it is observed
// down (the steady held-down state costs no extra LinkSetDowns).

func TestKeepaliveExternalReupIsRedowned16582(t *testing.T) {
	ops := newKaOps()
	tm := &tunnelManager{ops: ops}
	state, gen := newKAState(true, 3, 1)
	dead := &fakeProber{results: []probeOutcome{{result: ProbeDead, kind: UnsupportedNone}}}

	// Threshold: exactly one LinkSetDown, Up=false.
	tickN(tm, "gr0", state, dead, gen, 0, 3)
	if ops.downs() != 1 || state.Up {
		t.Fatalf("precondition: downs=%d up=%v, want 1/false", ops.downs(), state.Up)
	}
	// Steady held-down, link observed down: no further downs.
	tickN(tm, "gr0", state, dead, gen, 0, 3)
	if ops.downs() != 1 {
		t.Fatalf("held-down steady state must not re-down an observed-down link, downs=%d", ops.downs())
	}

	// External re-up: the kernel link is admin UP again but the
	// runner still holds it down (Up=false, failures past threshold).
	ops.mu.Lock()
	ops.observedUp = true
	ops.mu.Unlock()
	var transitions []bool
	tm.setLivenessChangeCallback(func(_ string, up bool) { transitions = append(transitions, up) })

	// Next dead tick must issue a SECOND LinkSetDown.
	tm.keepaliveTick("gr0", state, dead, gen, 0)
	if ops.downs() != 2 {
		t.Fatalf("external re-up must be re-downed on next dead tick, downs=%d want 2", ops.downs())
	}
	if state.Up {
		t.Fatal("Up must stay false after re-down")
	}
	// A re-down is not a liveness transition: no callback.
	if len(transitions) != 0 {
		t.Fatalf("re-down fired liveness transitions %v, want none", transitions)
	}
	// And once observed down again, silence resumes.
	tickN(tm, "gr0", state, dead, gen, 0, 3)
	if ops.downs() != 2 {
		t.Fatalf("after re-down, held-down steady state must be silent, downs=%d", ops.downs())
	}

	// Recovery still works: one alive tick re-ups exactly once.
	alive := &fakeProber{results: []probeOutcome{{result: ProbeAlive, kind: UnsupportedNone}}}
	tm.keepaliveTick("gr0", state, alive, gen, 0)
	if ops.ups() != 1 || !state.Up {
		t.Fatalf("recovery: ups=%d up=%v, want 1/true", ops.ups(), state.Up)
	}
	if len(transitions) != 1 || !transitions[0] {
		t.Fatalf("recovery transitions = %v, want [true]", transitions)
	}
}

func TestTunnelHeldDown16582(t *testing.T) {
	mk := func(up bool, failures, maxRetries int) *tunnelManager {
		state := &KeepaliveState{Up: up, Failures: failures, MaxRetries: maxRetries}
		return &tunnelManager{keepalives: map[string]*keepaliveRunner{
			"gr-0-0-0": {state: state},
		}}
	}
	cases := []struct {
		name string
		tm   *tunnelManager
		want bool
	}{
		{"held down at threshold", mk(false, 3, 3), true},
		{"held down past threshold", mk(false, 7, 3), true},
		{"up", mk(true, 0, 3), false},
		{"down but below threshold", mk(false, 2, 3), false},
		{"no runner", &tunnelManager{keepalives: map[string]*keepaliveRunner{}}, false},
		{"nil manager", nil, false},
	}
	for _, tc := range cases {
		if got := tc.tm.TunnelHeldDown("gr-0-0-0"); got != tc.want {
			t.Errorf("%s: TunnelHeldDown=%v want %v", tc.name, got, tc.want)
		}
	}
	// Facade mirrors the domain predicate and nil-guards.
	m := &Manager{tunnel: mk(false, 3, 3)}
	if !m.TunnelHeldDown("gr-0-0-0") {
		t.Error("Manager.TunnelHeldDown must mirror the domain predicate")
	}
	var nilMgr *Manager
	if nilMgr.TunnelHeldDown("gr-0-0-0") {
		t.Error("nil Manager must answer false")
	}
}
