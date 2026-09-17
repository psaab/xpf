package eventengine

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// #9916 F-135: nil *EventWithin must fail closed, not panic HandleEvent.
//
// withinMatches and pruneWindow dereference the clause with no nil test while two
// of the four consumers do check. No reachable producer today (compiler always
// appends non-nil); defense-in-depth per #3751. A nil entry in a non-empty list is
// malformed (missing is len==0), so the policy must not fire.
func TestNilWithinClauseFailsClosed9916(t *testing.T) {
	cases := map[string][]*config.EventWithin{
		"sole-nil":   {nil},
		"nil-first":  {nil, {Seconds: 60, TriggerOn: 2}},
		"nil-second": {{Seconds: 60, TriggerOn: 2}, nil},
	}
	for name, clauses := range cases {
		t.Run(name, func(t *testing.T) {
			pol := &config.EventPolicy{
				Name:          "p9916",
				Events:        []string{"ping_probe_failed"},
				WithinClauses: clauses,
			}
			e := New(nil, nil)
			defer e.Close()
			// Apply before evaluate: without it the event index is empty and the
			// cell passes vacuously (never evaluates).
			applyPolicies9984(e, []*config.EventPolicy{pol})

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("evaluation panicked on nil within clause: %v (#9916 F-135)", r)
				}
			}()
			// Assert EVERY synchronous evaluation fails closed — including the
			// threshold-crossing event (index 1 for TriggerOn:2 with the valid
			// sibling). Checking only the last would hide an early erroneous fire:
			// it would arm onLatched and suppress the rest, certifying a fail-open.
			ev := rpm.Event{Name: "ping_probe_failed", TestOwner: "o", TestName: "t"}
			for i := range 5 {
				if got := e.evaluateEvent(ev); len(got) != 0 {
					t.Fatalf("evaluation %d fired %d policies with a nil clause; must fail CLOSED every time (#9916 F-135)", i, len(got))
				}
			}
			// Probe-path smoke: HandleEvent (async worker) must not panic either.
			// No queue assertion here — the synchronous loop above is the fail-closed
			// pin; this covers the probe-goroutine entry the issue names.
			e.HandleEvent(ev)
		})
	}
}
