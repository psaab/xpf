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
			e.Apply([]*config.EventPolicy{pol})

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("HandleEvent panicked on nil within clause: %v (#9916 F-135)", r)
				}
			}()
			// Drive enough events to cross any threshold if the gate were open.
			for i := 0; i < 5; i++ {
				e.HandleEvent(rpm.Event{Name: "ping_probe_failed", TestOwner: "o", TestName: "t"})
			}
			// Fail closed: nothing queued (worker never runs a commit; queue stays empty).
			// Drain-check via Stats (no worker started? HandleEvent starts it; Close drains post-fix).
			// The panic is the RED; the no-fire is the fail-closed pin. Since HandleEvent
			// enqueues on fire and the worker would consume async, assert via evaluateEvent
			// directly (synchronous, no worker): must not trigger.
			got := e.evaluateEvent(rpm.Event{Name: "ping_probe_failed", TestOwner: "o", TestName: "t"})
			if len(got) != 0 {
				t.Fatalf("nil within clause fired %d policies; must fail CLOSED (#9916 F-135)", len(got))
			}
		})
	}
}
