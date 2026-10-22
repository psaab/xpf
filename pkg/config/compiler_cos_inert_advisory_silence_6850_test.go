package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6850: the five accepted-but-inert CoS advisories are an operator's ONLY
// signal that a knob does nothing. Every existing guard for them asserts one
// direction — that the advisory FIRES when the knob is set. None asserts that
// it stays SILENT when the knob is absent.
//
// A positive-only axis is not "mostly covered". It is covered in one direction
// and blind in the others, and the blind direction is invisible precisely
// because the tests pass: drop the `> 0` / `len(...) > 0` presence gate on any
// of these five and every pre-existing guard stays green while the advisory
// fires on configurations that never set the knob. An advisory that warns about
// a knob the operator did not configure is how the one signal they get becomes
// noise they learn to scroll past — the same harm the knob being inert causes,
// arriving by the opposite route.
//
// So each knob gets a PAIR. The negative row alone would pass if the advisory
// were deleted outright; the positive row alone is what already exists. Only
// together do they pin "fires exactly when the knob is set".
//
// Every negative fixture deliberately BUILDS THE ENCLOSING ENTITY — a
// traffic-control-profile, a scheduler, a rewrite-rules stanza — and omits only
// the knob. A fixture that omitted the whole stanza would leave the advisory's
// enclosing block unexecuted, so deleting the presence gate would change
// nothing and the cell would be a false green.
func TestInertAdvisoriesFireExactlyWhenTheKnobIsSet6850(t *testing.T) {
	// Shared CoS scaffolding so the surrounding compile paths run identically
	// in both directions of every pair.
	base := []string{
		"set class-of-service forwarding-classes class be queue-num 0",
		"set class-of-service schedulers s transmit-rate 10m",
		"set class-of-service scheduler-maps sm forwarding-class be scheduler s",
		"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
	}
	with := func(extra ...string) []string {
		return append(append([]string{}, base...), extra...)
	}

	for _, tc := range []struct {
		knob     string
		advisory string
		// setLines configures the knob; absentLines exercises the same
		// enclosing entity WITHOUT it.
		setLines    []string
		absentLines []string
	}{
		{
			knob:     "traffic-control-profiles guaranteed-rate",
			advisory: "guaranteed-rate / delay-buffer-rate are accepted",
			setLines: with(
				"set class-of-service traffic-control-profiles p shaping-rate 100m",
				"set class-of-service traffic-control-profiles p guaranteed-rate 50m",
			),
			// The profile still exists and still carries a shaping-rate, so the
			// loop over TrafficControlProfiles runs. Only the inert knob is gone.
			absentLines: with(
				"set class-of-service traffic-control-profiles p shaping-rate 100m",
			),
		},
		{
			knob:     "traffic-control-profiles delay-buffer-rate",
			advisory: "guaranteed-rate / delay-buffer-rate are accepted",
			setLines: with(
				"set class-of-service traffic-control-profiles p shaping-rate 100m",
				"set class-of-service traffic-control-profiles p delay-buffer-rate 20m",
			),
			absentLines: with(
				"set class-of-service traffic-control-profiles p shaping-rate 100m",
			),
		},
		{
			knob:     "rewrite-rules inet-precedence",
			advisory: "rewrite-rules inet-precedence is accepted for compatibility but inert",
			setLines: with(
				"set class-of-service rewrite-rules inet-precedence r forwarding-class be loss-priority low code-point 000",
			),
			// A dscp rewrite-rule instead: the rewrite-rules subtree is
			// populated and compiled, but no inet-precedence rule exists.
			absentLines: with(
				"set class-of-service rewrite-rules dscp r forwarding-class be loss-priority low code-point 000000",
			),
		},
		{
			knob:     "rewrite-rules exp",
			advisory: "rewrite-rules exp is accepted for compatibility but inert",
			setLines: with(
				"set class-of-service rewrite-rules exp r forwarding-class be loss-priority low code-point 000",
			),
			absentLines: with(
				"set class-of-service rewrite-rules dscp r forwarding-class be loss-priority low code-point 000000",
			),
		},
		{
			knob:     "scheduler codel-target",
			advisory: "codel-target is accepted for compatibility but inert",
			setLines: with(
				"set class-of-service schedulers s2 transmit-rate 5m",
				"set class-of-service schedulers s2 codel-target 5",
			),
			// s2 still exists and is still walked by the scheduler loop; it
			// simply has no codel-target.
			absentLines: with(
				"set class-of-service schedulers s2 transmit-rate 5m",
			),
		},
		{
			knob:     "priority-low-min-share",
			advisory: "priority-low-min-share is accepted for compatibility but inert",
			setLines: with(
				"set class-of-service interfaces ge-0/0/0 priority-low-min-share 10m",
			),
			absentLines: base,
		},
	} {
		t.Run(tc.knob+"/SET fires", func(t *testing.T) {
			if !advisoryPresent6850(t, tc.advisory, tc.setLines) {
				t.Fatalf("#6850: %s is set but its accepted-but-inert advisory did not "+
					"fire — the operator's only signal that the knob does nothing is gone",
					tc.knob)
			}
		})
		t.Run(tc.knob+"/ABSENT stays silent", func(t *testing.T) {
			if advisoryPresent6850(t, tc.advisory, tc.absentLines) {
				t.Fatalf("#6850: %s is NOT configured, yet its inert advisory fired. "+
					"An advisory that warns about a knob the operator never set trains "+
					"them to ignore the one signal they get — the same harm the inert "+
					"knob causes, by the opposite route", tc.knob)
			}
		})
	}
}

func advisoryPresent6850(t *testing.T, advisory string, lines []string) bool {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range lines {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := config.SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	for _, w := range config.ValidateConfig(cfg) {
		if strings.Contains(w, advisory) {
			return true
		}
	}
	return false
}
