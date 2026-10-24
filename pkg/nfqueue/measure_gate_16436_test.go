package nfqueue

import (
	"os"
	"strings"
	"testing"
)

// TestMeasureFragmentsDefaultNoDurationGate16436 pins #16436 clause 1: the
// default M4 run must not carry a duration-ratio pass criterion. The gate
// text must only fire behind the opt-in measurement flag.
func TestMeasureFragmentsDefaultNoDurationGate16436(t *testing.T) {
	src, err := os.ReadFile("measure_fragments_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	// Default leg: the fatal must be conditioned on the opt-in flag, so an
	// unguarded `if loadedP99 >` would fail this cell.
	if !strings.Contains(text, "measureHOL && loadedP99 > 5*maxInt64(baseP99, 1)") {
		t.Fatalf("M4 HOL fatal is not guarded by the opt-in measurement flag:\n%s", text)
	}
	if !strings.Contains(text, `os.Getenv("XPF_NFQUEUE_MEASURE_HOL")`) {
		t.Fatalf("M4 opt-in flag XPF_NFQUEUE_MEASURE_HOL not consulted:\n%s", text)
	}
	// The deterministic FragPool verdict must remain in the default suite.
	for _, want := range []string{"ErrFragmentCapacity", "CapacityDrops != 1", "survives"} {
		if !strings.Contains(text, want) {
			t.Fatalf("M4 deterministic FragPool check %q missing from default suite", want)
		}
	}
}

// TestRequireNetNSParentReportsPass16436 pins #16436 clause 2: the parent of
// a passing netns child must report PASS, not SKIP. It exercises the real
// requireNetNS parent path with a trivially passing child test.
func TestRequireNetNSParentReportsPass16436(t *testing.T) {
	if os.Getenv("XPF_NFQUEUE_IN_NETNS") != "" {
		// Child leg: requireNetNS runs the body directly after loopback-up.
		return
	}
	if !requireNetNS(t) {
		return
	}
	// requireNetNS returned normally, so this parent reports PASS. On the
	// defective harness it ended with t.Skip("netns child completed").
	// Also pin the harness source: no Skip-on-success remains.
	harness, err := os.ReadFile("harness_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(harness), `t.Skip("netns child completed")`) {
		t.Fatalf("requireNetNS still ends a successful child with t.Skip")
	}
}
