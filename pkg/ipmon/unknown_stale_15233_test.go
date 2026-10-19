package ipmon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/rpm"
)

// TestUnknownSeedNotKnown15233 is the A49-01 regression (#15233).
//
// rpm seeds every test LastStatus:"unknown" before any probe verdict.
// seedResultsLocked created failedTests[probe] for any result, and
// Status() keyed Known on mere presence — so Apply(cfg, unknown-seed)
// reported Known=true and FormatStatus rendered "Status: PASS" for a
// policy whose probe never produced a verdict. Track known only from
// pass/fail results.
func TestUnknownSeedNotKnown15233(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), []*rpm.ProbeResult{
		{ProbeName: "WAN", TestName: "wan-a", LastStatus: "unknown"},
	})
	st := e.Status()
	if len(st) != 1 {
		t.Fatalf("want 1 policy, got %d", len(st))
	}
	if st[0].Known {
		t.Fatal("A49-01: unknown seed must not mark policy Known")
	}
	if st[0].Failed {
		t.Fatal("unknown seed must not mark policy Failed")
	}
	var buf strings.Builder
	FormatStatus(&buf, st)
	if !strings.Contains(buf.String(), "Status: UNKNOWN") {
		t.Fatalf("unknown seed must render UNKNOWN:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "Status: PASS") {
		t.Fatalf("unknown seed rendered PASS:\n%s", buf.String())
	}
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("unknown seed must not inject overlay, got %+v", got)
	}

	// PASS only after a pass verdict.
	e.HandleTransition(rpm.Transition{
		ProbeName: "WAN", TestName: "wan-a", Status: "pass", Generation: 1,
		Results: []*rpm.ProbeResult{{ProbeName: "WAN", TestName: "wan-a", LastStatus: "pass"}},
	})
	st = e.Status()
	if !st[0].Known {
		t.Fatal("policy still Unknown after a pass verdict")
	}
	buf.Reset()
	FormatStatus(&buf, st)
	if !strings.Contains(buf.String(), "Status: PASS") {
		t.Fatalf("known-passing policy not rendered PASS:\n%s", buf.String())
	}
}

// TestStaleVersionedSnapshotIgnored15233 is the A49-03 regression (#15233).
//
// A FAIL transition (generation 2) lands, then a stale unversioned-in-effect
// snapshot taken before it (generation 1, still showing pass) is applied
// via ApplyVersioned — as reconcileIPMon does with rpm.ResultsVersioned().
// The stale snapshot must not overwrite the FAIL verdict or withdraw the
// failover overlay.
func TestStaleVersionedSnapshotIgnored15233(t *testing.T) {
	e, _ := newTestEngine(nil)
	cfg := testPolicyConfig()
	e.Apply(cfg, passResults())

	// FAIL transition at generation 2.
	e.HandleTransition(rpm.Transition{
		ProbeName: "WAN", TestName: "wan-a", Status: "fail", Generation: 2,
		Results: []*rpm.ProbeResult{
			{ProbeName: "WAN", TestName: "wan-a", LastStatus: "fail"},
			{ProbeName: "WAN", TestName: "wan-b", LastStatus: "pass"},
		},
	})
	if !e.Status()[0].Failed {
		t.Fatal("setup: policy not FAILED after fail transition")
	}
	overlayBefore := e.ActiveOverlay()
	if len(overlayBefore) != 2 {
		t.Fatalf("setup: overlay = %+v, want 2 routes", overlayBefore)
	}

	// Stale snapshot (generation 1 < 2) showing pass — must be ignored.
	e.ApplyVersioned(cfg, passResults(), 1)
	st := e.Status()[0]
	if !st.Failed {
		t.Fatal("A49-03: stale snapshot recovered FAILED policy")
	}
	if !st.Known {
		t.Fatal("A49-03: stale snapshot cleared Known")
	}
	if got := e.ActiveOverlay(); len(got) != 2 {
		t.Fatalf("A49-03: stale snapshot withdrew overlay: %+v", got)
	}

	// A fresher snapshot (generation 3) showing pass DOES recover.
	e.ApplyVersioned(cfg, passResults(), 3)
	if e.Status()[0].Failed {
		t.Fatal("fresh pass snapshot did not recover policy")
	}
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("fresh pass snapshot left overlay %+v", got)
	}
}

// TestStaleSnapshotUnknownProbeNotKnown15233 pins that a versioned
// snapshot carrying only unknown rows does not mark Known even when fresh.
func TestFreshUnknownVersionedNotKnown15233(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.ApplyVersioned(testPolicyConfig(), []*rpm.ProbeResult{
		{ProbeName: "WAN", TestName: "wan-a", LastStatus: "unknown"},
	}, 5)
	if e.Status()[0].Known {
		t.Fatal("fresh unknown snapshot must not mark Known")
	}
}
