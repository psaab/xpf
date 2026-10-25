package ipmon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/rpm"
)

// TestMixedKnownUnknown16632 is the R3-A49-02 regression (#16632).
//
// A policy whose probe has two tests — wan-a with a pass verdict and
// wan-b held forever without a verdict (rpm seeds it LastStatus
// "unknown": setup hold, pin failure, source not local) — was reported
// as passing: Status() keyed Known on ANY known test of the probe, and
// FormatStatus printed a single wildcard "* PASS" row whenever no test
// was failing. wan-b was never named, so an operator or scraper
// checking failover readiness saw PASS while one monitored uplink was
// not being measured.
//
// Acceptance: the defect cell names wan-b as UNKNOWN and does not
// print "* PASS"; the all-known control is unchanged.
func TestMixedKnownUnknown16632(t *testing.T) {
	e, _ := newTestEngine(nil)
	e.Apply(testPolicyConfig(), []*rpm.ProbeResult{
		{ProbeName: "WAN", TestName: "wan-a", LastStatus: "pass"},
		{ProbeName: "WAN", TestName: "wan-b", LastStatus: "unknown"},
	})
	st := e.Status()
	if len(st) != 1 {
		t.Fatalf("want 1 policy, got %d", len(st))
	}
	if st[0].Failed {
		t.Fatal("mixed known/unknown must not be FAILED")
	}
	if len(st[0].FailingTests) != 0 {
		t.Fatalf("FailingTests = %v, want none", st[0].FailingTests)
	}
	if len(st[0].UnknownTests) != 1 || st[0].UnknownTests[0] != "wan-b" {
		t.Fatalf("UnknownTests = %v, want [wan-b]", st[0].UnknownTests)
	}
	// PARTIAL: at least one verdict exists, so the policy is not wholly
	// UNKNOWN, but it is not PASS either.
	if st[0].Known {
		t.Fatal("policy with a verdict-less test must not be Known (would render PASS)")
	}

	var buf strings.Builder
	FormatStatus(&buf, st)
	out := buf.String()
	if !strings.Contains(out, "Status: PARTIAL") {
		t.Fatalf("mixed known/unknown must render PARTIAL:\n%s", out)
	}
	if strings.Contains(out, "* PASS") || strings.Contains(out, "Status: PASS") {
		t.Fatalf("mixed known/unknown rendered as PASS:\n%s", out)
	}
	if !strings.Contains(out, "wan-b") || !strings.Contains(out, "UNKNOWN") {
		t.Fatalf("defect cell must name wan-b as UNKNOWN:\n%s", out)
	}
	// The known passing test is named too — one row per test.
	if !strings.Contains(out, "wan-a") {
		t.Fatalf("known passing test wan-a must be named:\n%s", out)
	}
	if got := e.ActiveOverlay(); got != nil {
		t.Fatalf("unknown test must not inject overlay, got %+v", got)
	}

	// Control: both tests known-passing — unchanged PASS rendering,
	// no UnknownTests, no PARTIAL.
	e2, _ := newTestEngine(nil)
	e2.Apply(testPolicyConfig(), passResults())
	st2 := e2.Status()
	if !st2[0].Known || len(st2[0].UnknownTests) != 0 {
		t.Fatalf("all-known control: Known=%v UnknownTests=%v, want true/[]", st2[0].Known, st2[0].UnknownTests)
	}
	buf.Reset()
	FormatStatus(&buf, st2)
	if !strings.Contains(buf.String(), "Status: PASS") || strings.Contains(buf.String(), "PARTIAL") {
		t.Fatalf("all-known control must render PASS unchanged:\n%s", buf.String())
	}

	// Control: a failing test still renders FAIL and names the failure,
	// even alongside a verdict-less sibling.
	e3, _ := newTestEngine(nil)
	e3.Apply(testPolicyConfig(), []*rpm.ProbeResult{
		{ProbeName: "WAN", TestName: "wan-a", LastStatus: "fail"},
		{ProbeName: "WAN", TestName: "wan-b", LastStatus: "unknown"},
	})
	st3 := e3.Status()
	if !st3[0].Failed || len(st3[0].FailingTests) != 1 || st3[0].FailingTests[0] != "wan-a" {
		t.Fatalf("failing control: %+v", st3[0])
	}
	if len(st3[0].UnknownTests) != 1 || st3[0].UnknownTests[0] != "wan-b" {
		t.Fatalf("failing control UnknownTests = %v, want [wan-b]", st3[0].UnknownTests)
	}
	buf.Reset()
	FormatStatus(&buf, st3)
	out3 := buf.String()
	if !strings.Contains(out3, "Status: FAIL") {
		t.Fatalf("failing control must render FAIL:\n%s", out3)
	}
	if !strings.Contains(out3, "wan-b") || !strings.Contains(out3, "UNKNOWN") {
		t.Fatalf("failing control must still name wan-b UNKNOWN:\n%s", out3)
	}
}
