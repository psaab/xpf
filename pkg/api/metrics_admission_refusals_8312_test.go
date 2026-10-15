package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// #8312: bind the WIRING of the admission-refusal metric.
//
// A cell that only checked `Limiter.Refusals()` would pass while the exported
// series was never emitted, or emitted from a different limiter, or emitted
// with a constant — which is the shape that leaves an instrument present and
// inert. These drive the real collector and read the real samples.

func collectAdmissionRefusals8312(t *testing.T) map[string]float64 {
	t.Helper()
	c := newCollector(nil)
	ch := make(chan prometheus.Metric, 32)
	c.emitAdmissionRefusals(ch)
	close(ch)

	out := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if !strings.Contains(m.Desc().String(), "xpf_admission_refusals_total") {
			continue
		}
		label := ""
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == "limiter" {
				label = lp.GetValue()
			}
		}
		out[label] = pb.GetCounter().GetValue()
	}
	return out
}

// TestAdmissionRefusalsMetricTracksTheRealLimiter8312 is the wiring bind: a
// refusal on the process-wide SessionWalkLimiter must move the exported series
// for THAT label and no other.
//
// The other-labels assertion is the half that matters. A collector that emitted
// one limiter's count under every label, or hardcoded a value, satisfies "the
// session_walk series moved" — only the cross-label comparison separates them.
//
// MUTATION: emit `float64(diagcmd.SessionWalkLimiter.Refusals())` for every
// label instead of `l.limiter.Refusals()` -> the remote_walk assertion reds.
// Drop the `emitAdmissionRefusals` call from Collect -> the descriptor-coverage
// canary stays green (Describe/Collect are consistent either way) and only this
// cell notices, which is why it drives the emitter rather than a scrape.
func TestAdmissionRefusalsMetricTracksTheRealLimiter8312(t *testing.T) {
	before := collectAdmissionRefusals8312(t)
	for _, want := range []string{"session_walk", "remote_walk", "diagnostic"} {
		if _, ok := before[want]; !ok {
			t.Fatalf("no sample for limiter=%q; the metric must be emitted for every "+
				"limiter at ZERO too, or 'never refused' is indistinguishable from "+
				"'not scraped' — which is the answer this issue most needs to see", want)
		}
	}

	// Drive a REAL refusal on the process-wide session-walk limiter by filling
	// it, then asserting the refusal actually happened.
	var held []func()
	for i := 0; i < diagcmd.MaxConcurrentSessionWalks; i++ {
		rel, err := diagcmd.SessionWalkLimiter.Acquire()
		if err != nil {
			break
		}
		held = append(held, rel)
	}
	defer func() {
		for _, rel := range held {
			rel()
		}
	}()
	if len(held) != diagcmd.MaxConcurrentSessionWalks {
		t.Skipf("could not fill the shared limiter (%d/%d held; another test holds slots) — "+
			"skipping rather than asserting against a state the fixture did not reach",
			len(held), diagcmd.MaxConcurrentSessionWalks)
	}
	if _, err := diagcmd.SessionWalkLimiter.Acquire(); err == nil {
		t.Fatal("the limiter must be at capacity here, or no refusal is produced " +
			"and the assertion below is vacuous")
	}

	after := collectAdmissionRefusals8312(t)
	if got, want := after["session_walk"], before["session_walk"]+1; got != want {
		t.Errorf("limiter=session_walk refusals = %v, want %v — the exported series "+
			"does not track diagcmd.SessionWalkLimiter.Refusals()", got, want)
	}
	// The refusal was on session_walk ONLY. A collector reading one limiter for
	// every label passes the assertion above and fails this one.
	if got := after["remote_walk"]; got != before["remote_walk"] {
		t.Errorf("limiter=remote_walk refusals moved from %v to %v on a session_walk "+
			"refusal; the labels are not reading their own limiters", before["remote_walk"], got)
	}
	if got := after["diagnostic"]; got != before["diagnostic"] {
		t.Errorf("limiter=diagnostic refusals moved from %v to %v on a session_walk "+
			"refusal", before["diagnostic"], got)
	}
}

// TestAdmissionRefusalsDescriptorIsDeclared8312 pins that the Desc reaches
// Describe. The whole-collector coverage canary would catch an emitted-but-
// undeclared Desc at scrape time; this names the family so a failure says which
// one, and it is the cheap half of the same guarantee.
//
// MUTATION: remove `c.describeAdmissionRefusals(ch)` from Describe -> reds.
func TestAdmissionRefusalsDescriptorIsDeclared8312(t *testing.T) {
	c := newCollector(nil)
	ch := make(chan *prometheus.Desc, 1024)
	c.Describe(ch)
	close(ch)
	for d := range ch {
		if strings.Contains(d.String(), "xpf_admission_refusals_total") {
			return
		}
	}
	t.Error("xpf_admission_refusals_total is not declared in Describe(); the collector " +
		"is checked, so emitting it would error the scrape")
}
