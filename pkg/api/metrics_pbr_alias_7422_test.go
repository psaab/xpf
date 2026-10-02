package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// #7422 row 12: xpf_pbr_rules_installed is a DEPRECATED ALIAS of
// xpf_pbr_rules_desired, and the two must carry the SAME VALUE.
//
// TWO EXISTENCE CHECKS WOULD NOT DO. "Both metrics are emitted" is satisfied by
// two independent computations that agree today and drift tomorrow — an alias
// that drifts is two metrics with one name's worth of trust, and the drift is
// invisible because each is individually plausible. So this asserts equality of
// the VALUES, and production emits both from a single PBRBuildRulesAndStats
// result so they cannot differ.
//
// The alias points at _desired, never at _applied. Redefining a published
// metric's meaning under existing alert expressions is the same hazard as
// redefining a wire field across a version skew: the consumer is unchanged, the
// semantics move underneath it, and neither side reports the switch. Renaming
// outright fails to an alert that STOPS FIRING — invisible until it is needed.
func TestPBRInstalledIsAnAliasOfDesired7422(t *testing.T) {
	s := &Server{} // degraded / config-only boot, as the #4422 cell uses.
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	got := map[string]float64{}
	seen := map[string]bool{}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_pbr_rules_installed", "xpf_pbr_rules_desired", "xpf_pbr_rules_applied", "xpf_pbr_rules_mismatched":
			seen[mf.GetName()] = true
			ms := mf.GetMetric()
			if len(ms) != 1 {
				t.Fatalf("%s: got %d metrics, want 1", mf.GetName(), len(ms))
			}
			got[mf.GetName()] = ms[0].GetGauge().GetValue()
		}
	}

	if !seen["xpf_pbr_rules_installed"] {
		t.Fatal("xpf_pbr_rules_installed must still be emitted — it is a published " +
			"name and removing it breaks existing alert expressions silently")
	}
	if !seen["xpf_pbr_rules_desired"] {
		t.Fatal("xpf_pbr_rules_desired must be emitted as the honest name for the " +
			"config-derived value")
	}

	// THE ASSERTION THAT MATTERS: same value, not merely both present.
	if got["xpf_pbr_rules_installed"] != got["xpf_pbr_rules_desired"] {
		t.Fatalf("xpf_pbr_rules_installed (%v) and xpf_pbr_rules_desired (%v) must "+
			"carry the SAME value — _installed is an alias, and an alias that drifts "+
			"is two metrics with one name's worth of trust",
			got["xpf_pbr_rules_installed"], got["xpf_pbr_rules_desired"])
	}

	// Readback metrics are omitted together if either family listing fails.
	// Environment availability is intentionally not asserted; if occupancy is
	// present, the mismatch gauge must be present from the same complete read.
	if seen["xpf_pbr_rules_applied"] != seen["xpf_pbr_rules_mismatched"] {
		t.Fatalf("band occupancy and mismatch readbacks must be emitted together, got applied=%v mismatched=%v",
			seen["xpf_pbr_rules_applied"], seen["xpf_pbr_rules_mismatched"])
	}
}
