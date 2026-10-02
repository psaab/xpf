package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestPBRStatusEmittedWhenDataplaneUnloaded is the #4422 fail-on-revert proof:
// desired PBR rules and build-health gauges are derived from the active config
// (routing.PBRBuildRulesAndStats, a pure function — no netlink), so they must be
// emitted even with the dataplane unloaded (config-only / degraded boot). Collect
// must call collectPBRStatus BEFORE the `dp == nil || !dp.IsLoaded()` early-return;
// moving it back below the gate makes this RED. Config-derived gauges are emitted
// unconditionally so a zero-degradation state is present; the alerting hook is
// xpf_pbr_degraded_terms > 0.
func TestPBRStatusEmittedWhenDataplaneUnloaded(t *testing.T) {
	s := &Server{} // dp intentionally nil, store nil — degraded / config-only boot.
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	got := map[string]float64{}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_pbr_rules_installed", "xpf_pbr_degraded_terms":
			ms := mf.GetMetric()
			if len(ms) != 1 {
				t.Fatalf("%s: got %d metrics, want 1", mf.GetName(), len(ms))
			}
			got[mf.GetName()] = ms[0].GetGauge().GetValue()
		}
	}

	if _, ok := got["xpf_pbr_rules_installed"]; !ok {
		t.Error("xpf_pbr_rules_installed not emitted with dataplane unloaded " +
			"(collectPBRStatus must run BEFORE the dataplane gate)")
	}
	if _, ok := got["xpf_pbr_degraded_terms"]; !ok {
		t.Error("xpf_pbr_degraded_terms not emitted with dataplane unloaded")
	}
	// No active config → nothing installed, nothing degraded.
	if got["xpf_pbr_rules_installed"] != 0 {
		t.Errorf("xpf_pbr_rules_installed = %v, want 0 (no config)", got["xpf_pbr_rules_installed"])
	}
	if got["xpf_pbr_degraded_terms"] != 0 {
		t.Errorf("xpf_pbr_degraded_terms = %v, want 0 (no config)", got["xpf_pbr_degraded_terms"])
	}
}
