package dataplane

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// #14851: the shipped gate verdict must be a measured PASS, not an
// OVERRIDDEN install. Before this fix the tracked object measured
// 908732 processed insns (9.13% headroom) and was installed with
// XPF_SHIM_ALLOW_LOW_HEADROOM=1, so the verdict recorded OVERRIDDEN
// while the shim's true margin stayed below the #4555 floor. This
// test pins the shipped record: it fails on the pre-fix artifact
// (verdict OVERRIDDEN, override consumed) and passes only when the
// regenerated object clears the floor on its own measurement.
func TestShimGateVerdictIsMeasuredPass14851(t *testing.T) {
	raw, err := os.ReadFile("userspace_xdp_gate_verdict.json")
	if err != nil {
		t.Fatalf("read gate verdict: %v", err)
	}
	var v struct {
		Verdict          string `json:"verdict"`
		OverrideConsumed bool   `json:"override_consumed"`
		ObjectSHA256     string `json:"object_sha256"`
		Stats            struct {
			Measured       bool    `json:"measured"`
			ProcessedInsns int     `json:"processed_insns"`
			HeadroomPct    float64 `json:"headroom_pct"`
			FloorPct       float64 `json:"floor_pct"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse gate verdict: %v", err)
	}
	if v.Verdict != "PASS" || v.OverrideConsumed {
		t.Fatalf("#14851: shipped gate verdict is %q (override_consumed=%v); the tracked object must clear the #4555 floor without XPF_SHIM_ALLOW_LOW_HEADROOM", v.Verdict, v.OverrideConsumed)
	}
	if !v.Stats.Measured || v.Stats.HeadroomPct < v.Stats.FloorPct {
		t.Fatalf("#14851: shipped verdict stats measured=%v headroom=%.2f%% floor=%.1f%%; want a measured headroom at or above the floor", v.Stats.Measured, v.Stats.HeadroomPct, v.Stats.FloorPct)
	}
	if v.Stats.ProcessedInsns <= 0 || v.ObjectSHA256 == "" {
		t.Fatalf("#14851: shipped verdict carries no measurement (processed=%d sha=%q)", v.Stats.ProcessedInsns, v.ObjectSHA256)
	}
}

// #14851: the three helpers whose outlining bought the headroom back
// must stay outlined. They are map-touching helpers reached from many
// call sites; re-inlining any of them re-spends the per-calling-state
// verifier walk at every site and silently returns the object to
// OVERRIDDEN territory (no test fails, the gate just gets overridden
// again). The source is read directly because the property is the
// attribute itself — the same source-pin shape the shim's other
// verifier-cost invariants use.
func TestShimHeadroomOutlinesStayOutlined14851(t *testing.T) {
	raw, err := os.ReadFile("../../userspace-xdp/src/lib.rs")
	if err != nil {
		t.Fatalf("read shim source: %v", err)
	}
	src := string(raw)
	for _, fn := range []string{
		"incr_fallback_stat",
		"is_interface_nat_destination",
		"live_userspace_session_action",
	} {
		want := "#[inline(never)]\nfn " + fn + "("
		if !strings.Contains(src, want) {
			t.Errorf("#14851: %s lost its #[inline(never)] outline; re-inlining it re-spends verifier states at every call site (see the #14851 note in lib.rs)", fn)
		}
	}
}
