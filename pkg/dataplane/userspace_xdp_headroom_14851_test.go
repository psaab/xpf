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
//
// #14954 EXCEPTION (deliberate, measured, time-boxed by review): the
// GRE-inner fragment/declared-length/LAND guards are a Critical
// security fix that cannot wait for an entry-path headroom
// restructure. The regenerated object measures 873042 processed
// insns (12.70% headroom) and is installed OVERRIDDEN. This pin is
// therefore inverted to REQUIRE exactly that recorded state — a
// measured OVERRIDDEN verdict at 12.70% — so the exception cannot
// silently widen: any other verdict (PASS at a different count, a
// lower headroom, an unmeasured install) fails here and forces a
// fresh deliberate decision. Remove this exception when the shim
// next clears the 15% floor.
//
// #15645 SUPERSEDES the recorded count: the tracked 873042 object
// verifier-REJECTED on guest kernel 7.0.0 (processed 1000001 insns)
// and a fresh pinned build on this host rejected identically, so the
// shim's trace recorder was outlined behind a packed 5-argument
// subprogram (see the #15645 note in lib.rs). The regenerated object
// LOADS on this host at 920733 processed insns (7.93% headroom) and
// is installed OVERRIDDEN under the same exception shape: exactly
// this measured count, nothing else. 7.93% is worse than the #14954
// figure it replaces — the honest trade is recorded in
// docs/log/15645.md: a loadable object below the floor over an
// unloadable one above it. The exception must not silently widen
// further; any other count forces a fresh deliberate decision.
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
	if v.Stats.ProcessedInsns <= 0 || v.ObjectSHA256 == "" {
		t.Fatalf("#14851: shipped verdict carries no measurement (processed=%d sha=%q)", v.Stats.ProcessedInsns, v.ObjectSHA256)
	}
	if !v.Stats.Measured {
		t.Fatalf("#14851/#14954: shipped verdict is unmeasured; an unmeasured install is never acceptable")
	}
	// #14954/#15645 exception: exactly the measured OVERRIDDEN state
	// recorded for #15645. PASS at/above the floor also satisfies the
	// gate (the exception is a floor, not a ceiling on headroom).
	if v.Verdict == "PASS" && !v.OverrideConsumed && v.Stats.HeadroomPct >= v.Stats.FloorPct {
		return
	}
	if v.Verdict != "OVERRIDDEN" || !v.OverrideConsumed {
		t.Fatalf("#14851/#15645: shipped gate verdict is %q (override_consumed=%v); want measured PASS or the recorded #15645 OVERRIDDEN exception", v.Verdict, v.OverrideConsumed)
	}
	if v.Stats.ProcessedInsns != 920733 {
		t.Fatalf("#15645: OVERRIDDEN object measures %d processed insns; the recorded exception is exactly 920733 (7.93%%). A different count is a new object and needs a fresh deliberate decision", v.Stats.ProcessedInsns)
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
		"try_xdp_userspace",
		"is_interface_nat_destination",
		"live_userspace_session_action",
		// #15645: the packed trace callee. It carries the whole trace
		// value construction + map insert; if it re-inlines into the
		// trace call sites the object returns to the 1M reject.
		"record_trace_packed",
		// #15854: the three outlines that restored PASS headroom
		// (815623 processed insns, 18.44%) after the #15843 LAND gate
		// pushed the object to 963340 / guest-kernel reject. The
		// merged readiness trace is what makes binding_ready_slot
		// pay; re-inlining any of these re-spends the per-calling-
		// state walk (docs/log/15854.md).
		"land_gate",
		"wg_zone_admits_packet",
		"binding_ready_slot",
	} {
		want := "#[inline(never)]\nfn " + fn + "("
		if !strings.Contains(src, want) {
			t.Errorf("#14851/#15645: %s lost its #[inline(never)] outline; re-inlining it re-spends verifier states at every call site (see the #14851/#15645 notes in lib.rs)", fn)
		}
	}
}
