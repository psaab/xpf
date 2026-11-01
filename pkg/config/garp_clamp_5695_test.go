package config

import (
	"strings"
	"testing"
)

// Tests for #5695 (codex-182 M16): the configured gratuitous-arp-count accepted
// an effectively UNBOUNDED value. A large count schedules a huge per-VIP
// raw-socket send budget on failover (each VIP fans the full count; the burst
// helper fans (count-1) frames over (count-1)*50ms) — a self-inflicted
// CPU/socket-exhaustion vector.
//
// The PRIMARY fix is the runtime clamp (config.GratuitousARPBurstClamp, applied
// in pkg/vrrp sendGARP and pkg/daemon directSendGARPs — tested there). This
// file covers the config layer: the clamp helper and the doctrine-aligned
// commit-time WARNING (option a — never a hard reject, since the runtime
// clamps a too-large count fine; the no-schema-only-caps doctrine forbids
// rejecting a runtime-valid count at commit).
//
// FAIL-ON-REVERT: raise GratuitousARPBurstClamp so nothing clamps, or drop the
// validateGratuitousARPCountAST call from runPreWalkGates, and the warning
// assertions below go RED.

func TestClampGratuitousARPCount_5695(t *testing.T) {
	cases := []struct {
		in          int
		wantOut     int
		wantClamped bool
	}{
		{0, 0, false},   // unset — caller applies its own >0 default
		{-5, -5, false}, // negative — upper bound only
		{1, 1, false},   // Junos min
		{3, 3, false},   // default
		{8, 8, false},   // deployed value
		{16, 16, false}, // Junos max — must pass untouched
		{GratuitousARPBurstClamp, GratuitousARPBurstClamp, false}, // exactly at bound
		{GratuitousARPBurstClamp + 1, GratuitousARPBurstClamp, true},
		{100000, GratuitousARPBurstClamp, true}, // pathological — the M16 vector
	}
	for _, tc := range cases {
		gotOut, gotClamped := ClampGratuitousARPCount(tc.in)
		if gotOut != tc.wantOut || gotClamped != tc.wantClamped {
			t.Errorf("ClampGratuitousARPCount(%d) = (%d, %v), want (%d, %v)",
				tc.in, gotOut, gotClamped, tc.wantOut, tc.wantClamped)
		}
	}
	if GratuitousARPBurstClamp < 16 {
		t.Fatalf("clamp %d must be >= the Junos 1..16 range so no legitimate config is altered",
			GratuitousARPBurstClamp)
	}
}

// TestGratuitousARPCountCommitWarning_5695 proves an over-clamp count produces a
// commit warning (accepted, not rejected) and that in-range counts do not.
func TestGratuitousARPCountCommitWarning_5695(t *testing.T) {
	hasClampWarning := func(warnings []string) bool {
		for _, w := range warnings {
			if strings.Contains(w, "gratuitous-arp-count") &&
				strings.Contains(w, "runtime safety maximum") {
				return true
			}
		}
		return false
	}

	// Over the clamp: WARN (but still compile — never reject).
	over := flatTreeFromSets(t,
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set chassis cluster redundancy-group 1 gratuitous-arp-count 100000")
	cfg, err := CompileConfig(over)
	if err != nil {
		t.Fatalf("a too-large gratuitous-arp-count must be ACCEPTED (runtime clamps it), got commit error: %v", err)
	}
	if !hasClampWarning(cfg.Warnings) {
		t.Fatalf("gratuitous-arp-count 100000 must emit the clamp warning; warnings=%v", cfg.Warnings)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "100000") && strings.Contains(w, "#5695") {
			found = true
		}
	}
	if !found {
		t.Fatalf("clamp warning must name the offending value and #5695; warnings=%v", cfg.Warnings)
	}

	// In-range counts (incl. the Junos max 16 and deployed 8): NO clamp warning.
	for _, n := range []string{"1", "3", "8", "16", "32"} {
		ok := flatTreeFromSets(t,
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster authentication-key test-cluster-psk-6611",
			"set chassis cluster control-interface em0",
			"set chassis cluster peer-address 10.99.0.2",
			"set chassis cluster redundancy-group 1 node 1 priority 100",
			"set chassis cluster redundancy-group 1 gratuitous-arp-count "+n)
		cfg, err := CompileConfig(ok)
		if err != nil {
			t.Fatalf("in-range gratuitous-arp-count %s must compile clean: %v", n, err)
		}
		if hasClampWarning(cfg.Warnings) {
			t.Fatalf("in-range gratuitous-arp-count %s must NOT warn; warnings=%v", n, cfg.Warnings)
		}
	}
}
