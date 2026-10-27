package lldp

import (
	"strings"
	"testing"
	"time"
)

// #17130: EffectiveTiming is the single source of truth for the
// interval × hold formula. The commit-legal extreme 32768×10 must
// clamp to the 16-bit wire TTL (65535) exactly as encodeTTL does, not
// print/advertise 327680. RED without the clamp: ttlSeconds would be
// 327680 (and 16384×4 would be 65536).
func TestEffectiveTimingClampsHoldTime17130(t *testing.T) {
	cases := []struct {
		name         string
		cfg          *LLDPConfig
		wantInterval time.Duration
		wantHold     int
		wantTTL      int
	}{
		{"ieee-extreme", &LLDPConfig{Interval: 32768, HoldMultiplier: 10}, 32768 * time.Second, 10, 65535},
		{"just-over-max", &LLDPConfig{Interval: 16384, HoldMultiplier: 4}, 16384 * time.Second, 4, 65535},
		{"exact-max", &LLDPConfig{Interval: 13107, HoldMultiplier: 5}, 13107 * time.Second, 5, 65535},
		{"in-range", &LLDPConfig{Interval: 15, HoldMultiplier: 5}, 15 * time.Second, 5, 75},
		{"defaults-unset", &LLDPConfig{}, 30 * time.Second, 4, 120},
		{"defaults-nil", nil, 30 * time.Second, 4, 120},
		{"defaults-negative", &LLDPConfig{Interval: -5, HoldMultiplier: -1}, 30 * time.Second, 4, 120},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interval, holdMult, ttl := EffectiveTiming(tc.cfg)
			if interval != tc.wantInterval || holdMult != tc.wantHold || ttl != tc.wantTTL {
				t.Fatalf("EffectiveTiming(%+v) = (%v, %d, %d), want (%v, %d, %d)",
					tc.cfg, interval, holdMult, ttl, tc.wantInterval, tc.wantHold, tc.wantTTL)
			}
		})
	}
}

// #17130: RenderSummary prints the clamped hold time, and is the sole
// renderer of the "Hold time:" line for both show surfaces.
func TestRenderSummaryPrintsClampedHoldTime17130(t *testing.T) {
	cfg := &LLDPConfig{
		Interval:       32768,
		HoldMultiplier: 10,
		Interfaces:     []LLDPInterface{{Name: "ge-0/0/0"}, {Name: "ge-0/0/1", Disable: true}},
	}
	var b strings.Builder
	RenderSummary(&b, cfg, 2)
	out := b.String()
	for _, want := range []string{
		"LLDP:\n",
		"  Transmit interval: 32768s\n",
		"  Hold multiplier:   10\n",
		"  Hold time:         65535s\n",
		"  Interfaces:        ge-0/0/0, ge-0/0/1 (disabled)\n",
		"  Neighbors:         2\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderSummary output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "327680") {
		t.Errorf("RenderSummary printed unclamped hold time:\n%s", out)
	}

	// Negative neighbour count omits the count line.
	var b2 strings.Builder
	RenderSummary(&b2, cfg, -1)
	if strings.Contains(b2.String(), "Neighbors:") {
		t.Errorf("negative neighbours must omit count line:\n%s", b2.String())
	}

	// Nil and disabled keep the prior surfaces' lines verbatim.
	var b3 strings.Builder
	RenderSummary(&b3, nil, -1)
	if b3.String() != "LLDP not configured\n" {
		t.Errorf("nil cfg = %q, want not-configured line", b3.String())
	}
	var b4 strings.Builder
	RenderSummary(&b4, &LLDPConfig{Disable: true}, -1)
	if b4.String() != "LLDP: disabled\n" {
		t.Errorf("disabled cfg = %q, want disabled line", b4.String())
	}
}
