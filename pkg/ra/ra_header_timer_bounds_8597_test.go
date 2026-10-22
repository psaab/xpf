package ra

import (
	"net"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K72) — the three RA header timers reached ndp's UNSIGNED
// marshal with no runtime bound.
//
// The typed-leaf schema bounds all three to [0, max] at strict commit, and that
// gate is STRICT-only: the tolerant Load / peer-sync ingress downgrades it to a
// warning per #1960, so a negative or oversized value arrives intact.
//
// Measured on the wire before the fix:
//
//	DefaultLifetime = -1  ->  Router Lifetime 65535  (~18 hours)
//	ReachableTime   = -1  ->  4294967295 ms          (~49 days)
//	RetransTimer    = -1  ->  4294967295 ms
//
// A NEGATIVE router lifetime advertised this box as a default router for the
// MAXIMUM the field can express. `pruneUnmarshalableOptions` probes only the
// OPTIONS for a marshal abort; the header fields marshal without complaint
// precisely because they wrap silently.
//
// #4525 put a runtime floor on the advertisement INTERVAL for exactly this
// ingress. The header timers were not covered.

// wireRAHeader marshals a built RA and returns the three header timer fields as
// the peer would decode them.
//
// It goes through ndp.MarshalMessage + ParseMessage rather than reading the
// struct back, because the defect is in the MARSHAL: a negative Duration in the
// struct is visibly negative, and only becomes 65535 on the wire.
func wireRAHeader(t *testing.T, lifetime, reachable, retrans int) (uint16, uint32, uint32) {
	t.Helper()
	s := newSender(&config.RAInterfaceConfig{
		Interface:          "lo",
		DefaultLifetime:    lifetime,
		DefaultLifetimeSet: true,
		ReachableTime:      reachable,
		RetransTimer:       retrans,
		MaxAdvInterval:     600,
		MinAdvInterval:     200,
	}, &net.Interface{Name: "lo", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}})
	ra := s.buildRA()
	if ra == nil {
		t.Fatal("buildRA returned nil")
	}
	b, err := ndp.MarshalMessage(ra)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	got, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatalf("parsed %T, want *ndp.RouterAdvertisement", msg)
	}
	return uint16(got.RouterLifetime / time.Second),
		uint32(got.ReachableTime / time.Millisecond),
		uint32(got.RetransmitTimer / time.Millisecond)
}

// TestNegativeRAHeaderTimersDoNotWrapToTheMaximum_8597 is the RED-on-revert
// core. Reverting either clamp puts 65535 / 4294967295 back on the wire.
func TestNegativeRAHeaderTimersDoNotWrapToTheMaximum_8597(t *testing.T) {
	life, reach, retrans := wireRAHeader(t, -1, -1, -1)
	if life != 0 {
		t.Errorf("Router Lifetime = %d on the wire for a configured -1, want 0. A "+
			"negative lifetime advertising this box as a default router for %d seconds "+
			"is the OPPOSITE of what a nonsensical value should mean; 0 is the field's "+
			"own documented neutral (\"not a default router\")", life, life)
	}
	if reach != 0 {
		t.Errorf("Reachable Time = %d ms on the wire for a configured -1, want 0 "+
			"(the RFC 4861 \"unspecified\" sentinel)", reach)
	}
	if retrans != 0 {
		t.Errorf("Retrans Timer = %d ms on the wire for a configured -1, want 0", retrans)
	}
}

// TestOversizedRAHeaderTimersSaturate_8597: above the field width, the value
// saturates rather than wrapping. 70000 seconds used to marshal as 70000-65536
// = 4464 — a lifetime an order of magnitude SHORTER than asked for, which
// expires hosts' default route early.
func TestOversizedRAHeaderTimersSaturate_8597(t *testing.T) {
	life, _, _ := wireRAHeader(t, config.RARouterMaxLifetimeSeconds+4465, 0, 0)
	if life != config.RARouterMaxLifetimeSeconds {
		t.Errorf("Router Lifetime = %d on the wire, want the field maximum %d; an "+
			"oversized value must SATURATE, not wrap (the pre-fix value wrapped to 4464)",
			life, config.RARouterMaxLifetimeSeconds)
	}
}

// TestValidRAHeaderTimersAreUnchanged_8597 is the OVER-BROAD control. A clamp
// that flattened every timer, or that rejected the boundary, would satisfy the
// cells above and break every real RA.
func TestValidRAHeaderTimersAreUnchanged_8597(t *testing.T) {
	for _, tc := range []struct {
		life, reach, retrans int
	}{
		{1800, 30000, 1000},
		{0, 0, 0}, // the documented "not a default router" / "unspecified" case
		{config.RARouterMaxLifetimeSeconds, config.RAReachableRetransMaxMillis, config.RAReachableRetransMaxMillis},
		{1, 1, 1},
	} {
		life, reach, retrans := wireRAHeader(t, tc.life, tc.reach, tc.retrans)
		if int(life) != tc.life || int64(reach) != int64(tc.reach) || int64(retrans) != int64(tc.retrans) {
			t.Errorf("in-range (%d, %d, %d) marshalled as (%d, %d, %d); a valid value must "+
				"reach the wire exactly, including the boundary",
				tc.life, tc.reach, tc.retrans, life, reach, retrans)
		}
	}
}

// TestRAHeaderClampsBindTheSchemaConstants_8597 pins the agreement rather than
// a literal. The gate and the sender must not be able to disagree about where
// the ceiling is; a copied 65535 in the sender would drift the day the schema
// changed.
func TestRAHeaderClampsBindTheSchemaConstants_8597(t *testing.T) {
	if got := clampRAHeaderSeconds(config.RARouterMaxLifetimeSeconds); got != config.RARouterMaxLifetimeSeconds {
		t.Errorf("clampRAHeaderSeconds rejected the schema's own maximum: %d", got)
	}
	if got := clampRAHeaderSeconds(config.RARouterMaxLifetimeSeconds + 1); int64(got) != config.RARouterMaxLifetimeSeconds {
		t.Errorf("clampRAHeaderSeconds(max+1) = %d, want %d", got, config.RARouterMaxLifetimeSeconds)
	}
	if got := clampRAHeaderMillis(config.RAReachableRetransMaxMillis); int64(got) != config.RAReachableRetransMaxMillis {
		t.Errorf("clampRAHeaderMillis rejected the schema's own maximum: %d", got)
	}
	// And the strict gate still enforces the same range, so the runtime clamp
	// is a belt rather than the only bound.
	if err := config.ValidateInteger(0, config.RARouterMaxLifetimeSeconds)("-1"); err == nil {
		t.Error("the strict typed-leaf gate accepts a negative router lifetime; the " +
			"tolerant/strict split this clamp exists for no longer holds")
	}
}
