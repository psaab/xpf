package ra

// #12653: an explicit PREF64 lifetime below 8s (1-3s) used to reach the wire
// as 0. ndp encodes the RFC 8781 Scaled Lifetime with round(seconds/8), so
// 1-3s round to scaled 0 — which tells hosts the NAT64 prefix is no longer
// usable (delete), the exact opposite of "advertise briefly". This is
// pre-existing on master (from PR #12564 fold).
//
// Every assertion decodes the wire (MarshalMessage + ParseMessage), because
// the defect is in the marshal: the built option still carries 1-3s.
//
// Fix contract: every valid explicit lifetime rounds UP to the next 8s
// quantum (never down to 0 for a positive value, never down/early-expiry),
// so 1-8s -> 8s, 9s -> 16s, non-multiples like 1800 -> 1808s. Unset (<=0)
// still inherits and dropped overflow (>65528) still drops (#12536).

import (
	"fmt"
	"testing"
	"time"
)

func TestBuildRA_12653_ExplicitTinyPREF64LifetimeNotZeroOnWire(t *testing.T) {
	cases := []struct {
		life int
		want int // decoded seconds; -1 means PREF64 must be dropped
	}{
		{0, 1800}, // unset/default inherits the standard router lifetime
		{1, 8},
		{2, 8},
		{3, 8},
		{4, 8},
		{5, 8},
		{6, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{15, 16},
		{16, 16},
		{17, 24},
		{64, 64},
		{1800, 1800}, // exact multiple of 8
		{65521, 65528},
		{65528, 65528},
		{65529, -1}, // #12536 drop retained
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("life_%d", tc.life), func(t *testing.T) {
			p := wirePREF64_12536(t, tc.life)
			if tc.want < 0 {
				if p != nil {
					t.Fatalf("explicit lifetime %ds: PREF64 on wire with lifetime %v, want dropped", tc.life, p.Lifetime)
				}
				return
			}
			if p == nil {
				t.Fatalf("explicit lifetime %ds: PREF64 missing from wire, want %ds", tc.life, tc.want)
			}
			if got := int(p.Lifetime / time.Second); got != tc.want {
				t.Errorf("explicit lifetime %ds: wire PREF64 lifetime = %ds, want %ds (ceil to 8s)", tc.life, got, tc.want)
			}
			if p.Lifetime == 0 {
				t.Errorf("explicit lifetime %ds decoded as 0 (usable-prefix deletion)", tc.life)
			}
		})
	}
}
