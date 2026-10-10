// #12193 — the Prefix Information valid/preferred lifetimes reached ndp's
// UNSIGNED marshal with no runtime bound.
//
// The typed-leaf schema bounds both to [0, 0xffffffff] at strict commit, and
// that gate is STRICT-only: the tolerant Load / peer-sync ingress downgrades
// it to a warning, so an oversized value arrives intact. The compiler stores
// bare Atoi values, and buildRA converted them straight to
// time.Duration(seconds)*time.Second. ndp then marshals
// uint32(lifetime.Seconds()), so a configured 2^32 lands on the wire as 0 —
// "expired", timing the on-link prefix out immediately (RFC 4861 §6.3.4) —
// and 2^32+k lands as k. Worse, values above ~9.22e9 seconds overflow
// time.Duration itself before ndp ever sees them.
//
// The header, MTU, and VRRP sinks were already clamped under the same
// doctrine (#8597, #9914); PIO was the outlier.
//
// Measured on the wire before the fix (ndp.MarshalMessage of buildRA):
//
//	ValidLifetime = 4294967296  ->  PIO Valid Lifetime 0
//	ValidLifetime = 4294967297  ->  PIO Valid Lifetime 1
//	ValidLifetime = 1<<40       ->  garbage (Duration overflow + float wrap)
package ra

import (
	"net"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// wirePIO marshals a built RA carrying a single PIO and returns the valid and
// preferred lifetimes as the peer would decode them.
//
// It goes through ndp.MarshalMessage + ParseMessage rather than reading the
// struct back, because the defect is in the MARSHAL: a large Duration in the
// struct looks large, and only becomes 0 on the wire.
func wirePIO(t *testing.T, valid, pref int) (uint32, uint32) {
	t.Helper()
	s := newSender(&config.RAInterfaceConfig{
		Interface:      "lo",
		MaxAdvInterval: 600,
		MinAdvInterval: 200,
		Prefixes: []*config.RAPrefix{
			{
				Prefix:        "2001:db8::/64",
				OnLink:        true,
				Autonomous:    true,
				ValidLifetime: valid,
				PreferredLife: pref,
			},
		},
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
	var pi *ndp.PrefixInformation
	for _, opt := range got.Options {
		if p, ok := opt.(*ndp.PrefixInformation); ok {
			if pi != nil {
				t.Fatal("more than one PIO on the wire, want exactly one")
			}
			pi = p
		}
	}
	if pi == nil {
		t.Fatal("no PIO on the wire (dropped or never emitted)")
	}
	return uint32(pi.ValidLifetime / time.Second),
		uint32(pi.PreferredLifetime / time.Second)
}

// TestOversizedPIOLifetimesSaturate_12193 is the RED-on-revert core. Above
// the 32-bit field width the lifetimes saturate at 0xffffffff ("infinity")
// rather than wrapping: 2^32 used to marshal as 0, which times the on-link
// prefix out immediately per RFC 4861 §6.3.4.
func TestOversizedPIOLifetimesSaturate_12193(t *testing.T) {
	const maxPIO = uint32(0xffffffff)
	for _, tc := range []struct {
		name      string
		valid     int
		pref      int
		wantValid uint32
		wantPref  uint32
	}{
		// The defect marker: exactly 2^32 wrapped to 0 on the wire.
		{"two_pow_32_wraps_to_zero", 1 << 32, 7200, maxPIO, 7200},
		// 2^32+k wrapped to k; both lifetimes saturate together.
		{"two_pow_32_plus_k", (1 << 32) + 1004, (1 << 32) + 7, maxPIO, maxPIO},
		// Past the time.Duration range (~9.22e9 s): the int must be
		// clamped BEFORE the Duration conversion, or the conversion
		// itself overflows and ndp marshals garbage.
		{"beyond_duration_range", 1 << 40, 1 << 40, maxPIO, maxPIO},
		// 0xffffffff is RFC 4861 "infinity" and must pass through bit-exact.
		{"infinity_exact", 0xffffffff, 0xffffffff, maxPIO, maxPIO},
		// In-range values are byte-identical (no behavior change).
		{"ordinary_pair", 86400, 14400, 86400, 14400},
		// <=0 keeps the SLAAC-default semantics.
		{"defaults_preserved", 0, 0, defaultValidLifetime, defaultPreferredLifetime},
		{"negative_lifetimes_keep_defaults", -1, -1, defaultValidLifetime, defaultPreferredLifetime},
		// The pre-existing #2271 pref<=valid clamp still holds.
		{"pref_over_valid_clamps", 100, 200, 100, 100},
		// A defaulted preferred life under a saturated valid life is
		// untouched (604800 <= 0xffffffff).
		{"saturated_valid_default_pref", 1 << 32, 0, maxPIO, defaultPreferredLifetime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotValid, gotPref := wirePIO(t, tc.valid, tc.pref)
			if gotValid != tc.wantValid {
				t.Errorf("PIO Valid Lifetime = %d on the wire for a configured %d, "+
					"want %d; an oversized value must SATURATE, not wrap",
					gotValid, tc.valid, tc.wantValid)
			}
			if gotPref != tc.wantPref {
				t.Errorf("PIO Preferred Lifetime = %d on the wire for a configured %d, "+
					"want %d", gotPref, tc.pref, tc.wantPref)
			}
			if gotPref > gotValid {
				t.Errorf("wire PIO has Preferred %d > Valid %d; RFC 4861 §4.6.2 "+
					"requires Preferred <= Valid", gotPref, gotValid)
			}
		})
	}
}
