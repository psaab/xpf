package ra

// #12536: an explicit PREF64 lifetime (NAT64PrefixLife > 0) above the RFC 8781
// §4 maximum (65528s = 8191*8) must be DROPPED at the send sink, not encoded.
// The strict commit gate rejects such values, but tolerant Load / peer-sync
// ingress delivers them verbatim to buildRA. ndp.PREF64.marshal narrows
// round(seconds/8) to uint16 BEFORE its >8191 check, so 524284s and up wrap
// instead of failing, and the #3895 marshal probe never sees an error.
// Measured on the wire before the fix (MarshalMessage + ParseMessage):
//
//	524284, 524288, 2^31, 2^32  ->  PREF64 lifetime 0 ("do not use")
//	524300                      ->  PREF64 lifetime 16s
//	MaxInt                      ->  time.Duration overflow, lifetime 0
//
// Every assertion decodes the wire, because the defect is in the marshal: the
// built option still carries the large Duration.

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// wirePREF64_12536 builds the RA for an explicit PREF64 lifetime next to one
// control PIO, marshals it with the encoder conn.WriteTo uses, decodes it as a
// host would, and returns the decoded PREF64 (nil when dropped). The control
// PIO must survive every case: only the PREF64 may drop, never the RA.
func wirePREF64_12536(t *testing.T, life int) *ndp.PREF64 {
	t.Helper()
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface:       "trust0",
		NAT64Prefix:     "64:ff9b::/96",
		NAT64PrefixLife: life,
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
	})
	b, err := ndp.MarshalMessage(s.buildRA())
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	ra, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatalf("parsed %T, want *ndp.RouterAdvertisement", msg)
	}
	var pref64 *ndp.PREF64
	var controlPIO bool
	for _, opt := range ra.Options {
		switch o := opt.(type) {
		case *ndp.PREF64:
			if pref64 != nil {
				t.Fatal("more than one PREF64 on the wire")
			}
			pref64 = o
		case *ndp.PrefixInformation:
			if o.Prefix == netip.MustParseAddr("2001:db8::") && o.PrefixLength == 64 {
				controlPIO = true
			}
		}
	}
	if !controlPIO {
		t.Fatal("control PIO 2001:db8::/64 missing from the wire; only the PREF64 may drop")
	}
	return pref64
}

// FAIL-ON-REVERT: without the explicit-lifetime drop every row decodes a
// wrapped PREF64 (lifetime 0, or 16s for 524300) instead of no PREF64.
func TestBuildRA_12536_ExplicitPREF64OverflowPruned(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, life := range []int{524284, 524288, 524300, 1 << 31, 1 << 32, maxInt} {
		t.Run(fmt.Sprint(life), func(t *testing.T) {
			if p := wirePREF64_12536(t, life); p != nil {
				t.Fatalf("explicit lifetime %d: PREF64 on the wire with lifetime %v, want it dropped", life, p.Lifetime)
			}
		})
	}
}

// Boundary contract on the wire. Valid explicit lifetimes (multiples of 8, so
// the 8-second scaling is exact) decode unchanged. Every strict-invalid
// explicit value drops: 65529-65531 are the gray zone ndp would round down to
// 65528 (advertised as 65528 before #12536; FAIL-ON-REVERT), while 65532 and
// 100000 always failed marshal and were dropped by the #3895 probe, so those
// rows only pin that the outcome is uniform. Saturation is inherited-only
// (#12134).
func TestBuildRA_12536_ExplicitPREF64Boundaries(t *testing.T) {
	for _, life := range []int{8, 1800, 65520, 65528} {
		t.Run(fmt.Sprintf("kept_%d", life), func(t *testing.T) {
			p := wirePREF64_12536(t, life)
			if p == nil {
				t.Fatalf("valid explicit lifetime %d: PREF64 missing from the wire", life)
			}
			if got := int(p.Lifetime / time.Second); got != life {
				t.Errorf("wire PREF64 lifetime = %ds, want %ds", got, life)
			}
			if want := netip.MustParsePrefix("64:ff9b::/96"); p.Prefix != want {
				t.Errorf("wire PREF64 prefix = %v, want %v", p.Prefix, want)
			}
		})
	}
	for _, life := range []int{65529, 65530, 65531, 65532, 100000} {
		t.Run(fmt.Sprintf("dropped_%d", life), func(t *testing.T) {
			if p := wirePREF64_12536(t, life); p != nil {
				t.Fatalf("strict-invalid explicit lifetime %d: PREF64 on the wire with lifetime %v, want it dropped", life, p.Lifetime)
			}
		})
	}
}
