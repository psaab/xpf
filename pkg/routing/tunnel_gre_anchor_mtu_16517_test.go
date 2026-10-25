package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16517: the native-GRE anchor is a TUN that kept the kernel default
// MTU of 1500 when no MTU was configured, and adoption reset it to 1500.
// The local-origin encap guard refuses every outer larger than the
// transport MTU, so inner 1477-1500 (IPv4 outer, unkeyed) / 1457-1500
// (IPv6 outer) were silently dropped with no PTB back into the TUN.
// The fix defaults the anchor MTU from the underlay minus GRE overhead,
// mirroring wgTunMTUForEndpoint / Rust native_gre_inner_mtu:
// 1500-24=1476 (v4 unkeyed), 1500-28=1472 (v4 keyed),
// 1500-44=1456 (v6 unkeyed), 1500-48=1452 (v6 keyed).

func greAnchorTC(name, src, dst string) *config.TunnelConfig {
	return &config.TunnelConfig{
		Name: name, AnchorOnly: true, Mode: config.TunnelModeGRE,
		Source: src, Destination: dst,
	}
}

func TestAnchorDesiredMTU16517(t *testing.T) {
	cases := []struct {
		name string
		tc   *config.TunnelConfig
		want int
		ok   bool
	}{
		{"v4 unkeyed", greAnchorTC("gr-0-0-0", "192.0.2.1", "198.51.100.1"), 1476, true},
		{"v6 unkeyed", greAnchorTC("gr-0-0-0", "2001:db8::1", "2001:db8::2"), 1456, true},
		{"ip6gre v6", func() *config.TunnelConfig {
			tc := greAnchorTC("gr-0-0-0", "2001:db8::1", "2001:db8::2")
			tc.Mode = config.TunnelModeIP6GRE
			return tc
		}(), 1456, true},
		{"unset mode v4", func() *config.TunnelConfig {
			tc := greAnchorTC("gr-0-0-0", "192.0.2.1", "198.51.100.1")
			tc.Mode = config.TunnelModeUnset
			return tc
		}(), 1476, true},
		{"v4 keyed", func() *config.TunnelConfig {
			tc := greAnchorTC("gr-0-0-0", "192.0.2.1", "198.51.100.1")
			tc.Key = 7
			return tc
		}(), 1472, true},
		{"v6 keyed", func() *config.TunnelConfig {
			tc := greAnchorTC("gr-0-0-0", "2001:db8::1", "2001:db8::2")
			tc.Key = 7
			return tc
		}(), 1452, true},
		{"configured 1400 wins", func() *config.TunnelConfig {
			tc := greAnchorTC("gr-0-0-0", "192.0.2.1", "198.51.100.1")
			tc.MTU = 1400
			return tc
		}(), 1400, true},
		{"ipip no derived", func() *config.TunnelConfig {
			tc := greAnchorTC("ip-0-0-0", "192.0.2.1", "198.51.100.1")
			tc.Mode = config.TunnelModeIPIP
			return tc
		}(), 0, false},
		{"no endpoints no derived", anchorTC("gr-0-0-0"), 0, false},
		{"nil", nil, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := anchorDesiredMTU(c.tc)
			if got != c.want || ok != c.ok {
				t.Fatalf("anchorDesiredMTU = (%d,%v), want (%d,%v)", got, ok, c.want, c.ok)
			}
		})
	}
}

// RED on pre-fix master: create wrote no MTU (kernel 1500 stood).
func TestGREAnchorCreateDefaultsMTU16517(t *testing.T) {
	for _, c := range []struct {
		name, src, dst string
		want           int
	}{
		{"v4", "192.0.2.1", "198.51.100.1", 1476},
		{"v6", "2001:db8::1", "2001:db8::2", 1456},
	} {
		t.Run(c.name, func(t *testing.T) {
			ops := newFakeLinkOps()
			tm, _ := newReconcileManager(ops)
			if err := tm.Apply([]*config.TunnelConfig{greAnchorTC("gr-0-0-0", c.src, c.dst)}); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != c.want {
				t.Fatalf("create MTU writes = %v, want exactly [%d]", got, c.want)
			}
			if got := ops.links["gr-0-0-0"].Attrs().MTU; got != c.want {
				t.Fatalf("live MTU = %d, want %d", got, c.want)
			}
			// Second (owned) apply must not rewrite: live == derived.
			if err := tm.Apply([]*config.TunnelConfig{greAnchorTC("gr-0-0-0", c.src, c.dst)}); err != nil {
				t.Fatalf("Apply 2: %v", err)
			}
			if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 {
				t.Fatalf("owned reuse rewrote MTU: %v", got)
			}
		})
	}
}

// The acceptance control: an explicitly configured 1400 is unchanged.
func TestGREAnchorConfiguredMTUUnchanged16517(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	tc := greAnchorTC("gr-0-0-0", "192.0.2.1", "198.51.100.1")
	tc.MTU = 1400
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 1400 {
		t.Fatalf("configured create MTU writes = %v, want [1400]", got)
	}
}

// RED on pre-fix master: adoption wrote [1500].
func TestGREAnchorAdoptionDefaultsMTU16517(t *testing.T) {
	ops := newFakeLinkOps()
	seedAnchor(ops, "gr-0-0-0", 42, 1476) // correctly reduced device
	tm, _ := newReconcileManager(ops)
	if err := tm.Apply([]*config.TunnelConfig{greAnchorTC("gr-0-0-0", "192.0.2.1", "198.51.100.1")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 0 {
		t.Fatalf("adoption of an already-1476 GRE anchor wrote MTU %v, want no write (pre-fix: [1500])", got)
	}
}

// Anchors created before the fix sit at 1500 and are OWNED on the next
// apply (never adopted again): owned reuse must lower them once, and
// must never raise a smaller hand-set MTU.
func TestGREAnchorOwnedReuseLowersStale1500_16517(t *testing.T) {
	ops := newFakeLinkOps()
	tm, _ := newReconcileManager(ops)
	tc := greAnchorTC("gr-0-0-0", "192.0.2.1", "198.51.100.1")
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 1: %v", err)
	}
	// Simulate a pre-fix anchor: kernel default restored out-of-band.
	ops.links["gr-0-0-0"].Attrs().MTU = 1500
	ops.mtuSet["gr-0-0-0"] = nil
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 1476 {
		t.Fatalf("owned reuse of stale-1500 GRE anchor wrote %v, want [1476]", got)
	}
	// A smaller hand-set MTU is never raised.
	ops.links["gr-0-0-0"].Attrs().MTU = 1400
	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
		t.Fatalf("Apply 3: %v", err)
	}
	if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 {
		t.Fatalf("owned reuse raised a hand-set 1400: %v", got)
	}
	if got := ops.links["gr-0-0-0"].Attrs().MTU; got != 1400 {
		t.Fatalf("live MTU = %d, want 1400 untouched", got)
	}
}
