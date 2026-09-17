package ra

import (
	"net"
	"testing"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// #9914 F-119 fail-on-revert: LinkMTU must be saturating-clamped at the
// send sink, not advertised verbatim.
//
// Tolerant load / peer-sync can deliver values outside the strict schema
// domain, so the sink owns the final [1280, 65535] normalization.
func wireLinkMTU9914(t *testing.T, mtu int) (uint32, bool) {
	t.Helper()
	s := newSender(&config.RAInterfaceConfig{
		Interface:      "lo",
		MaxAdvInterval: 600,
		MinAdvInterval: 200,
		LinkMTU:        mtu,
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
	for _, opt := range got.Options {
		if m, ok := opt.(*ndp.MTU); ok {
			return m.MTU, true
		}
	}
	return 0, false
}

func TestLinkMTUSaturatesAtSendSink_9914(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   int
		want uint32
	}{
		{"below minimum clamps up", 1, 1280},
		{"1279 clamps up", 1279, 1280},
		{"minimum unchanged", 1280, 1280},
		{"common 1500 unchanged", 1500, 1500},
		{"jumbo 9000 unchanged", 9000, 9000},
		{"ceiling unchanged", 65535, 65535},
		{"above ceiling saturates", 65536, 65535},
		{"large typo saturates", 100000, 65535},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := wireLinkMTU9914(t, tc.in)
			if !ok {
				t.Fatalf("LinkMTU %d: no MTU option on the wire, want %d", tc.in, tc.want)
			}
			if got != tc.want {
				t.Errorf("LinkMTU %d advertised MTU %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// Unset (0) and negative LinkMTU omit the option — the documented neutral
// ("advertised link MTU, 0 = omit"). The clamp must not invent an MTU.
func TestLinkMTUUnsetOmitsOption_9914(t *testing.T) {
	for _, mtu := range []int{0, -1} {
		if got, ok := wireLinkMTU9914(t, mtu); ok {
			t.Errorf("LinkMTU %d: got MTU option %d on the wire, want omitted", mtu, got)
		}
	}
}
