package userspace

import "testing"

func TestClassifyHostInboundGlobalAcceptFamilyPairing11436(t *testing.T) {
	cfg := cfgWithHostInbound("edge", []string{"ping"}, nil)
	cases := []struct {
		name     string
		proto    uint8
		icmpType uint8
		family   string
		want     HostInboundStatus
	}{
		{"icmpv4 on IPv4 remains global", 1, 3, "ip", HostInboundGlobalAccept},
		{"icmpv6 on IPv6 remains global", 58, 135, "ip6", HostInboundGlobalAccept},
		{"icmpv4 on IPv6 is zone-gated", 1, 3, "ip6", HostInboundDenied},
		{"icmpv6 on IPv4 is zone-gated", 58, 135, "ip", HostInboundDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyHostInbound(cfg, "edge", tc.proto, true, 0, u8ptr(tc.icmpType), tc.family)
			if got.Status != tc.want {
				t.Fatalf("status = %v, want %v (%+v)", got.Status, tc.want, got)
			}
		})
	}
}
