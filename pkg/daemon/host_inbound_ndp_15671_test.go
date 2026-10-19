package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #15671: kernel-chain ND default accept is withdrawn only when a
// view carries `protocols ndp except`; the per-zone ndp token admits
// ND through the SSOT render.
func TestHostInboundNDPExceptWithdrawsGlobalAccept15671(t *testing.T) {
	mk := func(except []string) []dpuserspace.ZoneHostInboundView {
		return []dpuserspace.ZoneHostInboundView{{
			Zone:            "trust",
			Protocols:       []string{"ospf"},
			ProtocolsExcept: except,
			V6Addrs:         []string{"2001:db8::1"},
		}}
	}
	withND := buildHostInboundFilterPayload(mk(nil), nil, nil, nil, nil, false)
	if !strings.Contains(withND, "icmpv6 type { 133, 134, 135, 136 }") {
		t.Fatalf("default payload missing ND accept:\n%s", withND)
	}
	withoutND := buildHostInboundFilterPayload(mk([]string{"ndp"}), nil, nil, nil, nil, false)
	if strings.Contains(withoutND, "icmpv6 type { 133, 134, 135, 136 }") {
		t.Fatalf("ndp-except payload still globally accepts ND:\n%s", withoutND)
	}
	// Per-zone ndp token admits ND scoped to the zone addresses.
	ndpViews := []dpuserspace.ZoneHostInboundView{{
		Zone: "trust", Protocols: []string{"ndp"}, V6Addrs: []string{"2001:db8::1"},
	}}
	ndpPayload := buildHostInboundFilterPayload(ndpViews, nil, nil, nil, nil, false)
	if !strings.Contains(ndpPayload, "icmpv6 type { 133, 134, 135, 136 }") {
		t.Fatalf("ndp-token payload missing ND admit:\n%s", ndpPayload)
	}
	// Fence oracle follows the same withdrawal.
	fence := buildHostInboundFencePayload(mk([]string{"ndp"}), nil, nil, nil, nil, nil, nil, dhcpBackstopLists{})
	if strings.Contains(fence, "icmpv6 type { 133, 134, 135, 136 }") {
		t.Fatalf("ndp-except fence still accepts ND:\n%s", fence)
	}
}
