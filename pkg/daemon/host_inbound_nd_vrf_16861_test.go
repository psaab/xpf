package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16861: a zone interface that is a routing-instance (VRF) member
// presents NDISC to LOCAL_IN as iifname=<member> with sdif unset
// (vrf_ip6_rcv keeps skb->dev = member for NDISC). The #15931 scoped
// ND admit keyed only on iifname=<master> meta sdifname=<member>
// therefore never matches a unicast NA/NS to the firewall, and the
// packet falls to the zone catch-all drop. Each VRF scope must ALSO
// admit ND keyed on the member as iifname, in steady state and in the
// fences, while an `ndp except` view on a VRF member still drops ND.
//
// RED pre-fix: no ND line names the member as a bare iifname (the
// member appears only after `meta sdifname`).

func ndVRFViews16861() []dpuserspace.ZoneHostInboundView {
	return []dpuserspace.ZoneHostInboundView{
		{Zone: "trust", SystemServices: []string{"ssh"}, V6Addrs: []string{"2001:db8:1::1"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-blue", Slaves: []string{"ge-0-0-1"}}}},
		{Zone: "except", SystemServices: []string{"ssh"}, ProtocolsExcept: []string{"ndp"}, V6Addrs: []string{"2001:db8:2::1"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-red", Slaves: []string{"ge-0-0-2"}}}},
	}
}

// hasMemberIIFND reports a ND accept whose iifname is the member
// itself (not the master, not via sdifname).
func hasMemberIIFND(payload, member string) bool {
	for _, l := range strings.Split(payload, "\n") {
		if strings.Contains(l, `iifname "`+member+`"`) &&
			strings.Contains(l, "133, 134, 135, 136") && strings.Contains(l, "accept") &&
			!strings.Contains(l, "sdifname") {
			return true
		}
	}
	return false
}

func TestNDVRFMemberIIFNameAdmit16861(t *testing.T) {
	views := ndVRFViews16861()
	steady := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	// Defect cell: retaining VRF member admits unicast + multicast ND
	// by its own iifname (NDISC identity).
	if !hasMemberIIFND(steady, "ge-0-0-1") {
		t.Fatalf("steady: VRF member lost member-iifname ND admit (NDISC identity):\n%s", steady)
	}
	// Preservation: the master+sdif scoped admit stays (non-NDISC
	// enslaved ingress still presents master/sdif).
	foundScoped := false
	for _, l := range strings.Split(steady, "\n") {
		if strings.Contains(l, `"vrf-blue"`) && strings.Contains(l, "sdifname") &&
			strings.Contains(l, "133, 134, 135, 136") && strings.Contains(l, "accept") {
			foundScoped = true
		}
		// The member admit must not widen to the master alone.
		if strings.Contains(l, `iifname "vrf-blue"`) && !strings.Contains(l, "sdifname") &&
			strings.Contains(l, "133, 134, 135, 136") && strings.Contains(l, "accept") {
			t.Fatalf("steady: ND admit widened to bare VRF master: %q", l)
		}
	}
	if !foundScoped {
		t.Fatalf("steady: master+sdif ND admit lost:\n%s", steady)
	}
	// Except cell: the ndp-except VRF view gains no ND admit on any
	// scope — neither master+sdif nor member-iifname.
	for _, l := range ndLines15931(steady) {
		if strings.Contains(l, "ge-0-0-2") || strings.Contains(l, "vrf-red") {
			t.Fatalf("steady: ndp-except VRF view admitted ND: %q\n%s", l, steady)
		}
	}
	// Fences: same member-iifname admission, same except withdrawal.
	for name, fence := range map[string]string{
		"cold-boot": buildHostInboundFencePayload(views, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}),
		"gap":       buildHostInboundGapFencePayload(views, nil, []string{"2001:db8:1::9"}, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil),
	} {
		if !hasMemberIIFND(fence, "ge-0-0-1") {
			t.Fatalf("%s fence: VRF member lost member-iifname ND admit:\n%s", name, fence)
		}
		for _, l := range ndLines15931(fence) {
			if strings.Contains(l, "ge-0-0-2") || strings.Contains(l, "vrf-red") {
				t.Fatalf("%s fence: ndp-except VRF view admitted ND: %q", name, l)
			}
		}
	}
	// Ordering (fence): the member-iifname multicast ND admit must
	// precede the member-iifname ff02 drop in the fence, or the drop
	// shadows it.
	fence := buildHostInboundFencePayload(views, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{})
	admit := strings.Index(fence, `iifname "ge-0-0-1" ip6 daddr ff02::/16 icmpv6 type { 133, 134, 135, 136 } accept`)
	drop := strings.Index(fence, `iifname "ge-0-0-1" ip6 daddr ff02::/16 drop`)
	if admit < 0 {
		t.Fatalf("fence: member-iifname multicast ND admit missing:\n%s", fence)
	}
	if drop >= 0 && admit > drop {
		t.Fatalf("fence: member-iifname ND admit shadowed by ff02 drop:\n%s", fence)
	}
}
