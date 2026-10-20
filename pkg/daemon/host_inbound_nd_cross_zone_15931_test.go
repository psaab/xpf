package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #15931 two-view fixture: zone A excludes ND (`protocols all` +
// `ndp except`, the compiled positive set below), zone B retains the
// ND default (ssh only, no ND token, no exclusion). Each zone owns a
// distinct IPv6 destination and a distinct ingress netdev, the shape
// BuildZoneHostInboundViews produces for real interfaces.
func ndCrossZoneViews15931() []dpuserspace.ZoneHostInboundView {
	return []dpuserspace.ZoneHostInboundView{
		{
			Zone:            "zonea",
			SystemServices:  []string{"ssh"},
			Protocols:       []string{"ospf"},
			ProtocolsExcept: []string{"ndp"},
			V6Addrs:         []string{"2001:db8:a::1"},
			IngressNetdevs:  []string{"ge-a"},
		},
		{
			Zone:           "zoneb",
			SystemServices: []string{"ssh"},
			V6Addrs:        []string{"2001:db8:b::1"},
			IngressNetdevs: []string{"ge-b"},
		},
	}
}

func ndLines15931(payload string) []string {
	var out []string
	for _, l := range strings.Split(payload, "\n") {
		if strings.Contains(l, "133, 134, 135, 136") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// B-scoped NS (ICMPv6 135, in the 133-136 set) is admitted on B's
// ingress; no ND accept may name A's ingress, A's addresses alone, or
// be unscoped (which would re-admit A). A's own catch-all still drops.
func TestNDExceptScopedToOwningView15931(t *testing.T) {
	views := ndCrossZoneViews15931()
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	nd := ndLines15931(payload)
	if len(nd) == 0 {
		t.Fatalf("two-view payload lost B's ND admission entirely:\n%s", payload)
	}
	for _, l := range nd {
		if !strings.Contains(l, `"ge-b"`) {
			t.Errorf("ND accept not scoped to B's ingress (admits A or unscoped): %q\n%s", l, payload)
		}
		if strings.Contains(l, "ge-a") {
			t.Errorf("ND accept reaches excluding zone A: %q", l)
		}
	}
	// A's ingress catch-all still denies everything unmatched on A.
	if !strings.Contains(payload, `iifname "ge-a"`) || !strings.Contains(payload, "drop") {
		t.Fatalf("A's ingress deny missing:\n%s", payload)
	}
	// Control: no exclusion anywhere -> B-style default still scoped per
	// retaining view (and the single-view default is preserved).
	single := buildHostInboundFilterPayload(views[1:], nil, nil, nil, nil, true)
	if len(ndLines15931(single)) == 0 {
		t.Fatalf("default-only payload lost ND admission:\n%s", single)
	}
	// Control: every view excludes -> no ND accept at all.
	allExcluded := ndCrossZoneViews15931()
	allExcluded[1].ProtocolsExcept = []string{"ndp"}
	if got := ndLines15931(buildHostInboundFilterPayload(allExcluded, nil, nil, nil, nil, true)); len(got) != 0 {
		t.Fatalf("all-excluded payload still admits ND: %v", got)
	}
}

// Cold-boot fence preserves B: the fence (no per-service accepts) must
// carry B's scoped ND admit ahead of its address drops, and no ND
// admit for A. The gap fence shares the same mandatory admits.
func TestNDExceptColdBootFencePreservesB15931(t *testing.T) {
	views := ndCrossZoneViews15931()
	fence := buildHostInboundFencePayload(views, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{})
	nd := ndLines15931(fence)
	if len(nd) == 0 {
		t.Fatalf("cold-boot fence dropped B's ND admission:\n%s", fence)
	}
	for _, l := range nd {
		if !strings.Contains(l, `"ge-b"`) || strings.Contains(l, "ge-a") {
			t.Errorf("fence ND admit not B-scoped: %q\n%s", l, fence)
		}
	}
	gap := buildHostInboundGapFencePayload(views, []string{"2001:db8:b::9"}, nil, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil)
	if len(ndLines15931(gap)) == 0 {
		t.Fatalf("gap fence dropped B's ND admission:\n%s", gap)
	}
	// No views (no config yet): the mandatory unscoped admit remains.
	if len(ndLines15931(buildHostInboundFencePayload(nil, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}))) == 0 {
		t.Fatal("config-less fence must keep the mandatory ND admit")
	}
}

// The scoped ND admits reference the aggregate counter in the steady
// chain (F4/B3: counted, verified in TestNDMulticastRetainingViews15931
// for the multicast form); the counter object is also declared
// unconditionally so the fence's counterless form stays legal.
func TestNDScopedAcceptKeepsCounterDeclared15931(t *testing.T) {
	payload := buildHostInboundFilterPayload(ndCrossZoneViews15931(), nil, nil, nil, nil, true)
	if !strings.Contains(payload, "counter xpfhia_icmp6_nd {") {
		t.Fatalf("ND accept counter no longer declared:\n%s", payload)
	}
}

// Triple-review fold: multicast ND cells.
// Retaining views (B ssh, E empty-token, A except as control) admit
// ff02::/16 ND on their own ingress in steady state AND through the
// cold-boot fence; the excluding view never does. Admitted multicast
// ND carries the named counter (steady state only; fences are
// counterless by #5719).
func ndMulticastViews15931() []dpuserspace.ZoneHostInboundView {
	return []dpuserspace.ZoneHostInboundView{
		{Zone: "zonea", SystemServices: []string{"ssh"}, Protocols: []string{"ospf"}, ProtocolsExcept: []string{"ndp"}, V6Addrs: []string{"2001:db8:a::1"}, IngressNetdevs: []string{"ge-a"}},
		{Zone: "zoneb", SystemServices: []string{"ssh"}, V6Addrs: []string{"2001:db8:b::1"}, IngressNetdevs: []string{"ge-b"}},
		{Zone: "zonee", V6Addrs: []string{"2001:db8:e::1"}, IngressNetdevs: []string{"ge-e"}},
	}
}

func hasNDMulticastOn(payload, dev string) bool {
	for _, l := range strings.Split(payload, "\n") {
		if strings.Contains(l, `"`+dev+`"`) && strings.Contains(l, "ff02::/16") &&
			strings.Contains(l, "133, 134, 135, 136") && strings.Contains(l, "accept") {
			return true
		}
	}
	return false
}

func TestNDMulticastRetainingViews15931(t *testing.T) {
	views := ndMulticastViews15931()
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	if !hasNDMulticastOn(payload, "ge-b") {
		t.Fatalf("steady: ssh retaining view lost multicast ND:\n%s", payload)
	}
	if !hasNDMulticastOn(payload, "ge-e") {
		t.Fatalf("steady: empty-token (no-stanza) retaining view lost multicast ND (B1):\n%s", payload)
	}
	if hasNDMulticastOn(payload, "ge-a") {
		t.Fatalf("steady: excluding view admitted multicast ND:\n%s", payload)
	}
	// Counted (F4/B3): steady multicast ND accept references the counter.
	found := false
	for _, l := range strings.Split(payload, "\n") {
		if strings.Contains(l, "ff02::/16") && strings.Contains(l, "133, 134, 135, 136") && strings.Contains(l, "accept") {
			if !strings.Contains(l, "xpfhia_icmp6_nd") {
				t.Fatalf("steady multicast ND accept uncounted: %q", l)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no steady multicast ND accept found")
	}
	// Cold-boot fence: same retaining admission, uncounted, no A.
	fence := buildHostInboundFencePayload(views, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{})
	if !hasNDMulticastOn(fence, "ge-b") || !hasNDMulticastOn(fence, "ge-e") {
		t.Fatalf("fence: retaining views lost multicast ND (B2):\n%s", fence)
	}
	if hasNDMulticastOn(fence, "ge-a") {
		t.Fatalf("fence: excluding view admitted multicast ND:\n%s", fence)
	}
	if strings.Contains(fence, "xpfhia_icmp6_nd") {
		t.Fatalf("fence must stay counterless (#5719):\n%s", fence)
	}
	// Ordering: fence multicast admit precedes the ff02 drop on same ingress.
	bAdmit := strings.Index(fence, `iifname "ge-b" ip6 daddr ff02::/16 icmpv6 type { 133, 134, 135, 136 } accept`)
	bDrop := strings.Index(fence, `iifname "ge-b" ip6 daddr ff02::/16 drop`)
	if bAdmit < 0 || (bDrop >= 0 && bAdmit > bDrop) {
		t.Fatalf("fence ND admit must precede ff02 drop:\n%s", fence)
	}
}

// Opus mixed-scope: B ingress-retaining + C destination-only retaining
// both get ND accepts; excluded C gets none; no unscoped accept while
// a sibling excludes (Codex F1 empty-seed shape included).
func TestNDMixedScopeAndUnscopedGate15931(t *testing.T) {
	mk := func(cExcept []string) []dpuserspace.ZoneHostInboundView {
		return []dpuserspace.ZoneHostInboundView{
			{Zone: "zoneb", SystemServices: []string{"ssh"}, V6Addrs: []string{"2001:db8:b::1"}, IngressNetdevs: []string{"ge-b"}},
			{Zone: "zonec", SystemServices: []string{"ssh"}, ProtocolsExcept: cExcept, V6Addrs: []string{"2001:db8:c::1"}},
		}
	}
	payload := buildHostInboundFilterPayload(mk(nil), nil, nil, nil, nil, true)
	if !strings.Contains(payload, "ip6 daddr 2001:db8:c::1 icmpv6 type { 133, 134, 135, 136 }") {
		t.Fatalf("destination-only retaining view lost its fallback (mixed-scope):\n%s", payload)
	}
	excluded := buildHostInboundFilterPayload(mk([]string{"ndp"}), nil, nil, nil, nil, true)
	if strings.Contains(excluded, "2001:db8:c::1 icmpv6 type") {
		t.Fatalf("excluded destination-only view got an ND fallback:\n%s", excluded)
	}
	// F1: fully-overridden zone shape — empty seeded default view +
	// excluding override view carrying the only ingress/address.
	f1 := []dpuserspace.ZoneHostInboundView{
		{Zone: "trust"},
		{Zone: "trust", SystemServices: []string{"ssh"}, Protocols: []string{"ospf"}, ProtocolsExcept: []string{"ndp"}, V6Addrs: []string{"2001:db8:f::1"}, IngressNetdevs: []string{"ge-f"}},
	}
	for name, pl := range map[string]string{
		"steady": buildHostInboundFilterPayload(f1, nil, nil, nil, nil, true),
		"fence":  buildHostInboundFencePayload(f1, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}),
	} {
		for _, l := range strings.Split(pl, "\n") {
			trim := strings.TrimSpace(l)
			if strings.HasPrefix(trim, "icmpv6 type { 133, 134, 135, 136 }") {
				t.Fatalf("%s: empty default view reinstated unscoped ND accept (F1): %q\n%s", name, l, pl)
			}
		}
		if strings.Contains(pl, "2001:db8:f::1 icmpv6 type { 133, 134, 135, 136 }") && strings.Contains(pl, "accept") {
			// destination fallback to excluded addr must not exist either
			for _, l := range strings.Split(pl, "\n") {
				if strings.Contains(l, "2001:db8:f::1") && strings.Contains(l, "133, 134, 135, 136") {
					t.Fatalf("%s: excluded address got ND accept (F1): %q", name, l)
				}
			}
		}
	}
	// Control: no exclusion anywhere, scopeless views -> unscoped admit.
	plain := buildHostInboundFilterPayload([]dpuserspace.ZoneHostInboundView{{Zone: "zoneb", SystemServices: []string{"ssh"}}}, nil, nil, nil, nil, true)
	if len(ndLines15931(plain)) == 0 {
		t.Fatalf("scopeless no-exclusion payload lost ND:\n%s", plain)
	}
}

// Round-2 (Opus2): a retaining any-service view retains UNICAST ND
// through fencing. Steady state skips its scoped ND (bare full admit
// covers it, #6618), but fences have no full-service admit: when a
// sibling excludes (suppressing the unscoped fallback) the fence must
// still emit a scoped ND admit for the any-service view's ingress.
func TestNDAnyServiceFenceRetainsUnicast15931(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{Zone: "zonea", SystemServices: []string{"ssh"}, ProtocolsExcept: []string{"ndp"}, V6Addrs: []string{"2001:db8:a::1"}, IngressNetdevs: []string{"ge-a"}},
		{Zone: "zoneany", SystemServices: []string{"any-service"}, V6Addrs: []string{"2001:db8:17::1"}, IngressNetdevs: []string{"ge-any"}},
	}
	// Steady: no scoped ND rule names ge-any (bare admit covers ND);
	// B-fixture sanity: ND exists at all via... zonea excludes, zoneany
	// skipped, so steady ND lines must be NONE scoped to ge-any.
	steady := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	// Scoped-emission skip = no UNICAST scoped rule for ge-any (the
	// ff02::/16 multicast exemption is shared infrastructure and is
	// not the #6618 duplicate).
	for _, l := range strings.Split(steady, "\n") {
		if strings.Contains(l, `"ge-any"`) && strings.Contains(l, "2001:db8:17::1") && strings.Contains(l, "133, 134, 135, 136") {
			t.Fatalf("steady must skip scoped unicast ND for any-service view (bare admit covers): %q", l)
		}
	}
	if !strings.Contains(steady, "ip6 daddr 2001:db8:17::1 accept") {
		t.Fatalf("steady lost any-service bare admit:\n%s", steady)
	}
	// Cold-boot + gap fences: scoped unicast ND admit for ge-any must
	// exist (destination 2001:db8:17::1 in the union), none for ge-a.
	for name, fence := range map[string]string{
		"cold-boot": buildHostInboundFencePayload(views, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}),
		"gap":       buildHostInboundGapFencePayload(views, []string{"2001:db8:17::9"}, nil, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil),
	} {
		found := false
		for _, l := range strings.Split(fence, "\n") {
			if strings.Contains(l, `"ge-any"`) && strings.Contains(l, "2001:db8:17::1") && strings.Contains(l, "133, 134, 135, 136") && strings.Contains(l, "accept") {
				found = true
			}
			if strings.Contains(l, `"ge-a"`) && strings.Contains(l, "133, 134, 135, 136") && strings.Contains(l, "accept") {
				t.Fatalf("%s fence: excluding view got ND admit: %q\n%s", name, l, fence)
			}
		}
		if !found {
			t.Fatalf("%s fence: any-service retaining view lost unicast ND:\n%s", name, fence)
		}
	}
}
