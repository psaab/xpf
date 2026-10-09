package routing

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type probePinReadbackTable12088 struct {
	family int
	table  int
}

type probePinReadbackOps12088 struct {
	*fakeProbePinOps
	ruleListCalls  map[int]int
	routeListCalls map[probePinReadbackTable12088]int
	linkCalls      int
	mutationCalls  int
}

func newProbePinReadbackOps12088(fake *fakeProbePinOps) *probePinReadbackOps12088 {
	return &probePinReadbackOps12088{
		fakeProbePinOps: fake,
		ruleListCalls:   make(map[int]int),
		routeListCalls:  make(map[probePinReadbackTable12088]int),
	}
}

func (o *probePinReadbackOps12088) RuleList(family int) ([]netlink.Rule, error) {
	o.ruleListCalls[family]++
	return o.fakeProbePinOps.RuleList(family)
}

func (o *probePinReadbackOps12088) RouteListFiltered(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	o.routeListCalls[probePinReadbackTable12088{family: family, table: filter.Table}]++
	return o.fakeProbePinOps.RouteListFiltered(family, filter, mask)
}

func (o *probePinReadbackOps12088) LinkByName(name string) (netlink.Link, error) {
	o.linkCalls++
	return o.fakeProbePinOps.LinkByName(name)
}

func (o *probePinReadbackOps12088) RuleAdd(rule *netlink.Rule) error {
	o.mutationCalls++
	return o.fakeProbePinOps.RuleAdd(rule)
}

func (o *probePinReadbackOps12088) RuleDel(rule *netlink.Rule) error {
	o.mutationCalls++
	return o.fakeProbePinOps.RuleDel(rule)
}

func (o *probePinReadbackOps12088) RouteAdd(route *netlink.Route) error {
	o.mutationCalls++
	return o.fakeProbePinOps.RouteAdd(route)
}

func (o *probePinReadbackOps12088) RouteDel(route *netlink.Route) error {
	o.mutationCalls++
	return o.fakeProbePinOps.RouteDel(route)
}

func probePinReadbackFixture12088() ([]ProbePin, *probePinReadbackOps12088) {
	all := BuildProbePins(rpmConfigWithPins(), map[string]string{"reth0": "ge-0/0/2"})
	pins := all[:3] // one IPv6 pin and two IPv4 pins
	fake := &fakeProbePinOps{links: map[string]int{
		"ge-0-0-3":    31,
		"ge-0-0-2.50": 32,
		"ge-0-0-2.80": 33,
	}}
	for _, pin := range pins {
		family := unix.AF_INET
		bits := 32
		linkIndex := fake.links[pin.Interface]
		if net.ParseIP(pin.Target).To4() == nil {
			family, bits = unix.AF_INET6, 128
		}
		rule := netlink.NewRule()
		rule.Family = family
		rule.Mark = pin.Mark
		if family == unix.AF_INET {
			mask := uint32(0xffffffff)
			rule.Mask = &mask
		}
		rule.Table = pin.Table
		rule.Priority = pin.Priority
		fake.rules = append(fake.rules, *rule)
		fake.routes = append(fake.routes, netlink.Route{
			Family: family, Table: pin.Table,
			Dst: &net.IPNet{
				IP: net.ParseIP(pin.Target), Mask: net.CIDRMask(bits, bits),
			},
			Gw: net.ParseIP(pin.NextHop), LinkIndex: linkIndex,
			Flags: int(netlink.FLAG_ONLINK), Type: unix.RTN_UNICAST,
			Scope: unix.RT_SCOPE_UNIVERSE,
		})
	}
	return pins, newProbePinReadbackOps12088(fake)
}

func assertProbePinReadbackOnlyKey12088(t *testing.T, got map[string]error, key string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("Verify errors = %v, want only %q", got, key)
	}
	if err := got[key]; err == nil {
		t.Fatalf("Verify errors = %v, want non-nil error for %q", got, key)
	}
}

func TestVerifyProbePinsReadback12088(t *testing.T) {
	pins, ops := probePinReadbackFixture12088()
	m := &Manager{probePin: &probePinManager{ops: ops}}
	if got := m.VerifyProbePins(pins); len(got) != 0 {
		t.Fatalf("VerifyProbePins() = %v, want healthy IPv4 and IPv6 pins", got)
	}
	if ops.ruleListCalls[unix.AF_INET] != 1 || ops.ruleListCalls[unix.AF_INET6] != 1 {
		t.Fatalf("rule dump calls = %v, want one per family", ops.ruleListCalls)
	}
	for _, pin := range pins {
		family := unix.AF_INET
		if net.ParseIP(pin.Target).To4() == nil {
			family = unix.AF_INET6
		}
		if calls := ops.routeListCalls[probePinReadbackTable12088{family, pin.Table}]; calls != 1 {
			t.Fatalf("route dump calls = %v, want one for family %d/table %d", ops.routeListCalls, family, pin.Table)
		}
	}
	if len(ops.routeListCalls) != len(pins) {
		t.Fatalf("route dump calls = %v, want one per configured family/table", ops.routeListCalls)
	}
	if ops.mutationCalls != 0 {
		t.Fatalf("Verify made %d kernel mutation calls, want 0", ops.mutationCalls)
	}
}

func TestVerifyProbePinsZeroPinsDoesNoKernelWork12088(t *testing.T) {
	ops := newProbePinReadbackOps12088(&fakeProbePinOps{links: map[string]int{}})
	m := &Manager{probePin: &probePinManager{ops: ops}}
	if got := m.VerifyProbePins(nil); got != nil {
		t.Fatalf("VerifyProbePins(nil) = %v, want nil", got)
	}
	if ops.linkCalls != 0 || len(ops.ruleListCalls) != 0 || len(ops.routeListCalls) != 0 || ops.mutationCalls != 0 {
		t.Fatalf("zero-pin Verify performed kernel work: links=%d rules=%v routes=%v mutations=%d",
			ops.linkCalls, ops.ruleListCalls, ops.routeListCalls, ops.mutationCalls)
	}
}

func TestVerifyProbePinsMissingRuleOrRoute12088(t *testing.T) {
	for _, tc := range []struct {
		name string
		omit func(*fakeProbePinOps, ProbePin)
	}{
		{
			name: "missing rule",
			omit: func(fake *fakeProbePinOps, pin ProbePin) {
				for i := range fake.rules {
					if fake.rules[i].Priority == pin.Priority {
						fake.rules = append(fake.rules[:i], fake.rules[i+1:]...)
						return
					}
				}
			},
		},
		{
			name: "rule survives route deletion",
			omit: func(fake *fakeProbePinOps, pin ProbePin) {
				for i := range fake.routes {
					if fake.routes[i].Table == pin.Table {
						fake.routes = append(fake.routes[:i], fake.routes[i+1:]...)
						return
					}
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pins, ops := probePinReadbackFixture12088()
			pin := pins[1]
			tc.omit(ops.fakeProbePinOps, pin)
			got := (&probePinManager{ops: ops}).Verify(pins)
			assertProbePinReadbackOnlyKey12088(t, got, pin.TestKey)
			if ops.mutationCalls != 0 {
				t.Fatalf("Verify made %d kernel mutation calls, want 0", ops.mutationCalls)
			}
		})
	}
}

func TestVerifyProbePinsRejectsMismatchedRule12088(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*netlink.Rule)
	}{
		{"partial fwmark mask", func(r *netlink.Rule) { mask := uint32(0xff); r.Mask = &mask }},
		{"wrong mark", func(r *netlink.Rule) { r.Mark++ }},
		{"wrong table", func(r *netlink.Rule) { r.Table++ }},
		{"wrong priority", func(r *netlink.Rule) { r.Priority++ }},
		{"source selector", func(r *netlink.Rule) { _, src, _ := net.ParseCIDR("192.0.2.0/24"); r.Src = src }},
		{"destination selector", func(r *netlink.Rule) { _, dst, _ := net.ParseCIDR("198.51.100.1/32"); r.Dst = dst }},
		{"ingress selector", func(r *netlink.Rule) { r.IifName = "eth0" }},
		{"egress selector", func(r *netlink.Rule) { r.OifName = "eth0" }},
		{"tos selector", func(r *netlink.Rule) { r.Tos = 1 }},
		{"tunnel selector", func(r *netlink.Rule) { r.TunID = 1 }},
		{"goto selector", func(r *netlink.Rule) { r.Goto = 100 }},
		{"flow selector", func(r *netlink.Rule) { r.Flow = 1 }},
		{"suppression selector", func(r *netlink.Rule) { r.SuppressPrefixlen = 0 }},
		{"suppression group selector", func(r *netlink.Rule) { r.SuppressIfgroup = 1 }},
		{"invert selector", func(r *netlink.Rule) { r.Invert = true }},
		{"destination-port selector", func(r *netlink.Rule) { r.Dport = netlink.NewRulePortRange(80, 80) }},
		{"source-port selector", func(r *netlink.Rule) { r.Sport = netlink.NewRulePortRange(80, 80) }},
		{"ip-protocol selector", func(r *netlink.Rule) { r.IPProto = 6 }},
		{"uid selector", func(r *netlink.Rule) { r.UIDRange = netlink.NewRuleUIDRange(1, 2) }},
		{"rule protocol selector", func(r *netlink.Rule) { r.Protocol = 1 }},
		{"different action", func(r *netlink.Rule) { r.Type = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pins, ops := probePinReadbackFixture12088()
			pin := pins[1]
			for i := range ops.rules {
				if ops.rules[i].Priority == pin.Priority {
					tc.mutate(&ops.rules[i])
					break
				}
			}
			got := (&probePinManager{ops: ops}).Verify(pins)
			assertProbePinReadbackOnlyKey12088(t, got, pin.TestKey)
		})
	}
}

func TestVerifyProbePinsRejectsMismatchedRoute12088(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*netlink.Route)
	}{
		{"wrong next-hop", func(r *netlink.Route) { r.Gw = net.ParseIP("172.16.50.254") }},
		{"wrong egress", func(r *netlink.Route) { r.LinkIndex++ }},
		{"wrong table", func(r *netlink.Route) { r.Table += 100 }},
		{"missing onlink", func(r *netlink.Route) { r.Flags = 0 }},
		{"dead route", func(r *netlink.Route) { r.Flags |= int(unix.RTNH_F_DEAD) }},
		{"unresolved nexthop", func(r *netlink.Route) { r.Flags |= int(unix.RTNH_F_UNRESOLVED) }},
		{"non-host destination", func(r *netlink.Route) { r.Dst.Mask = net.CIDRMask(24, 32) }},
		{"wrong destination", func(r *netlink.Route) { r.Dst.IP = net.ParseIP("1.1.1.2") }},
		{"wrong family", func(r *netlink.Route) { r.Family = unix.AF_INET6 }},
		{"non-unicast route", func(r *netlink.Route) { r.Type = unix.RTN_BLACKHOLE }},
		{"link scope", func(r *netlink.Route) { r.Scope = unix.RT_SCOPE_LINK }},
		{"multipath route", func(r *netlink.Route) {
			r.MultiPath = []*netlink.NexthopInfo{{Gw: net.ParseIP("172.16.50.1"), LinkIndex: r.LinkIndex}}
		}},
		{"tos-scoped route", func(r *netlink.Route) { r.Tos = 1 }},
		{"preferred source route", func(r *netlink.Route) { r.Src = net.ParseIP("192.0.2.10") }},
		{"wrong metric", func(r *netlink.Route) { r.Priority = 10 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pins, ops := probePinReadbackFixture12088()
			pin := pins[1]
			for i := range ops.routes {
				if ops.routes[i].Table == pin.Table {
					tc.mutate(&ops.routes[i])
					break
				}
			}
			got := (&probePinManager{ops: ops}).Verify(pins)
			assertProbePinReadbackOnlyKey12088(t, got, pin.TestKey)
		})
	}
}

// Carrier loss only marks the installed route LINKDOWN. The pin shape remains
// valid, so RPM must send probes and let genuine packet loss drive failover.
func TestVerifyProbePinsAcceptsLinkdownRoutes12088(t *testing.T) {
	pins, ops := probePinReadbackFixture12088()
	for i := range ops.routes {
		ops.routes[i].Flags |= int(unix.RTNH_F_LINKDOWN)
	}

	if got := (&probePinManager{ops: ops}).Verify(pins); len(got) != 0 {
		t.Fatalf("Verify rejected carrier-down pins: %v", got)
	}
}

func TestVerifyProbePinsRejectsCompetingSameMetricRoute12088(t *testing.T) {
	pins, ops := probePinReadbackFixture12088()
	pin := pins[1]
	for _, route := range ops.routes {
		if route.Table == pin.Table {
			conflict := route
			conflict.Gw = net.ParseIP("172.16.50.254")
			ops.routes = append(ops.routes, conflict)
			break
		}
	}
	got := (&probePinManager{ops: ops}).Verify(pins)
	assertProbePinReadbackOnlyKey12088(t, got, pin.TestKey)
}

func TestVerifyProbePinsReadbackErrorsArePerPin12088(t *testing.T) {
	t.Run("rule dump error", func(t *testing.T) {
		pins, ops := probePinReadbackFixture12088()
		ops.failRuleList = map[int]error{unix.AF_INET: errors.New("injected rule dump error")}
		got := (&probePinManager{ops: ops}).Verify(pins)
		if len(got) != 2 || got[pins[1].TestKey] == nil || got[pins[2].TestKey] == nil {
			t.Fatalf("Verify errors = %v, want errors for both IPv4 pins after the family dump error", got)
		}
	})
	t.Run("route dump error", func(t *testing.T) {
		pins, ops := probePinReadbackFixture12088()
		ops.failRouteListFiltered = map[int]error{pins[1].Table: errors.New("injected route dump error")}
		got := (&probePinManager{ops: ops}).Verify(pins)
		assertProbePinReadbackOnlyKey12088(t, got, pins[1].TestKey)
	})
}

func TestVerifyProbePinsBadPinDoesNotFailHealthyPin12088(t *testing.T) {
	pins, ops := probePinReadbackFixture12088()
	pin := pins[1]
	for i := range ops.routes {
		if ops.routes[i].Table == pin.Table {
			ops.routes[i].Gw = net.ParseIP("172.16.50.254")
			break
		}
	}
	got := (&probePinManager{ops: ops}).Verify(pins)
	assertProbePinReadbackOnlyKey12088(t, got, pin.TestKey)
}

func TestVerifyProbePinsRejectsInvalidFamily12088(t *testing.T) {
	pins, ops := probePinReadbackFixture12088()
	pin := pins[1]
	pin.NextHop = "2001:db8::2"
	got := (&probePinManager{ops: ops}).Verify([]ProbePin{pin})
	assertProbePinReadbackOnlyKey12088(t, got, pin.TestKey)
	if ops.linkCalls != 0 || len(ops.ruleListCalls) != 0 || len(ops.routeListCalls) != 0 {
		t.Fatalf("invalid pin performed kernel reads: links=%d rules=%v routes=%v",
			ops.linkCalls, ops.ruleListCalls, ops.routeListCalls)
	}
}

func TestVerifyProbePinsRejectsInvalidAssignment12088(t *testing.T) {
	pins, ops := probePinReadbackFixture12088()
	pin := pins[1]
	pin.Table++
	got := (&probePinManager{ops: ops}).Verify([]ProbePin{pin})
	assertProbePinReadbackOnlyKey12088(t, got, pin.TestKey)
	if ops.linkCalls != 0 || len(ops.ruleListCalls) != 0 || len(ops.routeListCalls) != 0 {
		t.Fatalf("invalid assignment performed kernel reads: links=%d rules=%v routes=%v",
			ops.linkCalls, ops.ruleListCalls, ops.routeListCalls)
	}
}

func TestVerifyProbePinsMissingLinkIsPerPin12088(t *testing.T) {
	pins, ops := probePinReadbackFixture12088()
	delete(ops.links, pins[1].Interface)
	got := (&probePinManager{ops: ops}).Verify(pins)
	assertProbePinReadbackOnlyKey12088(t, got, pins[1].TestKey)
	if ops.routeListCalls[probePinReadbackTable12088{unix.AF_INET, pins[1].Table}] != 0 {
		t.Fatalf("missing-link pin triggered its table readback: routes=%v", ops.routeListCalls)
	}
}
