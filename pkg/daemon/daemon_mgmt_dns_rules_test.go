package daemon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type fakeMgmtDNSRuleOps struct {
	rules             []netlink.Rule
	failAddAtPriority map[int]error
}

func (f *fakeMgmtDNSRuleOps) RuleAdd(rule *netlink.Rule) error {
	if err := f.failAddAtPriority[rule.Priority]; err != nil {
		return err
	}
	key := mgmtDNSRuleTestKey(*rule)
	for _, current := range f.rules {
		if mgmtDNSRuleTestKey(current) == key {
			return unix.EEXIST
		}
	}
	f.rules = append(f.rules, *rule)
	return nil
}

func (f *fakeMgmtDNSRuleOps) RuleDel(rule *netlink.Rule) error {
	key := mgmtDNSRuleTestKey(*rule)
	for i, current := range f.rules {
		if mgmtDNSRuleTestKey(current) == key {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return nil
		}
	}
	return unix.ENOENT
}

func (f *fakeMgmtDNSRuleOps) RuleList(family int) ([]netlink.Rule, error) {
	var out []netlink.Rule
	for _, rule := range f.rules {
		if rule.Family == family {
			out = append(out, rule)
		}
	}
	return out, nil
}

func mgmtDNSRuleTestKey(rule netlink.Rule) string {
	dst := ""
	if rule.Dst != nil {
		dst = rule.Dst.String()
	}
	dport := 0
	if rule.Dport != nil {
		dport = int(rule.Dport.Start)
	}
	return fmt.Sprintf("%d/%d/%d/%d/%s/%s/%d/%d", rule.Family, rule.Priority,
		rule.Table, rule.Type, rule.IifName, dst, rule.IPProto, dport)
}

func TestMgmtDNSRulesAreLeaseScopedAndDeduplicated11385(t *testing.T) {
	leases := []*dhcp.Lease{
		{Interface: "fxp0", Family: dhcp.AFInet, DNS: []netip.Addr{
			netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("192.0.2.53"),
		}},
		{Interface: "fxp1", Family: dhcp.AFInet6, DNS: []netip.Addr{
			netip.MustParseAddr("2001:db8::53"),
		}},
		{Interface: "ge-0-0-0", Family: dhcp.AFInet, DNS: []netip.Addr{
			netip.MustParseAddr("9.9.9.9"),
		}},
		{Interface: "fxp0", Family: dhcp.AFInet, DNS: []netip.Addr{
			netip.MustParseAddr("fe80::1"),
		}},
	}
	ops := &fakeMgmtDNSRuleOps{}
	if err := reconcileMgmtDNSRules(ops, leases, map[string]bool{"fxp0": true, "fxp1": true}); err != nil {
		t.Fatalf("reconcile management DNS rules: %v", err)
	}
	if len(ops.rules) != 8 {
		t.Fatalf("installed %d rules, want UDP+TCP lookup/shadow pairs for each of the two management nameservers: %+v",
			len(ops.rules), ops.rules)
	}
	want := map[string]bool{
		"2/2500/999/1/lo/192.0.2.53/32/17/53":     true,
		"2/2501/0/7/lo/192.0.2.53/32/17/53":       true,
		"2/2502/999/1/lo/192.0.2.53/32/6/53":      true,
		"2/2503/0/7/lo/192.0.2.53/32/6/53":        true,
		"10/2500/999/1/lo/2001:db8::53/128/17/53": true,
		"10/2501/0/7/lo/2001:db8::53/128/17/53":   true,
		"10/2502/999/1/lo/2001:db8::53/128/6/53":  true,
		"10/2503/0/7/lo/2001:db8::53/128/6/53":    true,
	}
	got := make(map[string]bool, len(ops.rules))
	for _, rule := range ops.rules {
		got[mgmtDNSRuleTestKey(rule)] = true
	}
	if !maps.Equal(got, want) {
		t.Fatalf("management DNS rules = %v, want exactly %v", got, want)
	}
	ready, err := mgmtDNSRuleReadiness(ops)
	if err != nil {
		t.Fatalf("read installed-rule state: %v", err)
	}
	if !maps.Equal(ready, map[string]bool{"192.0.2.53": true, "2001:db8::53": true}) {
		t.Fatalf("ready nameservers = %v, want both complete rule pairs", ready)
	}
}

func TestMgmtDNSRuleReadinessRequiresExpectedActions11385(t *testing.T) {
	server := netip.MustParseAddr("192.0.2.53")
	lease := &dhcp.Lease{Interface: "fxp0", Family: dhcp.AFInet, DNS: []netip.Addr{server}}
	pair := mgmtDNSRulePairs([]*dhcp.Lease{lease}, map[string]bool{"fxp0": true})[0]

	tests := []struct {
		name  string
		rules []netlink.Rule
	}{
		{
			name: "wrong lookup action",
			rules: []netlink.Rule{
				func() netlink.Rule {
					rule := pair.lookup
					rule.Type = unix.RTN_UNREACHABLE
					return rule
				}(),
				pair.shadow,
			},
		},
		{
			name: "wrong shadow action",
			rules: []netlink.Rule{
				pair.lookup,
				func() netlink.Rule {
					rule := pair.shadow
					rule.Type = unix.RTN_UNICAST
					return rule
				}(),
			},
		},
		{
			name: "wrong shadow table",
			rules: []netlink.Rule{
				pair.lookup,
				func() netlink.Rule {
					rule := pair.shadow
					rule.Table = mgmtDNSRuleLookupTable
					return rule
				}(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &fakeMgmtDNSRuleOps{rules: slices.Clone(tt.rules)}
			ready, err := mgmtDNSRuleReadiness(ops)
			if err != nil {
				t.Fatalf("read invalid rule state: %v", err)
			}
			if ready[server.String()] {
				t.Fatalf("nameserver accepted with a wrong policy-rule action: %+v", ops.rules)
			}

			if err := reconcileMgmtDNSRules(ops, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
				t.Fatalf("repair invalid rule pair: %v", err)
			}
			ready, err = mgmtDNSRuleReadiness(ops)
			if err != nil {
				t.Fatalf("read repaired rule state: %v", err)
			}
			if !ready[server.String()] {
				t.Fatalf("correct lookup/unreachable pair not ready after repair: %+v", ops.rules)
			}
		})
	}
}

func TestNetlinkMgmtDNSRuleListReadsKernelAction11385(t *testing.T) {
	rules, err := netlinkMgmtDNSRuleOps{}.RuleList(unix.AF_INET)
	if err != nil {
		t.Fatalf("list IPv4 rules with actions: %v", err)
	}
	for _, rule := range rules {
		if rule.Priority == 0 && rule.Table == unix.RT_TABLE_LOCAL {
			if rule.Type != unix.RTN_UNICAST {
				t.Fatalf("local-table rule action = %d, want unicast lookup (%d)", rule.Type, unix.RTN_UNICAST)
			}
			return
		}
	}
	t.Skip("kernel has no default priority-0 local-table rule")
}

func TestMgmtDNSRuleDumpDecodesActionAndExtendedTable11385(t *testing.T) {
	makeMessage := func(priority, table int, action uint8) []byte {
		msg := nl.NewRtMsg()
		msg.Family = unix.AF_INET
		msg.Dst_len = 32
		msg.Table = uint8(table)
		if table > 255 {
			msg.Table = unix.RT_TABLE_UNSPEC
		}
		msg.Type = action
		raw := append([]byte(nil), msg.Serialize()...)
		raw = append(raw, nl.NewRtAttr(nl.FRA_DST, net.ParseIP("192.0.2.53").To4()).Serialize()...)
		raw = append(raw, nl.NewRtAttr(nl.FRA_IIFNAME, []byte("lo\x00")).Serialize()...)
		raw = append(raw, nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(uint32(priority))).Serialize()...)
		if table > 255 {
			raw = append(raw, nl.NewRtAttr(unix.RTA_TABLE, nl.Uint32Attr(uint32(table))).Serialize()...)
		}
		raw = append(raw, nl.NewRtAttr(nl.FRA_IP_PROTO, nl.Uint32Attr(uint32(unix.IPPROTO_UDP))).Serialize()...)
		var portBuf [4]byte
		binary.NativeEndian.PutUint16(portBuf[0:2], 53)
		binary.NativeEndian.PutUint16(portBuf[2:4], 53)
		raw = append(raw, nl.NewRtAttr(nl.FRA_DPORT_RANGE, portBuf[:]).Serialize()...)
		return raw
	}
	rules, err := decodeMgmtDNSRuleMessages(unix.AF_INET, [][]byte{
		makeMessage(mgmtDNSRulePriority, mgmtDNSRuleLookupTable, unix.RTN_UNICAST),
		makeMessage(mgmtDNSRuleShadowPriority, unix.RT_TABLE_UNSPEC, nl.FR_ACT_UNREACHABLE),
	})
	if err != nil {
		t.Fatalf("decode synthetic policy-rule dump: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("decoded %d rules, want lookup and shadow", len(rules))
	}
	for i, wantKind := range []string{"lookup", "shadow"} {
		_, kind, ok := managedMgmtDNSRule(rules[i])
		if !ok || kind != wantKind {
			t.Fatalf("decoded rule %d = %#v, kind=%q, want %q", i, rules[i], kind, wantKind)
		}
	}
}
func TestMgmtDNSRuleFailureKeepsNameserverOutOfResolver11385(t *testing.T) {
	server := netip.MustParseAddr("192.0.2.53")
	leases := []*dhcp.Lease{{Interface: "fxp0", Family: dhcp.AFInet, DNS: []netip.Addr{server}}}
	ops := &fakeMgmtDNSRuleOps{failAddAtPriority: map[int]error{
		mgmtDNSRuleShadowPriority: errors.New("injected shadow failure"),
	}}
	if err := reconcileMgmtDNSRules(ops, leases, map[string]bool{"fxp0": true}); err == nil {
		t.Fatal("a failed miss-shadow install must fail DNS-rule reconciliation")
	}
	for _, rule := range ops.rules {
		if rule.Priority == mgmtDNSRulePriority {
			t.Fatalf("lookup was installed without its unreachable shadow: %+v", rule)
		}
	}
	ready, err := mgmtDNSRuleReadiness(ops)
	if err != nil {
		t.Fatalf("read installed-rule state: %v", err)
	}
	in := mergeDNSInputWithMgmtDNSRules(nil, leases, map[string]bool{"fxp0": true}, ready)
	if slices.Contains(in.NameServers, server.String()) {
		t.Fatalf("nameserver was published without a complete lookup/shadow pair: %v", in.NameServers)
	}
}

func TestMergeDNSInputPublishesOnlySteeredManagementNameservers11385(t *testing.T) {
	mgmt := map[string]bool{"fxp0": true}
	leases := []*dhcp.Lease{
		{Interface: "fxp0", Family: dhcp.AFInet, DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}},
		{Interface: "ge-0-0-0", Family: dhcp.AFInet, DNS: []netip.Addr{netip.MustParseAddr("9.9.9.9")}},
	}
	if got := mergeDNSInputWithMgmtDNSRules(nil, leases, mgmt, nil).NameServers; !slices.Equal(got, []string{"9.9.9.9"}) {
		t.Fatalf("unsteered management DNS leaked into resolver input: %v", got)
	}
	ready := map[string]bool{"192.0.2.53": true}
	if got := mergeDNSInputWithMgmtDNSRules(nil, leases, mgmt, ready).NameServers; !slices.Equal(got, []string{"192.0.2.53", "9.9.9.9"}) {
		t.Fatalf("steered management nameserver was not merged with default-context DNS: %v", got)
	}
}

func TestMgmtDNSRulesFollowLeaseRenewalAndWithdrawal11385(t *testing.T) {
	ops := &fakeMgmtDNSRuleOps{}
	mgmt := map[string]bool{"fxp0": true}
	first := &dhcp.Lease{Interface: "fxp0", Family: dhcp.AFInet,
		DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}
	second := &dhcp.Lease{Interface: "fxp0", Family: dhcp.AFInet,
		DNS: []netip.Addr{netip.MustParseAddr("192.0.2.54")}}
	if err := reconcileMgmtDNSRules(ops, []*dhcp.Lease{first}, mgmt); err != nil {
		t.Fatalf("install first lease rules: %v", err)
	}
	// A rule at the same priorities but with a different selector is owned by
	// another policy and must survive this reconcile.
	foreign := netlink.NewRule()
	foreign.Family, foreign.Priority, foreign.Table, foreign.IifName = unix.AF_INET, mgmtDNSRulePriority, 300, "fxp0"
	_, foreign.Dst, _ = net.ParseCIDR("192.0.2.53/32")
	ops.rules = append(ops.rules, *foreign)

	if err := reconcileMgmtDNSRules(ops, []*dhcp.Lease{second}, mgmt); err != nil {
		t.Fatalf("renew lease with changed nameserver: %v", err)
	}
	if got := len(ops.rules); got != 5 {
		t.Fatalf("after renewal have %d rules, want second nameserver UDP+TCP pairs plus untouched foreign rule: %+v", got, ops.rules)
	}
	for _, rule := range ops.rules {
		if rule.Table == mgmtVRFTableID && rule.Dst != nil && rule.Dst.String() == "192.0.2.53/32" {
			t.Fatalf("withdrawn nameserver rule survived renewal: %+v", rule)
		}
	}
	if !slices.ContainsFunc(ops.rules, func(rule netlink.Rule) bool {
		return rule.Table == 300 && rule.Priority == mgmtDNSRulePriority && rule.IifName == "fxp0"
	}) {
		t.Fatal("unrelated rule at a reserved priority was removed")
	}

	if err := reconcileMgmtDNSRules(ops, nil, mgmt); err != nil {
		t.Fatalf("withdraw final lease: %v", err)
	}
	if len(ops.rules) != 1 || ops.rules[0].Table != 300 {
		t.Fatalf("after final withdrawal rules = %+v, want only unrelated rule", ops.rules)
	}
}

// TestMgmtDNSRulesScopedToDNSOnly14971 is the #14971 (D31-03) regression:
// every installed rule must carry IPProto in {UDP,TCP} and Dport 53-53, a
// legacy unscoped pair must be migrated away, readiness must require all
// four rules, and a non-DNS packet to the nameserver must not be steered.
func TestMgmtDNSRulesScopedToDNSOnly14971(t *testing.T) {
	server := netip.MustParseAddr("192.0.2.53")
	lease := &dhcp.Lease{Interface: "fxp0", Family: dhcp.AFInet, DNS: []netip.Addr{server}}
	mgmt := map[string]bool{"fxp0": true}

	// Fresh install: exactly UDP+TCP lookup/shadow, all scoped.
	ops := &fakeMgmtDNSRuleOps{}
	if err := reconcileMgmtDNSRules(ops, []*dhcp.Lease{lease}, mgmt); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(ops.rules) != 4 {
		t.Fatalf("installed %d rules, want 4 scoped rules: %+v", len(ops.rules), ops.rules)
	}
	for _, rule := range ops.rules {
		if rule.IPProto != unix.IPPROTO_UDP && rule.IPProto != unix.IPPROTO_TCP {
			t.Fatalf("rule not protocol-scoped (proto=%d): %+v", rule.IPProto, rule)
		}
		if rule.Dport == nil || rule.Dport.Start != 53 || rule.Dport.End != 53 {
			t.Fatalf("rule not port-scoped to DNS 53: %+v", rule)
		}
		if rule.Sport != nil {
			t.Fatalf("rule must not constrain source port: %+v", rule)
		}
	}
	ready, err := mgmtDNSRuleReadiness(ops)
	if err != nil || !ready[server.String()] {
		t.Fatalf("ready=%v err=%v, want nameserver ready with all four rules", ready, err)
	}

	// Legacy migration: seed pre-#14971 unscoped pair at 2500/2501, reconcile
	// must delete them and install scoped pairs; readiness holds after.
	legacyLookup := netlink.NewRule()
	legacyLookup.Family, legacyLookup.Priority, legacyLookup.Table = unix.AF_INET, mgmtDNSUDPRulePriority, mgmtDNSRuleLookupTable
	legacyLookup.Type, legacyLookup.IifName = unix.RTN_UNICAST, mgmtDNSRuleInterface
	_, legacyDst, _ := net.ParseCIDR("192.0.2.53/32")
	legacyLookup.Dst = legacyDst
	legacyShadow := *legacyLookup
	legacyShadow.Priority, legacyShadow.Table, legacyShadow.Type = mgmtDNSUDPShadowPriority, unix.RT_TABLE_UNSPEC, nl.FR_ACT_UNREACHABLE
	legacyOps := &fakeMgmtDNSRuleOps{rules: []netlink.Rule{*legacyLookup, legacyShadow}}
	if ready, _ := mgmtDNSRuleReadiness(legacyOps); ready[server.String()] {
		t.Fatal("legacy unscoped pair must not make nameserver ready")
	}
	if err := reconcileMgmtDNSRules(legacyOps, []*dhcp.Lease{lease}, mgmt); err != nil {
		t.Fatalf("migrate legacy rules: %v", err)
	}
	for _, rule := range legacyOps.rules {
		if rule.IPProto == 0 || rule.Dport == nil {
			t.Fatalf("legacy unscoped rule survived migration: %+v", rule)
		}
	}
	if len(legacyOps.rules) != 4 {
		t.Fatalf("after migration %d rules, want 4 scoped: %+v", len(legacyOps.rules), legacyOps.rules)
	}
	if ready, _ := mgmtDNSRuleReadiness(legacyOps); !ready[server.String()] {
		t.Fatalf("nameserver not ready after migration: %+v", legacyOps.rules)
	}

	// Partial pair (one transport only) must not be ready. Pairs are sorted
	// by proto (TCP=6 before UDP=17), so find the UDP pair explicitly.
	pairs := mgmtDNSRulePairs([]*dhcp.Lease{lease}, mgmt)
	if len(pairs) != 2 {
		t.Fatalf("pairs=%d want 2 (UDP+TCP)", len(pairs))
	}
	var udpPair mgmtDNSRulePair
	foundUDP := false
	for _, p := range pairs {
		if p.key.proto == unix.IPPROTO_UDP {
			udpPair, foundUDP = p, true
		}
	}
	if !foundUDP {
		t.Fatal("no UDP pair built")
	}
	partial := &fakeMgmtDNSRuleOps{rules: []netlink.Rule{udpPair.lookup, udpPair.shadow}}
	if ready, _ := mgmtDNSRuleReadiness(partial); ready[server.String()] {
		t.Fatal("UDP-only pair must not make nameserver ready (TCP DNS would fall through)")
	}
	// Wrong-proto rule (TCP proto at UDP priority) must be classified invalid.
	bad := udpPair.lookup
	bad.IPProto = unix.IPPROTO_TCP
	if _, kind, ok := managedMgmtDNSRule(bad); !ok || kind != "invalid" {
		t.Fatalf("wrong-proto rule kind=%q ok=%v want invalid", kind, ok)
	}
	// Non-DNS dport at UDP priority must be invalid.
	badPort := udpPair.lookup
	badPort.Dport = netlink.NewRulePortRange(443, 443)
	if _, kind, ok := managedMgmtDNSRule(badPort); !ok || kind != "invalid" {
		t.Fatalf("wrong-port rule kind=%q ok=%v want invalid", kind, ok)
	}
}

func TestMgmtDNSRulesSteerOnlyDefaultContextHostLookups11385(t *testing.T) {
	enterPrivateNetns9813(t)
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find loopback: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("bring loopback up: %v", err)
	}
	wan := addDNSRuleTestDummy(t, "wan0", "198.51.100.1/24")
	fxp := addDNSRuleTestDummyLink(t, "fxp0")

	manager, err := routing.New()
	if err != nil {
		t.Fatalf("create routing manager: %v", err)
	}
	defer manager.Close()
	if err := manager.ReconcileVRFs([]routing.VRFSpec{
		{Name: config.ManagementVRFInstanceName, TableID: config.ManagementVRFTableID},
		{Name: "tenant", TableID: 1001},
	}); err != nil {
		t.Skipf("cannot establish VRF miss-terminator control in this kernel: %v", err)
	}
	if err := manager.BindInterfaceToVRF("fxp0", config.ManagementVRFInstanceName); err != nil {
		t.Skipf("cannot bind fxp0 into the management VRF: %v", err)
	}
	addDNSRuleTestAddress(t, fxp, "192.0.2.1/24")

	_, defaultDst, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	gateway := net.ParseIP("198.51.100.254")
	if err := netlink.RouteReplace(&netlink.Route{
		Dst: defaultDst, Gw: gateway, LinkIndex: wan.Attrs().Index, Table: unix.RT_TABLE_MAIN,
	}); err != nil {
		t.Fatalf("install main-table WAN default: %v", err)
	}

	server := net.ParseIP("192.0.2.53")
	before, err := netlink.RouteGet(server)
	if err != nil || len(before) == 0 {
		t.Fatalf("baseline main-table route lookup: routes=%v err=%v", before, err)
	}
	if before[0].LinkIndex != wan.Attrs().Index {
		t.Fatalf("baseline lookup used link %d, want main-table WAN link %d", before[0].LinkIndex, wan.Attrs().Index)
	}

	lease := &dhcp.Lease{Interface: "fxp0", Family: dhcp.AFInet,
		DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}
	if err := reconcileMgmtDNSRules(netlinkMgmtDNSRuleOps{}, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("install live management DNS rules: %v", err)
	}
	// #14971: installed live rules must be DNS-scoped (proto + dport 53).
	liveRules, err := netlinkMgmtDNSRuleOps{}.RuleList(unix.AF_INET)
	if err != nil {
		t.Fatalf("list live rules: %v", err)
	}
	scoped := 0
	for _, rule := range liveRules {
		if _, kind, ok := managedMgmtDNSRule(rule); ok && (kind == "lookup" || kind == "shadow") {
			scoped++
			if (rule.IPProto != unix.IPPROTO_UDP && rule.IPProto != unix.IPPROTO_TCP) || rule.Dport == nil || rule.Dport.Start != 53 || rule.Dport.End != 53 {
				t.Fatalf("live rule not DNS-scoped: %+v", rule)
			}
		}
	}
	if scoped != 4 {
		t.Fatalf("live scoped rules=%d want 4 (UDP+TCP pairs)", scoped)
	}
	// Plain RouteGet carries no L4 selector, so pre-#14971 it matched the
	// unscoped lookup; post-fix it must stay on the main WAN route — that is
	// the non-DNS control (any non-DNS traffic to the nameserver).
	routed, err := netlink.RouteGet(server)
	if err != nil || len(routed) == 0 {
		t.Fatalf("non-DNS route lookup: routes=%v err=%v", routed, err)
	}
	if routed[0].LinkIndex != wan.Attrs().Index {
		t.Fatalf("non-DNS host traffic was steered into mgmt VRF: %+v, want WAN link %d", routed[0], wan.Attrs().Index)
	}
	if tenant, tenantErr := netlink.RouteGetWithOptions(server, &netlink.RouteGetOptions{VrfName: "vrf-tenant"}); tenantErr == nil {
		t.Fatalf("VRF-bound local lookup was redirected through management DNS rules: %+v", tenant)
	}
	mgmtAddr, err := netlink.ParseAddr("192.0.2.1/24")
	if err != nil {
		t.Fatalf("parse management interface address: %v", err)
	}
	if err := netlink.LinkSetDown(fxp); err != nil {
		t.Fatalf("withdraw management connected route: %v", err)
	}
	// Non-DNS traffic must still reach main/WAN even when mgmt link is down
	// (pre-fix the unscoped shadow blackholed it).
	miss, missErr := netlink.RouteGet(server)
	if missErr != nil || len(miss) == 0 || miss[0].LinkIndex != wan.Attrs().Index {
		t.Fatalf("non-DNS traffic blackholed by DNS shadow: routes=%v err=%v", miss, missErr)
	}
	if err := netlink.LinkSetUp(fxp); err != nil {
		t.Fatalf("restore management interface: %v", err)
	}
	if err := netlink.AddrAdd(fxp, mgmtAddr); err != nil && !errors.Is(err, unix.EEXIST) {
		t.Fatalf("restore management address: %v", err)
	}

	if err := reconcileMgmtDNSRules(netlinkMgmtDNSRuleOps{}, nil, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("withdraw live management DNS rules: %v", err)
	}
	after, err := netlink.RouteGet(server)
	if err != nil || len(after) == 0 || after[0].LinkIndex != wan.Attrs().Index {
		t.Fatalf("after lease withdrawal main route = %v, err=%v; want WAN link %d", after, err, wan.Attrs().Index)
	}
}

func addDNSRuleTestDummy(t *testing.T, name, address string) netlink.Link {
	t.Helper()
	link := addDNSRuleTestDummyLink(t, name)
	addDNSRuleTestAddress(t, link, address)
	return link
}

func addDNSRuleTestDummyLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Skipf("cannot create %s in private netns: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring %s up: %v", name, err)
	}
	return link
}

func addDNSRuleTestAddress(t *testing.T, link netlink.Link, address string) {
	t.Helper()
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		t.Fatalf("parse %s address: %v", address, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("add address %s to %s: %v", address, link.Attrs().Name, err)
	}
}
