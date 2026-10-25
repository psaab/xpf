package daemon

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #15059 (A36-01 residual): #14971 scoped the steering rules to DNS, but a
// management-DHCP nameserver that is already covered by a main-table
// connected/static route or equals a configured control-plane peer must be
// refused (with a warning) — its DNS must not be diverted into table 999.
// On origin/master reconcileMgmtDNSRules installs the scoped pairs for such
// a server unconditionally, so this test is RED pre-fix.

func route15059(dst string, proto int, table int) netlink.Route {
	_, ipnet, _ := net.ParseCIDR(dst)
	r := netlink.Route{Dst: ipnet, Protocol: netlink.RouteProtocol(proto), Table: table, Type: unix.RTN_UNICAST}
	if proto == unix.RTPROT_KERNEL {
		r.Scope = netlink.SCOPE_LINK // kernel connected shape (mgmtRouteIsConnected)
	}
	return r
}

func TestMgmtDNSRefusesNameserverCoveredByMainRouteOrPeer15059(t *testing.T) {
	mgmt := map[string]bool{"fxp0": true}
	covered := netip.MustParseAddr("192.0.2.53")      // inside main connected 192.0.2.0/24
	peer := netip.MustParseAddr("198.51.100.2")       // configured peer, no main prefix
	uncovered := netip.MustParseAddr("198.51.101.53") // legitimate mgmt nameserver
	leases := []*dhcp.Lease{{Interface: "fxp0", Family: dhcp.AFInet,
		DNS: []netip.Addr{covered, peer, uncovered}}}

	mainRoutes := []netlink.Route{
		route15059("192.0.2.0/24", unix.RTPROT_KERNEL, unix.RT_TABLE_MAIN),
		// A main static covering a different server is exercised via the
		// peer-covered/connected legs; uncovered stays outside both.
	}

	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{PeerAddress: peer.String()}

	buf, restore := captureSlog(t)
	ops := &fakeMgmtDNSRuleOps{}
	err := reconcileMgmtDNSRulesFiltered(ops, leases, mgmt, mainRoutes, cfg)
	restore()
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// Only the uncovered nameserver gets rules (4 scoped rules).
	if len(ops.rules) != 4 {
		t.Fatalf("installed %d rules, want 4 for uncovered only: %+v", len(ops.rules), ops.rules)
	}
	for _, r := range ops.rules {
		if r.Dst != nil && (r.Dst.IP.String() == covered.String() || r.Dst.IP.String() == peer.String()) {
			t.Fatalf("refused nameserver got a steering rule: %+v", r)
		}
	}
	ready, err := mgmtDNSRuleReadiness(ops)
	if err != nil {
		t.Fatal(err)
	}
	if ready[covered.String()] || ready[peer.String()] {
		t.Fatalf("refused nameserver ready: %v", ready)
	}
	if !ready[uncovered.String()] {
		t.Fatalf("uncovered nameserver should be ready: %v", ready)
	}
	// Publication gate: refused servers must not be published even if ready map lied.
	in := mergeDNSInputWithMgmtDNSRules(cfg, leases, mgmt, ready)
	for _, ns := range in.NameServers {
		if ns == covered.String() || ns == peer.String() {
			t.Fatalf("refused nameserver published: %v", in.NameServers)
		}
	}
	if !strings.Contains(buf.String(), covered.String()) {
		t.Fatalf("expected warning naming covered server, logs: %s", buf.String())
	}
	if !strings.Contains(buf.String(), peer.String()) {
		t.Fatalf("expected warning naming peer server, logs: %s", buf.String())
	}
	// Control: without main coverage / peer config, all three install.
	ops2 := &fakeMgmtDNSRuleOps{}
	if err := reconcileMgmtDNSRulesFiltered(ops2, leases, mgmt, nil, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	if len(ops2.rules) != 12 {
		t.Fatalf("control installed %d rules, want 12: %+v", len(ops2.rules), ops2.rules)
	}
}

func TestMgmtDNSRefusalIsExactPeerNotPrefix15059(t *testing.T) {
	// Peer equality is exact: a nameserver merely inside a peer's /24 (not
	// equal) and not main-covered must still be steered.
	mgmt := map[string]bool{"fxp0": true}
	server := netip.MustParseAddr("198.51.100.53")
	leases := []*dhcp.Lease{{Interface: "fxp0", Family: dhcp.AFInet, DNS: []netip.Addr{server}}}
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{PeerAddress: "198.51.100.2", FabricPeerAddress: "198.51.100.2"}
	ops := &fakeMgmtDNSRuleOps{}
	if err := reconcileMgmtDNSRulesFiltered(ops, leases, mgmt, nil, cfg); err != nil {
		t.Fatal(err)
	}
	if len(ops.rules) != 4 {
		t.Fatalf("non-peer nameserver refused incorrectly: %+v", ops.rules)
	}
}

// #16782: every operator static is FRR-installed as RTPROT_ZSTATIC (196),
// not RTPROT_STATIC (4), so the #15059 static leg was dead in production.
// A non-default 196 route must refuse; a 196 default (the FRR-rendered
// WAN DHCP default) must NOT refuse a legitimate mgmt nameserver.
func TestMgmtDNSRefusesFRRZStaticCoveredNameserver16782(t *testing.T) {
	mgmt := map[string]bool{"fxp0": true}
	covered := netip.MustParseAddr("10.20.0.53")
	legit := netip.MustParseAddr("198.51.101.53")
	leases := []*dhcp.Lease{{Interface: "fxp0", Family: dhcp.AFInet,
		DNS: []netip.Addr{covered, legit}}}
	mainRoutes := []netlink.Route{
		route15059("10.20.0.0/16", 196, unix.RT_TABLE_MAIN),
		// FRR-rendered default: covers everything, must not refuse legit.
		{Protocol: netlink.RouteProtocol(196), Table: unix.RT_TABLE_MAIN,
			Type: unix.RTN_UNICAST, Gw: net.ParseIP("198.51.100.1")},
	}
	if reason, refused := mgmtDNSRefusedNameserver(covered, mainRoutes, nil); !refused {
		t.Fatalf("proto-196 covered nameserver not refused")
	} else if !strings.Contains(reason, "static") || !strings.Contains(reason, "10.20.0.0/16") {
		t.Fatalf("refusal reason = %q, want static 10.20.0.0/16", reason)
	}
	if reason, refused := mgmtDNSRefusedNameserver(legit, mainRoutes, nil); refused {
		t.Fatalf("legit nameserver refused via default only: %q", reason)
	}
	// Manual RTPROT_STATIC default likewise must not refuse.
	if _, refused := mgmtDNSRefusedNameserver(legit, []netlink.Route{
		route15059("0.0.0.0/0", unix.RTPROT_STATIC, unix.RT_TABLE_MAIN),
	}, nil); refused {
		t.Fatal("RTPROT_STATIC default refused legit nameserver")
	}
	// Manual non-default static still refuses (pre-existing leg).
	if _, refused := mgmtDNSRefusedNameserver(covered, []netlink.Route{
		route15059("10.20.0.0/16", unix.RTPROT_STATIC, unix.RT_TABLE_MAIN),
	}, nil); !refused {
		t.Fatal("RTPROT_STATIC non-default no longer refuses")
	}
	// A 196 route in a non-main table must not refuse.
	if _, refused := mgmtDNSRefusedNameserver(covered, []netlink.Route{
		route15059("10.20.0.0/16", 196, 999),
	}, nil); refused {
		t.Fatal("table-999 196 route refused nameserver")
	}
	ops := &fakeMgmtDNSRuleOps{}
	if err := reconcileMgmtDNSRulesFiltered(ops, leases, mgmt, mainRoutes, &config.Config{}); err != nil {
		t.Fatal(err)
	}
	if len(ops.rules) != 4 {
		t.Fatalf("installed %d rules, want 4 for legit only: %+v", len(ops.rules), ops.rules)
	}
	if got := mgmtDNSRefusedSet(leases, mgmt, mainRoutes, &config.Config{}); !got[covered.String()] || got[legit.String()] {
		t.Fatalf("refused set = %v", got)
	}
	// IPv6 FRR static leg.
	v6 := netip.MustParseAddr("2001:db8:20::53")
	if _, refused := mgmtDNSRefusedNameserver(v6, []netlink.Route{
		route15059("2001:db8:20::/48", 196, unix.RT_TABLE_MAIN),
	}, nil); !refused {
		t.Fatal("IPv6 proto-196 covered nameserver not refused")
	}
}

// #16782 ordering: the first mgmt-DNS reconcile in applyConfigLocked runs
// before applyFRRFull, so a second reconcile must run after it or a
// nameserver newly covered by this commit's FRR statics stays steered.
func TestMgmtDNSReconcileRerunsAfterFRR16782(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_apply.go"))
	frr := strings.Index(src, "frrErr := d.applyFRRFull(cfg, commitOverlay)")
	if frr < 0 {
		t.Fatal("applyFRRFull call not found")
	}
	first := strings.Index(src, "d.applyMgmtDNSRules()")
	second := strings.Index(src[frr:], "d.applyMgmtDNSRules()")
	if first < 0 || first > frr {
		t.Fatal("pre-FRR applyMgmtDNSRules missing")
	}
	if second < 0 {
		t.Fatal("no applyMgmtDNSRules re-run after applyFRRFull (#16782)")
	}
}
