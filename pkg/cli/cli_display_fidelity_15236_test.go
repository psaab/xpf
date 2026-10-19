package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #15236 A52-02: completion spellings must match, VRF tables must be scanned,
// unknown protocols must be rejected.
func TestShowRouteProtocolAliases15236(t *testing.T) {
	mk := func(cidr string, proto int) netlink.Route {
		_, n, _ := net.ParseCIDR(cidr)
		return netlink.Route{Dst: n, Protocol: netlink.RouteProtocol(proto)}
	}
	lister := fakeRouteLister{
		v4: []netlink.Route{
			mk("10.1.0.0/24", unix.RTPROT_KERNEL),
			mk("10.2.0.0/24", unix.RTPROT_DHCP),
			mk("10.3.0.0/24", unix.RTPROT_STATIC),
		},
		vrfV4: []netlink.Route{mk("10.9.0.0/24", unix.RTPROT_KERNEL)},
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply("routing-instances { blue { instance-type virtual-router; interface reth0.0; routing-options { static { route 10.9.0.0/24 next-hop 192.0.2.1; } } } }", nil); err != nil {
		// TableID may be assigned by sync apply; if fixture shape differs, still exercise main+VRF via manager below.
		t.Logf("syncapply: %v", err)
	}
	c := &CLI{store: store, routing: routing.NewManagerWithRouteListerForTest(lister)}
	// Ensure a routing instance exists for GetAllTableRoutes if config compiled one;
	// otherwise the VRF leg is covered by routing-level test below.
	// VRF/other-table routes must also be scanned (GetAllTableRoutes).
	{
		cfg := store.ActiveConfig()
		if cfg == nil || len(cfg.RoutingInstances) == 0 {
			t.Fatalf("fixture has no routing instance: %+v", cfg)
		}
		t.Logf("instances: %+v", cfg.RoutingInstances[0])
		out := captureStdout(t, func() {
			if err := c.showRoutesForProtocol("direct"); err != nil {
				t.Fatalf("direct: %v", err)
			}
		})
		if !strings.Contains(out, "10.9.0.0/24") {
			t.Errorf("direct missing VRF-table connected route 10.9.0.0/24:\n%s", out)
		}
	}
	for _, proto := range []string{"direct", "local", "kernel", "connected"} {
		out := captureStdout(t, func() {
			if err := c.showRoutesForProtocol(proto); err != nil {
				t.Fatalf("protocol %s: %v", proto, err)
			}
		})
		if !strings.Contains(out, "10.1.0.0/24") {
			t.Errorf("protocol %s missing connected route:\n%s", proto, out)
		}
	}
	out := captureStdout(t, func() {
		if err := c.showRoutesForProtocol("Access-internal"); err != nil {
			t.Fatalf("Access-internal: %v", err)
		}
	})
	if !strings.Contains(out, "10.2.0.0/24") {
		t.Errorf("Access-internal missing dhcp route:\n%s", out)
	}
	if err := c.showRoutesForProtocol("bogusproto"); err == nil {
		t.Error("unknown protocol must be rejected, not print (no routes)")
	}
	// Routing-level alias unit checks.
	for token, want := range map[string]string{"direct": "connected", "local": "connected", "kernel": "connected", "Access-internal": "dhcp", "IS-IS": "isis"} {
		if got := routing.NormalizeRouteProtocol(token); got != want {
			t.Errorf("NormalizeRouteProtocol(%q)=%q want %q", token, got, want)
		}
	}
	if got := routing.NormalizeRouteProtocol("bogus"); got != "" {
		t.Errorf("unknown normalized to %q, want empty", got)
	}
}

// #15236 A52-03: SessionHAState derives RG from reth, not RG0.
func TestSessionHAState15236(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1": {Name: "reth1", RedundancyGroup: 1},
		"reth2": {Name: "reth2", RedundancyGroup: 2},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth1.0"}},
	}
	primary := func(rg int) (bool, bool) {
		switch rg {
		case 0:
			return true, true // RG0 primary — must NOT drive the result
		case 1:
			return false, true // data RG1 backup
		case 2:
			return true, true
		}
		return false, false
	}
	if got := config.SessionHAState(cfg, "reth1.0", "", 0, 0, nil, primary); got != "Backup" {
		t.Errorf("reth1 session HA=%q want Backup (RG1, not RG0 Active)", got)
	}
	if got := config.SessionHAState(cfg, "reth2", "", 0, 0, nil, primary); got != "Active" {
		t.Errorf("reth2 session HA=%q want Active", got)
	}
	if got := config.SessionHAState(cfg, "ge-0/0/9", "", 0, 0, nil, primary); got != "unknown" {
		t.Errorf("unowned iface HA=%q want unknown", got)
	}
	if got := config.SessionHAState(cfg, "", "", 7, 0, map[uint16]string{7: "trust"}, primary); got != "Backup" {
		t.Errorf("zone-derived HA=%q want Backup", got)
	}
}

// #15236 A52-04: peer summary request carries filters.
func TestBuildPeerSummaryRequest15236(t *testing.T) {
	_, src, _ := net.ParseCIDR("10.0.0.0/8")
	f := sessionFilter{zoneID: 3, hasProto: true, proto: 6, srcNet: src, dstPort: 443, natOnly: true, appName: "junos-https", iface: "reth1.0", snatPool: "pool1"}
	req := buildPeerSummaryRequest(f)
	if req.Zone != 3 || req.Protocol == "" || req.SourcePrefix != "10.0.0.0/8" || req.DestinationPort != 443 || !req.NatOnly || req.Application != "junos-https" || req.InterfaceFilter != "reth1.0" || req.SourceNatPool != "pool1" {
		t.Errorf("summary request dropped filters: %+v", req)
	}
	if got := buildPeerSummaryRequest(sessionFilter{}); got.Zone != 0 || got.Protocol != "" {
		t.Errorf("empty filter should stay unfiltered: %+v", got)
	}
	var _ = pb.GetSessionSummaryRequest{}
}

// stats DP for A52-05
type stats15236DP struct {
	dataplane.DataPlane
}

func (d *stats15236DP) IsLoaded() bool           { return true }
func (d *stats15236DP) SessionCount() (int, int) { return 7, 5 }
func (d *stats15236DP) ReadGlobalCounter(idx uint32) (uint64, error) {
	switch idx {
	case dataplane.GlobalCtrSessionsNew:
		return 100, nil
	case dataplane.GlobalCtrSessionsClosed:
		return 30, nil
	}
	return 0, nil
}

// #15236 A52-05: Current sessions is occupancy (12), not 100-30=70.
func TestShowFlowStatisticsCurrentSessions15236(t *testing.T) {
	c := &CLI{dp: &stats15236DP{}}
	out := captureStdout(t, func() {
		if err := c.showFlowStatistics(); err != nil {
			t.Fatalf("showFlowStatistics: %v", err)
		}
	})
	if !strings.Contains(out, "Current sessions:") || !strings.Contains(out, "12") {
		t.Errorf("Current sessions should be SessionCount 12:\n%s", out)
	}
	if strings.Contains(out, "Current sessions:                70") {
		t.Errorf("Current sessions still create-minus-close 70:\n%s", out)
	}
	if !strings.Contains(out, "Local forwarding sessions (created-closed):") {
		t.Errorf("local gauge should be relabelled:\n%s", out)
	}
}

// #15236 A52-07: packet-drop filter predicate — numeric protocol + Junos iface.
func TestPacketDropPredicate15236(t *testing.T) {
	canonical, ok := normalizeMonitorProtocol("6")
	if !ok || canonical == "" {
		t.Fatalf("normalize 6: %q %v", canonical, ok)
	}
	f := &monitorFlowFilter{Protocol: canonical}
	rec := &logging.EventRecord{Protocol: "TCP", ProtocolNum: 6, IngressIface: "ge-0-0-0"}
	if !f.matches(rec) {
		t.Error("numeric protocol 6 must match TCP record")
	}
	if f.matches(&logging.EventRecord{Protocol: "UDP", ProtocolNum: 17, IngressIface: "ge-0-0-0"}) {
		t.Error("protocol 6 must not match UDP")
	}
	if !monitorIfaceNamesMatch("ge-0/0/0", "ge-0-0-0") {
		t.Error("Junos iface ge-0/0/0 must match Linux ge-0-0-0")
	}
	if _, ok := normalizeMonitorProtocol("bogus"); ok {
		t.Error("bogus protocol must be rejected")
	}
	var _ = cluster.NewManager
}
