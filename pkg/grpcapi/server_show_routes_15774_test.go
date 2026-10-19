package grpcapi

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type routeLister15774 struct{ tableID int }

func (l routeLister15774) routes(family int) []netlink.Route {
	if family == netlink.FAMILY_V6 {
		return nil
	}
	mk := func(cidr string, proto int, gw string) netlink.Route {
		_, n, _ := net.ParseCIDR(cidr)
		r := netlink.Route{Dst: n, Protocol: netlink.RouteProtocol(proto), Priority: 5}
		if gw != "" {
			r.Gw = net.ParseIP(gw)
			r.LinkIndex = 11
		}
		return r
	}
	return []netlink.Route{
		mk("10.1.0.0/24", unix.RTPROT_KERNEL, ""),
		mk("10.2.0.0/24", unix.RTPROT_DHCP, "192.0.2.1"),
		{ // ECMP in VRF/main depending on caller view; LinkIndex resolved generically
			Dst:      func() *net.IPNet { _, n, _ := net.ParseCIDR("10.20.0.0/16"); return n }(),
			Protocol: netlink.RouteProtocol(unix.RTPROT_STATIC), Priority: 5,
			MultiPath: []*netlink.NexthopInfo{{LinkIndex: 11, Gw: net.ParseIP("192.0.2.1")}, {LinkIndex: 12, Gw: net.ParseIP("192.0.2.2")}},
		},
	}
}
func (l routeLister15774) RouteList(_ netlink.Link, family int) ([]netlink.Route, error) {
	return l.routes(family), nil
}
func (l routeLister15774) RouteListFiltered(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
	if filter == nil || filter.Table != l.tableID {
		return nil, fmt.Errorf("table filter = %v, want %d", filter, l.tableID)
	}
	if family == netlink.FAMILY_V6 {
		return nil, nil
	}
	_, n, _ := net.ParseCIDR("10.9.0.0/24")
	return []netlink.Route{{Dst: n, Gw: net.ParseIP("192.0.2.9"), LinkIndex: 11, Protocol: netlink.RouteProtocol(unix.RTPROT_KERNEL), Priority: 5}}, nil
}
func (routeLister15774) RouteListFilteredIter(int, *netlink.Route, uint64, func(netlink.Route) bool) error {
	return nil
}
func (routeLister15774) LinkByIndex(index int) (netlink.Link, error) {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("ge-0-0-%d", index-11)}}, nil
}
func (routeLister15774) LinkByName(name string) (netlink.Link, error) {
	return nil, fmt.Errorf("unexpected VRF lookup %q", name)
}

type frrExec15774 struct{ frr.RecordingExecutor }

func (frrExec15774) Vtysh(_ context.Context, cmd string) (string, error) {
	switch cmd {
	case "show ip route vrf all json":
		return `{"vrf-blue":{"10.9.0.0/24":[{"prefix":"10.9.0.0/24","protocol":"static","selected":true,"installed":true,"distance":5,"table":100,"nexthops":[{"ip":"192.0.2.1","interfaceName":"ge-0-0-0","active":true,"fib":true}]}]}}`, nil
	case "show ipv6 route vrf all json":
		return `{}`, nil
	}
	return "", fmt.Errorf("unexpected vtysh %q", cmd)
}

func server15774(t *testing.T) (*Server, *config.Config) {
	t.Helper()
	const tableID = 412074
	cfg := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{{Name: "blue", InstanceType: "virtual-router", TableID: tableID}}}
	s := &Server{
		routing: routing.NewManagerWithRouteListerForTest(routeLister15774{tableID: tableID}),
		frr:     frr.NewForTest(t.TempDir()+"/frr.conf", &frrExec15774{}),
	}
	return s, cfg
}

func TestGRPCRouteProtocolParity15774(t *testing.T) {
	s, cfg := server15774(t)
	resp, err := s.showRouteProtocol(&pb.ShowTextRequest{Topic: "route-protocol:direct"}, cfg, &strings.Builder{})
	if err != nil {
		t.Fatalf("showRouteProtocol direct: %v", err)
	}
	for _, want := range []string{"10.1.0.0/24", "10.9.0.0/24"} {
		if !strings.Contains(resp.Output, want) {
			t.Errorf("gRPC protocol direct missing %s:\n%s", want, resp.Output)
		}
	}
	// alias case-insensitivity
	resp, err = s.showRouteProtocol(&pb.ShowTextRequest{Topic: "route-protocol:Access-internal"}, cfg, &strings.Builder{})
	if err != nil || !strings.Contains(resp.Output, "10.2.0.0/24") {
		t.Fatalf("Access-internal = %v %+v", err, resp)
	}
	// ECMP legs in protocol view
	resp, err = s.showRouteProtocol(&pb.ShowTextRequest{Topic: "route-protocol:static"}, cfg, &strings.Builder{})
	if err != nil || !strings.Contains(resp.Output, "192.0.2.2") {
		t.Fatalf("protocol static ECMP second leg missing: %v\n%+v", err, resp)
	}
	// unknown fails loudly
	_, err = s.showRouteProtocol(&pb.ShowTextRequest{Topic: "route-protocol:bogusproto"}, cfg, &strings.Builder{})
	if err == nil || status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bogus protocol err = %v, want InvalidArgument", err)
	}
}

func TestGRPCRouteTerseDetailInstanceParity15774(t *testing.T) {
	s, cfg := server15774(t)
	var tb strings.Builder
	if err := s.showRouteTerse(cfg, &tb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tb.String(), "10.9.0.0/24") {
		t.Errorf("gRPC terse missing VRF route:\n%s", tb.String())
	}
	if !strings.Contains(tb.String(), "192.0.2.2") {
		t.Errorf("gRPC terse missing ECMP leg:\n%s", tb.String())
	}
	var db strings.Builder
	if err := s.showRouteDetail(context.Background(), &db); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(db.String(), "10.9.0.0/24") || !strings.Contains(db.String(), "vrf-blue") {
		t.Errorf("gRPC detail missing VRF route:\n%s", db.String())
	}
	// instance view with TableID 0 must fall back to VRF-device lookup via GetInstanceRoutes
	cfg2 := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{{Name: "blue", InstanceType: "virtual-router", TableID: 0}}}
	var ib strings.Builder
	s.showRouteInstance("blue", cfg2, &ib)
	if strings.Contains(ib.String(), "(table 0)") {
		t.Errorf("instance view rendered bogus table 0:\n%s", ib.String())
	}
	if !strings.Contains(ib.String(), "not found") {
		t.Errorf("instance view should surface VRF lookup failure, got:\n%s", ib.String())
	}
	// ECMP in instance view (configured table)
	var ib2 strings.Builder
	s.showRouteInstance("blue", cfg, &ib2)
	if !strings.Contains(ib2.String(), "10.9.0.0/24") {
		t.Errorf("instance view missing route:\n%s", ib2.String())
	}
}
