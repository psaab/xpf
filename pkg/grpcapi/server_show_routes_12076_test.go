package grpcapi

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

const forwardingInstanceTableID12076 = 412001

type forwardingRouteLister12076 struct {
	route netlink.Route
}

func (f forwardingRouteLister12076) RouteListFiltered(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
	if filter == nil || filter.Table != forwardingInstanceTableID12076 {
		return nil, fmt.Errorf("route-table filter = %v; want table %d", filter, forwardingInstanceTableID12076)
	}
	if family == netlink.FAMILY_V6 {
		return nil, nil
	}
	return []netlink.Route{f.route}, nil
}
func (forwardingRouteLister12076) RouteList(_ netlink.Link, _ int) ([]netlink.Route, error) {
	return nil, nil
}
func (forwardingRouteLister12076) RouteListFilteredIter(int, *netlink.Route, uint64, func(netlink.Route) bool) error {
	return nil
}
func (forwardingRouteLister12076) LinkByIndex(int) (netlink.Link, error) {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "test0"}}, nil
}
func (forwardingRouteLister12076) LinkByName(name string) (netlink.Link, error) {
	return nil, fmt.Errorf("unexpected VRF lookup for %q", name)
}

func TestForwardingInstanceRouteHandlersUseConfiguredTableID12076(t *testing.T) {
	_, destination, err := net.ParseCIDR("10.9.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{{
		Name:         "fbf-isp",
		InstanceType: "forwarding",
		TableID:      forwardingInstanceTableID12076,
	}}}
	s := &Server{routing: routing.NewManagerWithRouteListerForTest(forwardingRouteLister12076{
		route: netlink.Route{Dst: destination, Gw: net.ParseIP("192.0.2.1")},
	})}

	tableResponse, err := s.showRouteTable(
		&pb.ShowTextRequest{Topic: "route-table:fbf-isp.inet.0"}, cfg, &strings.Builder{},
	)
	if err != nil {
		t.Fatalf("showRouteTable: %v", err)
	}
	if tableResponse == nil || !strings.Contains(tableResponse.Output, "10.9.0.0/24") {
		t.Fatalf("showRouteTable response = %+v; want configured forwarding-instance route", tableResponse)
	}

	testResponse, err := s.showTestRouting(
		&pb.ShowTextRequest{Topic: "test-routing:dest=10.9.0.5,instance=fbf-isp"}, cfg, &strings.Builder{},
	)
	if err != nil {
		t.Fatalf("showTestRouting: %v", err)
	}
	if testResponse == nil || !strings.Contains(testResponse.Output, "10.9.0.0/24") {
		t.Fatalf("showTestRouting response = %+v; want configured forwarding-instance route", testResponse)
	}
}
