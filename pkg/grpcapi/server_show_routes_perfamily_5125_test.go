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
	"golang.org/x/sys/unix"
)

// perFamilyFailLister is a routeLister double (satisfied structurally — the
// interface is unexported in pkg/routing but all its methods are exported)
// that succeeds for IPv4 and fails for IPv6. It backs the #5125 CALLER-side
// fail-on-revert test: the `show route` render callers must RENDER the
// successful IPv4 partial AND emit a non-fatal warning, never bail on the
// per-family error and drop the whole display.
type perFamilyFailLister struct{}

func (perFamilyFailLister) routesFor(family int) ([]netlink.Route, error) {
	if family == netlink.FAMILY_V6 {
		return nil, fmt.Errorf("simulated netlink dump failure for IPv6")
	}
	_, dst, _ := net.ParseCIDR("10.0.1.0/24")
	return []netlink.Route{{
		Dst:      dst,
		Gw:       net.ParseIP("10.0.1.1"),
		Protocol: netlink.RouteProtocol(unix.RTPROT_STATIC),
		Priority: 5,
	}}, nil
}

func (f perFamilyFailLister) RouteListFiltered(family int, _ *netlink.Route, _ uint64) ([]netlink.Route, error) {
	return f.routesFor(family)
}
func (f perFamilyFailLister) RouteList(_ netlink.Link, family int) ([]netlink.Route, error) {
	return f.routesFor(family)
}
func (f perFamilyFailLister) RouteListFilteredIter(family int, _ *netlink.Route, _ uint64, fn func(netlink.Route) bool) error {
	routes, err := f.routesFor(family)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if !fn(route) {
			break
		}
	}
	return nil
}
func (perFamilyFailLister) LinkByIndex(int) (netlink.Link, error) {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-0"}}, nil
}
func (perFamilyFailLister) LinkByName(name string) (netlink.Link, error) {
	return nil, fmt.Errorf("link %q not found", name)
}

func serverWithPartialRouting() *Server {
	rm := routing.NewManagerWithRouteListerForTest(perFamilyFailLister{})
	return &Server{routing: rm}
}

// TestShowRouteAllRendersPartialAndWarns is the KEY #5125 caller-side test.
// With IPv6 dumps failing and IPv4 succeeding, showRouteAll must:
//
//	(a) NOT return an error (non-fatal — the caller must not bail), and
//	(b) render the successful IPv4 route (partial preserved), and
//	(c) emit an in-band warning that surfaces the per-family failure.
//
// It goes RED two ways:
//   - if a caller reverts to `if err != nil { return ...Errorf }` it drops
//     the render (no IPv4 route, an error returned) — fails (a) and (b);
//   - if the backend reverts to swallowing the error, err is nil so no
//     warning is emitted — fails (c).
func TestShowRouteAllRendersPartialAndWarns(t *testing.T) {
	s := serverWithPartialRouting()
	var buf strings.Builder

	if err := s.showRouteAll(&config.Config{}, &buf); err != nil {
		t.Fatalf("showRouteAll must not bail on a per-family failure; got err %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "10.0.1.0/24") {
		t.Errorf("successful IPv4 route must still render (partial not dropped); output:\n%s", out)
	}
	if !strings.Contains(out, "warning") || !strings.Contains(out, "inet6") {
		t.Errorf("per-family failure must be surfaced as an in-band warning naming inet6; output:\n%s", out)
	}
}

// TestShowRouteTerseRendersPartialAndWarns is the terse-view mirror.
func TestShowRouteTerseRendersPartialAndWarns(t *testing.T) {
	s := serverWithPartialRouting()
	var buf strings.Builder

	if err := s.showRouteTerse(&buf); err != nil {
		t.Fatalf("showRouteTerse must not bail on a per-family failure; got err %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "10.0.1.0/24") {
		t.Errorf("successful IPv4 route must still render; output:\n%s", out)
	}
	if !strings.Contains(out, "warning") {
		t.Errorf("per-family failure must be surfaced as an in-band warning; output:\n%s", out)
	}
}

// TestGetRoutesRPCReturnsPartialNotError proves the structured GetRoutes RPC
// returns the successful IPv4 routes on a partial per-family failure (logging
// the error) instead of dropping the whole response with an Internal error.
func TestGetRoutesRPCReturnsPartialNotError(t *testing.T) {
	s := serverWithPartialRouting()

	resp, err := s.GetRoutes(nil, &pb.GetRoutesRequest{})
	if err != nil {
		t.Fatalf("GetRoutes RPC must return the partial, not a hard error; got %v", err)
	}
	if resp == nil || len(resp.Routes) == 0 {
		t.Fatalf("expected the successful IPv4 route in the partial response; got %+v", resp)
	}
	var sawV4 bool
	for _, r := range resp.Routes {
		if r.Destination == "10.0.1.0/24" {
			sawV4 = true
		}
	}
	if !sawV4 {
		t.Errorf("successful IPv4 route missing from partial response: %+v", resp.Routes)
	}
}
