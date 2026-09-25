package grpcapi

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

const routeCap10708 = 100000

type routeLister10708 struct {
	total       int
	listCalls   int
	iterCalls   int
	iterVisited int
	multiPath   []*netlink.NexthopInfo
}

func (r *routeLister10708) route(n int) netlink.Route {
	route := netlink.Route{Dst: &net.IPNet{
		IP:   net.IPv4(10, byte(n>>16), byte(n>>8), byte(n)),
		Mask: net.CIDRMask(32, 32),
	}}
	if n == 0 {
		route.MultiPath = r.multiPath
	}
	return route
}

func (r *routeLister10708) RouteList(_ netlink.Link, family int) ([]netlink.Route, error) {
	r.listCalls++
	if family == netlink.FAMILY_V6 {
		return nil, nil
	}
	out := make([]netlink.Route, r.total)
	for i := range r.total {
		out[i] = r.route(i)
	}
	return out, nil
}

func (r *routeLister10708) RouteListFiltered(family int, _ *netlink.Route, _ uint64) ([]netlink.Route, error) {
	return r.RouteList(nil, family)
}

func (r *routeLister10708) RouteListFilteredIter(family int, _ *netlink.Route, _ uint64, fn func(netlink.Route) bool) error {
	r.iterCalls++
	if family == netlink.FAMILY_V6 {
		return nil
	}
	for i := range r.total {
		r.iterVisited++
		if !fn(r.route(i)) {
			return nil
		}
	}
	return nil
}

func (*routeLister10708) LinkByIndex(int) (netlink.Link, error) { return nil, nil }
func (*routeLister10708) LinkByName(string) (netlink.Link, error) { return nil, nil }

func TestGetRoutesCapStreamsKernelTable10708(t *testing.T) {
	lister := &routeLister10708{total: routeCap10708 + 1}
	s := &Server{routing: routing.NewManagerWithRouteListerForTest(lister)}
	resp, err := s.GetRoutes(context.Background(), &pb.GetRoutesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(resp.Routes); got != routeCap10708 {
		t.Fatalf("GetRoutes rendered %d routes; want cap %d", got, routeCap10708)
	}
	if resp.Routes[0].Destination != "10.0.0.0/32" || resp.Routes[len(resp.Routes)-1].Destination != "10.1.134.159/32" {
		t.Fatalf("unexpected bounded route endpoints: first=%q last=%q", resp.Routes[0].Destination, resp.Routes[len(resp.Routes)-1].Destination)
	}
	if lister.iterCalls == 0 || lister.listCalls != 0 {
		t.Fatalf("GetRoutes must use the incremental netlink iterator, iter=%d list=%d", lister.iterCalls, lister.listCalls)
	}
	if !resp.Truncated {
		t.Fatal("GetRoutes did not mark its omitted route as truncated")
	}
	if lister.iterVisited != routeCap10708+1 {
		t.Fatalf("visited %d routes to detect truncation, want exactly cap+1", lister.iterVisited)
	}
}

func TestGetRoutesECMPPathsCountAgainstResponseCap10708(t *testing.T) {
	nextHops := make([]*netlink.NexthopInfo, routeCap10708+1)
	for i := range nextHops {
		nextHops[i] = &netlink.NexthopInfo{
			Gw: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
		}
	}
	lister := &routeLister10708{total: 1, multiPath: nextHops}
	s := &Server{routing: routing.NewManagerWithRouteListerForTest(lister)}
	resp, err := s.GetRoutes(context.Background(), &pb.GetRoutesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Routes) != routeCap10708 || !resp.Truncated {
		t.Fatalf("ECMP response has %d paths, truncated=%v; want %d and true",
			len(resp.Routes), resp.Truncated, routeCap10708)
	}
	if resp.Routes[0].NextHop != "10.0.0.0" ||
		resp.Routes[len(resp.Routes)-1].NextHop != "10.1.134.159" {
		t.Fatalf("ECMP cap lost or reordered paths: first=%q last=%q",
			resp.Routes[0].NextHop, resp.Routes[len(resp.Routes)-1].NextHop)
	}
}

// Generate the table on demand, including on the old buffered executor path.
// The fixture itself must not allocate a whole RIB before the measurement.
type ribReader10708 struct {
	path      string
	total     int
	remaining  int
	line      string
	offset    int
	readBytes int
	closed    bool
}

func (r *ribReader10708) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) && r.remaining > 0 {
		if r.offset == 0 {
			index := r.total - r.remaining
			path := "65001"
			if r.path != "" {
				path += " " + r.path
			}
			r.line = fmt.Sprintf("*> 10.%d.%d.%d/32 192.0.2.1 0 %s i\n",
				byte(index>>16), byte(index>>8), byte(index), path)
		}
		copied := copy(p[n:], r.line[r.offset:])
		n += copied
		r.offset += copied
		if r.offset == len(r.line) {
			r.offset = 0
			r.remaining--
		}
	}
	r.readBytes += n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (r *ribReader10708) Close() error {
	r.closed = true
	return nil
}

type ribExecutor10708 struct {
	frr.RecordingExecutor
	reader   *ribReader10708
	finished bool
}

func (e *ribExecutor10708) Vtysh(context.Context, string) (string, error) {
	b, err := io.ReadAll(e.reader)
	return string(b), err
}

func (e *ribExecutor10708) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return e.reader, func() error { e.finished = true; return nil }, nil
}

func TestBGPRoutesCapAndBoundedAllocation10708(t *testing.T) {
	var firstAllocation uint64
	for _, total := range []int{routeCap10708 + 1, 4 * routeCap10708} {
		e := &ribExecutor10708{reader: &ribReader10708{total: total, remaining: total}}
		s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", e)}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		resp, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: "routes"})
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatal(err)
		}
		allocated := after.TotalAlloc - before.TotalAlloc
		t.Logf("table=%d allocated=%d output=%d upstream=%d", total, allocated, len(resp.Output), e.reader.readBytes)
		if got := strings.Count(resp.Output, "/32"); got != routeCap10708 {
			t.Errorf("table=%d rendered %d routes, want cap %d", total, got, routeCap10708)
		}
		if !strings.Contains(resp.Output, "... table truncated at 100000 routes") {
			t.Errorf("table=%d: missing visible truncation notice", total)
		}
		// Scanner read-ahead may include one 64 KiB buffer beyond cap+1.
		if e.reader.readBytes > (routeCap10708+1)*64+(64<<10) {
			t.Errorf("read %d upstream bytes: the handler materialized the table past the cap", e.reader.readBytes)
		}
		if !e.reader.closed || !e.finished {
			t.Error("capped RIB producer was not closed and reaped")
		}
		if firstAllocation == 0 {
			firstAllocation = allocated
		} else if allocated > firstAllocation+(8<<20) {
			t.Errorf("allocation grew with table size: %d -> %d bytes, want cap-bounded allocation", firstAllocation, allocated)
		}
	}
}

func TestBGPRoutesExactCapIsNotMarkedTruncated10708(t *testing.T) {
	e := &ribExecutor10708{reader: &ribReader10708{
		total: routeCap10708, remaining: routeCap10708,
	}}
	s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", e)}
	resp, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: "routes"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(resp.Output, "/32"); got != routeCap10708 {
		t.Fatalf("rendered %d routes at exact cap, want %d", got, routeCap10708)
	}
	if strings.Contains(resp.Output, "table truncated") {
		t.Fatal("exact-cap BGP table was marked truncated without an omitted route")
	}
	if e.reader.remaining != 0 || !e.reader.closed || !e.finished {
		t.Fatalf("exact-cap stream did not finish normally: remaining=%d closed=%v finished=%v",
			e.reader.remaining, e.reader.closed, e.finished)
	}
}

func TestGetRoutesExactCapIsNotMarkedTruncated10708(t *testing.T) {
	lister := &routeLister10708{total: routeCap10708}
	s := &Server{routing: routing.NewManagerWithRouteListerForTest(lister)}
	resp, err := s.GetRoutes(context.Background(), &pb.GetRoutesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Routes) != routeCap10708 || resp.Truncated {
		t.Fatalf("exact-cap result has %d routes, truncated=%v; want %d and false",
			len(resp.Routes), resp.Truncated, routeCap10708)
	}
	if lister.iterVisited != routeCap10708 {
		t.Fatalf("visited %d routes at exact cap; want %d without probing a nonexistent extra route",
			lister.iterVisited, routeCap10708)
	}
}

func TestBGPResponseByteCapTruncatesLongPaths10708(t *testing.T) {
	const total = 20
	e := &ribExecutor10708{reader: &ribReader10708{
		path: strings.Repeat("x", 768<<10), total: total, remaining: total,
	}}
	s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", e)}
	resp, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: "routes"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Output) > maxGRPCBGPOutputBytes {
		t.Fatalf("response is %d bytes, above %d-byte bound", len(resp.Output), maxGRPCBGPOutputBytes)
	}
	if got := strings.Count(resp.Output, "/32"); got == 0 || got >= total {
		t.Fatalf("rendered %d routes from %d oversized paths; want a non-empty bounded prefix", got, total)
	}
	if !strings.Contains(resp.Output, "response bytes") {
		t.Fatal("byte-limited BGP response lacks a truncation notice")
	}
	if e.reader.readBytes >= total*(768<<10) {
		t.Fatal("byte-limited BGP handler consumed the complete synthetic RIB")
	}
}
