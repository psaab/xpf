package routing

import (
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestStreamRoutesResolvesLinksOutsideNetlinkCallback10708(t *testing.T) {
	h, err := netlink.NewHandle()
	if err != nil {
		t.Skipf("create netlink handle: %v", err)
	}
	closeHandle := true
	defer func() {
		if closeHandle {
			h.Close()
		}
	}()

	links, err := h.LinkList()
	if err != nil {
		t.Skipf("list netlink links: %v", err)
	}
	linkNames := make(map[int]string, len(links))
	for _, link := range links {
		if link != nil && link.Attrs() != nil {
			linkNames[link.Attrs().Index] = link.Attrs().Name
		}
	}

	wantInterface := ""
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		err := h.RouteListFilteredIter(family, &netlink.Route{}, 0, func(route netlink.Route) bool {
			if name := linkNames[route.LinkIndex]; route.LinkIndex > 0 && name != "" {
				wantInterface = name
				return false
			}
			for _, nextHop := range route.MultiPath {
				if nextHop != nil {
					if name := linkNames[nextHop.LinkIndex]; nextHop.LinkIndex > 0 && name != "" {
						wantInterface = name
						return false
					}
				}
			}
			return true
		})
		if err != nil {
			t.Skipf("dump family %d routes: %v", family, err)
		}
		if wantInterface != "" {
			break
		}
	}
	if wantInterface == "" {
		t.Skip("main route table has no route attached to a listed link")
	}

	reader := &routeReader{ops: h}
	type result struct {
		found   bool
		stopped bool
		err     error
	}
	completed := make(chan result, 1)
	go func() {
		found := false
		stopped, err := reader.StreamRoutes(func(route RouteEntry) bool {
			if route.Interface == wantInterface {
				found = true
				return false
			}
			return true
		})
		completed <- result{found: found, stopped: stopped, err: err}
	}()

	select {
	case got := <-completed:
		if got.err != nil {
			t.Fatalf("StreamRoutes: %v", got.err)
		}
		if !got.found || !got.stopped {
			t.Fatalf("StreamRoutes found=%v stopped=%v for linked route %q", got.found, got.stopped, wantInterface)
		}
	case <-time.After(5 * time.Second):
		closeHandle = false // A regression may still hold the shared socket lock.
		t.Fatal("StreamRoutes deadlocked resolving a link from the netlink iterator callback")
	}
}
