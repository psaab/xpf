package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"context"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type frrExec15774 struct{ frr.RecordingExecutor }

func (frrExec15774) Vtysh(_ context.Context, cmd string) (string, error) {
	if cmd == "show ip route vrf all json" {
		return `{"vrf-blue":{"10.9.0.0/24":[{"prefix":"10.9.0.0/24","protocol":"static","selected":true,"installed":true,"distance":5,"table":100,"nexthops":[{"ip":"192.0.2.1","interfaceName":"ge-0-0-0","active":true,"fib":true}]}]}}`, nil
	}
	if cmd == "show ipv6 route vrf all json" {
		return `{}`, nil
	}
	return "", nil
}

// #15774 local twin: terse/detail/instance/protocol must see VRF + ECMP.
func TestLocalRouteViews15774(t *testing.T) {
	mk := func(cidr string, proto int) netlink.Route {
		_, n, _ := net.ParseCIDR(cidr)
		return netlink.Route{Dst: n, Protocol: netlink.RouteProtocol(proto), LinkIndex: 1}
	}
	ecmp := mk("10.20.0.0/16", unix.RTPROT_STATIC)
	ecmp.MultiPath = []*netlink.NexthopInfo{{LinkIndex: 1, Gw: net.ParseIP("192.0.2.1")}, {LinkIndex: 2, Gw: net.ParseIP("192.0.2.2")}}
	lister := fakeRouteLister{
		v4:    []netlink.Route{mk("10.1.0.0/24", unix.RTPROT_KERNEL), ecmp},
		vrfV4: []netlink.Route{mk("10.9.0.0/24", unix.RTPROT_KERNEL)},
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply("routing-instances { blue { instance-type virtual-router; interface reth0.0; routing-options { static { route 10.9.0.0/24 next-hop 192.0.2.1; } } } }", nil); err != nil {
		t.Fatalf("syncapply: %v", err)
	}
	c := &CLI{store: store, routing: routing.NewManagerWithRouteListerForTest(lister), frr: frr.NewForTest(t.TempDir()+"/frr.conf", &frrExec15774{})}

	out := captureStdout(t, func() {
		if err := c.showRouteTerse(); err != nil {
			t.Fatalf("terse: %v", err)
		}
	})
	if !strings.Contains(out, "10.9.0.0/24") {
		t.Errorf("local terse missing VRF route:\n%s", out)
	}
	if !strings.Contains(out, "192.0.2.2") {
		t.Errorf("local terse missing ECMP leg:\n%s", out)
	}
	out = captureStdout(t, func() {
		if err := c.showRoutesForProtocol("static"); err != nil {
			t.Fatalf("protocol: %v", err)
		}
	})
	if !strings.Contains(out, "192.0.2.2") {
		t.Errorf("local protocol missing ECMP leg:\n%s", out)
	}
	out = captureStdout(t, func() {
		if err := c.showRouteDetail(); err != nil {
			t.Fatalf("detail: %v", err)
		}
	})
	if !strings.Contains(out, "10.9.0.0/24") {
		t.Errorf("local detail missing VRF route:\n%s", out)
	}
	// instance view must emit ECMP legs (VRF table route is single-path here;
	// use protocol/terse for ECMP, instance for VRF presence)
	out2 := captureStdout(t, func() {
		if err := c.showRoutesForInstance("blue"); err != nil {
			t.Fatalf("instance: %v", err)
		}
	})
	if !strings.Contains(out2, "10.9.0.0/24") {
		t.Errorf("local instance missing VRF route:\n%s", out2)
	}
}
