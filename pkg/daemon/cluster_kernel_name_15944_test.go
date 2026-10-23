package daemon

import (
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15944 H23-02: cluster address resolution passed the AUTHORED Junos
// interface name ("ge-0/0/0.0") straight to net.InterfaceByName, which
// expects the kernel name ("ge-0-0-0"), so heartbeat/control and
// fabric/sync address selection degraded to the fallback despite the
// config compiling green. The resolver now threads
// cfg.ResolveKernelIfName through clusterInterfaceAddrsByName (the
// #5714 pattern resolveInterfaceAddrsDegraded already used).
//
// FAIL-ON-REVERT: dropping the ResolveKernelIfName call makes the stub
// record "ge-0/0/0.0" and the lookup miss, returning the fallback.

func stubClusterAddrs15944(t *testing.T, byKernel map[string][]net.Addr) *[]string {
	t.Helper()
	seen := &[]string{}
	prev := interfaceAddrsByName
	t.Cleanup(func() { interfaceAddrsByName = prev })
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		*seen = append(*seen, kernelName)
		addrs, ok := byKernel[kernelName]
		if !ok {
			return nil, errors.New("no such device")
		}
		return addrs, nil
	}
	return seen
}

func TestResolveClusterInterfaceAddrResolvesKernelName15944(t *testing.T) {
	addrs := []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)}}
	seen := stubClusterAddrs15944(t, map[string][]net.Addr{"ge-0-0-0": addrs})

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	got := resolveClusterInterfaceAddr(cfg, "ge-0/0/0.0", "10.0.0.9", "192.0.2.254")
	if got != "10.0.0.5" {
		t.Fatalf("resolveClusterInterfaceAddr(ge-0/0/0.0) = %q, want 10.0.0.5 (kernel ge-0-0-0)", got)
	}
	if len(*seen) == 0 || (*seen)[len(*seen)-1] != "ge-0-0-0" {
		t.Fatalf("kernel lookups = %v, want last lookup ge-0-0-0", *seen)
	}

	// Already-kernel names keep working, and a nil cfg keeps the
	// LinuxIfName-only behaviour for hand-built callers.
	if got := resolveClusterInterfaceAddr(nil, "ge-0/0/0", "10.0.0.9", ""); got != "10.0.0.5" {
		t.Fatalf("nil cfg: got %q, want 10.0.0.5", got)
	}
	// Unknown interface still degrades to the fallback.
	if got := resolveClusterInterfaceAddr(cfg, "ge-0/0/9.0", "", "192.0.2.254"); got != "192.0.2.254" {
		t.Fatalf("unknown iface: got %q, want fallback 192.0.2.254", got)
	}
}
