package daemon

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
)

// TestWebMgmtDualStackBindsBothFamilies14583 is the #14583 (Y07-02) decisive
// regression: a dual-stack web-management interface must yield BOTH an IPv4
// and an IPv6 listener per leg, not the single IPv4-first address the old
// resolveInterfaceAddr returned.
//
// FAIL-ON-REVERT: restoring the single-address resolver (or dropping the
// per-family expansion in resolveAPIBinds) leaves Addrs/HTTPSAddrs with one
// entry and this test goes RED.
func TestWebMgmtDualStackBindsBothFamilies14583(t *testing.T) {
	prev := interfaceAddrsByName
	defer func() { interfaceAddrsByName = prev }()
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		if kernelName == "ge-0-0-0" {
			return []net.Addr{
				&net.IPNet{IP: net.IPv4(10, 9, 9, 5), Mask: net.CIDRMask(24, 32)},
				&net.IPNet{IP: net.ParseIP("2001:db8::5"), Mask: net.CIDRMask(64, 128)},
			}, nil
		}
		return nil, errNoSuchIface14583(kernelName)
	}

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{
			HTTPS: true, HTTPSInterface: "ge-0/0/0.0", SystemGeneratedCert: true,
			APIAuth: webmgmtTestAuth(t),
		},
	}
	d := &Daemon{}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, cfg)
	want := []string{"10.9.9.5:443", "[2001:db8::5]:443"}
	if len(apiCfg.HTTPSAddrs) != len(want) {
		t.Fatalf("dual-stack HTTPSAddrs = %v, want %v (one listener per family)", apiCfg.HTTPSAddrs, want)
	}
	for i := range want {
		if apiCfg.HTTPSAddrs[i] != want[i] {
			t.Fatalf("HTTPSAddrs[%d] = %q, want %q (full %v)", i, apiCfg.HTTPSAddrs[i], want[i], apiCfg.HTTPSAddrs)
		}
	}
}

// TestWebMgmtLinkLocalOnlyZonedBind14583 pins the link-local half of #14583:
// a link-local-only interface must yield a ZONED bind (fe80::…%zone) that the
// kernel accepts, never the bare [fe80::…]:443 that failed EINVAL.
//
// FAIL-ON-REVERT: returning ipNet.IP.String() without the zone leaves the
// bind unscoped and this test goes RED.
func TestWebMgmtLinkLocalOnlyZonedBind14583(t *testing.T) {
	prev := interfaceAddrsByName
	defer func() { interfaceAddrsByName = prev }()
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		if kernelName == "ge-0-0-0" {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			}, nil
		}
		return nil, errNoSuchIface14583(kernelName)
	}

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.System.Services = &config.SystemServicesConfig{
		WebManagement: &config.WebManagementConfig{
			HTTPS: true, HTTPSInterface: "ge-0/0/0.0", SystemGeneratedCert: true,
			APIAuth: webmgmtTestAuth(t),
		},
	}
	d := &Daemon{}
	apiCfg := api.Config{Addr: "127.0.0.1:8080"}
	d.resolveAPIBinds(&apiCfg, cfg)
	if len(apiCfg.HTTPSAddrs) != 1 || apiCfg.HTTPSAddrs[0] != "[fe80::1%ge-0-0-0]:443" {
		t.Fatalf("link-local HTTPSAddrs = %v, want [[fe80::1%%ge-0-0-0]:443] (zoned bind)", apiCfg.HTTPSAddrs)
	}
	// The zoned spelling must carry the zone (the kernel EINVAL came from the
	// missing zone): SplitHostPort yields the scoped host verbatim.
	host, _, err := net.SplitHostPort(apiCfg.HTTPSAddrs[0])
	if err != nil {
		t.Fatalf("zoned bind %q does not split: %v", apiCfg.HTTPSAddrs[0], err)
	}
	if host != "fe80::1%ge-0-0-0" {
		t.Fatalf("zoned host = %q, want fe80::1%%ge-0-0-0", host)
	}
}

type errNoSuchIface14583 string

func (e errNoSuchIface14583) Error() string { return "no such kernel interface: " + string(e) }
