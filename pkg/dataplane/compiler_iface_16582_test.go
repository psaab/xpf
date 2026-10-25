package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #16582: the zone loop must not LinkSetUp a GRE tunnel a keepalive
// runner holds down. Driven through the REAL programZoneMaps ->
// mapZoneInterface path over a simulated host (the #8119 fixture
// shape): the tunnel netdev starts admin DOWN (keepalive took it
// down), the resolver reports it held down, and the compile must
// leave it down. Controls: no resolver and resolver-not-held both
// bring it up (pre-#16582 behaviour for ordinary interfaces).

type heldDownDP16582 struct{ DataPlane }

func (heldDownDP16582) SetZoneConfig(uint16, ZoneConfig) error { return nil }
func (heldDownDP16582) SetZone(int, uint16, uint16, uint32, uint8, uint8, uint32) error {
	return nil
}
func (heldDownDP16582) AddTxPort(int) error                     { return nil }
func (heldDownDP16582) SetVlanIfaceInfo(int, int, uint16) error { return nil }

const heldDownPhys16582 = "gr-0-0-0"
const heldDownIdx16582 = 4299

func heldDownConfig16582() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"vpn": {Name: "vpn", Interfaces: []string{heldDownPhys16582 + ".0"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		heldDownPhys16582: {
			Name: heldDownPhys16582,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0},
			},
			Tunnel: &config.TunnelConfig{Name: heldDownPhys16582},
		},
	}
	return cfg
}

// runHeldDownCompile drives one compileZones-equivalent zone pass
// and returns how many times the zone loop called LinkSetUp on the
// tunnel netdev. The link starts WITHOUT IFF_UP.
func runHeldDownCompile16582(t *testing.T) int {
	t.Helper()
	cfg := heldDownConfig16582()
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	result.rxTagStripOffCache[heldDownPhys16582] = true
	link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{
		Name:  heldDownPhys16582,
		Index: heldDownIdx16582,
		// No FlagUp: keepalive holds the tunnel admin DOWN.
	}}
	result.ifCache[heldDownPhys16582] = &net.Interface{Index: heldDownIdx16582, Name: heldDownPhys16582}
	result.linkCache[heldDownPhys16582] = link
	result.linkIdxMap[heldDownIdx16582] = link

	ups := 0
	oldUp, oldDown := zoneLinkSetUpSeam, zoneLinkSetDownSeam
	t.Cleanup(func() { zoneLinkSetUpSeam, zoneLinkSetDownSeam = oldUp, oldDown })
	zoneLinkSetUpSeam = func(netlink.Link) error { ups++; return nil }
	zoneLinkSetDownSeam = func(netlink.Link) error { return nil }

	if _, err := programZoneMaps(heldDownDP16582{}, cfg, result); err != nil {
		t.Fatalf("programZoneMaps: %v", err)
	}
	return ups
}

func TestZoneLoopLeavesKeepaliveHeldDownTunnelDown16582(t *testing.T) {
	t.Cleanup(func() { SetTunnelHeldDownResolver(nil) })
	SetTunnelHeldDownResolver(func(linuxName string) bool {
		return linuxName == heldDownPhys16582
	})
	if ups := runHeldDownCompile16582(t); ups != 0 {
		t.Fatalf("zone loop re-upped a keepalive-held-down tunnel: LinkSetUp calls=%d, want 0", ups)
	}
}

func TestZoneLoopHeldDownControls16582(t *testing.T) {
	t.Cleanup(func() { SetTunnelHeldDownResolver(nil) })

	// No resolver registered (non-daemon embedder): pre-#16582
	// behaviour — the zone loop brings the interface up.
	SetTunnelHeldDownResolver(nil)
	if ups := runHeldDownCompile16582(t); ups != 1 {
		t.Fatalf("no-resolver control: LinkSetUp calls=%d, want 1", ups)
	}

	// Resolver present but tunnel not held down: still brought up.
	SetTunnelHeldDownResolver(func(string) bool { return false })
	if ups := runHeldDownCompile16582(t); ups != 1 {
		t.Fatalf("not-held control: LinkSetUp calls=%d, want 1", ups)
	}

	// Resolver keyed by a DIFFERENT netdev name must not suppress
	// this tunnel's bring-up (the predicate is per-Linux-name).
	SetTunnelHeldDownResolver(func(linuxName string) bool { return linuxName == "gr-9-9-9" })
	if ups := runHeldDownCompile16582(t); ups != 1 {
		t.Fatalf("other-tunnel control: LinkSetUp calls=%d, want 1", ups)
	}
}
