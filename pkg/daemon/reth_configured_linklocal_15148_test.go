package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #15148 (B05-01): a configured fe80::1/64 on a RETH unit is the operator's
// router link-local (installed as an RG VIP on the primary). The per-member
// link tail stripped every link-local except the auto stable pattern and
// then added a per-node EUI-64, so the configured address disappeared on
// every apply until the 2s direct-mode VIP reconcile re-added it, while a
// per-node EUI-64 stayed on the owner.
//
// Fail-on-revert (each verified by restoring the pre-fix behaviour):
//   - strip: drop the configured exemption from linkLocalShouldKeep and
//     TestRethConfiguredLinkLocalSurvivesStrip15148 deletes fe80::1.
//   - ensure-suppression: drop the configured guard from
//     ensureRethLinkLocalExcluding (or route the parent repair through the
//     old unconditional ensure) and the EUI-64 add fires.
//   - wiring: route the parent tail through the old unconditional
//     remove/ensure pair and the configured address never reaches the seam.

func stubRethLinkLocalSeams15148(t *testing.T, mac net.HardwareAddr, live []net.IP) (deleted, added *[]net.IP) {
	t.Helper()
	deleted = &[]net.IP{}
	added = &[]net.IP{}
	// Stateful fake link: AddrDel really removes the address, so the
	// subsequent ensure sees the post-strip state exactly as on a live
	// netdev. Without this the ensure's "already have one" check would see
	// the just-deleted stale address and skip the EUI-64.
	state := append([]net.IP(nil), live...)
	origAddrs, origDel, origAdd := rethLinkAddrsFn, rethLinkAddrDelFn, rethLinkAddrAddFn
	rethLinkAddrsFn = func(string) (netlink.Link, []netlink.Addr, error) {
		link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{
			HardwareAddr: mac,
		}}
		addrs := make([]netlink.Addr, 0, len(state))
		for _, ip := range state {
			addrs = append(addrs, netlink.Addr{
				IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)},
			})
		}
		return link, addrs, nil
	}
	rethLinkAddrDelFn = func(_ netlink.Link, addr *netlink.Addr) error {
		*deleted = append(*deleted, addr.IP)
		for i, ip := range state {
			if ip.Equal(addr.IP) {
				state = append(state[:i], state[i+1:]...)
				break
			}
		}
		return nil
	}
	rethLinkAddrAddFn = func(_ netlink.Link, addr *netlink.Addr) error {
		*added = append(*added, addr.IPNet.IP)
		state = append(state, addr.IPNet.IP)
		return nil
	}
	t.Cleanup(func() {
		rethLinkAddrsFn, rethLinkAddrDelFn, rethLinkAddrAddFn = origAddrs, origDel, origAdd
	})
	return deleted, added
}

func equalIPs(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func eui64FromMAC15148(mac net.HardwareAddr) net.IP {
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

// The exact claimed mechanism on the parent: live fe80::1 (the configured
// VIP) plus a stale kernel auto address. The strip must keep fe80::1,
// delete only the stale address, and add no EUI-64.
func TestRethConfiguredLinkLocalSurvivesStrip15148(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0xbf, 0x72, 1, 2, 3}
	configured := net.ParseIP("fe80::1")
	stale := net.ParseIP("fe80::dead:beef")
	deleted, added := stubRethLinkLocalSeams15148(t, mac, []net.IP{configured, stale})

	cfg := &config.InterfaceConfig{
		Name: "reth0",
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"fe80::1/64", "2001:db8::8/64"}},
		},
	}
	rethParentLinkLocalRepair("ge-0-0-1", cfg)

	if !equalIPs(*deleted, []net.IP{stale}) {
		t.Fatalf("deleted = %v, want only the stale auto link-local %v; "+
			"the configured fe80::1 must survive the per-apply strip (#15148)", *deleted, stale)
	}
	if len(*added) != 0 {
		t.Fatalf("added = %v, want none: a configured link-local must not be "+
			"replaced/supplemented by a per-node EUI-64 (#15148)", *added)
	}
}

// The VLAN-child twin: the configured fe80::1 lives on unit 80 (vlan-id 180).
// The child strip must keep it and the ensure must not add an EUI-64.
func TestRethConfiguredLinkLocalSurvivesVlanStrip15148(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0xbf, 0x72, 1, 2, 3}
	configured := net.ParseIP("fe80::1")
	stale := net.ParseIP("fe80::dead:beef")
	deleted, added := stubRethLinkLocalSeams15148(t, mac, []net.IP{configured, stale})

	origRemove, origEnsure := removeAutoLinkLocalFn, ensureRethLinkLocalFn
	removeAutoLinkLocalFn = removeAutoLinkLocalExcluding
	ensureRethLinkLocalFn = ensureRethLinkLocalExcluding
	t.Cleanup(func() { removeAutoLinkLocalFn, ensureRethLinkLocalFn = origRemove, origEnsure })

	cfg := &config.InterfaceConfig{
		Name: "reth0",
		Units: map[int]*config.InterfaceUnit{
			80: {Number: 80, VlanID: 180, Addresses: []string{
				"fe80::1/64", "2001:db8:80::8/64"}},
		},
	}
	rethSubIfaceLinkLocalRepair(cfg, "ge-7-0-1.180")

	if !equalIPs(*deleted, []net.IP{stale}) {
		t.Fatalf("deleted = %v, want only the stale auto link-local %v; "+
			"the configured fe80::1 on the VLAN unit must survive (#15148)", *deleted, stale)
	}
	if len(*added) != 0 {
		t.Fatalf("added = %v, want none: no EUI-64 on a VLAN child with a "+
			"configured link-local (#15148)", *added)
	}
}

// Control: with no configured link-local, the pre-existing behaviour is
// unchanged — a stale auto address is stripped and an EUI-64 is ensured on
// an IPv6 unit.
func TestRethNoConfiguredLinkLocalStillEnsuresEUI6415148(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0xbf, 0x72, 1, 2, 3}
	stale := net.ParseIP("fe80::dead:beef")
	deleted, added := stubRethLinkLocalSeams15148(t, mac, []net.IP{stale})

	cfg := &config.InterfaceConfig{
		Name: "reth0",
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"2001:db8::8/64"}},
		},
	}
	rethParentLinkLocalRepair("ge-0-0-1", cfg)

	if !equalIPs(*deleted, []net.IP{stale}) {
		t.Fatalf("deleted = %v, want [%v] (stale auto strip unchanged)", *deleted, stale)
	}
	if !equalIPs(*added, []net.IP{eui64FromMAC15148(mac)}) {
		t.Fatalf("added = %v, want the EUI-64 %v for an IPv6 unit with no "+
			"configured link-local", *added, eui64FromMAC15148(mac))
	}
}

// Control: the auto stable pattern still survives the strip exactly as
// before, even when a configured link-local is also present.
func TestRethStableLinkLocalStillSurvivesStrip15148(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0xbf, 0x72, 1, 2, 3}
	stable := cluster.StableRethLinkLocal(1, 1)
	configured := net.ParseIP("fe80::1")
	stale := net.ParseIP("fe80::dead:beef")
	deleted, added := stubRethLinkLocalSeams15148(t, mac, []net.IP{stable, configured, stale})

	cfg := &config.InterfaceConfig{
		Name: "reth0",
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"fe80::1/64", "2001:db8::8/64"}},
		},
	}
	rethParentLinkLocalRepair("ge-0-0-1", cfg)

	if !equalIPs(*deleted, []net.IP{stale}) {
		t.Fatalf("deleted = %v, want only [%v]; both the stable pattern %v "+
			"and the configured %v must survive", *deleted, stale, stable, configured)
	}
	if len(*added) != 0 {
		t.Fatalf("added = %v, want none", *added)
	}
}

// Control: a unit whose only IPv6 is the configured link-local itself still
// counts as configured (no EUI-64), and a non-IPv6 unit gets neither strip
// exemption nor ensure.
func TestRethConfiguredLinkLocalOnlyUnit15148(t *testing.T) {
	if !rethUnitHasConfiguredLinkLocal(&config.InterfaceConfig{
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"fe80::1/64"}},
		},
	}, 0) {
		t.Fatal("rethUnitHasConfiguredLinkLocal must recognise fe80::1/64")
	}
	got := configuredRethLinkLocalIPs(&config.InterfaceConfig{
		Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"fe80::1/64", "10.0.0.1/24", "fe80::1/64"}},
		},
	}, 0)
	if !equalIPs(got, []net.IP{net.ParseIP("fe80::1")}) {
		t.Fatalf("configuredRethLinkLocalIPs = %v, want [fe80::1] (de-duplicated, v4 ignored)", got)
	}
}
