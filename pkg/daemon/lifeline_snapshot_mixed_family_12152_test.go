package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

// slaacAddr is a FINITE-lifetime (ValidLft != forever) global IPv6 address —
// what SLAAC always produces. The defect under test is that ANY finite-lifetime
// global address in ANY family marks the whole NIC dhcpManaged, so this one
// v6 address poisons an otherwise static v4 NIC into the DHCP-only branch.
func slaacAddr12152(cidr string) netlink.Addr {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet, ValidLft: 7200}
}

func dhcpAddr12152(cidr string) netlink.Addr {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet, ValidLft: 3600}
}

// TestMixedStaticV4SLAACV6PreservesStaticV4_12152 is the #12152 regression
// cell. A NIC with a static (permanent) global IPv4 address plus a SLAAC
// (finite-lifetime) global IPv6 address must keep its static v4 snapshot:
// Address= + Gateway= for v4, not the DHCP-only file. The old classifier set
// dhcpManaged for the whole NIC on ANY finite ValidLft in ANY family, so the
// always-finite SLAAC v6 address flipped static v4 into `DHCP=yes` with no
// Address=/Gateway=, and the rename link-cycle dropped the IPv4 default route.
//
// FAIL-ON-REVERT: restoring the any-family classifier makes this write
// `DHCP=yes` and reds the Address=/Gateway= assertions.
func TestMixedStaticV4SLAACV6PreservesStaticV4_12152(t *testing.T) {
	st := staticLifelineSeams(t)
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{
			staticAddr("192.0.2.10/24"),
			slaacAddr12152("2001:db8::10/64"),
		}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return []netlink.Route{{Gw: net.ParseIP("2001:db8::1")}}, nil
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("mixed static-v4/SLAAC-v6 observation must still write the bootstrap fxp0 .network: %v", err)
	}
	got := string(data)
	if !contains6789(got, "Address=192.0.2.10/24") {
		t.Errorf("the STATIC v4 address must be snapshotted even with a finite-lifetime v6 address present; got:\n%s", got)
	}
	if !contains6789(got, "Gateway=192.0.2.1") {
		t.Errorf("the v4 default gateway must be snapshotted; the rename link-cycle drops it otherwise; got:\n%s", got)
	}
	if contains6789(got, "DHCP=yes") {
		t.Errorf("a finite-lifetime IPV6 address (SLAAC) must not flip STATIC v4 into a DHCP-only .network; got:\n%s", got)
	}
	if !contains6789(got, "DHCP=ipv6") {
		t.Errorf("the finite-lifetime v6 address must retain per-family DHCP behavior; got:\n%s", got)
	}

	if contains6789(got, "Address=2001:db8::10/64") {
		t.Errorf("the finite-lifetime SLAAC v6 address must remain dynamic, not be pinned into the snapshot; got:\n%s", got)
	}
	if contains6789(got, "Gateway=2001:db8::1") {
		t.Errorf("the SLAAC v6 gateway must not be pinned into the snapshot; got:\n%s", got)
	}
	if !*st.reloaded {
		t.Error("the lifeline must still complete on a mixed static-v4/SLAAC-v6 NIC")
	}
}

// TestIPv4OnlyStaticControl_12152 is the control for the cell above: the same
// static v4 NIC without any v6 address. It pins that the defect trigger is the
// finite-lifetime v6 address, not the static v4 observation itself.
func TestIPv4OnlyStaticControl_12152(t *testing.T) {
	st := staticLifelineSeams(t)
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return nil, nil
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("v4-only static observation must still write the bootstrap fxp0 .network: %v", err)
	}
	got := string(data)
	if !contains6789(got, "Address=192.0.2.10/24") {
		t.Errorf("the static v4 address must be snapshotted; got:\n%s", got)
	}
	if !contains6789(got, "Gateway=192.0.2.1") {
		t.Errorf("the v4 default gateway must be snapshotted; got:\n%s", got)
	}
	if contains6789(got, "DHCP=") {
		t.Errorf("a permanent v4 address is STATIC and must not produce any DHCP directive; got:\n%s", got)
	}

	if !*st.reloaded {
		t.Error("the lifeline must still complete on a v4-only static NIC")
	}
}

func TestDHCPv4OnlyUsesFactoryNetwork_12152(t *testing.T) {
	st := staticLifelineSeams(t)
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{dhcpAddr12152("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return nil, nil
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("DHCPv4 lifeline must write the bootstrap fxp0 .network: %v", err)
	}
	got := string(data)
	const factoryNetwork = "# Managed by xpfd — #1922 bootstrap lifeline (DHCP)\n" +
		"[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nUseDNS=yes\nUseRoutes=yes\n"
	if got != factoryNetwork {
		t.Errorf("a DHCPv4-only lifeline must keep the byte-stable factory DHCP network; got:\n%s", got)
	}
	if contains6789(got, "Address=192.0.2.10/24") || contains6789(got, "Gateway=192.0.2.1") {
		t.Errorf("DHCPv4 lease addressing must not be pinned as a static snapshot; got:\n%s", got)
	}
	if !contains6789(got, "[DHCPv4]\nUseDNS=yes\nUseRoutes=yes\n") {
		t.Errorf("DHCPv4 options must remain enabled on the DHCP-managed lifeline; got:\n%s", got)
	}
	if !*st.reloaded {
		t.Error("the lifeline must still complete on a DHCPv4-only NIC")
	}
}

func TestDHCPv4WithStaticV6PreservesStaticV6_12152(t *testing.T) {
	st := staticLifelineSeams(t)
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{
			dhcpAddr12152("192.0.2.10/24"),
			staticAddr("2001:db8::10/64"),
		}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return []netlink.Route{{Gw: net.ParseIP("2001:db8::1")}}, nil
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("mixed DHCPv4/static-v6 observation must write the bootstrap fxp0 .network: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		"DHCP=ipv4",
		"Address=2001:db8::10/64",
		"Gateway=2001:db8::1",
		"[DHCPv4]\nUseDNS=yes\nUseRoutes=yes\n",
	} {
		if !contains6789(got, want) {
			t.Errorf("mixed DHCPv4/static-v6 lifeline must contain %q; got:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{
		"DHCP=yes",
		"DHCP=ipv6",
		"Address=192.0.2.10/24",
		"Gateway=192.0.2.1",
	} {
		if contains6789(got, unwanted) {
			t.Errorf("mixed DHCPv4/static-v6 lifeline must not contain %q; got:\n%s", unwanted, got)
		}
	}
	if !*st.reloaded {
		t.Error("the lifeline must still complete on a mixed DHCPv4/static-v6 NIC")
	}
}

func TestDHCPv4FactoryRestartKeepsNetworkUnchanged_12152(t *testing.T) {
	st := staticLifelineSeams(t)
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	var addrs []netlink.Addr
	gw4, gw6 := "", ""
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) { return addrs, nil }
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		switch {
		case family == netlink.FAMILY_V4 && gw4 != "":
			return []netlink.Route{{Gw: net.ParseIP(gw4)}}, nil
		case family == netlink.FAMILY_V6 && gw6 != "":
			return []netlink.Route{{Gw: net.ParseIP(gw6)}}, nil
		default:
			return nil, nil
		}
	}

	changed, err := writeBootstrapLifelineNetwork(defaultMgmtInterface, false)
	if err != nil || !changed {
		t.Fatalf("factory boot must write the DHCP .network: changed=%v err=%v", changed, err)
	}
	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	factory, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name     string
		addrs    []netlink.Addr
		gw4, gw6 string
	}{
		{
			name:  "DHCPv4 lease",
			addrs: []netlink.Addr{dhcpAddr12152("192.0.2.10/24")},
			gw4:   "192.0.2.1",
		},
		{
			name: "DHCPv4 lease plus SLAAC after RA",
			addrs: []netlink.Addr{
				dhcpAddr12152("192.0.2.10/24"),
				slaacAddr12152("2001:db8::10/64"),
			},
			gw4: "192.0.2.1",
			gw6: "fe80::1",
		},
		{
			name:  "DHCPv4 lease before RA",
			addrs: []netlink.Addr{dhcpAddr12152("192.0.2.10/24")},
			gw4:   "192.0.2.1",
		},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			addrs, gw4, gw6 = step.addrs, step.gw4, step.gw6
			changed, err := writeBootstrapLifelineNetwork(defaultMgmtInterface, true)
			if err != nil {
				t.Fatalf("snapshot write failed: %v", err)
			}
			if changed {
				t.Fatal("DHCP-managed snapshot must not rewrite the byte-stable factory network")
			}
			data, err := os.ReadFile(netPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != string(factory) {
				t.Fatalf("DHCP-managed snapshot changed the factory network:\ngot:\n%s\nwant:\n%s", data, factory)
			}
		})
	}
}
