package daemon

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

// #11717: management address sources must fence option-121 routes before the
// corresponding connected kernel route is present. Both families and both
// independent sources are exercised with empty kernel route inventories.
func TestMgmtVRFClasslessAddressConnectedPrefixesWithoutKernelRoute11717(t *testing.T) {
	tests := []struct {
		name      string
		config    []string
		family    dhcp.AddressFamily
		leaseAddr string
		covered   string
		unrelated string
		gateway   string
	}{
		{
			name: "IPv4 configured address",
			config: []string{
				"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
			},
			family:    dhcp.AFInet,
			covered:   "192.0.2.42/32",
			unrelated: "198.51.100.0/24",
			gateway:   "192.0.2.1",
		},
		{
			name: "IPv4 lease address",
			config: []string{
				"set interfaces fxp0 unit 0 family inet dhcp",
			},
			family:    dhcp.AFInet,
			leaseAddr: "192.0.2.200/24",
			covered:   "192.0.2.42/32",
			unrelated: "198.51.100.0/24",
			gateway:   "192.0.2.1",
		},
		{
			name: "IPv6 configured address",
			config: []string{
				"set interfaces fxp0 unit 0 family inet6 address 2001:db8:1::2/64",
			},
			family:    dhcp.AFInet6,
			covered:   "2001:db8:1::42/128",
			unrelated: "2001:db8:2::/64",
			gateway:   "2001:db8::1",
		},
		{
			name: "IPv6 lease address",
			config: []string{
				"set interfaces fxp0 unit 0 family inet6 dhcpv6-client client-type statefull",
			},
			family:    dhcp.AFInet6,
			leaseAddr: "2001:db8:1::123/64",
			covered:   "2001:db8:1::42/128",
			unrelated: "2001:db8:2::/64",
			gateway:   "2001:db8::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(dhcpClasslessTrustOverrideEnv, "")
			store := testStoreWithSetConfig(t, tc.config)
			cfg := store.ActiveConfig()
			mgmtSet := managementVRFIfaceSet(cfg)
			if !mgmtSet["fxp0"] {
				t.Fatalf("fixture did not place fxp0 in management VRF: %v", mgmtSet)
			}

			fake := &fakeMgmtProgrammer{links: map[string]int{"fxp0": 7}}
			if len(fake.v4) != 0 || len(fake.v6) != 0 {
				t.Fatal("fixture must start without seeded kernel routes")
			}
			lease := &dhcp.Lease{
				Interface: "fxp0",
				Family:    tc.family,
				ClasslessRoutes: []dhcp.LeaseRoute{
					{Destination: netip.MustParsePrefix(tc.covered), Gateway: netip.MustParseAddr(tc.gateway)},
					{Destination: netip.MustParsePrefix(tc.unrelated), Gateway: netip.MustParseAddr(tc.gateway)},
				},
			}
			if tc.leaseAddr != "" {
				lease.Address = netip.MustParsePrefix(tc.leaseAddr)
			}

			if err := (&Daemon{store: store}).applyMgmtVRFRoutesTo(
				fake, []*dhcp.Lease{lease}, mgmtSet); err != nil {
				t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
			}
			got := replacedDestinations9943(fake.replaced)
			if got[tc.covered] != 0 {
				t.Errorf("classless route %s inside address prefix reached RouteReplace: %v", tc.covered, got)
			}
			if got[tc.unrelated] != 1 {
				t.Errorf("unrelated classless route %s must install exactly once: %v", tc.unrelated, got)
			}
		})
	}
}

func TestMgmtVRFAddressConnectedTrustOverrideWithoutKernelRoute11717(t *testing.T) {
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")
	store := testStoreWithSetConfig(t, []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
	})
	mgmtSet := managementVRFIfaceSet(store.ActiveConfig())
	fake := &fakeMgmtProgrammer{links: map[string]int{"fxp0": 7}}
	lease := classlessLease9943("192.0.2.42/32")

	if err := (&Daemon{store: store}).applyMgmtVRFRoutesTo(
		fake, []*dhcp.Lease{lease}, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	if got := replacedDestinations9943(fake.replaced)["192.0.2.42/32"]; got != 1 {
		t.Errorf("trust override must allow the connected-overlap route exactly once, got %d", got)
	}
}
