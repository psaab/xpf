package config

import "testing"

// #18573: AddressIdentitiesByNetdev is the "configured ownership" set the
// direct-VIP reconcile and the userspace snapshot judge a stamped kernel
// address against. Its RETH half must use the SAME netdev naming as the VIP
// install (RethVIPsByRG) — a mismatch would make every installed VIP look
// like a leftover and the reconcile would delete what it just added.
func TestAddressIdentitiesByNetdev18573(t *testing.T) {
	cfg := rethCfg16590(func(c *Config) {
		c.Interfaces.Interfaces["reth0"].Units[80].Disable = true
		c.Interfaces.Interfaces["reth0"].Units[50].Addresses = []string{"172.16.50.8/24", "2001:DB8:50:0::8/64"}
		c.Interfaces.Interfaces["ge-0/0/3"] = &InterfaceConfig{
			Name: "ge-0/0/3", VlanTagging: true,
			Units: map[int]*InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"192.0.2.1/24"}},
				20: {Number: 20, VlanID: 20, Addresses: []string{"198.51.100.1/24"}},
				30: {Number: 30, VlanID: 30, Disable: true, Addresses: []string{"203.0.113.1/24"}},
			},
		}
		c.Interfaces.Interfaces["ge-0/0/4"] = &InterfaceConfig{
			Name: "ge-0/0/4", Disable: true,
			Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"192.0.2.99/24"}}},
		}
	})
	got := cfg.AddressIdentitiesByNetdev()

	// Every installed VIP is configured under its install netdev.
	for netdev, vips := range cfg.RethVIPsForRG(1) {
		for _, vip := range vips {
			if !got[netdev][VRRPVIPIdentity(vip)] {
				t.Fatalf("installed VIP %s on %s is missing from the configured set %v", vip, netdev, got)
			}
		}
	}
	want := map[string][]string{
		"ge-0-0-2.50": {"172.16.50.8/24", "2001:db8:50::8/64"},
		"ge-0-0-3":    {"192.0.2.1/24"},
		"ge-0-0-3.20": {"198.51.100.1/24"},
	}
	for netdev, ids := range want {
		for _, id := range ids {
			if !got[netdev][id] {
				t.Fatalf("%s %s missing: %v", netdev, id, got)
			}
		}
	}
	for _, absent := range []struct{ netdev, id string }{
		{"ge-0-0-2.80", "172.16.80.8/24"}, // disabled RETH unit
		{"ge-0-0-3.30", "203.0.113.1/24"}, // disabled plain unit
		{"ge-0-0-4", "192.0.2.99/24"},     // disabled interface
		{"ge-0-0-2.50", "172.16.50.8/25"}, // same host, other prefix
	} {
		if got[absent.netdev][absent.id] {
			t.Fatalf("%s %s must not be configured: %v", absent.netdev, absent.id, got)
		}
	}
}
