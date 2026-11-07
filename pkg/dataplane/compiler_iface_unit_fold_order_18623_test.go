package dataplane

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBareNetdevUnitFoldUsesNumericOrder18623(t *testing.T) {
	const iface = "hb.1"
	linuxName := config.LinuxIfName(iface)
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			iface: {
				Name: iface,
				Units: map[int]*config.InterfaceUnit{
					7: {
						Number:             7,
						Addresses:          []string{"10.99.14.7/24", "10.99.14.8/24", "2001:db8:14::7/64", "2001:db8:14::8/64"},
						PrimaryAddress:     "10.99.14.7/24",
						PreferredAddress:   "10.99.14.8/24",
						PrimaryAddressV6:   "2001:db8:14::7/64",
						PreferredAddressV6: "2001:db8:14::8/64",
					},
					0: {
						Number:             0,
						Addresses:          []string{"10.99.14.1/24", "10.99.14.2/24", "2001:db8:14::1/64", "2001:db8:14::2/64"},
						PrimaryAddress:     "10.99.14.1/24",
						PreferredAddress:   "10.99.14.2/24",
						PrimaryAddressV6:   "2001:db8:14::1/64",
						PreferredAddressV6: "2001:db8:14::2/64",
					},
				},
			},
		}},
	}
	wantAddrs := []string{
		"10.99.14.1/24", "10.99.14.2/24", "2001:db8:14::1/64", "2001:db8:14::2/64",
		"10.99.14.7/24", "10.99.14.8/24", "2001:db8:14::7/64", "2001:db8:14::8/64",
	}

	// Recompile repeatedly: map iteration used to make the aggregate's first
	// selectors and address order vary between renders.
	for attempt := range 128 {
		result := &CompileResult{ifCache: map[string]*net.Interface{
			linuxName: {
				Index:        80,
				Name:         linuxName,
				HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x81},
			},
		}}
		buildInterfaceNetworkdModels(cfg, result, map[string]bool{})
		found := false
		for _, model := range result.ManagedInterfaces {
			if model.Name != linuxName {
				continue
			}
			found = true
			if model.PrimaryAddress != "10.99.14.1/24" || model.PreferredAddress != "10.99.14.2/24" ||
				model.PrimaryAddressV6 != "2001:db8:14::1/64" || model.PreferredAddressV6 != "2001:db8:14::2/64" {
				t.Fatalf("attempt %d selected non-lowest-unit selectors: primary=%q preferred=%q primaryV6=%q preferredV6=%q",
					attempt, model.PrimaryAddress, model.PreferredAddress, model.PrimaryAddressV6, model.PreferredAddressV6)
			}
			if len(model.Addresses) != len(wantAddrs) {
				t.Fatalf("attempt %d addresses=%v, want %v", attempt, model.Addresses, wantAddrs)
			}
			for i, want := range wantAddrs {
				if model.Addresses[i] != want {
					t.Fatalf("attempt %d address[%d]=%q, want %q (all=%v)", attempt, i, model.Addresses[i], want, model.Addresses)
				}
			}
			break
		}
		if !found {
			t.Fatalf("attempt %d emitted no bare-netdev row %q: %+v", attempt, linuxName, result.ManagedInterfaces)
		}
	}
}
