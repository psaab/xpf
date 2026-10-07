package config

import (
	"fmt"
	"reflect"
	"testing"
)

func TestManagementInterfacesExcludedFromDefaultIngress_12061(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{}
	for _, name := range []string{"ge-0/0/1", "ge-0/0/2", "fxp0", "em0", "fab0"} {
		cfg.Interfaces.Interfaces[name] = &InterfaceConfig{
			Name:  name,
			Units: map[int]*InterfaceUnit{0: {Number: 0}},
		}
	}

	if got, want := DefaultInstanceIngressIfaces(cfg), []string{"ge-0-0-1", "ge-0-0-2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default-instance ingress = %v, want %v", got, want)
	}

	cfg.RoutingInstances = []*RoutingInstanceConfig{{Name: "vrf-a", TableID: 100}}
	for i := range 21 {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes, &StaticRoute{
			Destination: fmt.Sprintf("10.0.%d.0/24", i),
			NextTable:   "vrf-a",
		})
	}
	if err := validateRoutingRuleWindowsStrict(cfg); err != nil {
		t.Fatalf("21 next-table routes fit the 100-rule window with two ingress interfaces (capacity 50), got %v", err)
	}
}
