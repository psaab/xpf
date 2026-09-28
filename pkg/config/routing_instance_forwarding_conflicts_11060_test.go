package config

import (
	"strings"
	"testing"
)

func TestRIDualClaimIncludesForwardingInstancesInEitherOrder11060(t *testing.T) {
	base := "set interfaces ge-0/0/7 unit 0 family inet address 192.0.2.1/24"
	for _, tc := range []struct {
		name      string
		instance1 string
		instance2 string
	}{
		{name: "forwarding-first", instance1: "forwarding", instance2: "blue"},
		{name: "vrf-first", instance1: "blue", instance2: "forwarding"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instanceLines := func(name string) []string {
				if name == "forwarding" {
					return []string{
						"set routing-instances forwarding instance-type forwarding",
						"set routing-instances forwarding interface ge-0/0/7.0",
					}
				}
				return []string{
					"set routing-instances blue instance-type virtual-router",
					"set routing-instances blue interface ge-0/0/7.0",
				}
			}
			lines := []string{base}
			lines = append(lines, instanceLines(tc.instance1)...)
			lines = append(lines, instanceLines(tc.instance2)...)

			_, strictErr := CompileConfig(buildTree(t, lines))
			if strictErr == nil {
				t.Fatal("strict compile accepted forwarding and VRF claims on ge-0-0-7")
			}
			for _, want := range []string{"ge-0-0-7", "forwarding", "blue", "#11060"} {
				if !strings.Contains(strictErr.Error(), want) {
					t.Errorf("strict conflict %q omits %q", strictErr, want)
				}
			}

			cfg, err := CompileConfigLenient(buildTree(t, lines))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			if len(cfg.QuarantinedRIMemberDeviceConflicts) != 1 ||
				cfg.QuarantinedRIMemberDeviceConflicts[0].LinuxName != "ge-0-0-7" {
				t.Fatalf("forwarding/VRF conflict evidence = %+v",
					cfg.QuarantinedRIMemberDeviceConflicts)
			}
			for _, ri := range cfg.RoutingInstances {
				if len(ri.Interfaces) != 0 {
					t.Errorf("ambiguous membership remained in %s: %v", ri.Name, ri.Interfaces)
				}
			}
		})
	}
}
