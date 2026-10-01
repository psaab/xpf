package config

import (
	"strings"
	"testing"
)

func routingInstanceLifelineTree11364(t *testing.T, role string) *ConfigTree {
	t.Helper()
	return buildTree(t, []string{
		"set interfaces ge-0/0/4 unit 0 family inet address 10.4.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.1.0.1/24",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-1234567890",
		"set chassis cluster node 0",
		"set chassis cluster " + role + " ge-0/0/4",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/4.0",
		"set routing-instances blue interface ge-0/0/1.0",
	})
}

func TestConfiguredLifelineCannotJoinTenantRoutingInstance11364(t *testing.T) {
	for _, role := range []string{"control-interface", "fabric-interface", "fabric1-interface"} {
		t.Run(role, func(t *testing.T) {
			_, err := CompileConfig(routingInstanceLifelineTree11364(t, role))
			if err == nil {
				t.Fatal("strict commit accepted a configured host-inbound lifeline as a tenant-VRF member")
			}
			for _, want := range []string{"routing-instances \"blue\"", "ge-0/0/4", "lifeline", "#11364"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("lifeline membership error %q omits %q", err, want)
				}
			}
		})
	}
}

func TestTolerantCompileQuarantinesConfiguredLifelineRIMember11364(t *testing.T) {
	cfg, err := CompileConfigLenient(routingInstanceLifelineTree11364(t, "control-interface"))
	if err != nil {
		t.Fatalf("tolerant compile must keep the stored config bootable: %v", err)
	}
	if got := cfg.RoutingInstances[0].Interfaces; len(got) != 1 || got[0] != "ge-0/0/1.0" {
		t.Fatalf("tolerant compile left lifeline membership or dropped its data co-member: %v", got)
	}
	var warning string
	for _, got := range cfg.Warnings {
		if strings.Contains(got, "#11364") && strings.Contains(got, "ge-0/0/4") {
			warning = got
			break
		}
	}
	if warning == "" {
		t.Fatalf("tolerant compile silently removed no lifeline membership; warnings=%v", cfg.Warnings)
	}
}
