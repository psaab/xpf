package config

import (
	"strings"
	"testing"
)

func forwardingMemberTree11312(t *testing.T, family, address string) *ConfigTree {
	t.Helper()
	return buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family " + family + " address " + address,
		"set routing-instances ISP-B instance-type forwarding",
		"set routing-instances ISP-B interface ge-0/0/1.0",
	})
}

func TestForwardingInstanceMemberRejectedForIPv4AndIPv6_11312(t *testing.T) {
	for _, tc := range []struct {
		name    string
		family  string
		address string
	}{
		{name: "ipv4", family: "inet", address: "10.0.1.1/24"},
		{name: "ipv6", family: "inet6", address: "2001:db8:1::1/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(forwardingMemberTree11312(t, tc.family, tc.address))
			if err == nil {
				t.Fatal("strict commit accepted an interface member under instance-type forwarding")
			}
			for _, want := range []string{"ISP-B", "ge-0/0/1.0", "instance-type forwarding", "#11312"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("rejection %q omits %q", err, want)
				}
			}
		})
	}
}

func TestForwardingInstanceMemberWarnsOnTolerantPathForIPv4AndIPv6_11312(t *testing.T) {
	for _, tc := range []struct {
		name    string
		family  string
		address string
	}{
		{name: "ipv4", family: "inet", address: "10.0.1.1/24"},
		{name: "ipv6", family: "inet6", address: "2001:db8:1::1/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(forwardingMemberTree11312(t, tc.family, tc.address))
			if err != nil {
				t.Fatalf("tolerant load must keep the existing config bootable: %v", err)
			}
			var found string
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "forwarding-instance interface membership") {
					found = warning
				}
			}
			if found == "" {
				t.Fatalf("tolerant compile accepted the unsupported member silently: %v", cfg.Warnings)
			}
			for _, want := range []string{"ISP-B", "ge-0/0/1.0", "#11312"} {
				if !strings.Contains(found, want) {
					t.Errorf("warning %q omits %q", found, want)
				}
			}
			if got := cfg.RoutingInstances[0].Interfaces; len(got) != 1 || got[0] != "ge-0/0/1.0" {
				t.Errorf("tolerant compile erased the authored member: %v", got)
			}
		})
	}
}

func TestForwardingInstanceMemberGateLeavesControlsAccepted_11312(t *testing.T) {
	t.Run("virtual-router-member", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
			"set routing-instances ISP-B instance-type virtual-router",
			"set routing-instances ISP-B interface ge-0/0/1.0",
		}))
		if err != nil {
			t.Fatalf("virtual-router interface membership must remain valid: %v", err)
		}
		if len(cfg.RoutingInstances) != 1 || len(cfg.RoutingInstances[0].Interfaces) != 1 {
			t.Fatalf("virtual-router member was lost: %+v", cfg.RoutingInstances)
		}
	})

	t.Run("statics-only-forwarding", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set routing-instances ISP-B instance-type forwarding",
			"set routing-instances ISP-B routing-options static route 0.0.0.0/0 next-hop 192.0.2.1",
		}))
		if err != nil {
			t.Fatalf("statics-only forwarding instance must remain valid: %v", err)
		}
		if len(cfg.RoutingInstances) != 1 || len(cfg.RoutingInstances[0].StaticRoutes) != 1 {
			t.Fatalf("forwarding static route was lost: %+v", cfg.RoutingInstances)
		}
	})
}
