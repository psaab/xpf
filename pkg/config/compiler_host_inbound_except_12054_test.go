package config

import (
	"reflect"
	"strings"
	"testing"
)

func hostInboundExcept12054Tree(t *testing.T) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic {
		system-services { any-service; ssh { except; } }
	} } } }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func hostInboundExcept12054FlatTree(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func hostInboundExcept12054FlatZoneTree(t *testing.T) *ConfigTree {
	return hostInboundExcept12054FlatTree(t,
		"set security zones security-zone trust host-inbound-traffic system-services any-service",
		"set security zones security-zone trust host-inbound-traffic system-services ssh except")
}

func hostInboundExcept12054InterfaceTree(t *testing.T) *ConfigTree {
	return hostInboundExcept12054FlatTree(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services any-service",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh except")
}

func TestHostInboundExcept12054FlatAndInterfaceStrictReject(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
	}{
		{name: "flat-zone", tree: hostInboundExcept12054FlatZoneTree(t)},
		{name: "per-interface", tree: hostInboundExcept12054InterfaceTree(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree)
			if err == nil || !strings.Contains(err.Error(), "ssh") {
				t.Fatalf("strict compile error = %v, want rejection naming excluded token ssh", err)
			}
		})
	}
}

func TestHostInboundExcept12054FlatAndInterfaceLenientWarnAndKeep(t *testing.T) {
	cases := []struct {
		name string
		tree *ConfigTree
		get  func(*Config) *HostInboundTraffic
	}{
		{
			name: "flat-zone",
			tree: hostInboundExcept12054FlatZoneTree(t),
			get:  func(cfg *Config) *HostInboundTraffic { return cfg.Security.Zones["trust"].HostInboundTraffic },
		},
		{
			name: "per-interface",
			tree: hostInboundExcept12054InterfaceTree(t),
			get: func(cfg *Config) *HostInboundTraffic {
				return cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0.0"]
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			hib := tc.get(cfg)
			if hib == nil || !reflect.DeepEqual(hib.SystemServices, []string{"any-service"}) {
				t.Fatalf("lenient system-services = %v, want [any-service]", hib)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "ssh") {
					return
				}
			}
			t.Fatalf("lenient warnings do not name excluded token ssh: %v", cfg.Warnings)
		})
	}
}

func TestHostInboundExcept12054AnyServiceStrictRejects(t *testing.T) {
	_, err := CompileConfig(hostInboundExcept12054Tree(t))
	if err == nil || !strings.Contains(err.Error(), "ssh") {
		t.Fatalf("strict compile error = %v, want rejection naming excluded token ssh", err)
	}
}

func TestHostInboundExcept12054AnyServiceLenientWarnsAndKeepsToken(t *testing.T) {
	cfg, err := CompileConfigLenient(hostInboundExcept12054Tree(t))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	got := cfg.Security.Zones["trust"].HostInboundTraffic.SystemServices
	if !reflect.DeepEqual(got, []string{"any-service"}) {
		t.Fatalf("lenient system-services = %v, want [any-service]", got)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "ssh") {
			return
		}
	}
	t.Fatalf("lenient warnings do not name excluded token ssh: %v", cfg.Warnings)
}
