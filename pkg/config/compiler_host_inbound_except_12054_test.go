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

func hostInboundExcept12054ProtocolsHierarchicalTree(t *testing.T, protocols string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic {
		system-services { any-service; }
		protocols { ` + protocols + ` }
	} } } }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func hostInboundExcept12054ProtocolsFlatZoneTree(t *testing.T) *ConfigTree {
	return hostInboundExcept12054FlatTree(t,
		"set security zones security-zone trust host-inbound-traffic system-services any-service",
		"set security zones security-zone trust host-inbound-traffic protocols all",
		"set security zones security-zone trust host-inbound-traffic protocols ospf except")
}

func hostInboundExcept12054ProtocolsInterfaceTree(t *testing.T) *ConfigTree {
	return hostInboundExcept12054FlatTree(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services any-service",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols all",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols ospf except")
}

func TestHostInboundExcept12054FlatAndInterfaceStrictReject(t *testing.T) {
	cases := []struct {
		name      string
		tree      *ConfigTree
		wantScope string
	}{
		{name: "flat-zone", tree: hostInboundExcept12054FlatZoneTree(t), wantScope: "host-inbound-traffic"},
		{name: "per-interface", tree: hostInboundExcept12054InterfaceTree(t), wantScope: `interfaces "ge-0/0/0.0"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree)
			if err == nil || !strings.Contains(err.Error(), "any-service") ||
				!strings.Contains(err.Error(), "ssh") || !strings.Contains(err.Error(), tc.wantScope) {
				t.Fatalf("strict compile error = %v, want any-service rejection naming ssh at %s", err, tc.wantScope)
			}
		})
	}
}

func TestHostInboundExcept12054FlatAndInterfaceLenientWarnAndKeep(t *testing.T) {
	cases := []struct {
		name      string
		tree      *ConfigTree
		get       func(*Config) *HostInboundTraffic
		wantScope string
	}{
		{
			name:      "flat-zone",
			tree:      hostInboundExcept12054FlatZoneTree(t),
			get:       func(cfg *Config) *HostInboundTraffic { return cfg.Security.Zones["trust"].HostInboundTraffic },
			wantScope: "host-inbound-traffic",
		},
		{
			name: "per-interface",
			tree: hostInboundExcept12054InterfaceTree(t),
			get: func(cfg *Config) *HostInboundTraffic {
				return cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0.0"]
			},
			wantScope: `interfaces "ge-0/0/0.0"`,
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
				if strings.Contains(warning, "ssh") && strings.Contains(warning, "any-service") &&
					strings.Contains(warning, tc.wantScope) {
					return
				}
			}
			t.Fatalf("lenient warnings do not name any-service/ssh at %s: %v", tc.wantScope, cfg.Warnings)
		})
	}
}

func TestHostInboundExcept12054AnyServiceStrictRejects(t *testing.T) {
	_, err := CompileConfig(hostInboundExcept12054Tree(t))
	if err == nil || !strings.Contains(err.Error(), "any-service") || !strings.Contains(err.Error(), "ssh") {
		t.Fatalf("strict compile error = %v, want any-service rejection naming excluded token ssh", err)
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
		if strings.Contains(warning, "any-service") && strings.Contains(warning, "ssh") &&
			strings.Contains(warning, "host-inbound-traffic") {
			return
		}
	}
	t.Fatalf("lenient warnings do not name any-service/excluded token ssh: %v", cfg.Warnings)
}
func TestHostInboundExcept12054ProtocolsStrictReject(t *testing.T) {
	cases := []struct {
		name      string
		tree      *ConfigTree
		wantScope string
	}{
		{
			name:      "hierarchical-subblock",
			tree:      hostInboundExcept12054ProtocolsHierarchicalTree(t, "all; ospf { except; }"),
			wantScope: "host-inbound-traffic",
		},
		{
			name:      "hierarchical-flat-tail",
			tree:      hostInboundExcept12054ProtocolsHierarchicalTree(t, "all; ospf except;"),
			wantScope: "host-inbound-traffic",
		},
		{
			name:      "flat-set-tail",
			tree:      hostInboundExcept12054ProtocolsFlatZoneTree(t),
			wantScope: "host-inbound-traffic",
		},
		{
			name:      "per-interface-flat-set-tail",
			tree:      hostInboundExcept12054ProtocolsInterfaceTree(t),
			wantScope: `interfaces "ge-0/0/0.0"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree)
			if err == nil || !strings.Contains(err.Error(), "any-service") ||
				!strings.Contains(err.Error(), "protocols") || !strings.Contains(err.Error(), "ospf") ||
				!strings.Contains(err.Error(), tc.wantScope) {
				t.Fatalf("strict compile error = %v, want protocols-except rejection naming any-service/ospf at %s", err, tc.wantScope)
			}
		})
	}
}

func TestHostInboundExcept12054ProtocolsLenientWarnAndKeep(t *testing.T) {
	cases := []struct {
		name      string
		tree      *ConfigTree
		get       func(*Config) *HostInboundTraffic
		wantScope string
	}{
		{
			name:      "hierarchical-subblock",
			tree:      hostInboundExcept12054ProtocolsHierarchicalTree(t, "all; ospf { except; }"),
			get:       func(cfg *Config) *HostInboundTraffic { return cfg.Security.Zones["trust"].HostInboundTraffic },
			wantScope: "host-inbound-traffic",
		},
		{
			name:      "hierarchical-flat-tail",
			tree:      hostInboundExcept12054ProtocolsHierarchicalTree(t, "all; ospf except;"),
			get:       func(cfg *Config) *HostInboundTraffic { return cfg.Security.Zones["trust"].HostInboundTraffic },
			wantScope: "host-inbound-traffic",
		},
		{
			name:      "flat-set-tail",
			tree:      hostInboundExcept12054ProtocolsFlatZoneTree(t),
			get:       func(cfg *Config) *HostInboundTraffic { return cfg.Security.Zones["trust"].HostInboundTraffic },
			wantScope: "host-inbound-traffic",
		},
		{
			name: "per-interface-flat-set-tail",
			tree: hostInboundExcept12054ProtocolsInterfaceTree(t),
			get: func(cfg *Config) *HostInboundTraffic {
				return cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0.0"]
			},
			wantScope: `interfaces "ge-0/0/0.0"`,
		},
	}
	wantProtocols := without10292(HostInboundAllExpansionProtocols(), "ospf")
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
			if !reflect.DeepEqual(hib.Protocols, wantProtocols) {
				t.Fatalf("lenient protocols = %v, want all except ospf: %v", hib.Protocols, wantProtocols)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "any-service") && strings.Contains(warning, "protocols") &&
					strings.Contains(warning, "ospf") && strings.Contains(warning, tc.wantScope) {
					return
				}
			}
			t.Fatalf("lenient warnings do not name any-service/protocols exclusion ospf at %s: %v", tc.wantScope, cfg.Warnings)
		})
	}
}

func TestHostInboundExcept12054LenientWarnsEveryAffectedStanza(t *testing.T) {
	tree, errs := NewParser(`security { zones {
		security-zone a { host-inbound-traffic { system-services { any-service; ssh { except; } } } }
		security-zone b { host-inbound-traffic { system-services { any-service; telnet { except; } } } }
	} }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}

	foundA, foundB := false, false
	for _, warning := range cfg.Warnings {
		foundA = foundA || (strings.Contains(warning, `zone "a"`) &&
			strings.Contains(warning, "any-service") && strings.Contains(warning, "ssh"))
		foundB = foundB || (strings.Contains(warning, `zone "b"`) &&
			strings.Contains(warning, "any-service") && strings.Contains(warning, "telnet"))
	}
	if !foundA || !foundB {
		t.Fatalf("lenient warnings do not name each affected stanza: %v", cfg.Warnings)
	}
}

func TestHostInboundExcept12054LenientExceptWarningDoesNotHideUnknownToken(t *testing.T) {
	tree, errs := NewParser(`security { zones {
		security-zone a { host-inbound-traffic { system-services { any-service; ssh { except; } } } }
		security-zone b { host-inbound-traffic { system-services { sssh; } } }
	} }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}

	foundExcept, foundUnknown := false, false
	for _, warning := range cfg.Warnings {
		foundExcept = foundExcept || (strings.Contains(warning, `zone "a"`) &&
			strings.Contains(warning, "any-service") && strings.Contains(warning, "ssh"))
		foundUnknown = foundUnknown || (strings.Contains(warning, `zone "b"`) &&
			strings.Contains(warning, "sssh") && strings.Contains(warning, "not a recognized system-service"))
	}
	if !foundExcept || !foundUnknown {
		t.Fatalf("lenient warnings must retain both except and unknown-token diagnostics: %v", cfg.Warnings)
	}
}

func TestHostInboundExcept12054UnknownExclusionUsesTokenDiagnostic(t *testing.T) {
	tree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic {
		system-services { any-service; sssh except; }
	} } } }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "sssh") ||
		!strings.Contains(err.Error(), "not a recognized system-service") ||
		strings.Contains(err.Error(), "inert except") {
		t.Fatalf("strict compile error = %v, want unknown-token diagnostic for sssh", err)
	}
}

func TestHostInboundExcept12054DuplicateExclusionsNamedOnce(t *testing.T) {
	tree, errs := NewParser(`security { zones { security-zone trust {
		host-inbound-traffic { system-services { any-service; } }
		host-inbound-traffic { system-services { ssh { except; } } }
		host-inbound-traffic { system-services { ssh { except; } } }
	} } }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil || strings.Count(err.Error(), `"ssh"`) != 1 {
		t.Fatalf("strict compile error = %v, want ssh exclusion named exactly once", err)
	}
}
