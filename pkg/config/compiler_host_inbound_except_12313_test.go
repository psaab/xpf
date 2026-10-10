package config

import (
	"strings"
	"testing"
)

func hostInboundExcept12313Tree(t *testing.T, overrides ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	}
	lines = append(lines, overrides...)
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

func hostInboundExcept12313Pair(anyScope, exceptScope string) []string {
	const prefix = "set security zones security-zone trust interfaces "
	return []string{
		prefix + anyScope + " host-inbound-traffic system-services any-service",
		prefix + exceptScope + " host-inbound-traffic system-services all",
		prefix + exceptScope + " host-inbound-traffic system-services ssh except",
	}
}

func TestHostInboundExcept12313PhysicalUnitUnionStrictReject(t *testing.T) {
	for _, tc := range []struct {
		name        string
		anyScope    string
		exceptScope string
	}{
		{name: "physical-any-unit-except", anyScope: "ge-0/0/0", exceptScope: "ge-0/0/0.0"},
		{name: "unit-any-physical-except", anyScope: "ge-0/0/0.0", exceptScope: "ge-0/0/0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := hostInboundExcept12313Tree(t, hostInboundExcept12313Pair(tc.anyScope, tc.exceptScope)...)
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), "any-service") ||
				!strings.Contains(err.Error(), "ssh") ||
				!strings.Contains(err.Error(), `interfaces "`+tc.anyScope+`"`) ||
				!strings.Contains(err.Error(), `interfaces "`+tc.exceptScope+`"`) {
				t.Fatalf("strict compile error = %v, want cross-scope inert-except rejection naming any-service, ssh, and both scopes", err)
			}
		})
	}
}

func TestHostInboundExcept12313PhysicalUnitUnionLenientWarnAndKeep(t *testing.T) {
	for _, tc := range []struct {
		name        string
		anyScope    string
		exceptScope string
	}{
		{name: "physical-any-unit-except", anyScope: "ge-0/0/0", exceptScope: "ge-0/0/0.0"},
		{name: "unit-any-physical-except", anyScope: "ge-0/0/0.0", exceptScope: "ge-0/0/0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := hostInboundExcept12313Tree(t, hostInboundExcept12313Pair(tc.anyScope, tc.exceptScope)...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			found := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "full-admit except") &&
					strings.Contains(warning, "any-service") && strings.Contains(warning, "ssh") &&
					strings.Contains(warning, `interfaces "`+tc.anyScope+`"`) &&
					strings.Contains(warning, `interfaces "`+tc.exceptScope+`"`) {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient warnings do not name any-service, ssh, and both unioned scopes: %v", cfg.Warnings)
			}
			unit := ResolveInterfaceHostInbound(cfg)["ge-0/0/0.0"]
			if unit == nil || !hostInboundAdmitsSystemService(unit.SystemServices, "ssh") {
				t.Fatalf("lenient runtime unit services = %v, want the union to admit excluded ssh", unit)
			}
		})
	}
}

func TestHostInboundExcept12313CrossScopeProtocolExceptWarn(t *testing.T) {
	tree := hostInboundExcept12313Tree(t,
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services any-service",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols all",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols ospf except")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "full-admit except") &&
			strings.Contains(warning, "any-service") && strings.Contains(warning, "protocols") &&
			strings.Contains(warning, "ospf") && strings.Contains(warning, `interfaces "ge-0/0/0"`) &&
			strings.Contains(warning, `interfaces "ge-0/0/0.0"`) {
			return
		}
	}
	t.Fatalf("lenient warnings do not name cross-scope protocols ospf exclusion: %v", cfg.Warnings)
}

func TestHostInboundExcept12313ZoneInterfaceReplaceIsNotCrossScopeUnion(t *testing.T) {
	// #6515: a per-interface stanza replaces the zone stanza, so the zone's
	// any-service does not flow into this interface's runtime admission set.
	tree := hostInboundExcept12313Tree(t,
		"set security zones security-zone trust host-inbound-traffic system-services any-service",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services all",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh except")
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile: zone/interface replace must not be diagnosed as a runtime union: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "full-admit except") {
			t.Fatalf("zone/interface replacement unexpectedly produced a cross-scope warning: %v", cfg.Warnings)
		}
	}
	services, _, overridden := cfg.Security.Zones["trust"].InterfaceHostInboundEffective("ge-0/0/0.0")
	if !overridden || hostInboundAdmitsSystemService(services, "ssh") || hostInboundAdmitsSystemService(services, "any-service") {
		t.Fatalf("effective interface services = %v, overridden=%v; want zone full-admit replaced by all-except-ssh", services, overridden)
	}
}

func TestHostInboundExcept12313DisjointPhysicalAndUnitScopesStaySilent(t *testing.T) {
	tree := hostInboundExcept12313Tree(t, hostInboundExcept12313Pair("ge-0/0/0", "ge-0/0/1.0")...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile: disjoint override scopes must stay silent: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "full-admit except") {
			t.Fatalf("disjoint override scopes unexpectedly produced a cross-scope warning: %v", cfg.Warnings)
		}
	}
}
