package config

import (
	"strings"
	"testing"
)

// #16604: when no instance named `default` is declared, that literal in a NAT
// scope is the master-instance alias and the compiler lowers it to "" plus a
// provenance flag. #17677: a declared instance named `default` keeps its
// literal meaning.

func TestNATDefaultRoutingInstanceLowers16604(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, append(natScopeBase15278(),
		"set security nat source rule-set snat-ok from routing-instance cust-a",
		"set routing-instances cust-a instance-type virtual-router",
		"set security nat source rule-set snat-ok to routing-instance default",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1",
	)))
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.ToRoutingInstance != "" || !rs.ToRoutingInstanceDefault {
		t.Fatalf("to scope = %q default=%v, want \"\"/true", rs.ToRoutingInstance, rs.ToRoutingInstanceDefault)
	}
	if rs.FromRoutingInstance != "cust-a" || rs.FromRoutingInstanceDefault {
		t.Fatalf("from scope = %q default=%v, want cust-a/false", rs.FromRoutingInstance, rs.FromRoutingInstanceDefault)
	}
	if got := natRuleSetScopeTier(rs); got != SourceNATTierRoutingInstance {
		t.Fatalf("tier = %d, want routing-instance tier %d", got, SourceNATTierRoutingInstance)
	}
	if wire := NATRoutingInstanceScopeWire(cfg, rs.ToRoutingInstance, rs.ToRoutingInstanceDefault); wire != NATDefaultRoutingInstanceWire {
		t.Fatalf("wire = %q, want token", wire)
	}
}

// #17677: a routing-instance actually NAMED `default` keeps its literal
// meaning through COMPILATION (typed fields), not only through the raw-string
// normalizer — the #16604 declared-instance leg. Compile a declared-default
// source rule-set and require the typed scope stays "default"/false and the
// wire value stays the literal (named-instance match), never the master token.
func TestNATDefaultDeclaredInstanceKeepsLiteral16604(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, append(natScopeBase15278(),
		"set routing-instances default instance-type virtual-router",
		"set security nat source rule-set snat-ok from routing-instance default",
		"set security nat source rule-set snat-ok to routing-instance default",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1",
	)))
	if err != nil {
		t.Fatalf("strict compile with declared default: %v", err)
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromRoutingInstance != "default" || rs.FromRoutingInstanceDefault {
		t.Fatalf("from scope = %q default=%v, want default/false (declared instance)", rs.FromRoutingInstance, rs.FromRoutingInstanceDefault)
	}
	if rs.ToRoutingInstance != "default" || rs.ToRoutingInstanceDefault {
		t.Fatalf("to scope = %q default=%v, want default/false (declared instance)", rs.ToRoutingInstance, rs.ToRoutingInstanceDefault)
	}
	if wire := NATRoutingInstanceScopeWire(cfg, rs.ToRoutingInstance, rs.ToRoutingInstanceDefault); wire != "default" {
		t.Fatalf("declared default wire = %q, want literal default", wire)
	}
	if wire := NormalizeNATRoutingInstanceScope16604(cfg, "default"); wire != "default" {
		t.Fatalf("declared default normalize = %q, want literal default", wire)
	}
}

func TestNATDefaultStaticAndNAT64Lower16604(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, append(natScopeBase15278(),
		"set security nat static rule-set stat-ok from routing-instance default",
		"set security nat static rule-set stat-ok rule R1 match destination-address 198.51.100.5/32",
		"set security nat static rule-set stat-ok rule R1 then static-nat prefix 10.0.0.5/32",
	)))
	if err != nil {
		t.Fatalf("static compile: %v", err)
	}
	srs := cfg.Security.NAT.Static[0]
	if srs.FromRoutingInstance != "" || !srs.FromRoutingInstanceDefault {
		t.Fatalf("static scope = %q default=%v, want \"\"/true", srs.FromRoutingInstance, srs.FromRoutingInstanceDefault)
	}

	ncfg, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security nat nat64 rule-set rs1 from routing-instance default",
	))
	if err != nil {
		t.Fatalf("nat64 compile: %v", err)
	}
	nrs := ncfg.Security.NAT.NAT64[0]
	if !nrs.FromRoutingInstanceDefault {
		t.Fatalf("nat64 default flag not set: %+v", nrs)
	}
	found := false
	for _, ri := range NAT64EffectiveRoutingInstances(ncfg, nrs) {
		if ri == NATDefaultRoutingInstanceWire {
			found = true
		}
		if ri == "" {
			t.Fatalf("effective RI still carries lowered empty: %v", NAT64EffectiveRoutingInstances(ncfg, nrs))
		}
	}
	if !found {
		t.Fatalf("effective RI = %v, want wire token", NAT64EffectiveRoutingInstances(ncfg, nrs))
	}
}
func TestNATDefaultDeclaredNAT64ScopeKeepsNamedInstance17677(t *testing.T) {
	cfg, err := compileNAT64Scope(t, nat64ScopeLines(
		"set routing-instances default instance-type virtual-router",
		"set security nat nat64 rule-set rs1 from routing-instance default",
	))
	if err != nil {
		t.Fatalf("NAT64 compile with declared default: %v", err)
	}
	rs := cfg.Security.NAT.NAT64[0]
	if rs.FromRoutingInstance != "default" || rs.FromRoutingInstanceDefault ||
		len(rs.FromRoutingInstances) != 1 || rs.FromRoutingInstances[0] != "default" {
		t.Fatalf("NAT64 scope = %+v, want literal default in singular/list without alias flag", rs)
	}
	effective := NAT64EffectiveRoutingInstances(cfg, rs)
	if len(effective) != 1 || effective[0] != "default" {
		t.Fatalf("effective NAT64 scopes = %v, want [default]", effective)
	}
	namedKey, _ := nat64PrefixOwnerKeyScoped(cfg, rs)
	masterKey, _ := nat64PrefixOwnerKeyScoped(cfg, &NAT64RuleSet{
		Prefix: rs.Prefix, FromRoutingInstanceDefault: true,
	})
	if namedKey == masterKey {
		t.Fatal("NAT64 named-default owner key collides with explicit-master key")
	}
}

func TestNATDefaultInterfaceEgressScope16604(t *testing.T) {
	// ge-0/0/3.50 is in vrf-a (ifaceEgressCfg); a default-scoped rule must
	// NOT claim it, a vrf-a-scoped rule must, an unscoped rule must.
	mk := func(toRI string, def bool) *Config {
		cfg := ifaceEgressCfg("", "", toRI, "192.0.2.10/32", "192.0.2.10")
		for _, rs := range cfg.Security.NAT.Source {
			if rs.Name == "iface-rs" {
				rs.ToRoutingInstanceDefault = def
			}
		}
		return cfg
	}
	if overlapsIfaceEgress(t, mk("default", true)) {
		t.Fatal("explicit-default egress must not claim the vrf-a interface address")
	}
	// Hand-built raw literal (no flag) must behave identically.
	if overlapsIfaceEgress(t, mk("default", false)) {
		t.Fatal("raw default egress must not claim the vrf-a interface address")
	}
	// A declared `default` is a named VRF, so its interface address remains
	// eligible for a rule scoped to that instance.
	declaredDefault := mk("default", false)
	declaredDefault.RoutingInstances = []*RoutingInstanceConfig{{
		Name: "default", Interfaces: []string{"ge-0/0/3.50"},
	}}
	if !overlapsIfaceEgress(t, declaredDefault) {
		t.Fatal("declared-default egress must claim the interface address in that named instance")
	}
	if !overlapsIfaceEgress(t, mk("vrf-a", false)) {
		t.Fatal("vrf-a egress control must claim the vrf-a interface address")
	}
	if !overlapsIfaceEgress(t, mk("", false)) {
		t.Fatal("unscoped egress control must claim the vrf-a interface address")
	}
}

func TestNATDefaultCohortControlStillCompiles16604(t *testing.T) {
	// The #15278 must-compile control (nat_cohort_15278_test.go:137) keeps
	// compiling strict, now with the alias lowered rather than verbatim.
	cfg, err := CompileConfig(buildTree(t, append(natScopeBase15278(),
		"set security nat source rule-set snat-ok to routing-instance default",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1",
	)))
	if err != nil {
		t.Fatalf("control must compile strict: %v", err)
	}
	rs := cfg.Security.NAT.Source[0]
	if strings.Contains(rs.ToRoutingInstance, "default") {
		t.Fatalf("literal default survived lowering: %q", rs.ToRoutingInstance)
	}
}
