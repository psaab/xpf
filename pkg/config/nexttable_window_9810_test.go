package config

import (
	"fmt"
	"strings"
	"testing"
)

// STEP-0 RED cells for #9810 (SYN-WIN-01 counting unit + N==0 agreement).
// Each leak costs one ip-rule slot per default-instance ingress interface at
// the applier (per-ingress rules since #9420), but the strict gate and
// StaticRouteExclusions still count one slot per leak. With N=4 and L=30 the
// gate passes (30 <= 100) while the kernel fits only 25 leaks.

// mk9810LeakCfg builds a config with n unclaimed default-instance ingress
// units (ge-0/0/0..n-1 unit 0) and L global next-table leaks at DISTINCT
// destinations (distinct: shared fixtures also feed the FIB dedupe key).
func mk9810LeakCfg(n, l int) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("ge-0/0/%d", i)
		cfg.Interfaces.Interfaces[name] = &InterfaceConfig{
			Name:  name,
			Units: map[int]*InterfaceUnit{0: {Number: 0}},
		}
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{{Name: "vrf-a", TableID: 100}}
	for i := 0; i < l; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "vrf-a",
			})
	}
	return cfg
}

// TestStrictGateCountsPerIngressInterface_9810 pins the #9810 acceptance row:
// with four ingress units the applier fits floor(100/4)=25 leaks, so L=30
// must be refused and L=25 must pass.
func TestStrictGateCountsPerIngressInterface_9810(t *testing.T) {
	if err := validateRoutingRuleWindowsStrict(mk9810LeakCfg(4, 30)); err == nil {
		t.Fatal("30 leaks over 4 ingress interfaces need 120 ip-rule slots; " +
			"the gate must refuse, got nil")
	} else if !strings.Contains(err.Error(), "next-table") {
		t.Fatalf("refusal must name next-table, got %q", err)
	}

	if err := validateRoutingRuleWindowsStrict(mk9810LeakCfg(4, 25)); err != nil {
		t.Fatalf("25 leaks over 4 ingress interfaces fit the 100-slot window, got %v", err)
	}
}

// TestStrictGateNoIngressRejectsLeaks_9810 pins the N==0 arm: with no
// resolvable ingress interface the applier installs NOTHING (#9420
// fail-closed), so the installed set is empty and any eligible leak must be
// refused up front. The no-leak control must stay silent.
func TestStrictGateNoIngressRejectsLeaks_9810(t *testing.T) {
	if err := validateRoutingRuleWindowsStrict(mk9810LeakCfg(0, 1)); err == nil {
		t.Fatal("a leak with no ingress interface can never install; " +
			"the gate must refuse, got nil")
	}
	if err := validateRoutingRuleWindowsStrict(mk9810LeakCfg(0, 0)); err != nil {
		t.Fatalf("no leaks must pass silently, got %v", err)
	}
}

// TestStaticRouteExclusionsCostPerIngress_9810 pins that the shared verdict
// draws the window down N slots per leak, leak-atomically: 25 of 30 fit.
func TestStaticRouteExclusionsCostPerIngress_9810(t *testing.T) {
	cfg := mk9810LeakCfg(4, 30)
	excl := StaticRouteExclusions(cfg)

	for i, sr := range cfg.RoutingOptions.StaticRoutes {
		reason := excl[sr]
		if i < 25 && reason != "" {
			t.Errorf("leak %d fits the window (25x4=100) but is excluded: %q", i, reason)
		}
		if i >= 25 && reason == "" {
			t.Errorf("leak %d is past the window (26x4=104>100) but is published", i)
		}
	}
}

// TestStaticRouteExclusionsNoIngressExcludesAll_9810 pins that with no
// ingress interface every eligible leak is excluded — the kernel installs
// none, so the FIB/show verdict must publish none.
func TestStaticRouteExclusionsNoIngressExcludesAll_9810(t *testing.T) {
	cfg := mk9810LeakCfg(0, 2)
	excl := StaticRouteExclusions(cfg)

	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if excl[sr] == "" {
			t.Errorf("leak %s cannot install with no ingress interface but is published",
				sr.Destination)
		}
	}
}

// TestStaticRouteExclusionsFamilyOrderMatchesApplier_9810 pins that the
// verdict draws the window down in the applier's order: v4-first by PARSED
// CIDR (#6583), not v4-list-then-v6-list. A v6 CIDR under `static` is legal
// (#9820); the kernel draws it in the v6 group while a list-order verdict
// would draw it in v4 position and pick different truncation survivors.
func TestStaticRouteExclusionsFamilyOrderMatchesApplier_9810(t *testing.T) {
	cfg := mk9810LeakCfg(1, 0)
	v6dst := &StaticRoute{Destination: "2001:db8::/32", NextTable: "vrf-a"}
	cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes, v6dst)
	for i := 0; i < 99; i++ {
		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
			&StaticRoute{
				Destination: fmt.Sprintf("10.10.%d.0/24", i),
				NextTable:   "vrf-a",
			})
	}
	v4tail := &StaticRoute{Destination: "10.200.0.0/24", NextTable: "vrf-a"}
	cfg.RoutingOptions.Inet6StaticRoutes = []*StaticRoute{v4tail}

	excl := StaticRouteExclusions(cfg)
	if excl[v6dst] == "" {
		t.Error("the v6 leak is 101st in applier (parsed-CIDR v4-first) order " +
			"and must be excluded")
	}
	if reason := excl[v4tail]; reason != "" {
		t.Errorf("the v6-list v4 leak is 100th in applier order and must be "+
			"published, got %q", reason)
	}
}

// TestStrictGateNoIngressEndToEnd_9810 pins the N=0 arm on the real commit
// paths: a single leak with no interfaces is refused at strict commit (the
// applier could install nothing) and downgraded to a warning on tolerant
// load (#1960 no-brick). Companion to the N=1 overflow e2e cells in
// compiler_routing_rules_test.go, which would otherwise silently cover N=0.
func TestStrictGateNoIngressEndToEnd_9810(t *testing.T) {
	sets := []string{
		"set routing-instances vr instance-type virtual-router",
		"set routing-options static route 10.9.0.0/24 next-table vr.inet.0",
	}
	t.Run("strict rejects", func(t *testing.T) {
		tree := flatTreeFromSets(t, sets...)
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "next-table") {
			t.Fatalf("strict commit must reject a leak with no ingress, got %v", err)
		}
		if !strings.Contains(err.Error(), "0 default-instance ingress interfaces") {
			t.Errorf("the refusal must name the N=0 cause, got %q", err)
		}
	})
	t.Run("lenient warns", func(t *testing.T) {
		tree := flatTreeFromSets(t, sets...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant load must NOT reject a leak with no ingress, got %v", err)
		}
		if !hasWarningContaining(cfg.Warnings, "next-table") {
			t.Fatalf("tolerant load must record a next-table window warning, got %v", cfg.Warnings)
		}
	})
}
