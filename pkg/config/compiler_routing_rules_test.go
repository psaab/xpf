package config

import (
	"fmt"
	"strings"
	"testing"
)

// mkLeakingInstance builds a config with ONE routing-instance that imports
// the main table via an interface-routes rib-group and carries n static
// connected prefixes on its member interface unit. family selects v4 ("inet")
// or v6 ("inet6") addresses (and the corresponding rib-group field), so the
// #3876 per-prefix window gate can be exercised on either family.
func mkLeakingInstance(n int, family string) *Config {
	cfg := &Config{}
	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if family == "inet6" {
			addrs = append(addrs, fmt.Sprintf("2001:db8:%x::1/64", i))
		} else {
			addrs = append(addrs, fmt.Sprintf("10.%d.%d.1/24", i/256, i%256))
		}
	}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: addrs},
		}},
	}
	cfg.RoutingOptions.RibGroups = map[string]*RibGroup{
		"leak": {Name: "leak", ImportRibs: []string{"inet.0", "inet6.0"}},
	}
	ri := &RoutingInstanceConfig{
		Name:       "dmz-vr",
		TableID:    101,
		Interfaces: []string{"ge-0/0/1.0"},
	}
	if family == "inet6" {
		ri.InterfaceRoutesRibGroupV6 = "leak"
	} else {
		ri.InterfaceRoutesRibGroup = "leak"
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{ri}
	return cfg
}

// mkNextTableCfg builds a *Config with n global static routes that each carry a
// next-table VRF-leak target, for the direct window-gate unit test. The target
// value is non-empty (what the applier counts toward its ip-rule window); the
// gate under test only counts next-table routes and does not resolve the target.
// One unclaimed unit (N=1, #9810) preserves the 100-pass/101-reject boundary.
func mkNextTableCfg(n int) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}
	routes := make([]*StaticRoute, n)
	for i := range routes {
		routes[i] = &StaticRoute{Destination: "10.0.0.0/8", NextTable: "vr"}
	}
	cfg.RoutingOptions.StaticRoutes = routes
	return cfg
}

// TestRoutingRuleWindowsStrictGate_5854 unit-tests the admission-cap
// over-subscription gate directly: at or below each cap (100 next-table rule
// entries, 1000 rib-group leak rules) it passes; above either cap it returns an
// error. It also pins the counting semantics (both static-route lists count;
// an instance with no rib-group reference does not; a v6-only reference does).
//
// FAIL-ON-REVERT: reverting validateRoutingRuleWindowsStrict to always return
// nil (the pre-#5854 warn-only behaviour) turns the over-limit sub-tests RED.
func TestRoutingRuleWindowsStrictGate_5854(t *testing.T) {
	t.Run("next-table at limit passes", func(t *testing.T) {
		if err := validateRoutingRuleWindowsStrict(mkNextTableCfg(maxNextTableRules)); err != nil {
			t.Fatalf("%d next-table routes must pass, got %v", maxNextTableRules, err)
		}
	})

	t.Run("next-table over limit rejected", func(t *testing.T) {
		// Split across inet + inet6 to prove both lists count toward the window.
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}
		cfg.RoutingOptions.StaticRoutes = mkNextTableCfg(60).RoutingOptions.StaticRoutes
		cfg.RoutingOptions.Inet6StaticRoutes = mkNextTableCfg(41).RoutingOptions.StaticRoutes
		err := validateRoutingRuleWindowsStrict(cfg)
		if err == nil || !strings.Contains(err.Error(), "next-table") {
			t.Fatalf("101 next-table routes must be rejected, got %v", err)
		}
		if !strings.Contains(err.Error(), "101") {
			t.Errorf("error should report the combined count 101, got %q", err)
		}
	})

	t.Run("rib-group at limit passes", func(t *testing.T) {
		if err := validateRoutingRuleWindowsStrict(mkLeakingInstance(maxRibGroupLeakRules, "inet")); err != nil {
			t.Fatalf("%d leaked prefixes must pass, got %v", maxRibGroupLeakRules, err)
		}
	})

	t.Run("rib-group over limit rejected", func(t *testing.T) {
		err := validateRoutingRuleWindowsStrict(mkLeakingInstance(1001, "inet"))
		if err == nil || !strings.Contains(err.Error(), "rib-group") {
			t.Fatalf("1001 leaked prefixes must be rejected, got %v", err)
		}
		if !strings.Contains(err.Error(), "1001") {
			t.Errorf("error should report the prefix count 1001, got %q", err)
		}
	})

	t.Run("instance without rib-group reference not counted", func(t *testing.T) {
		cfg := mkLeakingInstance(1001, "inet")
		cfg.RoutingInstances[0].InterfaceRoutesRibGroup = ""
		if err := validateRoutingRuleWindowsStrict(cfg); err != nil {
			t.Fatalf("an instance without a rib-group reference must not count, got %v", err)
		}
	})

	t.Run("v6-only rib-group reference counted", func(t *testing.T) {
		if err := validateRoutingRuleWindowsStrict(mkLeakingInstance(1001, "inet6")); err == nil {
			t.Fatal("a v6-only rib-group over-limit must be rejected")
		}
	})
}

// nextTableOverLimitSets returns flat `set` commands for 101 next-table static
// routes (one over the 100-entry admission cap) all pointing at a DEFINED
// routing-instance, so the #5693 next-table definedness gate passes and the
// #5854 admission-cap gate is the one that fires. One unclaimed unit (N=1,
// #9810) keeps this a genuine overflow cell rather than an N=0 reject.
func nextTableOverLimitSets() []string {
	sets := []string{
		"set routing-instances vr instance-type virtual-router",
		"set interfaces ge-0/0/0 unit 0",
	}
	for i := 0; i <= maxNextTableRules; i++ { // 0..100 => 101 distinct routes
		sets = append(sets, fmt.Sprintf(
			"set routing-options static route 10.%d.%d.0/24 next-table vr.inet.0", i/256, i%256))
	}
	return sets
}

// whose interface-routes rib-group imports the main table and whose member
// unit carries 1001 connected prefixes (one over the 1000-rule admission cap).
func ribGroupOverLimitSets() []string {
	return ribGroupPrefixSets(maxRibGroupLeakRules+1, "inet.0")
}

func ribGroupPrefixSets(prefixCount int, importRib string) []string {
	sets := []string{
		"set routing-instances vr instance-type virtual-router",
		"set routing-instances vr routing-options interface-routes rib-group inet leak",
		"set routing-instances vr interface ge-0/0/1.0",
		fmt.Sprintf("set routing-options rib-groups leak import-rib %s", importRib),
	}
	for i := 0; i < prefixCount; i++ {
		sets = append(sets, fmt.Sprintf(
			"set interfaces ge-0/0/1 unit 0 family inet address 10.%d.%d.1/24", i/256, i%256))
	}
	return sets
}

// TestRoutingRuleWindowsStrictReject_5854 proves the #5854 fix end-to-end on the
// STRICT commit path: a config that exceeds either ip-rule admission cap is
// HARD-REJECTED by CompileConfig instead of committing green and being silently
// truncated at apply time (routes claimed but not programmed).
//
// FAIL-ON-REVERT: removing the validateRoutingRuleWindowsStrict call from
// runUniformGates (or reverting the gate to a no-op) makes CompileConfig accept
// the over-limit configs, so these reject assertions fire RED.
func TestRoutingRuleWindowsStrictReject_5854(t *testing.T) {
	t.Run("next-table 101 rejected at commit", func(t *testing.T) {
		tree := flatTreeFromSets(t, nextTableOverLimitSets()...)
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "next-table") {
			t.Fatalf("strict CompileConfig must reject 101 next-table routes, got %v", err)
		}
	})

	t.Run("rib-group 1001 rejected at commit", func(t *testing.T) {
		tree := flatTreeFromSets(t, ribGroupOverLimitSets()...)
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "rib-group") {
			t.Fatalf("strict CompileConfig must reject 1001 rib-group leak prefixes, got %v", err)
		}
	})
}

// TestRoutingRuleWindowsLenientWarns_5854 proves the strict/tolerant split: the
// SAME over-limit configs LOAD (never hard-fail) on the tolerant path
// (CompileConfigLenient) with a downgrade warning, so an already-committed or
// peer-synced generation that predates this rejection still boots (#1960 — the
// applier's admission caps keep the excess inert).
//
// FAIL-ON-REVERT: dropping opts.lenientRoutingRuleWindows from the lenient opts
// (or otherwise hard-rejecting in lenient) makes these loads error → RED.
func TestRoutingRuleWindowsLenientWarns_5854(t *testing.T) {
	t.Run("next-table 101 loads with a warning", func(t *testing.T) {
		tree := flatTreeFromSets(t, nextTableOverLimitSets()...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant load must NOT reject 101 next-table routes, got %v", err)
		}
		if !hasWarningContaining(cfg.Warnings, "next-table") {
			t.Fatalf("tolerant load must record a next-table window warning, got %v", cfg.Warnings)
		}
	})

	t.Run("rib-group 1001 loads with a warning", func(t *testing.T) {
		tree := flatTreeFromSets(t, ribGroupOverLimitSets()...)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant load must NOT reject 1001 rib-group prefixes, got %v", err)
		}
		if !hasWarningContaining(cfg.Warnings, "rib-group") {
			t.Fatalf("tolerant load must record a rib-group window warning, got %v", cfg.Warnings)
		}
	})
}

func TestRibGroupLeakPrefixCountMatchesApply11397(t *testing.T) {
	t.Run("v4 group ignores v6 prefixes", func(t *testing.T) {
		cfg := mkLeakingInstance(800, "inet")
		v6 := mkLeakingInstance(800, "inet6")
		unit := cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0]
		unit.Addresses = append(unit.Addresses,
			v6.Interfaces.Interfaces["ge-0/0/1"].Units[0].Addresses...)
		if got, want := ribGroupLeakPrefixCount(cfg), 800; got != want {
			t.Fatalf("v4-only group counts %d prefixes, want %d", got, want)
		}
		if err := validateRoutingRuleWindowsStrict(cfg); err != nil {
			t.Fatalf("800 v4 leaks must fit the window despite 800 unused v6 prefixes: %v", err)
		}
	})

	t.Run("v6 group ignores v4 prefixes", func(t *testing.T) {
		cfg := mkLeakingInstance(800, "inet6")
		v4 := mkLeakingInstance(800, "inet")
		unit := cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0]
		unit.Addresses = append(unit.Addresses,
			v4.Interfaces.Interfaces["ge-0/0/1"].Units[0].Addresses...)
		if got, want := ribGroupLeakPrefixCount(cfg), 800; got != want {
			t.Fatalf("v6-only group counts %d prefixes, want %d", got, want)
		}
		if err := validateRoutingRuleWindowsStrict(cfg); err != nil {
			t.Fatalf("800 v6 leaks must fit the window despite 800 unused v4 prefixes: %v", err)
		}
	})

	t.Run("shared source table is counted once", func(t *testing.T) {
		cfg := mkLeakingInstance(600, "inet")
		second := mkLeakingInstance(600, "inet")
		peer := second.RoutingInstances[0]
		peer.Name = "dmz-vr-peer"
		peer.Interfaces = []string{"ge-0/0/2.0"}
		cfg.Interfaces.Interfaces["ge-0/0/2"] = second.Interfaces.Interfaces["ge-0/0/1"]
		cfg.Interfaces.Interfaces["ge-0/0/2"].Name = "ge-0/0/2"
		cfg.RoutingInstances = append(cfg.RoutingInstances, peer)
		if got, want := ribGroupLeakPrefixCount(cfg), 600; got != want {
			t.Fatalf("shared table installs %d prefixes, want %d", got, want)
		}
		if err := validateRoutingRuleWindowsStrict(cfg); err != nil {
			t.Fatalf("one 600-rule source table must fit the window: %v", err)
		}
	})

	t.Run("self-only group counts no leaked prefixes", func(t *testing.T) {
		cfg := mkLeakingInstance(1500, "inet")
		cfg.RoutingOptions.RibGroups["leak"].ImportRibs = []string{"dmz-vr.inet.0"}
		if got := ribGroupLeakPrefixCount(cfg); got != 0 {
			t.Fatalf("self-only import produces %d leak rules, want 0", got)
		}
		if err := validateRoutingRuleWindowsStrict(cfg); err != nil {
			t.Fatalf("self-only 1500-prefix group must not consume leak slots: %v", err)
		}
	})
}

func TestRibGroupWindowGateVRFOnlyAndMainImport11397(t *testing.T) {
	t.Run("VRF-only 1500-prefix group commits with Phase 2 warning", func(t *testing.T) {
		sets := ribGroupPrefixSets(1500, "peer.inet.0")
		sets = append(sets, "set routing-instances peer instance-type virtual-router")
		cfg, err := CompileConfig(flatTreeFromSets(t, sets...))
		if err != nil {
			t.Fatalf("VRF-only group must not consume phase-one leak slots: %v", err)
		}
		if !hasWarningContaining(cfg.Warnings, "Phase 2 deferral") {
			t.Fatalf("VRF-only import must retain its Phase 2 warning, got %v", cfg.Warnings)
		}
	})

	t.Run("main-importing 1500-prefix group remains rejected", func(t *testing.T) {
		_, err := CompileConfig(flatTreeFromSets(t, ribGroupPrefixSets(1500, "inet.0")...))
		if err == nil || !strings.Contains(err.Error(), "rib-group") ||
			!strings.Contains(err.Error(), "1500") {
			t.Fatalf("1500 main-table leaks must be rejected with their count, got %v", err)
		}
	})
	t.Run("sibling-family main import counts zero and commits", func(t *testing.T) {
		cfg := mkLeakingInstance(1500, "inet")
		cfg.RoutingOptions.RibGroups["leak"].ImportRibs = []string{"inet6.0"}
		if got := ribGroupLeakPrefixCount(cfg); got != 0 {
			t.Fatalf("v4 slot importing only inet6.0 counts %d leaks, want 0", got)
		}
		if err := validateRoutingRuleWindowsStrict(cfg); err != nil {
			t.Fatalf("v4 slot importing only inet6.0 must not consume leak slots: %v", err)
		}

		sets := ribGroupPrefixSets(1500, "inet6.0")
		if _, err := CompileConfig(flatTreeFromSets(t, sets...)); err != nil {
			t.Fatalf("1500 v4 prefixes imported only from inet6.0 must commit: %v", err)
		}
	})
}
