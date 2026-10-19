package config

import (
	"strings"
	"testing"
)

// TestNextTableFamilyIndexRejected_15201 proves #15201 (A10-03):
// parseNextTableInstance discards the `.inet[6].N` suffix, so a next-table
// whose family or index does not match the route's own table commits and
// leaks into the named instance's unicast table instead of being rejected.
//
// Cases (blue is a DEFINED instance, so the #5693 definedness gate passes
// and only the new family/index gate can fire):
//   - IPv4 route (global `static`, i.e. inet.0) to `blue.inet6.0`
//   - IPv4 route to `blue.inet.2` (Junos inet.2 is the RPF table, not unicast)
//   - IPv6 route (rib inet6.0) to `blue.inet.0`
//   - IPv6 route to `blue.inet6.2`
//   - IPv4 route to `blue.inet6.2` (both family and index wrong)
//
// FAIL-ON-REVERT: dropping the family/index check from
// validateNextTableTargetReferencesStrict makes CompileConfig accept every
// case below, so the reject assertions fire RED.
func TestNextTableFamilyIndexRejected_15201(t *testing.T) {
	base := []string{
		"set routing-instances blue instance-type virtual-router",
		"set interfaces ge-0/0/0 unit 0",
	}
	cases := []struct {
		name string
		sets []string
	}{
		{"v4-route-to-inet6-table", []string{
			"set routing-options static route 10.0.0.0/8 next-table blue.inet6.0",
		}},
		{"v4-route-to-inet2", []string{
			"set routing-options static route 10.0.0.0/8 next-table blue.inet.2",
		}},
		{"v6-route-to-inet-table", []string{
			"set routing-options rib inet6.0 static route 2001:db8::/32 next-table blue.inet.0",
		}},
		{"v6-route-to-inet6-2", []string{
			"set routing-options rib inet6.0 static route 2001:db8::/32 next-table blue.inet6.2",
		}},
		{"v4-route-to-inet6-2", []string{
			"set routing-options static route 10.0.0.0/8 next-table blue.inet6.2",
		}},
		{"v4-route-bare-suffix-garbage", []string{
			"set routing-options static route 10.0.0.0/8 next-table blue.inetgarbage",
		}},
		{"v4-route-inet6-no-index", []string{
			"set routing-options static route 10.0.0.0/8 next-table blue.inet6",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sets := append(append([]string{}, base...), tc.sets...)
			tree := flatTreeFromSets(t, sets...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected CompileConfig to reject %s; it committed and would leak into blue's unicast table", tc.name)
			}
			if !strings.Contains(err.Error(), "next-table") {
				t.Fatalf("error %q must name the next-table operand", err.Error())
			}
			// The error must quote the raw token the operator typed.
			raw := tc.sets[0][strings.LastIndex(tc.sets[0], "next-table ")+len("next-table "):]
			if !strings.Contains(err.Error(), raw) {
				t.Fatalf("error %q must quote raw next-table token %q", err.Error(), raw)
			}
		})
	}
}

// TestNextTableFamilyIndexValidControls_15201 guards the legitimate shapes
// that must stay unchanged: matching family + index 0, the bare-instance
// shorthand (no suffix — Junos requires the suffixed form, but xpf has
// always accepted the bare name and consumers construct it directly), and
// dotted instance names containing ".inet".
func TestNextTableFamilyIndexValidControls_15201(t *testing.T) {
	t.Run("v4-to-inet0", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances blue instance-type virtual-router",
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 10.0.0.0/8 next-table blue.inet.0",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("valid v4 next-table must compile, got %v", err)
		}
		if len(cfg.RoutingOptions.StaticRoutes) != 1 ||
			cfg.RoutingOptions.StaticRoutes[0].NextTable != "blue" {
			t.Fatalf("compiled route = %+v, want NextTable blue", cfg.RoutingOptions.StaticRoutes)
		}
	})
	t.Run("v6-to-inet6-0", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances blue instance-type virtual-router",
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options rib inet6.0 static route 2001:db8::/32 next-table blue.inet6.0",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("valid v6 next-table must compile, got %v", err)
		}
		if len(cfg.RoutingOptions.Inet6StaticRoutes) != 1 ||
			cfg.RoutingOptions.Inet6StaticRoutes[0].NextTable != "blue" {
			t.Fatalf("compiled route = %+v, want NextTable blue", cfg.RoutingOptions.Inet6StaticRoutes)
		}
	})
	t.Run("dotted-instance-v4", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances a.inet.b instance-type virtual-router",
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 10.0.0.0/8 next-table a.inet.b.inet.0",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("dotted instance next-table must compile (#5632), got %v", err)
		}
		if cfg.RoutingOptions.StaticRoutes[0].NextTable != "a.inet.b" {
			t.Fatalf("NextTable = %q, want a.inet.b", cfg.RoutingOptions.StaticRoutes[0].NextTable)
		}
	})
	t.Run("dotted-instance-wrong-family", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances a.inet.b instance-type virtual-router",
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 10.0.0.0/8 next-table a.inet.b.inet6.0",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("dotted instance with wrong family must be rejected")
		}
	})
}

// TestNextTableFamilyIndexLenientDowngrade_15201 proves the tolerant load /
// peer-sync path downgrades the new rejection to a warning (#1960 no-brick),
// exactly like the #5693 definedness gate it extends.
func TestNextTableFamilyIndexLenientDowngrade_15201(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set routing-instances blue instance-type virtual-router",
		"set interfaces ge-0/0/0 unit 0",
		"set routing-options static route 10.0.0.0/8 next-table blue.inet6.0",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig must reject the family-mismatched next-table")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must NOT brick on a family-mismatched next-table, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "next-table") && strings.Contains(w, "blue.inet6.0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant load must record a next-table downgrade warning, got %v", cfg.Warnings)
	}
}

// TestParseNextTableSuffix_15201 pins the suffix parser: only a terminal
// ".inet.0" / ".inet6.0" is a well-formed Junos unicast target; every other
// suffixed or malformed shape is reported malformed so the strict gate can
// reject it instead of silently discarding the suffix.
func TestParseNextTableSuffix_15201(t *testing.T) {
	cases := []struct {
		raw       string
		instance  string
		suffix    string
		hasSuffix bool
	}{
		{"blue.inet.0", "blue", ".inet.0", true},
		{"blue.inet6.0", "blue", ".inet6.0", true},
		{"a.inet.b.inet.0", "a.inet.b", ".inet.0", true},
		{"a.inet.b.inet6.0", "a.inet.b", ".inet6.0", true},
		{"blue", "blue", "", false},
		{"blue.inet.2", "blue", ".inet.2", true},
		{"blue.inet6.2", "blue", ".inet6.2", true},
		{"blue.inetgarbage", "blue", ".inetgarbage", true},
		{"blue.inet6", "blue", ".inet6", true},
		{"blue.inet.0.extra", "blue", ".inet.0.extra", true},
	}
	for _, tc := range cases {
		instance, suffix, hasSuffix := parseNextTableSuffix(tc.raw)
		if instance != tc.instance || suffix != tc.suffix || hasSuffix != tc.hasSuffix {
			t.Errorf("parseNextTableSuffix(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.raw, instance, suffix, hasSuffix, tc.instance, tc.suffix, tc.hasSuffix)
		}
		// parseNextTableInstance must agree on the instance part.
		if got := parseNextTableInstance(tc.raw); got != tc.instance {
			t.Errorf("parseNextTableInstance(%q) = %q, want %q", tc.raw, got, tc.instance)
		}
	}
}

// TestNextTableV6UnderBareStatic_15201 pins the #9820 shape: a v6
// destination authored under bare `static` stays in the inet list, so
// family must come from the destination, not the list. Its inet6.0
// target must accept and its inet.0 target must reject.
func TestNextTableV6UnderBareStatic_15201(t *testing.T) {
	t.Run("v6-bare-static-to-inet6-0-accepted", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances target instance-type virtual-router",
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 2001:db8::/32 next-table target.inet6.0",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("v6 route under bare static to inet6.0 must compile, got %v", err)
		}
	})
	t.Run("v6-bare-static-to-inet-0-rejected", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set routing-instances target instance-type virtual-router",
			"set interfaces ge-0/0/0 unit 0",
			"set routing-options static route 2001:db8::/32 next-table target.inet.0",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("v6 route under bare static to inet.0 must be rejected")
		}
	})
}

// TestNextTableBadSuffixExcluded_15201 pins the tolerant-path half: a route
// whose raw suffix is invalid for its destination family is excluded from
// the userspace FIB / show verdicts (StaticRouteExcludedReason), while the
// matching-family and bare-name controls stay published.
func TestNextTableBadSuffixExcluded_15201(t *testing.T) {
	defined := map[string]struct{}{"blue": {}}
	cases := []struct {
		name string
		sr   *StaticRoute
		want string // substring; "" means not excluded
	}{
		{"v4-bad-family", &StaticRoute{Destination: "10.0.0.0/8", NextTable: "blue", NextTableRaw: "blue.inet6.0"}, "invalid table suffix"},
		{"v4-inet2", &StaticRoute{Destination: "10.0.0.0/8", NextTable: "blue", NextTableRaw: "blue.inet.2"}, "invalid table suffix"},
		{"v6-bad-family", &StaticRoute{Destination: "2001:db8::/32", NextTable: "blue", NextTableRaw: "blue.inet.0"}, "invalid table suffix"},
		{"v4-good", &StaticRoute{Destination: "10.0.0.0/8", NextTable: "blue", NextTableRaw: "blue.inet.0"}, ""},
		{"v6-good", &StaticRoute{Destination: "2001:db8::/32", NextTable: "blue", NextTableRaw: "blue.inet6.0"}, ""},
		{"v4-bare", &StaticRoute{Destination: "10.0.0.0/8", NextTable: "blue"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := StaticRouteExcludedReason(tc.sr, false, defined)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("StaticRouteExcludedReason = %q, want not excluded", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("StaticRouteExcludedReason = %q, want containing %q", got, tc.want)
			}
		})
	}
}
