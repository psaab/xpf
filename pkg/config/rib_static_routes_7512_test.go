package config

import (
	"fmt"
	"strings"
	"testing"
)

// #7512 — `routing-options rib inet.0 { static { ... } }` compiled to NOTHING.
//
// The rib loop matched only `inet6.0` / `*.inet6.0`, and every other name fell
// through with no branch and NO ELSE. So the ordinary Junos way to scope IPv4
// statics discarded every route, `commit` succeeded, and no warning was emitted.
//
// The operator-realistic shape is the symmetric pair, which is exactly what
// someone writes once they have learned that IPv6 statics need `rib inet6.0`:
//
//	routing-options {
//	    rib inet.0  { static { route 0.0.0.0/0 { next-hop 10.0.0.1; } } }
//	    rib inet6.0 { static { route ::/0      { next-hop 2001:db8::1; } } }
//	}
//
// That committed clean, installed the IPv6 default route, and silently lost the
// IPv4 one — a total IPv4 blackhole whose only symptom is a routing failure that
// looks like a network problem, because `show configuration` renders the stanza
// back verbatim.

func rib7512Compile(t *testing.T, cfgText string) *Config {
	t.Helper()
	tree, errs := NewParser(cfgText).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse errors: %v\n%s", errs, cfgText)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v\n%s", err, cfgText)
	}
	return cfg
}

func rib7512Prefixes(routes []*StaticRoute) []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		if r != nil {
			out = append(out, r.Destination)
		}
	}
	return out
}

func rib7512DiscardWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "DISCARDED") {
			out = append(out, w)
		}
	}
	return out
}

// TestRibInet0AgreesWithBareStatic_7512 is the core property, asserted as an
// AGREEMENT between the spellings rather than against a hand-written literal.
// The same route reaches the same table however it is scoped, so pinning one
// spelling to an expectation would only encode which one I trusted — and in this
// family the trusted spelling (`rib inet6.0`) was the one that worked while the
// obvious one silently did not.
func TestRibInet0AgreesWithBareStatic_7512(t *testing.T) {
	const prefix = "10.211.0.0/24"
	spellings := map[string]string{
		"bare static":  fmt.Sprintf(`routing-options { static { route %s { next-hop 10.0.0.1; } } }`, prefix),
		"rib inet.0":   fmt.Sprintf(`routing-options { rib inet.0 { static { route %s { next-hop 10.0.0.1; } } } }`, prefix),
		"vrf V.inet.0": fmt.Sprintf(`routing-instances { V { instance-type vrf; routing-options { rib V.inet.0 { static { route %s { next-hop 10.0.0.1; } } } } } }`, prefix),
	}
	var ref []string
	var refName string
	for _, name := range []string{"bare static", "rib inet.0", "vrf V.inet.0"} {

		cfg := rib7512Compile(t, spellings[name])
		routes := cfg.RoutingOptions.StaticRoutes
		if len(cfg.RoutingInstances) > 0 {
			routes = cfg.RoutingInstances[0].StaticRoutes
		}
		got := rib7512Prefixes(routes)
		if ref == nil {
			ref, refName = got, name
			continue
		}
		if strings.Join(got, ",") != strings.Join(ref, ",") {
			t.Fatalf("%s compiled to %v but %s compiled to %v — one route, two meanings "+
				"depending on how it was scoped", name, got, refName, ref)
		}
	}
	if len(ref) != 1 || ref[0] != prefix {
		t.Errorf("every spelling agrees on %v, but the authored route is %s", ref, prefix)
	}
}

// TestSymmetricRibPairInstallsBothFamilies_7512 is the regression guard for the
// reported configuration. It asserts BOTH families, because the defect was
// precisely that one of them worked: a test that checked only IPv4 would have
// passed before the fix if it had also been written against `rib inet6.0`, and a
// test that checked only IPv6 passes both before AND after.
func TestSymmetricRibPairInstallsBothFamilies_7512(t *testing.T) {
	cfg := rib7512Compile(t, `routing-options {
        rib inet.0  { static { route 0.0.0.0/0 { next-hop 10.0.0.1; } } }
        rib inet6.0 { static { route ::/0      { next-hop 2001:db8::1; } } }
    }`)
	v4 := rib7512Prefixes(cfg.RoutingOptions.StaticRoutes)
	v6 := rib7512Prefixes(cfg.RoutingOptions.Inet6StaticRoutes)
	if len(v4) != 1 || v4[0] != "0.0.0.0/0" {
		t.Errorf("IPv4 default route from `rib inet.0` = %v, want [0.0.0.0/0] — this is the "+
			"blackhole: IPv6 forwards and IPv4 goes nowhere, with a clean commit", v4)
	}
	if len(v6) != 1 || v6[0] != "::/0" {
		t.Errorf("IPv6 default route from `rib inet6.0` = %v, want [::/0] — the pre-existing "+
			"behaviour must not regress while fixing its sibling", v6)
	}
}

// TestVRFRibInet0IsCarried_7512 binds the WIRING, not the callee.
// compileRoutingInstances copies fields off the per-instance
// RoutingOptionsConfig ONE BY ONE, so both the v4 routes and the unhandled-rib
// record are lost for a VRF unless named there. Deleting either copy leaves the
// global-scope tests entirely green.
func TestVRFRibInet0IsCarried_7512(t *testing.T) {
	cfg := rib7512Compile(t, `routing-instances { V { instance-type vrf;
        routing-options { rib V.inet.0 { static { route 10.211.0.0/24 { next-hop 10.0.0.1; } } } }
    } }`)
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("expected one routing instance, got %d", len(cfg.RoutingInstances))
	}
	got := rib7512Prefixes(cfg.RoutingInstances[0].StaticRoutes)
	if len(got) != 1 || got[0] != "10.211.0.0/24" {
		t.Errorf("VRF `rib V.inet.0` routes = %v, want [10.211.0.0/24]", got)
	}

	// ...and the unhandled-rib record must cross the same copy.
	cfg2 := rib7512Compile(t, `routing-instances { V { instance-type vrf;
        routing-options { rib V.inet.2 { static { route 10.211.0.0/24 { next-hop 10.0.0.1; } } } }
    } }`)
	warns := rib7512DiscardWarnings(cfg2)
	if len(warns) != 1 {
		t.Fatalf("a VRF rib the compiler does not implement must warn exactly once, got %d: %v",
			len(warns), warns)
	}
	if !strings.Contains(warns[0], `routing-instance "V"`) || !strings.Contains(warns[0], "V.inet.2") {
		t.Errorf("the warning must name the instance AND the rib, got: %q", warns[0])
	}
}

// TestUnimplementedRibWarnsOnBothPaths_7512 is the missing `else` — the durable
// half. Adding an `inet.0` branch alone would leave `inet.2`, `inet.3`, a typo'd
// `ient.0` and every future table name silently eating routes exactly as before.
//
// WARN, not reject, and both paths are asserted separately: `rib inet.2` is
// valid Junos that xpf does not implement, so a box may already hold a committed
// config containing one. Rejecting at strict commit would fail the tolerant load
// of a config the running node itself accepted — the #1960 no-brick class. A
// warning reaches both paths, which is why no lenient* opt is needed here.
func TestUnimplementedRibWarnsOnBothPaths_7512(t *testing.T) {
	const text = `routing-options { rib inet.2 { static { route 10.211.0.0/24 { next-hop 10.0.0.1; } } } }`

	tolerant := rib7512Compile(t, text)
	warns := rib7512DiscardWarnings(tolerant)
	if len(warns) != 1 {
		t.Fatalf("tolerant load must WARN exactly once about the discarded rib, got %d: %v", len(warns), warns)
	}
	for _, want := range []string{`"inet.2"`, "1 static route", "DISCARDED"} {
		if !strings.Contains(warns[0], want) {
			t.Errorf("warning must contain %q — it has to name the rib and how much was lost; got: %q", want, warns[0])
		}
	}

	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	strict, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit must ACCEPT an unimplemented rib (valid Junos; rejecting it "+
			"would brick the tolerant load of a config a running box already committed): %v", err)
	}
	if len(rib7512DiscardWarnings(strict)) != 1 {
		t.Errorf("strict commit must warn too — a warning that fires only on the tolerant path " +
			"is invisible at the moment the operator can still act on it")
	}
}

// TestImplementedAndEmptyRibsDoNotWarn_7512 is the TIGHTENING control, and it is
// what a delete-the-branch matrix cannot see. An over-warning implementation —
// one that reports every rib, or reports a rib that lost nothing — would fire on
// real configurations and train operators to scroll past the warning that
// matters, which is the #6617 cost.
func TestImplementedAndEmptyRibsDoNotWarn_7512(t *testing.T) {
	for name, text := range map[string]string{
		"rib inet.0 (implemented)":   `routing-options { rib inet.0 { static { route 10.211.0.0/24 { next-hop 10.0.0.1; } } } }`,
		"rib inet6.0 (implemented)":  `routing-options { rib inet6.0 { static { route 2001:db8:211::/48 { next-hop 2001:db8::1; } } } }`,
		"VRF V.inet.0 implemented":   `routing-instances { V { instance-type vrf; routing-options { rib V.inet.0 { static { route 10.211.0.0/24 { next-hop 10.0.0.1; } } } } } }`,
		"empty rib, nothing lost":    `routing-options { rib inet.2 { } }`,
		"rib with route-less static": `routing-options { rib inet.2 { static { } } }`,
		"bare static, no rib":        `routing-options { static { route 10.211.0.0/24 { next-hop 10.0.0.1; } } }`,
	} {
		if got := rib7512DiscardWarnings(rib7512Compile(t, text)); len(got) != 0 {
			t.Errorf("%s must NOT warn — nothing was discarded; got %d: %v", name, len(got), got)
		}
	}
}

func TestCrossScopeRibSelectorsWarnAndDiscard_11335(t *testing.T) {
	const route = `static { route 10.211.0.0/24 { next-hop 10.0.0.1; } }`
	const route6 = `static { route 2001:db8:211::/48 { next-hop 2001:db8::1; } }`
	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "other instance rib inside instance",
			text: `routing-instances {
				A { instance-type vrf; routing-options { rib B.inet.0 { ` + route + ` } } }
				B { instance-type vrf; }
			}`,
			want: `rib "B.inet.0"`,
		},
		{
			name: "other instance inet6 rib inside instance",
			text: `routing-instances {
				A { instance-type vrf; routing-options { rib B.inet6.0 { ` + route6 + ` } } }
				B { instance-type vrf; }
			}`,
			want: `rib "B.inet6.0"`,
		},
		{
			name: "main table rib inside instance",
			text: `routing-instances {
				A { instance-type vrf; routing-options { rib inet.0 { ` + route + ` } } }
			}`,
			want: `rib "inet.0"`,
		},
		{
			name: "instance rib at global scope",
			text: `routing-options { rib B.inet.0 { ` + route + ` } }
				routing-instances { B { instance-type vrf; } }`,
			want: `rib "B.inet.0"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := rib7512Compile(t, tc.text)
			warnings := rib7512DiscardWarnings(cfg)
			if len(warnings) != 1 {
				t.Fatalf("cross-scope rib must produce one discard warning, got %d: %v", len(warnings), warnings)
			}
			if !strings.Contains(warnings[0], "cross-scope rib selector") ||
				!strings.Contains(warnings[0], tc.want) {
				t.Fatalf("warning %q must identify the cross-scope selector %q", warnings[0], tc.want)
			}

			tree, errs := NewParser(tc.text).Parse()
			if len(errs) != 0 {
				t.Fatalf("strict fixture parse errors: %v", errs)
			}
			strict, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("cross-scope rib should be warned and discarded, not silently installed or rejected: %v", err)
			}
			strictWarnings := rib7512DiscardWarnings(strict)
			if len(strictWarnings) != 1 ||
				!strings.Contains(strictWarnings[0], "cross-scope rib selector") ||
				!strings.Contains(strictWarnings[0], tc.want) {
				t.Errorf("strict compile must warn about the cross-scope selector %q, got %v", tc.want, strictWarnings)
			}
			if got := rib7512Prefixes(cfg.RoutingOptions.StaticRoutes); len(got) != 0 {
				t.Errorf("cross-scope routes must not be filed in the global table, got %v", got)
			}
			if got := rib7512Prefixes(cfg.RoutingOptions.Inet6StaticRoutes); len(got) != 0 {
				t.Errorf("cross-scope routes must not be filed in the global IPv6 table, got %v", got)
			}
			for _, ri := range cfg.RoutingInstances {
				if got := rib7512Prefixes(ri.StaticRoutes); len(got) != 0 {
					t.Errorf("cross-scope routes must not be filed in instance %q, got %v", ri.Name, got)
				}
				if got := rib7512Prefixes(ri.Inet6StaticRoutes); len(got) != 0 {
					t.Errorf("cross-scope routes must not be filed in instance %q IPv6 table, got %v", ri.Name, got)
				}
			}
		})
	}
}

func TestInScopeRibSelectorsRemainAccepted_11335(t *testing.T) {
	cfg := rib7512Compile(t, `routing-options {
		rib inet.0 { static { route 192.0.2.0/24 { next-hop 10.0.0.1; } } }
		rib inet6.0 { static { route 2001:db8:10::/48 { next-hop 2001:db8::1; } } }
	}
	routing-instances { A { instance-type vrf; routing-options {
		rib A.inet.0 { static { route 198.51.100.0/24 { next-hop 10.0.1.1; } } }
		rib A.inet6.0 { static { route 2001:db8:20::/48 { next-hop 2001:db8:1::1; } } }
	} } }`)

	if got := rib7512Prefixes(cfg.RoutingOptions.StaticRoutes); strings.Join(got, ",") != "192.0.2.0/24" {
		t.Errorf("global rib inet.0 routes = %v, want [192.0.2.0/24]", got)
	}
	if got := rib7512Prefixes(cfg.RoutingOptions.Inet6StaticRoutes); strings.Join(got, ",") != "2001:db8:10::/48" {
		t.Errorf("global rib inet6.0 routes = %v, want [2001:db8:10::/48]", got)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("got %d routing instances, want one", len(cfg.RoutingInstances))
	}
	ri := cfg.RoutingInstances[0]
	if got := rib7512Prefixes(ri.StaticRoutes); strings.Join(got, ",") != "198.51.100.0/24" {
		t.Errorf("instance A rib A.inet.0 routes = %v, want [198.51.100.0/24]", got)
	}
	if got := rib7512Prefixes(ri.Inet6StaticRoutes); strings.Join(got, ",") != "2001:db8:20::/48" {
		t.Errorf("instance A rib A.inet6.0 routes = %v, want [2001:db8:20::/48]", got)
	}
	if warnings := rib7512DiscardWarnings(cfg); len(warnings) != 0 {
		t.Errorf("in-scope rib selectors must remain warning-free, got %v", warnings)
	}
}
