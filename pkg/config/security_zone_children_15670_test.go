package config

import (
	"strings"
	"testing"
)

// #15670 (V3-02): standard Junos security-zone children were closed-world
// hard-rejected on strict commit and, on the tolerant path, poisoned the
// whole zone via #11575 DroppedEnforcementChild (zone unbound, policies /
// host-inbound inert). They must parse onto ZoneConfig, keep the zone bound
// on both paths, and surface an accepted-only advisory where xpf has no
// runtime for the knob (all except the enforcement-bearing white-list,
// which must NOT be silently modeled — see below).

func zoneChildrenConfig15670(t *testing.T, extra string) *ConfigTree {
	t.Helper()
	text := `interfaces {
 ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } }
}
security {
 screen { ids-option safe { tcp { land; } } }
 zones { security-zone trust {
  interfaces { ge-0/0/0.0; }
  screen safe;
  ` + extra + `
 } }
}
`
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse config: %v", errs)
	}
	return tree
}

func TestStandardZoneChildrenCommitAndStayBound15670(t *testing.T) {
	cases := []struct {
		name  string
		extra string
		check func(t *testing.T, z *ZoneConfig)
	}{
		{"application-tracking", "application-tracking;", func(t *testing.T, z *ZoneConfig) {
			if !z.ApplicationTracking {
				t.Fatalf("ApplicationTracking not set: %+v", z)
			}
		}},
		{"source-identity-log", "source-identity-log;", func(t *testing.T, z *ZoneConfig) {
			if !z.SourceIdentityLog {
				t.Fatalf("SourceIdentityLog not set: %+v", z)
			}
		}},
		{"enable-reverse-reroute", "enable-reverse-reroute;", func(t *testing.T, z *ZoneConfig) {
			if !z.EnableReverseReroute {
				t.Fatalf("EnableReverseReroute not set: %+v", z)
			}
		}},
		{"unidirectional-session-refreshing", "unidirectional-session-refreshing;", func(t *testing.T, z *ZoneConfig) {
			if !z.UnidirectionalRefresh {
				t.Fatalf("UnidirectionalRefresh not set: %+v", z)
			}
		}},
		{"advance-policy-based-routing-profile", "advance-policy-based-routing-profile apbr-prof;", func(t *testing.T, z *ZoneConfig) {
			if z.AdvancePBRProfile != "apbr-prof" {
				t.Fatalf("AdvancePBRProfile = %q, want apbr-prof", z.AdvancePBRProfile)
			}
		}},
		{"advanced-connection-tracking", "advanced-connection-tracking { mode allow-target-host; timeout 120; track-all-policies-to-this-zone; }", func(t *testing.T, z *ZoneConfig) {
			if z.AdvancedConnectionTracking == nil {
				t.Fatalf("AdvancedConnectionTracking nil: %+v", z)
			}
			act := z.AdvancedConnectionTracking
			if act.Mode != "allow-target-host" || act.Timeout != 120 || !act.TrackAllPolicies {
				t.Fatalf("ACT = %+v, want mode=allow-target-host timeout=120 trackAll=true", act)
			}
		}},
		{"white-list", "white-list wl1;", func(t *testing.T, z *ZoneConfig) {
			if len(z.WhiteList) != 1 || z.WhiteList[0] != "wl1" {
				t.Fatalf("WhiteList = %v, want [wl1]", z.WhiteList)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := zoneChildrenConfig15670(t, tc.extra)
			for _, path := range []string{"strict", "lenient"} {
				var cfg *Config
				var err error
				if path == "strict" {
					cfg, err = CompileConfig(tree)
				} else {
					cfg, err = CompileConfigLenient(tree)
				}
				if err != nil {
					t.Fatalf("%s compile rejected standard zone child %q: %v", path, tc.name, err)
				}
				z := cfg.Security.Zones["trust"]
				if z == nil {
					t.Fatalf("%s: zone trust missing", path)
				}
				if z.DroppedEnforcementChild {
					t.Fatalf("%s: standard zone child %q poisoned the zone (#11575 quarantine reproduced)", path, tc.name)
				}
				if len(z.Interfaces) != 1 || z.Interfaces[0] != "ge-0/0/0.0" {
					t.Fatalf("%s: zone unbound or membership lost: %v", path, z.Interfaces)
				}
				if z.ScreenProfile != "safe" {
					t.Fatalf("%s: screen binding lost: %+v", path, z)
				}
				if path == "strict" {
					tc.check(t, z)
				}
				// No unknown-child / quarantine warning may fire.
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "unknown child keyword") || strings.Contains(w, "DroppedEnforcementChild") {
						t.Fatalf("%s: quarantine warning for standard child %q: %q", path, tc.name, w)
					}
				}
			}
		})
	}
}

// All seven together (flat-set spelling, the shape `display set` emits).
func TestStandardZoneChildrenFlatSet15670(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust application-tracking",
		"set security zones security-zone trust source-identity-log",
		"set security zones security-zone trust enable-reverse-reroute",
		"set security zones security-zone trust unidirectional-session-refreshing",
		"set security zones security-zone trust advance-policy-based-routing-profile apbr-prof",
		"set security zones security-zone trust advanced-connection-tracking mode allow-any-host",
		"set security zones security-zone trust advanced-connection-tracking timeout 60",
		"set security zones security-zone trust white-list wl1",
		"set security zones security-zone trust white-list wl2",
	}))
	if err != nil {
		t.Fatalf("flat-set standard zone children rejected: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil || z.DroppedEnforcementChild {
		t.Fatalf("flat-set zone poisoned: %+v", z)
	}
	if !z.ApplicationTracking || !z.SourceIdentityLog || !z.EnableReverseReroute || !z.UnidirectionalRefresh {
		t.Fatalf("flat-set flags lost: %+v", z)
	}
	if z.AdvancePBRProfile != "apbr-prof" {
		t.Fatalf("flat-set APBR profile = %q", z.AdvancePBRProfile)
	}
	if z.AdvancedConnectionTracking == nil || z.AdvancedConnectionTracking.Mode != "allow-any-host" || z.AdvancedConnectionTracking.Timeout != 60 {
		t.Fatalf("flat-set ACT = %+v", z.AdvancedConnectionTracking)
	}
	if len(z.WhiteList) != 2 {
		t.Fatalf("flat-set WhiteList = %v, want 2 entries", z.WhiteList)
	}
	if len(z.Interfaces) != 1 {
		t.Fatalf("flat-set zone unbound: %v", z.Interfaces)
	}
}

// The inert knobs must warn accepted-only (never silently believed enforced);
// white-list is enforcement-bearing (screen bypass) with no runtime, so it
// must warn too — modeling it without a runtime must not be silent. The
// advisory reaches ValidateConfig (alarm recompute surfaces) as well as
// cfg.Warnings.
func TestStandardZoneChildrenAcceptedOnlyAdvisory15670(t *testing.T) {
	tree := zoneChildrenConfig15670(t, "application-tracking;\n  source-identity-log;\n  enable-reverse-reroute;\n  unidirectional-session-refreshing;\n  advance-policy-based-routing-profile apbr-prof;\n  advanced-connection-tracking { mode allow-any-host; }\n  white-list wl1;")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	joined := strings.Join(cfg.Warnings, "\n") + "\n" + strings.Join(ValidateConfig(cfg), "\n")
	for _, want := range []string{"application-tracking", "source-identity-log", "enable-reverse-reroute", "unidirectional-session-refreshing", "advance-policy-based-routing-profile", "advanced-connection-tracking", "white-list", "accepted-only", "#15670"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("accepted-only advisory missing %q; warnings=%v validate=%v", want, cfg.Warnings, ValidateConfig(cfg))
		}
	}
}

// Malformed shapes must fail closed: strict rejects, tolerant poisons the
// zone (never silently widened/dropped).
func TestStandardZoneChildrenMalformedFailClosed15670(t *testing.T) {
	cases := []struct{ name, extra string }{
		{"flag with operand", "application-tracking extra;"},
		{"profile without name", "advance-policy-based-routing-profile;"},
		{"bad ACT mode", "advanced-connection-tracking { mode bogus-mode; }"},
		{"bad ACT timeout", "advanced-connection-tracking { timeout not-a-number; }"},
		{"unknown ACT child", "advanced-connection-tracking { bogus-child; }"},
		{"white-list without name", "white-list;"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := zoneChildrenConfig15670(t, tc.extra)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict compile accepted malformed %q (%s)", tc.extra, tc.name)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile must not hard-fail (#1960): %v", err)
			}
			z := cfg.Security.Zones["trust"]
			if z == nil || !z.DroppedEnforcementChild {
				t.Fatalf("malformed %q did not poison zone on tolerant path: %+v", tc.extra, z)
			}
			if len(z.Interfaces) != 0 {
				t.Fatalf("malformed %q left zone bound: %v", tc.extra, z.Interfaces)
			}
		})
	}
}
