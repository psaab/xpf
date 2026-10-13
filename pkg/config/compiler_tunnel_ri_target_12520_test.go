package config

import (
	"fmt"
	"strings"
	"testing"
)

func tunnelRITargetTree12520(t *testing.T, target, level string, instanceType string) *ConfigTree {
	t.Helper()
	lines := []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
	}
	prefix := "set interfaces gr-0/0/0 tunnel"
	if level == "unit" {
		prefix = "set interfaces gr-0/0/0 unit 0 tunnel"
	}
	lines = append(lines, prefix+" routing-instance destination "+target)
	if instanceType != "" {
		lines = append(lines, "set routing-instances "+target+" instance-type "+instanceType)
	}
	return treeFromSet(t, lines)
}

func tunnelConfigAtLevel12520(cfg *Config, level string) *TunnelConfig {
	iface := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if level == "unit" {
		return iface.Units[0].Tunnel
	}
	return iface.Tunnel
}

func TestTunnelRoutingInstanceTargetsStrictAndTolerant12520(t *testing.T) {
	badTargets := []struct {
		name         string
		target       string
		instanceType string
		wantReason   string
	}{
		{name: "undefined", target: "missing", wantReason: "undefined"},
		{name: "forwarding", target: "fwd", instanceType: "forwarding", wantReason: "forwarding instance"},
		{name: "reserved management", target: "mgmt", wantReason: "reserved for the management VRF"},
	}
	for _, level := range []string{"interface", "unit"} {
		for _, tc := range badTargets {
			t.Run(level+"/"+tc.name, func(t *testing.T) {
				tree := tunnelRITargetTree12520(t, tc.target, level, tc.instanceType)
				if _, err := CompileConfig(tree); err == nil {
					t.Fatalf("strict compile accepted tunnel target %q", tc.target)
				} else if !strings.Contains(err.Error(), "#12520") || !strings.Contains(err.Error(), tc.wantReason) {
					t.Fatalf("strict error %q does not identify target class %q", err, tc.wantReason)
				}

				cfg, err := CompileConfigLenient(tunnelRITargetTree12520(t, tc.target, level, tc.instanceType))
				if err != nil {
					t.Fatalf("tolerant compile rejected legacy target %q: %v", tc.target, err)
				}
				if got := tunnelConfigAtLevel12520(cfg, level).RoutingInstance; got != "" {
					t.Fatalf("tolerant tunnel target = %q, want quarantined target cleared to default", got)
				}
				foundWarning := false
				for _, warning := range cfg.Warnings {
					if strings.Contains(warning, "#12520") && strings.Contains(warning, tc.target) {
						foundWarning = true
						break
					}
				}
				if !foundWarning {
					t.Fatalf("tolerant compile omitted #12520 warning for target %q: %v", tc.target, cfg.Warnings)
				}
			})
		}
	}
}

func TestTunnelRoutingInstanceTolerantQuarantinesEveryClaim12520(t *testing.T) {
	cfg, err := CompileConfigLenient(treeFromSet(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination missing",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.3",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.4",
		"set interfaces gr-0/0/1 tunnel routing-instance destination mgmt",
		"set interfaces gr-0/0/1 unit 0 family inet address 10.0.1.1/30",
	}))
	if err != nil {
		t.Fatalf("tolerant compile rejected legacy targets: %v", err)
	}
	var targetWarnings []string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12520") {
			targetWarnings = append(targetWarnings, warning)
		}
	}
	if len(targetWarnings) != 2 {
		t.Fatalf("got %d #12520 warnings, want one per invalid claim: %v",
			len(targetWarnings), targetWarnings)
	}
	for _, want := range []string{"gr-0/0/0", "missing", "gr-0/0/1", "mgmt"} {
		found := false
		for _, warning := range targetWarnings {
			if strings.Contains(warning, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("#12520 warnings omit %q: %v", want, targetWarnings)
		}
	}
	for _, ifName := range []string{"gr-0/0/0", "gr-0/0/1"} {
		if got := cfg.Interfaces.Interfaces[ifName].Tunnel.RoutingInstance; got != "" {
			t.Errorf("%s tunnel target = %q, want quarantined default", ifName, got)
		}
	}
}

func TestTunnelRoutingInstanceTargetValidVRFAccepts12520(t *testing.T) {
	for _, level := range []string{"interface", "unit"} {
		t.Run(level, func(t *testing.T) {
			cfg, err := CompileConfig(tunnelRITargetTree12520(t, "blue", level, "virtual-router"))
			if err != nil {
				t.Fatalf("strict compile rejected supported VRF target: %v", err)
			}
			if got := tunnelConfigAtLevel12520(cfg, level).RoutingInstance; got != "blue" {
				t.Fatalf("compiled tunnel target = %q, want blue", got)
			}
		})
	}
}

// skipWarned12520 reports whether a tolerant warning names skipped as the
// quarantined GRE tunnel dropped in favour of owner.
func skipWarned12520(cfg *Config, skipped, owner string) bool {
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "is skipped on tolerant load") &&
			strings.Contains(warning, "#12520") && strings.Contains(warning, "#10654") &&
			strings.Contains(warning, fmt.Sprintf("tunnel %q", skipped)) &&
			strings.Contains(warning, fmt.Sprintf("where tunnel %q", owner)) {
			return true
		}
	}
	return false
}

// TestTolerantQuarantineSkipsCollidingGRETunnel12520 pins the post-clear
// #10654 identity check: clearing a quarantined target must never let the
// quarantined tunnel take a GRE outer identity from a tunnel that owns it.
func TestTolerantQuarantineSkipsCollidingGRETunnel12520(t *testing.T) {
	pair := func(ifName, target string) []string {
		lines := []string{
			"set interfaces " + ifName + " tunnel source 192.0.2.1",
			"set interfaces " + ifName + " tunnel destination 192.0.2.2",
			"set interfaces " + ifName + " unit 0 family inet address 10.0." + ifName[len(ifName)-1:] + ".1/30",
		}
		if target != "" {
			lines = append(lines, "set interfaces "+ifName+" tunnel routing-instance destination "+target)
		}
		return lines
	}
	cases := []struct {
		name    string
		lines   []string
		emitted []string
		skipped [][2]string // {skipped endpoint, owning endpoint}
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name:    "undefined target sorts before the valid tunnel",
			lines:   append(pair("gr-0/0/0", "missing"), pair("gr-0/0/1", "")...),
			emitted: []string{"gr-0/0/1.0"},
			skipped: [][2]string{{"gr-0/0/0.0", "gr-0/0/1.0"}},
		},
		{
			name:    "management target sorts before the valid tunnel",
			lines:   append(pair("gr-0/0/0", "mgmt"), pair("gr-0/0/1", "")...),
			emitted: []string{"gr-0/0/1.0"},
			skipped: [][2]string{{"gr-0/0/0.0", "gr-0/0/1.0"}},
		},
		{
			name: "forwarding target sorts before the valid tunnel",
			lines: append(append(pair("gr-0/0/0", "fwd"), pair("gr-0/0/1", "")...),
				"set routing-instances fwd instance-type forwarding"),
			emitted: []string{"gr-0/0/1.0"},
			skipped: [][2]string{{"gr-0/0/0.0", "gr-0/0/1.0"}},
		},
		{
			name:    "undefined target sorts after the valid tunnel",
			lines:   append(pair("gr-0/0/0", ""), pair("gr-0/0/1", "missing")...),
			emitted: []string{"gr-0/0/0.0"},
			skipped: [][2]string{{"gr-0/0/1.0", "gr-0/0/0.0"}},
		},
		{
			name:    "two quarantined tunnels keep the first-sorting one",
			lines:   append(pair("gr-0/0/0", "missing"), pair("gr-0/0/1", "mgmt")...),
			emitted: []string{"gr-0/0/0.0"},
			skipped: [][2]string{{"gr-0/0/1.0", "gr-0/0/0.0"}},
		},
		{
			name: "unit override is skipped without inheriting the interface tunnel",
			lines: append([]string{
				"set interfaces gr-0/0/0 tunnel source 192.0.2.3",
				"set interfaces gr-0/0/0 tunnel destination 192.0.2.4",
				"set interfaces gr-0/0/0 unit 0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 unit 0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination missing",
				"set interfaces gr-0/0/0 unit 0 family inet address 10.0.9.1/30",
				"set interfaces gr-0/0/0 unit 1 family inet address 10.0.8.1/30",
			}, pair("gr-0/0/1", "")...),
			emitted: []string{"gr-0/0/0.1", "gr-0/0/1.0"},
			skipped: [][2]string{{"gr-0/0/0.0", "gr-0/0/1.0"}},
			check: func(t *testing.T, cfg *Config) {
				ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
				if _, kept := ifc.Units[0]; kept {
					t.Errorf("skipped unit gr-0/0/0.0 still compiled: %+v", ifc.Units[0])
				}
				if ifc.Tunnel == nil || ifc.Tunnel.Source != "192.0.2.3" {
					t.Errorf("interface-level tunnel = %+v, want the untouched 192.0.2.3 tunnel", ifc.Tunnel)
				}
			},
		},
		{
			name: "keyed quarantined tunnel does not collide with an unkeyed one",
			lines: append(append(pair("gr-0/0/0", "missing"), pair("gr-0/0/1", "")...),
				"set interfaces gr-0/0/0 tunnel key 5"),
			emitted: []string{"gr-0/0/0.0", "gr-0/0/1.0"},
		},
		{
			name: "valid duplicates stay with the #10654 gate",
			lines: append(append(pair("gr-0/0/0", ""), pair("gr-0/0/1", "")...),
				"set interfaces gr-0/0/2 tunnel source 192.0.2.3",
				"set interfaces gr-0/0/2 tunnel destination 192.0.2.4",
				"set interfaces gr-0/0/2 tunnel routing-instance destination missing",
				"set interfaces gr-0/0/2 unit 0 family inet address 10.0.2.1/30"),
			emitted: []string{"gr-0/0/0.0", "gr-0/0/1.0", "gr-0/0/2.0"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(treeFromSet(t, tc.lines))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			var emitted []string
			for _, ep := range EmitTunnelEndpointNames(cfg) {
				emitted = append(emitted, ep.Name)
				if ep.Tunnel.RoutingInstance != "" {
					t.Errorf("%s target = %q, want the default routing domain", ep.Name, ep.Tunnel.RoutingInstance)
				}
			}
			if strings.Join(emitted, ",") != strings.Join(tc.emitted, ",") {
				t.Errorf("emitted endpoints = %v, want %v", emitted, tc.emitted)
			}
			skipWarnings := 0
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "is skipped on tolerant load") && strings.Contains(warning, "#12520") {
					skipWarnings++
				}
			}
			if skipWarnings != len(tc.skipped) {
				t.Errorf("got %d skip warnings, want %d: %v", skipWarnings, len(tc.skipped), cfg.Warnings)
			}
			for _, skip := range tc.skipped {
				if !skipWarned12520(cfg, skip[0], skip[1]) {
					t.Errorf("no warning skips %s for owner %s: %v", skip[0], skip[1], cfg.Warnings)
				}
				ifName := strings.TrimSuffix(skip[0], ".0")
				if ifc := cfg.Interfaces.Interfaces[ifName]; tc.check == nil && ifc.Tunnel != nil {
					t.Errorf("skipped %s still carries its tunnel: %+v", ifName, ifc.Tunnel)
				}
			}
			if tc.check != nil {
				tc.check(t, cfg)
			}
		})
	}
}

// TestTunnelRITargetPreservesEstablishedTailGatePriority12520 pins the strict
// first error for the tail gates #12520 runs after (#9909 is pinned by the
// forwarding case of TestWireguardTunnelRoutingInstanceBound9909): each config
// also carries an undefined target, so moving the #12520 call ahead of any of
// these gates turns that case's first error into #12520.
func TestTunnelRITargetPreservesEstablishedTailGatePriority12520(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "mixed outer family before target",
			cmds: []string{
				"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 tunnel destination 2001:db8::1",
				"set interfaces gr-0/0/0 tunnel routing-instance destination missing",
			},
			want: "#5162",
		},
		{
			name: "unimplemented IPIP before target",
			cmds: []string{
				"set interfaces ip-0/0/0 tunnel source 192.0.2.1",
				"set interfaces ip-0/0/0 tunnel destination 192.0.2.2",
				"set interfaces ip-0/0/0 tunnel routing-instance destination missing",
			},
			want: "#4785",
		},
		{
			name: "duplicate GRE outer before separate target",
			cmds: []string{
				"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/1 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/1 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/2 tunnel source 192.0.2.3",
				"set interfaces gr-0/0/2 tunnel destination 192.0.2.4",
				"set interfaces gr-0/0/2 tunnel routing-instance destination missing",
			},
			want: "#10654",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(treeFromSet(t, tc.cmds))
			if err == nil {
				t.Fatal("strict compile accepted a config with an established tail-gate error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("first error = %v, want %s priority", err, tc.want)
			}
			if strings.Contains(err.Error(), "#12520") {
				t.Errorf("new target gate stole first-error priority from %s: %v",
					tc.want, err)
			}
		})
	}
}
