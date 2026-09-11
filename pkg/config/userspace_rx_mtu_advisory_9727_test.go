package config

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rxMTUCfg9727 builds the minimum Config the advisory reads: zones naming
// interface refs, and interfaces carrying interface-level and unit-level MTUs.
func rxMTUCfg9727(zones map[string][]string, ifaces map[string]*InterfaceConfig) *Config {
	cfg := &Config{}
	cfg.Security.Zones = map[string]*ZoneConfig{}
	for name, refs := range zones {
		cfg.Security.Zones[name] = &ZoneConfig{Name: name, Interfaces: refs}
	}
	cfg.Interfaces.Interfaces = ifaces
	return cfg
}

func iface9727(name string, mtu int, units map[int]int) *InterfaceConfig {
	ifc := &InterfaceConfig{Name: name, MTU: mtu, Units: map[int]*InterfaceUnit{}}
	for n, unitMTU := range units {
		ifc.Units[n] = &InterfaceUnit{MTU: unitMTU}
	}
	return ifc
}

func rxMTUWarnings9727(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#9727") {
			out = append(out, w)
		}
	}
	return out
}

// TestJumboMTUOnABoundInterfaceWarnsNamingTheBudget9727 is the acceptance cell:
// MTU 9000 on a zoned data interface warns and names the budget; MTU 1500 does not.
func TestJumboMTUOnABoundInterfaceWarnsNamingTheBudget9727(t *testing.T) {
	cfg := rxMTUCfg9727(map[string][]string{"trust": {"ge-0/0/1.0"}},
		map[string]*InterfaceConfig{"ge-0/0/1": iface9727("ge-0/0/1", 9000, map[int]int{0: 0})})
	appendUserspaceRxMTUAdvisoryLocked(cfg, compileOpts{})
	got := rxMTUWarnings9727(cfg)
	if len(got) != 1 {
		t.Fatalf("expected one advisory for the jumbo bound interface, got %d: %v", len(got), cfg.Warnings)
	}
	for _, want := range []string{"ge-0/0/1", "9000", strconv.Itoa(userspaceRxMTUBudget), "kernel_rx_dropped"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("advisory must name %q: %s", want, got[0])
		}
	}

	quiet := rxMTUCfg9727(map[string][]string{"trust": {"ge-0/0/1.0"}},
		map[string]*InterfaceConfig{"ge-0/0/1": iface9727("ge-0/0/1", 1500, map[int]int{0: 0})})
	appendUserspaceRxMTUAdvisoryLocked(quiet, compileOpts{})
	if w := rxMTUWarnings9727(quiet); len(w) != 0 {
		t.Fatalf("MTU 1500 must not warn: %v", w)
	}
}

func TestRxMTUAdvisoryBoundaryAndUnitOverride9727(t *testing.T) {
	for _, tc := range []struct {
		name            string
		ifcMTU, unitMTU int
		warn            bool
	}{
		{"exactly the budget fits", userspaceRxMTUBudget, 0, false},
		{"one byte over warns", userspaceRxMTUBudget + 1, 0, true},
		{"unit MTU overrides a jumbo interface MTU", 9000, 1500, false},
		{"a jumbo unit MTU warns under a small interface MTU", 1500, 9000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := rxMTUCfg9727(map[string][]string{"trust": {"ge-0/0/1.0"}},
				map[string]*InterfaceConfig{"ge-0/0/1": iface9727("ge-0/0/1", tc.ifcMTU, map[int]int{0: tc.unitMTU})})
			appendUserspaceRxMTUAdvisoryLocked(cfg, compileOpts{})
			if got := len(rxMTUWarnings9727(cfg)) == 1; got != tc.warn {
				t.Fatalf("warned=%v, want %v: %v", got, tc.warn, cfg.Warnings)
			}
		})
	}
}

// TestRxMTUAdvisoryStaysSilentForInterfacesTheDataplaneDoesNotBind9727 is the
// control that keeps the warning aimed: interfaces the userspace dataplane never
// binds must not be told their jumbo MTU is a problem. Each exclusion gets its
// own case, so dropping one of them is visible on its own.
func TestRxMTUAdvisoryStaysSilentForInterfacesTheDataplaneDoesNotBind9727(t *testing.T) {
	tunnel := iface9727("gr-0/0/0", 9000, map[int]int{0: 0})
	tunnel.Tunnel = &TunnelConfig{}
	fabMember := iface9727("ge-0/0/5", 9000, map[int]int{0: 0})
	fabMember.LocalFabricMember = "ge-0/0/5"
	for _, tc := range []struct {
		name  string
		zone  string
		ref   string
		iface *InterfaceConfig
	}{
		{"fxp", "trust", "fxp0.0", iface9727("fxp0", 9000, map[int]int{0: 0})},
		{"em", "trust", "em0.0", iface9727("em0", 9000, map[int]int{0: 0})},
		{"lo0", "trust", "lo0.0", iface9727("lo0", 9000, map[int]int{0: 0})},
		{"tunnel", "trust", "gr-0/0/0.0", tunnel},
		{"local fabric member", "trust", "ge-0/0/5.0", fabMember},
		{"mgmt zone", "mgmt", "ge-0/0/6.0", iface9727("ge-0/0/6", 9000, map[int]int{0: 0})},
		{"control zone", "control", "ge-0/0/6.0", iface9727("ge-0/0/6", 9000, map[int]int{0: 0})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, _, _ := strings.Cut(tc.ref, ".")
			cfg := rxMTUCfg9727(map[string][]string{tc.zone: {tc.ref}}, map[string]*InterfaceConfig{base: tc.iface})
			appendUserspaceRxMTUAdvisoryLocked(cfg, compileOpts{})
			if w := rxMTUWarnings9727(cfg); len(w) != 0 {
				t.Fatalf("%s is not bound by the userspace dataplane and must not warn: %v", tc.name, w)
			}
		})
	}
	unzoned := rxMTUCfg9727(map[string][]string{}, map[string]*InterfaceConfig{"ge-0/0/7": iface9727("ge-0/0/7", 9000, map[int]int{0: 0})})
	appendUserspaceRxMTUAdvisoryLocked(unzoned, compileOpts{})
	if w := rxMTUWarnings9727(unzoned); len(w) != 0 {
		t.Fatalf("an interface in no zone is not bound and must not warn: %v", w)
	}
}

func TestRxMTUAdvisoryIsSuppressedOnTheTolerantPaths9727(t *testing.T) {
	cfg := rxMTUCfg9727(map[string][]string{"trust": {"ge-0/0/1.0"}},
		map[string]*InterfaceConfig{"ge-0/0/1": iface9727("ge-0/0/1", 9000, map[int]int{0: 0})})
	appendUserspaceRxMTUAdvisoryLocked(cfg, compileOpts{suppressContestedTrunkZoneAdvisory: true})
	if w := rxMTUWarnings9727(cfg); len(w) != 0 {
		t.Fatalf("the tolerant boot/peer-sync paths must not repeat the advisory: %v", w)
	}
}

// TestUserspaceUMEMConstantsMatchTheHelper9727 binds the Go budget to the Rust
// constants it describes, so a UMEM resize cannot leave the advisory stale.
func TestUserspaceUMEMConstantsMatchTheHelper9727(t *testing.T) {
	src, err := os.ReadFile("../../userspace-dp/src/afxdp/mod.rs")
	if err != nil {
		t.Fatalf("read helper source: %v", err)
	}
	for name, want := range map[string]int{"UMEM_FRAME_SIZE": userspaceUMEMFrameSize, "UMEM_HEADROOM": userspaceUMEMHeadroom} {
		m := regexp.MustCompile(`(?m)^const ` + name + `: u32 = (\d+);`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("no %s declaration found in userspace-dp/src/afxdp/mod.rs", name)
		}
		if got, _ := strconv.Atoi(string(m[1])); got != want {
			t.Errorf("%s is %d in the helper but %d in the Go advisory", name, got, want)
		}
	}
}

// TestJumboMTUAdvisoryReachesTheCompiledConfig9727 binds the wiring: the unit
// cells above call the advisory directly, so this compiles real set commands
// and requires the warning on the result.
func TestJumboMTUAdvisoryReachesTheCompiledConfig9727(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set interfaces ge-0/0/1 mtu 9000",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	})
	if w := rxMTUWarnings9727(cfg); len(w) != 1 || !strings.Contains(w[0], "ge-0/0/1") {
		t.Fatalf("the compiled config must carry the jumbo MTU advisory for ge-0/0/1: %v", cfg.Warnings)
	}
}
