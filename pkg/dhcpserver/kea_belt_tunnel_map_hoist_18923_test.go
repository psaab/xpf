package dhcpserver

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18923: usableKeaDevices15206 resolves every declared interface and unit
// ref, both spellings, so resolving each through ResolveKernelIfName rebuilt
// Config.TunnelNameMap — a walk of every interface and every unit — per ref,
// making the belt O((I+U)^2) per DHCP family per standalone commit. The map
// is a pure function of the active config, which the belt never mutates, so
// one build per filter call is sound and the twin resolver
// (Config.ResolveKernelIfNameWith, exported for this belt) consumes it.
//
// Two cells pin the two halves of that contract:
//
//   - TestKeaBeltUsableSetMatchesPerRefResolution18923: the usable set is
//     BYTE-IDENTICAL to the pre-#18923 per-ref expression over the corpus —
//     the hoist must not change a single resolved name (error and empty
//     cases included).
//   - TestKeaBeltBuildsTunnelNameMapOnce18923: the belt routes its map
//     builds through keaTunnelNameMapFn EXACTLY ONCE per filter call, at
//     every input size. Counted, not timed, for the reason #8862 records:
//     a wall-clock threshold is either flaky or too loose to fail.
//
// FAIL-ON-REVERT: revert the belt to per-ref ResolveKernelIfName and the
// count cell reports 0 builds through the seam (the rebuilds happen inside
// ResolveKernelIfName, invisible to it) while the usable set stays identical
// — which is exactly the defect: same output, quadratic cost.
func TestKeaBeltBuildsTunnelNameMapOnce18923(t *testing.T) {
	orig := keaTunnelNameMapFn
	defer func() { keaTunnelNameMapFn = orig }()

	for _, z := range []int{1, 2, 8, 32, 128} {
		active := scalingActiveCfg18923(z)
		// Non-vacuity: the corpus really declares z physical interfaces and
		// the belt resolves all of them, so a size-dependent build count has
		// room to appear. Computed before the counter is installed.
		if got := len(usableKeaDevices15206(active)); got < z {
			t.Fatalf("z=%d: usable set has %d entries, want at least one per interface", z, got)
		}
		n := 0
		keaTunnelNameMapFn = func(c *config.Config) map[string]string {
			n++
			return orig(c)
		}
		if filtered, _ := FilterKeaInterfaces15206(phantomV4Config15206(), active, "4", func(string, ...any) {}); filtered == nil {
			t.Fatalf("z=%d: belt returned a nil config", z)
		}
		if n != 1 {
			t.Errorf("z=%d: belt built the tunnel-name map %d times through the seam, want exactly 1 "+
				"(per-ref ResolveKernelIfName rebuilds it once per interface and unit and the belt is "+
				"quadratic again, #18923)", z, n)
		}
	}
}

// TestKeaBeltUsableSetMatchesPerRefResolution18923 pins behaviour identity:
// the hoisted usable set equals the set the pre-#18923 per-ref expression
// produced, over the existing belt corpus (activeCfg15206: physical, RETH
// parent and member, VLAN unit) and a hostile corpus adding nil interface
// and unit entries, per-unit and interface-level tunnels, and an undeclared
// reth unit.
func TestKeaBeltUsableSetMatchesPerRefResolution18923(t *testing.T) {
	for name, active := range map[string]*config.Config{
		"existing-corpus": activeCfg15206(),
		"hostile-corpus":  hostileActiveCfg18923(),
		"empty-config":    {},
	} {
		got := usableKeaDevices15206(active)
		want := perRefUsable18923(active)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: hoisted usable set %v != per-ref usable set %v", name, got, want)
		}
	}
}

// perRefUsable18923 is the pre-#18923 belt body, kept verbatim: both
// spellings of every declared interface and unit, each resolved through
// ResolveKernelIfName (which builds the tunnel-name map per call).
func perRefUsable18923(active *config.Config) map[string]bool {
	usable := make(map[string]bool)
	for name, ifc := range active.Interfaces.Interfaces {
		usable[active.ResolveKernelIfName(name)] = true
		linux := config.LinuxIfName(name)
		if linux != name {
			usable[active.ResolveKernelIfName(linux)] = true
		}
		if ifc == nil {
			continue
		}
		for unitNum, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			suffix := "." + strconv.Itoa(unitNum)
			usable[active.ResolveKernelIfName(name+suffix)] = true
			if linux != name {
				usable[active.ResolveKernelIfName(linux+suffix)] = true
			}
		}
	}
	return usable
}

// scalingActiveCfg18923 declares z four-unit physical interfaces plus one
// two-unit GRE tunnel interface, so both the ref count and the tunnel map
// grow with z.
func scalingActiveCfg18923(z int) *config.Config {
	ifaces := make(map[string]*config.InterfaceConfig, z+1)
	for i := range z {
		name := fmt.Sprintf("ge-0/0/%d", i)
		units := make(map[int]*config.InterfaceUnit, 4)
		for u := range 4 {
			units[u] = &config.InterfaceUnit{Number: u}
		}
		ifaces[name] = &config.InterfaceConfig{Name: name, Units: units}
	}
	ifaces["gr-0/0/0"] = &config.InterfaceConfig{Name: "gr-0/0/0", Units: map[int]*config.InterfaceUnit{
		0: {Number: 0, Tunnel: &config.TunnelConfig{Name: "gr-0-0-0", Source: "10.0.0.1"}},
		1: {Number: 1, Tunnel: &config.TunnelConfig{Name: "gr-0-0-0u1", Source: "10.0.0.3"}},
	}}
	return &config.Config{Interfaces: config.InterfacesConfig{Interfaces: ifaces}}
}

func hostileActiveCfg18923() *config.Config {
	return &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			80: {Number: 80, VlanID: 180},
			9:  nil,
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
		"reth1": {Name: "reth1", RedundancyGroup: 1, VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			80: {Number: 80, VlanID: 180},
		}},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: &config.TunnelConfig{Source: "10.0.1.1", Destination: "10.0.1.2"}, Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
			2: {Number: 2},
		}},
		"ge-0/0/7": nil,
	}}}
}
