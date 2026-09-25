package daemon

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestLogicalUnitDeviceKeyForRef9821 pins the declared-first producer-key
// derivation (#9821 #5): a ref that NAMES a declared interface yields that
// interface's device even when dotted; unit refs resolve against the split
// base's stanza; malformed suffixes keep the Literal spelling.
func TestLogicalUnitDeviceKeyForRef9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			10: {Number: 10, VlanID: 100},
		}},
		"ge-0/0/6": {Name: "ge-0/0/6", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
			3: {Number: 3},
		}},
		"p.01": {Name: "p.01", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	cases := []struct {
		name string
		ref  string
		want string
	}{
		{"declared dotted bare is its own device", "ge-0/0/5.0", "ge-0-0-5.0"},
		{"declared dotted unit vlan wins", "ge-0/0/5.0.10", "ge-0-0-5.0.100"},
		{"declared dotted unit zero collapses", "ge-0/0/5.0.0", "ge-0-0-5.0"},
		{"padded declared name never normalized", "p.01", "p.01"},
		{"ordinary unit ref", "ge-0/0/6.3", "ge-0-0-6.3"},
		{"ordinary unit zero collapses", "ge-0/0/6.0", "ge-0-0-6"},
		{"padded undeclared ref canonicalizes", "ge-0/0/6.03", "ge-0-0-6.3"},
		{"malformed suffix keeps literal spelling", "ge-0/0/6.xx", "ge-0-0-6.xx"},
		{"unknown base keeps producer spelling", "ge-0/0/9.4", "ge-0-0-9.4"},
		{"unknown bare keeps base spelling", "ge-0/0/9", "ge-0-0-9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := logicalUnitDeviceKeyForRef(cfg, tc.ref); got != tc.want {
				t.Errorf("logicalUnitDeviceKeyForRef(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
	if got := logicalUnitDeviceKeyForRef(nil, "ge-0/0/6.3"); got != "ge-0-0-6.3" {
		t.Errorf("nil-cfg logicalUnitDeviceKeyForRef = %q, want ge-0-0-6.3 (legacy)", got)
	}
}

// TestRIMemberNoNewBind8994_9821 is the #16 killer pin (Codex R2F1): the
// restructured plural bind set for the tunnel-collision corpus member
// `gr-0/0/0` is EXACTLY today's set — structural resolution must not invent
// a bind for the generated key that textually matches the tunnel key.
func TestRIMemberNoNewBind8994_9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"gr-0/0/0":   {Name: "gr-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"gr-0/0/0.0": {Name: "gr-0/0/0.0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	tunMap := map[string]string{"gr-0/0/0.0": "gr-0-0-0"}
	got := riMemberLinuxNames(cfg, tunMap, "gr-0/0/0")
	if !reflect.DeepEqual(got, []string{"gr-0-0-0"}) {
		t.Errorf("riMemberLinuxNames(gr-0/0/0) = %q, want [gr-0-0-0] exactly — no new bind", got)
	}
}

// TestRIMemberDeclaredDottedBindsDeclared9821 pins the issue-probe fix: a
// declared dotted member binds its OWN device, and the bind agrees with the
// shared resolver (#8994 doctrine, both consumers now declared-first).
func TestRIMemberDeclaredDottedBindsDeclared9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	got := riMemberLinuxNames(cfg, nil, "ge-0/0/5.0")
	if !reflect.DeepEqual(got, []string{"ge-0-0-5.0"}) {
		t.Fatalf("riMemberLinuxNames(ge-0/0/5.0) = %q, want [ge-0-0-5.0]", got)
	}
	if resolver := cfg.ResolveKernelIfName("ge-0/0/5.0"); resolver != got[0] {
		t.Errorf("bind %q disagrees with resolver %q — both must name the declared device", got[0], resolver)
	}
}

// TestRIMemberDeclaredCollisionBindsDeclared9821 pins §5.6 exception (a): a
// declared-bare member colliding with another interface's tunnel key binds
// the DECLARED device (tunMap skipped), not the tunnel.
func TestRIMemberDeclaredCollisionBindsDeclared9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"gr-0/0/0":   {Name: "gr-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"gr-0/0/0.0": {Name: "gr-0/0/0.0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	tunMap := map[string]string{"gr-0/0/0.0": "gr-0-0-0"}
	if got := riMemberLinuxName(cfg, tunMap, "gr-0/0/0.0"); got != "gr-0-0-0.0" {
		t.Errorf("singular riMemberLinuxName(gr-0/0/0.0) = %q, want declared gr-0-0-0.0 (tunMap skipped)", got)
	}
	if got := riMemberLinuxNames(cfg, tunMap, "gr-0/0/0.0"); !reflect.DeepEqual(got, []string{"gr-0-0-0.0"}) {
		t.Errorf("plural riMemberLinuxNames(gr-0/0/0.0) = %q, want [gr-0-0-0.0]", got)
	}
}

// TestRIMemberBindUndottedControl9821 pins the untouched shapes: bare members
// with vlan/tagged units and per-unit tunnels resolve exactly as before.
func TestRIMemberBindUndottedControl9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			10: {Number: 10, VlanID: 100},
		}},
		"gr-0/0/1": {Name: "gr-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
			1: {Number: 1},
		}},
	}}}
	tunMap := map[string]string{"gr-0/0/1.1": "gr-0-0-1u1"}
	if got := riMemberLinuxNames(cfg, nil, "ge-0/0/0"); !reflect.DeepEqual(got, []string{"ge-0-0-0", "ge-0-0-0.100"}) {
		t.Errorf("bare ge-0/0/0 = %q, want base + vlan child", got)
	}
	if got := riMemberLinuxNames(cfg, tunMap, "gr-0/0/1"); !reflect.DeepEqual(got, []string{"gr-0-0-1", "gr-0-0-1u1"}) {
		t.Errorf("bare gr-0/0/1 = %q, want base + per-unit tunnel", got)
	}
	if got := riMemberLinuxNames(cfg, tunMap, "gr-0/0/1.1"); !reflect.DeepEqual(got, []string{"gr-0-0-1u1"}) {
		t.Errorf("unit gr-0/0/1.1 = %q, want [gr-0-0-1u1] via tunMap", got)
	}
}

// TestResolveMemberDeclaredBase9821 pins the D16 4-level alias order:
// exact split-Base → linux-match split-Base → linux-match RAW →
// linux-match Literal. Raw before canon; first-sorted on lenient pairs.
func TestResolveMemberDeclaredBase9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/1":    {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1.01": {Name: "ge-0/0/1.01", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1.1":  {Name: "ge-0/0/1.1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"p.0":         {Name: "p.0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	cases := []struct {
		name      string
		member    string
		wantBase  string
		wantUnit  int
		wantWhole bool
		wantOK    bool
	}{
		{"exact bare", "p.0", "p.0", 0, true, true},
		{"exact unit", "ge-0/0/1.0", "ge-0/0/1", 0, false, true},
		{"L2 dash member for slash stanza", "ge-0-0-1.0", "ge-0/0/1", 0, false, true},
		{"L2 dash bare", "ge-0-0-1", "ge-0/0/1", 0, true, true},
		{"L2 outranks L3 (unit reading wins)", "ge-0-0-1.01", "ge-0/0/1", 1, false, true},
		{"L2 malformed unit matches nothing", "ge-0-0-1.01x", "ge-0/0/1", -1, false, true},
		{"unresolvable bare", "unknown", "", -1, false, false},
		{"unresolvable unit", "unknown.5", "", -1, false, false},
		{"malformed unit on declared base", "ge-0/0/1.xx", "ge-0/0/1", -1, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveMemberDeclaredBase(cfg, tc.member)
			if got.ok != tc.wantOK || got.base != tc.wantBase || got.unit != tc.wantUnit {
				t.Errorf("resolveMemberDeclaredBase(%q) = %+v, want base=%q unit=%d ok=%v",
					tc.member, got, tc.wantBase, tc.wantUnit, tc.wantOK)
			} else if got.ok && got.hasUnit == tc.wantWhole {
				t.Errorf("resolveMemberDeclaredBase(%q) = %+v, want whole=%v",
					tc.member, got, tc.wantWhole)
			}
		})
	}
	// L3 positive needs a cfg where L2 cannot fire: only the dotted
	// declaration exists, so the split base matches nothing but the whole
	// RAW member does (verbatim alias-bare).
	cfg3 := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/1.01": {Name: "ge-0/0/1.01", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	got3 := resolveMemberDeclaredBase(cfg3, "ge-0-0-1.01")
	if !got3.ok || got3.hasUnit || got3.base != "ge-0/0/1.01" {
		t.Errorf("L3 verbatim alias-bare = %+v, want whole base ge-0/0/1.01", got3)
	}
	// L4 positive needs its own cfg: dash padded member for an UNPADDED
	// slash declaration (RAW misses, Literal hits).
	cfg4 := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/2.1": {Name: "ge-0/0/2.1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	got := resolveMemberDeclaredBase(cfg4, "ge-0-0-2.01")
	if !got.ok || got.hasUnit || got.base != "ge-0/0/2.1" {
		t.Errorf("L4 canon alias-bare = %+v, want whole base ge-0/0/2.1", got)
	}
	// Lenient slash/dash pair resolves deterministically first-sorted
	// (strict rejects the pair; lenient must not flap on map order).
	cfgPair := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	got = resolveMemberDeclaredBase(cfgPair, "ge-0/0-1.0")
	if !got.ok || got.base != "ge-0-0-1" || got.unit != 0 {
		t.Errorf("lenient pair = %+v, want first-sorted base ge-0-0-1 unit 0", got)
	}
	if got := resolveMemberDeclaredBase(nil, "ge-0/0/1.0"); got.ok {
		t.Errorf("nil-cfg resolve = %+v, want !ok", got)
	}
}

// TestDHCPLeaseKeysDeclaredDotted9821 pins #6 through the shared helper:
// whole/unit readings on declared (incl. dotted and dash-alias) members,
// with legacy fallbacks for unresolvable shapes.
func TestDHCPLeaseKeysDeclaredDotted9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			10: {Number: 10, VlanID: 100},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	sorted := func(keys []string) []string {
		out := append([]string(nil), keys...)
		sort.Strings(out)
		return out
	}
	if got := sorted(dhcpLeaseKeysForMember(cfg, "ge-0/0/5.0")); !reflect.DeepEqual(got, []string{"ge-0-0-5.0", "ge-0-0-5.0.100"}) {
		t.Errorf("whole dotted member keys = %q, want base + vlan child", got)
	}
	if got := dhcpLeaseKeysForMember(cfg, "ge-0/0/5.0.10"); !reflect.DeepEqual(got, []string{"ge-0-0-5.0.100"}) {
		t.Errorf("dotted unit member keys = %q, want [ge-0-0-5.0.100]", got)
	}
	if got := dhcpLeaseKeysForMember(cfg, "ge-0-0-1.0"); !reflect.DeepEqual(got, []string{"ge-0-0-1"}) {
		t.Errorf("dash unit member keys = %q, want declared device", got)
	}
	if got := dhcpLeaseKeysForMember(cfg, "ge-0/0/9"); !reflect.DeepEqual(got, []string{"ge-0-0-9"}) {
		t.Errorf("undeclared whole keys = %q, want legacy device key", got)
	}
	if got := dhcpLeaseKeysForMember(cfg, "ge-0/0/9.4"); !reflect.DeepEqual(got, []string{"ge-0-0-9"}) {
		t.Errorf("undeclared unit keys = %q, want legacy bare-base fallback", got)
	}
	if got := dhcpLeaseKeysForMember(cfg, ""); got != nil {
		t.Errorf("empty member keys = %q, want nil", got)
	}
}

// v6poolCfg9821 builds a cfg with one v6 subnet per listed (iface, unit)
// plus a global and a VRF static route toward the given nexthop, so pool
// membership is observable as resolved[pool][nexthop] ("" = absent).
func v6poolCfg9821(t *testing.T, ifaces map[string]map[int]string, member, nh string) *config.Config {
	t.Helper()
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{}}}
	for name, units := range ifaces {
		ifc := &config.InterfaceConfig{Name: name, Units: map[int]*config.InterfaceUnit{}}
		for num, cidr := range units {
			ifc.Units[num] = &config.InterfaceUnit{Number: num, Addresses: []string{cidr}}
		}
		cfg.Interfaces.Interfaces[name] = ifc
	}
	mkroute := func() []*config.StaticRoute {
		return []*config.StaticRoute{{Destination: "2001:db8:ffff::/48",
			NextHops: []config.NextHopEntry{{Address: nh}}}}
	}
	cfg.RoutingOptions.Inet6StaticRoutes = mkroute()
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "RA", InstanceType: "vrf", Interfaces: []string{member},
		Inet6StaticRoutes: mkroute(),
	}}
	return cfg
}

// TestPoolBothDeclaredStaysDefault9821 pins the R3F2 shape: declared `p.0`
// + declared `p.0.2` with member `p.0` — `p.0.2`'s prefixes are default-only
// (another interface's base device is never its sub-unit).
func TestPoolBothDeclaredStaysDefault9821(t *testing.T) {
	cfg := v6poolCfg9821(t, map[string]map[int]string{
		"p.0":   {0: "2001:db8:a::1/64"},
		"p.0.2": {0: "2001:db8:b::1/64"},
	}, "p.0", "2001:db8:b::9")
	// Second nexthop pair observing the member's OWN subnet (member live).
	mkroute := func(nh string) []*config.StaticRoute {
		return []*config.StaticRoute{{Destination: "2001:db8:ffff::/48",
			NextHops: []config.NextHopEntry{{Address: nh}}}}
	}
	cfg.RoutingOptions.Inet6StaticRoutes = append(cfg.RoutingOptions.Inet6StaticRoutes, mkroute("2001:db8:a::9")...)
	cfg.RoutingInstances[0].Inet6StaticRoutes = append(cfg.RoutingInstances[0].Inet6StaticRoutes, mkroute("2001:db8:a::9")...)
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	if got[""]["2001:db8:b::9"] != "p.0.2" {
		t.Errorf("default pool: p.0.2 nexthop = %q, want p.0.2 (default-only)", got[""]["2001:db8:b::9"])
	}
	if got["vrf-RA"]["2001:db8:b::9"] != "" {
		t.Errorf("VRF pool: p.0.2 nexthop = %q, want absent (member p.0 claims no ownership)", got["vrf-RA"]["2001:db8:b::9"])
	}
	// The member itself is LIVE (legacy: fully dead — collected nothing):
	// its own subnet resolves VRF-only.
	if got["vrf-RA"]["2001:db8:a::9"] != "p.0" {
		t.Errorf("VRF pool: p.0 nexthop = %q, want p.0 (member live)", got["vrf-RA"]["2001:db8:a::9"])
	}
	if got[""]["2001:db8:a::9"] != "" {
		t.Errorf("default pool: p.0 nexthop = %q, want absent (claimed VRF-only)", got[""]["2001:db8:a::9"])
	}
}

// TestPoolUndeclaredClaimStaysDefault9821 pins the GLM-R2F2 shape: producer
// key `ge-0-0-5.0.100` (owner `ge-0/0/5.0`) under an undeclared `ge-0/0/5`
// claim — default-only, never attributed by textual nesting.
func TestPoolUndeclaredClaimStaysDefault9821(t *testing.T) {
	cfg := v6poolCfg9821(t, map[string]map[int]string{
		"ge-0/0/5.0": {100: "2001:db8:c::1/64"},
	}, "ge-0/0/5", "2001:db8:c::9")
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	if got[""]["2001:db8:c::9"] != "ge-0-0-5.0.100" {
		t.Errorf("default pool nexthop = %q, want ge-0-0-5.0.100", got[""]["2001:db8:c::9"])
	}
	if got["vrf-RA"]["2001:db8:c::9"] != "" {
		t.Errorf("VRF pool nexthop = %q, want absent", got["vrf-RA"]["2001:db8:c::9"])
	}
}

// TestPoolDottedWholeMemberVRFOnly9821 pins the single-declared fix: a whole
// dotted member moves its units' prefixes (incl. vlan children) VRF-only.
// Legacy contributed NOTHING here (first-cut base undeclared → miss, and the
// dotted spelling failed the whole-device test) — the member was dead.
func TestPoolDottedWholeMemberVRFOnly9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0, Addresses: []string{"2001:db8:d::1/64"}},
			10: {Number: 10, VlanID: 100, Addresses: []string{"2001:db8:e::1/64"}},
		}},
	}}}
	mkroute := func(nh string) []*config.StaticRoute {
		return []*config.StaticRoute{{Destination: "2001:db8:ffff::/48",
			NextHops: []config.NextHopEntry{{Address: nh}}}}
	}
	cfg.RoutingOptions.Inet6StaticRoutes = append(mkroute("2001:db8:d::9"), mkroute("2001:db8:e::9")...)
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "RA", InstanceType: "vrf", Interfaces: []string{"ge-0/0/5.0"},
		Inet6StaticRoutes: append(mkroute("2001:db8:d::9"), mkroute("2001:db8:e::9")...),
	}}
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	if got["vrf-RA"]["2001:db8:d::9"] != "ge-0-0-5.0" {
		t.Errorf("VRF unit-0 nexthop = %q, want ge-0-0-5.0", got["vrf-RA"]["2001:db8:d::9"])
	}
	if got["vrf-RA"]["2001:db8:e::9"] != "ge-0-0-5.0.100" {
		t.Errorf("VRF vlan nexthop = %q, want ge-0-0-5.0.100", got["vrf-RA"]["2001:db8:e::9"])
	}
	if got[""]["2001:db8:d::9"] != "" || got[""]["2001:db8:e::9"] != "" {
		t.Errorf("default pool kept claimed prefixes: %q %q, want absent (VRF-only)",
			got[""]["2001:db8:d::9"], got[""]["2001:db8:e::9"])
	}
}

// TestPoolDottedUnitZeroExcludesSiblings9821 pins #9063 on dotted shapes: a
// unit-0 member claims exactly unit 0; the vlan sibling stays default-only.
func TestPoolDottedUnitZeroExcludesSiblings9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0, Addresses: []string{"2001:db8:f::1/64"}},
			10: {Number: 10, VlanID: 100, Addresses: []string{"2001:db8:10::1/64"}},
		}},
	}}}
	mkroute := func(nh string) []*config.StaticRoute {
		return []*config.StaticRoute{{Destination: "2001:db8:ffff::/48",
			NextHops: []config.NextHopEntry{{Address: nh}}}}
	}
	cfg.RoutingOptions.Inet6StaticRoutes = append(mkroute("2001:db8:f::9"), mkroute("2001:db8:10::9")...)
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "RA", InstanceType: "vrf", Interfaces: []string{"ge-0/0/5.0.0"},
		Inet6StaticRoutes: append(mkroute("2001:db8:f::9"), mkroute("2001:db8:10::9")...),
	}}
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	if got["vrf-RA"]["2001:db8:f::9"] != "ge-0-0-5.0" {
		t.Errorf("VRF unit-0 nexthop = %q, want ge-0-0-5.0", got["vrf-RA"]["2001:db8:f::9"])
	}
	if got["vrf-RA"]["2001:db8:10::9"] != "" {
		t.Errorf("VRF vlan nexthop = %q, want absent (unit-0 claims no siblings)", got["vrf-RA"]["2001:db8:10::9"])
	}
	if got[""]["2001:db8:10::9"] != "ge-0-0-5.0.100" {
		t.Errorf("default vlan nexthop = %q, want ge-0-0-5.0.100 (sibling stays)", got[""]["2001:db8:10::9"])
	}
}

// TestPoolUndeclaredBareClaimsNothing9821 pins the ownership rule at its
// boundary: an undeclared bare member claims nothing, even when a declared
// interface nests textually beneath it (legacy pulled those prefixes by
// device-spelling prefix — spurious, no ownership).
func TestPoolUndeclaredBareClaimsNothing9821(t *testing.T) {
	cfg := v6poolCfg9821(t, map[string]map[int]string{
		"unknown.5": {0: "2001:db8:11::1/64"},
	}, "unknown", "2001:db8:11::9")
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	if got[""]["2001:db8:11::9"] != "unknown.5" {
		t.Errorf("default nexthop = %q, want unknown.5 (stays)", got[""]["2001:db8:11::9"])
	}
	if got["vrf-RA"]["2001:db8:11::9"] != "" {
		t.Errorf("VRF nexthop = %q, want absent (no ownership, no claim)", got["vrf-RA"]["2001:db8:11::9"])
	}
}

// TestPoolVlanIDAddressingMisses9821 CHARACTERIZES the structural consequence
// (D2, intended): units are addressed by unit NUMBER, so `B.100` for unit 10
// with vlan-id 100 misses — legacy hit by device-spelling coincidence while
// the member-units consumers (overlap, rib-group) already keyed on the
// configured unit and saw nothing. Pools now agree with them.
func TestPoolVlanIDAddressingMisses9821(t *testing.T) {
	cfg := v6poolCfg9821(t, map[string]map[int]string{
		"ge-0/0/7": {10: "2001:db8:12::1/64"},
	}, "ge-0/0/7.100", "2001:db8:12::9")
	// The fixture unit needs its vlan-id for the device spelling.
	cfg.Interfaces.Interfaces["ge-0/0/7"].Units[10].VlanID = 100
	got := inferIPv6StaticNextHopInterfaces(cfg, nil)
	if got[""]["2001:db8:12::9"] != "ge-0-0-7.100" {
		t.Errorf("default nexthop = %q, want ge-0-0-7.100 (unclaimed, stays)", got[""]["2001:db8:12::9"])
	}
	if got["vrf-RA"]["2001:db8:12::9"] != "" {
		t.Errorf("VRF nexthop = %q, want absent (vlan-id is not a unit address)", got["vrf-RA"]["2001:db8:12::9"])
	}
}

// TestAssembleFRRConfigDeclaredNetdevs9821 pins the production construction
// (#9821 D7): every declaration lands in DeclaredNetdevs in BOTH spellings
// → its kernel device (unit refs are NOT keys). The render cells prove what
// the map DOES; this proves the assembler BUILDS it.
func TestAssembleFRRConfigDeclaredNetdevs9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/1":   {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	d := &Daemon{}
	fc := d.assembleFRRConfig(cfg, nil)
	want := map[string]string{
		"ge-0/0/5.0": "ge-0-0-5.0",
		"ge-0-0-5.0": "ge-0-0-5.0",
		"ge-0/0/1":   "ge-0-0-1",
		"ge-0-0-1":   "ge-0-0-1",
	}
	if !reflect.DeepEqual(fc.DeclaredNetdevs, want) {
		t.Errorf("assembled DeclaredNetdevs = %q, want %q", fc.DeclaredNetdevs, want)
	}
}

// TestBuildZoneRGMapDeclaredDotted9821 pins dotted-member resolution and
// complete, order-independent ownership for a multi-RG zone.
func TestBuildZoneRGMapDeclaredDotted9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"p.0":   {Name: "p.0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{1: {Number: 1}}},
		"q.0":   {Name: "q.0", RedundancyGroup: 2, Units: map[int]*config.InterfaceUnit{1: {Number: 1}}},
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z":  {Interfaces: []string{"p.0.1"}},
		"zz": {Interfaces: []string{"p.0.1", "q.0.1"}},
		"r":  {Interfaces: []string{"reth0.0"}},
	}
	zoneIDs := map[string]uint16{"z": 5, "zz": 6, "r": 7}
	got := buildZoneRGMap(cfg, zoneIDs)
	if !reflect.DeepEqual(got[5], []int{1}) {
		t.Errorf("zone z RG set = %v, want [1] (dotted owner resolves)", got[5])
	}
	if !reflect.DeepEqual(got[6], []int{1, 2}) {
		t.Errorf("multi-RG zone zz RG set = %v, want [1 2]", got[6])
	}
	if !reflect.DeepEqual(got[7], []int{1}) {
		t.Errorf("zone r RG set = %v, want [1] (undotted control)", got[7])
	}

	cfg.Security.Zones["zz"] = &config.ZoneConfig{Interfaces: []string{"q.0.1", "p.0.1"}}
	reversed := buildZoneRGMap(cfg, zoneIDs)
	if !reflect.DeepEqual(got, reversed) {
		t.Errorf("multi-RG zone ownership changed with interface order: forward=%v reversed=%v", got, reversed)
	}
}
