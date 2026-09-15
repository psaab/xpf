package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// zoneDottedCfg9821 builds a tolerant-shape config: a declared dotted
// interface next to an undotted control. Struct-built (no compile): strict
// admission still rejects single-declared dotted ZONE members (pinned in
// TestZoneMemberStillRejectsSingleDeclaredDotted9821), while these cells pin
// the runtime binders' key agreement, which is what lenient boots enforce.
func zoneDottedCfg9821(members ...string) *Config {
	return &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/5.0": {
				Name: "ge-0/0/5.0",
				Units: map[int]*InterfaceUnit{
					0: {Number: 0},
					1: {Number: 1},
				},
			},
			"ge-0/0/6": {
				Name: "ge-0/0/6",
				Units: map[int]*InterfaceUnit{
					0: {Number: 0},
				},
			},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {Interfaces: members},
		}},
	}
}

func zoneKeys9821(t *testing.T, m map[string]string) []string {
	t.Helper()
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestZoneMirrorsAgreeDeclaredDotted9821: InterfaceZoneMap and
// junosHostZoneByInterface agree key-for-key on declared-dotted members
// (bare fan-down, unit + base bind, padded normalization).
func TestZoneMirrorsAgreeDeclaredDotted9821(t *testing.T) {
	cases := []struct {
		name   string
		member string
		want   []string
	}{
		{"bareFansDown", "ge-0/0/5.0", []string{"ge-0/0/5.0", "ge-0/0/5.0.0", "ge-0/0/5.0.1"}},
		{"unitBindsBase", "ge-0/0/5.0.1", []string{"ge-0/0/5.0", "ge-0/0/5.0.1"}},
		{"paddedNormalizes", "ge-0/0/5.0.01", []string{"ge-0/0/5.0", "ge-0/0/5.0.1"}},
		{"undottedBare", "ge-0/0/6", []string{"ge-0/0/6", "ge-0/0/6.0"}},
		{"undottedUnit", "ge-0/0/6.0", []string{"ge-0/0/6", "ge-0/0/6.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := zoneDottedCfg9821(tc.member)
			zm := zoneKeys9821(t, InterfaceZoneMap(cfg))
			if !reflect.DeepEqual(zm, tc.want) {
				t.Errorf("InterfaceZoneMap keys = %q, want %q", zm, tc.want)
			}
			jn := zoneKeys9821(t, junosHostZoneByInterface(cfg))
			if !reflect.DeepEqual(jn, tc.want) {
				t.Errorf("junosHostZoneByInterface keys = %q, want %q", jn, tc.want)
			}
		})
	}
}

// TestZoneLogicalKeysMatchFanDown9821: the conflict detector's key SSOT
// claims the same SET as the runtime fan-down for every member spelling
// except the deliberately different trailing-dot policy (bare there,
// literal in the runtime maps — preserved on both sides, pinned
// separately below, never leveled).
func TestZoneLogicalKeysMatchFanDown9821(t *testing.T) {
	cfg := zoneDottedCfg9821()
	setOf := func(keys []string) []string {
		out := append([]string{}, keys...)
		sort.Strings(out)
		return out
	}
	for _, member := range []string{
		"ge-0/0/5.0", "ge-0/0/5.0.1", "ge-0/0/5.0.01", "ge-0/0/6", "ge-0/0/6.0",
		"ge-0/0/9", "ge-0/0/9.3", "ge-0/0/6.foo",
	} {
		zn := setOf(zoneIfaceLogicalKeys(cfg, member))
		rt := setOf(InterfaceUnitRefKeys(cfg, member))
		if !reflect.DeepEqual(zn, rt) {
			t.Errorf("member %q: logical keys %q != fan-down keys %q", member, zn, rt)
		}
	}
	// Trailing-dot: conflict keys treat as bare (fan-down), runtime binds
	// the literal. Deliberately different — pin both so neither drifts.
	if got, want := setOf(zoneIfaceLogicalKeys(cfg, "ge-0/0/6.")), []string{"ge-0/0/6", "ge-0/0/6.0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("zoneIfaceLogicalKeys(trailing) = %q, want %q", got, want)
	}
	if got, want := InterfaceUnitRefKeys(cfg, "ge-0/0/6."), []string{"ge-0/0/6."}; !reflect.DeepEqual(got, want) {
		t.Errorf("InterfaceUnitRefKeys(trailing) = %q, want %q", got, want)
	}
}

// TestZoneConflictDetectsDeclaredDottedOverlap9821: in the strict-reachable
// both-declared shape, two zones claiming one dotted unit (one via bare
// fan-down, one explicitly) are REJECTED naming both zones — the #3072
// fail-closed the unswapped detector would miss.
func TestZoneConflictDetectsDeclaredDottedOverlap9821(t *testing.T) {
	tree := vrfTree9809(t, []string{
		"set interfaces p description base",
		"set interfaces p.0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces p.0 unit 1 family inet address 10.0.1.1/24",
		"set security zones security-zone aaa interfaces p.0",
		"set security zones security-zone zzz interfaces p.0.1",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted zones aaa+p.0 and zzz+p.0.1 sharing unit p.0.1")
	}
	for _, want := range []string{"p.0.1", `"aaa"`, `"zzz"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("conflict error %q does not name %s", err.Error(), want)
		}
	}
}

// TestJunosHostNetdevByRefDeclaredWins9821: a key that is both a generated
// unit key and a declared interface resolves to the DECLARED netdev,
// deterministically (map iteration order must not matter — 50 rounds).
func TestJunosHostNetdevByRefDeclaredWins9821(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p":   {Name: "p", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
	name := func(ifName string, unit *InterfaceUnit) string {
		if unit == nil {
			return "D:" + ifName
		}
		return "U:unit"
	}
	for i := range 50 {
		got := junosHostNetdevByRef(cfg, name)
		if got["p.0"] != "D:p.0" {
			t.Fatalf("round %d: netdevByRef[p.0] = %q, want declared D:p.0", i, got["p.0"])
		}
		if got["p"] != "D:p" || got["p.0.0"] != "U:unit" {
			t.Fatalf("round %d: unexpected map %q", i, got)
		}
	}
}

// sortedTokens9821 compares override token sets order-insensitively: refs
// walk sorted but alias spellings can order unit-before-bare, so only the
// SET is load-bearing (view grouping canonicalizes order anyway).
func sortedTokens9821(t *testing.T, hib *HostInboundTraffic) []string {
	t.Helper()
	if hib == nil {
		return nil
	}
	out := append([]string{}, hib.SystemServices...)
	sort.Strings(out)
	return out
}

func overrideCfg9821() *Config {
	return &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p":   {Name: "p"},
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
			"ge-0/0/5.0": {
				Name: "ge-0/0/5.0",
				Units: map[int]*InterfaceUnit{
					0: {Number: 0},
					1: {Number: 1},
				},
			},
			"ge-0/0/6": {Name: "ge-0/0/6", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0", "ge-0/0/5.0", "ge-0/0/6"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.0":        {SystemServices: []string{"ssh"}},
					"p.0.1":      {SystemServices: []string{"ntp"}},
					"ge-0/0/5.0": {SystemServices: []string{"a"}},
					"ge-0/0/6":   {SystemServices: []string{"c"}},
				},
			},
		}},
	}
}

// TestResolveInterfaceHostInboundDeclaredDotted9821: a dotted-physical
// override fans down; unit overrides merge atop; alias+unit co-authored
// spellings union as sets.
func TestResolveInterfaceHostInboundDeclaredDotted9821(t *testing.T) {
	cfg := overrideCfg9821()
	cfg.Security.Zones["z"].InterfaceHostInbound["ge-0/0/5.0.1"] = &HostInboundTraffic{SystemServices: []string{"b"}}
	got := ResolveInterfaceHostInbound(cfg)
	want := map[string][]string{
		"p.0":          {"ssh"},
		"p.0.0":        {"ssh"},
		"p.0.1":        {"ntp", "ssh"},
		"ge-0/0/5.0":   {"a"},
		"ge-0/0/5.0.0": {"a"},
		"ge-0/0/5.0.1": {"a", "b"},
		"ge-0/0/6":     {"c"},
		"ge-0/0/6.0":   {"c"},
	}
	for key, wantToks := range want {
		if gotToks := sortedTokens9821(t, got[key]); !reflect.DeepEqual(gotToks, wantToks) {
			t.Errorf("override[%q] = %q, want %q", key, gotToks, wantToks)
		}
	}
	// Alias-bare + unit co-authored: the SET is the union regardless of
	// spelling order.
	cfg2 := overrideCfg9821()
	cfg2.Security.Zones["z"].InterfaceHostInbound = map[string]*HostInboundTraffic{
		"ge-0/0/5.00":  {SystemServices: []string{"a"}},
		"ge-0/0/5.0.1": {SystemServices: []string{"b"}},
	}
	got2 := ResolveInterfaceHostInbound(cfg2)
	if toks := sortedTokens9821(t, got2["ge-0/0/5.0.1"]); !reflect.DeepEqual(toks, []string{"a", "b"}) {
		t.Errorf("alias+unit override set = %q, want [a b]", toks)
	}
}

// TestStampZoneDHCPScopeWithheldDeclaredDotted9821: withhold stamps follow
// dotted fan-down, and the DHCP-client carve-out survives it.
func TestStampZoneDHCPScopeWithheldDeclaredDotted9821(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {Interfaces: []string{"p.0"}},
		}},
		System: SystemConfig{DHCPServer: DHCPServerConfig{
			DHCPLocalServer: &DHCPLocalServerConfig{
				Groups: map[string]*DHCPServerGroup{"g": {Interfaces: []string{"p.0"}}},
			},
		}},
	}
	stampZoneDHCPScopeWithheld(cfg)
	zone := cfg.Security.Zones["z"]
	for _, ref := range []string{"p.0", "p.0.0", "p.0.1"} {
		if !zone.WithholdsZoneLevelDHCPFor(ref) {
			t.Errorf("withhold missing for %q (server on bare p.0 must cover children)", ref)
		}
	}
	// Both-role carve-out: unit 1 is also the firewall's own DHCP client →
	// NOT withheld there. The bare ref is not withheld either once ANY unit
	// is a client (pre-existing bare-answers-any rule, undotted-identical).
	// Unit 0 stays withheld: server-covered via the bare `p.0` server ref
	// and running no client itself.
	cfg.Interfaces.Interfaces["p.0"].Units[1].DHCP = true
	cfg.ForwardingOptions.DHCPRelay = &DHCPRelayConfig{
		Groups: map[string]*DHCPRelayGroup{"r": {Interfaces: []string{"p.0.1"}}},
	}
	stampZoneDHCPScopeWithheld(cfg)
	if zone.WithholdsZoneLevelDHCPFor("p.0.1") {
		t.Errorf("client carve-out lost: p.0.1 (relay member + own client) withheld")
	}
	if zone.WithholdsZoneLevelDHCPFor("p.0") {
		t.Errorf("bare carve-out lost: p.0 must read client-true once any unit is a client (pre-existing rule)")
	}
	if !zone.WithholdsZoneLevelDHCPFor("p.0.0") {
		t.Errorf("unit-0 withhold lost: server-covered, no client")
	}
}

// TestDupHostOverrideMapDeclaredDotted9821: the gate mirror agrees with the
// runtime map on canonical keys (multi-dot Literals added; undotted-padded
// raw-only preserved exactly).
func TestDupHostOverrideMapDeclaredDotted9821(t *testing.T) {
	cfg := overrideCfg9821()
	cfg.Security.Zones["z"].InterfaceHostInbound["p.0.01"] = &HostInboundTraffic{SystemServices: []string{"ntp"}}
	cfg.Security.Zones["z"].InterfaceHostInbound["ge-0/0/6.01"] = &HostInboundTraffic{SystemServices: []string{"ntp"}}
	got := buildHostInboundOverrideMapLocal(cfg)
	rt := ResolveInterfaceHostInbound(cfg)
	// Canonical keys agree between gate mirror and runtime map.
	for _, key := range []string{"p.0", "p.0.0", "p.0.1", "ge-0/0/5.0", "ge-0/0/5.0.0", "ge-0/0/6", "ge-0/0/6.0"} {
		if sortedTokens9821(t, got[key]) == nil && sortedTokens9821(t, rt[key]) == nil {
			continue
		}
		if !reflect.DeepEqual(sortedTokens9821(t, got[key]), sortedTokens9821(t, rt[key])) {
			t.Errorf("key %q: gate %q != runtime %q", key, sortedTokens9821(t, got[key]), sortedTokens9821(t, rt[key]))
		}
	}
	// Multi-dot padded authored spelling gains its canonical key...
	if sortedTokens9821(t, got["p.0.1"]) == nil {
		t.Errorf("gate mirror missing canonical p.0.1 for authored p.0.01")
	}
	// ...while undotted-padded keeps raw-only (pre-existing gate behavior).
	if _, ok := got["ge-0/0/6.1"]; ok {
		t.Errorf("gate mirror must not add canonical ge-0/0/6.1 for authored ge-0/0/6.01 (pre-existing raw-only)")
	}
	if got["ge-0/0/6.01"] == nil {
		t.Errorf("gate mirror lost raw ge-0/0/6.01")
	}
}

// TestHostInboundRolesDeclaredDotted9821: role classification across the
// dotted shapes incl. sibling exclusion and both-role retention. DHCP
// clienthood is per-case: the classifier reads the unit's actual flag.
func TestHostInboundRolesDeclaredDotted9821(t *testing.T) {
	newCfg := func(dhcpUnits ...int) *Config {
		units := map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}
		for _, n := range dhcpUnits {
			units[n].DHCP = true
		}
		return &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p.0":      {Name: "p.0", Units: units},
			"ge-0/0/6": {Name: "ge-0/0/6", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}}}
	}
	cases := []struct {
		name       string
		dhcpUnits  []int
		serverRefs []string
		ref        string
		wantServer bool
		wantClient bool
	}{
		{"serverOnly", nil, []string{"p.0"}, "p.0.1", true, false},
		{"clientOnly", []int{1}, nil, "p.0.1", false, true},
		{"bothRoles", []int{1}, []string{"p.0.1"}, "p.0.1", true, true},
		{"siblingExcluded", nil, []string{"p.0.0"}, "p.0.1", false, false},
		{"undottedControl", nil, []string{"ge-0/0/6"}, "ge-0/0/6.1", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newCfg(tc.dhcpUnits...)
			r := hostInboundDHCPRolesFor(cfg, tc.serverRefs, tc.ref)
			if r.server != tc.wantServer || r.client != tc.wantClient {
				t.Errorf("roles(%q) = %+v, want server=%v client=%v", tc.ref, r, tc.wantServer, tc.wantClient)
			}
		})
	}
}

// TestStanzaAdvisoryKeysDeclaredDotted9821: the stanza advisory resolves
// dotted members to their enforcement unit keys — a zone whose every unit
// is overridden silences the zone-level scoping advisory (pre-fix it
// warned: the bare dotted ref resolved to no key the override map holds).
func TestStanzaAdvisoryKeysDeclaredDotted9821(t *testing.T) {
	build := func(overrides map[string]*HostInboundTraffic) *Config {
		return &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
			}},
			Security: SecurityConfig{Zones: map[string]*ZoneConfig{
				"z": {
					Interfaces:           []string{"ge-0/0/5.0"},
					HostInboundTraffic:   &HostInboundTraffic{SystemServices: []string{"all"}},
					InterfaceHostInbound: overrides,
				},
			}},
		}
	}
	scoping := func(cfg *Config) []string {
		var out []string
		for _, w := range validateHostInboundStanzaWarnings(cfg) {
			if strings.Contains(w, "expands to the union of the") {
				out = append(out, w)
			}
		}
		return out
	}
	allOverridden := build(map[string]*HostInboundTraffic{
		"ge-0/0/5.0.0": {SystemServices: []string{"ssh"}},
		"ge-0/0/5.0.1": {SystemServices: []string{"ssh"}},
	})
	if got := scoping(allOverridden); len(got) != 0 {
		t.Fatalf("zone-level scoping advisory should be silenced when every unit is overridden, got %v", got)
	}
	noneOverridden := build(nil)
	if got := scoping(noneOverridden); len(got) == 0 {
		t.Fatal("zone-level scoping advisory must fire when no override covers the units (trigger control)")
	}
}

// TestInterfaceHostInboundOverrideStamp9821: the compiled stamp agrees with
// the runtime map on every canonical key; nil stamps keep legacy behavior.
func TestInterfaceHostInboundOverrideStamp9821(t *testing.T) {
	newCfg := func() *Config {
		return &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				"p":   {Name: "p"},
				"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
			}},
			Security: SecurityConfig{Zones: map[string]*ZoneConfig{
				"z": {
					Interfaces: []string{"p.0"},
					InterfaceHostInbound: map[string]*HostInboundTraffic{
						"p.0":   {SystemServices: []string{"ssh"}},
						"p.0.1": {SystemServices: []string{"ntp"}},
					},
				},
			}},
		}
	}
	eff := func(t *testing.T, z *ZoneConfig, ref string) ([]string, bool) {
		t.Helper()
		svc, _, declared := z.InterfaceHostInboundOverride(ref)
		out := append([]string{}, svc...)
		sort.Strings(out)
		return out, declared
	}
	// Stamped: inheritance, union, exclusion, empty.
	cfg := newCfg()
	stampResolvedInterfaceOverrides(cfg)
	zone := cfg.Security.Zones["z"]
	if toks, ok := eff(t, zone, "p.0.0"); !ok || !reflect.DeepEqual(toks, []string{"ssh"}) {
		t.Errorf("stamped p.0.0 = %q,%v want [ssh],true", toks, ok)
	}
	if toks, ok := eff(t, zone, "p.0.1"); !ok || !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
		t.Errorf("stamped p.0.1 = %q,%v want [ntp ssh],true", toks, ok)
	}
	if toks, ok := eff(t, zone, "p.0.01"); !ok || !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
		t.Errorf("stamped p.0.01 = %q,%v want [ntp ssh],true", toks, ok)
	}
	cfg2 := newCfg()
	cfg2.Security.Zones["z"].InterfaceHostInbound = map[string]*HostInboundTraffic{
		"p": {SystemServices: []string{"ssh"}},
	}
	stampResolvedInterfaceOverrides(cfg2)
	if toks, ok := eff(t, cfg2.Security.Zones["z"], "p.0.1"); ok || len(toks) != 0 {
		t.Errorf("unrelated-parent inherit: got %q,%v want absent", toks, ok)
	}
	// Empty override: declared-true with empty tokens.
	cfg3 := newCfg()
	cfg3.Security.Zones["z"].InterfaceHostInbound = map[string]*HostInboundTraffic{
		"p.0.1": {},
	}
	stampResolvedInterfaceOverrides(cfg3)
	if toks, ok := eff(t, cfg3.Security.Zones["z"], "p.0.1"); !ok || len(toks) != 0 {
		t.Errorf("empty override: got %q,%v want [],true", toks, ok)
	}
	// Nil stamp: legacy behavior preserved exactly (incl. first-dot inherit).
	cfg4 := newCfg()
	if toks, ok := eff(t, cfg4.Security.Zones["z"], "p.0.1"); !ok || !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("nil-stamp p.0.1 = %q,%v want [ntp],true (legacy: base p carries nothing, exact only)", toks, ok)
	}
	// Stanza-less bind-only shape: absent agrees with the runtime map (no
	// fan-down without a stanza on either side); explicit child overrides
	// still hit.
	cfg5 := &Config{
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {InterfaceHostInbound: map[string]*HostInboundTraffic{
				"st0": {SystemServices: []string{"ssh"}},
			}},
		}},
	}
	stampResolvedInterfaceOverrides(cfg5)
	if toks, ok := eff(t, cfg5.Security.Zones["z"], "st0.7"); ok || len(toks) != 0 {
		t.Errorf("stanza-less st0.7 = %q,%v want absent (runtime agrees: no fan-down)", toks, ok)
	}
	cfg5.Security.Zones["z"].InterfaceHostInbound["st0.7"] = &HostInboundTraffic{SystemServices: []string{"ntp"}}
	stampResolvedInterfaceOverrides(cfg5)
	if toks, ok := eff(t, cfg5.Security.Zones["z"], "st0.7"); !ok || !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("explicit st0.7 = %q,%v want [ntp],true (no fan-down without a stanza, both maps)", toks, ok)
	}
	// Alias queries resolve through the stamped set: `p.0.001` is no authored
	// key, but its Literal `p.0.1` is — the R6-3 requirement.
	if toks, ok := eff(t, zone, "p.0.001"); !ok || !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
		t.Errorf("alias query p.0.001 = %q,%v want [ntp ssh],true", toks, ok)
	}
}

// TestStampRawAliasUnionCompleteness9821 (D19 example (b), NEW BEHAVIOR): a
// raw alias unit key and its canonical key BOTH map to the complete
// union(parent, child) — multi-dot (`p.0.01`/`p.0.1`), single-dot (`p.01`/
// `p.1`, converging the method with runtime #18 which already binds Literal),
// and empty-child-with-parent (the union is the parent set, still declared).
// Method and runtime agree on every canonical key; the runtime holds no raw
// keys (it binds Literal only — the raw half is the method's).
func TestStampRawAliasUnionCompleteness9821(t *testing.T) {
	eff := func(t *testing.T, z *ZoneConfig, ref string) ([]string, bool) {
		t.Helper()
		svc, _, declared := z.InterfaceHostInboundOverride(ref)
		out := append([]string{}, svc...)
		sort.Strings(out)
		return out, declared
	}
	// Multi-dot: authored alias child + dotted parent.
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p":   {Name: "p"},
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.0":    {SystemServices: []string{"ssh"}},
					"p.0.01": {SystemServices: []string{"ntp"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg)
	zone := cfg.Security.Zones["z"]
	rt := ResolveInterfaceHostInbound(cfg)
	for _, q := range []string{"p.0.01", "p.0.1"} {
		if toks, ok := eff(t, zone, q); !ok || !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
			t.Errorf("multi-dot method %q = %q,%v want [ntp ssh],true", q, toks, ok)
		}
	}
	if toks := sortedTokens9821(t, rt["p.0.1"]); !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
		t.Errorf("multi-dot runtime p.0.1 = %q want [ntp ssh]", toks)
	}
	if _, ok := rt["p.0.01"]; ok {
		t.Error("runtime must not bind the raw alias p.0.01 (Literal-only)")
	}
	if toks, ok := eff(t, zone, "p.0.0"); !ok || !reflect.DeepEqual(toks, []string{"ssh"}) {
		t.Errorf("fan-down control p.0.0 = %q,%v want [ssh],true", toks, ok)
	}
	// Single-dot: authored padded child + undotted parent (the pre-existing
	// method-side divergence D19 converges with runtime #18).
	cfg1 := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p": {Name: "p", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p":    {SystemServices: []string{"ssh"}},
					"p.01": {SystemServices: []string{"ntp"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg1)
	zone1 := cfg1.Security.Zones["z"]
	rt1 := ResolveInterfaceHostInbound(cfg1)
	for _, q := range []string{"p.01", "p.1"} {
		if toks, ok := eff(t, zone1, q); !ok || !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
			t.Errorf("single-dot method %q = %q,%v want [ntp ssh],true", q, toks, ok)
		}
	}
	if toks := sortedTokens9821(t, rt1["p.1"]); !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
		t.Errorf("single-dot runtime p.1 = %q want [ntp ssh]", toks)
	}
	// Empty child with a parent: the union is the parent set, still declared.
	cfg2 := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p":   {Name: "p"},
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.0":    {SystemServices: []string{"ssh"}},
					"p.0.01": {},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg2)
	zone2 := cfg2.Security.Zones["z"]
	rt2 := ResolveInterfaceHostInbound(cfg2)
	for _, q := range []string{"p.0.01", "p.0.1"} {
		if toks, ok := eff(t, zone2, q); !ok || !reflect.DeepEqual(toks, []string{"ssh"}) {
			t.Errorf("empty-child method %q = %q,%v want [ssh],true", q, toks, ok)
		}
	}
	if toks := sortedTokens9821(t, rt2["p.0.1"]); !reflect.DeepEqual(toks, []string{"ssh"}) {
		t.Errorf("empty-child runtime p.0.1 = %q want [ssh]", toks)
	}
}

// TestStampBareAliasKeys9821 (D20, characterization): authored `p.00` of
// declared `p.0` stamps {`p.00`, `p.0`, `p.0.N` fan-down} with the bare value
// on the first two and inherit-unions on the units — regardless of dot count.
// Method and runtime agree on the declared-bare key and every child.
func TestStampBareAliasKeys9821(t *testing.T) {
	eff := func(t *testing.T, z *ZoneConfig, ref string) ([]string, bool) {
		t.Helper()
		svc, _, declared := z.InterfaceHostInboundOverride(ref)
		out := append([]string{}, svc...)
		sort.Strings(out)
		return out, declared
	}
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p":   {Name: "p"},
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.00": {SystemServices: []string{"ssh"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg)
	zone := cfg.Security.Zones["z"]
	rt := ResolveInterfaceHostInbound(cfg)
	for _, q := range []string{"p.00", "p.0", "p.0.0", "p.0.1"} {
		if toks, ok := eff(t, zone, q); !ok || !reflect.DeepEqual(toks, []string{"ssh"}) {
			t.Errorf("bare-alias method %q = %q,%v want [ssh],true", q, toks, ok)
		}
	}
	for _, k := range []string{"p.0", "p.0.0", "p.0.1"} {
		if toks := sortedTokens9821(t, rt[k]); !reflect.DeepEqual(toks, []string{"ssh"}) {
			t.Errorf("bare-alias runtime %q = %q want [ssh]", k, toks)
		}
	}
	if _, ok := rt["p.00"]; ok {
		t.Error("runtime must not bind the raw bare alias p.00 (Literal-only)")
	}
}

// TestStampAliasQueryNoChildOverride9821 (R6-3, characterization): with NO
// child override, an alias query (`p.0.001`) still hits the stamped canonical
// (`p.0.1`) through the raw+Literal probe — fan-down stamps the canonical key
// only, so the probe (not the stamp) is what satisfies the raw spelling.
func TestStampAliasQueryNoChildOverride9821(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p":   {Name: "p"},
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.0": {SystemServices: []string{"ssh"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg)
	zone := cfg.Security.Zones["z"]
	if _, ok := zone.ResolvedInterfaceOverrides["p.0.001"]; ok {
		t.Fatal("stamp must not hold a raw p.0.001 key (nothing authored it)")
	}
	if zone.ResolvedInterfaceOverrides["p.0.1"] == nil {
		t.Fatal("stamp must hold fan-down p.0.1 for the probe to land on")
	}
	svc, _, declared := zone.InterfaceHostInboundOverride("p.0.001")
	out := append([]string{}, svc...)
	sort.Strings(out)
	if !declared || !reflect.DeepEqual(out, []string{"ssh"}) {
		t.Errorf("alias query p.0.001 = %q,%v want [ssh],true (parent-only, no child)", out, declared)
	}
}

// TestStampAbsenceAgreement9821 (D19 example (a) + F-D19 unlisted-unit
// corollary + R6-4 synthetic-row proof, characterization): every absence
// agrees between method and runtime — an unrelated parent's override never
// leaks onto a dotted child; a zone-listed UNCONFIGURED unit reports
// zone-level on both sides; a synthetic bind-only row (stanza-less `st0.0`)
// finds an inherited entry in NEITHER map.
func TestStampAbsenceAgreement9821(t *testing.T) {
	eff := func(t *testing.T, z *ZoneConfig, ref string) ([]string, bool) {
		t.Helper()
		svc, _, declared := z.InterfaceHostInboundOverride(ref)
		out := append([]string{}, svc...)
		sort.Strings(out)
		return out, declared
	}
	// (a) Unrelated parent: override on `p`, query `p.0.1` → absent both sides.
	cfgA := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p":   {Name: "p"},
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p": {SystemServices: []string{"ssh"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfgA)
	if toks, ok := eff(t, cfgA.Security.Zones["z"], "p.0.1"); ok || len(toks) != 0 {
		t.Errorf("unrelated-parent method p.0.1 = %q,%v want absent", toks, ok)
	}
	if ov := ResolveInterfaceHostInbound(cfgA)["p.0.1"]; ov != nil {
		t.Errorf("unrelated-parent runtime p.0.1 = %v want absent", ov.SystemServices)
	}
	// Unlisted-unit corollary: zone-listed `ge-0/0/9.99` (unit 99 NOT
	// configured) reports ZONE-level on both sides, while the configured
	// sibling still inherits the parent override.
	cfgB := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces:         []string{"ge-0/0/9.99"},
				HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"ge-0/0/9": {SystemServices: []string{"ntp"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfgB)
	zoneB := cfgB.Security.Zones["z"]
	if toks, ok := eff(t, zoneB, "ge-0/0/9.99"); ok || len(toks) != 0 {
		t.Errorf("unlisted-unit method override = %q,%v want absent", toks, ok)
	}
	if ov := ResolveInterfaceHostInbound(cfgB)["ge-0/0/9.99"]; ov != nil {
		t.Errorf("unlisted-unit runtime = %v want absent", ov.SystemServices)
	}
	svc, _, overridden := zoneB.InterfaceHostInboundEffective("ge-0/0/9.99")
	if overridden || !reflect.DeepEqual(svc, []string{"ssh"}) {
		t.Errorf("unlisted-unit effective = %q,%v want zone-level [ssh],false", svc, overridden)
	}
	if toks, ok := eff(t, zoneB, "ge-0/0/9.0"); !ok || !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("configured-sibling control ge-0/0/9.0 = %q,%v want [ntp],true", toks, ok)
	}
	// R6-4 synthetic bind-only row: stanza-less `st0.0` zoned via
	// bind-interface finds an inherited entry in NEITHER map → both absent.
	cfgC := &Config{
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"st0.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"st0": {SystemServices: []string{"ssh"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfgC)
	if toks, ok := eff(t, cfgC.Security.Zones["z"], "st0.0"); ok || len(toks) != 0 {
		t.Errorf("bind-only method st0.0 = %q,%v want absent", toks, ok)
	}
	if ov := ResolveInterfaceHostInbound(cfgC)["st0.0"]; ov != nil {
		t.Errorf("bind-only runtime st0.0 = %v want absent", ov.SystemServices)
	}
}

// TestStampEmptyOverrideAndNilStampPins9821 (F-D19, characterization): an
// empty child override declares (empty both spellings, no parent); an empty
// `st0.7` child under a stanza-less `st0` owner stays child-only empty (no
// fan-down without a stanza — both maps); a nil stamp keeps the legacy Cut
// walk byte-identical incl. the dotted misparse (programmatic-only scope:
// the compiled path for that shape is authoritative-absent, pinned above).
func TestStampEmptyOverrideAndNilStampPins9821(t *testing.T) {
	eff := func(t *testing.T, z *ZoneConfig, ref string) ([]string, bool) {
		t.Helper()
		svc, _, declared := z.InterfaceHostInboundOverride(ref)
		out := append([]string{}, svc...)
		sort.Strings(out)
		return out, declared
	}
	// Empty alias child, no parent: declared-true empty on both spellings.
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p":   {Name: "p"},
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.0.01": {},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg)
	zone := cfg.Security.Zones["z"]
	for _, q := range []string{"p.0.01", "p.0.1"} {
		if toks, ok := eff(t, zone, q); !ok || len(toks) != 0 {
			t.Errorf("empty-alias method %q = %q,%v want [],true", q, toks, ok)
		}
	}
	if ov := ResolveInterfaceHostInbound(cfg)["p.0.1"]; ov == nil {
		t.Error("empty-alias runtime p.0.1 = absent want declared-true empty")
	} else if len(ov.SystemServices) != 0 || len(ov.Protocols) != 0 {
		t.Errorf("empty-alias runtime p.0.1 = %v/%v want empty", ov.SystemServices, ov.Protocols)
	}
	// Stanza-less st0 owner + explicit EMPTY child: child-only empty both maps
	// (no fan-down without a stanza, so the parent does NOT union in).
	cfgS := &Config{
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {InterfaceHostInbound: map[string]*HostInboundTraffic{
				"st0":   {SystemServices: []string{"ssh"}},
				"st0.7": {},
			}},
		}},
	}
	stampResolvedInterfaceOverrides(cfgS)
	if toks, ok := eff(t, cfgS.Security.Zones["z"], "st0.7"); !ok || len(toks) != 0 {
		t.Errorf("stanza-less empty-child method st0.7 = %q,%v want [],true", toks, ok)
	}
	if ov := ResolveInterfaceHostInbound(cfgS)["st0.7"]; ov == nil {
		t.Error("stanza-less empty-child runtime st0.7 = absent want declared-true empty")
	} else if len(ov.SystemServices) != 0 {
		t.Errorf("stanza-less empty-child runtime st0.7 = %q want empty (no parent union without a stanza)", ov.SystemServices)
	}
	// Nil stamp: legacy first-dot walk, byte-identical — `p.0.1` inherits the
	// `p` override through the misparse (Cut base `p`). Programmatic-only:
	// hand-built cfgs bypassing compile. The COMPILED shape is absent.
	cfgN := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p":   {Name: "p"},
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p": {SystemServices: []string{"ssh"}},
				},
			},
		}},
	}
	if toks, ok := eff(t, cfgN.Security.Zones["z"], "p.0.1"); !ok || !reflect.DeepEqual(toks, []string{"ssh"}) {
		t.Errorf("nil-stamp legacy p.0.1 = %q,%v want [ssh],true (first-dot inherit from p)", toks, ok)
	}
}

// TestStampCoauthoredBareAliasAgreement9821 pins the review fix: co-authored
// bare aliases in one zone (`p.0`→ssh + `p.00`→ntp) first-win on the canonical
// in BOTH constructions — the runtime #18 bare arm and the stamp — so method
// and enforcement agree exactly (ssh-only) on both spellings. Pre-fix the
// stamp unioned (ssh∪ntp) where the runtime first-won (ssh). Strict-reachable:
// override keys carry no alias gate (unlike unit definitions), so both
// spellings author freely.
func TestStampCoauthoredBareAliasAgreement9821(t *testing.T) {
	eff := func(t *testing.T, z *ZoneConfig, ref string) ([]string, bool) {
		t.Helper()
		svc, _, declared := z.InterfaceHostInboundOverride(ref)
		out := append([]string{}, svc...)
		sort.Strings(out)
		return out, declared
	}
	runtime := func(t *testing.T, cfg *Config, key string) []string {
		t.Helper()
		hib := ResolveInterfaceHostInbound(cfg)[key]
		if hib == nil {
			return nil
		}
		out := append([]string{}, hib.SystemServices...)
		sort.Strings(out)
		return out
	}
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.0":  {SystemServices: []string{"ssh"}},
					"p.00": {SystemServices: []string{"ntp"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg)
	zone := cfg.Security.Zones["z"]
	// Canonical spelling: both constructions first-win ssh.
	if toks, ok := eff(t, zone, "p.0"); !ok || !reflect.DeepEqual(toks, []string{"ssh"}) {
		t.Errorf("method p.0 = %q,%v — want [ssh],true (first-winner, not union)", toks, ok)
	}
	if toks := runtime(t, cfg, "p.0"); !reflect.DeepEqual(toks, []string{"ssh"}) {
		t.Errorf("runtime p.0 = %q — want [ssh]", toks)
	}
	// Raw alias spelling: post-pass propagates the winner; runtime binds
	// the Literal, so both answer ssh-only.
	if toks, ok := eff(t, zone, "p.00"); !ok || !reflect.DeepEqual(toks, []string{"ssh"}) {
		t.Errorf("method p.00 = %q,%v — want [ssh],true (winner propagation)", toks, ok)
	}
	// Fan-down unit keys still union in both (different identities).
	if toks, ok := eff(t, zone, "p.0.0"); !ok || !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
		t.Errorf("method p.0.0 = %q,%v — want [ntp ssh],true (fan-down union preserved)", toks, ok)
	}
	if toks := runtime(t, cfg, "p.0.0"); !reflect.DeepEqual(toks, []string{"ntp", "ssh"}) {
		t.Errorf("runtime p.0.0 = %q — want [ntp ssh]", toks)
	}
}

// TestStampAliasBeforeCanonicalAgreement9821 pins that bare-target
// first-wins holds REGARDLESS of author order (review GPT-1): a signed-zero
// alias `p.-0` sorts BEFORE its canonical `p.0`, so the alias writes first
// and the canonical's direct merge must skip — not union — exactly as the
// runtime #18 bare arm does.
func TestStampAliasBeforeCanonicalAgreement9821(t *testing.T) {
	eff := func(t *testing.T, z *ZoneConfig, ref string) ([]string, bool) {
		t.Helper()
		svc, _, declared := z.InterfaceHostInboundOverride(ref)
		out := append([]string{}, svc...)
		sort.Strings(out)
		return out, declared
	}
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.0":  {SystemServices: []string{"ssh"}},
					"p.-0": {SystemServices: []string{"ntp"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg)
	zone := cfg.Security.Zones["z"]
	// `p.-0` sorts first (`-` < `0`); both constructions must answer its
	// value on both spellings.
	if toks, ok := eff(t, zone, "p.0"); !ok || !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("method p.0 = %q,%v — want [ntp],true (alias first-wins)", toks, ok)
	}
	if toks, ok := eff(t, zone, "p.-0"); !ok || !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("method p.-0 = %q,%v — want [ntp],true", toks, ok)
	}
	got := ResolveInterfaceHostInbound(cfg)["p.0"]
	if got == nil {
		t.Fatal("runtime has no p.0 key")
	}
	if toks := append([]string{}, got.SystemServices...); !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("runtime p.0 = %q — want [ntp] (agreement with method)", toks)
	}
}

// TestStampUnitAliasOntoDeclaredBareAgreement9821 pins the Spark-F2 shape:
// unit-alias `p.0.001` (step-3 Literal `p.0.1` — requires declared `p.0`)
// co-authored with declared-bare `p.0.1`. The alias writes first (padding
// sorts first, structurally); the bare direct merge must skip, not union —
// exact runtime parity. Strict-reachable: override keys carry no alias gate.
func TestStampUnitAliasOntoDeclaredBareAgreement9821(t *testing.T) {
	eff := func(t *testing.T, z *ZoneConfig, ref string) ([]string, bool) {
		t.Helper()
		svc, _, declared := z.InterfaceHostInboundOverride(ref)
		out := append([]string{}, svc...)
		sort.Strings(out)
		return out, declared
	}
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p.0":   {Name: "p.0", Units: map[int]*InterfaceUnit{1: {Number: 1}}},
			"p.0.1": {Name: "p.0.1", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {
				Interfaces: []string{"p.0.1"},
				InterfaceHostInbound: map[string]*HostInboundTraffic{
					"p.0.1":   {SystemServices: []string{"ssh"}},
					"p.0.001": {SystemServices: []string{"ntp"}},
				},
			},
		}},
	}
	stampResolvedInterfaceOverrides(cfg)
	zone := cfg.Security.Zones["z"]
	if toks, ok := eff(t, zone, "p.0.1"); !ok || !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("method p.0.1 = %q,%v — want [ntp],true (unit-alias first-wins)", toks, ok)
	}
	if toks, ok := eff(t, zone, "p.0.001"); !ok || !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("method p.0.001 = %q,%v — want [ntp],true", toks, ok)
	}
	got := ResolveInterfaceHostInbound(cfg)["p.0.1"]
	if got == nil {
		t.Fatal("runtime has no p.0.1 key")
	}
	if toks := append([]string{}, got.SystemServices...); !reflect.DeepEqual(toks, []string{"ntp"}) {
		t.Errorf("runtime p.0.1 = %q — want [ntp] (agreement with method)", toks)
	}
}
