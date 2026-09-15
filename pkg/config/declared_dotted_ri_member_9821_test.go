package config

import (
	"reflect"
	"strings"
	"testing"
)

// declaredDottedCfg9821 builds the issue's probe shape programmatically: a
// declared dotted interface with an addressed unit 0, plus an undotted
// control interface. Routing instances are attached per-test: compiling
// through set lines would route every assertion through all gates at once,
// while these cells pin one consumer each.
func declaredDottedCfg9821() *Config {
	return &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/5.0": {
				Name: "ge-0/0/5.0",
				Units: map[int]*InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.55.0.1/24"}},
				},
			},
			"ge-0/0/6": {
				Name: "ge-0/0/6",
				Units: map[int]*InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.66.0.1/24"}},
				},
			},
		}},
	}
}

// TestInterfaceUnitRefKeysDeclaredDotted9821: a member naming a declared
// dotted interface IS that bare interface (#8994 precedence) and fans down
// like any bare ref; a unit of it binds the canonical Literal.
func TestInterfaceUnitRefKeysDeclaredDotted9821(t *testing.T) {
	cfg := declaredDottedCfg9821()
	cfg.Interfaces.Interfaces["ge-0/0/5.0"].Units[10] = &InterfaceUnit{Number: 10}
	cases := []struct {
		name string
		ref  string
		want []string
	}{
		{"declaredBareFansDown", "ge-0/0/5.0", []string{"ge-0/0/5.0", "ge-0/0/5.0.0", "ge-0/0/5.0.10"}},
		{"declaredUnitLiteral", "ge-0/0/5.0.1", []string{"ge-0/0/5.0.1"}},
		{"declaredUnitPaddedAlias", "ge-0/0/5.0.01", []string{"ge-0/0/5.0.1"}},
		{"canonAliasFansDown", "ge-0/0/5.00", []string{"ge-0/0/5.0", "ge-0/0/5.0.0", "ge-0/0/5.0.10"}},
		{"undottedUnitLiteral", "ge-0/0/6.0", []string{"ge-0/0/6.0"}},
		{"undottedUnitPadded", "ge-0/0/6.01", []string{"ge-0/0/6.1"}},
		{"undottedBareFansDown", "ge-0/0/6", []string{"ge-0/0/6", "ge-0/0/6.0"}},
		{"undeclaredBareLiteral", "ge-0/0/9", []string{"ge-0/0/9"}},
		{"undeclaredUnitLiteral", "ge-0/0/9.1", []string{"ge-0/0/9.1"}},
		{"malformedLiteral", "ge-0/0/6.foo", []string{"ge-0/0/6.foo"}},
		{"trailingDotLiteral", "ge-0/0/6.", []string{"ge-0/0/6."}},
		{"emptyNil", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InterfaceUnitRefKeys(cfg, tc.ref); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("InterfaceUnitRefKeys(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
	// Both-declared: fan-down keys are generated from the member's own base.
	both := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p":   {Name: "p", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
	if got, want := InterfaceUnitRefKeys(both, "p"), []string{"p", "p.0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("InterfaceUnitRefKeys(p) = %q, want %q", got, want)
	}
	if got, want := InterfaceUnitRefKeys(both, "p.0"), []string{"p.0", "p.0.0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("InterfaceUnitRefKeys(p.0) = %q, want %q", got, want)
	}
	// Nil config degrades to legacy canon-then-cut.
	if got, want := InterfaceUnitRefKeys(nil, "ge-0/0/0.01"), []string{"ge-0/0/0.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("InterfaceUnitRefKeys(nil, padded) = %q, want %q", got, want)
	}
}

// TestRoutingInstanceMemberUnitsDeclaredDotted9821: member-relative parsing
// resolves each member's OWN units. The both-declared assertions compare
// ADDRESSES, not key strings: `p.0` names p's unit 0 for member `p` and the
// declared interface for member `p.0`, and only the addresses tell them apart.
func TestRoutingInstanceMemberUnitsDeclaredDotted9821(t *testing.T) {
	cfg := declaredDottedCfg9821()
	mus := RoutingInstanceMemberUnits(cfg, "ge-0/0/5.0")
	if len(mus) != 1 || mus[0].Ref != "ge-0/0/5.0.0" || !reflect.DeepEqual(mus[0].Addresses, []string{"10.55.0.1/24"}) {
		t.Fatalf("member ge-0/0/5.0 resolves to %+v, want [{ge-0/0/5.0.0 [10.55.0.1/24]}]", mus)
	}
	if mus := RoutingInstanceMemberUnits(cfg, "ge-0/0/6.0"); len(mus) != 1 || mus[0].Ref != "ge-0/0/6.0" {
		t.Fatalf("undotted control resolves to %+v, want [{ge-0/0/6.0 ...}]", mus)
	}
	// Trailing-dot members bind nothing (no-fallback proof: no legacy
	// reparse, same empty outcome as the old Atoi-failure skip).
	if mus := RoutingInstanceMemberUnits(cfg, "ge-0/0/6."); len(mus) != 0 {
		t.Fatalf("trailing-dot member resolves to %+v, want empty", mus)
	}

	both := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p":   {Name: "p", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.0.1/24"}}}},
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.1.0.1/24"}}}},
	}}}
	mus = RoutingInstanceMemberUnits(both, "p")
	if len(mus) != 1 || !reflect.DeepEqual(mus[0].Addresses, []string{"10.0.0.1/24"}) {
		t.Fatalf("both-declared member p resolves to %+v, want p's unit-0 addresses", mus)
	}
	mus = RoutingInstanceMemberUnits(both, "p.0")
	if len(mus) != 1 || mus[0].Ref != "p.0.0" || !reflect.DeepEqual(mus[0].Addresses, []string{"10.1.0.1/24"}) {
		t.Fatalf("both-declared member p.0 resolves to %+v, want [{p.0.0 [10.1.0.1/24]}]", mus)
	}
}

// TestRibGroupConnectedPrefixesDeclaredDotted9821: the rib-group leak set
// sees a declared-dotted member's unit addresses (previously skipped: the
// reparse hit a nil stanza).
func TestRibGroupConnectedPrefixesDeclaredDotted9821(t *testing.T) {
	cfg := declaredDottedCfg9821()
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "RA", InterfaceRoutesRibGroup: "RG", Interfaces: []string{"ge-0/0/5.0"}},
	}
	got := RibGroupConnectedPrefixes(cfg)["RA"]
	want := []string{"10.55.0.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RibGroupConnectedPrefixes[RA] = %q, want %q", got, want)
	}
}

// TestStrictUnitRefGateDeclaredDotted9821 pins the gate arms directly: RI
// accepts exact-declared and declared-unit refs; CoS accepts exact-declared
// but still rejects double-dot (its binders key exact names); the zone arm
// matches RI (its end-to-end admission is owned by the DEFINED gate).
func TestStrictUnitRefGateDeclaredDotted9821(t *testing.T) {
	withMember := func(ri, zone, cos string) *Config {
		cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}, 1: {Number: 1}}},
		}}}
		if ri != "" {
			cfg.RoutingInstances = []*RoutingInstanceConfig{{Name: "RA", Interfaces: []string{ri}}}
		}
		if zone != "" {
			cfg.Security.Zones = map[string]*ZoneConfig{"z": {Interfaces: []string{zone}}}
		}
		if cos != "" {
			cfg.ClassOfService = &ClassOfServiceConfig{Interfaces: map[string]*CoSInterface{cos: {}}}
		}
		return cfg
	}
	cases := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{"riExactDeclared", withMember("p.0", "", ""), ""},
		{"riDeclaredUnit", withMember("p.0.1", "", ""), ""},
		{"riMalformedStillRejects", withMember("p.0.x", "", ""), "invalid logical unit"},
		{"zoneDeclaredUnit", withMember("", "p.0.1", ""), ""},
		{"cosExactDeclared", withMember("", "", "p.0"), ""},
		{"cosDoubleDotStillRejects", withMember("", "", "p.0.1"), "invalid logical unit"},
		{"cosMalformedStillRejects", withMember("", "", "ge-0/0/0.foo"), "invalid logical unit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInterfaceUnitReferencesStrict(tc.cfg)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("gate rejected: %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("gate accepted, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("gate error %q does not contain %q", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

// TestDeclaredDottedMemberStrictProbe9821 is the issue's probe end to end:
// strict accepts the declared-dotted member with NO "not in interfaces
// config" warning; an undeclared dotted member still warns.
func TestDeclaredDottedMemberStrictProbe9821(t *testing.T) {
	compile := func(t *testing.T, member string) *Config {
		t.Helper()
		tree := vrfTree9809(t, []string{
			"set interfaces ge-0/0/5.0 unit 0 family inet address 10.55.0.1/24",
			"set routing-instances RA instance-type virtual-router",
			"set routing-instances RA interface " + member,
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile with member %q: %v", member, err)
		}
		return cfg
	}
	hasMemberWarning := func(cfg *Config) bool {
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "not in interfaces config") {
				return true
			}
		}
		return false
	}
	if cfg := compile(t, "ge-0/0/5.0"); hasMemberWarning(cfg) {
		t.Errorf("declared member warns: %q", cfg.Warnings)
	}
	if cfg := compile(t, "ge-0/0/9.0"); !hasMemberWarning(cfg) {
		t.Errorf("undeclared member does not warn: %q", cfg.Warnings)
	}
}

// TestZoneMemberStillRejectsSingleDeclaredDotted9821 pins the preserved
// asymmetry: strict zone admission (DEFINED gate) still rejects a dotted
// zone member whose cut base is undeclared, while strict RI accepts the
// same spelling. See the plan's zone disposition: admission preserved,
// runtime made consistent.
func TestZoneMemberStillRejectsSingleDeclaredDotted9821(t *testing.T) {
	tree := vrfTree9809(t, []string{
		"set interfaces ge-0/0/5.0 unit 0 family inet address 10.55.0.1/24",
		"set security zones security-zone z interfaces ge-0/0/5.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile accepted a single-declared dotted zone member")
	}
	if !strings.Contains(err.Error(), "not defined under `interfaces`") {
		t.Fatalf("reject reason %q is not the DEFINED gate", err.Error())
	}
}

// TestVRFOverlapSeesDeclaredDottedMember9821: the overlap detector sees
// prefixes through declared-dotted members (previously invisible: zero
// units resolved, zero prefixes scanned).
func TestVRFOverlapSeesDeclaredDottedMember9821(t *testing.T) {
	warns := vrf2387WarningsWith(t, []string{
		"set interfaces ge-0/0/5.0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/7.0 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/5.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/7.0",
	}, CompileConfig)
	if len(warns) != 1 {
		t.Fatalf("expected exactly one overlap warning, got %d: %v", len(warns), warns)
	}
	for _, want := range []string{`"RI-A"`, `"RI-B"`, "10.0.0.0/24"} {
		if !strings.Contains(warns[0], want) {
			t.Errorf("warning missing %q: %s", want, warns[0])
		}
	}
	// Distinct space: no warning (the overlap gate, not the member shape,
	// decides).
	warns = vrf2387WarningsWith(t, []string{
		"set interfaces ge-0/0/5.0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/7.0 unit 0 family inet address 10.1.0.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/5.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/7.0",
	}, CompileConfig)
	if len(warns) != 0 {
		t.Fatalf("expected no overlap warning, got %v", warns)
	}
}

// TestVRFOverlapPBRTrioDeclaredDotted9821: newly-visible dotted-member
// prefixes trip the pre-existing overlap+PBR hard gate — intended. Without
// PBR the same overlap commits with a warning; lenient admits + records.
func TestVRFOverlapPBRTrioDeclaredDotted9821(t *testing.T) {
	base := []string{
		"set interfaces ge-0/0/5.0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/7.0 unit 0 family inet address 10.0.0.2/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 192.168.1.1/24",
		"set routing-instances RA instance-type virtual-router",
		"set routing-instances RA interface ge-0/0/5.0",
		"set routing-instances RB instance-type virtual-router",
		"set routing-instances RB interface ge-0/0/7.0",
	}
	refused, warnings, admissions := vrfVerdict9809(t, base)
	if refused || warnings != 1 || admissions != 0 {
		t.Fatalf("warn-only: refused=%v warnings=%d admissions=%d, want (false,1,0)", refused, warnings, admissions)
	}
	steered := append(append([]string{}, base...),
		"set firewall family inet filter f term t from source-address 10.9.0.0/16",
		"set firewall family inet filter f term t then routing-instance RA",
		"set firewall family inet filter f term d then accept",
		"set interfaces ge-0/0/1 unit 0 family inet filter input f",
	)
	refused, _, admissions = vrfVerdict9809(t, steered)
	if !refused {
		t.Fatal("overlap+PBR must strict-reject once the overlap is visible")
	}
	if admissions == 0 {
		t.Fatal("lenient path must record the admitted overlap")
	}
}

// TestRoutingInstanceByInterfaceLiteralKeys9821: the NAT scope index keys
// canonical Literals so padded members hit the same key the runtime binds.
func TestRoutingInstanceByInterfaceLiteralKeys9821(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p.0":      {Name: "p.0", Units: map[int]*InterfaceUnit{1: {Number: 1}}},
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{1: {Number: 1}}},
		}},
		RoutingInstances: []*RoutingInstanceConfig{
			{Name: "RA", Interfaces: []string{"p.0.01"}},
			{Name: "RB", Interfaces: []string{"ge-0/0/0.01", "ge-0/0/0"}},
			{Name: "RC", Interfaces: []string{"p.0.1"}},
		},
	}
	got := routingInstanceByInterface(cfg)
	// Padded declared-unit member keys the canonical unit (runtime binds it);
	// first-in-sorted-order wins the normalized collision (RA < RC).
	if got["p.0.1"] != "RA" {
		t.Errorf(`riByIface["p.0.1"] = %q, want "RA"`, got["p.0.1"])
	}
	if _, ok := got["p.0.01"]; ok {
		t.Errorf("raw padded key p.0.01 still indexed: %q", got)
	}
	// Undotted padded: same normalization (fixes a pre-existing miss where
	// the reader probed canonical `ge-0/0/0.1` but the map held `ge-0/0/0.01`).
	if got["ge-0/0/0.1"] != "RB" {
		t.Errorf(`riByIface["ge-0/0/0.1"] = %q, want "RB"`, got["ge-0/0/0.1"])
	}
	if got["ge-0/0/0"] != "RB" {
		t.Errorf(`riByIface["ge-0/0/0"] = %q, want "RB"`, got["ge-0/0/0"])
	}
}
