package config

import (
	"reflect"
	"strings"
	"testing"
)

func mixed10521Config(withOrdinary bool) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"fxp0": {
			Name: "fxp0",
			Units: map[int]*InterfaceUnit{
				0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
			},
		},
	}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"mgmt": {
			Name:               "mgmt",
			Interfaces:         []string{"fxp0.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	if withOrdinary {
		cfg.Interfaces.Interfaces["ge-0/0/1"] = &InterfaceConfig{
			Name: "ge-0/0/1",
			Units: map[int]*InterfaceUnit{
				0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
			},
		}
		cfg.Security.Zones["untrust"] = &ZoneConfig{
			Name:               "untrust",
			Interfaces:         []string{"ge-0/0/1.0"},
			HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
		}
	}
	return cfg
}

func mixed10521Deny(name string) *Policy {
	return &Policy{
		Name:   name,
		Action: PolicyDeny,
		Match: PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"any"},
		},
	}
}

func mixed10521GlobalDeny(name string) *Policy {
	p := mixed10521Deny(name)
	p.Match.ToZones = []string{"junos-host"}
	return p
}

func mixed10521Warning(cfg *Config) []string {
	return validateJunosHostDirectDeliveryWarnings(cfg)
}

func assertMixed10521LifelineProgram(t *testing.T, proj JunosHostDenyProjection) {
	t.Helper()
	for _, p := range proj.Programs {
		if p.Zone != "mgmt" {
			continue
		}
		if p.Representable || len(p.IngressNetdevs) != 0 || len(p.RulesV4) != 0 || len(p.RulesV6) != 0 {
			t.Fatalf("lifeline-only mgmt program must be an empty non-representable stub: %+v", p)
		}
		return
	}
	t.Fatalf("projection omitted lifeline-only mgmt stub: %+v", proj.Programs)
}

// TestJunosHostLifelineMixedGlobal10521 pins Option A for a global DENY. The
// ordinary sibling still renders and is recorded per zone, but the shared key
// also applies to mgmt where fxp0 is intentionally never scoped, so exactly one
// direct-delivery warning remains and names mgmt.
func TestJunosHostLifelineMixedGlobal10521(t *testing.T) {
	const name = "global-block"
	key := JunosHostGlobalPolicyKey(name)

	for _, tc := range []struct {
		name          string
		withOrdinary  bool
		wantRendered  bool
		wantZones     map[string]bool
		wantLifelines []string
		wantWarnings  int
	}{
		{
			name:          "arm A lifeline only",
			withOrdinary:  false,
			wantRendered:  false,
			wantLifelines: []string{"mgmt"},
			wantWarnings:  1,
		},
		{
			name:          "arm B ordinary sibling",
			withOrdinary:  true,
			wantRendered:  true,
			wantZones:     map[string]bool{"untrust": true},
			wantLifelines: []string{"mgmt"},
			wantWarnings:  1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mixed10521Config(tc.withOrdinary)
			cfg.Security.GlobalPolicies = []*Policy{mixed10521GlobalDeny(name)}
			proj := BuildJunosHostDenyProjection(cfg)
			if got := proj.RenderedPolicyKeys[key]; got != tc.wantRendered {
				t.Fatalf("RenderedPolicyKeys[%q] = %v, want %v: %+v", key, got, tc.wantRendered, proj.RenderedPolicyKeys)
			}
			if tc.wantZones == nil {
				if _, ok := proj.RenderedPolicyZoneKeys[key]; ok {
					t.Fatalf("lifeline-only arm must not have rendered zones: %+v", proj.RenderedPolicyZoneKeys)
				}
			} else if !reflect.DeepEqual(proj.RenderedPolicyZoneKeys[key], tc.wantZones) {
				t.Fatalf("RenderedPolicyZoneKeys[%q] = %v, want %v", key, proj.RenderedPolicyZoneKeys[key], tc.wantZones)
			}
			if !reflect.DeepEqual(proj.LifelineOnlyZones[key], tc.wantLifelines) {
				t.Fatalf("LifelineOnlyZones[%q] = %v, want %v", key, proj.LifelineOnlyZones[key], tc.wantLifelines)
			}
			assertMixed10521LifelineProgram(t, proj)
			warnings := mixed10521Warning(cfg)
			if len(warnings) != tc.wantWarnings {
				t.Fatalf("want %d direct-delivery warning(s), got %d: %v", tc.wantWarnings, len(warnings), warnings)
			}
			if !strings.Contains(warnings[0], `"mgmt"`) {
				t.Fatalf("warning must name uncovered lifeline zone mgmt: %v", warnings[0])
			}
			if tc.withOrdinary && (!strings.Contains(warnings[0], "ordinary zone") || !strings.Contains(warnings[0], "lifeline NEVER-deny")) {
				t.Fatalf("mixed warning must explain ordinary coverage and lifeline exemption: %v", warnings[0])
			}
			if tc.withOrdinary && !strings.Contains(warnings[0], "). The kernel rule is enforced") {
				t.Fatalf("mixed warning must append a standalone coverage sentence: %v", warnings[0])
			}
		})
	}
}

// TestJunosHostLifelineMixedFromAny10521 is the same coverage split for the
// from-zone any key. The policy is shared across zones, so one ordinary render
// must not silence the uncovered lifeline warning.
func TestJunosHostLifelineMixedFromAny10521(t *testing.T) {
	const name = "any-block"
	key := JunosHostZonePairPolicyKey("any", name)
	t.Run("arm A lifeline only", func(t *testing.T) {
		cfg := mixed10521Config(false)
		cfg.Security.Policies = []*ZonePairPolicies{{
			FromZone: "any",
			ToZone:   "junos-host",
			Policies: []*Policy{mixed10521Deny(name)},
		}}
		proj := BuildJunosHostDenyProjection(cfg)
		if proj.RenderedPolicyKeys[key] {
			t.Fatalf("lifeline-only from-zone any key must not be rendered: %+v", proj.RenderedPolicyKeys)
		}
		if want := []string{"mgmt"}; !reflect.DeepEqual(proj.LifelineOnlyZones[key], want) {
			t.Fatalf("LifelineOnlyZones[%q] = %v, want %v", key, proj.LifelineOnlyZones[key], want)
		}
		assertMixed10521LifelineProgram(t, proj)
		warnings := mixed10521Warning(cfg)
		if len(warnings) != 1 || !strings.Contains(warnings[0], `"mgmt"`) {
			t.Fatalf("lifeline-only from-zone any policy must warn once for mgmt: %v", warnings)
		}
	})

	cfg := mixed10521Config(true)
	cfg.Security.Policies = []*ZonePairPolicies{{
		FromZone: "any",
		ToZone:   "junos-host",
		Policies: []*Policy{mixed10521Deny(name)},
	}}
	proj := BuildJunosHostDenyProjection(cfg)
	if !proj.RenderedPolicyKeys[key] {
		t.Fatalf("from-zone any key must remain rendered on untrust: %+v", proj.RenderedPolicyKeys)
	}
	if want := map[string]bool{"untrust": true}; !reflect.DeepEqual(proj.RenderedPolicyZoneKeys[key], want) {
		t.Fatalf("RenderedPolicyZoneKeys[%q] = %v, want %v", key, proj.RenderedPolicyZoneKeys[key], want)
	}
	if want := []string{"mgmt"}; !reflect.DeepEqual(proj.LifelineOnlyZones[key], want) {
		t.Fatalf("LifelineOnlyZones[%q] = %v, want %v", key, proj.LifelineOnlyZones[key], want)
	}
	warnings := mixed10521Warning(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], `"mgmt"`) {
		t.Fatalf("from-zone any mixed policy must retain one mgmt warning: %v", warnings)
	}
}

// TestJunosHostLifelineMixedGlobalPermit10521 pins the coverage suffix on the
// application-restricted permit path. The ordinary sibling has an https coarse
// admit outside the junos-ssh permit, while the lifeline remains uncovered.
func TestJunosHostLifelineMixedGlobalPermit10521(t *testing.T) {
	cfg := mixed10521Config(true)
	for _, zoneName := range []string{"mgmt", "untrust"} {
		cfg.Security.Zones[zoneName].HostInboundTraffic = &HostInboundTraffic{
			SystemServices: []string{"ssh", "https"},
		}
	}
	const name = "global-permit"
	cfg.Security.GlobalPolicies = []*Policy{{
		Name:   name,
		Action: PolicyPermit,
		Match: PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"junos-ssh"},
			ToZones:              []string{"junos-host"},
		},
	}}

	key := JunosHostGlobalPolicyKey(name)
	proj := BuildJunosHostDenyProjection(cfg)
	if got := proj.LifelineOnlyZones[key]; !reflect.DeepEqual(got, []string{"mgmt"}) {
		t.Errorf("permit LifelineOnlyZones[%q] = %v, want [mgmt]", key, got)
	}
	if got := mixed10521Warning(cfg); len(got) != 1 || !strings.Contains(got[0], `"mgmt"`) {
		t.Fatalf("mixed global permit must warn once naming mgmt: %v", got)
	}
}

// TestJunosHostLifelinePerZoneControls10521 prevents the shared-key fix from
// changing ordinary per-zone behavior: a lifeline-only exact zone warns, a
// rendered ordinary exact zone suppresses, and the two warnings do not merge.
func TestJunosHostLifelinePerZoneControls10521(t *testing.T) {
	const name = "zone-block"
	t.Run("mgmt-only retains warning", func(t *testing.T) {
		cfg := mixed10521Config(true)
		cfg.Security.Policies = []*ZonePairPolicies{{
			FromZone: "mgmt",
			ToZone:   "junos-host",
			Policies: []*Policy{mixed10521Deny(name)},
		}}
		key := JunosHostZonePairPolicyKey("mgmt", name)
		proj := BuildJunosHostDenyProjection(cfg)
		if proj.RenderedPolicyKeys[key] {
			t.Fatalf("lifeline-only exact zone must not be rendered: %+v", proj.RenderedPolicyKeys)
		}
		if want := []string{"mgmt"}; !reflect.DeepEqual(proj.LifelineOnlyZones[key], want) {
			t.Fatalf("LifelineOnlyZones[%q] = %v, want %v", key, proj.LifelineOnlyZones[key], want)
		}
		if got := mixed10521Warning(cfg); len(got) != 1 || !strings.Contains(got[0], `from-zone "mgmt"`) {
			t.Fatalf("mgmt exact policy must retain one warning: %v", got)
		}
	})

	t.Run("dual exact zones warn only mgmt", func(t *testing.T) {
		cfg := mixed10521Config(true)
		cfg.Security.Policies = []*ZonePairPolicies{
			{FromZone: "mgmt", ToZone: "junos-host", Policies: []*Policy{mixed10521Deny(name)}},
			{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{mixed10521Deny(name)}},
		}
		mgmtKey := JunosHostZonePairPolicyKey("mgmt", name)
		untrustKey := JunosHostZonePairPolicyKey("untrust", name)
		proj := BuildJunosHostDenyProjection(cfg)
		if proj.RenderedPolicyKeys[mgmtKey] || !proj.RenderedPolicyKeys[untrustKey] {
			t.Fatalf("dual exact zones have wrong rendered keys: %+v", proj.RenderedPolicyKeys)
		}
		if want := map[string]bool{"untrust": true}; !reflect.DeepEqual(proj.RenderedPolicyZoneKeys[untrustKey], want) {
			t.Fatalf("ordinary exact zone map = %v, want %v", proj.RenderedPolicyZoneKeys[untrustKey], want)
		}
		warnings := mixed10521Warning(cfg)
		if len(warnings) != 1 || !strings.Contains(warnings[0], `from-zone "mgmt"`) || strings.Contains(warnings[0], `from-zone "untrust"`) {
			t.Fatalf("dual exact zones must warn only for mgmt: %v", warnings)
		}
	})
}

// TestJunosHostLifelineZonesAreSorted10521 pins deterministic uncovered-zone
// naming when one shared policy applies to multiple lifeline-only zones.
func TestJunosHostLifelineZonesAreSorted10521(t *testing.T) {
	cfg := mixed10521Config(true)
	cfg.Interfaces.Interfaces["em0"] = &InterfaceConfig{
		Name: "em0",
		Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"203.0.113.1/24"}},
		},
	}
	cfg.Security.Zones["aaa"] = &ZoneConfig{
		Name:               "aaa",
		Interfaces:         []string{"em0.0"},
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	cfg.Security.GlobalPolicies = []*Policy{mixed10521GlobalDeny("sorted-global")}

	key := JunosHostGlobalPolicyKey("sorted-global")
	proj := BuildJunosHostDenyProjection(cfg)
	if want := []string{"aaa", "mgmt"}; !reflect.DeepEqual(proj.LifelineOnlyZones[key], want) {
		t.Fatalf("LifelineOnlyZones[%q] = %v, want %v", key, proj.LifelineOnlyZones[key], want)
	}
	warnings := mixed10521Warning(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], `{"aaa", "mgmt"}`) {
		t.Fatalf("shared warning must name sorted uncovered zones once: %v", warnings)
	}
}

// TestJunosHostNoInterfaceDoesNotRetainLifelineWarning10521 guards the
// no-interface case separately: it has no ingress path and is not a
// lifeline-only applicability. A shared global policy must remain suppressible
// when its ordinary sibling is fully enforced.
func TestJunosHostNoInterfaceDoesNotRetainLifelineWarning10521(t *testing.T) {
	cfg := mixed10521Config(true)
	delete(cfg.Security.Zones, "mgmt")
	delete(cfg.Interfaces.Interfaces, "fxp0")
	cfg.Security.Zones["empty"] = &ZoneConfig{
		Name:               "empty",
		HostInboundTraffic: &HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	cfg.Security.GlobalPolicies = []*Policy{mixed10521GlobalDeny("no-interface")}
	key := JunosHostGlobalPolicyKey("no-interface")
	proj := BuildJunosHostDenyProjection(cfg)
	if got := proj.LifelineOnlyZones[key]; len(got) != 0 {
		t.Fatalf("no-interface zone must not be recorded as lifeline-only: %v", got)
	}
	if got := mixed10521Warning(cfg); len(got) != 0 {
		t.Fatalf("no-interface zone must not retain a shared warning: %v", got)
	}
}
