package config

import "testing"

const crossScopeExceptUnit12317 = "ge-0/0/0.0"

func compileCrossScopeExcept12317(t *testing.T, lenient bool, directives ...string) *Config {
	t.Helper()
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	}
	lines = append(lines, directives...)
	tree := flat10292(t, lines...)
	var cfg *Config
	var err error
	if lenient {
		cfg, err = CompileConfigLenient(tree)
	} else {
		cfg, err = CompileConfig(tree)
	}
	if err != nil {
		t.Fatalf("compile (lenient=%t): %v", lenient, err)
	}
	return cfg
}

func assertExceptSSHPorts12317(t *testing.T, services []string, wantSSH, wantNetconf, wantHTTP bool) {
	t.Helper()
	for _, family := range []string{"ip", "ip6"} {
		tuples := hostInboundAdmissionTupleSet12053(services, family)
		_, hasSSH := tuples[hostInboundTupleKey12053{proto: 6, port: 22, portSet: true}]
		_, hasNetconf := tuples[hostInboundTupleKey12053{proto: 6, port: 830, portSet: true}]
		_, hasHTTP := tuples[hostInboundTupleKey12053{proto: 6, port: 80, portSet: true}]
		if hasSSH != wantSSH || hasNetconf != wantNetconf || hasHTTP != wantHTTP {
			t.Errorf("services %v tuples on %s include ssh:22=%t netconf:830=%t http:80=%t; want %t,%t,%t",
				services, family, hasSSH, hasNetconf, hasHTTP, wantSSH, wantNetconf, wantHTTP)
		}
	}
}

func TestHostInboundCrossScopeExceptAliasUnion12317(t *testing.T) {
	cases := []struct {
		name       string
		directives []string
	}{
		{
			name: "physical-alias-unit-exclusion",
			directives: []string{
				"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services netconf-ssh",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services all",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh except",
			},
		},
		{
			name: "physical-exclusion-unit-alias",
			directives: []string{
				"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services all",
				"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh except",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services netconf-ssh",
			},
		},
	}
	for _, lenient := range []bool{false, true} {
		mode := "strict"
		if lenient {
			mode = "lenient"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					cfg := compileCrossScopeExcept12317(t, lenient, tc.directives...)
					effective := ResolveInterfaceHostInbound(cfg)[crossScopeExceptUnit12317]
					if effective == nil {
						t.Fatalf("no effective host-inbound override for %s", crossScopeExceptUnit12317)
					}
					assertExceptSSHPorts12317(t, effective.SystemServices, false, true, true)
					gate := buildHostInboundOverrideMapLocal(cfg)[crossScopeExceptUnit12317]
					if gate == nil {
						t.Fatalf("duplicate-address gate has no override for %s", crossScopeExceptUnit12317)
					}
					assertExceptSSHPorts12317(t, gate.SystemServices, false, true, true)
				})
			}
		})
	}
}

func TestHostInboundZoneAndInterfaceExceptRemainSeparate12317(t *testing.T) {
	cases := []struct {
		name              string
		directives        []string
		wantSSH, wantHTTP bool
	}{
		{
			name: "zone-exclusion-does-not-filter-replacing-interface-alias",
			directives: []string{
				"set security zones security-zone trust host-inbound-traffic system-services all",
				"set security zones security-zone trust host-inbound-traffic system-services ssh except",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services netconf-ssh",
			},
			wantSSH:  true,
			wantHTTP: false,
		},
		{
			name: "interface-exclusion-filters-alias-and-replaces-zone",
			directives: []string{
				"set security zones security-zone trust host-inbound-traffic system-services netconf-ssh",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services all",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh except",
			},
			wantSSH:  false,
			wantHTTP: true,
		},
	}
	for _, lenient := range []bool{false, true} {
		mode := "strict"
		if lenient {
			mode = "lenient"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					cfg := compileCrossScopeExcept12317(t, lenient, tc.directives...)
					zone := cfg.Security.Zones["trust"]
					services, _, overridden := zone.InterfaceHostInboundEffective(crossScopeExceptUnit12317)
					if !overridden {
						t.Fatal("unit must have a replacing interface-level stanza")
					}
					assertExceptSSHPorts12317(t, services, tc.wantSSH, true, tc.wantHTTP)
				})
			}
		})
	}
}

func TestHostInboundCrossScopeExceptLegacyOverride12317(t *testing.T) {
	zone := &ZoneConfig{InterfaceHostInbound: map[string]*HostInboundTraffic{
		"ge-0/0/0": {
			SystemServices: []string{"netconf-ssh"},
		},
		"ge-0/0/0.0": {
			SystemServices:       hostInboundFilterExcept(HostInboundAllExpansionServices(), []string{"ssh"}, false),
			systemServicesExcept: []string{"ssh"},
		},
	}}
	services, _, declared := zone.InterfaceHostInboundOverride(crossScopeExceptUnit12317)
	if !declared {
		t.Fatal("hand-built zone lost its physical/unit override")
	}
	assertExceptSSHPorts12317(t, services, false, true, true)
}

func TestHostInboundSingleStanzaExceptControl12317(t *testing.T) {
	for _, lenient := range []bool{false, true} {
		mode := "strict"
		if lenient {
			mode = "lenient"
		}
		t.Run(mode, func(t *testing.T) {
			cfg := compileCrossScopeExcept12317(t, lenient,
				"set security zones security-zone trust host-inbound-traffic system-services all",
				"set security zones security-zone trust host-inbound-traffic system-services ssh except",
			)
			services := cfg.Security.Zones["trust"].HostInboundTraffic.SystemServices
			assertExceptSSHPorts12317(t, services, false, true, true)
		})
	}
}
