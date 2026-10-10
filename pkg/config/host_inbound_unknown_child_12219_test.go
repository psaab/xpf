package config

import (
	"strings"
	"testing"
)

func TestHostInboundUnknownInnerChildrenWarn12219(t *testing.T) {
	cases := []struct {
		name              string
		commands          []string
		wantScope         string
		wantEmptyOverride bool
	}{
		{
			name: "zone stanza",
			commands: []string{
				"set security zones security-zone trust host-inbound-traffic system-service ssh",
			},
			wantScope: `security zone "trust" host-inbound-traffic`,
		},
		{
			name: "per-interface stanza replaces with deny-all",
			commands: []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set security zones security-zone trust host-inbound-traffic system-services ssh",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-service ssh",
			},
			wantEmptyOverride: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.commands)
			_, strictErr := CompileConfig(tree)
			if strictErr == nil {
				t.Fatal("strict compile accepted an unknown host-inbound child")
			}
			if tc.wantEmptyOverride {
				if !strings.Contains(strictErr.Error(), zoneInterfacePackedTailReason) {
					t.Fatalf("strict error = %v, want the earlier #6735 packed-tail rejection", strictErr)
				}
			} else if !strings.Contains(strictErr.Error(), `unknown child keyword "system-service"`) {
				t.Fatalf("strict compile error = %v, want rejection naming the exact unknown child", strictErr)
			}

			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var warning string
			for _, got := range cfg.Warnings {
				if strings.Contains(got, `unknown child keyword "system-service"`) {
					warning = got
					break
				}
			}
			if warning == "" {
				t.Fatalf("warnings %v do not record the discarded system-service child", cfg.Warnings)
			}
			if !strings.Contains(warning, tc.wantScope) {
				t.Fatalf("warning %q does not identify scope %q", warning, tc.wantScope)
			}
			if tc.wantEmptyOverride {
				if !strings.Contains(warning, "no recognized admission remains") || !strings.Contains(warning, "replaces zone admission with deny-all") {
					t.Fatalf("warning %q does not explain the empty override's deny-all effect", warning)
				}
				zone := cfg.Security.Zones["trust"]
				if svc, proto, overridden := zone.InterfaceHostInboundEffective("ge-0/0/0.0"); !overridden || len(svc) != 0 || len(proto) != 0 {
					t.Fatalf("effective per-interface view = (%v, %v, overridden=%v), want diagnosed deny-all override", svc, proto, overridden)
				}
			}
		})
	}
}

func TestHostInboundUnknownChildSurvivesRepeatedBlocks12219(t *testing.T) {
	tree, parseErrs := NewParser(`security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-services ping;
            }
            host-inbound-traffic {
                system-service ssh;
            }
        }
    }
}`).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse: %v", parseErrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if got := zone.HostInboundTraffic.SystemServices; len(got) != 1 || got[0] != "ping" {
		t.Fatalf("repeated blocks services = %v, want [ping]", got)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, `unknown child keyword "system-service"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("repeated blocks lost unknown-child warning: %v", cfg.Warnings)
	}
}

func TestHostInboundUnknownCompactKeyTailsWarn12219(t *testing.T) {
	cases := []struct {
		name          string
		config        string
		wantKeyword   string
		wantProtocols []string
	}{
		{
			name: "unknown service child",
			config: `security { zones { security-zone trust {
				host-inbound-traffic system-service ssh;
			} } }`,
			wantKeyword: "system-service",
		},
		{
			name: "unknown protocol child",
			config: `security { zones { security-zone trust {
				host-inbound-traffic protocol ospf;
			} } }`,
			wantKeyword: "protocol",
		},
		{
			name: "unknown compact child with recognized body",
			config: `security { zones { security-zone trust {
				host-inbound-traffic system-service ssh { protocols ospf; }
			} } }`,
			wantKeyword:   "system-service",
			wantProtocols: []string{"ospf"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierarchical(t, tc.config)
			_, strictErr := CompileConfig(tree)
			if strictErr == nil || !strings.Contains(strictErr.Error(), `unknown child keyword "`+tc.wantKeyword+`"`) {
				t.Fatalf("strict compile error = %v, want unknown child %q", strictErr, tc.wantKeyword)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			hib := cfg.Security.Zones["trust"].HostInboundTraffic
			if len(hib.UnknownChildren) != 1 || hib.UnknownChildren[0] != tc.wantKeyword {
				t.Fatalf("unknown children = %v, want [%s]", hib.UnknownChildren, tc.wantKeyword)
			}
			if len(hib.Protocols) != len(tc.wantProtocols) {
				t.Fatalf("protocols = %v, want %v", hib.Protocols, tc.wantProtocols)
			}
			for i, want := range tc.wantProtocols {
				if hib.Protocols[i] != want {
					t.Fatalf("protocols = %v, want %v", hib.Protocols, tc.wantProtocols)
				}
			}
			if !hasWarning(cfg.Warnings, `unknown child keyword "`+tc.wantKeyword+`"`) {
				t.Fatalf("warnings %v do not name unknown child %q", cfg.Warnings, tc.wantKeyword)
			}
		})
	}
}

func TestHostInboundKnownPackedTailsAndBracketListsStillBind12219(t *testing.T) {
	cases := []struct {
		name         string
		config       string
		interfaceRef string
		wantServices []string
		wantProtocol []string
	}{
		{
			name: "zone packed service",
			config: `security { zones { security-zone trust {
				host-inbound-traffic system-services ssh;
			} } }`,
			wantServices: []string{"ssh"},
		},
		{
			name: "per-interface packed service",
			config: `security { zones { security-zone trust {
				interfaces { ge-0/0/0.0 {
					host-inbound-traffic system-services ssh;
				} }
			} } }`,
			interfaceRef: "ge-0/0/0.0",
			wantServices: []string{"ssh"},
		},
		{
			name: "bracket lists",
			config: `security { zones { security-zone trust {
				host-inbound-traffic system-services [ ssh ping ];
				host-inbound-traffic protocols [ ospf bgp ];
			} } }`,
			wantServices: []string{"ssh", "ping"},
			wantProtocol: []string{"ospf", "bgp"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(parseHierarchical(t, tc.config))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			zone := cfg.Security.Zones["trust"]
			hib := zone.HostInboundTraffic
			if tc.interfaceRef != "" {
				hib = zone.InterfaceHostInbound[tc.interfaceRef]
			}
			if hib == nil {
				t.Fatal("host-inbound stanza was not compiled")
			}
			if len(hib.UnknownChildren) != 0 {
				t.Fatalf("known packed body was misclassified as unknown: %v", hib.UnknownChildren)
			}
			if strings.Join(hib.SystemServices, ",") != strings.Join(tc.wantServices, ",") {
				t.Fatalf("system services = %v, want %v", hib.SystemServices, tc.wantServices)
			}
			if strings.Join(hib.Protocols, ",") != strings.Join(tc.wantProtocol, ",") {
				t.Fatalf("protocols = %v, want %v", hib.Protocols, tc.wantProtocol)
			}
		})
	}
}

func TestHostInboundUnknownChildDenyAllClaimUsesEffectiveOverride12219(t *testing.T) {
	cases := []struct {
		name   string
		config string
		want   string
	}{
		{
			name: "physical and unit overrides union",
			config: `interfaces { ge-0/0/0 {
				unit 0 { family inet { address 10.0.0.1/24; } }
			} }
			security { zones { security-zone trust {
				host-inbound-traffic { system-services ping; }
				interfaces {
					ge-0/0/0 { host-inbound-traffic { system-services ssh; } }
					ge-0/0/0.0 { host-inbound-traffic { system-service ping; } }
				}
			} } }`,
			want: "ssh",
		},
		{
			name: "uppercase recognized service",
			config: `interfaces { ge-0/0/0 {
				unit 0 { family inet { address 10.0.0.1/24; } }
			} }
			security { zones { security-zone trust {
				host-inbound-traffic { system-services dns; }
				interfaces { ge-0/0/0.0 {
					host-inbound-traffic {
						system-services SSH;
						system-service ping;
					}
				} }
			} } }`,
			want: "SSH",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(parseHierarchical(t, tc.config))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var warning string
			for _, got := range cfg.Warnings {
				if strings.Contains(got, `interfaces "ge-0/0/0.0"`) &&
					strings.Contains(got, `unknown child keyword "system-service"`) {
					warning = got
					break
				}
			}
			if warning == "" {
				t.Fatalf("warnings %v do not name the per-interface unknown child", cfg.Warnings)
			}
			if strings.Contains(warning, "deny-all") {
				t.Fatalf("warning falsely claims the effective override is deny-all: %q", warning)
			}
			zone := cfg.Security.Zones["trust"]
			svc, proto, overridden := zone.InterfaceHostInboundEffective("ge-0/0/0.0")
			if !overridden || len(svc) != 1 || svc[0] != tc.want || len(proto) != 0 {
				t.Fatalf("effective override = (%v, %v, overridden=%v), want ([%s], [], true)", svc, proto, overridden, tc.want)
			}
		})
	}
}

func hasWarning(warnings []string, text string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, text) {
			return true
		}
	}
	return false
}
