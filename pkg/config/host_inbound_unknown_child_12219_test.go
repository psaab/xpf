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
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "system-service") {
				t.Fatalf("strict compile error = %v, want rejection naming system-service", err)
			}

			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var warning string
			for _, got := range cfg.Warnings {
				if strings.Contains(got, "unknown child keyword") && strings.Contains(got, "system-service") {
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
                system-service ssh;
            }
            host-inbound-traffic {
                system-services ping;
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
