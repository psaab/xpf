package config

import (
	"strings"
	"testing"
)

func TestBGPRouterASMissingIsRejectedAndWarned11313(t *testing.T) {
	cases := []struct {
		name      string
		commands  []string
		wantScope string
	}{
		{
			name: "global BGP with inherited peer-as but no router AS",
			commands: []string{
				"set protocols bgp group G peer-as 65002",
				"set protocols bgp group G neighbor 10.0.0.2",
			},
		},
		{
			name: "global BGP stanza without neighbors",
			commands: []string{
				"set protocols bgp graceful-restart",
			},
		},
		{
			name: "routing-instance BGP without router AS",
			commands: []string{
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 protocols bgp group G peer-as 65002",
				"set routing-instances VR1 protocols bgp group G neighbor 10.1.0.2",
			},
			wantScope: "routing-instance VR1",
		},
		{
			name: "group local-as is not a router AS",
			commands: []string{
				"set protocols bgp group G local-as 65001",
				"set protocols bgp group G peer-as 65002",
				"set protocols bgp group G neighbor 10.0.0.2",
			},
		},
		{
			name: "neighbor local-as is not a router AS",
			commands: []string{
				"set protocols bgp group G peer-as 65002",
				"set protocols bgp group G neighbor 10.0.0.2 local-as 65001",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTreeFromSet(t, tc.commands))
			if err == nil {
				t.Fatal("strict compile accepted a BGP stanza with no effective router AS")
			}
			for _, want := range []string{"protocols bgp", "missing router AS", "local-as", "autonomous-system", tc.wantScope} {
				if want != "" && !strings.Contains(err.Error(), want) {
					t.Errorf("strict error %q omits %q", err, want)
				}
			}

			cfg, err := CompileConfigLenient(buildTreeFromSet(t, tc.commands))
			if err != nil {
				t.Fatalf("tolerant compile must preserve loadability: %v", err)
			}
			var warning string
			for _, candidate := range cfg.Warnings {
				if strings.Contains(candidate, "BGP router AS") {
					warning = candidate
					break
				}
			}
			if warning == "" {
				t.Fatalf("tolerant compile accepted missing router AS silently; warnings=%v", cfg.Warnings)
			}
			for _, want := range []string{"missing router AS", "local-as", "autonomous-system", tc.wantScope} {
				if want != "" && !strings.Contains(warning, want) {
					t.Errorf("warning %q omits %q", warning, want)
				}
			}
		})
	}
}

func TestBGPRouterASDoesNotStealManagementDiagnosticPriority11313(t *testing.T) {
	build := func() *ConfigTree {
		return buildTree(t, []string{
			"set interfaces fxp0 unit 0 family inet address 192.0.2.1/24",
			"set routing-instances blue instance-type virtual-router",
			"set routing-instances blue interface fxp0.0",
			"set protocols bgp group G peer-as 65002",
			"set protocols bgp group G neighbor 10.0.0.2",
		})
	}

	_, err := CompileConfig(build())
	if err == nil || !strings.Contains(err.Error(), "#11392") ||
		strings.Contains(err.Error(), "missing router AS") {
		t.Fatalf("strict diagnostic = %v, want the #11392 management error before missing router AS", err)
	}

	cfg, err := CompileConfigLenient(build())
	if err != nil {
		t.Fatalf("tolerant compile must preserve loadability: %v", err)
	}
	managementWarning, bgpWarning := -1, -1
	for i, warning := range cfg.Warnings {
		if strings.Contains(warning, "management-class routing-instance interface membership") {
			managementWarning = i
		}
		if strings.Contains(warning, "BGP router AS") {
			bgpWarning = i
		}
	}
	if managementWarning < 0 || bgpWarning < 0 {
		t.Fatalf("both tail-gate warnings must be present: %v", cfg.Warnings)
	}
	if managementWarning >= bgpWarning {
		t.Fatalf("warning order = %v, want #11392 before BGP router-AS warning", cfg.Warnings)
	}
}
