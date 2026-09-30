package config

import (
	"strings"
	"testing"
)

func TestBGPRouterASMissingIsRejectedAndWarned11313(t *testing.T) {
	cases := []struct {
		name       string
		commands   []string
		wantScope  string
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
