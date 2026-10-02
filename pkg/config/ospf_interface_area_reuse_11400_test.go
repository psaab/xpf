package config

import (
	"strings"
	"testing"
)

func TestOSPFAreaInterfaceReuseRejected11400(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "ospfv2 global",
			cmds: []string{
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
				"set protocols ospf area 0.0.0.1 interface ge-0/0/1.0",
			},
			want: "OSPF",
		},
		{
			name: "ospfv3 global",
			cmds: []string{
				"set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0",
				"set protocols ospf3 area 0.0.0.1 interface ge-0/0/1.0",
			},
			want: "OSPFv3",
		},
		{
			name: "resolved aliases in a routing instance",
			cmds: []string{
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
				"set routing-instances blue protocols ospf area 0.0.0.1 interface ge-0-0-1.0",
			},
			want: "routing-instances \"blue\"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.cmds))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "multiple areas") {
				t.Fatalf("strict compile error = %v, want a cross-area interface diagnostic containing %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "ge-0-0-1") {
				t.Fatalf("diagnostic does not name the resolved Linux interface: %v", err)
			}
		})
	}
}

func TestOSPFAreaInterfaceReuseLenientWarns11400(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0",
		"set protocols ospf3 area 0.0.0.1 interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("lenient compile rejected an existing cross-area interface: %v", err)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "OSPF interface area membership") &&
			strings.Contains(warning, "OSPFv3") && strings.Contains(warning, "multiple areas") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile did not warn about OSPFv3 cross-area membership: %v", cfg.Warnings)
	}
	if cfg.Protocols.OSPFv3 == nil || len(cfg.Protocols.OSPFv3.Areas) != 2 {
		t.Fatalf("lenient compile must preserve the configured areas for readback: %+v", cfg.Protocols.OSPFv3)
	}
}

func TestOSPFAreaInterfaceReuseEquivalentIDsAccepted11400(t *testing.T) {
	_, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 1 interface ge-0/0/1.0",
		"set protocols ospf area 0.0.0.1 interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("equivalent integer and dotted-quad spellings of area 1 are one area: %v", err)
	}
}
