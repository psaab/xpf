package config

import (
	"strings"
	"testing"
)

func managementRIMemberTree11392(t *testing.T, iface, member string) *ConfigTree {
	t.Helper()
	return buildTree(t, []string{
		"set interfaces " + iface + " unit 0 family inet address 192.0.2.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface " + member,
	})
}

func TestManagementClassRIMemberRejectedOnCommit11392(t *testing.T) {
	for _, tc := range []struct{ iface, member string }{
		{iface: "fxp0", member: "fxp0.0"},
		{iface: "fab0", member: "fab0.0"},
		{iface: "em0", member: "em0.0"},
	} {
		t.Run(tc.iface, func(t *testing.T) {
			_, err := CompileConfig(managementRIMemberTree11392(t, tc.iface, tc.member))
			if err == nil {
				t.Fatalf("strict commit accepted management-class RI member %s", tc.member)
			}
			for _, want := range []string{"blue", tc.member, tc.iface, "management", "#11392"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("rejection %q omits %q", err, want)
				}
			}
		})
	}
}

func TestManagementClassRIMemberWarnsOnTolerantPath11392(t *testing.T) {
	cfg, err := CompileConfigLenient(managementRIMemberTree11392(t, "fxp0", "fxp0.0"))
	if err != nil {
		t.Fatalf("tolerant load must keep the existing config bootable: %v", err)
	}
	var warning string
	for _, got := range cfg.Warnings {
		if strings.Contains(got, "management-class routing-instance interface membership") {
			warning = got
			break
		}
	}
	if warning == "" {
		t.Fatalf("tolerant compile accepted management member silently: %v", cfg.Warnings)
	}
	for _, want := range []string{"blue", "fxp0.0", "fxp0", "vrf-mgmt", "#11392"} {
		if !strings.Contains(warning, want) {
			t.Errorf("warning %q omits %q", warning, want)
		}
	}
	if got := cfg.RoutingInstances[0].Interfaces; len(got) != 0 {
		t.Fatalf("tolerant compile exposed management-class member to consumers: %v", got)
	}
}

func TestOrdinaryRIMemberStillPassesManagementGate11392(t *testing.T) {
	if _, err := CompileConfig(managementRIMemberTree11392(t, "ge-0/0/1", "ge-0/0/1.0")); err != nil {
		t.Fatalf("ordinary virtual-router member must remain valid: %v", err)
	}
}

func TestManagementClassRIMemberQuarantinePreservesUnaffectedFanout11392(t *testing.T) {
	for _, tc := range []struct {
		name        string
		iface       string
		tunnelName  string
		wantMembers []string
		wantKeys    map[string]string
		wantClaim   *RoutingInstanceMemberPrimaryClaim
	}{
		{
			name:        "management primary keeps ordinary fanout",
			iface:       "em0",
			tunnelName:  "gr-0-0-0",
			wantMembers: []string{"em0.0"},
			wantKeys:    map[string]string{"em0.0": "gr-0-0-0"},
		},
		{
			name:       "ordinary primary survives management fanout",
			iface:      "ge-0/0/0",
			tunnelName: "fxp0",
			wantKeys:   map[string]string{"ge-0/0/0": "ge-0-0-0"},
			wantClaim: &RoutingInstanceMemberPrimaryClaim{
				Instance: "blue", InterfaceKey: "ge-0/0/0", LinuxName: "ge-0-0-0",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
				tc.iface: {
					Name: tc.iface,
					Units: map[int]*InterfaceUnit{
						0: {Number: 0, Tunnel: &TunnelConfig{Name: tc.tunnelName}},
					},
				},
			}
			ri := &RoutingInstanceConfig{
				Name: "blue", InstanceType: "virtual-router", Interfaces: []string{tc.iface},
			}
			cfg.RoutingInstances = []*RoutingInstanceConfig{ri}

			tunnelNames := cfg.TunnelNameMap()
			keysBefore := RoutingInstanceMemberDeviceKeysForInstance(cfg, tunnelNames, ri)
			if len(keysBefore) != 2 {
				t.Fatalf("fixture bare-member fanout = %+v, want primary and unit key", keysBefore)
			}
			quarantineRIRoleMembers(cfg, tunnelNames)

			if len(ri.Interfaces) != len(tc.wantMembers) {
				t.Fatalf("sanitized members = %v, want %v", ri.Interfaces, tc.wantMembers)
			}
			for i, want := range tc.wantMembers {
				if ri.Interfaces[i] != want {
					t.Errorf("sanitized member[%d] = %q, want %q", i, ri.Interfaces[i], want)
				}
			}
			if got := len(cfg.QuarantinedRIMemberPrimaryClaims); tc.wantClaim == nil && got != 0 {
				t.Fatalf("unexpected retained primary claims: %+v", cfg.QuarantinedRIMemberPrimaryClaims)
			} else if tc.wantClaim != nil &&
				(got != 1 || cfg.QuarantinedRIMemberPrimaryClaims[0] != *tc.wantClaim) {
				t.Fatalf("retained primary claims = %+v, want [%+v]",
					cfg.QuarantinedRIMemberPrimaryClaims, *tc.wantClaim)
			}
			keys := RoutingInstanceMemberDeviceKeysForInstance(cfg, tunnelNames, ri)
			got := make(map[string]string, len(keys))
			for _, key := range keys {
				got[key.InterfaceKey] = key.LinuxName
			}
			if len(got) != len(tc.wantKeys) {
				t.Fatalf("sanitized ownership keys = %v, want %v", got, tc.wantKeys)
			}
			for key, want := range tc.wantKeys {
				if got[key] != want {
					t.Errorf("sanitized ownership key %q = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}
