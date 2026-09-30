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
	if got := cfg.RoutingInstances[0].Interfaces; len(got) != 1 || got[0] != "fxp0.0" {
		t.Fatalf("tolerant compile erased the authored member: %v", got)
	}
}

func TestOrdinaryRIMemberStillPassesManagementGate11392(t *testing.T) {
	if _, err := CompileConfig(managementRIMemberTree11392(t, "ge-0/0/1", "ge-0/0/1.0")); err != nil {
		t.Fatalf("ordinary virtual-router member must remain valid: %v", err)
	}
}
