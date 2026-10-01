package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileLenientManagementRIMember11392(t *testing.T) *config.Config {
	t.Helper()
	lines := []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface fxp0.0",
		"set routing-instances blue interface ge-0/0/1.0",
	}
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse set command %q: %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set config path %q: %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile tolerant management-member fixture: %v", err)
	}
	return cfg
}

func TestTolerantManagementRIMemberDoesNotEnterUserspaceRoutesOrDomain11392(t *testing.T) {
	cfg := compileLenientManagementRIMember11392(t)
	instances := buildInterfaceRoutingInstances(cfg)
	v4Tables, v6Tables := buildInterfaceRouteTables(cfg)

	if got := instances["fxp0.0"]; got != "" {
		t.Errorf("management interface routing domain = %q, want default domain", got)
	}
	if got := v4Tables["fxp0.0"]; got != "" {
		t.Errorf("management interface IPv4 table = %q, want default table", got)
	}
	if got := v6Tables["fxp0.0"]; got != "" {
		t.Errorf("management interface IPv6 table = %q, want default table", got)
	}

	if got := instances["ge-0/0/1.0"]; got != "blue" {
		t.Errorf("ordinary interface routing domain = %q, want blue", got)
	}
	if got := v4Tables["ge-0/0/1.0"]; got != "blue.inet.0" {
		t.Errorf("ordinary interface IPv4 table = %q, want blue.inet.0", got)
	}
	if got := v6Tables["ge-0/0/1.0"]; got != "blue.inet6.0" {
		t.Errorf("ordinary interface IPv6 table = %q, want blue.inet6.0", got)
	}
}
