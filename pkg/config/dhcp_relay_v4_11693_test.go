package config

import (
	"strings"
	"testing"
)

func dhcpRelayV4Tree11693(t *testing.T, server, activeServerGroup string) *ConfigTree {
	t.Helper()
	lines := []string{
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
	}
	if activeServerGroup != "<absent>" {
		lines = append(lines, "set forwarding-options dhcp-relay group lan active-server-group "+activeServerGroup)
	}
	switch server {
	case "<absent>":
	case "<empty>":
		lines = append(lines, "set forwarding-options dhcp-relay server-group sg")
	default:
		lines = append(lines, "set forwarding-options dhcp-relay server-group sg "+server)
	}
	return buildTree(t, lines)
}

func TestDHCPRelayV4StrictRejectsBlackholeInputs11693(t *testing.T) {
	cases := []struct {
		name              string
		server            string
		activeServerGroup string
	}{
		{name: "empty active-server-group", server: "192.0.2.1", activeServerGroup: "<absent>"},
		{name: "undefined active-server-group", server: "192.0.2.1", activeServerGroup: "missing"},
		{name: "empty referenced server-group", server: "<empty>", activeServerGroup: "sg"},
		{name: "invalid server", server: "not-an-ip", activeServerGroup: "sg"},
		{name: "unspecified server", server: "0.0.0.0", activeServerGroup: "sg"},
		{name: "loopback server", server: "127.0.0.1", activeServerGroup: "sg"},
		{name: "multicast server", server: "224.0.0.1", activeServerGroup: "sg"},
		{name: "link-local server", server: "169.254.1.1", activeServerGroup: "sg"},
		{name: "IPv6 server", server: "2001:db8::1", activeServerGroup: "sg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(dhcpRelayV4Tree11693(t, tc.server, tc.activeServerGroup))
			if err == nil {
				t.Fatal("strict CompileConfig accepted a DHCPv4 relay that cannot forward to a usable server")
			}
			if !strings.Contains(err.Error(), "forwarding-options dhcp-relay") {
				t.Fatalf("error %q does not identify the DHCPv4 relay", err)
			}
		})
	}
}

func TestDHCPRelayV4InvalidConfigWarnsOnLenientLoad11693(t *testing.T) {
	cfg, err := CompileConfigLenient(dhcpRelayV4Tree11693(t, "0.0.0.0", "sg"))
	if err != nil {
		t.Fatalf("tolerant compile rejected legacy config: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "DHCPRelay v4") && strings.Contains(warning, "0.0.0.0") {
			return
		}
	}
	t.Fatalf("tolerant config has no v4 DHCPRelay warning for unusable server: %v", cfg.Warnings)
}

func TestDHCPRelayV4ValidServerSpellingPreserved11693(t *testing.T) {
	cfg, err := CompileConfig(dhcpRelayV4Tree11693(t, "192.0.2.1", "sg"))
	if err != nil {
		t.Fatalf("valid DHCPv4 relay rejected: %v", err)
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	if relay == nil || relay.ServerGroups["sg"] == nil {
		t.Fatalf("valid DHCPv4 server-group missing after compile: %+v", relay)
	}
	if got := relay.ServerGroups["sg"].Servers; len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("valid server bytes changed during compile: %q", got)
	}
}
