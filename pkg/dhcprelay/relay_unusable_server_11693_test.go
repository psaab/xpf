package dhcprelay

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestComputeDesiredRejectsUnusableIPv4ServerClasses11693(t *testing.T) {
	for _, server := range []string{
		"not-an-ip",
		"0.0.0.0",
		"127.0.0.1",
		"224.0.0.1",
		"169.254.1.1",
		"2001:db8::1",
	} {
		t.Run(server, func(t *testing.T) {
			cfg := &config.DHCPRelayConfig{
				ServerGroups: map[string]*config.DHCPRelayServerGroup{
					"sg": {Name: "sg", Servers: []string{server}},
				},
				Groups: map[string]*config.DHCPRelayGroup{
					"g": {Name: "g", Interfaces: []string{"ge-0-0-0"}, ActiveServerGroup: "sg"},
				},
			}
			if got := computeDesired(cfg, nil); len(got) != 0 {
				t.Fatalf("unusable server %q produced desired relay state: %+v", server, got)
			}
		})
	}
}

func TestComputeDesiredPreservesValidIPv4ServerBytes11693(t *testing.T) {
	cfg := &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {Name: "g", Interfaces: []string{"ge-0-0-0"}, ActiveServerGroup: "sg"},
		},
	}
	got := computeDesired(cfg, nil)
	dr, ok := got["ge-0-0-0"]
	if !ok {
		t.Fatal("valid DHCPv4 server did not produce desired relay state")
	}
	want := relaySpec{servers: []string{"192.0.2.1"}, kernelName: "ge-0-0-0"}
	if !reflect.DeepEqual(dr.spec, want) {
		t.Fatalf("valid relay spec changed: got %+v, want %+v", dr.spec, want)
	}
	if len(dr.servers) != 1 || dr.servers[0].IP.String() != "192.0.2.1" {
		t.Fatalf("valid resolved server changed: %+v", dr.servers)
	}
}

func TestComputeDesiredRejectsMissingOrEmptyServerGroup11693(t *testing.T) {
	cases := []struct {
		name              string
		serverGroups      map[string]*config.DHCPRelayServerGroup
		activeServerGroup string
	}{
		{
			name: "empty active-server-group",
			serverGroups: map[string]*config.DHCPRelayServerGroup{
				"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
			},
		},
		{
			name:              "undefined active-server-group",
			activeServerGroup: "missing",
		},
		{
			name: "empty referenced server-group",
			serverGroups: map[string]*config.DHCPRelayServerGroup{
				"sg": {Name: "sg"},
			},
			activeServerGroup: "sg",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.DHCPRelayConfig{
				ServerGroups: tc.serverGroups,
				Groups: map[string]*config.DHCPRelayGroup{
					"g": {Name: "g", Interfaces: []string{"ge-0-0-0"}, ActiveServerGroup: tc.activeServerGroup},
				},
			}
			if got := computeDesired(cfg, nil); len(got) != 0 {
				t.Fatalf("invalid active-server-group produced desired relay state: %+v", got)
			}
		})
	}
}
