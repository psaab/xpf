package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestCompiledDottedLifelineOwnershipAndGapFence12848(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-1234567890",
		"set chassis cluster control-interface hb.1",
		"set chassis cluster fabric-interface ge-0/0/0.100",
		"set interfaces hb.1",
		"set interfaces hb.2 unit 0 family inet address 192.0.2.2/32",
		"set interfaces hb.10 unit 0 family inet address 192.0.2.10/32",
		"set interfaces ge-0/0/0.100 unit 0 family inet address 198.51.100.1/32",
		"set interfaces ge-0/0/0.200 unit 0 family inet address 192.0.2.200/32",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig: %v", err)
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Interfaces: []string{"hb.2.0", "hb.10.0", "ge-0/0/0.100.0", "ge-0/0/0.200.0"}},
	}

	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	filter := buildHostInboundFencePayload(views, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{})
	if !strings.Contains(filter, " drop") {
		t.Errorf("compiled default-deny view rendered no DROP rule:\n%s", filter)
	}
	for _, address := range []string{"192.0.2.2", "192.0.2.10", "192.0.2.200"} {
		if !strings.Contains(filter, address) {
			t.Errorf("compiled sibling address %s missing from rendered host-inbound deny rules:\n%s", address, filter)
		}
	}
	if strings.Contains(filter, "198.51.100.1") {
		t.Errorf("rendered host-inbound deny unexpectedly owns the configured fabric address:\n%s", filter)
	}

	lifelineNetdevs := dpuserspace.HostInboundLifelineIngressNetdevs(cfg)
	if got, want := strings.Join(lifelineNetdevs, ","), "fxp0,ge-0-0-0.100,hb.1"; got != want {
		t.Fatalf("compiled lifeline Linux netdevs = %q, want %q", got, want)
	}
	gap := buildHostInboundGapFencePayload(
		nil, []string{"192.0.2.2"}, nil, nil, nil,
		nil, nil, []string{"192.0.2.2"}, nil, lifelineNetdevs,
		dhcpBackstopLists{}, nil, nil,
	)
	wantException := "iifname " + nftIifnameSet(lifelineNetdevs) +
		" ip daddr " + nftAddrSet([]string{"192.0.2.2"}) + " accept"
	if !strings.Contains(gap, wantException) {
		t.Errorf("compiled unit-less lifeline missing from rendered gap exception %q:\n%s", wantException, gap)
	}
	if strings.Contains(gap, `"hb.2"`) || strings.Contains(gap, `"hb.10"`) ||
		strings.Contains(gap, `"ge-0-0-0.200"`) {
		t.Errorf("ordinary dotted siblings leaked into gap exception:\n%s", gap)
	}
}
