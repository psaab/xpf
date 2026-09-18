package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// stableRethHostInboundConfig10303 models a RETH/HA IPv6 host-service zone.
// The stable LL is deliberately absent from every configured/live address: it
// is a daemon-derived MASTER-only address, so the host-inbound renderer must
// add it from the deterministic cluster/RG identity.
func stableRethHostInboundConfig10303() *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:        7,
		NodeID:           0,
		NodeIDSet:        true,
		RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"2001:db8:61::1/64"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	return cfg
}

func hostServiceProbe10303(payload, addr string) bool {
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, "ip6 daddr") &&
			strings.Contains(line, addr) &&
			strings.Contains(line, "tcp dport 22 accept") {
			return true
		}
	}
	return false
}

func hostInboundDropProbe10303(payload, addr string) bool {
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, "ip6 daddr") &&
			strings.Contains(line, addr) &&
			strings.Contains(line, "drop") {
			return true
		}
	}
	return false
}

// TestHostInboundStableRethLLFailoverProbe10303 is the hermetic failover cell
// for #10303. A BACKUP render has no live stable LL, but an IPv6 SSH probe to
// the RA router address must hit the configured host-service ACCEPT before the
// per-zone catch-all DROP. The same config is what the new MASTER gets after
// failover, so the daddr scope is deterministic across the transition.
func TestHostInboundStableRethLLFailoverProbe10303(t *testing.T) {
	cfg := stableRethHostInboundConfig10303()
	stableLL := cluster.StableRethLinkLocal(7, 1).String()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)

	if !hostServiceProbe10303(payload, stableLL) {
		t.Fatalf("hermetic BACKUP host-service probe to %s is not admitted by the configured SSH rule; stable LL was not unioned into daddr set:\n%s", stableLL, payload)
	}
	if !hostInboundDropProbe10303(payload, stableLL) {
		t.Fatalf("hermetic BACKUP probe target %s has no host-inbound catch-all DROP after the service accept:\n%s", stableLL, payload)
	}
}

// TestHostInboundStableRethLLColdBootProbe10303 is the hermetic cold-boot cell
// for #10303. Before the first successful commit the cold-boot fence has no
// service accepts, so an LL SSH probe must be covered by its IPv6 destination
// DROP rather than fall through to policy accept.
func TestHostInboundStableRethLLColdBootProbe10303(t *testing.T) {
	cfg := stableRethHostInboundConfig10303()
	stableLL := cluster.StableRethLinkLocal(7, 1).String()
	views := buildAndCheckViews(t, cfg)
	sets := dpuserspace.BuildFenceAddrSets(cfg, views)
	payload := buildHostInboundFencePayload(sets.Views, sets.UnzonedV4, sets.UnzonedV6, nil)

	if !hostInboundDropProbe10303(payload, stableLL) {
		t.Fatalf("hermetic cold-boot LL SSH probe to %s is not fenced by an IPv6 destination DROP (would fall through to policy accept):\n%s", stableLL, payload)
	}
	if hostServiceProbe10303(payload, stableLL) {
		t.Fatalf("cold-boot fence unexpectedly admits SSH to stable LL %s:\n%s", stableLL, payload)
	}
}
