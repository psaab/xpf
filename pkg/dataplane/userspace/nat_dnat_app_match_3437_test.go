// #3437: DNAT `match application` source-port (H10) + ICMP type/code (H11)
// enforcement. These tests prove the Go snapshot builder carries the
// application's source-port and ICMP type/code constraints onto the userspace
// DestinationNATRuleSnapshot. Before the fix the DNAT builder reduced an
// application to protocol + destination-port only and DROPPED both, so a
// `match application` DNAT rule published the VIP to every source port and
// every ICMP type (a fail-open NAT widening). The per-flow match itself is
// enforced Rust-side in nat::tests::*_3437; dropping the builder assignment
// here turns these RED.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dnatAppConfig builds a config with a single DNAT rule-set whose only rule
// matches via `match application appName`, plus the named application.
func dnatAppConfig(appName string, app *config.Application) *config.Config {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{appName: app}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name:     "rs",
				FromZone: "untrust",
				Rules: []*config.NATRule{{
					Name: "r1",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.10",
						Application:        appName,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"},
				}},
			},
		},
	}
	return cfg
}

func TestBuildDNATSnapshotCarriesApplicationSourcePortMatch(t *testing.T) {
	cfg := dnatAppConfig("custom-app", &config.Application{
		Name:            "custom-app",
		Protocol:        "tcp",
		DestinationPort: "80",
		SourcePort:      "12345",
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchSourcePorts
	want := []NatPortRangeWire{{Low: 12345, High: 12345}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("MatchSourcePorts = %+v, want %+v", got, want)
	}
}

// A configured source-port that coalesces to nothing (all out of 1..65535)
// must emit the never-match sentinel ({Low:1, High:0}), not an empty list.
// Empty would be read downstream as "no source-port constraint" = match any
// source port — re-opening the fail-open this fix closes. RED-on-revert: with
// the plain coalesce (drop-to-empty), MatchSourcePorts is empty.
func TestBuildDNATSnapshotAppAllOutOfRangeSourcePortFailsClosed(t *testing.T) {
	cfg := dnatAppConfig("bad-src", &config.Application{
		Name:            "bad-src",
		Protocol:        "tcp",
		DestinationPort: "80",
		SourcePort:      "70000-80000", // entirely > 65535
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchSourcePorts
	if len(got) != 1 || got[0] != (NatPortRangeWire{Low: 1, High: 0}) {
		t.Fatalf("MatchSourcePorts = %+v, want one never-match sentinel {1,0}", got)
	}
}

func TestBuildDNATSnapshotCarriesApplicationICMPTypeMatch(t *testing.T) {
	typ := uint8(8) // echo-request, like junos-icmp-ping
	cfg := dnatAppConfig("ping-app", &config.Application{
		Name:     "ping-app",
		Protocol: "icmp",
		ICMPType: &typ,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].MatchICMPType == nil || *snaps[0].MatchICMPType != 8 {
		t.Fatalf("MatchICMPType = %v, want *8", snaps[0].MatchICMPType)
	}
	if snaps[0].MatchICMPCode != nil {
		t.Fatalf("MatchICMPCode = %v, want nil (unconstrained code)", snaps[0].MatchICMPCode)
	}
}

func TestBuildDNATSnapshotCarriesApplicationICMPTypeAndCodeMatch(t *testing.T) {
	typ := uint8(3) // destination-unreachable
	code := uint8(1)
	cfg := dnatAppConfig("unreach-app", &config.Application{
		Name:     "unreach-app",
		Protocol: "icmp",
		ICMPType: &typ,
		ICMPCode: &code,
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].MatchICMPType == nil || *snaps[0].MatchICMPType != 3 {
		t.Fatalf("MatchICMPType = %v, want *3", snaps[0].MatchICMPType)
	}
	if snaps[0].MatchICMPCode == nil || *snaps[0].MatchICMPCode != 1 {
		t.Fatalf("MatchICMPCode = %v, want *1", snaps[0].MatchICMPCode)
	}
}

// An application with neither source-port nor ICMP type/code leaves both axes
// unconstrained (the common case). Guards against the fix narrowing the
// historical match-any behavior.
func TestBuildDNATSnapshotUnconstrainedApplicationLeavesL4Empty(t *testing.T) {
	cfg := dnatAppConfig("plain", &config.Application{
		Name:            "plain",
		Protocol:        "tcp",
		DestinationPort: "80",
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if len(snaps[0].MatchSourcePorts) != 0 {
		t.Fatalf("MatchSourcePorts = %+v, want empty", snaps[0].MatchSourcePorts)
	}
	if snaps[0].MatchICMPType != nil || snaps[0].MatchICMPCode != nil {
		t.Fatalf("MatchICMPType/Code = %v/%v, want nil/nil",
			snaps[0].MatchICMPType, snaps[0].MatchICMPCode)
	}
}
