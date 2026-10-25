package cluster

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16425 (R3-F05-03): probeSourceFor picked the FIRST VIP/unit address
// regardless of the target's family. On a dual-stack unit whose
// `family inet6` is authored before `family inet`, an IPv4 target bound
// to that unit resolved to the IPv6 VIP on the primary, the udp4 dial
// failed, and the probe was not-completed every cycle — the RG's
// ip-monitoring sensor was silently inert on the node that owns the RG,
// so loss of the upstream gateway never demoted the primary.
//
// The fix selects the first address OF THE TARGET'S FAMILY (VIP list
// first, then the configured unit addresses) and strict commit rejects
// a bound target whose unit has no address of that family (the config
// gate lives in pkg/config; see ip_monitor_family_16425_test.go there).

// dualStackMonitorConfig builds a config whose reth0 unit 0 carries an
// IPv6 address FIRST and an IPv4 address second (authoring order), with
// RG 1 owning reth0 — the exact shape the defect needs. The physical
// member keeps RethVIPsForRG's device key aligned with
// resolveProbeInterface.
func dualStackMonitorConfig(addrs []string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			"reth0": {
				Name:            "reth0",
				RedundancyGroup: 1,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: addrs},
				},
			},
		}},
	}
}

func primaryMonitor16425(t *testing.T, addrs []string, target *config.IPMonitorTarget) (*Manager, *Monitor, *config.RedundancyGroup) {
	t.Helper()
	rg := &config.RedundancyGroup{
		ID:             1,
		Preempt:        true,
		NodePriorities: map[int]int{0: 200, 1: 100},
		IPMonitoring:   &config.IPMonitoring{GlobalWeight: 255, Targets: []*config.IPMonitorTarget{target}},
	}
	ccfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(ccfg)
	drainEvents(m, 1)
	m.SetGroupStateForTesting(1, StatePrimary)
	mon := NewMonitor(m, ccfg.RedundancyGroups)
	mon.SetConfig(dualStackMonitorConfig(addrs))
	return m, mon, rg
}

// TestProbeSourceForFamilySelection16425 pins the source selection
// directly: family is matched against the target, in both orders and
// both families, and a unit with no same-family address yields a
// source-free probe instead of a wrong-family bind.
func TestProbeSourceForFamilySelection16425(t *testing.T) {
	target4 := &config.IPMonitorTarget{Address: "10.0.0.1", Weight: 255, Interface: "reth0.0"}
	for _, tc := range []struct {
		name    string
		addrs   []string
		target  *config.IPMonitorTarget
		wantSrc string
	}{
		{"v4 target, inet6 authored first (defect)", []string{"2001:db8::2/64", "10.0.0.2/24"}, target4, "10.0.0.2"},
		{"v4 target, inet authored first (control)", []string{"10.0.0.2/24", "2001:db8::2/64"}, target4, "10.0.0.2"},
		{"v6 target, inet authored first", []string{"10.0.0.2/24", "2001:db8::2/64"}, &config.IPMonitorTarget{Address: "2001:db8::1", Weight: 255, Interface: "reth0.0"}, "2001:db8::2"},
		{"v4 target, unit has no IPv4 (source-free, not wrong-family)", []string{"2001:db8::2/64"}, target4, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, mon, rg := primaryMonitor16425(t, tc.addrs, tc.target)
			src, device, _ := mon.probeSourceFor(rg, tc.target)
			if src != tc.wantSrc {
				t.Fatalf("probeSourceFor src = %q, want %q (#16425)", src, tc.wantSrc)
			}
			if device != "ge-0-0-0" {
				t.Fatalf("probeSourceFor device = %q, want ge-0-0-0 (reth0 member)", device)
			}
		})
	}
}

// TestIPMonitorPrimaryDualStackDemotes16425 is the end-to-end acceptance
// shape: the defect row (inet6 first) with an unreachable gateway must
// install the ip-monitoring debt and drop the primary's weight to 0
// after the polls, exactly like the inet-first control. Pre-fix the
// primary picked the IPv6 unit address as the udp4 probe's source, the
// dial failed (not-completed), and the weight stayed 255 forever. The
// dial itself is what discriminates pre/post fix — with the IPv6
// source the real dialer cannot even open the udp4 socket.
// Loopback spellings are used so the REAL defaultICMPDialer can bind
// the selected source on this host: ::1 for the v6 entry, 127.0.0.1 for
// the v4 entry. The gateway is 10.255.255.1 — NOT a 127.x address,
// because the kernel answers ICMP echo for the whole 127/8 on loopback,
// so a 127.x "dead" gateway would falsely measure reachable.
func TestIPMonitorPrimaryDualStackDemotes16425(t *testing.T) {
	run := func(t *testing.T, addrs []string) int {
		target := &config.IPMonitorTarget{Address: "10.255.255.1", Weight: 255, Interface: "reth0.0"}
		m, mon, _ := primaryMonitor16425(t, addrs, target)
		injectFakeNl(mon)
		setNoDampening(mon)
		// No icmpDialer / probeFn override: the real probeICMP +
		// defaultICMPDialer path is the instrument under test.
		for range 3 {
			mon.poll()
		}
		return m.GroupStates()[0].Weight
	}
	if w := run(t, []string{"::1/128", "127.0.0.1/8"}); w != 0 {
		t.Fatalf("defect row (inet6 first) weight = %d, want 0: the primary must measure the "+
			"unreachable gateway from the IPv4 unit address and demote (#16425)", w)
	}
	if w := run(t, []string{"127.0.0.1/8", "::1/128"}); w != 0 {
		t.Fatalf("control row (inet first) weight = %d, want 0 (#16425 control)", w)
	}
}

// TestIPMonitorPrimaryDualStackReachable16425 is the reachable control:
// with the gateway answering, neither order may demote. It also pins
// that the probe actually runs (completed) rather than being skipped.
func TestIPMonitorPrimaryDualStackReachable16425(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []string
	}{
		{"inet6 first", []string{"::1/128", "127.0.0.1/8"}},
		{"inet first", []string{"127.0.0.1/8", "::1/128"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := &config.IPMonitorTarget{Address: "127.0.0.1", Weight: 255, Interface: "reth0.0"}
			m, mon, _ := primaryMonitor16425(t, tc.addrs, target)
			injectFakeNl(mon)
			setNoDampening(mon)
			var gotSrc string
			var calls int
			mon.probeFn = func(_ context.Context, _ *config.IPMonitorTarget, src, _ string) (bool, bool) {
				calls++
				gotSrc = src
				return true, true
			}
			for range 3 {
				mon.poll()
			}
			if calls == 0 || gotSrc != "127.0.0.1" {
				t.Fatalf("probe src = %q (calls %d), want 127.0.0.1 with probes running (#16425)", gotSrc, calls)
			}
			if w := m.GroupStates()[0].Weight; w != 255 {
				t.Fatalf("reachable gateway weight = %d, want 255 (#16425 control)", w)
			}
		})
	}
}
