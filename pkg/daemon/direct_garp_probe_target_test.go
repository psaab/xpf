package daemon

import (
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

// #3922: the direct-mode (private-rg-election / no-reth-vrrp) supplementary
// gateway ARP probe in directSendGARPs must compute its target as the subnet's
// first usable host (network address + 1, via vrrp.GatewayProbeTarget), NOT by
// forcing the network address's last octet to .1. On /25-or-longer subnets, or
// a subnet whose network does not end in .0, the legacy forced-.1 computation
// landed OUTSIDE the subnet — the probe went to a foreign address and the real
// gateway's ARP cache was never re-bound to the new master's MAC → post-
// failover blackhole. #2377 fixed the analogous forced-.1 in vrrp.sendGARP but
// missed this direct-mode site.
//
// These tests exercise the full directSendGARPs path through the directARPProbeFn
// seam. They are fail-on-revert: the /25 and /28 cases assert the target is the
// in-subnet network+1, which the pre-#3922 forced-.1 code computed OUTSIDE the
// subnet (RED); the /32 and VIP-is-first-host cases assert NO directed probe
// fires, which the forced-.1 code violated by synthesizing an out-of-range .1
// target (RED). The /24-.1 case is unchanged (network .0 + 1 = .1) and stays
// green on both the fix and the revert.

// probeCapture records the sender/target of every directARPProbeFn call.
type probeCapture struct {
	mu      sync.Mutex
	calls   int
	senders []net.IP
	targets []net.IP
}

func installProbeSeam(t *testing.T, cap *probeCapture) {
	t.Helper()
	prev := directARPProbeFn
	directARPProbeFn = func(_ string, sender, target net.IP) error {
		cap.mu.Lock()
		cap.calls++
		cap.senders = append(cap.senders, append(net.IP(nil), sender...))
		cap.targets = append(cap.targets, append(net.IP(nil), target...))
		cap.mu.Unlock()
		return nil
	}
	t.Cleanup(func() { directARPProbeFn = prev })
}

// directProbeTestDaemon builds a cluster-mode Daemon that owns RG 1 with a
// single IPv4 VIP at the given CIDR on reth0, so directSendGARPs exercises the
// supplementary gateway-probe path for that prefix.
func directProbeTestDaemon(t *testing.T, vipCIDR string) *Daemon {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set chassis cluster cluster-id 1\n" +
			"set chassis cluster authentication-key test-cluster-psk-6611\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
			"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
			"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
			"set interfaces reth0 unit 0 family inet address " + vipCIDR + "\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Daemon{
		store:             s,
		rgStates:          make(map[int]*rgStateMachine),
		directVIPOwned:    map[int]bool{1: true},
		directAnnounceSeq: map[int]uint64{1: 1},
	}
}

func TestDirectSendGARPs_ProbeTargetRespectsPrefix(t *testing.T) {
	cases := []struct {
		name      string
		vipCIDR   string
		wantProbe bool
		wantGW    string
	}{
		// /24, gateway .1 — unchanged: network .0 + 1 = .1. Green on both the
		// fix and the pre-#3922 forced-.1 revert.
		{"slash24_gw_dot1", "10.0.5.10/24", true, "10.0.5.1"},
		// /25 with a non-.0 network — the #3922 regression: network
		// 192.168.1.128 + 1 = .129, INSIDE .128-.255. Forced-.1 computes
		// 192.168.1.1, OUTSIDE the subnet → RED on revert.
		{"slash25_nonzero_network", "192.168.1.130/25", true, "192.168.1.129"},
		// /28: network 10.0.61.16 + 1 = .17, INSIDE .16-.31. Forced-.1
		// computes 10.0.61.1, OUTSIDE → RED on revert.
		{"slash28", "10.0.61.18/28", true, "10.0.61.17"},
		// /32 host route — no in-subnet gateway host; the probe is skipped.
		// Forced-.1 would synthesize 10.1.2.1 and fire → RED on revert.
		{"slash32_hostroute_skips", "10.1.2.3/32", false, ""},
		// /30 where the VIP is itself the first usable host (10.0.0.4 + 1 =
		// 10.0.0.5 == VIP) — the equals-VIP guard skips the self-probe.
		// Forced-.1 computes 10.0.0.1 (!= VIP) and fires → RED on revert.
		{"slash30_vip_is_first_host_skips", "10.0.0.5/30", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := directProbeTestDaemon(t, tc.vipCIDR)

			var cap probeCapture
			installProbeSeam(t, &cap)
			noop := func(string, net.IP, int, cluster.BurstStillValid) error { return nil }
			installBurstSeams(t, noop, noop)

			d.directSendGARPs(1)

			if !tc.wantProbe {
				if cap.calls != 0 {
					t.Fatalf("%s: expected NO directed ARP probe, got %d (targets %v) — "+
						"forced-.1 fired an out-of-subnet probe (#3922 regression)",
						tc.vipCIDR, cap.calls, cap.targets)
				}
				return
			}

			if cap.calls != 1 {
				t.Fatalf("%s: expected exactly 1 directed ARP probe, got %d", tc.vipCIDR, cap.calls)
			}
			gw := cap.targets[0]
			if gw.String() != tc.wantGW {
				t.Errorf("%s: probe target = %s, want %s (network+1)", tc.vipCIDR, gw, tc.wantGW)
			}
			_, ipNet, err := net.ParseCIDR(tc.vipCIDR)
			if err != nil {
				t.Fatalf("ParseCIDR(%q): %v", tc.vipCIDR, err)
			}
			if !ipNet.Contains(gw) {
				t.Errorf("%s: probe target %s is OUTSIDE the subnet %s — #3922 forced-.1 regression",
					tc.vipCIDR, gw, ipNet)
			}
			// The ARP sender must be the VIP (#2152), so the gateway re-binds
			// VIP -> our MAC rather than the interface primary -> MAC.
			vipIP, _, _ := net.ParseCIDR(tc.vipCIDR)
			if !cap.senders[0].Equal(vipIP.To4()) {
				t.Errorf("%s: probe sender = %s, want VIP %s (#2152)", tc.vipCIDR, cap.senders[0], vipIP)
			}
		})
	}
}
