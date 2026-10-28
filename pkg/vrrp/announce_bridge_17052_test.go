package vrrp

import (
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #17052 M3 pin (the M2 real-leg driver lives in test_seams.go).

// TestProbeSuccessInfoOnGARPFailure17052 pins M3: GARP fails, probe
// succeeds -> the Info must still fire (the probe is the rebind path
// for routers that ignore broadcast GARP).
func TestProbeSuccessInfoOnGARPFailure17052(t *testing.T) {
	origG, origN, origProbe := garpBurstFn, naBurstFn, arpProbeFn
	garpBurstFn = func(string, net.IP, int, cluster.BurstStillValid) error {
		return errors.New("garp boom")
	}
	naBurstFn = func(string, net.IP, int, cluster.BurstStillValid) error { return nil }
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() { garpBurstFn, naBurstFn, arpProbeFn = origG, origN, origProbe })

	var logs strings.Builder
	origLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(origLog) })

	vi := newInstance(Instance{
		Interface: "xpf-17052-m3", GroupID: 1, Priority: 200,
		AdvertiseInterval: 1000, VirtualAddresses: []string{"10.0.0.100/24"},
	}, &net.Interface{Name: "xpf-17052-m3"}, make(chan VRRPEvent, 8), nil)
	vi.setState(StateMaster)
	epoch := vi.garpEpoch.Add(1)
	vi.sendGARPReservedMode([]string{"10.0.0.100/24"}, epoch, vi.ownerGen.Load(), 3, false)
	if !strings.Contains(logs.String(), "probed subnet gateway") {
		t.Fatalf("probe-success Info missing when GARP failed but probe succeeded; logs:\n%s", logs.String())
	}
}
