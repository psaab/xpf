package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// firstApplyBurstConfig16636 builds a standalone (non-cluster)
// ip-monitoring config: policy "wan-failover" references probe WAN
// (a dead tcp-ping target) and probe "plain" is unreferenced. The
// test interval is 60s and successive-loss is 3, so without a burst
// the first FAIL verdict needs two further ticker cycles (~120s).
func firstApplyBurstConfig16636(t *testing.T) (*config.Config, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead tcp port: %v", err)
	}
	deadAddr := ln.Addr().String()
	_, deadPort, err := net.SplitHostPort(deadAddr)
	if err != nil {
		t.Fatalf("split dead addr: %v", err)
	}
	_ = ln.Close()
	_ = deadPort

	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", ProbeType: "tcp-ping", Target: "127.0.0.1", DestPort: deadPortInt(t, deadAddr), ProbeCount: 1, ProbeInterval: 60, TestInterval: 60, ThresholdSuccessive: 3},
		}},
		"plain": {Name: "plain", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", ProbeType: "tcp-ping", Target: "127.0.0.1", DestPort: deadPortInt(t, deadAddr), ProbeCount: 1, ProbeInterval: 60, TestInterval: 60, ThresholdSuccessive: 3},
		}},
	}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "192.0.2.1"},
			},
		},
	}}
	return cfg, deadAddr
}

func deadPortInt(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return port
}

// TestFirstApplyBurstsIPMonProbes16636 is the #16636 regression: the
// first reconcileRPM of a fresh Daemon (simulating a restarted xpfd)
// must burst the ip-monitoring-referenced probe so its FAIL verdict
// for a dead target arrives within the burst bound, not after
// (successive-loss-1) x test-interval. The unreferenced probe must
// stay on normal cadence (control: no FAIL transition). A second,
// config-changing reconcile must NOT re-burst (latch control).
func TestFirstApplyBurstsIPMonProbes16636(t *testing.T) {
	cfg, _ := firstApplyBurstConfig16636(t)

	d := &Daemon{rpm: rpm.New(), daemonCtx: context.Background()}
	transitions := make(chan rpm.Transition, 8)
	d.rpm.SetTransitionCallback(func(tr rpm.Transition) { transitions <- tr })
	defer d.rpm.StopAll()

	if !d.reconcileRPM(cfg) {
		t.Fatal("first reconcile must apply")
	}

	// Referenced probe: FAIL within burst bound (well under 60s tick).
	select {
	case tr := <-transitions:
		if tr.ProbeName != "WAN" || tr.TestName != "t" || tr.Status != "fail" {
			t.Fatalf("first transition = %+v, want WAN/t fail", tr)
		}
		if !tr.TakeoverBurst {
			t.Fatalf("first FAIL not marked as burst: %+v", tr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first post-restart FAIL verdict did not arrive within burst bound (2s); " +
			"pre-fix it needs (successive-loss-1) x test-interval (~120s)")
	}
	// Results-level check: WAN reads fail before any test-interval tick.
	for _, r := range d.rpm.Results() {
		if r.ProbeName == "WAN" && r.LastStatus != "fail" {
			t.Fatalf("WAN result LastStatus = %q, want fail", r.LastStatus)
		}
		if r.ProbeName == "plain" && r.LastStatus == "fail" {
			t.Fatalf("unreferenced probe was burst to fail: %+v", r)
		}
	}
	// Control: unreferenced probe must not emit a FAIL transition.
	select {
	case tr := <-transitions:
		t.Fatalf("unreferenced/control probe emitted transition: %+v", tr)
	case <-time.After(300 * time.Millisecond):
	}

	// Latch control: a second, changed reconcile must not re-burst.
	// Change WAN target port to another dead port so the hash changes
	// and probes re-apply; new verdicts start unknown and, without a
	// burst, no FAIL can arrive before the 60s ticker.
	cfg2, _ := firstApplyBurstConfig16636(t)
	// Drain any straggler transitions from first apply.
drain:
	for {
		select {
		case <-transitions:
		default:
			break drain
		}
	}
	if !d.reconcileRPM(cfg2) {
		t.Fatal("changed config must re-apply")
	}
	select {
	case tr := <-transitions:
		if tr.Status == "fail" {
			t.Fatalf("second reconcile re-burst (latch broken): %+v", tr)
		}
	case <-time.After(500 * time.Millisecond):
	}
}

// TestIPMonReferencedProbeNames16636 unit-pins the selector: only
// policies' MatchRPMProbe names that are present in the effective
// (HA-filtered) set are returned; HA gating is irrelevant here.
func TestIPMonReferencedProbeNames16636(t *testing.T) {
	cfg, _ := firstApplyBurstConfig16636(t)
	effective := cfg.Services.RPM
	got := ipMonReferencedProbeNames(cfg, effective)
	if len(got) != 1 {
		t.Fatalf("referenced = %v, want only WAN", got)
	}
	if _, ok := got["WAN"]; !ok {
		t.Fatalf("referenced = %v, missing WAN", got)
	}
	// Probe gated out of effective set -> not burst.
	withoutWAN := &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"plain": cfg.Services.RPM.Probes["plain"],
	}}
	if got := ipMonReferencedProbeNames(cfg, withoutWAN); len(got) != 0 {
		t.Fatalf("gated-out probe was selected: %v", got)
	}
	// No ip-monitoring -> nil.
	bare := &config.Config{}
	bare.Services.RPM = cfg.Services.RPM
	if got := ipMonReferencedProbeNames(bare, effective); got != nil {
		t.Fatalf("no-ipmon config selected %v, want nil", got)
	}
}
