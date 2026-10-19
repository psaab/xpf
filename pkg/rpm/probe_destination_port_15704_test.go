package rpm

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// rpmCarryTCPCfg builds a one-probe/one-test tcp-ping RPM stanza on port.
func rpmCarryTCPCfg(port int) *config.RPMConfig {
	return &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {
				Name:         "t",
				ProbeType:    "tcp-ping",
				Target:       "192.0.2.1",
				DestPort:     port,
				NextHop:      "10.0.0.1",
				TestInterval: 3600,
			},
		}},
	}}
}

// TestProbeMeasurementIdentityDestinationPort_15704 pins destination-port
// in the measurement identity: editing a tcp-ping test's port is a new
// measurement, while spelling the effective default explicitly is not.
func TestProbeMeasurementIdentityDestinationPort_15704(t *testing.T) {
	base := &config.RPMTest{
		Name:      "t",
		ProbeType: "tcp-ping",
		Target:    "192.0.2.1",
		DestPort:  80,
		NextHop:   "10.0.0.1",
	}
	want := probeMeasurementIdentity(base, nil)

	changed := *base
	changed.DestPort = 443
	if got := probeMeasurementIdentity(&changed, nil); got == want {
		t.Fatal("changing destination-port 80 -> 443 did not change the measurement identity — " +
			"the old port's verdict would be carried onto the new port")
	}

	implicit := *base
	implicit.DestPort = 0 // EffectiveDestinationPort() == 80
	if got := probeMeasurementIdentity(&implicit, nil); got != want {
		t.Fatal("implicit default port and explicit port 80 produced different identities — " +
			"identity must use EffectiveDestinationPort(), not the raw DestPort")
	}
}

// TestApplyDestinationPortChangeReseeds_15704 is the Apply-level gate:
// a tcp-ping test edited from port 80 (FAIL, streak 3) to port 443 must
// start clean instead of carrying LastStatus/SuccFail/RTT-loss counters
// into rpm results and, downstream, services ip-monitoring.
func TestApplyDestinationPortChangeReseeds_15704(t *testing.T) {
	const key = "WAN/t"
	ctx := context.Background()
	m := newCarryManager(t)

	m.Apply(ctx, rpmCarryTCPCfg(80))
	before := identityOf(m, key)
	setVerdict(m, key, "fail", 3)

	m.Apply(ctx, rpmCarryTCPCfg(443))

	if after := identityOf(m, key); before == after {
		t.Fatalf("setup: destination-port change did not move the measurement identity (%q)", before)
	}
	if got, sf := statusOf(m, key); got != "unknown" || sf != 0 {
		t.Fatalf("verdict after destination-port 80 -> 443 = (%q, %d), want (\"unknown\", 0) — "+
			"the old port's PASS/FAIL verdict and SuccFail streak must not be carried", got, sf)
	}
	m.mu.RLock()
	r := m.results[key]
	m.mu.RUnlock()
	if r == nil {
		t.Fatalf("result %q absent after port change, want present and reseeded", key)
	}
	if r.TotalSent != 0 || r.TotalRecv != 0 {
		t.Fatalf("counters after destination-port change = sent %d recv %d, want 0/0 — "+
			"the old port's RTT/loss counters must not be carried", r.TotalSent, r.TotalRecv)
	}
}
