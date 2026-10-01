package daemon

import (
	"log/slog"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// ambiguousDaemonCfg builds a config where the SAME IPv4 (192.0.2.1) is carried
// by two interfaces in two zones. When differ is true the two zones' host-inbound
// sets DIFFER (aaa default-deny, zzz ssh) — the #3718 ambiguity; when false they
// are IDENTICAL (both ssh) — a deliberate duplicate that must NOT be reported.
func ambiguousDaemonCfg(differ bool) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	aaa := &config.ZoneConfig{Name: "aaa", Interfaces: []string{"ge-0-0-0.0"}}
	if !differ {
		aaa.HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"ssh"}}
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"aaa": aaa,
		"zzz": {Name: "zzz", Interfaces: []string{"ge-0-0-1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	return cfg
}

// TestLogHostInboundAmbiguousTransitions is the #3718 fail-on-revert proof for
// the daemon-side observability: an ambiguous host-local address logs a WARN once
// on ENTRY (not every apply), and an INFO on RECOVERY once the ambiguity is
// resolved. An identical-service duplicate must never warn.
func TestLogHostInboundAmbiguousTransitions(t *testing.T) {
	sink := newCaptureSink()
	prev := slog.Default()
	slog.SetDefault(slog.New(capturingHandler{sink: sink}))
	defer slog.SetDefault(prev)

	d := &Daemon{}

	warnsFor := func(addr string) int {
		n := 0
		for _, r := range sink.records() {
			if r.level == slog.LevelWarn && r.attrs["address"] == addr {
				n++
			}
		}
		return n
	}
	infos := func() int {
		n := 0
		for _, r := range sink.records() {
			if r.level == slog.LevelInfo && r.msg == "host-inbound address ambiguity resolved — the address no longer has an order-dependent host-inbound verdict" {
				n++
			}
		}
		return n
	}

	// Apply 1: ambiguous → exactly one WARN for the address.
	d.logHostInboundAmbiguousTransitions(ambiguousDaemonCfg(true))
	if warnsFor("192.0.2.1") != 1 {
		t.Fatalf("first apply: warns = %d, want 1", warnsFor("192.0.2.1"))
	}
	if !d.hostInboundFailOpen.ambiguousAddrs["inet|192.0.2.1"] {
		t.Errorf("state not tracked: hostInboundFailOpen.ambiguousAddrs missing inet|192.0.2.1")
	}

	// Apply 2: still ambiguous → NO new WARN (state-transition dedup).
	d.logHostInboundAmbiguousTransitions(ambiguousDaemonCfg(true))
	if warnsFor("192.0.2.1") != 1 {
		t.Fatalf("second apply: warns = %d, want 1 (dedup — must not re-log a persisting ambiguity)", warnsFor("192.0.2.1"))
	}

	// Apply 3: services made identical → one INFO recovery, no new WARN, state cleared.
	d.logHostInboundAmbiguousTransitions(ambiguousDaemonCfg(false))
	if infos() != 1 {
		t.Errorf("recovery: infos = %d, want 1 (ambiguity resolved)", infos())
	}
	if warnsFor("192.0.2.1") != 1 {
		t.Errorf("recovery must not emit another warn, warns = %d", warnsFor("192.0.2.1"))
	}
	if d.hostInboundFailOpen.ambiguousAddrs["inet|192.0.2.1"] {
		t.Errorf("state not cleared after recovery: inet|192.0.2.1 still set")
	}
}

func TestLogHostInboundAmbiguousIngressTransitions11331(t *testing.T) {
	sink := newCaptureSink()
	prev := slog.Default()
	slog.SetDefault(slog.New(capturingHandler{sink: sink}))
	defer slog.SetDefault(prev)

	d := &Daemon{}
	views := []dpuserspace.ZoneHostInboundView{
		{Zone: "aaa", IngressDenyNetdevs: []string{"vrf-sfmix"}},
		{Zone: "zzz", IngressNetdevs: []string{"eth0"}},
	}
	d.logHostInboundAmbiguousIngressTransitions(views)
	d.logHostInboundAmbiguousIngressTransitions(views)

	warns := 0
	for _, r := range sink.records() {
		if r.level == slog.LevelWarn &&
			r.msg == "host-inbound effective VRF netdev has ambiguous zone ownership — applying destination-owner service rights before a counted fail-closed drop (#11331)" {
			warns++
			if r.attrs["netdev"] != "vrf-sfmix" || r.attrs["counter_zone"] != dpuserspace.UnzonedHostInboundZoneLabel {
				t.Errorf("warning attrs = %v, want netdev and counted sentinel", r.attrs)
			}
		}
	}
	if warns != 1 {
		t.Fatalf("persistent ambiguity emitted %d warnings, want one", warns)
	}
	if !d.hostInboundFailOpen.ambiguousIngress["vrf-sfmix"] {
		t.Fatal("ambiguous ingress state was not retained")
	}

	d.logHostInboundAmbiguousIngressTransitions(views[1:])
	infos := 0
	for _, r := range sink.records() {
		if r.level == slog.LevelInfo &&
			r.msg == "host-inbound ambiguous VRF netdev ownership resolved — zone-scoped ingress rules restored" &&
			r.attrs["netdev"] == "vrf-sfmix" {
			infos++
		}
	}
	if infos != 1 {
		t.Fatalf("ambiguity recovery emitted %d infos, want one", infos)
	}
	if d.hostInboundFailOpen.ambiguousIngress["vrf-sfmix"] {
		t.Fatal("ambiguous ingress state was not cleared")
	}
}
