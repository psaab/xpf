package daemon

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// ingress_ifname_15094_test.go — #15094 (A52-06).
//
// applySyslogConfig built the EventReader's ifindex->name map by calling
// netlink.LinkByName with the AUTHORED config name. A Junos-spelled name
// such as "ge-0/0/1" (docs/ha-cluster-userspace.conf:23) is not a kernel
// device — the kernel device is "ge-0-0-1" — so LinkByName failed and the
// interface was silently skipped. Every event arriving on that interface
// then resolved IngressIface="" and RT_FLOW / `show security log` rendered
// packet-incoming-interface="N/A"/"unknown", and interface-scoped live
// monitors matched nothing.
//
// The fix resolves through cfg.ResolveKernelIfName for the kernel lookup
// and stores the operator-facing (authored) name, including per-unit
// entries and RETH (resolved to the local physical member's ifindex,
// rendered under the reth unit name).
//
// #16065: SessionIfNamesByIfindex refuses a kernel ifindex claimed by
// different displayed unit names rather than first-wins. The ambiguous
// `lo` / `reth0` fixture is kept in a separate test; the #15094 cell below
// uses a unique RETH-to-loopback claim so its Junos-name resolution remains
// a positive control.
//
// RED-on-revert: restoring LinkByName(ifName) with the authored name
// leaves unique `reth0` unmapped and reds TestIngressIfNamesJunosSpelling15094;
// the kernel-spelled control still passes, proving the old gap.

func ingressCfg15094() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{NodeID: 0}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			// Junos RETH name uniquely resolves to the loopback kernel device.
			"reth0": {
				Name:            "reth0",
				RedundancyGroup: 1,
				Units:           map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
			"lo-member": {
				Name:            "lo",
				RedundantParent: "reth0",
			},
		}},
	}
}

func ambiguousIngressCfg15094() *config.Config {
	cfg := ingressCfg15094()
	cfg.Interfaces.Interfaces["lo"] = &config.InterfaceConfig{
		Name:  "lo",
		Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
	}
	return cfg
}

// rawEvent15094 builds a minimal SESSION_OPEN wire frame carrying the
// given ingress ifindex at [128:132], long enough for logEvent's
// extended-field parse (>= rawEventWireSize).
func rawEvent15094(ifindex uint32) []byte {
	data := make([]byte, 160)
	binary.LittleEndian.PutUint64(data[0:8], 1_700_000_000_000_000_000)
	copy(data[8:12], net.ParseIP("10.0.1.5").To4())
	copy(data[24:28], net.ParseIP("10.0.2.7").To4())
	binary.BigEndian.PutUint16(data[40:42], 41234)
	binary.BigEndian.PutUint16(data[42:44], 443)
	data[52] = 1 // SESSION_OPEN (eventTypeSessionOpen)
	data[53] = 6 // TCP
	data[55] = 2 // addrFamilyInet; #16127 drops unknown family 0
	// Keep the per-policy syslog gate open on the source==nil path:
	// logEvent suppresses SESSION_OPEN records whose trailing log byte
	// is 0. Set it so the record reaches the buffer.
	data[135] = 1 // #2508 log-syslog byte (rawEventLogSyslogOffset)
	binary.LittleEndian.PutUint32(data[128:132], ifindex)
	return data
}

func TestIngressIfNamesJunosSpelling15094(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	loIdx := uint32(lo.Index)

	cfg := ingressCfg15094()
	if got := cfg.ResolveKernelIfName("reth0"); got != "lo" {
		t.Fatalf("premise: ResolveKernelIfName(reth0) = %q, want %q", got, "lo")
	}
	if _, err := net.InterfaceByName("reth0"); err == nil {
		t.Skip("host unexpectedly has a reth0 device; premise cannot be exercised")
	}
	if got, ok := buildIfNames(cfg)[loIdx]; !ok || got != "reth0" {
		t.Fatalf("unique RETH ifindex mapping = %q (present=%v), want %q", got, ok, "reth0")
	}

	buf := logging.NewEventBuffer(16)
	er := logging.NewEventReader(nil, buf)
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)
	if !er.ProcessRawEvent(rawEvent15094(loIdx)) {
		t.Fatal("ProcessRawEvent rejected the fixture frame")
	}
	recs := buf.Latest(1)
	if len(recs) != 1 {
		t.Fatalf("buffer holds %d records, want 1 (syslog-gate offset wrong?)", len(recs))
	}
	if recs[0].IngressIface != "reth0" {
		t.Fatalf("Junos-spelled RETH event ingress = %q, want %q", recs[0].IngressIface, "reth0")
	}
}
func TestIngressIfNamesRejectsAmbiguousRethLoopback16065(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	loIdx := uint32(lo.Index)
	cfg := ambiguousIngressCfg15094()

	if got := cfg.ResolveKernelIfName("reth0"); got != "lo" {
		t.Fatalf("premise: ResolveKernelIfName(reth0) = %q, want %q", got, "lo")
	}
	if name, ok := buildIfNames(cfg)[loIdx]; ok {
		t.Fatalf("#16065: loopback ifindex %d is claimed by both lo.0 and reth0.0; got first-wins name %q", loIdx, name)
	}

	buf := logging.NewEventBuffer(16)
	er := logging.NewEventReader(nil, buf)
	(&Daemon{}).applySyslogConfig(er, cfg)
	if !er.ProcessRawEvent(rawEvent15094(loIdx)) {
		t.Fatal("ProcessRawEvent rejected the fixture frame")
	}
	recs := buf.Latest(1)
	if len(recs) != 1 {
		t.Fatalf("buffer holds %d records, want 1 (syslog-gate offset wrong?)", len(recs))
	}
	if recs[0].IngressIface != "" {
		t.Fatalf("ambiguous ifindex must resolve nameless, got %q", recs[0].IngressIface)
	}
}

// TestIngressIfNamesUnitAndKernelControl15094 pins the adjacent
// controls: the kernel-spelled interface still resolves (no behaviour
// change for names that already worked), and an unknown ifindex still
// resolves to "" (rendered N/A/unknown downstream, never a borrowed
// name).
func TestIngressIfNamesUnitAndKernelControl15094(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"lo": {Name: "lo", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}},
	}
	buf := logging.NewEventBuffer(16)
	er := logging.NewEventReader(nil, buf)
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)

	if !er.ProcessRawEvent(rawEvent15094(uint32(lo.Index))) {
		t.Fatal("ProcessRawEvent rejected the fixture frame")
	}
	recs := buf.Latest(1)
	if len(recs) != 1 {
		t.Fatalf("buffer holds %d records, want 1", len(recs))
	}
	if recs[0].IngressIface != "lo" {
		t.Fatalf("kernel-spelled control: IngressIface = %q, want %q", recs[0].IngressIface, "lo")
	}

	// Unknown ifindex: no entry, empty name (existing behaviour).
	if !er.ProcessRawEvent(rawEvent15094(999999)) {
		t.Fatal("ProcessRawEvent rejected the unknown-ifindex frame")
	}
	recs = buf.Latest(1)
	if len(recs) != 1 {
		t.Fatalf("buffer holds %d records, want 1", len(recs))
	}
	if recs[0].IngressIface != "" {
		t.Fatalf("unknown ifindex must resolve to empty, got %q", recs[0].IngressIface)
	}
	if strings.Contains(recs[0].IngressIface, "lo") {
		t.Fatalf("unknown ifindex borrowed a name: %q", recs[0].IngressIface)
	}
}
