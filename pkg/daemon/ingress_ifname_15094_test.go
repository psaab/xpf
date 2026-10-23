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
// #16065: the map is now config.SessionIfNamesByIfindex, the session
// tables' shared derivation. A device claimed by two DIFFERENT unit
// names (this fixture's lo device, claimed by lo.0 as "lo" and by
// reth0.0 as "reth0") is refused rather than first-wins named, so the
// Junos-spelling test below pins the refusal and the uniquely-claimed
// kernel control keeps the #15094 resolution assertion.
//
// RED-on-revert: restoring LinkByName(ifName) with the authored name
// reds every Junos-spelled cell below — only the kernel-spelled control
// ("lo") stays green, which is exactly the pre-fix behaviour.

func ingressCfg15094() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{NodeID: 0}},
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			// Kernel-spelled control: authored name == kernel name,
			// the one shape that already worked pre-fix.
			"lo": {
				Name:  "lo",
				Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
			// RETH whose local member's kernel device is loopback:
			// the member stanza is keyed "lo-member" with Name "lo",
			// so cfg.ResolveKernelIfName("reth0") == "lo" — a device
			// that exists on every test host — while the authored
			// "reth0" itself names no kernel device. This is the
			// Junos-spelling gap in miniature (cf. ge-0/0/1 ->
			// ge-0-0-1 on the lab config).
			"reth0": {
				Name:            "reth0",
				RedundancyGroup: 1,
				Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0},
					50: {Number: 50, VlanID: 50},
				},
			},
			"lo-member": {
				Name:            "lo",
				RedundantParent: "reth0",
			},
		}},
	}
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
	// Premise: the Junos-spelled RETH ref resolves to the loopback
	// kernel device, while the authored name itself is NOT a kernel
	// device — the exact gap the old LinkByName(ifName) fell into.
	if got := cfg.ResolveKernelIfName("reth0"); got != "lo" {
		t.Fatalf("premise: ResolveKernelIfName(reth0) = %q, want %q", got, "lo")
	}
	if _, err := net.InterfaceByName("reth0"); err == nil {
		t.Skip("host unexpectedly has a reth0 device; premise cannot be exercised")
	}

	buf := logging.NewEventBuffer(16)
	er := logging.NewEventReader(nil, buf)
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)

	// An event arriving on the loopback ifindex (the RETH's local
	// member device) must render under the operator-facing name.
	// #16065: the table is the session table's projection — reth0
	// unit 0 and lo unit 0 both claim {loIdx, 0} under DIFFERENT
	// display names ("reth0" vs "lo"), so the shared key is REFUSED
	// and neither name is stored. The pre-#16065 first-wins builder
	// named it "reth0"; the refusal is the honest answer (the device
	// is claimed by two units the event cannot distinguish), and it
	// is pinned directly in TestBuildIfNamesRefusesSharedWireGuard16065
	// for the TUN shape. Here the surviving assertion is the one the
	// #15094 fix actually owns: a unit that UNIQUELY claims its
	// device still resolves. That is the kernel-spelled control in
	// the next test; this fixture's RETH claim is now ambiguous, so
	// assert the refusal explicitly rather than the old winner.
	names := buildIfNames(cfg)
	if name, ok := names[loIdx]; ok {
		t.Fatalf("#16065: loopback ifindex %d is claimed by both reth0.0 (as \"reth0\") "+
			"and lo.0 (as \"lo\") — the shared key must be refused, got %q", loIdx, name)
	}
	if !er.ProcessRawEvent(rawEvent15094(loIdx)) {
		t.Fatal("ProcessRawEvent rejected the fixture frame")
	}
	recs := buf.Latest(1)
	if len(recs) != 1 {
		t.Fatalf("buffer holds %d records, want 1 (syslog-gate offset wrong?)", len(recs))
	}
	if recs[0].IngressIface != "" {
		t.Fatalf("ambiguous ifindex must resolve nameless, got %q — a first-wins sibling "+
			"name is the #16065 defect", recs[0].IngressIface)
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
