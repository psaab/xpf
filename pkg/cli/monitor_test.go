package cli

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/monitoriface"
)

type monitorInterfaceCLITestDP struct {
	dataplane.DataPlane

	loaded     bool
	counters   dataplane.InterfaceCounterValue
	gotIfindex int
}

func (f *monitorInterfaceCLITestDP) IsLoaded() bool {
	return f.loaded
}

func (f *monitorInterfaceCLITestDP) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
	f.gotIfindex = ifindex
	return f.counters, nil
}

func TestMonitorFlowFilter_MatchesAll(t *testing.T) {
	f := &monitorFlowFilter{Name: "empty"}
	rec := &logging.EventRecord{
		SrcAddr:  "10.0.1.5:443",
		DstAddr:  "10.0.2.1:80",
		Protocol: "TCP",
	}
	if !f.matches(rec) {
		t.Fatal("empty filter should match everything")
	}
}

func TestMonitorInterfaceDataplaneProjectsCounters(t *testing.T) {
	dp := &monitorInterfaceCLITestDP{
		loaded: true,
		counters: dataplane.InterfaceCounterValue{
			RxPackets: 10,
			RxBytes:   20,
			TxPackets: 30,
			TxBytes:   40,
		},
	}
	cli := &CLI{dp: dp}

	accessor := cli.monitorInterfaceDataplane()
	if accessor == nil {
		t.Fatal("monitorInterfaceDataplane() returned nil")
	}
	if _, ok := accessor.(monitoriface.RuntimeDataPlane); !ok {
		t.Fatalf("monitorInterfaceDataplane() = %T, want monitoriface.RuntimeDataPlane", accessor)
	}
	if !accessor.IsLoaded() {
		t.Fatal("IsLoaded() = false, want true")
	}

	got, err := accessor.ReadInterfaceCounters(42)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters() error = %v", err)
	}
	if dp.gotIfindex != 42 {
		t.Fatalf("ReadInterfaceCounters ifindex = %d, want 42", dp.gotIfindex)
	}
	if got != (monitoriface.InterfaceCounters{RxPackets: 10, RxBytes: 20, TxPackets: 30, TxBytes: 40}) {
		t.Fatalf("ReadInterfaceCounters() = %+v, want projected monitor counters", got)
	}
}

func TestMonitorFlowFilter_SrcPrefix(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.1.0/24")
	f := &monitorFlowFilter{Name: "src", SrcIP: cidr}

	// Match
	rec := &logging.EventRecord{SrcAddr: "10.0.1.5:443"}
	if !f.matches(rec) {
		t.Fatal("10.0.1.5 should match 10.0.1.0/24")
	}

	// No match
	rec = &logging.EventRecord{SrcAddr: "10.0.2.5:443"}
	if f.matches(rec) {
		t.Fatal("10.0.2.5 should not match 10.0.1.0/24")
	}
}

func TestMonitorFlowFilter_DstPrefix(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.0.0/16")
	f := &monitorFlowFilter{Name: "dst", DstIP: cidr}

	rec := &logging.EventRecord{DstAddr: "192.168.1.1:80"}
	if !f.matches(rec) {
		t.Fatal("192.168.1.1 should match 192.168.0.0/16")
	}

	rec = &logging.EventRecord{DstAddr: "10.0.0.1:80"}
	if f.matches(rec) {
		t.Fatal("10.0.0.1 should not match 192.168.0.0/16")
	}
}

func TestMonitorFlowFilter_Port(t *testing.T) {
	f := &monitorFlowFilter{Name: "port", SrcPort: 443, DstPort: 80}

	rec := &logging.EventRecord{SrcAddr: "10.0.1.5:443", DstAddr: "10.0.2.1:80"}
	if !f.matches(rec) {
		t.Fatal("should match exact ports")
	}

	rec = &logging.EventRecord{SrcAddr: "10.0.1.5:8080", DstAddr: "10.0.2.1:80"}
	if f.matches(rec) {
		t.Fatal("src port 8080 should not match filter for 443")
	}

	rec = &logging.EventRecord{SrcAddr: "10.0.1.5:443", DstAddr: "10.0.2.1:8443"}
	if f.matches(rec) {
		t.Fatal("dst port 8443 should not match filter for 80")
	}
}

func TestMonitorFlowFilter_Protocol(t *testing.T) {
	f := &monitorFlowFilter{Name: "tcp", Protocol: "tcp"}

	rec := &logging.EventRecord{Protocol: "TCP"}
	if !f.matches(rec) {
		t.Fatal("TCP should match case-insensitive")
	}

	rec = &logging.EventRecord{Protocol: "UDP"}
	if f.matches(rec) {
		t.Fatal("UDP should not match tcp filter")
	}
}

func TestMonitorFlowFilter_Interface(t *testing.T) {
	f := &monitorFlowFilter{Name: "iface", Iface: "trust0"}

	rec := &logging.EventRecord{IngressIface: "trust0"}
	if !f.matches(rec) {
		t.Fatal("trust0 should match")
	}

	rec = &logging.EventRecord{IngressIface: "untrust0"}
	if f.matches(rec) {
		t.Fatal("untrust0 should not match trust0 filter")
	}
}

func TestMonitorFlowFilter_Combined(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.1.0/24")
	f := &monitorFlowFilter{
		Name:     "combined",
		SrcIP:    cidr,
		DstPort:  80,
		Protocol: "tcp",
		Iface:    "trust0",
	}

	// All criteria match
	rec := &logging.EventRecord{
		SrcAddr:      "10.0.1.5:12345",
		DstAddr:      "10.0.2.1:80",
		Protocol:     "TCP",
		IngressIface: "trust0",
	}
	if !f.matches(rec) {
		t.Fatal("all criteria match, should pass")
	}

	// Wrong interface
	rec.IngressIface = "untrust0"
	if f.matches(rec) {
		t.Fatal("wrong interface should fail")
	}
}

func TestMonitorFlowState_FileConfig(t *testing.T) {
	s := newMonitorFlowState()
	s.filename = "test-trace"
	s.fileSize = 1048576
	s.files = 5
	s.match = "deny"

	if s.filename != "test-trace" {
		t.Fatalf("filename = %q, want test-trace", s.filename)
	}
	if s.fileSize != 1048576 {
		t.Fatalf("fileSize = %d, want 1048576", s.fileSize)
	}
	if s.files != 5 {
		t.Fatalf("files = %d, want 5", s.files)
	}
	if s.match != "deny" {
		t.Fatalf("match = %q, want deny", s.match)
	}
}

func TestMonitorFlowState_FilterPersistence(t *testing.T) {
	s := newMonitorFlowState()
	s.filters["test1"] = &monitorFlowFilter{Name: "test1", Protocol: "tcp"}
	s.filters["test2"] = &monitorFlowFilter{Name: "test2", Protocol: "udp"}

	if len(s.filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(s.filters))
	}

	// Filters persist across simulated stop/start
	s.active = true
	s.active = false

	if len(s.filters) != 2 {
		t.Fatal("filters should persist across stop/start")
	}
	if s.filters["test1"].Protocol != "tcp" {
		t.Fatal("filter test1 protocol should still be tcp")
	}
}

func TestMonitorFlowState_StartRequiresFileAndFilter(t *testing.T) {
	s := newMonitorFlowState()

	// No file, no filter
	if s.filename != "" {
		t.Fatal("should have no filename initially")
	}
	if len(s.filters) != 0 {
		t.Fatal("should have no filters initially")
	}

	// Set file only
	s.filename = "trace"
	if s.filename == "" {
		t.Fatal("filename should be set")
	}
	if len(s.filters) != 0 {
		t.Fatal("still no filters")
	}

	// Add filter
	s.filters["f1"] = &monitorFlowFilter{Name: "f1"}
	if len(s.filters) != 1 {
		t.Fatal("should have 1 filter")
	}

	// Now both preconditions are met
	if s.filename == "" || len(s.filters) == 0 {
		t.Fatal("both file and filter should be configured")
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10.0.1.5:443", "10.0.1.5"},
		{"[2001:db8::1]:80", "2001:db8::1"},
		{"10.0.1.5", "10.0.1.5"},
	}
	for _, tt := range tests {
		ip := extractIP(tt.input)
		if ip == nil {
			t.Fatalf("extractIP(%q) = nil", tt.input)
		}
		if ip.String() != tt.want {
			t.Fatalf("extractIP(%q) = %s, want %s", tt.input, ip, tt.want)
		}
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		input string
		want  uint16
	}{
		{"10.0.1.5:443", 443},
		{"[2001:db8::1]:80", 80},
		{"10.0.1.5", 0}, // no port
	}
	for _, tt := range tests {
		got := extractPort(tt.input)
		if got != tt.want {
			t.Fatalf("extractPort(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestAggregateUserspaceIfaceSnapshot(t *testing.T) {
	status := dpuserspace.ProcessStatus{
		Enabled:                true,
		ForwardingArmed:        true,
		NeighborGeneration:     11,
		LastSnapshotGeneration: 29,
		Bindings: []dpuserspace.BindingStatus{
			{
				Interface:           "ge-0-0-0",
				Ready:               true,
				Bound:               true,
				XSKRegistered:       true,
				ZeroCopy:            true,
				RXPackets:           10,
				RXBytes:             1000,
				TXPackets:           9,
				TXBytes:             900,
				DirectTXPackets:     8,
				CopyTXPackets:       1,
				InPlaceTXPackets:    2,
				SessionMisses:       3,
				NeighborMissPackets: 4,
				RouteMissPackets:    5,
				PolicyDeniedPackets: 6,
				ExceptionPackets:    7,
				SlowPathPackets:     8,
				LastError:           "bind failed",
			},
			{
				Interface:           "ge-0-0-0",
				Ready:               true,
				Bound:               true,
				XSKRegistered:       true,
				ZeroCopy:            false,
				RXPackets:           20,
				RXBytes:             2000,
				TXPackets:           19,
				TXBytes:             1900,
				DirectTXPackets:     18,
				CopyTXPackets:       2,
				InPlaceTXPackets:    3,
				SessionMisses:       1,
				NeighborMissPackets: 2,
				RouteMissPackets:    3,
				PolicyDeniedPackets: 4,
				ExceptionPackets:    5,
				SlowPathPackets:     6,
				LastError:           "bind failed",
			},
			{
				Interface:     "ge-0-0-1",
				SessionMisses: 99,
			},
		},
		RecentExceptions: []dpuserspace.ExceptionStatus{
			{Interface: "ge-0-0-0", Reason: "ha_inactive", SrcIP: "10.0.0.1", DstIP: "1.1.1.1", FromZone: "lan", ToZone: "wan"},
			{Interface: "ge-0-0-1", Reason: "ignored"},
		},
	}

	snap := aggregateUserspaceIfaceSnapshot("ge-0-0-0", status)
	if snap == nil {
		t.Fatal("expected userspace snapshot")
	}
	if !snap.HelperEnabled || !snap.ForwardingArmed {
		t.Fatal("expected helper enabled and armed")
	}
	if snap.Bindings != 2 || snap.ReadyBindings != 2 || snap.BoundBindings != 2 {
		t.Fatalf("unexpected binding counts: %+v", snap)
	}
	if snap.XSKRegistered != 2 || snap.ZeroCopyBindings != 1 {
		t.Fatalf("unexpected xsk/zc counts: %+v", snap)
	}
	if snap.RxPackets != 30 || snap.TxPackets != 28 {
		t.Fatalf("unexpected packet totals: rx=%d tx=%d", snap.RxPackets, snap.TxPackets)
	}
	if snap.DirectTXPackets != 26 || snap.CopyTXPackets != 3 || snap.InPlaceTXPackets != 5 {
		t.Fatalf("unexpected tx mode totals: direct=%d copy=%d inplace=%d", snap.DirectTXPackets, snap.CopyTXPackets, snap.InPlaceTXPackets)
	}
	if snap.SessionMisses != 4 || snap.NeighborMissPackets != 6 || snap.RouteMissPackets != 8 {
		t.Fatalf("unexpected miss totals: session=%d neigh=%d route=%d", snap.SessionMisses, snap.NeighborMissPackets, snap.RouteMissPackets)
	}
	if len(snap.LastErrors) != 1 || snap.LastErrors[0] != "bind failed" {
		t.Fatalf("unexpected last errors: %#v", snap.LastErrors)
	}
	if len(snap.RecentExceptions) != 1 || !strings.Contains(snap.RecentExceptions[0], "ha_inactive") {
		t.Fatalf("unexpected exceptions: %#v", snap.RecentExceptions)
	}
}

func TestRenderSingleInterfaceIncludesUserspaceSection(t *testing.T) {
	now := time.Now()
	baseline := &ifaceSnapshot{
		RxBytes:   1000,
		TxBytes:   2000,
		RxPkts:    10,
		TxPkts:    20,
		Timestamp: now.Add(-time.Second),
		Userspace: &userspaceIfaceSnapshot{
			RxBytes:             100,
			TxBytes:             200,
			RxPackets:           10,
			TxPackets:           20,
			DirectTXPackets:     5,
			CopyTXPackets:       1,
			InPlaceTXPackets:    2,
			SessionMisses:       1,
			NeighborMissPackets: 2,
			RouteMissPackets:    3,
			PolicyDeniedPackets: 4,
			ExceptionPackets:    5,
			SlowPathPackets:     6,
		},
	}
	prev := &ifaceSnapshot{
		Timestamp: now.Add(-time.Second),
		Userspace: &userspaceIfaceSnapshot{
			RxBytes:   100,
			TxBytes:   200,
			RxPackets: 10,
			TxPackets: 20,
		},
	}
	snap := &ifaceSnapshot{
		RxBytes:   2000,
		TxBytes:   4000,
		RxPkts:    20,
		TxPkts:    40,
		Timestamp: now,
		Userspace: &userspaceIfaceSnapshot{
			HelperEnabled:                     true,
			ForwardingArmed:                   true,
			NeighborGeneration:                7,
			LastSnapshotGen:                   8,
			Bindings:                          2,
			ReadyBindings:                     2,
			BoundBindings:                     2,
			XSKRegistered:                     2,
			ZeroCopyBindings:                  1,
			RxBytes:                           300,
			TxBytes:                           500,
			RxPackets:                         30,
			TxPackets:                         50,
			DirectTXPackets:                   15,
			CopyTXPackets:                     2,
			InPlaceTXPackets:                  3,
			TxCompletions:                     17,
			KernelRXDropped:                   18,
			KernelRXInvalidDescs:              19,
			KernelRXRingFull:                  20,
			DirectTXNoFrameFallbackPackets:    4,
			DirectTXBuildFallbackPackets:      5,
			DirectTXDisallowedFallbackPackets: 6,
			DebugPendingFillFrames:            21,
			DebugSpareFillFrames:              22,
			DebugFreeTXFrames:                 23,
			DebugPendingTXPrepared:            24,
			DebugPendingTXLocal:               25,
			DebugOutstandingTX:                26,
			DebugInFlightRecycles:             27,
			SessionMisses:                     4,
			NeighborMissPackets:               5,
			RouteMissPackets:                  6,
			PolicyDeniedPackets:               7,
			ExceptionPackets:                  8,
			SlowPathPackets:                   9,
			LastErrors:                        []string{"bind failed"},
			RecentExceptions:                  []string{"ha_inactive | 10.0.0.1 -> 1.1.1.1"},
		},
	}

	var buf bytes.Buffer
	renderSingleInterface(&buf, "host", "fab0", "ge-0-0-0", snap, prev, baseline, now.Add(-5*time.Second))
	out := buf.String()
	for _, want := range []string{
		"Userspace dataplane:",
		"Helper state:",
		"Binding state:",
		"Direct TX packets:",
		"TX completions:",
		"Kernel RX dropped:",
		"Kernel RX ring full:",
		"Direct TX no-frame:",
		"Pending TX local:",
		"Direct TX build-none:",
		"Direct TX disallowed:",
		"Session misses:",
		"Recent exceptions:",
		"bind failed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatPacketDropEvent(t *testing.T) {
	rec := logging.EventRecord{
		Time:         time.Date(2026, 3, 1, 7, 43, 11, 684547000, time.UTC),
		Type:         "POLICY_DENY",
		SrcAddr:      "172.16.103.254:5353",
		DstAddr:      "224.0.0.251:5353",
		Protocol:     "UDP",
		Action:       "deny",
		IngressIface: "trust0",
		PolicyName:   "deny-all",
	}
	line := formatPacketDropEvent(rec)
	if line == "" {
		t.Fatal("formatted line should not be empty")
	}
	// Should contain timestamp, addresses, protocol, interface, and reason
	for _, want := range []string{"07:43:11", "172.16.103.254:5353", "224.0.0.251:5353", "udp", "trust0", "Dropped by FLOW"} {
		if !contains(line, want) {
			t.Fatalf("line %q missing %q", line, want)
		}
	}
}

func TestFormatPacketDropEvent_Screen(t *testing.T) {
	rec := logging.EventRecord{
		Time:         time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		Type:         "SCREEN_DROP",
		SrcAddr:      "10.0.1.1:0",
		DstAddr:      "10.0.2.1:0",
		Protocol:     "ICMP",
		ScreenCheck:  "syn-flood",
		IngressIface: "untrust0",
	}
	line := formatPacketDropEvent(rec)
	if !contains(line, "SCREEN:syn-flood") {
		t.Fatalf("screen drop line should contain 'SCREEN:syn-flood': %s", line)
	}
}

func TestFormatFlowEvent(t *testing.T) {
	rec := logging.EventRecord{
		Time:        time.Date(2026, 3, 1, 10, 30, 0, 0, time.UTC),
		SrcAddr:     "10.0.1.5:12345",
		DstAddr:     "10.0.2.1:80",
		Protocol:    "TCP",
		Action:      "permit",
		InZoneName:  "trust",
		OutZoneName: "untrust",
		PolicyName:  "allow-web",
	}
	line := formatFlowEvent(rec)
	for _, want := range []string{"10:30:00", "10.0.1.5:12345", "10.0.2.1:80", "TCP", "permit", "trust", "untrust"} {
		if !contains(line, want) {
			t.Fatalf("line %q missing %q", line, want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && stringContains(s, substr)
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
