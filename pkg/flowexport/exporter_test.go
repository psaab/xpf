package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// v9Svc returns a minimal *config.ServicesConfig carrying a
// `flow-monitoring version9` stanza. BuildExportConfig gates the v9
// exporter on Version9 != nil (#2129), so tests that assert a non-nil
// ExportConfig must pass this instead of a nil services config.
func v9Svc() *config.ServicesConfig {
	return &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"t": {Name: "t"},
				},
			},
		},
	}
}

func TestBuildExportConfig_InlineJflowSourceAddress(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						InlineJflow:              true,
						InlineJflowSourceAddress: "10.0.1.10",
					},
				},
			},
		},
	}

	ec := BuildExportConfig(v9Svc(), fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if len(ec.Collectors) != 1 {
		t.Fatalf("expected 1 collector, got %d", len(ec.Collectors))
	}
	if ec.Collectors[0].SourceAddress != "10.0.1.10" {
		t.Errorf("SourceAddress = %q, want %q", ec.Collectors[0].SourceAddress, "10.0.1.10")
	}
}

func TestBuildSamplingZones(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust": {
					Interfaces: []string{"eth0.0"},
				},
				"untrust": {
					Interfaces: []string{"eth1.0"},
				},
				"dmz": {
					Interfaces: []string{"eth2.0"},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"eth0": {
					Units: map[int]*config.InterfaceUnit{
						0: {SamplingInput: true, SamplingOutput: true},
					},
				},
				"eth1": {
					Units: map[int]*config.InterfaceUnit{
						0: {SamplingInput: true},
					},
				},
				"eth2": {
					Units: map[int]*config.InterfaceUnit{
						0: {}, // no sampling
					},
				},
			},
		},
	}

	// Deterministic zone IDs: dmz=1, trust=2, untrust=3 (sorted)
	zoneIDs := map[string]uint16{"dmz": 1, "trust": 2, "untrust": 3}
	sz := BuildSamplingZones(cfg, zoneIDs)

	// trust (id=2) should have both input and output
	if d, ok := sz[2]; !ok || !d.Input || !d.Output {
		t.Errorf("trust zone: got %+v, want Input=true Output=true", sz[2])
	}
	// untrust (id=3) should have input only
	if d, ok := sz[3]; !ok || !d.Input || d.Output {
		t.Errorf("untrust zone: got %+v, want Input=true Output=false", sz[3])
	}
	// dmz (id=1) should not be in the map (no sampling)
	if _, ok := sz[1]; ok {
		t.Errorf("dmz zone should not have sampling, got %+v", sz[1])
	}
}

// TestBuildSamplingZonesSkipsNilZone is the fail-on-revert guard for the
// #3492 apply-path nil-zone crash class: a nil zone value (reachable on the
// tolerant/programmatic/HA-peer-sync config path) must be skipped, not
// dereferenced. Reverting the `if zone == nil` guard in BuildSamplingZones
// makes this test panic.
func TestBuildSamplingZonesSkipsNilZone(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				// trust references BOTH a healthy interface (eth0.0) AND a
				// nil-valued interface (nilif.0) so the inner
				// `ifCfg == nil` clause is exercised on the apply path.
				"trust": {Interfaces: []string{"eth0.0", "nilif.0"}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"eth0": {Units: map[int]*config.InterfaceUnit{
					0: {SamplingInput: true},
				}},
			},
		},
	}
	// Inject a nil zone slot and a nil interface value post-construction,
	// mirroring the reachable nil-slot invariant. "nilif" is a (nil) value
	// referenced by the trust zone above, so BuildSamplingZones reaches the
	// `if !ok || ifCfg == nil` comma-ok clause for it.
	cfg.Security.Zones["bogus"] = nil
	cfg.Interfaces.Interfaces["nilif"] = nil

	zoneIDs := map[string]uint16{"trust": 2, "bogus": 9}

	// Must not panic on the nil "bogus" zone or nil interface value.
	sz := BuildSamplingZones(cfg, zoneIDs)

	// The healthy zone is still mapped.
	if d, ok := sz[2]; !ok || !d.Input {
		t.Errorf("trust zone (id=2): want Input=true, got %+v (ok=%v)", sz[2], ok)
	}
	// The nil zone contributes nothing.
	if _, ok := sz[9]; ok {
		t.Errorf("nil zone (id=9) should not be in sampling map, got %+v", sz[9])
	}
}

func TestShouldExport(t *testing.T) {
	ec := &ExportConfig{
		SamplingZones: map[uint16]SamplingDir{
			2: {Input: true, Output: true},  // trust
			3: {Input: true, Output: false}, // untrust
		},
	}

	// Ingress zone has sampling input -> export
	if !ec.ShouldExport(2, 1) {
		t.Error("should export when ingress zone has sampling input")
	}
	// Egress zone has sampling output -> export
	if !ec.ShouldExport(1, 2) {
		t.Error("should export when egress zone has sampling output")
	}
	// Ingress zone=untrust (input only), egress zone=dmz (no sampling) -> export
	if !ec.ShouldExport(3, 1) {
		t.Error("should export when ingress zone has sampling input")
	}
	// Ingress zone=dmz (no sampling), egress zone=untrust (no output) -> skip
	if ec.ShouldExport(1, 3) {
		t.Error("should not export when neither zone has matching sampling")
	}
	// No sampling zones configured -> export all
	ecNone := &ExportConfig{}
	if !ecNone.ShouldExport(1, 2) {
		t.Error("should export all when no sampling zones configured")
	}
}

// TestExporterSharesSingleSampleCounter is the #2224 fail-on-revert
// guard: ExportConfig embeds the live 1-in-N sampleCounter
// (atomic.Uint64), so it MUST be held by pointer everywhere. NewExporter
// / NewIPFIXExporter take *ExportConfig and store that same pointer, so
// the exporter's internal cfg, the daemon-held *ExportConfig, and the
// session-close callback's ShouldExport all increment ONE counter.
//
// Revert the fix (cfg ExportConfig by value + NewExporter(*ec)) and this
// test fails two ways: (1) the exporter's cfg is a distinct copy with a
// freshly-zeroed counter, so sampling through it re-seeds the modulo
// cadence; (2) go vet flags the "copies lock value" diagnostic that this
// test's contract exists to prevent.
func TestExporterSharesSingleSampleCounter(t *testing.T) {
	const rate = 5
	// Empty Collectors -> dialCollectors opens no sockets and returns no
	// error, so the exporters construct without touching the network.
	ec := &ExportConfig{SamplingRate: rate}

	v9, err := NewExporter(ec)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	if v9.cfg != ec {
		t.Fatalf("v9 exporter cfg is a value copy (%p) not the shared *ExportConfig (%p): "+
			"copying forks the sampleCounter and re-seeds the 1-in-N cadence (#2224)", v9.cfg, ec)
	}

	ipfix, err := NewIPFIXExporter(ec)
	if err != nil {
		t.Fatalf("NewIPFIXExporter: %v", err)
	}
	if ipfix.cfg != ec {
		t.Fatalf("ipfix exporter cfg is a value copy (%p) not the shared *ExportConfig (%p) (#2224)",
			ipfix.cfg, ec)
	}

	// Drive the 1-in-N sampler across N packets through the SHARED config
	// (no SamplingZones -> every packet is eligible). The counter
	// increments per call (n := counter.Add(1)); ShouldExport returns true
	// exactly when n % rate == 0. So packet k (1-indexed) samples iff
	// k % rate == 0 -> exactly floor(N/rate) samples, evenly spaced.
	const packets = 100
	got := 0
	for k := 1; k <= packets; k++ {
		sampled := ec.ShouldExport(0, 0)
		wantSampled := k%rate == 0
		if sampled != wantSampled {
			t.Fatalf("packet %d: ShouldExport=%v, want %v (cadence broke -> "+
				"counter was forked, not shared)", k, sampled, wantSampled)
		}
		if sampled {
			got++
		}
	}
	want := packets / rate
	if got != want {
		t.Fatalf("sampled %d of %d packets at 1-in-%d, want %d", got, packets, rate, want)
	}

	// The shared counter has advanced to exactly `packets` — proving the
	// exporters did not fork their own zeroed copies. If cfg were copied
	// by value, v9.cfg/ipfix.cfg would each hold an independent counter
	// still at 0 while only `ec`'s advanced.
	if n := ec.sampleCounter.Load(); n != packets {
		t.Fatalf("shared sampleCounter = %d, want %d", n, packets)
	}
	if n := v9.cfg.sampleCounter.Load(); n != packets {
		t.Fatalf("v9 exporter sees sampleCounter = %d, want %d (counter forked)", n, packets)
	}
	if n := ipfix.cfg.sampleCounter.Load(); n != packets {
		t.Fatalf("ipfix exporter sees sampleCounter = %d, want %d (counter forked)", n, packets)
	}
}

func TestParseIfaceRef(t *testing.T) {
	tests := []struct {
		ref      string
		wantName string
		wantUnit int
		wantOK   bool
	}{
		// Valid references.
		{"eth0.0", "eth0", 0, true},
		{"trust0.5", "trust0", 5, true},
		{"ge-0/0/0.100", "ge-0/0/0", 100, true},
		// Bare name (no dot) — legitimate config form, implicit unit 0.
		{"enp6s0", "enp6s0", 0, true},
		{"ge-0/0/0", "ge-0/0/0", 0, true},
		// Malformed unit suffixes — strict parse rejects (#2463). The old
		// digit-accumulation scan accepted all of these with a wrong/zero
		// unit (1abc2->12, foo->0, -1->1).
		{"ge-0/0/0.1abc2", "ge-0/0/0", 0, false},
		{"ge-0/0/0.foo", "ge-0/0/0", 0, false},
		{"ge-0/0/0.-1", "ge-0/0/0", 0, false},
		{"ge-0/0/0.+1", "ge-0/0/0", 0, false},
		{"ge-0/0/0. 1", "ge-0/0/0", 0, false},
		{"ge-0/0/0.", "ge-0/0/0", 0, false},
		{"ge-0/0/0.12x", "ge-0/0/0", 0, false},
	}
	for _, tt := range tests {
		name, unit, ok := parseIfaceRef(tt.ref)
		if name != tt.wantName || unit != tt.wantUnit || ok != tt.wantOK {
			t.Errorf("parseIfaceRef(%q) = (%q, %d, %v), want (%q, %d, %v)",
				tt.ref, name, unit, ok, tt.wantName, tt.wantUnit, tt.wantOK)
		}
	}
}

// TestBuildSamplingZonesMalformedRefSkipped is the #2463 fail-on-revert
// guard at the caller layer: a zone whose only interface reference has a
// malformed unit suffix must NOT enable sampling on a bogus (digit-scan)
// unit — BuildSamplingZones warns and skips it, so the zone is absent from
// the result. A second zone with a valid reference still enables sampling
// on the correct unit.
//
// On master parseIfaceRef("ge-0/0/0.1abc2") returns unit 12; if the config
// happened to define unit 12 sampling it would silently be enabled, and a
// "foo"/"" suffix falls back to unit 0 — both divergences this test pins
// against.
func TestBuildSamplingZonesMalformedRefSkipped(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				// Malformed unit suffix: digit-scan would parse unit 12.
				"bad": {Interfaces: []string{"ge-0/0/0.1abc2"}},
				// Valid reference on unit 0.
				"good": {Interfaces: []string{"ge-0/0/1.0"}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Units: map[int]*config.InterfaceUnit{
						// Unit 12 has sampling enabled — the digit-scan
						// mis-parse would wrongly turn this on for "bad".
						12: {SamplingInput: true, SamplingOutput: true},
					},
				},
				"ge-0/0/1": {
					Units: map[int]*config.InterfaceUnit{
						0: {SamplingInput: true},
					},
				},
			},
		},
	}

	zoneIDs := map[string]uint16{"bad": 1, "good": 2}
	sz := BuildSamplingZones(cfg, zoneIDs)

	// "bad" (id=1) must NOT enable sampling — the malformed ref is skipped,
	// so the bogus unit-12 sampling config is never consulted.
	if d, ok := sz[1]; ok {
		t.Errorf("bad zone: malformed sampling-interface ref must be skipped, "+
			"got %+v (digit-scan mis-parse enabled the wrong unit)", d)
	}
	// "good" (id=2) enables input sampling on the correct unit 0.
	if d, ok := sz[2]; !ok || !d.Input || d.Output {
		t.Errorf("good zone: got %+v (ok=%v), want Input=true Output=false", sz[2], ok)
	}
}

func TestBuildSamplingZonesAbsentUnitDoesNotWidenExport(t *testing.T) {
	for _, tc := range []struct {
		name         string
		zoneRefs     []string
		wantEligible bool
	}{
		{name: "absent unit", zoneRefs: []string{"ge-0/0/0.1"}},
		{name: "defined unit", zoneRefs: []string{"ge-0/0/0.0"}, wantEligible: true},
		{
			name:         "absent plus defined unit",
			zoneRefs:     []string{"ge-0/0/0.1", "ge-0/0/0.0"},
			wantEligible: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Security: config.SecurityConfig{
					Zones: map[string]*config.ZoneConfig{
						"trust": {Interfaces: tc.zoneRefs},
					},
				},
				Interfaces: config.InterfacesConfig{
					Interfaces: map[string]*config.InterfaceConfig{
						"ge-0/0/0": {Units: map[int]*config.InterfaceUnit{
							0: {SamplingInput: true},
						}},
					},
				},
			}
			ec := &ExportConfig{SamplingZones: BuildSamplingZones(cfg, map[string]uint16{"trust": 1})}
			if got := ec.ShouldExport(1, 99); got != tc.wantEligible {
				t.Fatalf("ShouldExport(trust, unrelated) = %v, want %v (sampling zones: %#v)",
					got, tc.wantEligible, ec.SamplingZones)
			}
			if ec.ShouldExport(99, 99) {
				t.Fatal("session outside the configured sampling zone was exported")
			}
		})
	}

	// A truly absent sampling-zone restriction intentionally retains the
	// documented export-all behavior.
	if !(&ExportConfig{}).ShouldExport(99, 99) {
		t.Fatal("empty ExportConfig should remain export-all")
	}

	unrestricted := BuildSamplingZones(&config.Config{}, nil)
	if unrestricted != nil {
		t.Fatalf("no configured sampling restriction should produce nil zones, got %#v", unrestricted)
	}
	if !(&ExportConfig{SamplingZones: unrestricted}).ShouldExport(99, 99) {
		t.Fatal("nil sampling-zone result should retain export-all behavior")
	}
}

func TestBuildExportConfig_FlowServerSourceAddressTakesPrecedence(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress:            "10.0.1.20",
						InlineJflow:              true,
						InlineJflowSourceAddress: "10.0.1.10",
					},
				},
			},
		},
	}

	ec := BuildExportConfig(v9Svc(), fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if ec.Collectors[0].SourceAddress != "10.0.1.20" {
		t.Errorf("SourceAddress = %q, want flow-server source-address %q", ec.Collectors[0].SourceAddress, "10.0.1.20")
	}
}

func TestBuildExportConfig_DistinctSourceAddressesAreNotDeduped(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress: "10.0.1.10",
					},
					FamilyInet6: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress: "10.0.1.11",
					},
				},
			},
		},
	}

	// #6811: this fixture creates its two collectors by putting the same
	// address under BOTH families with different source-addresses, so they now
	// land in two (template, family) groups rather than one. The #3745 property
	// under test is unchanged — both collectors are RETAINED, neither deduped
	// away — so the assertion counts across groups instead of pinning one
	// group's length, which would have been asserting the grouping, not the
	// dedup.
	groups := ResolveV9TemplateGroups(v9Svc(), fo)
	if len(groups) == 0 {
		t.Fatal("expected at least one ExportConfig")
	}
	total := 0
	srcs := map[string]bool{}
	for _, g := range groups {
		total += len(g.Collectors)
		for _, c := range g.Collectors {
			srcs[c.SourceAddress] = true
		}
	}
	if total != 2 {
		t.Fatalf("expected 2 collectors across all groups, got %d", total)
	}
	if len(srcs) != 2 {
		t.Fatalf("expected 2 DISTINCT source addresses, got %d (%v) — the per-collector "+
			"source-address override was deduped away (#3745)", len(srcs), srcs)
	}
}

func TestIPFIXHeader(t *testing.T) {
	h := ipfixHeader{
		Version:        10,
		Length:         100,
		ExportTime:     1700000000,
		SequenceNumber: 42,
		ObservationID:  1,
	}
	b := encodeIPFIXHeader(h)
	if len(b) != 16 {
		t.Fatalf("header len = %d, want 16", len(b))
	}
	if v := binary.BigEndian.Uint16(b[0:2]); v != 10 {
		t.Errorf("version = %d, want 10", v)
	}
	if v := binary.BigEndian.Uint16(b[2:4]); v != 100 {
		t.Errorf("length = %d, want 100", v)
	}
	if v := binary.BigEndian.Uint32(b[4:8]); v != 1700000000 {
		t.Errorf("export time = %d, want 1700000000", v)
	}
	if v := binary.BigEndian.Uint32(b[8:12]); v != 42 {
		t.Errorf("seq = %d, want 42", v)
	}
	if v := binary.BigEndian.Uint32(b[12:16]); v != 1 {
		t.Errorf("observation ID = %d, want 1", v)
	}
}

func TestIPFIXTemplateSet(t *testing.T) {
	b := encodeIPFIXTemplateSet()
	if len(b) < 4 {
		t.Fatalf("template set too short: %d bytes", len(b))
	}
	// Set ID should be 2 (template)
	setID := binary.BigEndian.Uint16(b[0:2])
	if setID != ipfixSetIDTemplate {
		t.Errorf("set ID = %d, want %d", setID, ipfixSetIDTemplate)
	}
	setLen := binary.BigEndian.Uint16(b[2:4])
	if int(setLen) != len(b) {
		t.Errorf("set length = %d, want %d", setLen, len(b))
	}
	// First template ID should be 256 (v4)
	tmplID := binary.BigEndian.Uint16(b[4:6])
	if tmplID != ipfixTemplateIDv4 {
		t.Errorf("first template ID = %d, want %d", tmplID, ipfixTemplateIDv4)
	}
}

func TestIPFIXDataSetV4(t *testing.T) {
	now := time.Now()
	records := []FlowRecord{
		{
			SrcIP:     net.IPv4(10, 0, 1, 100),
			DstIP:     net.IPv4(10, 0, 2, 200),
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  6,
			Packets:   100,
			Bytes:     50000,
			StartTime: now.Add(-time.Second),
			EndTime:   now,
			IsIPv6:    false,
		},
	}

	ds := encodeIPFIXDataSet(records)
	if ds == nil {
		t.Fatal("expected non-nil data set")
	}
	// Set header: template ID 256
	setID := binary.BigEndian.Uint16(ds[0:2])
	if setID != ipfixTemplateIDv4 {
		t.Errorf("data set ID = %d, want %d", setID, ipfixTemplateIDv4)
	}
	// Length should be 4 (header) + 57 (one record) = 61
	setLen := binary.BigEndian.Uint16(ds[2:4])
	if setLen != 4+ipfixRecordSizeV4 {
		t.Errorf("data set length = %d, want %d", setLen, 4+ipfixRecordSizeV4)
	}
	// Verify source IP at offset 4
	srcIP := net.IP(ds[4:8])
	if !srcIP.Equal(net.IPv4(10, 0, 1, 100).To4()) {
		t.Errorf("src IP = %s, want 10.0.1.100", srcIP)
	}
}

func TestIPFIXDataSetV6(t *testing.T) {
	now := time.Now()
	records := []FlowRecord{
		{
			SrcIP:     net.ParseIP("2001:db8::1"),
			DstIP:     net.ParseIP("2001:db8::2"),
			SrcPort:   443,
			DstPort:   54321,
			Protocol:  6,
			Packets:   50,
			Bytes:     25000,
			StartTime: now.Add(-time.Second),
			EndTime:   now,
			IsIPv6:    true,
		},
	}

	ds := encodeIPFIXDataSet(records)
	if ds == nil {
		t.Fatal("expected non-nil data set")
	}
	setID := binary.BigEndian.Uint16(ds[0:2])
	if setID != ipfixTemplateIDv6 {
		t.Errorf("data set ID = %d, want %d", setID, ipfixTemplateIDv6)
	}
	setLen := binary.BigEndian.Uint16(ds[2:4])
	if setLen != 4+ipfixRecordSizeV6 {
		t.Errorf("data set length = %d, want %d", setLen, 4+ipfixRecordSizeV6)
	}
}

func TestBuildIPFIXExportConfig(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			VersionIPFIX: &config.NetFlowIPFIXConfig{
				Templates: map[string]*config.NetFlowIPFIXTemplate{
					"t1": {
						FlowActiveTimeout:   120,
						FlowInactiveTimeout: 30,
						TemplateRefreshRate: 90,
					},
				},
			},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name:      "test",
					InputRate: 100,
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 4739},
						},
					},
				},
			},
		},
	}

	ec := BuildIPFIXExportConfig(svc, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if ec.FlowActiveTimeout != 120*time.Second {
		t.Errorf("active timeout = %v, want 120s", ec.FlowActiveTimeout)
	}
	if ec.FlowInactiveTimeout != 30*time.Second {
		t.Errorf("inactive timeout = %v, want 30s", ec.FlowInactiveTimeout)
	}
	if ec.TemplateRefreshRate != 90*time.Second {
		t.Errorf("refresh rate = %v, want 90s", ec.TemplateRefreshRate)
	}
	if ec.SamplingRate != 100 {
		t.Errorf("sampling rate = %d, want 100", ec.SamplingRate)
	}
	if len(ec.Collectors) != 1 {
		t.Fatalf("collectors = %d, want 1", len(ec.Collectors))
	}
	if ec.Collectors[0].Address != "10.0.0.1:4739" {
		t.Errorf("collector address = %q, want %q", ec.Collectors[0].Address, "10.0.0.1:4739")
	}
}

func TestBuildIPFIXExportConfig_NilIPFIX(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
					},
				},
			},
		},
	}
	ec := BuildIPFIXExportConfig(svc, fo)
	if ec != nil {
		t.Error("expected nil ExportConfig when VersionIPFIX is not set")
	}
}

func TestBuildIPFIXExportConfig_DistinctSourceAddressesAreNotDeduped(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			VersionIPFIX: &config.NetFlowIPFIXConfig{
				Templates: map[string]*config.NetFlowIPFIXTemplate{
					"tmpl": {Name: "tmpl"},
				},
			},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress: "10.0.1.10",
					},
					FamilyInet6: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress: "10.0.1.11",
					},
				},
			},
		},
	}

	// #6811: this fixture creates its two collectors by putting the same
	// address under BOTH families with different source-addresses, so they now
	// land in two (template, family) groups rather than one. The #3745 property
	// under test is unchanged — both collectors are RETAINED, neither deduped
	// away — so the assertion counts across groups instead of pinning one
	// group's length, which would have been asserting the grouping, not the
	// dedup.
	groups := ResolveIPFIXTemplateGroups(svc, fo)
	if len(groups) == 0 {
		t.Fatal("expected at least one ExportConfig")
	}
	total := 0
	srcs := map[string]bool{}
	for _, g := range groups {
		total += len(g.Collectors)
		for _, c := range g.Collectors {
			srcs[c.SourceAddress] = true
		}
	}
	if total != 2 {
		t.Fatalf("expected 2 collectors across all groups, got %d", total)
	}
	if len(srcs) != 2 {
		t.Fatalf("expected 2 DISTINCT source addresses, got %d (%v) — the per-collector "+
			"source-address override was deduped away (#3745)", len(srcs), srcs)
	}
}

// TestV9TemplateFlowDirConditional pins the #3270 contract: fieldDirection
// (IE 61) appears in the v9 template IFF IncludeFlowDir is set. Opt-out keeps
// it absent (no #2613 synthetic-zero regression); opt-in advertises it so the
// collector parses the real sampling-direction-derived value. Reverting the
// splice (so the field never appears even with IncludeFlowDir) re-fails the
// present-when-enabled half.
func TestV9TemplateFlowDirConditional(t *testing.T) {
	for _, includeDir := range []bool{true, false} {
		opts := V9TemplateOptions{IncludeFlowDir: includeDir}
		for _, tc := range []struct {
			name   string
			fields []templateField
		}{
			{"v4", buildTemplateFieldsV4(opts)},
			{"v6", buildTemplateFieldsV6(opts)},
		} {
			found := false
			for _, f := range tc.fields {
				if f.fieldType == fieldDirection {
					found = true
				}
			}
			if found != includeDir {
				t.Errorf("includeDir=%v %s: fieldDirection present=%v, want %v",
					includeDir, tc.name, found, includeDir)
			}
		}
	}
}

// TestV9TemplateDroppedFieldsAbsent walks the encoded template FlowSet bytes
// and asserts the genuinely-dropped #2613 IEs stay absent.
//
// #2749: SrcTos (5), TCPFlags (6), InputSNMP (10) and OutputSNMP (14) are NO
// LONGER in this set — they are re-introduced with real values (forward DSCP,
// cumulative TCP control bits, ingress/egress ifindex) and pinned PRESENT by
// TestNetflowIngressInterfacePopulated / TestNetflowCosFieldsPopulated.
//
// #3270: flowDirection (61) is no longer unconditionally dropped — it is
// advertised when `export-extension flow-dir` is set, pinned conditionally by
// TestV9TemplateFlowDirConditional. This test walks the BASE template
// (IncludeFlowDir off) so IE 61 must still be absent there.
func TestV9TemplateDroppedFieldsAbsent(t *testing.T) {
	dropped := map[uint16]string{
		fieldDirection: "Direction",
	}
	for _, includeDir := range []bool{false} {
		tmplFS := encodeTemplateFlowSet(V9TemplateOptions{IncludeFlowDir: includeDir})
		if setID := binary.BigEndian.Uint16(tmplFS[0:2]); setID != 0 {
			t.Errorf("flowset ID = %d, want 0", setID)
		}
		off := 4
		for off+4 <= len(tmplFS) {
			off += 2 // skip template ID
			fieldCount := int(binary.BigEndian.Uint16(tmplFS[off : off+2]))
			off += 2
			for i := 0; i < fieldCount && off+4 <= len(tmplFS); i++ {
				ft := binary.BigEndian.Uint16(tmplFS[off : off+2])
				if name, bad := dropped[ft]; bad {
					t.Errorf("includeDir=%v: dropped IE %s (%d) found in v9 template",
						includeDir, name, ft)
				}
				off += 4
			}
		}
	}
}

func TestV9DataRecordSizeConsistency(t *testing.T) {
	now := time.Now()
	boot := now.Add(-time.Hour)

	for _, includeDir := range []bool{true, false} {
		opts := V9TemplateOptions{IncludeFlowDir: includeDir}
		records := []FlowRecord{
			{
				SrcIP: net.IPv4(10, 0, 1, 1), DstIP: net.IPv4(10, 0, 2, 2),
				SrcPort: 1234, DstPort: 80, Protocol: 6,
				Direction: 1, Packets: 10, Bytes: 1000,
				StartTime: now.Add(-time.Second), EndTime: now,
			},
		}
		ds := encodeDataFlowSet(records, boot, opts)
		if ds == nil {
			t.Fatalf("encodeDataFlowSet returned nil (includeDir=%v)", includeDir)
		}
		fields := buildTemplateFieldsV4(opts)
		expectedRecSize := recordSize(fields)
		// data flowset = 4 (header) + N * recordSize (padded to 4)
		expectedLen := 4 + expectedRecSize
		// Pad to 4
		expectedLen += (4 - expectedLen%4) % 4
		dataLen := int(binary.BigEndian.Uint16(ds[2:4]))
		if dataLen != expectedLen {
			t.Errorf("includeDir=%v: data set length = %d, want %d", includeDir, dataLen, expectedLen)
		}
	}
}

func TestBuildExportConfig_V9Extensions(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"t1": {
						Name:              "t1",
						FlowActiveTimeout: 60,
						ExportExtensions:  []string{"flow-dir"},
					},
				},
			},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
					},
				},
			},
		},
	}
	ec := BuildExportConfig(svc, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if !ec.V9TemplateOpts.IncludeFlowDir {
		t.Error("V9TemplateOpts.IncludeFlowDir should be true when flow-dir extension is set")
	}

	// Without flow-dir extension
	svc2 := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"t2": {
						Name:             "t2",
						ExportExtensions: nil,
					},
				},
			},
		},
	}
	ec2 := BuildExportConfig(svc2, fo)
	if ec2 == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if ec2.V9TemplateOpts.IncludeFlowDir {
		t.Error("V9TemplateOpts.IncludeFlowDir should be false when no extensions set")
	}
}
