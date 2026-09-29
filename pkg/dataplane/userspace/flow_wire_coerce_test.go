package userspace

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1977: these snapshot fields are Go int on the wire but Rust unsigned
// (u16/u32/u64); an out-of-range value would abort the whole apply_snapshot
// serde decode and silently disable the dataplane. The build-boundary guard in
// buildFlowSnapshot/buildFlowExportSnapshot must coerce every such field into
// its Rust wire range. These tests pin that for all 11 fields.

func assertInRange(t *testing.T, name string, v int, max int64) {
	t.Helper()
	if int64(v) < 0 || int64(v) > max {
		t.Fatalf("%s = %d, out of wire range [0,%d] (#1977 decode-abort risk)", name, v, max)
	}
}

func TestBuildFlowSnapshotCoercesOutOfRange_1977(t *testing.T) {
	cfg := &config.Config{}
	// #2486: TCPMSSAllTCP replaces TCPMSSIPsecVPN on the wire (ipsec-vpn is
	// rejected at commit and never serialized). Coerce-test all-tcp here.
	cfg.Security.Flow.TCPMSSAllTCP = 70000               // > u16 max
	cfg.Security.Flow.TCPMSSGreIn = -5                   // < 0
	cfg.Security.Flow.TCPMSSGreOut = math.MaxUint16 + 1  // > u16 max
	cfg.Security.Flow.UDPSessionTimeout = -1             // < 0
	cfg.Security.Flow.ICMPSessionTimeout = math.MaxInt64 // > MaxDurationSeconds
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{EstablishedTimeout: -7}

	snap := buildFlowSnapshot(cfg)
	assertInRange(t, "TCPMSSAllTCP", snap.TCPMSSAllTCP, math.MaxUint16)
	assertInRange(t, "TCPMSSGreIn", snap.TCPMSSGreIn, math.MaxUint16)
	assertInRange(t, "TCPMSSGreOut", snap.TCPMSSGreOut, math.MaxUint16)
	assertInRange(t, "UDPSessionTimeout", snap.UDPSessionTimeout, config.MaxDurationSeconds)
	assertInRange(t, "ICMPSessionTimeout", snap.ICMPSessionTimeout, config.MaxDurationSeconds)
	assertInRange(t, "TCPSessionTimeout", snap.TCPSessionTimeout, config.MaxDurationSeconds)
	// Specific coercions: out-of-range MSS -> 0; huge timeout -> MaxDurationSeconds.
	if snap.TCPMSSAllTCP != 0 || snap.TCPMSSGreIn != 0 || snap.TCPMSSGreOut != 0 {
		t.Fatalf("out-of-range MSS not coerced to 0: %+v", snap)
	}
	if int64(snap.ICMPSessionTimeout) != config.MaxDurationSeconds {
		t.Fatalf("huge ICMP timeout not capped to MaxDurationSeconds: %d", snap.ICMPSessionTimeout)
	}
	if snap.TCPSessionTimeout != 0 || snap.UDPSessionTimeout != 0 {
		t.Fatalf("negative timeouts not coerced to 0: %+v", snap)
	}

	// In-range values pass through unchanged (behavior-preserving).
	cfg2 := &config.Config{}
	cfg2.Security.Flow.TCPMSSGreIn = 1400
	cfg2.Security.Flow.UDPSessionTimeout = 90
	cfg2.Security.Flow.TCPSession = &config.TCPSessionConfig{EstablishedTimeout: 1800}
	snap2 := buildFlowSnapshot(cfg2)
	if snap2.TCPMSSGreIn != 1400 || snap2.UDPSessionTimeout != 90 || snap2.TCPSessionTimeout != 1800 {
		t.Fatalf("in-range values altered: %+v", snap2)
	}
}

func TestBuildFlowSnapshotCarriesUnstampedFabricCompatibility(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.AllowUnstampedFabricIngress = true
	snap := buildFlowSnapshot(cfg)
	if !snap.AllowUnstampedFabricIngress {
		t.Fatal("flow snapshot dropped allow-unstamped-fabric-ingress")
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal flow snapshot: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatalf("decode flow snapshot JSON: %v", err)
	}
	if fields["allow_unstamped_fabric_ingress"] != true {
		t.Fatalf("flow snapshot wire field = %v, want true", fields["allow_unstamped_fabric_ingress"])
	}
}

func TestBuildFlowExportSnapshotCoercesOutOfRange_1977(t *testing.T) {
	mk := func(port int) *config.Config {
		cfg := &config.Config{}
		cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"t1": {Name: "t1", FlowActiveTimeout: -1, FlowInactiveTimeout: math.MaxInt64},
				},
			},
		}
		cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"i1": {Name: "i1", InputRate: math.MaxInt64, FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: "10.0.0.1", Port: port, Version9Template: "t1"},
					},
				}},
			},
		}
		return cfg
	}

	snap := buildFlowExportSnapshot(mk(9995))
	if snap == nil {
		t.Fatal("expected a snapshot for a valid port")
	}
	assertInRange(t, "SamplingRate", snap.SamplingRate, math.MaxUint32)
	assertInRange(t, "ActiveTimeout", snap.ActiveTimeout, math.MaxUint32)
	assertInRange(t, "InactiveTimeout", snap.InactiveTimeout, math.MaxUint32)
	assertInRange(t, "CollectorPort", snap.CollectorPort, math.MaxUint16)
	if int64(snap.SamplingRate) != math.MaxUint32 {
		t.Fatalf("huge InputRate not capped to u32 max: %d", snap.SamplingRate)
	}
	if snap.ActiveTimeout != 0 {
		t.Fatalf("negative ActiveTimeout not coerced to 0: %d", snap.ActiveTimeout)
	}
	if int64(snap.InactiveTimeout) != math.MaxUint32 {
		t.Fatalf("huge InactiveTimeout not capped to u32 max: %d", snap.InactiveTimeout)
	}
	if snap.CollectorPort != 9995 {
		t.Fatalf("valid port altered: %d", snap.CollectorPort)
	}

	// Out-of-range port -> that server is skipped; no other server -> nil.
	if got := buildFlowExportSnapshot(mk(70000)); got != nil {
		t.Fatalf("out-of-range port should skip the server, got %+v", got)
	}
	if got := buildFlowExportSnapshot(mk(-1)); got != nil {
		t.Fatalf("negative port should skip the server, got %+v", got)
	}
}

func TestCoerceWireHelpers_1977(t *testing.T) {
	// u16 (covers TCPMSSAllTCP, now populated by buildFlowSnapshot, #2486).
	for _, tc := range []struct{ in, want int }{
		{70000, 0}, {-1, 0}, {math.MaxUint16 + 1, 0}, {math.MaxUint16, math.MaxUint16}, {0, 0}, {1400, 1400},
	} {
		if got := coerceWireU16("tcp_mss_all_tcp", tc.in); got != tc.want {
			t.Fatalf("coerceWireU16(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
	// u32 timeout.
	if coerceWireU32Timeout("x", -1) != 0 {
		t.Fatal("negative u32 timeout should coerce to 0")
	}
	if int64(coerceWireU32Timeout("x", math.MaxInt64)) != math.MaxUint32 {
		t.Fatal("huge u32 timeout should cap to u32 max")
	}
	if coerceWireU32Timeout("x", 60) != 60 {
		t.Fatal("in-range u32 timeout altered")
	}
	// u64 session timeout.
	if coerceWireSessionTimeout("x", -1) != 0 {
		t.Fatal("negative session timeout should coerce to 0")
	}
	if int64(coerceWireSessionTimeout("x", math.MaxInt64)) != config.MaxDurationSeconds {
		t.Fatal("huge session timeout should cap to MaxDurationSeconds")
	}
	if coerceWireSessionTimeout("x", 1800) != 1800 {
		t.Fatal("in-range session timeout altered")
	}
}

// TestFullSnapshotMarshalsInRange_1977 builds a full apply_snapshot from a
// config carrying out-of-range flow values and confirms the marshaled wire JSON
// keeps the flow/flow-export numerics within their Rust type ranges.
func TestFullSnapshotMarshalsInRange_1977(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.TCPMSSGreIn = 70000
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{EstablishedTimeout: math.MaxInt64}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if _, err := json.Marshal(&ControlRequest{Type: "apply_snapshot", Snapshot: snap}); err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertInRange(t, "Flow.TCPMSSGreIn", snap.Flow.TCPMSSGreIn, math.MaxUint16)
	assertInRange(t, "Flow.TCPSessionTimeout", snap.Flow.TCPSessionTimeout, config.MaxDurationSeconds)
}

// TestFlowExportSkipsInvalidPortContinuesToValid_1977 pins the skip-and-continue
// semantics (Codex r-code hardening): an out-of-range flow-server is skipped and
// scanning continues to the next valid server, rather than aborting the export.
func TestFlowExportSkipsInvalidPortContinuesToValid_1977(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9: &config.NetFlowV9Config{
			Templates: map[string]*config.NetFlowV9Template{
				"t1": {Name: "t1", FlowActiveTimeout: 60, FlowInactiveTimeout: 15},
			},
		},
	}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"i1": {Name: "i1", InputRate: 1000, FamilyInet: &config.SamplingFamily{
				FlowServers: []*config.FlowServer{
					{Address: "10.0.0.1", Port: 70000, Version9Template: "t1"}, // invalid -> skip
					{Address: "10.0.0.2", Port: 9995, Version9Template: "t1"},  // valid -> use
				},
			}},
		},
	}
	snap := buildFlowExportSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected the valid second server to be used after skipping the invalid first")
	}
	if snap.CollectorAddress != "10.0.0.2" || snap.CollectorPort != 9995 {
		t.Fatalf("expected 10.0.0.2:9995, got %s:%d", snap.CollectorAddress, snap.CollectorPort)
	}
}

// TestBuildFlowSnapshotThreadsPowerModeDisable pins the #2008 H14 thread-through:
// `security flow power-mode-disable` (cfg.Security.Flow.PowerModeDisable) must
// reach FlowSnapshot.PowerModeDisable, mirroring the GREAcceleration plumbing.
func TestBuildFlowSnapshotThreadsPowerModeDisable(t *testing.T) {
	cfg := &config.Config{}
	if snap := buildFlowSnapshot(cfg); snap.PowerModeDisable {
		t.Fatal("PowerModeDisable should be false when unset")
	}
	cfg.Security.Flow.PowerModeDisable = true
	if snap := buildFlowSnapshot(cfg); !snap.PowerModeDisable {
		t.Fatal("PowerModeDisable should be threaded into FlowSnapshot")
	}
}

// TestBuildFlowSnapshotThreadsGREAcceleration pins the #3360 thread-through:
// `security flow gre-performance-acceleration`
// (cfg.Security.Flow.GREPerformanceAcceleration) must reach
// FlowSnapshot.GREAcceleration so the wire bit reflects operator intent.
func TestBuildFlowSnapshotThreadsGREAcceleration(t *testing.T) {
	cfg := &config.Config{}
	if snap := buildFlowSnapshot(cfg); snap.GREAcceleration {
		t.Fatal("GREAcceleration should be false when unset")
	}
	cfg.Security.Flow.GREPerformanceAcceleration = true
	if snap := buildFlowSnapshot(cfg); !snap.GREAcceleration {
		t.Fatal("GREAcceleration should be threaded into FlowSnapshot")
	}
}
