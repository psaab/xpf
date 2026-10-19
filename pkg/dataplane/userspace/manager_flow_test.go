package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildFlowSnapshotIncludesTimeouts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.AllowDNSReply = true
	cfg.Security.Flow.AllowEmbeddedICMP = true
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 120,
	}
	cfg.Security.Flow.UDPSessionTimeout = 30
	cfg.Security.Flow.ICMPSessionTimeout = 10
	snap := buildFlowSnapshot(cfg)
	if !snap.AllowDNSReply {
		t.Fatal("AllowDNSReply = false")
	}
	if !snap.AllowEmbeddedICMP {
		t.Fatal("AllowEmbeddedICMP = false")
	}
	if snap.TCPSessionTimeout != 120 {
		t.Fatalf("TCPSessionTimeout = %d, want 120", snap.TCPSessionTimeout)
	}
	if snap.UDPSessionTimeout != 30 {
		t.Fatalf("UDPSessionTimeout = %d, want 30", snap.UDPSessionTimeout)
	}
	if snap.ICMPSessionTimeout != 10 {
		t.Fatalf("ICMPSessionTimeout = %d, want 10", snap.ICMPSessionTimeout)
	}
}

func TestBuildFlowSnapshotNilTCPSession(t *testing.T) {
	cfg := &config.Config{}
	snap := buildFlowSnapshot(cfg)
	if snap.TCPSessionTimeout != 0 {
		t.Fatalf("TCPSessionTimeout = %d, want 0", snap.TCPSessionTimeout)
	}
}

// TestBuildFlowSnapshotPacksALGDisableFlags verifies the `security alg <proto>
// disable` knobs reach the dataplane wire snapshot (#2008 H3/H4). Before the
// fix the flags were written only to the legacy flow_config_map (no userspace
// reader) and FlowSnapshot did not carry them at all, so `alg disable` was a
// silent no-op. The bit layout MUST match pkg/dataplane/compiler.go and the
// Rust ALG_DISABLE_* constants: DNS=0x01, FTP=0x02, SIP=0x04, TFTP=0x08.
func TestBuildFlowSnapshotPacksALGDisableFlags(t *testing.T) {
	cases := []struct {
		name string
		set  func(*config.ALGConfig)
		want uint8
	}{
		{"none", func(*config.ALGConfig) {}, 0x00},
		{"dns", func(a *config.ALGConfig) { a.DNSDisable = true }, 0x01},
		{"ftp", func(a *config.ALGConfig) { a.FTPDisable = true }, 0x02},
		{"sip", func(a *config.ALGConfig) { a.SIPDisable = true }, 0x04},
		{"tftp", func(a *config.ALGConfig) { a.TFTPDisable = true }, 0x08},
		{"pptp", func(a *config.ALGConfig) { a.PPTPDisable = true }, 0x10},
		{"dns+ftp", func(a *config.ALGConfig) {
			a.DNSDisable = true
			a.FTPDisable = true
		}, 0x03},
		{"all", func(a *config.ALGConfig) {
			a.DNSDisable = true
			a.FTPDisable = true
			a.SIPDisable = true
			a.TFTPDisable = true
			a.PPTPDisable = true
		}, 0x1f},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			tc.set(&cfg.Security.ALG)
			snap := buildFlowSnapshot(cfg)
			if snap.ALGDisableFlags != tc.want {
				t.Fatalf("ALGDisableFlags = 0x%02x, want 0x%02x", snap.ALGDisableFlags, tc.want)
			}
			// The flags must survive the JSON wire encoding the helper
			// decodes; a missing/renamed tag would silently drop them
			// (the #1961 failure class).
			data, err := json.Marshal(snap)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var rt FlowSnapshot
			if err := json.Unmarshal(data, &rt); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if rt.ALGDisableFlags != tc.want {
				t.Fatalf("round-trip ALGDisableFlags = 0x%02x, want 0x%02x", rt.ALGDisableFlags, tc.want)
			}
		})
	}
}

func TestBuildFlowExportSnapshot(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9: &config.NetFlowV9Config{
			Templates: map[string]*config.NetFlowV9Template{
				"tmpl1": {
					Name:              "tmpl1",
					FlowActiveTimeout: 120,
				},
			},
		},
	}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"inst1": {
				Name:      "inst1",
				InputRate: 100,
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: "10.0.1.1", Port: 9995, Version9Template: "tmpl1"},
					},
				},
			},
		},
	}

	snap := buildFlowExportSnapshot(cfg)
	if snap == nil {
		t.Fatal("expected non-nil flow export snapshot")
	}
	if snap.CollectorAddress != "10.0.1.1" {
		t.Fatalf("CollectorAddress = %q, want 10.0.1.1", snap.CollectorAddress)
	}
	if snap.CollectorPort != 9995 {
		t.Fatalf("CollectorPort = %d, want 9995", snap.CollectorPort)
	}
	if snap.SamplingRate != 100 {
		t.Fatalf("SamplingRate = %d, want 100", snap.SamplingRate)
	}
	if snap.ActiveTimeout != 120 {
		t.Fatalf("ActiveTimeout = %d, want 120", snap.ActiveTimeout)
	}
}

func TestBuildFlowExportSnapshotNilWhenNoConfig(t *testing.T) {
	cfg := &config.Config{}
	snap := buildFlowExportSnapshot(cfg)
	if snap != nil {
		t.Fatal("expected nil flow export snapshot with no config")
	}
}
