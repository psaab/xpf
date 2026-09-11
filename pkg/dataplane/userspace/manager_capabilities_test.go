package userspace

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestDeriveUserspaceConfigDefaults(t *testing.T) {
	cfg := deriveUserspaceConfig(&config.Config{})
	if cfg.Workers != 1 {
		t.Fatalf("Workers = %d, want 1", cfg.Workers)
	}
	if cfg.RingEntries != 1024 {
		t.Fatalf("RingEntries = %d, want 1024", cfg.RingEntries)
	}
	if cfg.ControlSocket == "" {
		t.Fatal("ControlSocket is empty")
	}
	if cfg.StateFile == "" {
		t.Fatal("StateFile is empty")
	}
}

func TestDeriveUserspaceCapabilitiesDetectsFirewallFeatures(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"trust": {Name: "trust"}}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{Name: "src"}}
	cfg.Security.Flow.AllowDNSReply = true
	// Firewall filters (inet/inet6), single-rate policers, and three-color
	// policers are now supported.
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{"f1": {Name: "f1"}}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; firewall filters and flow monitoring are now supported. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAdmitsThreeColorPolicers(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.ThreeColorPolicers = map[string]*config.ThreeColorPolicerConfig{
		"tcp1": {Name: "tcp1", ColorBlind: true, CIR: 1000000, CBS: 50000, ThenAction: "discard"},
	}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, want true for three-color policers. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesRejectsUnsupportedThreeColorPolicerActions(t *testing.T) {
	tests := []struct {
		name string
		pol  *config.ThreeColorPolicerConfig
	}{
		{
			name: "color-aware",
			pol:  &config.ThreeColorPolicerConfig{Name: "aware", CIR: 1000000, CBS: 50000, PBS: 50000, ThenAction: "discard"},
		},
		{
			// #9503: `then loss-priority <level>` is no longer here. It applies
			// meter-only and keeps forwarding armed (three_color_loss_priority_9503_test.go).
			// An action neither the Go gate nor the helper knows still refuses.
			name: "unknown-action",
			pol: &config.ThreeColorPolicerConfig{
				Name:       "unknown",
				ColorBlind: true,
				CIR:        1000000,
				CBS:        50000,
				PBS:        50000,
				ThenAction: "frobnicate",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Firewall.ThreeColorPolicers = map[string]*config.ThreeColorPolicerConfig{
				tt.pol.Name: tt.pol,
			}
			caps := deriveUserspaceCapabilities(cfg)
			if caps.ForwardingSupported {
				t.Fatal("ForwardingSupported = true, want fail-closed for unsupported three-color policer mode/action")
			}
			if !slices.Contains(caps.UnsupportedReasons, "userspace three-color policers require color-blind mode and a supported then action") {
				t.Fatalf("UnsupportedReasons = %+v, want three-color reason", caps.UnsupportedReasons)
			}
		})
	}
}

func TestDeriveUserspaceCapabilitiesAllowsPortMirroringRuntimeSlice(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span1": {
				Name:      "span1",
				InputRate: 10,
				Input:     []string{"ge-0/0/0.0"},
				Output:    "ge-0/0/1.0",
			},
		},
	}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, reasons: %+v", caps.UnsupportedReasons)
	}
	for _, r := range caps.UnsupportedReasons {
		if strings.Contains(r, "port mirroring") {
			t.Fatalf("stale port-mirroring rejection present: %+v", caps.UnsupportedReasons)
		}
	}
}

func TestDeriveUserspaceCapabilitiesAllowsFirewallFilters(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-RE": {Name: "protect-RE"},
	}
	cfg.Firewall.Policers = map[string]*config.PolicerConfig{
		"1mbps": {Name: "1mbps", BandwidthLimit: 125000, BurstSizeLimit: 50000},
	}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsIPsecConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
		"gw1": {Name: "gw1"},
	}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn1": {Name: "vpn1", Gateway: "gw1"},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; IPsec should not gate userspace forwarding. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsTunnelInterfaces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {
			Name:   "st0",
			Tunnel: &config.TunnelConfig{},
			Units: map[int]*config.InterfaceUnit{
				0: {Tunnel: &config.TunnelConfig{}},
			},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false; tunnel interfaces should not gate userspace forwarding. Reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsFlowMonitoring(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, want true (flow monitoring now supported); reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsDNSFlowKnobs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.AllowDNSReply = true
	cfg.Security.Flow.AllowEmbeddedICMP = true

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsHAFabricConfigs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:         22,
		PrivateRGElection: true,
		FabricInterface:   "fab0",
		FabricPeerAddress: "10.99.13.2",
	}

	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAdmitsHAPersistentSourceNAT8573(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 22}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-a": {
			Name:          "pool-a",
			Addresses:     []string{"203.0.113.10"},
			PersistentNAT: &config.PersistentNATConfig{InactivityTimeout: 300},
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "trust",
		ToZone:   "wan",
		Rules: []*config.NATRule{{
			Name: "snat",
			Then: config.NATThen{
				Type:     config.NATSource,
				PoolName: "pool-a",
			},
		}},
	}}

	// #8573 INVERTED. This cell used to assert the disarm — ForwardingSupported
	// false with the "leases are not HA-synchronized" reason. That reason was
	// measured false on the loss userspace cluster (a lease created on the
	// active reaches the standby, survives a failover, and is HONOURED by the
	// new active, which hands the same source identity the same translated
	// identity), so the disarm was removed and this now guards the OTHER
	// direction: a clustered persistent-NAT config must FORWARD.
	//
	// It is inverted rather than deleted on purpose. Deleting it would leave
	// nothing to red if the gate were reintroduced — and the gate's cost is a
	// total transit stop that presents as a link failure, which is what took
	// #8447 five rounds of cluster measurement to identify.
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false for a clustered persistent-NAT config, "+
			"reasons %+v. #8573 removed that disarm after measuring the premise false; "+
			"re-adding it stops transit entirely while the interfaces stay up and the "+
			"config commits clean — a connectivity failure with no NAT-shaped symptom",
			caps.UnsupportedReasons)
	}
	for _, r := range caps.UnsupportedReasons {
		if strings.Contains(r, "persistent-nat") {
			t.Errorf("a persistent-NAT unsupported reason is back: %q", r)
		}
	}
}

func TestEnsureRequiredSnapshotProtocolRejectsOldHelperForPersistentSourceNAT(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-a": {
			Name:          "pool-a",
			Addresses:     []string{"203.0.113.10"},
			PersistentNAT: &config.PersistentNATConfig{InactivityTimeout: 300},
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "trust",
		ToZone:   "wan",
		Rules: []*config.NATRule{{
			Name: "snat",
			Then: config.NATThen{
				Type:     config.NATSource,
				PoolName: "pool-a",
			},
		}},
	}}

	m := New()
	// #6648: BELOW THE FEATURE'S FLOOR, not below ProtocolVersion. This used to
	// say `ProtocolVersion - 1`, which asserted that a helper one version behind
	// the shared constant cannot represent persistent source NAT. It can:
	// persistent SNAT pool leases have been representable since v3
	// (MinProtocolPersistentSourceNAT), so the sentinel this test names is the
	// wrong answer for a v7 helper — the right one is the unconditional
	// egress-zone gate, and pinning the feature sentinel there was pinning the
	// coupling #6648 removes. Retargeted, not relaxed: the assertion is
	// unchanged and now runs against a helper that genuinely cannot carry the
	// feature.
	m.lastStatus.ConfigSnapshotProtocolVersion = MinProtocolPersistentSourceNAT - 1
	err := m.ensureRequiredSnapshotProtocolLocked(gateSnapshot(t, cfg))
	if !errors.Is(err, ErrPersistentSourceNATProtocolIncompatible) {
		t.Fatalf("error = %v, want ErrPersistentSourceNATProtocolIncompatible", err)
	}
}

// TestIsRequiredProtocolGateError is the #2138 regression: the
// commit-abort set must cover every sentinel emitted by
// ensureRequiredSnapshotProtocolLocked. Before #2138 the persistent
// source NAT gate disarmed the helper but was missing from the daemon's
// abort set, so a mismatch promoted the commit against a disarmed
// dataplane. The predicate must match BOTH required gates (bare and
// wrapped) and must NOT match unrelated errors.
func TestIsRequiredProtocolGateError(t *testing.T) {
	for _, sentinel := range []error{
		ErrPolicySchedulerProtocolIncompatible,
		ErrPersistentSourceNATProtocolIncompatible,
		ErrScopedGlobalZoneSetProtocolIncompatible,
	} {
		if !IsRequiredProtocolGateError(sentinel) {
			t.Errorf("IsRequiredProtocolGateError(%v) = false, want true (bare sentinel)", sentinel)
		}
		wrapped := fmt.Errorf("apply userspace config: %w", sentinel)
		if !IsRequiredProtocolGateError(wrapped) {
			t.Errorf("IsRequiredProtocolGateError(%v) = false, want true (wrapped sentinel)", wrapped)
		}
	}
	if IsRequiredProtocolGateError(nil) {
		t.Error("IsRequiredProtocolGateError(nil) = true, want false")
	}
	if IsRequiredProtocolGateError(errors.New("unrelated apply failure")) {
		t.Error("IsRequiredProtocolGateError(unrelated) = true, want false")
	}
}

func TestDeriveUserspaceCapabilitiesAllowsBasicScreenProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "basic"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"basic": {
			Name: "basic",
			TCP:  config.TCPScreen{Land: true, SynFin: true},
			ICMP: config.ICMPScreen{FloodThreshold: 100},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsSynCookieScreen(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.SynFloodProtectionMode = "syn-cookie"
	cfg.System.RootAuthentication = &config.RootAuthConfig{
		EncryptedPassword: "$6$rounds=5000$salt$hash",
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "flood"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"flood": {
			Name: "flood",
			TCP:  config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 100}},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, reasons: %+v", caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesRejectsSynCookieWithoutRootSecret(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.SynFloodProtectionMode = "syn-cookie"
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", ScreenProfile: "flood"},
	}
	cfg.Security.Screen = map[string]*config.ScreenProfile{
		"flood": {
			Name: "flood",
			TCP:  config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 100}},
		},
	}
	caps := deriveUserspaceCapabilities(cfg)
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true, want false without SYN-cookie secret material")
	}
	if len(caps.UnsupportedReasons) != 1 ||
		!strings.Contains(caps.UnsupportedReasons[0], "root-authentication") {
		t.Fatalf("UnsupportedReasons = %+v, want SYN-cookie root-authentication reason",
			caps.UnsupportedReasons)
	}
}

func TestDeriveUserspaceCapabilitiesAllowsSessionTimeouts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{
		EstablishedTimeout: 120,
	}
	cfg.Security.Flow.UDPSessionTimeout = 30
	cfg.Security.Flow.ICMPSessionTimeout = 10
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false, unexpected reasons: %+v", caps.UnsupportedReasons)
	}
}
