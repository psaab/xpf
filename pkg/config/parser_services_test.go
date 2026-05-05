package config

import (
	"strings"
	"testing"
)

func TestRPMDefaultsAndValidation(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		input := `services {
    rpm {
        probe monitor {
            test ping-test {
                target 8.8.8.8;
            }
            test tcp-test {
                probe-type tcp-ping;
                target 1.1.1.1;
            }
        }
    }
}
`
		parser := NewParser(input)
		tree, errs := parser.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse errors: %v", errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}

		pingTest := cfg.Services.RPM.Probes["monitor"].Tests["ping-test"]
		if got := pingTest.EffectiveProbeType(); got != DefaultRPMProbeType {
			t.Fatalf("EffectiveProbeType() = %q, want %q", got, DefaultRPMProbeType)
		}
		if got := pingTest.EffectiveProbeInterval(); got != DefaultRPMProbeIntervalSeconds {
			t.Fatalf("EffectiveProbeInterval() = %d, want %d", got, DefaultRPMProbeIntervalSeconds)
		}
		if got := pingTest.EffectiveProbeCount(); got != DefaultRPMProbeCount {
			t.Fatalf("EffectiveProbeCount() = %d, want %d", got, DefaultRPMProbeCount)
		}
		if got := pingTest.EffectiveTestInterval(); got != DefaultRPMTestIntervalSeconds {
			t.Fatalf("EffectiveTestInterval() = %d, want %d", got, DefaultRPMTestIntervalSeconds)
		}
		if got := pingTest.EffectiveSuccessiveLossThreshold(); got != DefaultRPMSuccessiveLosses {
			t.Fatalf("EffectiveSuccessiveLossThreshold() = %d, want %d", got, DefaultRPMSuccessiveLosses)
		}

		tcpTest := cfg.Services.RPM.Probes["monitor"].Tests["tcp-test"]
		if got := tcpTest.EffectiveDestinationPort(); got != DefaultRPMTCPDestinationPort {
			t.Fatalf("EffectiveDestinationPort() = %d, want %d", got, DefaultRPMTCPDestinationPort)
		}
	})

	t.Run("root probe-limit inheritance", func(t *testing.T) {
		input := `services {
    rpm {
        probe-limit 3;
        probe monitor {
            test inherited {
                target 8.8.8.8;
            }
            test explicit {
                target 1.1.1.1;
                probe-limit 5;
            }
        }
    }
}
`
		parser := NewParser(input)
		tree, errs := parser.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse errors: %v", errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}

		probe := cfg.Services.RPM.Probes["monitor"]
		if probe == nil {
			t.Fatal("expected probe monitor")
		}
		if got := probe.Tests["inherited"].ProbeLimit; got != 3 {
			t.Fatalf("inherited ProbeLimit = %d, want 3", got)
		}
		if got := probe.Tests["explicit"].ProbeLimit; got != 5 {
			t.Fatalf("explicit ProbeLimit = %d, want 5", got)
		}
	})

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "zero root probe limit rejected",
			input: `services {
    rpm {
        probe-limit 0;
        probe monitor {
            test ping-test {
                target 8.8.8.8;
            }
        }
    }
}
`,
			wantErr: "services rpm probe-limit",
		},
		{
			name: "missing target",
			input: `services {
    rpm {
        probe monitor {
            test ping-test {
                probe-type icmp-ping;
            }
        }
    }
}
`,
			wantErr: "target is required",
		},
		{
			name: "unsupported probe type",
			input: `services {
    rpm {
        probe monitor {
            test ping-test {
                probe-type udp-ping;
                target 8.8.8.8;
            }
        }
    }
}
`,
			wantErr: "unsupported probe-type",
		},
		{
			name: "invalid numeric value",
			input: `services {
    rpm {
        probe monitor {
            test ping-test {
                target 8.8.8.8;
                probe-count nope;
            }
        }
    }
}
`,
			wantErr: "invalid integer",
		},
		{
			name: "zero probe limit rejected",
			input: `services {
    rpm {
        probe monitor {
            test ping-test {
                target 8.8.8.8;
                probe-limit 0;
            }
        }
    }
}
`,
			wantErr: "must be > 0",
		},
		{
			name: "destination port range validated",
			input: `services {
    rpm {
        probe monitor {
            test ping-test {
                probe-type tcp-ping;
                target 8.8.8.8;
                destination-port 70000;
            }
        }
    }
}
`,
			wantErr: "1-65535",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewParser(tc.input)
			tree, errs := parser.Parse()
			if len(errs) > 0 {
				t.Fatalf("parse errors: %v", errs)
			}
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatal("expected compile error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CompileConfig() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestDynamicAddressFeed(t *testing.T) {
	input := `security {
    dynamic-address {
        feed-server threat-feed {
            url "https://feeds.example.com/threats.txt";
            update-interval 1800;
            hold-interval 3600;
            feed-name malware-ips;
        }
        feed-server geo-feed {
            url "https://feeds.example.com/geo.txt";
            update-interval 7200;
            feed-name geo-block;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	da := cfg.Security.DynamicAddress
	if da.FeedServers == nil || len(da.FeedServers) != 2 {
		t.Fatalf("expected 2 feed servers, got %v", da.FeedServers)
	}
	tf := da.FeedServers["threat-feed"]
	if tf == nil {
		t.Fatal("expected threat-feed server")
	}
	if tf.URL != "https://feeds.example.com/threats.txt" {
		t.Errorf("url: got %q", tf.URL)
	}
	if tf.UpdateInterval != 1800 {
		t.Errorf("update-interval: got %d, want 1800", tf.UpdateInterval)
	}
	if tf.HoldInterval != 3600 {
		t.Errorf("hold-interval: got %d, want 3600", tf.HoldInterval)
	}
	if tf.FeedName != "malware-ips" {
		t.Errorf("feed-name: got %q", tf.FeedName)
	}
}

func TestVLANInterfaceCompilation(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set interfaces enp7s0 vlan-tagging", "set interfaces enp7s0 unit 100 vlan-id 100", "set interfaces enp7s0 unit 100 family inet address 10.0.100.1/24", "set interfaces enp7s0 unit 200 vlan-id 200", "set interfaces enp7s0 unit 200 family inet address 10.0.200.1/24", "set interfaces enp7s0 unit 200 family inet6 address fd00:200::1/64"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["enp7s0"]
	if ifc == nil {
		t.Fatal("missing interface enp7s0")
	}
	if !ifc.VlanTagging {
		t.Error("expected vlan-tagging to be true")
	}
	if len(ifc.Units) != 2 {
		t.Fatalf("expected 2 units, got %d", len(ifc.Units))
	}
	unit100 := ifc.Units[100]
	if unit100 == nil {
		t.Fatal("missing unit 100")
	}
	if unit100.VlanID != 100 {
		t.Errorf("unit 100 vlan-id: got %d", unit100.VlanID)
	}
	if len(unit100.Addresses) != 1 || unit100.Addresses[0] != "10.0.100.1/24" {
		t.Errorf("unit 100 addresses: %v", unit100.Addresses)
	}
	unit200 := ifc.Units[200]
	if unit200 == nil {
		t.Fatal("missing unit 200")
	}
	if unit200.VlanID != 200 {
		t.Errorf("unit 200 vlan-id: got %d", unit200.VlanID)
	}
	if len(unit200.Addresses) != 2 {
		t.Errorf("unit 200 addresses: expected 2, got %v", unit200.Addresses)
	}
}

func TestInterfaceFilterAssignment(t *testing.T) {
	input := `interfaces {
    enp6s0 {
        unit 0 {
            family inet {
                filter {
                    input inet-source-dscp;
                }
                address 192.168.0.1/24;
            }
            family inet6 {
                filter {
                    input inet6-source-dscp;
                }
                address fd35::1/64;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ifc, ok := cfg.Interfaces.Interfaces["enp6s0"]
	if !ok {
		t.Fatal("expected enp6s0 interface")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("expected unit 0")
	}
	if unit.FilterInputV4 != "inet-source-dscp" {
		t.Errorf("expected FilterInputV4=inet-source-dscp, got %q", unit.FilterInputV4)
	}
	if unit.FilterInputV6 != "inet6-source-dscp" {
		t.Errorf("expected FilterInputV6=inet6-source-dscp, got %q", unit.FilterInputV6)
	}
}

func TestInterfaceSamplingAndFilterOutput(t *testing.T) {
	input := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                sampling {
                    input;
                    output;
                }
                filter {
                    input ingress-filter;
                    output egress-filter;
                }
                address 10.0.0.1/24;
            }
            family inet6 {
                dad-disable;
                sampling {
                    input;
                }
                filter {
                    input ingress-v6;
                    output egress-v6;
                }
                address 2001:db8::1/64;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("ge-0/0/0 not found")
	}
	unit := ifc.Units[0]
	if unit == nil {
		t.Fatal("unit 0 not found")
	}
	if !unit.SamplingInput {
		t.Error("sampling input should be true")
	}
	if !unit.SamplingOutput {
		t.Error("sampling output should be true")
	}
	if unit.FilterInputV4 != "ingress-filter" {
		t.Errorf("FilterInputV4 = %q", unit.FilterInputV4)
	}
	if unit.FilterOutputV4 != "egress-filter" {
		t.Errorf("FilterOutputV4 = %q", unit.FilterOutputV4)
	}
	if unit.FilterInputV6 != "ingress-v6" {
		t.Errorf("FilterInputV6 = %q", unit.FilterInputV6)
	}
	if unit.FilterOutputV6 != "egress-v6" {
		t.Errorf("FilterOutputV6 = %q", unit.FilterOutputV6)
	}
	if !unit.DADDisable {
		t.Error("dad-disable should be true")
	}
}

func TestFlowFlagsAndPowerMode(t *testing.T) {
	input := `security {
    flow {
        tcp-mss {
            all-tcp {
                mss 1400;
            }
        }
        gre-performance-acceleration;
        power-mode-disable;
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Security.Flow.GREPerformanceAcceleration {
		t.Error("GREPerformanceAcceleration should be true")
	}
	if !cfg.Security.Flow.PowerModeDisable {
		t.Error("PowerModeDisable should be true")
	}
}

func TestFlowFlagsSetSyntax(t *testing.T) {
	commands := []string{"set security flow gre-performance-acceleration", "set security flow power-mode-disable"}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Security.Flow.GREPerformanceAcceleration {
		t.Error("GREPerformanceAcceleration should be true")
	}
	if !cfg.Security.Flow.PowerModeDisable {
		t.Error("PowerModeDisable should be true")
	}
}

func TestLAGInterfaceHierarchical(t *testing.T) {
	input := `
interfaces {
    ae0 {
        description "LAG to switch";
        aggregated-ether-options {
            lacp {
                active;
                periodic fast;
            }
            link-speed 10g;
            minimum-links 1;
        }
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/0 {
        gigether-options {
            802.3ad ae0;
        }
    }
    ge-0/0/1 {
        gigether-options {
            802.3ad ae0;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ae0 := cfg.Interfaces.Interfaces["ae0"]
	if ae0 == nil {
		t.Fatal("missing ae0 interface")
	}
	if ae0.Description != "LAG to switch" {
		t.Errorf("ae0 description: got %q", ae0.Description)
	}
	if ae0.AggregatedEtherOpts == nil {
		t.Fatal("ae0 aggregated-ether-options is nil")
	}
	if !ae0.AggregatedEtherOpts.LACPActive {
		t.Error("expected LACP active")
	}
	if ae0.AggregatedEtherOpts.LACPPeriodic != "fast" {
		t.Errorf("LACP periodic: got %q, want fast", ae0.AggregatedEtherOpts.LACPPeriodic)
	}
	if ae0.AggregatedEtherOpts.LinkSpeed != "10g" {
		t.Errorf("link-speed: got %q, want 10g", ae0.AggregatedEtherOpts.LinkSpeed)
	}
	if ae0.AggregatedEtherOpts.MinimumLinks != 1 {
		t.Errorf("minimum-links: got %d, want 1", ae0.AggregatedEtherOpts.MinimumLinks)
	}
	u0 := ae0.Units[0]
	if u0 == nil {
		t.Fatal("ae0 missing unit 0")
	}
	if len(u0.Addresses) != 1 || u0.Addresses[0] != "10.0.1.1/24" {
		t.Errorf("ae0 unit 0 addresses: %v", u0.Addresses)
	}
	ge0 := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ge0 == nil {
		t.Fatal("missing ge-0/0/0")
	}
	if ge0.LAGParent != "ae0" {
		t.Errorf("ge-0/0/0 LAGParent: got %q, want ae0", ge0.LAGParent)
	}
	ge1 := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if ge1 == nil {
		t.Fatal("missing ge-0/0/1")
	}
	if ge1.LAGParent != "ae0" {
		t.Errorf("ge-0/0/1 LAGParent: got %q, want ae0", ge1.LAGParent)
	}
}

func TestLAGInterfaceSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set interfaces ae0 description \"LAG bundle\"", "set interfaces ae0 aggregated-ether-options lacp active", "set interfaces ae0 aggregated-ether-options lacp periodic fast", "set interfaces ae0 aggregated-ether-options link-speed 10g", "set interfaces ae0 aggregated-ether-options minimum-links 2", "set interfaces ae0 unit 0 family inet address 10.0.5.1/24", "set interfaces ge-0/0/0 gigether-options 802.3ad ae0", "set interfaces ge-0/0/1 gigether-options 802.3ad ae0"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ae0 := cfg.Interfaces.Interfaces["ae0"]
	if ae0 == nil {
		t.Fatal("missing ae0")
	}
	if ae0.AggregatedEtherOpts == nil {
		t.Fatal("aggregated-ether-options is nil")
	}
	if !ae0.AggregatedEtherOpts.LACPActive {
		t.Error("expected LACP active")
	}
	if ae0.AggregatedEtherOpts.LACPPeriodic != "fast" {
		t.Errorf("periodic: got %q, want fast", ae0.AggregatedEtherOpts.LACPPeriodic)
	}
	if ae0.AggregatedEtherOpts.LinkSpeed != "10g" {
		t.Errorf("link-speed: got %q", ae0.AggregatedEtherOpts.LinkSpeed)
	}
	if ae0.AggregatedEtherOpts.MinimumLinks != 2 {
		t.Errorf("minimum-links: got %d, want 2", ae0.AggregatedEtherOpts.MinimumLinks)
	}
	ge0 := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ge0 == nil {
		t.Fatal("missing ge-0/0/0")
	}
	if ge0.LAGParent != "ae0" {
		t.Errorf("ge-0/0/0 LAGParent: got %q", ge0.LAGParent)
	}
	ge1 := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if ge1 == nil {
		t.Fatal("missing ge-0/0/1")
	}
	if ge1.LAGParent != "ae0" {
		t.Errorf("ge-0/0/1 LAGParent: got %q", ge1.LAGParent)
	}
}

func TestFlexibleVlanTaggingHierarchical(t *testing.T) {
	input := `
interfaces {
    ge-0/0/0 {
        flexible-vlan-tagging;
        encapsulation flexible-ethernet-services;
        unit 100 {
            vlan-id 100;
            inner-vlan-id 200;
            family inet {
                address 10.0.100.1/24;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("missing ge-0/0/0")
	}
	if !ifc.FlexibleVlanTagging {
		t.Error("expected flexible-vlan-tagging to be true")
	}
	if ifc.Encapsulation != "flexible-ethernet-services" {
		t.Errorf("encapsulation: got %q, want flexible-ethernet-services", ifc.Encapsulation)
	}
	u100 := ifc.Units[100]
	if u100 == nil {
		t.Fatal("missing unit 100")
	}
	if u100.VlanID != 100 {
		t.Errorf("vlan-id: got %d, want 100", u100.VlanID)
	}
	if u100.InnerVlanID != 200 {
		t.Errorf("inner-vlan-id: got %d, want 200", u100.InnerVlanID)
	}
	if len(u100.Addresses) != 1 || u100.Addresses[0] != "10.0.100.1/24" {
		t.Errorf("addresses: %v", u100.Addresses)
	}
}

func TestFlexibleVlanTaggingSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set interfaces ge-0/0/0 flexible-vlan-tagging", "set interfaces ge-0/0/0 encapsulation flexible-ethernet-services", "set interfaces ge-0/0/0 unit 100 vlan-id 100", "set interfaces ge-0/0/0 unit 100 inner-vlan-id 200", "set interfaces ge-0/0/0 unit 100 family inet address 10.0.100.1/24", "set interfaces ge-0/0/0 unit 200 vlan-id 300", "set interfaces ge-0/0/0 unit 200 inner-vlan-id 400"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("missing ge-0/0/0")
	}
	if !ifc.FlexibleVlanTagging {
		t.Error("expected flexible-vlan-tagging")
	}
	if ifc.Encapsulation != "flexible-ethernet-services" {
		t.Errorf("encapsulation: got %q", ifc.Encapsulation)
	}
	u100 := ifc.Units[100]
	if u100 == nil {
		t.Fatal("missing unit 100")
	}
	if u100.VlanID != 100 {
		t.Errorf("unit 100 vlan-id: got %d", u100.VlanID)
	}
	if u100.InnerVlanID != 200 {
		t.Errorf("unit 100 inner-vlan-id: got %d", u100.InnerVlanID)
	}
	u200 := ifc.Units[200]
	if u200 == nil {
		t.Fatal("missing unit 200")
	}
	if u200.VlanID != 300 {
		t.Errorf("unit 200 vlan-id: got %d", u200.VlanID)
	}
	if u200.InnerVlanID != 400 {
		t.Errorf("unit 200 inner-vlan-id: got %d", u200.InnerVlanID)
	}
}

func TestLACPPassiveMode(t *testing.T) {
	tree := &ConfigTree{}
	setCommands := []string{"set interfaces ae0 aggregated-ether-options lacp passive", "set interfaces ae0 unit 0 family inet address 10.0.1.1/24"}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	ae0 := cfg.Interfaces.Interfaces["ae0"]
	if ae0 == nil {
		t.Fatal("missing ae0")
	}
	if ae0.AggregatedEtherOpts == nil {
		t.Fatal("aggregated-ether-options is nil")
	}
	if ae0.AggregatedEtherOpts.LACPActive {
		t.Error("expected LACP not active")
	}
	if !ae0.AggregatedEtherOpts.LACPPassive {
		t.Error("expected LACP passive")
	}
}

func TestInterfaceBandwidth(t *testing.T) {
	input := `interfaces {
    wan0 {
        bandwidth 1g;
        unit 0 {
            family inet {
                address 172.16.50.5/24;
            }
        }
    }
    trust0 {
        bandwidth 100m;
        unit 0 {
            family inet {
                address 10.0.1.10/24;
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse error: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	wan0 := cfg.Interfaces.Interfaces["wan0"]
	if wan0 == nil {
		t.Fatal("wan0 not found")
	}
	if wan0.Bandwidth != 1000000000 {
		t.Errorf("wan0 bandwidth = %d, want 1000000000", wan0.Bandwidth)
	}
	trust0 := cfg.Interfaces.Interfaces["trust0"]
	if trust0 == nil {
		t.Fatal("trust0 not found")
	}
	if trust0.Bandwidth != 100000000 {
		t.Errorf("trust0 bandwidth = %d, want 100000000", trust0.Bandwidth)
	}
}

func TestInterfaceBandwidthSetSyntax(t *testing.T) {
	cmds := []string{"set interfaces wan0 bandwidth 1g", "set interfaces wan0 unit 0 family inet address 172.16.50.5/24", "set interfaces trust0 bandwidth 100m", "set interfaces trust0 unit 0 family inet address 10.0.1.10/24", "set interfaces lo0 bandwidth 10000"}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	wan0 := cfg.Interfaces.Interfaces["wan0"]
	if wan0 == nil {
		t.Fatal("wan0 not found")
	}
	if wan0.Bandwidth != 1000000000 {
		t.Errorf("wan0 bandwidth = %d, want 1000000000", wan0.Bandwidth)
	}
	trust0 := cfg.Interfaces.Interfaces["trust0"]
	if trust0 == nil {
		t.Fatal("trust0 not found")
	}
	if trust0.Bandwidth != 100000000 {
		t.Errorf("trust0 bandwidth = %d, want 100000000", trust0.Bandwidth)
	}
	lo0 := cfg.Interfaces.Interfaces["lo0"]
	if lo0 == nil {
		t.Fatal("lo0 not found")
	}
	if lo0.Bandwidth != 10000 {
		t.Errorf("lo0 bandwidth = %d, want 10000", lo0.Bandwidth)
	}
}

func TestProxyARPHierarchical(t *testing.T) {
	input := `security {
    nat {
        proxy-arp {
            interface trust0.0 {
                address 10.0.1.100/32;
                address 10.0.1.101/32 to 10.0.1.110/32;
            }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if errs != nil {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Security.NAT.ProxyARP) != 1 {
		t.Fatalf("got %d proxy-arp entries, want 1", len(cfg.Security.NAT.ProxyARP))
	}
	entry := cfg.Security.NAT.ProxyARP[0]
	if entry.Interface != "trust0.0" {
		t.Errorf("interface = %q, want trust0.0", entry.Interface)
	}
	if len(entry.Addresses) != 11 {
		t.Errorf("got %d addresses, want 11: %v", len(entry.Addresses), entry.Addresses)
	}
	if entry.Addresses[0] != "10.0.1.100/32" {
		t.Errorf("first addr = %q, want 10.0.1.100/32", entry.Addresses[0])
	}
}

func TestProxyARPSetSyntax(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security nat proxy-arp interface trust0.0 address 10.0.1.100/32", "set security nat proxy-arp interface trust0.0 address 10.0.1.101/32 to 10.0.1.110/32"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.NAT.ProxyARP) != 1 {
		t.Fatalf("got %d proxy-arp entries, want 1", len(cfg.Security.NAT.ProxyARP))
	}
	entry := cfg.Security.NAT.ProxyARP[0]
	if entry.Interface != "trust0.0" {
		t.Errorf("interface = %q, want trust0.0", entry.Interface)
	}
	if len(entry.Addresses) != 11 {
		t.Errorf("got %d addresses, want 11: %v", len(entry.Addresses), entry.Addresses)
	}
}

func TestProxyARPSingleAddress(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security nat proxy-arp interface untrust0.0 address 203.0.113.5/32"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.NAT.ProxyARP) != 1 {
		t.Fatalf("got %d proxy-arp entries, want 1", len(cfg.Security.NAT.ProxyARP))
	}
	entry := cfg.Security.NAT.ProxyARP[0]
	if entry.Interface != "untrust0.0" {
		t.Errorf("interface = %q, want untrust0.0", entry.Interface)
	}
	if len(entry.Addresses) != 1 {
		t.Fatalf("got %d addresses, want 1", len(entry.Addresses))
	}
	if entry.Addresses[0] != "203.0.113.5/32" {
		t.Errorf("address = %q, want 203.0.113.5/32", entry.Addresses[0])
	}
}

func TestProxyARPBareIP(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{"set security nat proxy-arp interface trust0.0 address 10.0.1.50"} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.NAT.ProxyARP) != 1 {
		t.Fatalf("got %d proxy-arp entries, want 1", len(cfg.Security.NAT.ProxyARP))
	}
	entry := cfg.Security.NAT.ProxyARP[0]
	if len(entry.Addresses) != 1 {
		t.Fatalf("got %d addresses, want 1", len(entry.Addresses))
	}
	if entry.Addresses[0] != "10.0.1.50/32" {
		t.Errorf("address = %q, want 10.0.1.50/32", entry.Addresses[0])
	}
}

func TestDynamicAddressMultiFeedPaths(t *testing.T) {
	input := `security {
    dynamic-address {
        feed-server cloudflare {
            url https://www.cloudflare.com;
            update-interval 86400;
            hold-interval 864000;
            feed-name feed-cloudflare-ipv4 {
                path /ips-v4;
            }
            feed-name feed-cloudflare-ipv6 {
                path /ips-v6;
            }
        }
        address-name cloudflare-ipv4 {
            profile {
                feed-name feed-cloudflare-ipv4;
            }
        }
        address-name cloudflare-ipv6 {
            profile {
                feed-name feed-cloudflare-ipv6;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	da := cfg.Security.DynamicAddress
	if da.FeedServers == nil || len(da.FeedServers) != 1 {
		t.Fatalf("expected 1 feed server, got %d", len(da.FeedServers))
	}
	cf := da.FeedServers["cloudflare"]
	if cf == nil {
		t.Fatal("expected cloudflare feed server")
	}
	if cf.URL != "https://www.cloudflare.com" {
		t.Errorf("url = %q, want https://www.cloudflare.com", cf.URL)
	}
	if cf.UpdateInterval != 86400 {
		t.Errorf("update-interval = %d, want 86400", cf.UpdateInterval)
	}
	if cf.HoldInterval != 864000 {
		t.Errorf("hold-interval = %d, want 864000", cf.HoldInterval)
	}
	if len(cf.FeedEntries) != 2 {
		t.Fatalf("expected 2 feed entries, got %d", len(cf.FeedEntries))
	}
	if cf.FeedEntries[0].Name != "feed-cloudflare-ipv4" {
		t.Errorf("feed entry 0 name = %q", cf.FeedEntries[0].Name)
	}
	if cf.FeedEntries[0].Path != "/ips-v4" {
		t.Errorf("feed entry 0 path = %q", cf.FeedEntries[0].Path)
	}
	if cf.FeedEntries[1].Name != "feed-cloudflare-ipv6" {
		t.Errorf("feed entry 1 name = %q", cf.FeedEntries[1].Name)
	}
	if cf.FeedEntries[1].Path != "/ips-v6" {
		t.Errorf("feed entry 1 path = %q", cf.FeedEntries[1].Path)
	}
	if da.AddressBindings == nil || len(da.AddressBindings) != 2 {
		t.Fatalf("expected 2 address bindings, got %d", len(da.AddressBindings))
	}
	ab4 := da.AddressBindings["cloudflare-ipv4"]
	if ab4 == nil {
		t.Fatal("expected cloudflare-ipv4 address binding")
	}
	if len(ab4.FeedNames) != 1 || ab4.FeedNames[0] != "feed-cloudflare-ipv4" {
		t.Errorf("cloudflare-ipv4 feed-names = %v", ab4.FeedNames)
	}
	ab6 := da.AddressBindings["cloudflare-ipv6"]
	if ab6 == nil {
		t.Fatal("expected cloudflare-ipv6 address binding")
	}
	if len(ab6.FeedNames) != 1 || ab6.FeedNames[0] != "feed-cloudflare-ipv6" {
		t.Errorf("cloudflare-ipv6 feed-names = %v", ab6.FeedNames)
	}
}

func TestDynamicAddressMultiFeedPathsSetSyntax(t *testing.T) {
	lines := []string{"set security dynamic-address feed-server cloudflare url https://www.cloudflare.com", "set security dynamic-address feed-server cloudflare update-interval 1440", "set security dynamic-address feed-server cloudflare feed-name cloudflare-ipv4 path /ips-v4", "set security dynamic-address feed-server cloudflare feed-name cloudflare-ipv6 path /ips-v6", "set security dynamic-address address-name cloudflare-ipv4 profile feed-name cloudflare-ipv4", "set security dynamic-address address-name cloudflare-ipv6 profile feed-name cloudflare-ipv6"}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set path %q: %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	da := cfg.Security.DynamicAddress
	cf := da.FeedServers["cloudflare"]
	if cf == nil {
		t.Fatal("expected cloudflare feed server")
	}
	if cf.URL != "https://www.cloudflare.com" {
		t.Errorf("url = %q", cf.URL)
	}
	if cf.UpdateInterval != 1440 {
		t.Errorf("update-interval = %d, want 1440", cf.UpdateInterval)
	}
	if len(cf.FeedEntries) != 2 {
		t.Fatalf("expected 2 feed entries, got %d", len(cf.FeedEntries))
	}
	ab4 := da.AddressBindings["cloudflare-ipv4"]
	if ab4 == nil {
		t.Fatal("expected cloudflare-ipv4 address binding")
	}
	if len(ab4.FeedNames) != 1 || ab4.FeedNames[0] != "cloudflare-ipv4" {
		t.Errorf("cloudflare-ipv4 feed-names = %v", ab4.FeedNames)
	}
}

func TestDynamicAddressHostnameSyntax(t *testing.T) {
	input := `security {
    dynamic-address {
        feed-server cloudflare {
            hostname "www.cloudflare.com";
            update-interval 1440;
            feed-name cloudflare-ipv4 {
                path "/ips-v4";
            }
            feed-name cloudflare-ipv6 {
                path "/ips-v6";
            }
        }
        address-name cloudflare-ipv4 {
            profile {
                feed-name cloudflare-ipv4;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	da := cfg.Security.DynamicAddress
	cf := da.FeedServers["cloudflare"]
	if cf == nil {
		t.Fatal("expected cloudflare feed server")
	}
	if cf.Hostname != "www.cloudflare.com" {
		t.Errorf("hostname = %q, want www.cloudflare.com", cf.Hostname)
	}
	if cf.URL != "" {
		t.Errorf("url should be empty when hostname is used, got %q", cf.URL)
	}
	if len(cf.FeedEntries) != 2 {
		t.Fatalf("expected 2 feed entries, got %d", len(cf.FeedEntries))
	}
	ab := da.AddressBindings["cloudflare-ipv4"]
	if ab == nil || len(ab.FeedNames) != 1 || ab.FeedNames[0] != "cloudflare-ipv4" {
		t.Errorf("address binding = %v", ab)
	}
}

// #653: ValidateConfig emits a one-line warning at commit time when
// `services application-identification` is enabled, telling the
// operator that xpf AppID is port+protocol catalog matching only —
// no L7 DPI / signature engine — and pointing them at the runtime
// status command + the contract doc. The warning is informational
// (the knob is preserved, not stripped), unlike #915 surplus-sharing
// which warn-and-strips a no-op flag.
func TestValidateConfigAppIDWarnsWhenEnabled(t *testing.T) {
	lines := []string{
		"set services application-identification",
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !cfg.Services.ApplicationIdentification {
		t.Fatal("expected ApplicationIdentification=true after parse")
	}
	gotWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application-identification") &&
			strings.Contains(w, "port+protocol") {
			gotWarn = true
			break
		}
	}
	if !gotWarn {
		t.Fatalf("expected AppID contract warning on cfg.Warnings; got: %v",
			cfg.Warnings)
	}
}

// #653: ValidateConfig must NOT emit the AppID warning when
// `services application-identification` is NOT configured. Negative
// regression so the warning doesn't accidentally fire on every commit.
func TestValidateConfigAppIDSilentWhenDisabled(t *testing.T) {
	lines := []string{
		"set system dataplane-type userspace",
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application-identification") {
			t.Fatalf("AppID warning fired without the knob set: %v",
				cfg.Warnings)
		}
	}
}
