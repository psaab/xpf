package config

import "testing"

func compile12595(t *testing.T, input string) *Config {
	t.Helper()
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestRepeatedSamplingContainers12595(t *testing.T) {
	cfg := compile12595(t, `forwarding-options {
    sampling {
        instance i1 {
            input { rate 100; }
            family inet { output { flow-server 192.0.2.1 { port 2055; } } }
        }
    }
    sampling {
        instance i2 {
            input { rate 200; }
            family inet6 { output { flow-server 2001:db8::1 { port 2056; } } }
        }
    }
}
`)
	if cfg.ForwardingOptions.Sampling == nil {
		t.Fatal("sampling nil")
	}
	insts := cfg.ForwardingOptions.Sampling.Instances
	if len(insts) != 2 {
		t.Fatalf("instances = %v, want i1+i2", keys12595(insts))
	}
	if insts["i1"] == nil || insts["i1"].InputRate != 100 || insts["i1"].FamilyInet == nil {
		t.Errorf("i1 wrong: %+v", insts["i1"])
	}
	if insts["i2"] == nil || insts["i2"].InputRate != 200 || insts["i2"].FamilyInet6 == nil {
		t.Errorf("i2 wrong (second sampling container dropped): %+v", insts["i2"])
	}
}

func keys12595(m map[string]*SamplingInstance) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRepeatedDHCPBlocks12595(t *testing.T) {
	cfg := compile12595(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
                dhcp { lease-time 3600; }
                dhcp { retransmission-attempt 5; force-discover; }
            }
        }
    }
}
`)
	unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if !unit.DHCP {
		t.Fatal("DHCP false")
	}
	if unit.DHCPOptions == nil {
		t.Fatal("DHCPOptions nil (second dhcp block dropped?)")
	}
	if unit.DHCPOptions.LeaseTime != 3600 {
		t.Errorf("LeaseTime=%d want 3600 (first block)", unit.DHCPOptions.LeaseTime)
	}
	if unit.DHCPOptions.RetransmissionAttempt != 5 {
		t.Errorf("RetransmissionAttempt=%d want 5 (second block)", unit.DHCPOptions.RetransmissionAttempt)
	}
	if !unit.DHCPOptions.ForceDiscover {
		t.Error("ForceDiscover false want true (second block)")
	}
}

func TestRepeatedDHCPv6ClientBlocks12595(t *testing.T) {
	cfg := compile12595(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet6 {
                address 2001:db8::1/64;
                dhcpv6-client { client-type stateful; }
                dhcpv6-client { client-ia-type ia-na; req-option dns-server; }
            }
        }
    }
}
`)
	unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if !unit.DHCPv6 {
		t.Fatal("DHCPv6 false")
	}
	dc := unit.DHCPv6Client
	if dc == nil {
		t.Fatal("DHCPv6Client nil (second dhcpv6-client block dropped?)")
	}
	if dc.ClientType != "stateful" {
		t.Errorf("ClientType=%q want stateful (first block)", dc.ClientType)
	}
	if len(dc.ClientIATypes) != 1 || dc.ClientIATypes[0] != "ia-na" {
		t.Errorf("ClientIATypes=%v want [ia-na] (second block)", dc.ClientIATypes)
	}
	if len(dc.ReqOptions) != 1 || dc.ReqOptions[0] != "dns-server" {
		t.Errorf("ReqOptions=%v want [dns-server] (second block)", dc.ReqOptions)
	}
}
