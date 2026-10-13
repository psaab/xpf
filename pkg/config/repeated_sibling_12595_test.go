package config

import (
	"fmt"
	"net"
	"strconv"
	"testing"
)

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
	tests := []struct{ name, input string }{
		{"sampling siblings", `forwarding-options {
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
`},
		// Every top-level stanza compiles into the same ForwardingOptionsConfig.
		// Before #12595 each sampling container replaced the SamplingConfig,
		// so the second stanza dropped i1.
		{"top-level stanzas", `forwarding-options {
    sampling {
        instance i1 {
            input { rate 100; }
            family inet { output { flow-server 192.0.2.1 { port 2055; } } }
        }
    }
}
forwarding-options {
    sampling {
        instance i2 {
            input { rate 200; }
            family inet6 { output { flow-server 2001:db8::1 { port 2056; } } }
        }
    }
}
`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compile12595(t, tc.input)
			if cfg.ForwardingOptions.Sampling == nil {
				t.Fatal("sampling nil")
			}
			insts := cfg.ForwardingOptions.Sampling.Instances
			if len(insts) != 2 {
				t.Fatalf("instances = %v, want exactly i1+i2", keys12595(insts))
			}
			for name, want := range map[string]string{
				"i1": "rate=100 inet=[192.0.2.1:2055] inet6=<nil>",
				"i2": "rate=200 inet=<nil> inet6=[[2001:db8::1]:2056]",
			} {
				if got := samplingSummary12595(insts[name]); got != want {
					t.Errorf("%s = %s, want %s", name, got, want)
				}
			}
		})
	}
}

func keys12595(m map[string]*SamplingInstance) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// samplingSummary12595 renders a compiled instance with every collector it
// carries, so a dropped or doubled flow-server fails the comparison.
func samplingSummary12595(inst *SamplingInstance) string {
	if inst == nil {
		return "<missing>"
	}
	family := func(sf *SamplingFamily) string {
		if sf == nil {
			return "<nil>"
		}
		var servers []string
		for _, fs := range sf.FlowServers {
			servers = append(servers, net.JoinHostPort(fs.Address, strconv.Itoa(fs.Port)))
		}
		return fmt.Sprint(servers)
	}
	return fmt.Sprintf("rate=%d inet=%s inet6=%s", inst.InputRate, family(inst.FamilyInet), family(inst.FamilyInet6))
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
