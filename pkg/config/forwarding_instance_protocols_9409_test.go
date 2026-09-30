package config

import (
	"strings"
	"testing"
)

// #9409. `VRFName == ""` is overloaded in the FRR assembler: it means both "the
// master table" and "a forwarding instance's own kernel table", and the
// protocol renderer takes the first reading. Measured at HEAD before this
// change, on a config all four channels ACCEPT with zero warnings:
//
//	forwarding + ospf -> TWO `router ospf` blocks, NEITHER with a `vrf` suffix
//	forwarding + isis -> a GLOBAL `router isis xpf`
//	forwarding + rip  -> a GLOBAL `router rip`
//	forwarding + bgp  -> the instance's `peer-as 65002` neighbor under a SECOND
//	                     `router bgp 65001` — it JOINS THE GLOBAL AS

const fwdBase9409 = `
interfaces {
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
`

func compile9409(t *testing.T, text string) (*Config, error) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	return CompileConfig(tree)
}

func compileLenient9409(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path must not reject (#1960 no-brick): %v", err)
	}
	return cfg
}

func fwdInstance9409(protocols string) string {
	return fwdBase9409 + `
routing-instances { ISP-B { instance-type forwarding;
    routing-options { static { route 0.0.0.0/0 next-hop 10.0.1.254; } }
    protocols { ` + protocols + ` } } }`
}

func TestForwardingInstanceProtocolsRejected9409(t *testing.T) {
	cases := []struct{ name, protocols, wantProto string }{
		{"ospf", "ospf { area 0.0.0.0 { interface ge-0/0/1.0; } }", "ospf"},
		{"ospf3", "ospf3 { area 0.0.0.0 { interface ge-0/0/1.0; } }", "ospf3"},
		{"bgp", "bgp { group h { type external; peer-as 65002; neighbor 10.0.0.2; } }", "bgp"},
		{"rip", "rip { group g { neighbor ge-0/0/1.0; } }", "rip"},
		{"isis", "isis { interface ge-0/0/1.0; }", "isis"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compile9409(t, fwdInstance9409(tc.protocols))
			if err == nil {
				t.Fatalf("strict commit ACCEPTED protocols %s under instance-type "+
					"forwarding; FRR would activate it in the GLOBAL routing instance",
					tc.protocols)
			}
			msg := err.Error()
			// The message must name BOTH the instance and the protocol: an
			// operator with several instances cannot act on "some instance has
			// an unsupported protocol".
			if !strings.Contains(msg, "ISP-B") {
				t.Errorf("rejection %q does not name the instance", msg)
			}
			if !strings.Contains(msg, tc.wantProto) {
				t.Errorf("rejection %q does not name the protocol %q", msg, tc.wantProto)
			}
		})
	}
}

// TestForwardingInstanceStaticsStillAccepted9409 is the negative control that
// makes the rejection above meaningful: the gate must reject the PROTOCOLS, not
// the instance type. A forwarding instance carrying only statics is the
// documented FBF recipe (docs/multi-wan.md) and is exactly what
// test/incus/fbf-two-upstream-config.set commits.
func TestForwardingInstanceStaticsStillAccepted9409(t *testing.T) {
	text := fwdBase9409 + `
routing-instances { ISP-B { instance-type forwarding;
    routing-options { static { route 0.0.0.0/0 next-hop 10.0.1.254; } } } }`
	cfg, err := compile9409(t, text)
	if err != nil {
		t.Fatalf("a statics-only forwarding instance must still commit: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 || len(cfg.RoutingInstances[0].StaticRoutes) != 1 {
		t.Fatalf("the statics were lost: %+v", cfg.RoutingInstances)
	}
}

// TestVirtualRouterProtocolsStillAccepted9409 is the other control: per-instance
// protocols are supported, on an instance type that HAS a VRF device. A gate
// that rejected those too would be #9409 "fixed" by removing the feature.
func TestVirtualRouterProtocolsStillAccepted9409(t *testing.T) {
	text := fwdBase9409 + `
routing-instances { ISP-B { instance-type virtual-router;
    interface ge-0/0/1.0;
    protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0; } } } } }`
	cfg, err := compile9409(t, text)
	if err != nil {
		t.Fatalf("per-instance protocols on a virtual-router must still commit: %v", err)
	}
	if cfg.RoutingInstances[0].OSPF == nil {
		t.Fatal("the virtual-router's OSPF was dropped")
	}
}

// TestForwardingInstanceProtocolsWarnOnTolerantPath9409: #1960 no-brick. A box
// carrying this config from before the gate — or receiving it over HA
// config-sync — must still boot. The downgrade is only safe because the
// assembler drops the protocols (asserted in pkg/daemon), so the warning is
// paired with an inert render, not with the old global pollution.
func TestForwardingInstanceProtocolsWarnOnTolerantPath9409(t *testing.T) {
	cfg := compileLenient9409(t, fwdInstance9409("ospf { area 0.0.0.0 { interface ge-0/0/1.0; } }"))
	var found string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "forwarding-instance protocols") {
			found = w
		}
	}
	if found == "" {
		t.Fatalf("the tolerant path accepted silently; warnings = %v", cfg.Warnings)
	}
	if !strings.Contains(found, "ISP-B") {
		t.Errorf("the tolerant-path warning %q does not name the instance", found)
	}
	// The instance is still COMPILED with its protocols: the drop is the
	// assembler's job, not the compiler's, and a compiler that silently erased
	// them would make `show configuration` disagree with what was committed.
	if cfg.RoutingInstances[0].OSPF == nil {
		t.Error("the tolerant compile erased the instance's OSPF; the operator-visible " +
			"config must still show what was authored")
	}
}
