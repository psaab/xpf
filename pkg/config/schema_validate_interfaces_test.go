package config_test

// #1319 PR 3 — per-leaf validation matrix for the interfaces typed
// leaves, including the typed-KEY-slot feature (`family inet address
// <cidr>` carries its value in a named-instance identity token).
// Mirrors the chassis PR-2 matrix: every leaf × in-range / boundary /
// one-past / garbage in the flat-set shape, plus hierarchical-shape
// coverage for the deployed-config block style. Ranges are source-cited
// in pkg/config/schema.go next to each annotation.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type interfacesLeafCase struct {
	name     string
	template string
	leaf     string
	accept   []string
	reject   []string
}

var interfacesLeafMatrix = []interfacesLeafCase{
	{
		// Min-only: kernel/driver owns the ceiling; 0 is the compiler's
		// "unset" zero-value sentinel.
		name:     "mtu",
		leaf:     "mtu",
		template: "set interfaces ge-0-0-0 mtu %s",
		accept:   []string{"1", "1280", "1500", "9000", "65535", "99999"},
		reject:   []string{"0", "-1", "1500.5", "asd", ""},
	},
	{
		name:     "family-inet-mtu",
		leaf:     "mtu",
		template: "set interfaces ge-0-0-0 unit 0 family inet mtu %s",
		accept:   []string{"1", "1500"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "family-inet6-mtu",
		leaf:     "mtu",
		template: "set interfaces ge-0-0-0 unit 0 family inet6 mtu %s",
		accept:   []string{"1280", "1500"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		// 802.1Q 12-bit VID: 0 = untagged sentinel (#9899 accepts), 4095 reserved.
		name:     "vlan-id",
		leaf:     "vlan-id",
		template: "set interfaces ge-0-0-2 unit 50 vlan-id %s",
		accept:   []string{"0", "1", "50", "80", "4094"},
		reject:   []string{"4095", "-1", "asd", ""},
	},
	{
		name:     "inner-vlan-id",
		leaf:     "inner-vlan-id",
		template: "set interfaces ge-0/0/2 unit 50 inner-vlan-id %s",
		accept:   []string{"0", "1", "100", "4094"},
		reject:   []string{"4095", "-1", "asd", ""},
	},
	{
		// Typed KEY slot: the runtime net.ParseCIDRs configured
		// addresses and silently skips failures, so the prefix is
		// REQUIRED and the family must match the runtime's ip.To4()
		// classification. No ""-reject case: an absent identity token
		// just means no instance (nothing is compiled).
		name:     "family-inet-address",
		leaf:     "address",
		template: "set interfaces ge-0-0-0 unit 0 family inet address %s",
		accept:   []string{"10.0.1.10/24", "0.0.0.0/0", "192.168.1.1/32"},
		reject:   []string{"10.0.1.10", "2001:db8::1/64", "10.0.1.999/24", "10.0.1.10/33", "asd"},
	},
	{
		name:     "family-inet6-address",
		leaf:     "address",
		template: "set interfaces ge-0-0-0 unit 0 family inet6 address %s",
		accept:   []string{"2001:db8::1/64", "::1/128", "fe80::1/64"},
		// ::ffff:10.0.1.1/96 is a 4-in-6 form the runtime classifies as
		// inet (ip.To4() != nil) — rejected under family inet6.
		reject: []string{"2001:db8::1", "10.0.1.1/24", "::ffff:10.0.1.1/96", "2001:db8::1/129", "asd"},
	},
	{
		// One wire byte; 0 = unset sentinel + RFC 5798 resignation
		// value; 255 = address owner (valid).
		name:     "vrrp-priority",
		leaf:     "priority",
		template: "set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.10/24 vrrp-group 1 priority %s",
		accept:   []string{"1", "100", "200", "254", "255"},
		reject:   []string{"0", "256", "-1", "asd", ""},
	},
	{
		// Seconds; 40 s = 4000 cs is the last whole-second value that
		// fits the 12-bit VRRPv3 centisecond wire field.
		name:     "vrrp-advertise-interval",
		leaf:     "advertise-interval",
		template: "set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.10/24 vrrp-group 1 advertise-interval %s",
		accept:   []string{"1", "5", "40"},
		reject:   []string{"0", "41", "-1", "asd", ""},
	},
	{
		// xpf requires the prefix (netlink.ParseAddr contract): a bare
		// Junos-style virtual-address is advertised but never installed.
		name:     "vrrp-virtual-address",
		leaf:     "virtual-address",
		template: "set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.10/24 vrrp-group 1 virtual-address %s",
		accept:   []string{"10.0.1.1/24", "10.0.1.1/32"},
		reject:   []string{"10.0.1.1", "2001:db8::1/64", "asd", ""},
	},
	{
		// #2384 — IPv6 vrrp-group under family inet6. Same wire byte as
		// the inet priority; identical bounds.
		name:     "vrrp6-priority",
		leaf:     "priority",
		template: "set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::10/64 vrrp-group 1 priority %s",
		accept:   []string{"1", "100", "200", "254", "255"},
		reject:   []string{"0", "256", "-1", "asd", ""},
	},
	{
		// #2384 — the inet6 virtual-address must be a v6 CIDR; a v4
		// address (or bare IP) is rejected by ValidateIPv6CIDR. This is
		// the mirror of vrrp-virtual-address with the family flipped.
		name:     "vrrp6-virtual-address",
		leaf:     "virtual-address",
		template: "set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::10/64 vrrp-group 1 virtual-address %s",
		accept:   []string{"2001:db8::1/64", "fe80::1/64", "::1/128"},
		reject:   []string{"2001:db8::1", "10.0.1.1/24", "::ffff:10.0.1.1/96", "asd", ""},
	},
	{
		name:     "tunnel-source",
		leaf:     "source",
		template: "set interfaces gr-0-0-0 tunnel source %s",
		accept:   []string{"10.0.2.10", "2001:db8::1"},
		reject:   []string{"10.0.2.10/24", "10.0.2.999", "asd", ""},
	},
	{
		name:     "tunnel-destination-unit",
		leaf:     "destination",
		template: "set interfaces gr-0-0-0 unit 0 tunnel destination %s",
		accept:   []string{"192.0.2.1", "2001:db8::2"},
		reject:   []string{"192.0.2.1/32", "asd", ""},
	},
	{
		// netlink Ttl is one byte; omitted = default 64, explicit 0 rejects (#9899).
		name:     "tunnel-ttl",
		leaf:     "ttl",
		template: "set interfaces gr-0-0-0 tunnel ttl %s",
		accept:   []string{"1", "64", "255"},
		reject:   []string{"0", "256", "-1", "asd", ""},
	},
	{
		// GRE key is a 32-bit wire field; uint32(Atoi) wraps silently
		// outside it.
		name:     "tunnel-key",
		leaf:     "key",
		template: "set interfaces gr-0-0-0 tunnel key %s",
		accept:   []string{"0", "100", "4294967295"},
		reject:   []string{"-1", "4294967296", "asd", ""},
	},
	{
		// Exactly the silent compiler bound (parseTunnelWireguard).
		name:     "wireguard-listen-port",
		leaf:     "listen-port",
		template: "set interfaces wg-0-0-0 tunnel wireguard listen-port %s",
		accept:   []string{"1", "51820", "65535"},
		reject:   []string{"0", "65536", "-1", "asd", ""},
	},
	{
		name:     "wireguard-persistent-keepalive",
		leaf:     "persistent-keepalive",
		template: "set interfaces wg-0-0-0 tunnel wireguard peer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa persistent-keepalive %s",
		accept:   []string{"0", "25", "65535"},
		reject:   []string{"-1", "65536", "asd", ""},
	},
}

func TestSchemaValidate_Interfaces_Matrix(t *testing.T) {
	for _, tc := range interfacesLeafMatrix {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.accept {
				cmd := strings.TrimSpace(fmt.Sprintf(tc.template, v))
				if err := flatSchemaCheck(t, cmd); err != nil {
					t.Errorf("accept %q: unexpected error: %v", cmd, err)
				}
			}
			for _, v := range tc.reject {
				cmd := strings.TrimSpace(fmt.Sprintf(tc.template, v))
				err := flatSchemaCheck(t, cmd)
				if err == nil {
					t.Errorf("reject %q: expected error, got nil", cmd)
					continue
				}
				if !strings.Contains(err.Error(), tc.leaf) {
					t.Errorf("reject %q: error should reference %q: %v", cmd, tc.leaf, err)
				}
			}
		})
	}
}

// The deployed loss-cluster block style (docs/ha-cluster-userspace.conf)
// must keep validating: hierarchical family blocks, address instances
// with vrrp-group children, VLAN units, IPv6.
func TestSchemaValidate_Interfaces_DeployedConfigShapeAccepted(t *testing.T) {
	if err := schemaCheck(t, `interfaces {
    ge-0-0-1 {
        mtu 9000;
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.254/24;
                        priority 200;
                        advertise-interval 1;
                        preempt;
                        accept-data;
                    }
                }
            }
            family inet6 {
                address 2001:559:8585:ef00::1/64;
            }
        }
    }
    ge-0-0-2 {
        vlan-tagging;
        unit 50 {
            vlan-id 50;
            family inet {
                address 172.16.50.8/24;
            }
        }
    }
}`); err != nil {
		t.Fatalf("deployed-shape config rejected: %v", err)
	}
}

// Hierarchical shape: a bare (prefix-less) address inside a family block
// must reject — every runtime consumer net.ParseCIDRs it and would
// silently skip it.
func TestSchemaValidate_Interfaces_HierarchicalRejectsBareAddress(t *testing.T) {
	err := schemaCheck(t, `interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address 10.0.1.10;
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for bare address in hierarchical block, got nil")
	}
	if !strings.Contains(err.Error(), "address") || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("error should reference the address leaf and the missing prefix: %v", err)
	}
}

// Nested instance-name shape: `address { 10.0.0.999/24; }` supplies the
// identity token as a CHILD node. namedInstances compiles this shape, so
// the walkInstanceChildren key-slot path must validate it too.
func TestSchemaValidate_Interfaces_NestedAddressInstanceValidated(t *testing.T) {
	err := schemaCheck(t, `interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address {
                    10.0.1.999/24 {
                        primary;
                    }
                }
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for invalid nested address instance, got nil")
	}
	if !strings.Contains(err.Error(), "address") {
		t.Fatalf("error should reference the address slot: %v", err)
	}
}

// A wrong-family address must reject in the hierarchical shape as well.
func TestSchemaValidate_Interfaces_HierarchicalRejectsWrongFamily(t *testing.T) {
	err := schemaCheck(t, `interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet6 {
                address 10.0.1.10/24;
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for IPv4 address under family inet6, got nil")
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("error should explain the family mismatch: %v", err)
	}
}

// Accepted values must compile to exactly what was written — the gate
// must never reject something the compiler consumes, nor change what it
// produces (chassis PR-2 parity check).
func TestSchemaValidate_Interfaces_AcceptedValuesCompileAsWritten(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set interfaces ge-0-0-0 mtu 9000",
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.10/24",
		"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0-0-0"]
	if ifc == nil || ifc.MTU != 9000 {
		t.Fatalf("mtu must compile verbatim, got %+v", ifc)
	}
	unit := ifc.Units[0]
	if unit == nil || len(unit.Addresses) != 2 ||
		unit.Addresses[0] != "10.0.1.10/24" || unit.Addresses[1] != "2001:db8::1/64" {
		t.Fatalf("addresses must compile verbatim, got %+v", unit)
	}
	vlanIfc := cfg.Interfaces.Interfaces["ge-0-0-2"]
	if vlanIfc == nil || vlanIfc.Units[50] == nil || vlanIfc.Units[50].VlanID != 50 {
		t.Fatalf("vlan-id must compile verbatim, got %+v", vlanIfc)
	}
}

// The hierarchical PACKED one-liner `vrrp-group 1 priority 256;` packs
// the property into the instance node's Keys, which the schema walker's
// compiler-faithful contract consumes as identity tokens WITHOUT running
// the `priority` leaf's ValidateInteger(1,255) — so SchemaValidate alone
// still passes it (an inherent limit of the schema layer, same class as
// the chassis PR-2 `node 0 priority 300;` one-liner). #5184 backstops
// that bypass at the COMPILED-*Config layer: validateVRRPGroupPriorityStrict
// hard-rejects the out-of-range priority at strict commit, before the
// sendAdvert uint8 narrowing wraps 256 to the RFC 5798 resignation value 0.
// This test pins BOTH facts — the schema walker passes, the compile gate
// rejects — so a revert of either the gate or the schema deferral is caught.
func TestSchemaValidate_Interfaces_PackedVrrpOneLinerBypassesGate(t *testing.T) {
	const packed = `interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address 10.0.1.10/24 {
                    vrrp-group 1 priority 256;
                }
            }
        }
    }
}`
	// The schema walker still consumes the packed priority as an identity
	// token and does not range-check it (documented layer limit).
	if err := schemaCheck(t, packed); err != nil {
		t.Fatalf("schema walker unexpectedly rejected the packed one-liner "+
			"(the schema layer consumes it as identity tokens): %v", err)
	}
	// #5184: the compiled-*Config gate DOES reject it at strict commit.
	tree, errs := config.NewParser(packed).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict commit must reject the packed `vrrp-group 1 " +
			"priority 256` (uint8 wire truncation wraps 256 to the RFC 5798 " +
			"resignation priority 0), got nil error")
	} else if !strings.Contains(err.Error(), "priority 256") ||
		!strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error %q does not name the out-of-range packed priority", err.Error())
	}
}

// `set interfaces ge-0-0-0 unit 0 family inet address ?` — the typed
// KEY slot surfaces the schema placeholder plus the example CIDR at the
// empty identity slot on the live completion path.
func TestCompleteSetPath_AddressKeySlotExamples(t *testing.T) {
	got := config.CompleteSetPathWithValues([]string{
		"interfaces", "ge-0-0-0", "unit", "0", "family", "inet", "address",
	}, nil)
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
	}
	joined := strings.Join(names, " ")
	if !strings.Contains(joined, "<address>") {
		t.Fatalf("expected <address> placeholder in completions, got %v", names)
	}
	if !strings.Contains(joined, "10.0.1.10/24") {
		t.Fatalf("expected example 10.0.1.10/24 in completions, got %v", names)
	}
}
