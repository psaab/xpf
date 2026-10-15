package config

import (
	"strings"
	"testing"
)

// #13109 (D1-04): a zone poisoned by an unknown child (DroppedEnforcementChild)
// had its Interfaces wiped in P4 compileZones before P6b strict gates and
// QuarantinedZoneInterfaceKeys could see them. A second healthy zone claiming
// the same interface then silently took sole ownership instead of the
// interface being quarantined, the poisoned zone's zone-local address-book
// entries leaked into the global book, and the strict duplicate-interface
// error was masked behind the unknown-child error.

const poisonedContestedZone13109 = `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone alpha {
            interfaces {
                ge-0/0/0.0;
            }
            address-book {
                address srv 10.0.0.99/32;
            }
            host-inbound-traffic {
                system-services ssh;
            }
            tcp-rst;
            bogus-child;
        }
        security-zone beta {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
`

func compile13109(t *testing.T) (*Config, *ConfigTree) {
	t.Helper()
	tree, errs := NewParser(poisonedContestedZone13109).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse config: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	return cfg, tree
}

func TestPoisonedZoneContestedInterfaceQuarantined13109(t *testing.T) {
	cfg, _ := compile13109(t)

	alpha := cfg.Security.Zones["alpha"]
	if alpha == nil || !alpha.DroppedEnforcementChild {
		t.Fatalf("fixture: alpha must be poisoned, got %+v", alpha)
	}
	// Tolerant contract: poisoned zone is still unbound (no bindings survive).
	if len(alpha.Interfaces) != 0 {
		t.Fatalf("poisoned zone must be unbound, interfaces: %v", alpha.Interfaces)
	}
	if alpha.InterfaceHostInbound != nil || alpha.ScreenProfile != "" || alpha.ScreenProfileConfigured {
		t.Fatalf("poisoned zone retains host-inbound/screen bindings: %+v", alpha)
	}
	if alpha.HostInboundTraffic != nil || alpha.TCPRst {
		t.Fatalf("poisoned zone retains zone-level enforcement: %+v", alpha)
	}
	// The contested interface must not silently belong to beta.
	if _, quarantined := QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/0.0"]; !quarantined {
		t.Fatalf("contested ge-0/0/0.0 not quarantined, keys=%v", QuarantinedZoneInterfaceKeys(cfg))
	}
	if got := InterfaceZoneMap(cfg)["ge-0/0/0.0"]; got != "" {
		t.Fatalf("contested ge-0/0/0.0 must be unzoned (fails closed), got zone %q", got)
	}
	// Poisoned zone's zone-local address-book entry must not leak globally.
	if cfg.Security.AddressBook != nil && cfg.Security.AddressBook.Addresses["zone-local/alpha/srv"] != nil {
		t.Fatal("poisoned zone alpha address-book entry leaked into global book")
	}
}

func TestPoisonedZoneStrictDuplicateInterfaceFirstError13109(t *testing.T) {
	_, tree := compile13109(t)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict compile must reject contested poisoned config")
	}
	if !strings.Contains(err.Error(), "ge-0/0/0.0") || !strings.Contains(err.Error(), "security zones") {
		t.Fatalf("strict error must be duplicate-interface gate naming the interface and zones, got: %v", err)
	}
	// Control: without the duplicate, the unknown-child error still fires.
	single := strings.Replace(poisonedContestedZone13109, `        security-zone beta {
            interfaces {
                ge-0/0/0.0;
            }
        }
`, "", 1)
	stree, errs := NewParser(single).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse control: %v", errs)
	}
	if _, err := CompileConfig(stree); err == nil || !strings.Contains(err.Error(), "bogus-child") {
		t.Fatalf("control strict error must name unknown child, got: %v", err)
	}
}

// Control: a healthy duplicate claim must still be strictly rejected and
// leniently quarantined (pre-existing #3072 behaviour must not regress).
func TestHealthyDuplicateInterfaceUnchanged13109(t *testing.T) {
	src := strings.Replace(poisonedContestedZone13109, "            bogus-child;\n", "", 1)
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "ge-0/0/0.0") {
		t.Fatalf("healthy duplicate must be strict-rejected, got: %v", err)
	}
	ltree, _ := NewParser(src).Parse()
	cfg, err := CompileConfigLenient(ltree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if _, ok := QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/0.0"]; !ok {
		t.Fatal("healthy duplicate must be quarantined on tolerant path")
	}
	// Healthy zone's address-book entry must still fold globally.
	if cfg.Security.AddressBook == nil || cfg.Security.AddressBook.Addresses["zone-local/alpha/srv"] == nil {
		t.Fatal("healthy zone address-book entry must fold globally")
	}
}
