package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #5325: two policy-audit CLI surfaces keyed a LOGICAL zone-member name
// ("ge-0/0/9.50") against the BASE-keyed cfg.Interfaces.Interfaces map (keyed
// "ge-0/0/9") — a guaranteed miss. `show security zones detail` then rendered a
// correctly addressed interface with NO Address/DHCP lines (looked
// unaddressed), and `show vlans` left the Zone column blank for a correctly
// zoned VLAN unit. Both are fixed by splitting the "<base>.<unit>" reference and
// resolving the base interface + unit before the lookup, mirroring the
// #4908/C175-HC-116 repair in showChassisClusterStatus.
//
// The fixture binds one LOGICAL member (ge-0/0/9.50 → zone trust) and one
// BASE-only member (ge-0/0/1 → zone dmz, no unit suffix). The logical member
// exercises the bug; the base-only member is the no-regression guard.
func logicalUnitCLIStore(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/9 {
        vlan-tagging;
        unit 50 {
            vlan-id 50;
            family inet {
                address 10.0.9.1/24;
            }
        }
    }
    ge-0/0/1 {
        vlan-tagging;
        unit 10 {
            vlan-id 10;
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/9.50;
            }
        }
        security-zone dmz {
            interfaces {
                ge-0/0/1;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store} // dp nil: skip counter reads, exercise the display walk
}

// TestShowSecurityZonesDetailLogicalUnitAddress5325 is the RED-on-revert guard
// for `show security zones detail`. Filtering to the `trust` zone isolates the
// logical member ge-0/0/9.50; its configured address must appear. Reverting to
// the base-keyed `cfg.Interfaces.Interfaces[ifName]` lookup (ifName ==
// "ge-0/0/9.50") misses the base-keyed map and drops the Address line.
func TestShowSecurityZonesDetailLogicalUnitAddress5325(t *testing.T) {
	c := logicalUnitCLIStore(t)
	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(c.store.ActiveConfig(), true, "trust"); err != nil {
			t.Fatalf("showZonesDisplay(detail, trust): %v", err)
		}
	})
	if !strings.Contains(out, "ge-0/0/9.50:") {
		t.Fatalf("interface detail header for the logical member ge-0/0/9.50 missing:\n%s", out)
	}
	if !strings.Contains(out, "Address: 10.0.9.1/24") {
		t.Fatalf("logical zone member ge-0/0/9.50 address was dropped "+
			"(#5325 — base-keyed lookup missed the unit-qualified ref):\n%s", out)
	}
}

// TestShowSecurityZonesDetailBaseMemberNoRegression5325 proves a BASE-only zone
// member (no unit suffix) still resolves all its units' addresses — the
// behavior that already worked must remain byte-identical.
func TestShowSecurityZonesDetailBaseMemberNoRegression5325(t *testing.T) {
	c := logicalUnitCLIStore(t)
	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(c.store.ActiveConfig(), true, "dmz"); err != nil {
			t.Fatalf("showZonesDisplay(detail, dmz): %v", err)
		}
	})
	if !strings.Contains(out, "Address: 10.0.1.1/24") {
		t.Fatalf("base-only zone member ge-0/0/1 address dropped (regression):\n%s", out)
	}
}

// TestShowVlansLogicalUnitZoneColumn5325 is the RED-on-revert guard for
// `show vlans`. The Zone column of the ge-0/0/9 unit-50 VLAN row must name
// `trust`. Reverting to the raw-member-key build + base-name query
// (ifZone[ifc.Name]) leaves the Zone column blank for the unit-qualified
// binding. The base-only member (ge-0/0/1 → dmz) is the no-regression guard.
func TestShowVlansLogicalUnitZoneColumn5325(t *testing.T) {
	c := logicalUnitCLIStore(t)
	out := captureStdout(t, func() {
		if err := c.showVlans(); err != nil {
			t.Fatalf("showVlans: %v", err)
		}
	})

	logicalLine := findVlanRow(t, out, "ge-0/0/9")
	if !strings.Contains(logicalLine, "trust") {
		t.Fatalf("show vlans Zone column blank for the logical unit ge-0/0/9.50 "+
			"(#5325 — base-name query missed the logical-keyed ifZone):\nrow: %q\nfull:\n%s",
			logicalLine, out)
	}

	// No-regression: the base-only member still resolves its zone.
	baseLine := findVlanRow(t, out, "ge-0/0/1")
	if !strings.Contains(baseLine, "dmz") {
		t.Fatalf("show vlans Zone column blank for the base-only member ge-0/0/1 (regression):\nrow: %q\nfull:\n%s",
			baseLine, out)
	}
}

// findVlanRow returns the first `show vlans` output line containing iface.
func findVlanRow(t *testing.T, out, iface string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, iface) {
			return line
		}
	}
	t.Fatalf("no show vlans row for %s:\n%s", iface, out)
	return ""
}
