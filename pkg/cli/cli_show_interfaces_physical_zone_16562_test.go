package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #16562: the local `show interfaces <if> detail|extensive` twins keyed
// the zone map by baseIfName(member), so a VLAN trunk whose units sit in
// different zones printed a map-order-random "Security zone:" (and the
// #16556/#12899 qualifier) on the physical row. The gRPC twin fixed this
// in #14364 via physicalRowZoneKey; the predicate now lives in
// pkg/config (config.PhysicalRowZoneKey) and both local presenters use
// it, so a non-zero unit's zone is never attributed to the physical row.
//
// Fixture mirrors the issue trace, bound through the real config
// compiler so zone membership is exactly what an operator configures:
//   - <iface> is a VLAN trunk: unit 50 -> trust, unit 80 -> dmz
//     (physical row must print NO "Security zone:" line, stably), and
//   - <iface>.0 -> untrust as the positive control (physical row must
//     print "Security zone: untrust").
//
// The trunk and the control deliberately share ONE physical interface:
// a unit-0 binding and non-zero bindings on the same base prove the row
// resolves to the unit-0 zone — never to a map-order pick between the
// trunk zones. RED-on-revert: restoring baseIfName keying makes the row
// print trust or dmz nondeterministically (Go map iteration over
// cfg.Security.Zones) and the "no trust/dmz on physical row" / stability
// assertions fail.

// physicalZone16562CLI builds a CLI whose active config authors a REAL
// host interface (dash-named, so the authored slash form round-trips to
// the live kernel netdev the netlink walk enumerates) as a VLAN trunk
// with units 50/80 in trust/dmz and unit 0 in untrust. Skips when the
// host exposes no dash-named interface to exercise the mapping.
func physicalZone16562CLI(t *testing.T) (c *CLI, junos string) {
	t.Helper()
	j, k, ok := dashNamedKernelIface(t)
	if !ok {
		t.Skip("no dash-named host interface available to exercise slash->kernel resolution")
	}
	_ = k
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ` + j + ` {
        vlan-tagging;
        unit 0 { vlan-id 10; family inet { address 10.165.62.1/24; } }
        unit 50 { vlan-id 50; family inet { address 10.165.50.1/24; } }
        unit 80 { vlan-id 80; family inet { address 10.165.80.1/24; } }
    }
}
security {
    zones {
        security-zone trust { interfaces { ` + j + `.50; } }
        security-zone dmz { interfaces { ` + j + `.80; } }
        security-zone untrust { interfaces { ` + j + `.0; } }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store}, j
}

// physicalBlock16562 returns the rendered block for one physical
// interface (from its "Physical interface: <name>," header to the next
// physical header or end of output).
func physicalBlock16562(out, name string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Physical interface: ") {
			if in {
				break
			}
			in = strings.HasPrefix(line, "Physical interface: "+name+",")
			if !in {
				continue
			}
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// securityZoneLine16562 extracts the "Security zone:" line of a block,
// or "" when the block carries none.
func securityZoneLine16562(block string) string {
	for _, line := range strings.Split(block, "\n") {
		if strings.Contains(line, "Security zone:") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func TestShowInterfacesDetailPhysicalRowZone16562(t *testing.T) {
	c, junos := physicalZone16562CLI(t)
	// Repeat: under the old baseIfName keying the row's zone was chosen
	// by Go map iteration, so a single pass could coincidentally print
	// untrust. Twenty passes make a wrong attribution overwhelmingly
	// likely to surface while staying deterministic under the fix.
	for i := range 20 {
		out := captureStdout(t, func() {
			if err := c.showInterfacesDetail(junos); err != nil {
				t.Fatalf("showInterfacesDetail(%q): %v", junos, err)
			}
		})
		block := physicalBlock16562(out, junos)
		if block == "" {
			t.Fatalf("run %d: detail missing physical block for %q:\n%s", i, junos, out)
		}
		line := securityZoneLine16562(block)
		if line != "Security zone: untrust" {
			t.Fatalf("run %d: detail physical row zone = %q, want %q (trunk units 50/80 must not be attributed to the physical row):\n%s",
				i, line, "Security zone: untrust", block)
		}
	}
}

func TestShowInterfacesExtensivePhysicalRowZone16562(t *testing.T) {
	c, junos := physicalZone16562CLI(t)
	for i := range 20 {
		out := captureStdout(t, func() {
			if err := c.showInterfacesExtensiveFiltered(junos); err != nil {
				t.Fatalf("showInterfacesExtensiveFiltered(%q): %v", junos, err)
			}
		})
		block := physicalBlock16562(out, junos)
		if block == "" {
			t.Fatalf("run %d: extensive missing physical block for %q:\n%s", i, junos, out)
		}
		line := securityZoneLine16562(block)
		if line != "Security zone: untrust" {
			t.Fatalf("run %d: extensive physical row zone = %q, want %q (trunk units 50/80 must not be attributed to the physical row):\n%s",
				i, line, "Security zone: untrust", block)
		}
	}
}

// TestShowInterfacesTrunkOnlyNoPhysicalZone16562 pins the issue's exact
// acceptance shape: a trunk whose ONLY bindings are non-zero units
// (trust=.50, dmz=.80, no unit 0 anywhere) prints no "Security zone:"
// line at all on the physical row — in either presenter, on every run.
func trunkOnly16562CLI(t *testing.T) (c *CLI, junos string) {
	t.Helper()
	j, _, ok := dashNamedKernelIface(t)
	if !ok {
		t.Skip("no dash-named host interface available to exercise slash->kernel resolution")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ` + j + ` {
        vlan-tagging;
        unit 50 { vlan-id 50; family inet { address 10.165.50.1/24; } }
        unit 80 { vlan-id 80; family inet { address 10.165.80.1/24; } }
    }
}
security {
    zones {
        security-zone trust { interfaces { ` + j + `.50; } }
        security-zone dmz { interfaces { ` + j + `.80; } }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store}, j
}

func TestShowInterfacesTrunkOnlyNoPhysicalZone16562(t *testing.T) {
	c, junos := trunkOnly16562CLI(t)
	for i := range 20 {
		detail := captureStdout(t, func() {
			if err := c.showInterfacesDetail(junos); err != nil {
				t.Fatalf("showInterfacesDetail(%q): %v", junos, err)
			}
		})
		if block := physicalBlock16562(detail, junos); block == "" {
			t.Fatalf("run %d: detail missing physical block for %q:\n%s", i, junos, detail)
		} else if line := securityZoneLine16562(block); line != "" {
			t.Fatalf("run %d: detail trunk physical row printed %q, want no Security zone line:\n%s", i, line, block)
		}
		ext := captureStdout(t, func() {
			if err := c.showInterfacesExtensiveFiltered(junos); err != nil {
				t.Fatalf("showInterfacesExtensiveFiltered(%q): %v", junos, err)
			}
		})
		if block := physicalBlock16562(ext, junos); block == "" {
			t.Fatalf("run %d: extensive missing physical block for %q:\n%s", i, junos, ext)
		} else if line := securityZoneLine16562(block); line != "" {
			t.Fatalf("run %d: extensive trunk physical row printed %q, want no Security zone line:\n%s", i, line, block)
		}
	}
}
