package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"
)

// #12898 (the gRPC twin of #5325): the zones-detail text renderer
// (showZonesDetail) keyed a zone's LOGICAL member name ("ge-0/0/0.0",
// "reth0.50") directly against cfg.Interfaces.Interfaces, which is keyed by
// the BASE interface name ("ge-0/0/0" / "reth0"). The lookup missed every
// unit-qualified binding, so `show security zones detail` over gRPC rendered
// a correctly addressed member with NO Address/DHCP lines — in the exact
// policy-audit surface the local CLI had fixed in #5325. Both renderers now
// share config.ZoneMemberDetailLines (split base.N, resolve the base, render
// only the named unit), so the two surfaces stay byte-identical.
//
// The fixture is the issue's decisive check: one base interface with DISTINCT
// unit 0 and unit 50 addresses, bound unit-qualified to `trust`, plus one
// BARE member on `dmz` as the no-regression guard (a base member with no
// unit suffix still renders ALL its units — the already-correct case, kept
// byte-identical since #5325).
func unitMemberGRPCStore(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set interfaces ge-0/0/0 unit 50 family inet address 10.0.10.1/24
set interfaces ge-0/0/0 unit 50 family inet6 dhcpv6
set interfaces ge-0/0/1 unit 0 family inet address 192.168.1.1/24
set interfaces ge-0/0/1 unit 7 family inet address 192.168.7.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone trust interfaces ge-0/0/0.50
set security zones security-zone dmz interfaces ge-0/0/1`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store} // dp nil: counters skipped, interface detail runs
}

// zonesDetailIfaceBlock returns the 6-space-indented detail lines rendered
// under one member's `    <member>:` header — the Address/DHCP block and
// nothing else — so a test can assert per-unit isolation without ordering
// assumptions across units.
func zonesDetailIfaceBlock(t *testing.T, out, member string) string {
	t.Helper()
	header := "    " + member + ":"
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if line != header {
			continue
		}
		var b strings.Builder
		for _, next := range lines[i+1:] {
			if !strings.HasPrefix(next, "      ") {
				break
			}
			b.WriteString(next)
			b.WriteString("\n")
		}
		return b.String()
	}
	t.Fatalf("zones-detail missing interface header %q:\n%s", header, out)
	return ""
}

// TestShowZonesDetailUnitMemberAddress12898 is the RED-on-master guard: the
// trust zone binds ge-0/0/0.0 AND ge-0/0/0.50, and each member's block must
// show exactly its own unit's address and DHCP state. On master the unsplit
// LookupInterface(ifName) missed both members entirely (no Address lines);
// a fix that resolves the base but forgets the unit filter would instead leak
// unit 50's lines into .0's block and vice versa — both halves are asserted.
func TestShowZonesDetailUnitMemberAddress12898(t *testing.T) {
	s := unitMemberGRPCStore(t)
	var buf strings.Builder
	s.showZonesDetail(s.store.ActiveConfig(), "trust", &buf)
	out := buf.String()

	block0 := zonesDetailIfaceBlock(t, out, "ge-0/0/0.0")
	if !strings.Contains(block0, "Address: 10.0.0.1/24") {
		t.Fatalf("unit-qualified member ge-0/0/0.0 dropped its address "+
			"(#12898 — the base-keyed lookup missed the unit ref):\n%s", out)
	}
	if strings.Contains(block0, "10.0.10.1/24") || strings.Contains(block0, "DHCPv6") {
		t.Fatalf("member ge-0/0/0.0 rendered sibling unit 50's lines "+
			"(unit filter missing):\n%s", block0)
	}

	block50 := zonesDetailIfaceBlock(t, out, "ge-0/0/0.50")
	if !strings.Contains(block50, "Address: 10.0.10.1/24") {
		t.Fatalf("unit-qualified member ge-0/0/0.50 dropped its address:\n%s", out)
	}
	if !strings.Contains(block50, "DHCPv6: enabled") {
		t.Fatalf("unit-qualified member ge-0/0/0.50 dropped its DHCPv6 line:\n%s", out)
	}
	if strings.Contains(block50, "10.0.0.1/24") {
		t.Fatalf("member ge-0/0/0.50 rendered sibling unit 0's address:\n%s", block50)
	}
}

// TestShowZonesDetailBareMemberAllUnits12898 is the no-regression guard: a
// BARE zone member (no unit suffix) still renders ALL its units' addresses —
// the behavior that already worked on both surfaces stays byte-identical.
func TestShowZonesDetailBareMemberAllUnits12898(t *testing.T) {
	s := unitMemberGRPCStore(t)
	var buf strings.Builder
	s.showZonesDetail(s.store.ActiveConfig(), "dmz", &buf)
	block := zonesDetailIfaceBlock(t, buf.String(), "ge-0/0/1")
	for _, want := range []string{"Address: 192.168.1.1/24", "Address: 192.168.7.1/24"} {
		if !strings.Contains(block, want) {
			t.Fatalf("bare member ge-0/0/1 lost a unit's address "+
				"(all-units regression):\n%s", block)
		}
	}
}
