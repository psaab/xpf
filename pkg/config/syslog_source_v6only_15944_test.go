package config

import "testing"

// #15944 H4-01 fold: an IPv6-only unit's primary/preferred live only in
// the V6 slots, so the family-unspecified (hostname/empty collector)
// syslog resolver must fall back to them. Before the fold it read only
// the legacy PrimaryAddress slot, which is empty for a compiled
// IPv6-only unit, and returned "" — no source for hostname collectors.
//
// FAIL-ON-REVERT: narrowing the family=="" arm back to the legacy slot
// (parse(unit.PrimaryAddress)) returns "" for the first cell.

func TestSyslogV6OnlyHostnameCollector15944(t *testing.T) {
	cfg := compileHierStrict(t,
		"interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::2/64 { primary; } address 2001:db8::3/64 { preferred; } } } } }\n"+
			"security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }\n")
	unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if unit.PrimaryAddress != "" || unit.PrimaryAddressV6 != "2001:db8::2/64" {
		t.Fatalf("fixture precondition: legacy=%q v6=%q, want empty legacy slot with v6 primary", unit.PrimaryAddress, unit.PrimaryAddressV6)
	}
	if got := ResolveSyslogSourceAddr(cfg, "ge-0/0/0.0"); got != "2001:db8::2" {
		t.Errorf("ResolveSyslogSourceAddr = %q, want 2001:db8::2 (IPv6-only primary)", got)
	}
	if got := ResolveSyslogSourceAddrForCollector(cfg, "ge-0/0/0.0", "collector.example.net"); got != "2001:db8::2" {
		t.Errorf("hostname collector = %q, want 2001:db8::2", got)
	}
	if got := ResolveSyslogSourceAddrForCollector(cfg, "ge-0/0/0.0", ""); got != "2001:db8::2" {
		t.Errorf("empty collector = %q, want 2001:db8::2", got)
	}
	// Family-specified calls stay strict: the v6 primary must NOT serve
	// an IPv4 collector, and serves the IPv6 collector.
	if got := ResolveSyslogSourceAddrForCollector(cfg, "ge-0/0/0.0", "192.0.2.1"); got != "" {
		t.Errorf("IPv4 collector = %q, want \"\" (no IPv4 address on the unit)", got)
	}
	if got := ResolveSyslogSourceAddrForCollector(cfg, "ge-0/0/0.0", "2001:db8:9::1"); got != "2001:db8::2" {
		t.Errorf("IPv6 collector = %q, want 2001:db8::2", got)
	}
}

// Dual-stack control: the IPv4 primary still wins for a hostname
// collector (legacy family-blind behaviour), in both family orders.
func TestSyslogDualStackHostnamePrefersIPv4Primary15944(t *testing.T) {
	for _, src := range []string{
		"interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.2/24 { primary; } } family inet6 { address 2001:db8::2/64 { primary; } } } } }\nsecurity { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }\n",
		"interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::2/64 { primary; } } family inet { address 10.0.0.2/24 { primary; } } } } }\nsecurity { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }\n",
	} {
		cfg := compileHierStrict(t, src)
		if got := ResolveSyslogSourceAddrForCollector(cfg, "ge-0/0/0.0", "collector.example.net"); got != "10.0.0.2" {
			t.Errorf("dual-stack hostname collector = %q, want 10.0.0.2 (IPv4 primary wins)", got)
		}
	}
}
