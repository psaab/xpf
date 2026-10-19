package config

import (
	"net"
	"testing"
)

// #15078 (A47-01): ResolveSyslogSourceAddr had no collector-family input.
// It returned the unit's `primary` address — with inet winning over inet6
// at compile time (compiler_interfaces.go) — or else the first IPv4 on the
// kernel interface. A stream to an IPv6 collector on a dual-stack
// source-interface therefore bound an IPv4 source and failed to dial
// (mismatched address families) for the life of the config; #14597's
// retry re-derived the same wrong-family address and could not recover.
//
// FAIL-ON-REVERT: the family-blind resolver returns the IPv4 primary for
// the IPv6-collector cells below, so they go RED.

func syslogFamilyFixture15078() *Config {
	return &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				// Dual-stack: inet primary compiled first, so
				// PrimaryAddress is the IPv4 one (the defect shape).
				"reth1": {
					Name: "reth1",
					Units: map[int]*InterfaceUnit{
						100: {
							Number:           100,
							Addresses:        []string{"10.0.1.20/24", "2001:db8:1::20/64"},
							PrimaryAddress:   "10.0.1.20/24",
							PreferredAddress: "10.0.1.20/24",
						},
					},
				},
				// Only an inet6 primary exists.
				"reth2": {
					Name: "reth2",
					Units: map[int]*InterfaceUnit{
						0: {
							Number:         0,
							Addresses:      []string{"2001:db8:2::30/64"},
							PrimaryAddress: "2001:db8:2::30/64",
						},
					},
				},
			},
		},
	}
}

// The IPv6-collector arm: the configured addresses must yield the IPv6
// address, honouring the per-family preferred address when present.
func TestResolveSyslogSourceAddrForCollector_IPv6Collector15078(t *testing.T) {
	cfg := syslogFamilyFixture15078()
	if got := ResolveSyslogSourceAddrForCollector(cfg, "reth1.100", "2001:db8:9::1"); got != "2001:db8:1::20" {
		t.Errorf("IPv6 collector: resolved source = %q, want %q — a v4 primary "+
			"cannot dial an IPv6 collector (#15078)", got, "2001:db8:1::20")
	}
}

// Control: the IPv4-collector arm is unchanged (primary wins).
func TestResolveSyslogSourceAddrForCollector_IPv4CollectorControl15078(t *testing.T) {
	cfg := syslogFamilyFixture15078()
	if got := ResolveSyslogSourceAddrForCollector(cfg, "reth1.100", "192.0.2.1"); got != "10.0.1.20" {
		t.Errorf("IPv4 collector: resolved source = %q, want %q (control, must be unchanged)", got, "10.0.1.20")
	}
}

// No address of the collector's family on the unit: resolve to "" (the
// caller then leaves the bind unbound and warns) rather than returning a
// wrong-family address that fails the dial.
func TestResolveSyslogSourceAddrForCollector_NoMatchingFamily15078(t *testing.T) {
	cfg := syslogFamilyFixture15078()
	if got := ResolveSyslogSourceAddrForCollector(cfg, "reth2.0", "192.0.2.1"); got != "" {
		t.Errorf("IPv4 collector on an IPv6-only unit: resolved source = %q, want \"\" "+
			"(unbound), not a wrong-family address (#15078)", got)
	}
	if got := ResolveSyslogSourceAddrForCollector(cfg, "reth2.0", "2001:db8:9::1"); got != "2001:db8:2::30" {
		t.Errorf("IPv6 collector on an IPv6-only unit: resolved source = %q, want %q", got, "2001:db8:2::30")
	}
}

// A hostname collector carries no family: resolution keeps the legacy
// (family-blind, primary-first) behaviour.
func TestResolveSyslogSourceAddrForCollector_HostnameKeepsLegacy15078(t *testing.T) {
	cfg := syslogFamilyFixture15078()
	if got := ResolveSyslogSourceAddrForCollector(cfg, "reth1.100", "collector.example.net"); got != "10.0.1.20" {
		t.Errorf("hostname collector: resolved source = %q, want legacy primary %q", got, "10.0.1.20")
	}
	if got := ResolveSyslogSourceAddrForCollector(cfg, "reth1.100", ""); got != "10.0.1.20" {
		t.Errorf("empty collector: resolved source = %q, want legacy primary %q", got, "10.0.1.20")
	}
}

// Kernel arm (acceptance: "source-interface lo"): loopback carries both
// families. Asking for an IPv6 collector must pick ::1, not 127.0.0.1
// (127.0.0.1 is returned pre-fix and is exactly the dial failure).
// The IPv4 arm stays 127.0.0.1.
func TestResolveSyslogSourceAddrForCollector_KernelLoopback15078(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("no loopback interface")
	}
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{}}}
	if got := ResolveSyslogSourceAddrForCollector(cfg, "lo", "2001:db8:9::1"); got != "::1" {
		t.Errorf("kernel lo + IPv6 collector: resolved source = %q, want %q (#15078)", got, "::1")
	}
	if got := ResolveSyslogSourceAddrForCollector(cfg, "lo", "192.0.2.1"); got != "127.0.0.1" {
		t.Errorf("kernel lo + IPv4 collector: resolved source = %q, want %q (control)", got, "127.0.0.1")
	}
	// Legacy resolver pinned: still the first IPv4 (documents the defect
	// shape the family-aware entry point exists to fix).
	if got := ResolveSyslogSourceAddr(cfg, "lo"); got != "127.0.0.1" {
		t.Errorf("legacy ResolveSyslogSourceAddr(lo) = %q, want 127.0.0.1", got)
	}
}
