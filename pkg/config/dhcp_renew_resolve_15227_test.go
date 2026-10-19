package config

import (
	"strings"
	"testing"
)

// renewCfg15227 builds the #15227 A43-04 fixture directly: ge-0/0/0 unit 0
// (untagged DHCP), ge-0/0/3 unit 7 with vlan-id 50 (lease key ge-0-0-3.50),
// and ge-0/0/1 with no DHCP at all (control).
func renewCfg15227() *Config {
	return &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
		"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*InterfaceUnit{
			7: {Number: 7, VlanID: 50, DHCPv6: true},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0},
		}},
	}}}
}

// TestResolveDHCPRenewTarget15227 is the A43-04 RED/GREEN cell: every
// operator spelling of a DHCP unit resolves to the lease key the manager
// runs under. Pre-fix ResolveDHCPRenewTarget does not exist (build RED);
// with resolution deleted the Junos cells would return the raw spelling
// and miss the keyed client.
func TestResolveDHCPRenewTarget15227(t *testing.T) {
	cfg := renewCfg15227()
	cases := []struct{ in, want string }{
		{"ge-0/0/0", "ge-0-0-0"},       // bare Junos key, sole DHCP unit
		{"ge-0/0/0.0", "ge-0-0-0"},     // Junos ifd.unit
		{"ge-0-0-0", "ge-0-0-0"},       // Linux bare form
		{"ge-0-0-0.0", "ge-0-0-0"},     // Linux form with unit number
		{"ge-0/0/3.7", "ge-0-0-3.50"},  // unit number != vlan-id: key carries vlan-id
		{"ge-0-0-3.7", "ge-0-0-3.50"},  // Linux spelling of the same unit ref
		{"ge-0-0-3.50", "ge-0-0-3.50"}, // hidden lease-key workaround keeps working
		{"ge-0/0/3", "ge-0-0-3.50"},    // bare interface, sole DHCP unit (tagged)
	}
	for _, tc := range cases {
		got, err := cfg.ResolveDHCPRenewTarget(tc.in)
		if err != nil {
			t.Errorf("ResolveDHCPRenewTarget(%q) err = %v, want %q", tc.in, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("ResolveDHCPRenewTarget(%q) = %q, want lease key %q", tc.in, got, tc.want)
		}
	}
}

// TestResolveDHCPRenewTargetRefusals15227 pins the fail-closed controls:
// no behaviour change for targets that run no client.
func TestResolveDHCPRenewTargetRefusals15227(t *testing.T) {
	cfg := renewCfg15227()
	for _, in := range []string{"ge-0/0/1", "ge-0/0/1.0", "ge-0/0/9", "ge-0/0/3.9", "ge-0-0-3.99", ""} {
		if got, err := cfg.ResolveDHCPRenewTarget(in); err == nil {
			t.Errorf("ResolveDHCPRenewTarget(%q) = %q, want refusal", in, got)
		}
	}
	// A bare interface with several DHCP units refuses rather than
	// silently widening a scoped renew to all of them.
	multi := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/4": {Name: "ge-0/0/4", Units: map[int]*InterfaceUnit{
			0: {Number: 0, DHCP: true},
			1: {Number: 1, VlanID: 10, DHCP: true},
		}},
	}}}
	if _, err := multi.ResolveDHCPRenewTarget("ge-0/0/4"); err == nil ||
		!strings.Contains(err.Error(), "multiple units") {
		t.Errorf("multi-unit bare renew err = %v, want multiple-units refusal", err)
	}
	if got, err := multi.ResolveDHCPRenewTarget("ge-0/0/4.1"); err != nil || got != "ge-0-0-4.10" {
		t.Errorf("multi-unit unit renew = %q, %v; want ge-0-0-4.10", got, err)
	}
	// Nil config: raw target survives unchanged (manager diagnoses).
	var nilCfg *Config
	if got, err := nilCfg.ResolveDHCPRenewTarget("ge-0-0-0"); err != nil || got != "ge-0-0-0" {
		t.Errorf("nil-config resolve = %q, %v; want raw passthrough", got, err)
	}
}

// TestDHCPRenewCompletionNames15227 pins the completion direction of
// A43-04: completion offers resolvable config-key unit spellings only.
func TestDHCPRenewCompletionNames15227(t *testing.T) {
	got := DHCPRenewCompletionNames(renewCfg15227())
	want := []string{"ge-0/0/0.0", "ge-0/0/3.7"}
	if len(got) != len(want) {
		t.Fatalf("completion names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("completion names = %v, want %v", got, want)
		}
	}
	if names := DHCPRenewCompletionNames(nil); names != nil {
		t.Fatalf("nil-config completion = %v, want nil", names)
	}
}
