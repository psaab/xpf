package config

import (
	"strings"
	"testing"
)

// #3446: source- and destination-NAT `match destination-port` had no range
// validation. The parser used a bare strconv.Atoi (no bound check, non-numeric
// silently dropped) and the builders cast straight to uint16, so:
//   - H12: `destination-port 0`     → installed as the wildcard port (any).
//   - H13: `destination-port 70000` → uint16 wrap to 4464 (wrong port);
//          `destination-port -1`     → wrap to 65535.
//   - H14: `destination-port http`  → dropped → empty list → wildcard port.
//
// validateNATMatchDestinationPortStrict now rejects all of these at commit
// (mirroring static NAT #2491) and downgrades to a warning on the tolerant
// load / peer-sync path. RED-on-revert: delete the validator (or its
// registration in compiler.go) and the reject cases compile clean.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath, never NewParser.

func dnatTree(t *testing.T, dportCmd string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	cmds := []string{
		"set security zones security-zone untrust",
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set RS from zone untrust",
		"set security nat destination rule-set RS rule R1 match destination-address 203.0.113.10/32",
		dportCmd,
		"set security nat destination rule-set RS rule R1 then destination-nat pool p1",
	}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func snatTree(t *testing.T, dportCmd string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	cmds := []string{
		"set security nat source rule-set RS from zone lan",
		"set security nat source rule-set RS to zone wan",
		dportCmd,
		"set security nat source rule-set RS rule R1 then source-nat interface",
	}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func TestDNATMatchDestPortRejectedAtCommit_3446(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"zero", "set security nat destination rule-set RS rule R1 match destination-port 0"},
		{"over-range", "set security nat destination rule-set RS rule R1 match destination-port 70000"},
		{"negative", "set security nat destination rule-set RS rule R1 match destination-port -1"},
		{"nonnumeric", "set security nat destination rule-set RS rule R1 match destination-port http"},
		{"range-endpoint-over", "set security nat destination rule-set RS rule R1 match destination-port 65000 to 70000"},
		{"bracket-has-bad", "set security nat destination rule-set RS rule R1 match destination-port [ 80 0 ]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := dnatTree(t, tc.cmd)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted invalid DNAT destination-port %q (want reject)", tc.cmd)
			}
			// Lenient path must NOT brick (downgrade to warning) and must compile.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected %q (want warn-and-compile): %v", tc.cmd, err)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatalf("CompileConfigLenient produced no warning for %q", tc.cmd)
			}
		})
	}
}

func TestSNATMatchDestPortRejectedAtCommit_3446(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"zero", "set security nat source rule-set RS rule R1 match destination-port 0"},
		{"over-range", "set security nat source rule-set RS rule R1 match destination-port 70000"},
		{"nonnumeric", "set security nat source rule-set RS rule R1 match destination-port httpp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := snatTree(t, tc.cmd)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted invalid SNAT destination-port %q (want reject)", tc.cmd)
			}
			if _, err := CompileConfigLenient(tree); err != nil {
				t.Fatalf("CompileConfigLenient rejected %q (want warn-and-compile): %v", tc.cmd, err)
			}
		})
	}
}

func TestNATMatchDestPortValidStillCompiles_3446(t *testing.T) {
	// A valid single port, a valid range, and a valid bracket list must all
	// commit clean — the gate must not over-reject.
	valid := []string{
		"set security nat destination rule-set RS rule R1 match destination-port 8080",
		"set security nat destination rule-set RS rule R1 match destination-port 20000 to 20003",
		"set security nat destination rule-set RS rule R1 match destination-port [ 80 443 65535 1 ]",
	}
	for _, cmd := range valid {
		tree := dnatTree(t, cmd)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected VALID destination-port %q: %v", cmd, err)
		}
	}
	// Source NAT valid range.
	tree := snatTree(t, "set security nat source rule-set RS rule R1 match destination-port 1024 to 2048")
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected VALID SNAT destination-port range: %v", err)
	}
}

// The parser must preserve non-numeric tokens on InvalidDestinationPorts so the
// gate can see them (they used to be silently dropped). RED-on-revert: restore
// the bare `continue` in parseDNATPortList and InvalidDestinationPorts is empty.
func TestNATMatchDestPortInvalidTokenPreserved_3446(t *testing.T) {
	tree := dnatTree(t, "set security nat destination rule-set RS rule R1 match destination-port [ 80 http ]")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if len(rule.Match.DestinationPorts) != 1 || rule.Match.DestinationPorts[0] != 80 {
		t.Fatalf("DestinationPorts = %v, want [80] (numeric kept)", rule.Match.DestinationPorts)
	}
	found := false
	for _, tok := range rule.Match.InvalidDestinationPorts {
		if tok == "http" {
			found = true
		}
	}
	if !found {
		t.Fatalf("InvalidDestinationPorts = %v, want it to contain \"http\"", rule.Match.InvalidDestinationPorts)
	}
}
