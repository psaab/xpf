package config

import (
	"testing"
)

// #3450: a destination-NAT POOL's translated `port` and `address` had no strict
// commit validation. The pool parser used a bare strconv.Atoi (no bound check,
// non-numeric silently dropped → Port==0 = preserve-dest-port) and stored the
// address verbatim; the snapshot builder cast the port to uint16 and stripped
// any CIDR suffix from the address. So:
//   - M03: `port 70000` → uint16 wrap to 4464 (wrong backend port); `-1` → 65535.
//   - M04: `port 0` / `port httpp` → Port==0 → "preserve destination port" → the
//          requested rewrite is silently a no-op.
//   - M05: `address 10.0.0.0/24` → CIDR stripped to the network base 10.0.0.0
//          (no pool/range semantics).
//   - M06: `address web-server` (a name) → Rust fails to parse → installs NO
//          entry → the VIP is silently untranslated.
//
// validateDNATPoolStrict now rejects all of these at commit (mirroring static
// NAT #2491 / the match-dest-port #3446 doctrine) and downgrades to a warning
// on the tolerant load / peer-sync path. RED-on-revert: delete the validator
// (or its registration in compiler.go) and the reject cases compile clean.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath, never NewParser.

func dnatPoolTree(t *testing.T, poolCmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	cmds := append([]string{}, poolCmds...)
	cmds = append(cmds,
		"set security zones security-zone untrust",
		"set security nat destination rule-set RS from zone untrust",
		"set security nat destination rule-set RS rule R1 match destination-address 203.0.113.10/32",
		"set security nat destination rule-set RS rule R1 then destination-nat pool p1",
	)
	for _, cmd := range cmds {
		// CLAUDE.md: build flat-set syntax via ParseSetCommand (the production
		// tokenizer — strips the `set` verb, splits bracket lists / quotes) +
		// tree.SetPath, NEVER NewParser (which merges all lines into one node).
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func TestDNATPoolRejectedAtCommit_3450(t *testing.T) {
	cases := []struct {
		name string
		pool []string
	}{
		{"port-over-range", []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 port 70000"}},
		{"port-negative", []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 port -1"}},
		{"port-zero", []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 port 0"}},
		{"port-nonnumeric", []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 port httpp"}},
		// Junos nests the pool port under `address port <N>`. An invalid value
		// there must reject too (pre-#3450 it set Address="port" and dropped the
		// port entirely).
		{"address-port-over-range", []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 address port 70000"}},
		{"address-port-zero", []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 address port 0"}},
		{"address-non-host-cidr", []string{
			"set security nat destination pool p1 address 10.0.0.0/24"}},
		{"address-name", []string{
			"set security nat destination pool p1 address web-server"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := dnatPoolTree(t, tc.pool...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted invalid DNAT pool %q (want reject)", tc.name)
			}
			// Lenient path must NOT brick (downgrade to warning) and must compile.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient rejected %q (want warn-and-compile): %v", tc.name, err)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatalf("CompileConfigLenient produced no warning for %q", tc.name)
			}
		})
	}
}

func TestDNATPoolValidStillCompiles_3450(t *testing.T) {
	// A bare host IP, a /32, a /128, a valid port, and an address-only pool (no
	// port leaf = preserve destination port) must all commit clean — the gate
	// must not over-reject.
	valid := [][]string{
		{"set security nat destination pool p1 address 192.168.1.10"},
		{"set security nat destination pool p1 address 192.168.1.10/32"},
		{"set security nat destination pool p1 address 2001:db8::1/128"},
		{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 port 8080",
		},
		{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 port 1",
		},
		{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 port 65535",
		},
		// Junos `address port <N>` form (nested under address).
		{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination pool p1 address port 8080",
		},
	}
	for i, pool := range valid {
		tree := dnatPoolTree(t, pool...)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("CompileConfig rejected VALID DNAT pool case %d (%v): %v", i, pool, err)
		}
	}
}

// PortRaw must be preserved by the parser so the gate can distinguish a
// configured port from no `port` leaf. RED-on-revert: drop the `pool.PortRaw =
// v` assignment and a `port 0` / non-numeric port becomes indistinguishable
// from the preserve-dest-port default (PortRaw stays "").
func TestDNATPoolPortRawPreserved_3450(t *testing.T) {
	// Configured invalid port: PortRaw set even though Port collapses to 0.
	tree := dnatPoolTree(t,
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination pool p1 port httpp")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	pool := cfg.Security.NAT.Destination.Pools["p1"]
	if pool.PortRaw != "httpp" {
		t.Fatalf("PortRaw = %q, want \"httpp\"", pool.PortRaw)
	}
	if pool.Port != 0 {
		t.Fatalf("Port = %d, want 0 (non-numeric not parsed)", pool.Port)
	}

	// No port leaf: PortRaw empty, the legitimate preserve-dest-port mode.
	tree2 := dnatPoolTree(t, "set security nat destination pool p1 address 192.168.1.10")
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if pr := cfg2.Security.NAT.Destination.Pools["p1"].PortRaw; pr != "" {
		t.Fatalf("PortRaw = %q, want \"\" (no port leaf)", pr)
	}
}

// The Junos `address port <N>` form must set Port AND keep the address intact
// (pre-#3450 the parser set Address to the literal "port" and dropped the
// port). RED-on-revert: restore `pool.Address = nodeVal(prop)` and Address
// becomes "port" (or the address is lost) and Port stays 0.
func TestDNATPoolAddressPortFormParsed_3450(t *testing.T) {
	tree := dnatPoolTree(t,
		"set security nat destination pool p1 address 10.0.1.100/32",
		"set security nat destination pool p1 address port 80")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected valid `address port` pool: %v", err)
	}
	pool := cfg.Security.NAT.Destination.Pools["p1"]
	if pool.Address != "10.0.1.100/32" {
		t.Fatalf("Address = %q, want 10.0.1.100/32 (not clobbered by `address port`)", pool.Address)
	}
	if pool.Port != 80 {
		t.Fatalf("Port = %d, want 80 (from `address port 80`)", pool.Port)
	}
}
