package config

import (
	"strings"
	"testing"
)

// #5829: `interfaces <if> unit <identity>` had NO positional key validation.
// A non-numeric identity such as `unit tenant` passed schema + commit, and
// compileInterfaces then SILENTLY DISCARDED the whole unit on strconv failure
// (bare `continue`) — every child (addresses, firewall filters, sampling,
// DHCP/DDNS, tunnel) vanished with no diagnostic. Security bite: a unit-level
// input/output firewall FILTER committed with NO enforcement (fail-open).
//
// The fix is fail-CLOSED at two layers:
//   - schema: the `unit` instance key is typed (keyValidator ValidateLogicalUnit)
//     so `commit`/`commit check` (SchemaValidate) reject the malformed identity;
//   - compiler: compiler_interfaces.go returns a hard error (strict) / warns +
//     quarantines the unit (tolerant load / peer-sync) instead of the bare
//     `continue` — defense-in-depth for any path that bypasses SchemaValidate.
//
// Flat-set MUST be built with ParseSetCommand/SetPath (flatTreeFromSets), never
// NewParser (CLAUDE.md "Testing flat set syntax").
//
// FAIL-ON-REVERT: restore the bare `if err != nil { continue }` at
// compiler_interfaces.go AND drop `keyValidator: ValidateLogicalUnit` from the
// schema unit node → the malformed configs compile clean (filter dropped) and
// SchemaValidate accepts them → the reject assertions below go RED.

// TestUnit5829_MalformedRejectedAtCommit proves a non-numeric / negative /
// overflow / out-of-range logical unit is hard-rejected at strict commit by
// BOTH the schema gate and the compiler gate, naming the interface + bad token.
func TestUnit5829_MalformedRejectedAtCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string // substring expected in the error (the bad raw token)
	}{
		{
			// The exact security fail-open: a unit-level firewall filter under a
			// non-numeric unit. Before the fix this committed with no enforcement.
			name: "non-numeric unit carrying a firewall filter",
			cmds: []string{"set interfaces ge-0-0-0 unit tenant family inet filter input FOO"},
			want: `"tenant"`,
		},
		{
			name: "non-numeric unit carrying an address",
			cmds: []string{"set interfaces ge-0-0-0 unit foo family inet address 10.0.1.1/24"},
			want: `"foo"`,
		},
		{
			name: "negative unit",
			cmds: []string{"set interfaces ge-0-0-0 unit -1 family inet address 10.0.1.1/24"},
			want: `"-1"`,
		},
		{
			name: "integer-overflow unit",
			cmds: []string{"set interfaces ge-0-0-0 unit 99999999999999999999 family inet address 10.0.1.1/24"},
			want: `"99999999999999999999"`,
		},
		{
			name: "out-of-range unit (> MaxLogicalUnit)",
			cmds: []string{"set interfaces ge-0-0-0 unit 16386 family inet address 10.0.1.1/24"},
			want: `"16386"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, tc.cmds...)

			// Primary gate: schema keyValidator at commit-check.
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("SchemaValidate accepted malformed unit; want commit rejection")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SchemaValidate error must name the bad unit token %s: %v", tc.want, err)
			}

			// Defense-in-depth: compiler hard error (also covers any bypass of
			// SchemaValidate). Must NOT be a clean compile that drops the unit.
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted malformed unit (silent drop / fail-open); want reject")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CompileConfig error must name the bad unit token %s: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "ge-0-0-0") {
				t.Fatalf("error must name the interface: %v", err)
			}
		})
	}
}

// TestUnit5829_ValidUnitCompilesFilterReachesMap guards against a false-reject:
// a valid numeric unit (including the max boundary) with the SAME filter must
// compile identically and the filter must reach the typed map.
func TestUnit5829_ValidUnitCompilesFilterReachesMap(t *testing.T) {
	// FOO must be a defined filter (an undefined-filter reference is itself a
	// separate fail-open gate); the point here is the unit + its filter binding
	// survive compilation into the typed map.
	def := "set firewall family inet filter FOO term t1 then accept"
	cases := []struct {
		cmds    []string
		wantNum int
	}{
		{[]string{def, "set interfaces ge-0-0-0 unit 0 family inet filter input FOO"}, 0},
		// Max-boundary unit remains accepted.
		{[]string{def, "set interfaces ge-0-0-0 unit 16385 family inet filter input FOO"}, 16385},
	}
	for _, tc := range cases {
		tree := flatTreeFromSets(t, tc.cmds...)
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("SchemaValidate rejected a valid unit %d: %v", tc.wantNum, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected a valid unit %d: %v", tc.wantNum, err)
		}
		ifc := cfg.Interfaces.Interfaces["ge-0-0-0"]
		if ifc == nil {
			t.Fatalf("interface ge-0-0-0 missing after compiling unit %d", tc.wantNum)
		}
		unit, ok := ifc.Units[tc.wantNum]
		if !ok || unit == nil {
			t.Fatalf("valid unit %d not in the typed map: units=%v", tc.wantNum, ifc.Units)
		}
		if unit.FilterInputV4 != "FOO" {
			t.Fatalf("unit %d filter did not reach the typed map: got %q, want FOO", tc.wantNum, unit.FilterInputV4)
		}
	}
}

// TestUnit5829_LenientWarnsAndQuarantines proves the tolerant load / peer-sync
// path (CompileConfigLenient) does NOT hard-error and does NOT silently drop:
// it emits a deterministic warning naming the interface + bad token, and the
// malformed unit's filter is quarantined (never reattached to another unit).
func TestUnit5829_LenientWarnsAndQuarantines(t *testing.T) {
	tree := flatTreeFromSets(t, "set interfaces ge-0-0-0 unit tenant family inet filter input FOO")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a malformed unit (want warn): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "tenant") && strings.Contains(w, "ge-0-0-0") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no malformed-unit warning; got %v", cfg.Warnings)
	}
	// Quarantine: the malformed unit's filter must NOT have leaked onto any
	// unit (in particular it must not be silently misattributed to unit 0).
	if ifc := cfg.Interfaces.Interfaces["ge-0-0-0"]; ifc != nil {
		for num, u := range ifc.Units {
			if u != nil && u.FilterInputV4 == "FOO" {
				t.Fatalf("malformed unit's filter leaked onto unit %d (want quarantined): %+v", num, u)
			}
		}
	}
}
