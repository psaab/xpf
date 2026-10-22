package config

import (
	"strings"
	"testing"
)

// #9408: `protocols ospf reference-bandwidth` was an UNTYPED leaf whose value
// reached a `strconv.Atoi` with a discarded error, so:
//
//   - every SUFFIXED spelling (`1g`, `100m` — the forms Junos documentation
//     uses) compiled to 0 and rendered NO `auto-cost` line, leaving the
//     operator's cost basis at FRR's default with zero signal, and
//   - a bare integer was passed VERBATIM into `auto-cost reference-bandwidth`,
//     whose unit is Mbps, while the Junos leaf's unit is bits/s.
//
// The tree's own two cells concealed both halves: the FRR pin asserted
// "int in, int out" and said nothing about units, and the parser cell authored
// `10g` and then asserted only `ospf != nil`.
//
// Everything below drives the SSOT both the commit gate and the compiler call.

func compileRefBandwidth9408(t *testing.T, token string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set protocols ospf reference-bandwidth " + token,
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(%q): %v", token, err)
	}
	return cfg
}

func schemaValidateRefBandwidth9408(t *testing.T, token string) error {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set protocols ospf reference-bandwidth " + token,
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	return SchemaValidate(tree)
}

// THE UNIT. The leaf is BITS PER SECOND (Junos) and the compiled field is
// MEGABITS PER SECOND (FRR). Every row names one bandwidth in two spellings
// and asserts they land on the same Mbps number — a pin on the CONVERSION, not
// on a passthrough. Reverting the compiler to `strconv.Atoi` reds every
// suffixed row (they compile to 0) AND every plain-integer row (they compile
// to the bits/s number, six orders of magnitude out).
func TestOSPFReferenceBandwidthUnitConversion9408(t *testing.T) {
	for _, tc := range []struct {
		token    string
		wantMbps int
		note     string
	}{
		{"1g", 1000, "1 Gbps"},
		{"1000000000", 1000, "1 Gbps, plain bits/s — the same bandwidth as 1g"},
		{"100m", 100, "the Junos DEFAULT reference bandwidth"},
		{"100000000", 100, "the Junos default, plain bits/s"},
		{"10g", 10000, "10 Gbps"},
		{"1m", 1, "the FRR floor, 1 Mbps"},
		{"1000000", 1, "the FRR floor, plain bits/s"},
		{"4294967m", 4294967, "the FRR ceiling, 4294967 Mbps"},
	} {
		cfg := compileRefBandwidth9408(t, tc.token)
		if cfg.Protocols.OSPF == nil {
			t.Fatalf("%s: OSPF config is nil", tc.token)
		}
		if got := cfg.Protocols.OSPF.ReferenceBandwidthMbps; got != tc.wantMbps {
			t.Errorf("reference-bandwidth %s (%s): compiled %d Mbps, want %d",
				tc.token, tc.note, got, tc.wantMbps)
		}
		if err := schemaValidateRefBandwidth9408(t, tc.token); err != nil {
			t.Errorf("reference-bandwidth %s (%s): the commit gate REJECTED a value the compiler accepts: %v",
				tc.token, tc.note, err)
		}
	}
}

// THE GATE, with its positive controls in the same run. Each rejected row
// names a distinct failure mode, and each is paired against an accepted value
// on the same axis so "the gate rejects everything" cannot pass for "the gate
// works".
//
// The pairing matters because the pre-#9408 behaviour of EVERY row below was
// ACCEPT-and-silently-compile-to-0. A cell that only asserted "0 was not
// stored" would have been green before the fix as well.
func TestOSPFReferenceBandwidthCommitGate9408(t *testing.T) {
	for _, tc := range []struct {
		token   string
		wantErr string // substring the message must carry
		why     string
	}{
		{"1g", "", "CONTROL: a whole number of Gbps is accepted"},
		{"100m", "", "CONTROL: the Junos default is accepted"},
		{"1000000", "", "CONTROL: the exact FRR floor is accepted"},
		{"4294967000000", "", "CONTROL: the exact FRR ceiling is accepted"},

		// Below the floor. `100` is the shape an operator reaches for when
		// they believe the unit is Mbps, so the message must name the unit.
		{"100", "BITS PER SECOND", "100 bits/s is below the 1 Mbps floor"},
		{"10000", "BITS PER SECOND", "the pre-#9408 Mbps spelling of 10 Gbps is 10 kbps in Junos units"},
		{"9600", "BITS PER SECOND", "Junos's own minimum is still below what FRR can express"},

		// Above the FRR ceiling — a legal Junos value this platform cannot render.
		{"100t", "", "SKIP: `t` is not a Junos bandwidth suffix"},
		{"4294968000000", "maximum", "one Mbps above FRR's 4294967 ceiling"},
		{"100000000000000", "maximum", "Junos's own ceiling, 100 Tbps, exceeds FRR's"},

		// Not a whole number of Mbps: FRR cannot express it and truncating
		// would silently change every interface cost.
		{"1500000", "not a whole number of Mbps", "1.5 Mbps"},
		{"1234567", "not a whole number of Mbps", "an arbitrary bits/s value"},

		// Malformed.
		{"abc", "not a valid bandwidth", "not a number at all"},
		{"1gg", "not a valid bandwidth", "a doubled suffix"},
	} {
		if strings.HasPrefix(tc.why, "SKIP") {
			continue
		}
		err := schemaValidateRefBandwidth9408(t, tc.token)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("reference-bandwidth %s (%s): want ACCEPT, got %v", tc.token, tc.why, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("reference-bandwidth %s (%s): want REJECT, got ACCEPT — the pre-#9408 leaf accepted "+
				"this and compiled it to 0, which is indistinguishable from `not configured`", tc.token, tc.why)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("reference-bandwidth %s (%s): message must carry %q so the operator learns the unit; got %v",
				tc.token, tc.why, tc.wantErr, err)
		}
	}
}

// A NEGATIVE value is rejected. Called out separately because `-5` was
// specifically measured as ACCEPTED-and-rendering-nothing before #9408, and
// because it exercises the parser's own sign handling rather than the range.
func TestOSPFReferenceBandwidthRejectsNegative9408(t *testing.T) {
	if err := schemaValidateRefBandwidth9408(t, "-5"); err == nil {
		t.Error("reference-bandwidth -5 must be rejected; before #9408 it was accepted and rendered nothing")
	}
	cfg := compileRefBandwidth9408(t, "-5")
	if got := cfg.Protocols.OSPF.ReferenceBandwidthMbps; got != 0 {
		t.Errorf("a rejected value must leave the field UNSET so no auto-cost line is rendered; got %d", got)
	}
}

// FAIL SAFE ON THE TOLERANT PATH. SchemaValidate violations are downgraded to
// warnings by configstore.compileTreeLenient, so a persisted config carrying a
// value the gate rejects still reaches compileProtocols. It must leave the
// field UNSET (FRR's own default applies) rather than render an unconverted
// token into the managed section — one line vtysh rejects can degrade the
// whole reload.
//
// The control is the row directly beneath: the same code path stores a value
// it CAN convert, so "the compiler stores nothing" cannot pass for "the
// compiler fails safe".
func TestOSPFReferenceBandwidthCompilerFailsSafe9408(t *testing.T) {
	for _, tc := range []struct {
		token    string
		wantMbps int
	}{
		{"10000", 0},       // rejected: 10 kbps, below the FRR floor
		{"1500000", 0},     // rejected: not a whole number of Mbps
		{"abc", 0},         // rejected: unparseable
		{"1g", 1000},       // CONTROL: convertible, and stored
		{"100000000", 100}, // CONTROL: convertible, and stored
	} {
		cfg := compileRefBandwidth9408(t, tc.token)
		if got := cfg.Protocols.OSPF.ReferenceBandwidthMbps; got != tc.wantMbps {
			t.Errorf("reference-bandwidth %s: compiled %d Mbps, want %d", tc.token, got, tc.wantMbps)
		}
	}
}

// THE FLAT-SET CHAIN. `set protocols ospf passive reference-bandwidth 1g` is
// ONE command, and SetPath nests `reference-bandwidth` UNDER `passive` rather
// than beside it. The direct-children loop in compileProtocols read `passive`
// and dropped the rest of the run on a commit that reports success.
//
// This was already true before #9408 and the #8939 census recorded it as
// VACUOUS rather than as a loss, because the leaf compiled to 0 in BOTH
// spellings — two equal-but-empty compiles prove nothing. Typing the leaf is
// what made the loss observable, so the expansion lands in the same change.
//
// Every ordering is driven, because the loss is order-dependent: which leaf
// survives is whichever one SetPath put first.
func TestOSPFFlatSetChainKeepsEveryLeaf9408(t *testing.T) {
	compileOneLine := func(t *testing.T, line string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range []string{line, "set protocols ospf area 0.0.0.0 interface ge-0/0/1.0"} {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%v): %v", path, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", line, err)
		}
		return cfg
	}

	t.Run("passive then reference-bandwidth", func(t *testing.T) {
		cfg := compileOneLine(t, "set protocols ospf passive reference-bandwidth 1g")
		if !cfg.Protocols.OSPF.PassiveDefault {
			t.Error("passive lost")
		}
		if got := cfg.Protocols.OSPF.ReferenceBandwidthMbps; got != 1000 {
			t.Errorf("reference-bandwidth lost from the chain tail: got %d Mbps, want 1000", got)
		}
	})
	t.Run("reference-bandwidth then passive", func(t *testing.T) {
		cfg := compileOneLine(t, "set protocols ospf reference-bandwidth 1g passive")
		if !cfg.Protocols.OSPF.PassiveDefault {
			t.Error("passive lost from the chain tail")
		}
		if got := cfg.Protocols.OSPF.ReferenceBandwidthMbps; got != 1000 {
			t.Errorf("reference-bandwidth: got %d Mbps, want 1000", got)
		}
	})
	t.Run("router-id then reference-bandwidth", func(t *testing.T) {
		cfg := compileOneLine(t, "set protocols ospf router-id 10.0.0.1 reference-bandwidth 1g")
		if cfg.Protocols.OSPF.RouterID != "10.0.0.1" {
			t.Errorf("router-id: got %q", cfg.Protocols.OSPF.RouterID)
		}
		if got := cfg.Protocols.OSPF.ReferenceBandwidthMbps; got != 1000 {
			t.Errorf("reference-bandwidth lost from the chain tail: got %d Mbps, want 1000", got)
		}
	})
	t.Run("three leaves", func(t *testing.T) {
		// At TWO leaves a chain is indistinguishable from ordinary nesting; at
		// THREE the remainder packs onto ONE node's Keys, which is the shape a
		// recursive descent silently truncates.
		cfg := compileOneLine(t, "set protocols ospf router-id 10.0.0.1 reference-bandwidth 1g passive")
		if cfg.Protocols.OSPF.RouterID != "10.0.0.1" {
			t.Errorf("router-id: got %q", cfg.Protocols.OSPF.RouterID)
		}
		if got := cfg.Protocols.OSPF.ReferenceBandwidthMbps; got != 1000 {
			t.Errorf("reference-bandwidth: got %d Mbps, want 1000", got)
		}
		if !cfg.Protocols.OSPF.PassiveDefault {
			t.Error("passive lost from the packed tail")
		}
	})
	t.Run("the area subtree still resolves through the expansion", func(t *testing.T) {
		// expandFlatRun leaves a container leaf's subtree whole, and the area
		// loop reads the SAME expanded slice. Without that second half the
		// expansion would move `area` out from under the loop that reads it.
		cfg := compileOneLine(t, "set protocols ospf reference-bandwidth 1g")
		if len(cfg.Protocols.OSPF.Areas) != 1 || cfg.Protocols.OSPF.Areas[0].ID != "0.0.0.0" {
			t.Fatalf("area lost: %+v", cfg.Protocols.OSPF.Areas)
		}
		if len(cfg.Protocols.OSPF.Areas[0].Interfaces) != 1 {
			t.Fatalf("area interface lost: %+v", cfg.Protocols.OSPF.Areas[0])
		}
	})
}
