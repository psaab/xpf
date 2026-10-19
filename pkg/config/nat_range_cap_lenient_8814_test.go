package config

import (
	"strings"
	"testing"
)

// #8814: the 256-address cap on a NAT `address <low> to <high>` range was raised
// as a COMPILER error, so it fired on the LENIENT path as well as the strict one
// and a persisted config carrying an oversized range FAILED TO LOAD.
//
// `CompileConfigLenient`'s own doc says it exists "so an upgraded node boots
// through". A braced oversized range could not boot through, on master, before
// any recent change -- #8800 only removed the accident that hid it for the
// packed spelling.
//
// THE CAP IS NOT MOVED OUT OF THE COMPILER, and that is the one place this
// departs from the issue's stated remedy. Measured, the widest legal spelling
// `address 0.0.0.0/32 to 255.255.255.255/32` is 4294967296 addresses, so an
// expansion with no bound would try to allocate 4.29 billion strings on the
// LENIENT path -- the boot path. That trades a load failure for an OOM. The
// bound stays in expandAddressRange; only the ERROR became a recorded fact,
// which is the shape NATPool.PortRangeInvalidSpec and
// FirewallFilterTerm.UnknownFrom already use in this package.
func natPoolText8814(body string) string {
	return "security {\n nat {\n  source {\n   pool p1 {\n    " + body + "\n   }\n  }\n }\n}\n"
}

func proxyARPText8814(body string) string {
	return "security {\n nat {\n  proxy-arp {\n   interface ge-0-0-0 {\n    " + body + "\n   }\n  }\n }\n}\n"
}

func compileBoth8814(t *testing.T, text string) (lenient *Config, lenientErr, strictErr error) {
	t.Helper()
	tl, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	lenient, lenientErr = CompileConfigLenient(tl)
	ts, _ := NewParser(text).Parse()
	_, strictErr = CompileConfig(ts)
	return lenient, lenientErr, strictErr
}

func TestOversizedNATRangeLoadsLenientlyAndRejectsStrictly8814(t *testing.T) {
	for _, tc := range []struct {
		name       string
		text       string
		wantAddrs  int
		wantStrict bool // strict must reject
	}{
		{"257 IPs — one over the cap", natPoolText8814("address 10.0.0.1/32 to 10.0.1.1/32;"), 0, true},
		{"256 IPs — the boundary, unchanged", natPoolText8814("address 10.0.0.1/32 to 10.0.1.0/32;"), 256, false},
		{"2 IPs — ordinary range", natPoolText8814("address 10.0.0.1/32 to 10.0.0.2/32;"), 2, false},
		{"a plain address, no range", natPoolText8814("address 10.0.0.1/32;"), 1, false},
		// The whole domain: what an unbounded expansion would have allocated.
		{"the full IPv4 domain", natPoolText8814("address 0.0.0.0/32 to 255.255.255.255/32;"), 0, true},
		// An oversized range must not take the pool's OTHER addresses with it.
		{"oversized range beside a valid address", natPoolText8814("address 10.9.9.9/32;\n    address 10.0.0.1/32 to 10.0.1.1/32;"), 1, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg, lerr, serr := compileBoth8814(t, tc.text)
			if lerr != nil {
				t.Fatalf("CompileConfigLenient FAILED: %v\n"+
					"A persisted config must LOAD. This is the guarantee CompileConfigLenient "+
					"exists to provide -- an upgraded node, a peer sync, or a config file with a "+
					"range this build caps must boot through, with the strict path being the "+
					"thing that refuses new operator edits (#8814).", lerr)
			}
			pool := cfg.Security.NAT.SourcePools["p1"]
			if pool == nil {
				t.Fatal("pool p1 absent from the leniently compiled config")
			}
			if got := len(pool.Addresses); got != tc.wantAddrs {
				t.Errorf("pool has %d address(es), want %d — an oversized range must be OMITTED, "+
					"not fatal, and must not remove the pool's other addresses", got, tc.wantAddrs)
			}
			if tc.wantStrict {
				if serr == nil {
					t.Error("strict CompileConfig ACCEPTED an oversized range. The cap moving out of " +
						"the compiler trades toward exactly this failure: an operator can now author " +
						"a range the dataplane cannot expand (#8814)")
				} else if !strings.Contains(serr.Error(), "256") {
					t.Errorf("strict rejection does not name the cap: %v", serr)
				}
			} else if serr != nil {
				t.Errorf("strict CompileConfig rejected a legal config: %v", serr)
			}
		})
	}
}

// The proxy-arp caller of expandAddressRange had the IDENTICAL defect. Measured
// rather than assumed: on master a 257-address proxy-arp range failed
// CompileConfigLenient exactly as the pool case did. A fix that repaired only
// the pool would have left the same invariant broken one call site away.
func TestOversizedProxyARPRangeLoadsLenientlyAndRejectsStrictly8814(t *testing.T) {
	for _, tc := range []struct {
		name       string
		text       string
		wantStrict bool
	}{
		{"257 IPs — one over the cap", proxyARPText8814("address 10.0.0.1/32 to 10.0.1.1/32;"), true},
		{"256 IPs — the boundary, unchanged", proxyARPText8814("address 10.0.0.1/32 to 10.0.1.0/32;"), false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg, lerr, serr := compileBoth8814(t, tc.text)
			if lerr != nil {
				t.Fatalf("CompileConfigLenient FAILED: %v (#8814)", lerr)
			}
			if len(cfg.Security.NAT.ProxyARP) == 0 {
				t.Fatal("proxy-arp entry absent from the leniently compiled config")
			}
			if tc.wantStrict && serr == nil {
				t.Error("strict CompileConfig ACCEPTED an oversized proxy-arp range (#8814)")
			}
			if !tc.wantStrict && serr != nil {
				t.Errorf("strict CompileConfig rejected a legal proxy-arp range: %v", serr)
			}
		})
	}
}

// #15674 supersedes the #8814 malformed-is-fatal rule for RANGE errors:
// every expandAddressRange failure (malformed, non-host mask, mixed
// family, reversed) is now recorded, so lenient loads and strict rejects.
// IPv6 ranges are now valid (see nat_address_range_15674_test.go).
func TestMalformedRangesStillFailOnBothPaths8814(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"low > high", "address 10.0.0.9/32 to 10.0.0.1/32;"},
		{"not an IP", "address notanip to 10.0.0.1/32;"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg, lerr, serr := compileBoth8814(t, natPoolText8814(tc.body))
			if lerr != nil {
				t.Fatalf("CompileConfigLenient failed (#15674): %v", lerr)
			}
			if cfg == nil || cfg.Security.NAT.SourcePools["p1"] == nil {
				t.Fatal("pool absent on lenient path")
			}
			if got := len(cfg.Security.NAT.SourcePools["p1"].InvalidAddressRanges); got != 1 {
				t.Errorf("InvalidAddressRanges = %d, want 1", got)
			}
			if serr == nil {
				t.Error("strict CompileConfig accepted a malformed range")
			}
		})
	}
	// IPv6 ranges are valid since #15674.
	cfg, lerr, serr := compileBoth8814(t, natPoolText8814("address 2001:db8::1/128 to 2001:db8::9/128;"))
	if lerr != nil || serr != nil {
		t.Fatalf("IPv6 range must compile on both paths: lenient=%v strict=%v", lerr, serr)
	}
	if got := len(cfg.Security.NAT.SourcePools["p1"].Addresses); got != 9 {
		t.Errorf("IPv6 range expanded to %d, want 9", got)
	}
}

// The positive control the issue asks for: a cap that stops rejecting is the
// failure mode this change trades toward, so the strict rejection is asserted
// against a config that must be refused AND the recorded field is checked to be
// empty when it should be — otherwise "strict rejects" could be true for an
// unrelated reason.
func TestTheRecordedFieldIsOnlySetWhenOverCap8814(t *testing.T) {
	cfg, lerr, _ := compileBoth8814(t, natPoolText8814("address 10.0.0.1/32 to 10.0.1.0/32;"))
	if lerr != nil {
		t.Fatalf("lenient: %v", lerr)
	}
	if pool := cfg.Security.NAT.SourcePools["p1"]; pool == nil {
		t.Fatal("pool absent")
	} else if len(pool.OversizedAddressRanges) != 0 {
		t.Errorf("a 256-address range (AT the cap) was recorded as oversized: %v — the boundary is "+
			"inclusive and an off-by-one here would reject configs that are legal today",
			pool.OversizedAddressRanges)
	}
	cfg2, lerr2, _ := compileBoth8814(t, natPoolText8814("address 10.0.0.1/32 to 10.0.1.1/32;"))
	if lerr2 != nil {
		t.Fatalf("lenient: %v", lerr2)
	}
	pool2 := cfg2.Security.NAT.SourcePools["p1"]
	if pool2 == nil || len(pool2.OversizedAddressRanges) != 1 {
		t.Fatalf("a 257-address range was not recorded; without the record the strict gate has "+
			"nothing to reject and the cap silently disappears (got %v)", pool2)
	}
	if !strings.Contains(pool2.OversizedAddressRanges[0], "257") {
		t.Errorf("the recorded spec does not carry the size: %q", pool2.OversizedAddressRanges[0])
	}
}

// The FLAT `set` spelling, which decides whether this is operator-facing or
// config-file-only.
//
// The cells above compile hierarchical text through NewParser. That leaves the
// spelling an operator actually TYPES unpinned, and the distinction matters
// here: if the cap were reachable only from a persisted file, an operator could
// not author an oversized range interactively and the strict gate would be
// guarding a population of one. It is reachable, so the gate is doing
// operator-facing work and both halves have to hold in this spelling too.
//
// Raised by lane-8526 as a gap in the original coverage. It came out green,
// which is luck rather than diligence until something asserts it -- an
// unmeasured spelling is exactly how #8778's first fix looked complete.
//
// ParseSetCommand + SetPath, never NewParser: the parser treats newlines as
// whitespace and merges every set line into one node, so a measurement taken
// through it describes a tree nobody has (CLAUDE.md; #8808).
// The phrases that identify the RANGE-CAP gate specifically, rather than any
// rejection. Chosen from each gate's own message and deliberately narrower than
// "capped at": a future unrelated cap would contain that, and the point of
// #8822 is that a rejection from an unrelated cause must not satisfy this cell.
//
// If a gate's wording changes, this cell fails loudly and a human re-points it
// at the new wording — which is the intended cost. It cannot silently start
// accepting a different gate's rejection.
const (
	natPoolCapPhrase8822  = "a pool address range expands to one address per IP"
	proxyARPCapPhrase8822 = "NTF_PROXY neighbour per address"
)

func TestFlatSetSpellingHitsTheSameRangeCap8814(t *testing.T) {
	flat := func(t *testing.T, lines ...string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, l := range lines {
			path, err := ParseSetCommand(l)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", l, err)
			}
			// #8822: check SetPath too. This cell's own assertions (pool
			// non-nil, address count, recorded count) would catch a partial
			// tree today, so this is robustness rather than a live vacuity --
			// but a helper of this shape gets copied into cells with weaker
			// assertions, and there the positive control is gone.
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", l, err)
			}
		}
		return tree
	}
	for _, tc := range []struct {
		name       string
		line       string
		wantAddrs  int
		wantRecord int
		wantStrict bool
	}{
		{"257 IPs — one over the cap", "set security nat source pool p1 address 10.0.0.1/32 to 10.0.1.1/32", 0, 1, true},
		{"256 IPs — the boundary", "set security nat source pool p1 address 10.0.0.1/32 to 10.0.1.0/32", 256, 0, false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg, lerr := compileConfigWithOpts(flat(t, tc.line), lenientCompileOpts())
			if lerr != nil {
				t.Fatalf("CompileConfigLenient FAILED on the flat spelling: %v (#8814)", lerr)
			}
			pool := cfg.Security.NAT.SourcePools["p1"]
			if pool == nil {
				t.Fatal("pool p1 absent from the leniently compiled flat-set config")
			}
			if got := len(pool.Addresses); got != tc.wantAddrs {
				t.Errorf("flat set: pool has %d address(es), want %d", got, tc.wantAddrs)
			}
			if got := len(pool.OversizedAddressRanges); got != tc.wantRecord {
				t.Errorf("flat set: %d recorded oversized range(s), want %d — the flat spelling must "+
					"reach the same record-and-gate path as the hierarchical one, or the strict gate "+
					"guards only configs that arrive from a file", got, tc.wantRecord)
			}
			_, serr := compileConfigWithOpts(flat(t, tc.line), compileOpts{})
			if tc.wantStrict {
				if serr == nil {
					t.Error("flat set: strict CompileConfig ACCEPTED an oversized range — an operator can " +
						"author one interactively (#8814)")
				} else if !strings.Contains(serr.Error(), natPoolCapPhrase8822) {
					// #8822: assert WHICH gate rejected, not that something did.
					// `serr != nil` is a proxy: a later schema tightening on
					// `to`, a new required sibling, or a validator reordering
					// could reject this input for an unrelated reason, and then
					// the CAP GATE COULD BE DELETED AND THIS CELL STAY GREEN --
					// pinning "something rejects this line", which is not the
					// property #8814 is about.
					t.Errorf("flat set: strict rejected, but NOT with the range-cap gate.\n"+
						"  got: %v\n"+
						"  want a message containing %q\n"+
						"A rejection from an unrelated cause satisfies `err != nil` while the cap "+
						"gate is gone (#8822).", serr, natPoolCapPhrase8822)
				}
			}
			if !tc.wantStrict && serr != nil {
				t.Errorf("flat set: strict rejected a legal range: %v", serr)
			}
		})
	}
	// proxy-arp, the second caller, in the same spelling.
	line := "set security nat proxy-arp interface ge-0-0-0 address 10.0.0.1/32 to 10.0.1.1/32"
	cfg, lerr := compileConfigWithOpts(flat(t, line), lenientCompileOpts())
	if lerr != nil {
		t.Fatalf("flat set proxy-arp: CompileConfigLenient FAILED: %v", lerr)
	}
	recorded := 0
	for _, e := range cfg.Security.NAT.ProxyARP {
		if e != nil {
			recorded += len(e.OversizedRangeSpecs)
		}
	}
	if recorded != 1 {
		t.Errorf("flat set proxy-arp: %d recorded oversized range(s), want 1", recorded)
	}
	if _, serr := compileConfigWithOpts(flat(t, line), compileOpts{}); serr == nil {
		t.Error("flat set proxy-arp: strict CompileConfig accepted an oversized range (#8814)")
	} else if !strings.Contains(serr.Error(), proxyARPCapPhrase8822) {
		// #8822: the proxy-arp leg had the same `err != nil` proxy.
		t.Errorf("flat set proxy-arp: strict rejected, but NOT with the range-cap gate.\n"+
			"  got: %v\n"+
			"  want a message containing %q (#8822)", serr, proxyARPCapPhrase8822)
	}
}
