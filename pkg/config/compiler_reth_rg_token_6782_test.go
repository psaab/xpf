package config

import (
	"sort"
	"strings"
	"testing"
)

// #6782 — an invalid RETH redundancy-group commits as a non-HA address owned
// by BOTH nodes.
//
// compileInterfaces reads the token with `if v, err := strconv.Atoi(...);
// err == nil`, so a non-numeric token leaves the group at its 0 default and a
// negative one is stored verbatim. Every downstream consumer decides "is this a
// RETH?" with `redundancy-group > 0` (pkg/dataplane compiler_iface.go sets both
// isReth and isVRRPReth that way), so a non-positive group makes the interface
// read as ORDINARY: the 169.254.RG.NODE/32 link-local substitution does not
// fire and the reth's real service address is written onto the physical device.
// Both nodes share the synced config, so both configure it.
//
// These bind the gate AND the tolerant-path behaviour, in both directions.

// rethRGSet builds a minimal committable cluster config carrying one reth whose
// redundancy-group token is tok.
//
// The auth key is present because chassis-cluster commit independently requires
// one — without it every strict compile fails on THAT gate and a test asserting
// "strict rejects" would pass for the wrong reason.
func rethRGSet(tok string, extra ...string) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		`set chassis cluster authentication-key "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2Rl"`,
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
	}
	lines = append(lines, extra...)
	if tok != "" {
		lines = append(lines, "set interfaces reth0 redundant-ether-options redundancy-group "+tok)
	}
	return lines
}

func rethRGTree(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree
}

// TestRethRedundancyGroupTokenRejectedAtCommit6782 is the primary
// RED-on-revert: every token class that makes the interface read as
// NON-redundant must hard-reject on the strict commit path.
//
// The classes are enumerated rather than lumped, because they reach the same
// failure by different routes and a fix that only handles one of them looks
// identical from the outside: `abc`/`1.5`/an int64 overflow are DISCARDED parse
// errors that leave the group at 0, while `-1` parses SUCCESSFULLY and is
// stored verbatim.
func TestRethRedundancyGroupTokenRejectedAtCommit6782(t *testing.T) {
	for _, tc := range []struct {
		name, tok, wantIn string
	}{
		{"control-plane-group-zero", "0", "control-plane group"},
		{"negative", "-1", "is negative"},
		{"negative-large", "-99999", "is negative"},
		{"non-numeric", "abc", "is not an integer"},
		{"fractional", "1.5", "is not an integer"},
		{"int64-overflow", "99999999999999999999", "is not an integer"},
		{"above-octet-ceiling", "256", "not a valid IPv4 address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := rethRGTree(t, rethRGSet(tc.tok))
			cfg, err := CompileConfig(tree)
			if err == nil {
				got := -777
				if ifc := cfg.Interfaces.Interfaces["reth0"]; ifc != nil {
					got = ifc.RedundancyGroup
				}
				t.Fatalf("redundancy-group %q must be REJECTED at commit — it compiles to "+
					"RedundancyGroup=%d, which every downstream consumer reads as "+
					"NOT-a-RETH (isReth/isVRRPReth are `> 0`), so reth0's address is "+
					"configured as an ordinary static address on BOTH nodes (#6782)",
					tc.tok, got)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("the rejection must say WHY this particular token is unusable "+
					"(the classes have different causes and different operator fixes); "+
					"want %q in:\n%s", tc.wantIn, err)
			}
			if !strings.Contains(err.Error(), "reth0") {
				t.Fatalf("the rejection must name the offending interface:\n%s", err)
			}
		})
	}
}

// TestRethRedundancyGroupValidTokensStillCommit6782 is the TIGHTENING control
// in the other direction: a range gate that over-rejects is its own outage.
//
// The boundary is tested from BOTH sides — 1 and 255 must commit, 0 and 256
// must not (the reject side lives in the test above) — and the fixture never
// uses the value the bug FALLS BACK TO, so a gate that silently coerced its
// input to 0 could not pass this.
func TestRethRedundancyGroupValidTokensStillCommit6782(t *testing.T) {
	for _, tc := range []struct {
		name, tok string
		want      int
	}{
		{"lower-boundary-one", "1", 1},
		{"typical", "2", 2},
		{"upper-boundary-octet", "255", 255},
		{"explicit-plus-sign", "+3", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := rethRGTree(t, rethRGSet(tc.tok))
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("redundancy-group %q is a usable data-plane group and must "+
					"COMMIT — over-rejecting here takes a working cluster down: %v",
					tc.tok, err)
			}
			ifc := cfg.Interfaces.Interfaces["reth0"]
			if ifc == nil {
				t.Fatal("reth0 must compile")
			}
			if ifc.RedundancyGroup != tc.want {
				t.Fatalf("the accepted token must compile to the group the operator "+
					"WROTE; got %d want %d", ifc.RedundancyGroup, tc.want)
			}
			// The whole point of a valid group: the address survives to be
			// installed (as a VIP), rather than being suppressed.
			addrs := 0
			for _, u := range ifc.Units {
				addrs += len(u.Addresses)
			}
			if addrs == 0 {
				t.Fatal("a VALID redundancy-group must keep the reth's addresses — " +
					"suppressing them here would break every working cluster")
			}
		})
	}
}

// TestRethMissingRedundancyGroupStanzaStillCommits6782 pins the scope boundary
// explicitly, so a later "tighten it up" change has to argue with a test.
//
// A reth with NO redundant-ether-options is an ABSENT token, not an invalid
// one. Several in-tree configs legitimately touch a reth without redeclaring
// its group as a partial/overlay fragment (test/incus/sqm-cookbook-config.set
// sets an ADDRESS that way), so requiring presence would reject them. It is a
// separate policy question from the one #6782 reports.
func TestRethMissingRedundancyGroupStanzaStillCommits6782(t *testing.T) {
	tree := rethRGTree(t, rethRGSet(""))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a reth with NO redundant-ether-options stanza must still commit — "+
			"#6782 is about tokens that are PRESENT and unusable, and in-tree overlay "+
			"fragments rely on this: %v", err)
	}
}

// TestRethUndeclaredButPositiveGroupStillCommits6782 is the other half of the
// scope boundary. A positive group that names no declared `chassis cluster
// redundancy-group` does NOT trigger this fail-open — it still reads as
// RG-scoped and still takes the link-local substitution — so rejecting it would
// be a new restriction rather than a fix, and would break configs that declare
// interfaces before groups.
func TestRethUndeclaredButPositiveGroupStillCommits6782(t *testing.T) {
	tree := rethRGTree(t, rethRGSet("7"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a positive group that is merely undeclared must still commit: %v", err)
	}
	if got := cfg.Interfaces.Interfaces["reth0"].RedundancyGroup; got != 7 {
		t.Fatalf("the undeclared-but-positive group must compile verbatim; got %d", got)
	}
}

// TestRethInvalidRedundancyGroupSuppressesAddressesOnLenientLoad6782 is the
// #1960 half, and the one that decides whether this fix is real.
//
// The tolerant load / peer-sync path must not brick on a config an older binary
// accepted — so it warns instead of failing. But warning and then doing the
// damage anyway would make the lenient path the bug: the whole defect is that
// the reth's address gets configured on BOTH nodes. So the lenient path must
// additionally SUPPRESS the address.
//
// FAIL-ON-REVERT: delete the suppressInvalidRethAddresses call and the
// addresses survive; drop the warning and the diagnostic leg reds.
func TestRethInvalidRedundancyGroupSuppressesAddressesOnLenientLoad6782(t *testing.T) {
	for _, tok := range []string{"0", "-1", "abc", "256"} {
		t.Run(tok, func(t *testing.T) {
			tree := rethRGTree(t, rethRGSet(tok))
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("the tolerant path must still BOOT an already-persisted config "+
					"an older binary accepted (#1960); got: %v", err)
			}
			ifc := cfg.Interfaces.Interfaces["reth0"]
			if ifc == nil {
				t.Fatal("reth0 must still compile on the tolerant path")
			}
			addrs := []string{}
			for _, u := range ifc.Units {
				addrs = append(addrs, u.Addresses...)
			}
			if len(addrs) != 0 {
				t.Fatalf("the tolerant path must SUPPRESS the address of a reth whose "+
					"group is unusable — leaving %v installs it as an ordinary static "+
					"address on BOTH nodes, which is the entire defect #6782 reports",
					addrs)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "6782") && strings.Contains(w, "reth0") {
					found = true
				}
			}
			if !found {
				t.Fatalf("suppressing the address silently is its own trap — the operator "+
					"must be told which interface and why; warnings were: %v", cfg.Warnings)
			}
		})
	}
}

// TestRethValidGroupKeepsAddressesOnLenientLoad6782 is the tightening control
// for the suppression: it must fire ONLY for the unusable tokens. A suppression
// that ran unconditionally would strip every cluster's addresses on load — a
// far worse outage than the bug.
func TestRethValidGroupKeepsAddressesOnLenientLoad6782(t *testing.T) {
	tree := rethRGTree(t, rethRGSet("1"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	addrs := 0
	for _, u := range cfg.Interfaces.Interfaces["reth0"].Units {
		addrs += len(u.Addresses)
	}
	if addrs == 0 {
		t.Fatal("a VALID group must keep its addresses on the tolerant path — an " +
			"unconditional suppression would blackhole every healthy cluster on load")
	}
}

// TestRethInvalidGroupSuppressesInheritingMemberAddresses6782 covers the second
// consumer of the same data. A physical member carries the reth's addresses
// through RedundantParent, so suppressing only the reth would let the member
// reintroduce exactly what was removed.
//
// This is the smallest shape where dropping the member loop changes an outcome:
// without a member interface in the fixture the loop is dead code and its
// deletion is invisible.
func TestRethInvalidGroupSuppressesInheritingMemberAddresses6782(t *testing.T) {
	lines := rethRGSet("0",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.61.1/24",
	)
	cfg, err := CompileConfigLenient(rethRGTree(t, lines))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	member := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if member == nil {
		// Never t.Skip here. A skip on a fixture WE author is indistinguishable
		// from a pass, so an interface-naming change would silently retire this
		// guard instead of failing loudly.
		t.Fatalf("fixture broken: the member interface must compile, got interfaces %v",
			ifaceNames6782(cfg))
	}
	for _, u := range member.Units {
		if len(u.Addresses) != 0 {
			t.Fatalf("a member inheriting from a reth with an unusable group must not "+
				"keep addresses — it would reinstall on both nodes exactly what "+
				"suppressing the reth removed; got %v", u.Addresses)
		}
	}

	// Positive control: the same fixture with a VALID group must KEEP the
	// member's address. Without this, "zero addresses" above could be true
	// because the fixture never produced a member address in the first place —
	// an absence assertion is only as good as the payload's ability to produce
	// what it asserts absent.
	okLines := rethRGSet("1",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.61.1/24",
	)
	okCfg, err := CompileConfigLenient(rethRGTree(t, okLines))
	if err != nil {
		t.Fatalf("control compile: %v", err)
	}
	okMember := okCfg.Interfaces.Interfaces["ge-0/0/0"]
	if okMember == nil {
		t.Fatalf("control fixture broken: member must compile, got %v", ifaceNames6782(okCfg))
	}
	kept := 0
	for _, u := range okMember.Units {
		kept += len(u.Addresses)
	}
	if kept == 0 {
		t.Fatal("control failed: the member carries no address even with a VALID " +
			"group, so the suppression assertion above proves nothing")
	}
}

// ifaceNames6782 lists compiled interface names for fixture-breakage messages.
func ifaceNames6782(cfg *Config) []string {
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for n := range cfg.Interfaces.Interfaces {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// TestRethRGTokenProblemClassifier6782 pins the classifier directly, including
// the two boundaries, so a range edit that shifts a bound by one is caught even
// if no end-to-end fixture happens to sit on it.
func TestRethRGTokenProblemClassifier6782(t *testing.T) {
	bad := []string{"", "0", "-1", "abc", "1.5", "256", "99999"}
	for _, tok := range bad {
		if _, isBad := rethRGTokenProblem(tok); !isBad {
			t.Fatalf("token %q must be classified unusable", tok)
		}
	}
	good := []string{"1", "2", "155", "255"}
	for _, tok := range good {
		if why, isBad := rethRGTokenProblem(tok); isBad {
			t.Fatalf("token %q must be classified usable, got %q", tok, why)
		}
	}
}

// TestSuppressionIsScopedToTheOffendingReth6782 is the shape the sibling test
// above CANNOT reach, and the matrix proved it: dropping the
// `invalid[ifc.RedundantParent]` term from the member loop survived every other
// cell.
//
// The reason is that a fixture containing ONLY a valid reth never enters the
// member loop at all — suppressInvalidRethAddresses returns early on an empty
// `invalid` set — so the guard is shadowed by the early return and its deletion
// is invisible. The discriminating shape needs BOTH a reth whose group is
// unusable AND a healthy reth, each with its own member: only then does the
// term decide anything.
//
// Over-suppression here is not a cosmetic bug. Clearing a HEALTHY reth's member
// addresses on a tolerant load would black-hole a working cluster on the very
// path whose whole purpose (#1960) is to keep a node serving.
func TestSuppressionIsScopedToTheOffendingReth6782(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		`set chassis cluster authentication-key "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2Rl"`,
		"set chassis cluster node 0",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 2 node 0 priority 200",
		// The offender.
		"set interfaces reth0 redundant-ether-options redundancy-group 0",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.61.1/24",
		// The healthy neighbour, which must be left completely alone.
		"set interfaces reth1 redundant-ether-options redundancy-group 2",
		"set interfaces reth1 unit 0 family inet address 10.0.62.1/24",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.62.1/24",
	}
	cfg, err := CompileConfigLenient(rethRGTree(t, lines))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	countAddrs := func(name string) int {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			t.Fatalf("fixture broken: %s must compile, got %v", name, ifaceNames6782(cfg))
		}
		n := 0
		for _, u := range ifc.Units {
			n += len(u.Addresses)
		}
		return n
	}
	// The offender and its member are stripped.
	if got := countAddrs("reth0"); got != 0 {
		t.Fatalf("reth0 has an unusable group; its addresses must be suppressed, got %d", got)
	}
	if got := countAddrs("ge-0/0/0"); got != 0 {
		t.Fatalf("ge-0/0/0 inherits from the offending reth; its addresses must be "+
			"suppressed, got %d", got)
	}
	// The healthy neighbour keeps everything. This is the assertion the
	// single-reth fixtures could not make.
	if got := countAddrs("reth1"); got == 0 {
		t.Fatal("reth1's group is VALID — suppressing its addresses would black-hole a " +
			"healthy interface on the tolerant load path")
	}
	if got := countAddrs("ge-0/0/1"); got == 0 {
		t.Fatal("ge-0/0/1 inherits from a VALID reth — the member loop must be scoped " +
			"to members of the OFFENDING reth, not every member on the box")
	}
}

// #14441: the brace-elided spelling
// `redundant-ether-options redundancy-group 1;` parses as one node with
// Keys=[redundant-ether-options redundancy-group 1] and no Children, so the
// Children-only FindChild in compileInterfaces (and in the #6782 pre-walk
// gate, which mirrors it) found no rg child and RedundancyGroup stayed 0.
// Downstream isReth/isVRRPReth are `> 0`, so the reth read as an ordinary
// interface on both nodes. The elided spelling must compile identically to
// the braced twin on strict and lenient paths; braced + flat-set unchanged.
func TestElidedRedundantEtherOptionsCompilesGroup14441(t *testing.T) {
	const unit = "unit 0 { family inet { address 10.0.61.1/24; } }"
	elided := "interfaces { reth0 { redundant-ether-options redundancy-group 1; " + unit + " } }"
	braced := "interfaces { reth0 { redundant-ether-options { redundancy-group 1; } " + unit + " } }"
	parse := func(text string) *ConfigTree {
		p := NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %q: %v", text, perrs)
		}
		return tree
	}
	for _, tc := range []struct {
		name string
		tree *ConfigTree
		desc string
	}{
		{"elided-hierarchical", parse(elided), elided},
		{"braced-hierarchical", parse(braced), braced},
		{"flat-set", rethRGTree(t, rethRGSet("1")), "flat-set redundancy-group 1"},
	} {
		t.Run(tc.name+"/strict", func(t *testing.T) {
			cfg, err := CompileConfig(tc.tree)
			if err != nil {
				t.Fatalf("%s must COMMIT (valid group 1): %v", tc.desc, err)
			}
			ifc := cfg.Interfaces.Interfaces["reth0"]
			if ifc == nil {
				t.Fatal("reth0 must compile")
			}
			if ifc.RedundancyGroup != 1 {
				t.Fatalf("%s must compile RedundancyGroup=1 identically to the braced twin, got %d (#14441)", tc.desc, ifc.RedundancyGroup)
			}
			addrs := 0
			for _, u := range ifc.Units {
				addrs += len(u.Addresses)
			}
			if addrs == 0 {
				t.Fatal("valid group 1 must keep the reth address")
			}
		})
		t.Run(tc.name+"/lenient", func(t *testing.T) {
			cfg, err := CompileConfigLenient(tc.tree)
			if err != nil {
				t.Fatalf("lenient %s: %v", tc.desc, err)
			}
			ifc := cfg.Interfaces.Interfaces["reth0"]
			if ifc == nil || ifc.RedundancyGroup != 1 {
				t.Fatalf("lenient %s must compile RedundancyGroup=1, got %+v", tc.desc, ifc)
			}
		})
	}
}

// #14441 gate-mirror: an UNUSABLE elided token must not escape the #6782
// gate just because it is packed. Strict must reject and lenient must warn
// + suppress, exactly as for the braced spelling.
func TestElidedRedundantEtherOptionsBadTokenGated14441(t *testing.T) {
	for _, tok := range []string{"0", "abc", "256"} {
		elided := "interfaces { reth0 { redundant-ether-options redundancy-group " + tok + "; unit 0 { family inet { address 10.0.61.1/24; } } } }"
		p := NewParser(elided)
		tree, perrs := p.Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("elided redundancy-group %q must be REJECTED at commit (#14441/#6782)", tok)
		} else if !strings.Contains(err.Error(), "reth0") {
			t.Fatalf("rejection must name reth0, got: %v", err)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient must boot (#1960): %v", err)
		}
		ifc := cfg.Interfaces.Interfaces["reth0"]
		if ifc == nil {
			t.Fatal("reth0 must compile on lenient path")
		}
		addrs := 0
		for _, u := range ifc.Units {
			addrs += len(u.Addresses)
		}
		if addrs != 0 {
			t.Fatalf("lenient elided bad token %q must suppress addresses (#6782), kept %d", tok, addrs)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "6782") && strings.Contains(w, "reth0") {
				found = true
			}
		}
		if !found {
			t.Fatalf("lenient elided bad token %q must warn (#6782), got %v", tok, cfg.Warnings)
		}
	}
}
