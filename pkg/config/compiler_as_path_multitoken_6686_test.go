package config

import (
	"strings"
	"testing"
)

// #6686: a `policy-options as-path <name> <regex>` written in its
// MULTI-TOKEN (unquoted) spelling compiled to the FIRST token only, so
// `.* 65000 .*` became `.*` — the whole-path wildcard. A
// `from as-path AP1; then accept` term built on that definition accepts
// EVERY BGP path instead of only those transiting AS 65000: a route-leak /
// hijack-acceptance exposure that committed clean with zero warnings while
// `show configuration` displayed the authored regex back verbatim.

// aspathCompile builds a tree from flat `set` lines and returns the
// compiled as-path regex for name, plus the compile error.
func aspathCompileSet(t *testing.T, lines ...string) (string, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, cerr := CompileConfig(tree)
	if cfg == nil {
		return "", cerr
	}
	ap := cfg.PolicyOptions.ASPaths["AP1"]
	if ap == nil {
		return "", cerr
	}
	return ap.Regex, cerr
}

// aspathCompileSrc is aspathCompileSet for the hierarchical brace spelling.
func aspathCompileSrc(t *testing.T, src string) (string, error) {
	t.Helper()
	tree, perr := NewParser(src).Parse()
	if perr != nil {
		t.Fatalf("parse %q: %v", src, perr)
	}
	cfg, cerr := CompileConfig(tree)
	if cfg == nil {
		return "", cerr
	}
	ap := cfg.PolicyOptions.ASPaths["AP1"]
	if ap == nil {
		return "", cerr
	}
	return ap.Regex, cerr
}

// TestASPath6686SpellingsAgreeOnTheAuthoredRegex is the core guard. Five
// spellings of ONE as-path definition must compile to ONE regex.
//
// The assertion is written as an AGREEMENT between the spellings first and
// a literal second, deliberately: pinning only the packed spelling to a
// hand-written expectation encodes which side is trusted, and in the
// sibling packed-body work (#7457) the defect turned out to be on the side
// every issue had assumed was correct. Agreement fails whichever side
// breaks.
//
// FAIL-ON-REVERT: restoring `Regex: child.Keys[2]` (and the child loop's
// `ap.Regex = entry.Keys[0]`) in compilePolicyOptions makes the three
// unquoted spellings compile to `.*` while the quoted ones keep the full
// pattern, so both the agreement check and the wildcard check red.
func TestASPath6686SpellingsAgreeOnTheAuthoredRegex(t *testing.T) {
	const authored = `.* 65000 .*`

	type spelling struct {
		name  string
		regex string
	}
	var got []spelling

	// 1. flat set, QUOTED — the spelling that always worked.
	r, err := aspathCompileSet(t, `set policy-options as-path AP1 ".* 65000 .*"`)
	if err != nil {
		t.Fatalf("quoted flat set: compile: %v", err)
	}
	got = append(got, spelling{"flat-set quoted", r})

	// 2. flat set, UNQUOTED — the #6686 defect. `multi: true` packs the
	//    tail onto the node's own Keys: [".*" "65000" ".*"].
	r, err = aspathCompileSet(t, `set policy-options as-path AP1 .* 65000 .*`)
	if err != nil {
		t.Fatalf("unquoted flat set: compile: %v", err)
	}
	got = append(got, spelling{"flat-set unquoted", r})

	// 3. hierarchical leaf, QUOTED.
	r, err = aspathCompileSrc(t, "policy-options {\n    as-path AP1 \".* 65000 .*\";\n}\n")
	if err != nil {
		t.Fatalf("quoted hierarchical: compile: %v", err)
	}
	got = append(got, spelling{"hierarchical quoted", r})

	// 4. hierarchical leaf, UNQUOTED — the issue reports the defect in
	//    BOTH spellings, so both are covered.
	r, err = aspathCompileSrc(t, "policy-options {\n    as-path AP1 .* 65000 .*;\n}\n")
	if err != nil {
		t.Fatalf("unquoted hierarchical: compile: %v", err)
	}
	got = append(got, spelling{"hierarchical unquoted", r})

	// 5. hierarchical BRACE BODY, unquoted — the same widening one level
	//    down, where the regex tokens land on a CHILD leaf's Keys.
	r, err = aspathCompileSrc(t, "policy-options {\n    as-path AP1 {\n        .* 65000 .*;\n    }\n}\n")
	if err != nil {
		t.Fatalf("unquoted hierarchical body: compile: %v", err)
	}
	got = append(got, spelling{"hierarchical body unquoted", r})

	for _, s := range got {
		if s.regex != got[0].regex {
			t.Errorf("spelling %q compiled Regex=%q, but %q compiled Regex=%q — "+
				"the two spellings of one as-path definition disagree",
				s.name, s.regex, got[0].name, got[0].regex)
		}
		// The security property, stated directly: the authored pattern is
		// a TRANSIT match; `.*` matches every AS path there is.
		if s.regex == ".*" {
			t.Errorf("spelling %q compiled Regex=%q — the whole-path wildcard. "+
				"A `from as-path AP1; then accept` term now accepts EVERY BGP "+
				"path instead of only those transiting AS 65000 (#6686)", s.name, s.regex)
		}
		if s.regex != authored {
			t.Errorf("spelling %q compiled Regex=%q, want the authored %q",
				s.name, s.regex, authored)
		}
	}
}

// TestASPath6686EmptyRegexRejectedStrictWarnedLenient covers the value that
// reached the FRR render with no diagnostic at all: `set policy-options
// as-path AP1` with no regex compiled to Regex "" and committed clean. xpf
// then renders `bgp as-path access-list AP1 permit` with no argument — an
// incomplete FRR command, and a single CMD_WARNING_CONFIG_FAILED exits the
// whole vtysh add-batch non-zero, failing the ENTIRE frr-reload.
//
// Strict (commit / commit-check) must REJECT; the tolerant load / peer-sync
// path must WARN and still boot (#1960 no-brick).
//
// FAIL-ON-REVERT: deleting the validatePolicyASPathRegexStrict call from
// the gate chain makes the strict leg return nil and reds.
func TestASPath6686EmptyRegexRejectedStrictWarnedLenient(t *testing.T) {
	build := func() *ConfigTree {
		tree := &ConfigTree{}
		path, err := ParseSetCommand(`set policy-options as-path AP1`)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("setpath: %v", err)
		}
		return tree
	}

	if _, err := CompileConfig(build()); err == nil {
		t.Fatal("strict commit ACCEPTED `as-path AP1` with no regex — xpf would " +
			"render `bgp as-path access-list AP1 permit` with no argument and " +
			"fail the entire frr-reload (#6686)")
	} else if !strings.Contains(err.Error(), "as-path AP1") {
		t.Errorf("strict rejection does not name the as-path: %v", err)
	}

	cfg, err := CompileConfigLenient(build())
	if err != nil {
		t.Fatalf("tolerant load REJECTED an already-persisted config (#1960 brick): %v", err)
	}
	if !warnMentions(cfg.Warnings, "as-path AP1") {
		t.Errorf("tolerant load produced no as-path warning; warnings=%v", cfg.Warnings)
	}
}

// TestASPath6686MalformedRegexRejectedStrictWarnedLenient is the same gate
// for a regex FRR's regcomp cannot compile.
func TestASPath6686MalformedRegexRejectedStrictWarnedLenient(t *testing.T) {
	build := func() *ConfigTree {
		tree := &ConfigTree{}
		path, err := ParseSetCommand(`set policy-options as-path AP1 "((("`)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("setpath: %v", err)
		}
		return tree
	}

	if _, err := CompileConfig(build()); err == nil {
		t.Fatal("strict commit ACCEPTED an as-path regex `(((` — frr-reload " +
			"rejects the rendered line and fails the entire FRR config load (#6686)")
	}
	cfg, err := CompileConfigLenient(build())
	if err != nil {
		t.Fatalf("tolerant load REJECTED an already-persisted config (#1960 brick): %v", err)
	}
	if !warnMentions(cfg.Warnings, "as-path AP1") {
		t.Errorf("tolerant load produced no as-path warning; warnings=%v", cfg.Warnings)
	}
}

// TestASPath6686RealRegexesStillCommitClean is the TIGHTENING control. The
// gate above is a new commit-path rejection, so it owes a proof that it
// does not over-reject the AS-path regular expressions operators actually
// write — including the multi-token pattern the fix now reconstructs
// (which a whitespace-hostile validator would reject) and `^$`, the
// locally-originated match, which an "empty means absent" validator that
// stripped metacharacters would reject.
//
// A validator tightened to reject spaces, or to reject any pattern that is
// not a bare ASN, reds here while every delete-the-guard cell stays green.
func TestASPath6686RealRegexesStillCommitClean(t *testing.T) {
	for _, re := range []string{
		`.* 65000 .*`,      // transit through AS 65000 — the #6686 pattern
		`^65000$`,          // exactly one AS
		`^65000 65001$`,    // an exact two-AS path (multi-token by nature)
		`(65000|65001)`,    // alternation
		`65000{1,3}`,       // POSIX ERE bound
		`[65000-65999]`,    // AS set with a range — one AS in 65000..65999
		`.*`,               // an INTENTIONAL match-everything
		`^$`,               // locally originated (empty AS path)
		`^65000 .* 65010$`, // origin + transit
	} {
		tree := &ConfigTree{}
		line := `set policy-options as-path AP1 "` + re + `"`
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
		cfg, cerr := CompileConfig(tree)
		if cerr != nil {
			t.Errorf("strict commit REJECTED a legitimate as-path regex %q: %v", re, cerr)
			continue
		}
		if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != re {
			t.Errorf("as-path regex %q compiled to %#v, want it preserved verbatim", re, ap)
		}
	}
}

func warnMentions(warnings []string, want string) bool {
	for _, w := range warnings {
		if strings.Contains(w, want) {
			return true
		}
	}
	return false
}
