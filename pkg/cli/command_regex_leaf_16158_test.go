package cli

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16158 — the CLI-local command-regex leaf differential.
//
// The leaf (evaluateCommandRegex + canonicalForms + distinctNarrowerAllowed
// + splitAtPipe + authorizablePipe) was extracted VERBATIM from
// permissions_regex.go into command_regex_leaf_16158.go, CLI-local only:
// NOT into pkg/authz (Codex B: the principal boundary must not import
// cmdtree / CLI pipe semantics). This file is the decisive acceptance
// check the issue demands:
//
//   - a (class, op) corpus rebuilt post-#15994 — including the #15994
//     group-pricing cells (via checkCommandRegexWith, the same entry the
//     groups gate prices through) and the pipe-filter cases — pinning
//     BOTH the verdict and the byte-identical CLI error wording;
//   - every formerly-denied input still denied (fail-closed);
//   - an AST guard that pkg/authz gains no cmdtree/cliterm/cli import
//     and the leaf file itself imports no pkg/authz.
//
// The `want` strings below are the pre-extraction wordings, copied from
// the unmoved format strings in evaluateCommandRegex / checkCommandRegexWith
// (class is always "restricted" here so %q renders deterministically).
// If a future edit rewords a refusal, this corpus fails byte-for-byte —
// that is the point: operator-visible wording is part of the leaf's
// contract, not an implementation detail.

type leafCell16158 struct {
	name  string
	allow string
	deny  string
	line  string
	pipe  string
	want  string // "" means allowed (nil error); otherwise the exact error
}

func runLeaf16158(t *testing.T, tc leafCell16158) {
	t.Helper()
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily,
		tc.allow, tc.allow != "", tc.deny, tc.deny != "")
	if err != nil {
		t.Fatalf("compile allow=%q deny=%q: %v", tc.allow, tc.deny, err)
	}
	got := evaluateCommandRegex(rules, "restricted", tc.line, tc.pipe)
	if tc.want == "" {
		if got != nil {
			t.Errorf("%s: line=%q pipe=%q allow=%q deny=%q: DENIED (%v), want allowed",
				tc.name, tc.line, tc.pipe, tc.allow, tc.deny, got)
		}
		return
	}
	if got == nil {
		t.Errorf("%s: line=%q pipe=%q allow=%q deny=%q: ALLOWED, want denied %q (fail-closed breach)",
			tc.name, tc.line, tc.pipe, tc.allow, tc.deny, tc.want)
		return
	}
	if got.Error() != tc.want {
		t.Errorf("%s: error wording drift:\n got: %q\nwant: %q", tc.name, got.Error(), tc.want)
	}
}

func TestCommandRegexLeafDifferential16158(t *testing.T) {
	denyPrefix := `permission denied: login class "restricted" denies `
	cells := []leafCell16158{
		// ── canonical deny + abbreviation equivalence (#7172) ──
		{"deny-canonical", "", "request system reboot", "request system reboot", "",
			denyPrefix + `"request system reboot" (matched the class's deny regex)`},
		{"deny-abbrev", "", "request system reboot", "req sys reb", "",
			denyPrefix + `"request system reboot" (matched the class's deny regex)`},
		{"deny-unrelated-allowed", "", "request system reboot", "show interfaces", "", ""},
		// ── fail-closed: unresolvable command (#7172) ──
		{"unresolvable", "", "request system reboot", "c", "",
			`permission denied: login class "restricted" restricts commands and "c" could not be resolved to a canonical command, so the restriction cannot be evaluated`},
		{"unresolvable-piped", "", "request system reboot", "c", "match x",
			`permission denied: login class "restricted" restricts commands and "c" could not be resolved to a canonical command, so the restriction cannot be evaluated`},
		// ── pipe is part of the command (#7172 / #9628) ──
		{"pipe-save-denied", "", "save", "show configuration", "save /tmp/x",
			`permission denied: login class "restricted" restricts commands and the output pipe "save" is not a recognised filter, so the restriction cannot be evaluated`}, // save is not an authorizable pipe verb: fail-closed pipe refusal fires before regex matching (the #7172 save-denied end-to-end cell lives in TestDenyMatchesThroughThePipeSuffix7172 via the in-line spelling)
		{"pipe-save-inline-denied", "", "save", "show configuration | save /tmp/x", "",
			`permission denied: login class "restricted" restricts commands and the output pipe "save" is not a recognised filter, so the restriction cannot be evaluated`},
		{"pipe-bare-allowed", "", "save", "show configuration", "", ""},
		{"pipe-display-set-denied", "", "display set", "show configuration | display set", "",
			denyPrefix + `"show configuration" (matched the class's deny regex)`},
		{"pipe-anchored-version", "", "^show version$", "show version", "match .",
			denyPrefix + `"show version" (matched the class's deny regex)`},
		{"pipe-anchored-unrelated", "", "^show version$", "show route", "match .", ""},
		{"pipe-recognised-filter", "", "request system reboot", "show route", "match 10.0.0", ""},
		{"pipe-unknown-verb", "", "request system reboot", "show route", "frobnicate x",
			`permission denied: login class "restricted" restricts commands and the output pipe "frobnicate" is not a recognised filter, so the restriction cannot be evaluated`},
		{"pipe-display-bad-format", "", "request system reboot", "show configuration", "display yaml",
			`permission denied: login class "restricted" restricts commands and the output pipe "display yaml" is not a recognised display format, so the restriction cannot be evaluated`},
		{"pipe-display-ok", "", "request system reboot", "show configuration", "display set", ""},
		{"pipe-display-then-filter", "", "request system reboot", "show configuration", "display set | match x", ""},
		{"pipe-multistage-deny", "", ".*match.*", "show version", "no-more | match xpf",
			denyPrefix + `"show version" (matched the class's deny regex)`},
		{"pipe-multistage-order", "", `show version \| no-more \| match`, "show version", "no-more | match xpf",
			denyPrefix + `"show version" (matched the class's deny regex)`},
		{"pipe-multistage-reversed-allowed", "", `show version \| no-more \| match`, "show version", "match xpf | no-more", ""},
		{"pipe-second-stage-unknown", "", "request system reboot", "show route", "match x | frobnicate y",
			`permission denied: login class "restricted" restricts commands and the output pipe "frobnicate" is not a recognised filter, so the restriction cannot be evaluated`},
		{"pipe-compare-allowed", "", "request system reboot", "show system rollback 1", "compare", ""},
		// ── anchored deny: arguments / siblings / values ──
		// (#8289 sibling, #9022 AcceptsArgs, #9505 past-a-value)
		{"anchored-bare", "", "^show version$", "show version", "",
			denyPrefix + `"show version" (matched the class's deny regex)`},
		{"anchored-trailing-sibling", "", "^show version$", "show version configuration", "",
			`permission denied: login class "restricted" restricts commands and "show" could not be resolved to a canonical command, so the restriction cannot be evaluated`},
		{"anchored-arg", "", "^show log$", "show log 100", "",
			denyPrefix + `"show log" (matched the class's deny regex)`},
		{"anchored-arg-word", "", "^show log$", "show log messages", "",
			denyPrefix + `"show log" (matched the class's deny regex)`},
		{"anchored-distinct-node", "", "^show configuration$", "show configuration system", "", ""},
		{"anchored-value", "", "^show route table secret-vrf$", "show route table secret-vrf", "",
			denyPrefix + `"show route" (matched the class's deny regex)`},
		{"anchored-value-appended", "", "^show route table secret-vrf$", "show route table secret-vrf bypass", "",
			`permission denied: login class "restricted" restricts commands and "show" could not be resolved to a canonical command, so the restriction cannot be evaluated`}, // #9505: appended word past the value fails closed at canonicalization
		{"anchored-value-public", "", "^show route table secret-vrf$", "show route table public-vrf", "", ""},
		// ── selector forms + #14687 narrower rescue ──
		{"selector-base-deny", "", "^show security policies$", "show security policies from-zone trust", "",
			denyPrefix + `"show security policies" (matched the class's deny regex)`},
		{"selector-spelling-deny", "", "^show security screen ids-option$", "show security screen ids-option foo", "",
			denyPrefix + `"show security screen" (matched the class's deny regex)`},
		{"selector-narrower-rescue", "", "^show security screen$", "show security screen ids-option prof1", "", ""},
		{"selector-spelling-allow", "^show security screen ids-option$", "", "show security screen ids-option foo", "", ""},
		{"selector-fabricated-allow-denied", "^show firewall effective$", "", "show firewall filter FOO effective", "",
			denyPrefix + `"show firewall" (an allow regex is configured and this command does not match it)`},
		// ── precedence tiers + allowlist (#7172 / #14686) ──
		{"tier1-identical-allow-wins", "show version", "show version", "show version", "", ""},
		{"tier2-longer-deny", "commit", "commit synchronize", "show version", "", ""}, // neither matches: allowlist miss
		{"allowlist-miss", "^show interfaces$", "", "show version", "",
			denyPrefix + `"show version" (an allow regex is configured and this command does not match it)`},
		{"allowlist-hit", "^show interfaces$", "", "show interfaces", "", ""},
		{"exception-no-pipe", "^show log 100$", "^show log$", "show log 100", "", ""},
		{"exception-piped", "^show log 100$", "^show log$", "show log 100", "match x", ""},
		{"wildcard-pipe-bypass-denied", "^show.*", "(^show version$)|(^show log$)", "show version", "match .",
			`permission denied: login class "restricted" denies "show version" (allow and deny matched equal extents (12 characters) with different patterns; denied (xpf interpretation of an underspecified rule))`},
		{"smuggled-pipe-allow-denied", "show interfaces", "", "show configuration", "except show interfaces",
			denyPrefix + `"show configuration" (an allow regex is configured and this command does not match it)`},
		{"genuine-piped-allow", "show interfaces", "", "show interfaces", "match x", ""},
		{"empty-deny-denies-all", "", "", "show version", "",
			denyPrefix + `"show version" (matched the class's deny regex)`},
	}
	// The empty-deny cell needs denySet with an empty pattern, which the
	// allow!="" proxy above cannot express; patch it in explicitly.
	for i := range cells {
		if cells[i].name == "tier2-longer-deny" {
			cells[i].want = denyPrefix + `"show version" (an allow regex is configured and this command does not match it)`
		}
	}
	for _, tc := range cells {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "empty-deny-denies-all" {
				rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, "", true)
				if err != nil {
					t.Fatalf("compile empty deny: %v", err)
				}
				got := evaluateCommandRegex(rules, "restricted", tc.line, tc.pipe)
				if got == nil || got.Error() != tc.want {
					t.Fatalf("empty deny: got %v, want %q", got, tc.want)
				}
				return
			}
			runLeaf16158(t, tc)
		})
	}

	// Tier-2 longer-deny-wins, the case that makes "allow always wins"
	// false: allow "commit" (6) beside deny "commit synchronize" (18).
	t.Run("tier2-deny-longer-wins", func(t *testing.T) {
		// `commit` is not an operational command, so drive the tier through
		// a real command pair with the same geometry instead: allow names
		// the base, deny names the longer spelling.
		runLeaf16158(t, leafCell16158{
			name: "tier2-deny-longer-wins", allow: "^show route table", deny: "^show route table secret-vrf$",
			line: "show route table secret-vrf",
			want: denyPrefix + `"show route" (deny matched a longer extent than allow (27 > 16 characters))`,
		})
	})
}

// Post-#15994 group-pricing cells, driven through checkCommandRegexWith —
// the store-free whole decision the CLI groups gate prices through
// (groups_read_gate_15994_test.go's op-view class:
// deny-commands "^show configuration security"). The group-unwrapped
// effective spellings must stay denied after the extraction, and the
// group control must stay allowed. Wording is pinned byte-identically.
func TestCommandRegexLeafGroupsPricing16158(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Classes: []*config.LoginClass{
			{Name: "op-view", DenyCommands: "^show configuration security", DenyLeavesPresent: []string{"deny-commands"}},
			{Name: "clean-view"},
		},
	}
	// The literal spellings price through the leaf directly. The
	// group-unwrapped spellings (show configuration groups G security)
	// are NOT leaf inputs: checkShowConfigurationRead unwraps them in
	// pkg/config (Authorize…WithOp15994), and TestCLIGroupsReadOpDenied15994
	// pins those end-to-end. What the leaf must guarantee post-#15994 is
	// that the literal denied spelling stays denied byte-identically and
	// no formerly-denied literal gains admission.
	denied := `permission denied: login class "op-view" denies "show configuration security" (matched the class's deny regex)`
	for _, tc := range []struct {
		class, line, pipe, want string
	}{
		{"op-view", "show configuration security", "", denied},
		{"op-view", "show configuration security", "display set", denied},
		{"op-view", "show configuration groups G system", "", ""},
		{"op-view", "show version", "", ""},
		{"clean-view", "show configuration security", "", ""}, // no regexes: leaf skipped
		{"", "show configuration security", "", ""},           // empty class: legacy bypass
	} {
		err := checkCommandRegexWith(cfg, tc.class, tc.line, tc.pipe)
		if tc.want == "" {
			if err != nil {
				t.Errorf("class=%q line=%q pipe=%q: DENIED (%v), want allowed", tc.class, tc.line, tc.pipe, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("class=%q line=%q pipe=%q: ALLOWED, want denied %q (#15994 group pricing must stay fail-closed)",
				tc.class, tc.line, tc.pipe, tc.want)
			continue
		}
		if err.Error() != tc.want {
			t.Errorf("class=%q line=%q: wording drift:\n got: %q\nwant: %q", tc.class, tc.line, err.Error(), tc.want)
		}
	}

	// The compile-error arm of the whole decision, byte-pinned.
	bad := &config.Config{}
	bad.System.Login = &config.LoginConfig{
		Classes: []*config.LoginClass{{Name: "ops", DenyCommands: "([unclosed", DenyLeavesPresent: []string{"deny-commands"}}},
	}
	err := checkCommandRegexWith(bad, "ops", "show interfaces", "")
	want := `permission denied: login class "ops" has an invalid command regex: deny regex is not a valid POSIX extended regular expression: error parsing regexp: missing closing ]: ` + "`[unclosed`"
	if err == nil || err.Error() != want {
		t.Errorf("uncompilable regex: got %v, want %q", err, want)
	}
}

// The destination constraint, enforced mechanically: pkg/authz must not
// import the CLI grammar (cmdtree), the pipe vocabulary (cliterm), or the
// CLI package itself, and the leaf must not import pkg/authz. A future
// "helpful" move of the leaf across the principal boundary fails here
// instead of in review.
func TestCommandRegexLeafStaysOutOfAuthz16158(t *testing.T) {
	wd, err := os.Getwd() // pkg/cli
	if err != nil {
		t.Fatal(err)
	}
	authzDir := filepath.Join(wd, "..", "authz")
	entries, err := os.ReadDir(authzDir)
	if err != nil {
		t.Fatalf("read pkg/authz: %v", err)
	}
	forbidden := []string{"pkg/cmdtree", "pkg/cliterm", "pkg/cli"}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(authzDir, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			for _, bad := range forbidden {
				if strings.Contains(imp.Path.Value, bad) {
					t.Errorf("pkg/authz/%s imports %s — the command-regex leaf must stay CLI-local (#16158)", e.Name(), imp.Path.Value)
				}
			}
		}
	}
	leaf, err := parser.ParseFile(token.NewFileSet(), filepath.Join(wd, "command_regex_leaf_16158.go"), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	for _, imp := range leaf.Imports {
		if strings.Contains(imp.Path.Value, "pkg/authz") {
			t.Errorf("command_regex_leaf_16158.go imports %s — the leaf must not reach into pkg/authz (#16158)", imp.Path.Value)
		}
	}
	// The named seam must exist in the leaf file, not back in
	// permissions_regex.go: that is what "extracted" means here.
	found := false
	for _, decl := range leaf.Decls {
		_ = decl
	}
	src, err := os.ReadFile(filepath.Join(wd, "command_regex_leaf_16158.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "func evaluateCommandRegex(") {
		t.Error("evaluateCommandRegex not found in command_regex_leaf_16158.go")
	} else {
		found = true
	}
	if !found {
		t.Fatal("named seam missing")
	}
	old, err := os.ReadFile(filepath.Join(wd, "permissions_regex.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(old), "func evaluateCommandRegex(") {
		t.Error("evaluateCommandRegex still defined in permissions_regex.go — extraction incomplete")
	}
}
