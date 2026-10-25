package config

import (
	"strings"
	"testing"
)

// #16530: ASPathDef.RegexUnquotedBracket is derived only from the bracket
// provenance persisted in the JSON DB. ConfigTree.Format(), which produces
// the HA config-sync payload (ShowActive -> SyncApply re-parses it) and the
// rollback slots, rendered leaf keys without `[ ]`, so after Format->Parse
// the flag was false. The peer, or a `rollback N`, then strict-accepted and
// rendered the mangled regex that the primary's lenient compile omits.
//
// FormatSetForLoadMerge already carries leaf brackets for flat replay
// (#10084); the hierarchical renderer now does the same for leaves.
// FormatSet keeps the #6668 zero-churn rule and is deliberately unchanged.

// boolMask16530 renders a provenance mask for failure messages.
func boolMask16530(m []bool) string {
	parts := make([]string, len(m))
	for i, b := range m {
		if b {
			parts[i] = "1"
		} else {
			parts[i] = "0"
		}
	}
	return strings.Join(parts, "")
}

// reparseFormat16530 round-trips tree through Format and returns the reparsed
// tree together with its as-path leaf.
func asPathLeaf16530(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	po := tree.FindChild("policy-options")
	if po == nil {
		t.Fatalf("no policy-options in tree:\n%s", tree.Format())
	}
	nodes := po.FindChildren("as-path")
	if len(nodes) == 0 {
		t.Fatalf("no as-path in tree:\n%s", tree.Format())
	}
	return nodes[0]
}

// TestFormatReparsePreservesUnquotedBracketFlag16530 is the acceptance
// probe from the issue: the flag must survive Format->Parse, so the
// reparsed tree receives the identical strict verdict (reject with the
// #9881 quote diagnostic) and the identical lenient warning/omission.
//
// FAIL-ON-REVERT: rendering leaf keys without brackets again makes every
// unquoted row reparse with KeysBracketed empty, CompileConfig stops
// returning the quote diagnostic, and this test reds.
func TestFormatReparsePreservesUnquotedBracketFlag16530(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"instance tail", `policy-options { as-path AP1 [0-9]+; }`},
		{"single-token brackets", `policy-options { as-path AP1 [0-9]; }`},
		{"full-tail brackets", `policy-options { as-path AP1 [ .* 65000 .* ]; }`},
		{"brace-body entry", `policy-options { as-path AP1 { [0-9]+; } }`},
		{"tokenless leading pair", `policy-options { as-path AP1 []0-9]+; }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, tc.src)

			origCfgErr := func() error {
				_, err := CompileConfig(tree)
				return err
			}()
			if origCfgErr == nil || !strings.Contains(origCfgErr.Error(), "UNQUOTED") {
				t.Fatalf("premise: original tree must strict-reject with the quote diagnostic, got %v\n%s", origCfgErr, tree.Format())
			}
			reparsed := parseHierText(t, tree.Format())
			origLeaf := asPathLeaf16530(t, tree)
			gotLeaf := asPathLeaf16530(t, reparsed)
			// For the brace-body form the regex lives on a child entry.
			origSpan, gotSpan := origLeaf, gotLeaf
			if len(origLeaf.Children) > 0 {
				origSpan = origLeaf.Children[len(origLeaf.Children)-1]
				gotSpan = gotLeaf.Children[len(gotLeaf.Children)-1]
			}
			if len(origSpan.KeysBracketed) == 0 {
				t.Fatalf("premise: authored leaf carries no bracket provenance: %q", origSpan.Keys)
			}
			// The invariant is the compiled flag, not the exact mask: a
			// gap-loss token (`[]0-9]+` lexes as one token `0-9]+`)
			// re-lexes as two tokens (`0-9`, `+`) once bracketed, so its
			// mask widens while the Regex and the flag stay identical.
			if !asPathKeysHaveUnquotedBracket(gotSpan, len(gotSpan.Keys)-(len(origSpan.Keys)-2)) && len(origLeaf.Children) == 0 {
				// instance-tail form: regex starts at key 2
				if !asPathKeysHaveUnquotedBracket(gotSpan, 2) {
					t.Fatalf("Format->Parse dropped the unquoted-bracket flag:\norig mask %s keys %q\ngot  mask %s keys %q\nFormat:\n%s",
						boolMask16530(origSpan.KeysBracketed), origSpan.Keys,
						boolMask16530(gotSpan.KeysBracketed), gotSpan.Keys, tree.Format())
				}
			}
			if len(origLeaf.Children) > 0 && !asPathKeysHaveUnquotedBracket(gotSpan, 0) {
				t.Fatalf("Format->Parse dropped the unquoted-bracket flag (brace body):\norig mask %s keys %q\ngot  mask %s keys %q\nFormat:\n%s",
					boolMask16530(origSpan.KeysBracketed), origSpan.Keys,
					boolMask16530(gotSpan.KeysBracketed), gotSpan.Keys, tree.Format())
			}
			_, err := CompileConfig(reparsed)
			if err == nil {
				t.Fatalf("reparsed tree strict-ACCEPTED the unquoted-bracket regex (#16530)\nFormat:\n%s", tree.Format())
			}
			if !strings.Contains(err.Error(), "UNQUOTED") || !strings.Contains(err.Error(), "as-path AP1") {
				t.Fatalf("strict diagnostic changed across Format->Parse:\nwant quote diagnostic, got %v", err)
			}
			// Except for the gap-loss row the diagnostic is byte-identical;
			// there the joined Regex legitimately differs (`0-9]+` vs
			// `0-9 +` — both joins of the same stripped text).
			if tc.name != "tokenless leading pair" && err.Error() != origCfgErr.Error() {
				t.Fatalf("strict diagnostic changed across Format->Parse:\nwant %v\ngot  %v", origCfgErr, err)
			}

			// Lenient parity: the tolerant path warns naming the as-path and
			// still compiles, on both sides of the round trip.
			for label, tr := range map[string]*ConfigTree{"orig": tree, "reparsed": reparsed} {
				cfg, lerr := CompileConfigLenient(tr)
				if lerr != nil {
					t.Fatalf("%s: lenient compile failed: %v", label, lerr)
				}
				ap := cfg.PolicyOptions.ASPaths["AP1"]
				if ap == nil {
					t.Fatalf("%s: lenient compile lost AP1", label)
				}
				if !ap.RegexUnquotedBracket {
					t.Fatalf("%s: RegexUnquotedBracket=false after round trip (Regex=%q)", label, ap.Regex)
				}
				if !warnMentions(cfg.Warnings, "as-path AP1") {
					t.Fatalf("%s: lenient compile produced no as-path warning; warnings=%v", label, cfg.Warnings)
				}
			}

			// Fixed point: a second Format changes nothing. The gap-loss
			// row is exempt from byte equality (its single token `0-9]+`
			// re-lexes as two), but its second render must be stable.
			if tc.name == "tokenless leading pair" {
				if got, want := parseHierText(t, reparsed.Format()).Format(), reparsed.Format(); got != want {
					t.Fatalf("gap-loss Format is not stable at the second render:\nwant:\n%s\ngot:\n%s", want, got)
				}
			} else if got, want := reparsed.Format(), tree.Format(); got != want {
				t.Fatalf("Format is not a fixed point:\nwant:\n%s\ngot:\n%s", want, got)
			}
		})
	}
}

// TestFormatControlsUnchanged16530 pins the controls: a quoted regex stays
// quoted and accepted with the pattern intact, a quoted token inside
// brackets stays faithful (accepted), a bare regex stays bare (accepted),
// and FormatSet keeps rendering leaves without brackets (#6668).
func TestFormatControlsUnchanged16530(t *testing.T) {
	for _, tc := range []struct {
		name       string
		src        string
		wantRegex  string
		wantFormat string // substring the hierarchical render must contain
	}{
		{"quoted regex", `policy-options { as-path AP1 "[123-125]"; }`, `[123-125]`, `as-path AP1 "[123-125]";`},
		{"quoted inside brackets", `policy-options { as-path AP1 [ "65000" ]; }`, `65000`, `as-path AP1 [ "65000" ];`},
		{"bare multitoken", `policy-options { as-path AP1 .* 65000 .*; }`, `.* 65000 .*`, `as-path AP1 .* 65000 .*;`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierText(t, tc.src)
			if got := tree.Format(); !strings.Contains(got, tc.wantFormat) {
				t.Fatalf("Format changed the control spelling:\nwant substring %q\ngot:\n%s", tc.wantFormat, got)
			}
			reparsed := parseHierText(t, tree.Format())
			cfg, err := CompileConfig(reparsed)
			if err != nil {
				t.Fatalf("control rejected after Format->Parse: %v\n%s", err, tree.Format())
			}
			ap := cfg.PolicyOptions.ASPaths["AP1"]
			if ap == nil || ap.Regex != tc.wantRegex {
				t.Fatalf("control compiled as %+v, want Regex=%q", ap, tc.wantRegex)
			}
			if ap.RegexUnquotedBracket {
				t.Fatalf("control acquired RegexUnquotedBracket (Regex=%q)", ap.Regex)
			}
			if got, want := reparsed.Format(), tree.Format(); got != want {
				t.Fatalf("control Format is not a fixed point:\nwant:\n%s\ngot:\n%s", want, got)
			}
		})
	}

	// #6668 zero-churn half: the flat display-set renderer still emits no
	// bracket delimiters for leaves, bracketed or not.
	tree := parseHierText(t, `policy-options { as-path AP1 [0-9]+; }`)
	if got := tree.FormatSet(); got != "set policy-options as-path AP1 0-9 +\n" {
		t.Fatalf("FormatSet changed the #6668 no-churn contract: %q", got)
	}
	// Containers keep their hierarchical spelling too: only leaves gained
	// brackets.
	wide := parseHierText(t, `security { zones { security-zone trust { interfaces { [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic { system-services ssh; } } } } } }`)
	if strings.Contains(wide.Format(), "[") {
		t.Fatalf("container acquired brackets in Format (only leaves may):\n%s", wide.Format())
	}
}
