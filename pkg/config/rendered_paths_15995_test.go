package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// renderedPathSet derives the complete paths a scoped render of path
// can print, from the RENDERER's own output — FormatPathSetRedacted
// lines (fold 5: NOT from the matcher under test, which would make
// the property a self-oracle). Each `set …` line's token sequence is
// a rendered statement path; all of its prefixes are included (the
// renderer prints those ancestor spellings as it descends), and a
// bracketed `[ m1 m2 ]` group expands to the combined spelling plus
// one rendered path per member.
func renderedPathSet(t *ConfigTree, path []string) map[string]bool {
	out := map[string]bool{}
	if t == nil {
		return out
	}
	// Rendered paths from renderer output only: complete set lines
	// (leaf statements) plus block-opener containers (below).
	setLines := []string{}
	set := t.FormatPathSetRedacted(path)
	for _, line := range strings.Split(set, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "set ") {
			continue
		}
		setLines = append(setLines, line)
		for _, seq := range expandBracketSpellings(strings.Fields(strings.TrimPrefix(line, "set "))) {
			out[strings.Join(seq, " ")] = true
		}
	}
	// Containers: a proper token prefix of a set line is a rendered
	// container iff the hierarchical output opens a block whose keys
	// equal that prefix's trailing keys — EXCEPT a prefix that is an
	// exact token-wise prefix of the REQUEST: the set renderer
	// re-prefixes scoped lines with the REQUESTED (truncated)
	// spelling, so truncated-spelling prefixes are request text, not
	// rendered node paths (their rendered forms carry the omitted
	// keys and appear as other prefixes/lines). Both oracle inputs
	// are renderer output (set + hierarchical), never the matcher.
	hier := t.FormatPathRedacted(path)
	var openers []struct{ keys []string }
	for _, line := range strings.Split(hier, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, "{") {
			openers = append(openers, struct{ keys []string }{hierLineKeys(line)})
		}
	}
	for _, line := range setLines {
		for _, seq := range expandBracketSpellings(strings.Fields(strings.TrimPrefix(line, "set "))) {
			for i := 1; i < len(seq); i++ {
				prefix := seq[:i]
				// Skip exact request prefixes (truncated spelling).
				isReqPrefix := len(prefix) <= len(path)
				if isReqPrefix {
					for j := range prefix {
						if prefix[j] != path[j] {
							isReqPrefix = false
							break
						}
					}
				}
				if isReqPrefix {
					continue
				}
				for _, op := range openers {
					if len(op.keys) <= len(prefix) && strings.Join(prefix[len(prefix)-len(op.keys):], " ") == strings.Join(op.keys, " ") {
						out[strings.Join(prefix, " ")] = true
					}
				}
			}
		}
	}
	return out
}

// hierLineKeys extracts a hierarchical render line's key tokens.
func hierLineKeys(line string) []string {
	trimmed := strings.TrimSpace(line)
	stmt := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(trimmed, "{"), ";"))
	stmt = strings.TrimSpace(strings.TrimPrefix(stmt, "inactive:"))
	return strings.Fields(stmt)
}

// expandBracketSpellings expands `[ a b ]` groups in a set-line token
// sequence into the combined sequence plus one sequence per member.
func expandBracketSpellings(toks []string) [][]string {
	open, closeIdx := -1, -1
	for i, tk := range toks {
		if tk == "[" {
			open = i
		}
		if tk == "]" && open >= 0 {
			closeIdx = i
			break
		}
	}
	if open < 1 || closeIdx < 0 {
		return [][]string{toks}
	}
	members := toks[open+1 : closeIdx]
	combined := append(append([]string(nil), toks[:open]...), members...)
	combined = append(combined, toks[closeIdx+1:]...)
	out := [][]string{combined}
	for _, m := range members {
		seq := append(append([]string(nil), toks[:open]...), m)
		seq = append(seq, toks[closeIdx+1:]...)
		out = append(out, seq)
	}
	return out
}

// pricedPathSet15995 probes the gate with one anchored deny per
// candidate path: a path is "priced" iff denying exactly it (anchored)
// refuses the read. The gate must refuse precisely the rendered set.
func pricedPathSet15995(t *testing.T, tree *ConfigTree, path []string, candidates map[string]bool) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for cand := range candidates {
		cfg := cfg15995(t, "", "^"+cand+"$")
		if err := AuthorizeConfigShowPathRendered(cfg, "limited", path, "", []*ConfigTree{tree}); err != nil {
			out[cand] = true
		}
	}
	// Note: candidates embedding the request's truncated spelling
	// (e.g. `... from-zone trust policy p1 then` for a truncated
	// intermediate) are not complete rendered paths; the expected-set
	// filter in the test excludes them via the completion rule.
	return out
}

func TestPricedEqualsRenderedPathSet15995(t *testing.T) {
	shapes := []struct {
		name string
		text string
		path []string
	}{
		{"intermediate-context", `security { policies {
			from-zone trust to-zone untrust { policy p1 { then { permit; } } }
			from-zone trust to-zone trust { policy p2 { then { permit; } } }
		} }`, []string{"security", "policies", "from-zone", "trust", "policy", "p1"}},
		{"terminal-multikey", `security { policies {
			from-zone trust to-zone untrust { policy p1 { then { permit; } } }
		} }`, []string{"security", "policies", "from-zone", "trust"}},
		{"keyword-only", `firewall {
			filter f1 { term t1 { then accept; } }
			filter f2 { term t1 { then accept; } }
		}`, []string{"firewall", "filter"}},
		{"named-user", `system { login { user admin { class limited; } user bob { class limited; } } }`,
			[]string{"system", "login", "user"}},
		{"plain-subtree", `security {
			zones { security-zone trust { description x; } }
			ipsec { vpn vpn1 { bind-interface st0.0; } }
		}`, []string{"security"}},
		{"deep-leaf", `system { host-name h15995; services { ssh; } }`, []string{"system"}},
		{"bracketed-group", `security { zones {
			security-zone [ zga zgb ] { tcp-rst; }
			security-zone trust { description x; }
		} }`, []string{"security", "zones", "security-zone", "zgb"}},
	}
	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.text).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			rendered := renderedPathSet(tree, tc.path)
			// Completions for truncated intermediates live in the
			// UNSCOPED set render (complete statement paths).
			fullRendered := renderedPathSet(tree, nil)
			if len(rendered) == 0 {
				t.Fatalf("rendered set empty for %v (premise)", tc.path)
			}
			// Expected refused set: every TRUE rendered strict
			// descendant of the request, plus beyond-request trail
			// ancestors carrying omitted keys. A candidate p from
			// the renderer output is a true descendant iff its
			// tokens, after NORMALIZING any truncated intermediate
			// segment, strictly extend the request. Normalization:
			// p embeds the truncated spelling iff p has the request
			// as a proper token prefix AND the renderer ALSO emits
			// (in `rendered`) a completion q that shares p's
			// post-request tail (tokens after the request) as its
			// own tail after strictly more leading tokens — the
			// omitted keys inserted. Such p are re-prefix artifacts:
			// drop ONLY p (its normalized completion q is kept and
			// asserted). True descendants — p extending the request
			// with NO longer completion in rendered (e.g. plain
			// [security] → security zones …, [firewall filter] →
			// firewall filter f1 …) — are KEPT and must be priced.
			reqStr := strings.Join(tc.path, " ")
			expected := map[string]bool{}
			for p := range rendered {
				if p == reqStr {
					continue
				}
				toks := strings.Fields(p)
				// Exact request prefix: caller's domain.
				if len(toks) <= len(tc.path) {
					isPrefix := true
					for i := range toks {
						if toks[i] != tc.path[i] {
							isPrefix = false
							break
						}
					}
					if isPrefix {
						continue
					}
					expected[p] = true
					continue
				}
				// Proper extension: artifact iff a longer completion
				// with the same post-request tail exists in rendered.
				extends := true
				for i := range tc.path {
					if toks[i] != tc.path[i] {
						extends = false
						break
					}
				}
				if !extends {
					expected[p] = true
					continue
				}
				// Completion = the COMPLETE set line for the
				// same leaf: it contains p's tokens as a subsequence
				// with the omitted keys inserted (not necessarily
				// a suffix — `then permit` gains a trailing token).
				// Detect: some rendered q whose tokens, with the
				// request's spelled intermediate segment expanded,
				// end with p's post-request tokens AND whose hier
				// trail proves descent. Practical exact test for
				// these shapes: q's LAST token equals p's last
				// token and q is longer, and q was rendered by the
				// same scope (all q in rendered are).
				artifact := false
				for q := range fullRendered {
					qt := strings.Fields(q)
					if q != p && len(qt) > len(toks) && qt[len(qt)-1] == toks[len(toks)-1] {
						// Require q to contain p's post-request
						// tokens in order as a subsequence.
						rest := toks[len(tc.path):]
						// subsequence check over q's tokens after
						// the shared request-length position is
						// meaningless (positions shift); instead
						// check the final len(rest) tokens of q
						// equal rest OR rest is a subsequence.
						if isSubseq15995(rest, qt) {
							artifact = true
							break
						}
					}
				}
				if artifact {
					continue // normalized completion asserted via q
				}
				expected[p] = true
			}
			// Assert normalized completions too: every complete
			// (unscoped-render) path that contains all request
			// tokens as a subsequence and strictly extends the
			// matched scope is a rendered path of this read.
			for q := range fullRendered {
				if q == reqStr {
					continue
				}
				if isSubseq15995(tc.path, strings.Fields(q)) && len(strings.Fields(q)) > len(tc.path) {
					expected[q] = true
				}
				// Trail ancestors of the completion (e.g. the
				// complete intermediate context itself) are
				// proper prefixes of such q that appear in
				// fullRendered.
				qt := strings.Fields(q)
				for i := len(tc.path) + 1; i < len(qt); i++ {
					pre := strings.Join(qt[:i], " ")
					if fullRendered[pre] && isSubseq15995(tc.path, qt[:i]) {
						expected[pre] = true
					}
				}
			}
			if len(expected) == 0 {
				t.Fatalf("expected set empty for %v — oracle asserts nothing (premise)", tc.path)
			}
			allCands := map[string]bool{}
			for p := range rendered {
				allCands[p] = true
			}
			for q := range fullRendered {
				allCands[q] = true
			}
			priced := pricedPathSet15995(t, tree, tc.path, allCands)
			var missing []string
			for p := range expected {
				if !priced[p] {
					missing = append(missing, p)
				}
			}
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Errorf("rendered paths left unpriced for %v: %v", tc.path, missing)
			}
		})
	}
}

// TestNavigateWalkerParity17267 makes the display-width and authorization
// rendered-path wrappers share a branch-complete contract. The expected
// rendered paths are independent fixture truths; node-pointer comparison then
// proves both wrappers selected exactly the same terminal nodes.
func TestNavigateWalkerParity17267(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		path       []string
		wantWidth  int
		wantPaths  [][]string
	}{
		{
			name:      "empty-path",
			text:      `system { host-name fw; }`,
			path:      nil,
			wantWidth: 0,
		},
		{
			name:      "multi-key-leaf",
			text:      `system { host-name fw; }`,
			path:      []string{"system", "host-name", "fw"},
			wantWidth: 2,
			wantPaths: [][]string{{"system", "host-name", "fw"}},
		},
		{
			name: "multi-key-prefix-terminal",
			text: `security { policies { from-zone trust to-zone untrust {
				policy p1 { then { permit; } }
			} } }`,
			path:      []string{"security", "policies", "from-zone", "trust"},
			wantWidth: 2,
			wantPaths: [][]string{{"security", "policies", "from-zone", "trust", "to-zone", "untrust"}},
		},
		{
			name: "multi-key-pair-continuation",
			text: `security { policies { from-zone trust to-zone untrust {
				policy p1 { then { permit; } }
			} } }`,
			path:      []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust"},
			wantWidth: 4,
			wantPaths: [][]string{{"security", "policies", "from-zone", "trust", "to-zone", "untrust"}},
		},
		{
			name: "union-descent-multikey-4562",
			text: `security { policies {
				from-zone trust to-zone untrust { policy p1 { then { permit; } } }
				from-zone trust to-zone untrust { policy p2 { then { deny; } } }
			} }`,
			path: []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"},
			wantPaths: [][]string{
				{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p1"},
				{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p2"},
			},
			wantWidth: 1,
		},
		{
			name: "union-descent-single-key-4562",
			text: `interfaces { ge-0-0-0 { mtu 1500; } }
				interfaces { ge-0-0-0 { mtu 9000; } }`,
			path: []string{"interfaces", "ge-0-0-0", "mtu"},
			wantPaths: [][]string{
				{"interfaces", "ge-0-0-0", "mtu", "1500"},
				{"interfaces", "ge-0-0-0", "mtu", "9000"},
			},
			wantWidth: 1,
		},
		{
			name: "terminal-bare-keyword-fanout",
			text: `firewall {
				filter f1 { term t1 { then accept; } }
				filter f2 { term t1 { then accept; } }
			}`,
			path: []string{"firewall", "filter"},
			wantPaths: [][]string{
				{"firewall", "filter", "f1"},
				{"firewall", "filter", "f2"},
			},
			wantWidth: 1,
		},
		{
			name: "bracketed-later-member-terminal",
			text: `security { zones { security-zone [ zga zgb ] { tcp-rst; } } }`,
			path: []string{"security", "zones", "security-zone", "zgb"},
			wantPaths: [][]string{
				{"security", "zones", "security-zone", "zga", "zgb"},
			},
			wantWidth: 2,
		},
		{
			name: "bracketed-later-member-descent",
			text: `security { zones { security-zone [ zga zgb ] { tcp-rst; } } }`,
			path: []string{"security", "zones", "security-zone", "zgb", "tcp-rst"},
			wantPaths: [][]string{
				{"security", "zones", "security-zone", "zga", "zgb", "tcp-rst"},
			},
			wantWidth: 1,
		},
		{
			name: "failed-multi-key-continuation",
			text: `root { pair v extra x; pair v other y; }`,
			path: []string{"root", "pair", "v", "extra", "y"},
			wantWidth: 0,
			wantPaths: nil,
		},
		{
			name: "duplicate-bracket-groups-descent",
			text: `security { zones { security-zone [ zga zgb ] { tcp-rst; } security-zone [ zgb zgc ] { admin; } } }`,
			path: []string{"security", "zones", "security-zone", "zgb", "admin"},
			wantPaths: [][]string{
				{"security", "zones", "security-zone", "zgb", "zgc", "admin"},
			},
			wantWidth: 1,
		},
		{
			name: "wildcard-instance-descent",
			text: `interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } }`,
			path: []string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "address", "192.0.2.1/24"},
			wantPaths: [][]string{
				{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "address", "192.0.2.1/24"},
			},
			wantWidth: 2,
		},
		{
			name:      "missing-first-path",
			text:      `system { host-name fw; }`,
			path:      []string{"missing"},
			wantWidth: 0,
		},
		{
			name:      "missing-descendant",
			text:      `system { host-name fw; }`,
			path:      []string{"system", "missing", "leaf"},
			wantWidth: 0,
		},
		{
			name: "deep-path-no-walker-depth-cap",
			text: `a b { c d { e f { g h { i j { k l { m n; } } } } } }`,
			path: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"},
			wantPaths: [][]string{
				{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"},
			},
			wantWidth: 2,
		},
		{
			name:      "deep-path-past-tree",
			text:      `a b { c d { e f; } }`,
			path:      []string{"a", "b", "c", "d", "e", "f", "g", "h"},
			wantWidth: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.text).Parse()
			if len(errs) != 0 {
				t.Fatalf("fixture parse: %v", errs)
			}
			display, width := navigatePathWidth(tree.Children, tc.path)
			priced := navigateRenderedMatches(tree.Children, tc.path)
			if width != tc.wantWidth {
				t.Errorf("navigatePathWidth consumed %d tokens, want %d", width, tc.wantWidth)
			}
			if len(display) != len(priced) {
				t.Fatalf("display matched %d nodes, pricing matched %d", len(display), len(priced))
			}
			var paths [][]string
			for i, n := range display {
				if n != priced[i].node {
					t.Errorf("terminal match %d differs: display=%p pricing=%p", i, n, priced[i].node)
				}
			}
			for _, match := range priced {
				paths = append(paths, match.path)
			}
			if !reflect.DeepEqual(paths, tc.wantPaths) {
				t.Errorf("pricing paths = %q, want %q", paths, tc.wantPaths)
			}
		})
	}
}

// TestConfigShowAuthzUnionDescent17267 is the authz-side #4562 witness. A
// selector omits the final pair of two duplicate context keys and names a
// child held only by the second block. Pricing must traverse the union and
// charge the full context path that the renderer actually reaches.
func TestConfigShowAuthzUnionDescent17267(t *testing.T) {
	cfg := cfg15995(t, "", `^security policies from-zone untrust to-zone trust$`)
	tree := buildDupPolicyContext(t)
	path := []string{"security", "policies", "from-zone", "untrust", "policy", "B"}
	if out := tree.FormatPathRedacted(path); !strings.Contains(out, "policy B") {
		t.Fatalf("premise failed: path selector did not render second duplicate's policy B:\n%s", out)
	}
	if err := AuthorizeConfigShowPathRendered(cfg, "limited", path, "", []*ConfigTree{tree}); err == nil {
		t.Fatal("selector for policy B was ALLOWED though it renders denied duplicate context (#17267)")
	}
}

// isSubseq15995 reports whether sub appears in seq in order.
func isSubseq15995(sub, seq []string) bool {
	i := 0
	for _, x := range seq {
		if i < len(sub) && x == sub[i] {
			i++
		}
	}
	return i == len(sub)
}
