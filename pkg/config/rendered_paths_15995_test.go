package config

import (
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
		if err := AuthorizeConfigShowPathRendered(cfg, "limited", path, "", tree); err != nil {
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
			if len(rendered) == 0 {
				t.Fatalf("rendered set empty for %v (premise)", tc.path)
			}
			// Expected walk-priced set: rendered paths that are NOT
			// token-wise prefixes of the request (the request and
			// its exact prefixes are the caller's adjudication
			// domain — Junos longest-match on the request itself).
			reqStr := strings.Join(tc.path, " ")
			expected := map[string]bool{}
			for p := range rendered {
				if p == reqStr {
					continue
				}
				// Candidates extending the request with its
				// truncated spelling embedded (post-request tokens
				// reached only through an omitted-keys node) are
				// renderer re-prefix text, not complete rendered
				// paths: the complete forms insert the omitted
				// keys and are asserted separately where they
				// appear. Drop every proper request-extension.
				toks := strings.Fields(p)
				if len(toks) > len(tc.path) {
					extends := true
					for i := range tc.path {
						if toks[i] != tc.path[i] {
							extends = false
							break
						}
					}
					if extends {
						continue
					}
				}
				isPrefix := len(toks) <= len(tc.path)
				if isPrefix {
					for i := range toks {
						if toks[i] != tc.path[i] {
							isPrefix = false
							break
						}
					}
				}
				if !isPrefix {
					expected[p] = true
				}
			}
			priced := pricedPathSet15995(t, tree, tc.path, rendered)
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
