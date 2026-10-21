package config

import (
	"sort"
	"strings"
	"testing"
)

// renderedPathSet derives the complete paths a scoped render of path
// can print, FROM the render walk itself: navigate the same trail the
// renderer navigates (navigateRenderedMatches — the matcher's trail is
// the renderer's navigation), then walk every descendant. This is the
// reference set for the priced==rendered property cell.
func renderedPathSet(t *ConfigTree, path []string) map[string]bool {
	out := map[string]bool{}
	if t == nil {
		return out
	}
	if len(path) == 0 {
		var walk func(ns []*Node, prefix []string)
		walk = func(ns []*Node, prefix []string) {
			for _, n := range ns {
				p := append(append([]string(nil), prefix...), n.Keys...)
				out[strings.Join(p, " ")] = true
				walk(n.Children, p)
			}
		}
		walk(t.Children, nil)
		return out
	}
	for _, m := range navigateRenderedMatches(t.Children, path) {
		for _, anc := range m.ancestors {
			out[strings.Join(anc, " ")] = true
		}
		var walk func(n *Node, prefix []string)
		walk = func(n *Node, prefix []string) {
			for _, ch := range n.Children {
				p := append(append([]string(nil), prefix...), ch.Keys...)
				out[strings.Join(p, " ")] = true
				walk(ch, p)
			}
		}
		walk(m.node, m.path)
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
				toks := strings.Fields(p)
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
