package config

import (
	"strings"
	"testing"
)

// #12528: `is-fragment` and `flexible-match-range` swallow a fused `then`
// tail. The terminal action never reaches the compiled term, leaving
// Action="" — which the userspace dataplane reads as fall-through/Accept,
// so an intended discard/reject becomes fail-open. Every row must be
// REJECTED by BOTH strict gates (SchemaValidate and CompileConfig), naming
// the fused `then`. Positive controls prove bare leaves still commit.

func hier12528(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func flat12528(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	return replaySetLines(t, lines)
}

func assertRejected12528(t *testing.T, name string, tree *ConfigTree, want string) {
	t.Helper()
	if err := SchemaValidate(tree, nil); err == nil {
		t.Errorf("%s: SchemaValidate accepted fused tail (want rejection naming %q)", name, want)
	} else if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: SchemaValidate error %q does not name %q", name, err, want)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Errorf("%s: CompileConfig accepted fused tail", name)
	}
}

func TestIsFragmentFusedThenRejected12528(t *testing.T) {
	rows := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{"F13 flat LoadSet discard", func(t *testing.T) *ConfigTree {
			return flat12528(t,
				"set firewall family inet filter F term T from is-fragment then discard",
				"set firewall family inet filter F term allow then accept")
		}},
		{"F13 flat LoadSet reject", func(t *testing.T) *ConfigTree {
			return flat12528(t,
				"set firewall family inet filter F term T from is-fragment then reject",
				"set firewall family inet filter F term allow then accept")
		}},
		{"N6 extra token", func(t *testing.T) *ConfigTree {
			return flat12528(t,
				"set firewall family inet filter F term T from is-fragment foo",
				"set firewall family inet filter F term T then discard")
		}},
		{"N3 named LoadOverride braced", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term T { from { is-fragment then discard; } } } } }`)
		}},
		{"N4 named LoadOverride nested then", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term T { from { is-fragment { then { discard; } } } } } } }`)
		}},
		{"N1 named packed", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term T from is-fragment then discard; } } }`)
		}},
		{"N2 named compact hierarchical", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term T { from is-fragment then discard; } } } }`)
		}},
		{"H1 nameless nested", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term { T from is-fragment { then { discard; } } } } } }`)
		}},
		{"H reject nameless", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term { T from is-fragment { then { reject; } } } } } }`)
		}},
		{"H leaf spelling nameless", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term { T from is-fragment then discard; } } } }`)
		}},
		{"H inet6", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet6 { filter F { term { T from is-fragment { then { discard; } } } } } }`)
		}},
		{"H any family", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family any { filter F { term { T from is-fragment { then { discard; } } } } } }`)
		}},
		{"hier Children shape", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term T { from { is-fragment { then { discard; } } } then { accept; } } } } }`)
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			want := "then"
			if r.name == "N6 extra token" {
				want = "foo"
			}
			assertRejected12528(t, r.name, r.tree(t), want)
		})
	}
	// N6 names the stray token instead.
	t.Run("N6 names foo", func(t *testing.T) {
		tree := flat12528(t,
			"set firewall family inet filter F term T from is-fragment foo",
			"set firewall family inet filter F term T then discard")
		if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "foo") {
			t.Fatalf("CompileConfig error = %v, want naming foo", err)
		}
	})
	// N1 round-trip: display set -> load set replay must also reject.
	t.Run("N1 display-set round-trip", func(t *testing.T) {
		fused := flat12528(t,
			"set firewall family inet filter F term T from is-fragment then discard")
		lines := strings.Split(strings.TrimSpace(fused.FormatSetForLoadMerge()), "\n")
		replayed := replaySetLines(t, lines)
		assertRejected12528(t, "round-trip fused", replayed, "then")
	})
}

func TestFlexMatchRangeFusedThenRejected12528(t *testing.T) {
	t.Run("flat LoadSet", func(t *testing.T) {
		tree := flat12528(t,
			"set firewall family inet filter F term T from flexible-match-range range R match-start layer-3",
			"set firewall family inet filter F term T from flexible-match-range range R byte-offset 9",
			"set firewall family inet filter F term T from flexible-match-range range R bit-length 8",
			"set firewall family inet filter F term T from flexible-match-range range R match-value 0x11",
			"set firewall family inet filter F term T from flexible-match-range range R then discard",
			"set firewall family inet filter F term allow then accept")
		assertRejected12528(t, "flat flex", tree, "then")
	})
	t.Run("named LoadOverride nested", func(t *testing.T) {
		tree := hier12528(t, `firewall { family inet { filter F { term T { from { flexible-match-range { range R { match-start layer-3; byte-offset 9; bit-length 8; match-value 0x11; then discard; } } } } } } }`)
		assertRejected12528(t, "override flex", tree, "then")
	})
	t.Run("nameless LoadMerge shape", func(t *testing.T) {
		tree := hier12528(t, `firewall { family inet { filter F { term { T from flexible-match-range range R { match-start layer-3; byte-offset 9; bit-length 8; match-value 0x11; then { discard; } } } } } }`)
		assertRejected12528(t, "nameless flex", tree, "then")
	})
	t.Run("flex node extra child", func(t *testing.T) {
		tree := hier12528(t, `firewall { family inet { filter F { term T { from { flexible-match-range { then { discard; } } } } } } }`)
		assertRejected12528(t, "flex then child", tree, "then")
	})
	t.Run("range extra keys", func(t *testing.T) {
		tree := flat12528(t,
			"set firewall family inet filter F term T from flexible-match-range range R then discard")
		assertRejected12528(t, "range then keys", tree, "then")
	})
}

func TestFusedThenPositiveControls12528(t *testing.T) {
	controls := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{"ordinary protocol value is unchanged", func(t *testing.T) *ConfigTree {
			return flat12528(t,
				"set firewall family inet filter F term T from protocol tcp",
				"set firewall family inet filter F term T then discard")
		}},
		{"bare is-fragment hier", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term T { from { is-fragment; } then { discard; } } } } }`)
		}},
		{"bare is-fragment flat", func(t *testing.T) *ConfigTree {
			return flat12528(t,
				"set firewall family inet filter F term T from is-fragment",
				"set firewall family inet filter F term T then discard")
		}},
		{"flex without fused then", func(t *testing.T) *ConfigTree {
			return hier12528(t, `firewall { family inet { filter F { term T { from { flexible-match-range { range R { match-start layer-3; byte-offset 9; bit-length 8; match-value 0x11; } } } then { discard; } } } } }`)
		}},
		{"flex flat no fused", func(t *testing.T) *ConfigTree {
			return flat12528(t,
				"set firewall family inet filter F term T from flexible-match-range range R byte-offset 9",
				"set firewall family inet filter F term T then discard")
		}},
	}
	for _, c := range controls {
		t.Run(c.name, func(t *testing.T) {
			tree := c.tree(t)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected control: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected control: %v", err)
			}
			term := firstInetTerm(t, cfg, "F")
			if term.Action != "discard" {
				t.Fatalf("control term action = %q, want discard", term.Action)
			}
		})
	}
	// Lenient path must warn, not silently accept.
	t.Run("lenient warns", func(t *testing.T) {
		tree := flat12528(t,
			"set firewall family inet filter F term T from is-fragment then discard")
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient must not hard-fail: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "then") && strings.Contains(w, "12528") {
				found = true
			}
		}
		if !found {
			t.Fatalf("lenient warnings %q do not name fused then (#12528)", cfg.Warnings)
		}
	})
}
