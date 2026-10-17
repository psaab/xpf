package config

import (
	"reflect"
	"testing"
)

// compileNTPText compiles one config text and returns the NTP server list and
// per-server modifier options.
func compileNTPText(t *testing.T, text string) ([]string, map[string]NTPServerOption) {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("compile %q: err=%v cfg=%v", text, err, cfg)
	}
	return cfg.System.NTPServers, cfg.System.NTPServerOptions
}

// compileNTPKeyIDs14596 returns the stripped per-server key ids (#14596).
func compileNTPKeyIDs14596(t *testing.T, text string) []int {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("compile %q: err=%v cfg=%v", text, err, cfg)
	}
	return cfg.System.NTPServerKeyIDs
}

// TestNTPServerModifierSpellingsAgree_7132 is the fail-on-revert for the
// compact-spelling capture.
//
// #2419's contract: the compact spelling (`server A key 5;` — modifier and its
// argument on the stanza's own Keys) and the block spelling
// (`server A { key 5; }` — modifier as a child) must compile identically.
//
// The bug this pins is one line, and it sat directly beneath the fix for the
// same class. `ntpServerValues` DOES capture compact modifiers off the parent's
// Keys — and then discarded them:
//
//	if !touched { return servers, nil }
//
// `touched` is set only by the CHILD-modifier loop, so on a compact spelling it
// is always false and every captured option was thrown away on return.
//
// FAIL-ON-REVERT: restore that early return and every COMPACT subtest below
// goes RED with `map[]` against the block spelling's populated map.
func TestNTPServerModifierSpellingsAgree_7132(t *testing.T) {
	cases := []struct{ name, mod, val string }{
		{"key", "key", "5"},
		{"version", "version", "4"},
		{"routing-instance", "routing-instance", "xpfaaa"},
		// `prefer` is here deliberately and is the reason this test exists
		// separately from TestCompactBlockEquivalenceInventory2419.
		//
		// That gate detects "the compact spelling drops the VALUE". `prefer` is
		// value-less, so it has nothing to drop and the gate is structurally
		// blind to it — it reported three divergent sites while FOUR modifiers
		// were broken. A fix validated only against that gate would have left
		// `prefer` silently compact-blind.
		{"prefer", "prefer", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sep := " "
			if c.val == "" {
				sep = ""
			}
			blockSrv, blockOpts := compileNTPText(t,
				"system { ntp { server xpfarg { "+c.mod+sep+c.val+"; } } }")
			compactSrv, compactOpts := compileNTPText(t,
				"system { ntp { server xpfarg "+c.mod+sep+c.val+"; } }")

			// Non-vacuity: if the BLOCK spelling records nothing either, the
			// comparison below is `nil == nil` and proves nothing about the
			// compact path. #14596: `key` is stripped into NTPServerKeyIDs,
			// so its non-vacuity lives there, not in the options map.
			if c.mod == "key" {
				if got := compileNTPKeyIDs14596(t, "system { ntp { server xpfarg { key 5; } } }"); len(got) != 1 || got[0] != 5 {
					t.Fatalf("block spelling recorded no stripped key id; this cell cannot prove anything about the compact spelling")
				}
			} else if len(blockOpts) == 0 {
				t.Fatalf("block spelling recorded no options for %q; this cell "+
					"cannot prove anything about the compact spelling", c.mod)
			}
			if !reflect.DeepEqual(blockSrv, compactSrv) {
				t.Errorf("server list differs: block=%v compact=%v", blockSrv, compactSrv)
			}
			if !reflect.DeepEqual(blockOpts, compactOpts) {
				t.Errorf("#7132/#2419: the compact spelling must compile to the "+
					"same typed config as the block spelling.\n  block   = %+v\n  compact = %+v\n"+
					"An empty compact map means the modifiers were captured off the "+
					"parent's Keys and then discarded on return.", blockOpts, compactOpts)
			}
		})
	}
}

// TestNTPServerNoModifiersYieldsNoOptions_7132 is the over-reach guard.
//
// Without it, the test above is satisfied by always returning a populated map —
// including for a plain `server A` with no modifiers at all, which would put an
// all-zero option in the typed config (and in the #4406 golden) for every NTP
// server anyone has ever configured.
func TestNTPServerNoModifiersYieldsNoOptions_7132(t *testing.T) {
	srv, opts := compileNTPText(t, "system { ntp { server xpfarg; } }")
	if len(srv) != 1 || srv[0] != "xpfarg" {
		t.Fatalf("precondition: expected one server, got %v", srv)
	}
	if len(opts) != 0 {
		t.Errorf("a server with no modifiers must carry NO options entry, got %+v", opts)
	}
}

// TestNTPServerModifierRegressionShapes_7132 pins the two shapes the previous
// lane broke and fixed while building this, recorded as fixtures because they
// are the same class the issue is about.
func TestNTPServerModifierRegressionShapes_7132(t *testing.T) {
	// 1. Skipping only the modifier NAME left its argument to be read as a
	//    second server: `server a key 5` -> servers [a, 5].
	srv, opts := compileNTPText(t, "system { ntp { server xpfarg key 5; } }")
	if !reflect.DeepEqual(srv, []string{"xpfarg"}) {
		t.Errorf("a modifier's ARGUMENT must not be read as a server: got %v", srv)
	}
	// #14596: the key id lands in NTPServerKeyIDs, stripped off the option.
	if got := compileNTPKeyIDs14596(t, "system { ntp { server xpfarg key 5; } }"); len(got) != 1 || got[0] != 5 {
		t.Errorf("the modifier argument must land as a stripped key id: got %v (opts %+v)", got, opts)
	}
	if opts["xpfarg"].Key != 0 {
		t.Errorf("Key must be stripped off the option by #14596: got %+v", opts)
	}

	// 2. An early return on empty Keys dropped the #6689 nested-BLOCK shape,
	//    whose servers live in Children rather than on Keys.
	nested, _ := compileNTPText(t, "system { ntp { server { xpfaaa; xpfbbb; } } }")
	if !reflect.DeepEqual(nested, []string{"xpfaaa", "xpfbbb"}) {
		t.Errorf("the nested-block spelling must yield both servers, got %v", nested)
	}
}
