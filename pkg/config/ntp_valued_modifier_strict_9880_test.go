package config_test

import (
	"strings"
	"testing"
)

// #9880: the strict schema gate refused EVERY valued modifier on a generic
// typed leaf, so valid Junos NTP authentication (`server <addr> key <n>` /
// `version <n>` / `routing-instance <ri>`) and `threshold <n> action <a>`
// could not be committed — while the lenient path compiled the same tree.
//
// Every cell here drives SchemaValidate (the strict commit gate), never
// lenient compile: the pre-fix suite stayed green precisely because the
// #7132 modifier cells compile leniently.

// Test9880_ValuedModifiersCommitBothSpellings is the fail-on-revert: each
// valued modifier must strict-commit in the packed spelling (modifier and
// value on the leaf's Keys), the block spelling (modifier as an AST
// child), and the flat-set spelling (which SetPath files as a child).
// Pre-fix every row failed with `unknown modifier "<value>"`.
func Test9880_ValuedModifiersCommitBothSpellings(t *testing.T) {
	hier := []struct{ name, body string }{
		{"key/packed", `server 1.1.1.1 key 5;`},
		{"key/block", "server 1.1.1.1 {\n key 5;\n}"},
		{"version/packed", `server 1.1.1.1 version 4;`},
		{"version/block", "server 1.1.1.1 {\n version 4;\n}"},
		{"routing-instance/packed", `server 1.1.1.1 routing-instance foo;`},
		{"routing-instance/block", "server 1.1.1.1 {\n routing-instance foo;\n}"},
		{"action/packed", `threshold 400 action accept;`},
		{"action/block", "threshold 400 {\n action accept;\n}"},
		{"action/reject", `threshold 400 action reject;`},
		{"hostname-server/key", `server pool.ntp.org key 7;`},
	}
	for _, tc := range hier {
		if err := schemaCheck(t, "system {\n ntp {\n"+tc.body+"\n}\n}"); err != nil {
			t.Errorf("%s: SchemaValidate rejected valid Junos: %v", tc.name, err)
		}
	}
	flat := []string{
		"set system ntp server 1.1.1.1 key 5",
		"set system ntp server 1.1.1.1 version 4",
		"set system ntp server 1.1.1.1 routing-instance foo",
		"set system ntp threshold 400 action accept",
		"set system ntp threshold 400 action reject",
	}
	for _, cmd := range flat {
		if err := flatSchemaCheck(t, cmd); err != nil {
			t.Errorf("%s: SchemaValidate rejected valid Junos: %v", cmd, err)
		}
	}
	// Split flat-set lines (one statement per line, as an operator staging
	// a commit writes them) must agree with the single-line form.
	if err := flatSchemaCheck(t,
		"set system ntp server 1.1.1.1",
		"set system ntp server 1.1.1.1 key 5",
	); err != nil {
		t.Errorf("split set lines: SchemaValidate rejected valid Junos: %v", err)
	}
}

// Test9880_PreferPresenceOnlyControl is the control: `prefer` takes no
// value and passed strict even pre-fix. It must keep passing — the fix
// widens valued modifiers without disturbing presence-only ones.
func Test9880_PreferPresenceOnlyControl(t *testing.T) {
	if err := schemaCheck(t, "system {\n ntp {\n server 1.1.1.1 prefer;\n}\n}"); err != nil {
		t.Errorf("prefer/packed: %v", err)
	}
	if err := schemaCheck(t, "system {\n ntp {\n server 1.1.1.1 {\n prefer;\n}\n}\n}"); err != nil {
		t.Errorf("prefer/block: %v", err)
	}
	if err := flatSchemaCheck(t, "set system ntp server 1.1.1.1 prefer"); err != nil {
		t.Errorf("prefer/flat-set: %v", err)
	}
}

// Test9880_ModifierValueGarbageRejectedNamingLeaf pins value validation:
// a value the compiler cannot honor (non-integer key/version, which
// Atoi-drop to the unset sentinel; a non-enum action, which the chrony
// renderer ignores) must fail loud at commit, with the error naming the
// leaf path and the modifier.
func Test9880_ModifierValueGarbageRejectedNamingLeaf(t *testing.T) {
	cases := []struct {
		name, text, leaf, mod string
	}{
		{"key/non-integer/packed", `server 1.1.1.1 key notanint;`, "system ntp server", "key"},
		{"key/non-integer/block", "server 1.1.1.1 {\n key notanint;\n}", "system ntp server", "key"},
		{"key/zero", `server 1.1.1.1 key 0;`, "system ntp server", "key"},
		{"key/negative", "server 1.1.1.1 {\n key -3;\n}", "system ntp server", "key"},
		{"version/non-integer", `server 1.1.1.1 version banana;`, "system ntp server", "version"},
		{"action/non-enum/packed", `threshold 400 action frobnicate;`, "system ntp threshold", "action"},
		{"action/non-enum/block", "threshold 400 {\n action frobnicate;\n}", "system ntp threshold", "action"},
	}
	for _, tc := range cases {
		err := schemaCheck(t, "system {\n ntp {\n"+tc.text+"\n}\n}")
		if err == nil {
			t.Errorf("%s: SchemaValidate accepted garbage, want reject", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.leaf) || !strings.Contains(err.Error(), tc.mod) {
			t.Errorf("%s: rejection must name the leaf and modifier, got: %v", tc.name, err)
		}
	}
	flat := []struct{ cmd, leaf, mod string }{
		{"set system ntp server 1.1.1.1 key notanint", "system ntp server", "key"},
		{"set system ntp server 1.1.1.1 key 0", "system ntp server", "key"},
		{"set system ntp threshold 400 action frobnicate", "system ntp threshold", "action"},
	}
	for _, tc := range flat {
		err := flatSchemaCheck(t, tc.cmd)
		if err == nil {
			t.Errorf("%s: SchemaValidate accepted garbage, want reject", tc.cmd)
			continue
		}
		if !strings.Contains(err.Error(), tc.leaf) || !strings.Contains(err.Error(), tc.mod) {
			t.Errorf("%s: rejection must name the leaf and modifier, got: %v", tc.cmd, err)
		}
	}
}

// Test9880_ModifierArityGarbageRejected pins the arity half: a missing
// value, a trailing token past the declared args, a trailing token on a
// presence-only modifier, and an unknown modifier keyword must all still
// be rejected, naming the leaf.
func Test9880_ModifierArityGarbageRejected(t *testing.T) {
	cases := []struct {
		name, text, leaf, want string
	}{
		{"key/extra/block", "server 1.1.1.1 {\n key 5 6;\n}", "system ntp server", "unknown modifier"},
		{"key/extra/packed", `server 1.1.1.1 key 5 6;`, "system ntp server", "unknown modifier"},
		{"action/extra", `threshold 400 action accept reject;`, "system ntp threshold", "unknown modifier"},
		{"key/bare/block", "server 1.1.1.1 {\n key;\n}", "system ntp server", `modifier "key" requires a value`},
		{"key/bare/packed", `server 1.1.1.1 key;`, "system ntp server", `modifier "key" requires a value`},
		{"key/bare/modifier-only", `server key;`, "system ntp server", `modifier "key" requires a value`},
		{"action/bare", `threshold 400 action;`, "system ntp threshold", `modifier "action" requires a value`},
		{"prefer/trailing/block", "server 1.1.1.1 {\n prefer foo;\n}", "system ntp server", "unknown modifier"},
		{"prefer/trailing/packed", `server 1.1.1.1 prefer foo;`, "system ntp server", "unknown modifier"},
		{"unknown/block", "server 1.1.1.1 {\n bogus 5;\n}", "system ntp server", "unknown modifier"},
		{"unknown/packed", `server 1.1.1.1 bogus;`, "system ntp server", "unknown modifier"},
	}
	for _, tc := range cases {
		err := schemaCheck(t, "system {\n ntp {\n"+tc.text+"\n}\n}")
		if err == nil {
			t.Errorf("%s: SchemaValidate accepted garbage, want reject", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.leaf) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: rejection must name the leaf (%q) with %q, got: %v", tc.name, tc.leaf, tc.want, err)
		}
	}
	flat := []struct{ cmd, leaf, want string }{
		{"set system ntp server 1.1.1.1 key", "system ntp server", `modifier "key" requires a value`},
		{"set system ntp threshold 400 action", "system ntp threshold", `modifier "action" requires a value`},
		{"set system ntp server 1.1.1.1 prefer foo", "system ntp server", "unknown modifier"},
		{"set system ntp server 1.1.1.1 bogus 5", "system ntp server", "unknown modifier"},
	}
	for _, tc := range flat {
		err := flatSchemaCheck(t, tc.cmd)
		if err == nil {
			t.Errorf("%s: SchemaValidate accepted garbage, want reject", tc.cmd)
			continue
		}
		if !strings.Contains(err.Error(), tc.leaf) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: rejection must name the leaf (%q) with %q, got: %v", tc.cmd, tc.leaf, tc.want, err)
		}
	}
}

// Test9880_MultiModifierPacking pins the packed-tail walk when several
// modifiers share one statement: each valued modifier must consume
// exactly its own value — a following modifier keyword must not be
// swallowed as a value, and a swallowed keyword (`key version`) must
// fail value validation rather than silently binding.
func Test9880_MultiModifierPacking(t *testing.T) {
	if err := schemaCheck(t, "system {\n ntp {\n server 1.1.1.1 key 5 version 4 prefer routing-instance foo;\n}\n}"); err != nil {
		t.Errorf("packed multi-modifier: %v", err)
	}
	if err := schemaCheck(t, "system {\n ntp {\n server 1.1.1.1 {\n key 5;\n version 4;\n prefer;\n routing-instance foo;\n}\n}\n}"); err != nil {
		t.Errorf("block multi-modifier: %v", err)
	}
	if err := flatSchemaCheck(t, "set system ntp server 1.1.1.1 key 5 version 4"); err != nil {
		t.Errorf("flat-set multi-modifier: %v", err)
	}
	if err := schemaCheck(t, "system {\n ntp {\n server 1.1.1.1 prefer key 5;\n}\n}"); err != nil {
		t.Errorf("presence-then-valued packing: %v", err)
	}
	err := schemaCheck(t, "system {\n ntp {\n server 1.1.1.1 key version;\n}\n}")
	if err == nil {
		t.Fatal("`key version` accepted: the modifier keyword was swallowed as the key id, want reject")
	}
	if !strings.Contains(err.Error(), "system ntp server") || !strings.Contains(err.Error(), "key") {
		t.Fatalf("rejection must name the leaf and modifier, got: %v", err)
	}
}

// Test9880_ValueAsBlockStaysRejected pins the deliberate boundary: a
// value nested as a block member (`key { 5; }`) is not Junos for a
// valued leaf — the block-value exception (#6774) is an explicit
// per-leaf opt-in no modifier takes — so it stays rejected rather than
// committing a shape the modifier readers do not take values from.
func Test9880_ValueAsBlockStaysRejected(t *testing.T) {
	for name, text := range map[string]string{
		"key":    "server 1.1.1.1 {\n key {\n 5;\n}\n}",
		"action": "threshold 400 {\n action {\n accept;\n}\n}",
	} {
		err := schemaCheck(t, "system {\n ntp {\n"+text+"\n}\n}")
		if err == nil {
			t.Errorf("%s-as-block: SchemaValidate accepted, want reject", name)
			continue
		}
		if !strings.Contains(err.Error(), "system ntp") {
			t.Errorf("%s-as-block: rejection must name the leaf, got: %v", name, err)
		}
	}
}

// Test9880_ModifierHeadedMultitokenRejected pins validation/compiler
// agreement about the primary token (review fold): when the FIRST token is
// itself a modifier keyword, the compiler reads the statement as modifiers
// with no address and yields no server — so the gate must reject rather
// than read the head as the value. `server prefer key 5` passed `prefer`
// as a hostname here while compiling to zero servers. A sibling supplying
// an address must NOT rescue the statement: the address-less node still
// contributes nothing (its modifiers are dropped, not merged), so sibling
// rescue would be a silent drop wearing an accept.
func Test9880_ModifierHeadedMultitokenRejected(t *testing.T) {
	cases := []struct {
		name, text, leaf string
	}{
		{"prefer/key", `server prefer key 5;`, "system ntp server"},
		{"prefer/version", `server prefer version 4;`, "system ntp server"},
		{"prefer/routing-instance", `server prefer routing-instance foo;`, "system ntp server"},
		{"prefer/prefer", `server prefer prefer;`, "system ntp server"},
		{"threshold/action-head", `threshold action accept;`, "system ntp threshold"},
		// Sibling present: the address-less node still compiles to
		// nothing, so the verdict must not change.
		{"prefer/key/with-sibling", "server 1.1.1.1;\n server prefer key 5;", "system ntp server"},
	}
	for _, tc := range cases {
		err := schemaCheck(t, "system {\n ntp {\n"+tc.text+"\n}\n}")
		if err == nil {
			t.Errorf("%s: SchemaValidate accepted an address-less statement that compiles to no server, want reject", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.leaf) || !strings.Contains(err.Error(), "missing value") {
			t.Errorf("%s: rejection must name the leaf (%q) as missing value, got: %v", tc.name, tc.leaf, err)
		}
	}
	// Flat-set files the head modifier as a child (the #7132 absorber
	// descends on modifier keywords), so these reject via the lone
	// modifier-only branch rather than the multi-token rule — pin the
	// verdict, which must agree regardless of path.
	for _, cmd := range []string{
		"set system ntp server prefer key 5",
		"set system ntp server prefer prefer",
	} {
		err := flatSchemaCheck(t, cmd)
		if err == nil {
			t.Errorf("%s: SchemaValidate accepted, want reject", cmd)
			continue
		}
		if !strings.Contains(err.Error(), "system ntp server") {
			t.Errorf("%s: rejection must name the leaf, got: %v", cmd, err)
		}
	}
}
