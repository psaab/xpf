package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// wildcard_keyvalidator_inventory_6844_test.go -- #6844.
//
// #6844 made SchemaValidate run a keyValidator on a WILDCARD TYPED LEAF's
// keyword. #6834 had already done so for wildcard CONTAINERS; the typed-leaf
// branch returns before that rule was reached, so a wildcard typed leaf
// validated its VALUE and never its identity.
//
// That is a change to a shared gate, so its blast radius is enumerated here
// rather than left to be discovered. Every leaf in this list newly gained
// identity validation, and any leaf ADDED to the set later shows up as a diff
// in this test rather than as a config that stops committing in the field.

// collectWildcardTypedLeafKeyValidators walks setSchema for the exact shape the
// #6844 rule newly reaches.
func collectWildcardTypedLeafKeyValidators(t *testing.T) []string {
	t.Helper()
	out := map[string]bool{}
	// Cycle guard keyed on (node, path) rather than on the node alone.
	//
	// A pointer-only `seen` map suppressed the SECOND route to a shared node,
	// and the schema shares nodes heavily: `groups <name>` re-hosts the whole
	// tree, so every top-level subtree has both a direct and a group-hosted
	// route. Whichever sorted first won and the other was never reported. That
	// makes the inventory blind to a genuine alias, which is the one thing an
	// inventory of "every site the rule reaches" must not be.
	visited := map[string]bool{}
	var walk func(n *schemaNode, path []string)
	walk = func(n *schemaNode, path []string) {
		if n == nil {
			return
		}
		key := fmt.Sprintf("%p|%s", n, strings.Join(path, " "))
		if visited[key] {
			return
		}
		visited[key] = true
		if w := n.wildcard; w != nil {
			// The EXACT shape walkSchemaNode's typed-leaf branch reaches. The
			// runtime condition is `isTypedLeaf() && (validator != nil ||
			// treeValidator != nil)` -- a leaf with a keyValidator but NO value
			// validator never enters that branch at all, so listing it here
			// would overstate the blast radius.
			if w.isTypedLeaf() && w.keyValidator != nil &&
				(w.validator != nil || w.treeValidator != nil) {
				p := strings.Join(path, " ")
				p = strings.TrimPrefix(p, "groups <wildcard> ")
				out[p+" <wildcard-key>"] = true
			}
			walk(w, append(append([]string(nil), path...), "<wildcard>"))
		}
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(n.children[k], append(append([]string(nil), path...), k))
		}
	}
	walk(setSchema, nil)
	res := make([]string, 0, len(out))
	for k := range out {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

// TestWildcardTypedLeafKeyValidatorRuleIsWired_6844 is the behavioural half.
//
// The inventory above reads schema METADATA. It passes with the walker hunk
// reverted, because nothing in it asks whether walkSchemaNode actually invokes
// the validator — an inventory of sites a rule "reaches" that cannot tell
// whether the rule runs.
//
// This drives each inventoried destination through the real gate. The file
// destination is already covered by the rejection cells; host and user were
// not, and a revert that broke only those would have shown up nowhere.
func TestWildcardTypedLeafKeyValidatorRuleIsWired_6844(t *testing.T) {
	for _, dest := range []struct{ stanza, src string }{
		{"file", `system { syslog { file audit { "daemon;auth" info; } } }`},
		{"host", `system { syslog { host 192.0.2.10 { "daemon;auth" info; } } }`},
		{"user", `system { syslog { user root { "daemon;auth" info; } } }`},
	} {
		t.Run(dest.stanza, func(t *testing.T) {
			p := NewParser(dest.src)
			tree, errs := p.Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			_, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			err = SchemaValidate(tree)
			if err == nil {
				t.Fatalf("the %s destination ACCEPTED an injectable facility. The typed-leaf "+
					"identity rule in walkSchemaNode is not running for this destination, "+
					"and the metadata inventory cannot see that.", dest.stanza)
			}
			if !strings.Contains(err.Error(), "syslog facility") {
				t.Errorf("%s rejected, but not by the facility gate: %v", dest.stanza, err)
			}
		})
	}
}

// TestWildcardTypedLeafKeyValidatorInventory_6844 pins the blast radius.
//
// The list is short on purpose. If it grows, someone installed a keyValidator
// on a wildcard typed leaf and that leaf's identity is now gated at commit --
// which may be exactly right, but it is a behaviour change to a shared gate and
// should be a deliberate edit here rather than a surprise.
func TestWildcardTypedLeafKeyValidatorInventory_6844(t *testing.T) {
	want := []string{
		"system syslog file <wildcard-key>",
		"system syslog host <wildcard-key>",
		"system syslog user <wildcard-key>",
	}
	got := collectWildcardTypedLeafKeyValidators(t)

	// Anti-vacuity: a walk that reached nothing would report an empty set and
	// "no unexpected sites", which is indistinguishable from a clean result.
	if len(got) == 0 {
		t.Fatal("the walk found NO wildcard typed leaf with a keyValidator, not even " +
			"the three system-syslog facility slots this issue added. The walk is not " +
			"reaching the schema and would report clean whatever the schema said")
	}

	inWant := map[string]bool{}
	for _, w := range want {
		inWant[w] = true
	}
	for _, g := range got {
		if !inWant[g] {
			t.Errorf("NEW wildcard typed leaf with a keyValidator: %s\n"+
				"    Its identity is now gated at commit by the #6844 rule. If that is "+
				"intended, add it here; if not, the leaf wants a value validator rather "+
				"than a key one.", g)
		}
	}
	inGot := map[string]bool{}
	for _, g := range got {
		inGot[g] = true
	}
	for _, w := range want {
		if !inGot[w] {
			t.Errorf("%s no longer has a wildcard typed-leaf keyValidator. If the gate "+
				"was removed, the #6844 injectable-facility hole is open again.", w)
		}
	}
}
