package cmdtree

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16151: completion <-> Canonicalize agreement, without merging them.
//
// Steps 1-2 of R7 (dedup the twin completion walkers, descriptions as a
// projection) already landed as #16138: CompleteFromTree is the
// name-only projection of the single CompleteFromTreeWithDesc walk,
// pinned by completion_walker_parity_16138_test.go. What remained
// untested was the claim that replaces the REJECTED step 3 (merging
// Canonicalize into a provider-capable walk via a walkPolicy bool):
// every keyword completion offers is exactly a keyword Canonicalize
// accepts, per level, and no provider is reachable from Canonicalize.
//
// The agreement is stated at the resolveTreeWord level, not as
// "every enumerated path canonicalizes CanonicalOK". Those differ:
// a keyword that opens a value slot (a typed leaf, a RequiresValue
// dynamic, a childless placeholder, an option subtree) is a lawful
// completion offer and resolves as a keyword, yet a line ending at
// it is incomplete (#14687/#15719) and Canonicalize must refuse it.
// Collapsing the two would either force Canonicalize to accept
// dangling selectors (the #14687 bypass) or force completion to
// stop offering them. So below, "Canonicalize accepts this keyword"
// means: the word resolves to that keyword (never rewritten to a
// sibling, never refused as unknown/ambiguous at that slot), and a
// refusal — when there is one — is solely the end-of-line
// incompleteness that filling the pending value (or, for a keyword
// behind an unfilled dynamic value, supplying that value) removes.

type keywordPath16151 struct {
	path  []string
	level map[string]*Node
	node  *Node
}

func enumerateKeywordPaths16151(tree map[string]*Node) []keywordPath16151 {
	var out []keywordPath16151
	var walk func(level map[string]*Node, prefix []string)
	walk = func(level map[string]*Node, prefix []string) {
		names := make([]string, 0, len(level))
		for name := range level {
			if !isPlaceholder(name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			path := append(append([]string(nil), prefix...), name)
			out = append(out, keywordPath16151{path: path, level: level, node: level[name]})
			if level[name].Children != nil {
				walk(level[name].Children, path)
			}
		}
	}
	walk(tree, nil)
	return out
}

func shortestUniquePrefix16151(level map[string]*Node, word string) string {
	for n := 1; n <= len(word); n++ {
		prefix := word[:n]
		count := 0
		for name := range level {
			if !isPlaceholder(name) && strings.HasPrefix(name, prefix) {
				count++
			}
		}
		if count == 1 {
			return prefix
		}
	}
	return word
}

// canonicalAcceptsKeyword16151 reports whether Canonicalize accepts
// kp.path's final keyword AS that keyword. On CanonicalOK the
// canonical spelling must reproduce the path exactly. A non-OK
// result counts as acceptance only when filling the final keyword's
// pending value, or descending to one of its child keywords, turns
// the same path CanonicalOK — i.e. the refusal is the end-of-line
// incompleteness of that keyword's own slot (#14687/#15719), not a
// disagreement about the keyword. Keywords behind an ancestor's
// unfilled value are classified by the caller.
func canonicalAcceptsKeyword16151(kp keywordPath16151, tree map[string]*Node) bool {
	got, res := Canonicalize(tree, kp.path)
	if res == CanonicalOK {
		if len(got) != len(kp.path) {
			return false
		}
		for i := range got {
			if got[i] != kp.path[i] {
				return false
			}
		}
		return true
	}
	if _, res2 := Canonicalize(tree, append(append([]string(nil), kp.path...), "16151-value")); res2 == CanonicalOK {
		return true
	}
	if kp.node != nil {
		for name := range kp.node.Children {
			if isPlaceholder(name) {
				continue
			}
			if _, res2 := Canonicalize(tree, append(append([]string(nil), kp.path...), name)); res2 == CanonicalOK {
				return true
			}
		}
	}
	return false
}

// checkKeywordAgreement16151 asserts, for every enumerated keyword
// path of tree: completion offers the keyword by full spelling and
// by unique abbreviation; CompleteFromTreeWithDesc carries it with
// its node description; (when checkLookup) LookupDesc agrees; and
// Canonicalize accepts the keyword as itself, allowing the
// value-insertion rescue for keywords behind an ancestor's unfilled
// value (e.g. `show firewall filter <name> effective`).
// Returns the number of paths checked.
func checkKeywordAgreement16151(t *testing.T, tree map[string]*Node, checkLookup bool) int {
	t.Helper()
	paths := enumerateKeywordPaths16151(tree)
	if len(paths) == 0 {
		t.Fatalf("enumerated 0 keyword paths — the walker is broken, not the tree empty")
	}
	for _, kp := range paths {
		leaf := kp.path[len(kp.path)-1]
		parent := kp.path[:len(kp.path)-1]
		joined := strings.Join(kp.path, " ")

		for _, partial := range []string{leaf, shortestUniquePrefix16151(kp.level, leaf)} {
			names := CompleteFromTree(tree, parent, partial, nil)
			found := false
			for _, n := range names {
				if n == leaf {
					found = true
				}
			}
			if !found {
				t.Errorf("completion does not offer keyword %q (path %q, partial %q): got %v", leaf, joined, partial, names)
			}
			// Abbreviated completion must agree with Canonicalize's
			// abbreviation expansion for complete lines: when the
			// full path canonicalizes, the abbreviated last word
			// must canonicalize to the same full path.
			if partial != leaf {
				if got, res := Canonicalize(tree, append(append([]string(nil), parent...), partial)); res == CanonicalOK {
					want := strings.Join(kp.path, " ")
					if strings.Join(got, " ") != want {
						t.Errorf("Canonicalize(abbreviated %q) = %q, want %q", partial, strings.Join(got, " "), want)
					}
				}
			}
		}

		pairs := CompleteFromTreeWithDesc(tree, parent, leaf, nil)
		desc := ""
		for _, p := range pairs {
			if p.Name == leaf {
				desc = p.Desc
			}
		}
		if desc == "" {
			t.Errorf("CompleteFromTreeWithDesc(%q, partial %q) offers no description for keyword %q (pairs %v)", joined, leaf, leaf, pairs)
		}
		if kp.node.Desc != "" && desc != "" && desc != kp.node.Desc {
			t.Errorf("description drift on %q: WithDesc %q != node Desc %q", joined, desc, kp.node.Desc)
		}
		if checkLookup {
			if got := LookupDesc(parent, leaf, false); got != desc {
				t.Errorf("LookupDesc(%q, %q) = %q, want WithDesc description %q", joined, leaf, got, desc)
			}
		}

		if !canonicalAcceptsKeyword16151(kp, tree) {
			// Behind one or more ancestors' unfilled values?
			// Insert a dummy value at every subset of gaps
			// (before each word after the first, plus a trailing
			// gap for the final keyword's own slot) and require
			// some insertion to canonicalize ending in this
			// keyword, e.g. `show security policies from-zone
			// <z> to-zone <z> hit-count` and `show firewall
			// filter <name> family <fam>`. Insertions are
			// values, never keywords, so a rescue cannot
			// rewrite the keyword under test to a sibling.
			rescued := false
			n := len(kp.path)
			for mask := 1; mask < (1<<n) && !rescued; mask++ {
				var cand []string
				for i, w := range kp.path {
					if i >= 1 && mask&(1<<(i-1)) != 0 {
						cand = append(cand, "16151-value")
					}
					cand = append(cand, w)
				}
				// (trailing-value variant tried below)
				if _, res := Canonicalize(tree, cand); res == CanonicalOK {
					rescued = true
					break
				}
				// Also try cand + trailing value (final slot).
				if _, res := Canonicalize(tree, append(append([]string(nil), cand...), "16151-value")); res == CanonicalOK {
					rescued = true
				}
			}
			if rescued {
				continue
			}
			t.Errorf("Canonicalize does not accept keyword path %q as itself — every keyword completion offers must be a keyword Canonicalize accepts", joined)
		}
	}
	return len(paths)
}

func TestCompletionCanonicalizeKeywordAgreement16151(t *testing.T) {
	paths := enumerateKeywordPaths16151(OperationalTree)
	if len(paths) < 400 {
		t.Fatalf("enumerated only %d keyword paths from OperationalTree; enumeration is broken", len(paths))
	}
	if got := checkKeywordAgreement16151(t, OperationalTree, true); got != len(paths) {
		t.Errorf("agreement checked %d of %d keyword paths", got, len(paths))
	}
}

// Seeded divergence: a ModifierOnly child (#14688) is offered by
// completion at its parent level, yet no canonical line reaches it
// after the dynamic value, and the bare form ends mid-value. The
// agreement helper must classify it as NOT accepted — if this went
// green, the agreement check would be test-only-green on exactly
// the drift it exists to catch.
func TestCompletionCanonicalizeAgreementSeededDivergence16151(t *testing.T) {
	dyn := func(cfg *config.Config) []string { return []string{"alpha"} }
	tree := map[string]*Node{
		"showx": {Desc: "synthetic show", Children: map[string]*Node{
			"iface": {
				Desc:          "dynamic selector",
				DynamicFn:     dyn,
				RequiresValue: true,
				Children: map[string]*Node{
					"terse": {Desc: "modifier only", ModifierOnly: true},
				},
			},
		}},
	}
	names := CompleteFromTree(tree, []string{"showx", "iface"}, "terse", nil)
	found := false
	for _, n := range names {
		if n == "terse" {
			found = true
		}
	}
	if !found {
		t.Fatalf("seeded tree broken: completion does not offer terse, got %v", names)
	}
	iface := tree["showx"].Children["iface"]
	kp := keywordPath16151{path: []string{"showx", "iface", "terse"}, level: iface.Children, node: iface.Children["terse"]}
	if canonicalAcceptsKeyword16151(kp, tree) {
		t.Fatalf("seeded divergence not detected: Canonicalize accepts %v as itself", kp.path)
	}
	if _, res := Canonicalize(tree, []string{"showx", "iface", "16151-value", "terse"}); res == CanonicalOK {
		t.Fatalf("seeded divergence not seeded: value-inserted form canonicalizes OK")
	}
	// Control: the parent keyword itself DOES agree, so the red
	// above is the terse slot, not a broken synthetic tree.
	parentKP := keywordPath16151{path: []string{"showx", "iface"}, level: tree["showx"].Children, node: iface}
	if !canonicalAcceptsKeyword16151(parentKP, tree) {
		t.Fatalf("control failed: Canonicalize does not accept the parent path %v (value-filled) as itself", parentKP.path)
	}
}

// No provider is reachable from Canonicalize: counting providers
// must stay at zero across canonicalizations that traverse, consume
// and refuse dynamic values, while completion DOES invoke them
// (positive control).
func TestCanonicalizeInvokesNoProvider16151(t *testing.T) {
	calls := 0
	counting := func(cfg *config.Config) []string { calls++; return []string{"alpha", "beta"} }
	countingCtx := func(cfg *config.Config, words []string) []string { calls++; return []string{"gamma"} }
	tree := map[string]*Node{
		"cmd": {Desc: "synthetic", Children: map[string]*Node{
			"value": {Desc: "dynamic leaf", DynamicFn: counting, Children: map[string]*Node{
				"detail": {Desc: "detail"},
			}},
			"ctx": {Desc: "context dynamic", ContextDynamicFn: countingCtx},
		}},
	}
	lines := [][]string{
		{"cmd", "value", "alpha"},
		{"cmd", "value", "detail"},
		{"cmd", "value", "alpha", "detail"},
		{"cmd", "ctx", "gamma"},
		{"cmd", "ctx", "anything"},
		{"cmd", "value"},
		{"cmd", "nonexistent"},
		{"c"},
	}
	for _, line := range lines {
		before := calls
		Canonicalize(tree, line)
		if calls != before {
			t.Errorf("Canonicalize(%v) invoked a completion provider (%d calls) — providers must be unreachable from the authorization path", line, calls-before)
		}
	}
	if calls != 0 {
		t.Fatalf("Canonicalize invoked providers %d times total", calls)
	}
	before := calls
	_ = CompleteFromTree(tree, []string{"cmd", "value"}, "", nil)
	_ = CompleteFromTree(tree, []string{"cmd", "ctx"}, "", nil)
	if calls == before {
		t.Fatalf("positive control failed: completion never invoked the counting providers; the zero above proves nothing")
	}
}

// Canonicalize must stay structurally provider-free, bound by the
// same AST site census as the #8304/#9505 scope guards, with
// HasDynamic as positive control. Also pin the shared
// resolveTreeWord routing and the absence of the rejected
// walkPolicy/AllowProviders merge.
func TestCanonicalizeProviderFreeScope16151(t *testing.T) {
	if control := fieldReadSitesByFunc(t, "HasDynamic"); len(control) < 2 {
		t.Fatalf("positive control failed: HasDynamic reads found in %v", sortedFuncs(control))
	}
	for _, field := range []string{"DynamicFn", "ContextDynamicFn", "DynamicValues"} {
		sites := fieldReadSitesByFunc(t, field)
		for _, fn := range sortedFuncs(sites) {
			if fn == "Canonicalize" {
				t.Errorf("%s is read in Canonicalize() (sites %v) — a provider must be unreachable from the authorization path", field, sites)
			}
		}
	}
	canonSrc, err := os.ReadFile("canonicalize.go")
	if err != nil {
		t.Fatalf("read canonicalize.go: %v", err)
	}
	treeSrc, err := os.ReadFile("tree.go")
	if err != nil {
		t.Fatalf("read tree.go: %v", err)
	}
	if !strings.Contains(string(canonSrc), "resolveTreeWord(") {
		t.Errorf("Canonicalize no longer routes through resolveTreeWord — the shared prefix rule the agreement rests on is gone")
	}
	if !strings.Contains(string(treeSrc), "resolveTreeWord(") {
		t.Errorf("completion walk no longer routes through resolveTreeWord — the shared prefix rule the agreement rests on is gone")
	}
	for _, banned := range []string{"walkPolicy", "AllowProviders"} {
		if strings.Contains(string(canonSrc), banned) || strings.Contains(string(treeSrc), banned) {
			t.Errorf("found %q — the rejected walkPolicy/AllowProviders merge (#16151 step 3) must not reappear", banned)
		}
	}
}
