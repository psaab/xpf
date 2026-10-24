package cli

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/optopic"
)

// #16469: #15942 regression — canonicalForms' top-level placeholder arm
// set awaitValue unconditionally, so the keyword after `show route`'s
// `<destination>` placeholder (`table`/`protocol`/`instance`, and the
// plain keywords `fib`/`terse`/`detail`/`summary`) was eaten as the
// placeholder's value. The walk then broke on the keyword's own value,
// minting no selector form and no extended base/full form:
//
//	show route table inet.0    -> base="show route", sel=[]   (was)
//	show route summary         -> base="show route"           (was)
//
// so anchored `deny-commands "^show route table$"` (and protocol /
// instance) silently stopped denying on the console while the remote
// CLI (registry Command `show route table`) still denied, and
// `^show route$` wrongly denied `show route summary` — a distinct
// own command. The fix peeks the next canonical token against the
// node's declared children: only a non-keyword token fills the
// placeholder; a keyword falls through to the normal arms, so the
// selector arm mints `show route table` and plain keywords extend
// base/full. canonicalPrefix (audit) shares canonicalForms, so it is
// fixed by the same change.
//
// Remote twin for the selector rows: pkg/grpcapi
// TestArgumentScopedDenyFiresOnGRPC16067 already pins
// `^show route table$` over topic `route-table:public-vrf` (denied)
// and `^show route protocol bgp$` over `route-protocol:bgp` (denied);
// TestPlaceholderSiblingConsoleRemoteAgreement16469 below asserts the
// console verdict equals the remote charge's verdict for every
// placeholder-sibling node that has a remote charge.

func eval16469(t *testing.T, allow, deny, line string) error {
	t.Helper()
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily,
		allow, allow != "", deny, deny != "")
	if err != nil {
		t.Fatalf("compile allow=%q deny=%q: %v", allow, deny, err)
	}
	return evaluateCommandRegex(rules, "restricted", line, "")
}

func TestPlaceholderSiblingSelectorDeny16469(t *testing.T) {
	for _, tc := range []struct {
		deny   string
		line   string
		denied bool
		why    string
	}{
		// The regression: anchored selector-spelling denies must bind.
		{"^show route table$", "show route table inet.0", true, "selector deny binds past the placeholder sibling"},
		{"^show route protocol$", "show route protocol bgp", true, "selector deny binds past the placeholder sibling"},
		{"^show route instance$", "show route instance blue", true, "selector deny binds past the placeholder sibling"},
		{"^show route table$", "show route table secret-vrf", true, "selector deny, value-named table"},
		// Positive controls that already passed pre-fix.
		{"^show route table inet.0$", "show route table inet.0", true, "full-spelling deny (control)"},
		{"^show route table", "show route table inet.0", true, "unanchored deny (control)"},
		{"^show firewall filter$", "show firewall filter F1", true, "dynamic-selector twin (control, #15973)"},
		// Selector doctrine for the base: ^show route$ denies the base
		// and its selector spellings, but NOT its own plain-keyword
		// subcommands.
		{"^show route$", "show route", true, "bare base denied"},
		{"^show route$", "show route 10.0.0.0/8", true, "base deny reaches the placeholder value form"},
		{"^show route$", "show route 10.0.0.0/8 exact", true, "base deny reaches placeholder + its child keyword"},
		{"^show route$", "show route table inet.0", true, "base deny reaches the selector spelling (selector doctrine)"},
		{"^show route$", "show route summary", false, "own plain-keyword command: not priced as the bare base"},
		{"^show route$", "show route fib", false, "own plain-keyword command"},
		{"^show route$", "show route terse", false, "own plain-keyword command"},
		{"^show route$", "show route detail", false, "own plain-keyword command"},
		// Plain keywords beside the placeholder are addressable as
		// their own commands in both directions.
		{"^show route summary$", "show route summary", true, "plain keyword beside placeholder is its own command"},
		{"^show route fib$", "show route fib", true, "plain keyword beside placeholder is its own command"},
		{"^show route summary$", "show route", false, "summary deny does not bind the bare base"},
		{"^show route summary$", "show route table inet.0", false, "summary deny does not bind a sibling selector"},
		// The selector deny stays narrow.
		{"^show route table$", "show route", false, "selector deny does not bind the bare base"},
		{"^show route table$", "show route 10.0.0.0/8", false, "selector deny does not bind the placeholder form"},
		{"^show route table$", "show route protocol bgp", false, "selector deny does not bind a sibling selector"},
		{"^show route table$", "show route summary", false, "selector deny does not bind a sibling plain keyword"},
		// Allow direction: selector and plain-keyword spellings satisfy
		// an anchored allow written against them; the base allow
		// satisfies the selector spelling (selector doctrine) but not
		// the distinct summary command.
		{"allow:^show route table$", "show route table inet.0", false, "selector-spelling allow satisfies (placeholder is allow below)"},
	} {
		allow, deny := "", tc.deny
		if strings.HasPrefix(tc.deny, "allow:") {
			allow, deny = strings.TrimPrefix(tc.deny, "allow:"), ""
		}
		err := eval16469(t, allow, deny, tc.line)
		if tc.denied && err == nil {
			t.Errorf("deny=%q allow=%q line=%q: ALLOWED, want denied — %s", deny, allow, tc.line, tc.why)
		}
		if !tc.denied && err != nil {
			t.Errorf("deny=%q allow=%q line=%q: denied (%v), want allowed — %s", deny, allow, tc.line, err, tc.why)
		}
	}

	// Anchored base allow: selector spellings admitted, the distinct
	// summary command refused by the allowlist.
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily,
		"^show route$", true, "", false)
	if err != nil {
		t.Fatalf("compile base allow: %v", err)
	}
	for _, line := range []string{"show route", "show route 10.0.0.0/8", "show route table inet.0"} {
		if err := evaluateCommandRegex(rules, "restricted", line, ""); err != nil {
			t.Errorf("allow=^show route$ line=%q: denied (%v), want allowed (selector doctrine)", line, err)
		}
	}
	if err := evaluateCommandRegex(rules, "restricted", "show route summary", ""); err == nil {
		t.Error("allow=^show route$ line=\"show route summary\": ALLOWED, want refused — summary is a distinct command, not a selector spelling of the base")
	}
}

// TestPlaceholderSiblingForms16469 pins the forms themselves, so a
// verdict that happens to agree for the wrong reason still fails.
func TestPlaceholderSiblingForms16469(t *testing.T) {
	for _, tc := range []struct {
		line              string
		base, full, chain string
		selectors         []string
	}{
		{"show route", "show route", "show route", "", nil},
		{"show route 10.0.0.0/8", "show route", "show route", "", nil},
		{"show route 10.0.0.0/8 exact", "show route", "show route", "", nil},
		{"show route table inet.0", "show route", "show route", "", []string{"show route table"}},
		{"show route protocol bgp", "show route", "show route", "", []string{"show route protocol"}},
		{"show route instance blue", "show route", "show route", "", []string{"show route instance"}},
		{"show route fib", "show route fib", "show route fib", "", nil},
		{"show route summary", "show route summary", "show route summary", "", nil},
		// Options-node placeholder beside keywords: the placeholder
		// fills, keywords stay options of the same command (no
		// fabricated selector forms, base unchanged).
		{"show security log zone trust", "show security log", "show security log", "", nil},
		{"show security log 5 zone trust", "show security log", "show security log", "", nil},
		{"ping 10.0.0.1 count 5", "ping", "ping", "", nil},
		// Childless placeholder beside keywords under a plain node.
		{"show chassis cluster data-plane flows all", "show chassis cluster data-plane flows all",
			"show chassis cluster data-plane flows all", "", nil},
		{"show chassis cluster data-plane flows 10", "show chassis cluster data-plane flows",
			"show chassis cluster data-plane flows", "", nil},
		// A keyword that is a child of the placeholder's value (not a
		// sibling) still resolves after the value fills the slot.
		{"show protocols bgp neighbor 10.0.0.1 received-routes",
			"show protocols bgp neighbor", "show protocols bgp neighbor", "", nil},
	} {
		canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(tc.line))
		if res != cmdtree.CanonicalOK {
			t.Fatalf("line %q did not canonicalize (res=%v)", tc.line, res)
		}
		base, full, selectors, chain := canonicalForms(canon)
		if base != tc.base || full != tc.full || chain != tc.chain {
			t.Errorf("line %q: forms base=%q full=%q chain=%q, want base=%q full=%q chain=%q",
				tc.line, base, full, chain, tc.base, tc.full, tc.chain)
		}
		got := append([]string(nil), selectors...)
		want := append([]string(nil), tc.selectors...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("line %q: selectors=%q, want %q", tc.line, selectors, tc.selectors)
		}
		if prefix := canonicalPrefix(canon); prefix != tc.base {
			t.Errorf("line %q: canonicalPrefix=%q, want base %q (audit consumer)", tc.line, prefix, tc.base)
		}
	}
}

// placeholderSiblingNodes16469 walks the operational tree and returns
// every node that has a placeholder child beside at least one keyword
// child, with the keyword path to it. This is the census the
// cross-surface cell is built over: a new placeholder-sibling node
// joins the cell automatically instead of silently escaping it.
func placeholderSiblingNodes16469() []struct {
	path     []string
	keywords []string
} {
	var out []struct {
		path     []string
		keywords []string
	}
	var walk func(children map[string]*cmdtree.Node, path []string)
	walk = func(children map[string]*cmdtree.Node, path []string) {
		for name, node := range children {
			if node == nil || strings.HasPrefix(name, "<") {
				continue
			}
			p := append(append([]string(nil), path...), name)
			hasPlaceholder := false
			var keywords []string
			for childName := range node.Children {
				if strings.HasPrefix(childName, "<") {
					hasPlaceholder = true
				} else {
					keywords = append(keywords, childName)
				}
			}
			if hasPlaceholder && len(keywords) > 0 {
				sort.Strings(keywords)
				out = append(out, struct {
					path     []string
					keywords []string
				}{p, keywords})
			}
			walk(node.Children, p)
		}
	}
	walk(cmdtree.OperationalTree, nil)
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i].path, " ") < strings.Join(out[j].path, " ")
	})
	return out
}

// TestPlaceholderSiblingConsoleRemoteAgreement16469 is the
// cross-surface cell: for every node in the operational tree that has
// a placeholder child beside keyword children, an anchored deny
// written against each addressable spelling (the base, and — for a
// RequiresValue+Dynamic keyword — its selector spelling) must deny
// the console line AND the remote charge for the same command.
// Console lines use a value token (`zzz16469`, `10.0.0.0/8` where the
// placeholder takes an address) that is not a keyword, so the line
// canonicalizes; remote charges come from the optopic registry, the
// same table the gRPC gate prices. Nodes whose keyword children have
// no remote charge (options of an Options node, nested placeholder
// chains) assert the console side against the keyword-extended form
// itself, which is the spelling the remote gate would charge if a
// topic existed.
func TestPlaceholderSiblingConsoleRemoteAgreement16469(t *testing.T) {
	nodes := placeholderSiblingNodes16469()
	if len(nodes) == 0 {
		t.Fatal("census found no placeholder-sibling nodes; the cell measures nothing")
	}
	// The census must at least cover the node this issue is about.
	foundRoute := false
	for _, n := range nodes {
		if strings.Join(n.path, " ") == "show route" {
			foundRoute = true
		}
	}
	if !foundRoute {
		t.Fatalf("census %v does not include `show route`", nodes)
	}
	// Options nodes are excluded from the ADDRESSABLE-SPELLING
	// agreement: their keywords (`count` under `ping`, `zone` under
	// `show security log`) are options of the one command, not
	// subcommands or selectors — canonicalForms deliberately mints
	// no form for them (#15973's `family` ruling), so there is no
	// `^ping count$` spelling for the surfaces to agree on. (They
	// remain in the census, and the base-spelling check below runs
	// over every censused node, Options included.) What remains is
	// exactly the `show route` geometry: a plain keyword extends
	// base/full as its own command, and a RequiresValue+Dynamic
	// keyword mints a selector form; both are addressable spellings
	// a remote charge can name.
	addressable := nodes[:0]
	for _, n := range nodes {
		if node := nodeAtPath16469(n.path); node != nil && !node.Options {
			addressable = append(addressable, n)
		}
	}
	if len(addressable) == 0 {
		t.Fatal("census found no non-Options placeholder-sibling nodes; the cell measures nothing")
	}

	// Remote charges by command, from the registry both surfaces read.
	remoteCommands := map[string]bool{}
	for _, e := range optopic.ShowTextEntries() {
		remoteCommands[e.Command] = true
	}

	// A placeholder value token that is never a keyword anywhere in
	// these subtrees.
	const value = "10.0.0.0/8"

	for _, n := range addressable {
		base := strings.Join(n.path, " ")
		// Resolve the node to classify its keyword children.
		node := nodeAtPath16469(n.path)
		if node == nil {
			t.Fatalf("census path %q does not resolve", base)
		}
		for _, kw := range n.keywords {
			child := node.Children[kw]
			addressable := base + " " + kw
			isSelector := child.IsTypedLeaf() || (child.RequiresValue && child.HasDynamic())
			// Console line: keyword, plus a value when the keyword
			// takes one.
			line := addressable
			if isSelector || child.HasDynamic() || child.IsTypedLeaf() {
				line += " " + value
			}
			canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(line))
			if res != cmdtree.CanonicalOK {
				// Some keyword children only canonicalize with a
				// real value (e.g. a dynamic pool name); the form
				// cell below still covers the spelling. Skip the
				// verdict agreement for those rather than weakening
				// the census.
				continue
			}
			// Anchored deny against the addressable spelling must
			// deny the console line.
			deny := "^" + addressable + "$"
			rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, deny, true)
			if err != nil {
				t.Fatalf("compile %q: %v", deny, err)
			}
			if err := evaluateCommandRegex(rules, "restricted", line, ""); err == nil {
				t.Errorf("node %q keyword %q: console line %q ALLOWED under deny %q, want denied",
					base, kw, line, deny)
			}
			// If the remote surface charges this command, the same
			// deny must deny the remote charge (evaluated the way
			// the gRPC gate evaluates its argument-free charge:
			// EvaluateForms over the full and bare forms).
			if remoteCommands[addressable] {
				full := addressable
				if isSelector {
					full = line // remote rebuilds `base + value` (#16067)
				}
				if d := rules.EvaluateForms(full, addressable); d.Allowed {
					t.Errorf("node %q keyword %q: remote charge %q ALLOWED under deny %q while console denies — surfaces disagree",
						base, kw, addressable, deny)
				}
			}
			_ = canon
		}
	}
	// The base spelling itself, over EVERY censused node (Options
	// included): a placeholder value must not step around an anchored
	// base deny, on either surface.
	for _, n := range nodes {
		base := strings.Join(n.path, " ")
		line := base + " " + value
		if _, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(line)); res == cmdtree.CanonicalOK {
			deny := "^" + base + "$"
			rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, deny, true)
			if err != nil {
				t.Fatalf("compile %q: %v", deny, err)
			}
			if err := evaluateCommandRegex(rules, "restricted", line, ""); err == nil {
				t.Errorf("node %q: console line %q ALLOWED under base deny %q, want denied", base, line, deny)
			}
			if remoteCommands[base] {
				if d := rules.EvaluateForms(line, base); d.Allowed {
					t.Errorf("node %q: remote forms (%q, %q) ALLOWED under base deny %q — surfaces disagree", base, line, base, deny)
				}
			}
		}
	}
}

func nodeAtPath16469(path []string) *cmdtree.Node {
	current := cmdtree.OperationalTree
	var node *cmdtree.Node
	for _, w := range path {
		var ok bool
		node, ok = current[w]
		if !ok || node == nil {
			return nil
		}
		current = node.Children
	}
	return node
}
