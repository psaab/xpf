package config

import (
	"fmt"
	"strings"
	"testing"
)

// #12528: `is-fragment` and `flexible-match-range` swallow a fused `then`
// tail. The terminal action never reaches the compiled term, leaving
// Action="" -- which the userspace dataplane reads as fall-through, so an
// intended discard/reject accepts. Strict compilation must refuse every
// fused shape with the exact diagnostic for its position; tolerant
// compilation must warn about every offending term and keep booting (#1960).
// The positive controls pin the position-aware scope (Review12678 B2):
// keyword-shaped names and legitimate packed spellings still commit.

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

// want12528 is the exact #12528 diagnostic for one finding kind.
func want12528(kind, family, filter, term, token string) string {
	where := fmt.Sprintf("firewall family %s filter %q term %q", family, filter, term)
	switch kind {
	case "then":
		return where + ": `then` follows `from is-fragment`, a bare flag that takes no " +
			"value or statements, so the firewall compiler never reads the action while " +
			"`show configuration` still displays it. The term is left with no action and " +
			"falls through to later terms. Move the action to the term's own block: " +
			"`from { is-fragment; } then { ...; }` (#12528)"
	case "token":
		return fmt.Sprintf("%s: token %q follows `from is-fragment`, a bare flag that takes "+
			"no value or statements, so the firewall compiler never reads it while "+
			"`show configuration` still displays it. Give `is-fragment` a statement of its "+
			"own: `from { is-fragment; ...; }`, or one `set ... from` command per match "+
			"(#12528)", where, token)
	case "flex":
		return where + ": `then` is written inside `from flexible-match-range`, which " +
			"reads only its named ranges and their match-start, byte-offset, bit-length, " +
			"match-value, match-mask and range fields, so the firewall compiler never reads " +
			"the action while `show configuration` still displays it. The term is left with " +
			"no action and falls through to later terms. Move the action to the term's own " +
			"block: `from { flexible-match-range { ... } } then { ...; }` (#12528)"
	case "packed":
		return fmt.Sprintf("%s: the packed spelling `from %s ... then ...` compiles, but its "+
			"set form (`show configuration | display set`, the `load merge` replay) nests "+
			"`then` under `%s`, where the firewall compiler never reads the action. Write "+
			"`from` and `then` as separate statements: `term <name> { from ...; then ...; }` "+
			"(#12528)", where, token, token)
	}
	panic("unknown #12528 finding kind " + kind)
}

func warnings12528(warnings []string) []string {
	var out []string
	for _, w := range warnings {
		if strings.Contains(w, "#12528") {
			out = append(out, w)
		}
	}
	return out
}

func term12528(t *testing.T, cfg *Config, family, filter, term string) *FirewallFilterTerm {
	t.Helper()
	pool := cfg.Firewall.FiltersInet
	if family == "inet6" {
		pool = cfg.Firewall.FiltersInet6
	}
	if f := pool[filter]; f != nil {
		for _, tm := range f.Terms {
			if tm.Name == term {
				return tm
			}
		}
	}
	t.Fatalf("family %s filter %q has no term %q", family, filter, term)
	return nil
}

type fused12528Row struct {
	name                 string
	tree                 func(*testing.T) *ConfigTree
	family, filter, term string
	kind, token          string
	// lenientAction is the historical compilation the tolerant path keeps:
	// "" for a dropped action, the authored action for a packed spelling.
	lenientAction string
}

func fusedRows12528() []fused12528Row {
	hier := func(text string) func(*testing.T) *ConfigTree {
		return func(t *testing.T) *ConfigTree { return hier12528(t, text) }
	}
	flat := func(lines ...string) func(*testing.T) *ConfigTree {
		return func(t *testing.T) *ConfigTree { return flat12528(t, lines...) }
	}
	return []fused12528Row{
		{name: "F13 flat discard", kind: "then", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from is-fragment then discard",
			"set firewall family inet filter F term allow then accept")},
		{name: "F13 flat reject", kind: "then", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from is-fragment then reject",
			"set firewall family inet filter F term allow then accept")},
		{name: "flat inet6", kind: "then", family: "inet6", filter: "F", term: "T", tree: flat(
			"set firewall family inet6 filter F term T from is-fragment then discard",
			"set firewall family inet6 filter F term allow then accept")},
		{name: "flat any", kind: "then", family: "any", filter: "F", term: "T", tree: flat(
			"set firewall family any filter F term T from is-fragment then discard",
			"set firewall family any filter F term allow then accept")},
		{name: "flat family-less filter", kind: "then", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall filter F term T from is-fragment then discard",
			"set firewall filter F term allow then accept")},
		{name: "N6 extra token", kind: "token", token: "foo", lenientAction: "discard",
			family: "inet", filter: "F", term: "T", tree: flat(
				"set firewall family inet filter F term T from is-fragment foo",
				"set firewall family inet filter F term T then discard")},
		{name: "flat second match nested under the flag", kind: "token", token: "protocol",
			lenientAction: "discard", family: "inet", filter: "F", term: "T", tree: flat(
				"set firewall family inet filter F term T from is-fragment protocol udp",
				"set firewall family inet filter F term T then discard")},
		{name: "N3 braced", kind: "then", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { is-fragment then discard; } } term allow { then accept; } } } }`)},
		{name: "N3 inet6", kind: "then", family: "inet6", filter: "F", term: "T",
			tree: hier(`firewall { family inet6 { filter F { term T { from { is-fragment then discard; } } } } }`)},
		{name: "N4 nested then", kind: "then", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { is-fragment { then { discard; } } } } term allow { then accept; } } } }`)},
		{name: "flat match before the flag", kind: "then", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from protocol udp is-fragment then discard",
			"set firewall family inet filter F term allow then accept")},
		{name: "nested family shape", kind: "then", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family { inet { filter F { term T { from { is-fragment then discard; } } } } } }`)},
		{name: "block-named filter and term", kind: "then", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter { F { term { T { from { is-fragment then discard; } } } } } } }`)},
		{name: "apply-groups", kind: "then", family: "inet", filter: "F", term: "T",
			tree: hier(`groups { G { firewall { family inet { filter F { term T { from { is-fragment then discard; } } } } } } } apply-groups G;`)},
		{name: "dangling then", kind: "then", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from is-fragment then")},
		{name: "tail set onto an existing flag", kind: "then", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from is-fragment",
			"set firewall family inet filter F term T from is-fragment then discard")},
		{name: "then count and discard", kind: "then", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from is-fragment then count C",
			"set firewall family inet filter F term T from is-fragment then discard")},
		{name: "second duplicate leaf fused", kind: "then", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { is-fragment; is-fragment then discard; } } } } }`)},
		{name: "then accept", kind: "then", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from is-fragment then accept")},
		{name: "quoted then", kind: "then", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { is-fragment "then" discard; } } } } }`)},
		{name: "flex flat issue rows", kind: "flex", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from flexible-match-range range R match-start layer-3",
			"set firewall family inet filter F term T from flexible-match-range range R byte-offset 9",
			"set firewall family inet filter F term T from flexible-match-range range R bit-length 8",
			"set firewall family inet filter F term T from flexible-match-range range R match-value 0x11",
			"set firewall family inet filter F term T from flexible-match-range range R then discard",
			"set firewall family inet filter F term allow then accept")},
		{name: "flex range body", kind: "flex", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range R { match-start layer-3; byte-offset 9; bit-length 8; match-value 0x11; then discard; } } } } } } }`)},
		{name: "flex range then block", kind: "flex", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range R { byte-offset 9; then { discard; } } } } } } } }`)},
		{name: "flex then beside the ranges", kind: "flex", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range R { byte-offset 9; } then { discard; } } } } } } }`)},
		{name: "flex packed in from", kind: "flex", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { flexible-match-range range R match-value 0x11 then discard; } } } } }`)},
		{name: "flex field run", kind: "flex", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range R { byte-offset 9 then discard; } } } } } } }`)},
		{name: "flex block-named range", kind: "flex", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range { R { byte-offset 9; then discard; } } } } } } } }`)},
		{name: "flex inet6 flat", kind: "flex", family: "inet6", filter: "F", term: "T", tree: flat(
			"set firewall family inet6 filter F term T from flexible-match-range range R byte-offset 9",
			"set firewall family inet6 filter F term T from flexible-match-range range R then discard")},
		{name: "flex flat after a field value", kind: "flex", family: "inet", filter: "F", term: "T", tree: flat(
			"set firewall family inet filter F term T from flexible-match-range range R match-value 0x11 then discard")},
		{name: "flex packed term with a body", kind: "flex", family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T from flexible-match-range range R { byte-offset 9; then discard; } } } }`)},
		{name: "N1 packed term", kind: "packed", token: "is-fragment", lenientAction: "discard",
			family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T from is-fragment then discard; term allow { then accept; } } } }`)},
		{name: "packed term with a then block", kind: "packed", token: "is-fragment", lenientAction: "discard",
			family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T from is-fragment { then discard; } } } }`)},
		{name: "packed term reject inet6", kind: "packed", token: "is-fragment", lenientAction: "reject",
			family: "inet6", filter: "F", term: "T",
			tree: hier(`firewall { family inet6 { filter F { term T from is-fragment then reject; } } }`)},
		{name: "flex packed term", kind: "packed", token: "flexible-match-range", lenientAction: "discard",
			family: "inet", filter: "F", term: "T",
			tree: hier(`firewall { family inet { filter F { term T from flexible-match-range range R match-value 0x11 then discard; } } }`)},
	}
}

func TestFirewallFusedThenRejected12528(t *testing.T) {
	for _, r := range fusedRows12528() {
		t.Run(r.name, func(t *testing.T) {
			want := want12528(r.kind, r.family, r.filter, r.term, r.token)
			if _, err := CompileConfig(r.tree(t)); err == nil || err.Error() != want {
				t.Fatalf("CompileConfig error = %v\nwant %s", err, want)
			}
			cfg, err := CompileConfigLenient(r.tree(t))
			if err != nil {
				t.Fatalf("lenient compile must boot (#1960): %v", err)
			}
			if got := warnings12528(cfg.Warnings); len(got) != 1 || got[0] != want {
				t.Fatalf("lenient #12528 warnings = %q\nwant [%s]", got, want)
			}
			if got := term12528(t, cfg, r.family, r.filter, r.term).Action; got != r.lenientAction {
				t.Fatalf("lenient action = %q, want historical %q", got, r.lenientAction)
			}
		})
	}
}

// Flat `set ... from is-fragment protocol udp` nests the second match under
// the flag, so the term compiled with no protocol constraint at all.
func TestFirewallFusedThenNestedMatchWasDropped12528(t *testing.T) {
	cfg, err := CompileConfigLenient(flat12528(t,
		"set firewall family inet filter F term T from is-fragment protocol udp",
		"set firewall family inet filter F term T then discard"))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if term := term12528(t, cfg, "inet", "F", "T"); !term.IsFragment || len(term.Protocols) != 0 {
		t.Fatalf("lenient term = {IsFragment:%t Protocols:%v}, want the flag without the nested protocol",
			term.IsFragment, term.Protocols)
	}
}

// The gate does not hide the older, more specific diagnostics on shapes those
// gates already refuse (Review12678 minor 2): the #8437 fused-sibling schema
// error and `from then` on N2, and the #10294 nameless-term error. Since
// #12777 the #12526 pre-walk message fires FIRST for nameless shapes; it
// names the same term and carries the #10294 tag, and the loop below pins
// that first-error text so a future precedence shift is deliberate.
func TestFirewallFusedThenKeepsOlderDiagnostics12528(t *testing.T) {
	n2 := hier12528(t, `firewall { family inet { filter F { term T { from is-fragment then discard; } } } }`)
	if err := SchemaValidate(n2, nil); err == nil || strings.Contains(err.Error(), "#12528") ||
		!strings.Contains(err.Error(), "names a SIBLING statement") || !strings.Contains(err.Error(), "#8437") {
		t.Fatalf("N2 SchemaValidate error = %v, want the #8437 fused-sibling diagnostic", err)
	}
	if _, err := CompileConfig(n2); err == nil || strings.Contains(err.Error(), "#12528") ||
		!strings.Contains(err.Error(), "`from then` is not enforced") {
		t.Fatalf("N2 CompileConfig error = %v, want the `from then` diagnostic", err)
	}
	for _, body := range []string{
		`family inet { filter F { term { T from is-fragment { then { discard; } } } } }`,
		`family inet { filter F { term { T from is-fragment then discard; } } }`,
		`family inet6 { filter F { term { T from is-fragment { then { reject; } } } } }`,
		`family any { filter F { term { T from is-fragment { then { discard; } } } } }`,
		`family inet { filter F { term { T from flexible-match-range range R { byte-offset 9; then { discard; } } } } }`,
		// A nameless body whose own block carries the fused tail: lowering
		// leaves its `from` readable, so only the #10294 hand-off keeps the
		// nameless diagnostic first.
		`family inet { filter F { term { T accept { from { is-fragment then discard; } } } } }`,
	} {
		tree := hier12528(t, "firewall { "+body+" }")
		_, err := CompileConfig(tree)
		if err == nil || strings.Contains(err.Error(), "#12528") ||
			!strings.Contains(err.Error(), "nameless `term` block starting with") ||
			!strings.Contains(err.Error(), "#10294/#12092/#12526") {
			t.Errorf("%s: CompileConfig error = %v, want the #12526 pre-walk nameless diagnostic first", body, err)
		}
		cfg, err := CompileConfigLenient(hier12528(t, "firewall { "+body+" }"))
		if err != nil {
			t.Fatalf("%s: lenient compile: %v", body, err)
		}
		if got := warnings12528(cfg.Warnings); len(got) != 0 {
			t.Errorf("%s: lenient #12528 warnings = %q, want none (the #10294 gate owns nameless terms)", body, got)
		}
	}
}

func TestFirewallFusedThenLenientWarnsEveryTerm12528(t *testing.T) {
	text := `firewall {
    family inet {
        filter F {
            term T { from { is-fragment then discard; } }
            term ok { from { is-fragment; } then discard; }
        }
        filter G {
            term U { from { flexible-match-range { range R { byte-offset 9; then discard; } } } }
        }
    }
    family inet6 {
        filter H { term V from is-fragment then reject; }
    }
}`
	want := []string{
		want12528("then", "inet", "F", "T", ""),
		want12528("flex", "inet", "G", "U", ""),
		want12528("packed", "inet6", "H", "V", "is-fragment"),
	}
	if _, err := CompileConfig(hier12528(t, text)); err == nil || err.Error() != want[0] {
		t.Fatalf("strict error = %v\nwant the first offending term: %s", err, want[0])
	}
	cfg, err := CompileConfigLenient(hier12528(t, text))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if got := warnings12528(cfg.Warnings); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lenient #12528 warnings =\n%s\nwant every offending term:\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// `show configuration | display set` and the LoadMerge replay render the
// hierarchical tree through FormatSetForLoadMerge. A packed spelling that
// compiles with its action replays into the fused shape that loses it; both
// sides are refused, each with the diagnostic for its own shape.
func TestFirewallFusedThenDisplaySetRoundTrip12528(t *testing.T) {
	for _, tc := range []struct {
		name, text      string
		hierWant        string // "" = the hierarchical spelling commits
		setWant         string
		replayedProtos  int
		replayedAction  string
		replayedFlexSet bool
	}{
		{name: "N1 packed term",
			text:     `firewall { family inet { filter F { term T from is-fragment then discard; } } }`,
			hierWant: want12528("packed", "inet", "F", "T", "is-fragment"),
			setWant:  want12528("then", "inet", "F", "T", "")},
		{name: "flex packed term",
			text:            `firewall { family inet { filter F { term T from flexible-match-range range R match-value 0x11 then discard; } } }`,
			hierWant:        want12528("packed", "inet", "F", "T", "flexible-match-range"),
			setWant:         want12528("flex", "inet", "F", "T", ""),
			replayedFlexSet: true},
		{name: "packed from with a second match",
			text:           `firewall { family inet { filter F { term T { from is-fragment protocol udp; then discard; } } } }`,
			setWant:        want12528("token", "inet", "F", "T", "protocol"),
			replayedAction: "discard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := hier12528(t, tc.text)
			_, err := CompileConfig(tree)
			if tc.hierWant == "" && err != nil {
				t.Fatalf("hierarchical spelling must commit: %v", err)
			}
			if tc.hierWant != "" && (err == nil || err.Error() != tc.hierWant) {
				t.Fatalf("hierarchical CompileConfig error = %v\nwant %s", err, tc.hierWant)
			}
			lines := strings.Split(strings.TrimSpace(tree.FormatSetForLoadMerge()), "\n")
			if _, err := CompileConfig(replaySetLines(t, lines)); err == nil || err.Error() != tc.setWant {
				t.Fatalf("replayed %q: CompileConfig error = %v\nwant %s", lines, err, tc.setWant)
			}
			cfg, err := CompileConfigLenient(replaySetLines(t, lines))
			if err != nil {
				t.Fatalf("lenient replay: %v", err)
			}
			term := term12528(t, cfg, "inet", "F", "T")
			if term.Action != tc.replayedAction || len(term.Protocols) != tc.replayedProtos ||
				(term.FlexMatch != nil) != tc.replayedFlexSet {
				t.Fatalf("lenient replayed term = {Action:%q Protocols:%v Flex:%t}, want the loss the gate refuses",
					term.Action, term.Protocols, term.FlexMatch != nil)
			}
		})
	}
}

func TestFirewallFusedThenPositiveControls12528(t *testing.T) {
	type want struct {
		action string
		frag   bool
		flex   bool
		protos string
		dports string
	}
	hier := func(text string) func(*testing.T) *ConfigTree {
		return func(t *testing.T) *ConfigTree { return hier12528(t, text) }
	}
	flat := func(lines ...string) func(*testing.T) *ConfigTree {
		return func(t *testing.T) *ConfigTree { return flat12528(t, lines...) }
	}
	controls := []struct {
		name                 string
		tree                 func(*testing.T) *ConfigTree
		family, filter, term string
		want                 want
	}{
		{"bare is-fragment braced", hier(`firewall { family inet { filter F { term T { from { is-fragment; } then { discard; } } } } }`),
			"inet", "F", "T", want{action: "discard", frag: true}},
		{"bare is-fragment flat", flat("set firewall family inet filter F term T from is-fragment", "set firewall family inet filter F term T then discard"),
			"inet", "F", "T", want{action: "discard", frag: true}},
		{"is-fragment beside protocol", hier(`firewall { family inet { filter F { term T { from { is-fragment; protocol udp; } then discard; } } } }`),
			"inet", "F", "T", want{action: "discard", frag: true, protos: "udp"}},
		{"packed from is-fragment", hier(`firewall { family inet { filter F { term T { from is-fragment; then discard; } } } }`),
			"inet", "F", "T", want{action: "discard", frag: true}},
		{"packed from is-fragment protocol udp", hier(`firewall { family inet { filter F { term T { from is-fragment protocol udp; then discard; } } } }`),
			"inet", "F", "T", want{action: "discard", frag: true, protos: "udp"}},
		{"packed from is-fragment destination-port 53", hier(`firewall { family inet { filter F { term T { from is-fragment destination-port 53; then accept; } } } }`),
			"inet", "F", "T", want{action: "accept", frag: true, dports: "53"}},
		{"term named is-fragment", hier(`firewall { family inet { filter F { term is-fragment { from { is-fragment; } then { discard; } } } } }`),
			"inet", "F", "is-fragment", want{action: "discard", frag: true}},
		{"term named is-fragment flat", flat("set firewall family inet filter F term is-fragment from is-fragment", "set firewall family inet filter F term is-fragment then discard"),
			"inet", "F", "is-fragment", want{action: "discard", frag: true}},
		{"term named is-fragment quoted", hier(`firewall { family inet { filter F { term "is-fragment" { from { is-fragment; } then { discard; } } } } }`),
			"inet", "F", "is-fragment", want{action: "discard", frag: true}},
		{"term named is-fragment inet6", hier(`firewall { family inet6 { filter F { term is-fragment { from { is-fragment; } then { discard; } } } } }`),
			"inet6", "F", "is-fragment", want{action: "discard", frag: true}},
		{"filter named is-fragment", hier(`firewall { family inet { filter is-fragment { term T { from { protocol udp; } then { discard; } } } } }`),
			"inet", "is-fragment", "T", want{action: "discard", protos: "udp"}},
		{"filter named is-fragment flat", flat("set firewall family inet filter is-fragment term T from protocol udp", "set firewall family inet filter is-fragment term T then discard"),
			"inet", "is-fragment", "T", want{action: "discard", protos: "udp"}},
		{"filter named is-fragment inet6", hier(`firewall { family inet6 { filter is-fragment { term T { from { next-header udp; } then { discard; } } } } }`),
			"inet6", "is-fragment", "T", want{action: "discard", protos: "udp"}},
		{"term named flexible-match-range", hier(`firewall { family inet { filter F { term flexible-match-range { from { protocol udp; } then { discard; } } } } }`),
			"inet", "F", "flexible-match-range", want{action: "discard", protos: "udp"}},
		{"term named flexible-match-range flat", flat("set firewall family inet filter F term flexible-match-range from protocol udp", "set firewall family inet filter F term flexible-match-range then discard"),
			"inet", "F", "flexible-match-range", want{action: "discard", protos: "udp"}},
		{"term named flexible-match-range quoted inet6", hier(`firewall { family inet6 { filter F { term "flexible-match-range" { from { next-header udp; } then { discard; } } } } }`),
			"inet6", "F", "flexible-match-range", want{action: "discard", protos: "udp"}},
		{"filter named flexible-match-range flat", flat("set firewall family inet filter flexible-match-range term T from protocol udp", "set firewall family inet filter flexible-match-range term T then discard"),
			"inet", "flexible-match-range", "T", want{action: "discard", protos: "udp"}},
		{"filter named flexible-match-range quoted", hier(`firewall { family inet { filter "flexible-match-range" { term T { from { protocol udp; } then { discard; } } } } }`),
			"inet", "flexible-match-range", "T", want{action: "discard", protos: "udp"}},
		{"term named then", hier(`firewall { family inet { filter F { term then { from { is-fragment; } then { discard; } } } } }`),
			"inet", "F", "then", want{action: "discard", frag: true}},
		{"term named then flat", flat("set firewall family inet filter F term then from is-fragment", "set firewall family inet filter F term then then discard"),
			"inet", "F", "then", want{action: "discard", frag: true}},
		{"prefix-list named is-fragment braced except", hier(`policy-options { prefix-list is-fragment { 10.0.0.0/8; } } firewall { family inet { filter F { term T { from { source-prefix-list { is-fragment except; } } then { discard; } } } } }`),
			"inet", "F", "T", want{action: "discard"}},
		{"prefix-list named is-fragment flat except", flat("set policy-options prefix-list is-fragment 10.0.0.0/8", "set firewall family inet filter F term T from source-prefix-list is-fragment except", "set firewall family inet filter F term T then discard"),
			"inet", "F", "T", want{action: "discard"}},
		{"prefix-list named is-fragment braced destination", hier(`policy-options { prefix-list is-fragment { 10.0.0.0/8; } } firewall { family inet { filter F { term T { from { destination-prefix-list { is-fragment; } } then { discard; } } } } }`),
			"inet", "F", "T", want{action: "discard"}},
		{"range named then flat", flat("set firewall family inet filter F term T from flexible-match-range range then byte-offset 9", "set firewall family inet filter F term T then discard"),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"range named then packed", hier(`firewall { family inet { filter F { term T { from { flexible-match-range range then { byte-offset 9; } } then { discard; } } } } }`),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"range named then block-named", hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range { then { byte-offset 9; } } } } then { discard; } } } } }`),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"range named then flat with match-start", flat("set firewall family inet filter F term T from flexible-match-range range then match-start layer-3", "set firewall family inet filter F term T from flexible-match-range range then byte-offset 9", "set firewall family inet filter F term T then discard"),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"then-first flex", hier(`firewall { family inet { filter F { term T then discard from flexible-match-range range R byte-offset 9; } } }`),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"then-first is-fragment", hier(`firewall { family inet { filter F { term T then discard from is-fragment; } } }`),
			"inet", "F", "T", want{action: "discard", frag: true}},
		{"then-first is-fragment inet6", hier(`firewall { family inet6 { filter F { term T then discard from is-fragment; } } }`),
			"inet6", "F", "T", want{action: "discard", frag: true}},
		{"packed term protocol", hier(`firewall { family inet { filter F { term T from protocol udp then discard; } } }`),
			"inet", "F", "T", want{action: "discard", protos: "udp"}},
		{"packed term is-fragment then protocol", hier(`firewall { family inet { filter F { term T from is-fragment protocol udp then discard; } } }`),
			"inet", "F", "T", want{action: "discard", frag: true, protos: "udp"}},
		{"counter named is-fragment", hier(`firewall { family inet { filter F { term T { from { is-fragment; } then { count is-fragment; discard; } } } } }`),
			"inet", "F", "T", want{action: "discard", frag: true}},
		{"counter named flexible-match-range", hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range R { byte-offset 9; } } } then { count flexible-match-range; discard; } } } } }`),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"policer named is-fragment", hier(`firewall { policer is-fragment { if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; } then discard; } family inet { filter F { term T { from { is-fragment; } then { policer is-fragment; accept; } } } } }`),
			"inet", "F", "T", want{action: "accept", frag: true}},
		{"flex braced", hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range R { match-start layer-3; byte-offset 9; bit-length 8; match-value 0x11; } } } then { discard; } } } } }`),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"flex flat", flat("set firewall family inet filter F term T from flexible-match-range range R match-start layer-3", "set firewall family inet filter F term T from flexible-match-range range R byte-offset 9", "set firewall family inet filter F term T then discard"),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"flex packed from", hier(`firewall { family inet { filter F { term T { from flexible-match-range range R byte-offset 9; then discard; } } } }`),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"flex packed inside braced from", hier(`firewall { family inet { filter F { term T { from { flexible-match-range range R byte-offset 9; } then discard; } } } }`),
			"inet", "F", "T", want{action: "discard", flex: true}},
		{"flex beside is-fragment", hier(`firewall { family inet { filter F { term T { from { flexible-match-range { range R { byte-offset 9; } } is-fragment; } then { discard; } } } } }`),
			"inet", "F", "T", want{action: "discard", frag: true, flex: true}},
	}
	for _, c := range controls {
		t.Run(c.name, func(t *testing.T) {
			if err := SchemaValidate(c.tree(t), nil); err != nil {
				t.Fatalf("SchemaValidate rejected control: %v", err)
			}
			cfg, err := CompileConfig(c.tree(t))
			if err != nil {
				t.Fatalf("CompileConfig rejected control: %v", err)
			}
			term := term12528(t, cfg, c.family, c.filter, c.term)
			got := want{
				action: term.Action,
				frag:   term.IsFragment,
				flex:   term.FlexMatch != nil,
				protos: strings.Join(term.Protocols, ","),
				dports: strings.Join(term.DestinationPorts, ","),
			}
			if got != c.want {
				t.Fatalf("compiled term = %+v, want %+v", got, c.want)
			}
			lenient, err := CompileConfigLenient(c.tree(t))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if w := warnings12528(lenient.Warnings); len(w) != 0 {
				t.Fatalf("lenient compile warned on a valid control: %q", w)
			}
		})
	}
}
