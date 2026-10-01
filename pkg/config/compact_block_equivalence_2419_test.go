package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// ---- value synthesis ------------------------------------------------------

// isValuelessFlag9056 reports whether a schema node is a VALUELESS BOOLEAN FLAG:
// a childless, wildcard-less, non-multi leaf that takes no argument AND declares
// no value metadata of any kind.
//
// The metadata clause is not decoration. `args` is the field that says a leaf
// takes a value, but a hand-built fixture node can declare a valueType, a
// placeholder or a valueHint while leaving `args` at its zero value -- and
// synth_value_hints_8662_test.go is full of exactly those, deliberately, because
// it pins the synthesiser's PATHS rather than the shipped schema. Refusing on
// `args == 0` alone made every one of those cases report "synthPair refused to
// synthesise", which is a claim about this predicate rather than about a flag.
//
// Measured over the shipped schema at 1748e11a2: 511 nodes match the shape and
// ZERO of them declare any value metadata, so the clause changes no verdict on
// real config and only excludes the fixture shape it was added for. One
// predicate is used by BOTH collectCompactSites and synthPair so the population
// and the refusal cannot drift apart -- a flag the census enumerates but
// synthPair still values would get the fixture `allow-dns-reply xpfaaa;`, and a
// flag synthPair refuses but the census does not enumerate would be skipped
// everywhere with no bucket to show for it.
func isValuelessFlag9056(n *schemaNode) bool {
	return n != nil &&
		n.args == 0 && n.wildcard == nil && len(n.children) == 0 && !n.multi &&
		n.valueType == ValueAny && n.validator == nil &&
		n.placeholder == "" && n.valueHint == ValueHintNone &&
		len(n.valueExamples) == 0 && n.valueDesc == ""
}

// synthPair returns two DISTINCT plausible values for a valued leaf. Two are
// needed for the vacuity guard: if the compiled config is identical for both,
// this leaf's value is not observable in the typed config and the cell cannot
// prove anything.
func synthPair(n *schemaNode) (string, string, bool) {
	// #9056: a VALUELESS BOOLEAN FLAG has no value to vary, and this function's
	// contract is two distinct values for a VALUED leaf.
	//
	// Without this it fell through to the `ValueIdentifier, ValueAny` arm --
	// ValueAny is the zero value of valueType, so an undeclared type reads as
	// "any" -- and handed back "xpfaaa"/"xpfbbb". The fixture built from that is
	// `allow-dns-reply xpfaaa;`, which is not a spelling of anything: the
	// compiler's FindChild sees the leaf either way, so both probe values
	// compile alike, the vacuity guard fires, and the site is recorded
	// "leaf value not observable" -- a verdict about the SYNTHESISER, not about
	// the leaf.
	//
	// Returning false instead is what lets the flag shape be enumerated by
	// collectCompactSites without every site-walking consumer inheriting a
	// meaningless fixture: they skip on !ok exactly as they did when the shape
	// was outside the population, and the two censuses that CAN rule on a flag
	// (runCompactBlockCensus and the scope-safety guards) branch on
	// compactSite.flag and use PRESENCE as the discriminator instead.
	if isValuelessFlag9056(n) {
		return "", "", false
	}
	// #8662: a folded token that is a WILDCARD-NAMED container carries no leaf
	// value of its own — the token after it is the INSTANCE NAME, and that is
	// what the compact spelling packs onto the parent. Vary the name.
	//
	// This is the shape `security-zone <z> interfaces <if>` uses, and it is why
	// that site was invisible to this census even after #8679 widened the
	// predicate to children-bearing tokens: `interfaces` declares args:0 and a
	// wildcard, so neither the old `args == 1` clause nor a leaf-value
	// synthesiser could reach it.
	if n.args == 0 && n.wildcard != nil {
		w := n.wildcard
		if len(w.valueExamples) >= 2 {
			return w.valueExamples[0], w.valueExamples[1], true
		}
		if w.valueHint == ValueHintInterfaceName {
			return "ge-0/0/0.0", "ge-0/0/1.0", true
		}
		return "xpfia", "xpfib", true
	}
	if len(n.valueExamples) >= 2 {
		return n.valueExamples[0], n.valueExamples[1], true
	}
	// #8662 fixture sweep: a leaf that declares no examples used to fall
	// straight through to the invented pair "xpfaaa"/"xpfbbb". Many leaves
	// REJECT that — `unit xpfaaa` is not a unit number — so BOTH spellings
	// compiled to nothing, the vacuity guard fired, and the site was recorded
	// "leaf value not observable". That verdict was about the FIXTURE, not the
	// leaf, and it made 103 sites unrulable.
	//
	// The schema already says what these leaves take. valueHint is the
	// strongest signal and is what `?` completion uses, so synthesising from it
	// costs nothing and cannot drift from the schema's own idea of the value.
	switch n.valueHint {
	case ValueHintUnitNumber:
		return "0", "1", true
	case ValueHintInterfaceName:
		return "ge-0/0/0.0", "ge-0/0/1.0", true
	case ValueHintZoneName:
		return "xpfzonea", "xpfzoneb", true
	case ValueHintAddressName, ValueHintPolicyAddress:
		return "xpfaddra", "xpfaddrb", true
	case ValueHintAppName, ValueHintPolicyApp:
		return "xpfappa", "xpfappb", true
	case ValueHintAppSetName:
		return "xpfapsa", "xpfapsb", true
	case ValueHintPolicyName:
		return "xpfpola", "xpfpolb", true
	case ValueHintPoolName:
		return "xpfpoola", "xpfpoolb", true
	case ValueHintScreenProfile:
		return "xpfscra", "xpfscrb", true
	case ValueHintStreamName:
		return "xpfstra", "xpfstrb", true
	}
	// A numeric-looking placeholder (`<n>`, `<0..128>`, `<seconds>`) means the
	// invented identifier will be rejected. Prefer two small integers.
	//
	// #8690 — DO NOT "FIX" THE `id` TEST TO A WORD BOUNDARY. It matches `id` as
	// a SUBSTRING, so `<provider-name>` (prov-ID-er), `<identity>` and
	// `<bandwidth>` get numeric probes as well as `<uid>` and `<vlan-id>`. That
	// reads as a defect and was measured as a fix: bounding `id` to a whole
	// token made the census measure LESS — checked 699 -> 697, not-observable
	// 236 -> 238. Two sites are observable ONLY because the loose match hands
	// them a number.
	//
	// A heuristic that is wrong for the right reason can be right in effect.
	// Recorded here rather than only in an issue comment because the next
	// reader will find the substring match before they find the measurement.
	if ph := strings.ToLower(n.placeholder); ph != "" {
		if strings.ContainsAny(ph, "0123456789") ||
			strings.Contains(ph, "number") || strings.Contains(ph, "count") ||
			strings.Contains(ph, "seconds") || strings.Contains(ph, "priority") ||
			strings.Contains(ph, "weight") || strings.Contains(ph, "cost") ||
			strings.Contains(ph, "metric") || strings.Contains(ph, "id") {
			return "1", "2", true
		}
	}
	// #8690: an ENUM leaf that declares only one example. The schema knows the
	// rest of the set — it is inside the ValidateEnum closure — and the closure
	// NAMES it when it rejects. See enumPairFromValidator.
	if v1, v2, ok := enumPairFromValidator(n); ok {
		return v1, v2, true
	}
	switch n.valueType {
	case ValueInteger:
		return "1", "2", true
	case ValueIPAddress:
		return "192.0.2.1", "192.0.2.2", true
	case ValueCIDR:
		return "192.0.2.0/24", "198.51.100.0/24", true
	case ValueBool:
		return "true", "false", true
	case ValueIdentifier, ValueAny:
		return "xpfaaa", "xpfbbb", true
	case ValueCryptHash:
		return `"$6$salt$aaa"`, `"$6$salt$bbb"`, true
	case ValueMAC:
		return "02:00:00:00:00:01", "02:00:00:00:00:02", true
	case ValuePCIAddr:
		return "0000:09:00.0", "0000:0a:00.0", true
	// #8690: three declared types the switch did not cover, so six leaves fell
	// through to the one-example bailout below and were recorded "no two
	// distinct synthesizable values" — a verdict about this function, not about
	// the leaf. Each is synthesizable from its own declared type.
	case ValueHostname:
		return "xpfa.example.com", "xpfb.example.com", true
	case ValueDate:
		return "2026-03-01", "2026-03-31", true
	case ValueUnixSocketPath:
		return "/run/xpf/xpfa.sock", "/run/xpf/xpfb.sock", true
	}
	if len(n.valueExamples) == 1 {
		return "", "", false // one example, cannot vary
	}
	return "", "", false
}

// enumPairFromValidator recovers an enum leaf's accepted set from the leaf's
// OWN validator, for the #8690 unruled-fixture sweep.
//
// Five sites sat in "no two distinct synthesizable values" while their schema
// plainly knew a second value: `system services {dhcp,dhcpv6}-local-server
// dynamic-dns backend` (rfc2136 | kea-d2), `system services dynamic-dns
// provider <p> backend` (six backends), `system services ssh protocol-version`
// (v1 | v2). Each declares ONE valueExamples entry, and the accepted set lives
// in a ValidateEnum closure that cannot be enumerated.
//
// It does not have to be. ValidateEnum's REJECTION names the whole set —
// "invalid value %q (expected one of: a, b, c)" — so a deliberately invalid
// probe makes the schema state its own answer. That is better than the two
// alternatives:
//
//   - parsing valueDesc prose invents a grammar over free text ("rfc2136
//     [live] | kea-d2 [reserved, not in image]") that would silently produce
//     WRONG values as the wording drifts;
//   - copying the sets into this file duplicates the schema, which is the
//     failure mode every census note in this package is about.
//
// THE PARSE CANNOT PRODUCE A WRONG ANSWER, ONLY NO ANSWER: every candidate it
// extracts is RE-VERIFIED by calling the same validator with it, so a
// mis-parsed token is dropped rather than probed. A leaf whose validator is not
// a ValidateEnum, or whose message shape differs, yields no pair and the site
// stays in its skip bucket — the honest degradation.
func enumPairFromValidator(n *schemaNode) (v1, v2 string, ok bool) {
	if n.valueType != ValueEnumOf || n.validator == nil {
		return "", "", false
	}
	// A validator is free to dereference the *Config it is handed; this probes
	// with nil because the census has no config at this point. A panic means
	// "this validator cannot answer the question", not a census failure.
	defer func() {
		if recover() != nil {
			v1, v2, ok = "", "", false
		}
	}()
	err := n.validator("\x00xpf-no-such-enum-value", nil)
	if err == nil {
		return "", "", false // accepts anything; not an enumerable set
	}
	const marker = "expected one of: "
	i := strings.Index(err.Error(), marker)
	if i < 0 {
		return "", "", false
	}
	var accepted []string
	for _, cand := range strings.Split(err.Error()[i+len(marker):], ",") {
		cand = strings.TrimSpace(cand)
		cand = strings.TrimSuffix(cand, ")")
		cand = strings.TrimSpace(cand)
		if cand == "" {
			continue
		}
		if n.validator(cand, nil) != nil {
			continue // the parse produced something the gate itself refuses
		}
		accepted = append(accepted, cand)
		if len(accepted) == 2 {
			return accepted[0], accepted[1], true
		}
	}
	return "", "", false
}

// ---- required-sibling context ---------------------------------------------

// contextFor returns statements that must accompany the stanza under test for
// its enclosing object to be REGISTERED in the typed config at all.
//
// Without them the vacuity guard correctly reports "value not observable" and
// the site is skipped — but for the wrong reason: the leaf IS observable, the
// synthesized fixture was just incomplete. `security log stream <n>` is the
// worked example: compiler_security_log.go records the stream only when
// `stream.Host != ""`, so a transport-only fixture compiles to no stream at
// all and BOTH spellings agree on nothing.
//
// This is the generative walk's structural limit: it cannot infer which
// siblings an object requires. Entries are added here as the skip list is
// worked through, and the remaining skip count is REPORTED so the census stays
// an explicit floor rather than a silent one.
func contextFor(parent []string) string {
	return contextForStanza(parent, "")
}

// contextForStanza is contextFor plus the stanza under test, for the #8690
// entries whose required sibling depends on WHICH stanza is being probed.
//
// contextFor keeps its original signature and its original answers: every entry
// added below is gated on a NON-EMPTY stanza, so the six other censuses that
// call contextFor(parent) get byte-identical fixtures to before. Widening a
// shared helper under several in-flight guards is how a census starts measuring
// something nobody asked it to.
func contextForStanza(parent []string, stanza string) string {
	if legacy := legacyContextFor(parent); legacy != "" || stanza == "" {
		return legacy
	}
	switch strings.Join(parent, " ") {

	// #8690 uncompilable-bucket sweep. Everything below was measured from the
	// compiler's own rejection of the generated fixture, not guessed: each
	// entry is the smallest addition that makes `compileText` return a config
	// instead of nil, and the census then rules the site normally.
	//
	// A RE-OPENED BLOCK MERGES, which is what makes parent-level context
	// sufficient for a requirement that lives INSIDE the stanza under test.
	// `probe p1 { test t1 { target ...; } test t1 { destination-port 7; } }`
	// compiles to one test carrying both -- measured before relying on it.

	// `services rpm probe <p> test <t>: target is required` (12 sites).
	case "services rpm probe xpfarg":
		return "test xpfarg { target address 192.0.2.1; } "

	// `services ip-monitoring policy <p>` needs a match, a preferred-route with
	// a next-hop, AND a real rpm probe to reference -- the last one is a
	// sibling of `ip-monitoring` under `services`, out of reach of any
	// parent-level context, which is what preambleFor is for (10 sites).
	case "services ip-monitoring", "services ip-monitoring policy xpfarg",
		"services ip-monitoring policy xpfarg then",
		"services ip-monitoring policy xpfarg then preferred-route",
		"services ip-monitoring policy xpfarg then preferred-route routing-instance xpfarg":
		return ipMonitoringContext8690

	// `firewall three-color-policer <n>` requires a complete rate set, and
	// single-rate / two-rate are MUTUALLY EXCLUSIVE -- so the context depends on
	// which stanza is under test, which is why this function takes the stanza
	// (9 sites).
	case "firewall three-color-policer xpfarg":
		if stanza == "two-rate" {
			return "two-rate { committed-information-rate 1m; committed-burst-size 1k; " +
				"peak-information-rate 2m; peak-burst-size 2k; } "
		}
		return "single-rate { committed-information-rate 1m; committed-burst-size 1k; " +
			"excess-burst-size 1k; } "

	// `security nat source pool <p> port deterministic` needs a host address, a
	// block size, and (from the preamble) a pool address range to cut blocks
	// out of (2 sites).
	case "security nat source pool xpfarg port":
		return "deterministic { host address 10.0.0.0/24; block-size 64; } "
	case "security nat source pool xpfarg port deterministic":
		return "host address 10.0.0.0/24; block-size 64; "
	}
	return ""
}

// legacyContextFor holds the entries that predate #8690, so both entry points
// answer them identically.
func legacyContextFor(parent []string) string {
	switch strings.Join(parent, " ") {
	case "security log stream xpfarg":
		return "host 192.0.2.10; "
	}
	return ""
}

// ipMonitoringContext8690 is shared by every ip-monitoring site because the
// policy's requirements are checked as a whole: a match, and at least one
// then-preferred-route route carrying a next-hop.
const ipMonitoringContext8690 = "match { rpm-probe r1; } then { preferred-route { " +
	"route 10.9.9.0/24 { next-hop 192.0.2.254; } } } "

// preambleFor returns top-level scaffolding placed BEFORE the site's own text,
// for a requirement that lives outside the site's own container tree (#8690).
//
// contextFor can only reach inside the innermost parent. Two classes of
// requirement are not there:
//
//   - `services ip-monitoring policy <p> match rpm-probe <r>` must name a probe
//     configured under `services rpm`, a SIBLING of ip-monitoring;
//   - `security policies ... policy <p> scheduler-name <s>` must name a
//     scheduler configured under the top-level `schedulers` stanza;
//   - `security nat source pool <p> port deterministic` needs the POOL to carry
//     an address range, a sibling of `port`.
//
// Top-level blocks re-open and merge exactly as inner ones do, so a preamble
// naming the same containers adds to the site's fixture rather than replacing
// it.
func preambleFor(parent []string, stanza string) string {
	joined := strings.Join(parent, " ")
	switch {
	case strings.HasPrefix(joined, "services ip-monitoring"):
		return "services { rpm { probe r1 { test t1 { target address 192.0.2.1; } } } } "
	case strings.HasPrefix(joined, "security nat source pool xpfarg"):
		return "security { nat { source { pool xpfarg { address 203.0.113.0/24; } } } } "
	case joined == "security policies global" ||
		strings.HasPrefix(joined, "security policies from-zone"):
		if stanza == "policy xpfarg" {
			return "schedulers { scheduler xpfaaa { start-time \"08:00:00\"; " +
				"stop-time \"17:00:00\"; } scheduler xpfbbb { start-time \"08:00:00\"; " +
				"stop-time \"17:00:00\"; } } "
		}
	}
	return ""
}

// ---- text construction ----------------------------------------------------

// nest renders `a { b { c { <inner> } } }` for path [a b c].
func nest(path []string, inner string) string {
	if len(path) == 0 {
		return inner
	}
	return path[0] + " { " + nest(path[1:], inner) + " }"
}

func compileText(t *testing.T, text string) *Config {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		return nil
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		return nil
	}
	cfg.Warnings = nil
	return cfg
}

func cfgEqual(a, b *Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	return reflect.DeepEqual(a, b)
}

// ---- the walk -------------------------------------------------------------

type compactSite struct {
	container []string // token path of the enclosing container
	leaf      string
	node      *schemaNode
	// flag marks a VALUELESS BOOLEAN LEAF -- args:0, no wildcard, no children
	// (`allow-dns-reply;`, `tcp-rst;`, `no-syn-check;`). #9056.
	//
	// It exists because such a leaf has no VALUE to vary, and every probe in
	// this file was built around varying one. synthPair needs two distinct
	// values and a flag has none, so the discriminator for a flag site is
	// PRESENCE: `stanza { flag; }` against `stanza { }`. Same question -- does
	// the elided spelling reach the compiler -- asked with the only axis the
	// shape offers.
	flag bool
}

// A site is compactable when the innermost container is EITHER a plain keyword
// stanza (`authentication`, `transport`) OR a NAMED INSTANCE
// (`interface ge-0/0/0.0`, `user ops`, `stream audit`).
//
// This census previously excluded named instances, on the stated premise that
// collapsing one "produces a node the compiler cannot recognise as that named
// instance at all". That premise was WRONG, and wrong in the direction that
// hides defects. It was generalized from a single probe — `interfaces {
// ge-0/0/0 description hello; }`, which really does compile to zero interfaces
// — to every named instance in the schema. Measured on the rest:
//
//	interface ge-0/0/0.0 { cost 10; }        -> ifaces=1 cost=10
//	interface ge-0/0/0.0 cost 10;            -> ifaces=1 cost=0     <- recognised, body dropped
//
// The instance IS recognised; only its body is lost. That is strictly worse
// than not recognising it, because the half-built object reaches the renderer
// and the runtime: `show configuration` displays what the operator wrote, the
// interface binds normally, and it enforces nothing. #7653 is the same shape
// two levels deep, where the dropped body is OSPF authentication.
//
// So the exclusion was hiding ~169 sites of the same class the census exists to
// count. Removing it is not a scope change; it is a correction.

func collectCompactSites() []compactSite {
	var out []compactSite
	seen := map[string]bool{}
	var walk func(n *schemaNode, path []string, depth int)
	walk = func(n *schemaNode, path []string, depth int) {
		if n == nil || depth > 7 {
			return
		}
		names := make([]string, 0, len(n.children))
		for name := range n.children {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			ch := n.children[name]
			if ch == nil {
				continue
			}
			// #8662: the `children == nil` clause that used to sit here made
			// this census blind to an entire class, and blind SILENTLY — those
			// sites were never enumerated, so they appeared in no skip bucket
			// and the "the census is a FLOOR" note did not account for them.
			//
			// A folded token that declares children is still foldable. Two
			// shapes hit it, and #8662 verified both by hand:
			//
			//	class-of-service { schedulers be transmit-rate 1g; }
			//	  -> transmit-rate has children exact/percent/remainder,
			//	     declared (per its own comment) "purely so
			//	     `set ... transmit-rate ?` surfaces them". Compiled: braced
			//	     125000000, elided 0.
			//	security { zones { security-zone trust interfaces ge-0/0/0.0; } }
			//	  -> `interfaces` is a nested named-instance container.
			//	     Compiled: braced [ge-0/0/0.0], elided [] — and the elided
			//	     form walks past the strict gate that rejects the braced one
			//	     for an undefined interface, so the zone boots with no
			//	     members on a commit that reported success.
			//
			// Declaring children for `?` completion is not a statement about
			// whether the compiler reads a folded tail, so predicating the
			// census on it excluded sites for a reason unrelated to the
			// property being measured.
			// #8662 second half: admit the WILDCARD-NAMED container shape
			// alongside the arg-valued one. `interfaces` under a security-zone
			// is args:0 with a wildcard for the interface name, so it was
			// outside the site model even after the children-bearing widening
			// — the model assumed an instance is named by an `args` token.
			//
			// Measured alone, as its own variable: 15 sites, 9 under groups,
			// 1 uncompilable, 3 not-observable, 1 EQUIVALENT
			// (`chassis cluster redundancy-group <n> ip-monitoring family inet`,
			// read correctly in both spellings) and 1 DIVERGENT — the zone
			// member this issue was filed on.
			wildcardNamed := ch.args == 0 && ch.wildcard != nil
			// A THIRD SHAPE: an ARG-NAMED container that ALSO carries a
			// wildcard body. `system syslog file <name>` is args:1 for the file
			// name, PLUS a wildcard for the open-ended facility keyword, PLUS
			// modifier children -- so it satisfies NEITHER clause above. Not a
			// bare valued leaf (it has children); not a wildcard-NAMED
			// container (its instance comes from args, not the wildcard, and
			// every existing branch requires wildcard == nil).
			//
			// THE BLINDNESS WAS SILENT AND IT DISARMED A DIFFERENT GUARD. These
			// pairs produced NO census site, so when #8943/#8957 admitted
			// `syslog file` / `host` / `user` to the elision scope, the standing
			// empty-equivalence verification -- the rule this pass requires
			// before ANY admission -- passed over all three by examining
			// nothing. Green, and about nothing.
			//
			//	sites for pair (syslog, <leaf>)   before 0   after 6
			//
			// #8852 offers two remedies, "fix the census or the classifier".
			// #8957 took the classifier branch and registered the three as
			// `named-container`, which is legitimate by that guard's text and
			// correctly diagnosed the shape. It leaves the verification
			// vacuous, which is a different thing from being wrong. This takes
			// the census branch, so the rule examines them instead.
			//
			// BOUNDED, AND MEASURED BEFORE WIDENING A SHARED INSTRUMENT:
			// exactly six schema nodes carry this shape -- the three syslog
			// destinations and their `groups` mirrors. No other container in
			// the schema is arg-named with a wildcard body, so this is three
			// containers wide rather than a re-baselining of every lane's
			// population.
			argNamedWithBody := ch.args >= 1 && ch.wildcard != nil
			// #9056: THE FOURTH SHAPE, and the one whose exclusion was the most
			// completely silent -- a VALUELESS BOOLEAN FLAG.
			//
			//	args == 0 && wildcard == nil && children == nil
			//
			// `allow-dns-reply;`, `security-zone <z> tcp-rst;`, `tcp-session
			// no-syn-check;`. Every clause above requires either an `args` token
			// or a wildcard, so a flag satisfies NONE of them: it was never
			// enumerated, appeared in no skip bucket, and its absence was
			// indistinguishable from a clean verdict. Measured at the time of
			// this widening: 511 flag sites in the schema, of which 93 DIVERGE.
			//
			// The exclusion was not a scope decision. It is an artefact of the
			// site model having been built around synthPair, which needs two
			// distinct VALUES -- so the shape that has no value at all fell out
			// of the population rather than out of a bucket. The discriminator
			// for these sites is PRESENCE, and runCompactBlockCensus supplies
			// it; see compactSite.flag.
			flagLeaf := isValuelessFlag9056(ch)
			if (ch.wildcard == nil && ch.args == 1 || wildcardNamed || argNamedWithBody || flagLeaf) && len(path) >= 1 {
				key := strings.Join(path, "/") + "|" + name
				if !seen[key] {
					seen[key] = true
					out = append(out, compactSite{
						container: append([]string(nil), path...), leaf: name, node: ch,
						flag: flagLeaf,
					})
				}
			}
			elem := name
			for i := 0; i < ch.args; i++ {
				elem += " xpfarg"
			}
			np := append(append([]string(nil), path...), elem)
			walk(ch, np, depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, append(append([]string(nil), path...), "xpfname"), depth+1)
		}
	}
	walk(setSchema, nil, 0)
	return out
}

// ---- the gate --------------------------------------------------------------

// inventoryPath records the sites that are KNOWN to drop the compact spelling
// today. It is a checked-in expected-failure list, not a suppression: the gate
// asserts the divergent set EQUALS it, so a NEW compact-blind reader reds the
// suite, and a site that gets FIXED without updating the file reds it too.
const inventoryPath = "testdata/compact_block_divergences_2419.txt"

// filedFixed is HALF of the positive control: sites that were filed as
// compact-blind, were verified by hand, and have since been FIXED. The
// instrument must now find them EQUIVALENT.
//
// These four were the original control. The first version of this instrument
// found only 2 of the 4 — args rendered as their own nesting level hid one, and
// a fixture missing a required sibling hid the other — which is why they were
// asserted present by construction rather than trusted.
//
// Fixing them would ordinarily END the control, and an instrument with no
// known-true anchor reports "clean" for the same reason the textual sweeps did.
// So they change SIDES rather than leaving: an instrument that cannot see a
// repaired site is as broken as one that cannot see a defective one, and only a
// control with both directions can tell the two apart.
var filedFixed = map[string]string{
	"protocols ospf area xpfarg interface xpfarg authentication simple-password":         "#6818",
	"snmp v3 usm local-engine user xpfarg authentication-sha256 authentication-password": "#6822",
	// #6821 moved here from filedByDesign rather than being deleted. Its
	// blocker -- the gate not validating a container's packed tail -- was
	// removed by the `packedTail` opt-in, so the divergence is fixed rather
	// than deliberate. Deleting the lines instead would stop the site being
	// checked in EITHER direction, which is the stale-allowlist failure this
	// file exists to prevent.
	"security log stream xpfarg transport protocol":    "#6821",
	"security log stream xpfarg transport tls-profile": "#6821",
	// #8933 moved the eight `policy-options policy-statement <p> term <t> then
	// <action>` sites here from the inventory, and this one from
	// filedStillOpen, rather than deleting them: a site dropped from both maps
	// stops being checked in EITHER direction. This anchor is the one whose
	// retirement from filedStillOpen is explained in full below.
	"policy-options policy-statement xpfarg term xpfarg then local-preference": "#8933",
	// #8690 family 3 moved this here from filedStillOpen rather than deleting
	// it, for the same reason #6821 moved its two: a site dropped from both
	// maps stops being checked in EITHER direction, and the anchor's value is
	// that it keeps being checked after it is fixed. The class-of-service
	// classifier binding is now normalized, so the instrument must report it
	// CLEAN -- and if a future change re-breaks it, this entry is what says so.
	"class-of-service interfaces xpfarg classifiers dscp":                                 "#8690",
	"protocols ospf area xpfarg interface xpfarg bfd-liveness-detection minimum-interval": "#8690",
	// #11314's scalar global router-id is consumed by routing-options. The
	// compact inventory found its brace-elided leaf was dropped; normalization
	// now preserves the compiled value, and this fixed anchor keeps that repair
	// checked in both directions.
	"routing-options router-id": "#11314",
}

// filedByDesign is the category the inventory did not previously distinguish:
// sites that diverge DELIBERATELY, where compiling the compact spelling would
// reverse a decision someone made on purpose.
//
// Without this, a stale inventory line and a considered design decision look
// identical -- both are "a site that diverges" -- and the next person to work
// through the list has no way to tell that fixing one of them undoes #6662.
//
// `system login user ... authentication <leaf>` is the whole of it today. The
// compact spelling is REJECTED at commit by the #6662 packed-login-body gate,
// which names the rewrite. On the tolerant load / peer-sync path it is a
// warning and the stanza stays inert -- deliberately, so a peer-synced config
// behaves exactly as the binary that accepted it behaved (#1960). Compiling the
// value there would change RBAC across an HA sync, silently, on nodes that
// disagree about the binary version.
//
// So #6817, filed as "silently drops the credential", describes a state that no
// longer exists: it is neither silent (commit names it, load warns) nor
// accidental.
var filedByDesign = map[string]string{
	// #6821's two transport leaves USED to sit here, blocked on the strict gate
	// learning to validate a container's packed tail. That blocker is gone: the
	// schema node now sets `packedTail: true`, walkSchemaNode validates the same
	// expansion `packedBodyChildren` hands the compiler, and the #3350
	// tls-profile check reads it too -- so the compact spelling is validated,
	// compiled and rejected exactly as the block spelling is. This tripwire
	// firing is what said the decision had been reversed; see
	// security_log_transport_compact_6821_test.go.

	"system login user xpfarg authentication encrypted-password": "#6817 -> resolved by #6662",
	"system login user xpfarg authentication ssh-ed25519":        "#6817 -> resolved by #6662",
	"system login user xpfarg authentication ssh-rsa":            "#6817 -> resolved by #6662",
	"system login user xpfarg authentication ssh-dsa":            "#6817 -> resolved by #6662",
}

// filedStillOpen is the OTHER half: sites verified BY HAND to be compact-blind
// at this commit, which the instrument must still find.
//
// Membership here is not "it appears in the inventory" — the inventory is what
// this control exists to check. Each was confirmed by reading the compiler:
// each reads only prop.Children (or FindChild, which searches only children) for
// a value the compact spelling puts on the stanza's own Keys.
var filedStillOpen = map[string]string{
	// #8690 family 4 REPLACED the LACP anchor that used to sit here, and the
	// replacement is chosen to end the recurrence rather than to postpone it.
	//
	// The old anchor was an `empty` site, and an `empty` site is BY DEFINITION
	// a candidate for the next widening — so it was consumed the moment its own
	// family was normalized, and any `empty` replacement would be consumed by
	// whoever takes the next one. lane-8015 lost the same control twice for
	// exactly this reason and diagnosed it: re-anchor to a PARTIAL site, which
	// TestNormalizerScopeNeverCoversAPartialSite8690 forbids ANY scope from
	// covering. The control becomes structurally immune to the sweep instead of
	// needing a new hand-verification every increment.
	//
	// Verified by reading the compiler, which is what membership here requires:
	// compileInterfaces skips `if child.IsLeaf { continue }` at
	// compiler_interfaces.go:31, and the compact `ge-0/0/0 mtu 9000;` IS a leaf
	// (Keys ["ge-0/0/0","mtu","9000"]). So the whole INSTANCE is dropped, not
	// just the value — measured: the braced spelling compiles mtu=9000 and the
	// compact one compiles no interface at all.
	//
	// It also keeps the property the swap must preserve: a different compiler
	// file from the other anchor below (compiler_protocols.go).
	"interfaces xpfname mtu": "compiler_interfaces.go:31",
	// #8690 family 4 replaced the ospf anchor family 3 put here, which family 4
	// then normalized -- the SECOND anchor in this map to be invalidated by the
	// next family to land. That churn was the anchor's fault, not the sweep's:
	// both previous choices were `empty` sites, and an `empty` site is by
	// definition a candidate for the next widening.
	//
	// This one is chosen to be DURABLE rather than convenient. It is a site
	// whose drop shape is "partial", which means something already consumes
	// part of its tail -- so TestNormalizerScopeNeverCoversAPartialSite8690
	// FORBIDS any scope from covering it. It cannot be normalized by a family
	// sweep, so it stays divergent for as long as the partial rule holds, and
	// the control stops needing a new anchor every increment.
	//
	// compiler_routing.go:1073-1083 -- the policy `then` arm walks
	// `for _, ac := range tc.Children` and switches on the action name, so a
	// compact `then local-preference 200;` leaves the value on the `then`
	// node's own Keys and never reaches the switch. Different compiler file
	// from the LACP anchor above, which is the property this second entry
	// exists to provide.
	// #8933 RETIRED the `then local-preference` anchor that stood here, and the
	// reason it had to go is a correction to the argument that put it here.
	//
	// It was chosen to be DURABLE on the premise that a "partial" site is
	// structurally immune to a family sweep, because
	// TestNormalizerScopeNeverCoversAPartialSite8690 forbids any scope from
	// covering one. THAT PREMISE IS FALSE, and #8933 is the counterexample: a
	// site is "partial" when the elided form compiles to something non-empty,
	// i.e. when SOMETHING CONSUMED PART OF THE TAIL -- but that consumer can be
	// the DEFECT rather than a legitimate reader. For `then <action>` the
	// compiler packed the action name into PolicyTerm.Action, which is exactly
	// the corruption #8933 fixes. Admitting the pair removes the consumer, the
	// site becomes equivalent, and the "immune" anchor is consumed like the two
	// `empty` anchors before it. Third anchor in a row invalidated by the next
	// family to land, and this one was picked expressly to end that churn.
	//
	// THE PROPERTY THAT ACTUALLY HOLDS is the one the first anchor above has
	// and nobody wrote down: its container slot is an ARG PLACEHOLDER. The
	// normalizer's predicate is keyed on a (container keyword, head) pair, and
	// production calls it with `node.Keys[0]` -- which for these sites is an
	// arbitrary INSTANCE NAME (`ge-0/0/0`, `bd1`), not a keyword. No static
	// pair can name it, so no ADMISSION can reach it. That is a permanent bound
	// of the predicate (#8921), not a contingent classification.
	//
	// #8932 NARROWED WHAT THAT BUYS, and the correction is mine. I wrote that
	// this was "the only durability argument on offer that a later fix cannot
	// dissolve". The bound is real and the inference was one step too wide: it
	// says no PAIR-KEYED admission can reach the site, and says nothing about
	// the other two remedies.
	//
	//	packedStatements     declared on a NODE, not keyed on a pair -- not
	//	                     subject to this bound at all. Measured on
	//	                     bridge-domains: it does NOT fix that site, but for
	//	                     an unrelated reason (the compiler skips the leaf
	//	                     before any run-splitting happens), not because the
	//	                     bound stopped it.
	//	a compiler change    reaches anything.
	//
	// So an instance-name slot makes an anchor durable against the sweep that
	// consumed the previous three, and NOT against a fix aimed at the site. If
	// #8932's bridge-domains row is ever fixed, this anchor goes with it and
	// becomes the fourth. The honest statement is that this is the most durable
	// argument available, not an argument that cannot be dissolved.
	//
	// Verified by reading the compiler, which is what membership here requires:
	// compiler_services.go:2404 reaches the value with
	// `child.FindChild("routing-interface")`, and the compact spelling
	// `bd1 routing-interface irb.100;` is a LEAF whose Keys are
	// ["bd1","routing-interface","irb.100"] -- there is no child to find, so
	// the value is dropped entirely.
	//
	// It also keeps the property the swap must preserve: a THIRD compiler file
	// (compiler_services.go), distinct from the compiler_interfaces.go anchor
	// above and from the compiler_routing.go anchor it replaces.
	"bridge-domains xpfname routing-interface": "compiler_services.go:2404",
}

type censusResult struct {
	divergent []string
	checked   int
	skipped   map[string]int
	// dropShape records, for each DIVERGENT site, what the compact spelling
	// actually produced:
	//
	//	"empty"   the compiled config is identical to the stanza with an EMPTY
	//	          body — the folded value contributed nothing at all.
	//	"partial" it differs from both the block form and the empty stanza —
	//	          something was read, but not what was written.
	//
	// #8662: this is the distinction a normalizer increment needs per SITE, and
	// it used to exist only in a scratch probe. Recording it in the census, and
	// emitting it into the inventory, means a lane widening the normalizer
	// checks the shape of the site it is about to touch instead of inferring it
	// from the family the site belongs to.
	//
	// It is also the safety rule made checkable: a site is only safe to
	// normalize by truncating its tail once the tail is measured to reach no
	// reader, and "empty" IS that measurement. "partial" means something DOES
	// consume it, so truncating could take away a value that is currently
	// being read.
	dropShape map[string]string
	// state records the outcome for EVERY site the census considered:
	// "equivalent", "divergent", or a skip reason.
	//
	// Without it, "not in the divergent set" conflates three different things
	// -- the site was equivalent, the site was skipped, or the site does not
	// exist under that spelling at all. The filedFixed control asserted only
	// absence from the divergent set, so an anchor whose fixture stopped
	// PARSING, or whose key was quietly misspelled, passed as "fixed". That is
	// a check failing to a value indistinguishable from healthy.
	state map[string]string

	// unobservedClass sub-classifies the "leaf value not observable" bucket
	// (#8690). That bucket is the largest by far and the census's own note
	// called every member "a site whose synthesized fixture was too thin" —
	// which is true of five of them and false of the other 231. Counting the
	// three cases separately is the difference between a fixture backlog and a
	// set of leaves nothing reads.
	unobservedClass map[string]int
}

// The three answers to "why did changing the value change nothing?", in the
// order a reader should rule them out.
const (
	// unobservedNothingRegistered: the whole fixture compiles to an EMPTY
	// config. This is the case the census note describes — the stanza never
	// registered, so of course the leaf is invisible. A contextFor /
	// preambleFor entry addresses it.
	unobservedNothingRegistered = "nothing registered (fixture too thin)"
	// unobservedLeafIgnored: the stanza registered and compiles IDENTICALLY to
	// its own empty skeleton. The fixture is fine; the compiler reads the
	// stanza and does not read this leaf — under EITHER spelling, which is why
	// the site cannot be a compact/block divergence. Whether that is a defect
	// (a leaf that commits and does nothing) or correct (a leaf consumed
	// elsewhere, or one needing an in-stanza sibling) is a question about the
	// COMPILER, not about this census.
	unobservedLeafIgnored = "stanza registered, leaf contributed nothing"
	// unobservedOther: something registered and the value still did not vary.
	unobservedOther = "registered, but the value did not vary"
)

// renderInstanceNames fills a container path's INSTANCE-NAME slots from each
// container's own schema declaration, for FIXTURE TEXT ONLY (#8690).
//
// THE CENSUS NAMES EVERY INSTANCE "xpfarg", whatever the container declares its
// name must look like. `unit xpfarg` is not a unit number, so the compiler
// drops the whole unit — and then the leaf under test, its siblings and any
// scaffold inside it are all invisible, which the census records as "leaf value
// not observable". The verdict is about the site MODEL, not the leaf.
//
// Measured: 69 of the 236 not-observable sites become observable with
// schema-derived instance names, and 24 of those are DIVERGENT — sites this
// census could not see at all. They include
// `interfaces <if> unit <u> family inet filter input`, where the brace-elided
// spelling binds NO FILTER, commits clean on the strict path, and emits fewer
// warnings than the correct spelling because there is no binding left to warn
// about.
//
// The site KEY keeps "xpfarg". The key is an identity — the inventory, every
// per-site verdict and three lanes' family lists are keyed on it — and
// re-rendering identities to fix a fixture would rewrite the whole inventory
// for a reason that has nothing to do with what it records.
//
// A slot is only filled when the container's own declaration yields something
// OTHER than the generic identifier, so a container that declares nothing keeps
// the old name and the old behaviour.
func renderInstanceNames(container []string) []string {
	n := setSchema
	out := make([]string, 0, len(container))
	for _, elem := range container {
		fields := strings.Fields(elem)
		if len(fields) == 0 {
			return container
		}
		name := fields[0]
		node := n.children[name]
		if name == "xpfname" || node == nil {
			node = n.wildcard
		}
		if node == nil {
			return container // cannot resolve; leave the path exactly as it was
		}
		rendered := name
		for range fields[1:] {
			v := "xpfarg"
			if iv, _, ok := synthPair(node); ok && iv != "xpfaaa" {
				v = iv
			}
			rendered += " " + v
		}
		out = append(out, rendered)
		n = node
	}
	return out
}

// renderScaffold rewrites a contextForStanza / preambleFor string so its
// instance names match the rendered fixture (#8690).
//
// The scaffolds are written against the CANONICAL path and say things like
// `pool xpfarg { address 203.0.113.0/24; }`. Once the fixture renders that pool
// as `pool xpfpoola`, the scaffold names a DIFFERENT pool and its content lands
// on the wrong object — the site under test goes back to uncompilable, which is
// how TestTheScaffoldedFamiliesAreRuled_8690 caught this.
//
// The substitution is element-wise ("pool xpfarg" -> "pool xpfpoola"), not a
// bare "xpfarg" -> name replacement: a scaffold may mention several containers
// and only the matching one may move.
func renderScaffold(text string, canonical, rendered []string) string {
	if text == "" {
		return text
	}
	for i := range canonical {
		if i >= len(rendered) || canonical[i] == rendered[i] {
			continue
		}
		text = strings.ReplaceAll(text, canonical[i], rendered[i])
	}
	return text
}

func runCompactBlockCensus(t *testing.T) censusResult {
	t.Helper()
	res := censusResult{
		skipped: map[string]int{}, state: map[string]string{},
		dropShape: map[string]string{}, unobservedClass: map[string]int{},
	}
	emptyCfg := compileText(t, "")
	for _, s := range collectCompactSites() {
		siteKey := strings.Join(s.container, " ") + " " + s.leaf
		if len(s.container) > 0 && strings.HasPrefix(s.container[0], "groups") {
			res.skipped["under groups (schema re-host, duplicate coverage)"]++
			res.state[siteKey] = "skipped: under groups"
			continue
		}
		var v1, v2 string
		if !s.flag {
			var ok bool
			v1, v2, ok = synthPair(s.node)
			if !ok {
				res.skipped["no two distinct synthesizable values"]++
				res.state[siteKey] = "skipped: no two distinct synthesizable values"
				continue
			}
		}
		// contextForStanza / preambleFor are keyed on the CANONICAL path (the
		// one carrying "xpfarg"), so existing scaffold entries keep matching;
		// only the fixture TEXT uses the rendered names.
		parent := s.container[:len(s.container)-1]
		stanza := s.container[len(s.container)-1]
		ctx := contextForStanza(parent, stanza)
		pre := preambleFor(parent, stanza)
		rendered := renderInstanceNames(s.container)
		ctx = renderScaffold(ctx, s.container, rendered)
		pre = renderScaffold(pre, s.container, rendered)
		parent = rendered[:len(rendered)-1]
		stanza = rendered[len(rendered)-1]
		blockV1 := pre + nest(parent, ctx+stanza+" { "+s.leaf+" "+v1+"; }")
		blockV2 := pre + nest(parent, ctx+stanza+" { "+s.leaf+" "+v2+"; }")
		compact := pre + nest(parent, ctx+stanza+" "+s.leaf+" "+v1+";")
		if s.flag {
			// #9056: a valueless flag has no second VALUE, so the "b" spelling
			// omits the leaf. The vacuity guard below then reads as "the
			// presence of this flag is not observable in the typed config",
			// which is the same property it asserts for a valued leaf and the
			// only one this shape can express.
			blockV1 = pre + nest(parent, ctx+stanza+" { "+s.leaf+"; }")
			blockV2 = pre + nest(parent, ctx+stanza+" { }")
			compact = pre + nest(parent, ctx+stanza+" "+s.leaf+";")
		}

		cb1, cb2, cc := compileText(t, blockV1), compileText(t, blockV2), compileText(t, compact)
		if cb1 == nil || cb2 == nil || cc == nil {
			res.skipped["a spelling did not parse or compile"]++
			res.state[siteKey] = "skipped: a spelling did not parse or compile"
			continue
		}
		// VACUITY GUARD. If changing the VALUE does not change the compiled
		// config, this cell cannot observe a dropped value and calling it a
		// pass would be meaningless. #6821 sat in this bucket until its
		// required-sibling context line was added — every entry here is an
		// UNRULED candidate, not a clean site.
		if cfgEqual(cb1, cb2) {
			res.skipped["leaf value not observable in the typed config"]++
			res.state[siteKey] = "skipped: leaf value not observable"
			// #8690: say WHICH of the three it is, so the bucket stops reading
			// as one backlog.
			switch skel := compileText(t, pre+nest(parent, ctx+stanza+" { }")); {
			case cfgEqual(cb1, emptyCfg):
				res.unobservedClass[unobservedNothingRegistered]++
			case skel != nil && cfgEqual(cb1, skel):
				res.unobservedClass[unobservedLeafIgnored]++
			default:
				res.unobservedClass[unobservedOther]++
			}
			continue
		}
		res.checked++
		if !cfgEqual(cb1, cc) {
			res.divergent = append(res.divergent, siteKey)
			res.state[siteKey] = "divergent"
			// #8662: classify WHAT the compact spelling produced. The empty
			// stanza is the reference for "the folded value contributed
			// nothing"; anything else means a reader consumed part of it.
			shape := "partial"
			if skel := compileText(t, pre+nest(parent, ctx+stanza+" { }")); skel != nil && cfgEqual(cc, skel) {
				shape = "empty"
			}
			res.dropShape[siteKey] = shape
		} else {
			res.state[siteKey] = "equivalent"
		}
	}
	sort.Strings(res.divergent)
	return res
}

func readInventory(t *testing.T) (sites []string, wantChecked int) {
	t.Helper()
	raw, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if _, err := fmt.Sscanf(line, "# checked: %d", &wantChecked); err == nil {
				continue
			}
			continue
		}
		site, _ := splitInventoryLine(line)
		sites = append(sites, site)
	}
	sort.Strings(sites)
	return sites, wantChecked
}

// splitInventoryLine separates a site from its drop-shape marker.
//
// #8662: inventory lines carry a trailing TAB + shape ("empty" / "partial").
// The gate's equality assertion compares SITES, so the marker is stripped here
// and the assertion's meaning is unchanged — the shape is metadata about a
// member, not part of the membership.
//
// Lines without a marker are accepted so the file stays readable if a marker is
// ever hand-edited away; the shape is then "" and a caller must treat that as
// UNKNOWN rather than as "partial". Defaulting an unknown to either value would
// silently license or forbid a normalization on no evidence.
func splitInventoryLine(line string) (site, shape string) {
	if i := strings.IndexByte(line, '\t'); i >= 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return line, ""
}

// readInventoryShapes returns site -> drop shape for every line that carries a
// marker. Intended for a lane widening the normalizer: check the shape of the
// site you are about to touch rather than inferring it from its family.
func readInventoryShapes(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if site, shape := splitInventoryLine(line); shape != "" {
			out[site] = shape
		}
	}
	return out
}

// TestCompactBlockEquivalenceInventory2419 is the #2419 class gate.
//
// The property: for every config leaf under a PLAIN KEYWORD stanza, the compact
// spelling (`stanza leaf value;` — value on the stanza's own Keys) and the block
// spelling (`stanza { leaf value; }`) must compile to the same typed config. A
// compiler stanza that iterates only prop.Children reads one and silently drops
// the other.
//
// Today 194 sites fail that property. They are recorded in the inventory file
// rather than suppressed, so this gate does three things at once:
//
//   - a NEW compact-blind reader is an unexpected divergence -> RED;
//   - a site FIXED without updating the inventory -> RED, so the file cannot
//     rot into a stale allowlist;
//   - the CHECKED count is a ratchet, so sites cannot silently drain out of the
//     tested population into the skip buckets (which is how an instrument stops
//     measuring while still reporting success).
func TestCompactBlockEquivalenceInventory2419(t *testing.T) {
	res := runCompactBlockCensus(t)
	want, wantChecked := readInventory(t)

	inWant := map[string]bool{}
	for _, s := range want {
		inWant[s] = true
	}
	inGot := map[string]bool{}
	for _, s := range res.divergent {
		inGot[s] = true
	}
	for _, s := range res.divergent {
		if !inWant[s] {
			t.Errorf("#2419: NEW compact-blind site (compact spelling drops the value): %s\n"+
				"    A compiler stanza was added or changed to read only prop.Children.\n"+
				"    Fix the reader, or add the site to %s with a reason.", s, inventoryPath)
		}
	}
	for _, s := range want {
		if !inGot[s] {
			t.Errorf("#2419: %s lists %q as compact-blind, but it now compiles equivalently.\n"+
				"    If you fixed it, REMOVE the line — a stale inventory is an allowlist "+
				"that hides the next regression.", inventoryPath, s)
		}
	}
	// Coverage ratchet.
	if res.checked < wantChecked {
		t.Errorf("#2419: checked-cell coverage DROPPED from %d to %d. Sites moved out of the "+
			"tested population into the skip buckets; the census stops measuring them.",
			wantChecked, res.checked)
	}
	// Anti-vacuity for the control maps themselves.
	//
	// Deleting an entry from any of them is SILENT: the site stays in the
	// inventory, the equality comparison above still passes, and the control
	// simply stops checking it. A control that can be emptied without anything
	// noticing is not a control. These are minimums, not exact counts, so
	// adding an anchor never needs a second edit here -- but draining one out
	// does.
	if len(filedFixed) < 2 {
		t.Errorf("filedFixed holds %d anchors, want at least 2 (#6818, #6822, #6821). "+
			"An entry was removed, and the site it named is no longer checked in "+
			"either direction.", len(filedFixed))
	}
	if len(filedStillOpen) < 2 {
		t.Errorf("filedStillOpen holds %d anchors, want at least 2 from DIFFERENT "+
			"compiler files. With fewer, a fault confined to one file can silence "+
			"the whole known-true half of the control.", len(filedStillOpen))
	}
	if len(filedByDesign) < 4 {
		t.Errorf("filedByDesign holds %d entries, want at least 4 (the four `system "+
			"login user ... authentication` leaves). A dropped entry turns a "+
			"deliberate divergence back into an ordinary inventory line, which is "+
			"exactly the confusion this category exists to prevent.\n"+
			"The floor was 6 until #6821: its two transport leaves were by-design "+
			"divergent only because the gate could not validate a container's "+
			"packed tail. `packedTail` removed that blocker, so they MOVED to "+
			"filedFixed -- a count that falls because a population shrank is the "+
			"fix working, and carrying the old number forward would demand entries "+
			"that should no longer exist.", len(filedByDesign))
	}

	// Positive control, both directions.
	//
	// A one-directional control cannot distinguish a working instrument from one
	// that has silently started reporting every site as divergent (or as clean).
	// Anchoring known-FIXED and known-OPEN sites separately does.
	for site, issue := range filedStillOpen {
		if got := res.state[site]; got != "divergent" && got != "" {
			t.Errorf("#2419 POSITIVE CONTROL: %s (%s) is %s. A known-true anchor that "+
				"drifted into a skip bucket stops proving anything while still not "+
				"appearing as a failure.", site, issue, got)
		}
		if !inGot[site] {
			t.Errorf("#2419 POSITIVE CONTROL: the instrument no longer finds %s (%s), "+
				"a site verified BY HAND to be compact-blind at this commit. An "+
				"instrument that stops finding known-true sites reports clean for the "+
				"same reason a textual sweep does.", site, issue)
		}
	}
	for site, issue := range filedFixed {
		// Require the state to be OBSERVED as equivalent. Asserting only
		// "absent from the divergent set" let an anchor pass by being SKIPPED
		// (a fixture that stopped parsing, a value that stopped being
		// observable) or by not existing at all — a misspelled key is absent
		// from every set, so the size floors alone do not catch it either.
		switch got := res.state[site]; got {
		case "equivalent":
		case "divergent":
			t.Errorf("#2419 POSITIVE CONTROL: the instrument reports %s (%s) as still "+
				"compact-blind, but it was FIXED. Either the fix regressed, or the "+
				"instrument has started calling everything divergent — which would make "+
				"the inventory comparison above pass for the wrong reason.", site, issue)
		case "":
			t.Errorf("#2419 POSITIVE CONTROL: %s (%s) was never CONSIDERED by the census. "+
				"The anchor key does not name a real site — it is absent from the "+
				"divergent set for the wrong reason, and would have passed as 'fixed'.",
				site, issue)
		default:
			t.Errorf("#2419 POSITIVE CONTROL: %s (%s) was %s, not evaluated. A skipped "+
				"site is UNRULED, not fixed; passing it as fixed is exactly the check "+
				"that fails to a value indistinguishable from healthy.", site, issue, got)
		}
	}
	// Deliberate divergences must STAY divergent. This is not a duplicate of the
	// filedStillOpen loop: those are sites awaiting a fix, these are sites where
	// a fix would be a REGRESSION, and a reader working down the inventory needs
	// to be told which is which before they "fix" one.
	for site, issue := range filedByDesign {
		if !inGot[site] {
			t.Errorf("#2419: %s (%s) now compiles the compact spelling, but it is "+
				"divergent BY DESIGN. Compiling it reverses the decision recorded at "+
				"that entry — re-read it before removing this line.", site, issue)
		}
	}
}

// TestCompactBlockCensusReport2419 prints the census. It asserts nothing the
// gate above does not; it exists so the numbers — including the UNRULED skips —
// are visible in `go test -v` output rather than only in a PR body.
func TestCompactBlockCensusReport2419(t *testing.T) {
	res := runCompactBlockCensus(t)
	t.Logf("#2419 compact/block equivalence census")
	t.Logf("  cells CHECKED (vacuity-guarded): %d", res.checked)
	t.Logf("  cells DIVERGENT:                 %d", len(res.divergent))
	keys := make([]string, 0, len(res.skipped))
	for k := range res.skipped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  cells SKIPPED — %-52s %d", k, res.skipped[k])
	}
	t.Logf("  NOTE: the %d 'not observable' skips are UNRULED, not clean. The census "+
		"is a FLOOR.", res.skipped["leaf value not observable in the typed config"])
	// #8690: and they are not one population. This note used to say every one
	// of them was "a site whose synthesized fixture was too thin to observe the
	// value (as #6821 was before its required-sibling context line)". Measured,
	// that describes FIVE of them. The rest register their stanza perfectly
	// well and simply add nothing to it, which is a question about the compiler
	// rather than about the fixture — and a very different piece of work.
	for _, k := range []string{
		unobservedNothingRegistered, unobservedLeafIgnored, unobservedOther,
	} {
		t.Logf("    of which — %-46s %d", k, res.unobservedClass[k])
	}
}
