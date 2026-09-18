package config

import (
	"fmt"
	"strconv"
	"strings"
)

// policerMissingValueSuffix9882 marks an UnknownActions entry that is not an
// unrecognized token but a RECOGNIZED marking action without its value
// (`then { forwarding-class; }`). The entry reads "<action> (missing value)"
// and validateFirewallPolicerUnknownActionsStrict renders it with the
// requires-a-value message instead of the unknown-action one. One channel,
// two presentations: the strict/lenient doctrine and the gate ordering are
// identical either way (malformed `then` input is loud on both paths).
const policerMissingValueSuffix9882 = " (missing value)"

// policerThenExtras9882 returns the tokens a policer `then` action carries
// beyond its declared arity — mirroring thenActionExtras8971 for filter
// terms, including its bounds. Runs on the hoisted siblings, so a token
// naming a DECLARED action was already split into its own statement; what
// remains past the arity is either an unknown token or a value in a slot
// the action does not declare, and both must be loud rather than swallowed.
func policerThenExtras9882(child *Node, container *schemaNode) []string {
	if child == nil || len(child.Keys) < 2 {
		return nil
	}
	if container == nil {
		return nil
	}
	action := resolveSchemaChild(container, child.Keys[0])
	if action == nil || action.multi || len(action.children) > 0 || action.wildcard != nil {
		// Unknown keyword, a value list, or a container: not this reader's
		// business — the loop's own default arm reports an unknown head,
		// and reporting it twice would name the same token in two messages
		// (the #8971 rule, bound for bound).
		return nil
	}
	start := 1 + action.args
	if start >= len(child.Keys) {
		return nil
	}
	return append([]string(nil), child.Keys[start:]...)
}

// policerThenSawDiscard9882 reports whether `discard` was already authored in
// this policer's `then` (the ThenActions accumulated so far, across blocks and
// across firewall roots). The forwarding-class arm is LONE-ONLY: it must not
// overwrite an authored discard, or a discard+FC conflict downgraded to a
// warning on the lenient path stops dropping (base compiled discard+FC to
// discard in both orders, both families — measured on 92bf892c2 — while an
// unconditional arm meters when FC is last). ThenActions still records the FC
// so the #8445 gate fires; only the ThenAction survivor is fenced.
func policerThenSawDiscard9882(actions []string) bool {
	for _, a := range actions {
		if a == "discard" {
			return true
		}
	}
	return false
}

// shieldPolicerThenValues9882 folds block-form values back into their head's
// Keys before hoistAndSplitRun8939 runs. A leaf whose declared arity is
// UNSATISFIED by its own Keys carries its values as children — the nodeVal
// contract (`loss-priority { high; }` reads "high" from Children[0]) — and
// the hoist would otherwise lift the value out as a sibling statement. That
// turned a marking into an unknown token (strict rejects a spelling the base
// accepted) while ThenAction fell back to the discard default (lenient flips
// meter-only traffic into dropped excess).
//
// Consumption is POSITIONAL (#9124: declared slots win even when the value
// spells a sibling): leading children fill unsatisfied value slots first,
// each folded key carrying its quote/bracket provenance with it (#8921:
// masks move with keys). Anything a consumed value itself carries — tail
// keys, subtree — is promoted to sibling position behind the head for the
// hoist to expand, so `loss-priority { high; low; }` keeps high as the value
// and flags low rather than losing either silently. Children beyond the
// satisfied arity are never values and stay nested for the hoist.
//
// Copy-on-write: heads that consume are rebuilt; every other node is shared
// with the input tree. Idempotent: a second pass finds every arity satisfied
// and returns the list unchanged.
//
// Policer-local by design. The shared hoister still strips block-form values
// at its other call sites; none of them has a measured block-value reader
// today, and widening the shared helper would need fleet-wide census
// re-adjudication. If another site grows one, promote this there — do not
// re-derive it.
func shieldPolicerThenValues9882(children []*Node, container *schemaNode) []*Node {
	if container == nil || len(children) == 0 {
		return children
	}
	out := make([]*Node, 0, len(children))
	for _, n := range children {
		if n == nil || len(n.Keys) == 0 || len(n.Children) == 0 {
			out = append(out, n)
			continue
		}
		head := resolveSchemaChild(container, n.Keys[0])
		if head == nil || head.args <= 0 {
			out = append(out, n)
			continue
		}
		need := head.args - (len(n.Keys) - 1)
		if need <= 0 {
			out = append(out, n)
			continue
		}
		// Fold leading key-carrying children into Keys until the arity is
		// satisfied; keyless children are degenerate (the parser never
		// emits them — #4827) and pass through nested for the hoist, which
		// keeps them as-is for the loop's default arm to report. What a
		// consumed value carried (tail keys, subtree) is promoted to
		// sibling position behind the head, so consumption never drops.
		newKeys := append([]string(nil), n.Keys...)
		var newQuoted, newBracketed []bool
		if n.KeysHaveQuoteProvenance() {
			newQuoted = append([]bool(nil), n.KeysQuoted...)
		}
		if len(n.KeysBracketed) == len(n.Keys) && len(n.Keys) > 0 {
			newBracketed = append([]bool(nil), n.KeysBracketed...)
		}
		var promoted, nested []*Node
		needLeft := need
		for _, c := range n.Children {
			if needLeft == 0 || c == nil || len(c.Keys) == 0 {
				nested = append(nested, c)
				continue
			}
			needLeft--
			newKeys = append(newKeys, c.Keys[0])
			if newQuoted != nil || c.KeysHaveQuoteProvenance() {
				for len(newQuoted) < len(newKeys)-1 {
					newQuoted = append(newQuoted, false)
				}
				newQuoted = append(newQuoted, c.KeyQuoted(0))
			}
			if newBracketed != nil || len(c.KeysBracketed) > 0 {
				for len(newBracketed) < len(newKeys)-1 {
					newBracketed = append(newBracketed, false)
				}
				newBracketed = append(newBracketed, c.KeyBracketed(0))
			}
			if len(c.Keys) > 1 {
				tail := &Node{Keys: append([]string(nil), c.Keys[1:]...), IsLeaf: true, Line: c.Line, Column: c.Column}
				tq := make([]bool, len(tail.Keys))
				tb := make([]bool, len(tail.Keys))
				for i := range tail.Keys {
					tq[i] = c.KeyQuoted(i + 1)
					tb[i] = c.KeyBracketed(i + 1)
				}
				tail.setKeysQuoted(tq)
				tail.setKeysBracketed(tb)
				promoted = append(promoted, tail)
			}
			promoted = append(promoted, c.Children...)
		}
		// Rebuild only if something was consumed; otherwise share the node.
		if needLeft == need {
			out = append(out, n)
			continue
		}
		rebuilt := &Node{
			Keys:       newKeys,
			IsLeaf:     len(nested) == 0,
			Annotation: n.Annotation,
			Inactive:   n.Inactive,
			Line:       n.Line,
			Column:     n.Column,
			Children:   nested,
		}
		rebuilt.setKeysQuoted(newQuoted)
		rebuilt.setKeysBracketed(newBracketed)
		out = append(out, rebuilt)
		out = append(out, promoted...)
	}
	return out
}

func compileFirewall(node *Node, fw *FirewallConfig) error {
	if fw.FiltersInet == nil {
		fw.FiltersInet = make(map[string]*FirewallFilter)
	}
	if fw.FiltersInet6 == nil {
		fw.FiltersInet6 = make(map[string]*FirewallFilter)
	}
	if fw.Policers == nil {
		fw.Policers = make(map[string]*PolicerConfig)
	}

	// Compile policer definitions. Reuses the existing entry when the same
	// policer is defined across two `firewall` roots (GPT-2): parseStatements
	// APPENDS a repeated top-level block rather than merging it, and
	// compileSections dispatches every root into this same map, so a fresh
	// struct per root would overwrite the first root's ThenActions/UnknownActions
	// and erase the conflict/unknown evidence before the gates run. The
	// three-color loop below already reuses; this mirrors it. Rates overwrite
	// per-field when present (Junos merge), the flag ORs, actions accumulate,
	// and ThenAction resolves last-wins in author order (with the lone-only FC
	// fence).
	for _, polInst := range namedInstances(node.FindChildren("policer")) {
		pol := fw.Policers[polInst.name]
		if pol == nil {
			pol = &PolicerConfig{
				Name:       polInst.name,
				ThenAction: "discard", // default action
			}
			fw.Policers[polInst.name] = pol
		}

		ifExceeding := polInst.node.FindChild("if-exceeding")
		if ifExceeding != nil {
			// #9235: `if-exceeding bandwidth-limit 1m burst-size-limit 15k` is ONE
			// flat-set command, and SetPath nests the second leaf under the first,
			// so this loop saw bandwidth-limit and nothing else -- the policer was
			// installed with BurstSizeLimit 0. Lenient-path only
			// (CompileConfigLenient via Store.Load / Store.SyncApply); the schema
			// gate refuses the spelling on the operator's commit path.
			for _, child := range expandRunChildren9235(ifExceeding.Children, policerIfExceedingSchema9235()) {
				switch child.Name() {
				case "bandwidth-limit":
					if v := nodeVal(child); v != "" {
						pol.BandwidthLimit = parseBandwidthLimit(v)
					}
				case "burst-size-limit":
					if v := nodeVal(child); v != "" {
						pol.BurstSizeLimit = parseBurstSizeLimit(v)
					}
				}
			}
		}

		// M2 (#3850 mirror): read EVERY `then` block. FindChild-first
		// silently dropped the second block (`then {discard;}
		// then {foo;}` committed clean), exactly the duplicate-block hole
		// #3842 closed for filter terms. Actions accumulate across blocks;
		// a terminal resolves last-wins in block order (Junos merges
		// duplicate stanzas).
		for _, thenNode := range polInst.node.FindChildren("then") {
			// #9882: leaf form. `then foo;` (packed single) never folds — the
			// fold only fires when the head names a DECLARED child
			// (normalizeCompactNodes) — so the node stays Keys=["then","foo"]
			// with no children and a children-only walk sees nothing: the
			// typo would bypass UnknownActions exactly as before the fix.
			// Walk the Keys tail like compileFilterThen's leaf path does
			// (#2399), with the same arg consumption and the same default
			// arm. GPT-3: read the tail EVEN WHEN the node carries children
			// (`then foo { discard; }` is Keys=["then","foo"] with a child —
			// IsLeaf false — and skipping it lets foo bypass while the child
			// processes discard). A merged tail-with-children is read by BOTH
			// halves, which is correct — both are authored intent (the #3842
			// accumulate-everything philosophy). Legitimate elided shapes
			// (`then loss-priority { high; }`) are folded by the normalizer
			// before this runs, so a surviving tail+children is malformed.
			if len(thenNode.Keys) >= 2 {
				keys := thenNode.Keys[1:]
				for i := 0; i < len(keys); i++ {
					k := keys[i]
					arg := func() string {
						if i+1 < len(keys) {
							i++
							return keys[i]
						}
						return ""
					}
					switch k {
					case "discard":
						pol.ThenActions = append(pol.ThenActions, "discard")
						pol.ThenAction = "discard"
					case "loss-priority":
						pol.ThenActions = append(pol.ThenActions, "loss-priority")
						if v := arg(); v != "" {
							pol.ThenAction = "loss-priority " + v
						} else {
							pol.UnknownActions = append(pol.UnknownActions, "loss-priority"+policerMissingValueSuffix9882)
						}
					case "forwarding-class":
						pol.ThenActions = append(pol.ThenActions, "forwarding-class")
						if v := arg(); v != "" {
							// LONE-ONLY (GPT-1): never overwrite an authored discard —
							// see policerThenSawDiscard9882.
							if !policerThenSawDiscard9882(pol.ThenActions) {
								pol.ThenAction = "forwarding-class " + v
							}
						} else {
							pol.UnknownActions = append(pol.UnknownActions, "forwarding-class"+policerMissingValueSuffix9882)
						}
					default:
						pol.UnknownActions = append(pol.UnknownActions, k)
					}
				}
			}
			// #9882: expand a one-line run before walking. `then
			// forwarding-class af11 loss-priority high;` (and the flat-set
			// single command) nests or packs the later statements where a
			// children-only walk keeps just the head — a silent loss on the
			// lenient path and, for the flat-set shape, on strict too. The
			// hoist is a no-op for the canonical separate-statement shapes.
			thenSchema := policerThenSchema9882()
			// Shield block-form values BEFORE the hoist lifts nested runs:
			// `loss-priority { high; }` carries its value as a child and
			// the hoist would otherwise promote it to a sibling unknown.
			children := shieldPolicerThenValues9882(thenNode.Children, thenSchema)
			for _, child := range hoistAndSplitRun8939(children, thenSchema) {
				// #8445: record what was AUTHORED before applying last-wins.
				// The gate's question is which actions were written, not which
				// one survived.
				switch child.Name() {
				case "discard", "loss-priority", "forwarding-class":
					pol.ThenActions = append(pol.ThenActions, child.Name())
				default:
					// #9882: record the unknown `then` token for the strict commit
					// gate instead of dropping it — the policer path never got the
					// UnknownActions channel filter terms got in #2399, so a typo
					// kept the "discard" default with zero diagnostic. Kept OUT of
					// ThenActions, which feeds the #8445 terminal-vs-marking gate
					// and classifies known actions only.
					pol.UnknownActions = append(pol.UnknownActions, child.Name())
				}
				switch child.Name() {
				case "discard":
					pol.ThenAction = "discard"
				case "loss-priority":
					if v := nodeVal(child); v != "" {
						pol.ThenAction = "loss-priority " + v
					} else {
						// M1: a marking without a value is malformed, not a
						// silent discard — flag it for the gate. (Hierarchical
						// strict rejects first at SchemaValidate arity; this
						// covers flat-set and the lenient path.)
						pol.UnknownActions = append(pol.UnknownActions, "loss-priority"+policerMissingValueSuffix9882)
					}
				case "forwarding-class":
					// #9882: Junos mark-and-forward. The dataplane does not act on
					// the marking, so this compiles to meter-only (DiscardExcess
					// stays false) — exactly what the #8445 message promises for
					// the lone-forwarding-class spelling. Before this arm the
					// statement was recorded but never acted on, so ThenAction
					// kept the "discard" default and the policer dropped traffic
					// the operator asked to be marked and forwarded.
					// LONE-ONLY (GPT-1): never overwrite an authored discard —
					// see policerThenSawDiscard9882.
					if v := nodeVal(child); v != "" {
						if !policerThenSawDiscard9882(pol.ThenActions) {
							pol.ThenAction = "forwarding-class " + v
						}
					} else {
						// M1: see loss-priority above.
						pol.UnknownActions = append(pol.UnknownActions, "forwarding-class"+policerMissingValueSuffix9882)
					}
				}
				// #9882: tokens fused past the action's declared arity are
				// unknown, not values — `then { discard foo; }` must not
				// swallow `foo` any more than `then { foo; }` does. Runs on
				// the hoisted siblings, so a DECLARED trailing action was
				// already split into its own statement and only the
				// genuinely extra tokens land here (the #8971 shape).
				if extras := policerThenExtras9882(child, thenSchema); len(extras) > 0 {
					pol.UnknownActions = append(pol.UnknownActions, extras...)
				}
			}
		}

		// Check for logical-interface-policer flag (ORs across roots — see above).
		if polInst.node.FindChild("logical-interface-policer") != nil {
			pol.LogicalInterfacePolicer = true
		}
		// Already in fw.Policers (set at creation above); no trailing write —
		// the three-color shape. A name-keyed overwrite here is what erased
		// cross-root evidence before the gates (GPT-2).
	}

	// Compile three-color policer definitions
	if fw.ThreeColorPolicers == nil {
		fw.ThreeColorPolicers = make(map[string]*ThreeColorPolicerConfig)
	}
	for _, tcpInst := range namedInstances(node.FindChildren("three-color-policer")) {
		tcp := fw.ThreeColorPolicers[tcpInst.name]
		if tcp == nil {
			tcp = &ThreeColorPolicerConfig{
				Name:       tcpInst.name,
				ThenAction: "discard",
			}
			fw.ThreeColorPolicers[tcpInst.name] = tcp
		}

		singleRates := tcpInst.node.FindChildren("single-rate")
		if len(singleRates) > 0 {
			tcp.SingleRateConfigured = true
			tcp.TwoRate = false
		}
		for _, sr := range singleRates {
			if sr.FindChild("color-blind") != nil {
				tcp.ColorBlind = true
				tcp.ColorBlindConfigured = true
			}
			if sr.FindChild("color-aware") != nil {
				tcp.ColorAwareConfigured = true
			}
			for _, child := range sr.Children {
				switch child.Name() {
				case "committed-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.CIR = parseBandwidthLimit(v)
					}
				case "committed-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.CBS = parseBurstSizeLimit(v)
					}
				case "excess-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.PBS = parseBurstSizeLimit(v)
					}
				}
			}
		}

		twoRates := tcpInst.node.FindChildren("two-rate")
		if len(twoRates) > 0 {
			tcp.TwoRateConfigured = true
			tcp.TwoRate = true
		}
		for _, tr := range twoRates {
			if tr.FindChild("color-blind") != nil {
				tcp.ColorBlind = true
				tcp.ColorBlindConfigured = true
			}
			if tr.FindChild("color-aware") != nil {
				tcp.ColorAwareConfigured = true
			}
			for _, child := range tr.Children {
				switch child.Name() {
				case "committed-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.CIR = parseBandwidthLimit(v)
					}
				case "committed-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.CBS = parseBurstSizeLimit(v)
					}
				case "peak-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.PIR = parseBandwidthLimit(v)
					}
				case "peak-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.PBS = parseBurstSizeLimit(v)
					}
				}
			}
		}

		// M2 (#3850 mirror): read EVERY `then` block — see the policer loop.
		for _, thenNode := range tcpInst.node.FindChildren("then") {
			// #9882: leaf form — see the policer loop above. `then foo;` never
			// folds, so without this walk the typo bypasses UnknownActions.
			// GPT-3: tail read even when non-leaf — see the policer loop above.
			if len(thenNode.Keys) >= 2 {
				keys := thenNode.Keys[1:]
				for i := 0; i < len(keys); i++ {
					k := keys[i]
					arg := func() string {
						if i+1 < len(keys) {
							i++
							return keys[i]
						}
						return ""
					}
					switch k {
					case "discard":
						tcp.ThenActions = append(tcp.ThenActions, "discard")
						tcp.ThenAction = "discard"
					case "loss-priority":
						tcp.ThenActions = append(tcp.ThenActions, "loss-priority")
						if v := arg(); v != "" {
							tcp.ThenAction = "loss-priority " + v
						} else {
							tcp.UnknownActions = append(tcp.UnknownActions, "loss-priority"+policerMissingValueSuffix9882)
						}
					case "forwarding-class":
						tcp.ThenActions = append(tcp.ThenActions, "forwarding-class")
						if v := arg(); v != "" {
							// LONE-ONLY (GPT-1): see the policer loop above.
							if !policerThenSawDiscard9882(tcp.ThenActions) {
								tcp.ThenAction = "forwarding-class " + v
							}
						} else {
							tcp.UnknownActions = append(tcp.UnknownActions, "forwarding-class"+policerMissingValueSuffix9882)
						}
					default:
						tcp.UnknownActions = append(tcp.UnknownActions, k)
					}
				}
			}
			// #9882: expand a one-line run — see the policer loop above.
			thenSchema := threeColorPolicerThenSchema9882()
			children := shieldPolicerThenValues9882(thenNode.Children, thenSchema)
			for _, child := range hoistAndSplitRun8939(children, thenSchema) {
				// #8445: see the policer loop above — identical last-wins switch,
				// identical authored set. #9882: identical UnknownActions channel
				// and identical forwarding-class arm.
				switch child.Name() {
				case "discard", "loss-priority", "forwarding-class":
					tcp.ThenActions = append(tcp.ThenActions, child.Name())
				default:
					// #9882: see the policer loop above.
					tcp.UnknownActions = append(tcp.UnknownActions, child.Name())
				}
				switch child.Name() {
				case "discard":
					tcp.ThenAction = "discard"
				case "loss-priority":
					if v := nodeVal(child); v != "" {
						tcp.ThenAction = "loss-priority " + v
					} else {
						// M1: see the policer loop above.
						tcp.UnknownActions = append(tcp.UnknownActions, "loss-priority"+policerMissingValueSuffix9882)
					}
				case "forwarding-class":
					// #9882: see the policer loop above — Junos mark-and-forward,
					// meter-only on this dataplane. The Go capability gate and
					// the Rust shape check both admit the marking (the #9503
					// pattern), and the #9503 advisory already warns it is inert.
					// LONE-ONLY (GPT-1): see the policer loop above.
					if v := nodeVal(child); v != "" {
						if !policerThenSawDiscard9882(tcp.ThenActions) {
							tcp.ThenAction = "forwarding-class " + v
						}
					} else {
						// M1: see the policer loop above.
						tcp.UnknownActions = append(tcp.UnknownActions, "forwarding-class"+policerMissingValueSuffix9882)
					}
				}
				// #9882: fused tokens past the arity — see the policer loop.
				if extras := policerThenExtras9882(child, thenSchema); len(extras) > 0 {
					tcp.UnknownActions = append(tcp.UnknownActions, extras...)
				}
			}
		}
	}

	// #4535: a three-color policer with NEITHER `color-blind` nor
	// `color-aware` configured defaults to COLOR-BLIND mode, matching
	// Junos (which accepts and enforces such a policer). Without this
	// default the snapshot carries color_blind=false, which the userspace
	// capability gate (userspaceSupportsThreeColorPolicers) treats as
	// unsupported color-aware mode and disarms the WHOLE dataplane
	// (ForwardingSupported=false) — refusing a valid Junos config outright.
	// Applied after all instances merge so a color statement split across
	// set-lines / firewall blocks is fully observed first. Only the
	// UNSPECIFIED case changes: explicit `color-aware` keeps ColorBlind
	// false (its documented unsupported-mode disarm is unchanged),
	// explicit `color-blind` keeps it true.
	for _, tcp := range fw.ThreeColorPolicers {
		if tcp == nil {
			continue
		}
		if !tcp.ColorBlindConfigured && !tcp.ColorAwareConfigured {
			tcp.ColorBlind = true
		}
	}
	// #9883: the schema-declared `firewall family` set — the SAME
	// firewallFamilyPermitted9017 source the #9017 token gate reads, built once
	// here so the af loop below consults it without re-allocating. Declaring a
	// fourth family permits it in the #9017/#3884/#4296 gates automatically; a
	// hardcoded list would be a second place to remember. The dest switch below
	// still needs an explicit arm for the new family (SPARK-F2) — until then it
	// inherits the IPv4 default, which TestDeclaredFamilyDestArms9883 forbids.
	firewallPermitted := firewallFamilyPermitted9017()

	for _, familyNode := range node.FindChildren("family") {
		// The shared extractor: the token installed under is always a token
		// the #9017 gate judged (effective token plus trailing tokens on
		// structured nodes), so gate and compiler cannot disagree on any
		// shape — including a malformed multi-key child, whose residue the
		// quarantine below also consults.
		for _, m := range firewallFamilyMembers9883(familyNode) {
			afNode, af := m.AfNode, m.Af
			// #9883 QUARANTINE: an address-family token the schema does not
			// declare (a typo like `inett`, or a not-yet-modelled family)
			// compiles to NOTHING — out of BOTH pools — as does a
			// structured member carrying an undeclared trailing token. The
			// old default-fold installed the braced spelling into the IPv4
			// pool on the tolerant path while the #9017 warning told the
			// operator it enforces no rule at all — an inverted diagnostic.
			// Skipping makes the message true on every route. An interface
			// hook naming the quarantined filter dangles: strict already
			// rejects the token, and on the tolerant path the #3296 reference
			// gate warns. Per #3296, the userspace snapshot-integrity backstop
			// then refuses to publish such a broken snapshot (fail-closed, prior
			// state kept — proven in #3296, not re-proven here; this PR pins the
			// backstop INPUT: pools empty + hook dangling + both warnings) — the
			// hook never degrades to Accept on the userspace path. The kernel lo0
			// path fails closed separately via the dangling pre-check in
			// applyLo0Filter (fence on cold-start, retain on existing-state).
			if firewallFamilyQuarantined9883(m, firewallPermitted) {
				continue
			}
			// #4287: a Junos `family any` filter is protocol-independent —
			// it matches BOTH IPv4 and IPv6. Folding it into FiltersInet
			// only (the pre-#4287 behavior for every non-inet6 family) lost
			// its IPv6 arm: a `family any` discard/deny filter enforced on
			// v4 only silently let v6 through (a security fail-open). Compile
			// it into BOTH pools so the deny applies to both families. The
			// #3884 cross-family same-name collision gate
			// (validateFirewallFilterFamilyCollisionsAST) now also treats an
			// `any`+`inet6` same-name reuse as a collision, since `any` folds
			// into FiltersInet6 too — a name shared with a distinct inet6
			// filter would otherwise silently overwrite in FiltersInet6.
			// #9883 SPARK-F2: the IPv4 default is for "inet" ONLY. A 4th DECLARED
			// family MUST add an explicit dest arm here — it must NOT silently
			// inherit the IPv4 fold (that would reintroduce the pre-#9883
			// wrong-pool compile for the new family). TestDeclaredFamilyDestArms9883
			// fails if a declared family lacks an explicit arm.
			var dests []map[string]*FirewallFilter
			switch af {
			case "inet":
				dests = []map[string]*FirewallFilter{fw.FiltersInet}
			case "inet6":
				dests = []map[string]*FirewallFilter{fw.FiltersInet6}
			case "any":
				dests = []map[string]*FirewallFilter{fw.FiltersInet, fw.FiltersInet6}
			default:
				// Unreachable today: the quarantine above skips every undeclared
				// token, and the only declared families are inet/inet6/any. A 4th
				// declared family lands here until it gets its own arm — fold into
				// IPv4 (the pre-quarantine default) so the filter still installs
				// somewhere rather than voiding silently; the dest-arms test forces
				// the explicit arm at dev time.
				dests = []map[string]*FirewallFilter{fw.FiltersInet}
			}

			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
				filter := &FirewallFilter{Name: filterInst.name}

				// #4316 (fable-167 F-3a): record interface-specific so the
				// commit advisory can flag the single-shared-counter divergence.
				if filterInst.node.FindChild("interface-specific") != nil {
					filter.InterfaceSpecific = true
				}

				for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
					term := &FirewallFilterTerm{
						Name: termInst.name,
					}

					// #3850: apply EVERY `from {}` block, not just the first via
					// FindChild — a duplicate block (a `load merge`/`load
					// override` that splits its conditions, or a hierarchical
					// config authored twice) must AND-combine every condition,
					// never be dropped (a fail-open widening of the term match).
					// compileFilterFrom accumulates into term. Flat-set is
					// unaffected: SetPath merges duplicate containers into one
					// node (ast_edit.go), so this only changes the hierarchical
					// (parser / load merge) shape.
					// #6685: `term t1 then discard;` packs the term body onto the
					// term node's Keys, leaving Children empty — the term compiled
					// with an EMPTY Action, so a discard did not discard while the
					// term still existed and still matched.
					termBody := packedBody(termInst.node,
						schemaForPath("firewall", "family", af, "filter", "term"))

					fromSchema := schemaForPath("firewall", "family", af, "filter", "term", "from")
					var rangeNames map[string]bool
					for _, fromNode := range termBody.FindChildren("from") {
						// A `from` written as a one-line STATEMENT inside the term
						// block — `term t1 { from protocol tcp; }` — packs the
						// condition onto the from node's own Keys, exactly as the
						// term-level packing does one level up. compileFilterFrom
						// reads children, so the condition was dropped and the term
						// matched EVERYTHING. Found by comparing the two spellings
						// for #6685, where this is the NESTED side.
						rangeNames = compileFilterFrom(packedBody(fromNode, fromSchema),
							term, af, rangeNames)
					}
					// #10071: when a schema-unknown `from` leaf is packed onto
					// the term itself, packedBody deliberately leaves the original
					// node unchanged rather than guessing how many operands the
					// unknown leaf owns. Preserve the filter compiler's existing
					// unknown-leaf contract by giving compileFilterFrom the
					// synthetic `from` statement so it can record the leaf.
					if termBody == termInst.node {
						for _, packedFrom := range firewallPackedTermFromNodes(termInst.node,
							schemaForPath("firewall", "family", af, "filter", "term")) {
							rangeNames = compileFilterFrom(packedBody(packedFrom, fromSchema),
								term, af, rangeNames)
						}
					}
					// Finalize only after all same-name range fragments have
					// merged, including fragments in later `from` blocks (#9899).
					if fm := term.FlexMatch; fm != nil {
						if fm.BitLength == 0 {
							fm.BitLength = 32
						}
						if fm.Mask == 0 {
							// #3203: default mask covers the low BitLength bits.
							if fm.BitLength >= 32 {
								fm.Mask = 0xFFFFFFFF
							} else {
								fm.Mask = uint32(1)<<fm.BitLength - 1
							}
						}
					}
					// #9875: record the value-bearing `from` leaves this term
					// WROTE but left EMPTY (`from protocol;`, #8480) — the
					// F-005 half of the tolerant-path widening. Post-compile a
					// valueless leaf and an omitted one are byte-identical
					// empty slices, so the marker must be captured from the AST
					// here, before the node is out of scope. This calls the SAME
					// firewallTermValuelessFromLeaves helper on the SAME raw
					// term node (termInst.node, NOT the packed termBody) the
					// #8480 pre-walk gate walks, with the SAME from-schema
					// compileFilterFrom is lowered with two statements above —
					// packing copies and never mutates, so gate and marker see
					// identical input (including packed tails, which the helper
					// expands via packedBody rather than relying on the
					// compact normalizer's scope admitting the pair) and the
					// recorded set can never drift from the strict-reject set.
					// Before #10071/#10072, term-level packed valueless and
					// unknown leaves escaped BOTH the gate and this recording
					// identically (strict-path packing defects, not a
					// marker/gate divergence). Their fixes now surface the
					// packed leaves to the strict gate and marker view. The
					// snapshot builder, the lo0 mirror and the PBR classifier
					// fail the term closed on this field; the strict path
					// rejects it in pre-walk before compilation, so a committed
					// config never carries it.
					term.ValuelessFrom = firewallTermValuelessFromLeaves(termInst.node,
						schemaForPath("firewall", "family", af, "filter", "term", "from"))

					// #3850: apply EVERY `then {}` block. compileFilterThen
					// accumulates modifiers (count/log/forwarding-class/...); a
					// terminal action (accept/discard/reject) resolves last-wins
					// across blocks (Junos merges duplicate stanzas), so the
					// second block's action is applied, never silently dropped.
					for _, thenNode := range termBody.FindChildren("then") {
						compileFilterThen(thenNode, term)
					}

					// #3076: a tcp-flags expression the dataplane cannot enforce
					// (disjunction, a negated group, an unknown flag, or a
					// self-contradictory required/forbidden pair) is rejected —
					// without a reject such an expression committed cleanly and
					// the constraint was silently dropped on the wire (fail-open).
					// #4953: the reject moved OUT of the section compiler and into
					// the strict/tolerant gate validateFirewallTCPFlagsStrict
					// (runUniformGates) so the commit / commit-check path still
					// hard-rejects but the load / peer-sync path downgrades to a
					// warning — an already-persisted or peer-synced config an
					// older binary accepted still BOOTS (#1960 no-brick). The term
					// keeps its raw (unparseable) TCPFlags, which the userspace
					// snapshot builder detects and marks TCPFlagsUnparseable so the
					// Rust filter compiler fails the term CLOSED (#3367) — the raw
					// value IS the deny sentinel, never widening to match-all.

					filter.Terms = append(filter.Terms, term)
				}

				for _, dest := range dests {
					dest[filter.Name] = filter
				}
			}
		}
	}
	return nil
}

// validateFirewallFilterFamilyCollisionsAST walks every top-level `firewall`
// node and rejects a firewall-filter NAME reused across two DIFFERENT non-inet6
// families (#3884, fable-review-161 F-030).
//
// compileFirewall selects the destination map with `dest := fw.FiltersInet`
// (compiler_firewall.go) and only switches to fw.FiltersInet6 when the family
// is literally "inet6" — so every DECLARED non-inet6 family (inet, any) folds
// into the single fw.FiltersInet pool, then writes `dest[filter.Name] =
// filter` unconditionally. An UNDECLARED token (a typo like `inett`, or a
// not-yet-modelled family) is QUARANTINED by compileFirewall (#9883): it
// compiles to NOTHING, out of both pools, so it neither folds nor collides
// and this gate ignores it. A same-name filter authored under a second
// DECLARED family therefore silently OVERWRITES the first (last-write-wins).
// If `family inet filter blockX { ... then discard; }` is
// followed by `family any filter blockX { ... then accept; }`, the effective
// IPv4 filter becomes accept-all — a deny silently downgraded to an accept
// (a security fail-open).
//
// Downstream consumers reference filters by NAME within the inet (V4) / inet6
// (V6) buckets only — an interface unit's FilterInputV4 resolves against
// fw.FiltersInet, FilterInputV6 against fw.FiltersInet6 (compiler_validate_warn.go,
// routing/rules.go, dataplane/userspace/filters.go). There is no family
// dimension in the reference, so once two DECLARED non-inet6 families share a
// name the map cannot disambiguate them — the reuse is genuinely ambiguous.
// Junos namespaces firewall filters per family; xpf folds them, so it rejects
// the reuse fail-closed instead of resolving it by arbitrary map-write order.
//
// FiltersInet6 holds `family inet6` filters AND the v6 arm of `family any`
// filters (#4287 dual-compiles `any` into BOTH pools), so a name shared
// between family inet and family inet6 still lands in two DIFFERENT maps per
// arm and does NOT collide — that legitimate dual-stack case (the same filter
// name for the V4 and V6 path) is preserved. Flagged: a name under >= 2
// distinct DECLARED non-inet6 families (inet/any overwrite in FiltersInet),
// and a name under BOTH any and inet6 (overwrite in FiltersInet6 via the
// dual-compile — the any+inet6 cross-check below).
//
// Strict path (commit / commit-check, lenient=false): the first collision is a
// hard compile error naming the offending filter and its families. Lenient path
// (load / peer-sync, lenient=true): every collision is returned as a warning and
// compilation continues with the existing last-write-wins behavior, so an
// already-persisted or peer-synced config that an older binary silently accepted
// still BOOTS (#1960 / #3261 fail-closed-on-load doctrine).
//
// The traversal mirrors compileFirewall's family/filter walk exactly (BOTH AST
// shapes: hierarchical `family inet { filter ... }` and the set-command
// `family { inet { filter ... } }`), and aggregates across every top-level
// `firewall {}` block because compileFirewall compiles each into the same
// fw.FiltersInet map — a collision split across two blocks is just as real.
func validateFirewallFilterFamilyCollisionsAST(nodes []*Node, lenient bool) ([]string, error) {
	// filterFamilies[name] = the ordered set of DISTINCT non-inet6 families that
	// define a filter of this name (all folding into the shared FiltersInet pool).
	filterFamilies := map[string][]string{}
	// order preserves first-seen filter-name order for a deterministic error.
	order := []string{}
	// inet6Names records filter names defined under `family inet6` (their own
	// FiltersInet6 pool). #4287 compiles a `family any` filter into BOTH pools,
	// so an `any` name that ALSO names a distinct inet6 filter now collides in
	// FiltersInet6 — tracked here and flagged below.
	inet6Names := map[string]bool{}
	// #9883: undeclared families are quarantined out of both pools by
	// compileFirewall, so they can neither overwrite nor duplicate — this gate
	// ignores them (the #9017 token gate names the typo instead). Without the
	// skip, `inett/X` + `inet/X` would warn here about a silent overwrite that
	// no longer happens, contradicting the token warning on the same config.
	firewallPermitted := firewallFamilyPermitted9017()

	// #8426: definitions per (family, name). `filterFamilies` above is a set of
	// DISTINCT families and therefore CANNOT see a second definition inside one
	// family — the `return` below is what discards it, deliberately, because the
	// #3884 gate it feeds is about cross-family reuse. That leaves the
	// same-family duplicate unguarded, and it reaches the same unconditional
	// `dest[filter.Name] = filter` with the same consequence the #3884 message
	// describes: the later block replaces the earlier WHOLE, so a `then discard`
	// can silently become accept-all.
	//
	// Tracked for inet6 too. inet6 filters live in their own FiltersInet6 pool
	// so they cannot collide cross-family — but the write into that pool is the
	// same last-writer-wins, and `inet6Names` is a bool set that cannot count.
	seenInFamily := map[string]map[string]bool{}
	dupFamilies := map[string][]string{}
	dupOrder := []string{}
	noteDup := func(name, fam string) {
		if seenInFamily[fam] == nil {
			seenInFamily[fam] = map[string]bool{}
		}
		if !seenInFamily[fam][name] {
			seenInFamily[fam][name] = true
			return
		}
		for _, f := range dupFamilies[name] {
			if f == fam {
				return // this (name, family) duplicate already recorded
			}
		}
		if len(dupFamilies[name]) == 0 {
			dupOrder = append(dupOrder, name)
		}
		dupFamilies[name] = append(dupFamilies[name], fam)
	}

	record := func(name, fam string) {
		for _, f := range filterFamilies[name] {
			if f == fam {
				return // same family already recorded — not a cross-family reuse
			}
		}
		if len(filterFamilies[name]) == 0 {
			order = append(order, name)
		}
		filterFamilies[name] = append(filterFamilies[name], fam)
	}

	for _, fwNode := range nodes {
		if fwNode.Name() != "firewall" {
			continue
		}
		for _, familyNode := range fwNode.FindChildren("family") {
			// The shared extractor (see compileFirewall): same members, same
			// tokens, same quarantine verdict — this gate cannot see a
			// family the compiler installs differently.
			for _, m := range firewallFamilyMembers9883(familyNode) {
				afNode, af := m.AfNode, m.Af
				if firewallFamilyQuarantined9883(m, firewallPermitted) {
					continue // #9883: compiles to NOTHING, cannot collide
				}
				if af == "inet6" {
					// Its own dest map (FiltersInet6). It cannot collide with
					// the FiltersInet pool, but #4287 dual-applies `family any`
					// into FiltersInet6 too, so record inet6 names for the
					// any+inet6 cross-check below.
					for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
						if filterInst.name != "" {
							noteDup(filterInst.name, "inet6")
							inet6Names[filterInst.name] = true
						}
					}
					continue
				}
				for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
					if filterInst.name == "" {
						continue
					}
					noteDup(filterInst.name, af)
					record(filterInst.name, af)
				}
			}
		}
	}

	var warnings []string
	// #8426: same-family duplicates first — a name defined twice under ONE
	// family is a strictly more local error than a cross-family reuse, and
	// reporting it first gives the operator the smaller edit.
	for _, name := range dupOrder {
		fams := dupFamilies[name]
		msg := fmt.Sprintf(
			"firewall filter %q is defined more than once under the same family "+
				"(%s) — the later block REPLACES the earlier one whole (its terms, "+
				"its `then discard`), because compileFirewall writes "+
				"`dest[filter.Name] = filter` unconditionally; Junos merges "+
				"same-name blocks, xpf does not, so combine them into one filter "+
				"(#8426)",
			name, strings.Join(fams, ", "))
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
	}
	for _, name := range order {
		fams := filterFamilies[name]
		if len(fams) < 2 {
			continue
		}
		msg := fmt.Sprintf(
			"firewall filter %q is defined under multiple non-inet6 families "+
				"(%s) — xpf folds every family except inet6 into one name-keyed "+
				"filter map, so the later definition silently overwrites the "+
				"earlier (a discard filter can become accept-all — fail-open); "+
				"Junos namespaces filters per family, so rename one of them (#3884)",
			name, strings.Join(fams, ", "))
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
	}
	// #4287 any+inet6 cross-check: a `family any` filter now folds into the
	// FiltersInet6 pool as well, so a name shared with a distinct `family inet6`
	// filter silently overwrites in FiltersInet6 (the same fail-open the pool
	// gate above defends against, but on the v6 side). `any` names are recorded
	// in filterFamilies (and thus `order`), so iterating order catches them.
	for _, name := range order {
		if !inet6Names[name] {
			continue
		}
		hasAny := false
		for _, f := range filterFamilies[name] {
			if f == "any" {
				hasAny = true
				break
			}
		}
		if !hasAny {
			continue
		}
		msg := fmt.Sprintf(
			"firewall filter %q is defined under both family any and family "+
				"inet6 — xpf compiles a family any filter into BOTH the inet and "+
				"inet6 pools (#4287), so the any definition and the inet6 "+
				"definition collide in the inet6 pool and one silently overwrites "+
				"the other (fail-open); rename one of them",
			name)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
	}
	return warnings, nil
}

// familyAnySpecificMatches is the set of firewall-filter `from` match leaves
// that only make sense for ONE address family and must not appear under a
// `family any` filter (#4296):
//
//   - source-address / destination-address: a firewall-filter address match is
//     always an IP prefix LITERAL (v4 or v6), which binds to exactly one family.
//   - icmp-type / icmp-code: ICMPv4 and ICMPv6 use DIFFERENT numeric type/code
//     tables (echo-request is 8 for v4, 128 for v6); compileFilterFrom resolves
//     the symbolic name via the ICMPv4 table for af=="any" (filter_match_resolve.go),
//     so the resulting numeric is correct for at most one family.
//
// (next-header is the inet6 spelling of `protocol` and matches family-agnostic
// L4 protocol NUMBERS, so it is NOT family-specific and is deliberately absent.
// source-prefix-list / destination-prefix-list reference NAMED prefix-lists that
// may legitimately mix v4 and v6 prefixes, so they are NOT in this static set —
// their family content is not knowable from the leaf keyword alone. A prefix-list
// whose RESOLVED prefixes cover only ONE family is caught separately by the
// content-aware check in validateFirewallFilterFamilyAnyMatchesAST — see #4426.)
var familyAnySpecificMatches = map[string]bool{
	"source-address":      true,
	"destination-address": true,
	"icmp-type":           true,
	"icmp-code":           true,
}

// plFamily records which address families a prefix-list's resolved prefixes
// cover. Both false means empty or all-unclassifiable; both true means a
// legitimately mixed v4+v6 list; exactly one true is a single-family list.
type plFamily struct {
	hasV4 bool
	hasV6 bool
}

// prefixFamily classifies a single prefix-list entry as IPv4 or IPv6 by the
// only discriminator that cannot collide: a v6 literal always contains a colon
// and a v4 dotted-quad always contains a dot but never a colon. The optional
// `/len` mask is stripped first. A token that is neither (garbage — caught
// elsewhere by the prefix-list validators) sets neither flag so it never drives
// a false single-family verdict.
func prefixFamily(p string) (v4, v6 bool) {
	host := p
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if strings.Contains(host, ":") {
		return false, true
	}
	if strings.Contains(host, ".") {
		return true, false
	}
	return false, false
}

// firewallPrefixListFamilies collects, for every `policy-options prefix-list
// NAME`, the address families its resolved prefixes cover. It mirrors
// compilePolicyOptions' prefix reading exactly (namedInstances +
// inst.node.Children, each child's full Keys slice — the #3996 dual-shape
// read), so the family verdict matches what the compiler actually loads. The
// tree passed here is already apply-groups-expanded, so applied group
// prefix-lists are inlined at top level; an un-applied group's prefix-list is
// absent, matching the compiler (which ignores both it and any reference to
// it). Used by the #4426 family-any single-family prefix-list gate.
func firewallPrefixListFamilies(nodes []*Node) map[string]plFamily {
	out := map[string]plFamily{}
	for _, top := range nodes {
		if top == nil || top.Name() != "policy-options" {
			continue
		}
		for _, inst := range namedInstances(top.FindChildren("prefix-list")) {
			if inst.name == "" {
				continue
			}
			fam := out[inst.name]
			for _, entry := range inst.node.Children {
				for _, p := range entry.Keys {
					if p == "" {
						continue
					}
					if v4, v6 := prefixFamily(p); v4 {
						fam.hasV4 = true
					} else if v6 {
						fam.hasV6 = true
					}
				}
			}
			out[inst.name] = fam
		}
	}
	return out
}

// validateFirewallFilterFamilyAnyMatchesAST walks every top-level `firewall`
// node and rejects a `family any` filter term whose `from` block carries a
// FAMILY-SPECIFIC match leaf (#4296, fable-review-167 F-1 residual).
//
// #4287 fixed the original fail-open (a `family any` deny compiled into the
// IPv4 pool only, silently letting IPv6 through) by dual-compiling a `family
// any` filter into BOTH FiltersInet and FiltersInet6. But a family-specific
// match under `family any` is dual-compiled VERBATIM: a v4 `source-address` (or
// a symbolic icmp-type that resolves via the ICMPv4 table for af=="any") lands
// in the FiltersInet6 pool as a predicate that can NEVER match a v6 packet, so
// the v6 term falls through to the implicit ACCEPT — an imperfect v6 UNDER-block
// (it degrades to the pre-#4287 state for that term; never an over-block, so no
// legitimate v6 traffic is broken). These configs are also non-Junos (Junos
// disallows family-specific matches under `family any`) and only reachable via a
// hierarchical config-file / peer-synced AST, since the flat `set` schema does
// not model `family any`.
//
// Rather than silently dual-compile a match that cannot work for one family,
// this gate REJECTS it at commit with a message pointing the operator at
// `family inet` / `family inet6`. Strict path (commit / commit-check,
// lenient=false): the first offending match is a hard compile error. Lenient
// path (load / peer-sync, lenient=true): every offending match is returned as a
// warning and compilation continues with the existing dual-compile behavior, so
// an already-persisted or peer-synced config that an older binary silently
// accepted still BOOTS (#1960 / #3261 fail-closed-on-load doctrine).
//
// #4426 residual: a `source-prefix-list` / `destination-prefix-list` reference
// is not a static family-specific keyword (a named prefix-list MAY mix families),
// so it is deliberately NOT in familyAnySpecificMatches. But a reference whose
// RESOLVED prefixes cover only ONE family reproduces the SAME v6 (or v4)
// under-block: `from source-prefix-list v4-only then discard` under `family any`
// dual-compiles the v4-only list into the inet6 pool, where the v6 arm has zero
// v6 prefixes, matches nothing, and falls through to the implicit ACCEPT. This
// gate therefore also resolves each prefix-list reference against the candidate
// tree's `policy-options prefix-list` definitions and rejects (strict) / warns
// (lenient) when a DIRECTION's referenced prefix-lists collectively cover a
// single family only. A mixed-family list, or two lists that together cover both
// families in one direction, is accepted — that is the legitimate `family any`
// shape #4287 enables. An empty or undefined reference is left to the empty-set
// semantics and validateFirewallPrefixListReferencesStrict respectively.
//
// The traversal mirrors compileFirewall's family/filter/term/from walk exactly
// (BOTH AST shapes) and aggregates across every top-level `firewall {}` block.
func validateFirewallFilterFamilyAnyMatchesAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	plFamilies := firewallPrefixListFamilies(nodes)
	// #9883: skip quarantined members — a filter that compiles to NOTHING
	// cannot under-block any family, and flagging its matches would
	// contradict the token gate's warning on the same config.
	firewallPermitted := firewallFamilyPermitted9017()
	for _, fwNode := range nodes {
		if fwNode.Name() != "firewall" {
			continue
		}
		for _, familyNode := range fwNode.FindChildren("family") {
			// The shared extractor (see compileFirewall): same members, same
			// tokens — this gate cannot see a family the compiler installs
			// differently.
			for _, m := range firewallFamilyMembers9883(familyNode) {
				afNode, af := m.AfNode, m.Af
				if firewallFamilyQuarantined9883(m, firewallPermitted) {
					continue
				}
				if af != "any" {
					continue
				}
				for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
					if filterInst.name == "" {
						continue
					}
					for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
						// Per-direction prefix-list coverage, accumulated across
						// every `from` block of the term (#4426). Index 0 = source,
						// 1 = destination. POSITIVE (`source-prefix-list X`) and
						// EXCEPT (`source-prefix-list X except`) refs are tracked
						// SEPARATELY because they fail differently under `family
						// any`: a single-family POSITIVE list under-blocks the
						// missing family (its arm matches nothing), while a
						// single-family EXCEPT list OVER-matches the missing family
						// (that arm is `except` over an empty set = match ALL — the
						// clean-except branch of resolvePrefixListAddrs, #4338).
						var posFam, excFam [2]plFamily
						var hasPos, hasExc [2]bool
						var dirNames [2][]string
						for _, fromNode := range termInst.node.FindChildren("from") {
							for _, child := range fromNode.Children {
								mname := child.Name()
								// #4426: accumulate the resolved family coverage of
								// every source/destination-prefix-list reference so a
								// single-family list under `family any` is caught below.
								dir := -1
								switch mname {
								case "source-prefix-list":
									dir = 0
								case "destination-prefix-list":
									dir = 1
								}
								if dir >= 0 {
									for _, ref := range firewallPrefixListRefs(child) {
										fam, ok := plFamilies[ref.Name]
										if !ok {
											// Undefined reference — left to
											// validateFirewallPrefixListReferencesStrict.
											continue
										}
										dirNames[dir] = append(dirNames[dir], ref.Name)
										if ref.Except {
											hasExc[dir] = true
											if fam.hasV4 {
												excFam[dir].hasV4 = true
											}
											if fam.hasV6 {
												excFam[dir].hasV6 = true
											}
										} else {
											hasPos[dir] = true
											if fam.hasV4 {
												posFam[dir].hasV4 = true
											}
											if fam.hasV6 {
												posFam[dir].hasV6 = true
											}
										}
									}
									continue
								}
								if !familyAnySpecificMatches[mname] {
									continue
								}
								detail := mname
								if vals := firewallMatchValues(child); len(vals) > 0 {
									detail = mname + " " + vals[0]
								}
								msg := fmt.Sprintf(
									"firewall filter %q term %q: `from %s` is a family-specific match not allowed under `family any` — a family any filter compiles into BOTH the inet (v4) and inet6 (v6) pools (#4287), and a single-family match (a v4/v6 address literal or a per-family icmp type/code) can never match the other family, silently under-blocking it; use `family inet` or `family inet6` (#4296)",
									filterInst.name, termInst.name, detail)
								if !lenient {
									return nil, fmt.Errorf("%s", msg)
								}
								warnings = append(warnings, msg)
							}
						}
						// #4426: a direction whose referenced prefix-lists cover
						// exactly ONE family under `family any` is a commit-time
						// surprise — but the failure mode (and so the message) differs
						// by whether the coverage is POSITIVE or EXCEPT. Reject strict /
						// warn lenient in both cases, mirroring the #4296 remedy.
						// Both-families and empty coverage are fine.
						for dir, keyword := range [2]string{"source-prefix-list", "destination-prefix-list"} {
							// Effective match semantics for this direction, mirroring
							// resolvePrefixListAddrs (#4338): a DEFINED positive ref
							// makes the direction positive-wins (any `except` ref is
							// dropped, warned separately); only a SOLE `except` (no
							// positive ref) uses the clean-except match-ALL semantics.
							var fam plFamily
							except := false
							switch {
							case hasPos[dir]:
								fam = posFam[dir] // positive-wins; except refs ignored
							case hasExc[dir]:
								fam = excFam[dir]
								except = true
							default:
								continue // no defined refs in this direction
							}
							if fam.hasV4 == fam.hasV6 {
								// both (legit mixed / dual-list) or neither (empty).
								continue
							}
							names := strings.Join(dirNames[dir], " ")
							var msg string
							if except {
								// Single-family `except` list: the arm for the family
								// the list does NOT cover evaluates `except` over an
								// empty set = MATCH ALL — an over-block on `then
								// discard`, a fail-OPEN over-accept on `then accept`.
								// This is the OPPOSITE of an under-block, so it needs
								// its own message (#4426, coordinator review).
								haveFam, overFam := "inet (v4)", "inet6 (v6)"
								if fam.hasV6 {
									haveFam, overFam = "inet6 (v6)", "inet (v4)"
								}
								msg = fmt.Sprintf(
									"firewall filter %q term %q: `from %s %s except` references only %s prefixes under `family any` — a family any filter compiles into BOTH the inet (v4) and inet6 (v6) pools (#4287), and an `except` over a prefix set with no %s entries matches EVERY %s packet (an over-block on `then discard`, a fail-open over-accept on `then accept`); use `family inet` / `family inet6`, or an except prefix-list covering both families (#4426)",
									filterInst.name, termInst.name, keyword, names, haveFam, overFam, overFam)
							} else {
								// Single-family POSITIVE list: the arm for the missing
								// family has no matching prefixes → matches nothing →
								// falls through to the implicit ACCEPT (silent
								// under-block).
								haveFam, missFam := "inet (v4)", "inet6 (v6)"
								if fam.hasV6 {
									haveFam, missFam = "inet6 (v6)", "inet (v4)"
								}
								msg = fmt.Sprintf(
									"firewall filter %q term %q: `from %s %s` references only %s prefixes under `family any` — a family any filter compiles into BOTH the inet (v4) and inet6 (v6) pools (#4287), so the %s arm has no matching prefixes and silently under-blocks that family; use `family inet` / `family inet6`, or a prefix-list covering both families (#4426)",
									filterInst.name, termInst.name, keyword, names, haveFam, missFam)
							}
							if !lenient {
								return nil, fmt.Errorf("%s", msg)
							}
							warnings = append(warnings, msg)
						}
					}
				}
			}
		}
	}
	return warnings, nil
}

// firewallMatchValues extracts every value carried by a `from` match-criterion
// node, across BOTH parser AST shapes (#2545):
//
//   - hierarchical leaf  `protocol tcp;`            → Keys=["protocol","tcp"]
//   - bracket list       `protocol [ tcp udp ];`    → Keys=["protocol","tcp","udp"]
//   - flat set command   `... protocol tcp` (one    → Keys=["protocol"] with a
//     line per value, merged under one node)          child node per value
//
// Returning the full slice lets the caller ACCUMULATE repeated occurrences into
// a match-ANY set instead of overwriting (the prior scalar last-write-wins bug).
// Empty / blank tokens are skipped so an empty result means "criterion absent".
//
// #6714: EVERY key of each child, not Keys[0]. The node's own tail was already
// read in full (Keys[1:]), so taking one key per child made the identical token
// sequence read differently depending on which side of the AST the parser put
// it on — `flag basic-datapath session;` kept both and
// `flag { basic-datapath session; }` kept one. That shape comes from a
// hand-authored or `load merge`d file (a value tail packed onto a statement
// inside a value block, or a bracket list nested in one); the canonical Junos
// spellings put one token per child, which is why it survived every
// brace-authored fixture in this package.
//
// Two things it is deliberately NOT:
//
//   - It does NOT descend. A child with a sub-block (`neighbor 10.0.0.1
//     { metric 2; }`) contributes its NAME only; descending would promote
//     `metric` and `2` into the value list. That is the line between this and
//     plainListValues (ast.go), which descends and must only ever be pointed at
//     a leaf whose subtree is entirely values.
//   - It does NOT become safe for a leaf with per-value option KEYWORDS. It
//     already promoted every token of the node's own tail, so a leaf like
//     `ntp server <ip> prefer` was never eligible and still keeps its own
//     reader (ntpServerValues). This change did not widen that exposure; it
//     made the two sides of one node agree.
func firewallMatchValues(child *Node) []string {
	var vals []string
	self := child.Keys[0]
	for i, k := range child.Keys[1:] {
		if k == self && !child.KeyQuoted(i+1) {
			// Only bare self-repeats are keywords; quoted tokens are values.
			continue
		}
		if k != "" {
			vals = append(vals, k)
		}
	}
	for _, vn := range child.Children {
		for _, k := range vn.Keys {
			if k != "" {
				vals = append(vals, k)
			}
		}
	}
	return vals
}

// firewallPrefixListRefs extracts every prefix-list reference carried by a
// firewall-filter `from source-prefix-list` / `destination-prefix-list` match
// node, across BOTH parser AST shapes (#3843 — the prefix-list-ref instance of
// the #2419 dual-shape class):
//
//   - hierarchical single-name leaf  `source-prefix-list plX;`
//     → Keys=["source-prefix-list","plX"], no children
//     hierarchical single-name+except `source-prefix-list plX except;`
//     → Keys=["source-prefix-list","plX","except"], no children
//   - hierarchical block             `source-prefix-list { pl1; pl2 except; }`
//     → one child node per name (child.Keys=["pl1"] / ["pl2","except"])
//   - flat set command               `set ... source-prefix-list plX except`
//     → one child node (child.Keys=["plX"] / ["plX","except"])
//
// The single-name leaf shape was SILENTLY DROPPED before #3843: the caller only
// iterated child.Children and never read child.Keys[1], so a `load merge`/config-
// file term compiled with NO prefix-list scope (implicit match-all) yet passed
// strict commit cleanly — a fail-open. Reading BOTH child.Keys[1:] AND
// child.Children guarantees the scope survives every shape; an unresolvable name
// is still hard-rejected by validateFirewallPrefixListReferencesStrict, so a
// dropped scope is impossible (fail-closed).
func firewallPrefixListRefs(child *Node) []PrefixListRef {
	var refs []PrefixListRef
	// A token slice is a sequence of `<name> [except]` groups: an `except`
	// modifier attaches to the prefix-list name immediately preceding it.
	appendTokens := func(tokens []string) {
		for i := 0; i < len(tokens); {
			name := tokens[i]
			i++
			if name == "" {
				continue
			}
			ref := PrefixListRef{Name: name}
			if i < len(tokens) && tokens[i] == "except" {
				ref.Except = true
				i++
			}
			refs = append(refs, ref)
		}
	}
	// Single-name / flat leaf shape: the name(s) ride on this node's own Keys.
	appendTokens(child.Keys[1:])
	// Block / flat-set shape: one child node per referenced prefix-list.
	for _, plNode := range child.Children {
		appendTokens(plNode.Keys)
	}
	return refs
}

// firewallPackedUnknownFromLeaves returns schema-unknown leaves carried on a
// packed `from` node. The generic packed-body expander cannot safely synthesize
// an unknown leaf because its operand arity is not in the schema, but the
// firewall compiler already has an explicit UnknownFrom contract for exactly
// that case. Consume the unknown leaf's opaque tail until the next unquoted
// schema-known `from` head; this preserves the first leaf name without
// mistaking its value for another leaf.
func firewallPackedUnknownFromLeaves(node *Node, schema *schemaNode) []string {
	if node == nil || schema == nil || len(node.Keys) == 0 {
		return nil
	}
	// If the generic expander recognized the whole packed tail, all keys are
	// represented by synthesized children (including nested chains such as
	// `flexible-match-range range r`). Only inspect the raw tail when expansion
	// declined it, which is the opaque-unknown case this fallback owns.
	if packedBody(node, schema) != node {
		return nil
	}
	consumed, current := consumeNodeKeys(node.Keys, schema)
	if consumed >= len(node.Keys) || current == nil {
		return nil
	}

	// Keep the same open-schema stack as packedBodyChildren. A fallback scan
	// must recognize a known descendant (`range` under `flexible-match-range`)
	// before deciding that the token is an unknown root leaf; otherwise a
	// mixed known/unknown tail reports the descendant instead of the authored
	// unknown leaf.
	levels := []*schemaNode{current}
	var out []string
	for i := consumed; i < len(node.Keys); {
		at := -1
		var childSchema *schemaNode
		if !node.KeyQuoted(i) {
			for level := len(levels) - 1; level >= 0; level-- {
				if candidate := resolveSchemaChild(levels[level], node.Keys[i]); candidate != nil {
					at = level
					childSchema = candidate
					break
				}
			}
		}
		if childSchema != nil {
			n, refined := consumeNodeKeys(node.Keys[i:], childSchema)
			if childSchema.multi && childSchema.children == nil && n > 1 &&
				node.KeyBracketed(i+n-1) {
				for n < len(node.Keys)-i && node.KeyBracketed(i+n) {
					n++
				}
			}
			if n <= 0 {
				n = 1
			}
			levels = append(levels[:at+1], refined)
			i += n
			continue
		}

		if node.Keys[i] != "" {
			out = append(out, node.Keys[i])
		}
		i++
		for i < len(node.Keys) {
			if !node.KeyQuoted(i) {
				known := false
				for level := len(levels) - 1; level >= 0; level-- {
					if resolveSchemaChild(levels[level], node.Keys[i]) != nil {
						known = true
						break
					}
				}
				if known {
					break
				}
			}
			i++
		}
	}
	return out
}

// firewallPackedTermFromNodes extracts every packed `from` statement from a
// firewall term when the generic expander bails out on a schema-unknown leaf.
// `then` is a term-level sibling, so it bounds each from tail. The returned
// nodes are fresh and carry quote and bracket provenance for every operand.
func firewallPackedTermFromNodes(termNode *Node, termSchema *schemaNode) []*Node {
	if termNode == nil || termSchema == nil || len(termNode.Keys) == 0 {
		return nil
	}
	consumed, _ := consumeNodeKeys(termNode.Keys, termSchema)
	var out []*Node
	for i := consumed; i < len(termNode.Keys); i++ {
		if termNode.KeyQuoted(i) || termNode.Keys[i] != "from" {
			continue
		}
		end := i + 1
		for end < len(termNode.Keys) {
			if !termNode.KeyQuoted(end) &&
				(termNode.Keys[end] == "from" || termNode.Keys[end] == "then") {
				break
			}
			end++
		}
		keys := append([]string{"from"}, termNode.Keys[i+1:end]...)
		from := &Node{Keys: keys}
		quoted := make([]bool, len(keys))
		bracketed := make([]bool, len(keys))
		for j := i + 1; j < end; j++ {
			quoted[j-i] = termNode.KeyQuoted(j)
			bracketed[j-i] = termNode.KeyBracketed(j)
		}
		from.setKeysQuoted(quoted)
		from.setKeysBracketed(bracketed)
		out = append(out, from)
	}
	return out
}

// compileFilterFrom compiles a firewall-filter term's `from` match block. The
// family ("inet" / "inet6") selects the ICMPv4 vs ICMPv6 icmp-type name table
// when resolving symbolic icmp-type values (#3205).
func compileFilterFrom(node *Node, term *FirewallFilterTerm, family string, rangeNames map[string]bool) map[string]bool {
	fromSchema := schemaForPath("firewall", "family", family, "filter", "term", "from")
	if fromSchema == nil {
		// Family-independent fallback for family-less / unknown AST shapes.
		fromSchema = schemaForPath("firewall", "family", "inet", "filter", "term", "from")
	}
	for _, unknown := range firewallPackedUnknownFromLeaves(node, fromSchema) {
		// The packed scanner emits each opaque leaf once; retaining the
		// existing append semantics for ordinary child nodes keeps duplicate
		// authored leaves observable to the existing strict gate.
		term.UnknownFrom = append(term.UnknownFrom, unknown)
	}
	for _, child := range node.Children {
		switch child.Name() {
		case "dscp", "traffic-class":
			// Multi-value (#2545): ACCUMULATE every value rather than
			// overwrite. Handle BOTH AST shapes — a bracket/flat-set list
			// carries values as child.Keys[1:] and/or child nodes, while a
			// hierarchical leaf carries a single value via nodeVal.
			term.DSCPs = append(term.DSCPs, firewallMatchValues(child)...)
			// #8773: Junos spells this field `dscp` under family inet and
			// `traffic-class` under family inet6. This arm is deliberately
			// family-blind — the two name the same six bits — but the
			// cross-family spelling is recorded so the commit can say so
			// instead of accepting it silently.
			if (family == "inet" && child.Name() == "traffic-class") ||
				(family == "inet6" && child.Name() == "dscp") {
				term.CrossFamilyMatchSpellings = append(term.CrossFamilyMatchSpellings, child.Name())
			}
		case "protocol", "next-header":
			// `next-header` is the IPv6 spelling of `protocol` (Junos family
			// inet6). It matches the IPv6 Next Header / L4 protocol number, which
			// the dataplane already enforces via term.Protocols — so it is an
			// ALIAS for the existing protocol matcher, not new matching. Before
			// #3307 it had no switch case and was silently dropped (the term lost
			// its protocol constraint); routing it to Protocols enforces it.
			term.Protocols = append(term.Protocols, firewallMatchValues(child)...)
			// #8781: Junos spells this `protocol` under family inet and
			// `next-header` under family inet6. Like the dscp/traffic-class arm
			// above, this one is deliberately family-blind — they select the
			// same L4 protocol — but the cross-family spelling is recorded so
			// the commit names it instead of accepting it silently.
			if (family == "inet" && child.Name() == "next-header") ||
				(family == "inet6" && child.Name() == "protocol") {
				term.CrossFamilyMatchSpellings = append(term.CrossFamilyMatchSpellings, child.Name())
			}
		case "source-address":
			// Multi-value (#2419/#2545): a bracket/flat-set list collapses
			// onto child.Keys[1:] (firewallMatchValues), a hierarchical
			// block carries each address as a child node — handle both.
			// #6463/#10011: record every literal classifyFilterAddrFamily rejects
			// on term.UnknownAddresses (kept VERBATIM in SourceAddresses) so the
			// snapshot builder can set the AddressUnrepresentable wire marker
			// on the tolerant path — the Rust parse_address drops such a token
			// per-token, and a partially-malformed or zone-scoped list would
			// otherwise silently narrow a discard/reject term (fail-open).
			srcValues := firewallMatchValues(child)
			recordFilterAddrTokens(term, srcValues)
			term.SourceAddresses = append(term.SourceAddresses, srcValues...)
		case "destination-address":
			dstValues := firewallMatchValues(child)
			recordFilterAddrTokens(term, dstValues)
			term.DestAddresses = append(term.DestAddresses, dstValues...)
		case "destination-port":
			// #3205: resolve named/service ports to numerics and record any
			// unresolved token for the strict commit gate (fail closed).
			term.DestinationPorts = append(term.DestinationPorts, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "source-prefix-list":
			// #3843: read BOTH the single-name leaf shape
			// (`source-prefix-list plX;` → child.Keys[1:]) AND the block /
			// flat-set shape (`source-prefix-list { plX except; }` /
			// `set ... source-prefix-list plX` → child.Children). Iterating
			// only child.Children silently dropped the leaf-shape scope.
			term.SourcePrefixLists = append(term.SourcePrefixLists, firewallPrefixListRefs(child)...)
		case "destination-prefix-list":
			term.DestPrefixLists = append(term.DestPrefixLists, firewallPrefixListRefs(child)...)
		case "source-port":
			term.SourcePorts = append(term.SourcePorts, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "destination-port-except":
			// #2622 negated port match: match all destination ports EXCEPT
			// these. Multi-value/bracket-list, same accumulation as the
			// positive destination-port case. #3205: resolve named ports and
			// record unresolved tokens. An unresolved except port is
			// hard-rejected at commit by validateFilterMatchValuesStrict, so an
			// operator never reaches the dataplane with one. If a leniently
			// loaded / peer-synced snapshot still carries an unresolved token,
			// the Rust dataplane now fails CLOSED: port_match returns false for
			// a constrained term with an empty PortMatcher::Any in BOTH
			// directions, so the except term matches NOTHING (not all ports).
			// Pre-#3205 this except case failed OPEN — an unresolved except port
			// matched every port, including the one it was meant to exclude.
			term.DestPortsExcept = append(term.DestPortsExcept, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "source-port-except":
			term.SourcePortsExcept = append(term.SourcePortsExcept, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "icmp-type":
			// #3205: resolve symbolic icmp-type names (echo-request, ...) to
			// their numeric value using the family-appropriate Junos table.
			// strconv.Atoi alone silently dropped every name, leaving the type
			// set empty (matches ALL ICMP — a policy bypass). An unresolved
			// token is recorded for the strict commit gate (fail closed).
			for _, v := range firewallMatchValues(child) {
				if n, ok := resolveICMPTypeToken(v, family); ok {
					term.ICMPTypes = append(term.ICMPTypes, n)
				} else {
					term.UnknownICMPTypes = append(term.UnknownICMPTypes, v)
				}
			}
		case "icmp-code":
			for _, v := range firewallMatchValues(child) {
				if n, ok := resolveICMPCodeToken(v); ok {
					term.ICMPCodes = append(term.ICMPCodes, n)
				} else {
					term.UnknownICMPCodes = append(term.UnknownICMPCodes, v)
				}
			}
		case "tcp-flags":
			// Can be bracket list or single value: tcp-flags "syn ack" or [ syn ack ]
			term.TCPFlags = append(term.TCPFlags, firewallMatchValues(child)...)
		case "is-fragment":
			term.IsFragment = true
		case "flexible-match-range":
			for _, rangeInst := range namedInstances(child.FindChildren("range")) {
				// Count distinct range names for #5823. Repeated blocks for
				// the same name are fragments of one object, just as in flat
				// set syntax; merge their fields in authored order (#9899).
				if rangeNames == nil {
					rangeNames = make(map[string]bool)
				}
				if !rangeNames[rangeInst.name] {
					rangeNames[rangeInst.name] = true
					term.FlexMatchRangeNames = append(term.FlexMatchRangeNames, rangeInst.name)
				}
				if term.FlexMatch != nil && rangeInst.name != term.FlexMatchRangeNames[0] {
					continue // distinct later ranges remain fail-closed
				}
				fm := term.FlexMatch
				if fm == nil {
					fm = &FlexMatchConfig{MatchStart: "layer-3"}
				}
				rangeSchema := resolveSchemaPath9235("firewall", "family", "inet", "filter", "term", "from", "flexible-match-range", "range")
				for _, rc := range expandResolvingRuns9792(packedBody(rangeInst.node, rangeSchema).Children, rangeSchema) {
					switch rc.Name() {
					case "match-start":
						if v := nodeVal(rc); v != "" {
							// #3232: only layer-3 (the default) and layer-4 are
							// implemented in the userspace matcher. `payload` (and
							// any other token) would previously be stored but
							// silently evaluated at the L3 base by the wire builder
							// and Rust matcher — a wrong-offset match (security
							// evasion). layer-3/layer-4 carry through to the wire;
							// everything else is recorded so
							// validateFilterFlexMatchStrict fails the commit closed.
							switch v {
							case "layer-3", "layer-4":
								fm.MatchStart = v
							default:
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-start "+v)
							}
						}
					case "byte-offset":
						if v := nodeVal(rc); v != "" {
							// #3203: a parse error (or a value outside 0..255,
							// the wire field width) must FAIL CLOSED at commit,
							// not silently coerce the offset to 0. Record the
							// token for validateFilterFlexMatchStrict.
							if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 255 {
								fm.ByteOffset = uint8(n)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "byte-offset "+v)
							}
						}
					case "bit-length":
						if v := nodeVal(rc); v != "" {
							// #3203: bit-length must be 1..32 (the wire value is a
							// u32 read of ceil(bits/8) bytes). strconv.Atoi
							// followed by an unchecked uint8() cast previously
							// truncated an out-of-range value (e.g. 999 -> 231)
							// silently; a non-numeric token was ignored, leaving
							// bit-length 0 (later defaulted to 32). Fail closed on
							// either by recording the token.
							if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 32 {
								fm.BitLength = uint8(n)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "bit-length "+v)
							}
						}
					case "range", "match-value":
						if v := nodeVal(rc); v != "" {
							// Format: "0xVALUE/0xMASK" or just "0xVALUE".
							// #3203: a ParseUint error (malformed hex or a value
							// wider than 32 bits) previously left fm.Value/fm.Mask
							// at the zero default — the rule then matched value 0
							// instead of the intended pattern, with a clean
							// commit. Fail closed: record the unparseable token.
							parts := strings.SplitN(v, "/", 2)
							if val, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "0x"), 16, 32); err == nil {
								fm.Value = uint32(val)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-value "+parts[0])
							}
							if len(parts) == 2 {
								if mask, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 32); err == nil {
									fm.Mask = uint32(mask)
								} else {
									term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-mask "+parts[1])
								}
							}
						}
					case "match-mask":
						if v := nodeVal(rc); v != "" {
							if mask, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32); err == nil {
								fm.Mask = uint32(mask)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-mask "+v)
							}
						}
					}
				}
				term.FlexMatch = fm
				// Continue counting distinct names: multiple ranges retain
				// the existing strict refusal and tolerant fail-closed marker.
			}
		default:
			// #3307: a `from` match leaf the dataplane does NOT enforce. The
			// schema gate is opt-in, so an unknown leaf (ttl, source-mac-address,
			// ip-options, fragment-offset, hop-limit, ...) passes commit and was
			// previously dropped silently here — the term then enforced a BROADER
			// match than authored (an accept over-permits, a discard/reject
			// over-drops). Record it so validateFilterFromMatchStrict can reject
			// the commit fail-closed instead of silently dropping the constraint.
			// The enforced set is exactly the cases above; every one maps to a
			// wire field the snapshot builder emits and the Rust matcher reads.
			term.UnknownFrom = append(term.UnknownFrom, child.Name())
		}
	}
	return rangeNames
}

// rejectMessageTypes is the set of message-types Junos accepts after
// `then reject <type>` (RFC 792 ICMP-unreachable codes plus tcp-reset). A term
// with one of these still acts as a plain reject — the dataplane does not act
// on the message-type today (#2399 fold) — but the type is recognized so a real
// Juniper config import (`then reject tcp-reset`) commits cleanly instead of
// being flagged as an unknown action. A token NOT in this set after `reject` is
// a typo and is still flagged.
var rejectMessageTypes = map[string]bool{
	"administratively-prohibited": true,
	"bad-host-tos":                true,
	"bad-network-tos":             true,
	"host-prohibited":             true,
	"host-unreachable":            true,
	"network-prohibited":          true,
	"network-unreachable":         true,
	"port-unreachable":            true,
	"precedence-cutoff":           true,
	"precedence-violation":        true,
	"protocol-unreachable":        true,
	"source-host-isolated":        true,
	"source-route-failed":         true,
	"tcp-reset":                   true,
}

func compileFilterThen(node *Node, term *FirewallFilterTerm) {
	// Handle leaf form: "then discard;" or "then accept;" produces
	// Keys=["then", "discard"] with IsLeaf=true and no children. A leaf can
	// also carry an argument-bearing modifier, e.g. "then forwarding-class be"
	// → Keys=["then","forwarding-class","be"], so the keyword consumes its
	// following token rather than treating it as a separate action.
	if node.IsLeaf && len(node.Keys) >= 2 {
		keys := node.Keys[1:]
		for i := 0; i < len(keys); i++ {
			k := keys[i]
			arg := func() string {
				// Consume the modifier's argument if present.
				if i+1 < len(keys) {
					i++
					return keys[i]
				}
				return ""
			}
			switch k {
			case "accept":
				term.Action = "accept"
				term.TerminalActions = append(term.TerminalActions, "accept")
			case "reject":
				term.Action = "reject"
				term.TerminalActions = append(term.TerminalActions, "reject")
				// Junos `then reject <message-type>`: the term is a plain
				// reject; capture a KNOWN message-type for fidelity. Only
				// consume the following token if it is a recognized type — a
				// typo (e.g. `reject blorp`) must fall through to the default
				// arm and be flagged, not silently swallowed as the reject arg.
				if i+1 < len(keys) && rejectMessageTypes[keys[i+1]] {
					i++
					term.RejectMessageType = keys[i]
				}
			case "discard":
				term.Action = "discard"
				term.TerminalActions = append(term.TerminalActions, "discard")
			case "next":
				// `then next term` / bare `then next` — explicit fall-through
				// to the next term (a no-op terminating-wise). Consume an
				// optional "term" token.
				term.NextTerm = true
				if i+1 < len(keys) && keys[i+1] == "term" {
					i++
				}
			case "log":
				term.Log = true
			case "syslog":
				// #6853: record the distinct action, and keep Log set so the
				// dataplane still emits the event. Behaviour-preserving.
				term.Log = true
				term.Syslog = true
			case "routing-instance":
				if v := arg(); v != "" {
					term.RoutingInstance = v
				}
			case "count":
				if v := arg(); v != "" {
					term.Count = v
				}
			case "forwarding-class":
				if v := arg(); v != "" {
					term.ForwardingClass = v
				}
			case "loss-priority":
				if v := arg(); v != "" {
					term.LossPriority = v
				}
			case "dscp", "traffic-class":
				if v := arg(); v != "" {
					term.DSCPRewrite = v
				}
			case "policer":
				if v := arg(); v != "" {
					term.Policer = v
				}
			default:
				// #2399 (032-16): an unrecognized `then` token must NOT be
				// silently dropped — it would default to ACCEPT in the
				// dataplane (fail-open). Record it so the strict commit gate
				// (validateFilterActionsStrict) can reject the operator's typo.
				term.UnknownActions = append(term.UnknownActions, k)
			}
		}
		return
	}

	// issue 8939: FLATTEN A CHAIN BEFORE WALKING. The flat-set spelling
	// `set … then count c1 dscp af11` is ONE command, and SetPath nests the
	// leaves rather than making them siblings:
	//
	//	[then]
	//	  [count c1]
	//	    [dscp af11]
	//
	// so this loop -- which walks DIRECT children -- sees `count` and nothing
	// else. The braced and packed-tail spellings are handled above and by
	// packedStatements; this is the third shape.
	//
	// Same remedy as #6524's applicationDirectLeaves, and for the reason that
	// issue recorded: the chain is a SUPPORTED spelling, so the reader learns
	// to walk it rather than the schema learning to reject it -- a reject would
	// leave the LENIENT path (boot load, HA SyncApply) untouched, which is
	// exactly where already-stored configs are.
	for _, child := range flattenThenChain8939(node.Children) {
		// #8971: A TRAILING TOKEN ON A `then` ACTION WAS SILENTLY DISCARDED.
		//
		//	then { count c1 c2; }      count="c1"       c2 DISCARDED, warnings=0
		//	then { dscp af11 af21; }   dscp="af11"      af21 DISCARDED
		//	then { accept extra1; }    action="accept"  extra1 DISCARDED
		//
		// Each arm below reads child.Keys[1] and ignores Keys[2:], so a token
		// the operator typed vanished with no rejection and no warning. The
		// LEAF path already recorded an unrecognised token in UnknownActions
		// (#2399) precisely so the strict gate could refuse the typo; the
		// CHILDREN path did not, so which of the two you got depended on the
		// spelling.
		//
		// Recorded here rather than rejected inline: validateFilterActionsStrict
		// already turns UnknownActions into a commit refusal with a message
		// naming the token, and the tolerant path already warns. Reusing that
		// keeps ONE answer for "the operator typed something we do not know"
		// instead of a second one that only this spelling reaches.
		if extras := thenActionExtras8971(child); len(extras) > 0 {
			term.UnknownActions = append(term.UnknownActions, extras...)
		}
		switch child.Name() {
		case "accept":
			term.Action = "accept"
			term.TerminalActions = append(term.TerminalActions, "accept")
		case "reject":
			term.Action = "reject"
			term.TerminalActions = append(term.TerminalActions, "reject")
			// `then reject <message-type>` — capture a KNOWN type for fidelity;
			// a typo after reject is flagged (see leaf-form note above). The
			// message-type is the second key (block form) or a single child.
			if len(child.Keys) >= 2 && rejectMessageTypes[child.Keys[1]] {
				term.RejectMessageType = child.Keys[1]
			} else if len(child.Keys) >= 2 {
				// Unknown token after reject — a typo. Flag it.
				term.UnknownActions = append(term.UnknownActions, "reject "+child.Keys[1])
			} else {
				for _, mt := range child.Children {
					if len(mt.Keys) >= 1 {
						if rejectMessageTypes[mt.Keys[0]] {
							term.RejectMessageType = mt.Keys[0]
						} else {
							term.UnknownActions = append(term.UnknownActions, "reject "+mt.Keys[0])
						}
					}
				}
			}
		case "discard":
			term.Action = "discard"
			term.TerminalActions = append(term.TerminalActions, "discard")
		case "next":
			// `then next term` / bare `then next` — explicit fall-through.
			term.NextTerm = true
		case "log":
			term.Log = true
		case "syslog":
			// #6853: record the distinct action, and keep Log set so the
			// dataplane still emits the event. Behaviour-preserving.
			term.Log = true
			term.Syslog = true
		case "routing-instance":
			if len(child.Keys) >= 2 {
				term.RoutingInstance = child.Keys[1]
			}
		case "count":
			if len(child.Keys) >= 2 {
				term.Count = child.Keys[1]
			}
		case "forwarding-class":
			if len(child.Keys) >= 2 {
				term.ForwardingClass = child.Keys[1]
			}
		case "loss-priority":
			if len(child.Keys) >= 2 {
				term.LossPriority = child.Keys[1]
			}
		case "dscp", "traffic-class":
			term.DSCPRewrite = nodeVal(child)
		case "policer":
			if len(child.Keys) >= 2 {
				term.Policer = child.Keys[1]
			}
		default:
			// #2399 (032-16): see leaf-form note above — record the unknown
			// `then` token for the strict commit gate instead of dropping it.
			term.UnknownActions = append(term.UnknownActions, child.Name())
		}
	}
}

// flattenThenChain8939 hoists actions that SetPath nested beneath a terminating
// `then` action into siblings. Recursive: one `set` command can chain several.
//
// GATED ON THE SCHEMA, not applied blanket. `then reject <message-type>`
// legitimately carries a body -- `reject` declares fourteen message-type
// children -- and hoisting that would turn the message type into a sibling
// action. Only an action the schema says holds NOTHING can have something
// nested under it by the chain, and that is the discriminator.
func flattenThenChain8939(children []*Node) []*Node {
	var thenSchema *schemaNode
	if fam := resolveSchemaChild(setSchema, "firewall"); fam != nil {
		if f := resolveSchemaChild(fam, "family"); f != nil {
			if inet := resolveSchemaChild(f, "inet"); inet != nil {
				if filt := resolveSchemaChild(inet, "filter"); filt != nil {
					if filt.wildcard != nil {
						filt = filt.wildcard
					}
					if tm := resolveSchemaChild(filt, "term"); tm != nil {
						if tm.wildcard != nil {
							tm = tm.wildcard
						}
						thenSchema = resolveSchemaChild(tm, "then")
					}
				}
			}
		}
	}
	if thenSchema == nil {
		return children
	}
	var out []*Node
	changed := false
	var visit func(n *Node)
	visit = func(n *Node) {
		if n == nil {
			return
		}
		act := resolveSchemaChild(thenSchema, n.Name())
		if act == nil || len(act.children) > 0 || act.wildcard != nil || len(n.Children) == 0 {
			out = append(out, n)
			return
		}
		// A terminating action carrying children: the chain. Keep the action,
		// hoist what was nested under it.
		changed = true
		head := &Node{
			Keys:       append([]string(nil), n.Keys...),
			IsLeaf:     true,
			Annotation: n.Annotation,
			Inactive:   n.Inactive,
			Line:       n.Line,
			Column:     n.Column,
		}
		if n.KeysQuoted != nil {
			head.KeysQuoted = append([]bool(nil), n.KeysQuoted...)
		}
		out = append(out, head)
		for _, c := range n.Children {
			visit(c)
		}
	}
	for _, c := range children {
		visit(c)
	}
	if !changed {
		// #9153: even with no CHAIN to hoist, a single node can carry a packed
		// RUN of actions on its own Keys.
		return expandFlatRun(children, thenSchema)
	}
	// #9153: HOISTING THE CHAIN IS NOT ENOUGH -- THE LAST LINK CARRIES A RUN.
	//
	//	set ... term t1 then count c1 log discard
	//	  then > [count c1] > [log discard]        <- one node, TWO actions
	//
	// flattenThenChain8939 lifts each nested node out of the chain, but a node
	// whose Keys are `[log discard]` is still one node, and compileFilterThen
	// reads its first key and drops the rest. The terminating `discard` was
	// therefore LOST while `count` and `log` survived, so the term fell through
	// to whatever followed -- a FAIL-OPEN, on a clean commit with no warnings.
	//
	// expandFlatRun splits a node's Keys at every token the container declares
	// as another leaf, which is exactly this. It is arity-aware since #9124, so
	// `count c1` is not cut at its VALUE.
	return expandFlatRun(out, thenSchema)
}

// thenActionExtras8971 returns the tokens a `then` action carries beyond its
// declared arity — the ones every arm of the children walk reads past.
//
// #8971: the arity comes from the SCHEMA rather than a hand-kept list, so a new
// `then` action is covered the day it is declared. A keyword the schema does not
// know is left alone: the switch's own default arm reports that, and reporting
// it twice would name the same token in two messages.
func thenActionExtras8971(child *Node) []string {
	if child == nil || len(child.Keys) < 2 {
		return nil
	}
	thenSchema := filterThenSchema8971()
	if thenSchema == nil {
		return nil
	}
	act := resolveSchemaChild(thenSchema, child.Keys[0])
	if act == nil || act.multi || len(act.children) > 0 || act.wildcard != nil {
		// Unknown keyword, a value list, or a container: not this gate's
		// business.
		return nil
	}
	start := 1 + act.args
	if start >= len(child.Keys) {
		return nil
	}
	return append([]string(nil), child.Keys[start:]...)
}

// filterThenSchema8971 resolves the firewall filter term `then` container.
func filterThenSchema8971() *schemaNode {
	fw := resolveSchemaChild(setSchema, "firewall")
	if fw == nil {
		return nil
	}
	fam := resolveSchemaChild(fw, "family")
	if fam == nil {
		return nil
	}
	inet := resolveSchemaChild(fam, "inet")
	if inet == nil {
		return nil
	}
	filt := resolveSchemaChild(inet, "filter")
	if filt == nil {
		return nil
	}
	if filt.wildcard != nil {
		filt = filt.wildcard
	}
	tm := resolveSchemaChild(filt, "term")
	if tm == nil {
		return nil
	}
	if tm.wildcard != nil {
		tm = tm.wildcard
	}
	return resolveSchemaChild(tm, "then")
}
