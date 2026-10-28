package config

import (
	"fmt"
	"sort"
	"strings"
)

// #16450: the firewall ROOT, `family`, family-member and filter levels were
// open-world above the #10294 term gate.
//
// A misspelt keyword at any of those levels strict-committed clean with
// zero warnings and silently dropped the line:
//
//	set firewall family inet filter wan-in trem allow-ssh from source-address 198.51.100.0/24
//
// is filed under a `trem` node. SchemaValidate passed it (open-world),
// compileFirewall only ever visits `term` children of a filter, so term
// allow-ssh was built only from its other lines: an accept for TCP/22
// from ANY source. The mirror shapes are `fitler`/`filters` at the family
// level (the whole line's filter is never compiled, while sibling lines
// under the correct `filter` still build a widened/partial filter),
// `tem`/`trem`/`terms` at the filter level, `filtre` at the family level,
// `fam` for `family` at the firewall root, and any other unknown child
// directly under `firewall`, under a family member, or under a filter.
//
// WHY NOT closedWorld: closedWorld INHERITS (see #9017), so arming it on
// `family` or `filter` would close the entire term grammar beneath and
// reject valid configuration such as `from source-prefix-list trusted`.
// This gate is scoped to exactly the levels it judges and inherits
// nothing. The permitted sets are READ FROM THE SCHEMA (#9017's rule),
// so a keyword declared later is permitted automatically.
//
// It runs on the AST (pre-walk, after compact normalization and implicit-
// inet re-homing, before section compilation) for the reason the defect
// exists at all: an unknown child at these levels compiles to NOTHING or
// to a widened term, so by the time cfg.Firewall exists there is no
// trace of the dropped token left to validate. That also covers cases a
// typed-config gate cannot see: a filter whose EVERY line is misspelt
// (no filter is compiled at all), a misspelt `family` keyword at the
// root (`fam`, folded into #16450 by the reconcile as R3-B24-04), and an
// unknown child directly under `firewall` (`xpfbogus`).
//
// Strict (commit / commit-check) hard-rejects the first offender.
// Lenient (Store.Load / Store.SyncApply) warns once per distinct finding
// so an already-persisted or peer-synced config still BOOTS (#1960);
// compilation continues with the pre-#16450 behaviour there (the dropped
// line stays dropped — the warning is the diagnostic, exactly as the
// sibling AST gates #9017/#9323/#9552 do).
//
// Apply statements (apply-groups / apply-groups-except / apply-macro,
// #7029) are Junos meta statements permitted at any hierarchy point and
// are never judged, at any of the four levels. Quoted/bracketed tokens
// are authored values, never statement heads (#9635): a packed tail scan
// stops at the first such token instead of inventing a keyword from it.

// firewallLevelChildTokens16450 returns the statement keywords declared
// directly under a schema node, sorted, or nil if the node is missing.
func firewallLevelChildTokens16450(n *schemaNode) []string {
	if n == nil {
		return nil
	}
	out := make([]string, 0, len(n.children))
	for k := range n.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// firewallFamilyMemberSchema16450 resolves the `filter`-carrying schema
// node for a family member token (inet/inet6/any), or nil.
func firewallFamilyMemberSchema16450(af string) *schemaNode {
	fam := schemaFirewall.children["family"]
	if fam == nil {
		return nil
	}
	return fam.children[af]
}

type firewallLevelGate16450 struct {
	lenient  bool
	warnings []string
	seen     map[string]bool
}

func (g *firewallLevelGate16450) report(msg string) error {
	if !g.lenient {
		return fmt.Errorf("%s", msg)
	}
	if !g.seen[msg] {
		g.seen[msg] = true
		g.warnings = append(g.warnings, msg)
	}
	return nil
}

// check judges one statement head tok at a level whose permitted set is
// declared (sorted, for the message). ctx identifies the level in the
// diagnostic (e.g. `firewall family inet filter "wan-in"`).
func (g *firewallLevelGate16450) check(ctx, tok string, declared []string) error {
	if tok == "" || routingInstanceApplyMetaKeyword9323(tok) {
		return nil
	}
	for _, d := range declared {
		if d == tok {
			return nil
		}
	}
	msg := fmt.Sprintf("%s: unknown child %q (#16450): "+
		"the compiler reads only %s here; remove the typo — the line is dropped and any term it belonged to compiles without it",
		ctx, tok, strings.Join(declared, ", "))
	return g.report(msg)
}

// checkPackedTail judges statement heads packed onto node.Keys starting
// at index from, walking descend's grammar the way
// firstUnknownPackedKeyword15778 does: a resolving child consumes
// 1+args keys (plus a compoundKey sub-token); a leaf with no
// children/wildcard owns the rest of the tail as values and ends the
// scan; quoted/bracketed tokens are values and end the scan. Only the
// first unknown head is reported — everything after it is that unknown
// statement's own tail.
func (g *firewallLevelGate16450) checkPackedTail(ctx string, node *Node, descend *schemaNode, from int, declared []string) error {
	if descend == nil || node == nil {
		return nil
	}
	i := from
	for i < len(node.Keys) {
		if node.KeyQuoted(i) || node.KeyBracketed(i) {
			return nil
		}
		tok := node.Keys[i]
		child := descend.children[tok]
		if child == nil {
			// Not a statement head at this level. Could be an authored
			// value of a preceding leaf that owns the tail — but the
			// caller guarantees Keys[from] is a statement head and every
			// resolving step below consumes values positionally, so a
			// token reaching here unresolved IS an unknown head.
			return g.check(ctx, tok, declared)
		}
		if (child.children == nil && child.wildcard == nil) || child.closedWorldOpaque {
			// Leaf owns the rest as values/body.
			return nil
		}
		consumed := 1 + child.args
		if child.compoundKey && i+1 < len(node.Keys) {
			consumed++
		}
		i += consumed
		// A container head's own args are consumed; its packed BODY
		// statements (if any) ride as children, not keys, for the
		// shapes reaching this gate after compact normalization. Any
		// further keys are the next packed sibling head, judged by the
		// next loop iteration against the same level grammar.
	}
	return nil
}

// validateFirewallLevelChildrenAST16450 is the #16450 gate. See file doc.
func validateFirewallLevelChildrenAST16450(nodes []*Node, lenient bool) ([]string, error) {
	rootDeclared := firewallLevelChildTokens16450(schemaFirewall)
	if len(rootDeclared) == 0 {
		// Schema unreadable: decline to judge rather than refuse every
		// firewall config (mirrors #9323/#9552).
		return nil, nil
	}
	g := &firewallLevelGate16450{lenient: lenient, seen: map[string]bool{}}
	for _, fw := range nodes {
		if fw == nil || fw.Name() != "firewall" {
			continue
		}
		if err := g.walkFirewallRoot(fw, rootDeclared); err != nil {
			return g.warnings, err
		}
	}
	return g.warnings, nil
}

// walkFirewallRoot judges children directly under one `firewall` node:
// declared children are family/filter/policer/three-color-policer;
// anything else (fam, xpfbogus, ...) is unknown. A packed root node
// (`firewall family inet filter ...` as one leaf) carries its first
// statement head on Keys[1], judged via the packed-tail walk.
func (g *firewallLevelGate16450) walkFirewallRoot(fw *Node, rootDeclared []string) error {
	if len(fw.Keys) >= 2 {
		// Packed/elided root: Keys[1] is the first statement head and
		// its body rides as children of the resolved statement — after
		// compact normalization this shape normally no longer reaches
		// the gate; judge the head token only.
		if err := g.check("firewall", fw.Keys[1], rootDeclared); err != nil {
			return err
		}
	}
	for _, child := range fw.Children {
		if child == nil {
			continue
		}
		name := child.Name()
		if routingInstanceApplyMetaKeyword9323(name) {
			continue
		}
		switch name {
		case "family":
			if err := g.walkFamilyNode(child); err != nil {
				return err
			}
		case "filter":
			// Implicit-inet filter: after normalizeImplicitInetFilters9899
			// these are re-homed under family inet before the pre-walk,
			// but judge defensively if one reaches here (direct callers).
			for _, inst := range namedInstances([]*Node{child}) {
				if err := g.walkFilterInstance("firewall family inet", "inet", inst.name, inst.node); err != nil {
					return err
				}
			}
		case "policer", "three-color-policer":
			// Declared; their bodies are owned by their own gates
			// (closedWorld on policer, UnknownActions, ...). Not judged here.
			continue
		default:
			if err := g.check("firewall", name, rootDeclared); err != nil {
				return err
			}
		}
	}
	return nil
}

// walkFamilyNode judges one `family` node via its members (the shared
// familyMembers extractor, so the token judged is the token
// the compiler installs under).
func (g *firewallLevelGate16450) walkFamilyNode(famNode *Node) error {
	// Every child of the set-command shape becomes a member via the
	// extractor, and the packed shape's member IS famNode — so the
	// member walk judges every child at this level. Keys past the
	// family token on a structured node are residue owned by #9017.
	for _, m := range familyMembers(famNode) {
		if err := g.walkFamilyMember(m); err != nil {
			return err
		}
	}
	return nil
}

func (g *firewallLevelGate16450) walkFamilyMember(m familyMember) error {
	afNode := m.AfNode
	if afNode == nil {
		return nil
	}
	ctx := fmt.Sprintf("firewall family %s", m.Af)
	memberSchema := firewallFamilyMemberSchema16450(m.Af)
	declared := firewallLevelChildTokens16450(memberSchema)
	if len(declared) == 0 {
		// Undeclared family token: the #9017 gate owns it and
		// compileFirewall quarantines it to nothing. Decline here so
		// the operator gets the one precise #9017 diagnostic.
		return nil
	}
	// Packed member tail: `family inet filter f ...` packed onto the
	// member node's keys (flat-set shape before SetPath nesting, or a
	// hand-built tree). Keys are [family, inet, <head>...] for the
	// packed shape and [inet, <head>...] for a set-shape child. Find
	// the head offset: the first key past the family token.
	if len(afNode.Children) == 0 && len(afNode.Keys) >= 2 {
		// Leaf member: the tail past the family token is a flattened
		// set-command remainder (e.g. [fam...] never reaches here; a
		// leaf [family inet filter f term t then accept] or
		// [inet filter f ...]). Judge its first head only if it is
		// not the family token itself.
		headIdx := -1
		for i, k := range afNode.Keys {
			if k == m.Af {
				headIdx = i + 1
				break
			}
		}
		if headIdx >= 0 && headIdx < len(afNode.Keys) {
			if err := g.checkPackedTail(ctx, afNode, memberSchema, headIdx, declared); err != nil {
				return err
			}
			// If the head resolved to `filter`, the filter instance on
			// the tail is still compiled by namedInstances elsewhere;
			// its body's packed term heads are compiler-owned shapes
			// the term gate covers. Nothing more at this level.
			return nil
		}
		return nil
	}
	for _, child := range afNode.Children {
		if child == nil {
			continue
		}
		name := child.Name()
		if routingInstanceApplyMetaKeyword9323(name) {
			continue
		}
		if name != "filter" {
			if err := g.check(ctx, name, declared); err != nil {
				return err
			}
			continue
		}
		for _, inst := range namedInstances([]*Node{child}) {
			if err := g.walkFilterInstance(ctx, m.Af, inst.name, inst.node); err != nil {
				return err
			}
		}
	}
	return nil
}

// walkFilterInstance judges children directly under one filter
// instance: only `interface-specific` and `term` are declared. Anything
// else (trem, terms, tem, xpfbogus, ...) is unknown. Packed filter
// tails (`filter f term t ...` flattened) carry the first body head
// past the filter name.
func (g *firewallLevelGate16450) walkFilterInstance(familyCtx, af, filterName string, node *Node) error {
	if node == nil {
		return nil
	}
	ctx := fmt.Sprintf("%s filter %q", familyCtx, filterName)
	memberSchema := firewallFamilyMemberSchema16450(af)
	var filterSchema *schemaNode
	if memberSchema != nil {
		filterSchema = memberSchema.children["filter"]
	}
	declared := firewallLevelChildTokens16450(filterSchema)
	if len(declared) == 0 {
		return nil
	}
	if len(node.Children) == 0 && len(node.Keys) >= 2 {
		// Packed leaf: [filter, <name>, <head>...] or [<name>, <head>...].
		headIdx := -1
		for i, k := range node.Keys {
			if k == filterName {
				headIdx = i + 1
				break
			}
		}
		if headIdx >= 0 && headIdx < len(node.Keys) {
			return g.checkPackedTail(ctx, node, filterSchema, headIdx, declared)
		}
		return nil
	}
	for _, child := range node.Children {
		if child == nil {
			continue
		}
		name := child.Name()
		if routingInstanceApplyMetaKeyword9323(name) {
			continue
		}
		if name == "interface-specific" || name == "term" {
			continue
		}
		if err := g.check(ctx, name, declared); err != nil {
			return err
		}
	}
	return nil
}
