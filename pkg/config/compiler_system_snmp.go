package config

// compiler_system_snmp.go holds the SNMP compiler evicted from
// compiler_system.go (#16146): pure in-package code motion,
// unchanged call graph. The package-level snmpCommunityPermitted15124
// cache below keeps its single declaration; Go package initialization
// order is dependency-driven, so the move changes no init ordering.

import (
	"fmt"
	"sort"
	"strings"
)

// #15124 (A85-05): an UNKNOWN child of `snmp community <c>` — `client
// 10.0.0.0/8`, `clinets …`, `client-list-nam L`, or any other undeclared
// keyword — was skipped by both community walks with no error or warning,
// so a one-letter typo in the operator-authored source ACL left the
// community answering EVERY source (AllowsSource reads an empty allowlist
// as allow-all) on a green commit. Prior fixes (#4289, #4834, #5472,
// #5833, #5898, #8778, #9416, #10687) each fixed a NAMED spelling; none
// added a default arm. This gate is that default arm.
//
// NOT closedWorld on the community schema: that flag INHERITS, and the
// recorded #9265 measurement shows it would refuse the legal flat-set
// chain `community <c> client-list-name L authorization read-only`
// (the inherited walk sees `authorization` under the terminal
// `client-list-name` leaf) and the deliberate accept-with-advisory
// `view` knob (#4306). This gate is scoped to the community level,
// inherits nothing, and reads its permitted set from the schema
// (snmpCommunitySchema9416) so a child declared later is permitted
// automatically. The inert knobs `view` and `logical-system` stay
// accept-with-advisory (snmpInertKnobWarnings) and are permitted here.
//
// Strict (commit / commit-check): hard-reject naming the token.
// Lenient (load / peer-sync): warn AND quarantine the community to
// deny-all, the #5833 shape — the authored restriction (if any) cannot
// be trusted, so the community must not answer any source until the
// operator fixes the typo. Never echoes the community NAME (a secret).

// snmpCommunityKnownChildren15124 returns the permitted child keywords
// of `snmp community <c>`: the schema-declared children plus the inert
// knobs the compiler deliberately accepts with an advisory.
func snmpCommunityKnownChildren15124() (permitted map[string]bool, declared []string) {
	permitted = map[string]bool{}
	if schema := snmpCommunitySchema9416(); schema != nil {
		for k := range schema.children {
			permitted[k] = true
		}
	}
	// Inert knobs accepted with an advisory by snmpInertKnobWarnings
	// (#4306/#9416): modelled nowhere, enforced nowhere, but NAMED at
	// commit — not unknown, and not source restrictions to quarantine
	// over (a `logical-system` block's nested restriction already gets
	// its own explicit fail-open advisory there).
	permitted["view"] = true
	permitted["logical-system"] = true
	declared = make([]string, 0, len(permitted))
	for k := range permitted {
		declared = append(declared, k)
	}
	sort.Strings(declared)
	return permitted, declared
}

// snmpCommunityUnknownMessage renders the operator-facing text for an
// unknown community child. `lenient` appends the quarantine note, so the
// two paths cannot describe the same condition differently. Only the
// offending TOKEN is named — never the community name (a secret).
func snmpCommunityUnknownMessage15124(tok string, declared []string, lenient bool) string {
	msg := fmt.Sprintf(
		"snmp community: %q is not a community statement xpf implements (known: %s) — it compiles to NOTHING: it commits clean, renders in `show configuration`, and has no effect; a mistyped source restriction (e.g. `client` for `clients`, `client-list-nam` for `client-list-name`) would leave the community answering every source (#15124)",
		tok, strings.Join(declared, ", "))
	if lenient {
		msg += "; the affected community is quarantined to deny-all until the statement is fixed"
	}
	return msg
}

// snmpCommunityUnknownChildren15124 reports the unknown child keywords
// authored under one community block, across every AST shape
// compileSNMP accepts:
//
//   - braced / hierarchical children (after expandFlatRun, the same view
//     the statement collection reads, so flat-set chains are judged as
//     the statements they flatten to);
//   - the Keys-packed run on the community node itself
//     (`community <c> client 10.0.0.0/8;` brace-elided), scanned with the
//     schema's arity so a declared leaf's VALUE is never mistaken for a
//     keyword — including a `clients` value run, which ends only at the
//     next declared keyword;
//   - children nested under a leaf the walk descends through
//     (`authorization`, `routing-instance`): a flat-set chain nests the
//     next statement there, and an unknown token in that position is the
//     same typo one level down. `routing-instance`'s own body is
//     closedWorld in the schema, so only its chain-nested siblings are
//     judged here, not its declared body.
//
// Apply statements are skipped (Junos permits them at any level, #7029).
// A declared leaf's value children (e.g. the braced `clients { … }`
// entries) are VALUES, never judged.
func snmpCommunityUnknownChildren15124(child *Node, commChildren []*Node, permitted map[string]bool) []string {
	var unknown []string
	seen := map[string]bool{}
	report := func(tok string) {
		if tok == "" || seen[tok] {
			return
		}
		seen[tok] = true
		unknown = append(unknown, tok)
	}
	// Keys-packed run on the community node: Keys[0]=="community",
	// Keys[1]==<name>, the rest is the packed body.
	packedSchema := snmpCommunitySchema9416()
	for i := 2; i < len(child.Keys); i++ {
		tok := child.Keys[i]
		if isApplyStatementKeyword(tok) {
			break
		}
		if !permitted[tok] {
			report(tok)
			break
		}
		leaf := resolveSchemaChild(packedSchema, tok)
		if leaf == nil {
			break
		}
		if leaf.multi {
			// A multi leaf (`clients`) owns the whole value run: it ends
			// only at the next DECLARED keyword.
			j := i + 1
			for j < len(child.Keys) && resolveSchemaChild(packedSchema, child.Keys[j]) == nil && !isApplyStatementKeyword(child.Keys[j]) {
				j++
			}
			i = j - 1
			continue
		}
		i += leaf.args
		// A container leaf (`routing-instance`) packs its body's first
		// keyword next; the following iterations judge it, because the
		// container's declared body keywords are not community children.
		if len(leaf.children) > 0 {
			for k := i + 1; k < len(child.Keys); k++ {
				inner := child.Keys[k]
				if isApplyStatementKeyword(inner) {
					break
				}
				if _, ok := leaf.children[inner]; !ok {
					report(inner)
					break
				}
				innerLeaf := leaf.children[inner]
				if innerLeaf.multi {
					m := k + 1
					for m < len(child.Keys) && resolveSchemaChild(packedSchema, child.Keys[m]) == nil && leaf.children[child.Keys[m]] == nil && !isApplyStatementKeyword(child.Keys[m]) {
						m++
					}
					k = m - 1
					continue
				}
				k += innerLeaf.args
			}
			break
		}
	}
	// Expanded child statements, plus any statement nested under a leaf
	// the statement collection descends through (flat-set chain links).
	var walkNested func(nodes []*Node)
	walkNested = func(nodes []*Node) {
		for _, n := range nodes {
			if n == nil || len(n.Keys) == 0 {
				continue
			}
			tok := n.Name()
			if isApplyStatementKeyword(tok) {
				continue
			}
			if !permitted[tok] {
				report(tok)
				continue
			}
			// Only the descent keywords can carry a chain-nested sibling;
			// a declared leaf's children are its VALUES.
			switch tok {
			case "authorization", "routing-instance":
				walkNested(n.Children)
			}
		}
	}
	walkNested(commChildren)
	return unknown
}

// snmpCommunityPermitted15124 / snmpCommunityDeclared15124 cache the
// gate's permitted set (schema-derived + inert knobs) so compileSNMP
// does not rebuild and re-sort it per community block.
var snmpCommunityPermitted15124, snmpCommunityDeclared15124 = func() (map[string]bool, []string) {
	return snmpCommunityKnownChildren15124()
}()

func compileSNMP(node *Node, sys *SystemConfig, cfg *Config, lenient bool) error {
	snmp := sys.SNMP
	if snmp == nil {
		snmp = &SNMPConfig{}
	}
	if snmp.Communities == nil {
		snmp.Communities = make(map[string]*SNMPCommunity)
	}
	if snmp.TrapGroups == nil {
		snmp.TrapGroups = make(map[string]*SNMPTrapGroup)
	}
	if snmp.V3Users == nil {
		snmp.V3Users = make(map[string]*SNMPv3User)
	}
	if snmp.ClientLists == nil {
		snmp.ClientLists = make(map[string][]SNMPClient)
	}

	// #9416: read the `snmp` stanza's own PACKED body, not `node.Children`.
	//
	// `snmp client-list trusted 10.0.0.0/8;` written with the outer brace
	// elided puts the whole run on the snmp node's OWN Keys with no Children at
	// all, and a loop over Children sees an empty body -- the #2419 class, and
	// the reason `snmp client-list` appeared as a NEW compact-blind site the
	// moment this compiler learned the keyword. The inline `clients` sibling is
	// NOT compact-blind (compileSNMP has a bespoke Keys scan for the community
	// body), so registering the named form in the divergence inventory would
	// have shipped it strictly worse than the spelling it is meant to match.
	//
	// packedBodyChildren resolves the tail THROUGH THE SCHEMA and returns
	// node.Children unchanged when there is no tail, so the ordinary braced
	// spelling is bit-identical.
	snmpChildren := packedBodyChildren(node, resolveSchemaChild(setSchema, "snmp"))
	// A brace-elided `system snmp <scalar> <value>` line is stored on the
	// system node's Keys. Its scalar keywords are intentionally outside the
	// shared top-level SNMP schema, so preserve those directly here.
	if len(node.Keys) >= 3 {
		switch node.Keys[1] {
		case "location":
			snmp.Location = node.Keys[2]
		case "contact":
			snmp.Contact = node.Keys[2]
		case "description":
			snmp.Description = node.Keys[2]
		}
	}

	// #9416 PRE-PASS: collect every `snmp client-list <name>` definition BEFORE
	// the community loop. A community may reference a list that is written
	// AFTER it -- Junos imposes no ordering, and `show configuration` sorts
	// `client-list` before `community` anyway, but a persisted or peer-synced
	// tree carries whatever order it was built in. Resolving inside the
	// community loop would make an ordering the operator cannot see decide
	// whether the restriction applies or the community is quarantined.
	//
	// Same-name blocks ACCUMULATE rather than overwrite, for the reason #5472
	// established on the community side: a later empty block must not be able
	// to erase an earlier block's prefixes, because an emptied list resolves to
	// the unresolved arm and (lenient) quarantines every community that
	// references it.
	// #15706: a two-level container (`client-list { <L> { ... } }`) names its
	// instances one level down. namedInstances peels that level (Keys<2 ->
	// children are the instances); the named spelling (`client-list <L> ...`)
	// passes through unchanged. Without this only the first?/named spelling
	// was read and every two-level list was dropped, leaving referencing
	// communities unresolved (strict reject / lenient quarantine).
	for _, child := range snmpChildren {
		if child.Name() != "client-list" {
			continue
		}
		for _, inst := range namedInstances([]*Node{child}) {
			if inst.name == "" {
				continue
			}
			// parseSNMPClientListPrefixes expects Keys[1]==list name.
			// namedInstances returns the sub-node (Keys[0]==name) for the
			// two-level shape, so synthesize the named node shape it reads.
			node := inst.node
			if len(node.Keys) < 2 || node.Keys[1] != inst.name {
				node = &Node{Keys: append([]string{"client-list", inst.name}, node.Keys[1:]...), Children: node.Children}
			}
			snmp.ClientLists[inst.name] = append(snmp.ClientLists[inst.name], parseSNMPClientListPrefixes(node)...)
		}
	}
	// #9416: a malformed prefix inside a NAMED list gets the SAME treatment as
	// one inside an inline `clients` run (#4834/#5833) -- strict rejects naming
	// the token, lenient warns and the list is quarantined by emptying it, which
	// routes every referencing community to the unresolved arm below and thence
	// to deny-all. A named list is where this matters MOST: one typo'd
	// `restrict` would otherwise degrade a deny-except entry to a plain allow
	// for every community that references the list, not just one.
	for _, listName := range sortedClientListNames9416(snmp.ClientLists) {
		listWarnings, listMalformed, err := validateSNMPClients(snmp.ClientLists[listName], lenient)
		if err != nil {
			return fmt.Errorf("snmp client-list %q: %w", listName, err)
		}
		if cfg != nil {
			cfg.Warnings = append(cfg.Warnings, listWarnings...)
		}
		if listMalformed {
			snmp.ClientLists[listName] = nil
		}
	}

	// #15124: an UNREFERENCED `snmp client-list` (no community names it via
	// `client-list-name`) restricts nothing. That is not fail-open by
	// itself — no community claims the restriction — but it is the usual
	// residue of a `client-list-nam` typo on the community side, so name it
	// on BOTH paths rather than letting the definition sit silently inert.
	// Referenced names are collected from the same statement views the
	// community loop resolves (children, expanded chains, packed runs).
	if cfg != nil && len(snmp.ClientLists) > 0 {
		referenced := map[string]bool{}
		for _, child := range snmpChildren {
			if child.Name() != "community" {
				continue
			}
			commChildren := child.Children
			if len(child.Keys) < 2 && len(child.Children) > 0 {
				commChildren = child.Children[0].Children
			}
			var stmts []*Node
			var collectRefs func(nodes []*Node)
			collectRefs = func(nodes []*Node) {
				for _, n := range nodes {
					stmts = append(stmts, n)
					collectRefs(n.Children)
				}
			}
			collectRefs(expandFlatRun(commChildren, snmpCommunitySchema9416()))
			for _, ref := range snmpCommunityListRefs(stmts) {
				referenced[ref] = true
			}
			for i := 2; i+1 < len(child.Keys); i++ {
				if child.Keys[i] == "client-list-name" {
					referenced[child.Keys[i+1]] = true
				}
			}
		}
		for _, listName := range sortedClientListNames9416(snmp.ClientLists) {
			if !referenced[listName] {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
					"snmp client-list %q is not referenced by any community `client-list-name` — it restricts no community, so every community without its own `clients` restriction answers every source; if a community was meant to use it, check the `client-list-name` spelling (#15124)", listName))
			}
		}
	}

	// #5833: communities whose `clients` allowlist carried a malformed token on
	// the tolerant load / peer-sync path are quarantined to deny-all. Sticky
	// across same-name merge blocks (#5472): once a community is quarantined a
	// LATER well-formed block must NOT un-quarantine it (its policy is no longer
	// trustworthy). Empty on the strict path (a malformed token hard-rejects
	// before it can be recorded here).
	if snmp.quarantinedComms == nil {
		snmp.quarantinedComms = make(map[string]bool)
	}
	quarantinedComms := snmp.quarantinedComms

	for _, child := range snmpChildren {
		switch child.Name() {
		case "location":
			snmp.Location = nodeVal(child)
		case "contact":
			snmp.Contact = nodeVal(child)
		case "description":
			snmp.Description = nodeVal(child)
		case "community":
			// #15706: peel two-level containers (`community { <c> { ... } }`)
			// via namedInstances so the 2nd+ instance is not dropped; the
			// named spelling passes through as one instance. Body below is
			// per-instance (named `child`/`commName` preserved).
			for _, commInst15706 := range namedInstances([]*Node{child}) {
				child := commInst15706.node
				commName := commInst15706.name
				if commName != "" {
					commChildren := child.Children
					if len(child.Keys) < 2 && len(child.Children) > 0 {
						// Only peel when child is still the container (Keys<2);
						// namedInstances already peeled two-level instances
						// (their node is the instance, Keys[0]==name).
						if child.Name() == "community" {
							commChildren = child.Children[0].Children
						}
					}
					// #15124: reject (strict) / warn + quarantine (lenient) on
					// any UNKNOWN child of this community block, before the
					// statement collection below silently skips it. Judged on
					// the same expanded view the collection reads, plus the
					// Keys-packed run on this node. A quarantined community is
					// forced deny-all at the clientNets build below, sticky
					// across same-name merge blocks like #5833's.
					if unknown := snmpCommunityUnknownChildren15124(child, expandFlatRun(commChildren, snmpCommunitySchema9416()), snmpCommunityPermitted15124); len(unknown) > 0 {
						for _, tok := range unknown {
							msg := snmpCommunityUnknownMessage15124(tok, snmpCommunityDeclared15124, lenient)
							if !lenient {
								return fmt.Errorf("%s", msg)
							}
							if cfg != nil {
								cfg.Warnings = append(cfg.Warnings, msg)
							}
						}
						if lenient {
							quarantinedComms[commName] = true
						}
					}
					// Parse THIS block's authorization + clients into locals first.
					// A same-name sibling block is then MERGED into any existing
					// entry rather than overwriting it (#5472), so a later block
					// cannot silently drop an earlier block's source-IP allowlist.
					var blockAuth string
					var blockClients []SNMPClient
					// #8778: flat `set` builds a CHAIN, not siblings. The command
					//   set snmp community public authorization read-only clients 10.0.0.0/8
					// produces
					//   community public
					//     authorization read-only
					//       clients 10.0.0.0/8        <- CHILD of authorization
					// so a loop over one level sees `authorization` and never sees
					// `clients` at all. The allowlist was silently dropped, and an
					// empty allowlist is documented allow-all rather than deny —
					// the operator's restriction inverted, on a commit that
					// succeeded. Splitting the same statements across two `set`
					// lines enforced correctly, so the difference was a line break.
					//
					// Descend only through keywords this switch recognises. A
					// `clients` node's own children hold its VALUE tokens (prefixes
					// and `restrict`), which parseSNMPClients reads and which must
					// not be mistaken for statements.
					//
					// #9416: `client-list-name` and `routing-instance` join the
					// descent set. They are not decoration -- a keyword this walk
					// does not name is silently skipped, which is precisely how the
					// named-list spelling reached AllowsSource as an empty (=
					// allow-all) allowlist. `routing-instance` carries its own
					// `clients` / `client-list-name` body, so the descent continues
					// through it and those statements are collected as the
					// community's own; the SCOPING is not enforced and
					// snmpInertKnobWarnings says so.
					//
					// #9416: expandFlatRun FIRST. A flat `set` builds a CHAIN and
					// packs its tail onto ONE node's Keys, so
					//   set snmp community c client-list-name L authorization read-only
					// arrives as a single node with
					//   Keys = [client-list-name, L, authorization, read-only]
					// and a reader that treats Keys[1:] as the leaf's values would
					// take "authorization" and "read-only" as two more list NAMES --
					// which then resolve to nothing and quarantine the community.
					// That is fail-closed rather than fail-open, but it rejects a
					// config the operator wrote correctly.
					//
					// The expansion is schema-gated: `clients` is `multi: true` so
					// its value run is never cut, `routing-instance` declares
					// children so its subtree stays whole, and `client-list-name`
					// is `args: 1` so exactly one token follows it. That is the same
					// information the SetPath walk already had; this reader simply
					// never asked for it.
					commChildren = expandFlatRun(commChildren, snmpCommunitySchema9416())
					var stmts []*Node
					var collect func(nodes []*Node)
					collect = func(nodes []*Node) {
						for _, n := range nodes {
							switch n.Name() {
							case "authorization", "clients", "client-list-name":
								stmts = append(stmts, n)
								collect(n.Children)
							case "routing-instance":
								stmts = append(stmts, n)
								// The instance body has TWO packed shapes and both
								// drop the restriction if unread.
								//
								// packedBodyChildren handles `routing-instance ri
								// clients 10.0.0.0/8;` -- the brace-elided spelling,
								// where the whole run sits on this node's own Keys
								// and Children is empty (#2419).
								//
								// expandFlatRun handles the flat-set CHAIN, where
								// `set ... routing-instance ri clients X
								// client-list-name L` nests each leaf under the
								// previous one instead of beside it (#8939).
								//
								// They are different shapes, not two names for one:
								// the first is extra tokens on ONE node, the second
								// is a chain of nodes. Reading only one leaves the
								// other silently allow-all.
								riSchema := snmpRoutingInstanceSchema9416()
								collect(expandFlatRun(packedBodyChildren(n, riSchema), riSchema))
							}
						}
					}
					collect(commChildren)
					blockListRefs := snmpCommunityListRefs(stmts)
					for _, prop := range stmts {
						switch prop.Name() {
						case "authorization":
							blockAuth = nodeVal(prop)
						case "clients":
							// #4289: Junos `clients` source-IP allowlist.
							// parseSNMPClients handles both AST shapes and the
							// per-entry `restrict` modifier. Accumulate so a
							// clients block split across load-merge / flat-set
							// replays is not dropped.
							blockClients = append(blockClients, parseSNMPClients(prop)...)
						}
					}
					// Flat form: the whole community body can arrive packed onto
					// this node's Keys —
					//   community public authorization read-only clients 10.0.0.0/8
					// — which is what `set snmp community public authorization
					// read-only clients 10.0.0.0/8` produces, and what the
					// brace-elided hierarchical spelling produces too.
					//
					// #8778: this loop read `authorization` and NOT `clients`, so
					// the one-line spelling compiled to an EMPTY allowlist. That is
					// not a smaller allowlist, it is the INVERSE of one: AllowsSource
					// documents `len(Clients) == 0` as allow-all (the Junos default),
					// so the community became answerable from every source while the
					// operator's config said otherwise and the commit reported
					// success. Splitting the same statements across two `set` lines
					// enforced correctly, so the difference was a line break.
					//
					// The run after `clients` is handed to parseSNMPClients rather
					// than parsed here, so the `restrict` modifier and the #5898
					// orphan-`restrict` fail-closed path behave identically to the
					// braced spelling instead of being reimplemented beside them.
					//
					// #9416: `client-list-name` and `routing-instance` are cut
					// points here for the same reason they are descent keywords
					// above. Without them the `clients` run-scan would swallow a
					// trailing `client-list-name L` as two more PREFIXES -- both
					// unparseable, which (#4834) hard-rejects on the strict path
					// and quarantines on the lenient one. That is fail-closed
					// rather than fail-open, but it rejects a valid config, so the
					// keyword set here must stay in step with the descent set.
					snmpCommunityKeyword9416 := func(tok string) bool {
						switch tok {
						case "authorization", "clients", "client-list-name", "routing-instance":
							return true
						}
						return false
					}
					for i := 2; i < len(child.Keys); i++ {
						switch child.Keys[i] {
						case "authorization":
							if i+1 < len(child.Keys) {
								blockAuth = child.Keys[i+1]
							}
						case "client-list-name":
							if i+1 < len(child.Keys) {
								blockListRefs = append(blockListRefs, child.Keys[i+1])
							}
						case "routing-instance":
							// Skip the instance NAME; its body's keywords are read
							// by the following iterations exactly as if they had
							// been written at community level.
							i++
						case "clients":
							j := i + 1
							for j < len(child.Keys) && !snmpCommunityKeyword9416(child.Keys[j]) {
								j++
							}
							run := append([]string{"clients"}, child.Keys[i+1:j]...)
							blockClients = append(blockClients, parseSNMPClients(&Node{Keys: run})...)
							i = j - 1
						}
					}
					// #9416: resolve the named lists into the SAME `Clients` field
					// the inline form populates, so AllowsSource, compileClientNets,
					// the API surface and the reconcile hash all keep working on one
					// field rather than acquiring a parallel enforcement path.
					//
					// An UNRESOLVABLE or EMPTY reference must never fall through to
					// allow-all: strict hard-rejects, lenient warns and quarantines
					// the community to deny-all, the same two-channel shape #5833
					// settled on for a malformed inline token.
					resolvedClients, unresolvedRefs := resolveSNMPClientListRefs(blockListRefs, snmp.ClientLists)
					blockClients = append(blockClients, resolvedClients...)
					if len(unresolvedRefs) > 0 {
						if !lenient {
							return snmpUnresolvedClientListError(unresolvedRefs)
						}
						if cfg != nil {
							cfg.Warnings = append(cfg.Warnings, snmpUnresolvedClientListMessage(unresolvedRefs, true))
						}
						quarantinedComms[commName] = true
					}
					// #4834: reject/warn on an unparseable `clients` entry before
					// it reaches compileClientNets. See validateSNMPClients for
					// why this matters beyond a plain prefix typo: it also
					// catches a mistyped "restrict" keyword, which otherwise
					// silently detaches from the preceding prefix and turns a
					// deny-except entry into an unrestricted allow (fail-open).
					// Validate only THIS block's new entries: on the merge path an
					// earlier block's entries were already validated (and, strict,
					// would have aborted), so re-validating the accumulated list
					// would double-report the same warning.
					clientWarnings, blockMalformed, err := validateSNMPClients(blockClients, lenient)
					if err != nil {
						return err
					}
					if cfg != nil {
						cfg.Warnings = append(cfg.Warnings, clientWarnings...)
					}
					// #5833: a malformed token on the lenient path quarantines the
					// community (strict already aborted above). Record it BEFORE the
					// clientNets build below so the deny-all override wins.
					if blockMalformed {
						quarantinedComms[commName] = true
					}
					// #5472: same-name `community` blocks MERGE into one entry
					// instead of a plain map overwrite. Junos treats two
					// `community public { ... }` siblings as a single configuration
					// node; the old `Communities[name] = comm` overwrite let a later
					// duplicate with NO `clients` replace an earlier block that had
					// an allowlist — and AllowsSource reads an empty allowlist as
					// allow-all, so the source-IP restriction was silently erased
					// (security fail-open: any source could then query the
					// community). Accumulating the allowlist keeps the restriction
					// on BOTH the strict commit and the lenient load / HA
					// config-sync paths (a warn-and-keep-last-writer gate would
					// still open the community on the lenient path).
					comm := snmp.Communities[commName]
					if comm == nil {
						comm = &SNMPCommunity{Name: commName}
						snmp.Communities[commName] = comm
					}
					comm.Clients = append(comm.Clients, blockClients...)
					// #9416: preserve the authored references. This is what the
					// reconcile hash reads -- a community whose only restriction is
					// an UNRESOLVABLE reference has an empty Clients and is
					// quarantined through clientNets, which the hash cannot see, so
					// without this an edit that added such a reference to a
					// previously-unrestricted community would hash EQUAL and the
					// running agent would keep serving every source.
					for _, ref := range blockListRefs {
						if !containsString9416(comm.ClientListNames, ref) {
							comm.ClientListNames = append(comm.ClientListNames, ref)
						}
					}
					// A later block updates the authorization only when it
					// explicitly states one; an omitted authorization must NOT
					// clear a value an earlier block established (do not let an
					// empty duplicate downgrade read-write back to the read-only
					// default).
					if blockAuth != "" {
						comm.Authorization = blockAuth
					}
					if comm.Authorization == "" {
						comm.Authorization = "read-only"
					}
					// #4711: (re)build the allocation-free client-prefix cache from
					// the now-merged Clients, so AllowsSource does an
					// allocation-free match per incoming v2c packet instead of
					// re-parsing every prefix on every packet. Runs here, before
					// the config is published to the SNMP agent, so the cache is
					// set with no concurrent readers.
					comm.clientNets = compileClientNets(comm.Clients)
					// #5833: fail CLOSED for a quarantined community. compileClientNets
					// above would drop the malformed token and leave the surviving
					// broad allow live (fail-open); override the enforcement cache with
					// an explicit deny-all so no source can query this community until
					// the operator fixes the typo. Sticky across merge blocks, so a
					// later well-formed block for the same community cannot reopen it.
					if quarantinedComms[commName] {
						comm.clientNets = snmpQuarantineClientNets()
					}
				}
			}
		case "trap-group":
			// #15706: peel two-level containers and MERGE same-name blocks:
			// look up or create the group, accumulate Targets/Categories,
			// update Version only when non-empty. Zero-target validation is
			// deferred until after the whole snmp loop (below) so a later
			// same-name block can supply targets.
			for _, tgInst15706 := range namedInstances([]*Node{child}) {
				tgName := tgInst15706.name
				if tgName == "" {
					continue
				}
				instNode15706 := tgInst15706.node
				tg := snmp.TrapGroups[tgName]
				if tg == nil {
					tg = &SNMPTrapGroup{Name: tgName}
					snmp.TrapGroups[tgName] = tg
				}
				tgChildren := expandFlatRun(packedBodyChildren(instNode15706, schemaForPath("snmp", "trap-group")), schemaForPath("snmp", "trap-group"))
				// packedBodyChildren on a named node with no packed tail
				// returns its Children (the braced body); on a two-level
				// instance node (Keys[0]==name) the schema walk declines
				// and also returns Children. Fall back explicitly.
				if len(tgChildren) == 0 {
					tgChildren = instNode15706.Children
				}
				for _, prop := range tgChildren {
					switch prop.Name() {
					case "targets":
						// targets may carry multiple values: one per child
						// (hierarchical `targets { a; b; }`) and/or packed in
						// the leaf Keys (flat-set / bracketed list).
						tg.Targets = append(tg.Targets, firewallMatchValues(prop)...)
					case "version":
						// #3948: carry the trap-group SNMP version to the
						// emitter. Schema enum is v1|v2|all; an empty value
						// (unspecified) defaults to v2c in pkg/snmp/traps.go.
						// Without this the version was parsed but dropped, so a
						// `version v1` group silently emitted v2c traps that a
						// v1-only receiver drops.
						if v := nodeVal(prop); v != "" {
							tg.Version = v
						}
					case "categories":
						// #5522: retain the configured trap categories so the
						// runtime can enforce the filter. `categories` is a
						// schema `multi: true` leaf, so the bracketed/flat-set
						// list collapses onto the leaf Keys and/or its children
						// (the #2419 dual-shape) — read BOTH via
						// firewallMatchValues. A trap-group with NO categories
						// stanza leaves this nil, which pkg/snmp/traps.go treats
						// as "all categories" (the Junos default). Before this
						// the key was recognized but DISCARDED, so a group
						// scoped to exclude `link` still received every
						// linkUp/linkDown notification (filter bypass).
						tg.Categories = append(tg.Categories, firewallMatchValues(prop)...)
					default:
						// #2990: a typoed child key (e.g. `tragets`) would
						// otherwise be silently dropped, committing a trap
						// group with zero targets that sends nothing. Strict
						// (commit / commit-check): reject so the operator is
						// told about the typo instead of losing every
						// notification at runtime. Lenient (load / HA-sync):
						// downgrade to a warning so an already-persisted bad
						// config still boots — the runtime ignores the unknown
						// key, so it is inert (#1960 fail-closed-on-load).
						if !lenient {
							return fmt.Errorf("snmp trap-group %q: unknown statement %q (valid: targets, version, categories)", tgName, prop.Name())
						}
						if cfg != nil {
							cfg.Warnings = append(cfg.Warnings,
								fmt.Sprintf("snmp trap-group %q: unknown statement %q (downgraded to warning on tolerant path; ignored at runtime)", tgName, prop.Name()))
						}
					}
				}
				// #15706: category vocabulary validation and the zero-target
				// check are deferred to the post-loop validation below, once
				// every same-name block has been merged — a later block may
				// add the missing targets/categories.
			}
		case "v3":
			compileSNMPv3(child, snmp)
		}
	}

	// #15706/#2990/#15256: validate each MERGED trap group once, after all
	// trap-group blocks have accumulated. Deterministic (sorted) order.
	for _, tgName := range sortedTrapGroupNames15706(snmp.TrapGroups) {
		tg := snmp.TrapGroups[tgName]
		if len(tg.Categories) > 0 {
			hasEmitted := false
			for _, cat := range tg.Categories {
				lc := strings.ToLower(strings.TrimSpace(cat))
				if !validTrapCategory15256(lc) {
					if !lenient {
						return fmt.Errorf("snmp trap-group %q: invalid trap category %q (valid Junos categories: authentication, chassis, chassis-cluster, configuration, link, otn-alarms, remote-operations, rmon-alarm, routing, services, sonet-alarms, startup, timing-events, vrrp-events)", tgName, cat)
					}
					if cfg != nil {
						cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("snmp trap-group %q: invalid trap category %q (downgraded to warning on tolerant path; ignored at runtime)", tgName, cat))
					}
				}
				if lc == "link" {
					hasEmitted = true
				}
			}
			if !hasEmitted && cfg != nil {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("snmp trap-group %q: categories %v include no category xpf emits (only \"link\" is emitted today), so this group will receive no traps — add \"link\" or remove the categories scope if traps are expected (#15256)", tgName, tg.Categories))
			}
		}
		if len(tg.Targets) == 0 {
			if !lenient {
				return fmt.Errorf("snmp trap-group %q: no targets configured (a trap group with zero targets sends no notifications)", tgName)
			}
			if cfg != nil {
				cfg.Warnings = append(cfg.Warnings,
					fmt.Sprintf("snmp trap-group %q: no targets configured (downgraded to warning on tolerant path; sends no notifications)", tgName))
			}
		}
	}

	sys.SNMP = snmp
	if cfg != nil {
		cfg.Warnings = append(cfg.Warnings, snmpInertKnobWarnings(snmpChildren)...)
	}
	return nil
}

// sortedTrapGroupNames15706 returns trap-group names in deterministic order
// for the deferred merged validation in compileSNMP (#15706).
func sortedTrapGroupNames15706(m map[string]*SNMPTrapGroup) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// snmpInertKnobWarnings emits accept-with-advisory notes for the top-level
// `snmp` knobs xpf recognizes but does not enforce (#4306 S-5). The
// security-relevant ones are called out explicitly: a MIB `view` (on a
// community or standalone) is NOT enforced, so a view-scoped community is
// silently promoted to full ifTable exposure; no `trap-options` statement is
// honoured (#9562, see snmpTrapOptionsAdvisory9562), and `source-address` in
// particular is NOT bound, so traps leave from the default egress IP. Messages are built
// from the node IDENTITY (keywords) only — never the community NAME (an SNMP
// community string is a secret). Deterministic, deduplicated output.
//
// #13089: the walk takes the SAME packed-body children compileSNMP walks
// (snmpChildren from packedBodyChildren), and a community's subtree is
// searched RECURSIVELY, so a knob spelled as a two-level container
// (`snmp { community { <name> { view v; } } }`) or a flat-set chain
// (`set snmp community <c> authorization ro view v` nests `view` under
// `authorization`, #8778) warns exactly like the direct-child spelling.
// Before, only the direct-child spelling warned and the other shapes — all
// accepted and compiled by compileSNMP — committed silently.
func snmpInertKnobWarnings(snmpChildren []*Node) []string {
	if len(snmpChildren) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var warnings []string
	add := func(msg string) {
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
	}
	for _, child := range snmpChildren {
		switch child.Name() {
		case "view":
			add("snmp view: MIB view scoping is accepted but NOT enforced by the SNMP agent (the full ifTable MIB is exposed regardless)")
		case "trap-options":
			// #9562: compileSNMP reads NOTHING under trap-options, so every
			// statement there gets an advisory, not only source-address. A
			// statement nobody has listed is covered by construction.
			for _, kw := range snmpTrapOptionsStatements9562(child) {
				add(snmpTrapOptionsAdvisory9562(kw))
			}
		case "health-monitor":
			add("snmp health-monitor: accepted but NOT implemented (no-op)")
		case "rmon":
			add("snmp rmon: accepted but NOT implemented (no-op)")
		case "community":
			// The community NAME is a secret — never echo it. Name only the
			// keyword. A view-scoped community answers the full ifTable.
			if communityHasInertStatement13089(child, "view") {
				add("snmp community view: per-community MIB view scoping is accepted but NOT enforced (the community answers the full ifTable)")
			}
			// #9416: the SIXTH spelling of the source restriction. Its
			// `clients` / `client-list-name` body IS applied to the community
			// (compileSNMP descends into it) — leaving it out would mean
			// allow-all, which is strictly worse than applying it on the wrong
			// instance. What is NOT honoured is the SCOPING: xpf's SNMP agent
			// binds one socket in the default instance and has no
			// routing-instance awareness, so the restriction applies to every
			// query rather than only to queries arriving via <ri>. Say which
			// half landed, because "accepted but not enforced" would be false
			// about the half that is.
			if communityHasInertStatement13089(child, "routing-instance") {
				add("snmp community routing-instance: the routing-instance SCOPING is accepted but NOT enforced (the agent answers in the default instance only) — any `clients` / `client-list-name` inside the block IS applied to the community, so the source restriction holds even though the scoping does not")
			}
			// xpf has no logical systems at all, so a logical-system-scoped
			// community is not merely unscoped — its whole body, including any
			// source restriction nested under it, is invisible to the compiler.
			if communityHasInertStatement13089(child, "logical-system") {
				add("snmp community logical-system: accepted but NOT implemented (xpf has no logical systems) — any `clients` / `client-list-name` nested inside the logical-system block is NOT applied, so the community is answerable from every source unless it also carries a restriction at community level")
			}
		case "interface", "filter-interfaces":
			// #9416: a DIFFERENT source-restriction axis from the `clients` /
			// `client-list-name` family — by arrival interface rather than by
			// source address — and unmodelled in the same silent way the named
			// client list was. Named rather than implemented: the agent binds a
			// wildcard UDP socket and does not resolve an incoming datagram's
			// arrival interface, so there is nothing to enforce against yet.
			add("snmp interface / filter-interfaces: restricting which interfaces the SNMP agent answers on is accepted but NOT enforced (the agent answers on every interface); use `community <c> clients` or `client-list-name` to restrict by SOURCE address instead")
		case "routing-instance-access":
			add("snmp routing-instance-access: accepted but NOT enforced (the agent serves the default routing instance only)")
		case "v3":
			// #9414: compileSNMPv3 reads only `usm local-engine user`; name
			// everything else under v3 by position (snmpV3InertWarnings9414).
			for _, msg := range snmpV3InertWarnings9414(child) {
				add(msg)
			}
		case "engine-id":
			// #9414: the engine ID is DERIVED (pkg/snmp buildEngineID, #5283).
			add("snmp engine-id: accepted but NOT applied — the SNMPv3 agent derives its authoritative engine ID from a persisted per-device identifier and the system host name (#5283), so a configured `local` ID, `use-mac-address` or `use-default-ip-address` is ignored and managers see the derived ID (#9414)")
		case "name":
			// #9414: sysName is os.Hostname() (pkg/snmp agent.go).
			add("snmp name: accepted but NOT applied — sysName always reports the system host name (#9414)")
		case "arp":
			add("snmp arp: accepted but NOT implemented (no-op) (#9414)")
		case "filter-duplicates":
			add("snmp filter-duplicates: accepted but NOT implemented — requests with a duplicate source address/port and request ID are not filtered (#9414)")
		case "nonvolatile":
			add("snmp nonvolatile: accepted but NOT implemented (no-op: the agent serves no writable objects, so no SET request is persisted) (#9414)")
		case "proxy":
			add("snmp proxy: accepted but NOT implemented — the agent does not proxy SNMP requests to other devices (#9414)")
		}
	}
	return warnings
}

// communityHasInertStatement13089 reports whether the community block carries
// a statement named keyword in any of the AST shapes compileSNMP accepts: the
// named body (`community <c> { view v; }`, and the brace-elided tail packed
// on the community line), the two-level container (`community { <c> { ... } }`,
// which adds a name level compileSNMP unwraps), and the flat-set CHAIN
// (#8778/#8939), where `set snmp community <c> authorization ro view v` nests
// `view` under the `authorization` leaf. The advisory fires on what the
// operator AUTHORED, so every statement in the community subtree is searched —
// a view nested three keywords deep is as inert as a direct one (#13089).
func communityHasInertStatement13089(community *Node, keyword string) bool {
	if community == nil {
		return false
	}
	// Brace-elided tail packed on the community line: the statement keywords
	// ride on Keys after the community name. (Firing on a value token that
	// happens to equal a keyword needs an operator to name a community after
	// one — the same pathological edge the previous Keys scan accepted.)
	for _, k := range community.Keys[1:] {
		if k == keyword {
			return true
		}
	}
	body := community.Children
	if len(community.Keys) < 2 && len(body) > 0 {
		// Two-level container. compileSNMP reads the first name block's body;
		// the advisory searches every name block — a view under ANY community
		// name in the container is equally inert.
		var inner []*Node
		for _, nameBlock := range body {
			inner = append(inner, nameBlock.Children...)
		}
		body = inner
	}
	return subtreeHasStatement13089(body, keyword)
}

// subtreeHasStatement13089 reports whether any node in the subtree is named
// keyword. Statement values live on a node's own Keys, never as child nodes,
// so a child named keyword is an authored statement (#13089).
func subtreeHasStatement13089(nodes []*Node, keyword string) bool {
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if n.Name() == keyword {
			return true
		}
		if subtreeHasStatement13089(n.Children, keyword) {
			return true
		}
	}
	return false
}

// systemInertKnobWarnings emits accept-with-advisory notes for the grouped
// `system` knobs that commit clean but do nothing (#4306 S-5): login banners /
// retry-options, NTP boot-server / authentication-key / source-address and
// per-server routing-instance, `internet-options` leaves beyond the one xpf
// models, and ssh rate-limit. Messages name the keyword only — never a leaf
// value (the NTP authentication-key is a secret).
//
// #13089: the walk spans every sibling block and every AST spelling
// compileSystem accepts. Three shapes were blind here, each silently
// suppressing a security-relevant advisory on a config that commits clean:
//
//   - a SECOND sibling block (`system { login {...} login {...} }`) —
//     FindChild saw only the first block, while compileSystem's own child
//     walk reads them all (#6957 sibling blocks);
//   - the flat-set CHAIN (`set system services ssh root-login deny
//     rate-limit 5` nests rate-limit under root-login, #8778) —
//     expandRun9235 hoists it back to the sibling position this walk reads;
//   - the brace-elided body packed on the block's own Keys
//     (`system { ntp authentication-key 1 type md5 value ...; }`) and on the
//     `system` line itself (`system services ssh rate-limit 5;`, #2419).
func systemInertKnobWarnings(sysNode *Node, system *SystemConfig) []string {
	if sysNode == nil {
		return nil
	}
	seen := map[string]bool{}
	var warnings []string
	add := func(msg string) {
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
	}
	// #13089: read the system body the way compileSystem does — and when the
	// whole body was packed brace-elided onto the `system` line, synthesize
	// the braced shape first (packedBodyChildren, schema-resolved like
	// compileSNMP's own reader). Guarded on EMPTY Children because a node can
	// carry BOTH a packed tail and a braced body (`system host-name fw1
	// { ... }` parses to exactly that), and the synthesis would drop the body.
	sysChildren := sysNode.Children
	if len(sysChildren) == 0 {
		sysChildren = packedBodyChildren(sysNode, systemSchema9792())
	}
	// blockHas reports whether a block carries a statement, either as a child
	// node or packed on the block's own Keys (the brace-elided one-liner
	// inside braces, e.g. `ntp authentication-key 1 type md5 value s;`). A
	// value token colliding with a keyword needs an operator to use an
	// advisory keyword as a leaf value — the same pathological edge the
	// community Keys scan in snmpInertKnobWarnings has always accepted.
	blockHas := func(n *Node, keyword string) bool {
		if n == nil {
			return false
		}
		if n.FindChild(keyword) != nil {
			return true
		}
		for _, k := range n.Keys[1:] {
			if k == keyword {
				return true
			}
		}
		return false
	}
	for _, login := range sysChildren {
		if login.Name() != "login" {
			continue
		}
		if blockHas(login, "message") {
			add("system login message: pre-login banner accepted but NOT applied")
		}
		if blockHas(login, "announcement") {
			add("system login announcement: post-login announcement accepted but NOT applied")
		}
		if blockHas(login, "retry-options") {
			add("system login retry-options: login retry/lockout policy accepted but NOT enforced")
		}
	}
	for _, ntp := range sysChildren {
		if ntp.Name() != "ntp" {
			continue
		}
		if blockHas(ntp, "boot-server") {
			add("system ntp boot-server: accepted but NOT enforced (no one-shot boot-time sync)")
		}
		if blockHas(ntp, "authentication-key") {
			// The key VALUE is a secret — name the keyword only.
			add("system ntp authentication-key: NTP authentication accepted but NOT enforced")
		}
		if blockHas(ntp, "source-address") {
			add("system ntp source-address: accepted but NOT bound (NTP uses the default source IP)")
		}
	}
	if system != nil {
		for _, id := range system.NTPServerKeyIDs {
			add(fmt.Sprintf("system ntp server key %d: NTP authentication accepted but NOT enforced (key %d stripped; no chrony keyfile is written, so the source is polled without authentication)", id, id))
		}
		for _, option := range system.NTPServerOptions {
			if option.RoutingInstance != "" {
				add("system ntp server routing-instance: accepted but NOT enforced (NTP sources assigned to a routing-instance are queried through the default instance)")
				break
			}
		}
		for _, option := range system.NTPServerOptions {
			if option.SourceAddress != "" {
				add("system ntp server source-address: accepted but NOT bound (chrony sources are not bound to a per-source source address) (#15709)")
				break
			}
		}
		for _, option := range system.NTPPeerOptions {
			if option.RoutingInstance != "" {
				add("system ntp peer routing-instance: accepted but NOT enforced (NTP peers assigned to a routing-instance are queried through the default instance) (#15709)")
				break
			}
		}
		for _, option := range system.NTPPeerOptions {
			if option.SourceAddress != "" {
				add("system ntp peer source-address: accepted but NOT bound (chrony peers are not bound to a per-peer source address) (#15709)")
				break
			}
		}
		if len(system.NTPTrustedKeyIDs) > 0 {
			add("system ntp trusted-key: NTP authentication accepted but NOT enforced (no chrony keyfile is written, so trusted keys are not used) (#15709)")
		}
	}
	for _, io := range sysChildren {
		if io.Name() != "internet-options" {
			continue
		}
		var extra []string
		collectInternetOptionsExtras13089(io, &extra)
		if len(extra) > 0 {
			sort.Strings(extra)
			add(fmt.Sprintf("system internet-options [%s]: accepted but NOT implemented (xpf models only no-ipv6-reject-zero-hop-limit)", strings.Join(extra, " ")))
		}
	}
	for _, svc := range sysChildren {
		if svc.Name() != "services" {
			continue
		}
		for _, ssh := range svc.Children {
			if ssh.Name() != "ssh" {
				continue
			}
			// #8778/#8939: hoist a chained rate-limit back beside root-login;
			// the packed one-liner is caught by blockHas's Keys scan.
			if blockHas(expandRun9235(ssh, systemServicesSSHSchema13089()), "rate-limit") {
				add("system services ssh rate-limit: accepted but NOT enforced (sshd has no per-minute connection-rate limiter)")
			}
		}
		// #15781: `system services netconf ssh` commits but starts no
		// NETCONF server (xpf has no NETCONF daemon). The host-inbound
		// tcp/830 opening alone must not read as a served port, so warn
		// explicitly. Typed-flag keyed (like the NTP key ids above): the
		// compiler reader already spans every AST spelling (#13089).
		if system != nil && system.Services != nil && system.Services.NetconfSSH {
			add("system services netconf ssh: accepted but NOT served (xpf has no NETCONF daemon; host-inbound tcp/830 admission alone does not provide NETCONF)")
		}
	}
	for _, lic := range sysChildren {
		if lic.Name() != "license" {
			continue
		}
		hasURL := system != nil && len(system.LicenseAutoUpdateURLs) > 0
		if !hasURL {
			for _, au := range lic.FindChildren("autoupdate") {
				if au.FindChild("url") != nil || (len(au.Keys) >= 3 && au.Keys[1] == "url") {
					hasURL = true
				}
			}
			if len(lic.Children) == 0 && len(lic.Keys) >= 4 && lic.Keys[1] == "autoupdate" && lic.Keys[2] == "url" {
				hasURL = true
			}
		}
		if hasURL {
			add("system license autoupdate url: accepted but NOT applied — xpf has no licensing runtime, so no license is fetched or updated (#15782)")
		}
	}
	return warnings
}

// blockHasNetconfSSH15781 reports whether a `netconf` container carries
// the `ssh` leaf in any spelling compileSystem accepts (#13089 shapes):
// braced child, packed on the netconf line (`netconf ssh;` — caught by
// packedBodyChildren), or the flat-set chain (`set system services
// netconf ssh` nests ssh under netconf). Used by compileSystem to set
// SystemServicesConfig.NetconfSSH (#15781).
func blockHasNetconfSSH15781(ncNode *Node) bool {
	if ncNode == nil {
		return false
	}
	if ncNode.FindChild("ssh") != nil {
		return true
	}
	for _, k := range ncNode.Keys[1:] {
		if k == "ssh" {
			return true
		}
	}
	for _, c := range packedBodyChildren(ncNode, schemaForPath("system", "services", "netconf")) {
		if c.Name() == "ssh" || blockHasNetconfSSH15781(c) {
			return true
		}
	}
	return subtreeHasStatement13089(ncNode.Children, "ssh")
}

// systemServicesSSHSchema13089 resolves the `system services ssh` container
// for systemInertKnobWarnings, so expandRun9235 can hoist a flat-set chain
// (`set system services ssh root-login deny rate-limit 5` nests rate-limit
// under root-login) back to the sibling position the advisory walks (#13089).
func systemServicesSSHSchema13089() *schemaNode {
	return resolveSchemaPath9235("system", "services", "ssh")
}

// collectInternetOptionsExtras13089 appends the name of every statement in an
// `internet-options` block that is not the one modelled leaf, descending
// through the subtree: a flat-set chain (`set system internet-options
// no-ipv6-reject-zero-hop-limit tcp-mss 1400`) nests the extra statement under
// the modelled leaf instead of beside it, and the direct-children walk this
// advisory had reported the block as fully modelled (#13089).
func collectInternetOptionsExtras13089(n *Node, extra *[]string) {
	for _, c := range n.Children {
		if c.Name() != "no-ipv6-reject-zero-hop-limit" {
			*extra = append(*extra, c.Name())
		} else if len(c.Keys) > 1 {
			// #15707: a packed tail on the modelled leaf itself
			// (`no-ipv6-reject-zero-hop-limit tcp-mss 1400`, the flat-set
			// chain / compact shape) — its head is an unmodelled extra
			// even though the leaf node is the modelled one.
			*extra = append(*extra, c.Keys[1])
		}
		collectInternetOptionsExtras13089(c, extra)
	}
}

// compileSNMPv3 parses the v3 { usm { local-engine { user <name> { ... } } } } hierarchy.
func compileSNMPv3(node *Node, snmp *SNMPConfig) {
	// Flat form: Keys = ["v3", "usm", "local-engine", "user", "<name>", "authentication-sha", "authentication-password", "<pass>"]
	// Index:       0      1         2              3       4                5                         6                       7
	if len(node.Keys) >= 8 && node.Keys[1] == "usm" && node.Keys[2] == "local-engine" && node.Keys[3] == "user" {
		userName := node.Keys[4]
		user := snmp.V3Users[userName]
		if user == nil {
			user = &SNMPv3User{Name: userName}
		}
		parseSNMPv3UserKeys(node.Keys[5:], user)
		snmp.V3Users[userName] = user
		return
	}

	// Hierarchical form: v3 -> usm -> local-engine -> user <name> { ... }
	//
	// #9561: look `usm` up through packedBodyChildren, not FindChild. The
	// brace-elided spellings put the path on v3's OWN Keys:
	//
	//	v3 usm { local-engine { user u1 { ... } } }   Keys=[v3 usm]
	//	v3 usm local-engine { user u1 { ... } }       Keys=[v3 usm local-engine]
	//	v3 usm local-engine user u1 { ... }           Keys=[v3 usm local-engine user u1]
	//
	// None has a `usm` CHILD, and none reaches the 8-key packed branch above,
	// so every one compiled to ZERO users with no warning. packedBodyChildren
	// rebuilds each into the braced chain, with the body attached under the
	// deepest node (#6818), and returns a braced v3's children unchanged.
	var usmNode *Node
	for _, c := range packedBodyChildren(node, schemaForPath("snmp", "v3")) {
		if c.Name() == "usm" {
			usmNode = c
			break
		}
	}
	if usmNode == nil {
		return
	}
	// #7653: `usm local-engine { user ... }` packs the intermediate container
	// onto the usm line, so local-engine sits in usmNode.Keys and this
	// FindChild returns nil -- and EVERY v3 user disappears. That is not a
	// credential downgrade but an SNMPv3 management outage from a config whose
	// text is correct. packedBodyChildren expands the tail schema-driven AND
	// (per #6818) attaches the nested block UNDER the packed node rather than
	// beside it, which is exactly the shape needed here: the users are
	// usmNode.Children and they belong under the synthesized local-engine.
	engineNode := usmNode.FindChild("local-engine")
	if engineNode == nil {
		for _, c := range packedBodyChildren(usmNode, schemaForPath("snmp", "v3", "usm")) {
			if c.Name() == "local-engine" {
				engineNode = c
				break
			}
		}
	}
	if engineNode == nil {
		return
	}
	// #15706: peel two-level `user { <name> { ... } }` containers via
	// namedInstances so the 2nd+ user is not dropped; the named spelling
	// (`user <name> { ... }`) passes through as one instance.
	var userNodes15706 []*Node
	for _, child := range engineNode.Children {
		if child.Name() != "user" {
			continue
		}
		for _, inst := range namedInstances([]*Node{child}) {
			node := inst.node
			if len(node.Keys) < 2 || node.Keys[1] != inst.name {
				// Two-level instance node: Keys[0]==name. Synthesize the
				// named `user <name>` node the body below reads (Keys[1],
				// Keys[2:] packed tail, Children body).
				node = &Node{Keys: append([]string{"user", inst.name}, node.Keys[1:]...), Children: node.Children}
			}
			userNodes15706 = append(userNodes15706, node)
		}
	}
	for _, child := range userNodes15706 {
		{
			userName := nodeVal(child)
			if userName == "" {
				continue
			}
			user := snmp.V3Users[userName]
			if user == nil {
				user = &SNMPv3User{Name: userName}
			}
			userChildren := child.Children
			if len(child.Keys) < 2 && len(child.Children) > 0 {
				userChildren = child.Children[0].Children
			}
			// #7653: the body may be PACKED onto the user's own instance line
			//   user ops authentication-sha256 authentication-password "s3cret";
			// leaving Children empty. The user was still REGISTERED -- with no
			// derived key -- and minimum-security enforcement keys on key
			// presence, so a noAuthNoPriv request naming this user bypasses the
			// authentication the operator authored. Route the trailing key run
			// through the same parseSNMPv3UserKeys the flat-set form uses above,
			// rather than a second copy of its table.
			if len(child.Keys) > 2 {
				parseSNMPv3UserKeys(child.Keys[2:], user)
			}
			// #9155-R02: EXPAND THE FLAT RUN before walking the user's body.
			//
			// `SetPath` builds a flat-set line as a NESTED CHAIN, not a packed run
			// on one node. For
			//
			//   set snmp v3 usm local-engine user alice \
			//       authentication-sha256 authentication-password A \
			//       privacy-aes128 privacy-password P
			//
			// the tree is
			//
			//   [user alice] > [authentication-sha256] > [authentication-password A]
			//                                             > [privacy-aes128 privacy-password P]
			//
			// so the privacy stanza is a GRANDCHILD of the password node and this
			// loop -- which iterates the user's own children -- never reached it.
			// The user compiled with authProto set and privProto EMPTY: the
			// operator configured authPriv, the commit succeeded, and the agent
			// served authNoPriv.
			//
			// IT EVADED BOTH #9155 COMMIT GATES, and the reason is structural: they
			// read the COMPILED config and key on a protocol being NAMED, so
			// `PrivProtocol != "" && PrivPassword == ""` cannot fire on a protocol
			// the compiler discarded before the gate ran. A gate downstream of a
			// dropping compiler is blind to exactly what it drops -- which is why
			// this fix belongs here and not in a third gate.
			//
			// The schema already declares every cut point (`user` names all five
			// protocol children, each with its `*-password`), so the shared #8939
			// splitter needs no shim for this container -- only to be called.
			// hoistAndSplitRun8939 rather than expandFlatRun: `authentication-sha256`
			// legitimately OWNS A BODY (its declared `authentication-password`
			// child), and expandFlatRun leaves body-owning leaves alone by design.
			// The privacy stanza is nested UNDER that body, which is exactly the
			// case hoistAndSplitRun8939 exists to lift.
			userChildren = hoistAndSplitRun8939(userChildren,
				schemaForPath("snmp", "v3", "usm", "local-engine", "user"))
			for _, prop := range userChildren {
				// #6822: the compact spelling
				//   authentication-sha256 authentication-password "s3cret";
				// flattens the credential onto this node's own Keys, where the
				// FindChild reads below cannot see it. The result was NOT a skipped
				// user -- the protocol comes from the case label, so the user was
				// registered as requiring SHA-256 and AES-128 with EMPTY passwords.
				//
				// parseSNMPv3UserKeys already reads exactly this key shape for the
				// flat-set path. Route the compact block form through the same
				// function rather than duplicating its table: a second copy is a
				// second thing to keep in step, and a divergence here is a silent
				// credential loss either way.
				//
				// packedBodyChildren (compact_tail.go) is the general expander and
				// is used for the #6818/#6821 siblings. It is the wrong tool HERE:
				// the protocol is carried by the case LABEL rather than by a value,
				// so the reader below needs the whole key run, not a rebuilt child
				// tree -- and parseSNMPv3UserKeys already consumes exactly that run.
				if len(prop.Keys) >= 3 {
					// Route ONLY the exact credential shape, and do NOT skip the
					// switch below.
					//
					// `len(Keys) >= 3` alone is not a discriminator: extra container
					// keys survive schema walking, so
					//   authentication-sha256 ignored ignored { authentication-password "good"; }
					// matched it, parseSNMPv3UserKeys recognised SHA-256 but not
					// `ignored`, left the password empty, and an unconditional
					// `continue` then skipped the real password CHILD the switch
					// would have compiled. That registers the user as requiring
					// SHA-256 with an EMPTY credential -- which is the #6822 defect
					// itself, reintroduced on a different shape.
					//
					// Falling through also fixes the precedence: a node can carry a
					// packed tail AND a real child, and the child is the canonical
					// block spelling, so it must win.
					switch prop.Keys[1] {
					case "authentication-password", "privacy-password":
						parseSNMPv3UserKeys(prop.Keys, user)
					}
				}
				// #14411: a wrapper container (`authentication { … }`) is not a
				// modelled statement; its protocol children compile exactly as
				// if written directly under the user. The strict gate rejects
				// the wrapped spelling, but the tolerant path compiles it at
				// the WRITTEN level rather than silently serving a bare user.
				if prop.Name() == "authentication" && len(prop.Keys) == 1 {
					applySNMPv3ProtocolChildren14411(prop.Children, user)
				}
				switch prop.Name() {
				case "authentication-md5":
					user.AuthProtocol = "md5"
					if pw := prop.FindChild("authentication-password"); pw != nil {
						user.AuthPassword = NewSecret(nodeVal(pw))
					}
				case "authentication-sha":
					user.AuthProtocol = "sha"
					if pw := prop.FindChild("authentication-password"); pw != nil {
						user.AuthPassword = NewSecret(nodeVal(pw))
					}
				case "authentication-sha256":
					user.AuthProtocol = "sha256"
					if pw := prop.FindChild("authentication-password"); pw != nil {
						user.AuthPassword = NewSecret(nodeVal(pw))
					}
				case "privacy-des":
					user.PrivProtocol = "des"
					if pw := prop.FindChild("privacy-password"); pw != nil {
						user.PrivPassword = NewSecret(nodeVal(pw))
					}
				case "privacy-aes128":
					user.PrivProtocol = "aes128"
					if pw := prop.FindChild("privacy-password"); pw != nil {
						user.PrivPassword = NewSecret(nodeVal(pw))
					}
				}
			}
			snmp.V3Users[userName] = user
		}
	}
}

// applySNMPv3ProtocolChildren14411 compiles protocol children found inside a
// wrapper container under an SNMPv3 user (#14411 tolerant-path arm; the
// strict gate rejects the wrapped placement). Packed tails on each protocol
// node are honoured via parseSNMPv3UserKeys exactly as at the user level.
func applySNMPv3ProtocolChildren14411(children []*Node, user *SNMPv3User) {
	for _, prop := range children {
		if len(prop.Keys) >= 3 {
			switch prop.Keys[1] {
			case "authentication-password", "privacy-password":
				parseSNMPv3UserKeys(prop.Keys, user)
			}
		}
		switch prop.Name() {
		case "authentication-md5":
			user.AuthProtocol = "md5"
			if pw := prop.FindChild("authentication-password"); pw != nil {
				user.AuthPassword = NewSecret(nodeVal(pw))
			}
		case "authentication-sha":
			user.AuthProtocol = "sha"
			if pw := prop.FindChild("authentication-password"); pw != nil {
				user.AuthPassword = NewSecret(nodeVal(pw))
			}
		case "authentication-sha256":
			user.AuthProtocol = "sha256"
			if pw := prop.FindChild("authentication-password"); pw != nil {
				user.AuthPassword = NewSecret(nodeVal(pw))
			}
		case "privacy-des":
			user.PrivProtocol = "des"
			if pw := prop.FindChild("privacy-password"); pw != nil {
				user.PrivPassword = NewSecret(nodeVal(pw))
			}
		case "privacy-aes128":
			user.PrivProtocol = "aes128"
			if pw := prop.FindChild("privacy-password"); pw != nil {
				user.PrivPassword = NewSecret(nodeVal(pw))
			}
		}
	}
}

// parseSNMPv3UserKeys parses flat-form keys after the user name.
// Keys like: ["authentication-sha256", "authentication-password", "adminpass"]
//
// #14411: the run may carry BOTH protocols packed on one line —
// `authentication-sha256 authentication-password A privacy-aes128
// privacy-password P`. The previous single-shot switch on keys[0] dropped the
// second protocol silently: the operator configured authPriv and the agent
// served authNoPriv (unencrypted). Walk the whole run one protocol pair per
// step (protocol, password-leaf, value = 3 tokens). A password value is
// consumed only as the value slot of its recognised pair and never re-read
// as a keyword; an unrecognised token is skipped one slot so a trailing
// unknown keyword stays for the #9155/#14411 gate to reject rather than
// being misparsed here.
func parseSNMPv3UserKeys(keys []string, user *SNMPv3User) {
	for i := 0; i < len(keys); {
		var passwordLeaf string
		switch keys[i] {
		case "authentication-md5":
			user.AuthProtocol = "md5"
			passwordLeaf = "authentication-password"
		case "authentication-sha":
			user.AuthProtocol = "sha"
			passwordLeaf = "authentication-password"
		case "authentication-sha256":
			user.AuthProtocol = "sha256"
			passwordLeaf = "authentication-password"
		case "privacy-des":
			user.PrivProtocol = "des"
			passwordLeaf = "privacy-password"
		case "privacy-aes128":
			user.PrivProtocol = "aes128"
			passwordLeaf = "privacy-password"
		default:
			i++
			continue
		}
		if i+2 < len(keys) && keys[i+1] == passwordLeaf {
			if passwordLeaf == "authentication-password" {
				user.AuthPassword = NewSecret(keys[i+2])
			} else {
				user.PrivPassword = NewSecret(keys[i+2])
			}
		}
		if i+1 < len(keys) && keys[i+1] == passwordLeaf {
			i += 3
		} else {
			i++
		}
	}
}
