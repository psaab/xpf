package config

// parseHostInboundNode parses a `host-inbound-traffic { system-services ...;
// protocols ...; }` subtree into a HostInboundTraffic. It is the SSOT for both
// the zone-level stanza and the per-interface override (#3362) so the two parse
// identically. A present-but-empty stanza returns a non-nil empty struct
// (preserving the historical zone-level behaviour where an empty stanza means
// "the operator opened nothing" → host-inbound enforcing, deny-all). A nil node
// (no stanza) returns nil.
func parseHostInboundNode(n *Node) *HostInboundTraffic {
	if n == nil {
		return nil
	}
	hib := &HostInboundTraffic{}
	for _, hit := range n.Children {
		switch hit.Name() {
		case "system-services":
			// #3703: system-services is a multi-value value-tail leaf. A
			// bracket / single-line / repeated list carries values as the
			// leaf's Keys[1:] AND/OR one-per-child; read BOTH via the
			// firewallMatchValues SSOT so every token reaches the compiled
			// slice (reading only child.Name()/Keys[0] dropped all but the
			// first list value — the #2419 collapse bug). The compiled slice
			// is then token-validated by validateHostInboundTokensStrict.
			hib.SystemServices = append(hib.SystemServices, firewallMatchValues(hit)...)
		case "protocols":
			hib.Protocols = append(hib.Protocols, firewallMatchValues(hit)...)
		}
	}
	return hib
}

// mergeHostInbound unions the SystemServices and Protocols of src into dst,
// implementing Junos merge semantics for repeated host-inbound-traffic blocks
// under one zone or interface (#4544). A hand-authored `load override` config
// can carry two literal `host-inbound-traffic { ... }` blocks; the hierarchical
// parser keeps them as separate same-key siblings (it does not merge same-key
// blocks — unlike flat-set SetPath / load-merge, which route through a
// same-key-container reuse and are structurally immune), so the compiler must
// union them here. Otherwise the second block silently overwrites the first
// (zone level) or is ignored (interface level), narrowing host-inbound
// admission — a service DoS — or fail-opening it if the dropped block was the
// restrictive one, versus what the operator authored.
//
// dst is nil for the first block, in which case src is returned UNCHANGED so a
// SINGLE block stays byte-identical to the pre-#4544 behaviour (no dedup, no
// copy — a single block preserves its exact token multiset). Only when a second
// block is actually merged are the unioned slices deduplicated (first-seen
// order preserved). src nil (no stanza) is a no-op.
func mergeHostInbound(dst, src *HostInboundTraffic) *HostInboundTraffic {
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	dst.SystemServices = dedupHostInboundTokens(append(dst.SystemServices, src.SystemServices...))
	dst.Protocols = dedupHostInboundTokens(append(dst.Protocols, src.Protocols...))
	return dst
}

// cloneHostInbound returns a deep copy of src (fresh backing arrays for both
// admission dimensions), preserving the exact token multiset and order — a copy
// is value-identical, it only breaks POINTER identity.
//
// Required by the #6391 multi-member fan. mergeHostInbound returns src UNCHANGED
// when dst is nil (the deliberate #4544 no-copy fast path), so fanning one parsed
// body across N member names would otherwise store the SAME pointer under N map
// keys. A later mergeHostInbound into any one of them mutates dst IN PLACE, so a
// subsequent single-scoped override on one member would silently surface on all
// the others:
//
//	interfaces {
//	    [ a b ] { host-inbound-traffic { system-services ssh; } }
//	    a       { host-inbound-traffic { system-services ping; } }
//	}
//
// With a shared pointer, merging `ping` into a mutates the value b also points
// at, so b wrongly admits ping. Cloning per key keeps the members independent.
// Pinned by TestHostInbound6391BracketBodyMembersDoNotShareBackingStore.
func cloneHostInbound(src *HostInboundTraffic) *HostInboundTraffic {
	if src == nil {
		return nil
	}
	return &HostInboundTraffic{
		SystemServices: append([]string(nil), src.SystemServices...),
		Protocols:      append([]string(nil), src.Protocols...),
	}
}

// dedupHostInboundTokens returns vals with duplicate entries removed, preserving
// first-seen order. Used only on the merged (2+ block) host-inbound path (#4544)
// so a single block keeps its exact token multiset (byte-identical behaviour).
func dedupHostInboundTokens(vals []string) []string {
	if len(vals) < 2 {
		return vals
	}
	seen := make(map[string]struct{}, len(vals))
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// bracketedGroupInstances8794 is namedInstances with Junos's bracketed zone GROUP
// fanned out: `security-zone [ trust untrust ] { screen edge; }` yields one
// instance per name, each sharing the body.
//
// #8810: NOT zone-specific despite where it lives. The same shape appears at
// `chassis device-map interface [ a b ]` and `protocols ospf area <a>
// interface [ a b ]`, so the helper is named for the SHAPE rather than the
// container. It was `zoneGroupInstances8794` while zones were its only caller;
// a zone-named helper enumerating a device-map reads as a mistake.
//
// #8794: namedInstances takes Keys[1] as the name and DISCARDS Keys[2:], so a
// group produced only its first zone. Not a missing body -- the later zone was
// never created:
//
//	security-zone [ trust untrust ] { screen edge; }   -> 1 zone
//	two explicit blocks                                -> 2 zones
//
// and the syntax is affirmatively supported (formatset_container_bracket_6668
// declares it valid with wantCommit: true).
//
// THE DISCRIMINATOR IS MEASURED, NOT ASSUMED, and it is why this cannot sweep
// in a packed tail. The lexer strips brackets, so the parser gives:
//
//	security-zone [ trust untrust ] { screen edge; }  Keys=[..trust untrust] children=1
//	security-zone trust untrust     { screen edge; }  Keys=[..trust untrust] children=1  (identical)
//	security-zone trust screen edge;                  Keys=[..trust screen edge] children=0
//
// A group has surplus keys AND a braced body; a packed tail has surplus keys
// and NO children. The two cannot overlap, so this is disjoint from the #8690
// normalizer's `len(Children) == 0` construction by the same property that
// separates them there.
//
// THERE IS NO BRACKET PROVENANCE TO PRESERVE, which dissolves the HA concern
// about ConfigTree.Format emitting bare keys: the bracketed and bare spellings
// parse to byte-identical trees (measured above), so a primary and a standby
// running this code fan out identically whichever spelling crosses the
// Format -> SyncApply boundary. A rolling upgrade still differs -- an OLD peer
// compiles one zone where a NEW one compiles two -- but that is the pre-fix
// behaviour on the old node, and it errs toward FEWER zones, which is the
// direction that fails closed.
//
// Scoped to zones deliberately. namedInstances is shared by many containers and
// fanning it out globally would change every one of them; that is a separate
// decision with its own evidence.
func bracketedGroupInstances8794(nodes []*Node) []struct {
	name string
	node *Node
} {
	var out []struct {
		name string
		node *Node
	}
	for _, child := range nodes {
		if len(child.Keys) >= 3 && len(child.Children) > 0 {
			for _, nm := range child.Keys[1:] {
				out = append(out, struct {
					name string
					node *Node
				}{nm, child})
			}
			continue
		}
		out = append(out, namedInstances([]*Node{child})...)
	}
	return out
}

func compileZones(node *Node, sec *SecurityConfig) error {
	for _, inst := range bracketedGroupInstances8794(node.FindChildren("security-zone")) {
		// #4818: find-or-create by name rather than always allocating a
		// fresh ZoneConfig. A hand-authored `load override` config can carry
		// two literal `security-zone <name> { ... }` TOP-LEVEL sibling
		// blocks — the hierarchical parser (parseStatements) keeps them as
		// separate same-key siblings (it does not merge), so namedInstances
		// yields TWO entries for the same zone name. The pre-fix unconditional
		// `zone := &ZoneConfig{...}` + `sec.Zones[inst.name] = zone` let the
		// second instance silently REPLACE the first, discarding its
		// interfaces/host-inbound/address-book/description/screen/tcp-rst
		// wholesale. This is the outer-instance analogue of the #4544 fix
		// below, which already merges repeated host-inbound-traffic blocks
		// WITHIN one instance — that fix is a no-op against a duplicate
		// instance because it never runs on the first instance's properties
		// once the whole ZoneConfig is replaced. Properties below now
		// accumulate into the SAME zone across every sibling instance:
		// Interfaces appends, HostInboundTraffic/InterfaceHostInbound merge
		// via mergeHostInbound, AddressBook merges by name (find-or-create,
		// same as parseAddressBookEntries already does for repeated
		// address/address-set children — #4706). ScreenProfile, TCPRst, and
		// Description are scalars with no natural union; they are last-wins
		// across sibling instances (matches their existing last-wins
		// behaviour across repeated properties WITHIN one instance).
		zone := sec.Zones[inst.name]
		if zone == nil {
			zone = &ZoneConfig{Name: inst.name}
			sec.Zones[inst.name] = zone
		}

		// #9792: a packed one-line run reaches this reader on the lenient path
		// (Store.Load / Store.SyncApply); expand it as #9235 does. Lenient path only.
		for _, prop := range expandResolvingRuns9792(inst.node.Children, securityZoneSchema9792()) {
			switch prop.Name() {
			case "interfaces":
				// #6525: iterate the NORMALIZED member nodes, not prop.Children
				// directly. The hierarchical COMPACT-LEAF spelling
				// `interfaces ge-0/0/1.0;` carries the member name on the
				// stanza's OWN Keys tail with nil Children, so a bare
				// `range prop.Children` ran the body ZERO times and the zone
				// compiled with no interfaces at all — silently, cleanly, and
				// with both strict zone-membership gates then passing
				// VACUOUSLY over the empty slice. zoneInterfaceMemberNodes
				// rewrites that shape onto the block shape this loop already
				// understands, so every spelling reaches the same body.
				for _, iface := range zoneInterfaceMemberNodes(prop) {
					// #5248: accumulate EVERY interface name this member node
					// carries, across all parser AST shapes, not just the first.
					// A bracketed flat-set / load-override membership list
					// `interfaces [ ge-0/0/0 ge-0/0/1 ]` arrives bracket-stripped
					// (the lexer drops `[`/`]`, #2419). Unlike a multi:true value
					// leaf — where the surplus tokens collapse onto ONE leaf's
					// Keys and firewallMatchValues recovers them — the schema
					// models the interface name as a WILDCARD container, so
					// SetPath NESTS each surplus token under the first member
					// (`interfaces -> ge-0/0/0(container) -> ge-0/0/1(leaf)`; a
					// 3+ list collapses the whole tail onto the deepest leaf's
					// Keys, e.g. `[b c]`). Reading only iface.Name() compiled just
					// the FIRST member and SILENTLY DROPPED the rest — a zone-
					// membership (security boundary) loss: the dropped interfaces
					// are left unmanaged / brought DOWN or evaluated against the
					// wrong zone, and their absence hid them from the strict
					// zone-interface-defined gate. zoneInterfaceMembers flattens
					// the nested chain so the hierarchical `{ a; b; }`, a single
					// `a`, and the bracketed `[ a b c ]` all yield every member.
					// #7031: FIRST-SEEN dedupe. Naming a member twice -- once
					// bare for membership, once as the head of a
					// host-inbound-traffic body -- is the ORDINARY way an
					// operator adds a member and then gives it an override, and
					// it is what `show configuration | display set` emits for a
					// zone that has both. It compiled to the member appearing
					// TWICE in zone.Interfaces, committing clean with no
					// warning, on master and on every tree measured in the
					// issue.
					//
					// Deduping here rather than at each consumer because the
					// duplicate has no meaning to preserve: zone membership is
					// a SET. The per-interface override map is already keyed by
					// name and merges (#4544/#4818), so the second mention has
					// always contributed nothing but the extra slice entry.
					//
					// First-seen order, not sorted: the slice order is what the
					// operator authored and several renderers show it verbatim.
					for _, member := range zoneInterfaceMembers(iface) {
						if !zoneHasInterface(zone, member) {
							zone.Interfaces = append(zone.Interfaces, member)
						}
					}
					// #3362: per-interface host-inbound-traffic override
					// (`interfaces <if> host-inbound-traffic { ... }`). Same
					// token grammar as the zone-level stanza; parsed by the
					// shared parseHostInboundNode so both shapes stay in lockstep.
					//
					// #4544/#4818: MERGE across ALL host-inbound-traffic blocks
					// under this interface (Junos merge semantics), not
					// FindChild (first-wins) and not a bare overwrite. A
					// hand-authored `load override` config can carry two
					// literal blocks under one interface — either as siblings
					// within one security-zone instance (#4544) or split
					// across two duplicate top-level security-zone instances
					// naming the same interface (#4818); the hierarchical
					// parser keeps all of them as separate same-key siblings —
					// it does NOT merge — so FindChild would read only the
					// first and a plain map assignment would drop whichever
					// instance's interface block ran first. Merge into
					// whatever is already recorded for this interface name.
					var hib *HostInboundTraffic
					for _, hn := range iface.FindChildren("host-inbound-traffic") {
						hib = mergeHostInbound(hib, parseHostInboundNode(hn))
					}
					if hib != nil {
						if zone.InterfaceHostInbound == nil {
							zone.InterfaceHostInbound = make(map[string]*HostInboundTraffic)
						}
						// #6391: apply the override to every name this member
						// node's KEYS carry, and NEVER to its CHILDREN. That
						// distinction is the whole fix; the two shapes it
						// separates are NOT interchangeable:
						//
						//   Keys=[a b], no membership child
						//       `interfaces { [ a b ] { host-inbound {...} } }`
						//     A body authored ON a bracket membership — the
						//     operator's MULTI-MEMBER intent. Both a and b get it.
						//
						//   Keys=[a], child leaf Keys=[b]
						//       `set ... interfaces [ a b ]`
						//       `set ... interfaces a host-inbound-traffic ... ssh`
						//     SetPath descends the wildcard for the FIRST token and
						//     NESTS the bracket tail under it, then the second `set`
						//     REUSES that same `a` container — so `a` ends up
						//     carrying both the `b` membership leaf and the
						//     host-inbound body even though ssh is scoped to `a`
						//     ALONE. Fanning here is the #6389 regression: it opens
						//     ssh on `b`, which the operator never configured
						//     (admission is additive — host_inbound_view.go).
						//
						// NO `set`-authored config can reach the multi-key shape,
						// which is what makes keying on Keys safe rather than merely
						// convenient. The interface name is `schemaNode.wildcard`
						// with args:0, multi:false, compoundKey:false
						// (schema_security.go), so SetPath's
						// `nodeKeyCount = 1 + childSchema.args` (ast_edit.go:289 —
						// NOT the same-named local in schema_complete.go,
						// which is the completion walker and decides
						// nothing here) is ALWAYS 1 and its
						// container branch stores exactly one token; surplus bracket
						// tokens can only land on a child LEAF (which has no
						// host-inbound child, so it is never read here). A bracket
						// list is therefore len(Keys)==1 from `set` and len(Keys)>1
						// ONLY from a hierarchical parse (`load override`, a
						// hand-authored config file). Pinned by
						// TestHostInbound6391FlatSetNeverYieldsMultiKeyContainer.
						//
						// A nested extra membership under a bracket body
						// (`[ a b ] { c; host-inbound {...} }`) fans to a and b but
						// NOT c: c is a nested membership statement, not a bracket
						// sibling of the node the body was authored on. Deliberate
						// (#6391), pinned by
						// TestHostInbound6391BracketBodyNestedExtraMemberScope.
						//
						// cloneHostInbound per key: mergeHostInbound returns src
						// unchanged when dst is nil, so storing `hib` directly under
						// several keys would alias ONE value across the members and a
						// later in-place merge on one would surface on all of them.
						//
						// #6525: read the keys through zoneInterfaceMemberKeys
						// rather than iface.Keys directly. It is iface.Keys
						// TRUNCATED at the first body keyword, which is a no-op
						// for every shape that existed before (`set` never puts
						// a body keyword on Keys — it is always a child) and
						// stops the compact-leaf packed spelling
						// `interfaces a host-inbound-traffic ...` from keying
						// the override on its own body tokens.
						//
						// #7027, measured at b4ac34f10: this truncation is now a
						// BELT IN FRONT OF A GATE, not a load-bearing read. The
						// issue reports that reverting it to iface.Keys leaves
						// the whole pkg/config suite green and reads that as a
						// missing assertion. It is not missing — the two
						// expressions never DIFFER. Instrumenting this site to
						// print whenever len(truncated) != len(iface.Keys) and
						// running the full package (rc=0, 0 build errors, 0
						// failures) produced ZERO hits: no config in the corpus
						// reaches a member node whose Keys carry a body keyword.
						//
						// The spelling the truncation was written for is now
						// rejected earlier: #6735's packed-tail gate refuses
						// `interfaces a host-inbound-traffic <tail>` at commit
						// (validateZoneInterfacePackedTailStrict), and the one
						// remaining keyword-on-Keys spelling, the nested block
						// `interfaces { a host-inbound-traffic { ... } }`, does
						// not reach this branch at all — it compiles to the
						// member with NO override, which is a separate question
						// and not this one.
						//
						// So a regression test for the truncation would first
						// need a config that both differs AND commits, and the
						// sweep found none. Kept rather than deleted, and kept
						// with this note rather than dressed up as load-bearing:
						// if #6735's gate is ever narrowed, this belt becomes
						// live again, and the next reader should know the
						// dependency runs in that direction.
						for _, name := range zoneInterfaceMemberKeys(iface) {
							zone.InterfaceHostInbound[name] = mergeHostInbound(zone.InterfaceHostInbound[name], cloneHostInbound(hib))
						}
					}
				}
			case "screen":
				zone.ScreenProfile = nodeVal(prop)
			case "host-inbound-traffic":
				// #4544: MERGE repeated zone-level host-inbound-traffic blocks
				// rather than overwrite (Junos merge semantics). This case
				// fires once per host-inbound-traffic child; `load override`
				// splices a raw hierarchical parse whose two literal blocks stay
				// as separate siblings, so a bare `=` assignment silently drops
				// every block but the last. Accumulate into the zone value.
				// #4818 extends this across duplicate top-level security-zone
				// instances too, since zone is now find-or-create.
				zone.HostInboundTraffic = mergeHostInbound(zone.HostInboundTraffic, parseHostInboundNode(prop))
			case "tcp-rst":
				zone.TCPRst = true
			case "description":
				zone.Description = nodeVal(prop)
			case "address-book":
				// #3061: zone-local address book. Same entry grammar as the
				// global book; resolved into the global book under
				// zone-qualified internal names later (resolveZoneLocalAddressBooks).
				// #4818: find-or-create rather than always allocating a fresh
				// AddressBook, so a second security-zone instance's
				// address-book block MERGES into the first's (by address/
				// address-set name, via parseAddressBookEntries's own
				// find-or-create — #4706) instead of replacing it outright.
				ab := zone.AddressBook
				if ab == nil {
					ab = &AddressBook{
						Addresses:   make(map[string]*Address),
						AddressSets: make(map[string]*AddressSet),
					}
					zone.AddressBook = ab
				}
				parseAddressBookEntries(prop, ab)
			}
		}
	}
	return nil
}

// zoneInterfaceMembers flattens every interface name a `security-zone`
// `interfaces` member node carries, across BOTH parser AST shapes (#5248 — the
// zone-membership instance of the #2419 dual-shape class):
//
//   - hierarchical block  `interfaces { a; b; }`  → one child leaf per name,
//     each read at the top of the recursion (iface.Keys = ["a"], ["b"])
//   - single membership    `interfaces a`          → iface.Keys = ["a"]
//   - bracket list          `interfaces [ a b c ]`  → a NESTED chain, because the
//     schema models the interface name as a WILDCARD container (not a multi:true
//     leaf): `interfaces -> a(container) -> leaf Keys=["b","c"]`. The lexer strips
//     the brackets (#2419) so the flat-set path is [..., interfaces, a, b, c];
//     SetPath descends the wildcard for `a`, then — the interface-name node has
//     no wildcard of its own — collapses every remaining token onto ONE leaf
//     under `a` (ast_edit.go SetPath, the childSchema==nil tail).
//
// Reading only the member's Name() (Keys[0]) compiled just the first member and
// silently dropped the rest (#5248). Recursing the nested chain and reading every
// key at each level recovers all members. A `host-inbound-traffic` body under a
// member is NOT an interface name — it is compiled separately (#3362) and skipped
// here, whether it arrives as a CHILD node (every shape `set` can author, plus
// the ordinary hierarchical block) or, since #6525, as a token on the member's
// own Keys (the hierarchical PACKED spelling `a host-inbound-traffic
// system-services ssh`, which used to compile three phantom members).
//
// The caller passes MEMBER nodes, never the `interfaces` STANZA node — the
// Keys loop starts at index 0, which is a member name for a child but the
// stanza keyword `interfaces` for the stanza itself. Use
// zoneInterfaceMemberNodes to normalize a stanza into member nodes (#6525).
//
// This helper is for zone MEMBERSHIP ONLY. Do NOT reuse it to scope a
// per-interface host-inbound override: it recurses into CHILDREN, and a flat-set
// `interfaces [ a b ]` puts the sibling `b` in a child of `a` (see the nesting
// above) while a subsequent `set ... interfaces a host-inbound-traffic ...`
// reuses that same `a` container. Fanning an override across this member set
// therefore opens the service on `b` for a config that scoped it to `a` alone —
// the #6389 regression, closed unmerged. compileZones scopes the override on the
// member node's own KEYS instead (zoneInterfaceMemberKeys), which separates the
// two shapes (#6391).
func zoneInterfaceMembers(iface *Node) []string {
	// #7029: the node itself may BE a meta statement. At the call site the
	// member nodes come straight from zoneInterfaceMemberNodes, so
	// `apply-groups-except G;` arrives here as `iface`, not as a child — which
	// is why guarding only the child loop below left the reject in place.
	if zoneInterfaceApplyMetaKeyword(iface.Name()) {
		return nil
	}
	names, hasBody := zoneInterfaceKeysBeforeBody(iface)
	if hasBody {
		// A body keyword landed on this node's OWN Keys, which means the
		// statement was written in the packed spelling
		// `<if> host-inbound-traffic system-services ssh` — everything from
		// that token on is the member's BODY, including this node's CHILDREN
		// (they are the body's contents, e.g. `system-services ssh`). Recursing
		// them would promote body keywords to phantom interface names (#6525).
		// The body itself is not compiled from this shape; that is the residual
		// tracked separately (see the helper doc below).
		return names
	}
	for _, child := range iface.Children {
		if zoneInterfaceBodyKeywords[child.Name()] {
			continue
		}
		// #7029: Junos permits apply-groups / apply-groups-except /
		// apply-macro at ANY point in the hierarchy, and ExpandGroups removes
		// only apply-groups -- the other two survive expansion as live nodes.
		// In the member slot they were read as interface NAMES, compiled as
		// phantom members, and the zone-interface-DEFINED gate then rejected
		// the commit:
		//
		//   REJECT security zone "Z" references interface
		//   "apply-groups-except", which is not defined under `interfaces`
		//
		// Fail-LOUD over-rejection, not a silent membership loss, but it
		// refuses a legal Junos config. zoneInterfaceNonMemberToken already
		// knew these three; this walk was the one place that did not ask it.
		if zoneInterfaceApplyMetaKeyword(child.Name()) {
			continue
		}
		names = append(names, zoneInterfaceMembers(child)...)
	}
	return names
}

// zoneInterfaceApplyMetaKeyword reports whether tok is one of the three Junos
// meta statements that may appear at any hierarchy point and are never an
// interface name (#7029).
//
// Deliberately NOT zoneInterfaceNonMemberToken, which is a superset: that one
// also covers the host-inbound body keywords, and the member walk already
// handles those through zoneInterfaceBodyKeywords with different semantics (a
// body keyword on the node's OWN Keys terminates the walk; a meta keyword is
// simply skipped). Widening the walk to the superset would conflate the two and
// change what a packed body does.
func zoneInterfaceApplyMetaKeyword(tok string) bool {
	switch tok {
	case "apply-groups", "apply-groups-except", "apply-macro":
		return true
	}
	return false
}

// zoneInterfaceBodyKeywords is the set of tokens that may legally appear UNDER a
// `security zones security-zone <z> interfaces <if>` member and are therefore
// part of the member's BODY — never a member NAME. It mirrors the schema: the
// interface-name wildcard's only child is `host-inbound-traffic`
// (schema_security.go). Keep the two in lockstep; a body keyword missing from
// this set is compiled as a phantom interface name, which then either fails the
// strict zone-interface-DEFINED gate (loud) or, on the tolerant path, lands in
// zone membership as an interface that does not exist (silent).
var zoneInterfaceBodyKeywords = map[string]bool{
	"host-inbound-traffic": true,
}

// zoneInterfaceKeysBeforeBody splits a member node's Keys at the first body
// keyword: it returns the interface names that precede it, and whether one was
// found. Empty keys are skipped.
//
// Before #6525 the caller read every key unconditionally. That is correct for
// every shape `set` can author (SetPath always makes `host-inbound-traffic` a
// CHILD node, never a Keys token) and for the ordinary hierarchical block, but
// the hierarchical PACKED spelling puts the body on Keys:
//
//	interfaces { ge-0/0/0.0 host-inbound-traffic system-services ssh; }
//	                        ^--------- body, not membership ---------^
//
// which compiled `host-inbound-traffic`, `system-services` and `ssh` as three
// phantom zone members. Truncating at the body keyword drops them. The packed
// body is NOT parsed into a per-interface override here — that is a separate
// gap in the same #2419 packed-body class, deliberately out of scope for #6525
// and filed on its own; the direction is fail-CLOSED (the override is absent, so
// the interface admits only what the zone-level stanza admits) rather than the
// fail-open a phantom membership would produce.
func zoneInterfaceKeysBeforeBody(iface *Node) (names []string, hasBody bool) {
	for _, k := range iface.Keys {
		if k == "" {
			continue
		}
		if zoneInterfaceBodyKeywords[k] {
			return names, true
		}
		names = append(names, k)
	}
	return names, false
}

// zoneInterfaceMemberKeys returns the interface names a member node carries on
// its OWN Keys — iface.Keys truncated at the first body keyword and with empty
// keys dropped. This is the #6391 host-inbound override scope: the override
// applies to every name in the node's Keys and NEVER to its children. See the
// long comment at the override site in compileZones for why the two shapes it
// separates are not interchangeable.
func zoneInterfaceMemberKeys(iface *Node) []string {
	names, _ := zoneInterfaceKeysBeforeBody(iface)
	return names
}

// zoneInterfaceMemberNodes returns the MEMBER NODES of a `security zones
// security-zone <z> interfaces` stanza node, normalizing the hierarchical
// compact-leaf shape onto the block shape (#6525).
//
// The stanza reaches the compiler in two structurally different shapes:
//
//	BLOCK   `interfaces { a; b; }`  → Keys=["interfaces"], one child per member.
//	                                  `set` also always leaves the stanza node at
//	                                  Keys=["interfaces"] with its members under
//	                                  Children — but NOT necessarily one child
//	                                  each. A flat bracket list nests instead:
//	                                  `set ... interfaces [ a b c ]` gives
//	                                  `interfaces -> a(container) -> leaf
//	                                  Keys=["b","c"]` (SetPath descends the
//	                                  interface-name wildcard for `a`, then
//	                                  collapses the rest onto one leaf — see the
//	                                  zoneInterfaceMembers comment above).
//	                                  zoneInterfaceMembers RECURSES, so both are
//	                                  read correctly; only the stanza-level
//	                                  Keys tail distinguishes COMPACT from `set`.
//	                                  Shape pinned by
//	                                  TestZoneInterfaces6735FlatSetBracketNestsRatherThanFanning.
//	COMPACT `interfaces a;`         → Keys=["interfaces","a"], Children=nil
//	        `interfaces [ a b ];`   → Keys=["interfaces","a","b"], Children=nil
//	        `interfaces a { ... }`  → Keys=["interfaces","a"], Children=BODY
//
// In the COMPACT shape the member names are on the STANZA's own Keys tail and
// prop.Children — if present at all — holds the member's BODY, not more
// members. compileZones iterated prop.Children directly, so the compact shape
// ran the loop body zero times (member silently DROPPED, #6525) or, when a body
// was present, ran it once with the BODY node mistaken for a member (member
// dropped AND its body keywords compiled as phantom member names).
//
// Synthesizing one member node `Keys=prop.Keys[1:], Children=prop.Children`
// makes every compact spelling take the identical code path as its block
// equivalent, so membership, the #5248 bracket flatten and the #6391
// Keys-scoped host-inbound override all stay in ONE implementation. In
// particular the override still keys on the synthesized node's Keys, so
// `interfaces [ a b ] { host-inbound-traffic {...} }` fans to a and b (the
// multi-member intent of a body authored ON a bracket membership) while
// `interfaces a { host-inbound-traffic {...} b; }` scopes it to `a` alone —
// exactly what the block spellings of those two configs already did.
//
// Note prop.Keys[0] is the stanza keyword `interfaces` itself and is skipped;
// passing prop straight to zoneInterfaceMembers (whose Keys loop starts at
// index 0, correct for a CHILD) would compile a zone member literally named
// `interfaces`.
func zoneInterfaceMemberNodes(prop *Node) []*Node {
	if len(prop.Keys) > 1 {
		return []*Node{{Keys: prop.Keys[1:], Children: prop.Children}}
	}
	return prop.Children
}

// zoneInterfaceStanzaMembers returns every interface name an `interfaces`
// STANZA node contributes to zone membership, across every AST shape. It is
// exactly what compileZones accumulates for that stanza, factored out so the
// fail-closed gate (validateZoneInterfacesNonEmptyStrict) asks the COMPILER'S
// OWN reader whether the stanza named anything rather than re-deriving it — a
// second derivation is precisely how this defect class arises.
func zoneInterfaceStanzaMembers(prop *Node) []string {
	var names []string
	for _, iface := range zoneInterfaceMemberNodes(prop) {
		names = append(names, zoneInterfaceMembers(iface)...)
	}
	return names
}

// zoneInterfaceMemberPackedTail reports whether a member node carries a body
// keyword on its Keys with FURTHER TOKENS AFTER IT, and returns those trailing
// tokens. It is the detector behind validateZoneInterfacePackedTailStrict
// (#6735); it recurses exactly the nodes zoneInterfaceMembers recurses, so the
// gate and the truncator can never disagree about which nodes are members.
//
// The shape it finds is IRREDUCIBLY AMBIGUOUS. The lexer strips brackets
// (#2419), so these two statements parse to byte-identical Keys:
//
//	interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];
//	interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh;
//
// The first is a bracket MEMBER LIST whose author expects both interfaces in
// the zone; the second is the PACKED BODY spelling whose author expects one
// member plus a host-inbound override. `zoneInterfaceKeysBeforeBody` truncates
// at the keyword, which silently discards the operator's intent in BOTH
// readings — the trailing member in the first, the whole override in the
// second. No amount of local cleverness distinguishes them, because the
// distinguishing punctuation is gone before the compiler sees the node.
//
// So this is not resolved by guessing; it is resolved by REFUSING. A statement
// whose two readings disagree about zone membership is rejected at commit and
// the operator rewrites it in the block spelling, which is unambiguous and
// fully supported:
//
//	interfaces { ge-0/0/0.0; ge-0/0/1.0; }                     // both members
//	interfaces { ge-0/0/0.0 { host-inbound-traffic {...} } }   // member + body
//
// Deliberate consequence, and the reason this is a REJECT rather than a
// warning: the packed-body spelling used to COMMIT, contributing membership
// while silently dropping the override (the fail-closed residual #6525 left
// open). Silently discarding an authored host-inbound directive is exactly the
// class of quiet security loss #6525 was opened for, so making it loud is the
// point rather than collateral. The tolerant load / peer-sync path still warns
// instead of rejecting (#1960 no-brick), where behavior is unchanged from
// before this gate.
//
// A body keyword with NOTHING after it (`interfaces a host-inbound-traffic;`)
// is NOT flagged: truncation loses nothing there, and rejecting it would be the
// #4191 over-rejection class. Neither is a WELL-FORMED body arriving as a CHILD
// node (`interfaces a { host-inbound-traffic {...} }`, and the bracket-list form
// `interfaces [ a b ] { host-inbound-traffic {...} }`) — those spellings are
// unambiguous and compile their override correctly today.
//
// A keyword arriving as a child node is NOT automatically safe, though, and
// assuming it was is the #6735 escape this function was extended to close. The
// `set` CLI reaches the ambiguous shape by DESCENT rather than by a Keys tail:
// `host-inbound-traffic` is a schema child of the interface-name wildcard, so
//
//	set ... interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ]
//
// parks `ge-0/0/1.0` in a leaf UNDER the keyword node instead of collapsing it
// onto one Keys slice. Both this detector and zoneInterfaceMembers skipped
// keyword children by name, so they agreed — and the statement committed with
// ge-0/0/1.0 dropped. The child arm now asks
// zoneInterfaceHostInboundStrayTokens whether the keyword's subtree holds
// anything that cannot be body content, which is exactly the dropped-member set.
func zoneInterfaceMemberPackedTail(iface *Node) (keyword string, tail []string, found bool) {
	for i, k := range iface.Keys {
		if k == "" {
			continue
		}
		if !zoneInterfaceBodyKeywords[k] {
			continue
		}
		for _, rest := range iface.Keys[i+1:] {
			if rest != "" {
				tail = append(tail, rest)
			}
		}
		if len(tail) > 0 {
			// This node's CHILDREN are the body, not members, so the recursion
			// below must not descend them — mirroring zoneInterfaceMembers,
			// which returns as soon as hasBody is true. The matched keyword is
			// returned rather than re-derived by the caller, so adding a second
			// entry to zoneInterfaceBodyKeywords cannot leave the reject naming
			// the wrong token.
			return k, tail, true
		}
		// Nothing follows the keyword ON KEYS, but the keyword's own CHILDREN
		// may still carry dropped member tokens (#6735 secondary escape). That
		// is the shape `set` produces whenever the keyword is the token
		// immediately after the first bracket token, e.g.
		//
		//	set ... interfaces [ host-inbound-traffic ge-0/0/1.0 ]
		//	  interfaces -> host-inbound-traffic -> leaf Keys=["ge-0/0/1.0"]
		//
		// Returning here without looking would let that statement commit with
		// ge-0/0/1.0 silently dropped. Only tokens that cannot be BODY content
		// count — see zoneInterfaceHostInboundStrayTokens.
		if stray := zoneInterfaceHostInboundStrayTokens(iface); len(stray) > 0 {
			return k, stray, true
		}
		return k, nil, false
	}
	for _, child := range iface.Children {
		if zoneInterfaceBodyKeywords[child.Name()] {
			// The keyword arrived as a CHILD NODE rather than on this node's
			// Keys. Its own subtree is the member's BODY — except for tokens
			// that cannot be body content, which are dropped members `SetPath`
			// parked under the keyword (#6735 B1, the flat-set/`set` ingest of
			// the headline statement `interfaces [ a host-inbound-traffic b ]`).
			// Skipping the node outright — what this loop did before #6735 —
			// is what let that statement commit with `b` silently dropped.
			if stray := zoneInterfaceHostInboundStrayTokens(child); len(stray) > 0 {
				return child.Name(), stray, true
			}
			continue
		}
		if kw, tail, ok := zoneInterfaceMemberPackedTail(child); ok {
			return kw, tail, true
		}
	}
	return "", nil, false
}

// zoneInterfaceHostInboundBodyKeywords is the set of tokens that may legally
// appear directly UNDER a `host-inbound-traffic` node. It is DERIVED from the
// schema factory the grammar itself uses (hostInboundSchemaChildren in
// schema_security.go) rather than restated, because a divergence between the two
// is always a bug: a body keyword missing here is read as a dropped member and
// hard-rejected at commit (a false reject on a legitimate override), and a
// non-body token silently added there would be read as body and dropped. There
// is no legitimate reason for the two to differ, so they share one source.
var zoneInterfaceHostInboundBodyKeywords = func() map[string]bool {
	m := make(map[string]bool, len(hostInboundSchemaChildren()))
	for name := range hostInboundSchemaChildren() {
		m[name] = true
	}
	return m
}()

// zoneInterfaceHostInboundStrayTokens returns the tokens a `host-inbound-traffic`
// KEYWORD NODE carries that cannot be host-inbound BODY content — i.e. the
// interface names the compiler drops on the floor (#6735).
//
// The keyword node is reached two ways, and both are lossy in the same way:
//
//	interfaces { a { host-inbound-traffic b; } }   -> keyword node Keys=[kw, b]
//	set ... interfaces [ a host-inbound-traffic b ] -> keyword node Keys=[kw],
//	                                                   child leaf Keys=[b]
//
// The second is the `set`/flat-set ingest of the exact statement #6735 is built
// around. `SetPath` DESCENDS `host-inbound-traffic` (schema_security.go declares
// it as a named child of the interface-name wildcard) instead of collapsing the
// bracket tail onto one leaf, so the trailing member parks UNDER the keyword
// where both the truncator and the pre-#6735 detector skipped it by name. The
// operator got a commit, a zone missing an interface, and no diagnostic.
//
// A token is stray only if it cannot be body content:
//
//   - the Keys tail is body if its FIRST token is a legal body keyword
//     (`host-inbound-traffic system-services ssh` — the packed body, whose
//     override is a separate pre-existing gap, deliberately not made loud here);
//     otherwise every token in it is a dropped member.
//   - a CHILD is body if its name is a legal body keyword; otherwise every token
//     in its subtree is dropped.
//
// Anything else — a keyword with nothing under it at all
// (`interfaces a host-inbound-traffic;`), or a well-formed nested body
// (`host-inbound-traffic { system-services ssh; }`) — yields no stray tokens and
// therefore no reject, which keeps the #4191 over-rejection carve-out intact.
func zoneInterfaceHostInboundStrayTokens(kw *Node) []string {
	var stray []string
	var tail []string
	seenKeyword := false
	for _, k := range kw.Keys {
		if k == "" {
			continue
		}
		if !seenKeyword {
			if zoneInterfaceBodyKeywords[k] {
				seenKeyword = true
			}
			continue
		}
		tail = append(tail, k)
	}
	if len(tail) > 0 && !zoneInterfaceNonMemberToken(tail[0]) {
		stray = append(stray, tail...)
	}
	for _, child := range kw.Children {
		if zoneInterfaceNonMemberToken(child.Name()) {
			continue
		}
		stray = append(stray, zoneInterfaceNodeTokens(child)...)
	}
	return stray
}

// zoneInterfaceNonMemberToken reports whether a token appearing under a
// `host-inbound-traffic` node is something OTHER than a dropped interface name:
// either legitimate body content, or one of the Junos statements that may
// appear at ANY point in the hierarchy and never denote content.
//
// The second class is not optional. `apply-groups-except` and `apply-macro`
// SURVIVE group expansion as live nodes (ExpandGroups removes only
// `apply-groups`, ast_groups.go), so they reach this gate verbatim. Treating one
// as a dropped member hard-rejects a legitimate config at commit — measured:
// `host-inbound-traffic { apply-groups-except G; system-services ping; }`
// rejected with "followed by apply-groups-except G". `apply-groups` is listed
// too so the set does not depend on expansion having run, which the tolerant
// display paths do not guarantee. Same three keywords, and the same reason, as
// nonInterfaceIfKeyword in dup_named_blocks.go.
func zoneInterfaceNonMemberToken(tok string) bool {
	if zoneInterfaceHostInboundBodyKeywords[tok] {
		return true
	}
	switch tok {
	case "apply-groups", "apply-groups-except", "apply-macro":
		return true
	}
	return false
}

// zoneInterfaceNodeTokens flattens every non-empty token a node subtree carries,
// in source order: its own Keys followed by each child's tokens. It is how a
// dropped member that `SetPath` nested several levels deep is named back to the
// operator instead of rendered as its first token alone.
func zoneInterfaceNodeTokens(n *Node) []string {
	var toks []string
	for _, k := range n.Keys {
		if k != "" {
			toks = append(toks, k)
		}
	}
	for _, child := range n.Children {
		toks = append(toks, zoneInterfaceNodeTokens(child)...)
	}
	return toks
}

// zoneInterfaceStanzaPackedTail is the stanza-level entry point for
// zoneInterfaceMemberPackedTail, normalizing the stanza into member nodes the
// same way zoneInterfaceStanzaMembers does (#6735).
func zoneInterfaceStanzaPackedTail(prop *Node) (keyword string, tail []string, found bool) {
	for _, iface := range zoneInterfaceMemberNodes(prop) {
		if kw, tail, ok := zoneInterfaceMemberPackedTail(iface); ok {
			return kw, tail, true
		}
	}
	return "", nil, false
}

// zoneHasInterface reports whether the zone already lists this member.
//
// #7031: zone membership is a SET, but it is stored as a slice because the
// authored order is operator-visible in several renderers. A linear scan is
// right at this size -- a zone's member list is a handful of names, and a map
// would have to be built and thrown away per zone per compile.
func zoneHasInterface(zone *ZoneConfig, member string) bool {
	for _, have := range zone.Interfaces {
		if have == member {
			return true
		}
	}
	return false
}
