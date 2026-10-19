package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// zoneLocalNamePrefix marks a zone-qualified internal address-book name
// minted by resolveZoneLocalAddressBooks (#3061). Strict validation reserves
// the `zone-local/` prefix for synthetic names: operator address-book entries
// may not begin with it, and security-zone names may not contain `/`. A `/`
// may still appear elsewhere in an entry name (for example `net_10.0.0.0/8`).
// Since the zone is the `/`-free first segment after the prefix,
// ZoneLocalUnqualify splits it from a `/`-bearing entry name unambiguously.
// Tolerant loads may encounter a persisted pre-validator literal key; the
// fold skips an existing global key of either kind and marks it in
// CollidingNames so policy references are refused rather than misbound.
const zoneLocalNamePrefix = "zone-local/"

// setAddressPrefix14967 records a prefix candidate for addr (#14967).
// The first distinct prefix wins Value; a second DISTINCT prefix is
// recorded in DuplicatePrefixes (authoring order, deduplicated) instead
// of silently overwriting the first. An identical repeat collapses —
// a `load merge` re-stating the same prefix, flat-set re-`set`, or a
// group and an inline definition agreeing on the prefix stay legal.
// Strict commit rejects a recorded duplicate; the tolerant path keeps
// Value for show surfaces but UsableValue refuses enforcement.
func setAddressPrefix14967(addr *Address, prefix string) {
	if addr == nil || prefix == "" {
		return
	}
	if addr.Value == "" {
		if len(addr.DuplicatePrefixes) == 0 {
			addr.Value = prefix
			return
		}
		// A duplicate was already recorded (e.g. a group prefix that
		// lost to the inline prefix): keep Value as the first winner
		// and only extend the recorded set.
		for _, p := range addr.DuplicatePrefixes {
			if p == prefix {
				return
			}
		}
		addr.DuplicatePrefixes = append(addr.DuplicatePrefixes, prefix)
		return
	}
	if prefix == addr.Value {
		return
	}
	if len(addr.DuplicatePrefixes) == 0 {
		addr.DuplicatePrefixes = []string{addr.Value, prefix}
		return
	}
	for _, p := range addr.DuplicatePrefixes {
		if p == prefix {
			return
		}
	}
	addr.DuplicatePrefixes = append(addr.DuplicatePrefixes, prefix)
}

// recordAddressTrailing14967 records tokens that rode past an address
// prefix (#14967). Unlike a plain append it is used on paths where the
// prefix slot was routed through setAddressPrefix14967, so a duplicate
// definition's trailing tokens are still captured even when its prefix
// did not win the value slot.
func recordAddressTrailing14967(addr *Address, tokens ...string) {
	if addr == nil || len(tokens) == 0 {
		return
	}
	addr.TrailingTokens = append(addr.TrailingTokens, tokens...)
}

// zoneLocalQualify mints the global-book key for a zone-local address-book
// entry. The `/`-free zone segment makes the qualified key unambiguous even
// when the entry name contains `/`. Strict validation reserves the prefix,
// but a tolerant load may preserve a pre-validator user token with that key.
func zoneLocalQualify(zone, name string) string {
	return zoneLocalNamePrefix + zone + "/" + name
}

// ZoneLocalQualify is the exported form of zoneLocalQualify for consumers
// (e.g. the dataplane compiler) that must name a zone-local entry in the
// folded global-book namespace.
func ZoneLocalQualify(zone, name string) string {
	return zoneLocalQualify(zone, name)
}

// ZoneLocalUnqualify reverses zoneLocalQualify. If qualified is a synthetic
// zone-local key minted by the #3061 fold ("zone-local/<zone>/<name>"), it
// returns the authored zone and address-book name with ok=true; any other
// token returns ok=false. The zone component is the `/`-free first segment
// after the prefix (validateAddressBookEntryNamesStrict forbids `/` in a
// security-zone name), so strings.Cut on the first `/` splits zone from name
// unambiguously even when <name> itself contains `/` (net_10.0.0.0/8) — the
// #4340 prefix-in-name convention. Only the reserved "zone-local/" prefix is
// withheld from operator entry names, so a non-synthetic `/`-bearing operator
// name (net_10.0.0.0/8) never matches the prefix and returns ok=false.
func ZoneLocalUnqualify(qualified string) (zone, name string, ok bool) {
	rest, found := strings.CutPrefix(qualified, zoneLocalNamePrefix)
	if !found {
		return "", "", false
	}
	z, n, sep := strings.Cut(rest, "/")
	if !sep || z == "" || n == "" {
		return "", "", false
	}
	return z, n, true
}

// DisplayAddressName returns the operator-facing name for an address-book
// token. A synthetic zone-local key (zone-local/<zone>/<name>) is unqualified
// back to the authored book name the operator configured; any other token is
// returned unchanged. Use this on inventory surfaces (REST/gRPC list fields,
// flat name lists) where the zone is already implied by the policy's
// from/to-zone, so the internal compiler namespace never leaks to the operator.
func DisplayAddressName(token string) string {
	if _, name, ok := ZoneLocalUnqualify(token); ok {
		return name
	}
	return token
}

// DisplayAddressNames maps DisplayAddressName over a token list, returning a
// NEW slice (it never mutates the caller's slice, which aliases the live
// compiled config). nil in → nil out so an inventory surface keeps its
// nil-vs-empty distinction. When no token needs unqualifying the returned slice
// is element-equal to the input.
func DisplayAddressNames(tokens []string) []string {
	if tokens == nil {
		return nil
	}
	out := make([]string, len(tokens))
	for i, t := range tokens {
		out[i] = DisplayAddressName(t)
	}
	return out
}

// sortedNamedBookNames15672 / sortedZoneNamesForBooks15672: deterministic
// iteration helpers for the named-book passes (#15672).
func sortedNamedBookNames15672(m map[string]*NamedAddressBook) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// mergeAddressBookEntries15672 unions src entries into dst (find-or-create
// via parseAddressBookEntries merge semantics are per-node; here entries
// are already compiled, so copy pointers for new names and record a
// collision when both sides define the same name).
func mergeAddressBookEntries15672(dst, src *AddressBook) {
	if dst.Addresses == nil {
		dst.Addresses = make(map[string]*Address)
	}
	if dst.AddressSets == nil {
		dst.AddressSets = make(map[string]*AddressSet)
	}
	for name, a := range src.Addresses {
		if _, exists := dst.Addresses[name]; exists {
			if dst.CollidingNames == nil {
				dst.CollidingNames = make(map[string]struct{})
			}
			dst.CollidingNames[name] = struct{}{}
			continue
		}
		if _, exists := dst.AddressSets[name]; exists {
			if dst.CollidingNames == nil {
				dst.CollidingNames = make(map[string]struct{})
			}
			dst.CollidingNames[name] = struct{}{}
			continue
		}
		dst.Addresses[name] = a
	}
	for name, s := range src.AddressSets {
		if _, exists := dst.AddressSets[name]; exists {
			if dst.CollidingNames == nil {
				dst.CollidingNames = make(map[string]struct{})
			}
			dst.CollidingNames[name] = struct{}{}
			continue
		}
		if _, exists := dst.Addresses[name]; exists {
			if dst.CollidingNames == nil {
				dst.CollidingNames = make(map[string]struct{})
			}
			dst.CollidingNames[name] = struct{}{}
			continue
		}
		dst.AddressSets[name] = s
	}
	dst.UnknownBookEntries = append(dst.UnknownBookEntries, src.UnknownBookEntries...)
	for n := range src.CollidingNames {
		if dst.CollidingNames == nil {
			dst.CollidingNames = make(map[string]struct{})
		}
		dst.CollidingNames[n] = struct{}{}
	}
}

// resolveNamedAddressBooks15672 folds each attached named book into its
// attached zones (#15672). It MUST run before the pristine validators and
// resolveZoneLocalAddressBooks: afterwards an attached book is
// indistinguishable from an inline zone-local book, so every pristine
// gate (name collision, reserved names, duplicate prefixes, ...) sees
// its entries under the zone scope. Conflict bookkeeping:
//   - zone already has an inline AddressBook -> AttachedBookConflict,
//     entries still merged; the strict gate rejects, the tolerant path
//     quarantines same-name references via CollidingNames.
//   - second book attaches to the same zone -> both marked conflict.
//
// Undefined attached zones are left for validateNamedAddressBookAttachStrict.
func resolveNamedAddressBooks15672(sec *SecurityConfig) {
	if len(sec.NamedAddressBooks) == 0 {
		return
	}
	for _, bookName := range sortedNamedBookNames15672(sec.NamedAddressBooks) {
		nb := sec.NamedAddressBooks[bookName]
		if nb == nil {
			continue
		}
		for _, zoneName := range nb.AttachedZones {
			z := sec.Zones[zoneName]
			if z == nil {
				continue
			}
			if z.AddressBook == nil {
				z.AddressBook = &AddressBook{Addresses: make(map[string]*Address), AddressSets: make(map[string]*AddressSet)}
				z.AddressBook.AttachedBookName = bookName
				mergeAddressBookEntries15672(z.AddressBook, &nb.AddressBook)
				continue
			}
			// Inline book or a previous attachment already present.
			z.AddressBook.AttachedBookConflict = true
			nb.AddressBook.AttachedBookConflict = true
			if z.AddressBook.AttachedBookName != "" && z.AddressBook.AttachedBookName != bookName {
				if other := sec.NamedAddressBooks[z.AddressBook.AttachedBookName]; other != nil {
					other.AddressBook.AttachedBookConflict = true
				}
			}
			mergeAddressBookEntries15672(z.AddressBook, &nb.AddressBook)
		}
	}
}

// validateNamedAddressBookAttachStrict (#15672) rejects: attach to an
// undefined zone, a zone with two attached books, and a zone combining
// an attached book with an inline `address-book`. Strict rejects;
// tolerant warns and the fold quarantines conflicting names.
func validateNamedAddressBookAttachStrict(cfg *Config) error {
	if cfg == nil || len(cfg.Security.NamedAddressBooks) == 0 {
		return nil
	}
	for _, bookName := range sortedNamedBookNames15672(cfg.Security.NamedAddressBooks) {
		nb := cfg.Security.NamedAddressBooks[bookName]
		if nb == nil {
			continue
		}
		for _, z := range nb.AttachedZones {
			if cfg.Security.Zones[z] == nil {
				return fmt.Errorf("security address-book %q attach zone %q: zone is not defined (#15672)", bookName, z)
			}
		}
		if nb.AddressBook.AttachedBookConflict {
			return fmt.Errorf("security address-book %q: its attached zone already has an address book (inline zone address-book or another attached book); a zone has at most one attached address book and cannot combine it with an inline address-book (#15672)", bookName)
		}
	}
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for z := range cfg.Security.Zones {
		zoneNames = append(zoneNames, z)
	}
	sort.Strings(zoneNames)
	for _, zn := range zoneNames {
		if z := cfg.Security.Zones[zn]; z != nil && z.AddressBook != nil && z.AddressBook.AttachedBookConflict {
			return fmt.Errorf("security zone %q address-book: zone already has an address book (inline zone address-book or another attached book); a zone has at most one attached address book and cannot combine it with an inline address-book (#15672)", zn)
		}
	}
	return nil
}

// resolveZoneLocalAddressBooks folds every zone-local address book (#3061)
// into the global SecurityConfig.AddressBook under zone-qualified internal
// names and rewrites each policy's match address tokens that resolve
// zone-locally to point at the qualified entry. After this pass the entire
// downstream resolution path (wire snapshot, nameToID, classifyPolicyAddresses,
// strict/warn validators) keeps operating on a single flat global book.
//
// Junos scoping: a policy's source-address resolves against its FROM zone's
// book, destination-address against its TO zone's book — zone-local first,
// then the global book. A token defined in a zone's local book is rewritten
// to that zone's qualified name (zone-local wins); a token NOT in the zone's
// local book is left unchanged so it falls back to the global book. A name
// present only in zone A's book is therefore invisible to a policy in zone B.
func resolveZoneLocalAddressBooks(sec *SecurityConfig) {
	hasLocal := false
	for _, z := range sec.Zones {
		if z != nil && z.AddressBook != nil {
			hasLocal = true
			break
		}
	}
	if !hasLocal {
		return
	}

	if sec.AddressBook == nil {
		sec.AddressBook = &AddressBook{
			Addresses:   make(map[string]*Address),
			AddressSets: make(map[string]*AddressSet),
		}
	}
	gb := sec.AddressBook

	localDefines := func(zone, name string) bool {
		z := sec.Zones[zone]
		if z == nil || z.AddressBook == nil {
			return false
		}
		if z.DroppedEnforcementChild {
			if _, ok := z.AddressBook.CollidingNames[name]; ok {
				return true
			}
			for _, entry := range z.AddressBook.UnknownBookEntries {
				for _, candidate := range entry.Names {
					if candidate == name {
						return true
					}
				}
			}
			return false
		}
		if _, ok := z.AddressBook.Addresses[name]; ok {
			return true
		}
		if _, ok := z.AddressBook.AddressSets[name]; ok {
			return true
		}
		for _, entry := range z.AddressBook.UnknownBookEntries {
			for _, candidate := range entry.Names {
				if candidate == name {
					return true
				}
			}
		}
		return false
	}

	// Inject each zone-local entry into the global book under its qualified
	// name. Address-set member references are re-pointed to the same zone's
	// qualified name when the member is also zone-local (zone-local first),
	// otherwise left as a global reference.
	// `address` and `address-set` share one operator-visible namespace (#5676),
	// so a pre-existing global key of EITHER kind is a literal twin.
	foldKeyTaken := func(q string) bool {
		_, isAddr := gb.Addresses[q]
		_, isSet := gb.AddressSets[q]
		return isAddr || isSet
	}
	markFoldCollision := func(name string) {
		if gb.CollidingNames == nil {
			gb.CollidingNames = make(map[string]struct{})
		}
		gb.CollidingNames[name] = struct{}{}
	}
	for zoneName, z := range sec.Zones {
		if z == nil || z.AddressBook == nil {
			continue
		}
		if len(z.AddressBook.CollidingNames) > 0 {
			if gb.CollidingNames == nil {
				gb.CollidingNames = make(map[string]struct{}, len(z.AddressBook.CollidingNames))
			}
			for name := range z.AddressBook.CollidingNames {
				gb.CollidingNames[zoneLocalQualify(zoneName, name)] = struct{}{}
			}
		}
		if z.DroppedEnforcementChild {
			// Unknown-book names must still be collision-quarantined so a
			// poisoned zone cannot make an unresolved policy token fall back to
			// an unrelated global address. Do not fold any enforcement entries.
			for _, entry := range z.AddressBook.UnknownBookEntries {
				for _, name := range entry.Names {
					markFoldCollision(zoneLocalQualify(zoneName, name))
				}
			}
			continue
		}
		for name, addr := range z.AddressBook.Addresses {
			q := zoneLocalQualify(zoneName, name)
			if foldKeyTaken(q) {
				// Keep the operator's entry, but refuse policy references rather
				// than silently substituting it for the zone-local definition.
				markFoldCollision(q)
				continue
			}
			// #9524: carry the unimplemented-form taint, or a zone-local mixed
			// entry would resolve to its prefix alone once folded. #14967:
			// likewise carry the duplicate-prefix and trailing-token taints,
			// or a folded entry would resolve to an arbitrarily chosen winner
			// (or its prefix alone) once qualified.
			gb.Addresses[q] = &Address{Name: q, Value: addr.Value, Description: addr.Description,
				TrailingTokens:     append([]string(nil), addr.TrailingTokens...),
				DuplicatePrefixes:  append([]string(nil), addr.DuplicatePrefixes...),
				UnimplementedForms: append([]string(nil), addr.UnimplementedForms...)}
		}
		for name, set := range z.AddressBook.AddressSets {
			q := zoneLocalQualify(zoneName, name)
			if foldKeyTaken(q) {
				markFoldCollision(q)
				continue
			}
			ns := &AddressSet{
				Name:           q,
				UnknownMembers: append([]string(nil), set.UnknownMembers...),
			}
			for _, m := range set.Addresses {
				if localDefines(zoneName, m) {
					ns.Addresses = append(ns.Addresses, zoneLocalQualify(zoneName, m))
				} else {
					ns.Addresses = append(ns.Addresses, m)
				}
			}
			for _, m := range set.AddressSets {
				if localDefines(zoneName, m) {
					ns.AddressSets = append(ns.AddressSets, zoneLocalQualify(zoneName, m))
				} else {
					ns.AddressSets = append(ns.AddressSets, m)
				}
			}
			gb.AddressSets[q] = ns
		}
		for _, entry := range z.AddressBook.UnknownBookEntries {
			for _, name := range entry.Names {
				markFoldCollision(zoneLocalQualify(zoneName, name))
			}
		}
	}

	rewrite := func(zone string, tokens []string) {
		// An empty or wildcard ("any") zone names no single zone-local book to
		// resolve against, so leave such tokens for the global book.
		if IsWildcardZone(zone) {
			return
		}
		for i, t := range tokens {
			// #9574: every match-all keyword stays a keyword, including the
			// `any-ipv4` / `any-ipv6` the compiled config now keeps, so a
			// zone-local object named after one cannot capture it.
			if t == "" || IsPolicyAddressWildcardKeyword(t) {
				continue
			}
			if localDefines(zone, t) {
				tokens[i] = zoneLocalQualify(zone, t)
			}
		}
	}
	for _, zpp := range sec.Policies {
		if zpp == nil {
			continue
		}
		for _, p := range zpp.Policies {
			if p == nil {
				continue
			}
			rewrite(zpp.FromZone, p.Match.SourceAddresses)
			rewrite(zpp.ToZone, p.Match.DestinationAddresses)
		}
	}
	// #3287: a scoped global policy (#3148, `match from-zone <z>` /
	// `match to-zone <z>`) resolves its zone-local address references against
	// that zone's local book, exactly like a zone-pair policy. Without this the
	// bare token kept pointing at the global book (where the entry exists only
	// under its zone-qualified name), so the address constraint silently
	// resolved to match-none and legitimate zone-scoped global traffic fell
	// through to default-deny. An unscoped global (empty / `any` scope) has no
	// single zone-local book and is left to resolve against the global book.
	//
	// #4626 M03: the scope is now a zone SET. Zone-local book resolution stays
	// defined only for a SINGLE concrete zone — a multi-zone scope
	// (`[ trust dmz ]`) has no single zone-local book, so it resolves against
	// the GLOBAL book, the same carve-out an unscoped/`any` global already gets
	// (a documented parity limitation: multi-zone scoped globals cannot use
	// zone-local address books). A one-element scope keeps the pre-#4626
	// single-zone behaviour exactly; `rewrite` itself no-ops for `any`/empty.
	for _, p := range sec.GlobalPolicies {
		if p == nil {
			continue
		}
		if len(p.Match.FromZones) == 1 {
			rewrite(p.Match.FromZones[0], p.Match.SourceAddresses)
		}
		if len(p.Match.ToZones) == 1 {
			rewrite(p.Match.ToZones[0], p.Match.DestinationAddresses)
		}
	}
}

// compileAddressBook folds one `security address-book` block into the global
// address book, MERGING with whatever earlier blocks contributed (#7524).
//
// It used to read the FIRST `global` child and then ASSIGN
// `sec.AddressBook = ab`, which lost entries in three different ways —
// measured, each losing a different one:
//
//	security { address-book { global { A } global { B } } }   -> [A]  (first wins)
//	security { address-book { global { A } }
//	           address-book { global { B } } }                -> [B]  (last wins)
//	security { address-book { global { A } } }
//	security { address-book { global { B } } }                -> [B]  (last wins)
//
// parseStatements APPENDS a repeated block rather than merging it, and
// compileSecurity iterates every `address-book` sibling and every `security`
// root — so all three shapes reach the compiler and all three silently dropped
// an address. "Replace or ignore earlier entries" is literal: the first case
// ignores, the other two replace.
//
// It matters because an address that vanishes is not a parse error anywhere
// downstream. A policy naming the dropped address compiles against a book that
// does not contain it, and the resulting rule matches a different set of
// traffic than the operator wrote — the same silent-narrowing class #4706 and
// #4818 fixed for the INNER and SIBLING merges. Those two did not reach the
// CONTAINERS, which is what this closes.
//
// LAZY ALLOCATION IS PRESERVED: the book is materialized only when a `global`
// block actually exists, so a config with no address-book still compiles to a
// nil AddressBook and every `!= nil` check downstream keeps its meaning.
// Within a block, #14967 changed same-name resolution: a second DISTINCT
// prefix for one name is recorded as a duplicate and rejected at commit
// (the pre-#14967 last-wins fold silently narrowed the entry to the last
// prefix); identical repeats and disjoint prefix/description halves
// still merge as before.
func compileAddressBook(node *Node, sec *SecurityConfig) error {
	globals := node.FindChildren("global")
	for _, g := range globals {
		if sec.AddressBook == nil {
			sec.AddressBook = &AddressBook{
				Addresses:   make(map[string]*Address),
				AddressSets: make(map[string]*AddressSet),
			}
		}
		parseAddressBookEntries(g, sec.AddressBook)
	}
	// #15672: named books `security address-book <name> { ... }`. The
	// schema wildcard delivers each as a child whose Keys[0] is the book
	// name (flat-set shape may pack the whole body onto Keys). Parse
	// entries like the global book, plus `attach { zone <z>; }`.
	for _, child := range node.Children {
		if child == nil || child.Name() == "global" || child.Name() == "" {
			continue
		}
		if isApplyStatementKeyword(child.Name()) {
			continue
		}
		name := child.Name()
		if sec.NamedAddressBooks == nil {
			sec.NamedAddressBooks = make(map[string]*NamedAddressBook)
		}
		nb := sec.NamedAddressBooks[name]
		if nb == nil {
			nb = &NamedAddressBook{Name: name}
			nb.Addresses = make(map[string]*Address)
			nb.AddressSets = make(map[string]*AddressSet)
			sec.NamedAddressBooks[name] = nb
		}
		parseAddressBookEntries(child, &nb.AddressBook)
		for _, a := range attachZones15672(child) {
			seen := false
			for _, z := range nb.AttachedZones {
				if z == a {
					seen = true
				}
			}
			if !seen {
				nb.AttachedZones = append(nb.AttachedZones, a)
			}
		}
		// Flat-set packed shape: `address-book <name> address ...` packs
		// the statement onto the book node's own Keys.
		if len(child.Keys) >= 3 && (child.Keys[1] == "address" || child.Keys[1] == "address-set") {
			if nb.CollidingNames == nil {
				nb.CollidingNames = make(map[string]struct{})
			}
			nb.CollidingNames[child.Keys[2]] = struct{}{}
		}
	}
	return nil
}

// attachZones15672 extracts `attach { zone <z>; }` values from a named
// book node across flat-set (Keys-packed / child leaves) and hierarchical
// (attach container with zone children) shapes.
func attachZones15672(book *Node) []string {
	var zones []string
	add := func(z string) {
		if z != "" {
			zones = append(zones, z)
		}
	}
	for _, child := range book.Children {
		if child == nil {
			continue
		}
		if child.Name() == "attach" {
			for _, z := range child.FindChildren("zone") {
				for _, v := range z.Keys[1:] {
					add(v)
				}
				for _, c := range z.Children {
					add(c.Name())
				}
			}
			// Packed: attach zone <z> on the attach node's Keys.
			if len(child.Keys) >= 3 && child.Keys[1] == "zone" {
				for _, v := range child.Keys[2:] {
					add(v)
				}
			}
			for _, c := range child.Children {
				if c.Name() != "zone" {
					add(c.Name())
				}
			}
		}
	}
	// Packed on the book node: ... attach zone <z>
	for i, k := range book.Keys {
		if k == "attach" && i+2 < len(book.Keys) && book.Keys[i+1] == "zone" {
			add(book.Keys[i+2])
		}
	}
	return zones
}

// addressSetMemberValues extracts every value carried by an address-set
// `address` / `address-set` member node, across BOTH parser AST shapes
// (#2419, #4791 — the address-set-member instance of the same dual-shape
// class as firewallMatchValues in compiler_firewall.go):
//
//   - single member          `address a;`             → Keys=["address","a"]
//   - bracket list            `address [ a b c ];`     → Keys=["address","a","b","c"]
//     (the lexer strips `[`/`]` and the multi:true schema leaf absorbs every
//     trailing token onto Keys, so a bracketed list collapses onto ONE node)
//   - flat set, one line each `set ... address a` +
//     `set ... address b`                              → one child per value
//   - bracketed child block   `address { [ a b ]; }`   → one child whose
//     Keys=["a","b"] (#14345: every child key is a member, not just Keys[0])
//
// Reading only member.Keys[1] (the pre-#4791 bug) compiles just the first
// bracket-list entry and silently drops the rest. Reading BOTH Keys[1:] AND
// every key of each child covers every shape the parser can produce.
func addressSetMemberValues(member *Node) []string {
	var vals []string
	for _, k := range member.Keys[1:] {
		if k != "" {
			vals = append(vals, k)
		}
	}
	for _, vn := range member.Children {
		for _, v := range vn.Keys {
			if v != "" {
				vals = append(vals, v)
			}
		}
	}
	return vals
}

// parseAddressBookEntries folds the `address` / `address-set` children of
// node into ab. node is either the `global` block under `security
// address-book` or a zone-local `address-book` block under `security zones
// security-zone <z>` (#3061) — the entry grammar is identical, only the
// attachment point differs.
func parseAddressBookEntries(node *Node, ab *AddressBook) {
	// #5826: O(1) membership index per address-set, keyed by set name. The old
	// appendUniqueString linearly scanned the FULL existing member slice on every
	// append, so a size-valid config with N unique members across repeated
	// same-name stanzas cost O(N²) string comparisons during commit / boot / HA
	// config-sync / validation. Each set gets a direct-address set and a
	// nested-set set (independent namespaces); the ordered slice on the persisted
	// *AddressSet is still the source of truth for FIRST-SEEN ORDER — a member is
	// appended to it only on a map MISS, so output order + exact union-by-name
	// dedup are byte-identical to the linear-scan version, now in O(N). The index
	// is compiler-local (not persisted / not on the wire).
	type addrSetIndex struct {
		addr map[string]struct{} // direct `address` members already appended
		set  map[string]struct{} // nested `address-set` members already appended
	}
	indexes := make(map[string]*addrSetIndex)
	// indexFor returns the membership index for set `name`, seeding it (once) from
	// any members `as` already carries — from an earlier same-name block in THIS
	// node, or a prior parseAddressBookEntries call on the same book (repeated
	// `address-book` roots union onto the persisted *AddressSet). The seed is
	// O(existing members), bounded by total member count.
	indexFor := func(name string, as *AddressSet) *addrSetIndex {
		idx := indexes[name]
		if idx == nil {
			idx = &addrSetIndex{
				addr: make(map[string]struct{}, len(as.Addresses)),
				set:  make(map[string]struct{}, len(as.AddressSets)),
			}
			for _, a := range as.Addresses {
				idx.addr[a] = struct{}{}
			}
			for _, s := range as.AddressSets {
				idx.set[s] = struct{}{}
			}
			indexes[name] = idx
		}
		return idx
	}
	// #14200: a container-shaped `address { h1 10.0.0.1/32; }` /
	// `address-set { s1 { ... } }` carries NO name on the entry node itself
	// (Keys==["address"]/["address-set"]); the hierarchical schema descent
	// admits it, but the entries below expect the name at Keys[1]. Such a node
	// must be recorded exactly like an unknown keyword (strict reject via
	// validateAddressSetMembersDefinedStrict; tolerant load warns and
	// quarantines same-name references via CollidingNames / zone-local fold),
	// never silently `continue`d — otherwise a zone-local reference falls back
	// to a broader same-name global twin. Names are recovered from immediate
	// children: a leaf child's Keys[0] is the entry name; a non-leaf child's
	// Keys are the name (and any packed tail, mirroring the default arm).
	recordNameless := func(child *Node) {
		entry := AddressBookUnknownEntry{Keyword: child.Name()}
		for _, nested := range child.Children {
			entry.Names = append(entry.Names, nested.Keys...)
		}
		ab.UnknownBookEntries = append(ab.UnknownBookEntries, entry)
		if len(entry.Names) > 0 {
			if ab.CollidingNames == nil {
				ab.CollidingNames = make(map[string]struct{})
			}
			for _, name := range entry.Names {
				ab.CollidingNames[name] = struct{}{}
			}
		}
	}
	for _, child := range node.Children {
		// #15672: book-level `description` (global, zone-local, or named
		// book). Checked before the entry switch so it never lands in
		// UnknownBookEntries. Flat-set shape packs it as
		// Keys=[description <text>]; hierarchical as a child node.
		if child.Name() == "description" {
			if v := nodeVal(child); v != "" {
				ab.Description = v
			}
			continue
		}
		// #15672: `attach` is consumed by compileAddressBook for named
		// books; on any other book it is not an entry.
		if child.Name() == "attach" {
			continue
		}
		switch child.Name() {
		case "address":
			// A single Junos `address <name>` may render as MULTIPLE sibling
			// AST nodes (flat-set: one leaf per sub-stanza) or as a single
			// hierarchical block, and the sub-stanzas (prefix, description,
			// ...) arrive in arbitrary order. Merge by name so a described
			// address keeps its prefix and a non-prefix sub-stanza never
			// overwrites Value (#2222).
			if len(child.Keys) < 2 {
				recordNameless(child)
				continue
			}
			name := child.Keys[1]
			addr := ab.Addresses[name]
			if addr == nil {
				addr = &Address{Name: name}
				ab.Addresses[name] = addr
			}
			mergeAddressNode(addr, child)
		case "address-set":
			// A single Junos `address-set <name>` may render as MULTIPLE
			// sibling AST nodes: the hierarchical parser does NOT fold two
			// literal `address-set S { ... }` blocks (unlike the flat-set
			// `SetPath`, which descends into one existing node), so a
			// hand-authored / `load override` config with duplicate blocks
			// arrives here as several `address-set S` children. Merge by name
			// so the second stanza UNIONS its members onto the first instead of
			// overwriting and silently dropping the earlier members (#4706) —
			// a silent policy-data-loss / narrowing bug. Mirror the merge-by-
			// name the `address` case was hardened to above (#2222). Junos
			// unions same-named address-sets, so dedup members (first-seen
			// order) rather than accumulating duplicates.
			if len(child.Keys) < 2 {
				recordNameless(child)
				continue
			}
			{
				name := child.Keys[1]
				as := ab.AddressSets[name]
				if as == nil {
					as = &AddressSet{Name: name}
					ab.AddressSets[name] = as
				}
				idx := indexFor(name, as)
				appendMembers := func(kind string, values []string) {
					if kind == "address" {
						for _, v := range values {
							if _, seen := idx.addr[v]; !seen {
								idx.addr[v] = struct{}{}
								as.Addresses = append(as.Addresses, v)
							}
						}
						return
					}
					for _, v := range values {
						if _, seen := idx.set[v]; !seen {
							idx.set[v] = struct{}{}
							as.AddressSets = append(as.AddressSets, v)
						}
					}
				}
				for _, member := range child.Children {
					switch member.Name() {
					case "address", "address-set":
						appendMembers(member.Name(), addressSetMemberValues(member))
					case "description":
						// Ignore the metadata value, not a packed member run
						// after it (`description "d" address a1`).
						if len(member.Keys) > 2 {
							appendPackedAddressSetMembers12831(member.Keys[2:], bracketMask12831(member, 2), appendMembers,
								func(kw string) { as.UnknownMembers = append(as.UnknownMembers, kw) })
						}
						for _, packed := range member.Children {
							appendPackedAddressSetMembers12831(packed.Keys, bracketMask12831(packed, 0), appendMembers,
								func(kw string) { as.UnknownMembers = append(as.UnknownMembers, kw) })
						}
					default:
						// #11822: retain unknown member keywords so deferred
						// validation and resolution can poison this set.
						if kw := member.Name(); kw != "" {
							as.UnknownMembers = append(as.UnknownMembers, kw)
						}
					}
				}
				// A brace-elided body may be packed on the address-set node.
				appendPackedAddressSetMembers12831(child.Keys[2:], bracketMask12831(child, 2), appendMembers,
					func(kw string) { as.UnknownMembers = append(as.UnknownMembers, kw) })
			}
		default:
			if isApplyStatementKeyword(child.Name()) || child.Name() == "" {
				continue
			}
			entry := AddressBookUnknownEntry{Keyword: child.Name()}
			if len(child.Keys) > 1 {
				entry.Names = append(entry.Names, child.Keys[1:]...)
			}
			// Hierarchical typo entries have no name on the parent node:
			// capture each immediate block name so zone-local references to
			// the dropped entry cannot fall back to a global twin.
			for _, nested := range child.Children {
				if !nested.IsLeaf {
					entry.Names = append(entry.Names, nested.Keys...)
				}
			}
			ab.UnknownBookEntries = append(ab.UnknownBookEntries, entry)
			if len(entry.Names) > 0 {
				if ab.CollidingNames == nil {
					ab.CollidingNames = make(map[string]struct{})
				}
				for _, name := range entry.Names {
					ab.CollidingNames[name] = struct{}{}
				}
			}
		}
	}
}

// appendPackedAddressSetMembers12831 reads recognized address-set member
// statements from packed keys. It preserves multi-valued members until the next
// recognized statement head, and records every unrecognized token so a typo
// cannot silently yield a valid subset.
func appendPackedAddressSetMembers12831(keys []string, bracketed []bool, appendMember func(string, []string), unknown func(string)) {
	for i := 0; i < len(keys); {
		if keys[i] == "description" && !keyBracketed12831(bracketed, i) {
			i += 2 // the schema admits one metadata value
			continue
		}
		kind := keys[i]
		if kind != "address" && kind != "address-set" {
			unknown(kind)
			i++
			continue
		}
		start := i + 1
		i = start
		for i < len(keys) {
			if keyBracketed12831(bracketed, i) {
				i++
				continue
			}
			if keys[i] == "address" || keys[i] == "address-set" || keys[i] == "description" {
				break
			}
			i++
		}
		if start == i {
			unknown(kind)
			continue
		}
		appendMember(kind, keys[start:i])
	}
}

func keyBracketed12831(bracketed []bool, i int) bool {
	return i >= 0 && i < len(bracketed) && bracketed[i]
}

func bracketMask12831(node *Node, start int) []bool {
	if node == nil || len(node.KeysBracketed) != len(node.Keys) || start < 0 || start > len(node.Keys) {
		return nil
	}
	return node.KeysBracketed[start:]
}

// mergeAddressNode folds one `address <name> ...` AST node into addr,
// handling both AST shapes and arbitrary sub-stanza ordering (#2222):
//
//   - flat-set prefix leaf:   Keys=[address name <prefix>], IsLeaf, no children
//   - flat-set sub-stanza:    Keys=[address name <kw> ...] with children
//     (e.g. [address name description] + child [web-server])
//   - hierarchical block:     Keys=[address name] with bare-leaf prefix child
//     and/or [description <text>] child
//
// The prefix is taken from Keys[2] ONLY when it parses as a CIDR/IP, never
// when it is a sub-stanza keyword such as "description". A bare-leaf child
// (hierarchical block prefix) is the other prefix source. Description is
// routed to its own field so it can never clobber Value.
func mergeAddressNode(addr *Address, node *Node) {
	// Sub-stanza keyword form: Keys[2] is a known attribute keyword
	// (currently only "description"), so it is NOT the prefix.
	if len(node.Keys) >= 3 && node.Keys[2] == "description" {
		if d := descriptionText(node); d != "" {
			addr.Description = d
		}
		// In a packed description leaf, the address value can follow the
		// description value: `address a1 description "d" 10.0.0.1/32`.
		if len(node.Keys) > 4 {
			if looksLikeIPOrCIDR(node.Keys[4]) {
				setAddressPrefix14967(addr, node.Keys[4])
				// #14967: tokens after a packed prefix are trailing even
				// when a duplicate prefix superseded the value slot.
				if len(node.Keys) > 5 {
					recordAddressTrailing14967(addr, node.Keys[5:]...)
				}
			} else {
				addr.TrailingTokens = append(addr.TrailingTokens, node.Keys[4:]...)
			}
		}
		return
	}

	// An address value form is usable only when its token parses as a prefix.
	// Known Junos forms such as dns-name / wildcard-address / range-address
	// are unsupported, and future keywords must be tainted by default rather
	// than letting another occurrence's prefix resolve this entry.
	valueToken := ""
	if len(node.Keys) >= 3 {
		valueToken = node.Keys[2]
	}
	valueIsPrefix := valueToken != "" && looksLikeIPOrCIDR(valueToken)
	if valueToken != "" && !valueIsPrefix {
		addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, valueToken)
	}

	// Prefix-bearing leaf: Keys[2] is the prefix iff it parses as an IP/CIDR.
	if valueIsPrefix {
		setAddressPrefix14967(addr, valueToken)
		// #3332: a named address takes exactly one prefix; anything after it
		// (Keys[3:]) is operator garbage the compiler silently dropped.
		if len(node.Keys) > 3 {
			recordAddressTrailing14967(addr, node.Keys[3:]...)
		}
	}

	// Hierarchical-block children: bare-leaf prefix and/or `description`.
	for _, sub := range node.Children {
		switch sub.Name() {
		case "description":
			if d := nodeVal(sub); d != "" {
				addr.Description = d
			}
			// A braced body may contain the packed equivalent of the
			// description leaf, with the prefix after its text.
			if len(sub.Keys) > 2 {
				if looksLikeIPOrCIDR(sub.Keys[2]) {
					setAddressPrefix14967(addr, sub.Keys[2])
					if len(sub.Keys) > 3 {
						recordAddressTrailing14967(addr, sub.Keys[3:]...)
					}
				} else {
					addr.TrailingTokens = append(addr.TrailingTokens, sub.Keys[2:]...)
				}
			}
		default:
			// #14967: the apply-groups duplicate marker carries the losing
			// prefix (and one trailing exemplar) for an entry whose inline
			// and group definitions conflict. Route it into the same
			// taints instead of the unknown-form default-deny below.
			if sub.Name() == "__xpf_duplicate_address_14967__" {
				for _, k := range sub.Keys[1:] {
					if looksLikeIPOrCIDR(k) {
						setAddressPrefix14967(addr, k)
					} else {
						addr.TrailingTokens = append(addr.TrailingTokens, k)
					}
				}
				continue
			}
			// A bare value leaf (the hierarchical block prefix) is usable only
			// when it parses as an IP/CIDR. Every other sub-stanza is a known
			// unsupported or future value form, so record it for default-deny
			// resolution instead of silently ignoring it.
			if len(sub.Keys) >= 1 && looksLikeIPOrCIDR(sub.Keys[0]) {
				setAddressPrefix14967(addr, sub.Keys[0])
				// #14967: extra keys on a bare prefix child (the #14424
				// group-leaf fold packs trailing tokens there) are trailing
				// tokens, not a second prefix.
				if len(sub.Keys) > 1 {
					recordAddressTrailing14967(addr, sub.Keys[1:]...)
				}
				continue
			}
			addr.UnimplementedForms = appendUniqueForm9524(addr.UnimplementedForms, sub.Name())
		}
	}
}

// descriptionText extracts the description string from a flat-set
// `address <name> description <text>` node. Two AST shapes are accepted
// (#2419 unified the multi-value flat-set leaf onto the node's own keys):
//
//   - unified leaf:  Keys=[address, name, description, <text>], no children
//   - legacy split:  Keys=[address, name, description] + child leaf <text>
//
// The unified form is what both the hierarchical parser and the post-#2419
// flat-set SetPath now produce for any multi-value leaf, so it is checked
// first; the child-leaf form is kept for backward compatibility.
func descriptionText(node *Node) string {
	if len(node.Keys) >= 4 {
		return node.Keys[3]
	}
	if len(node.Children) > 0 {
		return node.Children[0].Name()
	}
	return ""
}

// looksLikeIPOrCIDR reports whether s is a bare IP or a CIDR prefix,
// mirroring the acceptance of the address-book warn validator
// (net.ParseCIDR || net.ParseIP).
func looksLikeIPOrCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}
