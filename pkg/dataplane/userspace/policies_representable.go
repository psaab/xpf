package userspace

import (
	"net"

	"github.com/psaab/xpf/pkg/config"
)

// Address representability checks for the userspace matcher.
// Split from policies.go (#4421) with no logic change.

// allAddressTokensRepresentable reports whether EVERY token in a policy
// address list is representable by the userspace matcher (#3261). An empty list
// is "any" (representable). A single unrepresentable token taints the whole
// side so buildOneRuleSnapshot emits the address sentinel and the Rust
// integrity preflight rejects the snapshot (fail closed) instead of silently
// dropping that token and narrowing/collapsing the match.
func allAddressTokensRepresentable(addrRepresentable func(tok string) bool, addrs []string) bool {
	for _, tok := range addrs {
		if !addrRepresentable(tok) {
			return false
		}
	}
	return true
}

// nameRepresentable reports whether an address-book name (Address or
// AddressSet, recursively) is FULLY representable by the userspace matcher
// (#3261). It is structural and content-independent: every resolved member must
// be a feed-bound name (resolved via the snapshot overlay, #2049), or an
// Address whose value parses to a concrete prefix (CIDR / bare IP / "any"), or
// an AddressSet all of whose members are representable AND that contributes at
// least one CONCRETE prefix. An Address with an empty or unparseable value (a
// Junos dns-name / wildcard-address / range-address that compiled to
// Value=="") or an undefined reference makes the name UNREPRESENTABLE — so
// buildOneRuleSnapshot emits the address sentinel and the Rust preflight
// rejects the whole snapshot rather than (A) widening an empty value to
// 0.0.0.0/0 match-any, or (B) silently dropping the unrepresentable member of
// an otherwise-populated book (deny narrowing). Because the check does not
// inspect the per-name feed-overlay merge, a DIRECT policy token that names a
// feed (not inside a set) stays representable (no false reject); the empty-feed
// = MatchNone semantics are by design (#2049).
//
// #3261 convergent MAJOR (Codex MAJOR 2 + Claude-SMR): the SET branch
// additionally requires that at least one recursively-resolved member
// contributes a concrete prefix. Without this an EMPTY address-set or a pure
// self-cycle (X -> X) would be VACUOUSLY representable — no sentinel emitted —
// yet compile to an EMPTY book row. An empty-row deny side decodes to MatchNone,
// so a `deny <empty/cycle set>` matches nothing and falls through to a later
// permit / default-permit — a deny fail-OPEN on the exact lenient-load /
// peer-sync path this mechanism guards (the strict commit gate is downgraded to
// a warning there).
//
// #3294 (A′): a feed-bound MEMBER of a set now contributes its live feed
// prefixes to the enclosing set's row (expandBookNameRecursive is feed-aware),
// so it IS a concrete contribution when the feed has >= 1 live prefix. A set
// MIXING a feed member and a concrete member is representable AND its row
// carries BOTH (the feed-portion under-deny is closed). A feed-ONLY set is
// representable+enforced when its feed is live, and #3261-rejected (sentinel,
// fail-closed) only when the feed is currently empty (an empty row -> MatchNone
// -> the deny would otherwise drop silently).
func nameRepresentable(ab *config.AddressBook, feedOverlay map[string][]string, bindings map[string]*config.AddressBinding, name string, visited map[string]bool) bool {
	// The closure must be BOTH structurally resolvable AND contribute >=1
	// concrete prefix. The >=1-concrete requirement is enforced HERE, exactly
	// once at the top, mirroring strict's single `count==0` reject after
	// resolve(name) succeeds. An empty / pure-cycle / feed-only top-level set is
	// structurally resolvable (r=true) but has no concrete contribution (c=false)
	// -> rejected; a mutual-cycle-with-concrete set is (true,true) -> accepted.
	// (A direct feed name never reaches here — addrRepresentable short-circuits
	// it via feedOverlay, preserving the #2049 direct-feed exemption.)
	//
	// #5753: `bindings` (cfg.Security.DynamicAddress.AddressBindings) is threaded
	// into the recursion so that a DECLARED dynamic-address binding buried inside
	// a nested address-set whose feed is UNREADY (absent from feedOverlay) is
	// recognized as unresolved and fails CLOSED even when a static alias of the
	// same name exists — the nested-set arm of the #5645/#5751 partial-deny
	// fail-open. See nameRepresentability.
	r, c := nameRepresentability(ab, feedOverlay, bindings, name, visited)
	return r && c
}

// nameRepresentability returns (representable, concrete) for an address-book
// name as TWO INDEPENDENT bits — structural-resolvability is DECOUPLED from
// concrete-ness. This is the parity contract with the strict commit validator
// `policyMatchAddressBookResolves` (pkg/config/compiler_validate_strict.go):
// the dataplane's accept/reject decision must EXACTLY equal strict's so a
// commit-valid config never has its snapshot silently over-rejected (Codex
// MERGE-NEEDS-MAJOR).
//
//   - `representable` (structurally resolvable) is false ONLY if a member is
//     structurally invalid: an empty-string ref, an Address with Value=="",
//     an undefined reference, OR a nested set that is itself unresolvable OR
//     EMPTY (hasMember==false). This mirrors strict's `resolve()==false`
//     poisoning the parent. Crucially, a mutual or self cycle does NOT taint a
//     set that ALSO has its own resolvable member — the cycle revisit returns
//     representable (strict's `if seen[ref] { return true }`).
//   - `concrete` reports whether the name contributes at least one CONCRETE
//     prefix to a book row: a CIDR / bare-IP / explicit-`any` Address, a
//     feed-bound name whose feed currently has >= 1 live prefix (#3294 (A′):
//     its prefixes ARE now merged into the enclosing set's row by
//     expandBookNameRecursive), or a nested set that itself has a concrete
//     contribution. A feed-bound name with an EMPTY feed and a cycle revisit are
//     representable-but-NOT-concrete (an empty feed contributes no prefix, and a
//     cycle revisit contributes nothing, matching expandBookNameRecursive's
//     nil-on-revisit).
//
// The SET branch returns (hasMember, anyConcrete): an empty set is
// (false,false) (matches strict's resolvedAny==false reject); a structurally
// valid set with >=1 member, all members representable, cycles OK, is
// representable EVEN IF its own concrete contribution is false (concrete then
// propagates separately up the stack). The >=1-concrete-in-closure requirement
// is NOT enforced here — it is checked EXACTLY ONCE at the top in
// nameRepresentable (`r && c`), mirroring strict's single top-level `count==0`
// reject AFTER resolve(name) succeeds. This decouple fixes the mutual-cycle-
// with-concrete over-reject: `A { address concrete; address-set B }`,
// `B { address-set A }` — when A is the entry, B's only member is the cycle
// revisit of A (representable, not concrete), so B is (true,false); the old
// `return anyConcrete, anyConcrete` made B (false,false), which poisoned A and
// discarded A's own concrete. strict ACCEPTS this config, so the dataplane now
// must too.
//
// The direct Address / direct feed-name paths do not require `concrete`
// (addrRepresentable short-circuits feed names BEFORE nameRepresentable, so a
// policy referencing a feed name directly never reaches the top `r && c` gate),
// preserving the #2049 direct-feed exemption.
//
// #5753: `bindings` is the declared dynamic-address binding set
// (cfg.Security.DynamicAddress.AddressBindings). It is consulted AFTER the
// feedOverlay branch and BEFORE the static ab.Addresses lookup — mirroring the
// top-level addrRepresentable ordering — so a member name that is a DECLARED
// binding whose feed is currently UNREADY (hence absent from feedOverlay) is
// treated as unresolvable (false, false) even when a static address-book alias
// of the same name exists. This closes the nested-set arm of the #5645/#5751
// partial-deny fail-open: without it, the walk would resolve the static alias
// and enforce only the partial static subset while the unready feed's prefixes
// go unmatched (a `deny` fail-OPEN). A READY feed is still in feedOverlay and
// resolves normally in the branch above (no regression); a static alias with NO
// declared binding of that name is untouched (no over-block).
func nameRepresentability(ab *config.AddressBook, feedOverlay map[string][]string, bindings map[string]*config.AddressBinding, name string, visited map[string]bool) (representable, concrete bool) {
	if name == "" {
		return false, false
	}
	if visited[name] {
		// Cycle revisit: matches expandBookNameRecursive's nil-on-revisit and
		// strict's `if seen[ref] { return true }` — representable (does NOT taint
		// the name), but contributes nothing concrete. The top-level
		// >=1-concrete gate in nameRepresentable is what rejects a pure cycle.
		return true, false
	}
	if feeds, feedBound := feedOverlay[name]; feedBound {
		// Feed-bound name. #3294 (A′): expandBookNameRecursive now merges the
		// feed prefixes into an enclosing set's row, so a feed-bound member
		// with >= 1 live prefix IS a concrete contribution toward the set's
		// representability (a `deny <set>` enforces the feed portion). An
		// EMPTY feed (overlay key present, no live prefixes) stays
		// representable-but-NOT-concrete: match-none by #2049 design, NOT a
		// reject — so the concrete bit is gated on live prefix count, not set
		// unconditionally. A top-level direct feed token never reaches here
		// (addrRepresentable short-circuits it via feedOverlay BEFORE
		// nameRepresentable), preserving the #2049 direct-feed exemption.
		return true, len(feeds) > 0
	}
	// #5753: a DECLARED dynamic-address binding that is ABSENT from feedOverlay is
	// UNRESOLVED (at least one feed constituent has no installed snapshot yet —
	// SnapshotForBindings publishes a binding only when ALL feeds are ready). A
	// READY binding is in feedOverlay and already resolved by the branch above, so
	// reaching here means the feed is unready. It must fail CLOSED even when a
	// STATIC address-book entry of the SAME name exists (the ab.Addresses branch
	// below): otherwise a nested `deny <set-containing-name>` would enforce only
	// the partial static subset while the unready feed's prefixes go unmatched (a
	// deny fail-OPEN). Returning (false,false) here poisons the enclosing set so
	// buildOneRuleSnapshot emits the __unsupported_address__ sentinel and the Rust
	// preflight rejects the whole snapshot (previous-good retained / fresh-boot
	// default-deny) — the nested-set analogue of the top-level addrRepresentable
	// guard (#5751). Indexing a nil bindings map is safe (zero value nil).
	if bindings[name] != nil {
		return false, false
	}
	if ab == nil {
		return false, false
	}
	if addr, ok := ab.Addresses[name]; ok {
		// #9524: UsableValue is "" for an entry that also carries an
		// unimplemented value form, so a mixed entry is unrepresentable like the
		// sole-value case rather than representable by its prefix alone.
		if addressValueRepresentable(addr.UsableValue()) {
			return true, true
		}
		return false, false
	}
	set, ok := ab.AddressSets[name]
	if !ok {
		// Neither a static address/set nor a feed-bound name: an undefined
		// reference is unrepresentable.
		return false, false
	}
	visited[name] = true
	defer delete(visited, name)
	hasMember := false
	anyConcrete := false
	for _, member := range set.Addresses {
		hasMember = true
		r, c := nameRepresentability(ab, feedOverlay, bindings, member, visited)
		if !r {
			// A structurally-invalid member poisons the parent — matches strict's
			// abort on resolve()==false (also fires when the member is an EMPTY
			// nested set, which returns hasMember=false here).
			return false, false
		}
		anyConcrete = anyConcrete || c
	}
	for _, nested := range set.AddressSets {
		hasMember = true
		r, c := nameRepresentability(ab, feedOverlay, bindings, nested, visited)
		if !r {
			return false, false
		}
		anyConcrete = anyConcrete || c
	}
	// Structural resolvability and concrete-ness are returned as INDEPENDENT
	// bits. A set with >=1 member, all representable (cycles OK), is structurally
	// resolvable even if its own concrete contribution is false; concrete
	// propagates separately. An EMPTY set is (false,false) — matches strict's
	// resolvedAny==false. The >=1-concrete-in-closure rule is enforced ONCE at
	// the top in nameRepresentable, NOT here.
	return hasMember, anyConcrete
}

// addressValueRepresentable reports whether a single address-book entry VALUE
// resolves to a concrete matcher prefix. Mirrors the value handling in
// expandBookNameToCIDRs: "any" is match-any (representable); a CIDR or bare IP
// is representable; an empty value (#3261: a dns-name/wildcard/range sub-stanza
// that compiled to "") or any other unparseable token is NOT.
func addressValueRepresentable(value string) bool {
	switch value {
	case "any":
		return true
	case "":
		return false
	}
	if isV4CIDR(value) || isV6CIDR(value) {
		return true
	}
	return net.ParseIP(value) != nil
}
