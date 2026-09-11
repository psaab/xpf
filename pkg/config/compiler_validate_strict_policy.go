package config

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
)

// validatePolicyMatchAddressesStrict hard-rejects a policy
// source-address / destination-address token that is neither a known
// address-book name (Address or AddressSet), the `any` keyword, nor a
// parseable CIDR / bare IP (#2008). Such a token (a typo) reaches the
// dataplane as an opaque string, fails CIDR/IP parsing in the Rust
// literal parser, and is silently dropped to an empty set. Under
// `*-address-excluded` inversion an empty set evaluates to MATCH-ALL —
// a silent fail-open security bypass (a policy meant to exclude one
// address ends up matching every address). Failing the typo at commit
// turns the bypass into an operator-visible error.
//
// Legitimate forms accepted: address-book names, `any` (and the
// family-scoped `any-ipv4` / `any-ipv6`, which compilePolicy already
// normalizes to `0.0.0.0/0` / `::/0` and which parse as CIDRs anyway),
// literal CIDRs, and bare IPv4 / IPv6 addresses. Junos address RANGES
// are an address-book construct (expanded to /32s under the book) and
// are referenced from a policy only by book NAME, so no range form
// reaches this token list.
// policyMatchNamedAddressRefs collects every NAME that is a valid non-literal
// policy source/destination-address reference: an address-book entry (an
// Address or an AddressSet, global or already folded from a zone-local book)
// and a dynamic-address feed binding name. It is the single source of truth for
// the named-reference set that both the strict commit gate
// (validatePolicyMatchAddressesStrict, #2008/#3294) and the non-fatal warn pass
// (compiler_validate_warn.go, #3958) consult, so the two cannot drift and emit
// a spurious "not in address-book" warning for a form the strict path accepts.
//
// The dynamic-address feed binding NAME is included because the userspace
// dataplane resolves it as a DIRECT policy address token via the feed overlay
// (#2049/#3294) and enforces the live feed prefixes. Scope note: this set is
// for the DIRECT policy reference only — policyMatchAddressBookResolves (#3149)
// stays feed-UNaware so a feed member nested in an address-set still poisons its
// set at strict (the anti-Option-C guardrail; feed-in-set enforcement rides the
// dataplane set-row merge, not a strict-accept here).
func policyMatchNamedAddressRefs(cfg *Config) map[string]bool {
	names := make(map[string]bool)
	if cfg == nil {
		return names
	}
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			names[name] = true
		}
		for name := range ab.AddressSets {
			names[name] = true
		}
	}
	for name := range cfg.Security.DynamicAddress.AddressBindings {
		names[name] = true
	}
	return names
}

// policyMatchAddressTokenRecognized reports whether tok is a syntactically
// recognized policy source/destination-address reference of ANY form: the
// reserved wildcards (`any` / `any-ipv4` / `any-ipv6` / the empty token), a
// literal CIDR or bare IP, or a name in `named` (an address-book entry or a
// dynamic-address feed binding — see policyMatchNamedAddressRefs). It is the
// exact acceptance predicate validatePolicyMatchAddressesStrict (#2008/#3294)
// uses, factored out so the warn pass agrees with strict (#3958). It reports
// only that the token is a well-formed reference form, NOT that a named
// address-set's members fully resolve — that deeper check is #3149's domain
// (validatePolicyMatchAddressSetMembersStrict).
func policyMatchAddressTokenRecognized(tok string, named map[string]bool) bool {
	switch tok {
	case "", "any", "any-ipv4", "any-ipv6":
		return true
	}
	if named[tok] {
		return true
	}
	if _, _, err := net.ParseCIDR(tok); err == nil {
		return true
	}
	return net.ParseIP(tok) != nil
}

func validatePolicyMatchAddressesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	bookNames := policyMatchNamedAddressRefs(cfg)
	validToken := func(tok string) bool {
		return policyMatchAddressTokenRecognized(tok, bookNames)
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		for _, addr := range pol.Match.SourceAddresses {
			if !validToken(addr) {
				return policyMatchAddressError(scope, pol.Name, "source-address", addr)
			}
		}
		for _, addr := range pol.Match.DestinationAddresses {
			if !validToken(addr) {
				return policyMatchAddressError(scope, pol.Name, "destination-address", addr)
			}
		}
		return nil
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		// #9127: NAME THE ZONE PAIR. Policy names are unique per zone pair, not
		// globally, so an error carrying only the policy name does not identify
		// the stanza the operator has to go and edit -- two `allow-dns`
		// policies under different pairs are ordinary configuration.
		// validatePolicyLoggingStrict already supplied this scope; these four
		// are the consistency change, not a new convention.
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		for _, pol := range zpp.Policies {
			if err := check(scope, pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// validatePolicyMatchApplicationsStrict hard-rejects a security-policy
// `match application <name>` token that resolves to NONE of: a predefined
// junos-* application, a user-defined `applications application <name>`, or a
// user-defined `applications application-set <name>` (#3144). Such a token (a
// typo or an undefined app) was only WARNED at commit
// (compiler_validate_warn.go), yet the userspace capability gate
// (resolveUserspaceApplicationNames in pkg/dataplane/userspace/capabilities.go)
// resolves the SAME name set and returns false for an unknown name →
// expandUserspacePolicyApplications fails → the built rule carries the reserved
// __unsupported__ sentinel term → the dataplane refuses to arm that policy
// (#3261, helper integrity preflight). The operator
// gets a green commit and a silently DISARMED policy engine on the firewall's
// primary allow/deny path — a commit/apply contract split. Failing the
// undefined reference at commit turns the silent disarm into an
// operator-visible error.
//
// Resolution mirrors the runtime gate EXACTLY (ResolveApplication, which checks
// user apps then the predefined table, plus ResolveApplicationSet) so the
// commit gate and the runtime gate cannot diverge. The `any` keyword and the
// empty token are always accepted. Covers both zone-pair and global policies,
// and the multi-value `application [ a b c ]` list — pol.Match.Applications is
// populated from every list value (compiler_security.go reads m.Keys[1:] for
// the collapsed-bracket form and m.Children for the hierarchical form, the same
// accumulation firewallMatchValues performs), so iterating the typed list
// covers each element.
//
// Distinct from #2217 (validateApplicationSetMembersStrict), which rejects a
// DANGLING MEMBER of a DEFINED application-set. A direct policy reference to a
// wholly undefined name is neither an app nor a set, so #2217's
// ExpandApplicationSet walk never sees it — this gate is the one that catches
// it. Composes cleanly: a defined set with a bad member is #2217's error; an
// undefined top-level name is this gate's error.
//
// Strict on commit / commit-check (hard reject). Lenient on load / peer-sync
// (warn so an already-persisted or peer-synced config that an older binary
// accepted still BOOTS — #1960 no-brick; the dataplane independently refuses to
// arm such a policy, so a leniently-loaded bad config is no worse off than
// before, now flagged).
func validatePolicyMatchApplicationsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// appRefError returns nil if the token resolves, or a tailored reject.
	// Resolution mirrors resolveUserspaceApplicationNames
	// (pkg/dataplane/userspace/capabilities.go) EXACTLY so the commit gate and
	// the runtime gate cannot diverge: a name resolves only if it is a
	// predefined / user application OR an application-set that EXPANDS to >= 1
	// member. A defined-but-EMPTY application-set resolves by NAME but expands
	// to zero members → the runtime gate returns false → the built rule carries
	// the __unsupported__ sentinel → the dataplane refuses to arm that policy
	// (#3146 — the same fail-open class this gate kills).
	// #2217's validateApplicationSetMembersStrict `continue`s on an empty set,
	// so nothing else catches it.
	// issue 8889: ONE memo for the whole validation, not one per policy. Every
	// referencing policy re-expanded the same sets from scratch, so the real
	// cost was N_policies x B^4 -- 8 policies took 357ms at B=16 and 1125ms at
	// B=20. A per-call memo removes only the within-policy factor; sharing it
	// across the loop removes both. This runs under the store's READ lock in
	// CommitCheck, so writers (Commit, Load, HA SyncApply) queue behind it.
	appSetExpansions := newAppSetMemo()
	appRefError := func(scope, policyName, name string) error {
		switch name {
		case "", "any":
			return nil
		}
		if _, ok := ResolveApplication(name, cfg.Applications.Applications); ok {
			return nil
		}
		if _, ok := ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
			// A malformed member (ExpandApplicationSet error) is #2217's gate's
			// job and runs first; here a clean expansion to zero members is the
			// empty-set fail-open (#3146).
			expanded, err := expandAppSetMemo(name, &cfg.Applications, 0, appSetExpansions)
			if err == nil && len(expanded) == 0 {
				return policyMatchEmptyAppSetError(scope, policyName, name)
			}
			return nil
		}
		return policyMatchApplicationError(scope, policyName, name)
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		for _, app := range pol.Match.Applications {
			if err := appRefError(scope, pol.Name, app); err != nil {
				return err
			}
		}
		return nil
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		// #9127: NAME THE ZONE PAIR. Policy names are unique per zone pair, not
		// globally, so an error carrying only the policy name does not identify
		// the stanza the operator has to go and edit -- two `allow-dns`
		// policies under different pairs are ordinary configuration.
		// validatePolicyLoggingStrict already supplied this scope; these four
		// are the consistency change, not a new convention.
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		for _, pol := range zpp.Policies {
			if err := check(scope, pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// policyMatchApplicationError formats the #3144 undefined-application reject,
// naming the policy scope, the policy, and the unresolved application token.
func policyMatchApplicationError(scope, policyName, app string) error {
	where := fmt.Sprintf("policy %q", policyName)
	if scope != "" {
		where = fmt.Sprintf("%s policy %q", scope, policyName)
	}
	return fmt.Errorf(
		"security policies %s match application %q is not defined "+
			"(no predefined junos-* application, no `applications application "+
			"%q`, and no `applications application-set %q`) — an undefined "+
			"application reference commits but the userspace dataplane then "+
			"REFUSES to arm security policies (commit/apply split, fail-open) "+
			"— define the application/application-set or fix the name (#3144)",
		where, app, app, app)
}

// policyMatchEmptyAppSetError formats the #3146 reject for a policy
// referencing a DEFINED but EMPTY application-set. The set exists by name but
// expands to zero members, so the runtime resolveUserspaceApplicationNames
// returns false (ExpandApplicationSet len==0) and the dataplane refuses to arm
// security policies — the same commit/apply fail-open class as #3144.
func policyMatchEmptyAppSetError(scope, policyName, name string) error {
	where := fmt.Sprintf("policy %q", policyName)
	if scope != "" {
		where = fmt.Sprintf("%s policy %q", scope, policyName)
	}
	return fmt.Errorf(
		"security policies %s match application %q is a defined but EMPTY "+
			"application-set (it expands to zero applications) — the policy "+
			"commits but the userspace dataplane then REFUSES to arm security "+
			"policies (commit/apply split, fail-open) — add at least one "+
			"`applications application-set %q application <name>` member or "+
			"remove the reference (#3146)",
		where, name, name)
}

// policyMatchAddressBookResolves mirrors the runtime address resolver
// resolveUserspaceAddressBookEntry + expandUserspacePolicyAddresses
// (pkg/dataplane/userspace/capabilities.go) for a single address-book NAME
// token. It returns nil when the name fully resolves to >= 1 literal address
// (i.e. the runtime capability gate accepts it), or an error describing the
// FIRST member that does not resolve / the empty expansion that makes the
// gate refuse to arm.
//
// The fail-closed semantics are copied verbatim from the runtime so the commit
// gate and the runtime gate cannot diverge:
//
//   - a defined `address` with a non-empty Value resolves (accumulates one
//     literal); an `address` with an EMPTY value does NOT (the runtime returns
//     false on addr.Value == "").
//   - an `address-set` resolves only if EVERY direct and nested member resolves
//     AND it has at least one member (resolvedAny). A dangling member (a name
//     that is neither a defined address nor a defined set) fails the WHOLE set
//     — the runtime's `if !resolve(member) { return false }`. A defined-but-
//     EMPTY set fails (resolvedAny stays false).
//   - a cycle short-circuits to "resolved" for the inner visit (the runtime's
//     `if seenSets[ref] { return true }`), but a name that expands to ZERO
//     literals (e.g. a pure self-cycle) is still rejected by the outer
//     len(values) == 0 check that expandUserspacePolicyAddresses applies.
//
// `seen` is NOT backtracked (no defer delete), matching the runtime's
// persistent seenSets — this is deliberately distinct from ExpandAddressSet
// (predefined.go), whose visited map backtracks for a different purpose.
func policyMatchAddressBookResolves(ab *AddressBook, name string) error {
	seen := make(map[string]bool)
	count := 0 // literal addresses accumulated (mirrors expanded slice length)
	var firstErr error
	var resolve func(ref string) bool
	resolve = func(ref string) bool {
		if ref == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("empty member reference")
			}
			return false
		}
		if addr := ab.Addresses[ref]; addr != nil {
			if addr.Value == "" {
				if firstErr == nil {
					firstErr = fmt.Errorf("address %q has no configured prefix "+
						"(it resolves to no usable address)", ref)
				}
				return false
			}
			count++
			return true
		}
		set := ab.AddressSets[ref]
		if set == nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("member %q is not a defined address or "+
					"address-set", ref)
			}
			return false
		}
		if seen[ref] {
			return true // cycle: already counted up the stack (mirror runtime)
		}
		seen[ref] = true
		resolvedAny := false
		for _, m := range set.Addresses {
			if !resolve(m) {
				return false
			}
			resolvedAny = true
		}
		for _, m := range set.AddressSets {
			if !resolve(m) {
				return false
			}
			resolvedAny = true
		}
		if !resolvedAny {
			if firstErr == nil {
				firstErr = fmt.Errorf("address-set %q is empty "+
					"(it expands to no addresses)", ref)
			}
			return false
		}
		return true
	}
	if !resolve(name) {
		if firstErr == nil {
			firstErr = fmt.Errorf("%q resolves to no address", name)
		}
		return firstErr
	}
	if count == 0 {
		// Resolved true but accumulated no literal (e.g. a pure cycle):
		// mirrors expandUserspacePolicyAddresses' len(values) == 0 reject.
		return fmt.Errorf("address-set %q expands to no addresses", name)
	}
	return nil
}

// validatePolicyMatchAddressSetMembersStrict hard-rejects a security-policy
// source-address / destination-address that names a DEFINED address-book entry
// (an address or an address-set) the runtime address resolver cannot fully
// resolve to >= 1 literal address (#3149; also folds the empty-address-set case
// #3147). This is the address-book sibling of #2217
// (validateApplicationSetMembersStrict, the application-set member gate) and the
// #3144/#3146 application gate.
//
// The split with validatePolicyMatchAddressesStrict (#2008): that gate rejects a
// WHOLLY UNDEFINED token (a typo that is neither a defined name, `any`, nor a
// literal CIDR/IP). This gate handles the token that IS a defined book name but
// whose (recursive) members dangle, or that is a defined-but-EMPTY set, or a
// defined address with no prefix. In all of these the runtime
// resolveUserspaceAddressBookEntry returns false / an empty expansion →
// expandUserspacePolicyAddresses fails → the built rule carries the
// __unsupported_address__ sentinel → the dataplane refuses to arm that policy.
// The operator got a
// green commit (only a compiler_validate_warn.go warning) and a silently
// DISARMED allow/deny path — the same commit/apply fail-open class #3144/#3146
// close for applications.
//
// #3147 excluded-inversion safety: the resolver is applied to the SAME
// SourceAddresses / DestinationAddresses lists the runtime gate checks,
// regardless of the *-address-excluded flag. Rejecting an empty / dangling set
// at COMMIT is therefore fail-CLOSED for the excluded case too: an empty
// excluded set can never be committed, so it can never reach the dataplane and
// invert to match-all (the historic fail-open this constraint guards against).
//
// Resolution mirrors resolveUserspaceAddressBookEntry +
// expandUserspacePolicyAddresses EXACTLY (see policyMatchAddressBookResolves),
// so the commit gate and the runtime gate cannot diverge. `any` / `any-ipv4` /
// `any-ipv6` / the empty token and literal CIDR/IP tokens are not book names and
// are passed through (the #2008 gate already covers literals). Covers zone-pair
// + global policies and both source and destination, including the recursive
// address-set-of-address-sets case.
//
// Strict on commit / commit-check (hard reject naming the policy scope, the
// policy, the field, and the unresolved member). Lenient on load / peer-sync
// (warn via opts.lenientPolicyMatchAddressSetMembers so an already-persisted or
// peer-synced config an older binary accepted still BOOTS — #1960; the dataplane
// independently refuses to arm such a policy, so a leniently-loaded bad config
// is no worse off, now flagged). Same doctrine as lenientPolicyMatchApplications.
func validatePolicyMatchAddressSetMembersStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return nil
	}
	isDefinedName := func(tok string) bool {
		if _, ok := ab.Addresses[tok]; ok {
			return true
		}
		if _, ok := ab.AddressSets[tok]; ok {
			return true
		}
		return false
	}
	checkToken := func(scope, policyName, field, tok string) error {
		switch tok {
		case "", "any", "any-ipv4", "any-ipv6":
			return nil
		}
		// A wholly-undefined token / literal is the domain of
		// validatePolicyMatchAddressesStrict (#2008); only inspect defined names.
		if !isDefinedName(tok) {
			return nil
		}
		if err := policyMatchAddressBookResolves(ab, tok); err != nil {
			return policyMatchAddressSetError(scope, policyName, field, tok, err)
		}
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		for _, addr := range pol.Match.SourceAddresses {
			if err := checkToken(scope, pol.Name, "source-address", addr); err != nil {
				return err
			}
		}
		for _, addr := range pol.Match.DestinationAddresses {
			if err := checkToken(scope, pol.Name, "destination-address", addr); err != nil {
				return err
			}
		}
		return nil
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		// #9127: NAME THE ZONE PAIR. Policy names are unique per zone pair, not
		// globally, so an error carrying only the policy name does not identify
		// the stanza the operator has to go and edit -- two `allow-dns`
		// policies under different pairs are ordinary configuration.
		// validatePolicyLoggingStrict already supplied this scope; these four
		// are the consistency change, not a new convention.
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		for _, pol := range zpp.Policies {
			if err := check(scope, pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// policyMatchAddressSetError formats the #3149 / #3147 reject, naming the policy
// scope, the policy, the match field, the unresolved book name, and the inner
// resolution failure.
func policyMatchAddressSetError(scope, policyName, field, name string, cause error) error {
	where := fmt.Sprintf("policy %q", policyName)
	if scope != "" {
		where = fmt.Sprintf("%s policy %q", scope, policyName)
	}
	return fmt.Errorf(
		"security policies %s match %s %q does not fully resolve: %w — the "+
			"policy commits but the userspace dataplane then REFUSES to arm "+
			"security policies (commit/apply split, fail-open) — define the "+
			"missing address/address-set or fix the member (#3149)",
		where, field, name, cause)
}

// validatePolicyZoneReferencesStrict hard-rejects a security policy zone-pair
// (`from-zone <a> to-zone <b> { policy ... }`) whose from-zone or to-zone names
// a security zone the configuration never defines (#2401).
//
// Junos rejects an undefined zone reference at commit; this validator restores
// that fail-CLOSED parity. Without it, such a stanza was compiled and KEPT, but
// the userspace dataplane resolved the unknown zone name to no zone-id; before
// #3402 it then silently DROPPED the unindexed rule, so the zone pair fell
// through to `state.default_action` (a fail-OPEN deny under a permit default, a
// blackhole under a deny default, with no operator-visible signal beyond a
// stderr line).
//
// ValidateConfig already surfaced this as a warning only (commit succeeded with
// an unenforceable rule). This is the strict commit / commit-check gate;
// CompileConfigLenient downgrades it back to a warning (lenientPolicyZoneRefs)
// so an already-persisted or peer-synced config carrying a stale zone reference
// still boots the daemon. Since #3402 the dataplane no longer silently drops
// the rule: its integrity preflight rejects the WHOLE snapshot
// (SnapshotIntegrityError::UnresolvableZoneReference) and retains the previous
// good state (default-deny on a fresh boot), so a leniently-loaded bad config
// fails closed rather than silently un-enforcing the rule.
//
// Special zone tokens (`any`, `junos-host`, the empty token) are exempt; global
// policies are not iterated (see policyZoneSpecialTokens). Iteration is in
// cfg.Security.Policies order, which is deterministic (built in config order by
// compileSecurityPolicies), so the first-reported error is stable.
func validatePolicyZoneReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(zone string) bool {
		if _, special := policyZoneSpecialTokens[zone]; special {
			return true
		}
		_, ok := cfg.Security.Zones[zone]
		return ok
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		// #4230 (fable-167 P-1): the reserved self-traffic zone `junos-host`
		// on the FROM side of a zone-pair is host-ORIGINATED traffic — the
		// firewall's own sockets egress via the kernel TX path, never the
		// AF_XDP RX gate, so a `from-zone junos-host to-zone <z>` zone-pair
		// commits but silently never matches. Reject it at commit for the same
		// fail-closed parity as the GLOBAL `match from-zone junos-host` gate in
		// the GlobalPolicies loop below (#3611 Piece A closed only the global
		// form). policyZoneSpecialTokens exempts `junos-host` from the
		// undefined-zone check, so without this the zone-pair spelling escaped
		// every gate — committing clean while the dataplane never consulted it
		// (userspace-dp/src/policy.rs evaluate_junos_host_policy). The lenient
		// load / peer-sync path downgrades this to a warning
		// (lenientPolicyZoneRefs, the shared #1960 no-brick doctrine) so an
		// already-persisted or peer-synced config an older binary accepted
		// still boots. `to-zone junos-host` (host-INBOUND) stays supported —
		// it is consulted on the LocalDelivery gate (#3019/#3639) and is only
		// checked by the ordinary defined() gate below.
		if zpp.FromZone == "junos-host" {
			return fmt.Errorf(
				"security policy from-zone %q to-zone %q: from-zone junos-host (host-originated / locally-generated traffic) is not supported — such traffic egresses via the kernel TX path, not the AF_XDP RX gate, so the rule would commit but silently never match; remove the junos-host from-zone (#3611 Piece A, #4230)",
				zpp.FromZone, zpp.ToZone)
		}
		// #9570: `junos-global` is the reserved GLOBAL-policy context, not a
		// zone. The generic undefined-zone text below would tell the operator to
		// define `security-zone junos-global` (which #3055 rejects) and would
		// claim the rule is "silently never matched", which was false for this
		// token: the helper classified a zone-pair naming it as a device-wide
		// GLOBAL rule. Name the context instead. The tolerant path downgrades
		// this to a warning (lenientPolicyZoneRefs) and the snapshot builder then
		// poisons the rule so the helper refuses the whole snapshot
		// (pkg/dataplane/userspace/policies_reject_global_sentinel_9570.go).
		if side := ZonePairGlobalSentinelSide(zpp.FromZone, zpp.ToZone); side != "" {
			return fmt.Errorf(
				"security policy from-zone %q to-zone %q names %q as its %s: that is the reserved global-policy context, not a security zone, and a zone-pair stanza cannot reference it — write the policy under `security policies global` instead (#3055, #9570)",
				zpp.FromZone, zpp.ToZone, JunosGlobalZoneName, side)
		}
		if !defined(zpp.FromZone) {
			return fmt.Errorf(
				"security policy from-zone %q to-zone %q references undefined from-zone %q; define `set security zones security-zone %s` in the same commit; on a tolerant load the userspace helper refuses the WHOLE policy snapshot for an unresolvable zone (#3402), so none of the config's policies is enforced",
				zpp.FromZone, zpp.ToZone, zpp.FromZone, zpp.FromZone)
		}
		if !defined(zpp.ToZone) {
			return fmt.Errorf(
				"security policy from-zone %q to-zone %q references undefined to-zone %q; define `set security zones security-zone %s` in the same commit; on a tolerant load the userspace helper refuses the WHOLE policy snapshot for an unresolvable zone (#3402), so none of the config's policies is enforced",
				zpp.FromZone, zpp.ToZone, zpp.ToZone, zpp.ToZone)
		}
	}
	// #3148: a global policy may carry optional from-zone/to-zone match
	// context. An empty context means "all zones" (exempt via the "" special
	// token); a non-empty context that names an undefined zone makes the
	// dataplane fail CLOSED — since #3402 it raises
	// SnapshotIntegrityError::UnresolvableZoneReference (build_global_zone_scope
	// in userspace-dp/src/policy.rs), rejecting the whole snapshot rather than
	// silently producing a matches-nothing scope that removes the operator's
	// scoped global policy. Reject it at commit for the same fail-closed parity
	// as the zone-pair case above; the lenient path downgrades to a warning so
	// an already-persisted config still boots the daemon.
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		// #4626 M03: a scoped-global from-zone/to-zone match context is a zone
		// SET (`match from-zone [ a b ]`). Validate EVERY element per side —
		// the reserved-token direction split (#3639, #3611 Piece B) and the
		// undefined-zone fail-closed reject both apply per element:
		//
		//   - `match to-zone junos-host` (host-INBOUND) IS supported and
		//     commits — but ONLY as a lone token: a `to-zone` list that MIXES
		//     junos-host with any other zone is ambiguous (the host predicate
		//     is `ToZones == ["junos-host"]` exactly), so it is rejected.
		//   - `match from-zone junos-host` (host-ORIGINATED) stays rejected on
		//     every element: the firewall's own sockets egress via the kernel
		//     TX path, never the AF_XDP RX gate, so a from-zone junos-host
		//     global would commit but silently never match (#3611 Piece A).
		//   - A scope list that MIXES `any` with concrete zones is redundant
		//     (any ⊇ everything) and ambiguous, so it is rejected on either
		//     side (symmetric with the junos-host no-mix rule).
		//
		// (`any` alone and the empty scope stay exempt = all-zones, matching
		// build_global_zone_scope in policy.rs. The tolerant load path still
		// collapses a mixed set safely via IsWildcardZoneSet, but the strict
		// commit path never emits one.)
		if len(pol.Match.FromZones) > 1 && slices.Contains(pol.Match.FromZones, "any") {
			return fmt.Errorf(
				"security policies global policy %q match from-zone list %v mixes `any` with concrete zones; use either `any` (all zones) or an explicit zone list, not both (#4626)",
				pol.Name, pol.Match.FromZones)
		}
		if len(pol.Match.ToZones) > 1 && slices.Contains(pol.Match.ToZones, "any") {
			return fmt.Errorf(
				"security policies global policy %q match to-zone list %v mixes `any` with concrete zones; use either `any` (all zones) or an explicit zone list, not both (#4626)",
				pol.Name, pol.Match.ToZones)
		}
		if len(pol.Match.ToZones) > 1 && slices.Contains(pol.Match.ToZones, "junos-host") {
			return fmt.Errorf(
				"security policies global policy %q match to-zone list %v mixes `junos-host` with other zones; a host-inbound global must scope `to-zone junos-host` alone (#4626/#3639)",
				pol.Name, pol.Match.ToZones)
		}
		for _, z := range pol.Match.FromZones {
			if z == "junos-host" {
				return fmt.Errorf(
					"security policies global policy %q match from-zone %q is not supported (host-originated traffic egresses via the kernel TX path, not the AF_XDP RX gate, so a from-zone junos-host global would silently never match); remove the junos-host match context (#3611 Piece A)",
					pol.Name, z)
			}
			if !defined(z) {
				return fmt.Errorf(
					"security policies global policy %q match from-zone %q references undefined zone; define `set security zones security-zone %s` in the same commit; on a tolerant load the userspace helper refuses the WHOLE policy snapshot for an unresolvable zone (#3402), so none of the config's policies is enforced",
					pol.Name, z, z)
			}
		}
		for _, z := range pol.Match.ToZones {
			if !defined(z) {
				return fmt.Errorf(
					"security policies global policy %q match to-zone %q references undefined zone; define `set security zones security-zone %s` in the same commit; on a tolerant load the userspace helper refuses the WHOLE policy snapshot for an unresolvable zone (#3402), so none of the config's policies is enforced",
					pol.Name, z, z)
			}
		}
	}
	return nil
}

// validateDuplicatePolicyNamesStrict hard-rejects two security policies that
// share a name within the same enforcement context: the same from-zone/to-zone
// zone-pair, or the global rulebase (#3473). Junos/vSRX require a policy name to
// be unique within a from/to-zone context (and within `global`); a duplicate is
// a commit error there.
//
// xpf accepted duplicates silently. compilePolicies appends every named instance
// without a uniqueness check, so two `policy allow` rules in one zone-pair both
// survive into the compiled config — including when the offending pair is split
// across two top-level `security {}` blocks: parseStatements APPENDS a repeated
// block (it never merges), and compileConfig calls compileSecurity for EVERY
// `security` root, so compilePolicies appends each instance into the shared
// cfg.Security.Policies / cfg.Security.GlobalPolicies. This validator therefore
// reads the already-aggregated typed slices and is duplicate-block-safe by
// construction (the typed family's analogue of the forEachChild discipline that
// the raw-AST pre-walk gates use, #3562/#3566).
//
// First-match enforcement order stays correct even with a duplicate, but the
// userspace hit counter is NAME-keyed: RuleID = "<from>-><to>/<name>" (globals
// key on "junos-global->junos-global/<name>", pkg/dataplane/userspace), so the
// two rules COALESCE onto one Arc<PolicyRuleCounter>. `show security policies
// hit-count` and the counter APIs cannot tell the duplicates apart (H04/H05),
// removing one duplicate leaves the shared counter alive so the survivor inherits
// the removed rule's accumulated hits (M05), and buildPolicyRuleCounterIndex is
// last-write-wins on the RuleID so the Go side silently collapses the duplicate
// rows the helper publishes (H07).
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientDuplicatePolicyNames) so an already-persisted or peer-synced config that
// an older binary accepted still BOOTS (#1960 no-brick). A leniently-loaded
// duplicate keeps the shared-counter observability bug, but the firewall still
// enforces first-match correctly; the warning is the operator's only signal.
//
// Duplicate names across DIFFERENT zone-pairs stay legal (each pair is its own
// namespace), as does a zone-pair name reused in the global rulebase. Iteration
// is in compiled (config) order so the first-reported duplicate is deterministic.
func validateDuplicatePolicyNamesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Zone-pair policies: a name must be unique within a (from-zone, to-zone)
	// context. Multiple ZonePairPolicies may carry the same from/to (a repeated
	// stanza, or a pair split across two security blocks); accumulate names per
	// pair across every matching entry so a cross-stanza / cross-block duplicate
	// is still caught.
	seenByPair := make(map[string]map[string]struct{})
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		key := zpp.FromZone + "\x00" + zpp.ToZone
		seen := seenByPair[key]
		if seen == nil {
			seen = make(map[string]struct{})
			seenByPair[key] = seen
		}
		for _, p := range zpp.Policies {
			if p == nil {
				continue
			}
			if _, dup := seen[p.Name]; dup {
				return fmt.Errorf(
					"security policies from-zone %q to-zone %q has duplicate policy name %q; policy names must be unique within a zone-pair context — the duplicate shares a name-keyed hit counter so `show security policies hit-count` cannot distinguish the two rules and deleting one transfers its accumulated hits to the survivor; rename one of the duplicate policies (#3473)",
					zpp.FromZone, zpp.ToZone, p.Name)
			}
			seen[p.Name] = struct{}{}
		}
	}
	// Global policies form a single ordered rulebase; names must be unique across
	// the whole list regardless of any optional from/to-zone match context
	// (#3148) — the context is an extra match predicate, not a separate
	// namespace.
	seenGlobal := make(map[string]struct{})
	for _, p := range cfg.Security.GlobalPolicies {
		if p == nil {
			continue
		}
		if _, dup := seenGlobal[p.Name]; dup {
			return fmt.Errorf(
				"security policies global has duplicate policy name %q; global policy names must be unique — the duplicate shares a name-keyed hit counter, collapsing hit-count observability for the two rules; rename one of the duplicate policies (#3473)",
				p.Name)
		}
		seenGlobal[p.Name] = struct{}{}
	}
	return nil
}

// policyActionName renders a PolicyAction as its Junos `then` token for
// operator-facing validator errors.
func policyActionName(a PolicyAction) string {
	switch a {
	case PolicyPermit:
		return "permit"
	case PolicyDeny:
		return "deny"
	case PolicyReject:
		return "reject"
	default:
		return fmt.Sprintf("action(%d)", int(a))
	}
}

// policyTerminalActionError formats the commit-time error for a policy that
// does not resolve to exactly one terminal action (#3043).
func policyTerminalActionError(scope, polName, detail string) error {
	if scope != "" {
		return fmt.Errorf("%s policy %q: %s", scope, polName, detail)
	}
	return fmt.Errorf("policy %q: %s", polName, detail)
}

// validatePolicyTerminalActionStrict hard-rejects a security policy that does
// not specify EXACTLY ONE terminal action (#3043).
//
// PolicyAction's zero value is PolicyPermit (types_security.go:
// `PolicyPermit PolicyAction = iota`), so before this gate a policy whose
// `then` stanza carried only modifiers (`then log session-init` /
// `then count`) — or a typo'd / dropped terminal action — compiled with
// Action == PolicyPermit and silently PERMITTED every packet matching its
// match conditions. A rule the operator wrote as an audit/drop placeholder
// thus became a zone-pair-wide permit: a silent fail-OPEN security hole.
// Symmetrically, a policy that named MORE than one terminal action (e.g. a
// group-merged `then permit` + `then deny`) resolved last-wins by child
// visitation order rather than failing the commit, so the enforced action
// depended on parse order.
//
// Junos requires every policy term to have exactly one terminal action; this
// validator restores that fail-CLOSED parity. It checks each per-zone-pair
// policy and each global policy: terminalActions (populated in config order by
// compilePolicy) must have length exactly 1.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientPolicyTerminalAction) so an already-persisted or peer-synced config
// that an older binary accepted still BOOTS (#1960 fail-closed-on-load
// doctrine). On that tolerant path the runtime is independently safe:
// compilePolicy defaults an actionless policy's Action to PolicyDeny (NOT
// permit), so a leniently-loaded actionless policy DENIES rather than fails
// open. Iteration order (cfg.Security.Policies, then GlobalPolicies) is
// deterministic, so the first-reported error is stable.
func validatePolicyTerminalActionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		// #3850: two IDENTICAL terminal-action blocks (e.g. a `load merge` that
		// duplicates the SAME `then { permit; }`, now both accumulated by the
		// #3842 policyThenChildren read) are NOT a conflict — Junos merges them
		// silently. Dedup by distinct action VALUE before the count so an
		// identical duplicate collapses to one (commit succeeds, Junos-faithful)
		// and only DIFFERENT terminal actions (e.g. permit + reject) trip the
		// conflict gate. Before this the #3043 gate over-rejected `permit,permit`
		// as "2 conflicting terminal actions (permit, permit)" — fail-closed but
		// imprecise.
		seen := make(map[PolicyAction]bool, len(pol.terminalActions))
		distinct := make([]PolicyAction, 0, len(pol.terminalActions))
		for _, a := range pol.terminalActions {
			if !seen[a] {
				seen[a] = true
				distinct = append(distinct, a)
			}
		}
		switch len(distinct) {
		case 1:
			return nil
		case 0:
			return policyTerminalActionError(scope, pol.Name,
				"no terminal action; every policy must specify exactly one of "+
					"`then permit`, `then deny`, or `then reject` (a log-only / "+
					"count-only or typo'd policy silently PERMITTED all matching "+
					"traffic; it now defaults to deny on load)")
		default:
			names := make([]string, 0, len(distinct))
			for _, a := range distinct {
				names = append(names, policyActionName(a))
			}
			return policyTerminalActionError(scope, pol.Name, fmt.Sprintf(
				"%d conflicting terminal actions (%s); a policy must specify "+
					"exactly one of permit/deny/reject (the enforced action would "+
					"otherwise depend on parse order)",
				len(distinct), strings.Join(names, ", ")))
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		for _, pol := range zpp.Policies {
			if err := check(scope, pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// validatePolicyLogActionStrict hard-rejects a security policy whose `then log`
// names neither `session-init` nor `session-close` (#3060).
//
// Junos requires `then log` to carry at least one of session-init /
// session-close — a bare `then log` is not valid syntax. xpf's schema accepts
// the bare form, and compilePolicy sets pol.Log = &PolicyLog{} for it while
// leaving both SessionInit and SessionClose false. The result is a config that
// REPORTS logging enabled over REST (pkg/api/security.go: `Log: rule.Log !=
// nil`) and gRPC/CLI, yet emits NO session records because both log flags are
// false. On a security appliance this is the worst kind of silent gap: audit
// looks active while producing nothing.
//
// Rejecting the bare form at commit (Junos parity) is the strongest, simplest
// contract: no bare-log config can exist post-commit, which moots the
// REST/gRPC/CLI display divergence entirely (every surface agrees because a
// reported `pol.Log != nil` always carries at least one real session flag).
// Both per-zone-pair policies and global policies are checked. Iteration order
// (cfg.Security.Policies, then GlobalPolicies) is deterministic, so the
// first-reported error is stable.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientPolicyLogAction) so an already-persisted or peer-synced config that an
// older binary accepted still BOOTS (#1960 fail-closed-on-load doctrine). A
// leniently-loaded bare-log policy is harmless: it simply logs nothing (the
// pre-existing behavior), and the warning is the operator's signal to fix it.
// Same doctrine as validatePolicyTerminalActionStrict.
func validatePolicyLogActionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil || pol.Log == nil {
			return nil
		}
		if pol.Log.SessionInit || pol.Log.SessionClose {
			return nil
		}
		detail := "`then log` requires `session-init` and/or `session-close` " +
			"(a bare `then log` reports logging enabled but emits NO session " +
			"records — Junos requires at least one of session-init/session-close)"
		if scope != "" {
			return fmt.Errorf("%s policy %q: %s", scope, pol.Name, detail)
		}
		return fmt.Errorf("policy %q: %s", pol.Name, detail)
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		// #9127: NAME THE ZONE PAIR. Policy names are unique per zone pair, not
		// globally, so an error carrying only the policy name does not identify
		// the stanza the operator has to go and edit -- two `allow-dns`
		// policies under different pairs are ordinary configuration.
		// validatePolicyLoggingStrict already supplied this scope; these four
		// are the consistency change, not a new convention.
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		for _, pol := range zpp.Policies {
			if err := check(scope, pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

func policyMatchAddressError(scope, polName, field, addr string) error {
	if scope != "" {
		return fmt.Errorf(
			"%s policy %q: %s %q is not a defined address-book entry, the `any` keyword, or a valid CIDR/IP address",
			scope, polName, field, addr)
	}
	return fmt.Errorf(
		"policy %q: %s %q is not a defined address-book entry, the `any` keyword, or a valid CIDR/IP address",
		polName, field, addr)
}

// validateAddressBookEntryNamesStrict (#3061, relaxed in #4340) enforces the
// two naming invariants the zone-local address-book fold
// (resolveZoneLocalAddressBooks) depends on, while otherwise PERMITTING the
// prefix-in-name convention every real vSRX config uses: an address object is
// almost universally named after its prefix — net_10.0.0.0/8,
// net4_sfmix_72.52.96.201/32, net_2001:559:8585:200::/64. The `/` in such a
// name is only a display identifier, never a structural token; the whole
// downstream resolution path (policyMatchNamedAddressRefs,
// resolveUserspaceAddressBookEntry, the wire snapshot) keys address objects by
// the FULL name string via direct map lookups, so a `/` in the name resolves
// correctly end to end.
//
// The fold mints synthetic global names of the form zone-local/<zone>/<name>.
// Only two invariants keep that namespace collision-proof and unambiguously
// reversible (ZoneLocalUnqualify) — and neither needs a blanket `/` ban:
//
//  1. No operator-typed address-book ENTRY name (global or zone-local
//     address / address-set) may begin with the reserved "zone-local/"
//     prefix. If it could, a global address literally named
//     zone-local/trust/web-server would collide with the synthetic name the
//     fold mints for a zone-local `web-server` in zone trust, and the fold's
//     no-clobber guard would silently drop the zone-local entry (wrong
//     address resolution, no commit error — the #3061 hazard). Reserving only
//     this PREFIX, not every `/`, lets `/` appear freely elsewhere in a name.
//
//  2. No security-zone NAME may contain `/`. The zone is the FIRST segment
//     after the reserved prefix, and ZoneLocalUnqualify splits zone from name
//     on the first `/`; a `/`-free zone keeps that split unambiguous even
//     when the address NAME that follows contains `/`
//     (zone-local/trust/net_10.0.0.0/8 unqualifies to zone=trust,
//     name=net_10.0.0.0/8 because strings.Cut stops at the first `/`). Zones
//     never carry a prefix-in-name convention, so this costs nothing real.
//
// IMPORTANT: only the NAME token is checked, never an address VALUE/prefix —
// `address web-server 10.0.0.0/24` has always been fine (the name is
// web-server; the 10.0.0.0/24 prefix is the value). After #4340
// `address net_10.0.0.0/8 10.0.0.0/8` is ALSO fine: the `/` in the NAME is
// permitted, matching the prefix-in-name convention.
//
// MUST run on the PRISTINE global book, i.e. BEFORE resolveZoneLocalAddressBooks
// injects the `/`-bearing synthetic names; the caller enforces that ordering.
func validateAddressBookEntryNamesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// checkEntryName reserves ONLY the synthetic zone-local/ prefix on an
	// operator-typed address-book entry name (#4340); any other `/` is allowed.
	checkEntryName := func(kind, name string) error {
		if strings.HasPrefix(name, zoneLocalNamePrefix) {
			return fmt.Errorf(
				"%s name %q must not begin with the reserved %q prefix; that "+
					"namespace is reserved for the internal zone-local "+
					"address book — rename the object", kind, name, zoneLocalNamePrefix)
		}
		return nil
	}
	// checkZoneName keeps the full `/` ban on a security-zone name: the zone is
	// the unambiguous first segment of the synthetic zone-local/<zone>/<name>
	// key, so it must stay `/`-free.
	checkZoneName := func(name string) error {
		if strings.Contains(name, "/") {
			return fmt.Errorf(
				"security-zone name %q must not contain '/'; '/' is reserved "+
					"for the internal zone-local address-book namespace — "+
					"rename the zone", name)
		}
		return nil
	}
	checkBook := func(kind string, ab *AddressBook) error {
		if ab == nil {
			return nil
		}
		names := make([]string, 0, len(ab.Addresses)+len(ab.AddressSets))
		for n := range ab.Addresses {
			names = append(names, n)
		}
		for n := range ab.AddressSets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if err := checkEntryName(kind, n); err != nil {
				return err
			}
		}
		return nil
	}

	if err := checkBook("address-book entry", cfg.Security.AddressBook); err != nil {
		return err
	}

	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for z := range cfg.Security.Zones {
		zoneNames = append(zoneNames, z)
	}
	sort.Strings(zoneNames)
	for _, z := range zoneNames {
		if err := checkZoneName(z); err != nil {
			return err
		}
		zone := cfg.Security.Zones[z]
		if zone == nil {
			continue
		}
		if err := checkBook(fmt.Sprintf("security-zone %q address-book entry", z), zone.AddressBook); err != nil {
			return err
		}
	}
	return nil
}
