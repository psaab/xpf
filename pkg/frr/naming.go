package frr

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// FRR identifier naming for xpf-GENERATED objects (#5872).
//
// When a route-map sequence carries BOTH a same-family route-filter
// "match ip|ipv6 address prefix-list" line AND a `from prefix-list` match, the
// two same-type rules would COLLIDE inside FRR (route_map_add_match REPLACES a
// same-type rule, keeping the last), silently dropping the route-filter
// constraint (#5730). The renderer therefore materializes the from-prefix-list
// as an ACCESS-LIST — a distinct FRR rule type — so FRR ANDs the two
// constraints. That access-list needs a name, and the pre-#5872 renderer built
// it as `fromPrefixList + "_rf"`: a bare concatenation of an
// operator-controlled identifier with no namespace, no byte-length bound, and
// no collision registry. Three failure modes followed:
//
//   1. Length overflow — a long-but-valid Junos prefix-list name plus "_rf"
//      can exceed FRR's access-list identifier limit (128 bytes across FRR
//      versions), so the generated line is rejected on reload and the whole
//      managed section fails to load.
//   2. Truncation-collision — two DISTINCT long prefix-list names that share a
//      >=125-byte prefix produce "<name>_rf" values that FRR truncates to the
//      SAME stored identifier, merging two unrelated access-list definitions.
//      The route-filter of one term is then applied to the other — a silent,
//      security-relevant widening/narrowing of a routing policy.
//   3. Namespace confusion — a generated name and a raw operator name live in
//      one flat FRR access-list namespace with nothing distinguishing them.
//
// routeFilterACLName replaces the concatenation with a bounded, namespaced,
// deterministically-hashed name, and routeFilterACLNameCollision fails the
// apply CLOSED if two distinct logical identities would still map to one name
// or an operator name intrudes on the reserved namespace.

const (
	// frrACLNameMaxLen bounds a GENERATED FRR access-list identifier. FRR's
	// config parser caps an access-list name at 128 bytes across the versions
	// xpf targets; 96 leaves generous margin (and headroom for any stricter
	// downstream tooling) while still admitting a human-readable slice of the
	// source name.
	frrACLNameMaxLen = 96

	// routeFilterACLNamespace is the reserved prefix every xpf-generated
	// route-filter access-list name carries. It gives generated names a
	// distinct namespace so a generated name can never be confused with — or
	// silently collide with — a raw operator-supplied prefix-list name. Operator
	// prefix-list names that intrude on this namespace are rejected at commit by
	// routeFilterACLNameCollision, exactly as config.ReservedRedistSuffix is
	// reserved for protocol-specific redistribute route-maps.
	routeFilterACLNamespace = "xpf-rf-"

	// routeFilterACLHashHexLen is the length (in hex chars) of the deterministic
	// suffix. 16 hex chars = 8 bytes = 64 bits of SHA-256, so two distinct
	// logical identities collide only on a 64-bit hash collision — astronomically
	// unlikely, and routeFilterACLNameCollision still catches it and fails closed.
	routeFilterACLHashHexLen = 16
	// frrInlinePrefixListMaxLen bounds generated inline route-filter prefix-list
	// names well below FRR's 128-byte identifier limit.
	frrInlinePrefixListMaxLen = 96

	// inlinePrefixListNamespace is the reserved suffix attached to every
	// xpf-generated route-filter prefix-list. Operator prefix-lists using it
	// are rejected by routeFilterACLNameCollision.
	inlinePrefixListNamespace  = "-xpf-inline-"
	inlinePrefixListHashHexLen = 16
)

// prefixListFamilies returns the FRR address-family keyword(s) a prefix-list
// renders under: "ip" if it holds any IPv4 entry, "ipv6" if it holds any IPv6
// entry — BOTH (in that fixed, deterministic order) for a mixed v4+v6 list. A
// nil / empty list defaults to ["ip"] (the undefined/empty list then NOMATCHes
// every route, fail-closed).
//
// This is the per-family generalization of the pre-#2607 single-family selector
// and is the SINGLE source of the family decision, shared by the renderer
// (fromPrefixListRefs) and the collision precheck (routeFilterACLNameCollision)
// so the two never disagree. Binding BOTH families for a mixed referenced
// `from prefix-list` is the #2607 fix: the old collapse to one family
// ("ipv6 if any v6 entry") emitted only one `match ip|ipv6 address` line, so the
// other family's routes silently failed the term. A single-family (or empty)
// list still yields exactly one keyword, so its render is byte-identical to the
// pre-#2607 behavior.
func prefixListFamilies(pl *config.PrefixList) []string {
	// #7526: WHICH families a list holds is decided by config.PrefixListFamilies,
	// the single source the admission bound also reads. This function keeps only
	// the mapping to FRR's "ip"/"ipv6" match keywords, which are FRR spellings.
	//
	// The two used to derive it separately, and they disagreed: the renderer
	// emitted one match line per family while the bound counted one per NAME, so
	// a policy referencing mixed v4+v6 lists rendered up to twice the sequences
	// admission had approved. Sharing the predicate makes the counts equal by
	// construction rather than by two implementations agreeing.
	hasV4, hasV6 := config.PrefixListFamilies(pl)
	var fams []string
	if hasV4 {
		fams = append(fams, "ip")
	}
	if hasV6 {
		fams = append(fams, "ipv6")
	}
	// #7526: the nil / empty-list fallback to IPv4 lives in
	// config.PrefixListFamilies, not here. It used to be duplicated, and the
	// duplicate made the config-side normalization DEAD — a mutation removing
	// it changed no behaviour, because this fallback silently covered for it.
	// Two places deciding the same thing is exactly what this issue is about.
	return fams
}

// sanitizeFRRIdent maps an arbitrary (possibly operator-, peer-sync- or
// rollback-supplied) string to a safe, ASCII FRR-identifier FRAGMENT: every
// rune outside [A-Za-z0-9_] becomes '_'. It is deliberately lossy — the
// deterministic hash suffix, not this fragment, guarantees uniqueness, so the
// fragment only needs to be a readable, injection-safe, single-token hint. The
// output is pure ASCII (one byte per surviving/replaced rune boundary), so a
// later byte-length truncation can never split a multi-byte rune.
func sanitizeFRRIdent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// inlinePrefixListName derives a bounded FRR prefix-list name from the
// structured rendering identity. The readable portion preserves the historical
// `<policy>-<term>[_v4|_v6]` prefix; the reserved marker and digest keep
// operator lists and distinct contexts disjoint even when their readable
// prefixes truncate or their legacy concatenations alias.
func inlinePrefixListName(routeMapName, plPrefix, termName, familySuffix string) string {
	identity := make([]byte, 0, len(routeMapName)+len(plPrefix)+len(termName)+len(familySuffix)+4*8)
	identity = appendInlinePrefixListHashPart(identity, routeMapName)
	identity = appendInlinePrefixListHashPart(identity, plPrefix)
	identity = appendInlinePrefixListHashPart(identity, termName)
	identity = appendInlinePrefixListHashPart(identity, familySuffix)
	sum := sha256.Sum256(identity)
	var hashHex [inlinePrefixListHashHexLen]byte
	hex.Encode(hashHex[:], sum[:inlinePrefixListHashHexLen/2])

	readableBudget := frrInlinePrefixListMaxLen - len(inlinePrefixListNamespace) - inlinePrefixListHashHexLen
	readableCapacity := len(plPrefix) + 1 + len(termName) + len(familySuffix)
	if readableCapacity > readableBudget {
		readableCapacity = readableBudget
	}
	var name strings.Builder
	name.Grow(readableCapacity + len(inlinePrefixListNamespace) + inlinePrefixListHashHexLen)
	appendFRRInlineIdent(&name, plPrefix, readableBudget)
	if name.Len() < readableBudget {
		name.WriteByte('-')
		appendFRRInlineIdent(&name, termName, readableBudget)
	}
	if name.Len() < readableBudget {
		appendFRRInlineIdent(&name, familySuffix, readableBudget)
	}
	name.WriteString(inlinePrefixListNamespace)
	name.Write(hashHex[:])
	return name.String()
}

func appendInlinePrefixListHashPart(dst []byte, value string) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}

func appendFRRInlineIdent(name *strings.Builder, value string, maxLen int) {
	for _, r := range value {
		if name.Len() == maxLen {
			return
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			name.WriteRune(r)
		default:
			name.WriteByte('_')
		}
	}
}

// routeFilterACLName derives the FRR access-list name for the from-prefix-list
// materialized as an access-list (#5730 same-family coexistence). The name is:
//
//   - namespaced with routeFilterACLNamespace so it lives in a distinct space
//     from raw operator names;
//   - suffixed with a deterministic SHA-256 hash of (matchKW, FULL prefixList)
//     so two different logical identities never map to one name AND the output
//     is STABLE across daemon restarts (no map-iteration order, no randomness) —
//     hashing the FULL name (not the truncated readable slice) is what defeats
//     the truncation-collision of two long same-prefix names;
//   - bounded to frrACLNameMaxLen bytes, well under FRR's 128-byte limit.
//
// The renderer uses the SAME return value for both the access-list DEFINITION
// and the route-map REFERENCE, so the two always agree by construction.
func routeFilterACLName(prefixList, matchKW string) string {
	sum := sha256.Sum256([]byte(matchKW + "\x00" + prefixList))
	hashHex := hex.EncodeToString(sum[:])[:routeFilterACLHashHexLen]

	// Fixed overhead: namespace + readable + "-" + hash. Give the readable slice
	// whatever budget remains under the cap.
	fixed := len(routeFilterACLNamespace) + 1 + routeFilterACLHashHexLen
	readableBudget := frrACLNameMaxLen - fixed
	if readableBudget < 0 {
		readableBudget = 0
	}
	readable := sanitizeFRRIdent(prefixList)
	if len(readable) > readableBudget {
		readable = readable[:readableBudget]
	}
	return routeFilterACLNamespace + readable + "-" + hashHex
}

// routeFilterACLNameCollision fails the apply CLOSED when generated route-
// filter access-list or inline prefix-list names are not provably unambiguous:
//
//   - an operator prefix-list name intrudes on either reserved namespace;
//   - two distinct from-prefix-list identities map to one generated access-list
//     name in the same address family; or
//   - two distinct inline route-filter identities map to one generated
//     prefix-list name in the same address family.
//
// FRR merges same-named objects, so any case could silently widen or narrow a
// routing policy. Refuse to render — FRR keeps its last-good config — mirroring
// redistProtocolMapCollision / bgpComposedChainCollision. The order is
// deterministic so the first offending pair is reported stably.
func routeFilterACLNameCollision(po *config.PolicyOptionsConfig) error {
	if po == nil {
		return nil
	}
	names := make([]string, 0, len(po.PrefixLists))
	for name := range po.PrefixLists {
		names = append(names, name)
	}
	sort.Strings(names)

	// Reserved-namespace intrusion first: a deterministic, name-only check.
	for _, name := range names {
		if strings.HasPrefix(name, routeFilterACLNamespace) {
			return fmt.Errorf(
				"prefix-list %q uses the reserved %q namespace xpf reserves for "+
					"generated route-filter access-list names (#5872); FRR merges "+
					"same-named access-lists, so an operator name in this namespace "+
					"could shadow a generated one and silently alter a routing policy "+
					"— rename the prefix-list off the reserved prefix",
				name, routeFilterACLNamespace)
		}
	}

	// Final-name collision within each address family. A mixed v4+v6 referenced
	// prefix-list can materialize an access-list in BOTH families (#2607), so
	// check EVERY family the list renders under — not just one collapsed family
	// — else two lists colliding on the off-checked family's ACL name would slip
	// past and silently merge in FRR.
	seen := map[string]string{} // "<family>\x00<finalName>" -> prefix-list name
	for _, name := range names {
		for _, matchKW := range prefixListFamilies(po.PrefixLists[name]) {
			final := routeFilterACLName(name, matchKW)
			key := matchKW + "\x00" + final
			if prev, ok := seen[key]; ok && prev != name {
				return fmt.Errorf(
					"prefix-lists %q and %q map to the same generated route-filter "+
						"access-list name %q in the %s family (#5872 hash collision); "+
						"FRR would merge them and silently alter a routing policy — "+
						"refusing to render",
					prev, name, final, matchKW)
			}
			seen[key] = name
		}
	}
	return inlinePrefixListNameCollision(po)
}

type inlinePrefixListIdentity struct {
	routeMapName string
	plPrefix     string
	termName     string
	familySuffix string
	family       string
}

func inlinePrefixListIdentitiesForPolicy(routeMapName, plPrefix string, ps *config.PolicyStatement) []inlinePrefixListIdentity {
	if ps == nil {
		return nil
	}
	var identities []inlinePrefixListIdentity
	for _, term := range ps.Terms {
		if term == nil || len(term.RouteFilters) == 0 {
			continue
		}
		v4, v6 := partitionRouteFiltersByFamily(term.RouteFilters)
		if len(v4) > 0 && len(v6) > 0 {
			identities = append(identities,
				inlinePrefixListIdentity{routeMapName, plPrefix, term.Name, "_v4", "ip"},
				inlinePrefixListIdentity{routeMapName, plPrefix, term.Name, "_v6", "ipv6"})
			continue
		}
		family := "ip"
		for _, rf := range term.RouteFilters {
			if _, _, err := net.ParseCIDR(rf.Prefix); err == nil {
				if strings.Contains(rf.Prefix, ":") {
					family = "ipv6"
				}
				break
			}
		}
		identities = append(identities, inlinePrefixListIdentity{routeMapName, plPrefix, term.Name, "", family})
	}
	return identities
}

func policyHasInlineRouteFilters(ps *config.PolicyStatement) bool {
	if ps == nil {
		return false
	}
	for _, term := range ps.Terms {
		if term != nil && len(term.RouteFilters) > 0 {
			return true
		}
	}
	return false
}

func inlinePrefixListNameCollision(po *config.PolicyOptionsConfig) error {
	names := make([]string, 0, len(po.PrefixLists))
	for name := range po.PrefixLists {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		final := frrName(name)
		if strings.Contains(final, inlinePrefixListNamespace) {
			return fmt.Errorf(
				"prefix-list %q uses the reserved %q namespace xpf reserves for "+
					"generated inline route-filter prefix-lists; FRR merges same-named "+
					"prefix-lists, so an operator name in this namespace could shadow "+
					"a generated one and silently alter a routing policy — rename the "+
					"prefix-list without the reserved marker",
				name, inlinePrefixListNamespace)
		}
	}

	// Mirror the policy-options route-map contexts emitted by the base renderer:
	// standalone policy maps and per-source-protocol redistribute maps. The
	// structured route-map identity is included in the digest for composed and
	// narrowed aliases as well, so their readable prefixes cannot alias these.
	var policyNames []string
	for name, ps := range po.PolicyStatements {
		if policyHasInlineRouteFilters(ps) {
			policyNames = append(policyNames, name)
		}
	}
	if len(policyNames) == 0 {
		return nil
	}
	sort.Strings(policyNames)
	var identities []inlinePrefixListIdentity
	add := func(routeMapName, plPrefix string, ps *config.PolicyStatement) {
		identities = append(identities, inlinePrefixListIdentitiesForPolicy(routeMapName, plPrefix, ps)...)
	}
	for _, policyName := range policyNames {
		ps := po.PolicyStatements[policyName]
		if config.RouteMapSequenceCount(po, ps) <= config.MaxRouteMapSequences {
			add(policyName, policyName, ps)
		}
		for _, proto := range redistProtocols(ps) {
			routeMapName := redistProtocolRouteMapName(policyName, proto)
			filtered := redistPolicyForProtocol(ps, proto)
			if config.RouteMapSequenceCount(po, filtered) <= config.MaxRouteMapSequences {
				add(routeMapName, routeMapName, filtered)
			}
		}
	}

	sort.Slice(identities, func(i, j int) bool {
		a, b := identities[i], identities[j]
		if a.routeMapName != b.routeMapName {
			return a.routeMapName < b.routeMapName
		}
		if a.plPrefix != b.plPrefix {
			return a.plPrefix < b.plPrefix
		}
		if a.termName != b.termName {
			return a.termName < b.termName
		}
		if a.familySuffix != b.familySuffix {
			return a.familySuffix < b.familySuffix
		}
		return a.family < b.family
	})
	seen := make(map[string]inlinePrefixListIdentity, len(identities))
	for _, identity := range identities {
		final := inlinePrefixListName(identity.routeMapName, identity.plPrefix, identity.termName, identity.familySuffix)
		key := identity.family + "\x00" + final
		if previous, ok := seen[key]; ok && previous != identity {
			return fmt.Errorf(
				"inline route-filter identities %+v and %+v map to the same generated "+
					"prefix-list name %q in the %s family (#12068 hash collision); "+
					"FRR would merge them and silently alter a routing policy — refusing to render",
				previous, identity, final, identity.family)
		}
		seen[key] = identity
	}
	return nil
}
