// community_chain_16835.go — #16835 (R3-F12-02): the shared-token row
// of multi-member expanded community definitions.
//
// Junos evaluates each community member regex against each community on
// a route independently ("only one route community needs to match a
// given member"), so one community may satisfy two members — members
// [65000:.* .*:100] must match a route carrying only 65000:100. The
// #15779/#16788 public list cannot express that: every ordered
// permutation pattern consumes at least one whole token per factor
// (even a zero-width factor occurrence has nonempty consumed extent in
// a consuming match), so no finite set of whole-string patterns matches
// the shared row. The adjacent-literal row needs no new mechanism: the
// #16788 sequencer already shares the single separator between
// adjacent factors, and the tests pin it at the list layer.
//
// Live-probed FRR 10.7.1 facts this encoding rests on (netns bgpd,
// vtysh -f; harnesses in the package tests):
//   - `match community C1 C2` in one sequence is refused (% Unknown
//     command) and two `match community` lines REPLACE (only the last
//     survives, lib/routemap.c route_map_add_match), so members cannot
//     be AND-ed inside one sequence.
//   - A `deny` sequence may not carry `on-match next`/`on-match goto`
//     (the whole transaction is rejected); continuations are
//     permit-only. xpf's existing on-match goto uses
//     (policy_next_policy_11780) are all on permit sequences.
//   - `call NAME` loads even when NAME is undefined, and a called map
//     returning deny finishes the caller as deny, so a call cannot
//     gate a term selectively (a reject term would deny routes that
//     never matched the term either).
//
// The expressible encoding is therefore in-map, permit-only, and uses
// on-match goto. For a term whose ONLY match dimension is #16835
// chains (communityOrphanTerm16835) the renderer replaces the single
// `match community <public>` sequence with, per distinct chain
// alternative in authored order, alternating member/guard slots:
//
//	S:        permit, match <chain list of member 1>, goto S+20
//	S+10:     permit (match-all guard), goto NEXT
//	S+20:     permit, match <chain list of member 2>, goto S+40
//	S+30:     permit (guard), goto NEXT
//	...
//	B-20:     permit, match <chain list of member k>, goto B
//	B-10:     permit (guard), goto NEXT
//	B:        BODY — the original term sequence verbatim (own verb,
//	          sets, continuation), at bodySeq
//	NEXT=B+10: whatever followed the term anyway.
//
// Control flow: a route satisfying every member walks member slot ->
// next member slot -> ... -> BODY (each match gotos over its guard)
// and the term fires exactly once, sets exactly once. A route failing
// member i falls to the guard after it and gotos NEXT; the term never
// fires — fail-closed for reject, accept, and modify terms alike.
// Chains render only when EVERY distinct from-community alternative
// resolves to a chain; mixed terms and terms with sibling dimensions
// (route-filters, prefix-list, as-path, protocol) keep the historical
// render, because a goto cannot re-enter the Cartesian variant loop
// mid-term. Their public lists still under-match the shared row — the
// documented residual in docs/log/16835.md.
//
// Sequence accounting: one alternative with k distinct members
// occupies 2k slots, body +1: communityChainSlots16835 /
// communityExtraTermSeqWeight16835. pkg/config.RouteMapSequenceCount
// mirrors that weight for orphan terms so the strict ceiling gate and
// the renderer agree. Numbering gaps are legal FRR.
package frr

import (
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// communityChainNamespace marks every xpf-generated #16835 chain list.
const communityChainNamespace = "-xpf-com-"

// communityChainReserve16835 is the sequence step between consecutive
// route-map slots (the renderer numbers sequences in steps of 10).
// The chain slot arithmetic derives from it.
const communityChainReserve16835 = 10

// communityChainListName16835 derives the generated single-factor list
// name for one distinct member of a multi-member expanded definition:
// the FRR-normalized public name, the reserved marker, and a 64-bit
// digest of the RAW (public name, distinct member) pair. Bounded well
// under FRR's 128-byte identifier limit. The SAME value backs the
// definition and every chain reference.
func communityChainListName16835(name, member string) string {
	digest := communityListNameDigest(name, member)
	const maxLen = 96
	budget := maxLen - len(communityChainNamespace) - 16
	base := frrName(name)
	if len(base) > budget {
		base = base[:budget]
	}
	return base + communityChainNamespace + digest
}

// communityLiteralFactorPattern16835 renders one literal member as the
// single-factor expanded pattern of its chain list: the pipe-free
// whole-token spelling shared with the #16788 per-community anchoring
// (never the "(^| )" form FRR's vty pipe hook refuses).
func communityLiteralFactorPattern16835(member string) string {
	return "(^|[ ])" + sanitizeFRRValue(member) + "([ ]|$)"
}

// communityChainMembers16835 returns the distinct members of a
// definition in authored order when it is a multi-member expanded
// definition whose #16835 chain lists are rendered, else nil. It
// mirrors renderCommunityListDefinitions exactly: renderable
// (communityListRenderable), within the #15779 permutation bound
// (expandedCommunityConjunctionRenderable), at least two distinct
// members, expanded kind — so definition and reference cannot drift.
func communityChainMembers16835(po *config.PolicyOptionsConfig, name string) []string {
	if po == nil {
		return nil
	}
	cd := po.Communities[name]
	if cd == nil {
		return nil
	}
	members := dedupStrings(cd.Members)
	if len(members) < 2 || communityListKind(cd.Members) != "expanded" {
		return nil
	}
	if !communityListRenderable(cd.Members) || !expandedCommunityConjunctionRenderable(cd.Members) {
		return nil
	}
	return members
}

// communityChainWidth16835 reports the distinct-member count of the
// chain for name (0 when name is not a rendered chain definition).
func communityChainWidth16835(po *config.PolicyOptionsConfig, name string) int {
	return len(communityChainMembers16835(po, name))
}

// communityChainSlots16835 returns route-map slots one chain
// alternative occupies BEFORE the body slot: two per member (member
// slot + its guard). This is the slot invariant; the renderer
// allocates exactly this and pkg/config's orphan weight mirrors it.
func communityChainSlots16835(po *config.PolicyOptionsConfig, name string) int {
	return 2 * communityChainWidth16835(po, name)
}

// communityExtraTermSeqWeight16835 returns the sequence weight a term
// needs BEYOND the historical 1 the count allowed for its single
// community variant: sum of chain slots over distinct alternatives
// (the orphan body itself keeps the historical 1). Zero for
// non-orphan terms. Renderer and count share this definition.
func communityExtraTermSeqWeight16835(po *config.PolicyOptionsConfig, term *config.PolicyTerm) int {
	if term == nil || !communityOrphanTerm16835(po, term) {
		return 0
	}
	total := 0
	seen := make(map[string]bool, len(term.FromCommunity))
	for _, name := range term.FromCommunity {
		if seen[name] {
			continue
		}
		seen[name] = true
		total += communityChainSlots16835(po, name)
	}
	return total
}

// communityOrphanTerm16835 reports whether a term takes the chain
// render: at least one from-community alternative, EVERY distinct
// alternative resolves to a rendered chain, and no sibling match
// dimension (route-filters, prefix-list, as-path, protocol). LEXICAL
// only — never route data — so renderer, count, and tests agree.
func communityOrphanTerm16835(po *config.PolicyOptionsConfig, term *config.PolicyTerm) bool {
	if term == nil || len(term.FromCommunity) == 0 {
		return false
	}
	if len(term.RouteFilters) > 0 || len(term.PrefixList) > 0 || len(term.FromASPath) > 0 || len(term.FromProtocols) > 0 {
		return false
	}
	seen := make(map[string]bool, len(term.FromCommunity))
	for _, name := range term.FromCommunity {
		if seen[name] {
			continue
		}
		seen[name] = true
		if communityChainWidth16835(po, name) == 0 {
			return false
		}
	}
	return true
}

// communityMemberChainSequences16835 renders the pre-body chain slots
// for one alternative whose first member slot is at seq, interleaving
// a match-all guard after every member slot. Member slot i (0-based)
// gotos member slot i+1, the last gotos bodySeq; every guard gotos
// nextSeq (the slot after the body). See the file header for why one
// guard per member is required (a member failure falls to the very
// next slot, which must leave without testing further members).
func communityMemberChainSequences16835(b *strings.Builder, routeMapName, publicName string, members []string, seq, bodySeq, nextSeq int) {
	for i, member := range members {
		at := seq + i*2*communityChainReserve16835
		next := at + 2*communityChainReserve16835
		if i == len(members)-1 {
			next = bodySeq
		}
		b.WriteString("route-map " + frrName(routeMapName) + " permit " + strconv.Itoa(at) + "\n")
		b.WriteString(" match community " + communityChainListName16835(publicName, member) + "\n")
		b.WriteString(" on-match goto " + strconv.Itoa(next) + "\n")
		b.WriteString("exit\n")
		b.WriteString("route-map " + frrName(routeMapName) + " permit " + strconv.Itoa(at+communityChainReserve16835) + "\n")
		b.WriteString(" on-match goto " + strconv.Itoa(nextSeq) + "\n")
		b.WriteString("exit\n")
	}
}
