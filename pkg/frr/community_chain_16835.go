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
// on-match goto. For an orphan term (communityOrphanTerm16835), the
// renderer replaces the public community match with per-member chain
// slots. A mixed term with one distinct chain community uses the same
// gate before the ordinary sibling-dimension variants:
//
//	S:        permit, match <chain list of member 1>, goto S+20
//	S+10:     permit (match-all guard), goto NEXT
//	S+20:     permit, match <chain list of member 2>, goto S+40
//	S+30:     permit (guard), goto NEXT
//	...
//	B-20:     permit, match <chain list of member k>, goto B
//	B-10:     permit (guard), goto NEXT
//	B:        body sequence (or the first mixed sibling variant)
//	NEXT:     first sequence after the complete term body
//
// A route satisfying every member walks member slot -> next member
// slot -> ... -> BODY (each match gotos over its guard), where the
// original sibling match dimensions are still ANDed with the community
// chain. A route failing member i falls to its guard and skips the term;
// the shared-token chain never bypasses a sibling dimension.
//
// Orphan terms chain every distinct from-community alternative in
// authored order. Mixed terms are chain-lowered only when they have one
// distinct community alternative; multi-alternative mixed terms retain
// the historical Cartesian render. Their public lists still under-match
// the shared row, outside #17867's single-alternative scope.
//
// Sequence accounting: each chain alternative occupies 2k slots before
// its body: communityChainSlots16835 / communityExtraTermSeqWeight16835.
// pkg/config.RouteMapSequenceCount mirrors the reserve for orphan and
// supported mixed terms so the strict ceiling gate and renderer agree.
// Numbering gaps are legal FRR.
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
// allocates exactly this and pkg/config mirrors it for chain terms.
func communityChainSlots16835(po *config.PolicyOptionsConfig, name string) int {
	return 2 * communityChainWidth16835(po, name)
}

// communityExtraTermSeqWeight16835 returns the chain slots rendered before
// the body for an eligible community-only term or a single-chain mixed term.
// The body slots remain covered by the historical Cartesian count.
func communityExtraTermSeqWeight16835(po *config.PolicyOptionsConfig, term *config.PolicyTerm) int {
	if term == nil || (!communityOrphanTerm16835(po, term) && !communityMixedChainTerm16835(po, term)) {
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

// communityOrphanTerm16835 reports whether a term takes the original chain
// render: at least one from-community alternative, EVERY distinct alternative
// resolves to a rendered chain, and no sibling match dimension.
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

// communityMixedChainTerm16835 reports the mixed shape the shared-token
// chain can safely lower without changing the existing multi-alternative
// dispatch: exactly one distinct chain community plus sibling dimensions.
func communityMixedChainTerm16835(po *config.PolicyOptionsConfig, term *config.PolicyTerm) bool {
	if term == nil || len(term.FromCommunity) == 0 {
		return false
	}
	if len(term.RouteFilters)+len(term.PrefixList)+len(term.FromASPath)+len(term.FromProtocols) == 0 {
		return false
	}
	name := term.FromCommunity[0]
	for _, alternative := range term.FromCommunity[1:] {
		if alternative != name {
			return false
		}
	}
	return communityChainWidth16835(po, name) > 0
}

// communityMemberChainSequences16835 renders the pre-body chain slots
// for one alternative whose first member slot is at seq, interleaving
// a match-all guard after every member slot. Member slot i (0-based)
// gotos member slot i+1, the last gotos bodySeq; every guard gotos
// nextSeq after all mixed-term body variants. Member failure must leave
// the chain rather than fall into the next member.
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
