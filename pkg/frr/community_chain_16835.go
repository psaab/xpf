// community_chain_16835.go — #16835 (R3-F12-02): the shared-token row
// of multi-member expanded community definitions.
//
// #16788/#15779 render a multi-member expanded definition as ONE
// expanded community-list of ordered permutation patterns, and each
// such pattern consumes at least one whole token per factor (even a
// zero-width factor occurrence has nonempty consumed extent in a
// consuming match — standards trivia in docs/log/16835.md), so one
// community that satisfies two regex members can never satisfy the
// conjunction at the list layer: members [65000:.* .*:100] miss a
// route carrying only 65000:100. The same failure mode in reverse is
// over-matching: two factors must also be allowed to consume the SAME
// token when a later factor matches inside or next to an earlier one,
// and factors must stay confined to one token each.
//
// The #16835 evaluation therefore chains the per-member single-factor
// lists sequentially: a term whose only community dimension is such a
// definition renders as a generated continuation route-map of
// sequences seq, seq+10, ... numbered as a continuation of the term's
// own first sequence (following term sequences shift accordingly, by
// the reserved widths in communityChainReserve16835 /
// communityExtraTermSeqWeight16835). Render keeps the historical term
// sequence slots as pure `on-match next` trampolines; the generated
// chain route-map carries the per-member `match community` sequences
// with `on-match next`, and its last sequence carries the term's own
// set/action body — so the term's set clauses (including `set
// community` / `set comm-list ... delete`) run exactly once, and on a
// sibling community/route-filter/as-path/protocol mismatch the term's
// chain is never entered. On-match next is used instead of
// `on-match goto` because FRR's route_map_onmatch_apply compares an
// explicit goto target against the already-advanced next sequence
// (route_map_apply_match pre-advances *next when it is caller-visible),
// under which a fixed goto can skip sequences; on-match next is
// how consecutive (adjacent) community factors share evaluation.
// Alternatives rejected: multiple `match community` lines per sequence
// (FRR replaces a same-type rule, lib/routemap.c route_map_add_match),
// widening the permutation bound (finite bounds cannot express the
// shared row, and a bigger finite bound still misses), and per-token
// regex rewrites. FAIL-OPEN caveat (preserved verbatim so a reader can
// find the pre-existing hazard): a token match consumes a whole token
// even when it fails, discarding the remaining candidate tokens in
// FRR's walk — so the historical list-order question is preserved, and
// a route whose only 65000-prefixed community is its last token is
// still matched by the 65000:.* member via that first positional hit
// while a 1:100 member later in chain order is not re-tried against
// the same token; this under-match is the Junos-correct fail-closed
// direction (a reject term over-matches nothing), and the same
// positional consumption exists in the #15779 sequence patterns.
//
// Collision and render interplay: every chain list is emitted by
// renderCommunityListDefinitions for every multi-member expanded
// definition, referenced or not, keyed by (public name, distinct
// member); communityListCollision refuses the apply when one would
// fuse with an operator list, a delete backing, or another chain list.
// Chain evaluation is only correct while the chain lists are emitted
// exactly for rendered definitions — the shared predicates
// (communityListRenderable + expandedCommunityConjunctionRenderable +
// dedup) may not drift from that emission, and communityChainWidth16835
// must return no width for a definition whose chain lists are absent.
package frr

import (
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// communityChainNamespace marks every xpf-generated #16835 chain list.
const communityChainNamespace = "-xpf-com-"

// communityChainReserve16835 is the number of sequences one in-band
// community dimension occupies at the end of a term's route-map slots:
// the member chain is embedded after the term's other dimensions
// advance, so consecutive member factors share one following sequence
// instead of consuming the term's own slot. The default reserve remains
// 10 so a single community still costs one following sequence — the
// pre-#16835 render is unchanged for every other shape.
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
// definition whose #16835 chain lists are rendered, else nil. It is
// the single predicate behind the chain evaluation, the route-map
// sequence count, and the orphan rule; it must agree with
// renderCommunityListDefinitions, which emits the chain lists exactly
// for rendered definitions (renderable, within the permutation bound).
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

// communityChainWidth16835 reports how many route-map sequences of one
// from-community alternative are chain sequences when name resolves
// to a #16835 chain (the member count), else 0. Callers gate chain
// evaluation on a positive width, so 0 always takes the historical
// single-sequence path.
func communityChainWidth16835(po *config.PolicyOptionsConfig, name string) int {
	return len(communityChainMembers16835(po, name))
}

// communityExtraTermSeqWeight16835 reserves, per from-community
// alternative, the continuation sequences the member chain embeds
// after the term's other dimensions advance: max(0, (distinct
// members)-1) when this is a #16835 chain reference, else 0. The
// renderer and the composed-map count must share it so the reserved
// following sequences exist (a `route-map` permits numbering gaps
// freely) AND the NEXT term sequence exists; under-count is a hang
// (a goto/next reaching past the map), over-count is unreachable
// slots. Validation weight handed to pkg/config mirrors this
// invariant: see docs/log/16835.md.
func communityExtraTermSeqWeight16835(po *config.PolicyOptionsConfig, name string) int {
	if w := communityChainWidth16835(po, name); w > 1 {
		return w - 1
	}
	return 0
}

// communityTermSeqCount16835 returns the sequence the NEXT term starts
// at after a term whose community alternatives carry #16835 chains:
// each alternative's chain embeds consecutively after its base
// sequence, so following allocations must begin past the widest
// reserved prefix (max(1, alternatives) * (1 + widest reserved extra))
// or a later term's first sequence would collide with a chain slot.
// Callers pass the term's distinct community names.
func communityTermSeqCount16835(po *config.PolicyOptionsConfig, distinctNames []string, startSeq int) int {
	widest := 0
	for _, name := range distinctNames {
		if extra := communityExtraTermSeqWeight16835(po, name); extra > widest {
			widest = extra
		}
	}
	next := startSeq + communityChainReserve16835*(1+widest)
	if widest == 0 && len(distinctNames) == 0 {
		return startSeq + communityChainReserve16835
	}
	return next
}

// communityOrphanTerm16835 reports whether a term is the exact shape
// the #16835 chain evaluation serves: at least one from-community
// alternative resolves to a multi-member expanded chain, and the term
// carries no non-community match dimension (route-filters, prefix-list,
// as-path, protocol). Orphan is LEXICAL: it only inspects the term's
// authored match shape, never route data, so parent and count agree
// without evaluating.
func communityOrphanTerm16835(po *config.PolicyOptionsConfig, term *config.PolicyTerm) bool {
	if term == nil || len(term.FromCommunity) == 0 {
		return false
	}
	if len(term.RouteFilters) > 0 || len(term.PrefixList) > 0 || len(term.FromASPath) > 0 || len(term.FromProtocols) > 0 {
		return false
	}
	for _, name := range term.FromCommunity {
		if communityChainWidth16835(po, name) > 0 {
			return true
		}
	}
	return false
}

// communityMemberChainSequences16835 renders the permit chain for one
// from-community alternative: one `match community <chain list>`
// sequence per distinct member in authored order, `on-match next`
// between members, honouring the term's continuation on the last
// sequence (validNextPolicy emits the goto marker, nonTerminating
// emits on-match next). Every sequence is a permit: a member mismatch
// NOMATCH-aborts to the map's next term — a controlled REJECT needs a
// match-all deny sequence after every member chain to terminate the
// route (the accept/skip direction is fail-closed).
func communityMemberChainSequences16835(b *strings.Builder, routeMapName string, members []string, publicName string, seq int, validNextPolicy, nonTerminating bool) {
	for i, member := range members {
		b.WriteString("route-map " + frrName(routeMapName) + " permit " + itoa16835(seq) + "\n")
		b.WriteString(" match community " + communityChainListName16835(publicName, member) + "\n")
		last := i == len(members)-1
		switch {
		case validNextPolicy && last:
			b.WriteString(" " + nextPolicySequenceMarker + "\n")
		case nonTerminating || !last:
			b.WriteString(" on-match next\n")
		}
		b.WriteString("exit\n")
		seq += communityChainReserve16835
	}
}

// itoa16835 renders a route-map sequence number without strconv so
// this file stays dependency-light; sequences are non-negative.
func itoa16835(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [8]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
