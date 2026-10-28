package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// route_map_chain.go — the single chain composer (#17026, R4-Q42-03).
//
// Before #17026 two copies of the same algorithm rendered an ordered
// Junos policy chain into one FRR route-map: the BGP composer
// (renderComposedRouteMapWithDefault, #5277) and the redistribute
// composer (renderRedistComposedMapVariant16864, #15156). The
// redistribute copy replaced the shared
// config.ComposedChainSequenceCount overflow predicate with a hand
// sum of config.RouteMapSequenceCount over its members. Keeping two
// implementations meant every chain-composition fix (termination,
// next-policy rewiring, tail shapes) had to be made twice, and the
// copies could disagree on what a chain renders.
//
// composeChainRouteMap is now the only implementation. Both callers
// are thin adapters that prepare their members (and, for
// redistribute, their per-source / per-variant filtered statements)
// and their tail, then delegate. The overflow belt consults
// config.ComposedChainSequenceCount over the very statements that
// will render — for redistribute that is the filtered statement map,
// so the count truncates and saturates exactly as the render loop
// does, and the belt can never disagree with the gate SSOT.

// namedPolicy is one ordered chain member: the authored policy name
// (used for the per-member inline prefix-list prefix) and the
// statement that will actually render for this use site. For BGP
// chains stmt is the authored statement; for redistribute chains it
// is the per-source, per-variant filtered statement.
type namedPolicy struct {
	name string
	stmt *config.PolicyStatement
}

// chainTail carries the caller-specific ending of a composed map.
type chainTail struct {
	// fallbackAction is the verb ("permit"/"deny") of the plain
	// fall-off sequence emitted when no member terminates the chain.
	fallbackAction string
	// carvedBGPOnly (#15157) replaces the plain permit fall-off with
	// the carved pair (permit `match source-protocol bgp`, then
	// deny). It only ever applies when fallbackAction == "permit".
	carvedBGPOnly bool
	// leadingTagDeny, when non-empty, is emitted once before every
	// member body (the #15158 cluster tag deny for static
	// redistribution). Definitions still precede it.
	leadingTagDeny string
	// overflowWarn, when set, replaces the default oversized-chain
	// warning so each adapter keeps its operator-facing message.
	overflowWarn func(name string, sequences uint64)
}

// composeChainRouteMap renders members in order into one route-map
// named name, using renderPO for term rendering and for the sequence
// count (redistribute passes its variant-restricted view; BGP passes
// po unchanged, so renderPO == po there).
//
// Semantics (shared by both adapters, formerly duplicated):
//   - Each member's terms evaluate in order. A term's terminating
//     accept/reject wins immediately; a non-terminating term applies
//     its sets and falls through; `then next policy` jumps around
//     the member's remaining terms and its default to the next
//     member's first sequence (or to the fall-off tail for the last
//     reachable member).
//   - An explicit member default (accept/reject) terminates ordinary
//     fall-through with a match-all permit/deny unless a
//     `next policy` term can bypass it.
//   - If no member terminates, the tail decides: the carved pair
//     when carvedBGPOnly applies, otherwise a plain fallbackAction
//     sequence at the fall-off sequence.
//
// Overflow belt: if the SSOT count over members (plus the carved
// reserve) exceeds config.MaxRouteMapSequences, the expansion is
// NOT rendered; a bounded explicit deny is returned under name
// instead (#6807: the attachment naming this map is emitted
// regardless, and FRR denies an unresolvable name, so an explicit
// deny is the deliberate fail-closed shape) and the map is noted
// quarantined.
func (m *Manager) composeChainRouteMap(renderPO *config.PolicyOptionsConfig, name string, members []namedPolicy, tail chainTail) string {
	// The SSOT predicate over the exact statements that will render.
	// For BGP, members carry the authored statements, so this is
	// byte-for-byte the former
	// ComposedChainSequenceCount(po, po.PolicyStatements, chain)
	// call. For redistribute, members carry the filtered statements,
	// so the same predicate truncates at the first filtered member
	// whose default terminates (and saturates) exactly as the loop
	// below does — the hand sum it replaces did neither reliably
	// once variant filtering changed member shapes.
	counts := make(map[string]*config.PolicyStatement, len(members))
	chain := make([]string, 0, len(members))
	for _, member := range members {
		if member.stmt == nil {
			continue
		}
		counts[member.name] = member.stmt
		chain = append(chain, member.name)
	}
	if n := beltTotal16869(config.ComposedChainSequenceCount(renderPO, counts, chain), config.CarvedComposedExtraSequencesForStatements16869(counts, chain, tail.carvedBGPOnly, tail.fallbackAction)); n > config.MaxRouteMapSequences {
		if tail.overflowWarn != nil {
			tail.overflowWarn(name, n)
		} else {
			slog.Warn("oversized composed policy-chain route-map: expansion would overflow FRR "+
				"sequence numbers and poison the reload; rendering an explicit DENY under this name "+
				"instead — routes carrying this chain are withdrawn until it is reduced",
				"route-map", name, "sequences", n, "max", config.MaxRouteMapSequences)
		}
		m.noteQuarantined(name)
		return renderQuarantineDenyRouteMap(name)
	}

	type policyPart struct {
		definitions string
		body        string
		nextPolicy  bool
		startSeq    int
		defaultSeq  int
		defaultVerb string
	}
	parts := make([]policyPart, 0, len(members))
	seq := 10
	terminated := false
	for _, member := range members {
		if member.stmt == nil {
			continue
		}
		definitions, body, next := m.renderPolicyTermSequencesWithDefinitions(renderPO, name, name+"-"+member.name, member.stmt, seq)
		part := policyPart{definitions: definitions, body: body, nextPolicy: policyHasNextPolicyTerm(member.stmt), startSeq: seq}
		seq = next
		switch member.stmt.DefaultAction {
		case "accept":
			part.defaultVerb = "permit"
			part.defaultSeq = seq
			seq += 10
			terminated = !part.nextPolicy
		case "reject":
			part.defaultVerb = "deny"
			part.defaultSeq = seq
			seq += 10
			terminated = !part.nextPolicy
		}
		parts = append(parts, part)
		if terminated {
			break
		}
	}

	var b strings.Builder
	for _, part := range parts {
		b.WriteString(part.definitions)
	}
	if tail.leadingTagDeny != "" {
		b.WriteString(tail.leadingTagDeny)
	}

	fallbackSeq := seq
	carved := tail.carvedBGPOnly && tail.fallbackAction == "permit" && !terminated
	for i, part := range parts {
		target := fallbackSeq
		if i+1 < len(parts) {
			target = parts[i+1].startSeq
		}
		if part.nextPolicy {
			part.body = renderNextPolicyTarget(part.body, target)
		}
		b.WriteString(part.body)
		if part.defaultVerb != "" {
			fmt.Fprintf(&b, "route-map %s %s %d\n", frrName(name), part.defaultVerb, part.defaultSeq)
			b.WriteString("exit\n")
		}
	}
	if !terminated {
		if carved {
			fmt.Fprintf(&b, "route-map %s permit %d\n", frrName(name), fallbackSeq)
			b.WriteString(" match source-protocol bgp\n")
			b.WriteString("exit\n")
			fmt.Fprintf(&b, "route-map %s deny %d\n", frrName(name), fallbackSeq+10)
			b.WriteString("exit\n")
		} else {
			fmt.Fprintf(&b, "route-map %s %s %d\n", frrName(name), tail.fallbackAction, fallbackSeq)
			b.WriteString("exit\n")
		}
	}
	return b.String()
}
