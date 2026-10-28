package policymatch

import (
	"iter"

	"github.com/psaab/xpf/pkg/config"
)

// ZonePairStreamMode selects which governing question ZonePairStream answers
// (#17075, R4-Q45-02). The three modes share ONE tier classification and ONE
// config-order walk; they differ only in the applicability predicate, which is
// the part that genuinely differs between enforcement and display:
//
//   - StreamTransit: the runtime transit tiers for a concrete (from,to) flow
//     — exact, single-wildcard merged in config order, both-any. Host-bound
//     stanzas never govern a transit flow and are excluded.
//   - StreamHost: the junos-host gate — exact <from> -> junos-host (only for a
//     known ingress), then any -> junos-host. Transit `to-zone any` and
//     both-any stanzas are deliberately NOT pulled onto the host path
//     (#12094 F1).
//   - StreamView: the filtered operator view — every stanza
//     ZonePairPolicyAppliesToFilterPair selects for the filter pair, in tier
//     order. An unfiltered view (both filter axes empty) is a single
//     config-order pass, matching the historical `passes == 1` rendering.
type ZonePairStreamMode int

const (
	StreamTransit ZonePairStreamMode = iota
	StreamHost
	StreamView
)

// StanzaRef is one zone-pair stanza in stream order (#17075). SetIdx is the
// stanza's index in the source slice (the policySetID of the runtime ID
// namespace); Tier is ZonePairPolicyFilterTier(stanza). Policy is the typed
// rule for config sources and nil for inventory sources; Rule is the
// inventory rule for pb sources and nil for config sources — exactly one is
// set, mirroring which adapter produced the ref. Quarantined reports the
// source's quarantine verdict for the stanza: for config sources, either
// endpoint in the apply-time scrub set (the zone_detail_summary.go #12896
// set); for inventory sources, the server-stamped per-rule verdict.
type StanzaRef struct {
	SetIdx      int
	SliceIdx    int
	From, To    string
	Tier        int
	Policy      *config.Policy
	Rule        InventoryRule
	Quarantined bool
}

// InventoryRule is the inventory (pb.PolicyRule) projection ZonePairStream
// needs, decoupled from the generated protobuf type so pkg/policymatch does
// not import pkg/grpcapi/xpfv1 (which would invert the existing layering:
// pkg/grpcapi imports pkg/policymatch, never the reverse). Callers adapt each
// *pb.PolicyRule once with a literal.
type InventoryRule struct {
	Name        string
	Quarantined bool
	// Rule is the caller's original rule value (e.g. *pb.PolicyRule), carried
	// opaque so a view renders exactly the row it received.
	Rule any
}

// ZonePairStanza is one stanza header plus its rules, the unit every adapter
// yields and every consumer walks. Rules are in authored order with nil rules
type ZonePairStanza struct {
	SetIdx      int
	From, To    string
	Tier        int
	Rules       []StanzaRef
	Quarantined bool
}

// ZonePairStream yields the zone-pair stanzas governing (from,to) in tier
// order — exact (tier 0), single-wildcard (tier 1, both wildcard shapes
// merged in config order), both-any (tier 2) — as classified by the single
// ZonePairPolicyFilterTier. It is the single source of truth for "which
// zone-pair stanzas govern (from,to), and in what tier order" (#17075,
// R4-Q45-02): Match (transit and host), the cross-tier shadow lint,
// ZoneDetailPolicySummary and every filtered policy view walk this stream
// instead of re-deriving tier membership in a hand-written pass loop.
//
// src yields stanza headers in config order (see ConfigZonePairStanzas and
// InventoryStanzas). The stream owns nil-stanza/nil-rule skipping and
// the tier passes; src owns only the per-source rule projection. from/to are
// the query zones for StreamTransit/StreamHost and the filter zones for
// StreamView (either may be "" in StreamView, meaning unfiltered on that
// axis; both empty yields one config-order pass with no tier reordering).
//
// Quarantine liveness: config sources stamp StanzaRef.Quarantined from the
// apply-time scrub set; the stream itself never drops a quarantined stanza —
// enforcement callers never see one (their from/to are live zones, so a
// quarantined stanza cannot be applicable), while view callers render the
func ZonePairStream(src iter.Seq[ZonePairStanza], from, to string, mode ZonePairStreamMode) iter.Seq[StanzaRef] {
	applies := zonePairStreamPredicate(from, to, mode)
	singlePass := mode == StreamView && from == "" && to == ""
	return zonePairStreamOrdered(src, applies, singlePass)
}

func zonePairStreamOrdered(src iter.Seq[ZonePairStanza], applies func(from, to string) bool, singlePass bool) iter.Seq[StanzaRef] {
	return func(yield func(StanzaRef) bool) {
		if src == nil {
			return
		}
		// Materialize the stanza headers once: the tier passes re-walk them
		// (up to 3x), and a Seq cannot be replayed. Stanzas are few (one per
		// authored zone-pair) and StanzaRef is a small value, so this is one
		// bounded slice, not a copy of the rule bodies.
		var stanzas []ZonePairStanza
		for st := range src {
			stanzas = append(stanzas, st)
		}
		maxTier := 2
		if singlePass {
			maxTier = 0
		}
		for tier := 0; tier <= maxTier; tier++ {
			for _, st := range stanzas {
				if !applies(st.From, st.To) {
					continue
				}
				stanzaTier := ZonePairPolicyFilterTier(st.From, st.To)
				if !singlePass && stanzaTier != tier {
					continue
				}
				for _, ref := range st.Rules {
					ref.Tier = stanzaTier
					if !yield(ref) {
						return
					}
				}
			}
		}
	}
}

// ZonePairStanzasOrdered is the stanza-granular form of the stream for
// grouped renderers (CLI/gRPC detail views print a per-stanza header plus a
// trailing blank line, including for a stanza whose rules were all nil and
// skipped). It yields each applicable stanza once, in the same tier order,
// with Tier stamped on the stanza and on every ref. An empty stanza (no
// surviving rules) is yielded with zero rules so the grouped header/blank
// behavior is preserved byte-for-byte.
func ZonePairStanzasOrdered(src iter.Seq[ZonePairStanza], filter ZonePairPolicyFilter) iter.Seq[ZonePairStanza] {
	singlePass := filter.filterFrom == "" && filter.filterTo == ""
	return zonePairStanzasOrderedBy(src, func(from, to string) bool {
		return ZonePairPolicyAppliesToFilterPair(filter, from, to)
	}, singlePass)
}

func zonePairStanzasOrderedBy(src iter.Seq[ZonePairStanza], applies func(from, to string) bool, singlePass bool) iter.Seq[ZonePairStanza] {
	return func(yield func(ZonePairStanza) bool) {
		if src == nil {
			return
		}
		var stanzas []ZonePairStanza
		for st := range src {
			stanzas = append(stanzas, st)
		}
		maxTier := 2
		if singlePass {
			maxTier = 0
		}
		for tier := 0; tier <= maxTier; tier++ {
			for _, st := range stanzas {
				if !applies(st.From, st.To) {
					continue
				}
				stanzaTier := ZonePairPolicyFilterTier(st.From, st.To)
				if !singlePass && stanzaTier != tier {
					continue
				}
				out := st
				out.Tier = stanzaTier
				out.Rules = append([]StanzaRef(nil), st.Rules...)
				for i := range out.Rules {
					out.Rules[i].Tier = stanzaTier
				}
				if !yield(out) {
					return
				}
			}
		}
	}
}

// zonePairStreamPredicate returns the applicability test for one mode. The
// transit and host predicates encode the runtime's zone-pair selection
// directly; the view predicate delegates to the shared display selector so
// its host-gate, literal-any and quarantine-filter semantics stay defined in
// exactly one place (ZonePairPolicyAppliesToFilterPair).
func zonePairStreamPredicate(from, to string, mode ZonePairStreamMode) func(stanzaFrom, stanzaTo string) bool {
	switch mode {
	case StreamHost:
		return func(stanzaFrom, stanzaTo string) bool {
			if stanzaTo != JunosHostZone {
				return false
			}
			// Exact ingress tier is tier 0 and the from-any tier is tier 1
			// under ZonePairPolicyFilterTier, so tier order alone sequences
			// them; applicability only excludes other shapes.
			return stanzaFrom == from || stanzaFrom == "any"
		}
	case StreamView:
		// The filter's zone inventory is the config behind a config source;
		// inventory sources pass a nil-config filter (their zones are all
		// treated unknown, which only narrows wildcard expansion — the
		// remote callers construct the filter from the GetZones inventory
		// instead, see ZonePairStreamForFilter).
		return func(stanzaFrom, stanzaTo string) bool {
			return ZonePairPolicyAppliesToFilterPair(ZonePairPolicyFilter{filterFrom: from, filterTo: to, literalAny: from == "any" || to == "any"}, stanzaFrom, stanzaTo)
		}
	default: // StreamTransit
		return func(stanzaFrom, stanzaTo string) bool {
			if stanzaTo == JunosHostZone {
				return false
			}
			return (stanzaFrom == from || stanzaFrom == "any") &&
				(stanzaTo == to || stanzaTo == "any")
		}
	}
}

// ZonePairStreamForFilter is ZonePairStream in StreamView mode with a
// prepared ZonePairPolicyFilter (zone inventory + quarantine projection
// resolved once by NewZonePairPolicyFilter). The 8 filtered policy views use
// it so the filter semantics they historically applied — host-gate exclusion,
// literal-any authored-stanza matching, unknown/quarantined filter narrowing
// — are preserved exactly, while tier order and nil-skipping move into the
// stream.
func ZonePairStreamForFilter(src iter.Seq[ZonePairStanza], filter ZonePairPolicyFilter) iter.Seq[StanzaRef] {
	return zonePairStreamOrdered(src, func(from, to string) bool {
		return ZonePairPolicyAppliesToFilterPair(filter, from, to)
	}, filter.filterFrom == "" && filter.filterTo == "")
}

// ZonePairZoneSummaryStream yields, in tier order, the zone-pair stanzas that
// affect ONE viewed zone (the ZoneDetailPolicySummary / remote showZones
// question): a stanza affects the zone when either side literally names it,
// or is the "any" wildcard and the viewed zone is installed (not quarantined
// — a wildcard governs every INSTALLED zone only, #12896). This is the
// zone-summary applicability predicate, distinct from the (from,to) filter
// predicate; tier classification and config-order-within-tier are the shared
// stream's. viewedQuarantined is the viewed zone's own quarantine verdict.
func ZonePairZoneSummaryStream(src iter.Seq[ZonePairStanza], zone string, viewedQuarantined bool) iter.Seq[StanzaRef] {
	return zonePairStreamOrdered(src, func(from, to string) bool {
		fromAffects := from == zone || (from == "any" && !viewedQuarantined)
		toAffects := to == zone || (to == "any" && !viewedQuarantined)
		return fromAffects || toAffects
	}, false)
}

// ConfigZonePairStanzas adapts cfg.Security.Policies to the stanza sequence
// ZonePairStream consumes: config order, nil stanzas skipped (no ZonePairStanza
// is yielded for a nil *config.ZonePairPolicies, so grouped renderers never
// print a phantom ""->"" header; SetIdx is stamped per surviving stanza from
// its source index, so the runtime policySetID namespace stays aligned),
// nil rules skipped, and each ref stamped with the stanza's apply-time
// quarantine verdict (either endpoint in the scrub set — the same set
// ZoneDetailPolicySummary marks rows with, #12896). A nil cfg yields nothing.
// Authored non-nil stanzas with zero rules are still yielded, so their
// grouped header is preserved.
func ConfigZonePairStanzas(cfg *config.Config) iter.Seq[ZonePairStanza] {
	return func(yield func(ZonePairStanza) bool) {
		if cfg == nil {
			return
		}
		scrubbed := config.QuarantinedZoneNames(config.ZoneQuarantineNamesForConfig(cfg))
		for setIdx, zpp := range cfg.Security.Policies {
			st := ZonePairStanza{SetIdx: setIdx}
			if zpp == nil {
				continue
			}
			st.From, st.To = zpp.FromZone, zpp.ToZone
			_, fromScrubbed := scrubbed[zpp.FromZone]
			_, toScrubbed := scrubbed[zpp.ToZone]
			st.Quarantined = fromScrubbed || toScrubbed
			for sliceIdx, pol := range zpp.Policies {
				if pol == nil {
					continue
				}
				st.Rules = append(st.Rules, StanzaRef{
					SetIdx: setIdx, SliceIdx: sliceIdx, From: zpp.FromZone, To: zpp.ToZone,
					Policy: pol, Quarantined: st.Quarantined,
				})
			}
			if !yield(st) {
				return
			}
		}
	}
}

// InventoryStanzas builds the stanza sequence for an inventory source from a
// slice of stanza headers in response order. Each element already carries its
// rules as StanzaRefs (Rule.Rule holding the caller's original rule value);
// SetIdx is stamped here as the element index. The global "*"/"*" group and
// the synthetic "-"/"-" default row are the caller's to exclude or capture
// around the stream, exactly as the remote views do today — the stream orders
// only real zone-pair stanzas.
func InventoryStanzas(stanzas []ZonePairStanza) iter.Seq[ZonePairStanza] {
	return func(yield func(ZonePairStanza) bool) {
		for i, st := range stanzas {
			st.SetIdx = i
			if !yield(st) {
				return
			}
		}
	}
}
