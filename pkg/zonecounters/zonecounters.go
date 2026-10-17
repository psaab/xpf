// Package zonecounters carries the single canonical operator-facing wording for
// a security zone whose per-zone traffic counters are unavailable.
//
// IT IS A DEPENDENCY-FREE LEAF ON PURPOSE (#6895). Three surfaces print this
// state — the local CLI (pkg/cli), the gRPC text renderer (pkg/grpcapi) and the
// remote cli binary (cmd/cli) — and the natural home would be pkg/dataplane,
// beside the ErrCounterNotPopulated sentinel these sentences describe. But the
// #1451 retirement-boundary canary deliberately keeps cmd/cli free of root
// pkg/dataplane: the remote cli speaks gRPC and must not link the dataplane.
// Adding an allowlist entry to share two strings would weaken an intentional
// architectural boundary for a presentation concern, so the wording lives in a
// leaf all three may import and the boundary stays as designed.
package zonecounters

// The wording below is the rendering of dataplane.ErrCounterNotPopulated for a
// security zone.
//
// SINGLE-SOURCED ON PURPOSE (#6895). Three surfaces report this same state --
// the local CLI (pkg/cli), the gRPC text renderer (pkg/grpcapi) and the remote
// cli binary (cmd/cli) -- and before #6895 the generic sentence was duplicated
// verbatim in two of them with no test binding the agreement. They describe ONE
// dataplane condition, so a divergence between them is always a bug: an
// operator comparing two surfaces would reasonably read different wording as
// different states.
//
// Checking that agreement is also what surfaced a real gap: the local CLI had
// the #6845 overflow specialisation and the gRPC text renderer did NOT, so the
// same cluster reported slot exhaustion on one surface and the generic
// three-cause line on the other. Routing every surface through UnavailableLine
// fixes that by construction.
//
// WHY THE GENERIC LINE STAYS AMBIGUOUS. ReadZoneCounters returns
// ErrCounterNotPopulated for a pre-#3651 helper, a zone past the helper's
// hot-path slot capacity, AND a merely idle zone, because the helper's status
// snapshot is sparse and omits all-zero rows. Those three are genuinely
// indistinguishable at this layer and naming one would be a guess. The overflow
// line is different: when the helper reports its slot table has overflowed, that
// cause is KNOWN, it is the only one of the three that needs action, and traffic
// really is going uncounted.
const (
	unavailableGeneric = "  Traffic statistics: not available " +
		"(no per-zone volume published for this zone: helper predates " +
		"per-zone accounting, the zone exceeded the dataplane's " +
		"hot-path slot capacity, or the zone is idle)"

	unavailablePreDatingHelper = "  Traffic statistics: not available " +
		"(the running dataplane helper predates per-zone accounting, so it " +
		"publishes no per-zone volume at all; upgrade the helper)"

	unavailableIdle = "  Traffic statistics: not available " +
		"(the helper publishes per-zone volume and has slot capacity for this " +
		"zone, but has recorded none: the zone is idle)"

	unavailableOverflow = "  Traffic statistics: not available " +
		"(the dataplane's per-zone hot-path slot capacity is " +
		"EXHAUSTED, so this zone's traffic is not being counted " +
		"at all; reduce the number of configured zones or accept " +
		"that zones past the capacity go uncounted)"
)

// UnavailableLine returns the single canonical "not available" line
// every operator surface prints for a zone with no published per-zone volume.
//
// overflowActive selects the #6845 specialisation: pass the dataplane's
// reported slot-overflow bit. When it is true the cause is known and actionable;
// when false the three causes remain ambiguous and the generic line says so
// rather than guessing.
//
// It carries NO trailing newline, so callers that print a line and callers that
// assemble a buffer both use it unchanged.
//
// Deprecated for new callers: prefer UnavailableLineFor, which also consumes the
// layout version and can therefore name the pre-#3651-helper cause instead of
// folding it into the generic line (#7087). Kept so existing callers that have
// only the overflow bit compile unchanged; it delegates.
func UnavailableLine(overflowActive bool) string {
	return UnavailableLineFor(unknownLayoutVersion, overflowActive)
}

// unknownLayoutVersion is the sentinel UnavailableLine passes when its caller
// has no layout version to give. It is deliberately NOT 0: 0 is a MEANINGFUL
// value on this wire (absent field = pre-#3651 helper), so reusing it would make
// a caller that simply lacks the datum indistinguishable from one reporting an
// old helper — the exact conflation #7087 is about, reintroduced in the shim.
const unknownLayoutVersion = LayoutVersionUnknown

// LayoutVersionUnknown is what a caller passes when it could not read a status
// at all. Exported because the accessors that feed UnavailableLineFor need to
// distinguish "no status" from "layout version 0" (a pre-#3651 helper), and
// those are different sentences.
const LayoutVersionUnknown = ^uint32(0)

// UnavailableLineFor names WHICH of the three causes applies, when the wire says.
//
// #7087: the doc above this file's constants said the three causes are
// "genuinely indistinguishable at this layer and naming one would be a guess."
// That was true only because the layout-version field had no reader. It does
// carry the answer:
//
//	layoutVersion == 0   the helper predates per-zone accounting — KNOWN, and
//	                     not actionable on this box: it needs a helper upgrade.
//	overflowActive       the slot table is exhausted — KNOWN and actionable.
//	otherwise            a helper that publishes, with room, reporting nothing
//	                     for this zone: the zone is IDLE. Also known.
//
// So with both fields all three are distinguishable and none is a guess. The
// generic line survives only for callers that cannot supply a layout version.
//
// #14619: layoutVersion==0 is reachable ONLY from a helper that never
// sets the field. A current helper stamps its version unconditionally
// (even with no rows), so ">0, no row" is idle — the publisher must not
// manufacture 0 in the all-quiet state. Callers that also know this
// zone's slot membership should prefer UnavailableLineForZone, which
// splits slotted-idle from past-capacity under overflow.
//
// Order matters: an old helper publishes no overflow bit either, so the version
// check must come first or an upgrade-needed box would be reported as
// slot-exhausted — a wrong AND actionable diagnosis, which is worse than an
// ambiguous one.
func UnavailableLineFor(layoutVersion uint32, overflowActive bool) string {
	switch {
	case layoutVersion == 0:
		return unavailablePreDatingHelper
	case overflowActive:
		return unavailableOverflow
	case layoutVersion == unknownLayoutVersion:
		return unavailableGeneric
	default:
		return unavailableIdle
	}
}

// UnavailableLineForZone is the per-zone refinement of UnavailableLineFor
// for callers that know whether THIS zone holds a hot-path slot (#14619).
//
// The global overflow bit alone mislabels every slotted-but-idle zone as
// "not being counted at all" once more than 63 zones are configured.
// With the slotted set on the wire the split is exact:
//
//	layoutVersion == 0          pre-#3651 helper (checked first, as above)
//	slotted                     counted, nothing recorded: IDLE
//	overflow && !slotted        past capacity: genuinely uncounted
//	!overflow && !slotted       idle (no overflow: absence from the
//	                            sparse block is the idle signal; a zone
//	                            absent from an old helper's slotted set
//	                            — the field is omitted pre-#14619 — also
//	                            lands here only when overflow is off, so
//	                            no false "uncounted" is manufactured)
//
// Callers that cannot supply slotted keep UnavailableLineFor.
func UnavailableLineForZone(layoutVersion uint32, overflowActive bool, slotted bool) string {
	switch {
	case layoutVersion == 0:
		return unavailablePreDatingHelper
	case layoutVersion == unknownLayoutVersion:
		// No status readable: slotted is meaningless; preserve the
		// generic/overflow behaviour of UnavailableLineFor exactly.
		return UnavailableLineFor(layoutVersion, overflowActive)
	case slotted:
		return unavailableIdle
	case overflowActive:
		return unavailableOverflow
	default:
		return unavailableIdle
	}
}
