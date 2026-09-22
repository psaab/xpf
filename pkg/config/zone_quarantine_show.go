package config

import "fmt"

// Shared quarantine show-spelling SSOT (#10489 Q7, #6895 lesson).
//
// Every operator text surface that annotates a quarantined zone renders these
// spellings: the local CLI, gRPC text zones-detail, remote detail (which
// inherits gRPC text), and the showTestZone diagnostic. One const/format
// helper here keeps all surfaces byte-identical instead of each renderer
// re-deriving its own wording (#7473 composition rule for text).
//
// All runtime attributions below are PROSPECTIVE ("would ... if this snapshot
// is applied"): the verdict is config-derived from active configuration, which
// the dataplane may not have installed yet, so no line asserts applied-runtime
// state (R10). dp-nil renderers use these spellings identically; only the
// drift note is conditional on an applied-result baseline existing.
//
// This file carries TEXT ONLY. The verdict itself always comes from
// ZoneQuarantineExclusions / ZoneQuarantineExcludedReason (owned by #10490);
// nothing here re-derives the excluded set.

// ZoneQuarantineDispositionText is the shared degraded-state disposition body:
// what applying the active snapshot WOULD do to a quarantined zone.
const ZoneQuarantineDispositionText = "if this snapshot is applied, construction would omit the quarantined zone and clear its interface zone references; ordinary zone-directed traffic would then have no matching zone policy (default-deny); zone isolation would be DEGRADED until one zone is renamed"

// ZoneQuarantineHeadlineFor renders the full per-zone quarantine marker line:
// the QUARANTINED head naming id + survivor, plus the shared disposition body.
// Carries the two-space detail indent both text surfaces use; no trailing
// newline so Printf and buffer callers both use it unchanged (#6895 shape).
func ZoneQuarantineHeadlineFor(id uint16, survivor string) string {
	return fmt.Sprintf("  QUARANTINED (id %d collides with %q) — %s",
		id, survivor, ZoneQuarantineDispositionText)
}

// ZoneQuarantineIDQualifierFor renders the parenthetical appended to a kept
// zone-id line: the id is a stable pure function of the name (still TRUE, so
// kept), qualified with what applying the snapshot would do.
func ZoneQuarantineIDQualifierFor(survivor string) string {
	return fmt.Sprintf("(collides with %q — would not be installed if this snapshot is applied)",
		survivor)
}

// ZoneQuarantineCountersLine REPLACES the traffic-statistics block for a
// quarantined zone. The survivor's live counters are never shown under the
// quarantined name (F4): quarantined counters render UNAVAILABLE, never zero
// and never the survivor's volume.
const ZoneQuarantineCountersLine = "  Traffic statistics: UNAVAILABLE (quarantined zone — would be unpopulated if this snapshot is applied)"

// ZoneQuarantineScreenCountersLine replaces per-zone screen counters when the
// name is quarantined, so a colliding survivor's live counters are not reused.
const ZoneQuarantineScreenCountersLine = "  Screen statistics: UNAVAILABLE (quarantined zone — would be unpopulated if this snapshot is applied)"

// ZoneQuarantineLiveCountersUnavailable marks a live aggregate whose numeric
// zone ID cannot be attributed to a quarantined endpoint without reusing the
// surviving zone's counters.
const ZoneQuarantineLiveCountersUnavailable = "UNAVAILABLE (quarantined zone — live counters unavailable)"

// ZoneQuarantineReferenceQualifier marks a config reference whose runtime
// object has no unambiguous installed zone attribution.
const ZoneQuarantineReferenceQualifier = "(references quarantined zone — live attribution unavailable)"

// ZoneQuarantineInterfacesQualifier qualifies an interfaces header whose
// authored member list is kept verbatim; per-interface detail is unchanged.
const ZoneQuarantineInterfacesQualifier = "(would be unzoned if this snapshot is applied — quarantine candidate)"

// ZoneQuarantinePoliciesQualifier prefixes zone policy references/summaries
// for a quarantined zone.
const ZoneQuarantinePoliciesQualifier = "(would be scrubbed if this snapshot is applied — quarantine candidate)"

// ZoneQuarantineDriftNote is the #5067-style inventory-freshness banner,
// rendered ONLY when an applied result exists AND its key set differs from
// active config. It is a freshness note, NOT an applied-quarantine verdict:
// assignZoneIDs places both colliding names in cr.ZoneIDs, so the applied
// set can never identify the loser.
const ZoneQuarantineDriftNote = "note: zone inventory differs from last applied result — quarantine annotation follows active configuration"

// ZoneQuarantineTestZoneQualifierFor qualifies a showTestZone
// interface→zone match on a quarantined zone with the survivor/id the
// interface's zone assignment would resolve against.
func ZoneQuarantineTestZoneQualifierFor(id uint16, survivor string) string {
	return fmt.Sprintf("(quarantined: id %d collides with %q — would be unzoned if this snapshot is applied)",
		id, survivor)
}
