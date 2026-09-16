//! #7239 (#7160/#2387): the HA-wire encoding of a session's ROUTING DOMAIN.
//!
//! This exists for one reason: on the wire, **0 has to mean "the peer did not
//! state a domain"**, and the default routing instance also wants to be 0.
//! Those are different facts and crushing them together is what left the first
//! cut of this change unable to fix its own motivating case — a
//! legitimately-default-instance session from a NEW peer was indistinguishable
//! from an old peer's silence, so it fell back to deriving the domain from the
//! #7095 ingress fold, which is exactly the derivation #7239 is about.
//!
//! The shape is #7188's, deliberately, because that precedent is merged, in
//! this subsystem, and was built for the identical ambiguity: reserve 0 for
//! ABSENT and make every real state encode NON-ZERO — including the state that
//! means "nothing special here" (`TunnelDiscriminator::None` rides as
//! `WIRE_NONE = 1`, not as 0). Decoding returns three states rather than a
//! defaulted value, so a caller cannot silently treat absence as a domain.

/// The peer did not state a domain: a sender predating this field, whose
/// length-gated trailing field simply is not there.
pub(crate) const WIRE_ABSENT: u32 = 0;

/// The sender states THE DEFAULT ROUTING INSTANCE. Distinct from `WIRE_ABSENT`
/// on purpose — "I have no routing instances" is a statement, and it is the one
/// the overwhelming majority of deployments make.
pub(crate) const WIRE_DEFAULT_INSTANCE: u32 = 1;

/// #9956 F-032: the quarantine sentinel — must equal Go's
/// `QuarantinedRoutingInstanceDomain` (pinned by agreement in
/// `the_quarantine_sentinel_decodes_unrecognized_9956`). A row carrying it is
/// quarantined, NOT a member: the interface consumer must never let it
/// overwrite a surviving member's ifindex claim, and the sync handler refuses
/// to import under it while still deleting by exact key.
pub(crate) const QUARANTINED_ROUTING_DOMAIN: u32 = 2;

/// What a decoded wire value means. Mirrors `WireDiscriminator` (#7188).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireRoutingDomain {
    /// Sender predates the field. The caller keeps its pre-#7239 behaviour.
    Absent,
    /// Sender stated this domain. 0 here is the DEFAULT INSTANCE, stated.
    Present(u32),
    /// A value this build cannot place: not absent, not the default marker, and
    /// not inside the reserved routing-instance band. Coercing it into a domain
    /// would file a session under an identity we cannot reproduce.
    Unrecognized,
}

/// The reserved band `StableRoutingInstanceTableID` maps every named instance
/// into (`pkg/config/routinginstanceid.go`). Mirrored here so the decode can
/// tell a real domain from a corrupt or future-encoded value; the Go side pins
/// the same constants, and `routing_domain_wire_band_matches_go_7239` fails if
/// the two drift.
pub(crate) const DOMAIN_BAND_BASE: u32 = 100_000;
pub(crate) const DOMAIN_BAND_SPAN: u32 = 900_000;

/// Encode a domain for the wire. NEVER returns [`WIRE_ABSENT`]: a build that
/// has this function always makes a statement, which is what lets the receiver
/// read 0 as "the peer could not".
pub(crate) fn routing_domain_to_wire(domain: u32) -> u32 {
    if domain == 0 {
        WIRE_DEFAULT_INSTANCE
    } else {
        domain
    }
}

/// Decode a wire value into its three states.
pub(crate) fn routing_domain_from_wire(wire: u32) -> WireRoutingDomain {
    match wire {
        WIRE_ABSENT => WireRoutingDomain::Absent,
        WIRE_DEFAULT_INSTANCE => WireRoutingDomain::Present(0),
        d if d >= DOMAIN_BAND_BASE && d < DOMAIN_BAND_BASE + DOMAIN_BAND_SPAN => {
            WireRoutingDomain::Present(d)
        }
        _ => WireRoutingDomain::Unrecognized,
    }
}

#[cfg(test)]
#[path = "routing_domain_wire_tests.rs"]
mod tests;
