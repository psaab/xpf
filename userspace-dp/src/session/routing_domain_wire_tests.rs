//! #7239 wire-encoding cells. The whole module exists to keep three states
//! distinguishable, so these test the distinctions, not the arithmetic.

use super::*;

/// The load-bearing property, and the one #7188's R-M6 mutation cell exists to
/// protect on its own field: the encoder must NEVER emit the reserved value.
/// If it can, "the peer did not state a domain" and "the peer said default
/// instance" collapse, and the fallback derivation runs for a session that
/// explicitly told us it needed no derivation — which is #7239's own case.
///
/// FAIL-ON-REVERT: make `routing_domain_to_wire(0)` return 0 and this reds.
#[test]
fn the_encoder_never_emits_the_reserved_absent_value_7239() {
    for domain in [0u32, 1, 100_000, 999_999, u32::MAX] {
        assert_ne!(
            routing_domain_to_wire(domain),
            WIRE_ABSENT,
            "domain {domain} encoded as the reserved ABSENT value; a sender that \
             can emit 0 is indistinguishable from one that predates the field"
        );
    }
}

/// The default instance is a STATEMENT, not a silence, and it must survive the
/// round trip as one.
#[test]
fn the_default_instance_round_trips_as_present_not_absent_7239() {
    assert_eq!(routing_domain_to_wire(0), WIRE_DEFAULT_INSTANCE);
    assert_eq!(
        routing_domain_from_wire(routing_domain_to_wire(0)),
        WireRoutingDomain::Present(0),
        "a sender stating the default instance must decode as PRESENT(0). \
         Decoding it as Absent sends the receiver back to deriving the domain \
         from the ingress fold — the exact derivation #7239 removes."
    );
}

/// A tenant domain rides as itself, so the wire value is readable against
/// `StableRoutingInstanceTableID` output without a bias to undo.
#[test]
fn a_tenant_domain_round_trips_unchanged_7239() {
    for domain in [DOMAIN_BAND_BASE, 100_007, DOMAIN_BAND_BASE + DOMAIN_BAND_SPAN - 1] {
        assert_eq!(routing_domain_to_wire(domain), domain);
        assert_eq!(
            routing_domain_from_wire(domain),
            WireRoutingDomain::Present(domain)
        );
    }
}

/// Absence stays absence. This is what preserves the pre-#7239 behaviour — and
/// #8116's unresolvable-domain refusal — for a peer on the previous release.
#[test]
fn a_peer_predating_the_field_decodes_as_absent_7239() {
    assert_eq!(routing_domain_from_wire(0), WireRoutingDomain::Absent);
}

/// A value this build cannot place must NOT be coerced into a domain. Filing a
/// session under an identity we cannot reproduce is the failure #7188's
/// `Unrecognized` arm refuses, and the reasoning transfers exactly.
#[test]
fn an_unplaceable_value_is_unrecognized_not_coerced_7239() {
    for wire in [2u32, 99_999, DOMAIN_BAND_BASE + DOMAIN_BAND_SPAN, u32::MAX] {
        assert_eq!(
            routing_domain_from_wire(wire),
            WireRoutingDomain::Unrecognized,
            "wire value {wire} was placed as a domain; it is outside the reserved \
             band and is not the default marker, so this build cannot reproduce \
             what the sender meant"
        );
    }
}

/// The band mirrored here must match the Go constants that define it, or a
/// tenant domain decodes as Unrecognized and its sessions stop importing.
/// Pinned as an AGREEMENT rather than against literals: the literal would
/// encode which side is trusted, and the point is that neither is.
#[test]
fn routing_domain_wire_band_matches_go_7239() {
    let go = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("repo root")
            .join("pkg/config/routinginstanceid.go"),
    )
    .expect("read routinginstanceid.go");
    assert!(
        go.contains(&format!("RoutingInstanceTableIDBase = {DOMAIN_BAND_BASE}")),
        "DOMAIN_BAND_BASE ({DOMAIN_BAND_BASE}) no longer matches \
         RoutingInstanceTableIDBase in pkg/config/routinginstanceid.go"
    );
    assert!(
        go.contains(&format!("RoutingInstanceTableIDSpan = {DOMAIN_BAND_SPAN}")),
        "DOMAIN_BAND_SPAN ({DOMAIN_BAND_SPAN}) no longer matches \
         RoutingInstanceTableIDSpan in pkg/config/routinginstanceid.go"
    );
}

/// #9956 F-032: Go's `QuarantinedRoutingInstanceDomain` must decode as
/// Unrecognized, so a quarantined session synced to the HA peer is REFUSED
/// (fail-closed) rather than filed under a domain — in particular never under
/// the default domain (wire 1 decodes `Present(0)`, so a sentinel of 1 would
/// reintroduce the exact aliasing on the peer). Pinned as an AGREEMENT like
/// the band test: the value is read out of `routes.go`, so renumbering either
/// side breaks loudly instead of silently aliasing.
#[test]
fn the_quarantine_sentinel_decodes_unrecognized_9956() {
    let go = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("repo root")
            .join("pkg/dataplane/userspace/routes.go"),
    )
    .expect("read routes.go");
    let line = go
        .lines()
        .find(|l| l.contains("QuarantinedRoutingInstanceDomain uint32 = "))
        .expect("routes.go must define QuarantinedRoutingInstanceDomain");
    let value: u32 = line
        .rsplit('=')
        .next()
        .expect("const has a value")
        .trim()
        .parse()
        .expect("sentinel parses as u32");
    assert_eq!(
        QUARANTINED_ROUTING_DOMAIN, value,
        "Rust QUARANTINED_ROUTING_DOMAIN must equal Go's \
         QuarantinedRoutingInstanceDomain ({value}): the interface consumer \
         and the sync handler key off the Rust const"
    );
    assert_eq!(
        routing_domain_from_wire(routing_domain_to_wire(value)),
        WireRoutingDomain::Unrecognized,
        "quarantine sentinel {value} must round-trip as Unrecognized (refused \
         on import); Present(_) would file quarantined sessions under a live \
         domain on the peer"
    );
/// #9752: the Rust name→domain hash agrees with Go's
/// `config.StableRoutingInstanceTableID` on pinned literals. Vectors computed
/// via `go run` at base `9184222dd` (see `docs/pr/9752/fnv-vectors.txt`,
/// uncommitted scratch); the Go side pins the same literals in
/// `routinginstanceid_test.go` (C4), so either implementation drifting reds
/// its own suite. If this reds after touching `fnv1a64` or the fold, the
/// mirror — not the vectors — is wrong; verify against Go before "fixing".
#[test]
fn install_table_identity_matches_go_vectors_9752() {
    for (name, want_domain) in [
        ("blue", 525590u32),
        ("tenant-a", 259731),
        ("tenant-b", 788198),
        ("sfmix", 488570),
        ("scrub", 633963),
        ("ISP-B", 236616),
        ("vr1", 627081),
        ("mgmt", 579198),
        ("trust", 361106),
        ("wan", 384696),
        // UTF-8 multibyte (Codex-r2 demand): hashing is over raw bytes.
        ("é-vrf", 704427),
        ("a", 969824),
        ("A", 737632),
        ("Comcast-GigabitPro", 676172),
        ("x", 644139),
        ("zzz", 497540),
    ] {
        let (domain, check) = install_table_identity(name);
        assert_eq!(
            domain, want_domain,
            "name {name:?}: domain {domain} != Go {want_domain}"
        );
        // H2 is helper-local (no Go counterpart): pin determinism + the
        // u64-fold shape instead of agreement — same input, same check,
        // and the check is the hash's high half (non-degenerate).
        assert_eq!(
            install_table_identity(name).1,
            check,
            "name {name:?}: H2 nondeterministic across calls"
        );
    }
}

/// #9752: hashing the empty name is a caller bug (Go: `""` -> 106945,
/// IN-BAND — it could be a live instance's domain, and stamping it would
/// alias). Callers skip defaults before extraction (registry) or never
/// override on empty (PBR terms); the `debug_assert!` fails loud in tests.
/// The registry test pins that no row is ever keyed by it.
#[test]
#[should_panic(expected = "must be skipped before name extraction")]
fn empty_name_hash_panics_9752() {
    let _ = install_table_identity("");
}

/// #9752: the known Go collision pair collides here too (same function), so
/// the registry's first-wins determinism cell (forwarding_build) tests the
/// real shape rather than a synthetic one.
#[test]
fn known_go_collision_pair_collides_here_too_9752() {
    assert_eq!(
        install_table_identity("ri7").0,
        install_table_identity("ri116").0,
        "ri7/ri116 collide in Go (#9657); the mirror must collide identically"
    );
    assert_eq!(install_table_identity("ri7").0, 957120);
}
