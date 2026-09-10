// Tests for the session module (#1047). Originally inline in session.rs,
// relocated as session_tests.rs in P1 (PR #1051), then renamed to
// session/tests.rs alongside the structural split that introduced the
// session/ directory module and session/key.rs.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from session/mod.rs.
//
// #7342: `key_v4`, `tcp_key_v6`, `decision`, `metadata` and
// `install_forward_reverse_pair` are `pub(in crate::session)` because the
// close-state split's own test file drives the SAME fixtures. Sharing them
// rather than copying is deliberate: a second copy of `install_forward_reverse_pair`
// would let the two files disagree about what a forward/reverse pair looks
// like, and the whole subject of that file is how the two halves interact.

use crate::test_zone_ids::*;
use super::*;
// #2005 split: the timer-wheel constants used by the GC tests below were
// previously reachable via `super::*` through mod.rs's explicit
// `use wheel::{...}` re-export. mod.rs no longer imports them directly
// (the wheel-driving methods moved to session/expire.rs), so reference
// them explicitly here. Same symbols, same values — no behavior change.
use super::wheel::{FAR_FUTURE_OFFSET, WHEEL_BUCKETS, WHEEL_TICK_NS};
// #3152: TCP control bits used by the half-open / opening-state tests.
// `TCP_FIN`/`TCP_RST` reach the test via `super::*` (mod.rs imports them);
// SYN and ACK are not re-exported there, so bring them in explicitly.
use crate::tcp_flags::{TCP_ACK, TCP_SYN};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(in crate::session) fn key_v4() -> SessionKey {
    SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 12345,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn key_v6() -> SessionKey {
    SessionKey {
        addr_family: 10,
        protocol: PROTO_UDP,
        src_ip: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6 src")),
        dst_ip: IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().expect("v6 dst")),
        src_port: 5555,
        dst_port: 53,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

fn resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: None,
        tx_vlan_id: 0,
    }
}

pub(in crate::session) fn decision() -> SessionDecision {
    SessionDecision {
        resolution: resolution(),
        nat: NatDecision::default(),
    }
}

pub(in crate::session) fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

// #5445: the per-packet established-session lookup must NOT clone the bound
// `Arc<PolicyRuleCounter>`. Cloning `SessionMetadata` by value on every lookup
// bumped the SHARED refcount (a `LOCK XADD`) on the packet-forwarding hot path
// — the #919 hot-path-atomic problem. This is a perf-with-strong-count guard,
// not a behavioral RED-on-revert: reverting `clone_without_policy_counter` back
// to `entry.metadata.clone()` makes the returned `SessionLookup` hold an owned
// strong reference, so `Arc::strong_count` GROWS while the lookup result is
// alive → the equality assertion fails (RED). The accounting half proves the
// bound counter is still reachable BY BORROW and still increments.
#[test]
fn lookup_does_not_clone_policy_counter_arc_5445() {
    let mut table = SessionTable::new();
    let counter = std::sync::Arc::new(crate::policy::PolicyRuleCounter::default());
    let key = key_v4();

    let mut md = metadata();
    md.policy_counter = Some(counter.clone());
    md.policy_counter_idx = 7;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        md,
        1_000,
        PROTO_TCP,
        TCP_SYN | TCP_ACK,
    ));
    // Drain the install's Open delta — it holds a `SessionMetadata` clone (with
    // the Arc) until consumed, which would otherwise inflate the baseline.
    let _ = table.drain_deltas(8);

    // Baseline: the original test handle + the session entry's owned handle.
    let base = std::sync::Arc::strong_count(&counter);
    assert_eq!(base, 2, "entry owns exactly one bound-counter reference");

    // The per-packet established-session lookup (the #919 hot path).
    let lookup = table
        .lookup(&key, 2_000, TCP_ACK)
        .expect("established session hit");
    let during = std::sync::Arc::strong_count(&counter);
    assert_eq!(
        base, during,
        "#5445: the per-packet SessionLookup must NOT clone the policy_counter \
         Arc — reverting to `entry.metadata.clone()` bumps strong_count while \
         the lookup is held (RED)"
    );
    // The returned lookup carries the Copy fields but drops the bound Arc.
    assert!(
        lookup.metadata.policy_counter.is_none(),
        "the hot-path lookup return no longer carries the bound counter Arc"
    );
    assert_eq!(
        lookup.metadata.policy_counter_idx, 7,
        "the positional idx (Copy) still rides the lookup return"
    );
    drop(lookup);

    // The bound counter is still reachable BY BORROW from the owning entry (no
    // clone, no strong-count bump) and its accounting still increments.
    let before = counter.test_packet_count();
    {
        let bound = table
            .bound_policy_counter_for(&key)
            .expect("bound counter borrowable from the entry");
        assert_eq!(
            std::sync::Arc::strong_count(&counter),
            base,
            "resolving the bound counter by borrow must not bump strong_count"
        );
        crate::policy::record_policy_hit_counter(bound, 1_200);
    }
    assert_eq!(
        counter.test_packet_count(),
        before + 1,
        "#5445: the policy hit-count still increments via the borrowed handle"
    );
    // And no leaked reference survived the borrow-and-record.
    assert_eq!(
        std::sync::Arc::strong_count(&counter),
        base,
        "no strong reference leaked onto the hot path"
    );
}

/// #4109: a TCP IPv6 forward key. The shared `key_v6()` is UDP, but the TCP
/// state-machine tests need a v6 TCP flow to cover the second address family.
pub(in crate::session) fn tcp_key_v6() -> SessionKey {
    SessionKey {
        addr_family: 10,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6 src")),
        dst_ip: IpAddr::V6("2606:4700:4700::1111".parse::<Ipv6Addr>().expect("v6 dst")),
        src_port: 51000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

/// #4109: the reverse-companion key for a no-NAT forward session — the same
/// `reverse_session_key` transform the forwarding hot path
/// (`build_reverse_session_from_forward_match`) applies. `NatDecision::default`
/// makes the transform a pure src/dst + port swap, and it is its own inverse,
/// so `reverse_session_key(reverse_key_of(f), default) == f`.
fn reverse_key_of(forward: &SessionKey) -> SessionKey {
    reverse_session_key(forward, NatDecision::default())
}

/// #4109: install the forward entry AND its reverse companion for `forward`,
/// mirroring the production two-entry install (`poll_descriptor`): both halves
/// are installed from the SAME trigger flags, so a bare SYN starts both OPENING
/// (matching `established: !(is_initial_syn(..))`). Zones swap on the reverse
/// companion (faithful to `build_reverse_session_from_forward_match`, though the
/// state-machine tests do not depend on them). Returns the reverse-companion
/// key. Deltas emitted by the two installs are drained so a later assertion on
/// close/open deltas sees only what the test itself produced.
pub(in crate::session) fn install_forward_reverse_pair(
    table: &mut SessionTable,
    forward: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> SessionKey {
    assert!(table.install_with_protocol(
        forward.clone(),
        decision(),
        metadata(),
        now_ns,
        PROTO_TCP,
        tcp_flags,
    ));
    let reverse = reverse_key_of(forward);
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = TEST_WAN_ZONE_ID;
    reverse_metadata.egress_zone = TEST_LAN_ZONE_ID;
    assert!(table.install_with_protocol(
        reverse.clone(),
        decision(),
        reverse_metadata,
        now_ns,
        PROTO_TCP,
        tcp_flags,
    ));
    let _ = table.drain_deltas(8);
    reverse
}

#[test]
fn session_lookup_hits_after_install() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x10
    ));
    let hit = table.lookup(&key, now + 1_000_000, 0x10);
    assert_eq!(
        hit,
        Some(SessionLookup {
            decision: decision(),
            metadata: metadata(),
        })
    );
    let deltas = table.drain_deltas(8);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
    assert_eq!(deltas[0].key, key);
}

#[test]
fn missing_neighbor_seed_install_stays_out_of_delta_stream() {
    let mut table = SessionTable::new();
    let key = key_v4();
    assert!(table.install_with_protocol_with_origin(
        key,
        decision(),
        metadata(),
        SessionOrigin::MissingNeighborSeed,
        1_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert!(
        table.drain_deltas(8).is_empty(),
        "transient missing-neighbor seeds must stay local"
    );
}

#[test]
fn missing_neighbor_seed_expire_stays_out_of_delta_stream() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::MissingNeighborSeed,
        then,
        PROTO_TCP,
        0x10,
    ));
    assert!(table.drain_deltas(8).is_empty());
    table.last_gc_ns = then + 301_000_000_000;
    let expired = table.expire_stale_entries(then + 302_000_000_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].key, key);
    assert!(table.drain_deltas(8).is_empty());
}

#[test]
fn session_expire_removes_stale_entries() {
    let mut table = SessionTable::new();
    let key = key_v6();
    let then = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        then,
        PROTO_UDP,
        0
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 118_000_000_000;
    let expired = table.expire_stale(then + 120_000_000_000);
    assert_eq!(expired, 1);
    assert!(table.lookup(&key, then + 121_000_000_000, 0).is_none());
    let deltas = table.drain_deltas(8);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, key);
}

// #4915 RED-on-revert: the STABLE session id must be (a) non-zero for a real
// session (0 is the "unknown" wire sentinel), (b) DISTINCT for two concurrent
// sessions (so a reused 5-tuple is disambiguated), and (c) IDENTICAL across a
// session's Open and Close deltas — the correlatable key the RT_FLOW
// SESSION_CREATE / SESSION_CLOSE frames stamp at [152:160]. Reverting the id
// allocation or the delta threading flips these RED.
#[test]
fn session_id_is_stable_across_open_and_close() {
    let mut table = SessionTable::new();
    let a = key_v4(); // TCP
    let b = key_v6(); // UDP
    let t0 = 1_000_000_000u64;

    // Two distinct concurrent sessions get distinct, non-zero ids.
    assert!(table.install_with_protocol(a.clone(), decision(), metadata(), t0, PROTO_TCP, 0));
    assert!(table.install_with_protocol(b.clone(), decision(), metadata(), t0, PROTO_UDP, 0));
    let opens = table.drain_deltas(8);
    assert_eq!(opens.len(), 2);
    let a_open_id = opens.iter().find(|d| d.key == a).expect("a open").session_id;
    let b_open_id = opens.iter().find(|d| d.key == b).expect("b open").session_id;
    assert_ne!(a_open_id, 0, "a real session id must never be 0");
    assert_ne!(b_open_id, 0, "a real session id must never be 0");
    assert_ne!(
        a_open_id, b_open_id,
        "two concurrent sessions must get distinct ids"
    );

    // The Close delta for the UDP session `b` (reaped on the ~120 s idle window,
    // mirroring session_expire_removes_stale_entries) carries the SAME id its
    // Open delta did — the create/close correlation this change restores.
    table.last_gc_ns = t0 + 118_000_000_000;
    let expired = table.expire_stale(t0 + 120_000_000_000);
    assert_eq!(expired, 1);
    let closes: Vec<_> = table
        .drain_deltas(8)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Close)
        .collect();
    let b_close = closes.iter().find(|d| d.key == b).expect("b close");
    assert_eq!(
        b_close.session_id, b_open_id,
        "SESSION_CLOSE must carry the same stable id as its SESSION_CREATE"
    );
}

// #4915: the session id namespaces the worker in the high bits so ids are
// unique across the node's shared-nothing per-worker session tables; the low 48
// bits are a per-worker counter starting at 1. #6311 narrowed the worker half to
// 15 bits and put the node discriminator above it — on node 0 the layout is
// bit-identical to pre-#6311, which is what this pins.
#[test]
fn session_id_namespaces_worker_in_high_bits() {
    let mut table = SessionTable::new();
    table.set_session_id_namespace(0, 3);
    let t0 = 1_000_000_000u64;
    assert!(table.install_with_protocol(key_v4(), decision(), metadata(), t0, PROTO_TCP, 0));
    let opens = table.drain_deltas(8);
    assert_eq!(opens.len(), 1);
    let id = opens[0].session_id;
    assert_eq!(id >> 48, 3, "worker id must occupy the high bits");
    assert_eq!(
        id & 0x0000_FFFF_FFFF_FFFF,
        1,
        "the first session's per-worker counter starts at 1"
    );
}

// #6311: the SAME worker index on the two cluster nodes must mint DISJOINT ids.
// Both HA nodes run the same worker set (queue indices 0..N) and both per-worker
// counters start at 1, so before the node discriminator a peer id adopted
// verbatim on import (#5212) collided with the importing node's own id for that
// worker — guaranteed in active/active early after boot.
//
// RED on revert: drop the node half from `set_session_id_namespace` (ignore
// node_id, namespace = worker alone) and the two ids are equal.
#[test]
fn session_id_carries_the_node_discriminator_6311() {
    let mut node0 = SessionTable::new();
    let mut node1 = SessionTable::new();
    node0.set_session_id_namespace(0, 3);
    node1.set_session_id_namespace(1, 3);
    let t0 = 1_000_000_000u64;
    assert!(node0.install_with_protocol(key_v4(), decision(), metadata(), t0, PROTO_TCP, 0));
    assert!(node1.install_with_protocol(key_v4(), decision(), metadata(), t0, PROTO_TCP, 0));
    let id0 = node0.drain_deltas(8)[0].session_id;
    let id1 = node1.drain_deltas(8)[0].session_id;

    assert_ne!(
        id0, id1,
        "#6311: the same worker index on the two cluster nodes minted the SAME session id — \
         a standby that adopts a peer id would collide with its own"
    );
    // The ONLY difference is the node bit: the worker half and the counter are
    // untouched, so cross-node correlation and per-worker debuggability survive.
    assert_eq!(
        id0 ^ id1,
        1u64 << 63,
        "the node discriminator must be exactly the top bit — the worker field and the \
         counter must be unchanged by it"
    );
    assert_eq!(id0 >> 48, 3, "node 0 keeps the pre-#6311 layout");
    assert_eq!(
        id1 >> 48,
        (1 << 15) | 3,
        "node 1 sets the node bit above the worker field"
    );
}

// #6311: the structural consequence, driven through the REAL adoption path —
// an id ADOPTED from the peer can never be re-minted locally, so the pre-#5212
// same-node uniqueness property is restored without any `next_session_id`
// bookkeeping on the adoption path.
//
// The peer id is MINTED BY A NODE-1 TABLE, not written as a literal. An earlier
// draft of this test hardcoded `((1<<15)|3)<<48 | 1`, and the mutation matrix
// caught that as VACUOUS: a hardcoded peer id simply names a value the un-bitted
// allocator never produces, so the assertion passed with the node discriminator
// removed. It was a probe keyed to the fix rather than to the property. Deriving
// the peer id from a real (node 1, worker 3) table is what puts the node bit
// under test.
#[test]
fn adopted_peer_id_cannot_collide_with_a_local_id_6311() {
    let t0 = 1_000_000_000u64;

    // What the PEER actually mints for its first worker-3 session.
    let mut peer = SessionTable::new();
    peer.set_session_id_namespace(1, 3);
    assert!(peer.install_with_protocol(key_v4(), decision(), metadata(), t0, PROTO_TCP, 0));
    let peer_id = peer.drain_deltas(8)[0].session_id;
    assert_ne!(peer_id, 0, "fixture: the peer must have minted a real id");

    // This node runs the SAME worker index, and its counter also starts at 1 —
    // the exact point where the pre-#6311 namespaces collided.
    let mut local = SessionTable::new();
    local.set_session_id_namespace(0, 3);

    // Adopt the peer's id verbatim (#5212).
    let imported = key_v6();
    assert!(local.upsert_synced_with_origin(
        SessionInstall {
            key: imported.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::SyncImport,
            now_ns: t0,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            session_id: peer_id,
            tcp_close_class: 0,
        },
        false,
    ));
    assert_eq!(
        local.session_id_for(&imported),
        peer_id,
        "precondition: the import must ADOPT the peer id, or this test proves nothing"
    );

    // Now mint locally. The adoption did NOT advance `next_session_id`, so this
    // is counter 1 — which is precisely the value the peer used. It must still
    // differ, and it can only differ because of the node bit.
    let mine = key_v4();
    assert!(local.install_with_protocol(mine.clone(), decision(), metadata(), t0, PROTO_TCP, 0));
    let local_id = local.session_id_for(&mine);
    assert_ne!(
        local_id, peer_id,
        "#6311: this node's first worker-3 id equals the peer's first worker-3 id — the \
         adopted import and a locally-minted session share one correlation stamp"
    );
}

// #6198: the high-16 value 0xFFFF is RESERVED for the Go control plane, which
// mints `0xFFFF << 48 | counter48` for peer-synced sessions into the SAME BPF
// conntrack mirror field this table stamps. Before #6198 that reservation lived
// only in a Go comment, so nothing on this side stopped a worker id from landing
// on it. It is unreachable today (`binding.worker_id` is bounded by the worker
// count), but #6311 proposes re-partitioning exactly these bits — this pins the
// invariant so such a change has to confront it rather than silently alias.
//
// A hard `assert!`, not `debug_assert!`: `make test-rust` and the shipped helper
// both build `--release`, where a debug assertion is stripped and would guard
// nothing. Worker setup is config time, where docs/engineering-style.md prefers
// crash-start over running with a wrong invariant.
//
// #6311 re-partitioned these bits: `0xFFFF` is now node-bit-1 plus worker
// `0x7FFF`, so reaching the reservation requires BOTH halves. That is why this
// test names node 1 explicitly — a worker id of `0xFFFF` no longer reaches the
// reservation assert at all (it trips the narrower worker-range assert first,
// pinned separately below), and leaving it that way would have quietly turned
// this guard into a test of a different assertion.
#[test]
#[should_panic(expected = "reserved for the Go control plane")]
fn set_worker_id_rejects_the_control_plane_namespace_6198() {
    let mut table = SessionTable::new();
    table.set_session_id_namespace(1, SESSION_ID_MAX_WORKER as u32);
}

// #6311: a worker id that does not fit the narrowed 15-bit worker half must be
// REFUSED, not masked. Masking it (the pre-#6311 `& 0xFFFF` behaviour, applied
// to the narrower field) would carry into the node bit and mint ids inside the
// PEER node's namespace — a silent cross-node collision, strictly worse than the
// counter aliasing the old mask prevented. Unreachable today (worker ids are
// bounded by MAX_NAT_HOLDER_WORKERS = 128 where they are minted), which is
// exactly why it needs a pin.
#[test]
#[should_panic(expected = "does not fit")]
fn set_session_id_namespace_refuses_a_worker_id_that_would_reach_the_node_bit_6311() {
    let mut table = SessionTable::new();
    table.set_session_id_namespace(0, SESSION_ID_MAX_WORKER as u32 + 1);
}

// The paired NEGATIVE CONTROL: the highest worker id that is NOT reserved is
// accepted and namespaces normally. This passes with and without the assertion,
// so it proves the guard is scoped to the reserved value rather than rejecting
// large worker ids in general.
#[test]
fn set_worker_id_accepts_the_value_below_the_reservation_6198() {
    let mut table = SessionTable::new();
    // One below the reservation: node 1, worker 0x7FFE. Post-#6311 the
    // reservation is a NAMESPACE value, so the neighbour has to be named as a
    // (node, worker) pair too.
    table.set_session_id_namespace(1, SESSION_ID_MAX_WORKER as u32 - 1);
    let t0 = 1_000_000_000u64;
    assert!(table.install_with_protocol(key_v4(), decision(), metadata(), t0, PROTO_TCP, 0));
    let opens = table.drain_deltas(8);
    assert_eq!(opens.len(), 1);
    assert_eq!(
        opens[0].session_id >> 48,
        CONTROL_PLANE_SESSION_ID_WORKER_HI - 1,
        "an unreserved namespace must still namespace normally"
    );
}

// #5212 RED-on-revert: a peer-synced import ADOPTS the originating node's stable
// session id carried on the HA session-sync wire (SessionInstall.session_id)
// instead of minting a fresh node-local one, so the standby's SESSION_CLOSE
// RT_FLOW record correlates with the primary's SESSION_CREATE across HA nodes. A
// zero wire id (a legacy peer that predates the field) falls back to a fresh
// local alloc. Reverting the stamp in `upsert_synced_with_origin` (back to an
// unconditional `alloc_session_id()`) flips the first assertion RED: the adopted
// id would be a local worker-2 id, not the peer's worker-3 id. A distinct worker
// only keeps that revert assertion unambiguous — the id space is NOT partitioned
// by node, so a peer id in the SAME worker index collides with a local id in
// active/active (an accepted observability-only limitation, #6311).
#[test]
fn synced_import_adopts_peer_session_id_5212() {
    let mut table = SessionTable::new();
    // Local allocations would land in this node's (node 0, worker 2) namespace.
    table.set_session_id_namespace(0, 2);
    let now = 1_000_000_000u64;

    // A peer-originated id, adopted verbatim. Since #6311 the namespace carries
    // a NODE discriminator, so a peer id can no longer collide with a local one
    // even at the same worker index; the distinct worker here only keeps the
    // revert assertion unambiguous.
    let peer_id: u64 = (3u64 << 48) | 42;
    let key = key_v4();
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: key.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            session_id: peer_id,
            tcp_close_class: 0,
        },
        false,
    ));
    assert_eq!(
        table.session_id_for(&key),
        peer_id,
        "a peer-synced session must ADOPT the wire session id, not alloc a fresh local one"
    );

    // A second synced session carrying NO wire id (a legacy peer) falls back to a
    // FRESH LOCAL id: non-zero, in this node's (worker-2) namespace, and never
    // the peer's id.
    let key2 = key_v6();
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: key2.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_UDP,
            tcp_flags: 0,
            session_id: 0,
            tcp_close_class: 0,
        },
        false,
    ));
    let local_id = table.session_id_for(&key2);
    assert_ne!(local_id, 0, "a zero wire id must fall back to a fresh non-zero local id");
    assert_ne!(local_id, peer_id, "the fallback must be a fresh LOCAL id, not the peer's");
    assert_eq!(
        local_id >> 48,
        2,
        "the fallback id must be namespaced to this node's worker (2)"
    );
}

// === #4380 symmetric idle-timer (forward↔reverse companion) tests =========
//
// A flow is TWO independent entries that age independently. Junos measures a
// session's idle time from the last activity in EITHER direction, so a flow
// active on only one direction must NOT reap its quiet half. The GC-time
// companion probe (`companion_keeps_alive`, expire.rs) enforces that.

/// #4380 RED-on-revert: a flow with traffic on ONLY the reverse direction
/// (forward half frozen) must NOT reap its forward half while the reverse half
/// is still within its idle window — the active companion keeps both alive.
/// On revert (no companion probe) the forward half crosses its 300 s idle
/// timeout and is removed, leaving a half-open session (and, under NAT, a
/// later forward packet re-creating a session with a different translation).
#[test]
fn reverse_activity_keeps_forward_half_alive() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let then = 1_000_000_000u64;
    // ACK (not an initial SYN) installs both halves ESTABLISHED → 300 s window.
    let reverse = install_forward_reverse_pair(&mut table, &forward, then, TCP_ACK);
    // Reverse-only traffic: the read path re-stamps ONLY the entry a packet's
    // wire tuple resolves, so a reverse packet touches the reverse half and
    // leaves the forward half frozen at `then`.
    let t_rev = then + 250_000_000_000; // 250 s: reverse still active
    table.touch(&reverse, t_rev);
    // GC past the forward half's 300 s idle timeout while the reverse half is
    // still fresh (idle 60 s < 300 s).
    let now = then + 310_000_000_000; // 310 s
    table.last_gc_ns = now - 2_000_000_000;
    let expired = table.expire_stale_entries(now);
    assert!(
        expired.is_empty(),
        "asymmetric flow must not reap the quiet forward half while the reverse half is active",
    );
    assert_eq!(table.len(), 2, "both halves must survive");
    assert_eq!(
        table.last_pop_stats().kept_alive_by_companion,
        1,
        "the forward half must be retained via the active companion",
    );
    // No Close delta — the whole flow is still active.
    assert!(
        table.drain_deltas(8).is_empty(),
        "no Close delta while the flow is still active on the reverse direction",
    );
    // The FORWARD half specifically is still present.
    assert!(
        table.lookup(&forward, now, TCP_ACK).is_some(),
        "the forward half must be resolvable after the kept-alive GC pass",
    );
}

/// #4380 control: a genuinely idle flow — BOTH halves quiet past the timeout —
/// still reaps. The companion probe fails for each half (the sibling has also
/// crossed), so both are removed and exactly one Close delta fires (the forward
/// entry; reverse entries emit none).
#[test]
fn both_halves_idle_still_expire() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let then = 1_000_000_000u64;
    let _reverse = install_forward_reverse_pair(&mut table, &forward, then, TCP_ACK);
    // Neither half touched — both idle from `then`.
    let now = then + 310_000_000_000; // 310 s > 300 s established window
    table.last_gc_ns = now - 2_000_000_000;
    let _ = table.expire_stale_entries(now);
    assert_eq!(table.len(), 0, "a fully-idle flow must reap BOTH halves");
    assert_eq!(
        table.last_pop_stats().kept_alive_by_companion,
        0,
        "no half may be retained when both are idle",
    );
    let deltas = table.drain_deltas(8);
    assert_eq!(
        deltas
            .iter()
            .filter(|d| d.kind == SessionDeltaKind::Close)
            .count(),
        1,
        "exactly one Close delta (the forward entry) for the whole-flow reap",
    );
}

/// #4380 control: a symmetric flow (both halves actively touched) is unaffected
/// — neither half crosses its timeout, so the normal not-yet-due path handles
/// them and the companion-retention path is never taken.
#[test]
fn symmetric_flow_unaffected_by_companion_retention() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let then = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, then, TCP_ACK);
    // Both halves keep receiving traffic.
    let t_active = then + 250_000_000_000;
    table.touch(&forward, t_active);
    table.touch(&reverse, t_active);
    let now = then + 310_000_000_000;
    table.last_gc_ns = now - 2_000_000_000;
    let expired = table.expire_stale_entries(now);
    assert!(expired.is_empty(), "an actively-forwarding flow must not reap");
    assert_eq!(table.len(), 2, "both halves survive a symmetric flow");
    assert_eq!(
        table.last_pop_stats().kept_alive_by_companion,
        0,
        "the companion path is not needed when both halves are fresh",
    );
}

/// #4380 headline scenario, under NAT: a pool-SNAT'd flow active on ONLY the
/// reverse direction keeps its forward half alive, and a later forward packet
/// resolves the RETAINED entry with its ORIGINAL translation — NOT a re-create
/// that would hand the flow a different NAT mapping (the corruption the PR
/// closes). The forward entry carries the SNAT decision; the reverse companion
/// carries its `NatDecision::reverse`, so the companion probe must round-trip
/// through the reversed-nat key to find the sibling. RED on revert: without the
/// probe the forward half is reaped and the lookup below misses.
#[test]
fn nat_flow_reverse_activity_keeps_forward_half_alive() {
    let mut table = SessionTable::new();
    let forward = key_v4(); // TCP 10.0.0.1:12345 -> 8.8.8.8:443
    let then = 1_000_000_000u64;

    // Pool SNAT: source-translate 10.0.0.1:12345 -> 203.0.113.5:50000.
    let fwd_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
        rewrite_src_port: Some(50000),
        ..NatDecision::default()
    };
    let fwd_decision = SessionDecision {
        resolution: resolution(),
        nat: fwd_nat,
    };
    assert!(table.install_with_protocol(
        forward.clone(),
        fwd_decision,
        metadata(),
        then,
        PROTO_TCP,
        TCP_ACK,
    ));

    // Reverse companion: keyed on the reply wire tuple and carrying the
    // reversed decision, exactly as the forwarding path builds it. The reverse
    // key round-trips back to the forward key under the reversed nat.
    let reverse = reverse_session_key(&forward, fwd_nat);
    let reverse_nat = fwd_nat.reverse(
        forward.src_ip,
        forward.dst_ip,
        forward.src_port,
        forward.dst_port,
    );
    assert_eq!(
        reverse_session_key(&reverse, reverse_nat),
        forward,
        "reversed-nat companion key must round-trip back to the forward key",
    );
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    let reverse_decision = SessionDecision {
        resolution: resolution(),
        nat: reverse_nat,
    };
    assert!(table.install_with_protocol(
        reverse.clone(),
        reverse_decision,
        reverse_metadata,
        then,
        PROTO_TCP,
        TCP_ACK,
    ));
    let _ = table.drain_deltas(8);

    // Reverse-only traffic: only the reverse (reply) half is refreshed.
    let t_rev = then + 250_000_000_000; // 250 s
    table.touch(&reverse, t_rev);
    // GC past the forward half's 300 s idle timeout while the reverse is fresh.
    let now = then + 310_000_000_000; // 310 s
    table.last_gc_ns = now - 2_000_000_000;
    let expired = table.expire_stale_entries(now);
    assert!(
        expired.is_empty(),
        "the NAT'd flow's quiet forward half must not reap while the reverse half is active",
    );
    assert_eq!(table.len(), 2, "both NAT'd halves must survive");
    assert_eq!(
        table.last_pop_stats().kept_alive_by_companion,
        1,
        "the forward half is retained via the reversed-nat companion probe",
    );
    // The RETAINED forward entry still carries its ORIGINAL SNAT translation —
    // a later forward packet resolves the same entry, not a re-created session
    // with a different mapping.
    let hit = table
        .lookup(&forward, now, TCP_ACK)
        .expect("the SNAT'd forward half must survive and resolve");
    assert_eq!(
        hit.decision.nat, fwd_nat,
        "the retained forward entry must keep its original SNAT translation",
    );
}

// === #3227 per-application inactivity-timeout tests =========

/// `metadata()` with a custom per-application inactivity (idle) timeout stamped
/// (in nanoseconds) — mirrors the value the install path derives from a matched
/// application term's `inactivity-timeout`.
fn metadata_with_app_timeout(ns: u64) -> SessionMetadata {
    SessionMetadata {
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        inactivity_timeout_ns: Some(ns),
        policy_counter_idx: 0,
        policy_counter: None,
        ..metadata()
    }
}

/// #3227 unit: `session_timeout_ns` uses the per-application override for an
/// ESTABLISHED flow on every protocol, and `None` falls back byte-identically
/// to the global per-protocol timeout. A closing/RST TCP flow ignores the
/// override (short reap window preserved).
#[test]
fn session_timeout_ns_honors_app_override() {
    let to = SessionTimeouts::default();
    let app = 30_000_000_000u64; // 30 s

    // ESTABLISHED TCP (ACK, not closing): override wins; None -> global.
    // #3527: the opening override (6th arg) never touches the established branch.
    assert_eq!(session_timeout_ns(PROTO_TCP, 0x10, true, &to, Some(app), None), app);
    assert_eq!(
        session_timeout_ns(PROTO_TCP, 0x10, true, &to, None, None),
        DEFAULT_TCP_SESSION_TIMEOUT_NS
    );
    // #3152: OPENING TCP (handshake incomplete): the short opening window,
    // regardless of any per-app override (which is the established idle value).
    assert_eq!(
        session_timeout_ns(PROTO_TCP, crate::tcp_flags::TCP_SYN, false, &to, Some(app), None),
        DEFAULT_TCP_OPENING_TIMEOUT_NS
    );
    assert_eq!(
        session_timeout_ns(PROTO_TCP, crate::tcp_flags::TCP_SYN, false, &to, None, None),
        DEFAULT_TCP_OPENING_TIMEOUT_NS
    );
    // UDP / ICMP: override wins; None -> global. `established` is ignored.
    assert_eq!(session_timeout_ns(PROTO_UDP, 0, true, &to, Some(app), None), app);
    assert_eq!(
        session_timeout_ns(PROTO_UDP, 0, true, &to, None, None),
        DEFAULT_UDP_SESSION_TIMEOUT_NS
    );
    assert_eq!(session_timeout_ns(PROTO_ICMP, 0, true, &to, Some(app), None), app);
    assert_eq!(
        session_timeout_ns(PROTO_ICMP, 0, true, &to, None, None),
        DEFAULT_ICMP_SESSION_TIMEOUT_NS
    );
    // Closing/RST TCP: the override never extends the short reap window
    // (and the closing branch is consulted before the OPENING branch).
    assert_eq!(
        session_timeout_ns(PROTO_TCP, TCP_RST, false, &to, Some(app), None),
        TCP_RST_TIMEOUT_NS
    );
    assert_eq!(
        session_timeout_ns(PROTO_TCP, TCP_FIN, false, &to, Some(app), None),
        TCP_CLOSING_TIMEOUT_NS
    );
}

/// #3527 unit: `session_timeout_ns` applies the per-zone half-open override
/// ONLY on the OPENING branch. An established / closing / RST flow ignores it;
/// a half-open (bare-SYN) flow reaps on the override, replacing the global
/// `tcp_opening_ns`. `None` is byte-identical to pre-#3527.
#[test]
fn session_timeout_ns_honors_opening_override() {
    let to = SessionTimeouts::default();
    let zone_opening = 5_000_000_000u64; // 5 s syn-flood timeout
    let app = 30_000_000_000u64; // 30 s established idle override

    // OPENING TCP (bare SYN): the per-zone override replaces the 20 s default.
    assert_eq!(
        session_timeout_ns(PROTO_TCP, crate::tcp_flags::TCP_SYN, false, &to, None, Some(zone_opening)),
        zone_opening,
        "an OPENING half-open session must reap on the per-zone syn-flood timeout"
    );
    // The app (established) override does NOT leak into the opening window —
    // the zone opening override still wins there.
    assert_eq!(
        session_timeout_ns(
            PROTO_TCP,
            crate::tcp_flags::TCP_SYN,
            false,
            &to,
            Some(app),
            Some(zone_opening),
        ),
        zone_opening
    );
    // None -> the global opening window (pre-#3527 behavior).
    assert_eq!(
        session_timeout_ns(PROTO_TCP, crate::tcp_flags::TCP_SYN, false, &to, None, None),
        DEFAULT_TCP_OPENING_TIMEOUT_NS
    );
    // ESTABLISHED: the opening override must NOT touch the established window.
    assert_eq!(
        session_timeout_ns(PROTO_TCP, 0x10, true, &to, None, Some(zone_opening)),
        DEFAULT_TCP_SESSION_TIMEOUT_NS
    );
    // Closing / RST: the opening override must NOT extend the short reap window.
    assert_eq!(
        session_timeout_ns(PROTO_TCP, TCP_FIN, false, &to, None, Some(zone_opening)),
        TCP_CLOSING_TIMEOUT_NS
    );
    assert_eq!(
        session_timeout_ns(PROTO_TCP, TCP_RST, false, &to, None, Some(zone_opening)),
        TCP_RST_TIMEOUT_NS
    );
}

/// #3227 end-to-end: a session admitted by an application with a custom
/// `inactivity-timeout` (30 s) expires after that timeout — well before the
/// global 300 s TCP-established timeout. This is the fail-on-revert anchor:
/// drop the per-app stamp/read and this session survives to 300 s, so the
/// 35 s expiry assertion goes RED.
#[test]
fn session_with_app_inactivity_timeout_expires_before_global() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    // Custom 30 s app idle timeout (global TCP-established is 300 s).
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata_with_app_timeout(30 * WHEEL_TICK_NS),
        install_ns,
        PROTO_TCP,
        0x10, // ACK = established, not closing
    ));
    // Advance to install + 35 s: past the 30 s app timeout, far short of 300 s.
    let advance = install_ns + 35 * WHEEL_TICK_NS;
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert_eq!(
        expired.len(),
        1,
        "session must expire on the 30 s app inactivity-timeout, not the 300 s global timeout"
    );
    assert_eq!(expired[0].key, key);
    assert!(table.lookup(&key, advance + 1_000_000, 0).is_none());
}

/// #3227 regression: an application with NO custom inactivity-timeout (the
/// metadata override is `None`) ages on the global per-protocol timeout exactly
/// as before — it must NOT expire at 35 s, and DOES expire past the global
/// timeout. Uses UDP (60 s global, inside the 256-tick wheel) so a single GC
/// pass observes the global-timeout expiry without far-future re-bucketing.
#[test]
fn session_without_app_timeout_uses_global_timeout() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(), // inactivity_timeout_ns: None
        install_ns,
        PROTO_UDP,
        0,
    ));
    // 35 s in: still alive on the 60 s global UDP timeout.
    let early = install_ns + 35 * WHEEL_TICK_NS;
    table.last_gc_ns = early - SESSION_GC_INTERVAL_NS;
    assert!(
        table.expire_stale_entries(early).is_empty(),
        "no per-app timeout: must survive past 35 s on the global 60 s timeout"
    );
    // NB: do not lookup() here — a lookup refreshes last_seen and would extend
    // the idle window past the global timeout, masking the expiry below.
    // Past the global 60 s timeout: now it expires.
    let late = install_ns + 65 * WHEEL_TICK_NS;
    table.last_gc_ns = late - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(late);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].key, key);
}

// === #965 timer-wheel tests =================================

fn make_v4_key(src_octet: u8, port: u16) -> SessionKey {
    SessionKey {
        addr_family: 2,
        protocol: PROTO_UDP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, src_octet)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: port,
        dst_port: 53,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

/// Wheel pop expires an entry whose bucket the cursor advances past.
#[test]
fn wheel_pops_expired_entry_from_bucket() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    // UDP default timeout is 60 s. Advance past it; bypass GC gate.
    let advance = install_ns + 65 * WHEEL_TICK_NS;
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].key, key);
    assert!(table.lookup(&key, advance + 1_000_000, 0).is_none());
}

/// A touched entry is not popped from the wheel — its canonical
/// wheel_tick advanced, so the old bucket entry is dropped as stale
/// and the new bucket holds the live entry.
#[test]
fn wheel_skips_touched_entry() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    // Touch at install_ns + 30s — pushes the expiration target tick
    // forward by 30 (from install+60 to install+90).
    let touch_ns = install_ns + 30 * WHEEL_TICK_NS;
    table.touch(&key, touch_ns);
    // Advance past the ORIGINAL bucket (install+60) but not past
    // the new one (install+90). Bypass GC gate.
    let advance = install_ns + 65 * WHEEL_TICK_NS;
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert!(
        expired.is_empty(),
        "touched session should not expire yet; got {:?}",
        expired
    );
    assert!(table.lookup(&key, advance + 1_000_000, 0).is_some());
}

/// A timeout > 256 s lands in the FAR_FUTURE bucket; when popped,
/// re-checks expiration and re-buckets if still alive.
#[test]
fn wheel_handles_long_timeout_via_far_future_bucket() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    // 7200 s timeout — far longer than the 256-s wheel.
    let long_timeout_secs = 7200u64;
    let mut t = SessionTimeouts::default();
    t.udp_ns = long_timeout_secs * WHEEL_TICK_NS;
    table.set_timeouts(t);
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    // Advance 300 s — past one full rotation but well before the
    // real timeout. Bypass GC gate at every check.
    let advance = install_ns + 300 * WHEEL_TICK_NS;
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert!(
        expired.is_empty(),
        "long-timeout session must not expire prematurely"
    );
    // Advance past the real timeout — should now expire.
    let final_advance = install_ns + (long_timeout_secs + 5) * WHEEL_TICK_NS;
    table.last_gc_ns = final_advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(final_advance);
    assert_eq!(expired.len(), 1);
}

/// Entry with `expires_after = WHEEL_BUCKETS * TICK_NS` lands in
/// the FAR_FUTURE bucket (now_tick + 255), not the current bucket.
#[test]
fn wheel_handles_exact_256s_timeout() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    let mut t = SessionTimeouts::default();
    t.udp_ns = (WHEEL_BUCKETS as u64) * WHEEL_TICK_NS; // exactly 256 s
    table.set_timeouts(t);
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    // Verify the entry's wheel_tick is install_tick + 255, NOT
    // install_tick (which would mean "current bucket").
    let entry = table.entry_by_key(&key).expect("entry");
    let install_tick = install_ns / WHEEL_TICK_NS;
    assert_eq!(
        entry.wheel_tick,
        install_tick + FAR_FUTURE_OFFSET,
        "256-s timeout must land in FAR_FUTURE bucket, not current"
    );
}

/// First GC with a large monotonic now_ns must not walk billions
/// of empty buckets — wheel_observe lazily initializes cursor_tick
/// to the first observed now_tick.
#[test]
fn first_gc_with_large_monotonic_now_doesnt_walk_billions_of_buckets() {
    let mut table = SessionTable::new();
    // 10^18 ns = a typical CLOCK_MONOTONIC value after ~31 years.
    let huge_now = 1_000_000_000_000_000_000u64;
    // Should return immediately, no panic, no infinite loop.
    let expired = table.expire_stale_entries(huge_now);
    assert!(expired.is_empty());
    // Wheel should be initialized at the huge tick.
    assert!(table.wheel.initialized);
    assert_eq!(table.wheel.cursor_tick, huge_now / WHEEL_TICK_NS);
}

/// Sub-tick precision: at exactly `last_seen + expires_after`, the
/// session is NOT expired (matches today's strict `>` semantics).
/// This test exists in addition to the v8 sub-tick lag test.
#[test]
fn expiry_boundary_strict_greater_than() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    let mut t = SessionTimeouts::default();
    t.udp_ns = 1_000_000_000; // 1 s
    table.set_timeouts(t);
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    // Exactly at last_seen + expires_after: NOT expired.
    let at_boundary = install_ns + 1_000_000_000;
    table.last_gc_ns = at_boundary - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(at_boundary);
    assert!(
        expired.is_empty(),
        "exact-boundary entry must not expire under strict `>`"
    );
}

/// Wheel adds at most one tick of additional lag vs today's
/// hypothetical sub-tick scan. At +1 ns the wheel reports
/// not-yet-expired; at +TICK_NS+1 it reports expired.
#[test]
fn wheel_lags_today_subtick_by_at_most_one_tick() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    let mut t = SessionTimeouts::default();
    t.udp_ns = 1_000_000_000; // 1 s
    table.set_timeouts(t);
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    // +1 ns past expiration: wheel hasn't popped the bucket yet
    // (cursor < now_tick is still false at this sub-tick offset).
    let just_past = install_ns + 1_000_000_000 + 1;
    table.last_gc_ns = just_past - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(just_past);
    assert!(
        expired.is_empty(),
        "wheel may lag today's sub-tick scan by up to 1 tick"
    );
    // +1 wheel-tick + 1 ns past expiration: wheel MUST have caught
    // it. The cursor advances when now_tick advances.
    let one_tick_past = install_ns + 1_000_000_000 + WHEEL_TICK_NS + 1;
    table.last_gc_ns = one_tick_past - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(one_tick_past);
    assert_eq!(
        expired.len(),
        1,
        "wheel must pop the entry once cursor advances one tick past target"
    );
}

/// Session touched 100 times within a single tick produces at most
/// 2 wheel entries (the initial install push + at most one re-push
/// if the expiration tick changed). Throttle bounds duplicates.
#[test]
fn wheel_duplicate_count_per_session_bounded() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    // Touch 100 times within the same wheel tick (sub-second).
    for i in 0..100u64 {
        table.touch(&key, install_ns + i * 1_000_000); // 1 ms steps
    }
    // Count wheel entries for this key.
    let count: usize = table
        .wheel
        .buckets
        .iter()
        .map(|b| b.iter().filter(|e| e.key == key).count())
        .sum();
    assert!(
        count <= 2,
        "same-tick touches should produce <=2 wheel entries; got {}",
        count
    );
}

/// 50K sessions all expiring at the same tick: a single GC call
/// drains all of them from the popped bucket. No per-tick cap.
#[test]
fn wheel_sustained_overload_drains_all_buckets() {
    let mut table = SessionTable::new();
    let install_ns = 1_000_000_000u64;
    // Use 5K (not 50K) to keep test runtime sub-second; the
    // assertion is about behavior shape, not absolute capacity.
    const N: usize = 5000;
    // Default UDP timeout is 60s. Install all sessions at the
    // same install_ns so they share an expiration tick.
    for i in 0..N {
        let k = make_v4_key((i % 250) as u8, 1024 + (i / 250) as u16);
        assert!(table.install_with_protocol(
            k,
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
    }
    let advance = install_ns + 65 * WHEEL_TICK_NS;
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert_eq!(expired.len(), N, "all sessions must drain in one call");
    assert_eq!(table.len(), 0);
}

/// Alias path: lookup_with_origin called on a NAT-translated
/// reverse alias key resolves to the canonical forward key (via
/// reverse_translated_index), then pushes the CANONICAL key into
/// the wheel — never the alias. Round-3/4 of plan iteration caught
/// that the .map(|entry| { ... self.wheel ... }) shape wouldn't
/// compile; this test additionally validates the runtime
/// invariant that the canonical key, not the alias, lands in the
/// wheel after a sub-tick advance.
#[test]
fn wheel_alias_lookup_refreshes_canonical_key() {
    let mut table = SessionTable::new();
    // Install a forward session with NAT rewrite_dst so that the
    // alias index gets populated automatically by index_forward_nat_key.
    let canonical_key = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42)),
        src_port: 5201,
        dst_port: 42424,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let alias_key = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 5201,
        dst_port: 42424,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    let nat = SessionDecision {
        resolution: resolution(),
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        canonical_key.clone(),
        nat,
        reverse_metadata,
        install_ns,
        PROTO_TCP,
        0x10,
    ));
    // Sanity: install pushed the canonical key to its bucket.
    let initial_canonical_count: usize = table
        .wheel
        .buckets
        .iter()
        .map(|b| b.iter().filter(|e| e.key == canonical_key).count())
        .sum();
    assert_eq!(initial_canonical_count, 1, "install pushed canonical");
    let initial_alias_count: usize = table
        .wheel
        .buckets
        .iter()
        .map(|b| b.iter().filter(|e| e.key == alias_key).count())
        .sum();
    assert_eq!(initial_alias_count, 0, "alias key MUST NOT be in wheel");
    // Now look up via the ALIAS, advancing the canonical entry's
    // expiration tick by enough to cross the second-grid (so the
    // throttle fires a new push).
    let lookup_ns = install_ns + 2 * WHEEL_TICK_NS;
    let hit = table.lookup_with_origin(&alias_key, lookup_ns, 0x10);
    assert!(hit.is_some(), "alias lookup must hit");
    // Wheel state after alias lookup: canonical key has a NEW
    // entry (the one pushed by lookup_with_origin); alias key
    // STILL has no entries.
    let canonical_count: usize = table
        .wheel
        .buckets
        .iter()
        .map(|b| b.iter().filter(|e| e.key == canonical_key).count())
        .sum();
    assert!(
        canonical_count >= 2,
        "alias lookup must push a fresh wheel entry under the canonical key; \
         canonical_count={}",
        canonical_count
    );
    let alias_count: usize = table
        .wheel
        .buckets
        .iter()
        .map(|b| b.iter().filter(|e| e.key == alias_key).count())
        .sum();
    assert_eq!(
        alias_count, 0,
        "alias key MUST never appear in any bucket; alias_count={}",
        alias_count
    );
}

/// Sustained per-second touch on every session: K (entries
/// scanned per popped bucket) is bounded by N, and pop
/// classification matches the plan's expected pattern: every
/// scanned entry is a stale duplicate (entries_dropped_stale ≈ K),
/// no entries get re-bucketed (sessions are kept alive by
/// per-second touches that update wheel_tick), and no entries
/// expire.
///
/// This is the per-second-touch K-bound from §Acceptance gate 4b
/// (corrected per Codex round-7 #2 classifications and round-12
/// instrumentation requirement).
///
/// Test scale: N = 1000 (smaller than the 10K plan target to keep
/// CI runtime under 1 s; the assertion shape is what matters).
#[test]
fn wheel_per_second_touch_bounds_k_per_bucket() {
    let mut table = SessionTable::new();
    const N: usize = 1000;
    let install_ns = 1_000_000_000u64;
    // Install N sessions, each at a distinct sub-tick install
    // offset so they spread across buckets after warm-up.
    let keys: Vec<SessionKey> = (0..N)
        .map(|i| make_v4_key((i % 250) as u8, 1024 + (i / 250) as u16))
        .collect();
    for (i, k) in keys.iter().enumerate() {
        assert!(table.install_with_protocol(
            k.clone(),
            decision(),
            metadata(),
            install_ns + (i as u64) * 1_000, // 1 µs spacing
            PROTO_UDP,
            0
        ));
    }
    // Warm-up: touch every session once per tick for ≥ 300 ticks
    // so the wheel reaches steady state under per-second touch on
    // every session. After each touch round, run GC at the
    // matching tick.
    const WARMUP_TICKS: u64 = 300;
    for tick_off in 1..=WARMUP_TICKS {
        let now = install_ns + tick_off * WHEEL_TICK_NS;
        for k in &keys {
            table.touch(k, now);
        }
        table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
        let _ = table.expire_stale_entries(now);
    }
    // Measurement tick: advance one more, capture the next pop's
    // stats via last_pop_stats().
    let measure_now = install_ns + (WARMUP_TICKS + 1) * WHEEL_TICK_NS;
    for k in &keys {
        table.touch(k, measure_now);
    }
    table.last_gc_ns = measure_now - SESSION_GC_INTERVAL_NS;
    let _ = table.expire_stale_entries(measure_now);
    let stats = table.last_pop_stats();

    // §Acceptance gate 4b classifications under sustained per-
    // second touch: every popped entry is stale duplicate, no
    // re-bucketing, no expirations.
    assert!(
        stats.scanned > 0,
        "must have scanned entries; stats={:?}",
        stats
    );
    // K bound: scanned ≤ N × 1.2 (20 % headroom — a 2× duplicate-
    // push regression would scan >2 N and fail this).
    let k_bound = (N as f64 * 1.2) as usize;
    assert!(
        stats.scanned <= k_bound,
        "K (scanned) must be bounded by N×1.2 = {}; got scanned={} stats={:?}",
        k_bound,
        stats.scanned,
        stats
    );
    // No re-bucketing under sustained-per-tick touch: each
    // session's canonical wheel_tick advances every tick, so all
    // popped entries with stale `scheduled_tick != wheel_tick`
    // hit the dropped_stale path, not re-bucket.
    assert_eq!(
        stats.re_bucketed, 0,
        "expected 0 re-bucketed under per-second touch; stats={:?}",
        stats
    );
    assert_eq!(
        stats.expired, 0,
        "expected 0 expirations under per-second touch; stats={:?}",
        stats
    );
    // dropped_stale + dropped_gone + expired + re_bucketed = scanned.
    assert_eq!(
        stats.dropped_stale + stats.dropped_gone + stats.expired + stats.re_bucketed,
        stats.scanned,
        "case classification must sum to scanned; stats={:?}",
        stats
    );
    // dropped_stale dominates (the lazy-delete discriminator is
    // the right path for this workload).
    assert!(
        stats.dropped_stale >= stats.scanned * 9 / 10,
        "expected dropped_stale ≈ scanned (≥90 %); stats={:?}",
        stats
    );
}

/// Across one full wheel rotation under sustained per-second
/// touch, the total number of entries scanned ≈ 256 × N (every
/// bucket pops N stale duplicates). Catches leakage of stale
/// entries that the lazy-delete discriminator should drop on
/// visit but didn't.
#[test]
fn wheel_per_second_touch_total_scan_per_rotation_matches_model() {
    let mut table = SessionTable::new();
    const N: usize = 500;
    let install_ns = 1_000_000_000u64;
    let keys: Vec<SessionKey> = (0..N)
        .map(|i| make_v4_key((i % 250) as u8, 1024 + (i / 250) as u16))
        .collect();
    for (i, k) in keys.iter().enumerate() {
        assert!(table.install_with_protocol(
            k.clone(),
            decision(),
            metadata(),
            install_ns + (i as u64) * 1_000,
            PROTO_UDP,
            0
        ));
    }
    // Warm up beyond one full rotation so steady-state holds.
    const WARMUP_TICKS: u64 = 300;
    for tick_off in 1..=WARMUP_TICKS {
        let now = install_ns + tick_off * WHEEL_TICK_NS;
        for k in &keys {
            table.touch(k, now);
        }
        table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
        let _ = table.expire_stale_entries(now);
    }
    // Now measure across exactly WHEEL_BUCKETS=256 ticks.
    let mut total_scanned = 0usize;
    for tick_off in 1..=WHEEL_BUCKETS as u64 {
        let now = install_ns + (WARMUP_TICKS + tick_off) * WHEEL_TICK_NS;
        for k in &keys {
            table.touch(k, now);
        }
        table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
        let _ = table.expire_stale_entries(now);
        total_scanned += table.last_pop_stats().scanned;
    }
    // Plan §Acceptance gate 4b: total_scanned ∈ [0.9, 1.1] × 256 × N.
    let model = WHEEL_BUCKETS * N;
    let lower = (model as f64 * 0.9) as usize;
    let upper = (model as f64 * 1.1) as usize;
    assert!(
        (lower..=upper).contains(&total_scanned),
        "total_scanned ({}) must be within ±10% of model ({}); range [{}, {}]",
        total_scanned,
        model,
        lower,
        upper
    );
}

#[test]
fn expire_stale_entries_returns_helper_only_local_sessions() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let local_metadata = metadata();
    let local_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            ..resolution()
        },
        nat: NatDecision::default(),
    };
    // Install with SyncImport origin to mark as peer-synced
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        local_decision,
        local_metadata.clone(),
        SessionOrigin::SyncImport,
        then,
        PROTO_TCP,
        0x10,
    ));
    table.last_gc_ns = then + 301_000_000_000;
    let expired = table.expire_stale_entries(then + 302_000_000_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].key, key);
    assert_eq!(expired[0].decision, local_decision);
    assert_eq!(expired[0].metadata, local_metadata);
    assert!(table.drain_deltas(8).is_empty());
}

#[test]
fn take_synced_local_only_removes_helper_local_sessions() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    let local_metadata = metadata();
    let local_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            ..resolution()
        },
        nat: NatDecision::default(),
    };
    // Install with SyncImport origin so it's considered peer-synced
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        local_decision,
        local_metadata.clone(),
        SessionOrigin::SyncImport,
        now,
        PROTO_TCP,
        0x10,
    ));
    let removed = table
        .take_synced_local(&key)
        .expect("local session removed");
    assert_eq!(removed.decision, local_decision);
    assert_eq!(removed.metadata, local_metadata);
    assert!(table.lookup(&key, now + 1_000_000, 0x10).is_none());

    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x10,
    ));
    assert!(table.take_synced_local(&key).is_none());
    assert!(table.lookup(&key, now + 1_000_000, 0x10).is_some());
}

#[test]
fn tcp_fin_keeps_session_until_closing_timeout() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x10
    ));
    let _ = table.drain_deltas(8);
    let hit = table.lookup(&key, now + 1_000_000, TCP_FIN);
    assert_eq!(
        hit,
        Some(SessionLookup {
            decision: decision(),
            metadata: metadata(),
        })
    );
    // #9412: the FIN moves the session to CLOSING, which is announced once so
    // the peer's copy reaps on the same window.
    let closing = table.drain_deltas(8);
    assert_eq!(
        closing.iter().map(|d| (d.kind, d.tcp_close_class)).collect::<Vec<_>>(),
        vec![(SessionDeltaKind::Update, 1)]
    );
    assert!(table.lookup(&key, now + 2_000_000, 0x10).is_some());
    table.last_gc_ns = now + TCP_CLOSING_TIMEOUT_NS;
    let expired = table.expire_stale(now + TCP_CLOSING_TIMEOUT_NS + 1_000_000_000);
    assert_eq!(expired, 1);
    assert!(
        table
            .lookup(&key, now + TCP_CLOSING_TIMEOUT_NS + 2_000_000_000, 0)
            .is_none()
    );
    let deltas = table.drain_deltas(8);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, key);
}

#[test]
fn tcp_rst_uses_short_timeout_not_fin_timeout() {
    // #3046 FAIL-ON-REVERT: a RST'd TCP session must be reaped on the short
    // TCP_RST_TIMEOUT_NS, while a FIN-only graceful close keeps the 30s
    // TCP_CLOSING_TIMEOUT_NS. If the RST timeout selection reverts to the FIN
    // closing timeout (the #3046 bug — is_closing lumps RST with FIN at 30s)
    // the first expires_after_ns assert below RED-fails.
    assert!(
        TCP_RST_TIMEOUT_NS < TCP_CLOSING_TIMEOUT_NS,
        "RST timeout must be strictly shorter than the FIN close timeout"
    );
    let now = 1_000_000_000u64;

    // --- RST path: short timeout ---
    let mut table = SessionTable::new();
    let key = key_v4();
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x10
    ));
    let _ = table.drain_deltas(8);
    assert!(table.lookup(&key, now + 1_000_000, TCP_RST).is_some());
    let rst_entry = table.entry_by_key(&key).expect("rst entry");
    assert!(rst_entry.closing, "RST must mark the session closing");
    assert!(rst_entry.reset, "RST must set the sticky reset flag");
    assert_eq!(
        rst_entry.expires_after_ns, TCP_RST_TIMEOUT_NS,
        "RST'd session must use the short RST timeout, not the 30s FIN close timeout"
    );

    // --- FIN path (control): full 30s close timeout, no reset ---
    let mut table2 = SessionTable::new();
    let key2 = key_v4();
    assert!(table2.install_with_protocol(
        key2.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x10
    ));
    let _ = table2.drain_deltas(8);
    assert!(table2.lookup(&key2, now + 1_000_000, TCP_FIN).is_some());
    let fin_entry = table2.entry_by_key(&key2).expect("fin entry");
    assert!(fin_entry.closing, "FIN must mark the session closing");
    assert!(!fin_entry.reset, "FIN-only close must NOT set the reset flag");
    assert_eq!(
        fin_entry.expires_after_ns, TCP_CLOSING_TIMEOUT_NS,
        "FIN-only close must keep the 30s graceful close timeout"
    );

    // --- stickiness: a reordered non-RST segment after the RST must NOT
    //     promote the entry back to the 30s FIN close window ---
    assert!(table.lookup(&key, now + 2_000_000, 0x10).is_some());
    let post_ack = table.entry_by_key(&key).expect("rst entry post-ack");
    assert_eq!(
        post_ack.expires_after_ns, TCP_RST_TIMEOUT_NS,
        "a stray non-RST segment after a RST must not revert to the 30s FIN timeout"
    );

    // --- update_session sticky-reset (#3046 MINOR FAIL-ON-REVERT): a session
    //     that already carries reset=true, refreshed via update_session with a
    //     non-RST FIN trigger (the promote_synced_with_origin production reach),
    //     must KEEP the short 2s RST timeout. RED if update_session selects the
    //     timeout from only the current segment's flags
    //     (session_timeout_ns(FIN) == 30s) instead of consulting the sticky
    //     entry.reset — exactly mirroring the lookup.rs path.
    let fin_req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: now + 3_000_000,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FIN,
    };
    assert!(table.update_session(fin_req, false));
    let after_update = table.entry_by_key(&key).expect("entry after update_session");
    assert!(
        after_update.reset,
        "reset must stay sticky across an update_session refresh"
    );
    assert!(after_update.closing, "FIN keeps the session closing");
    assert_eq!(
        after_update.expires_after_ns, TCP_RST_TIMEOUT_NS,
        "update_session must consult the sticky reset flag: a non-RST FIN refresh of a RST'd session keeps the 2s timeout, not 30s"
    );
}

#[test]
fn closing_flag_is_sticky_across_nonclosing_update() {
    // #3489 FAIL-ON-REVERT: once a FIN moves a TCP session into the short 30s
    // TCP_CLOSING_TIMEOUT_NS close window, a subsequent NON-closing segment
    // (e.g. a reordered data-ACK, flags=0x10) refreshing the entry through
    // update_session MUST keep `closing` set and keep the 30s window — it must
    // NOT revert to the 300s established idle window. This is independent of the
    // in-place-vs-reference parity sweep (which is blinded by the reference
    // helper mirroring the same flag logic): it asserts the production
    // update_session path directly. Reverting mod.rs:1040 from `|=` to `=`
    // makes this test RED.
    assert!(
        TCP_CLOSING_TIMEOUT_NS < DEFAULT_TCP_SESSION_TIMEOUT_NS,
        "close window must be strictly shorter than the established window"
    );
    let now = 1_000_000_000u64;
    let mut table = SessionTable::new();
    let key = key_v4();

    // 1) Establish the session (carry ACK so it is ESTABLISHED, not OPENING —
    //    this is the state that would otherwise win the 300s window if closing
    //    were reverted).
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        TCP_ACK,
    ));
    let _ = table.drain_deltas(8);

    // 2) FIN seen on the forward half via update_session -> closing=true, 30s.
    let fin_req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FIN | TCP_ACK,
    };
    assert!(table.update_session(fin_req, false));
    let after_fin = table.entry_by_key(&key).expect("entry after FIN");
    assert!(after_fin.closing, "FIN must mark the session closing");
    assert!(!after_fin.reset, "FIN-only close must not set the reset flag");
    assert_eq!(
        after_fin.expires_after_ns, TCP_CLOSING_TIMEOUT_NS,
        "a FIN'd session must use the 30s close window"
    );

    // 3) A later NON-closing data-ACK (flags=0x10) refreshes the entry. The
    //    closing flag must stay sticky and the 30s window must persist. With
    //    the pre-#3489 non-sticky `=`, closing would flip to false here and the
    //    expires window would jump to the 300s established timeout.
    let ack_req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: now + 2_000_000,
        protocol: PROTO_TCP,
        tcp_flags: TCP_ACK,
    };
    assert!(table.update_session(ack_req, false));
    let after_ack = table.entry_by_key(&key).expect("entry after stray ACK");
    assert!(
        after_ack.closing,
        "a non-closing segment after a FIN must NOT clear the sticky closing flag (#3489)"
    );
    assert_eq!(
        after_ack.expires_after_ns, TCP_CLOSING_TIMEOUT_NS,
        "a FIN'd session refreshed by a stray non-closing segment must keep the \
         30s close window, not revert to the 300s established window (#3489)"
    );
}

/// #3489: the same stickiness must hold on the HA shared-promote path. A
/// peer-synced FIN'd session promoted to local ownership by a non-closing
/// forward segment (`update_session(.., ha_activation=true)`) must keep
/// `closing` and the 30s window — this is the exact production sequence the
/// bug report describes.
#[test]
fn closing_flag_is_sticky_on_ha_promote() {
    let now = 1_000_000_000u64;
    let mut table = SessionTable::new();
    let key = key_v4();

    // Install a peer-synced (standby) session that has already seen a FIN.
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::SyncImport,
        now,
        PROTO_TCP,
        TCP_FIN | TCP_ACK,
    ));
    let synced = table.entry_by_key(&key).expect("synced entry");
    assert!(synced.closing, "peer-synced FIN'd entry must be closing");
    assert_eq!(synced.expires_after_ns, TCP_CLOSING_TIMEOUT_NS);
    let _ = table.drain_deltas(8);

    // HA promote: a non-closing forward data-ACK takes local ownership.
    let promote_req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: TCP_ACK,
    };
    assert!(table.update_session(promote_req, true));
    let after = table.entry_by_key(&key).expect("entry after HA promote");
    assert!(
        after.closing,
        "an HA promote by a non-closing segment must keep the sticky closing flag (#3489)"
    );
    assert_eq!(
        after.expires_after_ns, TCP_CLOSING_TIMEOUT_NS,
        "an HA-promoted FIN'd session must keep the 30s close window (#3489)"
    );
}

/// #3152 FAIL-ON-REVERT: a TCP session created by a bare SYN (SYN set, ACK
/// clear) must start in the OPENING (half-open) state and take the short
/// `tcp_opening_ns` window, NOT the full established timeout. If the opening
/// state machine is reverted (a bare SYN routes to `tcp_established_ns`),
/// the `expires_after_ns` assert below RED-fails.
#[test]
fn bare_syn_session_starts_opening_with_short_timeout() {
    assert!(
        DEFAULT_TCP_OPENING_TIMEOUT_NS < DEFAULT_TCP_SESSION_TIMEOUT_NS,
        "opening window must be strictly shorter than the established window"
    );
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    // Bare SYN: SYN set, ACK clear — a connection-opening segment.
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    let entry = table.entry_by_key(&key).expect("opening entry");
    assert!(
        !entry.established,
        "a bare-SYN session must start OPENING (handshake incomplete)"
    );
    assert_eq!(
        entry.expires_after_ns, DEFAULT_TCP_OPENING_TIMEOUT_NS,
        "a bare-SYN (half-open) session must use the short opening timeout, \
         not the established timeout"
    );
}

/// #3152/#4109: a completed three-way handshake (SYN, SYN-ACK, ACK) promotes
/// the session from OPENING to ESTABLISHED, at which point the established idle
/// timeout applies. Modelled on the production TWO-entry conntrack (forward +
/// reverse companion, #4109): the server's SYN-ACK arrives on the REVERSE half
/// and promotes both companions; the forward completing ACK then re-stamps the
/// forward entry's established idle window. Promotion is sticky.
#[test]
fn tcp_handshake_promotes_opening_to_established() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    // 1) Opening SYN installs BOTH the forward entry and its reverse companion;
    //    a bare SYN starts both OPENING.
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    assert!(!table.entry_by_key(&forward).expect("opening fwd").established);
    assert!(!table.entry_by_key(&reverse).expect("opening rev").established);
    // 2) Reverse SYN-ACK (server's handshake response, carries ACK on the
    //    reverse half). It promotes the reverse companion AND, via #4109
    //    companion propagation, the forward entry.
    assert!(
        table
            .lookup(&reverse, now + 1_000_000, TCP_SYN | TCP_ACK)
            .is_some()
    );
    assert!(
        table
            .entry_by_key(&reverse)
            .expect("rev after synack")
            .established,
        "the reverse SYN-ACK promotes the reverse companion"
    );
    assert!(
        table
            .entry_by_key(&forward)
            .expect("fwd after synack")
            .established,
        "the reverse SYN-ACK promotes the forward companion too (#4109 F16)"
    );
    // 3) Forward completing ACK re-stamps the (already established) forward
    //    entry's idle window.
    assert!(table.lookup(&forward, now + 2_000_000, TCP_ACK).is_some());
    let entry = table.entry_by_key(&forward).expect("established entry");
    assert!(
        entry.established,
        "a completed 3-way handshake must promote the session to ESTABLISHED"
    );
    assert_eq!(
        entry.expires_after_ns, table.timeouts.tcp_established_ns,
        "an established session must use the established idle timeout"
    );
    // Stickiness: a later non-ACK segment must not demote back to OPENING.
    assert!(table.lookup(&forward, now + 3_000_000, 0).is_some());
    assert!(
        table
            .entry_by_key(&forward)
            .expect("still established")
            .established,
        "establishment is sticky — a later segment must not revert to OPENING"
    );
}

/// #4109 F16 FAIL-ON-REVERT (security/DoS): a bare SYN followed by a
/// forward-direction bare ACK — with NO reverse SYN-ACK ever seen — must NOT
/// promote the session to ESTABLISHED. `has_ack` alone on the FORWARD half is
/// not handshake evidence; only the server's reverse SYN-ACK is. The forward
/// entry therefore stays OPENING on the short 20s opening window, so the #3152
/// half-open reap bounds a "SYN then bare-ACK" flood exactly like a bare-SYN
/// flood. Before #4109 the forward ACK promoted the entry to the 300s
/// established window (the 2-packet bypass); reverting makes the `established` /
/// `expires_after_ns` asserts RED.
fn forward_ack_without_reverse_synack_stays_opening(forward: SessionKey) {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    // A forward-direction bare ACK (the attacker, with no server reply).
    assert!(table.lookup(&forward, now + 1_000_000, TCP_ACK).is_some());
    let fwd = table.entry_by_key(&forward).expect("fwd entry");
    assert!(
        !fwd.established,
        "a client-only ACK with no reverse SYN-ACK must NOT establish (#4109 F16)"
    );
    assert_eq!(
        fwd.expires_after_ns, DEFAULT_TCP_OPENING_TIMEOUT_NS,
        "a half-open session pinged by a client-only ACK stays on the short opening window"
    );
    // The reverse companion, never having seen a reply, is likewise OPENING.
    assert!(
        !table
            .entry_by_key(&reverse)
            .expect("rev entry")
            .established
    );
    // Reap proof: past the 20s opening window both halves reap — neither pinned
    // the 300s established window.
    let advance = now + 25 * WHEEL_TICK_NS;
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert_eq!(
        expired.len(),
        2,
        "both half-open companions reap at the opening window, not the 300s established window"
    );
}

#[test]
fn forward_ack_without_reverse_synack_stays_opening_v4() {
    forward_ack_without_reverse_synack_stays_opening(key_v4());
}

#[test]
fn forward_ack_without_reverse_synack_stays_opening_v6() {
    forward_ack_without_reverse_synack_stays_opening(tcp_key_v6());
}

/// #4109 FAIL-ON-REVERT (Copilot fold): the promotion gate requires a GENUINE
/// reverse SYN-ACK (`is_syn_ack`), not merely any ACK-bearing reverse segment.
/// A bare reverse ACK (ACK set, SYN clear) during OPENING cannot occur in a
/// legitimate 3-way handshake — the server's only pre-established reverse
/// segment is the SYN-ACK — but a server-spoofing attacker could inject one; it
/// must NOT promote a half-open session to ESTABLISHED. Loosening the gate back
/// to `has_ack` makes both `established` asserts RED. A subsequent genuine
/// reverse SYN-ACK still promotes (control).
fn reverse_bare_ack_does_not_promote_opening(forward: SessionKey) {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);
    // A bare reverse ACK (ACK-only, no SYN) — not a handshake SYN-ACK.
    assert!(table.lookup(&reverse, now + 1_000_000, TCP_ACK).is_some());
    assert!(
        !table.entry_by_key(&reverse).expect("rev entry").established,
        "a bare reverse ACK (no SYN) must NOT promote the reverse companion (#4109)"
    );
    assert!(
        !table.entry_by_key(&forward).expect("fwd entry").established,
        "a bare reverse ACK must NOT promote the forward companion either (#4109)"
    );
    // Control: a genuine reverse SYN-ACK DOES promote both halves.
    assert!(
        table
            .lookup(&reverse, now + 2_000_000, TCP_SYN | TCP_ACK)
            .is_some()
    );
    assert!(
        table.entry_by_key(&reverse).expect("rev").established,
        "a genuine reverse SYN-ACK promotes the reverse companion"
    );
    assert!(
        table.entry_by_key(&forward).expect("fwd").established,
        "a genuine reverse SYN-ACK promotes the forward companion"
    );
}

#[test]
fn reverse_bare_ack_does_not_promote_opening_v4() {
    reverse_bare_ack_does_not_promote_opening(key_v4());
}

#[test]
fn reverse_bare_ack_does_not_promote_opening_v6() {
    reverse_bare_ack_does_not_promote_opening(tcp_key_v6());
}

/// #4109 F17 FAIL-ON-REVERT (correctness/DoS): a unidirectional RST seen on ONE
/// half of a flow must reap BOTH the forward entry and its reverse companion at
/// the short 2s RST window. Before #4109 only the matched half moved to the 2s
/// window; the other half stayed on the 300s established timeout, so the #3046
/// reset reap was ~50% effective under a reset workload (every RST-closed flow
/// still pinned one established-timeout entry). Reverting makes the companion's
/// `closing`/`reset`/`expires_after_ns` asserts RED (it lingers at 300s).
fn unidirectional_rst_reaps_both_companions(forward: SessionKey) {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    // Establish the flow (first packet carries ACK → both entries ESTABLISHED at
    // install, 300s window) so the RST has a full-timeout companion to
    // short-circuit.
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    assert!(table.entry_by_key(&forward).expect("fwd").established);
    assert!(table.entry_by_key(&reverse).expect("rev").established);
    // A RST arrives on the REVERSE direction only (e.g. the server resets).
    assert!(table.lookup(&reverse, now + 1_000_000, TCP_RST).is_some());
    // The matched (reverse) half is on the 2s RST window...
    let rev = table.entry_by_key(&reverse).expect("rev after rst");
    assert!(rev.closing && rev.reset, "matched half is closing+reset");
    assert_eq!(rev.expires_after_ns, TCP_RST_TIMEOUT_NS);
    // ...and so is the forward companion (#4109 F17 propagation).
    let fwd = table.entry_by_key(&forward).expect("fwd after rst");
    assert!(fwd.closing, "the companion inherits closing (#4109 F17)");
    assert!(fwd.reset, "the companion inherits reset (#4109 F17)");
    assert_eq!(
        fwd.expires_after_ns, TCP_RST_TIMEOUT_NS,
        "the companion reaps on the 2s RST window, not the 300s established window (#4109 F17)"
    );
    // Reap proof: shortly past the 2s window BOTH halves are gone.
    let advance = now + 1_000_000 + 4 * WHEEL_TICK_NS;
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert_eq!(
        expired.len(),
        2,
        "a unidirectional RST reaps BOTH companions at the short 2s window"
    );
}

#[test]
fn unidirectional_rst_reaps_both_companions_v4() {
    unidirectional_rst_reaps_both_companions(key_v4());
}

#[test]
fn unidirectional_rst_reaps_both_companions_v6() {
    unidirectional_rst_reaps_both_companions(tcp_key_v6());
}

/// #4109 F17 FAIL-ON-REVERT: a one-sided graceful FIN reaps BOTH companions at
/// the 30s close window (#3489), not just the matched half. Same propagation as
/// the RST case but on the longer FIN window and without the reset flag.
fn unidirectional_fin_reaps_both_companions(forward: SessionKey) {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    // A FIN arrives on the FORWARD direction only.
    assert!(table.lookup(&forward, now + 1_000_000, TCP_FIN).is_some());
    let fwd = table.entry_by_key(&forward).expect("fwd after fin");
    assert!(fwd.closing && !fwd.reset, "matched half is FIN-closing, not reset");
    assert_eq!(fwd.expires_after_ns, TCP_CLOSING_TIMEOUT_NS);
    // The reverse companion inherits the FIN close window (#4109 F17).
    let rev = table.entry_by_key(&reverse).expect("rev after fin");
    assert!(rev.closing, "the companion inherits closing (#4109 F17)");
    assert!(
        !rev.reset,
        "a graceful FIN must not set the companion's reset flag"
    );
    assert_eq!(
        rev.expires_after_ns, TCP_CLOSING_TIMEOUT_NS,
        "the companion reaps on the 30s FIN window, not the 300s established window (#4109 F17)"
    );
    // Reap proof: past the 30s window BOTH halves are gone.
    let advance = now + 1_000_000 + 33 * WHEEL_TICK_NS;
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert_eq!(
        expired.len(),
        2,
        "a unidirectional FIN reaps BOTH companions at the 30s close window"
    );
}

#[test]
fn unidirectional_fin_reaps_both_companions_v4() {
    unidirectional_fin_reaps_both_companions(key_v4());
}

#[test]
fn unidirectional_fin_reaps_both_companions_v6() {
    unidirectional_fin_reaps_both_companions(tcp_key_v6());
}

/// #4109 negative control: an ALREADY-ESTABLISHED flow's forward ACK must not
/// be disturbed by the F16 promotion gate — it stays ESTABLISHED on the 300s
/// window. Guards against the gate accidentally demoting or shortening a
/// legitimately established session.
#[test]
fn established_flow_forward_ack_unaffected() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    // First packet carries ACK (mid-stream pickup) → ESTABLISHED at install.
    let _reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    assert!(table.entry_by_key(&forward).expect("established").established);
    // A later forward data-ACK keeps it established on the 300s window.
    assert!(table.lookup(&forward, now + 1_000_000, TCP_ACK).is_some());
    let entry = table.entry_by_key(&forward).expect("still established");
    assert!(
        entry.established,
        "an established flow's forward ACK must not demote it (#4109 F16 gate)"
    );
    assert_eq!(
        entry.expires_after_ns, table.timeouts.tcp_established_ns,
        "an established flow's forward ACK keeps the 300s established idle window"
    );
}

/// #3152 FAIL-ON-REVERT (reap proof): a half-open (bare-SYN) session that
/// never completes its handshake must be reaped at the short opening timeout
/// (20 s), far short of the 300 s established timeout — the SYN-flood
/// resource-exhaustion mitigation. A control established session installed at
/// the same instant must survive past the opening window. Revert the state
/// machine and the half-open session inherits the 300 s timeout, so the
/// `expired.len() == 1` assertion goes RED.
#[test]
fn half_open_session_reaps_at_opening_timeout() {
    let install_ns = 1_000_000_000u64;
    // Past the 20 s opening window, far short of the 300 s established window.
    let advance = install_ns + 25 * WHEEL_TICK_NS;

    // --- half-open (bare SYN, never completes): reaps at the opening window ---
    let mut table = SessionTable::new();
    let key = key_v4();
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_TCP,
        TCP_SYN,
    ));
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert_eq!(
        expired.len(),
        1,
        "a half-open (bare-SYN) session must reap at the short opening timeout, \
         not survive to the established timeout"
    );
    assert_eq!(expired[0].key, key);

    // --- control: an ESTABLISHED session survives past the opening window ---
    let mut table2 = SessionTable::new();
    let key2 = key_v4();
    // First packet carries ACK (a mid-stream pickup / non-bare-SYN) -> ESTABLISHED.
    assert!(table2.install_with_protocol(
        key2.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_TCP,
        TCP_ACK,
    ));
    table2.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    assert!(
        table2.expire_stale_entries(advance).is_empty(),
        "an established session must survive past the short opening window on the \
         established timeout"
    );
}

/// `metadata()` for a specific ingress zone id — used by the #3527 per-zone
/// half-open override tests.
fn metadata_with_zone(zone: u16) -> SessionMetadata {
    SessionMetadata {
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        ingress_zone: zone,
        ..metadata()
    }
}

/// #3527 FAIL-ON-REVERT: a bare-SYN (half-open) session in a zone with a
/// configured `syn-flood timeout` must reap on that per-zone window, not the
/// 20 s global default. The override (5 s) is shorter than the global opening
/// window, so the half-open reaps by 6 s while a control session in an
/// un-screened zone (global 20 s window) survives. Revert the enforcement
/// (`session_timeout_ns` ignores the override, or `set_opening_overrides`
/// never reaches the install) and the override session inherits the 20 s
/// default, surviving at 6 s — the `expired.len() == 1` assert goes RED.
#[test]
fn per_zone_syn_flood_timeout_reaps_half_open_on_override() {
    const SCREENED_ZONE: u16 = 7;
    let override_ns = 5 * WHEEL_TICK_NS; // 5 s syn-flood timeout
    let install_ns = 1_000_000_000u64;
    // Past the 5 s per-zone override, far short of the 20 s global default.
    let advance = install_ns + 6 * WHEEL_TICK_NS;

    let mut overrides = rustc_hash::FxHashMap::default();
    overrides.insert(SCREENED_ZONE, override_ns);

    // --- screened zone: install stamps the per-zone override at create time ---
    let mut table = SessionTable::new();
    table.set_opening_overrides(overrides.clone());
    let key = key_v4();
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata_with_zone(SCREENED_ZONE),
        install_ns,
        PROTO_TCP,
        TCP_SYN,
    ));
    let entry = table.entry_by_key(&key).expect("opening entry");
    assert!(!entry.established, "a bare-SYN session must start OPENING");
    assert_eq!(
        entry.expires_after_ns, override_ns,
        "a half-open session in a screened zone must reap on the per-zone \
         syn-flood timeout, not the 20 s global default"
    );
    assert_ne!(
        entry.expires_after_ns, DEFAULT_TCP_OPENING_TIMEOUT_NS,
        "the per-zone override must replace the global opening window"
    );
    table.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    let expired = table.expire_stale_entries(advance);
    assert_eq!(
        expired.len(),
        1,
        "the half-open session must reap at the 5 s per-zone window by 6 s"
    );
    assert_eq!(expired[0].key, key);

    // --- control: a half-open in an UNSCREENED zone survives past 6 s on the
    //     20 s global default (proves the override is per-zone, not global) ---
    let mut table2 = SessionTable::new();
    table2.set_opening_overrides(overrides);
    let key2 = key_v4();
    assert!(table2.install_with_protocol(
        key2.clone(),
        decision(),
        metadata_with_zone(SCREENED_ZONE + 1), // no override entry for this zone
        install_ns,
        PROTO_TCP,
        TCP_SYN,
    ));
    assert_eq!(
        table2.entry_by_key(&key2).expect("opening").expires_after_ns,
        DEFAULT_TCP_OPENING_TIMEOUT_NS,
        "an unscreened zone keeps the global opening window"
    );
    table2.last_gc_ns = advance - SESSION_GC_INTERVAL_NS;
    assert!(
        table2.expire_stale_entries(advance).is_empty(),
        "a half-open in an unscreened zone must survive past 6 s on the 20 s default"
    );
}

/// #3527: a SYN retransmit on a still-half-open session re-stamps the opening
/// window from the per-zone override (the refresh path in lookup.rs), not the
/// global default — so a stalled handshake in a screened zone keeps reaping on
/// the operator's window across retransmits.
#[test]
fn per_zone_syn_flood_timeout_applies_on_opening_refresh() {
    const SCREENED_ZONE: u16 = 9;
    let override_ns = 5 * WHEEL_TICK_NS;
    let now = 1_000_000_000u64;
    let mut overrides = rustc_hash::FxHashMap::default();
    overrides.insert(SCREENED_ZONE, override_ns);

    let mut table = SessionTable::new();
    table.set_opening_overrides(overrides);
    let key = key_v4();
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata_with_zone(SCREENED_ZONE),
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    // SYN retransmit (still OPENING, no ACK) — the refresh re-stamps the window.
    assert!(table.lookup(&key, now + 1_000_000, TCP_SYN).is_some());
    let entry = table.entry_by_key(&key).expect("still opening");
    assert!(!entry.established, "a SYN retransmit keeps the session OPENING");
    assert_eq!(
        entry.expires_after_ns, override_ns,
        "an OPENING refresh must re-stamp the per-zone override, not the global default"
    );
}

/// #3152 x #3227: the per-application inactivity timeout is the ESTABLISHED
/// idle window — it must NOT shorten or lengthen the OPENING half-open
/// window. A bare-SYN session carrying a per-app override still reaps on the
/// short opening timeout; once the handshake completes the per-app override
/// applies.
#[test]
fn opening_session_ignores_app_override_until_established() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let app = 120 * WHEEL_TICK_NS; // 120 s custom application idle timeout
    // Two-entry model (#4109): the forward entry carries the per-app override;
    // the reverse companion inherits it (build_reverse_session_from_forward_match
    // mirrors inactivity_timeout_ns). Both start OPENING off the bare SYN.
    assert!(table.install_with_protocol(
        forward.clone(),
        decision(),
        metadata_with_app_timeout(app),
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    let reverse = reverse_key_of(&forward);
    let mut reverse_meta = metadata_with_app_timeout(app);
    reverse_meta.is_reverse = true;
    assert!(table.install_with_protocol(
        reverse.clone(),
        decision(),
        reverse_meta,
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    let _ = table.drain_deltas(8);
    let opening = table.entry_by_key(&forward).expect("opening entry");
    assert!(!opening.established);
    assert_eq!(
        opening.expires_after_ns, DEFAULT_TCP_OPENING_TIMEOUT_NS,
        "a half-open session uses the short opening window even with a per-app \
         override stamped (the override is the established idle timeout)"
    );
    // Complete the handshake: the server's reverse SYN-ACK promotes both halves
    // (#4109 F16), then the forward completing ACK re-stamps the forward entry —
    // the per-app override now applies.
    assert!(
        table
            .lookup(&reverse, now + 1_000_000, TCP_SYN | TCP_ACK)
            .is_some()
    );
    assert!(table.lookup(&forward, now + 2_000_000, TCP_ACK).is_some());
    let est = table.entry_by_key(&forward).expect("established entry");
    assert!(est.established);
    assert_eq!(
        est.expires_after_ns, app,
        "once established the per-application inactivity timeout applies"
    );
}

#[test]
fn synced_sessions_do_not_emit_deltas() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    let synced_meta = metadata();
    table.upsert_synced(
        key.clone(),
        decision(),
        synced_meta.clone(),
        now,
        PROTO_TCP,
        0x10,
        false,
    );
    let hit = table.lookup(&key, now + 1_000_000, 0x10);
    assert_eq!(
        hit,
        Some(SessionLookup {
            decision: decision(),
            metadata: synced_meta,
        })
    );
    assert!(table.drain_deltas(8).is_empty());
    let _ = table.lookup(&key, now + 2_000_000, TCP_FIN);
    assert!(table.drain_deltas(8).is_empty());
}

#[test]
fn upsert_synced_does_not_clobber_live_local_session() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    let mut live = metadata();
    live.fabric_ingress = true;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        live.clone(),
        now,
        PROTO_TCP,
        0x10,
    ));
    let synced_meta = metadata();
    table.upsert_synced(
        key.clone(),
        SessionDecision {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            ..decision()
        },
        synced_meta,
        now + 1_000_000,
        PROTO_TCP,
        0x10,
        false,
    );
    let hit = table
        .lookup(&key, now + 2_000_000, 0x10)
        .expect("live session");
    assert_eq!(hit.metadata, live);
    assert_eq!(hit.decision, decision());
}

#[test]
fn upsert_synced_can_replace_live_local_session_when_allowed() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    let live = metadata();
    assert!(table.install_with_protocol(key.clone(), decision(), live, now, PROTO_TCP, 0x10,));
    let synced_meta = metadata();
    let synced_decision = SessionDecision {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
        ..decision()
    };
    assert!(table.upsert_synced(
        key.clone(),
        synced_decision,
        synced_meta.clone(),
        now + 1_000_000,
        PROTO_TCP,
        0x10,
        true,
    ));
    let hit = table
        .lookup(&key, now + 2_000_000, 0x10)
        .expect("synced session");
    assert_eq!(hit.metadata, synced_meta);
    assert_eq!(hit.decision, synced_decision);
}

#[test]
fn promote_synced_forward_session_emits_open_delta() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    let synced_meta = metadata();
    table.upsert_synced(
        key.clone(),
        decision(),
        synced_meta,
        now,
        PROTO_TCP,
        0x10,
        false,
    );
    let promoted = metadata();
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: promoted.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    }));
    let hit = table.lookup(&key, now + 2_000_000, 0x10);
    assert_eq!(
        hit,
        Some(SessionLookup {
            decision: decision(),
            metadata: promoted.clone(),
        })
    );
    let deltas = table.drain_deltas(8);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
    assert_eq!(deltas[0].key, key);
    assert_eq!(deltas[0].metadata, promoted);
}

#[test]
fn promote_synced_reverse_session_stays_quiet() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    let mut synced_meta = metadata();
    synced_meta.is_reverse = true;
    table.upsert_synced(
        key.clone(),
        decision(),
        synced_meta,
        now,
        PROTO_TCP,
        0x10,
        false,
    );
    let mut promoted = metadata();
    promoted.is_reverse = true;
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: promoted.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    }));
    let hit = table.lookup(&key, now + 2_000_000, 0x10);
    assert_eq!(
        hit,
        Some(SessionLookup {
            decision: decision(),
            metadata: promoted,
        })
    );
    assert!(table.drain_deltas(8).is_empty());
}

#[test]
fn demote_owner_rg_marks_forward_and_reverse_entries_synced() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let key_a = key_v4();
    let key_b = SessionKey {
        src_port: 42425,
        ..key_v4()
    };
    let key_other = SessionKey {
        src_port: 42426,
        ..key_v4()
    };
    let mut metadata_a = metadata();
    metadata_a.owner_rg_id = 1;
    let mut metadata_b = metadata();
    metadata_b.owner_rg_id = 1;
    metadata_b.is_reverse = true;
    let mut metadata_other = metadata();
    metadata_other.owner_rg_id = 2;
    assert!(table.install_with_protocol(
        key_a.clone(),
        decision(),
        metadata_a,
        now,
        PROTO_TCP,
        0x10,
    ));
    assert!(table.install_with_protocol(
        key_b.clone(),
        decision(),
        metadata_b,
        now,
        PROTO_TCP,
        0x10,
    ));
    assert!(table.install_with_protocol(
        key_other.clone(),
        decision(),
        metadata_other.clone(),
        now,
        PROTO_TCP,
        0x10,
    ));

    assert_eq!(table.demote_owner_rg(1).len(), 2);

    // Verify demoted sessions have peer-synced origin
    let mut a_origin = None;
    let mut b_origin = None;
    let mut other_origin = None;
    table.iter_with_origin(|key, _decision, _metadata, origin| {
        if key == &key_a {
            a_origin = Some(origin);
        } else if key == &key_b {
            b_origin = Some(origin);
        } else if key == &key_other {
            other_origin = Some(origin);
        }
    });
    assert!(a_origin.expect("key_a exists").is_peer_synced());
    assert!(b_origin.expect("key_b exists").is_peer_synced());
    assert!(
        !other_origin.expect("key_other exists").is_peer_synced(),
        "other RG should remain local"
    );
    assert_eq!(
        table
            .lookup(&key_other, now + 1_000_000, 0x10)
            .expect("other rg")
            .metadata,
        metadata_other
    );
}

#[test]
fn demote_owner_rg_returns_synced_entries_for_transition_refresh() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let key = key_v4();
    let mut metadata = metadata();
    metadata.owner_rg_id = 2;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata.clone(),
        SessionOrigin::SyncImport,
        now,
        PROTO_TCP,
        0x10,
    ));

    let demoted = table.demote_owner_rg(2);
    assert_eq!(demoted, vec![key.clone()]);

    let (_, _, origin) = table.entry_with_origin(&key).expect("session exists");
    assert_eq!(origin, SessionOrigin::SyncImport);
}

#[test]
fn owner_rg_session_keys_track_insert_update_and_delete() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let key = key_v4();
    let mut metadata_rg1 = metadata();
    metadata_rg1.owner_rg_id = 1;
    let mut metadata_rg2 = metadata();
    metadata_rg2.owner_rg_id = 2;

    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata_rg1.clone(),
        now,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(table.owner_rg_session_keys(&[1]), vec![key.clone()]);

    assert!(table.refresh_for_ha_activation(
        &key,
        decision(),
        metadata_rg2.clone(),
        now + 1_000_000,
        0x10,
    ));
    assert!(table.owner_rg_session_keys(&[1]).is_empty());
    assert_eq!(table.owner_rg_session_keys(&[2]), vec![key.clone()]);

    table.delete(&key);
    assert!(table.owner_rg_session_keys(&[2]).is_empty());
}

#[test]
fn reply_match_finds_tcp_snat_reverse_tuple() {
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 42424,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 5201,
        dst_port: 42424,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    assert!(reply_matches_forward_session(
        &forward,
        NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: None,
            ..NatDecision::default()
        },
        &reply,
    ));
}

#[test]
fn reply_match_finds_icmp_snat_reverse_tuple() {
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 0x1234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 0x1234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    assert!(reply_matches_forward_session(
        &forward,
        NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: None,
            ..NatDecision::default()
        },
        &reply,
    ));
}

#[test]
fn find_forward_nat_match_uses_reverse_index() {
    let mut table = SessionTable::new();
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 42424,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 5201,
        dst_port: 42424,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_dst: None,
        ..NatDecision::default()
    };
    let decision = SessionDecision {
        resolution: resolution(),
        nat,
    };
    assert!(table.install_with_protocol(
        forward.clone(),
        decision,
        metadata(),
        1_000_000_000,
        PROTO_TCP,
        0x10
    ));

    let hit = table
        .find_forward_nat_match(&reply)
        .expect("forward nat match");
    assert_eq!(hit.key, forward);
    assert_eq!(hit.decision.nat, nat);

    table.delete(&hit.key);
    assert!(table.find_forward_nat_match(&reply).is_none());
}

#[test]
fn find_forward_nat_match_uses_canonical_reverse_index() {
    let mut table = SessionTable::new();
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 42424,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let canonical_reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 5201,
        dst_port: 42424,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    };
    let decision = SessionDecision {
        resolution: resolution(),
        nat,
    };
    assert!(table.install_with_protocol(
        forward.clone(),
        decision,
        metadata(),
        1_000_000_000,
        PROTO_TCP,
        0x10
    ));

    let hit = table
        .find_forward_nat_match(&canonical_reply)
        .expect("canonical reverse match");
    assert_eq!(hit.key, forward);
    assert_eq!(hit.decision.nat, nat);

    table.delete(&hit.key);
    assert!(table.find_forward_nat_match(&canonical_reply).is_none());
}

#[test]
fn reverse_canonical_key_keeps_icmp_identifier_position() {
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        src_port: 0x1234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let reply = reverse_canonical_key(&forward, NatDecision::default());
    assert_eq!(reply.src_ip, IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)));
    assert_eq!(reply.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)));
    assert_eq!(reply.src_port, 0x1234);
    assert_eq!(reply.dst_port, 0);
}

#[test]
fn find_forward_nat_match_uses_canonical_reverse_index_for_icmp() {
    let mut table = SessionTable::new();
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        src_port: 0x1234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let canonical_reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 0x1234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
        ..NatDecision::default()
    };
    let decision = SessionDecision {
        resolution: resolution(),
        nat,
    };
    assert!(table.install_with_protocol(
        forward.clone(),
        decision,
        metadata(),
        1_000_000_000,
        PROTO_ICMP,
        0
    ));

    let hit = table
        .find_forward_nat_match(&canonical_reply)
        .expect("icmp canonical reverse match");
    assert_eq!(hit.key, forward);
    assert_eq!(hit.decision.nat, nat);

    table.delete(&hit.key);
    assert!(table.find_forward_nat_match(&canonical_reply).is_none());
}

#[test]
fn find_forward_wire_match_uses_translated_forward_index() {
    let mut table = SessionTable::new();
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 42528,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let translated = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 42528,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(42528),
        ..NatDecision::default()
    };
    let decision = SessionDecision {
        resolution: resolution(),
        nat,
    };
    assert!(table.install_with_protocol(
        forward.clone(),
        decision,
        metadata(),
        1_000_000_000,
        PROTO_TCP,
        0x10
    ));

    let hit = table
        .find_forward_wire_match(&translated)
        .expect("forward wire match");
    assert_eq!(hit.key, forward);
    assert_eq!(hit.decision.nat, nat);

    table.delete(&hit.key);
    assert!(table.find_forward_wire_match(&translated).is_none());
}

#[test]
fn lookup_uses_translated_reverse_alias() {
    let mut table = SessionTable::new();
    let reverse_wire = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42)),
        src_port: 5201,
        dst_port: 42424,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let reverse_canonical = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 5201,
        dst_port: 42424,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    let reverse_decision = SessionDecision {
        resolution: resolution(),
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };
    assert!(table.install_with_protocol(
        reverse_wire.clone(),
        reverse_decision,
        reverse_metadata.clone(),
        1_000_000_000,
        PROTO_TCP,
        0x10
    ));

    let hit = table
        .lookup(&reverse_canonical, 1_001_000_000, 0x10)
        .expect("translated reverse alias");
    assert_eq!(hit.decision, reverse_decision);
    assert_eq!(hit.metadata, reverse_metadata);

    table.delete(&reverse_wire);
    assert!(
        table
            .lookup(&reverse_canonical, 1_002_000_000, 0x10)
            .is_none()
    );
}

#[test]
fn dnat_port_in_reverse_wire_key() {
    // Forward: client:54321 -> external:80, DNAT rewrites dst to internal:8080
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        src_port: 54321,
        dst_port: 80,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    // Reply from internal:8080 -> client:54321
    let expected_reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        src_port: 8080,
        dst_port: 54321,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    assert!(reply_matches_forward_session(
        &forward,
        nat,
        &expected_reply
    ));
}

#[test]
fn dnat_plus_snat_ports_in_reverse_key() {
    // Forward: client:54321 -> external:80
    // DNAT: dst -> internal:8080, SNAT: src -> egress_ip
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        src_port: 54321,
        dst_port: 80,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        rewrite_src_port: None,
        rewrite_dst_port: Some(8080),
        nat64: false,
        nptv6: false,
    };
    // Reply: internal:8080 -> egress:54321
    let expected_reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 8080,
        dst_port: 54321,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    assert!(reply_matches_forward_session(
        &forward,
        nat,
        &expected_reply
    ));
}

#[test]
fn icmp_port_handling_unchanged_with_dnat_ports() {
    // ICMP ignores port rewriting even if NatDecision has port fields set
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        src_port: 0x1234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    // ICMP reverse: ports stay the same (ICMP has no port semantics)
    let expected_reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 0x1234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    assert!(reply_matches_forward_session(
        &forward,
        nat,
        &expected_reply
    ));
}

// #4074 FAIL-ON-REVERT (RFC 5508 §3.1): with pool SNAT translating the ICMP
// Query Identifier, two internal hosts pinging the SAME target with the SAME
// original id, both hidden behind ONE pool address, must produce DISTINCT
// reverse wire keys — otherwise the return replies collide on
// `(pool_addr, id)` and are mis-associated.
//
// The forward SNAT decision carries the translated id in `rewrite_src_port`.
// `reverse_wire_key` must fold it into the reverse key's `src_port` (the ICMP
// identifier is symmetric — the reply carries the same translated id at the
// same offset). Reverting the key.rs ICMP arm (ignore `rewrite_src_port`, keep
// the original id) collapses both reverse keys to `{T, P, 0x1234, 0}`, turning
// the `assert_ne!` RED.
#[test]
fn icmp_query_id_translation_demuxes_reverse_wire_key() {
    let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let pool = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let query_id = 0x1234u16;

    let mk_forward = |host: Ipv4Addr| SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(host),
        dst_ip: target,
        src_port: query_id,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    // Distinct translated ids allocated by pool SNAT for the two hosts.
    let mk_nat = |translated_id: u16| NatDecision {
        rewrite_src: Some(pool),
        rewrite_src_port: Some(translated_id),
        ..NatDecision::default()
    };

    let fwd_a = mk_forward(Ipv4Addr::new(10, 0, 0, 1));
    let fwd_b = mk_forward(Ipv4Addr::new(10, 0, 0, 2));
    let nat_a = mk_nat(40001);
    let nat_b = mk_nat(40002);

    // The reverse (reply) wire keys carry the translated id in src_port, so
    // they differ — the replies demux back to the right host.
    let rev_a = reverse_wire_key(&fwd_a, nat_a);
    let rev_b = reverse_wire_key(&fwd_b, nat_b);
    assert_eq!(rev_a.src_ip, target, "reply source is the pinged target");
    assert_eq!(rev_a.dst_ip, pool, "reply destination is the pool address");
    assert_eq!(
        rev_a.src_port, 40001,
        "reverse key carries the translated id"
    );
    assert_eq!(rev_a.dst_port, 0, "ICMP dst_port stays 0");
    assert_ne!(
        rev_a, rev_b,
        "distinct translated ids MUST give distinct reverse keys (no collision)",
    );

    // The reply that carries host A's translated id (40001) matches forward A
    // but NOT forward B (whose reverse key expects 40002).
    let reply_a = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: target,
        dst_ip: pool,
        src_port: 40001,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    assert!(reply_matches_forward_session(&fwd_a, nat_a, &reply_a));
    assert!(!reply_matches_forward_session(&fwd_b, nat_b, &reply_a));

    // The reverse companion session key is keyed on the translated id too, so
    // both hosts' companions have distinct primary keys.
    assert_ne!(
        reverse_session_key(&fwd_a, nat_a),
        reverse_session_key(&fwd_b, nat_b),
        "reverse companion keys must differ per translated id",
    );

    // Sanity: with NO translated id (rewrite_src_port None), ICMP keeps the
    // original id — the pre-#4074 behavior, and the collision case.
    let no_id_nat = NatDecision {
        rewrite_src: Some(pool),
        ..NatDecision::default()
    };
    assert_eq!(
        reverse_wire_key(&fwd_a, no_id_nat),
        reverse_wire_key(&fwd_b, no_id_nat),
        "without id translation the two reverse keys collide (documents the gap)",
    );
}

// #4088: the reverse-recovery path must work for an ICMP Query Identifier of 0
// (a valid on-wire id). Two hosts pinging the same target with id==0, both
// behind one pool address, are given DISTINCT translated ids by pool SNAT
// (source.rs, exercised in nat/tests.rs). Here we pin that the reverse keying
// carries the TRANSLATED id — not the original 0 — so the id==0 replies demux
// back to the right host and the original id (0) is recovered on the reverse.
// If the reverse keys ignored `rewrite_src_port` and kept the original id, both
// would collapse to `{T, P, 0, 0}` and the `assert_ne!` would go RED.
#[test]
fn icmp_query_id_zero_translation_demuxes_reverse_wire_key() {
    let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let pool = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    // The valid-but-uncommon id==0 case.
    let query_id = 0u16;

    let mk_forward = |host: Ipv4Addr| SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(host),
        dst_ip: target,
        src_port: query_id,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mk_nat = |translated_id: u16| NatDecision {
        rewrite_src: Some(pool),
        rewrite_src_port: Some(translated_id),
        ..NatDecision::default()
    };

    let fwd_a = mk_forward(Ipv4Addr::new(10, 0, 0, 1));
    let fwd_b = mk_forward(Ipv4Addr::new(10, 0, 0, 2));
    let nat_a = mk_nat(40001);
    let nat_b = mk_nat(40002);

    let rev_a = reverse_wire_key(&fwd_a, nat_a);
    let rev_b = reverse_wire_key(&fwd_b, nat_b);
    assert_eq!(
        rev_a.src_port, 40001,
        "reverse key carries the translated id, not the original 0",
    );
    assert_ne!(
        rev_a, rev_b,
        "distinct translated ids MUST give distinct reverse keys even when the original id is 0",
    );

    // The reply carrying host A's translated id (40001) matches forward A only.
    let reply_a = SessionKey {
        addr_family: 2,
        protocol: PROTO_ICMP,
        src_ip: target,
        dst_ip: pool,
        src_port: 40001,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    assert!(reply_matches_forward_session(&fwd_a, nat_a, &reply_a));
    assert!(!reply_matches_forward_session(&fwd_b, nat_b, &reply_a));

    // The reverse companion keys differ per translated id (no (pool, 0) collision).
    assert_ne!(
        reverse_session_key(&fwd_a, nat_a),
        reverse_session_key(&fwd_b, nat_b),
        "id==0 reverse companion keys must differ per translated id",
    );
}

#[test]
fn find_forward_nat_match_with_dnat_port_rewrite() {
    let mut table = SessionTable::new();
    // Forward: client:54321 -> external:80 with DNAT to internal:8080
    let forward = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        src_port: 54321,
        dst_port: 80,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    // Reply from internal:8080 -> client:54321
    let reply = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        src_port: 8080,
        dst_port: 54321,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        rewrite_dst_port: Some(8080),
        ..NatDecision::default()
    };
    let decision = SessionDecision {
        resolution: resolution(),
        nat,
    };
    assert!(table.install_with_protocol(
        forward.clone(),
        decision,
        metadata(),
        1_000_000_000,
        PROTO_TCP,
        0x10
    ));

    let hit = table
        .find_forward_nat_match(&reply)
        .expect("forward nat match with port");
    assert_eq!(hit.key, forward);
    assert_eq!(hit.decision.nat, nat);

    table.delete(&hit.key);
    assert!(table.find_forward_nat_match(&reply).is_none());
}

#[test]
fn configurable_tcp_timeout_changes_session_expiry() {
    let mut table = SessionTable::new();
    table.set_timeouts(SessionTimeouts::from_seconds(60, 0, 0));
    let key = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x10,
    ));
    // Session should expire after 60s (configured), not 300s (default)
    table.last_gc_ns = now + 59_000_000_000;
    let expired = table.expire_stale(now + 59_000_000_000 + SESSION_GC_INTERVAL_NS);
    assert_eq!(expired, 0, "session should not expire before 60s");

    table.last_gc_ns = now + 61_000_000_000;
    let expired = table.expire_stale(now + 61_000_000_000 + SESSION_GC_INTERVAL_NS);
    assert_eq!(expired, 1, "session should expire after 60s");
}

#[test]
fn configurable_udp_timeout_changes_session_expiry() {
    let mut table = SessionTable::new();
    table.set_timeouts(SessionTimeouts::from_seconds(0, 120, 0));
    let key = key_v6();
    let now = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_UDP,
        0,
    ));
    // Should not expire at 60s (the old default)
    table.last_gc_ns = now + 61_000_000_000;
    let expired = table.expire_stale(now + 61_000_000_000 + SESSION_GC_INTERVAL_NS);
    assert_eq!(expired, 0, "session should not expire before 120s");

    // Should expire after 120s
    table.last_gc_ns = now + 121_000_000_000;
    let expired = table.expire_stale(now + 121_000_000_000 + SESSION_GC_INTERVAL_NS);
    assert_eq!(expired, 1, "session should expire after 120s");
}

#[test]
fn default_timeouts_match_original_values() {
    let t = SessionTimeouts::default();
    assert_eq!(t.tcp_established_ns, 300_000_000_000);
    // #3152: the half-open opening window defaults to 20 s (Junos parity).
    assert_eq!(t.tcp_opening_ns, 20_000_000_000);
    assert_eq!(t.udp_ns, 60_000_000_000);
    assert_eq!(t.icmp_ns, 60_000_000_000);
}

#[test]
fn from_seconds_zero_uses_default() {
    let t = SessionTimeouts::from_seconds(0, 0, 0);
    assert_eq!(t.tcp_established_ns, DEFAULT_TCP_SESSION_TIMEOUT_NS);
    // #3152: the opening window is not snapshot-driven; always the default.
    assert_eq!(t.tcp_opening_ns, DEFAULT_TCP_OPENING_TIMEOUT_NS);
    assert_eq!(t.udp_ns, DEFAULT_UDP_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, DEFAULT_ICMP_SESSION_TIMEOUT_NS);
}

#[test]
fn from_seconds_overrides_values() {
    let t = SessionTimeouts::from_seconds(120, 30, 5);
    assert_eq!(t.tcp_established_ns, 120_000_000_000);
    assert_eq!(t.udp_ns, 30_000_000_000);
    assert_eq!(t.icmp_ns, 5_000_000_000);
}

#[test]
fn from_seconds_normal_value_unchanged() {
    // 1 hour: a realistic operator-configured timeout must convert exactly,
    // proving the saturation path does not perturb in-range values.
    let t = SessionTimeouts::from_seconds(3600, 3600, 3600);
    assert_eq!(t.tcp_established_ns, 3_600_000_000_000);
    assert_eq!(t.udp_ns, 3_600_000_000_000);
    assert_eq!(t.icmp_ns, 3_600_000_000_000);
}

#[test]
fn from_seconds_max_accepted_value_exact() {
    // The largest value the Go gate accepts (config.MaxDurationSeconds ==
    // MAX_SESSION_TIMEOUT_SECS) must convert exactly, NOT saturate-short.
    let t = SessionTimeouts::from_seconds(
        MAX_SESSION_TIMEOUT_SECS,
        MAX_SESSION_TIMEOUT_SECS,
        MAX_SESSION_TIMEOUT_SECS,
    );
    assert_eq!(t.tcp_established_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.udp_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, MAX_SESSION_TIMEOUT_NS);
    // The conversion must not have wrapped: the ns ceiling is < u64::MAX.
    assert_eq!(
        MAX_SESSION_TIMEOUT_NS,
        MAX_SESSION_TIMEOUT_SECS * 1_000_000_000
    );
}

#[test]
fn from_seconds_saturates_first_overflowing_value() {
    // The first value whose `secs * 1e9` exceeds the ns ceiling. Pre-#2441
    // this is where the raw multiply began to wrap (debug-panic / release-
    // wrap). It must now SATURATE at MAX_SESSION_TIMEOUT_NS, not wrap to a
    // tiny value (premature session expiry).
    let first_over = MAX_SESSION_TIMEOUT_SECS + 1;
    let t = SessionTimeouts::from_seconds(first_over, first_over, first_over);
    assert_eq!(t.tcp_established_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.udp_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, MAX_SESSION_TIMEOUT_NS);
}

#[test]
fn from_seconds_saturates_u64_max() {
    // u64::MAX * 1e9 wraps catastrophically with a raw multiply (debug:
    // panic, release: a near-zero timeout). Restoring the raw `*` makes this
    // test panic in debug / produce a tiny non-saturated value in release —
    // the fail-on-revert pin.
    let t = SessionTimeouts::from_seconds(u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(t.tcp_established_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.udp_ns, MAX_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, MAX_SESSION_TIMEOUT_NS);
    // Saturated, not wrapped-tiny: the result is a very large valid timeout.
    assert!(t.tcp_established_ns > DEFAULT_TCP_SESSION_TIMEOUT_NS);
}

/// #3714: a per-application inactivity timeout must be clamped to the Go
/// `appTimeoutMax` (86400 s) before the seconds→ns conversion. The Go compiler
/// rejects `inactivity-timeout > 86400` at commit, so a well-formed snapshot
/// never carries a larger value; a corrupt / mixed-version wire value (e.g.
/// `4294967295`) must NOT stamp an effectively never-expiring idle timeout.
/// Reverting the `s.min(APP_INACTIVITY_TIMEOUT_MAX_SECS)` clamp makes the two
/// over-bound assertions go RED (they would return the raw seconds in ns).
#[test]
fn app_inactivity_timeout_ns_clamps_to_go_commit_bound_3714() {
    let max_ns = u64::from(APP_INACTIVITY_TIMEOUT_MAX_SECS) * 1_000_000_000;

    // The pin: a corrupt u32::MAX snapshot value must clamp to 86400 s, NOT
    // stamp ~136 years (4294967295 * 1e9 ns) of retention.
    assert_eq!(
        app_inactivity_timeout_ns(Some(u32::MAX)),
        Some(max_ns),
        "u32::MAX inactivity_timeout must clamp to the 86400 s commit bound"
    );
    // One second over the bound clamps to exactly the bound.
    assert_eq!(
        app_inactivity_timeout_ns(Some(APP_INACTIVITY_TIMEOUT_MAX_SECS + 1)),
        Some(max_ns),
        "86401 s must clamp to the 86400 s commit bound"
    );

    // No regression at/under the bound: exact conversion, no clamp artifacts.
    assert_eq!(
        app_inactivity_timeout_ns(Some(APP_INACTIVITY_TIMEOUT_MAX_SECS)),
        Some(max_ns),
        "the exact 86400 s bound converts exactly (in range)"
    );
    assert_eq!(
        app_inactivity_timeout_ns(Some(30)),
        Some(30 * 1_000_000_000),
        "a normal 30 s app timeout converts exactly, unaffected by the clamp"
    );
    // 0 / None keep meaning "use the global per-protocol timeout".
    assert_eq!(
        app_inactivity_timeout_ns(Some(0)),
        None,
        "0 s means use-global (None), not the clamp bound"
    );
    assert_eq!(app_inactivity_timeout_ns(None), None, "None stays None");
}

#[test]
fn from_seconds_zero_still_defaults_after_saturation() {
    // 0 must remain "use the default", unaffected by the saturation helper.
    let t = SessionTimeouts::from_seconds(0, 0, 0);
    assert_eq!(t.tcp_established_ns, DEFAULT_TCP_SESSION_TIMEOUT_NS);
    assert_eq!(t.udp_ns, DEFAULT_UDP_SESSION_TIMEOUT_NS);
    assert_eq!(t.icmp_ns, DEFAULT_ICMP_SESSION_TIMEOUT_NS);
}

#[test]
fn iter_with_idle_reports_idle_time() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_time = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_time,
        PROTO_TCP,
        0x10,
    ));

    let now = install_time + 5_000_000_000; // 5 seconds later
    let mut found = false;
    table.iter_with_idle(now, |k, _decision, _metadata, idle_ns, _counters| {
        if k == &key {
            assert_eq!(idle_ns, 5_000_000_000);
            found = true;
        }
    });
    assert!(found, "session should be found in iter_with_idle");
}

#[test]
fn iter_with_idle_reflects_last_seen_update() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let install_time = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_time,
        PROTO_TCP,
        0x10,
    ));
    // Touch the session 3 seconds later
    let touch_time = install_time + 3_000_000_000;
    let _ = table.lookup(&key, touch_time, 0x10);

    // Check idle time 5 seconds after install (2 seconds after last touch)
    let now = install_time + 5_000_000_000;
    let mut idle = 0u64;
    table.iter_with_idle(now, |k, _, _, idle_ns, _counters| {
        if k == &key {
            idle = idle_ns;
        }
    });
    assert_eq!(idle, 2_000_000_000, "idle should be 2s since last touch");
}

#[test]
fn iter_with_idle_budgeted_bounds_and_resumes_full_coverage() {
    // #5287: the budgeted refresh walk must (1) examine AT MOST `budget` slab
    // slots per slice, (2) RESUME from the returned cursor, and (3) cover EVERY
    // forward entry within one full cycle. Reverting the walk to the unbounded
    // single-pass scan reddens the per-slice bound assertion (a single call
    // would then examine all N > BUDGET entries).
    let mut table = SessionTable::new();
    const N: usize = 25;
    const BUDGET: usize = 8;
    assert!(N > BUDGET, "test only meaningful when the table exceeds one slice");

    let install_time = 1_000_000_000u64;
    let mut installed = std::collections::HashSet::new();
    for i in 0..N {
        let mut key = key_v4();
        key.src_port = 10_000 + i as u16; // distinct 5-tuples -> distinct forward entries
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_time,
            PROTO_TCP,
            0x10,
        ));
        installed.insert(key);
    }

    let now = install_time + 5_000_000_000;
    let mut cursor = 0usize;
    let mut seen = std::collections::HashSet::new();
    let mut slices = 0usize;
    // Bounded loop guards against a non-advancing cursor hanging the test.
    for _ in 0..1024 {
        let mut this_slice = 0usize;
        let next = table.iter_with_idle_budgeted(cursor, BUDGET, now, |k, _d, meta, _idle, _c, _exp| {
            this_slice += 1;
            if !meta.is_reverse {
                seen.insert(k.clone());
            }
        });
        // (1) Hard per-slice bound — THE fail-on-revert assertion. An unbounded
        // single pass processes all N (> BUDGET) entries in one call.
        assert!(
            this_slice <= BUDGET,
            "slice examined {this_slice} slots, exceeds budget {BUDGET}",
        );
        slices += 1;
        cursor = next;
        if cursor == 0 {
            break; // returned-to-top => a full-table cycle completed
        }
    }
    // (2) The full table spanned MORE THAN ONE slice (resumed across ticks).
    assert!(
        slices > 1,
        "full table must span >1 slice at N={N} budget={BUDGET}, got {slices}",
    );
    // (3) One cycle refreshed EVERY installed forward entry exactly once.
    assert_eq!(seen, installed, "one cycle must cover every forward entry");
}

/// #6297: drive `iter_with_idle_budgeted` a full cycle at budget=1 and return
/// the number of slab SLOTS examined (occupied + vacant) over that cycle — i.e.
/// the walk's effective bound. Budget=1 examines exactly slot `cursor` per call
/// and returns `cursor + 1` (or 0 when that reaches the bound), so the call
/// count equals the examined-slot count. Precondition: a non-empty walk extent
/// (the empty-slab fast path returns 0 immediately, which this helper cannot
/// distinguish from a 1-slot cycle).
fn count_full_budgeted_sweep(table: &SessionTable, now_ns: u64) -> usize {
    let mut cursor = 0usize;
    let mut examined = 0usize;
    // The extent can never exceed capacity(); cap the loop generously above it
    // so a non-advancing cursor panics instead of spinning forever.
    let guard = table.entries_capacity_for_test() + 8;
    for _ in 0..guard {
        let next = table.iter_with_idle_budgeted(cursor, 1, now_ns, |_, _, _, _, _, _exp| {});
        examined += 1;
        if next == 0 {
            return examined;
        }
        cursor = next;
    }
    panic!("budgeted sweep did not complete within {guard} slices");
}

#[test]
fn iter_with_idle_budgeted_bounds_to_high_watermark_after_drain() {
    // #6297: the budgeted refresh walk must bound its round-robin sweep to the
    // LIVE-EXTENT high-watermark (1 + the highest slot ever handed out), NOT the
    // monotonic slab `capacity()`. The slab never shrinks, so after a
    // session-count spike drains, `capacity()` overshoots the peak extent (the
    // backing Vec doubles past it) and a capacity-bound walk re-scans vacant
    // slots every cycle. Reverting the bound to `entries.capacity()` reddens the
    // `examined < capacity` assertion below.
    let mut table = SessionTable::new();

    // Fill to a NON-power-of-two session count so the backing Vec's doubling
    // leaves capacity() STRICTLY above the watermark (the peak extent).
    const N: usize = 100;
    let install_time = 1_000_000_000u64;
    let mut keys = Vec::with_capacity(N);
    for i in 0..N {
        let mut key = key_v4();
        key.src_port = 10_000 + i as u16; // distinct 5-tuples -> distinct entries
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_time,
            PROTO_TCP,
            0x10,
        ));
        // Fresh slab, no prior vacancies -> installs land at contiguous slots
        // 0..N in call order.
        assert_eq!(
            table.handle_for_key(&key),
            Some(i as u32),
            "install {i} expected to land at slot {i}",
        );
        keys.push(key);
    }

    let watermark = table.slot_high_watermark_for_test();
    let capacity = table.entries_capacity_for_test();
    assert_eq!(watermark, N, "watermark must be 1 + the top occupied slot");
    assert!(
        capacity > watermark,
        "test needs a doubling gap: capacity {capacity} must exceed watermark \
         {watermark} (choose a non-power-of-two N)",
    );

    // Drain almost everything. capacity() AND the watermark are both monotonic,
    // so they stay put; only len() collapses -> the mostly-vacant slab the issue
    // describes.
    for key in keys.iter().take(N - 3) {
        table.delete(key);
    }
    assert_eq!(table.len(), 3, "drained to a near-empty table");
    assert_eq!(
        table.entries_capacity_for_test(),
        capacity,
        "slab capacity is monotonic — it never shrinks on drain",
    );
    assert_eq!(
        table.slot_high_watermark_for_test(),
        watermark,
        "watermark is monotonic — not shrunk on removal (see the invariant)",
    );

    // Count the slots EXAMINED over one full cycle.
    let now = install_time + 5_000_000_000;
    let examined = count_full_budgeted_sweep(&table, now);

    // THE fail-on-revert assertions: the walk stops at the live extent, not the
    // doubled capacity.
    assert_eq!(
        examined, watermark,
        "walk must examine exactly the high-watermark extent ({watermark}), got {examined}",
    );
    assert!(
        examined < capacity,
        "walk examined {examined} slots — must be < the monotonic capacity \
         {capacity} (reverting the bound to capacity() breaks this)",
    );
}

#[test]
fn iter_with_idle_budgeted_never_skips_a_live_session_above_the_len() {
    // #6297 correctness guard: the high-watermark bound must NEVER drop below a
    // live slot, or that session's last_seen would stop being mirrored into the
    // BPF conntrack map and the entry would look idle and expire early. Engineer
    // a table whose SOLE live session sits at a high slot far above len(), then
    // assert a full budgeted sweep still refreshes it. A bound that under-shot
    // (e.g. to len()) would skip it.
    let mut table = SessionTable::new();
    const N: usize = 64;
    let install_time = 1_000_000_000u64;
    let mut keys = Vec::with_capacity(N);
    for i in 0..N {
        let mut key = key_v4();
        key.src_port = 20_000 + i as u16;
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            install_time,
            PROTO_TCP,
            0x10,
        ));
        assert_eq!(table.handle_for_key(&key), Some(i as u32));
        keys.push(key);
    }
    let watermark = table.slot_high_watermark_for_test();
    assert_eq!(watermark, N);

    // Remove every session EXCEPT the one at the top slot (N-1). len() collapses
    // to 1 while the live session stays at slot N-1, far above len().
    let survivor = keys[N - 1].clone();
    for key in keys.iter().take(N - 1) {
        table.delete(key);
    }
    assert_eq!(table.len(), 1);
    assert_eq!(
        table.handle_for_key(&survivor),
        Some((N - 1) as u32),
        "survivor must still occupy the top slot",
    );
    // Watermark unchanged (monotonic) and strictly above the survivor's slot.
    assert_eq!(table.slot_high_watermark_for_test(), watermark);
    assert!(watermark > (N - 1));

    // A full budgeted sweep MUST refresh the survivor.
    let now = install_time + 5_000_000_000;
    let mut cursor = 0usize;
    let mut refreshed = false;
    for _ in 0..(table.entries_capacity_for_test() + 8) {
        let next = table.iter_with_idle_budgeted(cursor, 8, now, |k, _d, _m, _idle, _c, _exp| {
            if k == &survivor {
                refreshed = true;
            }
        });
        cursor = next;
        if cursor == 0 {
            break;
        }
    }
    assert!(
        refreshed,
        "the live session at slot {} (len={}, watermark={}) must be refreshed — \
         the bound must never drop below a live slot",
        N - 1,
        table.len(),
        watermark,
    );
}

#[test]
fn refresh_local_skips_peer_synced_entries() {
    let mut table = SessionTable::new();
    let key = key_v4();
    // Install with SyncImport origin (peer-synced)
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let new_decision = SessionDecision {
        resolution: ForwardingResolution {
            egress_ifindex: 99,
            ..decision().resolution
        },
        ..decision()
    };
    // refresh_local should return false for peer-synced sessions
    assert!(!table.refresh_local(&key, new_decision, metadata(), 2_000_000, 0x10));
    assert_eq!(table.owner_rg_session_keys(&[1]), vec![key.clone()]);
    // session should still have original decision
    let lookup = table.lookup(&key, 3_000_000, 0x10).expect("session");
    assert_ne!(lookup.decision.resolution.egress_ifindex, 99);
}

#[test]
fn refresh_for_ha_activation_updates_peer_synced_entries() {
    let mut table = SessionTable::new();
    let key = key_v4();
    // Install with SyncImport origin (peer-synced)
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let new_decision = SessionDecision {
        resolution: ForwardingResolution {
            egress_ifindex: 99,
            ..decision().resolution
        },
        ..decision()
    };
    // refresh_for_ha_activation should succeed even for peer-synced sessions
    assert!(table.refresh_for_ha_activation(&key, new_decision, metadata(), 2_000_000, 0x10));
    // session should now have updated decision
    let lookup = table.lookup(&key, 3_000_000, 0x10).expect("session");
    assert_eq!(lookup.decision.resolution.egress_ifindex, 99);
}

// ---------------------------------------------------------------------------
// #1752 Path E: in-place refresh differential tests.
//
// The pre-#1752 update_session did remove_entry + mutate + restore_entry. The
// in-place rewrite must be behaviorally equivalent (handle-normalized — the
// slab handle VALUE legitimately differs because remove+restore allocates a
// fresh slot while in-place keeps the slot). `reference_update_session` below
// reproduces the OLD path verbatim; every scenario applies the same op to two
// tables and asserts equivalence via observable views (entries, lookups,
// owner-RG key sets, deltas) — never raw u32 handles.
// ---------------------------------------------------------------------------

/// Verbatim reproduction of the pre-#1752 remove+restore update_session.
fn reference_update_session(
    table: &mut SessionTable,
    req: SessionUpdate<'_>,
    ha_activation: bool,
) -> bool {
    let SessionUpdate {
        key,
        decision,
        metadata,
        origin,
        now_ns,
        protocol,
        tcp_flags,
    } = req;
    let Some(mut entry) = table.remove_entry(key) else {
        return false;
    };
    if !ha_activation {
        if entry.origin.is_peer_synced() && !origin.is_peer_synced() {
        } else if entry.origin.is_peer_synced() && origin.is_peer_synced() {
            table.restore_entry(key.clone(), entry);
            return false;
        } else if !entry.origin.is_peer_synced() && origin.is_peer_synced() {
            table.restore_entry(key.clone(), entry);
            return false;
        }
    }
    let was_peer_synced = entry.origin.is_peer_synced();
    entry.decision = decision;
    entry.metadata = metadata.clone();
    entry.origin = origin;
    entry.install_epoch = table.next_epoch();
    entry.last_seen_ns = now_ns;
    // #3046: mirror update_session exactly — set the sticky reset flag FIRST,
    // then select the timeout consulting it (RST→short, FIN→30s), so the
    // in-place/reference parity sweeps stay byte-equivalent.
    entry.reset |= matches!(protocol, PROTO_TCP) && (tcp_flags & TCP_RST) != 0;
    // #3489: mirror update_session — `closing` is sticky too. If this stayed a
    // plain `=`, the in-place-vs-reference parity sweep would stay blind to the
    // #3489 bug (both sides would agree on the wrong non-sticky behavior).
    entry.closing |= matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0;
    // #3152/#4109: mirror update_session — promote OPENING -> ESTABLISHED only
    // on a genuine reverse SYN-ACK (is_syn_ack + is_reverse), then select the
    // timeout consulting the state. Keeping this in lock-step with the
    // production gate keeps the in-place-vs-reference parity sweep honest.
    entry.established |=
        matches!(protocol, PROTO_TCP) && is_syn_ack(tcp_flags) && metadata.is_reverse;
    entry.expires_after_ns = if entry.closing {
        if entry.reset {
            TCP_RST_TIMEOUT_NS
        } else {
            TCP_CLOSING_TIMEOUT_NS
        }
    } else {
        session_timeout_ns(
            protocol,
            tcp_flags,
            entry.established,
            &table.timeouts,
            entry.metadata.inactivity_timeout_ns,
            // #3527: mirror update_session — resolve the per-zone half-open
            // override so the reference parity sweep stays faithful.
            table.opening_override_for(entry.metadata.ingress_zone),
        )
    };
    let created_ns = entry.created_ns;
    table.restore_entry(key.clone(), entry);
    table.push_to_wheel(key, now_ns);
    if was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse {
        // #9412: production's promote stamps the entry's close class; mirror it.
        let tcp_close_class = table.close_class_wire_for(key);
        table.push_delta(SessionDelta {
            kind: SessionDeltaKind::Open,
            key: key.clone(),
            decision,
            metadata,
            origin,
            fabric_redirect_sync: false,
            created_ns,
            last_seen_ns: now_ns,
            counters: SessionCounters::default(),
            observed_tos: 0,
            observed_tcp_flags: 0,
            session_id: 0,
            bulk_resync: false,
            tcp_close_class,
        });
    }
    true
}

fn entries_equiv(a: &SessionTable, b: &SessionTable, key: &SessionKey) -> bool {
    match (a.entry_by_key(key), b.entry_by_key(key)) {
        (Some(ea), Some(eb)) => {
            ea.decision == eb.decision
                && ea.metadata == eb.metadata
                && ea.origin == eb.origin
                && ea.install_epoch == eb.install_epoch
                && ea.last_seen_ns == eb.last_seen_ns
                && ea.expires_after_ns == eb.expires_after_ns
                && ea.closing == eb.closing
                && ea.reset == eb.reset
                && ea.wheel_tick == eb.wheel_tick
        }
        (None, None) => true,
        _ => false,
    }
}

fn sorted_keys(mut v: Vec<SessionKey>) -> Vec<String> {
    let mut s: Vec<String> = v.drain(..).map(|k| format!("{k:?}")).collect();
    s.sort();
    s
}

/// Assert handle-normalized equivalence of two tables across entries, the
/// reverse/wire NAT lookups for the given probe keys, owner-RG key sets, and
/// drained deltas.
fn assert_tables_equiv(
    inplace: &mut SessionTable,
    reference: &mut SessionTable,
    keys: &[SessionKey],
    probe_keys: &[SessionKey],
    owner_rgs: &[i32],
) {
    assert_eq!(inplace.len(), reference.len(), "len mismatch");
    for k in keys {
        assert!(entries_equiv(inplace, reference, k), "entry mismatch for {k:?}");
    }
    for pk in probe_keys {
        assert_eq!(
            inplace.find_forward_nat_match(pk).map(|m| m.key),
            reference.find_forward_nat_match(pk).map(|m| m.key),
            "find_forward_nat_match diverged for {pk:?}"
        );
        assert_eq!(
            inplace.find_forward_wire_match(pk).map(|m| m.key),
            reference.find_forward_wire_match(pk).map(|m| m.key),
            "find_forward_wire_match diverged for {pk:?}"
        );
    }
    assert_eq!(
        sorted_keys(inplace.owner_rg_session_keys(owner_rgs)),
        sorted_keys(reference.owner_rg_session_keys(owner_rgs)),
        "owner_rg_session_keys diverged"
    );
    // #4915: the stable session id is a per-table monotonic counter that
    // legitimately differs between the in-place-promote path (which KEEPS the
    // original id) and the remove+reinstall reference path (which reallocates,
    // and whose manual delta helper hardcodes 0). It is an internal identity, not
    // an observable behavior these differential tests pin — `entries_equiv` above
    // already excludes it from entry comparison — so normalize it out of the
    // delta comparison rather than asserting two independent counters agree.
    let mut inplace_deltas = inplace.drain_deltas(256);
    let mut reference_deltas = reference.drain_deltas(256);
    for d in inplace_deltas.iter_mut() {
        d.session_id = 0;
    }
    for d in reference_deltas.iter_mut() {
        d.session_id = 0;
    }
    assert_eq!(inplace_deltas, reference_deltas, "deltas diverged");
}

fn nat_rewrite() -> SessionDecision {
    SessionDecision {
        resolution: resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            rewrite_src_port: Some(40001),
            ..NatDecision::default()
        },
    }
}

/// Build two identical tables with `key` installed at the given origin.
fn two_tables_with(
    key: &SessionKey,
    decision: SessionDecision,
    md: SessionMetadata,
    origin: SessionOrigin,
    now: u64,
) -> (SessionTable, SessionTable) {
    let mut a = SessionTable::new();
    let mut b = SessionTable::new();
    for t in [&mut a, &mut b] {
        assert!(t.install_with_protocol_with_origin(
            key.clone(),
            decision,
            md.clone(),
            origin,
            now,
            key.protocol,
            0,
        ));
    }
    (a, b)
}

#[test]
fn inplace_local_refresh_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let req = |now| SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: now,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(ip.update_session(req(2_000), false));
    assert!(reference_update_session(&mut rf, req(2_000), false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_peer_to_local_promote_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::SyncImport, 1_000);
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let r1 = ip.update_session(req.clone(), false);
    let r2 = reference_update_session(&mut rf, req, false);
    assert_eq!(r1, r2);
    assert!(r1, "promote should succeed");
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_peer_to_peer_reject_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::SyncImport, 1_000);
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SyncImport,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(!ip.update_session(req.clone(), false));
    assert!(!reference_update_session(&mut rf, req, false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_local_from_peer_reject_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SyncImport,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(!ip.update_session(req.clone(), false));
    assert!(!reference_update_session(&mut rf, req, false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_ha_activation_matches_reference() {
    let key = key_v4();
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::SyncImport, 1_000);
    // ha_activation=true always applies regardless of origin.
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SyncImport,
        now_ns: 3_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(ip.update_session(req.clone(), true));
    assert!(reference_update_session(&mut rf, req, true));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
}

#[test]
fn inplace_nat_reindex_matches_reference() {
    let key = key_v4();
    // baseline: default nat. refresh: nat rewrite -> reverse index keys change.
    let (mut ip, mut rf) = two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let probe_old = reverse_wire_key(&key, NatDecision::default());
    let probe_new = reverse_wire_key(&key, nat_rewrite().nat);
    let req = SessionUpdate {
        key: &key,
        decision: nat_rewrite(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(ip.update_session(req.clone(), false));
    assert!(reference_update_session(&mut rf, req, false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[probe_old, probe_new], &[1, 2]);
}

#[test]
fn inplace_owner_rg_transitions_match_reference() {
    let key = key_v4();
    for (from_rg, to_rg) in [(1i32, 2i32), (1, 0), (0, 1)] {
        let mut md_from = metadata();
        md_from.owner_rg_id = from_rg;
        let (mut ip, mut rf) =
            two_tables_with(&key, decision(), md_from, SessionOrigin::ForwardFlow, 1_000);
        let mut md_to = metadata();
        md_to.owner_rg_id = to_rg;
        let req = SessionUpdate {
            key: &key,
            decision: decision(),
            metadata: md_to,
            origin: SessionOrigin::ForwardFlow,
            now_ns: 2_000,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        assert!(ip.update_session(req.clone(), false));
        assert!(reference_update_session(&mut rf, req, false));
        assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[0, 1, 2]);
    }
}

#[test]
fn inplace_reject_reasserts_displaced_collision_like_reference() {
    // Simulate a secondary-index collision: another (bogus) handle has displaced
    // this session's reverse-wire index slot. Today's reject path re-asserts via
    // remove+restore; in-place re-asserts via index_forward_nat_key_parts. Both
    // must re-win the slot identically.
    let key = key_v4();
    let (mut ip, mut rf) =
        two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let collide = reverse_wire_key(&key, NatDecision::default());
    for t in [&mut ip, &mut rf] {
        // #4399: overwrite the bucket with a bogus handle -> the real
        // session's reverse-wire slot is displaced (the multimap analogue of
        // the pre-#4399 single-value `insert(collide, 9999)`).
        t.nat_reverse_index
            .insert(collide.clone(), smallvec::smallvec![9999u32]);
    }
    // local<-peer reject (origin SyncImport on a local entry).
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::SyncImport,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(!ip.update_session(req.clone(), false));
    assert!(!reference_update_session(&mut rf, req, false));
    // Both must have re-won the displaced slot back to the real session.
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[collide], &[1, 2]);
}

#[test]
fn inplace_accept_reasserts_displaced_collision_like_reference() {
    let key = key_v4();
    let (mut ip, mut rf) =
        two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
    let collide = reverse_wire_key(&key, NatDecision::default());
    for t in [&mut ip, &mut rf] {
        // #4399: overwrite the bucket with a bogus handle -> displaced slot.
        t.nat_reverse_index
            .insert(collide.clone(), smallvec::smallvec![9999u32]);
    }
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(ip.update_session(req.clone(), false));
    assert!(reference_update_session(&mut rf, req, false));
    assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[collide], &[1, 2]);
}

// ── #1855: corrupted key_to_handle contract ──────────────────────────
//
// A stale or vacant `key_to_handle` mapping is impossible-by-construction
// (per-worker single-writer `&mut self`, #964 eager-cleanup invariant in
// `remove_entry`); the rigs below reach it only via private-field access.
// The contract — decided in docs/research/1855-inplace-contract/plan.md —
// is the `remove_entry` #964 precedent:
//   - debug builds: `debug_assert!` fires (loud logic-bug detector),
//     documented by the `#[cfg(debug_assertions)]` `#[should_panic]`
//     variants below;
//   - release builds: tolerate + return false without touching the
//     reused-slot session, documented by the
//     `#[cfg(not(debug_assertions))]` `*_returns_false_no_panic` tests
//     (exercised by `cargo test --release`).

/// Rig: install `key` and `other`, then point `key`'s mapping at
/// `other`'s slab slot — a stale mapping onto a REUSED slot, which the
/// primary-key guard (`record.key != *key`) must catch.
fn rig_stale_handle_table() -> (SessionTable, SessionKey, SessionKey) {
    let key = key_v4();
    let other = key_v6();
    let mut t = SessionTable::new();
    assert!(t.install_with_protocol_with_origin(
        key.clone(), decision(), metadata(), SessionOrigin::ForwardFlow, 1_000, key.protocol, 0,
    ));
    assert!(t.install_with_protocol_with_origin(
        other.clone(), decision(), metadata(), SessionOrigin::ForwardFlow, 1_000, other.protocol, 0,
    ));
    let other_handle = *t.key_to_handle.get(&other).expect("other handle");
    t.key_to_handle.insert(key.clone(), other_handle);
    (t, key, other)
}

#[cfg(not(debug_assertions))]
#[test]
fn inplace_stale_handle_returns_false_no_panic() {
    let (mut t, key, other) = rig_stale_handle_table();
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    // Release contract: must not panic and must not mutate the unrelated
    // `other` session occupying the reused slot.
    let before = t.entry_by_key(&other).map(|e| e.last_seen_ns);
    assert!(!t.update_session(req, false));
    assert_eq!(t.entry_by_key(&other).map(|e| e.last_seen_ns), before);
    // refresh_for_ha_transition shares the primary-key guard (#1855 AGY r1:
    // symmetric release coverage).
    assert!(!t.refresh_for_ha_transition(&key, decision(), metadata(), 2_000));
    assert_eq!(t.entry_by_key(&other).map(|e| e.last_seen_ns), before);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "update_session: stale key_to_handle")]
fn inplace_stale_handle_asserts_in_debug() {
    let (mut t, key, _other) = rig_stale_handle_table();
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let _ = t.update_session(req, false);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "refresh_for_ha_transition: stale key_to_handle")]
fn ha_transition_stale_handle_asserts_in_debug() {
    let (mut t, key, _other) = rig_stale_handle_table();
    let _ = t.refresh_for_ha_transition(&key, decision(), metadata(), 2_000);
}

#[test]
fn inplace_randomized_sequence_matches_reference() {
    // Deterministic LCG (Math.random is unavailable in this env; fixed seed).
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    let keys = [key_v4(), key_v6()];
    let mut ip = SessionTable::new();
    let mut rf = SessionTable::new();
    // Install both keys identically.
    for t in [&mut ip, &mut rf] {
        for k in &keys {
            assert!(t.install_with_protocol_with_origin(
                k.clone(), decision(), metadata(), SessionOrigin::ForwardFlow, 1_000, k.protocol, 0,
            ));
        }
    }
    for step in 0..400u64 {
        let k = &keys[(next() % 2) as usize];
        let origin = if next() % 3 == 0 { SessionOrigin::SyncImport } else { SessionOrigin::ForwardFlow };
        let dec = if next() % 4 == 0 { nat_rewrite() } else { decision() };
        let mut md = metadata();
        md.owner_rg_id = (next() % 3) as i32; // 0,1,2
        md.is_reverse = next() % 5 == 0;
        let ha = next() % 7 == 0;
        // Vary tcp_flags so the FIN/RST `closing` + `expires_after_ns` branch is
        // exercised, not only the steady-state tcp_flags=0 path.
        let tcp_flags = match next() % 4 {
            0 => TCP_FIN,
            1 => TCP_RST,
            _ => 0,
        };
        let now = 2_000 + step * 10;
        let req = SessionUpdate {
            key: k,
            decision: dec,
            metadata: md,
            origin,
            now_ns: now,
            protocol: k.protocol,
            tcp_flags,
        };
        let r1 = ip.update_session(req.clone(), ha);
        let r2 = reference_update_session(&mut rf, req, ha);
        assert_eq!(r1, r2, "accept/reject diverged at step {step}");
        let probes: Vec<SessionKey> = keys
            .iter()
            .flat_map(|kk| {
                [
                    reverse_wire_key(kk, NatDecision::default()),
                    reverse_wire_key(kk, nat_rewrite().nat),
                ]
            })
            .collect();
        assert_tables_equiv(&mut ip, &mut rf, &keys, &probes, &[0, 1, 2]);
    }
}

/// Verbatim reproduction of the pre-#1752 remove+restore refresh_for_ha_transition.
fn reference_refresh_for_ha_transition(
    table: &mut SessionTable,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    now_ns: u64,
) -> bool {
    let Some(mut entry) = table.remove_entry(key) else {
        return false;
    };
    entry.decision = decision;
    entry.metadata = metadata;
    entry.install_epoch = table.next_epoch();
    entry.last_seen_ns = now_ns;
    table.restore_entry(key.clone(), entry);
    table.push_to_wheel(key, now_ns);
    true
}

#[test]
fn inplace_ha_transition_matches_reference() {
    let key = key_v4();
    // Case 0: identical decision + metadata (owner_rg_id stays 1, nat unchanged)
    // -> the no-reindex/skip branch. Case 1: nat rewrite + owner_rg 1->2 -> the
    // reindex branch. Baseline metadata() has owner_rg_id=1, so case 0 must NOT
    // mutate md (else it would also reindex).
    let reindex_md = {
        let mut m = metadata();
        m.owner_rg_id = 2;
        m
    };
    for (dec, md) in [(decision(), metadata()), (nat_rewrite(), reindex_md)] {
        let (mut ip, mut rf) =
            two_tables_with(&key, decision(), metadata(), SessionOrigin::SyncImport, 1_000);
        let probe_old = reverse_wire_key(&key, NatDecision::default());
        let probe_new = reverse_wire_key(&key, dec.nat);
        assert!(ip.refresh_for_ha_transition(&key, dec, md.clone(), 2_000));
        assert!(reference_refresh_for_ha_transition(&mut rf, &key, dec, md, 2_000));
        assert_tables_equiv(
            &mut ip,
            &mut rf,
            &[key.clone()],
            &[probe_old, probe_new],
            &[0, 1, 2],
        );
    }
}

/// Rig: `key_to_handle` points at a slab slot that was never allocated —
/// the `entries.get(handle) == None` guard arm. See the #1855 contract
/// comment above `rig_stale_handle_table`.
fn rig_vacant_handle_table() -> (SessionTable, SessionKey) {
    let key = key_v4();
    let mut t = SessionTable::new();
    t.key_to_handle.insert(key.clone(), 9999u32);
    (t, key)
}

#[cfg(not(debug_assertions))]
#[test]
fn inplace_vacant_handle_returns_false_no_panic() {
    // Release contract: the vacant-slot guard must return false without
    // panicking (the debug_assert is compiled out).
    let (mut t, key) = rig_vacant_handle_table();
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    assert!(!t.update_session(req, false));
    // refresh_for_ha_transition shares the same guard.
    assert!(!t.refresh_for_ha_transition(&key, decision(), metadata(), 2_000));
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "update_session: key_to_handle had stale handle")]
fn inplace_vacant_handle_asserts_in_debug() {
    let (mut t, key) = rig_vacant_handle_table();
    let req = SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: 2_000,
        protocol: PROTO_TCP,
        tcp_flags: 0,
    };
    let _ = t.update_session(req, false);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "refresh_for_ha_transition: stale handle")]
fn ha_transition_vacant_handle_asserts_in_debug() {
    let (mut t, key) = rig_vacant_handle_table();
    let _ = t.refresh_for_ha_transition(&key, decision(), metadata(), 2_000);
}

#[test]
fn inplace_fin_rst_closing_matches_reference() {
    // FIN/RST set `closing` and shorten expires_after_ns; verify the in-place
    // path writes them identically to the reference for both flags.
    let key = key_v4();
    for flags in [TCP_FIN, TCP_RST, TCP_FIN | TCP_RST] {
        let (mut ip, mut rf) =
            two_tables_with(&key, decision(), metadata(), SessionOrigin::ForwardFlow, 1_000);
        let req = SessionUpdate {
            key: &key,
            decision: decision(),
            metadata: metadata(),
            origin: SessionOrigin::ForwardFlow,
            now_ns: 2_000,
            protocol: PROTO_TCP,
            tcp_flags: flags,
        };
        assert!(ip.update_session(req.clone(), false));
        assert!(reference_update_session(&mut rf, req, false));
        assert!(
            ip.entry_by_key(&key).expect("entry").closing,
            "closing should be set for flags {flags:#x}"
        );
        assert_tables_equiv(&mut ip, &mut rf, &[key.clone()], &[], &[1, 2]);
    }
}

// ── #1760: NAT reverse-key 1:N collision telemetry counter ───────────
//
// Reproduces the latent collision documented by the #1758 research:
// under interface-mode SNAT (rewrite_src = Some(egress), rewrite_src_port
// = None), two distinct internal hosts using the SAME ephemeral source
// port to the SAME external server translate to the SAME reverse wire key
// K. The single-valued nat_reverse_index can only point at one of them,
// so the second install displaces the first — a displacement event the
// counter must observe.

/// Interface-mode SNAT decision: rewrite only the source IP to `egress`,
/// leave the source port untranslated (rewrite_src_port = None). This is
/// the default SNAT mode and the #1758 reachable collision vector.
fn iface_snat_decision(egress: Ipv4Addr) -> SessionDecision {
    SessionDecision {
        resolution: resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(egress)),
            ..NatDecision::default()
        },
    }
}

#[test]
fn nat_reverse_key_collision_counter_increments_on_displacement() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let egress = Ipv4Addr::new(203, 0, 113, 9);

    // Two distinct internal hosts, SAME ephemeral source port, SAME
    // external server — interface-mode SNAT'd to the SAME egress IP.
    // reverse_wire_key for both = {src=8.8.8.8:443, dst=203.0.113.9:5555}
    // (port comes from the untranslated original src_port). Identical K.
    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 5555;
    let mut s2 = key_v4();
    s2.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    s2.src_port = 5555;
    assert_ne!(s1, s2, "the two forward keys must be distinct sessions");

    let dec = iface_snat_decision(egress);
    // Guard the repro precondition: the two distinct forward keys really
    // do derive the same reverse wire key.
    assert_eq!(
        reverse_wire_key(&s1, dec.nat),
        reverse_wire_key(&s2, dec.nat),
        "interface-mode SNAT must make the two flows share reverse key K",
    );

    // First install: K -> S1. No prior occupant, so no displacement.
    assert!(table.install_with_protocol(s1.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        table.nat_reverse_key_collisions(),
        0,
        "a single install with no prior K occupant must not count",
    );

    // Second install: K -> S2 collides with the live S1. #4438: interface-mode
    // SNAT collapses BOTH the reverse-wire key AND the forward-wire key, and
    // the collision counter now aggregates bucket-growth across all three NAT
    // indexes — so this one logical flow-pair bumps it twice (reverse_wire +
    // forward_wire; reverse_canonical does NOT collide here, the internal src
    // IPs differ). It is an upper-bound "collision path exercised" signal, not
    // a pair census.
    assert!(table.install_with_protocol(s2.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        table.nat_reverse_key_collisions(),
        2,
        "S2 colliding with live S1 bumps reverse_wire + forward_wire (#4438)",
    );

    // Re-asserting S2's own ownership (refresh re-asserts the same handle)
    // must NOT count — the append dedups when the handle already owns the key.
    let refresh_ns = now + 2 * WHEEL_TICK_NS;
    let req = SessionUpdate {
        key: &s2,
        decision: dec,
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        now_ns: refresh_ns,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    };
    assert!(table.update_session(req, false));
    assert_eq!(
        table.nat_reverse_key_collisions(),
        2,
        "S2 re-asserting its own ownership must not count (dedup on re-add)",
    );
}

#[test]
fn nat_reverse_key_collision_counter_zero_without_collision() {
    // Two flows with DISTINCT reverse keys (different source ports) under
    // interface-mode SNAT must never increment the collision counter.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = iface_snat_decision(Ipv4Addr::new(203, 0, 113, 9));

    let mut a = key_v4();
    a.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    a.src_port = 5555;
    let mut b = key_v4();
    b.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    b.src_port = 6666; // distinct port -> distinct reverse wire key
    assert_ne!(
        reverse_wire_key(&a, dec.nat),
        reverse_wire_key(&b, dec.nat),
        "distinct source ports must yield distinct reverse keys",
    );

    assert!(table.install_with_protocol(a, dec, metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(b, dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        table.nat_reverse_key_collisions(),
        0,
        "non-colliding flows must leave the collision counter at 0",
    );
}

// ── #4399: 1:N reverse-key multimap + validate-on-lookup ─────────────
//
// The pre-#4399 single-value `nat_reverse_index` DISPLACED the earlier
// session on a reverse-key collision, so the displaced session's return
// traffic was mis-delivered or (once the later session closed) dropped.
// The multimap keeps BOTH colliding forward handles in one bucket and
// `find_forward_nat_match` validates each candidate against the full reply
// tuple. These tests are RED on the pre-#4399 single-value implementation.
//
// #6751 SCOPE NOTE — read the two-host interface-SNAT fixtures below as
// DEFENCE IN DEPTH, not as an accepted outcome. Interface-mode SNAT no longer
// ADMITS the byte-identical reverse tuple: the admission mint
// (`allocate_interface_identity`, nat/allocator.rs) reserves the translated
// reverse identity and PATs the later collider, so a live pair of internal
// hosts on one source port to one server can no longer reach these installs
// through the packet path. These tests install DIRECTLY into the table,
// bypassing admission, and they stay green deliberately: the non-bijective
// classes admission does not remove (DNAT-to-shared-backend, NAT64,
// non-bijective static NAT, and the `port no-translation` pairs the allocator
// admits on purpose) still land here, and the interface-mode fixture remains
// the cheapest shape in which to exercise the multimap. What they assert is
// that the index resolves DETERMINISTICALLY under an ambiguous tuple — NOT
// that the reply reaches the right internal host, which no index can decide
// once the tuple is ambiguous. That is why #6751 had to be fixed at
// admission.

fn small_bucket_len(table: &SessionTable, reverse_key: &SessionKey) -> usize {
    table
        .nat_reverse_index
        .get(reverse_key)
        .map_or(0, |bucket| bucket.len())
}

#[test]
fn nat_reverse_1n_collision_preserves_displaced_return_path() {
    // Two interface-mode SNAT sessions from DIFFERENT internal hosts
    // (10.0.0.1 / 10.0.0.2) using the SAME ephemeral source port to the SAME
    // external server collapse to the SAME external reverse wire key K
    // (source-IP-only rewrite, no port translation -> non-bijective, the
    // #1758 collision). The single-value index displaced S1 the moment S2
    // installed; the 1:N multimap keeps BOTH handles resolvable.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = iface_snat_decision(Ipv4Addr::new(203, 0, 113, 9));

    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 5555;
    let mut s2 = key_v4();
    s2.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    s2.src_port = 5555;

    let reply = reverse_wire_key(&s1, dec.nat);
    assert_eq!(
        reply,
        reverse_wire_key(&s2, dec.nat),
        "the two flows must share reverse wire key K",
    );

    assert!(table.install_with_protocol(s1.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(s2.clone(), dec, metadata(), now, PROTO_TCP, 0x10));

    // Both colliding handles coexist in bucket K (the single-value map held
    // only the last-installed S2).
    assert_eq!(
        small_bucket_len(&table, &reply),
        2,
        "both colliding forward handles must share the reverse-key bucket",
    );
    assert_eq!(
        table.nat_reverse_key_collisions(),
        2,
        "#4438: interface SNAT collides both reverse_wire and forward_wire, so \
         the aggregate collision counter bumps twice for this one flow-pair",
    );

    // A reply on K resolves to a LIVE forward session. Both validate — the
    // wire tuple is genuinely ambiguous under no-PAT interface SNAT — so the
    // multimap returns the first-installed S1 deterministically instead of
    // "whatever was written last".
    assert_eq!(
        table.find_forward_nat_match(&reply).map(|m| m.key),
        Some(s1.clone()),
        "reply on K resolves to the first-installed forward session",
    );

    // RED-on-revert: close S2 (the LAST-installed). The single-value map
    // stored K -> S2, so removing S2 wiped K entirely and STRANDED S1's
    // return path (find -> None). The multimap removes ONLY S2's handle,
    // leaving S1 resolvable.
    table.delete(&s2);
    assert_eq!(
        small_bucket_len(&table, &reply),
        1,
        "delete removes only S2's handle; S1's entry remains in the bucket",
    );
    assert_eq!(
        table.find_forward_nat_match(&reply).map(|m| m.key),
        Some(s1.clone()),
        "surviving S1 must still resolve after the colliding S2 closes \
         (single-value map returned None here)",
    );

    // Closing S1 too empties the bucket and drops the reverse key.
    table.delete(&s1);
    assert_eq!(
        small_bucket_len(&table, &reply),
        0,
        "the reverse key is dropped once its bucket empties",
    );
    assert_eq!(
        table.find_forward_nat_match(&reply),
        None,
        "no session left -> no reverse-NAT match",
    );
}

#[test]
fn nat_reverse_1n_delete_removes_specific_handle_not_the_key() {
    // Symmetric to the test above: closing the FIRST-installed session leaves
    // the SECOND resolvable. Proves the delete is per-handle, not per-key.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = iface_snat_decision(Ipv4Addr::new(203, 0, 113, 9));

    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 7777;
    let mut s2 = key_v4();
    s2.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    s2.src_port = 7777;
    let reply = reverse_wire_key(&s1, dec.nat);

    assert!(table.install_with_protocol(s1.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(s2.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(small_bucket_len(&table, &reply), 2);

    // Close S1 (first-installed). S2 must survive and resolve.
    table.delete(&s1);
    assert_eq!(small_bucket_len(&table, &reply), 1);
    assert_eq!(
        table.find_forward_nat_match(&reply).map(|m| m.key),
        Some(s2.clone()),
        "surviving S2 resolves after the first-installed S1 closes",
    );
}

#[test]
fn nat_reverse_1n_pool_snat_fast_path_stays_single_value() {
    // Pool-mode SNAT translates the source port (PAT) -> bijective -> two
    // distinct flows never share a reverse wire key, so every bucket stays
    // len 1 (the zero-collision fast path). Preserves the single-value
    // behavior the pool-mode SNAT throughput path depends on.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = nat_rewrite(); // rewrite_src + rewrite_src_port (PAT)

    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 5555;
    let reply = reverse_wire_key(&s1, dec.nat);

    assert!(table.install_with_protocol(s1.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        small_bucket_len(&table, &reply),
        1,
        "a bijective pool-mode SNAT reverse key must stay a len-1 bucket",
    );
    assert_eq!(table.nat_reverse_key_collisions(), 0, "no collision on PAT");
    assert_eq!(
        table.find_forward_nat_match(&reply).map(|m| m.key),
        Some(s1.clone()),
        "the pool-mode reply resolves through the single-value fast path",
    );
}

// ── #4438: 1:N forward_wire_index + reverse_translated_index multimaps ─
//
// #4399 fixed only nat_reverse_index. The OTHER two NAT session indexes
// still DISPLACED on a 1:N collision, so a colliding session hijacked an
// earlier one on the forward-wire or translated-alias path. These tests
// extend the #4399 discipline (bucket + validate-on-lookup + per-handle
// delete + pool-mode len-1 fast path) to both. They are RED on the
// pre-#4438 single-value implementation.

fn forward_wire_bucket_len(table: &SessionTable, wire_key: &SessionKey) -> usize {
    table
        .forward_wire_index
        .get(wire_key)
        .map_or(0, |bucket| bucket.len())
}

fn reverse_translated_bucket_len(table: &SessionTable, translated_key: &SessionKey) -> usize {
    table
        .reverse_translated_index
        .get(translated_key)
        .map_or(0, |bucket| bucket.len())
}

#[test]
fn forward_wire_1n_collision_preserves_displaced_session() {
    // Two interface-mode SNAT flows from DIFFERENT internal hosts using the
    // SAME ephemeral source port to the SAME external server collapse to the
    // SAME forward-wire key W (source-IP-only rewrite, no port translation ->
    // non-bijective, the #1758 collision; interface SNAT collides the
    // forward-wire tuple just as it collides the reverse-wire tuple). The
    // single-value index displaced S1 the moment S2 installed; the 1:N
    // multimap keeps BOTH handles resolvable.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = iface_snat_decision(Ipv4Addr::new(203, 0, 113, 9));

    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 5555;
    let mut s2 = key_v4();
    s2.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    s2.src_port = 5555;

    let wire = forward_wire_key(&s1, dec.nat);
    assert_eq!(
        wire,
        forward_wire_key(&s2, dec.nat),
        "interface SNAT must make the two flows share forward-wire key W",
    );
    // The forward-wire key genuinely differs from each untranslated key, so
    // the index is populated for both (index gate: forward_wire != key).
    assert_ne!(wire, s1);
    assert_ne!(wire, s2);

    assert!(table.install_with_protocol(s1.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(s2.clone(), dec, metadata(), now, PROTO_TCP, 0x10));

    assert_eq!(
        forward_wire_bucket_len(&table, &wire),
        2,
        "both colliding forward handles must share the forward-wire bucket",
    );
    // #4438: interface SNAT collides both reverse_wire and forward_wire, so the
    // aggregate collision counter bumps twice for this one flow-pair.
    assert_eq!(table.nat_reverse_key_collisions(), 2);

    // A forward-wire lookup on W resolves to a LIVE session. Both validate --
    // the wire tuple is genuinely ambiguous under no-PAT interface SNAT -- so
    // the multimap returns the first-installed S1 deterministically instead of
    // "whatever was written last".
    assert_eq!(
        table.find_forward_wire_match(&wire).map(|m| m.key),
        Some(s1.clone()),
        "forward-wire lookup on W resolves to the first-installed session",
    );

    // RED-on-revert: close S2 (the LAST-installed). The single-value map stored
    // W -> S2, so removing S2 wiped W entirely and STRANDED S1's wire lookup
    // (find -> None). The multimap removes ONLY S2's handle.
    table.delete(&s2);
    assert_eq!(
        forward_wire_bucket_len(&table, &wire),
        1,
        "delete removes only S2's handle; S1's entry remains in the bucket",
    );
    assert_eq!(
        table.find_forward_wire_match(&wire).map(|m| m.key),
        Some(s1.clone()),
        "surviving S1 must still resolve after colliding S2 closes \
         (single-value map returned None here)",
    );

    // Closing S1 too empties the bucket and drops the forward-wire key.
    table.delete(&s1);
    assert_eq!(
        forward_wire_bucket_len(&table, &wire),
        0,
        "the forward-wire key is dropped once its bucket empties",
    );
    assert!(table.find_forward_wire_match(&wire).is_none());
}

#[test]
fn forward_wire_1n_delete_removes_specific_handle_not_the_key() {
    // Symmetric: closing the FIRST-installed session leaves the SECOND
    // resolvable. Proves the forward-wire delete is per-handle, not per-key.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = iface_snat_decision(Ipv4Addr::new(203, 0, 113, 9));

    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 7777;
    let mut s2 = key_v4();
    s2.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    s2.src_port = 7777;
    let wire = forward_wire_key(&s1, dec.nat);

    assert!(table.install_with_protocol(s1.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(s2.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(forward_wire_bucket_len(&table, &wire), 2);

    // Close S1 (first-installed). S2 must survive and resolve on W.
    table.delete(&s1);
    assert_eq!(forward_wire_bucket_len(&table, &wire), 1);
    assert_eq!(
        table.find_forward_wire_match(&wire).map(|m| m.key),
        Some(s2.clone()),
        "surviving S2 resolves on W after the first-installed S1 closes",
    );
}

#[test]
fn forward_wire_1n_pool_snat_fast_path_stays_single_value() {
    // Pool-mode SNAT translates the source port (PAT) -> bijective -> two
    // distinct flows never share a forward-wire key, so every bucket stays
    // len 1 (the zero-collision fast path the throughput path depends on).
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = nat_rewrite(); // rewrite_src + rewrite_src_port (PAT)

    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 5555;
    let wire = forward_wire_key(&s1, dec.nat);

    assert!(table.install_with_protocol(s1.clone(), dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        forward_wire_bucket_len(&table, &wire),
        1,
        "a bijective pool-mode SNAT forward-wire key stays a len-1 bucket",
    );
    assert_eq!(
        table.find_forward_wire_match(&wire).map(|m| m.key),
        Some(s1.clone()),
        "the pool-mode forward-wire lookup resolves through the len-1 fast path",
    );
}

/// Build a reverse (reply-direction) SessionDecision whose NAT rewrites the
/// destination to a shared backend and a reverse metadata carrying the given
/// `zone` (used only to distinguish which reverse session resolved).
fn shared_backend_reverse(backend: IpAddr, zone: u16) -> (SessionDecision, SessionMetadata) {
    let decision = SessionDecision {
        resolution: resolution(),
        nat: NatDecision {
            rewrite_dst: Some(backend),
            ..NatDecision::default()
        },
    };
    let mut md = metadata();
    md.is_reverse = true;
    md.ingress_zone = zone;
    (decision, md)
}

#[test]
fn reverse_translated_1n_collision_preserves_displaced_alias() {
    // DNAT-to-shared-backend: client C reaches two external VIPs that both DNAT
    // to the SAME backend B. Each reverse entry's translated (alias) tuple
    // overwrites dst -> B, so the two DISTINCT reverse keys collapse to the
    // SAME translated key T (the non-bijective #1758 class). The single-value
    // index displaced R1 the moment R2 installed; the 1:N multimap keeps BOTH
    // aliases resolvable.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let backend = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50));
    let (rev_dec, r1_meta) = shared_backend_reverse(backend, 101);
    let (_, r2_meta) = shared_backend_reverse(backend, 202);

    let r1 = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: client,
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        src_port: 40001,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut r2 = r1.clone();
    r2.dst_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

    let t = translated_session_key(&r1, rev_dec.nat);
    assert_eq!(
        t,
        translated_session_key(&r2, rev_dec.nat),
        "both reverse sessions must share the translated alias key T",
    );
    // T differs from each stored reverse key (index gate: translated != key)
    // and from every primary key, so the T lookup takes the alias path.
    assert_ne!(t, r1);
    assert_ne!(t, r2);

    assert!(table.install_with_protocol(r1.clone(), rev_dec, r1_meta, now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(r2.clone(), rev_dec, r2_meta, now, PROTO_TCP, 0x10));

    assert_eq!(
        reverse_translated_bucket_len(&table, &t),
        2,
        "both colliding reverse handles must share the translated-key bucket",
    );
    assert_eq!(
        table.nat_reverse_key_collisions(),
        1,
        "the translated-key collision must be counted exactly once",
    );

    // Alias lookup on T resolves to the first-installed R1 deterministically
    // (distinguished by ingress_zone) instead of "whatever was written last".
    assert_eq!(
        table
            .lookup(&t, now + WHEEL_TICK_NS, 0x10)
            .map(|l| l.metadata.ingress_zone),
        Some(101),
        "alias lookup on T resolves to the first-installed reverse session",
    );

    // RED-on-revert: close R2 (the LAST-installed). The single-value map stored
    // T -> R2, so removing R2 wiped T entirely and STRANDED R1's alias lookup
    // (lookup -> None). The multimap removes ONLY R2's handle.
    table.delete(&r2);
    assert_eq!(reverse_translated_bucket_len(&table, &t), 1);
    assert_eq!(
        table
            .lookup(&t, now + 2 * WHEEL_TICK_NS, 0x10)
            .map(|l| l.metadata.ingress_zone),
        Some(101),
        "surviving R1 must still resolve via T after colliding R2 closes \
         (single-value map returned None here)",
    );

    // Closing R1 too empties the bucket and drops the translated key.
    table.delete(&r1);
    assert_eq!(reverse_translated_bucket_len(&table, &t), 0);
    assert!(table.lookup(&t, now + 3 * WHEEL_TICK_NS, 0x10).is_none());
}

#[test]
fn reverse_translated_1n_delete_removes_specific_handle_not_the_key() {
    // Symmetric: closing the FIRST-installed reverse session leaves the SECOND
    // resolvable via the shared translated key. Per-handle delete, not per-key.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let backend = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50));
    let (rev_dec, r1_meta) = shared_backend_reverse(backend, 101);
    let (_, r2_meta) = shared_backend_reverse(backend, 202);

    let r1 = SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: client,
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        src_port: 50002,
        dst_port: 8443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut r2 = r1.clone();
    r2.dst_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    let t = translated_session_key(&r1, rev_dec.nat);

    assert!(table.install_with_protocol(r1.clone(), rev_dec, r1_meta, now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(r2.clone(), rev_dec, r2_meta, now, PROTO_TCP, 0x10));
    assert_eq!(reverse_translated_bucket_len(&table, &t), 2);

    // Close R1 (first-installed). R2 must survive and resolve via T.
    table.delete(&r1);
    assert_eq!(reverse_translated_bucket_len(&table, &t), 1);
    assert_eq!(
        table
            .lookup(&t, now + WHEEL_TICK_NS, 0x10)
            .map(|l| l.metadata.ingress_zone),
        Some(202),
        "surviving R2 resolves via T after the first-installed R1 closes",
    );
}

// ── #1861: pair-admission preflight (can_admit) + refusal counters ────
//
// The transactional-install fix relies on `can_admit(needed)` being a
// sound preflight for the forward+reverse install pair: a passing
// preflight on the single-threaded table must make the subsequent
// `needed` installs infallible within the same descriptor iteration.

fn key_with_port(port: u16) -> SessionKey {
    SessionKey {
        src_port: port,
        ..key_v4()
    }
}

#[test]
fn can_admit_boundary_matches_install_cap() {
    let mut table = SessionTable::new();
    table.set_max_sessions_for_test(4);
    let now = 1_000_000_000u64;
    for port in 0..2u16 {
        assert!(table.install_with_protocol(
            key_with_port(10_000 + port),
            decision(),
            metadata(),
            now,
            PROTO_TCP,
            0x02,
        ));
    }
    // len == 2, cap == 4: a forward+reverse pair (2 slots) fits exactly.
    assert!(table.can_admit(2));
    assert!(table.install_with_protocol(
        key_with_port(10_002),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x02,
    ));
    // len == 3, cap == 4: a pair no longer fits, a single still does.
    assert!(!table.can_admit(2), "cap-1 must refuse a 2-slot pair");
    assert!(table.can_admit(1));
    assert!(table.install_with_protocol(
        key_with_port(10_003),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x02,
    ));
    // len == cap: nothing fits, and the raw install agrees (this is the
    // post-preflight infallibility contract: can_admit(n)==true ⇒ the
    // next n installs return true).
    assert!(!table.can_admit(1));
    assert!(!table.install_with_protocol(
        key_with_port(10_004),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x02,
    ));
    assert_eq!(table.create_drops(), 1, "at-cap install must count a create drop");
    // can_admit(0) is the tracking-not-required case — always true.
    assert!(table.can_admit(0));
}

#[test]
fn can_admit_is_conservative_for_replacements() {
    // Matches install_with_protocol_with_origin's own cap check, which
    // refuses replacements at cap even though they would not grow the
    // table. Crediting replacements in the preflight would break the
    // infallibility contract (preflight passes, install fails).
    let mut table = SessionTable::new();
    table.set_max_sessions_for_test(1);
    let now = 1_000_000_000u64;
    let key = key_with_port(20_000);
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now,
        PROTO_TCP,
        0x02,
    ));
    assert!(!table.can_admit(1));
    assert!(
        !table.install_with_protocol(key, decision(), metadata(), now, PROTO_TCP, 0x02),
        "raw install also refuses the replacement at cap — preflight matches"
    );
}

#[test]
fn admission_refused_and_install_partial_counters_accumulate() {
    let mut table = SessionTable::new();
    assert_eq!(table.admission_refused(), 0);
    assert_eq!(table.install_partial(), 0);
    table.note_admission_refused();
    table.note_admission_refused();
    table.note_install_partial();
    assert_eq!(table.admission_refused(), 2);
    assert_eq!(table.install_partial(), 1);
}

// ── #1870: sync-family upsert infallibility at max_sessions ─────────
//
// The UpsertLocal arm (session_glue) relies on
// `upsert_synced_with_origin(_, allow_replace_local=true)` having no
// failure mode: no cap check, and the only `false` exit (the
// local-clobber guard) is bypassed. Pin both at-cap shapes in a
// release-effective `assert!` (the arm's own debug_assert!s compile
// out — #1855 contract).
#[test]
fn upsert_synced_allow_replace_is_infallible_at_cap() {
    let mut table = SessionTable::new();
    table.set_max_sessions_for_test(1);
    let key = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(table.len(), 1, "table at cap");

    // Same-key replace at cap: succeeds without growth.
    assert!(
        table.upsert_synced(
            key.clone(),
            decision(),
            metadata(),
            now + 1,
            PROTO_TCP,
            0x10,
            true,
        ),
        "same-key upsert at cap must succeed"
    );
    assert_eq!(table.len(), 1);

    // New-key insert at cap: the sync family is uncapped by design
    // (#1861 row I11) — succeeds and grows past max_sessions.
    let second = SessionKey {
        src_port: key.src_port.wrapping_add(1),
        ..key
    };
    assert!(
        table.upsert_synced(
            second.clone(),
            decision(),
            metadata(),
            now + 2,
            PROTO_TCP,
            0x10,
            true,
        ),
        "new-key upsert at cap must succeed (uncapped sync family)"
    );
    assert_eq!(table.len(), 2, "table exceeds max_sessions by design");
    assert_eq!(table.create_drops(), 0, "no install-path drop counted");
}

// =====================================================================
// #2120: standby retention gate tests.
//
// The STANDBY must NOT age peer-synced sessions for an RG it does not
// forward (restoring the dead Go-GC IsLocalPrimary contract into the
// userspace wheel). These tests drive `expire_stale_entries_ha` with an
// `ExpireHaContext` built from closures so the per-RG forwarding
// predicate, the rg_epoch reader, and node_active are all controllable.
//
// NON-TAUTOLOGY: every HOLD test installs a peer-synced session that the
// PRE-FIX wheel (and the ha=None path) removes unconditionally; the
// assertion that it is RETAINED fails against the old behavior.
// =====================================================================

const TEST_CEIL_MULT: u64 = STALE_SYNCED_CEILING_MULT;
const TEST_CEIL_ABS_NS: u64 = STALE_SYNCED_CEILING_ABS_NS;

/// Build a context: this node forwards `forwarding_rgs`, node_active is
/// derived (forwards anything), and every RG reports epoch `epoch`
/// (including rg_epochs[0] for owner_rg_id<=0).
fn run_expire_ha(
    table: &mut SessionTable,
    now_ns: u64,
    forwarding_rgs: &[i32],
    epoch_for_rg: &dyn Fn(i32) -> u32,
) -> Vec<ExpiredSession> {
    let node_active = !forwarding_rgs.is_empty();
    let fwd = |rg: i32| -> bool {
        if rg > 0 {
            forwarding_rgs.contains(&rg)
        } else {
            node_active
        }
    };
    let ctx = ExpireHaContext {
        node_active,
        forwards_rg: &fwd,
        epoch_of: epoch_for_rg,
        ceiling_mult: TEST_CEIL_MULT,
        ceiling_abs_ns: TEST_CEIL_ABS_NS,
    };
    table.expire_stale_entries_ha(now_ns, Some(&ctx))
}

fn install_synced_tcp(table: &mut SessionTable, key: &SessionKey, rg: i32, now_ns: u64) {
    install_synced_tcp_origin(table, key, rg, now_ns, SessionOrigin::SyncImport);
}

fn install_synced_tcp_origin(
    table: &mut SessionTable,
    key: &SessionKey,
    rg: i32,
    now_ns: u64,
    origin: SessionOrigin,
) {
    let mut md = metadata();
    md.owner_rg_id = rg;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        origin,
        now_ns,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
}

// Advance just past the 300s TCP established timeout, bypassing the GC
// interval gate the way the existing wheel tests do.
fn past_tcp_timeout(then: u64) -> u64 {
    then + 302_000_000_000
}

#[test]
fn expire_holds_peer_synced_when_rg_inactive() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then + 301_000_000_000;
    // This node forwards NOTHING (pure standby). RG1 inactive.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert!(expired.is_empty(), "standby must NOT expire synced RG1 session");
    assert!(
        table.lookup(&key, past_tcp_timeout(then), 0x10).is_some(),
        "held session must still be present"
    );
    let s = table.last_pop_stats();
    assert_eq!(s.held_standby, 1, "exactly one held entry");
    assert_eq!(s.expired, 0);
    assert_eq!(s.reaped_stale_synced, 0);
}

#[test]
fn expire_ages_peer_synced_when_rg_active() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then + 301_000_000_000;
    // This node FORWARDS RG1 (active owner) and the epoch matches the
    // stamped one (0 at install) so SELF-HEAL does not fire -> AGE.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "active owner must age the session");
    assert!(table.lookup(&key, past_tcp_timeout(then), 0x10).is_none());
    let s = table.last_pop_stats();
    assert_eq!(s.expired, 1);
    assert_eq!(s.held_standby, 0);
}

#[test]
fn expire_ages_active_node_owned_session() {
    // A ForwardFlow (locally-created) session whose RG is active must
    // expire normally -- guards over-retention.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 1;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::ForwardFlow,
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "active-node-owned session must age");
    let s = table.last_pop_stats();
    assert_eq!(s.held_standby, 0);
}

#[test]
fn expire_holds_all_peer_synced_origins() {
    // SyncImport, SharedMaterialize, WorkerLocalImport are all
    // peer-synced -> all HELD on a non-forwarding node.
    for origin in [
        SessionOrigin::SyncImport,
        SessionOrigin::SharedMaterialize,
        SessionOrigin::WorkerLocalImport,
    ] {
        let mut table = SessionTable::new();
        let key = key_v4();
        let then = 1_000_000_000u64;
        install_synced_tcp_origin(&mut table, &key, 1, then, origin);
        table.last_gc_ns = then + 301_000_000_000;
        let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
        assert!(
            expired.is_empty(),
            "origin {:?} must be held on a non-forwarding node",
            origin
        );
        assert_eq!(table.last_pop_stats().held_standby, 1, "origin {:?}", origin);
    }
}

#[test]
fn expire_ages_shared_promote_origin() {
    // SharedPromote is set only on the active node (is_peer_synced()
    // false) -> must AGE, not hold (resolves SMR M3).
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp_origin(&mut table, &key, 1, then, SessionOrigin::SharedPromote);
    table.last_gc_ns = then + 301_000_000_000;
    // Node forwards nothing, but the entry is not peer-synced and
    // node_active is false -> (peer_synced || node_active) false -> AGE.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert_eq!(expired.len(), 1, "SharedPromote must age");
    assert_eq!(table.last_pop_stats().held_standby, 0);
}

#[test]
fn expire_holds_peer_synced_owner_rg_zero_whole_node_standby() {
    // fabric/reverse synced entry, owner_rg_id==0, node forwards
    // nothing -> held via the node-level path.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 0, then);
    table.last_gc_ns = then + 301_000_000_000;
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert!(expired.is_empty(), "owner_rg_id==0 whole-node standby must hold");
    assert_eq!(table.last_pop_stats().held_standby, 1);
}

#[test]
fn expire_ages_owner_rg_zero_on_active_node() {
    // KNOWN residual (plan A2#4): a peer-synced owner_rg_id==0 entry on
    // a node that IS active for some RG ages -- observable via the
    // dedicated counter, not a silent drop.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 0, then);
    table.last_gc_ns = then + 301_000_000_000;
    // node forwards RG1 (node_active true) but the entry's owner_rg_id==0
    // maps forwards_here -> node_active -> true; epoch matches (0) so no
    // self-heal -> AGE, tagged as the residual.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "owner_rg_id==0 on active node ages");
    let s = table.last_pop_stats();
    assert_eq!(
        s.aged_owner_rg_zero_active_node, 1,
        "the residual must be counted"
    );
    assert_eq!(s.held_standby, 0);
}

#[test]
fn expire_standalone_ages_normally() {
    // Standalone: ha=None path. A ForwardFlow owner_rg_id==0 session
    // must age exactly like the pre-#2120 wheel.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 0;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::ForwardFlow,
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    // ha=None -> standalone behavior.
    let expired = table.expire_stale_entries(past_tcp_timeout(then));
    assert_eq!(expired.len(), 1, "standalone ForwardFlow must age");
}

#[test]
fn expire_standalone_with_ctx_never_holds() {
    // Even with a context, a node that forwards NOTHING and a session
    // that is NOT peer-synced and owner_rg_id<=0 must age
    // ((peer_synced || node_active) false). Standalone safety.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 0;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::ForwardFlow,
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert_eq!(expired.len(), 1, "standalone-with-ctx must age");
    assert_eq!(table.last_pop_stats().held_standby, 0);
}

#[test]
fn expire_in_promotion_window_survives() {
    // Held past deadline while RG inactive, then this node STARTS
    // forwarding RG1 AND the epoch is bumped (r3 ordering) WITHOUT a
    // RefreshOwnerRGS landing. SELF-HEAL must re-stamp + survive.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    // First pass: standby, RG1 inactive -> HOLD (stamps seen_rg_epoch=epoch=0).
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Second pass: RG1 now active AND epoch bumped to 1 (promotion), but
    // RefreshOwnerRGS has not re-stamped. SELF-HEAL fires.
    table.last_gc_ns = t1;
    let t2 = t1 + 2_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 1);
    assert!(expired.is_empty(), "self-heal must keep the entry alive");
    let s = table.last_pop_stats();
    assert_eq!(s.healed_on_promote, 1, "self-heal must fire once");
    assert_eq!(s.expired, 0);
    // Re-stamped: it now ages from a full timeout. After another full
    // timeout with the SAME epoch it ages (no perpetual re-stamp).
    table.last_gc_ns = t2;
    let t3 = t2 + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t3, &[1], &|_| 1);
    assert_eq!(expired.len(), 1, "after self-heal it ages normally");
}

#[test]
fn expire_no_selfheal_when_epoch_unchanged() {
    // RG active but the epoch equals seen_rg_epoch (already healed):
    // the entry AGES (no perpetual re-stamp / over-retention).
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then + 301_000_000_000;
    // epoch == 0 == the install-stamped seen_rg_epoch, RG active.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "matching epoch + active RG -> age");
    assert_eq!(table.last_pop_stats().healed_on_promote, 0);
}

#[test]
fn expire_owner_rg_zero_survives_promotion() {
    // Held owner_rg_id==0 entry, then a NODE-LEVEL activation (epoch[0]
    // bumped). Self-heal must fire via the node epoch.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 0, then);
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Node-level activation: node forwards RG1 now, node-level epoch
    // bumped to 1. owner_rg_id==0 -> forwards_here == node_active true,
    // epoch_of(0)==1 != seen(0) -> SELF-HEAL.
    table.last_gc_ns = t1;
    let t2 = t1 + 2_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 1);
    assert!(expired.is_empty(), "node-level self-heal must keep it alive");
    assert_eq!(table.last_pop_stats().healed_on_promote, 1);
}

#[test]
fn expire_in_demotion_window_holds() {
    // A ForwardFlow session whose RG just flipped inactive, DemoteOwnerRGS
    // NOT yet applied -> held via the FORWARDING gate (!forwards_here),
    // not aged, because the node is still active for another RG.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 1; // RG1 -- about to be demoted
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::ForwardFlow, // demote flip not yet applied
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    // Node forwards RG2 (node_active true) but NOT RG1 (just demoted).
    // forwards_here(RG1)=false, node_active=true -> HOLD.
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[2], &|_| 0);
    assert!(expired.is_empty(), "demotion-window entry must be held");
    assert_eq!(table.last_pop_stats().held_standby, 1);
}

#[test]
fn expire_reaps_held_past_relative_ceiling() {
    // A held synced session past the relative ceiling
    // (MULT x 300s = 900s) is reaped even though the node never forwards
    // its RG (lost-primary-delete backstop).
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    // First HOLD pass arms first_held_ns at t1.
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Past the relative ceiling measured from first_held_ns (t1):
    // ceiling = min(3 x 300s, 7d) = 900s. Advance > 900s past t1.
    table.last_gc_ns = t1;
    let t2 = t1 + 901_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[], &|_| 0);
    assert_eq!(expired.len(), 1, "held entry past relative ceiling reaped");
    let s = table.last_pop_stats();
    assert_eq!(s.reaped_stale_synced, 1);
    assert_eq!(s.held_standby, 0);
}

#[test]
fn expire_reaps_held_at_abs_cap_for_long_timeout() {
    // A 30-day TCP timeout session, held, is reaped at the ABS cap
    // (~7d), NOT at 90 days (MULT x 30d). Bounds the pathological config.
    // To keep the wheel walk bounded we install at a large `then` and
    // jump in two bounded legs (~30d then ~7d) -- the wheel is O(elapsed
    // ticks) but each tick is a near-empty bucket check.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let thirty_days_secs = 30u64 * 24 * 60 * 60;
    table.set_timeouts(SessionTimeouts::from_seconds(thirty_days_secs, 0, 0));
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then;
    // Cross the 30-day timeout so the entry is idle-crossed. First hold
    // observation arms first_held_ns at t1 with held_ns == 0 -> HELD
    // (NOT reaped from its stale install-time last_seen).
    let thirty_days_ns = thirty_days_secs * 1_000_000_000;
    let t1 = then + thirty_days_ns + 2_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(
        expired.is_empty(),
        "idle-crossed long session held on first observation, not reaped"
    );
    // held_standby may be > 1: this single synthetic 30-day jump makes the
    // wheel cursor sweep millions of ticks, and a held entry is re-bucketed
    // to the current tick on each rotation (the same multi-rotation
    // re-processing the existing long-timeout Case-4 exhibits under a huge
    // jump). Production advances ~1 tick per call, so this is a test-only
    // artifact; the load-bearing assertions are "not reaped" + "still
    // present". first_held_ns is armed on the first observation so the cap
    // measures from there, not from the stale install-time last_seen.
    assert!(table.last_pop_stats().held_standby >= 1, "held at least once");
    assert_eq!(table.last_pop_stats().reaped_stale_synced, 0, "not yet reaped");
    // NOTE: presence via `table.len()`, NOT `lookup()` -- lookup refreshes
    // last_seen_ns (it is the packet path) and would defeat the timeout.
    assert_eq!(table.len(), 1, "long-timeout synced session retained on the standby");
    // ABS cap is 7 days from first_held_ns (t1). After > 7 days it is
    // reaped (the relative ceiling would be 90 days).
    table.last_gc_ns = t1;
    let seven_days_ns = 7u64 * 24 * 60 * 60 * 1_000_000_000;
    let t2 = t1 + seven_days_ns + 1_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[], &|_| 0);
    assert_eq!(expired.len(), 1, "reaped at the abs cap, not 90 days");
    assert!(
        table.last_pop_stats().reaped_stale_synced >= 1,
        "reaped at the abs cap"
    );
    assert_eq!(table.len(), 0, "gone after reap");
}

#[test]
fn expire_flapping_rg_still_reaps() {
    // A flapping RG (repeated promote-edge self-heals) re-stamps
    // last_seen on every activation but must NOT reset first_held_ns --
    // otherwise a dead leaked entry could be pinned forever. We arm
    // first_held, fire several self-heals (each advancing time + bumping
    // the epoch), then a final hold pass past the relative ceiling
    // measured from first_held_ns reaps it despite all the re-stamps.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    // First hold (RG inactive) arms first_held_ns at t_anchor.
    table.last_gc_ns = then;
    let t_anchor = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t_anchor, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Flap: self-heal on each activation edge (RG active + a NEW epoch).
    // Advance past the timeout each iteration so the entry is idle-crossed
    // and the SELF-HEAL arm fires (re-stamping last_seen but leaving
    // first_held_ns at t_anchor). After 4 iterations the total elapsed
    // since t_anchor exceeds the 900s relative ceiling -- yet self-heal
    // keeps re-stamping because it deliberately ignores the ceiling.
    let mut t = t_anchor;
    let mut epoch = 1u32;
    for _ in 0..4 {
        table.last_gc_ns = t;
        t += 302_000_000_000; // past the 300s timeout -> idle-crossed again
        let e = epoch;
        let expired = run_expire_ha(&mut table, t, &[1], &move |_| e);
        assert!(expired.is_empty(), "self-heal keeps the entry alive");
        assert_eq!(
            table.last_pop_stats().healed_on_promote,
            1,
            "each activation edge self-heals"
        );
        epoch += 1;
    }
    // We are now well past the 900s relative ceiling measured from
    // t_anchor, but the entry survived via self-heals. A HOLD pass (RG
    // inactive) reaps it: held_ns from first_held_ns (t_anchor) >>
    // ceiling, despite the self-heal re-stamps to last_seen.
    assert!(t - t_anchor > 900_000_000_000, "past ceiling after self-heals");
    table.last_gc_ns = t;
    let t_final = t + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t_final, &[], &|_| 0);
    assert_eq!(
        expired.len(),
        1,
        "flapping self-heals must NOT reset the leak ceiling -- reaped"
    );
    assert_eq!(table.last_pop_stats().reaped_stale_synced, 1);
}

#[test]
fn promotion_restamps_held_session() {
    // The command-landed complement to expire_in_promotion_window_survives:
    // hold past deadline, then refresh_for_ha_transition (RefreshOwnerRGS
    // path) re-stamps last_seen and clears the hold clock.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 0);
    assert!(expired.is_empty());
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // RefreshOwnerRGS landed -> refresh_for_ha_transition re-stamps.
    let mut md = metadata();
    md.owner_rg_id = 1;
    assert!(table.refresh_for_ha_transition(&key, decision(), md, t1 + 1_000_000));
    // Now ages from a full timeout on the active node.
    table.last_gc_ns = t1 + 1_000_000;
    let t2 = t1 + 1_000_000 + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 0);
    assert_eq!(expired.len(), 1, "after promotion refresh it ages normally");
}

#[test]
fn expire_fabric_ingress_ages_normally() {
    // fabric_ingress synced entries are NOT held (matches the fabric-skip
    // convention) -- they age even on a non-forwarding node.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    let mut md = metadata();
    md.owner_rg_id = 1;
    md.fabric_ingress = true;
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        md,
        SessionOrigin::SyncImport,
        then,
        PROTO_TCP,
        0x10,
    ));
    let _ = table.drain_deltas(8);
    table.last_gc_ns = then + 301_000_000_000;
    let expired = run_expire_ha(&mut table, past_tcp_timeout(then), &[], &|_| 0);
    assert_eq!(expired.len(), 1, "fabric_ingress synced must age");
    assert_eq!(table.last_pop_stats().held_standby, 0);
}

#[test]
fn expire_hold_does_not_poison_selfheal_under_epoch_skew() {
    // REGRESSION (Codex MAJOR): the worker reads the HA map and the
    // rg_epochs counter separately, so a HOLD can observe an OLD (still
    // inactive) map together with a NEW (already bumped) epoch -- the
    // old-map/new-epoch skew. The HOLD must NOT stamp seen_rg_epoch with
    // that new epoch; if it did, the NEXT pass (which sees the new ACTIVE
    // map + the same new epoch) would find current_epoch == seen_rg_epoch
    // and SKIP the self-heal, aging the very synced session this gate
    // exists to preserve.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then); // seen_rg_epoch = 0
    // Skewed HOLD pass: node still reports NOT forwarding RG1 (old map),
    // but epoch_of already returns the bumped value 7 (new epoch).
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t1, &[], &|_| 7);
    assert!(expired.is_empty(), "skewed hold must still hold");
    assert_eq!(table.last_pop_stats().held_standby, 1);
    // Next pass: the new ACTIVE map is now visible (node forwards RG1) and
    // the epoch is the same 7. With the fix, seen_rg_epoch is still 0
    // (HOLD did not stamp it), so current(7) != seen(0) -> SELF-HEAL.
    // Pre-fix (HOLD stamps seen=7) this would AGE -> failover drop.
    table.last_gc_ns = t1;
    let t2 = t1 + 2_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 7);
    assert!(
        expired.is_empty(),
        "self-heal must fire despite the skewed hold having seen epoch 7"
    );
    assert_eq!(
        table.last_pop_stats().healed_on_promote,
        1,
        "the skewed-hold session must self-heal, not age"
    );
}

#[test]
fn promotion_refresh_with_nonzero_epoch_ages_after_one_selfheal() {
    // Companion to promotion_restamps_held_session with a PRODUCTION
    // non-zero activation epoch (Codex Medium): refresh_for_ha_transition
    // resets seen_rg_epoch to 0, so an IDLE active-owned session self-heals
    // exactly ONCE (bounded one-shot extra retention) and then ages -- it
    // never lives forever and the over-retention is one timeout.
    let mut table = SessionTable::new();
    let key = key_v4();
    let then = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, then);
    // Hold while inactive.
    table.last_gc_ns = then;
    let t1 = then + 302_000_000_000;
    assert!(run_expire_ha(&mut table, t1, &[], &|_| 0).is_empty());
    // RefreshOwnerRGS lands -> re-stamp, seen_rg_epoch reset to 0.
    let mut md = metadata();
    md.owner_rg_id = 1;
    assert!(table.refresh_for_ha_transition(&key, decision(), md, t1 + 1_000_000));
    // Active node, production epoch 5. First idle expiry: current(5) !=
    // seen(0) -> one self-heal (bounded one-shot).
    table.last_gc_ns = t1 + 1_000_000;
    let t2 = t1 + 1_000_000 + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t2, &[1], &|_| 5);
    assert!(expired.is_empty(), "one bounded self-heal after refresh");
    assert_eq!(table.last_pop_stats().healed_on_promote, 1);
    // Second idle expiry: current(5) == seen(5, just stamped) -> AGE.
    table.last_gc_ns = t2;
    let t3 = t2 + 302_000_000_000;
    let expired = run_expire_ha(&mut table, t3, &[1], &|_| 5);
    assert_eq!(expired.len(), 1, "ages on the next pass -- no perpetual re-stamp");
}

// ===================================================================
// #2134: per-IP session-limit lifecycle, maintained inside SessionTable
// at the install/remove sinks + the two in-place HA transitions. These
// tests drive the REAL install/expire/promote/demote paths (NOT the
// retired ScreenState `session_created` manual hook the old screen tests
// used — that gap was exactly the #2134 no-op). Each is written to FAIL
// if its enforcement-driving count maintenance is reverted to a no-op.
// ===================================================================

/// A counted forward install with a distinct src IP per flow.
fn limit_key(src_octet: u8, dst_octet: u8, src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: 2,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, src_octet)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, dst_octet)),
        src_port,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

/// §5.1 enforcement decision (the security purpose): with the OFF-gate
/// ON, installing `n` forward flows from one source IP drives the count
/// to exactly `n` through the REAL install path, and the new-flow
/// enforcement predicate (`count >= limit`) holds for the (n+1)-th
/// attempt. This FAILS if the install-site increment is reverted (count
/// stays 0, the predicate never fires, the limit is a no-op — the #2134
/// bug). The DST mirror is asserted too.
#[test]
fn session_limit_count_increments_on_forward_install_src_and_dst() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    let limit = 3u32;

    // Distinct flows (distinct dst host so each is a fresh key) sharing
    // one src IP, all targeting one dst host so dst also counts.
    for i in 0..limit {
        let key = SessionKey {
            src_ip: src,
            dst_ip: dst,
            src_port: 40000 + i as u16,
            ..limit_key(7, 9, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key,
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
    }

    assert_eq!(
        table.session_limit_src_count(src),
        limit,
        "src count must equal the number of forward installs"
    );
    assert_eq!(
        table.session_limit_dst_count(dst),
        limit,
        "dst count must equal the number of forward installs"
    );
    // The (limit+1)-th new flow's enforcement predicate must fire.
    assert!(
        table.session_limit_src_count(src) >= limit,
        "over-limit src predicate must hold (enforcement would drop)"
    );
    assert!(
        table.session_limit_dst_count(dst) >= limit,
        "over-limit dst predicate must hold"
    );
}

/// §5.2 established-flow regression (the r2 BLOCKER): the per-packet
/// session HIT path (`lookup` / `touch`) must NOT change the per-IP
/// count — only a NEW install does. If the count were maintained
/// per-packet (or the check left in the screen stage), an at-limit
/// flow's own data packets would re-trip the limit. Here, after `n`
/// installs (count == n), MANY lookups/touches of those live sessions
/// leave the count at exactly `n` — never n+1, never growing.
#[test]
fn session_limit_count_unchanged_by_established_flow_packets() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
    let n = 4u32;
    let mut keys = Vec::new();
    for i in 0..n {
        let key = SessionKey {
            src_ip: src,
            src_port: 41000 + i as u16,
            ..limit_key(11, 9, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
        keys.push(key);
    }
    assert_eq!(table.session_limit_src_count(src), n);

    // Drive many established-flow data packets (session HIT + keepalive).
    for tick in 1..200u64 {
        for key in &keys {
            let _ = table.lookup(key, now + tick * 1_000_000, 0x10);
            table.touch(key, now + tick * 1_000_000);
        }
    }
    assert_eq!(
        table.session_limit_src_count(src),
        n,
        "established-flow packets must NOT change the count (r2 BLOCKER)"
    );
}

/// §5.3 decrement + evict-to-0 across the timer wheel + re-admit: after
/// expiry the count decrements and the map ENTRY is removed at 0 (#2128
/// evict-on-zero), and the IP can be admitted again.
#[test]
fn session_limit_decrements_and_evicts_on_expire() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let then = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(13, 9, 42000)
    };
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        then,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(table.session_limit_src_count(src), 1);
    assert_eq!(table.session_limit_src_map_len(), 1);

    table.last_gc_ns = then + 301_000_000_000;
    let expired = table.expire_stale_entries(then + 302_000_000_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(
        table.session_limit_src_count(src),
        0,
        "count must decrement on expire"
    );
    assert_eq!(
        table.session_limit_src_map_len(),
        0,
        "map entry must be evicted at 0 (#2128)"
    );
    assert_eq!(table.session_limit_dst_map_len(), 0);

    // Re-admittable: a fresh install for the same IP works and counts.
    let key2 = SessionKey {
        src_ip: src,
        src_port: 42001,
        ..limit_key(13, 9, 0)
    };
    assert!(table.install_with_protocol_with_origin(
        key2,
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        then + 303_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(table.session_limit_src_count(src), 1);
}

/// §5.4 decrement across the explicit `delete` path (clear / RST
/// teardown / fabric-cancel all funnel through `remove_entry`).
#[test]
fn session_limit_decrements_on_explicit_delete() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 15));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(15, 9, 43000)
    };
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        now,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(table.session_limit_src_count(src), 1);
    table.delete(&key);
    assert_eq!(table.session_limit_src_count(src), 0);
    assert_eq!(table.session_limit_src_map_len(), 0);
}

/// §5.6 (#3122) HA import → promote → demote → expire — the per-IP count
/// must be charged exactly ONCE across the whole lifecycle, with NO
/// double-count when a synced session is promoted to local and NO
/// premature decrement when it is demoted back. Before #3122 a peer-synced
/// import counted 0 locally (the limit-bypass bug); now it counts on
/// import, and the in-place promote/demote origin flips are count-neutral.
///
/// FAIL-ON-REVERT: restoring the `!origin.is_peer_synced()` exclusion on
/// the count (the #3122 bug) makes the FIRST assertion below RED — the
/// import would count 0 and a client could exceed its cap after failover.
#[test]
fn session_limit_ha_import_promote_demote_count() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 17));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(17, 9, 44000)
    };
    let mut meta = metadata();
    meta.owner_rg_id = 1;

    // Import a peer session (SyncImport) — #3122: MUST count locally so
    // the limit stays enforced after a failover. (This is the fail-on-
    // revert anchor: restoring the peer-synced count exclusion → 0 here.)
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: key.clone(),
            decision: decision(),
            metadata: meta.clone(),
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            session_id: 0,
            tcp_close_class: 0,
        },
        false,
    ));
    assert_eq!(
        table.session_limit_src_count(src),
        1,
        "#3122: peer-synced import MUST count toward the per-IP limit"
    );

    // Promote synced -> local (in-place update_session): COUNT-NEUTRAL.
    // The session was already counted at import; re-incrementing here would
    // double-count the same session across failover (the #3122 hazard).
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &key,
        decision: decision(),
        metadata: meta.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    }));
    assert_eq!(
        table.session_limit_src_count(src),
        1,
        "promote synced->local must NOT double-count (stays 1, not 2)"
    );

    // Demote local -> synced (in-place demote): COUNT-NEUTRAL — the session
    // is still present in the table, so its slot stays charged.
    assert_eq!(table.demote_owner_rg(1).len(), 1);
    assert_eq!(
        table.session_limit_src_count(src),
        1,
        "demote local->synced must NOT decrement (session still present)"
    );

    // Only the actual removal decrements, draining to 0 and evicting.
    table.delete(&key);
    assert_eq!(
        table.session_limit_src_count(src),
        0,
        "removal (the sole sink) decrements the imported session's slot"
    );
    assert_eq!(table.session_limit_src_map_len(), 0);
}

/// §5.6b (#3122) the FAILOVER LIMIT-BYPASS scenario, end to end: a client
/// drives N synced sessions onto the standby, then the standby becomes
/// active. Its per-IP count must already reflect the N synced sessions so
/// the enforcement predicate (`count >= limit`) fires for the (N+1)-th new
/// flow — a client at its cap before failover stays capped after.
///
/// FAIL-ON-REVERT: with the peer-synced count exclusion restored, the
/// imported sessions count 0 and the predicate never fires → bypass.
#[test]
fn session_limit_synced_sessions_enforced_after_failover() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 27));
    let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    let limit = 3u32;

    // Standby imports `limit` synced sessions from one source IP.
    for i in 0..limit {
        let mut meta = metadata();
        meta.owner_rg_id = 1;
        assert!(table.upsert_synced_with_origin(
            SessionInstall {
                key: SessionKey {
                    src_ip: src,
                    dst_ip: dst,
                    src_port: 48000 + i as u16,
                    ..limit_key(27, 9, 0)
                },
                decision: decision(),
                metadata: meta,
                origin: SessionOrigin::SyncImport,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
                session_id: 0,
                tcp_close_class: 0,
            },
            false,
        ));
    }

    // After failover the new active's enforcement predicate must fire for
    // the (limit+1)-th new flow — the synced sessions are visible to it.
    assert_eq!(
        table.session_limit_src_count(src),
        limit,
        "#3122: synced sessions must be counted on the standby-turned-active"
    );
    assert!(
        table.session_limit_src_count(src) >= limit,
        "#3122: over-limit predicate must fire post-failover (no bypass)"
    );
    assert!(
        table.session_limit_dst_count(dst) >= limit,
        "#3122: dst over-limit predicate must fire post-failover"
    );
}

/// §5.6c (#3122) a re-imported synced session (peer re-syncs the same key)
/// nets to count 1, not 2 — `upsert_synced_with_origin` removes the prior
/// entry (decrement, now origin-agnostic) before re-inserting (increment).
#[test]
fn session_limit_synced_reimport_nets_to_one() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 29));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(29, 9, 49000)
    };
    for t in 0..2u64 {
        let mut meta = metadata();
        meta.owner_rg_id = 1;
        assert!(table.upsert_synced_with_origin(
            SessionInstall {
                key: key.clone(),
                decision: decision(),
                metadata: meta,
                origin: SessionOrigin::SyncImport,
                now_ns: now + t * 1_000_000,
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
                session_id: 0,
                tcp_close_class: 0,
            },
            true,
        ));
    }
    assert_eq!(
        table.session_limit_src_count(src),
        1,
        "re-import of the same synced key must net to 1, not 2"
    );
    assert_eq!(table.session_limit_src_map_len(), 1);
}

/// §5.6d (#3122) a reverse-direction synced import must NOT count — only
/// the forward key of a session is charged, so the count stays once per
/// logical session regardless of how many directional entries HA syncs.
#[test]
fn session_limit_synced_reverse_import_excluded() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let rev_src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));
    let mut rev_meta = metadata();
    rev_meta.is_reverse = true;
    rev_meta.owner_rg_id = 1;
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: SessionKey {
                src_ip: rev_src,
                ..limit_key(31, 9, 50000)
            },
            decision: decision(),
            metadata: rev_meta,
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            session_id: 0,
            tcp_close_class: 0,
        },
        false,
    ));
    assert_eq!(
        table.session_limit_src_count(rev_src),
        0,
        "#3122: reverse-direction synced import must not count"
    );
}

/// §5.7 reverse + seed exclusion: reverse-flow and MissingNeighborSeed
/// installs must NOT increment (counted-class predicate).
#[test]
fn session_limit_excludes_reverse_and_seed_installs() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;

    let rev_src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 19));
    let rev_key = SessionKey {
        src_ip: rev_src,
        ..limit_key(19, 9, 45000)
    };
    let mut rev_meta = metadata();
    rev_meta.is_reverse = true;
    assert!(table.install_with_protocol_with_origin(
        rev_key,
        decision(),
        rev_meta,
        SessionOrigin::ReverseFlow,
        now,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(
        table.session_limit_src_count(rev_src),
        0,
        "reverse-flow install must not count"
    );

    let seed_src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21));
    let seed_key = SessionKey {
        src_ip: seed_src,
        ..limit_key(21, 9, 46000)
    };
    assert!(table.install_with_protocol_with_origin(
        seed_key,
        decision(),
        metadata(),
        SessionOrigin::MissingNeighborSeed,
        now,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(
        table.session_limit_src_count(seed_src),
        0,
        "missing-neighbor seed install must not count"
    );
}

/// §5.8 idempotent re-install (the defensive pre-clear path): installing
/// the same key twice nets to count 1, not 2 (pre-clear decrement +
/// install increment self-cancel on the same IP).
#[test]
fn session_limit_idempotent_reinstall_nets_to_one() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 23));
    let key = SessionKey {
        src_ip: src,
        ..limit_key(23, 9, 47000)
    };
    for t in 0..2u64 {
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now + t * 1_000_000,
            PROTO_TCP,
            0x10,
        ));
    }
    assert_eq!(
        table.session_limit_src_count(src),
        1,
        "re-install of the same key must net to 1, not 2"
    );
    assert_eq!(table.session_limit_src_map_len(), 1);
}

/// §5.9 differential / invariant (the strongest guard): after an
/// arbitrary sequence of install / expire / delete / promote / demote /
/// refresh, the sum of per-IP src counts EQUALS the number of live
/// counted entries. As of #3122 the counted-class is PRESENCE-based and
/// ORIGIN-AGNOSTIC (`!is_reverse && !is_seed` — peer-synced included).
/// Same for dst. Catches ANY missed transition site.
#[test]
fn session_limit_counts_match_live_counted_entries_invariant() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let mut now = 1_000_000_000u64;

    // Build a varied population.
    let mut counted_keys: Vec<SessionKey> = Vec::new();
    for i in 0..12u32 {
        now += 1_000_000;
        let key = SessionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, (i % 4) as u8 + 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, (i % 3) as u8 + 1)),
            src_port: 50000 + i as u16,
            ..limit_key(0, 0, 0)
        };
        let mut meta = metadata();
        meta.owner_rg_id = 1;
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            meta,
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
        counted_keys.push(key);
    }
    // A reverse + a seed (both uncounted) + a synced import (#3122:
    // now COUNTED — origin-agnostic presence-based counting).
    let mut rev_meta = metadata();
    rev_meta.is_reverse = true;
    let _ = table.install_with_protocol_with_origin(
        SessionKey {
            src_port: 60001,
            ..limit_key(9, 9, 0)
        },
        decision(),
        rev_meta,
        SessionOrigin::ReverseFlow,
        now,
        PROTO_TCP,
        0x10,
    );
    let _ = table.install_with_protocol_with_origin(
        SessionKey {
            src_port: 60002,
            ..limit_key(9, 9, 0)
        },
        decision(),
        metadata(),
        SessionOrigin::MissingNeighborSeed,
        now,
        PROTO_TCP,
        0x10,
    );
    let synced_key = SessionKey {
        src_port: 60003,
        ..limit_key(8, 8, 0)
    };
    let mut synced_meta = metadata();
    synced_meta.owner_rg_id = 1;
    let _ = table.upsert_synced_with_origin(
        SessionInstall {
            key: synced_key.clone(),
            decision: decision(),
            metadata: synced_meta.clone(),
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            session_id: 0,
            tcp_close_class: 0,
        },
        false,
    );

    // Mutate: delete a few, promote the synced import, refresh one,
    // then demote RG 1.
    table.delete(&counted_keys[0]);
    table.delete(&counted_keys[5]);
    assert!(table.promote_synced_with_origin(SessionUpdate {
        key: &synced_key,
        decision: decision(),
        metadata: synced_meta.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: now + 1_000_000,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
    }));
    // refresh that preserves origin/direction (must not change counts).
    let refresh_target = counted_keys[2].clone();
    assert!(table.refresh_for_ha_transition(&refresh_target, decision(), metadata(), now + 2_000_000));

    let check_invariant = |table: &SessionTable, label: &str| {
        let mut src_live: std::collections::HashMap<IpAddr, u32> = std::collections::HashMap::new();
        let mut dst_live: std::collections::HashMap<IpAddr, u32> = std::collections::HashMap::new();
        table.iter_with_origin(|key, _decision, md, origin| {
            // #3122: counted-class is origin-agnostic (presence-based) —
            // peer-synced entries count, only reverse + seed are excluded.
            if !md.is_reverse && !origin.is_transient_local_seed() {
                *src_live.entry(key.src_ip).or_insert(0) += 1;
                *dst_live.entry(key.dst_ip).or_insert(0) += 1;
            }
        });
        // Per-IP count must equal the number of live counted entries for
        // that IP, for every IP that has at least one live counted entry.
        for (ip, cnt) in &src_live {
            assert_eq!(
                table.session_limit_src_count(*ip),
                *cnt,
                "{label}: src count for {ip:?} must match live counted entries"
            );
        }
        for (ip, cnt) in &dst_live {
            assert_eq!(
                table.session_limit_dst_count(*ip),
                *cnt,
                "{label}: dst count for {ip:?} must match live counted entries"
            );
        }
        // Map sizes must exactly equal distinct live counted IP sets
        // (no leaked / orphaned entries — #2128).
        assert_eq!(
            table.session_limit_src_map_len(),
            src_live.len(),
            "{label}: src map size must equal distinct live counted src IPs"
        );
        assert_eq!(
            table.session_limit_dst_map_len(),
            dst_live.len(),
            "{label}: dst map size must equal distinct live counted dst IPs"
        );
    };
    check_invariant(&table, "after mutations");

    // Demote RG 1 — #3122: the RG-1 sessions flip local->synced but stay
    // PRESENT, so they remain counted (count-neutral demote). The
    // origin-agnostic invariant still holds across the flip.
    table.demote_owner_rg(1);
    check_invariant(&table, "after demote RG1");

    // Expire everything; counts must drain to empty.
    table.last_gc_ns = now + 600_000_000_000;
    let _ = table.expire_stale_entries(now + 601_000_000_000);
    assert_eq!(table.session_limit_src_map_len(), 0);
    assert_eq!(table.session_limit_dst_map_len(), 0);
}

/// §5.10 runtime disable clears the maps (reviewer B MAJOR): turning the
/// OFF-gate off must clear both count maps so a later re-enable starts
/// from 0 and cannot spuriously block an under-limit IP. FAILS if
/// clear-on-disable is omitted.
#[test]
fn session_limit_clear_on_disable() {
    let mut table = SessionTable::new();
    table.set_session_limit_active(true);
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 25));
    for i in 0..3u32 {
        let key = SessionKey {
            src_ip: src,
            src_port: 52000 + i as u16,
            ..limit_key(25, 9, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key,
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
    }
    assert_eq!(table.session_limit_src_count(src), 3);

    // Disable: both maps must clear.
    table.set_session_limit_active(false);
    assert_eq!(table.session_limit_src_map_len(), 0, "src map must clear on disable");
    assert_eq!(table.session_limit_dst_map_len(), 0, "dst map must clear on disable");

    // #4377 back-count-on-enable: the 3 sessions are STILL live, so
    // re-enabling must REBUILD the maps from them — count == 3, NOT the
    // old (buggy) "restart from 0". Clear-on-disable + back-count-on-enable
    // is idempotent: if clear-on-disable were omitted, the re-enable walk
    // would double-count to 6, so this still guards clear-on-disable.
    table.set_session_limit_active(true);
    assert_eq!(
        table.session_limit_src_count(src),
        3,
        "re-enable must back-count the 3 live sessions, not restart from 0"
    );

    // A fresh flow from the same IP adds to the back-counted total — the
    // cap now sees the true live count instead of a fresh empty allotment.
    let key = SessionKey {
        src_ip: src,
        src_port: 52999,
        ..limit_key(25, 9, 0)
    };
    assert!(table.install_with_protocol_with_origin(
        key,
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        now + 1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(
        table.session_limit_src_count(src),
        4,
        "new install must add to the back-counted 3, not to a stale 0"
    );
}

/// #4377 FAIL-ON-REVERT: the per-IP session-limit maps must be REBUILT
/// on the OFF->ON enable edge from the live slab, so a session installed
/// while the gate was INACTIVE is counted the moment the gate turns on —
/// its later teardown decrements a real increment instead of driving the
/// count below the live counted-session count (the #4377 cap bypass).
///
/// REVERT SIGNATURE: without the back-count, re-enable restarts the count
/// at 0; the pre-existing sessions' teardown then saturating_sub's below
/// 0 (hidden as 0) while sessions are still live, and the IP is handed a
/// fresh full allotment — a cap bypass. This test drives that exact path
/// and asserts the corrected counts at every step. It FAILS (the first
/// count assertion sees 0, not N) if `set_session_limit_active`'s
/// OFF->ON back-count is reverted.
#[test]
fn session_limit_backcount_on_enable_covers_preexisting_sessions() {
    let mut table = SessionTable::new();
    // Gate starts OFF (default). Install N forward sessions from one IP
    // while INACTIVE — none are counted (the OFF-gate skips the increment).
    let n = 4u32;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 40));
    let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40));
    let now = 1_000_000_000u64;
    let mut keys: Vec<SessionKey> = Vec::new();
    for i in 0..n {
        let key = SessionKey {
            src_ip: src,
            dst_ip: dst,
            src_port: 54000 + i as u16,
            ..limit_key(40, 40, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
        keys.push(key);
    }
    // #3122 invariant: also import ONE peer-synced session from the same
    // src IP (different dst so we can watch src back-count include it).
    let synced_dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 41));
    let synced_key = SessionKey {
        src_ip: src,
        dst_ip: synced_dst,
        src_port: 54900,
        ..limit_key(40, 41, 0)
    };
    let mut synced_meta = metadata();
    synced_meta.owner_rg_id = 1;
    let _ = table.upsert_synced_with_origin(
        SessionInstall {
            key: synced_key.clone(),
            decision: decision(),
            metadata: synced_meta,
            origin: SessionOrigin::SyncImport,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            session_id: 0,
            tcp_close_class: 0,
        },
        false,
    );
    // Gate OFF: nothing counted yet (the maps are empty).
    assert_eq!(table.session_limit_src_count(src), 0, "OFF: no count maintained");
    assert_eq!(table.session_limit_src_map_len(), 0);

    // OFF->ON edge: back-count. src has N local + 1 synced = N+1 live
    // counted sessions; both dst IPs get their own counted entries. The
    // #3122 synced session MUST be included (origin-agnostic predicate).
    table.set_session_limit_active(true);
    assert_eq!(
        table.session_limit_src_count(src),
        n + 1,
        "OFF->ON must back-count all live counted sessions incl. the #3122 synced import"
    );
    assert_eq!(
        table.session_limit_dst_count(dst),
        n,
        "dst back-count must equal the N forward sessions to that dst"
    );
    assert_eq!(
        table.session_limit_dst_count(synced_dst),
        1,
        "the #3122 synced session's dst must be back-counted too"
    );

    // Enforcement is now correct: a new flow from src sees the true live
    // count (N+1), not a fresh 0 allotment.
    let over_key = SessionKey {
        src_ip: src,
        dst_ip: dst,
        src_port: 54990,
        ..limit_key(40, 40, 0)
    };
    assert!(table.install_with_protocol_with_origin(
        over_key,
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        now + 1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(
        table.session_limit_src_count(src),
        n + 2,
        "new install adds to the back-counted total"
    );

    // Teardown of a PRE-EXISTING (installed-while-off) session decrements
    // from the back-counted total — it never drives the count below the
    // live counted-session count. Delete all N pre-existing forward
    // sessions one at a time and watch the count step down correctly.
    let mut expected = n + 2; // (N back-counted forward) + 1 synced + 1 new install
    for key in &keys {
        table.delete(key);
        expected -= 1;
        assert_eq!(
            table.session_limit_src_count(src),
            expected,
            "teardown of a pre-existing session must decrement a real increment"
        );
    }
    // After draining the N pre-existing forward sessions, src still has
    // the 1 synced + 1 new-install = 2 live counted sessions.
    assert_eq!(table.session_limit_src_count(src), 2);

    // The invariant the whole fix defends: the per-IP count equals the
    // number of live counted entries for that IP — never below it.
    let mut live_src = 0u32;
    table.iter_with_origin(|k, _d, md, origin| {
        if k.src_ip == src && !md.is_reverse && !origin.is_transient_local_seed() {
            live_src += 1;
        }
    });
    assert_eq!(
        table.session_limit_src_count(src),
        live_src,
        "count must equal live counted entries — never dropped below (the #4377 bypass)"
    );
}

/// OFF-gate zero-cost: when the feature is OFF, install/remove perform NO
/// counter maintenance (the maps stay empty regardless of traffic).
#[test]
fn session_limit_off_gate_skips_all_maintenance() {
    let mut table = SessionTable::new();
    // OFF (default).
    let now = 1_000_000_000u64;
    let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 27));
    for i in 0..5u32 {
        let key = SessionKey {
            src_ip: src,
            src_port: 53000 + i as u16,
            ..limit_key(27, 9, 0)
        };
        assert!(table.install_with_protocol_with_origin(
            key.clone(),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            now,
            PROTO_TCP,
            0x10,
        ));
        table.delete(&key);
    }
    assert_eq!(
        table.session_limit_src_count(src),
        0,
        "OFF-gate: no count maintained"
    );
    assert_eq!(table.session_limit_src_map_len(), 0);
    assert_eq!(table.session_limit_dst_map_len(), 0);
}

// === #2220 flow-cache per-session keepalive ====================
//
// The flow-cache fast path (poll_descriptor/flow_cache_hit.rs) is the
// ONLY code path that refreshes a forwarded flow's last_seen_ns. Before
// #2220 it used a binding-GLOBAL modulo-64 counter: a low-rate flow
// co-resident with a saturating flow could be served entirely from the
// cache for a whole timeout window without its session ever being
// touched, then reaped while still forwarding. The fix replaces that
// counter with `SessionTable::touch_if_stale`, a per-session
// time-threshold keepalive. These tests pin that contract and FAIL
// against the old global-modulo logic (modelled inline below).

/// touch_if_stale re-stamps a session ONLY once it has gone idle for at
/// least `expires_after_ns / SESSION_KEEPALIVE_DIVISOR` (a quarter of
/// its own timeout). Below that threshold it is a pure read (no write,
/// no wheel re-bucket); at/after it, last_seen advances.
#[test]
fn touch_if_stale_throttles_until_quarter_timeout() {
    let mut table = SessionTable::new();
    let key = key_v6(); // UDP, 60 s timeout
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));
    let timeout = table
        .entry_by_key(&key)
        .expect("session installed")
        .expires_after_ns;
    assert_eq!(timeout, DEFAULT_UDP_SESSION_TIMEOUT_NS, "UDP 60 s timeout");
    let quarter = timeout / SESSION_KEEPALIVE_DIVISOR; // 15 s

    // One ns BEFORE the quarter-timeout threshold: must NOT touch.
    let before = install_ns + quarter - 1;
    table.touch_if_stale(&key, before);
    assert_eq!(
        table.entry_by_key(&key).unwrap().last_seen_ns,
        install_ns,
        "touch_if_stale must not re-stamp before idle reaches timeout/4"
    );

    // AT the quarter-timeout threshold: must touch.
    let at = install_ns + quarter;
    table.touch_if_stale(&key, at);
    assert_eq!(
        table.entry_by_key(&key).unwrap().last_seen_ns,
        at,
        "touch_if_stale must re-stamp once idle reaches timeout/4"
    );

    // Immediately again (idle ~0): must NOT touch (steady-state read).
    table.touch_if_stale(&key, at + 1_000_000);
    assert_eq!(
        table.entry_by_key(&key).unwrap().last_seen_ns,
        at,
        "touch_if_stale must stay a pure read until the next threshold"
    );
}

/// FAIL-ON-REVERT core: a UDP flow served continuously from the flow
/// cache (touch_if_stale on every hit, sub-timeout cadence) must NEVER
/// be GC'd, and its last_seen must keep advancing across the whole run.
/// A control session that receives NO keepalive expires at its timeout
/// — proving the keepalive, not the wheel, is what keeps the live flow.
#[test]
fn touch_if_stale_keeps_active_cache_flow_alive() {
    let mut table = SessionTable::new();
    let live = key_v6(); // UDP 60 s, actively forwarding via the cache
    let dead = SessionKey {
        src_port: 6001,
        ..key_v6()
    }; // UDP 60 s, no traffic (control)
    let install_ns = 1_000_000_000u64;
    for k in [&live, &dead] {
        assert!(table.install_with_protocol(
            k.clone(),
            decision(),
            metadata(),
            install_ns,
            PROTO_UDP,
            0
        ));
    }
    let _ = table.drain_deltas(64);

    // Drive 600 s (10× the UDP timeout) of cache hits for the LIVE flow
    // at a 2 s per-flow cadence — the kind of moderate-rate flow #2220
    // says the old global-modulo counter could starve. Run GC every tick.
    let cadence = 2 * WHEEL_TICK_NS;
    let mut now = install_ns;
    for _ in 0..300u64 {
        now += cadence;
        table.touch_if_stale(&live, now);
        // GC gate: advance last_gc so each call actually sweeps.
        table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
        let expired = table.expire_stale_entries(now);
        // The live flow must never appear in an expiry batch.
        assert!(
            !expired.iter().any(|e| e.key == live),
            "active cache-served flow GC'd mid-flow at now={now}: {expired:?}"
        );
    }

    // Live flow still present, last_seen well past install (keepalive ran).
    let live_last = table
        .entry_by_key(&live)
        .expect("active cache flow must still be in the table")
        .last_seen_ns;
    assert!(
        live_last > install_ns + DEFAULT_UDP_SESSION_TIMEOUT_NS,
        "live flow last_seen ({live_last}) must advance past one timeout window"
    );

    // The untouched control flow expired at its 60 s timeout (a Close
    // delta was emitted for it) — confirms expiry is real, not disabled.
    assert!(
        table.entry_by_key(&dead).is_none(),
        "the no-traffic control session must have expired"
    );
    assert!(
        table
            .drain_deltas(64)
            .iter()
            .any(|d| d.key == dead && d.kind == SessionDeltaKind::Close),
        "expired control session must emit a Close delta"
    );
}

/// FAIL-ON-REVERT (explicit): replays the exact #2220 skew. A saturating
/// high-rate flow and a steady low-rate flow share a binding. The old
/// code is reproduced inline (one binding-global counter; a flow is
/// touched only when its OWN hit lands on a global multiple of 64). The
/// new code calls `touch_if_stale` per hit. The low-rate flow survives
/// under the new code and is reaped under the old — so this test fails
/// if `touch_if_stale` is reverted to the global-modulo counter.
#[test]
fn touch_if_stale_survives_skew_that_starves_global_modulo() {
    let install_ns = 1_000_000_000u64;
    let high = make_v4_key(1, 7001); // saturating UDP flow
    let low = make_v4_key(2, 7002); // steady low-rate UDP flow

    // Interleave: 64 high-rate hits per 1 low-rate hit, both cache-
    // resident. Run for 10× the UDP timeout. Per-flow now_ns spacing:
    // high hits ~every 1 ms, the low hit closes each 64-hit group.
    let group_span = 5 * WHEEL_TICK_NS; // low flow ~ every 5 s
    let groups = 120u64; // 600 s total

    // --- OLD logic (binding-global modulo-64), reproduced inline ---
    {
        let mut table = SessionTable::new();
        for k in [&high, &low] {
            assert!(table.install_with_protocol(
                k.clone(),
                decision(),
                metadata(),
                install_ns,
                PROTO_UDP,
                0
            ));
        }
        let mut global_touch: u64 = 0;
        let mut now = install_ns;
        let mut low_reaped = false;
        for _ in 0..groups {
            // 64 high-rate hits monopolise the modulo boundaries.
            for _ in 0..64u64 {
                now += group_span / 64;
                global_touch += 1;
                if global_touch & 63 == 0 {
                    table.touch(&high, now);
                }
            }
            // one low-rate hit — lands mid-group, never on & 63 == 0.
            global_touch += 1;
            if global_touch & 63 == 0 {
                table.touch(&low, now);
            }
            table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
            let expired = table.expire_stale_entries(now);
            if expired.iter().any(|e| e.key == low) {
                low_reaped = true;
            }
        }
        assert!(
            low_reaped && table.entry_by_key(&low).is_none(),
            "PRECONDITION: the OLD global-modulo logic must starve+reap \
             the low-rate flow — if this fails the test no longer proves \
             a regression"
        );
    }

    // --- NEW logic (per-session touch_if_stale) ---
    {
        let mut table = SessionTable::new();
        for k in [&high, &low] {
            assert!(table.install_with_protocol(
                k.clone(),
                decision(),
                metadata(),
                install_ns,
                PROTO_UDP,
                0
            ));
        }
        let mut now = install_ns;
        for _ in 0..groups {
            for _ in 0..64u64 {
                now += group_span / 64;
                table.touch_if_stale(&high, now);
            }
            table.touch_if_stale(&low, now);
            table.last_gc_ns = now - SESSION_GC_INTERVAL_NS;
            let expired = table.expire_stale_entries(now);
            assert!(
                !expired.iter().any(|e| e.key == low),
                "NEW logic must keep the low-rate flow alive (got {expired:?})"
            );
        }
        assert!(
            table.entry_by_key(&low).is_some(),
            "NEW per-session keepalive must leave the low-rate flow live"
        );
        assert!(
            table.entry_by_key(&high).is_some(),
            "the high-rate flow stays live too"
        );
    }
}

// === #2442 loss-of-sync resync tests ==========================
//
// `push_delta` drops a delta when the in-worker ring is at
// MAX_SESSION_DELTAS, counting `delta_drops` but — pre-#2442 — never
// surfacing the loss. The fix latches a loss-of-sync signal
// (`take_delta_loss`) that the worker loop reads to force a full owner-RG
// export so the downstream session-sync consumer rescans the table truth.

/// Build a synthetic Open delta from the shared test fixtures. Used only to
/// drive `push_delta` to the ring limit without installing real sessions.
fn open_delta(key: SessionKey) -> SessionDelta {
    SessionDelta {
        kind: SessionDeltaKind::Open,
        key,
        decision: decision(),
        metadata: metadata(),
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 0,
        bulk_resync: false,
        tcp_close_class: 0,
    }
}

/// (a) Overflowing the ring sets the loss latch and counts the drop.
/// FAIL-ON-REVERT: if `push_delta` stops setting `delta_loss_pending` the
/// latch stays false and this assert goes red — the loss becomes invisible.
#[test]
fn delta_ring_overflow_sets_loss_signal() {
    let mut table = SessionTable::new();
    // Fill exactly to the cap — no drops yet.
    for i in 0..MAX_SESSION_DELTAS {
        table.push_delta(open_delta(make_v4_key(1, 1000 + (i as u16))));
    }
    assert_eq!(table.delta_drops(), 0, "filling to cap must not drop");
    assert!(
        !table.take_delta_loss(),
        "no loss latched before any overflow"
    );
    // One more push overflows -> drop + loss latch.
    table.push_delta(open_delta(make_v4_key(2, 2000)));
    assert_eq!(table.delta_drops(), 1, "overflow must count one drop");
    assert!(table.delta_loss_pending, "overflow must latch loss-of-sync");
}

/// (b) The loss is reported to the consumer via `take_delta_loss`, and a
/// plain `drain_deltas` does NOT clear it (drain and loss are distinct
/// signals — the consumer must learn the stream was lossy).
#[test]
fn drain_does_not_clear_loss_only_take_does() {
    let mut table = SessionTable::new();
    for i in 0..=MAX_SESSION_DELTAS {
        table.push_delta(open_delta(make_v4_key(1, 100 + (i as u16))));
    }
    assert!(table.delta_loss_pending, "overflowed -> latched");
    // Draining the surviving deltas must not swallow the loss signal.
    let _ = table.drain_deltas(MAX_SESSION_DELTAS);
    assert!(
        table.delta_loss_pending,
        "drain must not clear the loss latch"
    );
    assert!(
        table.take_delta_loss(),
        "consumer take must observe the loss"
    );
}

/// (c) DEBOUNCE: a sustained overflow that drops many deltas before the
/// consumer reads raises exactly ONE loss episode. A second `take` with no
/// fresh drop in between returns false (no resync storm).
#[test]
fn loss_signal_debounces_a_burst_into_one_episode() {
    let mut table = SessionTable::new();
    // Overflow hard: push far past the cap so MANY deltas drop.
    for i in 0..(MAX_SESSION_DELTAS * 3) {
        table.push_delta(open_delta(make_v4_key((i % 250) as u8, (i % 1000) as u16)));
    }
    assert!(
        table.delta_drops() >= (MAX_SESSION_DELTAS as u64) * 2,
        "a 3x-cap burst drops well over a cap's worth"
    );
    // The whole burst collapses to one episode.
    assert!(table.take_delta_loss(), "first take sees the episode");
    assert!(
        !table.take_delta_loss(),
        "no fresh drop -> second take is silent (debounced)"
    );
}

/// (d) After the consumer takes (models a completed resync) the signal
/// clears; a FRESH overflow re-arms a NEW episode.
#[test]
fn fresh_overflow_after_take_rearms_a_new_episode() {
    let mut table = SessionTable::new();
    for i in 0..=MAX_SESSION_DELTAS {
        table.push_delta(open_delta(make_v4_key(1, i as u16)));
    }
    assert!(table.take_delta_loss(), "episode 1 observed");
    assert!(!table.take_delta_loss(), "cleared after take");
    // Drain so the ring is empty again (a real resync would too), then a new
    // burst overflows and re-arms.
    let _ = table.drain_deltas(MAX_SESSION_DELTAS * 4);
    for i in 0..=MAX_SESSION_DELTAS {
        table.push_delta(open_delta(make_v4_key(2, i as u16)));
    }
    assert!(
        table.take_delta_loss(),
        "a fresh overflow re-arms a new loss episode"
    );
}

/// RESYNC TRIGGER: the loss path re-exports owned forward sessions. Install
/// real owned sessions, drain their open deltas (consumer is caught up),
/// then run the same full-export walk the worker loop fires on loss and
/// assert every owned forward session is re-emitted as a fresh Open delta —
/// i.e. the consumer can rebuild the table truth after a lossy stream.
#[test]
fn loss_resync_re_exports_owned_forward_sessions() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let keys: Vec<SessionKey> = (0..5).map(|i| make_v4_key(10, 3000 + i)).collect();
    for key in &keys {
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_UDP,
            0
        ));
    }
    // Consumer drains the install open-deltas: it is now caught up.
    let drained = table.drain_deltas(64);
    assert_eq!(drained.len(), keys.len(), "one open delta per install");
    assert!(!table.has_pending_deltas());

    // The full-export walk the worker loop runs on loss (owner RG 1 from the
    // shared `metadata()` fixture) re-emits an open delta per owned session.
    let owner_rgs = table.all_owner_rg_ids();
    assert!(
        owner_rgs.contains(&1),
        "owner RG 1 (the metadata fixture) is present"
    );
    crate::afxdp::export_forward_sessions_for_owner_rgs(&mut table, &owner_rgs);
    let resync = table.drain_deltas(64);
    assert_eq!(
        resync.len(),
        keys.len(),
        "resync re-emits every owned forward session"
    );
    assert!(
        resync.iter().all(|d| d.kind == SessionDeltaKind::Open),
        "resync deltas are all Open (table-truth re-population)"
    );
    for key in &keys {
        assert!(
            resync.iter().any(|d| &d.key == key),
            "owned session {key:?} re-exported on resync"
        );
    }
}

/// #2442 MAJOR (hostile review): the resync re-export must NOT overflow the
/// 4096-slot ring. A worker can own up to DEFAULT_MAX_SESSIONS (131072)
/// forward sessions — 32x the ring. A naive "drain then push all N" overflows
/// at delta 4097, drops sessions 4097..N, re-latches the loss, and storms
/// every cycle (the peer never gets a complete snapshot).
///
/// This test installs >4096 owned forward sessions and runs the SAME chunked
/// drain-as-you-export the worker loop performs (collect candidates -> emit in
/// chunks of < cap -> drain between chunks). It asserts:
///   (a) the COMPLETE snapshot ships (all N open deltas reach the drain sink,
///       not 4096);
///   (b) the loss latch is CLEAR after the resync (no permanent re-arm);
///   (c) delta_drops does NOT grow across repeated resync cycles (converges).
///
/// FAIL-ON-REVERT: the naive unbounded export (push all then drain once) ships
/// only 4096 and leaves the latch armed with delta_drops > 0 — reds (a)/(b).
#[test]
fn resync_ships_complete_snapshot_above_ring_cap_without_relatching() {
    const RESYNC_EXPORT_CHUNK: usize = 2048; // mirror the worker loop
    let n: usize = MAX_SESSION_DELTAS + 1000; // 5096 > 4096 cap
    assert!(n > MAX_SESSION_DELTAS, "must exceed the ring to exercise the hole");

    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let mut keys: Vec<SessionKey> = Vec::with_capacity(n);
    for i in 0..n {
        // Unique keys: src octet 0..255 x port. dst is fixed in make_v4_key.
        let key = make_v4_key((i / 256) as u8, ((i % 256) as u16) + 1000);
        assert!(table.install_with_protocol(
            key.clone(),
            decision(),
            metadata(),
            now,
            PROTO_UDP,
            0
        ));
        keys.push(key);
    }
    // The installs themselves overflowed the ring (n > cap) and latched loss.
    assert!(table.delta_drops() > 0, "installing > cap deltas overflows the ring");
    let drops_after_install = table.delta_drops();

    // === one chunked drain-as-you-export resync cycle (mirrors loop_body) ===
    // The export PHASE alone must re-emit the complete owned-session set; the
    // backlog drain ships a subset and is a different signal.
    let exported = run_chunked_resync(&mut table, RESYNC_EXPORT_CHUNK);

    // (a) COMPLETE snapshot: every owned forward session re-emitted.
    assert_eq!(
        exported, n,
        "resync export must ship the COMPLETE snapshot ({n}), not the ring cap"
    );
    // (b) no permanent re-arm: the chunked export never overflowed.
    assert!(
        !table.take_delta_loss(),
        "loss latch must be CLEAR after a complete chunked resync"
    );
    assert_eq!(
        table.delta_drops(),
        drops_after_install,
        "the resync export itself must not drop a single delta"
    );

    // (c) convergence: a second resync cycle ships the same complete snapshot
    // and still drops nothing — delta_drops does not climb cycle over cycle.
    let exported2 = run_chunked_resync(&mut table, RESYNC_EXPORT_CHUNK);
    assert_eq!(exported2, n, "second cycle still ships the complete snapshot");
    assert_eq!(
        table.delta_drops(),
        drops_after_install,
        "delta_drops must NOT grow across resync cycles (converged)"
    );
    assert!(!table.take_delta_loss(), "still no spurious re-arm");
}

/// Drive the chunked drain-as-you-export resync the worker loop performs, but
/// drain into a counter sink instead of `flush_session_deltas`. Clears the
/// loss latch (as `take_delta_loss` does in the loop), drains+discards the
/// backlog so the ring starts empty, then emits the owned forward candidates
/// in chunks, draining between chunks. Returns the number of open deltas the
/// EXPORT PHASE shipped — the completeness measure for the re-derived snapshot.
fn run_chunked_resync(table: &mut SessionTable, chunk: usize) -> usize {
    let _ = table.take_delta_loss();
    // Drain (discard) the existing backlog so the ring starts empty, exactly
    // as the worker loop does before the chunked export.
    while !table.drain_deltas(256).is_empty() {}

    let owner_rgs = table.all_owner_rg_ids();
    let candidates = crate::afxdp::forward_export_candidates_for_owner_rgs(table, &owner_rgs);
    let mut exported = 0usize;
    for c in candidates.chunks(chunk) {
        for (key, decision, metadata, origin) in c.iter().cloned() {
            table.emit_open_delta_with_origin(key, decision, metadata, origin, true);
        }
        loop {
            let d = table.drain_deltas(256);
            if d.is_empty() {
                break;
            }
            exported += d.iter().filter(|x| x.kind == SessionDeltaKind::Open).count();
        }
    }
    exported
}

// ---- #2364: seeded session-index hashing --------------------------------

/// The session indices are private, so assert the hardening property at
/// the BuildHasher the maps are constructed with: `FxSeededState` over a
/// `SessionKey` must produce a seed-dependent bucket distribution (so an
/// attacker cannot precompute a collision chain offline) while staying
/// stable for a fixed seed (so the live table's lookup/insert agree).
///
/// Fail-on-revert: the reverted state used `FxHashMap::default()`
/// (= `FxBuildHasher`, unseeded). `FxBuildHasher::hash_one` ignores any
/// seed, so the "distribution depends on seed" arm below would fail.
#[test]
fn session_key_seeded_hash_depends_on_seed_and_is_stable() {
    use std::hash::BuildHasher;

    // 256 attacker-constructible keys (one src subnet, sweeping src_port).
    let keys: Vec<SessionKey> = (0..256u16)
        .map(|i| make_v4_key((i & 0xff) as u8, 40000u16.wrapping_add(i)))
        .collect();

    // Low bits of the hash model the open-addressing bucket the map would
    // probe; equal vectors ⇒ identical bucket layout.
    let dist = |seed: usize| -> Vec<u64> {
        let state = FxSeededState::with_seed(seed);
        keys.iter().map(|k| state.hash_one(k) & 0x3ff).collect()
    };

    // Stability within one seed (cache/lookup consistency).
    let s = 0x0123_4567usize;
    assert_eq!(dist(s), dist(s), "seeded session hash must be stable per seed");

    // Seed-dependence: some seed produces a different bucket layout for the
    // SAME key set. With the unseeded FxBuildHasher this is impossible
    // (the seed is ignored) → fail-on-revert.
    let reference = dist(0xA5A5_5A5A);
    let mut diverged = false;
    for seed in 1usize..4096 {
        if dist(seed) != reference {
            diverged = true;
            break;
        }
    }
    assert!(
        diverged,
        "session-key bucket layout did not change across seeds — index hash \
         is seed-independent (unseeded FxHashMap regression, #2364)"
    );
}

/// The seeded session table must still behave correctly end-to-end:
/// insert under the per-boot seed, look the key back up, get a hit.
/// Guards against the seed silently breaking normal lookup.
#[test]
fn seeded_session_table_round_trips_lookup() {
    let mut table = SessionTable::new();
    let key = make_v4_key(7, 41000);
    let now = 1_000_000_000u64;
    install_synced_tcp(&mut table, &key, 1, now);
    assert!(
        table.lookup(&key, now, 0x10).is_some(),
        "a key inserted into the seeded index must be found by the same key"
    );
    // A different key must miss — proves we are matching the key, not
    // succeeding for everything.
    let other = make_v4_key(8, 41001);
    assert!(
        table.lookup(&other, now, 0x10).is_none(),
        "a non-inserted key must miss under the seeded index"
    );
}

// ── #2501: per-session byte/packet accounting ───────────────────────────

/// A reverse SessionMetadata mirrors `metadata()` with `is_reverse: true`.
fn metadata_reverse() -> SessionMetadata {
    SessionMetadata {
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        is_reverse: true,
        ..metadata()
    }
}

#[test]
fn account_packet_forward_increments_fwd_counters() {
    let mut table = SessionTable::new();
    let key = key_v4();
    let now = 1_000_000_000u64;
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), now, PROTO_TCP, 0x10));

    table.account_packet(&key, 100, 0, 0);
    table.account_packet(&key, 250, 0, 0);

    let c = table.session_counters(&key).expect("forward entry exists");
    // FAIL-ON-REVERT: revert the hot-path increment and these go to 0.
    assert_eq!(c.fwd_packets, 2);
    assert_eq!(c.fwd_bytes, 350);
    assert_eq!(c.rev_packets, 0);
    assert_eq!(c.rev_bytes, 0);
}

#[test]
fn account_packet_reverse_folds_onto_forward_entry() {
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let fwd = key_v4();
    // No-NAT reverse wire key is the src/dst-swapped forward tuple — exactly
    // what `reverse_session_key(fwd, default_nat)` recovers.
    let rev = reverse_session_key(&fwd, NatDecision::default());

    // Install BOTH halves: forward (is_reverse=false) keyed by `fwd`, and the
    // reverse companion (is_reverse=true) keyed by `rev`. This mirrors the
    // poll_descriptor forward+reverse install pair.
    assert!(table.install_with_protocol(fwd.clone(), decision(), metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(
        rev.clone(),
        decision(),
        metadata_reverse(),
        now,
        PROTO_TCP,
        0x10,
    ));

    // A forward packet (keyed by the forward tuple) and a reverse packet
    // (keyed by the reply tuple).
    table.account_packet(&fwd, 1000, 0, 0);
    table.account_packet(&rev, 40, 0, 0);
    table.account_packet(&rev, 60, 0, 0);

    // Both directions must land on the canonical FORWARD entry so the
    // forward-only BPF mirror / close harvest sees the complete picture.
    let c = table.session_counters(&fwd).expect("forward entry exists");
    assert_eq!(c.fwd_packets, 1, "forward packet counted once");
    assert_eq!(c.fwd_bytes, 1000);
    // FAIL-ON-REVERT: drop the reverse→forward fold and rev_* stays 0 on the
    // forward entry (the reverse volume would be lost by the forward-only
    // conntrack mirror).
    assert_eq!(c.rev_packets, 2, "two reverse packets folded onto fwd entry");
    assert_eq!(c.rev_bytes, 100);
}

#[test]
fn account_packet_miss_is_noop() {
    let mut table = SessionTable::new();
    // No session installed — accounting an unknown key must not panic or
    // create state.
    table.account_packet(&key_v4(), 9999, 0, 0);
    assert!(table.session_counters(&key_v4()).is_none());
}

// #4074 FAIL-ON-REVERT: for a TRANSLATED pool-SNAT ICMP flow, a reverse (reply)
// packet's volume must fold onto the canonical FORWARD entry's `rev` counter —
// exactly like TCP/UDP — so the forward-only conntrack mirror / SESSION_CLOSE
// harvest sees the reply-direction bytes. `account_packet` does this by calling
// `reverse_session_key(reverse_entry_key, reverse_decision)` to recover the
// forward entry's key. Because SNAT translated the ICMP id X->Y, the reverse
// entry is keyed on Y; `NatDecision::reverse` stored the ORIGINAL id X in
// `rewrite_dst_port`. So `reverse_session_key` MUST read `rewrite_dst_port` to
// recover X and hit the forward entry {..,X,..}.
//
// Reverting the `reverse_session_key` ICMP arm to read only `rewrite_src_port`
// yields Y (not X) -> the forward entry is MISSED -> `account_packet` falls back
// to the reverse entry, so the FORWARD entry's `rev_*` stays 0 and the reply
// volume is lost by the forward-only harvest. This asserts the forward entry's
// `rev_*` is bumped, going RED on revert. Covers v4 + v6.
#[test]
fn account_packet_reverse_folds_onto_forward_translated_icmp() {
    for v6 in [false, true] {
        let mut table = SessionTable::new();
        let now = 1_000_000_000u64;
        let (proto, af, host, target, pool): (u8, u8, IpAddr, IpAddr, IpAddr) = if v6 {
            (
                PROTO_ICMPV6,
                10,
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
                IpAddr::V6("2001:db8:cafe::8".parse().unwrap()),
            )
        } else {
            (
                PROTO_ICMP,
                2,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            )
        };
        let orig_id: u16 = 0x1234; // X (original identifier)
        let translated_id: u16 = 40001; // Y (pool-allocated identifier)

        // Forward ICMP entry {host, target, X, 0}, pool-SNAT'd to {pool, .., Y}.
        let fwd = SessionKey {
            addr_family: af,
            protocol: proto,
            src_ip: host,
            dst_ip: target,
            src_port: orig_id,
            dst_port: 0,
                    discriminator: Default::default(),
                    routing_domain: 0,
        };
        let fwd_nat = NatDecision {
            rewrite_src: Some(pool),
            rewrite_src_port: Some(translated_id),
            ..NatDecision::default()
        };
        let fwd_decision = SessionDecision {
            resolution: resolution(),
            nat: fwd_nat,
        };
        // Reverse companion, keyed on the translated id (the reply carries Y).
        let rev = reverse_session_key(&fwd, fwd_nat);
        assert_eq!(rev.src_port, translated_id, "v6={v6}: companion keyed on Y");
        // The reverse entry's decision is the inverted forward decision — this
        // is exactly what build_reverse_session_from_forward_match installs.
        let rev_nat = fwd_nat.reverse(host, target, orig_id, 0);
        let rev_decision = SessionDecision {
            resolution: resolution(),
            nat: rev_nat,
        };

        assert!(table.install_with_protocol(fwd.clone(), fwd_decision, metadata(), now, proto, 0));
        assert!(table.install_with_protocol(
            rev.clone(),
            rev_decision,
            metadata_reverse(),
            now,
            proto,
            0,
        ));

        // A reverse (reply) packet keyed by the reverse-entry tuple.
        table.account_packet(&rev, 100, 0, 0);

        let c = table.session_counters(&fwd).expect("forward entry exists");
        assert_eq!(
            c.rev_packets, 1,
            "v6={v6}: reverse ICMP volume must fold onto the FORWARD entry",
        );
        assert_eq!(
            c.rev_bytes, 100,
            "v6={v6}: reverse bytes on the forward entry"
        );
        assert_eq!(c.fwd_packets, 0, "v6={v6}: no forward packet was accounted");
    }
}

#[test]
fn close_delta_carries_harvested_counters() {
    let mut table = SessionTable::new();
    let then = 1_000_000_000u64;
    let key = key_v4();
    assert!(table.install_with_protocol(key.clone(), decision(), metadata(), then, PROTO_TCP, 0x10));
    // Drain the Open delta so the next drain only sees the Close.
    let _ = table.drain_deltas(8);

    table.account_packet(&key, 500, 0, 0);
    table.account_packet(&key, 700, 0, 0);

    // Force expiry.
    table.last_gc_ns = then + 301_000_000_000;
    let expired = table.expire_stale_entries(then + 302_000_000_000);
    assert_eq!(expired.len(), 1);

    let deltas = table.drain_deltas(8);
    let close = deltas
        .iter()
        .find(|d| d.kind == SessionDeltaKind::Close)
        .expect("a Close delta was produced");
    // FAIL-ON-REVERT: stop harvesting `removed.counters` onto the Close delta
    // and these revert to 0 — the SESSION_CLOSE RT_FLOW frame loses volume.
    assert_eq!(close.counters.fwd_packets, 2);
    assert_eq!(close.counters.fwd_bytes, 1200);
}

// #2749 FAIL-ON-REVERT: a session close must carry the REAL observed ToS
// (forward-direction DSCP<<2) and the cumulative TCP control bits (OR of all
// flags seen in both directions). Reverting the `account_packet` stamping (or
// the expire.rs harvest of `removed.observed_*`) drops these to 0 — the exact
// #2613 regression that exported synthetic-zero ipClassOfService /
// tcpControlBits to collectors.
#[test]
fn close_delta_carries_observed_tos_and_tcp_flags() {
    let mut table = SessionTable::new();
    let then = 1_000_000_000u64;
    let fwd = key_v4();
    let rev = reverse_session_key(&fwd, NatDecision::default());
    // Install seeds the cumulative flags with the trigger packet's SYN (0x02).
    assert!(table.install_with_protocol(fwd.clone(), decision(), metadata(), then, PROTO_TCP, 0x02));
    assert!(table.install_with_protocol(
        rev.clone(),
        decision(),
        metadata_reverse(),
        then,
        PROTO_TCP,
        0x02,
    ));
    let _ = table.drain_deltas(8);

    // Forward packet: DSCP EF (46) → ToS byte 0xB8, TCP ACK (0x10).
    table.account_packet(&fwd, 500, 0x10, 46);
    // Reverse packet: FIN|ACK (0x11), a DIFFERENT DSCP (must NOT change the
    // forward ToS — the responder's class of service is irrelevant to srcTos).
    table.account_packet(&rev, 40, 0x11, 10);

    table.last_gc_ns = then + 301_000_000_000;
    // Both halves expire; only the forward (is_reverse=false) entry produces a
    // Close delta (expire.rs gates the close delta on !is_reverse).
    let expired = table.expire_stale_entries(then + 302_000_000_000);
    assert_eq!(expired.len(), 2);

    let deltas = table.drain_deltas(8);
    let close = deltas
        .iter()
        .find(|d| d.kind == SessionDeltaKind::Close)
        .expect("a Close delta was produced");
    // Forward-direction ToS = DSCP 46 << 2 = 184 (0xB8); reverse DSCP ignored.
    assert_eq!(close.observed_tos, 0xB8, "real forward ToS, not 0");
    // Cumulative flags = SYN(0x02) | ACK(0x10) | FIN|ACK(0x11) = 0x13.
    assert_eq!(
        close.observed_tcp_flags, 0x13,
        "OR of all TCP flags seen in both directions, not 0"
    );
}

// ── #6751: attribute a reverse-key collision to its CAUSE ────────────
//
// `nat_reverse_key_collisions` counts every reverse-key bucket growth, which
// is at least three populations with three different remedies:
//
//   * two distinct internal hosts choosing the same source port to the same
//     server under interface-mode SNAT — the cross-session return-traffic
//     leak this issue is about, and the ONLY one PAT-on-collision fixes;
//   * ONE host reusing an ephemeral port while its previous session is still
//     resident — same bucket growth, no leak between hosts;
//   * `port no-translation` / static SNAT pairs, which the allocator admits
//     DELIBERATELY (#6745 governs their steering row instead).
//
// The aggregate reads 2 on the loss cluster today with ONE LAN host
// configured, so what it is actually producing there is port reuse — which is
// precisely why it cannot answer "does the two-host shape happen". These
// tests pin that the new counter can.
//
// THE SMOKE CANNOT EXERCISE THIS. `make test-failover` drives iperf3 from a
// single LAN host, so it cannot produce two distinct internal sources racing
// for one port. A unit test is the only place the property is guaranteed to
// occur, which is why the collision is constructed here rather than observed.

#[test]
fn distinct_source_collision_is_attributed_6751() {
    // The #6751 shape: DIFFERENT internal hosts, same source port, same
    // server, interface-mode SNAT (source-IP-only rewrite).
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = iface_snat_decision(Ipv4Addr::new(203, 0, 113, 9));

    let mut s1 = key_v4();
    s1.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    s1.src_port = 5555;
    let mut s2 = key_v4();
    s2.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    s2.src_port = 5555;
    assert_eq!(
        reverse_wire_key(&s1, dec.nat),
        reverse_wire_key(&s2, dec.nat),
        "premise: the two flows must collide on one reverse wire key",
    );

    assert!(table.install_with_protocol(s1, dec, metadata(), now, PROTO_TCP, 0x10));
    assert_eq!(
        table.nat_reverse_key_collisions_distinct_src(),
        0,
        "one session cannot collide with itself",
    );

    assert!(table.install_with_protocol(s2, dec, metadata(), now, PROTO_TCP, 0x10));
    assert!(
        table.nat_reverse_key_collisions() > 0,
        "premise: the aggregate must see this collision",
    );
    assert!(
        table.nat_reverse_key_collisions_distinct_src() > 0,
        "a collision between DIFFERENT internal sources is the #6751 \
         cross-session leak and must be attributed as such -- this is the \
         number that decides whether PAT-on-collision is worth its risk",
    );
}

#[test]
fn reverse_index_collision_is_not_attributed_6751() {
    // THE DISCRIMINATING HALF. Without it the new counter could simply be an
    // alias of the aggregate and the test above would still pass.
    //
    // The population chosen is the one that would actually corrupt the
    // number: a collision on the REVERSE/alias index, where the indexed key's
    // `src_ip` is the EXTERNAL SERVER rather than an internal host. Two such
    // sessions with different servers look exactly like "two distinct
    // sources" to a naive comparison, so attributing them would inflate the
    // very number this counter exists to make trustworthy.
    //
    // An earlier revision tried SAME-SOURCE port reuse instead, and its
    // premise check caught it as VACUOUS: two sessions from one host that
    // share a reverse wire key must share (src_port, dst_ip, dst_port) too,
    // which makes them the same session key, so the push dedups and no
    // collision occurs at all. The assertion would have held for the wrong
    // reason. That is also why the loss cluster's aggregate of 2 cannot be
    // same-source forward reuse — it has to be one of the other index
    // populations.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let dec = iface_snat_decision(Ipv4Addr::new(203, 0, 113, 9));
    let mut meta = metadata();
    meta.is_reverse = true;

    let mut r1 = key_v4();
    r1.src_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let mut r2 = key_v4();
    r2.src_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));

    assert!(table.install_with_protocol(r1, dec, meta.clone(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(r2, dec, meta, now, PROTO_TCP, 0x10));

    // THE FIXTURE MUST ACTUALLY COLLIDE, or the assertion below is vacuous.
    assert!(
        table.nat_reverse_key_collisions() > 0,
        "premise: this reverse-index pair must produce a collision, otherwise \
         the distinct-source assertion below proves nothing",
    );
    assert_eq!(
        table.nat_reverse_key_collisions_distinct_src(),
        0,
        "a collision on the REVERSE/alias index must not be attributed: its \
         key.src_ip is the external server, so counting it would report \
         distinct SERVERS as distinct internal sources",
    );
}

#[test]
fn same_source_pat_collision_is_not_attributed_6751() {
    // THE SECOND DISCRIMINATING HALF, and the one that binds the src_ip
    // COMPARISON itself rather than the branch it runs in.
    //
    // Same internal host, two DIFFERENT forward sessions, one reverse wire
    // key: session A is PAT'd from :5555 to :6000, session B natively uses
    // :6000 and is translated address-only. Both collapse to
    // (8.8.8.8:443 -> 203.0.113.9:6000). That is the same-host port-reuse
    // population -- real, but NOT the #6751 cross-session leak, because one
    // host cannot steal its own return traffic in a way that crosses a
    // security boundary. It must move the aggregate and NOT the attributed
    // counter.
    //
    // A previous attempt at this half used same-source/different-dst_port and
    // its premise check caught it as VACUOUS: with one NAT decision, two
    // sessions from one host sharing a reverse wire key must share
    // (src_port, dst_ip, dst_port) too, so they are the same session key and
    // the push dedups. Making the two NAT DECISIONS differ is what creates a
    // genuine same-source collision.
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let egress = Ipv4Addr::new(203, 0, 113, 9);

    let mut pat = iface_snat_decision(egress);
    pat.nat.rewrite_src_port = Some(6000);

    let a = key_v4();
    let mut b = key_v4();
    b.src_port = 6000;
    assert_eq!(a.src_ip, b.src_ip, "fixture: both sessions are the SAME host");

    assert!(table.install_with_protocol(a, pat, metadata(), now, PROTO_TCP, 0x10));
    assert!(table.install_with_protocol(
        b,
        iface_snat_decision(egress),
        metadata(),
        now,
        PROTO_TCP,
        0x10
    ));

    // THE FIXTURE MUST ACTUALLY COLLIDE, or the assertion below is vacuous.
    assert!(
        table.nat_reverse_key_collisions() > 0,
        "premise: this same-source pair must produce a reverse-key collision, \
         otherwise the distinct-source assertion below proves nothing",
    );
    assert_eq!(
        table.nat_reverse_key_collisions_distinct_src(),
        0,
        "a collision between two sessions from the SAME internal host is \
         port reuse, not the #6751 cross-source leak, and must not be \
         attributed",
    );
}

/// #6752: SYN → SYN-ACK → **no final ACK** must reap on the OPENING window,
/// not hold both halves for the full established timeout.
///
/// The gap the issue names: promotion happens on the SYN-ACK, not on the final
/// ACK, so the reverse half jumped straight to the 300s class. #4109
/// deliberately did NOT extend the forward half's expiry, and said so — "a
/// handshake the client never completes still reaps on the short opening
/// window". Three days later #4380's companion probe, which is protocol- and
/// handshake-agnostic, made that false: at the forward half's 20s deadline it
/// saw the reverse half alive on its brand-new 300s window and re-stamped the
/// forward half off it. Both halves then persisted ~300s from the SYN-ACK.
///
/// WHY THE EXISTING COVERAGE DID NOT CATCH IT.
/// `tcp_handshake_promotes_opening_to_established` asserts the `established`
/// FLAG after the SYN-ACK, then sends the final ACK and only afterwards asserts
/// `expires_after_ns`. It never asserts the reverse entry's window after the
/// SYN-ACK, and it never runs the no-final-ACK case at all.
/// `forward_ack_without_reverse_synack_stays_opening` covers the opposite shape
/// (no SYN-ACK). Neither can see this.
#[test]
fn synack_without_final_ack_stays_on_the_opening_window_6752() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);

    // The server answers; the client never completes.
    assert!(
        table
            .lookup(&reverse, now + 1_000_000, TCP_SYN | TCP_ACK)
            .is_some()
    );

    let rev = table.entry_by_key(&reverse).expect("rev after synack");
    assert!(
        rev.established,
        "premise: the SYN-ACK still promotes the flag — this fix does not change \
         WHEN a flow counts as established, only which idle window it ages on",
    );
    assert_eq!(
        rev.expires_after_ns,
        table.timeouts.tcp_opening_ns,
        "the reverse half jumped to the ESTABLISHED idle window on the SYN-ACK, \
         so a handshake the client never completes is held for the full \
         established timeout instead of reaping at the opening window (#6752)",
    );
    let fwd = table.entry_by_key(&forward).expect("fwd after synack");
    assert_eq!(
        fwd.expires_after_ns,
        table.timeouts.tcp_opening_ns,
        "the forward half must also still be on the opening window",
    );

    // The companion probe must not resurrect either half. Step past the opening
    // window and expire: with the flow still half-open, BOTH halves must go.
    // A few seconds past the opening window — comfortably beyond it, and still
    // two orders of magnitude short of the 300s established window, so a reap
    // here can only mean the opening class was applied. The margin also clears
    // the wheel's `cursor_tick < now_tick` sweep boundary and the GC interval
    // gate, which is test plumbing rather than part of the property.
    let past = now + table.timeouts.tcp_opening_ns + 5_000_000_000;
    // Drive the wheel forward the way the other expiry tests do: the sweep only
    // examines ticks between `last_gc_ns` and `now_ns`.
    table.last_gc_ns = past - 2_000_000_000;
    table.expire_stale_entries(past);
    assert!(
        table.entry_by_key(&forward).is_none(),
        "the forward half survived past the opening window — the #4380 companion \
         probe extended it off the reverse half, which is exactly the resurrection \
         #6752 is about",
    );
    assert!(
        table.entry_by_key(&reverse).is_none(),
        "the reverse half survived past the opening window",
    );
}

/// #6752 NEGATIVE CONTROL — the completed handshake must still get its full
/// established window, in BOTH directions.
///
/// Without this the fix is indistinguishable from "never promote the idle
/// window at all", which would reap every legitimate idle TCP session at 20s.
/// The forward half's window is asserted directly; the reverse half's is
/// asserted through the companion probe, because a completed flow's reverse
/// half keeps whatever window its last segment stamped and relies on #4380 to
/// age with its sibling — so the probe must start extending again the moment
/// the handshake completes.
#[test]
fn completed_handshake_still_gets_the_established_window_6752() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);

    assert!(
        table
            .lookup(&reverse, now + 1_000_000, TCP_SYN | TCP_ACK)
            .is_some()
    );
    // The client completes. This segment reaches the slow path by construction:
    // `packet_eligible` admits a TCP packet to the flow cache only when
    // `is_ack_only`, and `should_cache` uses the same predicate, so neither the
    // SYN nor the SYN-ACK ever seeded an entry — the final ACK is a cache MISS.
    assert!(table.lookup(&forward, now + 2_000_000, TCP_ACK).is_some());

    let fwd = table.entry_by_key(&forward).expect("fwd after final ack");
    assert!(fwd.established);
    assert_eq!(
        fwd.expires_after_ns,
        table.timeouts.tcp_established_ns,
        "a COMPLETED handshake must get the established idle window — without \
         this the #6752 fix would reap every legitimate idle TCP session at the \
         20s opening window",
    );

    // Past the opening window but well inside the established one: the flow —
    // both halves — must still be there. The reverse half survives via the
    // companion probe, which the fix must have re-enabled on completion.
    let past_opening = now + table.timeouts.tcp_opening_ns + 5_000_000_000;
    table.last_gc_ns = past_opening - 2_000_000_000;
    table.expire_stale_entries(past_opening);
    assert!(
        table.entry_by_key(&forward).is_some(),
        "the completed flow's forward half was reaped at the opening window",
    );
    assert!(
        table.entry_by_key(&reverse).is_some(),
        "the completed flow's reverse half was reaped at the opening window — the \
         companion probe must extend again once the handshake completes, or the \
         fix trades a half-open leak for a reaped live session",
    );
}

/// #6752, the second half of the fix: the companion probe must not resurrect a
/// half-open flow that the SERVER keeps refreshing.
///
/// The effective-class change alone is not sufficient here, and the two cells
/// above cannot show it — with both halves on the opening window and no further
/// traffic, the probe's own idle test already fails, so it never gets the chance
/// to extend. The gap opens when the reverse half keeps receiving packets: a
/// server retransmitting its SYN-ACK (normally ~5 times over ~30 s) slides the
/// reverse half's window forward, and a handshake-agnostic probe then re-stamps
/// the forward half off it for as long as the retransmissions continue.
///
/// That is a smaller leak than the ~300 s the class change closes, and it is
/// stated that way rather than as "both halves for 300 s" — but it is the reason
/// `companion_keeps_alive` consults `handshake_pending` rather than relying on
/// the class change to make the probe harmless.
#[test]
fn retransmitted_synack_does_not_resurrect_the_forward_half_6752() {
    let mut table = SessionTable::new();
    let forward = key_v4();
    let now = 1_000_000_000u64;
    let reverse = install_forward_reverse_pair(&mut table, &forward, now, TCP_SYN);

    // Server answers, then retransmits 15 s later. The client never completes.
    assert!(
        table
            .lookup(&reverse, now + 1_000_000, TCP_SYN | TCP_ACK)
            .is_some()
    );
    let retransmit = now + 15_000_000_000;
    assert!(
        table
            .lookup(&reverse, retransmit, TCP_SYN | TCP_ACK)
            .is_some()
    );

    // Past the FORWARD half's opening window, while the reverse half is fresh
    // (10 s idle, inside its own 20 s window) — precisely the state in which the
    // probe would extend.
    let past_forward = retransmit + 10_000_000_000;
    assert!(
        past_forward.saturating_sub(now) > table.timeouts.tcp_opening_ns,
        "fixture: the forward half must have crossed its window",
    );
    assert!(
        past_forward.saturating_sub(retransmit) < table.timeouts.tcp_opening_ns,
        "fixture: the reverse half must still be INSIDE its window, or the probe \
         would decline for the ordinary idle reason and this cell would prove \
         nothing",
    );
    table.last_gc_ns = past_forward - 2_000_000_000;
    table.expire_stale_entries(past_forward);

    assert!(
        table.entry_by_key(&forward).is_none(),
        "the forward half was kept alive off a retransmitted SYN-ACK. The #4380 \
         companion probe is handshake-agnostic, so without the handshake_pending \
         refusal a server that keeps retransmitting holds the client-side half of \
         a handshake that never completed (#6752)",
    );
}

// ---- #7096: the fabric-redirected ingress identity ----

/// #7096: a fabric-redirected session must record NO ingress identity, not the
/// LOCAL fabric member's.
///
/// The two halves of the ingress record come from different sources for such a
/// packet: the zone is overridden to the peer's ORIGINAL ingress zone (correct —
/// the flow logically arrived on the peer's WAN), while `meta.ingress_ifindex`
/// is still the local fabric member's netdev because nothing in production
/// rewrites it. Recording that would make
/// `show security flow session interface ge-0-0-0` select flows that arrived on
/// the PEER's WAN, and `interface reth0.50` stop selecting them — and the same
/// filter drives `clear`, so it is a wrong-session deletion.
#[test]
fn a_fabric_redirected_session_records_no_ingress_identity_7096() {
    const LOCAL_FABRIC_MEMBER: u32 = 7;
    const TAG: u16 = 50;

    let (ifindex, vlan) = stamped_ingress_identity(LOCAL_FABRIC_MEMBER, TAG, true);
    assert_eq!(
        (ifindex, vlan),
        (0, 0),
        "a fabric-redirected session must record NO ingress identity. The peer's \
         real ingress interface is not knowable here — the fabric stamp carries a \
         u16 zone id and nothing else — so naming the local fabric member is a \
         confidently WRONG answer, which is strictly worse than the zone \
         approximation the Go side falls back to on zero (#7096)"
    );
}

/// THE PAIRED CELL. The suppression must not widen: an ordinary (non-fabric)
/// session must still record its true ingress identity, which is the whole point
/// of #4983 and the thing this fix must not undo.
///
/// Identical inputs to the cell above; only `fabric_ingress` differs. That is
/// what makes the pair discriminating rather than two separate demonstrations —
/// a fix that returned (0, 0) unconditionally would satisfy the first cell and
/// silently revert #4983.
#[test]
fn an_ordinary_session_still_records_its_true_ingress_identity_7096() {
    const LOCAL_FABRIC_MEMBER: u32 = 7;
    const TAG: u16 = 50;

    let (ifindex, vlan) = stamped_ingress_identity(LOCAL_FABRIC_MEMBER, TAG, false);
    assert_eq!(
        (ifindex, vlan),
        (LOCAL_FABRIC_MEMBER, TAG),
        "a session whose first packet did NOT arrive over the fabric must keep its \
         true {{ifindex, vlan}} identity — zeroing it unconditionally would revert \
         #4983 and put every session back on the #4792 zone approximation"
    );
}

/// #7096: the VLAN half must be cleared with the ifindex, not left behind.
///
/// The pair is the logical ingress unit and is meaningful only together — the Go
/// consumer keys `{parent ifindex, unit VLAN}`. A residual VLAN beside a zeroed
/// ifindex would key `{0, 50}`, which is not "no identity recorded" but a
/// DIFFERENT identity, and one that could collide with a real interface whose
/// ifindex resolution failed.
#[test]
fn the_fabric_stamp_clears_both_halves_of_the_pair_7096() {
    for vlan in [0u16, 1, 50, 4094] {
        let (ifindex, got_vlan) = stamped_ingress_identity(9, vlan, true);
        assert_eq!(
            (ifindex, got_vlan),
            (0, 0),
            "both halves must clear together for vlan {vlan}; a residual VLAN \
             beside a zeroed ifindex is a different identity, not an absent one"
        );
    }
}
// ===========================================================================
// #7160 (#2387) — routing_domain on SessionKey.
//
// The defect: two flows in different routing-instances that share a 5-tuple
// collided in the conntrack map, and because the established-session fast path
// short-circuits before `ingress_route_table_override`, tenant B's flow
// inherited tenant A's cached egress, NAT and POLICY decision. A cross-tenant
// policy bypass, not merely wrong forwarding.
//
// These cells guard the two properties the field's doc comment claims, both of
// which are invisible to every pre-existing test because every one of them
// runs in the default routing instance where the field is 0.
// ===========================================================================

/// Two tenants, one 5-tuple, two sessions. This is the whole point of the
/// field: before it, the second install found the first's entry.
#[test]
fn two_routing_domains_sharing_a_5tuple_are_distinct_sessions_7160() {
    let mut table = SessionTable::new();

    let mut tenant_a = key_v4();
    tenant_a.routing_domain = 0x1111_1111;
    let mut tenant_b = key_v4();
    tenant_b.routing_domain = 0x2222_2222;

    // Identical in every field a pre-#7160 SessionKey had.
    assert_eq!(tenant_a.src_ip, tenant_b.src_ip);
    assert_eq!(tenant_a.dst_ip, tenant_b.dst_ip);
    assert_eq!(tenant_a.src_port, tenant_b.src_port);
    assert_eq!(tenant_a.dst_port, tenant_b.dst_port);
    assert_eq!(tenant_a.protocol, tenant_b.protocol);
    assert_ne!(
        tenant_a, tenant_b,
        "keys differing only in routing_domain must not be equal; if they are, \
         the field is not participating in Eq and every guarantee below is void"
    );

    assert!(table.install_with_protocol(
        tenant_a.clone(),
        decision(),
        metadata(),
        1_000,
        PROTO_TCP,
        TCP_SYN,
    ));
    assert!(
        table.install_with_protocol(
            tenant_b.clone(),
            decision(),
            metadata(),
            1_000,
            PROTO_TCP,
            TCP_SYN,
        ),
        "tenant B's install was refused — its 5-tuple collided with tenant A's, \
         which is exactly the #2387 cross-tenant collision"
    );

    assert!(
        table.entry_by_key(&tenant_a).is_some(),
        "tenant A's session vanished when tenant B installed"
    );
    assert!(
        table.entry_by_key(&tenant_b).is_some(),
        "tenant B's session is missing; its install landed on tenant A's entry"
    );
}

/// The five key transforms split into two groups, and each half is asserted by
/// name so a failure says which transform moved rather than "a transform".
///
/// Phase 1 had all five PRESERVING the domain, on the belief that a flow's
/// routing domain is the same in both directions. Phase 2 measured that and it
/// is false here: the transit route lookup is not VRF-isolated (it uses the
/// default table unless a PBR term overrides it), so a flow that ingresses on
/// a routing-instance member interface and egresses out of the default
/// instance is a working configuration whose REPLY resolves a different
/// domain. Keying the reverse-match index on the forward domain blackholes
/// every such flow's replies.
///
///   * SAME-DIRECTION transforms preserve: they name another key of the same
///     direction, or navigate between the two halves of one flow.
///   * REVERSE-MATCH transforms zero: they build the index a REPLY is looked
///     up under, and the reply's domain is spent on a preference instead
///     (`find_forward_nat_match`), not on the bucket key.
#[test]
fn key_transforms_split_same_direction_preserve_from_reverse_match_zero_7160() {
    const DOMAIN: u32 = 0xABCD_1234;
    let mut key = key_v4();
    key.routing_domain = DOMAIN;
    let nat = decision().nat;

    let same_direction: [(&str, SessionKey); 3] = [
        ("forward_wire_key", super::key::forward_wire_key(&key, nat)),
        (
            "translated_session_key",
            super::key::translated_session_key(&key, nat),
        ),
        (
            "reverse_session_key",
            super::key::reverse_session_key(&key, nat),
        ),
    ];
    for (name, derived) in same_direction {
        assert_eq!(
            derived.routing_domain, DOMAIN,
            "{name} dropped the routing domain ({:#x} -> {:#x}). It names \
             another key of the SAME direction (or the flow's other half), so \
             a derived key in domain 0 would collide with the default instance \
             on that path.",
            DOMAIN, derived.routing_domain
        );
    }

    let reverse_match: [(&str, SessionKey); 2] = [
        ("reverse_wire_key", super::key::reverse_wire_key(&key, nat)),
        (
            "reverse_canonical_key",
            super::key::reverse_canonical_key(&key, nat),
        ),
    ];
    for (name, derived) in reverse_match {
        assert_eq!(
            derived.routing_domain, 0,
            "{name} carried the forward domain ({:#x}) onto a REVERSE-MATCH \
             key. That key is the bucket a REPLY is looked up under, and this \
             dataplane routes transit traffic in the DEFAULT table unless a PBR \
             term overrides it — so a flow whose egress leaves its routing \
             instance has a reply that resolves another domain and would now \
             find no bucket at all. That is a forwarding outage, not a \
             hardening; the isolation lives in find_forward_nat_match's \
             two-pass preference.",
            DOMAIN
        );
    }

    // And the zeroing must be a REWRITE, not a wholesale loss of identity: the
    // rest of the reverse key still has to be the reverse of this flow.
    let rev = super::key::reverse_wire_key(&key, nat);
    assert_eq!(rev.src_ip, key.dst_ip);
    assert_eq!(rev.dst_ip, key.src_ip);
}

/// The behavioural consequence at the LOOKUP layer, which is the layer that
/// decides which tenant's cached decision a reply inherits.
///
/// Two tenants, identical 5-tuples, contained in their own routing instances
/// (their replies arrive on interfaces in the same instance, so each reply
/// resolves its own domain). Both forward sessions land in ONE reverse bucket,
/// because the reverse-match index is domain-agnostic by construction. The
/// two-pass preference is the only thing that demuxes them.
///
/// FAIL-ON-REVERT: delete the preference in `find_forward_nat_match` and this
/// goes red — bucket order is install order, so tenant B's reply would take
/// tenant A's session and inherit its egress, NAT and policy decision.
#[test]
fn each_contained_tenants_reply_resolves_its_own_session_7160() {
    const DOMAIN_A: u32 = 0x0001_86A1;
    const DOMAIN_B: u32 = 0x0001_86A2;
    let mut table = SessionTable::new();
    let nat = decision().nat;

    let mut tenant_a = key_v4();
    tenant_a.routing_domain = DOMAIN_A;
    let mut tenant_b = key_v4();
    tenant_b.routing_domain = DOMAIN_B;

    assert!(table.install_with_protocol(
        tenant_a.clone(),
        decision(),
        metadata(),
        1_000,
        PROTO_TCP,
        TCP_SYN,
    ));
    assert!(table.install_with_protocol(
        tenant_b.clone(),
        decision(),
        metadata(),
        1_000,
        PROTO_TCP,
        TCP_SYN,
    ));

    // The reply each tenant's own interface produces: the reverse tuple, in
    // that tenant's domain.
    let mut reply_a = super::key::reverse_wire_key(&tenant_a, nat);
    reply_a.routing_domain = DOMAIN_A;
    let mut reply_b = reply_a.clone();
    reply_b.routing_domain = DOMAIN_B;

    let matched_a = table
        .find_forward_nat_match(&reply_a)
        .expect("tenant A's reply found no session at all — the domain-agnostic \
                 reverse bucket is not being probed");
    assert_eq!(
        matched_a.key.routing_domain, DOMAIN_A,
        "tenant A's reply resolved a session in domain {:#x} instead of its own \
         {:#x}. The reply now inherits another tenant's cached egress, NAT and \
         policy decision on the return path.",
        matched_a.key.routing_domain, DOMAIN_A
    );

    let matched_b = table
        .find_forward_nat_match(&reply_b)
        .expect("tenant B's reply found no session at all");
    assert_eq!(
        matched_b.key.routing_domain, DOMAIN_B,
        "tenant B's reply resolved a session in domain {:#x} instead of its own \
         {:#x}",
        matched_b.key.routing_domain, DOMAIN_B
    );
}

/// The regression this design exists to avoid, stated as a cell.
///
/// A flow that ingresses on a routing-instance member interface and egresses
/// out of the DEFAULT instance is a real, working configuration — this
/// dataplane's transit route lookup is not VRF-isolated, so the reply comes
/// back on a default-instance interface and resolves domain 0. Its session was
/// installed in the ingress interface's domain. If the reverse-match index
/// carried that domain, this reply would find nothing, the reverse direction
/// would be adjudicated as a new flow from the wrong zone pair, and the flow
/// would break outright.
///
/// FAIL-ON-REVERT: make `reverse_wire_key` / `reverse_canonical_key` preserve
/// the domain again and this goes red.
#[test]
fn a_reply_from_outside_the_flows_domain_still_resolves_its_session_7160() {
    const DOMAIN: u32 = 0x0001_86A3;
    let mut table = SessionTable::new();
    let nat = decision().nat;

    let mut forward = key_v4();
    forward.routing_domain = DOMAIN;
    assert!(table.install_with_protocol(
        forward.clone(),
        decision(),
        metadata(),
        1_000,
        PROTO_TCP,
        TCP_SYN,
    ));

    // The reply arrives on a default-instance interface: domain 0, not DOMAIN.
    let mut reply = super::key::reverse_wire_key(&forward, nat);
    reply.routing_domain = 0;

    let matched = table.find_forward_nat_match(&reply).expect(
        "a reply arriving in the default instance found no session for a flow \
         that ingressed in a routing instance. This dataplane routes transit \
         traffic in the DEFAULT table unless a PBR term overrides it, so this \
         is not an exotic shape — it is what an interface-bound routing \
         instance with no PBR does today, and this miss breaks the flow.",
    );
    assert_eq!(matched.key.routing_domain, DOMAIN);
    assert_eq!(matched.key, forward);
}

/// The NAT'd twin of the cell above, and it is not redundant with it.
///
/// With no NAT, `reverse_wire_key` and `reverse_canonical_key` produce the SAME
/// tuple, so the index carries one bucket that either transform's zeroing is
/// enough to place at domain 0 — and a revert of just ONE of them leaves that
/// cell green. Measured: reverting `reverse_wire_key` alone did exactly that.
/// Under NAT the two transforms produce DIFFERENT tuples, the reply arrives on
/// the WIRE tuple, and only `reverse_wire_key`'s zeroing puts that bucket where
/// the reply can find it.
///
/// FAIL-ON-REVERT: make `reverse_wire_key` preserve the domain and this goes
/// red on its own, without needing `reverse_canonical_key` reverted too.
#[test]
fn a_natted_reply_from_outside_the_flows_domain_still_resolves_its_session_7160() {
    const DOMAIN: u32 = 0x0001_86A5;
    let mut table = SessionTable::new();

    // Source NAT: the reply comes back addressed to the POOL tuple, which is
    // what `reverse_wire_key` names and `reverse_canonical_key` does not.
    let mut decision = decision();
    decision.nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 80, 41))),
        rewrite_src_port: Some(40001),
        ..NatDecision::default()
    };
    let nat = decision.nat;

    let mut forward = key_v4();
    forward.routing_domain = DOMAIN;
    assert_ne!(
        super::key::reverse_wire_key(&forward, nat),
        super::key::reverse_canonical_key(&forward, nat),
        "the fixture must NAT — with the two reverse transforms producing one \
         tuple this cell cannot distinguish which of them zeroes the domain"
    );
    assert!(table.install_with_protocol(
        forward.clone(),
        decision,
        metadata(),
        1_000,
        PROTO_TCP,
        TCP_SYN,
    ));

    // The reply the SERVER sends: addressed to the pool tuple, arriving on a
    // default-instance interface.
    let mut reply = super::key::reverse_wire_key(&forward, nat);
    reply.routing_domain = 0;

    let matched = table.find_forward_nat_match(&reply).expect(
        "a NAT'd reply arriving in the default instance found no session for a \
         flow that ingressed in a routing instance — the reverse WIRE bucket is \
         keyed on the forward domain, so the pool tuple the server actually \
         replies to is unreachable and the flow breaks",
    );
    assert_eq!(matched.key, forward);
}

/// A single-instance deployment must be bit-identical to pre-#7160: every key
/// is domain 0, so the preference pass accepts exactly what the fallback would
/// and the reverse bucket walk is unchanged.
#[test]
fn a_default_instance_reply_resolves_exactly_as_before_7160() {
    let mut table = SessionTable::new();
    let nat = decision().nat;

    let forward = key_v4();
    assert_eq!(forward.routing_domain, 0);
    assert!(table.install_with_protocol(
        forward.clone(),
        decision(),
        metadata(),
        1_000,
        PROTO_TCP,
        TCP_SYN,
    ));

    let reply = super::key::reverse_wire_key(&forward, nat);
    assert_eq!(reply.routing_domain, 0);
    let matched = table
        .find_forward_nat_match(&reply)
        .expect("the default-instance reply must still resolve its session");
    assert_eq!(matched.key, forward);
}

/// `reverse_match_key` is the ONE name for the domain-agnostic convention, so
/// the index side and the probe side cannot drift. It must be identity on a
/// domain-0 key (so a single-instance deployment allocates nothing extra) and
/// must change ONLY the domain otherwise.
#[test]
fn reverse_match_key_zeroes_only_the_domain_7160() {
    let plain = key_v4();
    assert_eq!(
        super::key::reverse_match_key(&plain),
        plain,
        "a domain-0 key must come back unchanged"
    );

    let mut scoped = key_v4();
    scoped.routing_domain = 0x0001_86A4;
    let probed = super::key::reverse_match_key(&scoped);
    assert_eq!(probed.routing_domain, 0);
    let mut expected = scoped.clone();
    expected.routing_domain = 0;
    assert_eq!(
        probed, expected,
        "reverse_match_key changed something other than the routing domain"
    );
}

// #7919: the by-key lookup-miss counters, and the property that matters is
// that they SEPARATE the three causes rather than reporting one number.
//
// The issue's own instruction, after three retired discriminators: "establish
// WHICH, because they need different fixes and the cheap one is wrong half the
// time." A single `lookup_miss` total would satisfy "we added instrumentation"
// while leaving exactly that question open, so each cause is asserted to move
// its OWN counter and to leave the other two alone.
//
// Both `touch_if_stale` and `account_packet` are driven, because they resolve
// through different functions (`record_by_key` vs `record_by_key_mut`) and a
// miss in one but not the other would be a materially different story than a
// miss in both — which is what the cluster measurement actually observed
// (`idle ~= age` on every frozen row means BOTH missed).
#[test]
fn lookup_miss_counters_separate_the_three_causes_7919() {
    let mut table = SessionTable::new();
    let key = key_v6();
    let install_ns = 1_000_000_000u64;
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        install_ns,
        PROTO_UDP,
        0
    ));

    // CONTROL FIRST. A hit must move NOTHING — without this the assertions
    // below pass for a counter that increments on every lookup.
    table.touch_if_stale(&key, install_ns + 1);
    table.account_packet(&key, 100, 0, 0);
    assert_eq!(
        table.lookup_miss_counts(),
        (0, 0, 0),
        "a session that RESOLVES must not count as a miss; a counter that moves \
         here measures traffic, not failure"
    );

    // CAUSE 1: no handle in the index at all — a key never installed.
    let mut absent = key_v6();
    absent.src_port = absent.src_port.wrapping_add(1);
    table.touch_if_stale(&absent, install_ns + 2);
    let (nh, sh, km) = table.lookup_miss_counts();
    assert_eq!(
        (nh, sh, km),
        (1, 0, 0),
        "an uninstalled key must count as no-handle and nothing else"
    );

    // The SAME cause through the &mut resolver, which is the one
    // `account_packet` uses. Both must count, or a frozen-counters-but-live-
    // idle-timer split would be invisible.
    table.account_packet(&absent, 100, 0, 0);
    assert_eq!(
        table.lookup_miss_counts(),
        (2, 0, 0),
        "account_packet resolves through record_by_key_mut and must count the \
         same cause; counting only the shared-ref path would hide exactly the \
         asymmetry #7919 used to diagnose this"
    );

    // CAUSE 2: a handle that outlived its record — resolves, but points past
    // the slab. Unreachable through the public API, which is why it needs the
    // seam and why it is worth counting at all.
    let mut stale = key_v6();
    stale.src_port = stale.src_port.wrapping_add(2);
    table.debug_force_handle(&stale, u32::MAX);
    table.touch_if_stale(&stale, install_ns + 3);
    assert_eq!(
        table.lookup_miss_counts(),
        (2, 1, 0),
        "a handle pointing past the slab must count as stale-handle ONLY — if \
         this lands on no-handle the two causes are indistinguishable and the \
         counters answer nothing"
    );

    // CAUSE 3: a handle resolving to a LIVE record whose stored key differs.
    // The index and the slab disagree; the lookup finds a session and
    // correctly refuses to account against it.
    let installed_handle = table
        .debug_handle_for_key(&key)
        .expect("the installed session must have a handle");
    let mut aliased = key_v6();
    aliased.src_port = aliased.src_port.wrapping_add(3);
    table.debug_force_handle(&aliased, installed_handle);
    table.account_packet(&aliased, 100, 0, 0);
    assert_eq!(
        table.lookup_miss_counts(),
        (2, 1, 1),
        "a handle resolving to a record with a DIFFERENT key must count as \
         key-mismatch ONLY. This is the cause that means the index and the slab \
         disagree, which is a different bug from either sibling"
    );

    // The installed session must still be intact — none of the misses above,
    // including the one that resolved ONTO its handle, may have disturbed it.
    assert!(
        table.entry_by_key(&key).is_some(),
        "the installed session must survive a miss on a different key"
    );
    assert_eq!(
        table.entry_by_key(&key).unwrap().last_seen_ns,
        install_ns,
        "the aliased lookup landed ON this record's handle and must not have          touched or accounted against it"
    );
}

// #7919: the read that backs the per-session counter query must distinguish
// "I hold this session and it carries no traffic" from "I do not hold it".
//
// Those are the two states the whole verb exists to separate, and they are the
// same zero at the call site if the accessor returns bare counters. `None` vs
// `Some(zeroed)` is what keeps them apart.
#[test]
fn counters_with_replica_flag_separates_not_held_from_held_and_idle_7919() {
    let mut table = SessionTable::new();
    let held = key_v4();
    let mut absent = key_v4();
    absent.src_port = held.src_port.wrapping_add(1);

    assert!(table.install_with_protocol(
        held.clone(),
        decision(),
        metadata(),
        1_000_000_000,
        PROTO_TCP,
        0x10,
    ));

    // HELD AND IDLE: present, counters zero.
    let (counters, replica) = table
        .counters_with_replica_flag(&held)
        .expect("a held session must be reported as held even with no traffic");
    assert_eq!(
        (counters.fwd_packets, counters.rev_packets),
        (0, 0),
        "a freshly installed session has no volume yet"
    );
    assert!(!replica, "a locally installed session is not a replica");

    // NOT HELD: absent entirely. This is the state that must NOT look like the
    // one above.
    assert!(
        table.counters_with_replica_flag(&absent).is_none(),
        "a key this table does not hold must report None, not a zeroed row — \
         collapsing them answers neither of the questions the query asks"
    );

    // And once traffic is accounted, the held row carries it.
    for _ in 0..321u32 {
        table.account_packet(&held, 1500, 0x10, 0);
    }
    let (counters, _) = table
        .counters_with_replica_flag(&held)
        .expect("still held after accounting");
    assert_eq!(
        counters.fwd_packets, 321,
        "the accessor must report the LIVE counters, not a snapshot from install"
    );
}
