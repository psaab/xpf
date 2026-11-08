//! #18780: one expiry call must do bounded work, however large the cohort
//! that crosses in one wheel tick.
//!
//! The live failure: RG activation (`RefreshOwnerRGS` ->
//! `refresh_for_ha_transition`) re-stamps every HA-managed row to the
//! activation instant T0. With UDP's 60 s window the whole table therefore
//! crosses in ONE tick at T0+60 (SELF-HEAL) and again at T0+120 (AGE).
//! `expire_stale_entries_ha` drained every due bucket in a single call, so
//! one `worker_loop` iteration did the whole table's classification, reap
//! and teardown, the worker heartbeat froze for ~11 s, the #18704 watchdog
//! moved the RGs, and the peer repeated it 120 s later (a ~135 s RG loop).
//!
//! The contract these cells pin:
//! 1. Per call, at most `EXPIRY_PASS_MAX_REAPS` rows are reaped and at most
//!    `EXPIRY_PASS_MAX_POPS` wheel hints are examined, independent of N.
//! 2. A budget-cut pass sets the backlog flag; the NEXT call (the next loop
//!    iteration, not the next 1 s GC tick) resumes the cursor, so the last
//!    row of a cohort of C rows due in one tick is reaped within
//!    `ceil(C / MAX_REAPS)` consecutive calls (stale hints ahead of it add
//!    `ceil(hints / MAX_POPS)`).
//! 3. Classification is unchanged: every row still SELF-HEALs once and then
//!    AGEs, and no row is reaped before its window.
//! 4. Node-level served evidence (`ExpireHaContext::node_served`, a
//!    shared-map lock per call) is computed only where the retention arm can
//!    use it: TCP, not closing, companion-eligible. A crossed UDP row never
//!    probes it.
//!
//! Time is simulated (explicit `now_ns`), never the wall clock (#8218).

use super::tests::{decision, metadata};
use super::*;
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr};

const SEC: u64 = 1_000_000_000;
const MS: u64 = 1_000_000;
const US: u64 = 1_000;

fn udp_key(i: u32) -> SessionKey {
    SessionKey {
        addr_family: 2,
        protocol: crate::ip_proto::PROTO_UDP,
        src_ip: IpAddr::V4(Ipv4Addr::from(0x0a40_0000u32 + i)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 211)),
        src_port: 40_000,
        dst_port: 9,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// Install flow `i` as both halves (the shape a one-packet UDP burst leaves
/// on every worker table) with `origin`. Returns both keys.
fn install_udp_pair(
    table: &mut SessionTable,
    i: u32,
    now_ns: u64,
    origin: SessionOrigin,
) -> [SessionKey; 2] {
    let forward = udp_key(i);
    let reverse = reverse_session_key(&forward, crate::nat::NatDecision::default());
    let mut md = metadata();
    assert!(table.install_with_protocol_with_origin(
        forward.clone(),
        decision(),
        md.clone(),
        origin,
        now_ns,
        crate::ip_proto::PROTO_UDP,
        0,
    ));
    md.is_reverse = true;
    assert!(table.install_with_protocol_with_origin(
        reverse.clone(),
        decision(),
        md,
        origin,
        now_ns,
        crate::ip_proto::PROTO_UDP,
        0,
    ));
    [forward, reverse]
}

fn ha_ctx<'a>(
    node_served: &'a dyn Fn(&SessionKey) -> NodeServedEvidence,
    forwards: &'a dyn Fn(i32) -> bool,
    epoch: &'a dyn Fn(i32) -> u32,
) -> ExpireHaContext<'a> {
    ExpireHaContext {
        node_active: true,
        forwards_rg: forwards,
        epoch_of: epoch,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served,
    }
}

#[derive(Default, Debug)]
struct Drive {
    max_scanned: usize,
    max_expired: usize,
    total_expired: usize,
    total_healed: usize,
    first_expiry_ns: Option<u64>,
    last_expiry_ns: Option<u64>,
}

/// Call the expiry pass every `step` from `from` to `to`, as the worker loop
/// does (most calls are gated by the 1 s interval; a backlog continues on the
/// next call), recording the per-call maxima.
fn drive(
    table: &mut SessionTable,
    ha: &ExpireHaContext<'_>,
    from: u64,
    to: u64,
    step: u64,
) -> Drive {
    let mut d = Drive::default();
    let mut now = from;
    while now <= to {
        let expired = table.expire_stale_entries_ha(now, Some(ha));
        let stats = table.last_pop_stats();
        d.max_scanned = d.max_scanned.max(stats.scanned);
        d.max_expired = d.max_expired.max(expired.len());
        d.total_expired += expired.len();
        d.total_healed += stats.healed_on_promote;
        if !expired.is_empty() {
            d.first_expiry_ns.get_or_insert(now);
            d.last_expiry_ns = Some(now);
        }
        now += step;
    }
    d
}

/// THE #18780 SHAPE, at two populations a factor of 4 apart: N peer-synced
/// UDP flows (2N rows) all re-stamped by one activation, then left idle. The
/// whole table crosses at T0+60 (SELF-HEAL) and again at T0+120 (AGE).
/// Per-call work must be the same constant at both populations, and the
/// node-served probe (a shared-map lock) must never run for these rows.
/// RED on master: one call healed and one call reaped all 2N rows, and every
/// crossed row probed `node_served` once.
#[test]
fn aligned_activation_cohort_per_call_work_is_bounded_18780() {
    let mut per_population = Vec::new();
    for flows in [2_048u32, 8_192] {
        let t0 = 1_000 * SEC;
        let activation = t0 + 5 * SEC;
        let mut table = SessionTable::new();
        let mut keys = Vec::with_capacity(2 * flows as usize);
        for i in 0..flows {
            keys.extend(install_udp_pair(&mut table, i, t0, SessionOrigin::SyncImport));
        }
        let rows = keys.len();
        assert_eq!(table.len(), rows, "premise: every half installed");
        let window = table.entry_by_key(&keys[0]).expect("row").expires_after_ns;
        assert_eq!(window, 60 * SEC, "premise: UDP default window");
        // RefreshOwnerRGS's write-site: every HA-managed row re-stamped to T0.
        for key in &keys {
            let md = table.entry_by_key(key).expect("row").metadata.clone();
            assert!(table.refresh_for_ha_transition(key, decision(), md, activation));
        }
        let probes = Cell::new(0u64);
        let node_served = |_: &SessionKey| {
            probes.set(probes.get() + 1);
            NodeServedEvidence::default()
        };
        let forwards = |_: i32| true;
        // The activation bumped the RG epoch; refresh recorded epoch 0.
        let epoch = |_: i32| 1u32;
        let ha = ha_ctx(&node_served, &forwards, &epoch);
        let d = drive(&mut table, &ha, activation, activation + 125 * SEC, 10 * MS);
        assert_eq!(d.total_healed, rows, "premise: every row SELF-HEALs once at T0+60");
        assert_eq!(d.total_expired, rows, "premise: every row AGEs at T0+120");
        assert_eq!(table.len(), 0, "premise: the cohort fully drained");
        assert!(
            d.max_scanned <= EXPIRY_PASS_MAX_POPS,
            "#18780: one call examined {} wheel hints at N={} rows (cap {})",
            d.max_scanned,
            rows,
            EXPIRY_PASS_MAX_POPS
        );
        assert!(
            d.max_expired <= EXPIRY_PASS_MAX_REAPS,
            "#18780: one call reaped {} rows at N={} rows (cap {})",
            d.max_expired,
            rows,
            EXPIRY_PASS_MAX_REAPS
        );
        assert_eq!(
            probes.get(),
            0,
            "#18780: {} crossed UDP rows probed node-served evidence (a shared-map lock each)",
            probes.get()
        );
        // Classification unchanged: no row reaped before its second window,
        // and the budget drains the cohort within ceil(2N / MAX_REAPS) calls
        // of 10 ms after the tick that first sees it crossed.
        let first = d.first_expiry_ns.expect("expiries");
        let last = d.last_expiry_ns.expect("expiries");
        assert!(
            first > activation + 2 * window,
            "#18780: a row was reaped {} ns before its second window",
            activation + 2 * window - first
        );
        let drain_calls = (rows as u64).div_ceil(EXPIRY_PASS_MAX_REAPS as u64);
        assert!(
            last <= first + drain_calls * 10 * MS,
            "#18780: the cohort's last row was reaped {} ms after its first (bound {} calls)",
            (last - first) / MS,
            drain_calls
        );
        per_population.push((rows, d.max_scanned, d.max_expired));
    }
    // Independence from N: the 4x population costs the same per call.
    assert_eq!(
        (per_population[0].1, per_population[0].2),
        (per_population[1].1, per_population[1].2),
        "#18780: per-call work must not grow with N: {per_population:?}"
    );
}

/// The expiry LAG bound. C idle local UDP rows plus one sentinel installed
/// LAST (so it sits at the back of the same bucket) cross in one tick. Under
/// the budget the sentinel is reaped on call `ceil((C+1) / MAX_REAPS)` of
/// consecutive calls 1 us apart: the backlog flag bypasses the 1 s interval
/// gate, so the extra delay is (calls - 1) worker-loop iterations, not
/// seconds. Every call reaps exactly `min(MAX_REAPS, remaining)`.
/// RED on master: the first call reaped all C+1 rows.
#[test]
fn reap_budget_lag_for_the_last_row_is_bounded_18780() {
    let t0 = 1_000 * SEC;
    let cohort = 1_000u32;
    let mut table = SessionTable::new();
    for i in 0..cohort {
        install_udp_pair(&mut table, i, t0, SessionOrigin::ForwardFlow);
    }
    let sentinel = install_udp_pair(&mut table, cohort, t0, SessionOrigin::ForwardFlow);
    let rows = table.len();
    assert_eq!(rows, 2 * (cohort as usize + 1), "premise: every half installed");
    // Prime the gate and the cursor, then step to the first call that sees
    // the cohort crossed (strict `>`: t0 + 60 s is still live).
    let _ = table.expire_stale_entries(t0);
    let _ = table.expire_stale_entries(t0 + 60 * SEC);
    assert_eq!(table.len(), rows, "premise: nothing crossed at exactly the window");
    let first_ns = t0 + 61 * SEC;
    let bound = (rows as u64).div_ceil(EXPIRY_PASS_MAX_REAPS as u64);
    let mut sentinel_call = None;
    let mut remaining = rows;
    for call in 1..=bound + 2 {
        let now = first_ns + (call - 1) * US;
        let expired = table.expire_stale_entries(now);
        assert_eq!(
            expired.len(),
            remaining.min(EXPIRY_PASS_MAX_REAPS),
            "#18780: call {call} must reap min(cap, remaining)"
        );
        remaining -= expired.len();
        if remaining > 0 {
            assert!(
                table.expiry_backlog(),
                "#18780: a budget-cut call must leave the backlog flag set (call {call})"
            );
        }
        if sentinel_call.is_none() && sentinel.iter().all(|k| table.entry_by_key(k).is_none()) {
            sentinel_call = Some(call);
        }
    }
    assert_eq!(remaining, 0, "the whole cohort reaps");
    assert!(!table.expiry_backlog(), "a drained wheel clears the backlog flag");
    let sentinel_call = sentinel_call.expect("sentinel reaped");
    assert!(
        sentinel_call <= bound,
        "#18780: the last row was reaped on call {sentinel_call}; bound ceil({rows}/{}) = {bound}",
        EXPIRY_PASS_MAX_REAPS
    );
}

/// A continuation call is not a fresh pass: it must not move `last_gc_ns`.
/// Cohort A (more than one call's reaps) is due at tick X; its drain runs a
/// fresh call at X+1.0 s and a continuation at X+1.9 s. Row B is due one tick
/// later, so the first call that may reap it is the fresh pass at X+2.0 s —
/// exactly 1 s after the previous FRESH pass. Were the continuation to
/// re-stamp `last_gc_ns`, that pass would be gated until X+2.9 s.
#[test]
fn continuation_does_not_shift_the_gc_cadence_18780() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let cohort = (EXPIRY_PASS_MAX_REAPS / 2 + 1) as u32;
    for i in 0..cohort {
        install_udp_pair(&mut table, i, t0, SessionOrigin::ForwardFlow);
    }
    let late = install_udp_pair(&mut table, cohort, t0 + SEC, SessionOrigin::ForwardFlow);
    let _ = table.expire_stale_entries(t0);
    // X = t0 + 60 s is the cohort's deadline tick; it is processed from X+1 s.
    let x = t0 + 60 * SEC;
    let first = table.expire_stale_entries(x + SEC);
    assert_eq!(first.len(), EXPIRY_PASS_MAX_REAPS, "premise: the cohort exceeds one call");
    assert!(table.expiry_backlog(), "premise: a backlog remains");
    let second = table.expire_stale_entries(x + SEC + 900 * MS);
    assert_eq!(
        first.len() + second.len(),
        2 * cohort as usize,
        "premise: the continuation finishes cohort A"
    );
    assert!(late.iter().all(|k| table.entry_by_key(k).is_some()), "premise: B not yet due");
    let third = table.expire_stale_entries(x + 2 * SEC);
    assert_eq!(
        third.len(),
        2,
        "#18780: the fresh pass 1 s after the previous FRESH pass must reap row B \
         (a continuation must not re-stamp the GC interval)"
    );
}

/// The POP half of the budget. A bucket holds more stale wheel hints than one
/// call may examine, ahead of one dead row. The cursor must not stall: the
/// hints drain at `MAX_POPS` per call and the dead row is reaped within
/// `ceil((hints + 1) / MAX_POPS)` calls. Stale hints come from removed rows,
/// whose hints the wheel drops lazily (`dropped_gone`).
#[test]
fn pop_budget_drains_stale_hints_without_stalling_18780() {
    let t0 = 1_000 * SEC;
    let hints = (EXPIRY_PASS_MAX_POPS + EXPIRY_PASS_MAX_POPS / 2) as u32;
    let mut table = SessionTable::new();
    let mut removed = Vec::with_capacity(hints as usize);
    for i in 0..hints {
        removed.push(udp_key(i));
        let md = metadata();
        assert!(table.install_with_protocol_with_origin(
            udp_key(i),
            decision(),
            md,
            SessionOrigin::ForwardFlow,
            t0,
            crate::ip_proto::PROTO_UDP,
            0,
        ));
    }
    let dead = udp_key(hints);
    assert!(table.install_with_protocol_with_origin(
        dead.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        t0,
        crate::ip_proto::PROTO_UDP,
        0,
    ));
    for key in &removed {
        assert!(table.remove_entry(key, RemovalKind::Terminal).is_some());
    }
    let _ = table.expire_stale_entries(t0);
    let first_ns = t0 + 61 * SEC;
    let bound = (u64::from(hints) + 1).div_ceil(EXPIRY_PASS_MAX_POPS as u64);
    let mut reaped_on = None;
    for call in 1..=bound + 2 {
        let expired = table.expire_stale_entries(first_ns + (call - 1) * US);
        assert!(
            table.last_pop_stats().scanned <= EXPIRY_PASS_MAX_POPS,
            "#18780: call {call} examined {} hints",
            table.last_pop_stats().scanned
        );
        if expired.iter().any(|e| e.key == dead) {
            reaped_on = Some(call);
        }
    }
    let reaped_on = reaped_on.expect("the dead row behind the stale hints is reaped");
    assert!(
        reaped_on <= bound,
        "#18780: the dead row was reaped on call {reaped_on}; bound {bound}"
    );
    assert!(table.entry_by_key(&dead).is_none());
}

/// The pop budget must never LIVELOCK on future hints. In steady state the
/// bucket at the cursor collects one far-future hint (cursor + 256) per
/// active long-timeout flow touched in the second since the last pass,
/// because `target_tick_for` clamps to 255 ticks ahead of `now`. A pass
/// rotates those to the back. A continuation that re-snapshotted the whole
/// bucket would re-rotate them every call and, with more than
/// `EXPIRY_PASS_MAX_POPS` of them, never leave the bucket — the cursor would
/// stop and nothing after it would ever expire. Row E, due one tick later,
/// must still be reaped on the next fresh pass.
#[test]
fn pop_budget_never_livelocks_on_future_hints_18780() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let dead = install_udp_pair(&mut table, 0, t0, SessionOrigin::ForwardFlow);
    let later = install_udp_pair(&mut table, 1, t0 + SEC, SessionOrigin::ForwardFlow);
    let _ = table.expire_stale_entries(t0);
    // Fresh passes each second until the cursor sits on D's deadline tick X.
    let x = t0 + 60 * SEC;
    let mut now = t0;
    while now < x {
        now += SEC;
        let _ = table.expire_stale_entries(now);
    }
    assert!(dead.iter().all(|k| table.entry_by_key(k).is_some()), "premise: D still due");
    // In second X+1, before its GC pass: 2 x MAX_POPS long-timeout rows are
    // installed; each hint targets (X+1)+255 = X+256, the cursor's bucket.
    let hints = 2 * EXPIRY_PASS_MAX_POPS as u32;
    let install_ns = x + SEC + 100 * MS;
    // New installs only: D and E keep their 60 s window.
    table.set_timeouts(SessionTimeouts::from_seconds(0, 1_000, 0));
    for i in 0..hints {
        assert!(table.install_with_protocol_with_origin(
            udp_key(1_000 + i),
            decision(),
            metadata(),
            SessionOrigin::ForwardFlow,
            install_ns,
            crate::ip_proto::PROTO_UDP,
            0,
        ));
    }
    assert_eq!(
        table.entry_by_key(&udp_key(1_000)).expect("long").expires_after_ns,
        1_000 * SEC,
        "premise: long-timeout rows (clamped to the far edge of the wheel)"
    );
    let pass_ns = x + SEC + 200 * MS;
    let first = table.expire_stale_entries(pass_ns);
    assert_eq!(first.len(), 2, "premise: D reaps on the first pass");
    let mut continuations = 0u64;
    while table.expiry_backlog() {
        continuations += 1;
        assert!(
            continuations <= u64::from(hints).div_ceil(EXPIRY_PASS_MAX_POPS as u64),
            "#18780: the cursor never left a bucket of {hints} future hints (livelock)"
        );
        let _ = table.expire_stale_entries(pass_ns + continuations * US);
    }
    let next = table.expire_stale_entries(x + 2 * SEC + 200 * MS);
    let mut reaped = next.len();
    let mut more = 0;
    while table.expiry_backlog() && more < 4 {
        more += 1;
        reaped += table.expire_stale_entries(x + 2 * SEC + 200 * MS + more * US).len();
    }
    assert!(
        later.iter().all(|k| table.entry_by_key(k).is_none()),
        "#18780: row E (due one tick after the future-hint bucket) was not reaped; reaped {reaped}"
    );
    assert_eq!(table.len(), hints as usize, "only the live long-timeout rows remain");
}

/// Lazy evidence, negative half: crossed UDP rows AGE (the activation edge is
/// already spent, epoch matches) and never call `node_served`, whose
/// production closure locks the node-global shared-session map. The decision
/// is unchanged (every row reaps on its own window; #18722's
/// `pair_exception_non_tcp_never_takes_the_arm_18722` pins that node evidence
/// cannot keep a UDP row). RED on master: one probe per crossed row.
#[test]
fn crossed_udp_rows_never_probe_node_served_evidence_18780() {
    let t0 = 1_000 * SEC;
    let flows = 64u32;
    let mut table = SessionTable::new();
    for i in 0..flows {
        install_udp_pair(&mut table, i, t0, SessionOrigin::SyncImport);
    }
    let probes = Cell::new(0u64);
    let node_served = |_: &SessionKey| {
        probes.set(probes.get() + 1);
        NodeServedEvidence::default()
    };
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_ctx(&node_served, &forwards, &epoch);
    let d = drive(&mut table, &ha, t0, t0 + 62 * SEC, 100 * MS);
    assert_eq!(d.total_expired, 2 * flows as usize, "premise: the UDP rows AGE");
    assert_eq!(d.total_healed, 0, "premise: no activation edge");
    assert_eq!(
        probes.get(),
        0,
        "#18780: crossed UDP rows probed node-served evidence {} times",
        probes.get()
    );
}

/// Lazy evidence, the two other arms of the precondition: a CLOSING TCP row
/// (FIN seen) and a companion-INELIGIBLE deliberate reap (the
/// `AgedOwnerRgZeroActiveNode` arm: peer-synced, owner RG 0, node active)
/// both reap without probing `node_served` — `opening_companion_keeps_alive`
/// returns false for the first and is never called for the second. RED on
/// master: one probe per crossed row in each case.
#[test]
fn closing_and_deliberate_reaps_never_probe_node_served_evidence_18780() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let closing = super::tests::key_v4();
    let mut rg_zero = super::tests::key_v4();
    rg_zero.src_port = 23_456;
    assert!(table.install_with_protocol_with_origin(
        closing.clone(),
        decision(),
        metadata(),
        SessionOrigin::SyncImport,
        t0,
        crate::ip_proto::PROTO_TCP,
        crate::tcp_flags::TCP_FIN | crate::tcp_flags::TCP_ACK,
    ));
    let mut md = metadata();
    md.owner_rg_id = 0;
    assert!(table.install_with_protocol_with_origin(
        rg_zero.clone(),
        decision(),
        md,
        SessionOrigin::SyncImport,
        t0,
        crate::ip_proto::PROTO_TCP,
        crate::tcp_flags::TCP_SYN,
    ));
    assert!(table.entry_by_key(&closing).expect("closing").closing, "premise: closing row");
    assert!(!table.entry_by_key(&rg_zero).expect("rg0").closing, "premise: open row");
    let probes = Cell::new(0u64);
    let node_served = |_: &SessionKey| {
        probes.set(probes.get() + 1);
        NodeServedEvidence::default()
    };
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_ctx(&node_served, &forwards, &epoch);
    let mut aged_rg_zero = 0usize;
    let mut now = t0;
    while table.len() > 0 && now < t0 + 4_000 * SEC {
        now += SEC;
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        aged_rg_zero += table.last_pop_stats().aged_owner_rg_zero_active_node;
    }
    assert_eq!(table.len(), 0, "premise: both rows reap");
    assert_eq!(aged_rg_zero, 1, "premise: the owner-RG-0 row took the deliberate arm");
    assert_eq!(
        probes.get(),
        0,
        "#18780: closing / companion-ineligible reaps probed node-served evidence {} times",
        probes.get()
    );
}

/// Lazy evidence, positive half (the gate must not be over-broad): a crossed
/// OPENING TCP replica whose serving pair keeps forwarding still probes
/// `node_served` and is still KEPT by the node-level arm (#16223/#18722).
#[test]
fn crossed_opening_tcp_replica_still_probes_and_is_kept_18780() {
    let t0 = 1_000 * SEC;
    let mut table = SessionTable::new();
    let forward = super::tests::key_v4();
    let reverse = super::tests::install_forward_reverse_pair(
        &mut table,
        &forward,
        t0,
        crate::tcp_flags::TCP_SYN,
    );
    let window = table.entry_by_key(&forward).expect("forward").expires_after_ns;
    let probes = Cell::new(0u64);
    let served = Cell::new(10u64);
    let node_served = |_: &SessionKey| {
        probes.set(probes.get() + 1);
        NodeServedEvidence {
            handshake_wire: TcpHandshakeState::Established.to_wire(),
            shared_established: true,
            shared_served: Some(served.get()),
            ..NodeServedEvidence::default()
        }
    };
    let forwards = |_: i32| true;
    let epoch = |_: i32| 0u32;
    let ha = ha_ctx(&node_served, &forwards, &epoch);
    let mut kept = 0usize;
    let mut now = t0;
    while now < t0 + 3 * window {
        now += SEC;
        if (now - t0) % (10 * SEC) == 0 {
            served.set(served.get() + 25);
        }
        let _ = table.expire_stale_entries_ha(now, Some(&ha));
        kept += table.last_pop_stats().kept_alive_by_companion;
    }
    assert!(probes.get() > 0, "#18780: a crossed opening TCP replica must still probe");
    assert!(kept > 0, "#18780: and the node-level arm must still keep it");
    assert!(
        table.entry_by_key(&forward).is_some() && table.entry_by_key(&reverse).is_some(),
        "#16223: a replica whose serving pair keeps forwarding survives"
    );
}
