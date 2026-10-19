// #9168 — the kernel RX counters must have a PRODUCER, not just a consumer.
// #15285 — `rx_ring_full` joins them: it must not be discarded by the publisher.
//
// `kernel_rx_dropped` and `kernel_rx_invalid_descs` were plumbed end to end
// (atomic -> snapshot -> wire -> Go decode -> `Kernel RX dropped:` in
// `pkg/monitoriface/monitor.go`) and never written. The worker sampled
// `statistics_v2()` once per second per binding and stored one of its six
// counters. `show` / `monitor` therefore reported a permanent hard 0.
// A CONSUMER TEST CANNOT SEE THIS. The pre-existing #802 cell
// (`ring_pressure_counters_round_trip_through_snapshot`) stores a value into
// the atomic itself and asserts the snapshot carries it — it is green whether
// or not anything in production ever stores. So the cells here are
// producer-side, and one of them binds the CALL SITE rather than the function:
// a package's own cells can prove `publish_kernel_xdp_statistics` behaves and
// say nothing about whether the worker loop calls it.

use super::kernel_stats::UNPLUMBED_KERNEL_STAT_FIELDS;
use super::BindingLiveState;
use crate::xsk_ffi::XdpStatisticsV2;

const PUBLISHER_SRC: &str = include_str!("kernel_stats.rs");
const XSK_FFI_SRC: &str = include_str!("../../xsk_ffi.rs");
const WORKER_LOOP_SRC: &str = include_str!("../worker/loop_body/mod.rs");

/// Drop `//` comment tails so a guard over the worker loop counts CODE.
///
/// Written after the first run of `worker_loop_hands_the_whole_sample_to_the_publisher_9168`
/// reported three `statistics_v2()` occurrences where there is one call: the
/// other two are the prose in the doc comments that explain this very fix. A
/// text guard that counts its own explanation is measuring the comment, and it
/// would have gone the other way just as easily — deleting the call while
/// leaving a comment mentioning it would have kept the count at 1.
///
/// Crude on purpose: it does not understand `//` inside a string or a block
/// comment. The `line_comments_are_stripped_and_code_is_not_9168` cell below
/// pins what it does and does not do, so the crudeness is a stated property
/// rather than an assumption.
fn code_only(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The declared field list of `pub struct XdpStatisticsV2`, in source order.
fn xdp_statistics_v2_fields() -> Vec<String> {
    let start = XSK_FFI_SRC
        .find("pub struct XdpStatisticsV2 {")
        .expect("XdpStatisticsV2 must still be declared in xsk_ffi.rs");
    let body = &XSK_FFI_SRC[start..];
    let end = body.find('}').expect("struct body must terminate");
    let mut out = Vec::new();
    for line in body[..end].lines().skip(1) {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once(':') else {
            continue;
        };
        out.push(name.trim().to_string());
    }
    assert!(
        out.len() >= 6,
        "parser found only {} fields on XdpStatisticsV2 — the FIXTURE is broken, \
         not the code. A field list this guard cannot read would let it pass \
         vacuously (#9168). Parsed: {out:?}",
        out.len(),
    );
    out
}

/// The `let XdpStatisticsV2 { .. } = stats;` destructure, split into the names
/// BOUND to a local (which must be published) and the names dropped with `_`
/// (which must be declared unplumbed).
fn destructured_names() -> (Vec<String>, Vec<String>) {
    let start = PUBLISHER_SRC
        .find("let XdpStatisticsV2 {")
        .expect("the publisher must still destructure the whole struct");
    let body = &PUBLISHER_SRC[start..];
    let end = body.find("} = stats;").expect("destructure must terminate");
    let mut bound = Vec::new();
    let mut dropped = Vec::new();
    for line in body[..end].lines().skip(1) {
        let line = line.trim().trim_end_matches(',');
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_suffix(": _") {
            dropped.push(name.trim().to_string());
        } else {
            bound.push(line.to_string());
        }
    }
    (bound, dropped)
}

/// THE PRODUCER CELL. Every plumbed field must arrive in its OWN atomic.
///
/// Distinct primes per field, so a cross-wire (rx_dropped landing in
/// `kernel_rx_invalid_descs`) fails rather than passing on equal values — the
/// shape that makes a "the fields round-trip" assertion vacuous.
///
/// FAIL-ON-REVERT: this is red on master, where nothing writes either atomic.
#[test]
fn publish_kernel_xdp_statistics_writes_every_plumbed_atom_9168() {
    use std::sync::atomic::Ordering;
    let live = BindingLiveState::new();
    assert_eq!(
        live.kernel_rx_dropped.load(Ordering::Relaxed),
        0,
        "setup: a fresh binding starts at zero, so a passing assertion below \
         cannot be the initial value",
    );

    live.publish_kernel_xdp_statistics(XdpStatisticsV2 {
        rx_dropped: 101,
        rx_invalid_descs: 103,
        tx_invalid_descs: 107,
        rx_ring_full: 109,
        rx_fill_ring_empty_descs: 113,
        tx_ring_empty_descs: 127,
    });

    let snap = live.snapshot();
    assert_eq!(
        snap.kernel_rx_dropped, 101,
        "the kernel's RX drop count must reach the atomic the `Kernel RX \
         dropped:` line reads; a permanent 0 there is the healthy value on the \
         instrument that would reveal a NIC dropping every packet (#9168)",
    );
    assert_eq!(
        snap.kernel_rx_invalid_descs, 103,
        "the kernel's invalid-descriptor count must reach its own atom (#9168)",
    );
    assert_eq!(
        snap.kernel_rx_ring_full, 109,
        "the kernel's RX ring-full count must reach its own atom per binding/queue; \
         discarding it made 'Kernel RX dropped: 0' unable to establish zero \
         ring-full loss (#15285)",
    );
    assert_eq!(
        snap.rx_fill_ring_empty_descs, 113,
        "#802's counter must keep working through the shared publisher",
    );

    // A SECOND sample must REPLACE, not accumulate: kernel XDP statistics are
    // absolute per socket, so a `fetch_add` here would report a running total
    // of running totals.
    live.publish_kernel_xdp_statistics(XdpStatisticsV2 {
        rx_dropped: 200,
        rx_invalid_descs: 201,
        rx_ring_full: 203,
        rx_fill_ring_empty_descs: 202,
        ..XdpStatisticsV2::default()
    });
    let snap = live.snapshot();
    assert_eq!(
        (
            snap.kernel_rx_dropped,
            snap.kernel_rx_invalid_descs,
            snap.kernel_rx_ring_full,
            snap.rx_fill_ring_empty_descs
        ),
        (200, 201, 203, 202),
        "kernel statistics are ABSOLUTE — publish must store(), not fetch_add()",
    );
}

/// COMPLETENESS. Every field the kernel struct declares is either published or
/// DECLARED unplumbed. This is the issue's own acceptance: the defect was a
/// field with a complete consumer and no producer, and the remedy has to be
/// something a future field cannot slip past.
///
/// Two halves, and both are needed:
///   - the exhaustive `let XdpStatisticsV2 { .. }` binding makes a NEW field a
///     compile error (checked here by comparing the parsed field list against
///     the parsed destructure, so this cell also fails if someone replaces the
///     destructure with `..`);
///   - every BOUND name must actually be stored, and every `_`-dropped name
///     must appear in `UNPLUMBED_KERNEL_STAT_FIELDS`. Binding a field and then
///     not storing it is exactly the original defect one layer in.
#[test]
fn every_kernel_statistic_is_published_or_declared_unplumbed_9168() {
    let fields = xdp_statistics_v2_fields();
    let (bound, dropped) = destructured_names();

    let mut seen: Vec<String> = bound.iter().chain(dropped.iter()).cloned().collect();
    seen.sort();
    let mut want = fields.clone();
    want.sort();
    assert_eq!(
        seen, want,
        "the publisher's destructure must name EVERY field of XdpStatisticsV2 — \
         a `..` rest pattern or a stale list is how a field reaches the wire \
         unwritten (#9168)",
    );

    for name in &bound {
        let store = format!(".store({name}, Ordering::Relaxed)");
        assert!(
            PUBLISHER_SRC.contains(&store),
            "`{name}` is bound out of the kernel statistics and then never \
             stored — that is the #9168 defect itself, one layer in",
        );
    }

    let mut dropped_sorted = dropped.clone();
    dropped_sorted.sort();
    let mut declared: Vec<String> = UNPLUMBED_KERNEL_STAT_FIELDS
        .iter()
        .map(|s| s.to_string())
        .collect();
    declared.sort();
    assert_eq!(
        dropped_sorted, declared,
        "every kernel statistic dropped by the publisher must be DECLARED in \
         UNPLUMBED_KERNEL_STAT_FIELDS with the reason in its doc comment. \
         Silently dropping one reads as a decision somebody made (#9168)",
    );
}

/// WIRING BIND. The worker loop must hand the WHOLE sample to the publisher.
///
/// The cells above prove `publish_kernel_xdp_statistics` behaves. They say
/// nothing about what its caller passes, and the original defect lived
/// entirely in the caller: it sampled all six counters and stored one. So this
/// cell reads the sample site.
///
/// Three assertions, each keyed to a way the site can regress:
///   - the sample happens exactly once, so a second unpublished sampler cannot
///     appear beside it;
///   - the sample is handed to the publisher (severing this is the mutation
///     that a publisher-only test cannot see);
///   - the worker loop stores no `stats.` field itself — the shape the defect
///     had, and the shape a "quick fix" would take.
#[test]
fn worker_loop_hands_the_whole_sample_to_the_publisher_9168() {
    let worker_loop = code_only(WORKER_LOOP_SRC);
    assert_eq!(
        worker_loop.matches("statistics_v2()").count(),
        1,
        "the worker loop must sample kernel XDP statistics exactly once; a \
         second sampler would be a second chance to discard them (#9168)",
    );
    assert_eq!(
        worker_loop
            .matches("b.live.publish_kernel_xdp_statistics(stats);")
            .count(),
        1,
        "the sampled `XdpStatisticsV2` must be handed to the publisher. \
         Severing this call leaves every producer-side cell green and restores \
         the permanent hard 0 the operator sees (#9168)",
    );
    assert_eq!(
        worker_loop.matches(".store(stats.").count(),
        0,
        "the worker loop must not store kernel statistic fields itself — that \
         is the partial-publish shape #9168 removed, and it is exactly what a \
         later one-counter fix would reintroduce",
    );
}

/// FIXTURE CONTROL for `code_only`.
///
/// The guard above is only as good as its comment stripper, and a stripper
/// that removed too much would silently delete the very call it is checking
/// for — leaving the count at 0 and reading as a severed call site, or
/// (if the assertion were `>= 0`) as a pass. Both directions are pinned here.
#[test]
fn line_comments_are_stripped_and_code_is_not_9168() {
    assert_eq!(code_only("// statistics_v2()").trim(), "");
    assert_eq!(
        code_only("    let x = f(); // statistics_v2()").trim(),
        "let x = f();",
    );
    assert_eq!(
        code_only("    if let Ok(stats) = b.xsk.device.statistics_v2() {").trim(),
        "if let Ok(stats) = b.xsk.device.statistics_v2() {",
    );
    // And the real subject: the worker loop mentions `statistics_v2()` three
    // times and CALLS it once. If this ever reads 1 without stripping, the
    // stripper has stopped being load-bearing and the cell above is weaker
    // than its message claims.
    assert!(
        WORKER_LOOP_SRC.matches("statistics_v2()").count()
            > code_only(WORKER_LOOP_SRC).matches("statistics_v2()").count(),
        "the raw worker-loop text must still OVERCOUNT the call relative to the \
         stripped text — that difference is the whole reason `code_only` exists. \
         If it ever reaches zero the stripper has stopped being load-bearing and \
         the guard above is weaker than its message claims",
    );
}
