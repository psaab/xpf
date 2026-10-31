//! #18560 cells for the helper-side `userspace_ctrl` stamp advance.

use super::super::*;
use super::*;

const LEAVING: CtrlStamp = CtrlStamp {
    config_generation: 11,
    fib_generation: 4,
};
const ENTERING: CtrlStamp = CtrlStamp {
    config_generation: 14,
    fib_generation: 5,
};
const NOW: u64 = 1_000_000_000_000;
const DEADLINE: u64 = NOW + 200_000_000;

/// A steady-state row Go wrote: enabled, current metadata version, every
/// Go-owned field set to something distinctive, stamped with `stamp`.
fn steady_row(stamp: CtrlStamp) -> UserspaceCtrlValue {
    UserspaceCtrlValue {
        enabled: 1,
        metadata_version: EXPECTED_CTRL_METADATA_VERSION,
        workers: 6,
        queue_count: 6,
        flags: 0x15,
        wg_port_count: 2,
        wg_ports: [51820, 51821, 0, 0, 0, 0, 0, 0],
        config_generation: stamp.config_generation,
        fib_generation: stamp.fib_generation,
        heartbeat_timeout_ms: 1500,
    }
}

struct FailingIo {
    fail_lookup: bool,
    value: UserspaceCtrlValue,
}

impl CtrlMapIo for FailingIo {
    fn lookup(&mut self) -> std::io::Result<UserspaceCtrlValue> {
        if self.fail_lookup {
            Err(std::io::Error::from_raw_os_error(libc::ENOENT))
        } else {
            Ok(self.value)
        }
    }
    fn update(&mut self, _value: &UserspaceCtrlValue) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(libc::EPERM))
    }
}

fn advance_on(row: &SharedCtrlRow, deadline: u64, now: u64) -> CtrlStampOutcome {
    let mut io = row.clone();
    let mut clock = || now;
    advance_ctrl_stamp(&mut io, LEAVING, ENTERING, deadline, &mut clock)
}

/// The advance writes exactly the two stamp fields and leaves every field Go
/// owns byte-for-byte as read. RED if the write changes any field other than
/// the stamp (a rebuild that happens to reproduce the same bytes is an
/// equivalent mutant this cell cannot see).
#[test]
fn advance_rewrites_only_the_stamp_18560() {
    let row = SharedCtrlRow::default();
    *row.value.lock().expect("row") = steady_row(LEAVING);
    assert_eq!(advance_on(&row, DEADLINE, NOW), CtrlStampOutcome::Advanced);
    let mut want = steady_row(LEAVING);
    want.config_generation = ENTERING.config_generation;
    want.fib_generation = ENTERING.fib_generation;
    assert_eq!(row.get(), want);
    assert_eq!(row.update_count(), 1);
}

/// Every decline writes nothing. A disabled row (Go fail-closed, bootstrap,
/// plan change, link cycle, teardown) is never touched, so the helper can
/// never re-enable ctrl; a foreign stamp or metadata version is left to Go.
#[test]
fn declines_never_write_18560() {
    let mut disabled = steady_row(LEAVING);
    disabled.enabled = 0;
    let mut old_version = steady_row(LEAVING);
    old_version.metadata_version = EXPECTED_CTRL_METADATA_VERSION + 1;
    let foreign = steady_row(CtrlStamp {
        config_generation: 10,
        fib_generation: 4,
    });
    for (value, want) in [
        (disabled, CtrlStampOutcome::DeclinedDisabled),
        (old_version, CtrlStampOutcome::DeclinedVersion),
        (foreign, CtrlStampOutcome::DeclinedForeignStamp),
    ] {
        let row = SharedCtrlRow::default();
        *row.value.lock().expect("row") = value;
        assert_eq!(advance_on(&row, DEADLINE, NOW), want, "{value:?}");
        assert_eq!(row.get(), value, "a {want:?} decline wrote the row");
        assert_eq!(row.update_count(), 0);
    }
}

/// No grant, an expired grant, and a grant inside the margin all decline
/// before the read. RED if the margin or the zero-grant guard is dropped.
#[test]
fn grant_deadline_and_margin_are_enforced_18560() {
    for (deadline, now) in [
        (0, NOW),
        (NOW, NOW),
        (NOW + CTRL_STAMP_DEADLINE_MARGIN_NS, NOW),
        (NOW - 1, NOW),
    ] {
        let row = SharedCtrlRow::default();
        *row.value.lock().expect("row") = steady_row(LEAVING);
        assert_eq!(
            advance_on(&row, deadline, now),
            CtrlStampOutcome::DeclinedDeadline,
            "deadline={deadline} now={now}"
        );
        assert_eq!(row.update_count(), 0);
    }
    assert!(ctrl_stamp_grant_open(NOW, NOW + CTRL_STAMP_DEADLINE_MARGIN_NS + 1));
}

/// The deadline is re-checked between the read and the write: a grant that
/// expires while the read is in flight writes nothing. RED if only the
/// pre-read check remains.
#[test]
fn grant_rechecked_before_the_write_18560() {
    let row = SharedCtrlRow::default();
    *row.value.lock().expect("row") = steady_row(LEAVING);
    let mut io = row.clone();
    let mut calls = 0u32;
    let mut clock = || {
        calls += 1;
        if calls == 1 { NOW } else { DEADLINE }
    };
    assert_eq!(
        advance_ctrl_stamp(&mut io, LEAVING, ENTERING, DEADLINE, &mut clock),
        CtrlStampOutcome::DeclinedDeadline
    );
    assert_eq!(row.update_count(), 0);
}

#[test]
fn map_errors_are_reported_18560() {
    let mut lookup_fails = FailingIo {
        fail_lookup: true,
        value: steady_row(LEAVING),
    };
    let mut clock = || NOW;
    assert_eq!(
        advance_ctrl_stamp(&mut lookup_fails, LEAVING, ENTERING, DEADLINE, &mut clock),
        CtrlStampOutcome::Error
    );
    let mut update_fails = FailingIo {
        fail_lookup: false,
        value: steady_row(LEAVING),
    };
    assert_eq!(
        advance_ctrl_stamp(&mut update_fails, LEAVING, ENTERING, DEADLINE, &mut clock),
        CtrlStampOutcome::Error
    );
}

/// The mirror must match the shim's `UserspaceCtrl` field for field: a
/// reordered or retyped shim field would make the helper write the stamp into
/// a Go-owned field. Read from the shim source, as the #9888 reason-table
/// agreement does.
#[test]
fn ctrl_stamp_mirror_matches_shim_struct_18560() {
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("userspace-xdp/src/lib.rs");
    let src = std::fs::read_to_string(&lib).expect("read shim lib.rs");
    let start = src.find("struct UserspaceCtrl {").expect("shim UserspaceCtrl");
    let body = &src[start..];
    let end = body.find("\n}").expect("end of UserspaceCtrl");
    let fields: Vec<(String, String)> = body[..end]
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|line| {
            let (name, ty) = line.trim_end_matches(',').split_once(':').expect("field line");
            (name.trim().to_string(), ty.trim().to_string())
        })
        .collect();
    let want: Vec<(&str, &str)> = vec![
        ("enabled", "u32"),
        ("metadata_version", "u32"),
        ("workers", "u32"),
        ("queue_count", "u32"),
        ("flags", "u32"),
        ("wg_port_count", "u32"),
        ("wg_ports", "[u16; WG_STEERED_PORT_SET_MAX]"),
        ("config_generation", "u64"),
        ("fib_generation", "u32"),
        ("heartbeat_timeout_ms", "u32"),
    ];
    let got: Vec<(&str, &str)> = fields.iter().map(|(n, t)| (n.as_str(), t.as_str())).collect();
    assert_eq!(got, want, "shim UserspaceCtrl drifted from the helper mirror");
    let wg = std::fs::read_to_string(lib.with_file_name("wg_classify.rs")).expect("read shim wg_classify.rs");
    assert!(
        wg.contains("pub const WG_STEERED_PORT_SET_MAX: usize = 8;"),
        "the mirror's wg_ports length (8) must match the shim's WG_STEERED_PORT_SET_MAX"
    );
}

fn coordinator_with_published(stamp: CtrlStamp) -> Coordinator {
    let mut coord = Coordinator::new();
    coord.seed_published_validation(ValidationState {
        snapshot_installed: true,
        config_generation: stamp.config_generation,
        fib_generation: stamp.fib_generation,
        neighbor_generation: 0,
    });
    coord
}

fn bump_to(coord: &mut Coordinator, fib_generation: u32) -> bool {
    let snapshot = crate::ConfigSnapshot {
        fib_generation,
        ..crate::ConfigSnapshot::default()
    };
    coord.bump_fib_generation_with_snapshot(&snapshot)
}

/// Wiring: a validation change published inside a grant advances the row
/// from the generation the workers left, right at the view store; outside a
/// grant nothing is written. RED if `store_runtime_view` stops calling the
/// advance, or calls it without the grant.
#[test]
fn view_store_advances_the_stamp_only_inside_a_grant_18560() {
    let mut coord = coordinator_with_published(LEAVING);
    let row = coord.install_ctrl_stamp_test_row(steady_row(LEAVING));
    coord.ctrl_stamp.test_now_ns = Some(NOW);

    // No grant: the publish lands, the row is untouched.
    assert!(bump_to(&mut coord, 5));
    assert_eq!(row.update_count(), 0, "a publish outside a grant wrote the ctrl row");
    assert_eq!(coord.ctrl_stamp_counters(), (0, 0, 0));

    // Go caught up (wrote 11/5 from the reply), then grants the next bump.
    *row.value.lock().expect("row") = steady_row(CtrlStamp {
        config_generation: 11,
        fib_generation: 5,
    });
    let grant = coord.open_ctrl_stamp_grant(DEADLINE, "test-pin");
    assert!(bump_to(&mut coord, 6));
    drop(grant);
    assert_eq!(row.update_count(), 1);
    assert_eq!(row.get().fib_generation, 6, "the row carries the generation just published");
    assert_eq!(row.get().config_generation, 11);
    assert_eq!(coord.ctrl_stamp_counters(), (1, 0, 0));

    // A republish that does not change the stamp (neighbor push, fabric
    // refresh) writes nothing even inside a grant.
    let grant = coord.open_ctrl_stamp_grant(DEADLINE, "test-pin");
    coord.republish_runtime_validation();
    drop(grant);
    assert_eq!(row.update_count(), 1);
}

/// A row Go left behind (its stamp is not the generation the workers just
/// left) is declined and counted, not overwritten.
#[test]
fn view_store_declines_a_row_go_has_not_caught_up_18560() {
    let mut coord = coordinator_with_published(LEAVING);
    let stale = steady_row(CtrlStamp {
        config_generation: 9,
        fib_generation: 4,
    });
    let row = coord.install_ctrl_stamp_test_row(stale);
    coord.ctrl_stamp.test_now_ns = Some(NOW);
    let grant = coord.open_ctrl_stamp_grant(DEADLINE, "test-pin");
    assert!(bump_to(&mut coord, 5));
    drop(grant);
    assert_eq!(row.get(), stale);
    assert_eq!(coord.ctrl_stamp_counters(), (0, 1, 0));
}

/// A failed clock read (`monotonic_nanos` returns 0) never opens a grant.
#[test]
fn zero_clock_never_opens_a_grant_18560() {
    assert!(!ctrl_stamp_grant_open(0, DEADLINE));
    let row = SharedCtrlRow::default();
    *row.value.lock().expect("row") = steady_row(LEAVING);
    assert_eq!(advance_on(&row, DEADLINE, 0), CtrlStampOutcome::DeclinedDeadline);
    assert_eq!(row.update_count(), 0);
}

/// A write that completes after the deadline is reported as late (the stated
/// residual), not as an advance. RED if the post-write check is dropped.
#[test]
fn write_completing_after_the_deadline_is_reported_late_18560() {
    let row = SharedCtrlRow::default();
    *row.value.lock().expect("row") = steady_row(LEAVING);
    let mut io = row.clone();
    let mut calls = 0u32;
    let mut clock = || {
        calls += 1;
        if calls <= 2 { NOW } else { DEADLINE }
    };
    assert_eq!(
        advance_ctrl_stamp(&mut io, LEAVING, ENTERING, DEADLINE, &mut clock),
        CtrlStampOutcome::LateWrite
    );
    let mut state = CtrlStampState::default();
    state.record(CtrlStampOutcome::LateWrite, LEAVING, ENTERING);
    assert_eq!((state.advances, state.declines, state.errors), (0, 0, 1));
}

/// The grant guard revokes the grant when dropped, including by unwinding.
#[test]
fn grant_guard_revokes_on_unwind_18560() {
    let coord = coordinator_with_published(LEAVING);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _grant = coord.open_ctrl_stamp_grant(DEADLINE, "test-pin");
        assert!(coord.ctrl_stamp_grant_for_test().is_some());
        panic!("handler unwinds");
    }));
    assert!(result.is_err());
    assert_eq!(coord.ctrl_stamp_grant_for_test(), None, "an unwinding handler left the grant open");
    // A zero deadline from Go opens nothing.
    let _none = coord.open_ctrl_stamp_grant(0, "test-pin");
    assert_eq!(coord.ctrl_stamp_grant_for_test(), None);
}

/// A row whose write records the view the workers can see at that moment.
struct ViewCheckingRow {
    reader: crate::afxdp::types::RuntimeViewReader,
    row: SharedCtrlRow,
    seen: std::sync::Arc<std::sync::Mutex<Option<CtrlStamp>>>,
}

impl CtrlMapIo for ViewCheckingRow {
    fn lookup(&mut self) -> std::io::Result<UserspaceCtrlValue> {
        self.row.lookup()
    }
    fn update(&mut self, value: &UserspaceCtrlValue) -> std::io::Result<()> {
        let v = self.reader.load().validation();
        *self.seen.lock().expect("seen") = Some(CtrlStamp {
            config_generation: v.config_generation,
            fib_generation: v.fib_generation,
        });
        self.row.update(value)
    }
}

/// Seat W: the advance runs AFTER the view store. When the row is written the
/// workers' channel already carries the entering generation, so the shim is
/// never told about a generation no worker can hold. RED if the advance moves
/// before `publish` (the write would see the leaving view).
#[test]
fn ctrl_row_is_written_after_the_view_is_published_18560() {
    let mut coord = coordinator_with_published(LEAVING);
    let row = SharedCtrlRow::default();
    *row.value.lock().expect("row") = steady_row(LEAVING);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    coord.ctrl_stamp.test_io = Some(Box::new(ViewCheckingRow {
        reader: coord.ha.runtime.reader(),
        row: row.clone(),
        seen: std::sync::Arc::clone(&seen),
    }));
    coord.ctrl_stamp.test_now_ns = Some(NOW);
    let grant = coord.open_ctrl_stamp_grant(DEADLINE, "test-pin");
    assert!(bump_to(&mut coord, 5));
    drop(grant);
    assert_eq!(row.update_count(), 1, "premise: the granted bump wrote the row");
    assert_eq!(
        *seen.lock().expect("seen"),
        Some(CtrlStamp {
            config_generation: LEAVING.config_generation,
            fib_generation: 5,
        }),
        "the row was written before the workers could see the generation it stamps"
    );
}
