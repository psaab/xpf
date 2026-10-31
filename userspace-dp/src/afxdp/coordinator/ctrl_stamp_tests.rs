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
/// owns byte-for-byte as read. RED if the write rebuilds the row or touches
/// any other field.
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
    coord.grant_ctrl_stamp(DEADLINE);
    assert!(bump_to(&mut coord, 6));
    coord.revoke_ctrl_stamp_grant();
    assert_eq!(row.update_count(), 1);
    assert_eq!(row.get().fib_generation, 6, "the row carries the generation just published");
    assert_eq!(row.get().config_generation, 11);
    assert_eq!(coord.ctrl_stamp_counters(), (1, 0, 0));

    // A republish that does not change the stamp (neighbor push, fabric
    // refresh) writes nothing even inside a grant.
    coord.grant_ctrl_stamp(DEADLINE);
    coord.republish_runtime_validation();
    coord.revoke_ctrl_stamp_grant();
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
    coord.grant_ctrl_stamp(DEADLINE);
    assert!(bump_to(&mut coord, 5));
    coord.revoke_ctrl_stamp_grant();
    assert_eq!(row.get(), stale);
    assert_eq!(coord.ctrl_stamp_counters(), (0, 1, 0));
}
