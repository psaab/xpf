//! #8121 part 2: the `export_idle_leases` / `import_idle_leases` control verbs.
//!
//! The wire form is strings for addresses and a REMAINING lifetime, never an
//! absolute deadline — see `IdleLeaseWire` and part 1's module header for why
//! each of those is node-local and cannot be carried.
//!
//! Conversion refuses rather than defaults. An address that does not parse
//! yields no record: a `0.0.0.0` fallback would be a plausible-looking address
//! that the receiver could resolve to a real pool slot, which is how a
//! malformed record becomes a wrong binding instead of a dropped one.

use super::super::ServerState;
use crate::ControlResponse;
use crate::afxdp::{IdleLeaseImportCounts, PoolDisplayLease, PoolIdleLease};
use crate::nat::IdleLeaseRecord;
use crate::protocol::{DisplayLeaseWire, IdleLeaseWire};
use std::net::IpAddr;

/// Whether an idle-lease import batch is worth a journald line.
///
/// ONE line per BATCH, never per record: this runs on every peer push, and a
/// per-record log on a bulk window is exactly the control-socket noise the
/// logging rules exist to prevent. So the predicate has to choose which
/// outcomes are worth a line at all, and it is extracted rather than inline
/// because that choice is the thing worth binding.
///
/// `skipped_existing` and `skipped_expired` are deliberately NOT notable. The
/// first is the ordinary steady state — the standby already rebuilt the lease
/// from a synced session — and the second is a lease that aged out in flight.
/// Logging either would put a line on every push.
///
/// #8573 ADDED `skipped_unknown_address`. It means the pool exists on this node
/// but does not contain the translated address the peer allocated from, i.e.
/// the two nodes disagree about the pool's address list. That is never normal,
/// and until #8573 it was also never logged: a batch in which EVERY lease was
/// refused for that reason emitted nothing, so the divergence was invisible.
/// That mattered less while the #1449 capability gate refused to forward
/// clustered persistent-NAT configs at all. #8573 removed that gate, on the
/// measurement that leases DO reach the standby — which makes the cases where
/// one does not the whole of the residual, and this line the operator's
/// surface for it.
fn idle_lease_import_is_notable(counts: &IdleLeaseImportCounts, malformed: u32) -> bool {
    counts.installed > 0
        || counts.skipped_port_busy > 0
        || counts.skipped_unknown_pool > 0
        || counts.skipped_unknown_address > 0
        || malformed > 0
}

fn to_wire(rec: &PoolIdleLease) -> IdleLeaseWire {
    let (remote_ip, remote_port) = match rec.lease.remote {
        Some((ip, port)) => (ip.to_string(), port),
        None => (String::new(), 0),
    };
    IdleLeaseWire {
        pool_name: rec.pool_name.clone(),
        protocol: rec.lease.protocol,
        src_ip: rec.lease.src_ip.to_string(),
        src_port: rec.lease.src_port,
        // #10018: scope is mandatory on the v25 control wire. It is emitted
        // even for domain 0 so a missing field remains distinguishable from
        // the real unscoped domain.
        routing_scope: Some(rec.lease.routing_scope),
        remote_ip,
        remote_port,
        translated_ip: rec.lease.translated_ip.to_string(),
        translated_port: rec.lease.translated_port,
        address_only: rec.lease.address_only,
        remaining_ns: rec.lease.remaining_ns,
        timeout_ns: rec.lease.timeout_ns,
    }
}

/// `None` when the record cannot be understood. The caller counts these rather
/// than substituting a default.
pub(super) fn from_wire(w: &IdleLeaseWire) -> Option<PoolIdleLease> {
    if w.pool_name.is_empty() || w.remaining_ns == 0 {
        return None;
    }
    // #10018: an old helper omits this field and serde maps that to `None`.
    // Refuse rather than defaulting to domain 0; otherwise a mixed helper
    // pair silently merges the record into the default tenant's lease.
    let routing_scope = w.routing_scope?;
    let src_ip: IpAddr = w.src_ip.parse().ok()?;
    let translated_ip: IpAddr = w.translated_ip.parse().ok()?;
    // An empty remote is `permit-any-remote-host`; a NON-empty one that does not
    // parse is a malformed record, NOT "any remote". Collapsing those two would
    // widen a lease's reuse scope on the standby — a different lease than the
    // active holds, wearing the same key.
    let remote = if w.remote_ip.is_empty() {
        None
    } else {
        Some((w.remote_ip.parse::<IpAddr>().ok()?, w.remote_port))
    };
    Some(PoolIdleLease {
        pool_name: w.pool_name.clone(),
        lease: IdleLeaseRecord {
            protocol: w.protocol,
            src_ip,
            src_port: w.src_port,
            routing_scope,
            remote,
            translated_ip,
            translated_port: w.translated_port,
            address_only: w.address_only,
            remaining_ns: w.remaining_ns,
            timeout_ns: w.timeout_ns,
        },
    })
}

pub(super) fn export(guard: &mut ServerState, response: &mut ControlResponse) {
    response.idle_leases = guard
        .afxdp
        .export_idle_persistent_leases_now()
        .iter()
        .map(to_wire)
        .collect();
}

pub(super) fn import(
    guard: &mut ServerState,
    wire: &[IdleLeaseWire],
    response: &mut ControlResponse,
) {
    let mut malformed = 0u32;
    let records: Vec<PoolIdleLease> = wire
        .iter()
        .filter_map(|w| {
            let parsed = from_wire(w);
            if parsed.is_none() {
                malformed += 1;
            }
            parsed
        })
        .collect();
    let counts = guard.afxdp.import_idle_persistent_leases_now(&records);
    if idle_lease_import_is_notable(&counts, malformed) {
        eprintln!(
            "xpf-dp: idle-lease import installed={} existing={} expired={} unknown_addr={} \
             unknown_pool={} port_busy={} malformed={}",
            counts.installed,
            counts.skipped_existing,
            counts.skipped_expired,
            counts.skipped_unknown_address,
            counts.skipped_unknown_pool,
            counts.skipped_port_busy,
            malformed,
        );
    }
    response.ok = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire() -> IdleLeaseWire {
        IdleLeaseWire {
            pool_name: "P".to_string(),
            protocol: 6,
            src_ip: "10.0.61.50".to_string(),
            src_port: 40000,
            routing_scope: Some(0),
            remote_ip: "8.8.8.8".to_string(),
            remote_port: 443,
            translated_ip: "203.0.113.1".to_string(),
            translated_port: 1024,
            address_only: false,
            remaining_ns: 5_000_000_000,
            timeout_ns: 300_000_000_000,
        }
    }

    /// #8573: which import outcomes earn a journald line.
    ///
    /// The table carries BOTH directions on purpose. A predicate that is simply
    /// `true` satisfies every notable row, and one that is `false` satisfies
    /// every quiet row; only having both can tell them apart.
    #[test]
    fn only_actionable_import_outcomes_are_logged_8573() {
        let zero = IdleLeaseImportCounts::default();

        for (label, counts, malformed) in [
            (
                "installed",
                IdleLeaseImportCounts {
                    installed: 1,
                    ..zero
                },
                0u32,
            ),
            (
                "unknown address — the nodes disagree about the pool's addresses",
                IdleLeaseImportCounts {
                    skipped_unknown_address: 1,
                    ..zero
                },
                0,
            ),
            (
                "unknown pool — the pool is missing here entirely",
                IdleLeaseImportCounts {
                    skipped_unknown_pool: 1,
                    ..zero
                },
                0,
            ),
            (
                "port busy — installing would duplicate a translated identity",
                IdleLeaseImportCounts {
                    skipped_port_busy: 1,
                    ..zero
                },
                0,
            ),
            ("malformed records", zero, 1),
        ] {
            assert!(
                idle_lease_import_is_notable(&counts, malformed),
                "#8573: a batch whose only outcome is {label} must be logged — it \
                 is the operator's only surface for a lease that did not reach \
                 this node, and after #8573 lifted the #1449 gate that is the \
                 whole of the residual"
            );
        }

        for (label, counts) in [
            (
                "already present — the steady state, rebuilt from a synced session",
                IdleLeaseImportCounts {
                    skipped_existing: 7,
                    ..zero
                },
            ),
            (
                "expired in flight",
                IdleLeaseImportCounts {
                    skipped_expired: 7,
                    ..zero
                },
            ),
        ] {
            assert!(
                !idle_lease_import_is_notable(&counts, 0),
                "a batch whose only outcome is {label} must stay QUIET — it \
                 happens on ordinary pushes, and a line here would be on every one"
            );
        }

        assert!(
            !idle_lease_import_is_notable(&zero, 0),
            "an empty batch must not log"
        );
    }

    /// Round trip: every field survives, so the wire form is not quietly
    /// dropping one that the receiver then defaults.
    #[test]
    fn idle_lease_wire_round_trips_8121() {
        let w = wire();
        let rec = from_wire(&w).expect("control: the well-formed record must parse");
        assert_eq!(to_wire(&rec), w);
    }

    /// `permit-any-remote-host` is an EMPTY remote, and it must survive as
    /// `None` rather than as an address.
    #[test]
    fn an_empty_remote_is_any_remote_host_8121() {
        let mut w = wire();
        w.remote_ip = String::new();
        w.remote_port = 0;
        let rec = from_wire(&w).expect("an any-remote lease is well-formed");
        assert_eq!(rec.lease.remote, None);
        assert_eq!(to_wire(&rec), w, "and it round-trips back to empty");
    }

    /// The discriminator that matters: a NON-EMPTY remote that does not parse is
    /// MALFORMED, not "any remote". Collapsing those two would widen a lease's
    /// reuse scope on the standby — a different lease than the active holds,
    /// wearing the same key — and it would do so silently, because the widened
    /// lease still works for the client that prompted it.
    #[test]
    fn a_malformed_remote_is_refused_not_widened_to_any_remote_8121() {
        let mut w = wire();
        w.remote_ip = "not-an-address".to_string();
        assert!(
            from_wire(&w).is_none(),
            "#8121: a malformed remote must be refused, never read as \
             permit-any-remote-host"
        );
        // CONTROL: the same record with a PARSEABLE remote is accepted, so the
        // refusal above is attributable to the remote and not to the fixture.
        w.remote_ip = "8.8.8.8".to_string();
        assert!(from_wire(&w).is_some());
    }

    /// Every other unusable field is refused rather than defaulted. A
    /// `0.0.0.0` fallback would be a plausible address the receiver could
    /// resolve to a real pool slot — a wrong binding instead of a dropped one.
    #[test]
    fn unusable_records_are_refused_rather_than_defaulted_8121() {
        for (label, mutate) in [
            (
                "empty pool",
                Box::new(|w: &mut IdleLeaseWire| w.pool_name.clear())
                    as Box<dyn Fn(&mut IdleLeaseWire)>,
            ),
            (
                "zero remaining",
                Box::new(|w: &mut IdleLeaseWire| w.remaining_ns = 0),
            ),
            (
                "bad src",
                Box::new(|w: &mut IdleLeaseWire| w.src_ip = "x".to_string()),
            ),
            (
                "bad translated",
                Box::new(|w: &mut IdleLeaseWire| w.translated_ip = "x".to_string()),
            ),
            (
                "missing routing scope",
                Box::new(|w: &mut IdleLeaseWire| w.routing_scope = None)
                    as Box<dyn Fn(&mut IdleLeaseWire)>,
            ),
        ] {
            let mut w = wire();
            // CONTROL: unmutated, this fixture parses — so each `None` below is
            // caused by the mutation and not by a broken base record.
            assert!(from_wire(&w).is_some(), "control for {label}");
            mutate(&mut w);
            assert!(from_wire(&w).is_none(), "{label} must be refused");
        }
    }
}

/// #8615: the DISPLAY export. One-way by construction — there is no
/// `from_wire` for this type and no import verb that accepts it, because the
/// record carries `active_flows` and design note 1 forbids that on anything a
/// peer can install.
fn to_display_wire(rec: &PoolDisplayLease) -> DisplayLeaseWire {
    let (remote_ip, remote_port) = match rec.lease.remote {
        Some((ip, port)) => (ip.to_string(), port),
        None => (String::new(), 0),
    };
    DisplayLeaseWire {
        pool_name: rec.pool_name.clone(),
        protocol: rec.lease.protocol,
        src_ip: rec.lease.src_ip.to_string(),
        src_port: rec.lease.src_port,
        routing_scope: Some(rec.lease.routing_scope),
        remote_ip,
        remote_port,
        translated_ip: rec.lease.translated_ip.to_string(),
        translated_port: rec.lease.translated_port,
        address_only: rec.lease.address_only,
        remaining_ns: rec.lease.remaining_ns,
        timeout_ns: rec.lease.timeout_ns,
        active_flows: rec.lease.active_flows,
    }
}

pub(super) fn export_display(guard: &mut ServerState, response: &mut ControlResponse) {
    response.display_leases = guard
        .afxdp
        .export_display_persistent_leases_now()
        .iter()
        .map(to_display_wire)
        .collect();
}
