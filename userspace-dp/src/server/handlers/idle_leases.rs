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
use crate::nat::{
    IdleLeaseRecord, MAX_PERSISTENT_NAT_LEASE_LIFETIME_NS, MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS,
};
use crate::protocol::{
    DisplayLeaseWire, IdleLeaseWire, LeaseExportRequest, PermittedRemoteWire,
    MAX_CONTROL_RESPONSE_BYTES, MAX_LEASE_EXPORT_PAGE,
};
use std::net::IpAddr;

/// #16589: byte budget for ONE lease-export page's serialized response.
/// Half the control cap leaves the response envelope and any future
/// additive fields ample room while keeping every page far under the
/// Go bounded reader's refusal point.
const LEASE_EXPORT_PAGE_BUDGET: usize = MAX_CONTROL_RESPONSE_BYTES / 2;

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
        || counts.skipped_identity_busy > 0
        || counts.skipped_clear_fenced > 0
        || counts.skipped_capacity > 0
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
        egress_scope: Some(rec.lease.egress_scope),
        remote_ip,
        remote_port,
        permit_any_remote: rec.lease.permit_any_remote,
        permitted_remotes: rec
            .lease
            .permitted_remotes
            .iter()
            .map(|(ip, port)| PermittedRemoteWire {
                ip: ip.to_string(),
                port: *port,
            })
            .collect(),
        translated_ip: rec.lease.translated_ip.to_string(),
        translated_port: rec.lease.translated_port,
        address_only: rec.lease.address_only,
        deterministic: rec.lease.deterministic,
        deterministic_mode: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(_)) => 1,
            Some(crate::nat::DeterministicPortedIdentity::V6(_)) => 2,
            None => 0,
        },
        deterministic_block_size: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(p)) => p.block_size,
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => p.block_size,
            None => 0,
        },
        deterministic_blocks_per_ip: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(p)) => p.blocks_per_ip,
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => p.blocks_per_ip,
            None => 0,
        },
        deterministic_host_prefix_len: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => p.host_prefix_len,
            _ => 0,
        },
        deterministic_host_base: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(p)) => {
                std::net::Ipv4Addr::from(p.host_base).to_string()
            }
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => {
                std::net::Ipv6Addr::from(p.host_base).to_string()
            }
            None => String::new(),
        },
        deterministic_host_count: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(p)) => p.host_count,
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => p.host_count,
            None => 0,
        },
        remaining_ns: rec.lease.remaining_ns,
        timeout_ns: rec.lease.timeout_ns,
    }
}

/// `None` when the record cannot be understood. The caller counts these rather
/// than substituting a default.
fn deterministic_identity_from_wire(
    w: &IdleLeaseWire,
) -> Option<Option<crate::nat::DeterministicPortedIdentity>> {
    if !w.deterministic {
        return Some(None);
    }
    match w.deterministic_mode {
        1 => {
            let base: std::net::Ipv4Addr = w.deterministic_host_base.parse().ok()?;
            Some(Some(crate::nat::DeterministicPortedIdentity::V4(
                crate::nat::DeterministicV4 {
                    block_size: w.deterministic_block_size,
                    blocks_per_ip: w.deterministic_blocks_per_ip,
                    host_base: u32::from(base),
                    host_count: w.deterministic_host_count,
                },
            )))
        }
        2 => {
            let base: std::net::Ipv6Addr = w.deterministic_host_base.parse().ok()?;
            Some(Some(crate::nat::DeterministicPortedIdentity::V6(
                crate::nat::DeterministicV6 {
                    block_size: w.deterministic_block_size,
                    blocks_per_ip: w.deterministic_blocks_per_ip,
                    host_prefix_len: w.deterministic_host_prefix_len,
                    host_base: base.octets(),
                    host_count: w.deterministic_host_count,
                },
            )))
        }
        _ => None,
    }
}
pub(super) fn from_wire(w: &IdleLeaseWire) -> Option<PoolIdleLease> {
    if w.pool_name.is_empty()
        || w.remaining_ns == 0
        || w.timeout_ns < MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS
    {
        return None;
    }
    // Address-only bindings preserve the source port. A mismatched peer value
    // is malformed rather than a different translated identity.
    if w.address_only && w.translated_port != w.src_port {
        return None;
    }
    // A release may re-arm expiry after the exporter samples `remaining_ns`;
    // clamp that honest skew, as well as peer values above the schema ceiling.
    let timeout_ns = w.timeout_ns.min(MAX_PERSISTENT_NAT_LEASE_LIFETIME_NS);
    let remaining_ns = w.remaining_ns.min(timeout_ns);
    // #10018: an old helper omits this field and serde maps that to `None`.
    // Refuse rather than defaulting to domain 0; otherwise a mixed helper
    // pair silently merges the record into the default tenant's lease.
    let routing_scope = w.routing_scope?;
    // #14322: same fail-closed rule as routing_scope — a pre-v50 helper
    // omits this field, and defaulting it to unscoped would merge egress
    // zones on the standby.
    let egress_scope = w.egress_scope?;
    let src_ip: IpAddr = w.src_ip.parse().ok()?;
    let translated_ip: IpAddr = w.translated_ip.parse().ok()?;
    // These legacy fields remain parse-validated for wire compatibility; the
    // endpoint-independent key and inbound admission use the permission set.
    let remote = if w.remote_ip.is_empty() {
        None
    } else {
        Some((w.remote_ip.parse::<IpAddr>().ok()?, w.remote_port))
    };
    let permitted_remotes = w
        .permitted_remotes
        .iter()
        .map(|remote| Some((remote.ip.parse::<IpAddr>().ok()?, remote.port)))
        .collect::<Option<Vec<_>>>()?;
    Some(PoolIdleLease {
        pool_name: w.pool_name.clone(),
        lease: IdleLeaseRecord {
            protocol: w.protocol,
            src_ip,
            src_port: w.src_port,
            routing_scope,
            egress_scope,
            remote,
            permit_any_remote: w.permit_any_remote,
            permitted_remotes,
            translated_ip,
            translated_port: w.translated_port,
            address_only: w.address_only,
            deterministic: w.deterministic,
            deterministic_identity: deterministic_identity_from_wire(w)?,
            remaining_ns,
            timeout_ns,
        },
    })
}

/// #16589: stable sort key for one exported lease. The allocator's
/// map iteration order is nondeterministic, so paging over the raw
/// order would skip/duplicate across pages. The key covers the full
/// wire identity (pool, protocol, source, scopes, translated,
/// remotes) so distinct wire rows never compare equal.
fn idle_lease_sort_key(w: &IdleLeaseWire) -> (String, u8, String, u16, u32, u32, String, u16, Vec<(String, u16)>, bool) {
    (
        w.pool_name.clone(),
        w.protocol,
        w.src_ip.clone(),
        w.src_port,
        w.routing_scope.unwrap_or(0),
        w.egress_scope.unwrap_or(0),
        w.translated_ip.clone(),
        w.translated_port,
        w.permitted_remotes
            .iter()
            .map(|r| (r.ip.clone(), r.port))
            .collect(),
        w.permit_any_remote,
    )
}

fn display_lease_sort_key(w: &DisplayLeaseWire) -> (String, u8, String, u16, u32, u32, String, u16, Vec<(String, u16)>, bool) {
    (
        w.pool_name.clone(),
        w.protocol,
        w.src_ip.clone(),
        w.src_port,
        w.routing_scope.unwrap_or(0),
        w.egress_scope.unwrap_or(0),
        w.translated_ip.clone(),
        w.translated_port,
        w.permitted_remotes
            .iter()
            .map(|r| (r.ip.clone(), r.port))
            .collect(),
        w.permit_any_remote,
    )
}

/// #16589: cut one sub-cap page out of a fully sorted wire population.
///
/// Returns `(page, more, next_cursor)`. The byte budget is enforced by
/// measuring each candidate row's JSON and always emitting at least
/// one row, so a single oversized row cannot wedge the pager (it is
/// still far under the cap: a row's remotes are bounded by the
/// allocator's 1024-remote ceiling).
fn page_wire<T: serde::Serialize + Clone>(
    all: &[T],
    request: Option<&LeaseExportRequest>,
) -> Result<(Vec<T>, bool, String), String> {
    let Some(req) = request.filter(|r| r.paged) else {
        // Pre-#16589 caller: single-shot, exactly as before.
        return Ok((all.to_vec(), false, String::new()));
    };
    let offset: usize = if req.cursor.is_empty() {
        0
    } else {
        req.cursor
            .parse()
            .map_err(|_| "invalid lease export cursor".to_string())?
    };
    if offset > all.len() {
        return Err(format!(
            "lease export cursor {offset} beyond population {}",
            all.len()
        ));
    }
    let count_cap = if req.max == 0 {
        MAX_LEASE_EXPORT_PAGE
    } else {
        (req.max as usize).min(MAX_LEASE_EXPORT_PAGE)
    };
    let mut page: Vec<T> = Vec::new();
    let mut bytes = 64usize; // response envelope slack
    let mut idx = offset;
    while idx < all.len() && page.len() < count_cap {
        let row_len = serde_json::to_vec(&all[idx])
            .map_err(|e| format!("encode lease row: {e}"))?
            .len()
            + 1;
        if !page.is_empty() && bytes.saturating_add(row_len) > LEASE_EXPORT_PAGE_BUDGET {
            break;
        }
        bytes = bytes.saturating_add(row_len);
        page.push(all[idx].clone());
        idx += 1;
    }
    let more = idx < all.len();
    let next = if more { idx.to_string() } else { String::new() };
    Ok((page, more, next))
}

pub(super) fn export(
    guard: &mut ServerState,
    request: Option<&LeaseExportRequest>,
    response: &mut ControlResponse,
) {
    let mut all: Vec<IdleLeaseWire> = guard
        .afxdp
        .export_idle_persistent_leases_now()
        .iter()
        .map(to_wire)
        .collect();
    all.sort_by(|a, b| idle_lease_sort_key(a).cmp(&idle_lease_sort_key(b)));
    match page_wire(&all, request) {
        Ok((page, more, next)) => {
            response.idle_leases = page;
            response.lease_export_more = more;
            response.lease_export_continuation = next;
        }
        Err(e) => {
            response.ok = false;
            response.error = e;
        }
    }
}

pub(super) fn import(
    guard: &mut ServerState,
    wire: &[IdleLeaseWire],
    generation_validated: bool,
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
    let counts = if generation_validated {
        guard
            .afxdp
            .import_idle_persistent_leases_after_generation_now(&records)
    } else {
        guard.afxdp.import_idle_persistent_leases_now(&records)
    };
    if idle_lease_import_is_notable(&counts, malformed) {
        eprintln!(
            "xpf-dp: idle-lease import installed={} existing={} clear_fenced={} expired={} \
             unknown_addr={} unknown_pool={} port_busy={} identity_busy={} capacity={} malformed={}",
            counts.installed,
            counts.skipped_existing,
            counts.skipped_clear_fenced,
            counts.skipped_expired,
            counts.skipped_unknown_address,
            counts.skipped_unknown_pool,
            counts.skipped_port_busy,
            counts.skipped_identity_busy,
            counts.skipped_capacity,
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
            routing_scope: Some(0),
            egress_scope: Some(0),
            src_ip: "10.0.61.50".to_string(),
            src_port: 40000,
            remote_ip: "8.8.8.8".to_string(),
            remote_port: 443,
            permit_any_remote: false,
            permitted_remotes: vec![
                PermittedRemoteWire {
                    ip: "8.8.8.8".to_string(),
                    port: 0,
                },
                PermittedRemoteWire {
                    ip: "1.1.1.1".to_string(),
                    port: 443,
                },
            ],
            translated_ip: "203.0.113.1".to_string(),
            translated_port: 1024,
            address_only: false,
            deterministic: false,
            deterministic_mode: 0,
            deterministic_block_size: 0,
            deterministic_blocks_per_ip: 0,
            deterministic_host_prefix_len: 0,
            deterministic_host_base: String::new(),
            deterministic_host_count: 0,
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
                "clear-fenced stale lease — the clear must be visible even after the entry is gone",
                IdleLeaseImportCounts {
                    skipped_clear_fenced: 1,
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
            (
                "address-only reverse identity already owned",
                IdleLeaseImportCounts {
                    skipped_identity_busy: 1,
                    ..zero
                },
                0,
            ),
            (
                "lease table at capacity",
                IdleLeaseImportCounts {
                    skipped_capacity: 1,
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
                "zero timeout",
                Box::new(|w: &mut IdleLeaseWire| w.timeout_ns = 0)
                    as Box<dyn Fn(&mut IdleLeaseWire)>,
            ),
            (
                "subsecond timeout",
                Box::new(|w: &mut IdleLeaseWire| w.timeout_ns = 1)
                    as Box<dyn Fn(&mut IdleLeaseWire)>,
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
                "malformed permitted remote",
                Box::new(|w: &mut IdleLeaseWire| {
                    w.permitted_remotes[0].ip = "not-an-address".to_string()
                }),
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

    #[test]
    fn skewed_honest_wire_lifetimes_are_clamped_10789_f4() {
        let mut skewed = wire();
        skewed.remaining_ns = skewed.timeout_ns + 1_000_000;
        let parsed = from_wire(&skewed).expect("honest clock skew must not drop a record");
        assert_eq!(parsed.lease.timeout_ns, skewed.timeout_ns);
        assert_eq!(parsed.lease.remaining_ns, skewed.timeout_ns);
        let normalized = to_wire(&parsed);
        assert_eq!(normalized.remaining_ns, skewed.timeout_ns);

        let mut oversized = wire();
        oversized.timeout_ns = MAX_PERSISTENT_NAT_LEASE_LIFETIME_NS + 200;
        oversized.remaining_ns = u64::MAX;
        let parsed = from_wire(&oversized).expect("oversized lifetimes must clamp");
        assert_eq!(
            parsed.lease.timeout_ns,
            MAX_PERSISTENT_NAT_LEASE_LIFETIME_NS
        );
        assert_eq!(
            parsed.lease.remaining_ns,
            MAX_PERSISTENT_NAT_LEASE_LIFETIME_NS
        );
    }
    #[test]
    fn address_only_import_requires_the_preserved_source_port_11496() {
        let mut w = wire();
        w.address_only = true;
        w.translated_port = w.src_port;
        let parsed = from_wire(&w).expect("matching preserved source port is valid");
        assert_eq!(parsed.lease.translated_port, w.src_port);

        w.translated_port += 1;
        assert!(
            from_wire(&w).is_none(),
            "address-only imports cannot carry a translated port different \
             from the source port"
        );
    }

    fn numbered_wire(i: u32, remotes: usize) -> IdleLeaseWire {
        let mut w = wire();
        w.src_ip = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        w.src_port = 1000 + (i % 60000) as u16;
        w.translated_port = 1024 + (i % 60000) as u16;
        w.permitted_remotes = (0..remotes)
            .map(|r| PermittedRemoteWire {
                ip: format!("8.8.{}.{}", r & 0xff, (r >> 8) & 0xff),
                port: 0,
            })
            .collect();
        w.remote_ip = String::new();
        w.remote_port = 0;
        w
    }

    /// #16589 acceptance (helper half): 300k remote-less leases page
    /// completely, every page at/under the control cap, small
    /// population stays single-page. RED on the pre-fix handler, which
    /// ignored lease_export and returned all 300k in one response.
    /// The remote-less control measures 62,040,918 B — just UNDER the
    /// cap solo, so the control pairs one pool with 150k x 4-remotes
    /// leases (the production shape: per-pool caps never bound the
    /// SUM across pools) and crosses it.
    #[test]
    fn paged_export_300k_leases_each_page_under_cap_16589() {
        let mut all: Vec<IdleLeaseWire> = (0..300_000).map(|i| numbered_wire(i, 0)).collect();
        all.sort_by(|a, b| idle_lease_sort_key(a).cmp(&idle_lease_sort_key(b)));
        // Control: 300k remote-less + 150k x 4 remotes unpaged crosses the cap.
        let mut ctrl = ControlResponse::default();
        ctrl.idle_leases = all.clone();
        ctrl.idle_leases
            .extend((0..150_000).map(|i| numbered_wire(300_000 + i, 4)));
        let ctrl_bytes = serde_json::to_vec(&ctrl).expect("serialize control").len() + 1;
        assert!(
            ctrl_bytes > MAX_CONTROL_RESPONSE_BYTES,
            "control: combined unpaged population must cross the cap, got {ctrl_bytes}"
        );
        let mut seen = Vec::new();
        let mut cursor = String::new();
        let mut pages = 0usize;
        loop {
            let req = LeaseExportRequest { paged: true, cursor: cursor.clone(), max: 0 };
            let (page, more, next) = page_wire(&all, Some(&req)).expect("page");
            let mut resp = ControlResponse::default();
            resp.idle_leases = page.clone();
            resp.lease_export_more = more;
            resp.lease_export_continuation = next.clone();
            let bytes = serde_json::to_vec(&resp).expect("serialize page").len() + 1;
            assert!(bytes <= MAX_CONTROL_RESPONSE_BYTES, "page {pages} is {bytes} bytes, over cap");
            seen.extend(page);
            pages += 1;
            if !more {
                break;
            }
            assert!(!next.is_empty() && next != cursor, "continuation must advance");
            cursor = next;
            assert!(pages < 1000, "pager must terminate");
        }
        assert!(pages > 1, "300k must take multiple pages, got {pages}");
        assert_eq!(seen.len(), 300_000);
        assert_eq!(seen, all, "pages must reassemble the sorted population exactly");
        // Small-population control stays single-page.
        let small = &all[..3];
        let req = LeaseExportRequest { paged: true, cursor: String::new(), max: 0 };
        let (page, more, next) = page_wire(small, Some(&req)).expect("small page");
        assert_eq!(page.len(), 3);
        assert!(!more && next.is_empty(), "small population must be single-page");
        // Unpaged (pre-#16589) request stays single-shot.
        let (page, more, _) = page_wire(small, None).expect("unpaged");
        assert_eq!(page.len(), 3);
        assert!(!more);
    }

    /// #16589 acceptance: 150k leases x 4 remotes (~54 MiB unpaged by
    /// the ledger's 361 B/lease measure, and over the cap once the
    /// response envelope and wider fields count) — asserted here by
    /// the stronger property that every paged response is under the
    /// cap and the reassembly is exact; plus cursor refusal.
    #[test]
    fn paged_export_150k_by_4_remotes_and_cursor_refusal_16589() {
        let mut all: Vec<IdleLeaseWire> = (0..150_000).map(|i| numbered_wire(i, 4)).collect();
        all.sort_by(|a, b| idle_lease_sort_key(a).cmp(&idle_lease_sort_key(b)));
        let mut seen = 0usize;
        let mut cursor = String::new();
        let mut pages = 0usize;
        loop {
            let req = LeaseExportRequest { paged: true, cursor: cursor.clone(), max: 0 };
            let (page, more, next) = page_wire(&all, Some(&req)).expect("page");
            let mut resp = ControlResponse::default();
            resp.idle_leases = page;
            let bytes = serde_json::to_vec(&resp).expect("serialize page").len() + 1;
            assert!(bytes <= MAX_CONTROL_RESPONSE_BYTES, "page {pages} over cap: {bytes}");
            seen += resp.idle_leases.len();
            pages += 1;
            if !more {
                break;
            }
            cursor = next;
            assert!(pages < 1000);
        }
        assert_eq!(seen, 150_000);
        assert!(pages > 1, "150k x 4 remotes must page, got {pages}");
        // A cursor past the population and a non-numeric cursor refuse.
        let bad = LeaseExportRequest { paged: true, cursor: "150001".into(), max: 0 };
        assert!(page_wire(&all, Some(&bad)).is_err(), "out-of-range cursor must refuse");
        let bad = LeaseExportRequest { paged: true, cursor: "x".into(), max: 0 };
        assert!(page_wire(&all, Some(&bad)).is_err(), "non-numeric cursor must refuse");
        // max is honoured and clamped by the helper ceiling.
        let req = LeaseExportRequest { paged: true, cursor: String::new(), max: 7 };
        let (page, more, next) = page_wire(&all, Some(&req)).expect("max page");
        assert_eq!(page.len(), 7);
        assert!(more && next == "7");
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
        egress_scope: Some(rec.lease.egress_scope),
        remote_ip,
        remote_port,
        permit_any_remote: rec.lease.permit_any_remote,
        permitted_remotes: rec
            .lease
            .permitted_remotes
            .iter()
            .map(|(ip, port)| PermittedRemoteWire {
                ip: ip.to_string(),
                port: *port,
            })
            .collect(),
        translated_ip: rec.lease.translated_ip.to_string(),
        translated_port: rec.lease.translated_port,
        address_only: rec.lease.address_only,
        deterministic: rec.lease.deterministic,
        deterministic_mode: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(_)) => 1,
            Some(crate::nat::DeterministicPortedIdentity::V6(_)) => 2,
            None => 0,
        },
        deterministic_block_size: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(p)) => p.block_size,
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => p.block_size,
            None => 0,
        },
        deterministic_blocks_per_ip: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(p)) => p.blocks_per_ip,
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => p.blocks_per_ip,
            None => 0,
        },
        deterministic_host_prefix_len: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => p.host_prefix_len,
            _ => 0,
        },
        deterministic_host_base: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(p)) => {
                std::net::Ipv4Addr::from(p.host_base).to_string()
            }
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => {
                std::net::Ipv6Addr::from(p.host_base).to_string()
            }
            None => String::new(),
        },
        deterministic_host_count: match rec.lease.deterministic_identity {
            Some(crate::nat::DeterministicPortedIdentity::V4(p)) => p.host_count,
            Some(crate::nat::DeterministicPortedIdentity::V6(p)) => p.host_count,
            None => 0,
        },
        remaining_ns: rec.lease.remaining_ns,
        timeout_ns: rec.lease.timeout_ns,
        active_flows: rec.lease.active_flows,
    }
}

pub(super) fn export_display(
    guard: &mut ServerState,
    request: Option<&LeaseExportRequest>,
    response: &mut ControlResponse,
) {
    let mut all: Vec<DisplayLeaseWire> = guard
        .afxdp
        .export_display_persistent_leases_now()
        .iter()
        .map(to_display_wire)
        .collect();
    all.sort_by(|a, b| display_lease_sort_key(a).cmp(&display_lease_sort_key(b)));
    match page_wire(&all, request) {
        Ok((page, more, next)) => {
            response.display_leases = page;
            response.lease_export_more = more;
            response.lease_export_continuation = next;
        }
        Err(e) => {
            response.ok = false;
            response.error = e;
        }
    }
}

/// #10784: revoke the authoritative allocator leases. Active flows retain
/// their occupied translation while the lease drains; the SHOW mirror is
/// cleared independently by the Go caller after this ack.
pub(super) fn clear(guard: &mut ServerState, response: &mut ControlResponse) {
    response.persistent_nat_lease_count = guard.afxdp.clear_persistent_nat_leases() as u64;
    response.ok = true;
}
