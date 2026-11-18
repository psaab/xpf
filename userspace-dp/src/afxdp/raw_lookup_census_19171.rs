//! #19171 fold 1 (lead, from the r24/r23 reviews): the census of every RAW
//! FIB lookup in production code, as a guard.
//!
//! Since #19171 the transit FIB keeps peer-owned connected prefixes. A raw
//! lookup for a destination inside one answers ForwardCandidate (or
//! MissingNeighbor) ON the peer-owned interface. That is safe only when HA
//! judges the answer before it reaches a transmit, a neighbor probe, or
//! persistence. codex-e's P2-1 (the reverse PBR re-selection) was one
//! unjudged caller, and the WireGuard selected-peer outer route (census U1)
//! was another. This test pins every production reference to a raw-lookup
//! entry point, keyed by (file, enclosing fn, callee), to the census in
//! `docs/log/19171.md`. A NEW reference fails here until someone classifies
//! it. A reference that disappears fails too, so the census cannot rot.
//!
//! What counts: every reference to an entry point, not only a call, so a
//! function-pointer use cannot slip past. Excluded: the definition, `use`
//! items, comments and strings, inline `#[cfg(test)]` modules, and files
//! declared under `#[cfg(test)]`.

use std::collections::BTreeMap;

/// The raw entry points: every FIB lookup that returns an unjudged answer.
/// `lookup_forwarding_resolution*` covers every variant (`_with_dynamic`,
/// `_in_table*`, `_for_flow*`, `_for_session*`, `_inner*`, `_v4`/`_v6`, ...).
const RAW_LOOKUP_PREFIX: &str = "lookup_forwarding_resolution";
const RAW_LOOKUP_EXACT: &[&str] = &[
    "select_v4_route",
    "select_v6_route",
    "resolve_forwarding",
    "resolve_tunnel_outer",
    "resolve_tunnel_outer_to",
];

/// How a reference's answer is used, per the census.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// HA judges the answer (`enforce_*`, `judge_packet_route`,
    /// `reresolve_stored_session`, an egress-RG gate, or the WireGuard
    /// selected-peer judgment) before any transmit, probe or persistence.
    Judged,
    /// The answer is read for a predicate, an MTU, an RG or attribution and
    /// cannot reach a transmit, probe or persistence.
    ReadOnly,
    /// The lookup implementation itself: a wrapper or recursion whose
    /// callers are classified in their own rows.
    Implementation,
    /// #326/#14669: the standby stores the raw answer so a session is
    /// forwarding-ready at activation; every hit re-resolves and judges it.
    StandbyReadiness,
    /// A `#[cfg(test)]` function inside a production file.
    TestOnly,
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_raw_lookup(name: &str) -> bool {
    name.starts_with(RAW_LOOKUP_PREFIX) || RAW_LOOKUP_EXACT.contains(&name)
}

/// Identifier tokens of a blanked source: `(start, end)` byte spans.
fn idents(src: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        if is_ident_byte(src[i]) && (i == 0 || !is_ident_byte(src[i - 1])) {
            let start = i;
            while i < src.len() && is_ident_byte(src[i]) {
                i += 1;
            }
            out.push((start, i));
        } else {
            i += 1;
        }
    }
    out
}

/// `fn` bodies of a blanked source: `(open, close, name)`, where open/close
/// are the body's brace offsets. A bodiless `fn` (a trait method
/// declaration) has none.
fn fn_bodies(src: &[u8], tokens: &[(usize, usize)]) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    for pair in tokens.windows(2) {
        let ((fs, fe), (ns, ne)) = (pair[0], pair[1]);
        if &src[fs..fe] != b"fn" || !src[fe..ns].iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Some(open) = src[ne..]
            .iter()
            .position(|b| *b == b'{' || *b == b';')
            .map(|p| ne + p)
        else {
            continue;
        };
        if src[open] == b';' {
            continue;
        }
        let mut depth = 0usize;
        let mut close = src.len();
        for (offset, b) in src[open..].iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push((
            open,
            close,
            String::from_utf8_lossy(&src[ns..ne]).into_owned(),
        ));
    }
    out
}

/// `use` items of a blanked source, as `(start, end)` spans. A `use` token
/// starts an item only at item position (after `;`, a brace, an attribute's
/// `]`, a `pub(...)` restriction's `)`, or the word `pub`), which excludes
/// the `use<..>` precise-capturing bound.
fn use_items(src: &[u8], tokens: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for (index, &(start, end)) in tokens.iter().enumerate() {
        if &src[start..end] != b"use" {
            continue;
        }
        let before = src[..start].iter().rposition(|b| !b.is_ascii_whitespace());
        let item_position = match before {
            None => true,
            Some(p) => {
                matches!(src[p], b';' | b'{' | b'}' | b']' | b')')
                    || (index > 0 && {
                        let (ps, pe) = tokens[index - 1];
                        &src[ps..pe] == b"pub" && pe == p + 1
                    })
            }
        };
        if !item_position {
            continue;
        }
        let stop = src[end..]
            .iter()
            .position(|b| *b == b';')
            .map_or(src.len(), |p| end + p);
        out.push((start, stop));
    }
    out
}

/// References to raw-lookup entry points in one source file, keyed by
/// (innermost enclosing fn, callee). The source is blanked here.
fn raw_lookup_references(src: &str) -> BTreeMap<(String, String), usize> {
    use crate::test_support::source_scan::{blank_cfg_test_modules, blank_comments_and_strings};
    let blanked = blank_cfg_test_modules(&blank_comments_and_strings(src));
    let bytes = blanked.as_bytes();
    let tokens = idents(bytes);
    let bodies = fn_bodies(bytes, &tokens);
    let uses = use_items(bytes, &tokens);
    let mut out = BTreeMap::new();
    for (index, &(start, end)) in tokens.iter().enumerate() {
        let name = &blanked[start..end];
        if !is_raw_lookup(name) {
            continue;
        }
        let is_definition = index > 0 && {
            let (ps, pe) = tokens[index - 1];
            &bytes[ps..pe] == b"fn" && bytes[pe..start].iter().all(u8::is_ascii_whitespace)
        };
        if is_definition || uses.iter().any(|&(us, ue)| us <= start && start < ue) {
            continue;
        }
        let enclosing = bodies
            .iter()
            .filter(|(open, close, _)| *open < start && start < *close)
            .max_by_key(|(open, _, _)| *open)
            .map_or_else(|| "<item>".to_string(), |(_, _, fn_name)| fn_name.clone());
        *out.entry((enclosing, name.to_string())).or_insert(0) += 1;
    }
    out
}

/// Every production reference, keyed by (path under `src`, fn, callee).
fn production_references() -> BTreeMap<(String, String, String), usize> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    crate::test_support::source_scan::afxdp_rs_files(&root, &mut files);
    let mut out = BTreeMap::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        if crate::test_support::source_scan::is_fixture(&root, &rel) {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source");
        for ((fn_name, callee), count) in raw_lookup_references(&src) {
            out.insert((rel.clone(), fn_name, callee), count);
        }
    }
    out
}

/// The census (`docs/log/19171.md`, "Raw FIB lookup census"). Each row is
/// `(path under src, enclosing fn, callee, references, class)`.
#[rustfmt::skip]
const RAW_LOOKUP_CALLERS: &[(&str, &str, &str, usize, Class)] = &[
    ("afxdp/coordinator/inject.rs", "inject_test_packet", "lookup_forwarding_resolution", 1, Class::Judged),
    ("afxdp/coordinator/mod.rs", "queue_warm_pass", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::Judged),
    ("afxdp/coordinator/tunnel_supervision.rs", "resolve_underlay_egress_mtu", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::ReadOnly),
    ("afxdp/coordinator/wg_control/tun_origin.rs", "build_wg_tun_origin_entries", "resolve_tunnel_outer_to", 1, Class::Judged),
    ("afxdp/forwarding/fabric.rs", "prefer_local_forward_candidate_for_fabric_ingress", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::Judged),
    ("afxdp/forwarding/fabric.rs", "prefer_local_forward_candidate_for_fabric_ingress", "lookup_forwarding_resolution_with_dynamic", 1, Class::Judged),
    ("afxdp/forwarding/fabric.rs", "prefer_local_forward_candidate_for_fabric_ingress_for_flow", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::Judged),
    ("afxdp/forwarding/fabric.rs", "prefer_local_forward_candidate_for_fabric_ingress_for_flow", "lookup_forwarding_resolution_with_dynamic", 1, Class::Judged),
    ("afxdp/forwarding/fabric.rs", "prefer_local_forward_candidate_for_fabric_ingress_for_flow", "lookup_forwarding_resolution_with_dynamic_for_flow", 1, Class::Judged),
    ("afxdp/forwarding/fabric.rs", "prefer_local_forward_candidate_for_fabric_ingress_for_flow", "lookup_forwarding_resolution_with_dynamic_for_flow_in_table", 1, Class::Judged),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_for_ip", "lookup_forwarding_resolution", 1, Class::TestOnly),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution", "lookup_forwarding_resolution_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_for_nat_flow", "lookup_forwarding_resolution_inner_ecmp", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_for_nat_flow", "lookup_forwarding_resolution_with_dynamic_for_flow", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_for_nat_flow", "lookup_forwarding_resolution_with_dynamic_for_flow_in_table", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_for_nat_flow", "lookup_forwarding_resolution_without_nat_local_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_in_table_with_dynamic", "lookup_forwarding_resolution_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_inner", "lookup_forwarding_resolution_inner_ecmp", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_inner_ecmp", "lookup_forwarding_resolution_inner_ecmp_suppressing", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_inner_ecmp_suppressing", "lookup_forwarding_resolution_v4_suppressing", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_inner_ecmp_suppressing", "lookup_forwarding_resolution_v6_suppressing", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_v4", "lookup_forwarding_resolution_v4_suppressing", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_v4_inner", "lookup_forwarding_resolution_v4_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_v4_inner", "select_v4_route", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_v4_suppressing", "lookup_forwarding_resolution_v4_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_v6", "lookup_forwarding_resolution_v6_suppressing", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_v6_inner", "lookup_forwarding_resolution_v6_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_v6_inner", "select_v6_route", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_v6_suppressing", "lookup_forwarding_resolution_v6_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_with_dynamic", "lookup_forwarding_resolution_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_with_dynamic_for_flow", "lookup_forwarding_resolution_inner_ecmp", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_with_dynamic_for_flow_in_table", "lookup_forwarding_resolution_inner_ecmp", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_without_nat_local", "lookup_forwarding_resolution_without_nat_local_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "lookup_forwarding_resolution_without_nat_local_inner", "lookup_forwarding_resolution_inner_ecmp_suppressing", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "resolve_forwarding", "lookup_forwarding_resolution_with_dynamic", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "resolve_junos_next_table_v4", "lookup_forwarding_resolution_v4_inner", 2, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "resolve_junos_next_table_v6", "lookup_forwarding_resolution_v6_inner", 2, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "try_deferred_leaks_v4", "lookup_forwarding_resolution_v4_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "try_deferred_leaks_v6", "lookup_forwarding_resolution_v6_inner", 1, Class::Implementation),
    ("afxdp/forwarding/fib.rs", "tunnel_next_hop_live", "resolve_tunnel_outer", 1, Class::ReadOnly),
    ("afxdp/forwarding/ha.rs", "cached_flow_decision_invalid_reason_inner", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::Judged),
    ("afxdp/forwarding/ha.rs", "cached_flow_decision_invalid_reason_inner", "lookup_forwarding_resolution_with_dynamic", 1, Class::Judged),
    ("afxdp/forwarding/ha.rs", "cached_flow_decision_invalid_reason_inner", "lookup_forwarding_resolution_with_dynamic_for_flow", 1, Class::Judged),
    ("afxdp/forwarding/ha.rs", "cached_flow_decision_invalid_reason_inner", "lookup_forwarding_resolution_with_dynamic_for_flow_in_table", 1, Class::Judged),
    ("afxdp/forwarding/ha.rs", "enforce_ha_resolution_snapshot", "lookup_forwarding_resolution_inner", 1, Class::ReadOnly),
    ("afxdp/forwarding/ha.rs", "fabric_redirect_rehome_agrees", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::Judged),
    ("afxdp/forwarding/ha.rs", "fabric_redirect_rehome_agrees", "lookup_forwarding_resolution_with_dynamic", 1, Class::Judged),
    ("afxdp/forwarding/ha.rs", "fabric_redirect_rehome_agrees", "lookup_forwarding_resolution_with_dynamic_for_flow", 1, Class::Judged),
    ("afxdp/forwarding/ha.rs", "fabric_redirect_rehome_agrees", "lookup_forwarding_resolution_with_dynamic_for_flow_in_table", 1, Class::Judged),
    ("afxdp/forwarding/tunnel.rs", "outer_neighbor_ifindex", "resolve_tunnel_outer", 1, Class::Judged),
    ("afxdp/forwarding/tunnel.rs", "resolve_tunnel_forwarding_resolution", "resolve_tunnel_outer", 1, Class::Implementation),
    ("afxdp/forwarding/tunnel.rs", "resolve_tunnel_outer", "resolve_tunnel_outer_to", 1, Class::Implementation),
    ("afxdp/forwarding/tunnel.rs", "resolve_tunnel_outer_to", "lookup_forwarding_resolution_v4", 1, Class::Implementation),
    ("afxdp/forwarding/tunnel.rs", "resolve_tunnel_outer_to", "lookup_forwarding_resolution_v6", 1, Class::Implementation),
    ("afxdp/forwarding_build/mod.rs", "build_fallible_forwarding_state", "lookup_forwarding_resolution_inner", 1, Class::ReadOnly),
    ("afxdp/forwarding_build/mod.rs", "build_fallible_forwarding_state", "resolve_tunnel_outer", 1, Class::ReadOnly),
    ("afxdp/frame/wg.rs", "outer_physical_egress_resolution", "lookup_forwarding_resolution_v4", 1, Class::Judged),
    ("afxdp/frame/wg.rs", "outer_physical_egress_resolution", "lookup_forwarding_resolution_v6", 1, Class::Judged),
    ("afxdp/gre.rs", "gre_transport_egress_ifindexes", "resolve_tunnel_outer", 1, Class::ReadOnly),
    ("afxdp/gre.rs", "gre_transport_tunnel_member_live", "resolve_tunnel_outer", 1, Class::ReadOnly),
    ("afxdp/icmp_embed/return_resolution.rs", "domain_scoped_fallback_resolution", "lookup_forwarding_resolution_in_table_with_dynamic", 2, Class::Judged),
    ("afxdp/icmp_embed/return_resolution.rs", "domain_scoped_fallback_resolution", "lookup_forwarding_resolution_with_dynamic", 1, Class::Judged),
    ("afxdp/ipsec_inner.rs", "d14_zone_gate", "lookup_forwarding_resolution", 1, Class::ReadOnly),
    ("afxdp/poll_descriptor/filter.rs", "revalidate_static_pbr_route_on_session_hit", "lookup_forwarding_resolution_in_table_with_dynamic", 2, Class::Judged),
    ("afxdp/poll_descriptor/filter.rs", "routing_instance_local_delivery_expected", "lookup_forwarding_resolution", 1, Class::ReadOnly),
    ("afxdp/poll_descriptor/flowless_verdict.rs", "flowless_base_resolution", "lookup_forwarding_resolution_in_table_with_dynamic", 2, Class::Judged),
    ("afxdp/poll_descriptor/flowless_verdict.rs", "flowless_base_resolution", "lookup_forwarding_resolution_without_nat_local", 1, Class::Judged),
    ("afxdp/poll_descriptor/mod.rs", "poll_binding_process_descriptor_in_view", "lookup_forwarding_resolution", 1, Class::Judged),
    ("afxdp/poll_descriptor/mod.rs", "poll_binding_process_descriptor_in_view", "lookup_forwarding_resolution_for_nat_flow", 1, Class::Judged),
    ("afxdp/poll_descriptor/mod.rs", "poll_binding_process_descriptor_in_view", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::Judged),
    ("afxdp/poll_descriptor/mod.rs", "poll_binding_process_descriptor_in_view", "resolve_forwarding", 1, Class::Judged),
    ("afxdp/poll_descriptor/policy_revalidation.rs", "resolve_current_forward_companion", "lookup_forwarding_resolution_for_session_without_cache", 1, Class::Judged),
    ("afxdp/session_glue/commands/demote_owner_rgs.rs", "handle_demote_owner_rgs", "lookup_forwarding_resolution_for_session_without_cache", 1, Class::Judged),
    ("afxdp/session_glue/commands/refresh_owner_rgs.rs", "collect_refresh_owner_rgs_items", "lookup_forwarding_resolution_for_session_without_cache", 1, Class::Judged),
    ("afxdp/session_glue/commands/upsert_synced.rs", "handle_upsert_synced", "lookup_forwarding_resolution_for_session_without_cache", 1, Class::StandbyReadiness),
    ("afxdp/session_glue/resolution.rs", "lookup_forwarding_resolution_for_session", "lookup_forwarding_resolution_for_session_with_cache", 1, Class::Implementation),
    ("afxdp/session_glue/resolution.rs", "lookup_forwarding_resolution_for_session_with_cache", "lookup_forwarding_resolution_with_dynamic_for_flow", 1, Class::Implementation),
    ("afxdp/session_glue/resolution.rs", "lookup_forwarding_resolution_for_session_with_cache", "lookup_forwarding_resolution_with_dynamic_for_flow_in_table", 1, Class::Implementation),
    ("afxdp/session_glue/resolution.rs", "lookup_forwarding_resolution_for_session_without_cache", "lookup_forwarding_resolution_for_session_with_cache", 1, Class::Implementation),
    ("afxdp/session_glue/resolution.rs", "lookup_forwarding_resolution_for_synced_session", "lookup_forwarding_resolution_for_session_with_cache", 1, Class::Implementation),
    ("afxdp/session_glue/resolve.rs", "adopted_resolution_in_install_table", "lookup_forwarding_resolution_with_dynamic_for_flow", 1, Class::Judged),
    ("afxdp/session_glue/resolve.rs", "adopted_resolution_in_install_table", "lookup_forwarding_resolution_with_dynamic_for_flow_in_table", 1, Class::Judged),
    ("afxdp/session_glue/resolve.rs", "resolve_flow_session_decision_with_conntrack_inner", "lookup_forwarding_resolution_for_session", 2, Class::Judged),
    ("afxdp/session_glue/resolve.rs", "resolve_flow_session_decision_with_conntrack_inner", "lookup_forwarding_resolution_for_session_without_cache", 2, Class::Judged),
    ("afxdp/session_glue/resolve.rs", "resolve_flow_session_decision_with_conntrack_inner", "lookup_forwarding_resolution_for_synced_session", 1, Class::Judged),
    ("afxdp/session_glue/resolve.rs", "retire_fabric_punt_seed_if_owner_active", "lookup_forwarding_resolution_for_session_without_cache", 1, Class::ReadOnly),
    ("afxdp/shared_ops/lookup.rs", "fabric_adoption_gate_for_wire", "lookup_forwarding_resolution_for_session", 1, Class::ReadOnly),
    ("afxdp/shared_ops/lookup.rs", "fabric_adoption_gate_for_wire", "lookup_forwarding_resolution_inner", 1, Class::ReadOnly),
    ("afxdp/shared_ops/lookup.rs", "fabric_adoption_recovery_for_wire", "lookup_forwarding_resolution_for_session", 1, Class::ReadOnly),
    ("afxdp/shared_ops/owner_rg.rs", "reverse_prewarm_owner_rg_candidates", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::ReadOnly),
    ("afxdp/shared_ops/reverse_synth.rs", "reverse_resolution_for_session_in_table_gated", "lookup_forwarding_resolution_in_table_with_dynamic", 1, Class::Judged),
];

/// THE GUARD. A new raw-lookup reference, a changed count, or a vanished one
/// fails here. To fix a failure: decide whether HA judges the new answer
/// before any transmit, probe or persistence (judge it if not), then add or
/// update the row here and in the census table in `docs/log/19171.md`.
#[test]
fn every_raw_fib_lookup_reference_is_in_the_19171_census() {
    let observed = production_references();
    let expected: BTreeMap<(String, String, String), usize> = RAW_LOOKUP_CALLERS
        .iter()
        .map(|(file, fn_name, callee, count, _)| {
            (
                (file.to_string(), fn_name.to_string(), callee.to_string()),
                *count,
            )
        })
        .collect();
    let mut problems = Vec::new();
    for (key, count) in &observed {
        match expected.get(key) {
            None => problems.push(format!("NEW (unclassified): {key:?} x{count}")),
            Some(want) if want != count => problems.push(format!(
                "COUNT CHANGED: {key:?} census x{want}, source x{count}"
            )),
            Some(_) => {}
        }
    }
    for key in expected.keys().filter(|key| !observed.contains_key(*key)) {
        problems.push(format!("VANISHED (stale census row): {key:?}"));
    }
    assert!(
        problems.is_empty(),
        "raw FIB lookup references differ from the #19171 census. A raw lookup can \
         answer on a peer-owned interface; classify each change (judged before \
         TX/probe/persist, or read-only) in docs/log/19171.md and RAW_LOOKUP_CALLERS:\n{}",
        problems.join("\n")
    );
}

/// Every class is used by at least one row, and no file is listed under a
/// path that does not exist (a typo would make a row permanently VANISHED).
#[test]
fn raw_lookup_census_rows_name_real_files_19171() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (file, ..) in RAW_LOOKUP_CALLERS {
        assert!(
            root.join(file).is_file(),
            "census row names a missing file: {file}"
        );
    }
    for class in [
        Class::Judged,
        Class::ReadOnly,
        Class::Implementation,
        Class::StandbyReadiness,
    ] {
        assert!(
            RAW_LOOKUP_CALLERS.iter().any(|row| row.4 == class),
            "class {class:?} has no row"
        );
    }
}

/// The scanner's contract, on fixture sources: it counts calls and
/// function-pointer references, attributes them to the innermost fn (a
/// closure belongs to its fn), and ignores definitions, `use` items,
/// comments, strings and inline test modules.
#[test]
fn raw_lookup_scanner_counts_only_production_references_19171() {
    let src = r#"
use super::fib::{lookup_forwarding_resolution, select_v4_route};
pub(in crate::afxdp) use super::tunnel::resolve_tunnel_outer;
pub(in crate::afxdp) fn lookup_forwarding_resolution_in_table(x: u8) -> u8 { x }
trait T { fn declared(&self); }
fn caller(state: &S) -> u8 {
    // lookup_forwarding_resolution(state) in a comment
    let note = "select_v4_route in a string";
    let closure = || lookup_forwarding_resolution_in_table(1);
    let pointer = [1u8].iter().map(|v| *v).map(select_v4_route);
    closure() + lookup_forwarding_resolution_in_table(2)
}
fn outer() {
    fn inner() { resolve_tunnel_outer(); }
    resolve_tunnel_outer_to();
}
#[cfg(test)]
mod tests {
    fn fixture() { lookup_forwarding_resolution_in_table(3); }
}
"#;
    let seen = raw_lookup_references(src);
    let key = |f: &str, c: &str| (f.to_string(), c.to_string());
    let want = BTreeMap::from([
        (key("caller", "lookup_forwarding_resolution_in_table"), 2),
        (key("caller", "select_v4_route"), 1),
        (key("inner", "resolve_tunnel_outer"), 1),
        (key("outer", "resolve_tunnel_outer_to"), 1),
    ]);
    assert_eq!(seen, want);
    // One more call is one more reference: the count is the guard's unit.
    let more = src.replace(
        "closure() +",
        "closure() + lookup_forwarding_resolution_in_table(4) +",
    );
    assert_eq!(
        raw_lookup_references(&more).get(&key("caller", "lookup_forwarding_resolution_in_table")),
        Some(&3)
    );
}
