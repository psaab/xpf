// Binding/queue planning helpers (#6234 split out of the former
// monolithic `server/helpers.rs`).
//
// One cohesive correctness unit (server/README.md): the binding-settle
// predicates, the canonical same-plan hash key
// (`snapshot_binding_plan_key` and its JSON-canonicalizing helpers), and
// the RX-queue / binding replanner (`replan_queues`,
// `replan_bindings_from_candidates`, `effective_rx_queues`,
// `plan_key_rx_queues`, `include_userspace_binding_interface`,
// `userspace_unbindable_netdev`, `snapshot_refuses_parent_netdev`,
// `binding_target_is_refused`). Hash ownership and layout ownership stay
// together so the same-plan skip and the produced layout can never
// disagree — the invariant fixed by #2915/#2916/#3007/#3175, and the
// reason #6691 round 8's refusal predicate is read by BOTH the hash
// filter and the candidate loop rather than restated in each. Cold path
// only (control responses), no per-packet work.

use super::{lock_server_state_recover, refresh_status, should_run_afxdp};
use crate::protocol::{BindingStatus, ConfigSnapshot, InterfaceSnapshot, QueueStatus};
use crate::server::ServerState;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) fn same_plan_apply_needs_binding_reconcile(
    state: &ServerState,
    previous_defer_workers: bool,
    next_defer_workers: bool,
) -> bool {
    if next_defer_workers || !should_run_afxdp(&state.status) {
        return false;
    }

    let runnable_bindings = state
        .status
        .bindings
        .iter()
        .filter(|binding| binding.registered && binding.ifindex > 0)
        .count();
    if runnable_bindings == 0 {
        return false;
    }
    if previous_defer_workers {
        return true;
    }

    let (_, planned_bindings) = state.afxdp.planned_counts();
    let live_bindings = state.afxdp.live_count();
    (planned_bindings < runnable_bindings || live_bindings < runnable_bindings)
        && state.status.bindings.iter().any(|binding| {
            binding.registered
                && binding.ifindex > 0
                && binding.last_error.is_empty()
                && (!binding.bound || !binding.xsk_registered)
        })
}

// wait_for_binding_settle polls until every binding has settled or the deadline
// passes, RELEASING the global ServerState lock across each sleep (#5862).
//
// The poll itself is unchanged from the pre-#5862 form — same refresh, same
// predicate, same 50 ms cadence, same deadline. The only difference is where the
// lock lives: it is taken for the refresh+check and dropped for the sleep,
// instead of being held by the caller across the whole 2 s.
//
// That matters because the lock is not the handler's; it is the WHOLE server's.
// The HA session socket is a separate socket served by a separate thread
// (lifecycle.rs), but `sync_session` dispatches through the same
// `Arc<Mutex<ServerState>>`, so a settle wait held under the lock stalled every
// session mirror behind it. The Go side gives a session request 3 s
// (sessionSyncRoundtripDeadline, pkg/dataplane/userspace/process_control.go),
// and #5380 aborts the REST of the bulk batch on the first transport failure —
// so a 2 s settle overlapping a mirror burst does not merely add latency, it
// can drop the remainder of a batch of up to 255 session mirrors during exactly
// the failover this path exists to support.
//
// Interleaving is the POINT, not a side effect: another request may mutate state
// between two polls. That is safe here because this is a CONVERGENCE wait, not a
// transaction — the predicate is re-evaluated from scratch on every iteration
// and the caller re-derives its response status after the wait returns.
//
// This is the same locked-kick / unlocked-wait split #2962 (owner-RG export
// ack-wait) and #4054 (bulk export push) already applied to the two other
// blocking waits that used to run under this lock.
pub(crate) fn wait_for_binding_settle(state: &Arc<Mutex<ServerState>>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        {
            let mut guard = lock_server_state_recover(&state);
            // GPT-4: never settle-wait (and never reconcile-refresh) on
            // quarantined state — the bindings vector itself may be torn.
            // The handler's re-lock refuses next.
            if guard.quarantined_after_panic {
                return;
            }
            refresh_status(&mut guard);
            if bindings_settled(&guard.status.bindings) || Instant::now() >= deadline {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn bindings_settled(bindings: &[BindingStatus]) -> bool {
    bindings.iter().all(|binding| {
        if !binding.registered {
            return !binding.bound && !binding.xsk_registered;
        }
        binding.ready || !binding.last_error.is_empty()
    })
}

#[cfg(test)]
pub(crate) fn same_binding_plan(current: &ConfigSnapshot, next: &ConfigSnapshot) -> bool {
    snapshot_binding_plan_key(current) == snapshot_binding_plan_key(next)
}

pub(crate) fn snapshot_binding_plan_key(snapshot: &ConfigSnapshot) -> String {
    let mut hasher = Sha256::new();
    update_snapshot_binding_plan_key(&mut hasher, snapshot);
    let digest = hasher.finalize();
    format!("sha256:{digest:x}")
}

fn update_snapshot_binding_plan_key(hasher: &mut Sha256, snapshot: &ConfigSnapshot) {
    let workers = snapshot
        .userspace
        .get("workers")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let ring_entries = snapshot
        .userspace
        .get("ring_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    hash_update(hasher, &format!("workers={workers};ring={ring_entries};"));
    if let Some(shared_umem) = snapshot.userspace.get("shared_umem") {
        hash_update(hasher, "shared_umem=");
        update_canonical_json_hash(hasher, shared_umem);
        hash_update(hasher, ";");
    }
    for iface in snapshot
        .interfaces
        .iter()
        .filter(|iface| include_userspace_binding_interface(iface))
        // #6691 round 8: a row whose bind target the snapshot REFUSES produces
        // no candidate in `replan_queues`, so it must not be hashed here
        // either. Both sides read the SAME predicate
        // (`binding_target_is_refused`), which is what keeps the #2915
        // hash/layout invariant a property of the code rather than of two
        // filters that happen to agree today.
        .filter(|iface| {
            let resolved = if iface.linux_name.is_empty() {
                linux_ifname(&iface.name)
            } else {
                iface.linux_name.clone()
            };
            !binding_target_is_refused(snapshot, iface, &resolved)
        })
    {
        // #3091: `vlan_id` and `parent_linux_name` are now binding-plan inputs
        // — `replan_queues` dedups a VLAN-child netdev onto its physical parent
        // using exactly these two fields. The #2915 invariant requires every
        // field the planner reads to construct the layout to bump the plan key,
        // so re-parenting or VLAN-tag changes trigger a replan (never a stale
        // plan). Additive: an old Go binary that omits them serializes the
        // serde defaults (0 / ""), matching the non-VLAN physical case.
        //
        // #3007: hash the EFFECTIVE rx_queues, not the raw snapshot field. When
        // the snapshot carries the degenerate `rx_queues == 0` fallback,
        // `replan_queues` resolves the real queue count from sysfs
        // (`rx_queue_count`), and THAT count drives `queue_count`/the layout. The
        // plan key must hash the same resolved value, or an out-of-band channel
        // change (`ethtool -L <if> combined N`, no config commit) would leave the
        // snapshot at 0, keep the key identical, and take the same-plan-skip while
        // the planner would actually produce a different layout. For a nonzero
        // snapshot the resolved value equals the raw field (sysfs is not read), so
        // the key is byte-identical to the pre-#3007 hash for the normal case.
        //
        // #3175: for an ORPHAN VLAN child (parent NOT a candidate) the layout
        // re-keys onto the parent's hardware queue count, so `plan_key_rx_queues`
        // hashes `rx_queue_count(parent)` here too — otherwise the child's lone
        // software-queue count is hashed and an out-of-band `ethtool -L <parent>`
        // would not bump the key. The normal VLAN case (parent IS a candidate)
        // and physical ifaces keep the #3007 `effective_rx_queues` behavior.
        let resolved_linux_name = if iface.linux_name.is_empty() {
            linux_ifname(&iface.name)
        } else {
            iface.linux_name.clone()
        };
        let rx_queues = plan_key_rx_queues(snapshot, iface, &resolved_linux_name);
        hash_update(
            hasher,
            &format!(
                "iface={}/{}/{}/{}/{}/{}/{}/{};",
                iface.name,
                iface.linux_name,
                iface.ifindex,
                iface.parent_ifindex,
                rx_queues,
                iface.tunnel,
                iface.vlan_id,
                iface.parent_linux_name
            ),
        );
    }
    for fab in &snapshot.fabrics {
        // #6691 round 9: a fabric whose parent netdev the snapshot REFUSES
        // produces no candidate in `replan_queues`, so it must not be hashed
        // here either — the #2915 hash/layout invariant, applied to the fabric
        // loop for the same reason it already applies to the interface loop.
        if snapshot_refuses_parent_netdev(snapshot, &fab.parent_linux_name) {
            continue;
        }
        // #3007: same effective-rx_queues resolution as the fabric candidate
        // loop in `replan_queues` — sysfs fallback when the snapshot is 0, then
        // `.max(1)` (fabric needs at least one TX queue). Keeps the key in lock
        // step with the value that drives the fabric candidate's queue count.
        let rx_queues = effective_rx_queues(fab.rx_queues, &fab.parent_linux_name).max(1);
        hash_update(
            hasher,
            &format!(
                "fabric={}/{}/{}/{};",
                fab.name, fab.parent_linux_name, fab.parent_ifindex, rx_queues
            ),
        );
    }
}

fn hash_update(hasher: &mut Sha256, input: &str) {
    hasher.update(input.as_bytes());
}

struct Sha256Writer<'a>(&'a mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn update_json_encoded<T: serde::Serialize + ?Sized>(hasher: &mut Sha256, value: &T) {
    serde_json::to_writer(Sha256Writer(hasher), value)
        .expect("canonical JSON hashing uses an infallible writer");
}

fn update_canonical_json_hash(hasher: &mut Sha256, value: &serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            hash_update(hasher, "[");
            let mut items = values.iter().map(canonical_json_key).collect::<Vec<_>>();
            items.sort();
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    hash_update(hasher, ",");
                }
                hash_update(hasher, item);
            }
            hash_update(hasher, "]");
        }
        serde_json::Value::Object(values) => {
            hash_update(hasher, "{");
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (idx, (key, value)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    hash_update(hasher, ",");
                }
                update_json_encoded(hasher, key);
                hash_update(hasher, ":");
                update_canonical_json_hash(hasher, value);
            }
            hash_update(hasher, "}");
        }
        _ => update_json_encoded(hasher, value),
    }
}

fn canonical_json_key(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

fn write_canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Array(values) => {
            out.push('[');
            let mut items = values.iter().map(canonical_json_key).collect::<Vec<_>>();
            items.sort();
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(item);
            }
            out.push(']');
        }
        serde_json::Value::Object(values) => {
            out.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (idx, (key, value)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical_json(value, out);
            }
            out.push('}');
        }
        _ => out.push_str(&serde_json::to_string(value).unwrap_or_default()),
    }
}

/// The NETDEV-INTRINSIC half of the binding refusal: "whatever row asks, an
/// AF_XDP socket may not be bound to this netdev".
///
/// #6691 round 8 split `include_userspace_binding_interface` in two because the
/// two halves behave differently under a REDIRECT. `replan_queues` re-keys an
/// orphan VLAN child onto its physical parent, so the child hands the planner a
/// netdev that is not its own — and the classes below travel with the netdev,
/// while the ones left in the caller (a mgmt/control ZONE, an empty zone, a
/// local-fabric ROLE) describe the ROW and must not be inherited by a sibling.
///
/// The Go control plane mirrors this split exactly in
/// `userspaceUnbindableNetdev` (pkg/dataplane/userspace/ingress_exclusions.go).
/// Only the `secure_tunnel` arm carries a decision this plane cannot re-derive,
/// which is why it is shipped rather than computed here (round 5).
pub(crate) fn userspace_unbindable_netdev(iface: &InterfaceSnapshot) -> bool {
    if iface.tunnel {
        return true;
    }
    let base = iface.name.split('.').next().unwrap_or(iface.name.as_str());
    if base.starts_with("fxp")
        || base.starts_with("em")
        || (base.starts_with("fab") && !iface.fabric_bond)
        || base == "lo0"
    {
        return true;
    }
    // #5619: an IPsec secure tunnel gets no AF_XDP binding.
    //
    // KEYED ON OWNERSHIP OR DEVICE KIND, NEVER ON NAME SHAPE (#6691 rounds 5
    // and 8). `secure_tunnel` is set by the Go control plane from
    // `snapshotSecureTunnel`, the union of two facts: some `security ipsec vpn
    // <name> bind-interface` NAMES this row's device
    // (`Config.SecureTunnelNetdevForRef`), OR the netdev the row resolves to
    // has kernel link kind `xfrm` (`liveXfrmNetdevs`). The first covers what an
    // IPsec configuration binds; the second covers a live xfrmi the config no
    // longer describes — a failed `LinkDel` retains one while the apply
    // proceeds on a deferred error, and a daemon restart leaves an untracked
    // one — which no config-keyed predicate can see. This plane reads the one
    // flag and does not care which half set it.
    //
    // This used to call a local `is_secure_tunnel_ifname(base)` mirroring
    // `config.IsSecureTunnelIfName`: `st` followed by an index in
    // `[0, 65536)`. Nothing reserves the `st` prefix (the Go schema accepts a
    // wildcard interface name), so a wildcard-authored `st5` with no VPN
    // anywhere is an ordinary physical NIC, and the shape test stripped it of
    // its AF_XDP binding — a traffic outage on a working interface. That local
    // predicate is DELETED rather than corrected: with the decision made from
    // ownership, a second hand-maintained copy of the name grammar had nothing
    // left to decide and could only drift from the Go one.
    //
    // The two planes now agree by CONSTRUCTION rather than by convention: the
    // Go side computes the flag once and ships it, so there is no Rust-side
    // rule to keep in sync. An older control plane that omits the field leaves
    // it false — and note which side each gate covers: the Go
    // `ensureSecureTunnelProtocolLocked` detects an older HELPER (this binary)
    // and refuses to publish to it. Nothing detects an older CONTROL PLANE from
    // here; that direction is covered by the snapshot version equality check in
    // `apply_snapshot`, which refuses a snapshot at any other version outright.
    //
    // WHY, in the order the reasons can actually be established (#6691 round 8).
    //
    // 1. IT BINDS A NETDEV THE DATAPLANE CANNOT TRANSMIT INTO. An xfrm
    //    interface has exactly ONE RX queue — `ip -d link` reports
    //    `numrxqueues 1` and `/sys/class/net/<if>/queues` holds a single
    //    `rx-0`, which is what both `rx_queue_count` (below) and the Go
    //    `userspaceRXQueueCount` read. Admitting it mints a binding on a
    //    netdev that has no egress path back from this dataplane, and costs a
    //    slot against MAX_BINDING_SLOTS.
    //
    //    BEFORE #7497 the harm was GLOBAL, and that is worth recording because
    //    every cite of this exclusion used to lead with it:
    //    `replan_bindings_from_candidates` took the MINIMUM queue count across
    //    every candidate, so one zoned xfrmi dragged every physical interface
    //    on the box down to one queue and one worker — the #3091 ~6 Gbps
    //    single-worker regression through a different door than the VLAN child
    //    #3091 named. Per-interface counts removed that amplification: the
    //    tunnel now costs ONE binding, and no other interface's queue count
    //    moves. `secure_tunnel_would_collapse_the_global_queue_count` asserted
    //    the collapse and was retired with the change — the assertion had
    //    become true with the exclusion deleted, so it guarded nothing. The
    //    fail-on-revert guards are now the two plan-IDENTITY tests
    //    (`secure_tunnel_adds_nothing_to_the_binding_plan`,
    //    `binding_candidate_excludes_secure_tunnel`), both measured to fail
    //    when this predicate stops refusing.
    //
    // 2. And it cannot be half-admitted. Keeping the xfrmi in the shim's
    //    ingress-adjudication map while withholding its binding is precisely
    //    the configuration the shim drops: an ingress-claimed ifindex with no
    //    READY binding takes `drop_degraded_transit`
    //    (userspace-xdp/src/lib.rs, BINDING_MISSING). The two sets move
    //    together or transit dies.
    //
    // NOT ASSERTED, deliberately: whether an XSK can come up on an
    // ARPHRD_NONE virtual netdev at all. Zero-copy plainly cannot (no
    // `ndo_bpf`/`ndo_xsk_wakeup`), but zero-copy is not required for every
    // socket role — `XskSocketRole::Private` returns false from
    // `requires_zerocopy` (afxdp/bind.rs), a generic-XDP interface is offered
    // `COPY_ONLY_BIND_FLAGS`, and a failed shared-UMEM group falls back to a
    // private socket automatically (`fallback_shared_group_to_private`). So a
    // copy-mode binding is REACHABLE in this code and earlier rounds of this
    // comment were wrong to say the bind could not happen. Settling it needs a
    // live NIC. Reason 1 does not depend on the answer.
    iface.secure_tunnel
}

pub(crate) fn include_userspace_binding_interface(iface: &InterfaceSnapshot) -> bool {
    if iface.zone.is_empty() {
        return false;
    }
    if !iface.local_fabric_member.is_empty() {
        return false;
    }
    if userspace_unbindable_netdev(iface) {
        return false;
    }
    !matches!(iface.zone.as_str(), "mgmt" | "control")
}

/// #3091: a VLAN-child interface (e.g. `reth0.80` → Linux netdev
/// `ge-0-0-2.80`) is a SOFTWARE VLAN device with a single RX queue. Its
/// VLAN-tagged frames are delivered on the PHYSICAL PARENT's hardware RX
/// queues (`ge-0-0-2`, 6 queues on the mlx5 VF), so the child must NOT enter
/// the queue planner's candidate list — its lone software queue would collapse
/// the per-interface `queue_count` min (see `replan_bindings_from_candidates`)
/// to 1, forcing a single worker and the ~6 Gbps forwarding regression. The
/// pre-existing #1921 `seen_linux` dedup misses VLAN children because the child
/// netdev name (`ge-0-0-2.80`) differs from the parent (`ge-0-0-2`).
///
/// Returns the parent Linux netdev name when `iface` is a distinct VLAN-child
/// netdev, else None (physical interfaces and non-VLAN units, whose
/// `parent_linux_name` is empty or equal to their own netdev, are handled by
/// the existing `seen_linux` dedup).
///
/// #2917 SSOT: this predicate is the single source of truth for the AF_XDP
/// VLAN-unit binding target across BOTH planes. The Go control plane mirrors it
/// exactly in `userspaceBindTargetNetdev`
/// (`pkg/dataplane/userspace/interfaces.go`), which feeds
/// `UserspaceBoundLinuxInterfaces` (the D3/RSS allowlist). A VLAN unit binds its
/// physical PARENT netdev on both planes; a non-VLAN unit binds its own netdev.
/// Keep the two implementations in lock-step — the Rust SSOT test
/// (`replan_queues_binds_vlan_unit_on_parent_netdev`, `main_tests.rs`) and the
/// Go cross-plane parity test (`snapshot_allowlist_test.go`) fail on divergence.
fn vlan_child_parent_netdev<'a>(iface: &'a InterfaceSnapshot, linux_name: &str) -> Option<&'a str> {
    if iface.vlan_id != 0
        && !iface.parent_linux_name.is_empty()
        && iface.parent_linux_name != linux_name
    {
        Some(iface.parent_linux_name.as_str())
    } else {
        None
    }
}

/// #3091: true when the physical netdev `parent` is itself a binding candidate
/// in this snapshot (a zoned, non-tunnel, non-VLAN data interface). When the
/// parent is a candidate, a VLAN child re-keyed onto it is fully covered by the
/// parent's per-queue XSKs (VLAN-tagged frames are captured on the parent's
/// hardware queues), so the child can be dropped from the candidate list.
fn snapshot_has_parent_candidate(snapshot: &ConfigSnapshot, parent: &str) -> bool {
    snapshot.interfaces.iter().any(|p| {
        if !include_userspace_binding_interface(p) {
            return false;
        }
        let p_linux = if p.linux_name.is_empty() {
            linux_ifname(&p.name)
        } else {
            p.linux_name.clone()
        };
        // The parent must be the physical netdev itself, not another VLAN
        // child that happens to share the name string.
        p_linux == parent && vlan_child_parent_netdev(p, &p_linux).is_none()
    })
}

/// #6691 round 8: the snapshot REFUSES this parent netdev on device grounds —
/// as opposed to simply not carrying it.
///
/// `snapshot_has_parent_candidate` returning false conflates two states that
/// need OPPOSITE handling, and the orphan branch of `replan_queues` was written
/// for only one of them:
///
///   - ABSENT. The physical parent is not in the snapshot at all (unzoned, not
///     configured). The child's tagged frames still arrive on the parent's
///     hardware queues, so re-keying the child onto the parent is the #3175 fix
///     and is correct.
///   - REFUSED. The parent IS in the snapshot and `userspace_unbindable_netdev`
///     rejected it. Re-keying onto it re-admits precisely the netdev the
///     binding contract just excluded — through a sibling row that never had to
///     pass the test itself.
///
/// The reachable case is a route-based IPsec tunnel with a zoned sibling unit:
/// `bind-interface st10` makes the base row `st10` a secure tunnel, while
/// `st10 unit 5 vlan-id 100` derives a DIFFERENT if_id and is correctly NOT one.
/// Measured at head on that snapshot, with the LAN at 4 hardware queues and the
/// xfrmi at its single queue: the planner produced a binding for `st10` and the
/// LAN's planned queue count fell from 4 to 1 — the #3091 single-worker
/// regression that `userspace_unbindable_netdev`'s secure-tunnel arm exists to
/// prevent, arriving through the child.
///
/// Deliberately mirrors `snapshot_has_parent_candidate`'s structure, including
/// the "must be the netdev itself, not another VLAN child sharing the name
/// string" guard, so the two answers are about the same row.
///
/// EVERY OWNER, NOT ANY OWNER (#6691 round 9). Round 8 refused as soon as ANY
/// owning row was unbindable, which reads a DISAGREEMENT between two rows as a
/// refusal. Rows do disagree: the Go builder sets a unit row's `tunnel` flag to
/// `iface.Tunnel != nil || unit.Tunnel != nil`, and a unit-0 row with no vlan-id
/// resolves to the BASE netdev, so `set interfaces ge-0/0/5 unit 0 tunnel ...`
/// ships an unbindable `ge-0/0/5.0` row and a bindable `ge-0/0/5` row on ONE
/// netdev. Under the ANY reading a zoned VLAN sibling of that NIC contributed no
/// candidate at all — and when the NIC's own base row is excluded for a ROW
/// reason (a `mgmt` zone, the shape `TestParentRedirectKeepsAMgmtZonedParent`
/// exists for), nothing else supplied it either, so the plan lost a netdev whose
/// ifindex the Go ingress map still carries. An ifindex in the ingress map with
/// no READY binding is `drop_degraded_transit` (BINDING_MISSING) — the unsafe
/// direction, by this file's own invariant.
///
/// Refusing only on unanimity keeps this in exact lock-step with the Go control
/// plane's `buildUserspaceRefusedNetdevs`
/// (`pkg/dataplane/userspace/ingress_exclusions.go`), which selects owners with
/// the same sentence — `userspaceOwnsItsNetdev`, i.e. the bind target is the
/// row's own netdev — and refuses only when every owner agrees. `secure_tunnel`
/// is unaffected: for `bind-interface st10` the only row whose netdev is `st10`
/// is the base xfrmi row (the sibling resolves to `st10.100`), so that bucket is
/// unanimous and the netdev stays refused.
///
/// A FABRIC PARENT IS AN OWNER (#6691 round 10), and getting the owner set wrong
/// is the whole failure mode of a unanimity rule: an EMPTY bucket answers "not
/// refused", which is right when nothing emits the netdev and catastrophic when
/// something does and was not counted. `set interfaces fab0 fabric-options
/// member-interfaces ge-0/0/0` emits that netdev into the fabric candidate loop
/// and (Go-side) into the ingress map and RSS allowlist WITHOUT creating an
/// interface row for it, so round 9 planned a binding on an unbindable ownerless
/// parent. The fabric's vote rides on the snapshot as
/// `FabricSnapshot.parent_unbindable` rather than being recomputed here: half
/// the evidence is a kernel link-kind dump only the Go plane takes. Round 11
/// then narrowed WHERE that vote counts to the ownerless case it was written
/// for — see the fallback comment in the body.
fn snapshot_refuses_parent_netdev(snapshot: &ConfigSnapshot, parent: &str) -> bool {
    let mut owners = 0usize;
    let mut unbindable = 0usize;
    for p in &snapshot.interfaces {
        let p_linux = if p.linux_name.is_empty() {
            linux_ifname(&p.name)
        } else {
            p.linux_name.clone()
        };
        if p_linux != parent || vlan_child_parent_netdev(p, &p_linux).is_some() {
            continue;
        }
        owners += 1;
        if userspace_unbindable_netdev(p) {
            unbindable += 1;
        }
    }
    // THE FABRIC IS A FALLBACK VOTER (#6691 round 11), counted only where no row
    // speaks for the netdev. Round 10 counted it beside any owning row, which put
    // TWO owners on one device with their verdicts computed from different
    // evidence — the Go side from a config lookup plus a kernel dump, this side
    // from a wire field decided at a different instant. A unanimity rule reads
    // any disagreement as an admission, so every way to make those two differ
    // was a fail-OPEN; two were reachable (a canonical alias in the member's
    // name, and a fabric refresh re-sampling the kernel between applies) and both
    // are fixed at their source in the control plane. This rule is what makes a
    // third one harmless: A DEVICE HAS ONE VERDICT — the row's where a row
    // exists, the fabric's where none does, which is the ownerless case round 10
    // was written for. Mirrors Go's snapshotNetdevVotes exactly
    // (pkg/dataplane/userspace/ingress_exclusions.go).
    if owners == 0 {
        for fab in &snapshot.fabrics {
            if fab.parent_linux_name.is_empty() || fab.parent_linux_name != parent {
                continue;
            }
            owners += 1;
            if fab.parent_unbindable {
                unbindable += 1;
            }
        }
    }
    owners > 0 && owners == unbindable
}

/// #6691 round 8: this row's AF_XDP binding would land on a netdev the snapshot
/// REFUSES, so the row contributes no candidate at all.
///
/// Shared by `replan_queues` (the LAYOUT) and `update_snapshot_binding_plan_key`
/// (the HASH) so the two cannot disagree about which rows produce candidates —
/// the #2915 invariant. A row dropped from the layout but still hashed would
/// over-key (extra replans, never a stale plan); a row hashed but not dropped
/// would under-key, which is the unsafe direction. Sharing the predicate makes
/// both impossible rather than merely unlikely.
pub(crate) fn binding_target_is_refused(
    snapshot: &ConfigSnapshot,
    iface: &InterfaceSnapshot,
    resolved_linux_name: &str,
) -> bool {
    match vlan_child_parent_netdev(iface, resolved_linux_name) {
        Some(parent) => snapshot_refuses_parent_netdev(snapshot, parent),
        // A non-VLAN row binds its OWN netdev, which its own row already
        // passed `include_userspace_binding_interface` for.
        None => false,
    }
}

/// #3175: resolve the rx_queue count the PLAN KEY must hash for `iface`,
/// mirroring exactly what `replan_queues`' candidate loop feeds the LAYOUT.
///
/// For an ORPHAN VLAN child — a VLAN unit whose physical parent is NOT itself a
/// binding candidate — `replan_queues` re-keys the child onto its parent netdev
/// and uses the parent's HARDWARE queue count (`rx_queue_count(parent)`), never
/// the child's lone software queue. The plan-key loop previously hashed the
/// child's own `effective_rx_queues`, so an out-of-band `ethtool -L <parent>
/// combined N` (no config commit) left the key unchanged → same-plan-skip →
/// stale layout. Hash the parent's count for the orphan case so the key follows
/// the layout, single-sourcing the resolution exactly as #3007 unified the
/// `rx_queues == 0` sysfs fallback.
///
/// The NORMAL VLAN case (parent IS a candidate) and physical/non-VLAN ifaces are
/// unchanged: the layout drops the normal VLAN child (it is covered by the
/// parent's own physical key entry), and physical ifaces use
/// `effective_rx_queues` exactly as before.
pub(crate) fn plan_key_rx_queues(
    snapshot: &ConfigSnapshot,
    iface: &InterfaceSnapshot,
    resolved_linux_name: &str,
) -> usize {
    if let Some(parent) = vlan_child_parent_netdev(iface, resolved_linux_name) {
        if !snapshot_has_parent_candidate(snapshot, parent) {
            // Orphan VLAN child: the layout re-keys onto the parent's hardware
            // queue count. Hash the same value so the key follows the layout.
            return rx_queue_count(parent);
        }
    }
    effective_rx_queues(iface.rx_queues, resolved_linux_name)
}

pub(crate) fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[BindingStatus],
    forwarding_armed: bool,
) -> Result<Vec<BindingStatus>, String> {
    let mut candidates: Vec<(String, usize)> = Vec::new();
    let mut ifindex_by_name: BTreeMap<String, i32> = BTreeMap::new();
    let mut seen_linux: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(snapshot) = snapshot {
        for iface in &snapshot.interfaces {
            // #2915: the binding candidate decision is a single shared
            // invariant. The plan-key hash
            // (`update_snapshot_binding_plan_key`) and the Go authoritative
            // allowlist (`UserspaceBoundLinuxInterfaces`) both filter through
            // the binding exclusion contract — zoned, non-tunnel,
            // non-local-fabric, excluding fxp*/em*/fab*/lo0 except for
            // configured unresolved fabric bonds (`fabric_bond`), and
            // mgmt/control zones. `replan_queues` MUST act on exactly that set;
            // a prefix-only `ge-*`/`xe-*`/`et-*` test (the pre-#2915 predicate)
            // let a `ge-*` netdev placed in a mgmt/control zone (or a
            // tunnel/local-fabric context) be planned as an AF_XDP binding
            // that neither the hash nor the control plane accounts for.
            if !include_userspace_binding_interface(iface) {
                continue;
            }
            let linux_name = if iface.linux_name.is_empty() {
                linux_ifname(&iface.name)
            } else {
                iface.linux_name.clone()
            };
            // #3091: dedup VLAN-child netdevs onto their physical parent. A
            // bondless-RETH WAN VLAN unit (`reth0.50`/`reth0.80` → Linux
            // `ge-0-0-2.50`/`ge-0-0-2.80`) is a software VLAN device with a
            // single RX queue, but its tagged frames arrive on the PARENT
            // netdev's hardware queues. Pushing it as a separate 1-queue
            // candidate collapses the `queue_count` min to 1 (single worker,
            // the #3091 ~6 Gbps regression). The #1921 `seen_linux` guard below
            // cannot catch this — the child netdev name differs from the parent.
            // #6691 round 8: this row's bind target is a netdev the snapshot
            // REFUSES — not one it merely lacks. Without this the orphan
            // re-key below hands the planner exactly the netdev the binding
            // contract just excluded, through a sibling row that never had to
            // pass the test itself. Asked BEFORE the orphan arm and through
            // the same helper the plan-key filter uses, so the layout and the
            // hash drop identical rows. Drop the child: its bind target is the
            // parent, so there is no netdev left for it to bind.
            if binding_target_is_refused(snapshot, iface, &linux_name) {
                continue;
            }
            if let Some(parent) = vlan_child_parent_netdev(iface, &linux_name) {
                if snapshot_has_parent_candidate(snapshot, parent) {
                    // The parent's per-queue XSKs already capture this VLAN's
                    // tagged frames; skip the 1-queue child entirely.
                    continue;
                }
                // Orphan VLAN child (parent absent from the candidate set):
                // re-key onto the parent netdev using the parent's HARDWARE
                // queue count, never the child's single software queue, so it
                // still cannot collapse the min.
                let parent = parent.to_string();
                if seen_linux.contains(&parent) {
                    continue;
                }
                let rx_queues = rx_queue_count(&parent);
                if rx_queues > 0 {
                    let parent_ifindex = if iface.parent_ifindex > 0 {
                        iface.parent_ifindex
                    } else {
                        iface.ifindex
                    };
                    ifindex_by_name.insert(parent.clone(), parent_ifindex);
                    seen_linux.insert(parent.clone());
                    candidates.push((parent, rx_queues));
                }
                continue;
            }
            // #1921: dedup by Linux netdev. The snapshot lists BOTH the
            // physical interface (`ge-0/0/0`) and its unit (`ge-0/0/0.0`);
            // both start with `ge-` and (for a non-VLAN unit) resolve to the
            // SAME Linux netdev (`ge-0-0-0`). Without this guard each netdev
            // is pushed twice, so replan_bindings_from_candidates plans two
            // bindings per (ifindex, queue_id) — a guaranteed double-bind:
            // the second XSK bind on an already-bound queue returns EBUSY,
            // the queue never goes READY, and the shim drops all transit on
            // it (the virtio multi-queue forwarding outage). One XSK per
            // (netdev, queue) is the AF_XDP contract; collapse duplicates
            // here exactly as the fabric loop below already does.
            if seen_linux.contains(&linux_name) {
                continue;
            }
            // #3007: resolve the effective rx_queues ONCE (snapshot value if
            // nonzero, else sysfs). `snapshot_binding_plan_key` hashes the SAME
            // helper, so the dedup key can never disagree with the layout.
            let rx_queues = effective_rx_queues(iface.rx_queues, &linux_name);
            if rx_queues > 0 {
                ifindex_by_name.insert(linux_name.clone(), iface.ifindex);
                seen_linux.insert(linux_name.clone());
                candidates.push((linux_name, rx_queues));
            }
        }
        // Include fabric parent interfaces so the userspace DP can transmit
        // fabric-redirect packets via XSK TX (and receive fabric ingress).
        for fabric in &snapshot.fabrics {
            if fabric.parent_ifindex <= 0 || fabric.parent_linux_name.is_empty() {
                continue;
            }
            // #6691 round 9: the fabric loop asks the refused index too. It did
            // not before, and round 8 recorded that as unreachable — a judgement
            // made when the exclusion was keyed on the ref's NAME. The kernel-kind
            // half classifies by DEVICE KIND, so it refuses an xfrm device
            // whatever it is called, and a slot-shaped `ge-0/0/0` created out of
            // band is a legal `fabric-options member-interfaces` value. Measured
            // Go-side on that config: the refused netdev went back into the
            // ingress set and the RSS allowlist through the sibling loops. This is
            // transparent to an ordinary fabric, whose physical parent is a data
            // NIC that no exclusion class names.
            if snapshot_refuses_parent_netdev(snapshot, &fabric.parent_linux_name) {
                continue;
            }
            if seen_linux.contains(&fabric.parent_linux_name) {
                continue;
            }
            // #3007: same effective-rx_queues resolution + plan-key hash.
            let rx_queues = effective_rx_queues(fabric.rx_queues, &fabric.parent_linux_name);
            let rx_queues = rx_queues.max(1); // fabric needs at least 1 queue for TX
            ifindex_by_name.insert(fabric.parent_linux_name.clone(), fabric.parent_ifindex);
            seen_linux.insert(fabric.parent_linux_name.clone());
            candidates.push((fabric.parent_linux_name.clone(), rx_queues));
        }
    }
    replan_bindings_from_candidates(workers, existing, candidates, ifindex_by_name, forwarding_armed)
}

/// Capacity of the two shim maps keyed by `BindingStatus::slot` —
/// `userspace_heartbeat` and `userspace_xsk_map`. Mirrors
/// `BINDING_SLOT_MAP_MAX_ENTRIES` in `userspace-xdp/src/binding_index.rs`, which
/// is the authority; Go pins the pair against the compiled shim in
/// `validateUserspaceShimSpecWith` (`pkg/dataplane/loader_userspace_shim.go`) so
/// a drift fails the load rather than surfacing here.
///
/// This is NOT `BINDING_ARRAY_MAX_ENTRIES` (1,048,576) and must not be confused
/// with it. That value bounds the composed index `ifindex * 16 + queue` into the
/// binding ARRAY; this one bounds `slot`, which is assigned densely below. It is
/// 256x smaller, so the write-side guards that check the composed index against
/// the larger value do not protect these two maps (#7497).
pub(crate) const MAX_BINDING_SLOTS: u32 = 4096;

/// Per-interface queue stride of the binding array. Mirrors
/// `BINDING_QUEUES_PER_IFACE` in `userspace-xdp/src/binding_index.rs`, which is
/// the authority, and `BindingQueuesPerIface` in `pkg/dataplane/constants.go`.
///
/// A queue id at or above this would make `ifindex * stride + queue` land in the
/// NEXT ifindex's row, so the Go publisher refuses one (#4894) and the shim
/// resolves no slot at all for one (#5173). The planner caps each interface's
/// queue count at it rather than refusing, so a NIC with more combined channels
/// than the stride stays usable on its first `BINDING_QUEUES_PER_IFACE` queues.
pub(crate) const BINDING_QUEUES_PER_IFACE: usize = 16;

/// Exclusive ceiling on a plannable interface index (#9900 F-150). Mirrors
/// `MAX_INTERFACES` in `bpf/headers/xpf_common.h`, which is the authority,
/// and `MaxInterfaces` in `pkg/dataplane/constants.go` (pinned to the C
/// header by `constants_test.go`).
///
/// The shim resolves the binding row as `ifindex * stride + queue` in `u32`
/// (`binding_slot`, `userspace-xdp/src/binding_index.rs`), so an ifindex at
/// or above 2^28 would wrap onto another row; the checked multiply there
/// fails it closed as a binding miss instead. This ceiling subsumes that
/// bound with room to spare (65536 * 16 + 15 slots stay far inside `u32`),
/// and the planner REFUSES any plan naming an ifindex at or above it — a
/// wild ifindex must be loud at plan time, not a row of silent
/// binding-missing queues on an interface that still reads up.
pub(crate) const MAX_BINDING_IFINDEX: i32 = 65536;

/// Mint a binding plan from candidates, or refuse it with a reason.
///
/// `Ok(vec![])` is a LEGITIMATELY empty plan (no candidates). Every refusal
/// (NAT-holder width, slot capacity, wild ifindex) is `Err(reason)` — never
/// an empty `Ok` — so the caller cannot mistake a refused plan for an empty
/// one and install zero bindings over a working config (GPT-6).
pub(crate) fn replan_bindings_from_candidates(
    workers: usize,
    existing: &[BindingStatus],
    candidates: Vec<(String, usize)>,
    ifindex_by_name: BTreeMap<String, i32>,
    forwarding_armed: bool,
) -> Result<Vec<BindingStatus>, String> {
    // #7497 blocker 6: prior state is carried forward keyed by the binding's
    // STABLE IDENTITY — `(interface, queue_id)` — and not by slot.
    //
    // Slot is a position in the minted sequence, not an identity. Under the old
    // global-minimum rule every interface contributed the same number of rows,
    // so the mapping happened to be stable for the cases that occurred; with a
    // per-interface queue count it is not. `[A(rx=4), B(rx=2)]` mints slot 5 as
    // `(A,q3)`; after `ethtool -L B combined 4`, slot 5 is `(B,q2)`. Carrying
    // `registered`/`armed`/`ready`/`last_error` across that reshuffle attaches
    // one interface's state to a different interface's queue, and a subsequent
    // `binding slot 5 unregister` retargets whichever row now holds the slot.
    // Since #6676 the shim no longer reduces the coordinate, so that queue's
    // packets then have nowhere to go.
    //
    // `(interface, queue_id)` is stable across a queue-count change on ANY
    // interface, across interfaces entering or leaving the candidate set, and
    // across a reordering of the candidate list.
    let mut existing_by_identity: BTreeMap<(String, u32), BindingStatus> = BTreeMap::new();
    for binding in existing {
        existing_by_identity.insert(
            (binding.interface.clone(), binding.queue_id),
            binding.clone(),
        );
    }
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    // #7497: per-interface queue counts. Each interface contributes
    // `min(rx_queues, BINDING_QUEUES_PER_IFACE)` rows instead of every
    // interface contributing the GLOBAL minimum.
    //
    // The old rule bound `min(rx) x interfaces` queues, which on an asymmetric
    // box left every queue above the global minimum unbound — and an unbound
    // queue is not merely idle: the shim takes `drop_degraded_transit` on
    // BINDING_MISSING, so it drops every transit packet RSS steers to it while
    // the interface still reads up.
    //
    // The 16 is the binding array's per-interface stride
    // (`BINDING_QUEUES_PER_IFACE`); a queue id at or above it would alias the
    // adjacent ifindex's queue-0 row, which the Go publisher already refuses
    // (#4894). Capping here rather than refusing keeps a NIC with more than 16
    // combined channels usable on its first 16.
    //
    // #9040: the cap is not silent any more. It was a bare `.min()` with no
    // eprintln, no status field and no counter, which made "this NIC is
    // dropping (Q-16)/Q of its transit" indistinguishable from a healthy plan
    // -- the exact property the SLOT-cap arm one function below refuses a plan
    // over, in its own words "a partial plan is an availability failure
    // indistinguishable from healthy".
    //
    // This still caps rather than refusing, because refusing would take a
    // working box offline on a change that is meant to make a silent loss
    // audible; which of the two is right is a product decision recorded on the
    // issue. What is NOT a product decision is whether the operator gets to
    // know, and the honest floor is that they do. The drop itself already
    // increments the `binding_missing` degraded-path reason, which #9040 also
    // exports as `xpf_dataplane_degraded_path_total{reason="binding_missing"}`
    // -- so this line names the cause at bring-up and the counter shows the
    // ongoing cost.
    let per_interface: Vec<(String, usize)> = candidates
        .iter()
        .map(|(name, rx)| {
            let bound = (*rx).min(BINDING_QUEUES_PER_IFACE);
            if *rx > BINDING_QUEUES_PER_IFACE {
                eprintln!(
                    "xpf-userspace-dp: WARNING {name}: {rx} RX queues exceeds the \
                     per-interface binding stride of {BINDING_QUEUES_PER_IFACE}; \
                     binding the first {bound}. RSS is only reshaped to fit the \
                     bound set on mlx5_core, so on any other driver the NIC keeps \
                     hashing across all {rx} queues and transit landing on queues \
                     {bound}..{rx} is DROPPED (degraded-path reason \
                     binding_missing, exported as \
                     xpf_dataplane_degraded_path_total). Reduce the channel count \
                     with `ethtool -L {name} combined {bound}` to recover it."
                );
            }
            (name.clone(), bound)
        })
        .collect();
    // The widest interface. This is what bounds the minted queue-id range, and
    // therefore the worker-id range, so it replaces the global minimum in the
    // #6211 check below.
    let queue_count = per_interface.iter().map(|(_, q)| *q).max().unwrap_or(0);
    let interfaces = candidates
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let interfaces_len = interfaces.len();
    // #6211 F2: worker ids are MINTED below as `queue_id % workers`, and the NAT
    // allocator records one holder BIT per worker id
    // (`nat::MAX_NAT_HOLDER_WORKERS`). An id too wide for that mask would set no
    // bit on reserve and clear no bit on release — self-consistent, but it
    // collapses that worker back to the pre-fix single-holder behaviour, freeing
    // a pool port while another worker still forwards through it. That is the
    // original over-release reintroduced through its own fix, so refuse the
    // whole plan instead: no bindings means no forwarding, which is fail-closed.
    //
    // Checked HERE and not against the raw `--workers` value. `queue_count` is
    // the per-interface RX-queue minimum, computed independently of `workers`,
    // and `queue_id < queue_count`, so the ids actually minted span
    // `[0, min(queue_count, workers))`. Capping `--workers` alone would REFUSE a
    // safe box — `--workers 200` on a 16-queue NIC mints ids 0..15 — while this
    // check refuses exactly the configurations that would mis-key a holder.
    let max_worker_id = queue_count.min(workers.max(1)).saturating_sub(1);
    if queue_count > 0 && max_worker_id >= crate::nat::MAX_NAT_HOLDER_WORKERS as usize {
        let reason = format!(
            "{} queues x {} workers mints worker_id {} \
             but the NAT holder mask tracks only {} workers (MAX_NAT_HOLDER_WORKERS); \
             an untracked worker would free a pool port another worker still holds",
            queue_count,
            workers,
            max_worker_id,
            crate::nat::MAX_NAT_HOLDER_WORKERS
        );
        eprintln!("replan_bindings: REFUSING plan — {reason}");
        return Err(reason);
    }

    // #7497: `slot` is minted DENSELY below — a plain counter over the bindings
    // that actually exist, i.e. `Σ min(rx_i, 16)` and NOT the product
    // `queue_count * interfaces.len()` — and indexes `userspace_heartbeat` and
    // `userspace_xsk_map`, which hold MAX_BINDING_SLOTS entries. Refuse a plan
    // that would mint a slot those maps cannot address.
    //
    // Checked on the PRODUCT actually minted, not on the interface count or the
    // queue count alone, for the same reason the NAT check above is: either
    // operand can be large on a box whose product is safe, so bounding one
    // would refuse a configuration that binds cleanly.
    //
    // Refusing the WHOLE plan is deliberate and matches the sibling. The
    // minting order below is queue-MAJOR (`for queue_id { for iface {`) WITH a
    // per-row skip, so a row holds only the interfaces that have that queue and
    // `slot` is dense over a RAGGED set — it is NOT
    // `queue_id * interfaces.len() + iface_index`, which was the formula while
    // every interface contributed the same count. Truncating at the capacity
    // would therefore not sacrifice some identifiable interface — it would
    // strand the HIGHEST queue ids across every interface that reaches them,
    // which is also why this refusal names counts rather than a culprit
    // interface: there isn't one.
    //
    // And capping to the first MAX_BINDING_SLOTS bindings would leave those
    // queues unbound, and an unbound queue does not degrade throughput — the shim takes
    // `drop_degraded_transit` on BINDING_MISSING, so every transit packet
    // arriving there is dropped while the interface still reads up and most
    // traffic still flows. That is an availability failure indistinguishable
    // from healthy. A refusal is loud and diagnosable; a partial plan is not.
    //
    // It is enforced HERE, at plan time, and not at XSK registration: by the
    // time `register_xsk_slot` runs (`crate::afxdp::bpf_map::ha`) bringup has
    // already torn down the previous bindings, so a failure there takes
    // forwarding down instead of declining to change it.
    // #7497: the SUM of the per-interface counts, not `queue_count x
    // interfaces`. Under the old rule those were the same number; they are not
    // once each interface contributes its own count, and using the product here
    // would refuse plans that fit.
    let planned_bindings: u64 = per_interface.iter().map(|(_, q)| *q as u64).sum();
    if planned_bindings > MAX_BINDING_SLOTS as u64 {
        let reason = format!(
            "{} interfaces contributing {} bindings \
             in total (widest interface has {} queues), but \
             userspace_heartbeat/userspace_xsk_map address only {} slots \
             (MAX_BINDING_SLOTS); the excess bindings could not be registered and \
             their RX queues would drop all transit traffic",
            interfaces_len, planned_bindings, queue_count, MAX_BINDING_SLOTS
        );
        eprintln!("replan_bindings: REFUSING plan — {reason}");
        return Err(reason);
    }

    // #9900 F-150: an ifindex at or above MAX_BINDING_IFINDEX refuses the
    // WHOLE plan, matching the slot-cap refusal above — a refusal is loud
    // and diagnosable; a partial plan is not. The shim composes the binding
    // row as `ifindex * stride + queue` in `u32`, so a wild ifindex either
    // wraps onto another interface's row (pre-#9900) or fails closed as a
    // binding miss on queues the interface still reads up (post-#9900) —
    // either way the plan must not mint it. Checked BEFORE slot minting, and
    // on the CANDIDATES (pre-cap: the queue cap cannot shrink an ifindex).
    // Missing names and non-positive ifindexes keep the existing per-binding
    // degrade in the minting loop below — only a resolved wild value refuses.
    if let Some((wild_iface, wild_ifindex)) = candidates
        .iter()
        .filter_map(|(name, _)| ifindex_by_name.get(name).map(|i| (name.as_str(), *i)))
        .find(|(_, ifindex)| *ifindex >= MAX_BINDING_IFINDEX)
    {
        let reason = format!(
            "interface {wild_iface} has ifindex \
             {wild_ifindex}, at or above the addressable ceiling \
             (MAX_BINDING_IFINDEX = {MAX_BINDING_IFINDEX}); its queues would fail \
             closed as binding misses while the interface still reads up"
        );
        eprintln!("replan_bindings: REFUSING plan — {reason}");
        return Err(reason);
    }

    // #7497 blocker 3: an operator upgrading onto per-interface queue counts can
    // go from ONE worker thread to as many as the widest interface has queues,
    // with no config change. `plan_workers` keys its map by `worker_id` and
    // spawns one worker per key, so the group count IS the thread count, and the
    // default poll mode is busy-poll (`pkg/dataplane/userspace/process.go`),
    // which means each of those threads spins. That must not be discovered from
    // a CPU graph.
    //
    // Report BOTH numbers and the knob that caps them. The knob does cap them:
    // `worker_id = queue_id % workers`, so the group count is
    // `min(workers, queues)` — measured across a (workers x queues) matrix and
    // pinned by `worker_knob_still_caps_worker_groups_7497`.
    let old_rule_queues = candidates.iter().map(|(_, rx)| *rx).min().unwrap_or(0);
    let old_groups = old_rule_queues.min(workers.max(1));
    let new_groups = queue_count.min(workers.max(1));
    if new_groups != old_groups {
        // Deduped so a re-applied snapshot does not repeat it. The static gates
        // a LOG LINE only — a lost race re-emits at worst, and never affects the
        // plan, which is why a global is acceptable here and would not be for
        // anything the returned bindings depend on.
        static LAST_REPORTED: AtomicU64 = AtomicU64::new(u64::MAX);
        let packed = ((old_groups as u64) << 32) | new_groups as u64;
        if LAST_REPORTED.swap(packed, Ordering::Relaxed) != packed {
            eprintln!(
                "replan_bindings: worker groups {} -> {} (#7497 per-interface queue \
                 counts; the widest interface has {} queues, the global minimum was \
                 {}). Each group is one worker thread, and under the default \
                 busy-poll mode each spins. Cap them with `workers <n>` under \
                 `system userspace-dataplane` — the plan mints \
                 min(workers, queues) groups.",
                old_groups, new_groups, queue_count, old_rule_queues
            );
        }
    }
    let mut out = Vec::with_capacity(planned_bindings as usize);
    let mut slot = 0u32;
    // Queue-major with per-row skipping: row `q` contains one entry for every
    // interface that HAS a queue `q`. Kept queue-major (rather than switching to
    // interface-major) so this change moves one thing — which queues exist — and
    // not also the order they are minted in.
    for queue_id in 0..queue_count {
        for (iface, iface_queues) in &per_interface {
            if queue_id >= *iface_queues {
                continue;
            }
            let mut binding = existing_by_identity
                .remove(&(iface.clone(), queue_id as u32))
                .unwrap_or_default();
            let had_existing = binding.last_change.is_some()
                || binding.registered
                || binding.armed
                || binding.ready
                || binding.bound
                || binding.xsk_registered;
            binding.slot = slot;
            binding.queue_id = queue_id as u32;
            binding.worker_id = (queue_id % workers.max(1)) as u32;
            binding.interface = iface.clone();
            binding.ifindex = *ifindex_by_name.get(iface).unwrap_or(&0);
            if binding.ifindex <= 0 {
                binding.registered = false;
                binding.armed = false;
                binding.ready = false;
            } else if !had_existing {
                binding.registered = true;
                // #6749: a NEWLY registered slot inherits the GLOBAL arm state
                // instead of `BindingStatus::default()`'s `armed = false`.
                //
                // Without this, ANY binding-plan expansion — a zone gaining an
                // interface, a fabric parent appearing, a queue-count change
                // that widens the slot range — silently disables the WHOLE
                // dataplane. `refresh_status` computes
                // `status.enabled = forwarding_armed && ... &&
                // bindings.iter().all(|b| b.registered && b.armed)`
                // (helpers/status.rs), so one unarmed slot makes `enabled`
                // false for every binding on the box, and Go's
                // `resolveCtrlEnableLocked` keys ctrl-enable on that flag —
                // ctrl goes to 0 and ALL transit drops.
                //
                // And it does not self-heal, which is what makes it
                // indefinite rather than a one-tick blip. The only writer of
                // per-binding `armed` outside this function is
                // `set_bindings_forwarding_armed`, reached only from the
                // `set_forwarding_state` handler — and Go suppresses that RPC
                // as a no-op whenever the arm state has not CHANGED
                // (`syncDesiredForwardingStateLocked`:
                // `if m.lastStatus.ForwardingArmed == desired { return nil }`).
                // The helper's GLOBAL `forwarding_armed` is still true across
                // an expansion, so nothing ever re-arms the new slot.
                //
                // Inheriting rather than hardcoding `true` is the point: on a
                // disarmed box (HA secondary, shutdown, a disarm from the
                // protocol gate) a new slot must come up disarmed, exactly as
                // `set_bindings_forwarding_armed` would have set it.
                binding.armed = forwarding_armed;
            }
            if binding.last_change.is_none() {
                binding.last_change = Some(Utc::now());
            }
            out.push(binding);
            slot += 1;
        }
    }
    Ok(out)
}

pub(crate) fn summarize_queues(bindings: &[BindingStatus]) -> Vec<QueueStatus> {
    let mut by_queue: BTreeMap<u32, Vec<&BindingStatus>> = BTreeMap::new();
    for binding in bindings {
        by_queue.entry(binding.queue_id).or_default().push(binding);
    }
    let mut out = Vec::with_capacity(by_queue.len());
    for (queue_id, group) in by_queue {
        let worker_id = group.first().map(|b| b.worker_id).unwrap_or(0);
        let interfaces = group
            .iter()
            .map(|b| b.interface.clone())
            .collect::<Vec<_>>();
        let registered = !group.is_empty() && group.iter().all(|b| b.registered);
        let armed = !group.is_empty() && group.iter().all(|b| b.registered && b.armed);
        let ready = !group.is_empty() && group.iter().all(|b| b.registered && b.ready);
        let last_change = group.iter().filter_map(|b| b.last_change).max();
        out.push(QueueStatus {
            queue_id,
            worker_id,
            interfaces,
            registered,
            armed,
            ready,
            last_change,
        });
    }
    out
}

pub(crate) fn linux_ifname(name: &str) -> String {
    name.replace('/', "-")
}

/// Resolve the effective RX queue count that drives the binding layout: the
/// snapshot's `rx_queues` when nonzero, otherwise the live sysfs channel count
/// (`rx_queue_count`). This is the SINGLE resolution path consumed by BOTH the
/// queue planner (`replan_queues`) and the same-plan dedup key
/// (`update_snapshot_binding_plan_key`), so the key can never hash a value that
/// disagrees with the layout (#3007). For a nonzero snapshot sysfs is never
/// read, so the key stays byte-identical to the pre-#3007 hash for the normal
/// case; the 0 fallback (no committed count) folds the resolved sysfs count into
/// the key so an out-of-band `ethtool -L` channel change forces a replan.
pub(crate) fn effective_rx_queues(snapshot_rx_queues: usize, linux_name: &str) -> usize {
    if snapshot_rx_queues > 0 {
        snapshot_rx_queues
    } else {
        rx_queue_count(linux_name)
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only override for `rx_queue_count`, keyed by netdev name. Lets a
    /// test drive the sysfs-resolved queue count without a real
    /// `/sys/class/net/<if>/queues` tree. Thread-local, so parallel test
    /// threads never cross-contaminate.
    static RX_QUEUE_COUNT_OVERRIDE: std::cell::RefCell<std::collections::HashMap<String, usize>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

#[cfg(test)]
pub(crate) fn set_rx_queue_count_override(name: &str, count: usize) {
    RX_QUEUE_COUNT_OVERRIDE.with(|m| {
        m.borrow_mut().insert(name.to_string(), count);
    });
}

#[cfg(test)]
pub(crate) fn clear_rx_queue_count_override() {
    RX_QUEUE_COUNT_OVERRIDE.with(|m| m.borrow_mut().clear());
}

pub(crate) fn rx_queue_count(name: &str) -> usize {
    #[cfg(test)]
    {
        if let Some(count) = RX_QUEUE_COUNT_OVERRIDE.with(|m| m.borrow().get(name).copied()) {
            return count;
        }
    }
    let path = format!("/sys/class/net/{name}/queues");
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    let count = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|entry| entry.starts_with("rx-"))
        .count();
    count.max(1)
}
