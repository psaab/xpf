//! #6311 session-id node-discriminator PLUMBING guard.
//!
//! The bit math in `SessionTable::set_session_id_namespace` is covered by unit
//! tests (`session::tests::session_id_carries_the_node_discriminator_6311` and
//! friends). Those tests construct the table directly, so they prove the
//! namespace is computed correctly — and prove NOTHING about whether the
//! production path ever hands it a real node id.
//!
//! That gap matters here more than usual, because the wrong value is not a
//! crash or an error: passing a hardcoded `0` at the call site (or dropping the
//! field from the snapshot) leaves the helper minting ids in exactly the
//! pre-#6311 layout, silently, on both nodes. Every unit test still passes.
//!
//! Driving the real path in a unit test would mean spawning a worker with a
//! bound AF_XDP socket, which no test in this crate does, so the plumbing is
//! bound HERE instead — at the source, across the five hops it takes:
//!
//!   Go `cfg.Chassis.Cluster.NodeID`
//!     -> `ConfigSnapshot.NodeID`      (json `node_id`)
//!     -> Rust `ConfigSnapshot.node_id` (serde `node_id`)
//!     -> `spawn_workers(.., snapshot.node_id, ..)`
//!     -> `worker_launch_plan(worker_id, node_id, ..)`   (#18640's helper)
//!     -> `WorkerLaunchPlan::new(worker_id, node_id, ..)`
//!     -> `let WorkerLaunchPlan { worker_id, node_id, .. } = plan`
//!     -> `worker_loop_setup(worker_id, node_id, ..)`
//!     -> `sessions.set_session_id_namespace(node_id, worker_id)`
//!
//! FAIL-ON-REVERT: hardcode the node id at any hop, drop the snapshot field on
//! either side, or rename the JSON key on one side only, and this goes RED.
//!
//! Each hop is anchored on the SYMBOLS that carry the node id, never on a
//! whole argument list (#19131): #17229 deleted a fifth `WorkerLaunchPlan::new`
//! argument (the dead `DnatTableFds`) and #18640 respelled another, and each
//! time a full-list anchor went red while the node id still flowed. Every
//! anchor is checked and every missing one is reported together, so one stale
//! anchor cannot hide the hops after it.
//!
//! What a source anchor cannot see is a constructor that stores a constant in
//! place of its argument (`WorkerLaunchPlan::new` in worker/launch.rs). That hop
//! is covered by the unit test `worker_launch_plan_keeps_the_node_id_19131`
//! (coordinator/reconcile/bringup_session_limit_shard_18640_tests.rs), which
//! builds a plan for node 1 and checks it keeps 1.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("userspace-dp should live directly under the repo root")
        .to_path_buf()
}

fn read(root: &Path, rel: &str) -> String {
    let path = root.join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e))
}

/// Collapse every whitespace run to a single space, and drop it just inside
/// parentheses, so an anchor survives a gofmt re-alignment or a rustfmt line
/// wrap (`f(\n    a,` and `f(a,` both read `f(a,`). The guard is about WHICH
/// SYMBOLS are wired to which, not about their column positions — pinning the
/// exact spacing would make a formatter run look like a deleted wiring.
fn normalize(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(")
        .replace(" )", ")")
}

/// Records a missing anchor instead of panicking on it, so every hop is
/// checked and reported (#19131).
fn check_contains(missing: &mut Vec<String>, haystack: &str, needle: &str, rel: &str, why: &str) {
    if !normalize(haystack).contains(&normalize(needle)) {
        missing.push(format!("{rel} no longer contains {needle:?} — {why}"));
    }
}

#[test]
fn session_id_node_discriminator_is_plumbed_from_the_snapshot_6311() {
    let root = repo_root();
    let mut missing = Vec::new();

    // Hop 1: the Go builder stamps the cluster node id onto the snapshot.
    let go_builder = read(&root, "pkg/dataplane/userspace/builder.go");
    check_contains(
        &mut missing,
        &go_builder,
        "NodeID: clusterNodeID(cfg),",
        "pkg/dataplane/userspace/builder.go",
        "the snapshot no longer carries the chassis-cluster node id, so every \
         helper namespaces session ids as node 0 and an adopted peer id collides \
         with a local one (#6311)",
    );

    // Hop 2: the two sides agree on the WIRE KEY. A rename on one side only is
    // silent — serde falls back to its default and node 1 keeps minting in node
    // 0's namespace.
    let go_proto = read(&root, "pkg/dataplane/userspace/protocol.go");
    check_contains(
        &mut missing,
        &go_proto,
        "`json:\"node_id,omitempty\"`",
        "pkg/dataplane/userspace/protocol.go",
        "the Go snapshot lost its `node_id` wire field (#6311)",
    );
    let rust_proto = read(&root, "userspace-dp/src/protocol/snapshot.rs");
    check_contains(
        &mut missing,
        &rust_proto,
        "#[serde(rename = \"node_id\", default)]",
        "userspace-dp/src/protocol/snapshot.rs",
        "the Rust snapshot lost its `node_id` wire field, so the Go side's value \
         is discarded (#6311)",
    );
    check_contains(
        &mut missing,
        &rust_proto,
        "pub node_id: u8,",
        "userspace-dp/src/protocol/snapshot.rs",
        "the Rust snapshot `node_id` field was renamed or removed (#6311)",
    );

    // Hop 3: bring-up reads it from the SNAPSHOT being applied, not from a
    // constant or from stale coordinator state.
    let bringup = read(
        &root,
        "userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs",
    );
    check_contains(
        &mut missing,
        &bringup,
        "snapshot.node_id,",
        "userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs",
        "worker spawn no longer takes the node id from the applied snapshot (#6311)",
    );
    // Hop 3b (#18640): spawn_workers builds each plan through worker_launch_plan;
    // a hardcoded node id at this call would be the silent revert.
    check_contains(
        &mut missing,
        &bringup,
        "worker_launch_plan(worker_id, node_id,",
        "userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs",
        "spawn_workers no longer passes its node id to the per-worker launch plan (#6311)",
    );
    check_contains(
        &mut missing,
        &bringup,
        "WorkerLaunchPlan::new(worker_id, node_id,",
        "userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs",
        "the per-worker launch plan no longer carries the node id (#6311)",
    );

    // Hop 3c: the worker unpacks the plan's node id and hands it to setup.
    let loop_body = read(&root, "userspace-dp/src/afxdp/worker/loop_body/mod.rs");
    check_contains(
        &mut missing,
        &loop_body,
        "let WorkerLaunchPlan { worker_id, node_id,",
        "userspace-dp/src/afxdp/worker/loop_body/mod.rs",
        "the worker no longer takes the node id from its launch plan (#6311)",
    );
    check_contains(
        &mut missing,
        &loop_body,
        "setup::worker_loop_setup(worker_id, node_id,",
        "userspace-dp/src/afxdp/worker/loop_body/mod.rs",
        "worker setup no longer receives the plan's node id (#6311)",
    );

    // Hop 4: worker setup applies it to the session table. A hardcoded 0 here is
    // the exact silent revert this guard exists for.
    let setup = read(&root, "userspace-dp/src/afxdp/worker/loop_body/setup.rs");
    check_contains(
        &mut missing,
        &setup,
        "sessions.set_session_id_namespace(node_id, worker_id);",
        "userspace-dp/src/afxdp/worker/loop_body/setup.rs",
        "the worker's session table is no longer namespaced by NODE — a peer id \
         adopted verbatim on import (#5212) collides with a local id (#6311)",
    );

    // The #6198 control-plane reservation must survive the re-partition: 0xFFFF
    // is now node-bit-1 plus worker 0x7FFF, and both allocators still write into
    // the same BPF conntrack mirror field.
    let go_convert = read(&root, "pkg/daemon/daemon_ha_userspace_convert.go");
    check_contains(
        &mut missing,
        &go_convert,
        "const userspaceSyncedSessionIDNamespace = uint64(0xFFFF) << 48",
        "pkg/daemon/daemon_ha_userspace_convert.go",
        "the Go control plane's reserved session-id namespace moved; \
         set_session_id_namespace's assert still names 0xFFFF (#6198/#6311)",
    );
    let session_mod = read(&root, "userspace-dp/src/session/mod.rs");
    check_contains(
        &mut missing,
        &session_mod,
        "pub(crate) const CONTROL_PLANE_SESSION_ID_WORKER_HI: u64 = 0xFFFF;",
        "userspace-dp/src/session/mod.rs",
        "the helper-side mirror of the Go control plane's reserved namespace \
         moved (#6198/#6311)",
    );

    assert!(missing.is_empty(), "#6311 plumbing anchors missing:\n  {}", missing.join("\n  "));
}
