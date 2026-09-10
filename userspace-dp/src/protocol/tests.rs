//! #1325: protocol-module integration test block.
//!
//! Pre-split, all of these tests lived in a single
//! `#[cfg(test)] mod tests { ... }` at the bottom of `protocol.rs`.
//! Post-split, they remain a single cohesive `#[cfg(test)] mod tests`
//! at the `protocol/` parent layer because every test exercises wire
//! contracts that span multiple sub-modules (ProcessStatus aggregates
//! BindingCountersSnapshot, WorkerRuntimeStatus, SourceNatPoolStatus,
//! etc.). The cross-domain placement rule (#1325 plan v3) puts the
//! ProcessStatus-rooted tests next to ProcessStatus; since
//! ProcessStatus lives in `control.rs` and the test types span every
//! sibling, the parent `protocol::tests` location is the simplest
//! correct home.
//!
//! Cross-module type references use `super::*` (re-exported via
//! `mod.rs` glob), which is equivalent to the absolute
//! `crate::protocol::X` form for this purpose.

use super::*;


// #3070: ZoneSnapshot host-inbound-traffic fields round-trip on the Go↔Rust
// wire. The Go control plane (pkg/dataplane/userspace) emits exactly these
// JSON keys; an older Go binary that omits them must still decode (serde
// default → not configured → admit-all).
#[test]
fn zone_snapshot_host_inbound_fields_roundtrip() {
    let zone = ZoneSnapshot {
        name: "wan".into(),
        id: 11,
        host_inbound_configured: true,
        host_inbound_system_services: vec!["ssh".into(), "ping".into(), "ike".into()],
        host_inbound_protocols: vec!["ospf".into(), "router-discovery".into()],
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&zone).expect("serialize ZoneSnapshot to Value");
    assert_eq!(value["host_inbound_configured"], true);
    assert_eq!(value["host_inbound_system_services"][0], "ssh");
    assert_eq!(value["host_inbound_system_services"][2], "ike");
    assert_eq!(value["host_inbound_protocols"][0], "ospf");

    let back: ZoneSnapshot = serde_json::from_value(value).expect("deserialize ZoneSnapshot");
    assert!(back.host_inbound_configured);
    assert_eq!(back.host_inbound_system_services, vec!["ssh", "ping", "ike"]);
    assert_eq!(back.host_inbound_protocols, vec!["ospf", "router-discovery"]);

    // Backward-compat: a payload from an older Go binary without the fields
    // decodes to "not configured" (admit-all) rather than failing.
    let legacy: ZoneSnapshot =
        serde_json::from_str(r#"{"name":"trust","id":3}"#).expect("decode legacy ZoneSnapshot");
    assert_eq!(legacy.name, "trust");
    assert_eq!(legacy.id, 3);
    assert!(!legacy.host_inbound_configured);
    assert!(legacy.host_inbound_system_services.is_empty());
    assert!(legacy.host_inbound_protocols.is_empty());
}

// #3082: the references-missing-profile set is an additive, skew-tolerant wire
// field. A snapshot from an OLD Go binary that does not emit
// `screen_missing_profile_zones` must still decode (the field defaults to
// empty), and a snapshot that DOES carry it must round-trip.
#[test]
fn screen_missing_profile_zones_wire_roundtrip_and_skew() {
    // Old-helper skew: a snapshot serialized WITHOUT the field must still
    // decode and yield an empty set (→ all-Pass, no warn). Start from a full
    // default snapshot (so every other required field is present) and strip the
    // additive key.
    let mut v = serde_json::to_value(ConfigSnapshot::default())
        .expect("serialize default ConfigSnapshot");
    v.as_object_mut()
        .expect("snapshot is a JSON object")
        .remove("screen_missing_profile_zones");
    let snap: ConfigSnapshot =
        serde_json::from_value(v).expect("snapshot without the field must decode");
    assert!(
        snap.screen_missing_profile_zones.is_empty(),
        "absent field must default to empty"
    );

    // Present: round-trips with both zone and profile preserved.
    let mut v = serde_json::to_value(ConfigSnapshot::default())
        .expect("serialize default ConfigSnapshot");
    v.as_object_mut().expect("snapshot is a JSON object").insert(
        "screen_missing_profile_zones".into(),
        serde_json::json!([{"zone":"trust","profile":"ghost"}]),
    );
    let snap: ConfigSnapshot =
        serde_json::from_value(v).expect("snapshot with the field must decode");
    assert_eq!(snap.screen_missing_profile_zones.len(), 1);
    assert_eq!(snap.screen_missing_profile_zones[0].zone, "trust");
    assert_eq!(snap.screen_missing_profile_zones[0].profile, "ghost");

    // #7888: the INERT sibling is a separate additive field and needs the same
    // two-direction skew proof. Extending this test in the same change is the
    // point — an additive wire field whose skew test is not extended is the
    // thing that LOOKS bound and is not.
    //
    // Old-helper skew: absent field must decode to empty, which is exactly
    // today's behaviour (inert zones Pass silently).
    let mut v = serde_json::to_value(ConfigSnapshot::default())
        .expect("serialize default ConfigSnapshot");
    v.as_object_mut()
        .expect("snapshot is a JSON object")
        .remove("screen_inert_profile_zones");
    let snap: ConfigSnapshot =
        serde_json::from_value(v).expect("snapshot without the inert field must decode");
    assert!(
        snap.screen_inert_profile_zones.is_empty(),
        "absent inert field must default to empty — an old Go binary that does not emit it \
         must leave the set empty, not fail the decode"
    );

    // Present: round-trips with both zone and profile preserved.
    let mut v = serde_json::to_value(ConfigSnapshot::default())
        .expect("serialize default ConfigSnapshot");
    v.as_object_mut().expect("snapshot is a JSON object").insert(
        "screen_inert_profile_zones".into(),
        serde_json::json!([{"zone":"trust","profile":"p"}]),
    );
    let snap: ConfigSnapshot =
        serde_json::from_value(v).expect("snapshot with the inert field must decode");
    assert_eq!(snap.screen_inert_profile_zones.len(), 1);
    assert_eq!(snap.screen_inert_profile_zones[0].zone, "trust");
    assert_eq!(snap.screen_inert_profile_zones[0].profile, "p");

    // The two fields are INDEPENDENT on the wire. A snapshot carrying only the
    // inert set must leave the missing set empty and vice versa — if one
    // decoder key were reused for both, this is the assertion that catches it.
    let mut v = serde_json::to_value(ConfigSnapshot::default())
        .expect("serialize default ConfigSnapshot");
    {
        let obj = v.as_object_mut().expect("snapshot is a JSON object");
        obj.insert(
            "screen_inert_profile_zones".into(),
            serde_json::json!([{"zone":"trust","profile":"p"}]),
        );
        obj.insert(
            "screen_missing_profile_zones".into(),
            serde_json::json!([{"zone":"wan","profile":"ghost"}]),
        );
    }
    let snap: ConfigSnapshot =
        serde_json::from_value(v).expect("snapshot with both fields must decode");
    assert_eq!(snap.screen_inert_profile_zones.len(), 1);
    assert_eq!(snap.screen_inert_profile_zones[0].zone, "trust");
    assert_eq!(snap.screen_missing_profile_zones.len(), 1);
    assert_eq!(
        snap.screen_missing_profile_zones[0].zone, "wan",
        "the two sets must decode independently; one key serving both would make the \
         helper's WARN text undecidable"
    );

    // A ref with only a zone (profile omitted) decodes with an empty profile.
    let r: ScreenMissingProfileRef =
        serde_json::from_str(r#"{"zone":"dmz"}"#).expect("ref with omitted profile decodes");
    assert_eq!(r.zone, "dmz");
    assert!(r.profile.is_empty());
}

#[test]
fn process_status_inject_packet_tuple_protocol_version_roundtrip() {
    let status = ProcessStatus {
        inject_packet_tuple_protocol_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(
        value["inject_packet_tuple_protocol_version"],
        INJECT_PACKET_TUPLE_PROTOCOL_VERSION
    );
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(
        back.inject_packet_tuple_protocol_version,
        INJECT_PACKET_TUPLE_PROTOCOL_VERSION
    );
}

#[test]
fn process_status_buffer_capacity_fields_roundtrip() {
    let status = ProcessStatus {
        session_table_entries: 77,
        max_sessions: 100,
        flow_cache_capacity: 4096,
        neighbor_entries: 9,
        neighbor_cache_capacity: 64,
        worker_runtime: vec![WorkerRuntimeStatus {
            worker_id: 2,
            session_table_entries: 77,
            max_sessions: 100,
            ..Default::default()
        }],
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["session_table_entries"], 77);
    assert_eq!(value["max_sessions"], 100);
    assert_eq!(value["flow_cache_capacity"], 4096);
    assert_eq!(value["neighbor_cache_capacity"], 64);
    assert_eq!(value["worker_runtime"][0]["session_table_entries"], 77);
    assert_eq!(value["worker_runtime"][0]["max_sessions"], 100);

    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.session_table_entries, 77);
    assert_eq!(back.max_sessions, 100);
    assert_eq!(back.flow_cache_capacity, 4096);
    assert_eq!(back.neighbor_cache_capacity, 64);
    assert_eq!(back.worker_runtime[0].session_table_entries, 77);
    assert_eq!(back.worker_runtime[0].max_sessions, 100);
}

// #1771 §2.6: round-trip + backward-compat pin for the resolver
// backoff-retry counter, the §2.5 ENOBUFS/re-dump counters, and the
// pending-keys / negative-keys gauges. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus families
// `xpf_userspace_neighbor_resolver_get_backoff_attempts_total`,
// `xpf_userspace_neighbor_netlink_{enobufs,redumps,redump_upserts}_total`,
// `xpf_userspace_neighbor_pending_keys`, `xpf_userspace_neg_neigh_keys`.
#[test]
fn process_status_neighbor_phase3_counters_roundtrip() {
    let status = ProcessStatus {
        neighbor_resolver_get_backoff_attempts_total: 7,
        neighbor_netlink_enobufs_total: 3,
        neighbor_netlink_redumps_total: 2,
        neighbor_netlink_redump_upserts_total: 11,
        neighbor_pending_keys: 4,
        neg_neigh_keys: 5,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    let keys = [
        ("neighbor_resolver_get_backoff_attempts_total", 7u64),
        ("neighbor_netlink_enobufs_total", 3),
        ("neighbor_netlink_redumps_total", 2),
        ("neighbor_netlink_redump_upserts_total", 11),
        ("neighbor_pending_keys", 4),
        ("neg_neigh_keys", 5),
    ];
    for (key, want) in keys {
        assert_eq!(value[key], want, "wire key {key}");
    }
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.neighbor_resolver_get_backoff_attempts_total, 7);
    assert_eq!(back.neighbor_netlink_enobufs_total, 3);
    assert_eq!(back.neighbor_netlink_redumps_total, 2);
    assert_eq!(back.neighbor_netlink_redump_upserts_total, 11);
    assert_eq!(back.neighbor_pending_keys, 4);
    assert_eq!(back.neg_neigh_keys, 5);

    // Pre-Phase-3 payload (keys absent) must decode with zero defaults.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    for (key, _) in keys {
        legacy_value
            .as_object_mut()
            .expect("ProcessStatus serializes to an object")
            .remove(key)
            .unwrap_or_else(|| panic!("new key {key} present before strip"));
    }
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-Phase-3 payload decodes");
    assert_eq!(legacy.neighbor_resolver_get_backoff_attempts_total, 0);
    assert_eq!(legacy.neighbor_netlink_enobufs_total, 0);
    assert_eq!(legacy.neighbor_netlink_redumps_total, 0);
    assert_eq!(legacy.neighbor_netlink_redump_upserts_total, 0);
    assert_eq!(legacy.neighbor_pending_keys, 0);
    assert_eq!(legacy.neg_neigh_keys, 0);
}

// #2375: round-trip + backward-compat pin for the pending_neigh
// distinct-hop capacity-drop counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_pending_neigh_capacity_drops_total`. Kept distinct
// from `pending_neigh_duplicate_drops_total` so a rename or a one-sided
// add fails a test instead of silently decoding zero (#1961 risk).
#[test]
fn process_status_pending_neigh_capacity_drops_roundtrip() {
    let status = ProcessStatus {
        pending_neigh_capacity_drops_total: 9,
        pending_neigh_duplicate_drops_total: 4,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["pending_neigh_capacity_drops_total"], 9);
    // The duplicate counter must stay a SEPARATE wire key, not conflated.
    assert_eq!(value["pending_neigh_duplicate_drops_total"], 4);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.pending_neigh_capacity_drops_total, 9);
    assert_eq!(back.pending_neigh_duplicate_drops_total, 4);

    // Pre-#2375 payload (key absent) must decode with a zero default
    // (#[serde(default)] backward-compat with an older daemon).
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("pending_neigh_capacity_drops_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#2375 payload decodes");
    assert_eq!(legacy.pending_neigh_capacity_drops_total, 0);
}

// #5673: round-trip + backward-compat pin for the aggregate
// dynamic-neighbor learn-cap drop counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_dynamic_neighbor_learn_cap_drops_total`. A rename or a
// one-sided add fails here instead of silently decoding zero on the Go side.
#[test]
fn process_status_dynamic_neighbor_learn_cap_drops_roundtrip() {
    let status = ProcessStatus {
        dynamic_neighbor_learn_cap_drops_total: 12,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["dynamic_neighbor_learn_cap_drops_total"], 12);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.dynamic_neighbor_learn_cap_drops_total, 12);

    // Pre-#5673 payload (key absent) must decode with a zero default
    // (#[serde(default)] backward-compat with an older daemon).
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("dynamic_neighbor_learn_cap_drops_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#5673 payload decodes");
    assert_eq!(legacy.dynamic_neighbor_learn_cap_drops_total, 0);
}

// #1807: round-trip + backward-compat pin for the worker-command-queue
// poison-recovery counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_worker_command_queue_poison_recoveries_total`.
#[test]
fn process_status_worker_command_queue_poison_recoveries_roundtrip() {
    let status = ProcessStatus {
        worker_command_queue_poison_recoveries: 3,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["worker_command_queue_poison_recoveries"], 3);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.worker_command_queue_poison_recoveries, 3);

    // Pre-#1807 payload (key absent) must decode with a zero default.
    // ProcessStatus has required fields, so build the legacy document by
    // stripping the new key from a serialized Default instance.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("worker_command_queue_poison_recoveries")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#1807 payload decodes");
    assert_eq!(legacy.worker_command_queue_poison_recoveries, 0);
}

// #6929: round-trip + backward-compat pin for the per-worker command-queue
// capacity-drop counter. The wire key feeds
// pkg/dataplane/userspace/protocol_status.go and the Prometheus counter
// `xpf_userspace_worker_command_queue_drops_total`. Its Go twin
// (TestWorkerCommandQueueDropsWireKeyLockstepWithRust6929) asserts the two
// spellings AGREE; this end pins the serialize/decode behaviour the agreement
// is about, including that an older payload without the key still decodes.
#[test]
fn process_status_worker_command_queue_drops_roundtrip_6929() {
    let status = ProcessStatus {
        worker_command_queue_drops: 3,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["worker_command_queue_drops"], 3);
    // The neighbouring counter must stay put. A rename that aliased the drop
    // field onto the poison key would satisfy every assertion about the drop
    // field alone while reporting a lossless recovery as a lost command.
    assert_eq!(
        value["worker_command_queue_poison_recoveries"], 0,
        "the capacity-drop field must not serialize onto the poison key"
    );
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.worker_command_queue_drops, 3);

    // Pre-#6929 payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("worker_command_queue_drops")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#6929 payload decodes");
    assert_eq!(legacy.worker_command_queue_drops, 0);
}

// #2402/#6641: round-trip + backward-compat pin for the shared-session
// poison-recovery counter. The wire key feeds
// pkg/dataplane/userspace/protocol_status.go and the Prometheus counter
// `xpf_userspace_shared_session_poison_recoveries_total`. A key rename on
// either side decodes silently as zero, which for THIS counter reads as
// "no worker panic ever touched HA session state" -- the exact reassuring
// value the defect already produced, so the tag is pinned on both sides.
#[test]
fn process_status_shared_session_poison_recoveries_roundtrip() {
    let status = ProcessStatus {
        shared_session_poison_recoveries: 7,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["shared_session_poison_recoveries"], 7);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.shared_session_poison_recoveries, 7);

    // Pre-#6641 payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("shared_session_poison_recoveries")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#6641 payload decodes");
    assert_eq!(legacy.shared_session_poison_recoveries, 0);
}

// #2315: round-trip + backward-compat pin for the GRE-decap RFC 6040
// §4.2 illegal-combination drop counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_gre_decap_ecn_illegal_drops_total`.
#[test]
fn process_status_gre_decap_ecn_illegal_drops_roundtrip() {
    let status = ProcessStatus {
        gre_decap_ecn_illegal_drops_total: 5,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["gre_decap_ecn_illegal_drops_total"], 5);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.gre_decap_ecn_illegal_drops_total, 5);

    // Pre-#2315 payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("gre_decap_ecn_illegal_drops_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#2315 payload decodes");
    assert_eq!(legacy.gre_decap_ecn_illegal_drops_total, 0);
}

// #2317: round-trip + backward-compat pin for the WG-decap RFC 6040
// §4.2 illegal-combination drop counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_wg_decap_ecn_illegal_drops_total`.
#[test]
fn process_status_wg_decap_ecn_illegal_drops_roundtrip() {
    let status = ProcessStatus {
        wg_decap_ecn_illegal_drops_total: 7,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["wg_decap_ecn_illegal_drops_total"], 7);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.wg_decap_ecn_illegal_drops_total, 7);

    // Pre-#2317 payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("wg_decap_ecn_illegal_drops_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#2317 payload decodes");
    assert_eq!(legacy.wg_decap_ecn_illegal_drops_total, 0);
}

// #2331: round-trip + backward-compat pin for the native-GRE encap
// DF-set oversized-outer drop counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_gre_encap_df_oversize_drops_total`.
#[test]
fn process_status_gre_encap_df_oversize_drops_roundtrip() {
    let status = ProcessStatus {
        gre_encap_df_oversize_drops_total: 9,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["gre_encap_df_oversize_drops_total"], 9);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.gre_encap_df_oversize_drops_total, 9);

    // Pre-#2331 payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("gre_encap_df_oversize_drops_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#2331 payload decodes");
    assert_eq!(legacy.gre_encap_df_oversize_drops_total, 0);
}

// #2782: round-trip + backward-compat pin for the native-GRE decap
// checksum-present invalid drop counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_gre_decap_checksum_invalid_drops_total`.
#[test]
fn process_status_gre_decap_checksum_invalid_drops_roundtrip() {
    let status = ProcessStatus {
        gre_decap_checksum_invalid_drops_total: 12,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["gre_decap_checksum_invalid_drops_total"], 12);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.gre_decap_checksum_invalid_drops_total, 12);

    // Pre-#2782 payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("gre_decap_checksum_invalid_drops_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#2782 payload decodes");
    assert_eq!(legacy.gre_decap_checksum_invalid_drops_total, 0);
}

// #6842: round-trip + backward-compat pin for the native-GRE decap
// unsupported-version REFUSAL counter (RFC 2637 / PPTP enhanced GRE is
// version 1). The wire key feeds pkg/dataplane/userspace/protocol_status.go
// and the Prometheus counter
// `xpf_userspace_gre_decap_unsupported_version_refusals_total`.
#[test]
fn process_status_gre_decap_unsupported_version_refusals_roundtrip() {
    let status = ProcessStatus {
        gre_decap_unsupported_version_refusals_total: 12,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["gre_decap_unsupported_version_refusals_total"], 12);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.gre_decap_unsupported_version_refusals_total, 12);

    // Pre-#6842 payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("gre_decap_unsupported_version_refusals_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#6842 payload decodes");
    assert_eq!(legacy.gre_decap_unsupported_version_refusals_total, 0);
}

// #2472: round-trip + backward-compat pin for the per-reason
// generated-error rate-limit drop counters. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus counters
// `xpf_userspace_{time_exceeded,packet_too_big,reject}_rate_limited_total`.
#[test]
fn process_status_generated_error_rate_limited_roundtrip() {
    let status = ProcessStatus {
        time_exceeded_rate_limited_total: 11,
        packet_too_big_rate_limited_total: 12,
        reject_rate_limited_total: 13,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["time_exceeded_rate_limited_total"], 11);
    assert_eq!(value["packet_too_big_rate_limited_total"], 12);
    assert_eq!(value["reject_rate_limited_total"], 13);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.time_exceeded_rate_limited_total, 11);
    assert_eq!(back.packet_too_big_rate_limited_total, 12);
    assert_eq!(back.reject_rate_limited_total, 13);

    // Pre-#2472 payload (keys absent) must decode with zero defaults.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    let obj = legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object");
    obj.remove("time_exceeded_rate_limited_total")
        .expect("new key present before strip");
    obj.remove("packet_too_big_rate_limited_total")
        .expect("new key present before strip");
    obj.remove("reject_rate_limited_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#2472 payload decodes");
    assert_eq!(legacy.time_exceeded_rate_limited_total, 0);
    assert_eq!(legacy.packet_too_big_rate_limited_total, 0);
    assert_eq!(legacy.reject_rate_limited_total, 0);
}

// #1760 W3': round-trip + backward-compat pin for the shared-map NAT
// reverse-key displacement counter. The wire key feeds
// pkg/dataplane/userspace/protocol.go and the Prometheus counter
// `xpf_userspace_session_nat_reverse_key_shared_displacements_total`.
/// #6751 PR 2/3: the three interface-mode SNAT registry counters round-trip on
/// the helper status wire under their exact serde keys, and an OLD helper that
/// omits them decodes to 0 rather than failing the whole status parse (#1961
/// additive-counter rule). Each carries a DISTINCT value so a rename that
/// crossed two keys cannot pass.
#[test]
fn process_status_interface_snat_registry_counters_roundtrip_6751() {
    let status = ProcessStatus {
        interface_snat_pat_collisions_total: 11,
        interface_snat_identity_exhaustion_total: 13,
        interface_snat_sync_identity_conflict_drops_total: 19,
        interface_snat_registry_cap_exhaustion_total: 17,
        ..Default::default()
    };
    let value: serde_json::Value = serde_json::to_value(&status).expect("serialize");
    assert_eq!(value["interface_snat_pat_collisions_total"], 11);
    assert_eq!(value["interface_snat_identity_exhaustion_total"], 13);
    assert_eq!(
        value["interface_snat_sync_identity_conflict_drops_total"],
        19
    );
    assert_eq!(value["interface_snat_registry_cap_exhaustion_total"], 17);
    let back: ProcessStatus = serde_json::from_value(value.clone()).expect("deserialize");
    assert_eq!(back.interface_snat_pat_collisions_total, 11);
    assert_eq!(back.interface_snat_identity_exhaustion_total, 13);
    assert_eq!(back.interface_snat_sync_identity_conflict_drops_total, 19);
    assert_eq!(back.interface_snat_registry_cap_exhaustion_total, 17);

    // Old-helper compatibility: all four keys absent -> 0, parse still OK.
    let mut obj = value.as_object().expect("object").clone();
    obj.remove("interface_snat_pat_collisions_total");
    obj.remove("interface_snat_identity_exhaustion_total");
    obj.remove("interface_snat_sync_identity_conflict_drops_total");
    obj.remove("interface_snat_registry_cap_exhaustion_total");
    let legacy: ProcessStatus =
        serde_json::from_value(serde_json::Value::Object(obj)).expect("legacy status parses");
    assert_eq!(legacy.interface_snat_pat_collisions_total, 0);
    assert_eq!(legacy.interface_snat_identity_exhaustion_total, 0);
    assert_eq!(legacy.interface_snat_sync_identity_conflict_drops_total, 0);
    assert_eq!(legacy.interface_snat_registry_cap_exhaustion_total, 0);
}

#[test]
fn process_status_nat_reverse_key_shared_displacements_roundtrip() {
    let status = ProcessStatus {
        nat_reverse_key_shared_displacements_total: 7,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["nat_reverse_key_shared_displacements_total"], 7);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.nat_reverse_key_shared_displacements_total, 7);

    // Pre-#1760-W3' payload (key absent) must decode with a zero default.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object")
        .remove("nat_reverse_key_shared_displacements_total")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#1760-W3' payload decodes");
    assert_eq!(legacy.nat_reverse_key_shared_displacements_total, 0);
}

// #1861: round-trip + backward-compat pin for the install-refusal trio
// (transactional session install). The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus counters
// `xpf_userspace_session_create_drops_total` /
// `xpf_userspace_session_install_admission_refused_total` /
// `xpf_userspace_session_install_partial_total` (+ per-worker copies).
#[test]
fn install_refusal_trio_roundtrip_and_key_absent_defaults() {
    let status = ProcessStatus {
        session_create_drops: 7,
        session_install_admission_refused: 5,
        session_install_partial: 1,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["session_create_drops"], 7);
    assert_eq!(value["session_install_admission_refused"], 5);
    assert_eq!(value["session_install_partial"], 1);
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.session_create_drops, 7);
    assert_eq!(back.session_install_admission_refused, 5);
    assert_eq!(back.session_install_partial, 1);

    // Pre-#1861 payload (keys absent) must decode with zero defaults.
    let mut legacy_value =
        serde_json::to_value(ProcessStatus::default()).expect("serialize default ProcessStatus");
    let obj = legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object");
    for key in [
        "session_create_drops",
        "session_install_admission_refused",
        "session_install_partial",
    ] {
        obj.remove(key).expect("new key present before strip");
    }
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#1861 payload decodes");
    assert_eq!(legacy.session_create_drops, 0);
    assert_eq!(legacy.session_install_admission_refused, 0);
    assert_eq!(legacy.session_install_partial, 0);

    // Same contract for the per-worker WorkerRuntimeStatus copies.
    let worker = WorkerRuntimeStatus {
        session_create_drops: 3,
        session_install_admission_refused: 2,
        session_install_partial: 1,
        ..Default::default()
    };
    let value = serde_json::to_value(&worker).expect("serialize WorkerRuntimeStatus to Value");
    assert_eq!(value["session_create_drops"], 3);
    let back: WorkerRuntimeStatus =
        serde_json::from_value(value).expect("deserialize WorkerRuntimeStatus");
    assert_eq!(back.session_create_drops, 3);
    assert_eq!(back.session_install_admission_refused, 2);
    assert_eq!(back.session_install_partial, 1);
    let mut legacy_value = serde_json::to_value(WorkerRuntimeStatus::default())
        .expect("serialize default WorkerRuntimeStatus");
    let obj = legacy_value
        .as_object_mut()
        .expect("WorkerRuntimeStatus serializes to an object");
    for key in [
        "session_create_drops",
        "session_install_admission_refused",
        "session_install_partial",
    ] {
        obj.remove(key).expect("new key present before strip");
    }
    let legacy: WorkerRuntimeStatus =
        serde_json::from_value(legacy_value).expect("pre-#1861 worker payload decodes");
    assert_eq!(legacy.session_create_drops, 0);
    assert_eq!(legacy.session_install_admission_refused, 0);
    assert_eq!(legacy.session_install_partial, 0);
}

// #1621 plan v2 + Copilot code-r1 C4: round-trip the new cold-path
// histogram fields through serde to confirm:
//   1. Default (zero / empty) WorkerRuntimeStatus omits every
//      cold_path_* field from the wire (skip_serializing_if).
//   2. Populated cold_path_* fields survive serialize → deserialize.
//   3. clock_source String preserves "tsc" exactly.
#[test]
fn worker_runtime_status_cold_path_fields_roundtrip_default_omitted() {
    let status = WorkerRuntimeStatus::default();
    let value: serde_json::Value = serde_json::to_value(&status)
        .expect("serialize default WorkerRuntimeStatus");
    // Every cold_path_* field MUST be absent in the JSON for a
    // default (uncalibrated) worker. This pins the wire-invariant
    // contract that pre-#1621 daemons see byte-identical payloads.
    let cold_keys = [
        // #1635 sparse v3 fields.
        "cold_path_layout_version",
        "cold_path_active_slot_ids",
        "cold_path_active_zone_from",
        "cold_path_active_zone_to",
        "cold_path_active_samples",
        "cold_path_active_sum_ns",
        "cold_path_active_buckets",
        "cold_path_active_builder_collision",
        "cold_path_overflow_active",
        "cold_path_sample_phase",
        "cold_path_wrapper_underflow_count",
        "cold_path_ns_per_tsc_q32",
        "cold_path_wrapper_ns_baseline",
        "cold_path_clock_source",
        "cold_path_snapshot_failed",
    ];
    if let Some(obj) = value.as_object() {
        for k in cold_keys {
            assert!(
                !obj.contains_key(k),
                "default WorkerRuntimeStatus must omit {k} on wire; got {value}"
            );
        }
    } else {
        panic!("expected JSON object, got {value:?}");
    }
}

#[test]
fn worker_runtime_status_cold_path_fields_roundtrip_populated() {
    // #1635 sparse v3 encoding: two active zone-pair slots.
    let buckets_a = {
        let mut b = vec![0u64; 48];
        b[5] = 42;
        b[6] = 100;
        b
    };
    let buckets_b = {
        let mut b = vec![0u64; 48];
        b[0] = 7;
        b
    };

    let status = WorkerRuntimeStatus {
        worker_id: 2,
        cold_path_layout_version: 3,
        cold_path_active_slot_ids: vec![0, 5],
        cold_path_active_zone_from: vec![1, 2],
        cold_path_active_zone_to: vec![3, 4],
        cold_path_active_samples: vec![142, 7],
        cold_path_active_sum_ns: vec![12345, 700],
        cold_path_active_buckets: vec![buckets_a.clone(), buckets_b.clone()],
        cold_path_active_builder_collision: vec![false, false],
        cold_path_overflow_active: true,
        cold_path_sample_phase: 50_000,
        cold_path_wrapper_underflow_count: 3,
        cold_path_ns_per_tsc_q32: 1_871_674_289,
        cold_path_wrapper_ns_baseline: 45,
        cold_path_clock_source: "tsc".into(),
        cold_path_snapshot_failed: 2,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize populated");
    // Spot-check a few fields are present + correctly nested.
    assert_eq!(value["cold_path_layout_version"], 3);
    assert_eq!(value["cold_path_sample_phase"], 50_000);
    assert_eq!(value["cold_path_clock_source"], "tsc");
    assert_eq!(value["cold_path_snapshot_failed"], 2);
    assert_eq!(value["cold_path_active_zone_from"][0], 1);
    assert_eq!(value["cold_path_active_zone_to"][1], 4);
    assert_eq!(value["cold_path_active_samples"][0], 142);
    assert_eq!(value["cold_path_active_buckets"][0][5], 42);
    assert_eq!(value["cold_path_active_buckets"][0][6], 100);
    assert_eq!(value["cold_path_overflow_active"], true);

    // Round-trip back.
    let back: WorkerRuntimeStatus =
        serde_json::from_value(value).expect("deserialize");
    assert_eq!(back.cold_path_layout_version, 3);
    assert_eq!(back.cold_path_active_slot_ids, vec![0, 5]);
    assert_eq!(back.cold_path_active_zone_from, vec![1, 2]);
    assert_eq!(back.cold_path_active_zone_to, vec![3, 4]);
    assert_eq!(back.cold_path_active_samples, vec![142, 7]);
    assert_eq!(back.cold_path_active_sum_ns, vec![12345, 700]);
    assert_eq!(back.cold_path_active_buckets, vec![buckets_a, buckets_b]);
    assert_eq!(back.cold_path_active_builder_collision, vec![false, false]);
    assert!(back.cold_path_overflow_active);
    assert_eq!(back.cold_path_sample_phase, 50_000);
    assert_eq!(back.cold_path_wrapper_underflow_count, 3);
    assert_eq!(back.cold_path_ns_per_tsc_q32, 1_871_674_289);
    assert_eq!(back.cold_path_wrapper_ns_baseline, 45);
    assert_eq!(back.cold_path_clock_source, "tsc");
    assert_eq!(back.cold_path_snapshot_failed, 2);
}

// #1782 Step-1: round-trip + backward-compat (key-absent) pin for the
// cold-start CoS instruments on WorkerRuntimeStatus. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus families
// xpf_userspace_worker_cos_wheel_ticks_advanced_{total,max} and
// xpf_userspace_worker_cos_queue_lease_undergrant_total{cause}.
#[test]
fn worker_runtime_status_cos_coldstart_counters_roundtrip() {
    let status = WorkerRuntimeStatus {
        cos_wheel_ticks_advanced_total: 1_000_001,
        cos_wheel_ticks_advanced_max: 999_999,
        cos_queue_lease_undergrant_seqlock_give_up: 1,
        cos_queue_lease_undergrant_cap_zero: 2,
        cos_queue_lease_undergrant_epoch_rotated: 3,
        cos_queue_lease_undergrant_share_exhausted: 4,
        cos_queue_lease_undergrant_class_cap: 5,
        cos_queue_lease_undergrant_outstanding_cap: 6,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize WorkerRuntimeStatus to Value");
    let keys = [
        ("cos_wheel_ticks_advanced_total", 1_000_001u64),
        ("cos_wheel_ticks_advanced_max", 999_999),
        ("cos_queue_lease_undergrant_seqlock_give_up", 1),
        ("cos_queue_lease_undergrant_cap_zero", 2),
        ("cos_queue_lease_undergrant_epoch_rotated", 3),
        ("cos_queue_lease_undergrant_share_exhausted", 4),
        ("cos_queue_lease_undergrant_class_cap", 5),
        ("cos_queue_lease_undergrant_outstanding_cap", 6),
    ];
    for (key, want) in keys {
        assert_eq!(value[key], want, "wire key {key}");
    }
    let back: WorkerRuntimeStatus =
        serde_json::from_value(value).expect("deserialize WorkerRuntimeStatus");
    assert_eq!(back.cos_wheel_ticks_advanced_total, 1_000_001);
    assert_eq!(back.cos_wheel_ticks_advanced_max, 999_999);
    assert_eq!(back.cos_queue_lease_undergrant_seqlock_give_up, 1);
    assert_eq!(back.cos_queue_lease_undergrant_cap_zero, 2);
    assert_eq!(back.cos_queue_lease_undergrant_epoch_rotated, 3);
    assert_eq!(back.cos_queue_lease_undergrant_share_exhausted, 4);
    assert_eq!(back.cos_queue_lease_undergrant_class_cap, 5);
    assert_eq!(back.cos_queue_lease_undergrant_outstanding_cap, 6);

    // Pre-#1782-Step-1 payload (keys absent) must decode with zero
    // defaults — the mixed-version back-compat contract.
    let mut legacy_value = serde_json::to_value(WorkerRuntimeStatus::default())
        .expect("serialize default WorkerRuntimeStatus");
    for (key, _) in keys {
        legacy_value
            .as_object_mut()
            .expect("WorkerRuntimeStatus serializes to an object")
            .remove(key)
            .unwrap_or_else(|| panic!("new key {key} present before strip"));
    }
    let legacy: WorkerRuntimeStatus =
        serde_json::from_value(legacy_value).expect("pre-Step-1 payload decodes");
    assert_eq!(legacy.cos_wheel_ticks_advanced_total, 0);
    assert_eq!(legacy.cos_wheel_ticks_advanced_max, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_seqlock_give_up, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_cap_zero, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_epoch_rotated, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_share_exhausted, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_class_cap, 0);
    assert_eq!(legacy.cos_queue_lease_undergrant_outstanding_cap, 0);
}

#[test]
fn source_nat_persistent_fields_roundtrip() {
    let rule = SourceNATRuleSnapshot {
        name: "snat".into(),
        pool_name: "pool1".into(),
        persistent_nat: true,
        persistent_nat_permit_any_remote_host: true,
        persistent_nat_inactivity_timeout: 600,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&rule).expect("serialize SourceNATRuleSnapshot");
    assert_eq!(value["persistent_nat"], true);
    assert_eq!(value["persistent_nat_permit_any_remote_host"], true);
    assert_eq!(value["persistent_nat_inactivity_timeout"], 600);
    let back: SourceNATRuleSnapshot =
        serde_json::from_value(value).expect("deserialize SourceNATRuleSnapshot");
    assert!(back.persistent_nat);
    assert!(back.persistent_nat_permit_any_remote_host);
    assert_eq!(back.persistent_nat_inactivity_timeout, 600);
}

#[test]
fn process_status_source_nat_pool_status_roundtrip() {
    let status = ProcessStatus {
        source_nat_pools: vec![SourceNatPoolStatus {
            rule_name: "snat".into(),
            pool_name: "pool1".into(),
            persistent_nat: true,
            live_flows: 2,
            used_ports: 1,
            persistent_leases: 1,
            allocations_total: 1,
            reuses_total: 3,
            exhaustion_total: 5,
            ..Default::default()
        }],
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus");
    assert_eq!(value["source_nat_pools"][0]["pool_name"], "pool1");
    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.source_nat_pools.len(), 1);
    assert_eq!(back.source_nat_pools[0].exhaustion_total, 5);
}

#[test]
fn inject_packet_request_tuple_metadata_wire_roundtrip() {
    let req = InjectPacketRequest {
        slot: 7,
        packet_length: 128,
        addr_family: libc::AF_INET as u8,
        protocol: 1,
        config_generation: 11,
        fib_generation: 12,
        metadata_valid: true,
        destination_ip: "172.16.80.200".into(),
        emit_on_wire: true,
        tuple_metadata_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
        source_ip: "172.16.80.8".into(),
        source_port: Some(4660),
        destination_port: Some(0),
    };
    let value: serde_json::Value =
        serde_json::to_value(&req).expect("serialize InjectPacketRequest to Value");
    let obj = value
        .as_object()
        .expect("InjectPacketRequest serializes as object");
    for key in [
        "tuple_metadata_version",
        "source_ip",
        "source_port",
        "destination_port",
    ] {
        assert!(
            obj.contains_key(key),
            "InjectPacketRequest wire key `{key}` missing: {value}"
        );
    }
    let back: InjectPacketRequest =
        serde_json::from_value(value).expect("deserialize InjectPacketRequest");
    assert_eq!(
        back.tuple_metadata_version,
        INJECT_PACKET_TUPLE_PROTOCOL_VERSION
    );
    assert_eq!(back.source_ip, "172.16.80.8");
    assert_eq!(back.source_port, Some(4660));
    assert_eq!(back.destination_port, Some(0));
}

#[test]
fn inject_packet_request_legacy_tuple_metadata_defaults_absent() {
    let legacy_json = r#"{
        "slot": 7,
        "packet_length": 128,
        "addr_family": 2,
        "protocol": 1,
        "metadata_valid": true,
        "destination_ip": "172.16.80.200",
        "emit_on_wire": true
    }"#;
    let req: InjectPacketRequest =
        serde_json::from_str(legacy_json).expect("legacy InjectPacketRequest decodes");
    assert_eq!(req.tuple_metadata_version, 0);
    assert_eq!(req.source_ip, "");
    assert_eq!(req.source_port, None);
    assert_eq!(req.destination_port, None);
}

// #825 plan §3.9 test #5: wire-format round-trip for
// BindingStatus. Construct with non-zero values on all four
// kick-latency fields, serialize, deserialize, assert equality.
// Companion to the BindingCountersSnapshot round-trip test in
// main.rs::tx_latency_hist_serialization_roundtrip — covers
// the rich BindingStatus wire shape that
// BindingCountersSnapshot projects from.
#[test]
fn tx_kick_latency_binding_status_wire_roundtrip() {
    let status = BindingStatus {
        worker_id: 3,
        slot: 7,
        ifindex: 11,
        queue_id: 2,
        tx_kick_latency_hist: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        tx_kick_latency_count: 136,
        tx_kick_latency_sum_ns: 1_234_567,
        tx_kick_retry_count: 42,
        ..Default::default()
    };

    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(back.tx_kick_latency_hist, status.tx_kick_latency_hist);
    assert_eq!(back.tx_kick_latency_count, status.tx_kick_latency_count);
    assert_eq!(back.tx_kick_latency_sum_ns, status.tx_kick_latency_sum_ns);
    assert_eq!(back.tx_kick_retry_count, status.tx_kick_retry_count);
}

// #825 plan §3.9 test #5: pre-#825 JSON payload — fields absent
// — must deserialize with the four kick-latency fields defaulted
// to empty Vec / zero u64. This pins the additive-wire contract
// at the rich BindingStatus layer; the projection into
// BindingCountersSnapshot inherits the same defaulting.
#[test]
fn tx_kick_latency_binding_status_backward_compat() {
    // Minimum plausible BindingStatus payload predating #825.
    // All four kick-latency fields absent.
    let legacy_json = r#"{
        "worker_id": 1,
        "slot": 0,
        "ifindex": 0,
        "queue_id": 0
    }"#;
    let status: BindingStatus =
        serde_json::from_str(legacy_json).expect("pre-#825 payload decodes");
    assert!(
        status.tx_kick_latency_hist.is_empty(),
        "pre-#825 payload must default to empty Vec<u64>",
    );
    assert_eq!(status.tx_kick_latency_count, 0);
    assert_eq!(status.tx_kick_latency_sum_ns, 0);
    assert_eq!(status.tx_kick_retry_count, 0);
}

// #825 plan §3.9 test #5 final clause: From<&BindingStatus>
// propagates the four kick-latency fields onto
// BindingCountersSnapshot — pin that the projection doesn't
// silently drop any of them.
#[test]
fn tx_kick_latency_from_binding_status_propagates() {
    let status = BindingStatus {
        worker_id: 5,
        queue_id: 3,
        tx_kick_latency_hist: vec![100, 200, 300],
        tx_kick_latency_count: 600,
        tx_kick_latency_sum_ns: 987_654,
        tx_kick_retry_count: 7,
        ..Default::default()
    };

    let snap: BindingCountersSnapshot = (&status).into();
    assert_eq!(snap.tx_kick_latency_hist, status.tx_kick_latency_hist);
    assert_eq!(snap.tx_kick_latency_count, status.tx_kick_latency_count);
    assert_eq!(snap.tx_kick_latency_sum_ns, status.tx_kick_latency_sum_ns);
    assert_eq!(snap.tx_kick_retry_count, status.tx_kick_retry_count);
}

// #1241: pin the TX completion-ring availability wire keys at the
// rich BindingStatus layer and the lean BindingCountersSnapshot
// projection. Missing keys would decode as zeros on the Go side,
// exactly the failure mode this telemetry is meant to avoid before
// full fairness measurements.
#[test]
fn tx_completion_ring_binding_status_wire_roundtrip() {
    let status = BindingStatus {
        worker_id: 3,
        slot: 7,
        ifindex: 11,
        queue_id: 2,
        tx_completion_ring_available: 17,
        tx_completion_ring_available_max: 29,
        ..Default::default()
    };

    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let value: serde_json::Value =
        serde_json::from_str(&json).expect("deserialize BindingStatus JSON");
    assert_eq!(value["tx_completion_ring_available"], 17);
    assert_eq!(value["tx_completion_ring_available_max"], 29);

    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(back.tx_completion_ring_available, 17);
    assert_eq!(back.tx_completion_ring_available_max, 29);
}

#[test]
fn tx_completion_ring_from_binding_status_propagates() {
    let status = BindingStatus {
        worker_id: 5,
        queue_id: 3,
        tx_completion_ring_available: 31,
        tx_completion_ring_available_max: 47,
        ..Default::default()
    };

    let snap: BindingCountersSnapshot = (&status).into();
    assert_eq!(
        snap.tx_completion_ring_available,
        status.tx_completion_ring_available
    );
    assert_eq!(
        snap.tx_completion_ring_available_max,
        status.tx_completion_ring_available_max
    );
}

#[test]
fn flow_cache_capacity_binding_status_wire_roundtrip_and_projection() {
    let status = BindingStatus {
        worker_id: 3,
        slot: 7,
        ifindex: 11,
        queue_id: 2,
        active_flow_count: 53,
        flow_cache_capacity: 4096,
        ..Default::default()
    };

    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus to Value");
    assert_eq!(value["flow_cache_capacity"], 4096);

    let back: BindingStatus = serde_json::from_value(value).expect("deserialize BindingStatus");
    assert_eq!(back.flow_cache_capacity, status.flow_cache_capacity);

    let snap: BindingCountersSnapshot = (&status).into();
    assert_eq!(snap.active_flow_count, status.active_flow_count);
    assert_eq!(snap.flow_cache_capacity, status.flow_cache_capacity);
}

#[test]
fn mirror_counters_binding_status_wire_roundtrip_and_projection() {
    let status = BindingStatus {
        worker_id: 7,
        slot: 1,
        ifindex: 11,
        queue_id: 2,
        mirrored_packets: 5,
        mirrored_bytes: 640,
        mirror_drops_no_frame: 1,
        mirror_drops_tx_frame_reserve: 2,
        mirror_drops_no_binding: 3,
        mirror_drops_queue_full: 4,
        ..Default::default()
    };

    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus to Value");
    let obj = value
        .as_object()
        .expect("BindingStatus serializes as a JSON object");
    for key in [
        "mirrored_packets",
        "mirrored_bytes",
        "mirror_drops_no_frame",
        "mirror_drops_tx_frame_reserve",
        "mirror_drops_no_binding",
        "mirror_drops_queue_full",
    ] {
        assert!(
            obj.contains_key(key),
            "BindingStatus wire key `{key}` missing: {value}"
        );
    }

    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(back.mirrored_packets, status.mirrored_packets);
    assert_eq!(back.mirrored_bytes, status.mirrored_bytes);
    assert_eq!(back.mirror_drops_no_frame, status.mirror_drops_no_frame);
    assert_eq!(
        back.mirror_drops_tx_frame_reserve,
        status.mirror_drops_tx_frame_reserve
    );
    assert_eq!(back.mirror_drops_no_binding, status.mirror_drops_no_binding);
    assert_eq!(back.mirror_drops_queue_full, status.mirror_drops_queue_full);

    let snap: BindingCountersSnapshot = (&status).into();
    assert_eq!(snap.mirrored_packets, status.mirrored_packets);
    assert_eq!(snap.mirrored_bytes, status.mirrored_bytes);
    assert_eq!(snap.mirror_drops_no_frame, status.mirror_drops_no_frame);
    assert_eq!(
        snap.mirror_drops_tx_frame_reserve,
        status.mirror_drops_tx_frame_reserve
    );
    assert_eq!(snap.mirror_drops_no_binding, status.mirror_drops_no_binding);
    assert_eq!(snap.mirror_drops_queue_full, status.mirror_drops_queue_full);
}

#[test]
fn syn_cookie_counters_binding_status_wire_roundtrip() {
    let status = BindingStatus {
        worker_id: 7,
        slot: 1,
        ifindex: 11,
        queue_id: 2,
        syn_cookie_challenges: 3,
        syn_cookie_secret_unavailable: 5,
        syn_cookie_syn_ack_sent: 7,
        syn_cookie_ack_rst_sent: 11,
        syn_cookie_reply_budget_drops: 13,
        syn_cookie_ack_valid: 17,
        syn_cookie_ack_invalid: 19,
        syn_cookie_bypass: 23,
        ..Default::default()
    };

    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus to Value");
    let obj = value
        .as_object()
        .expect("BindingStatus serializes as a JSON object");
    for key in [
        "syn_cookie_challenges",
        "syn_cookie_secret_unavailable",
        "syn_cookie_syn_ack_sent",
        "syn_cookie_ack_rst_sent",
        "syn_cookie_reply_budget_drops",
        "syn_cookie_ack_valid",
        "syn_cookie_ack_invalid",
        "syn_cookie_bypass",
    ] {
        assert!(
            obj.contains_key(key),
            "BindingStatus wire key `{key}` missing: {value}"
        );
    }

    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(back.syn_cookie_challenges, status.syn_cookie_challenges);
    assert_eq!(
        back.syn_cookie_secret_unavailable,
        status.syn_cookie_secret_unavailable
    );
    assert_eq!(back.syn_cookie_syn_ack_sent, status.syn_cookie_syn_ack_sent);
    assert_eq!(back.syn_cookie_ack_rst_sent, status.syn_cookie_ack_rst_sent);
    assert_eq!(
        back.syn_cookie_reply_budget_drops,
        status.syn_cookie_reply_budget_drops
    );
    assert_eq!(back.syn_cookie_ack_valid, status.syn_cookie_ack_valid);
    assert_eq!(back.syn_cookie_ack_invalid, status.syn_cookie_ack_invalid);
    assert_eq!(back.syn_cookie_bypass, status.syn_cookie_bypass);
}

// #943 Copilot round-2 finding #3: the rich BindingStatus wire
// shape carries the two new V_min fields, but nothing pinned
// their wire keys at this layer. A future serde-rename typo
// would silently project as zeros into the Go consumer (which
// tolerates unknown fields). Round-trip + key-presence catches
// both directions of the contract here.
#[test]
fn v_min_throttle_binding_status_wire_roundtrip() {
    let status = BindingStatus {
        worker_id: 9,
        slot: 1,
        ifindex: 4,
        queue_id: 6,
        v_min_throttle_hard_cap_overrides: 71,
        v_min_throttles: 73,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus to Value");
    let obj = value
        .as_object()
        .expect("BindingStatus serializes as a JSON object");
    for key in ["v_min_throttle_hard_cap_overrides", "v_min_throttles"] {
        assert!(
            obj.contains_key(key),
            "BindingStatus wire key `{key}` missing: {value}"
        );
    }
    let json = serde_json::to_string(&status).expect("serialize BindingStatus");
    let back: BindingStatus = serde_json::from_str(&json).expect("deserialize BindingStatus");
    assert_eq!(
        back.v_min_throttle_hard_cap_overrides,
        status.v_min_throttle_hard_cap_overrides
    );
    assert_eq!(back.v_min_throttles, status.v_min_throttles);
}

#[test]
fn policy_rule_snapshot_scheduler_fields_round_trip() {
    let snap = PolicyRuleSnapshot {
        rule_id: "security-policy:trust:untrust:allow-web".into(),
        policy_id: 17,
        name: "allow-web".into(),
        from_zone: "trust".into(),
        to_zone: "untrust".into(),
        scheduler_name: "workhours".into(),
        inactive: true,
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["junos-http".into()],
        action: "permit".into(),
        ..Default::default()
    };

    let value: serde_json::Value =
        serde_json::to_value(&snap).expect("serialize PolicyRuleSnapshot to Value");
    assert_eq!(value["rule_id"], "security-policy:trust:untrust:allow-web");
    assert_eq!(value["policy_id"], 17);
    assert_eq!(value["scheduler_name"], "workhours");
    assert_eq!(value["inactive"], true);

    let back: PolicyRuleSnapshot =
        serde_json::from_value(value).expect("deserialize PolicyRuleSnapshot");
    assert_eq!(back.rule_id, snap.rule_id);
    assert_eq!(back.policy_id, snap.policy_id);
    assert_eq!(back.scheduler_name, snap.scheduler_name);
    assert_eq!(back.inactive, snap.inactive);
}

#[test]
fn policy_rule_snapshot_legacy_scheduler_fields_default() {
    let legacy_json = r#"{
        "name": "allow-web",
        "from_zone": "trust",
        "to_zone": "untrust",
        "source_addresses": ["any"],
        "destination_addresses": ["any"],
        "applications": ["junos-http"],
        "action": "permit"
    }"#;

    let snap: PolicyRuleSnapshot =
        serde_json::from_str(legacy_json).expect("pre-#1378 PolicyRuleSnapshot decodes");
    assert_eq!(snap.rule_id, "");
    assert_eq!(snap.policy_id, 0);
    assert_eq!(snap.scheduler_name, "");
    assert_eq!(snap.inactive, false);
}

// #915 forward-compat: a pre-#915 CoSSchedulerSnapshot
// payload (no `surplus_sharing` field) must decode with
// `surplus_sharing == false` so the runtime sees the field
// as absent = opt-out, preserving Junos `transmit-rate
// exact` hard-cap semantics for older snapshot writers.
// Codex round-1 MAJOR 3 + Gemini round-1 #7.
#[test]
fn cos_scheduler_snapshot_surplus_sharing_default_false() {
    let legacy_json = r#"{
        "name": "iperf-a",
        "transmit_rate_bytes": 125000000,
        "transmit_rate_exact": true,
        "priority": "low",
        "buffer_size_bytes": 65536
    }"#;
    let snap: CoSSchedulerSnapshot =
        serde_json::from_str(legacy_json).expect("pre-#915 CoSSchedulerSnapshot decodes");
    assert_eq!(
        snap.surplus_sharing, false,
        "surplus_sharing must default to false for pre-#915 snapshots"
    );
    assert_eq!(
        snap.equal_flow_enforcement, false,
        "equal_flow_enforcement must default to false for older snapshots"
    );
    assert_eq!(
        snap.buffer_size_percent, 0.0,
        "buffer_size_percent must default to 0 for pre-#1336 snapshots"
    );
    assert_eq!(snap.transmit_rate_exact, true);
}

#[test]
fn cos_scheduler_snapshot_surplus_sharing_round_trip_true() {
    let snap = CoSSchedulerSnapshot {
        name: "iperf-a".into(),
        transmit_rate_bytes: 125_000_000,
        transmit_rate_percent: 0.0,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 65_536,
        buffer_size_percent: 0.0,
        surplus_sharing: true,
        equal_flow_enforcement: false,
        equal_flow_target_policy: String::new(),
    codel_target_ns: 0,
        ..Default::default()
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.surplus_sharing, true);
}

#[test]
fn cos_scheduler_snapshot_equal_flow_enforcement_round_trip_true() {
    let snap = CoSSchedulerSnapshot {
        name: "iperf-a".into(),
        transmit_rate_bytes: 125_000_000,
        transmit_rate_percent: 0.0,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 65_536,
        buffer_size_percent: 0.0,
        surplus_sharing: false,
        equal_flow_enforcement: true,
        equal_flow_target_policy: String::new(),
    codel_target_ns: 0,
        ..Default::default()
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.equal_flow_enforcement, true);
}

#[test]
fn cos_scheduler_snapshot_equal_flow_target_policy_round_trip() {
    // #1746: policy string survives the wire; absent field (older
    // snapshots / unset configs) decodes to the empty default, and an
    // unset policy serializes WITHOUT the field on the Go side
    // (omitempty) — the Rust serde default keeps decode compatible.
    let snap = CoSSchedulerSnapshot {
        name: "iperf-a".into(),
        transmit_rate_bytes: 125_000_000,
        transmit_rate_percent: 0.0,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 65_536,
        buffer_size_percent: 0.0,
        surplus_sharing: false,
        equal_flow_enforcement: true,
        equal_flow_target_policy: "mean".into(),
        codel_target_ns: 0,
        ..Default::default()
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.equal_flow_target_policy, "mean");

    // Older snapshot without the field decodes to the default "".
    let legacy = r#"{"name":"iperf-a","transmit_rate_bytes":125000000,"transmit_rate_exact":true,"equal_flow_enforcement":true}"#;
    let back: CoSSchedulerSnapshot = serde_json::from_str(legacy).expect("legacy deserialize");
    assert_eq!(back.equal_flow_target_policy, "");
}

#[test]
fn cos_scheduler_snapshot_buffer_size_percent_round_trip() {
    let snap = CoSSchedulerSnapshot {
        name: "percent-sched".into(),
        transmit_rate_bytes: 125_000_000,
        transmit_rate_percent: 0.0,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 0,
        buffer_size_percent: 10.0,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: String::new(),
    codel_target_ns: 0,
        ..Default::default()
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    assert!(
        json.contains("buffer_size_percent"),
        "percent field must be present in serialized scheduler JSON: {}",
        json
    );
    let back: CoSSchedulerSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.buffer_size_percent, 10.0);
    assert_eq!(back.buffer_size_bytes, 0);
}

// #943 additive-wire contract: a pre-#943 BindingStatus payload
// with both V_min fields absent must decode with zero defaults,
// matching the same defaulting pattern the kick-latency fields
// use above. Without this, the projection's `..Default::default`
// would compile but the wire side could silently break.
#[test]
fn v_min_throttle_binding_status_backward_compat() {
    let legacy_json = r#"{
        "worker_id": 1,
        "slot": 0,
        "ifindex": 0,
        "queue_id": 0
    }"#;
    let status: BindingStatus =
        serde_json::from_str(legacy_json).expect("pre-#943 payload decodes");
    assert_eq!(status.v_min_throttle_hard_cap_overrides, 0);
    assert_eq!(status.v_min_throttles, 0);
}

// #2008 M5: the application-identification catalog must decode from the Go
// snapshot's `app_catalog` field with the exact field names the Go side emits.
#[test]
fn config_snapshot_decodes_app_catalog() {
    let json = r#"{
        "version": 3,
        "generation": 1,
        "generated_at": "2024-01-01T00:00:00Z",
        "summary": {"host_name":"h","dataplane_type":"userspace","interface_count":0,
                    "zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false},
        "app_catalog": [
            {"app_id": 7, "protocol": 6, "dst_port_low": 443, "dst_port_high": 443},
            {"app_id": 9, "protocol": 6, "dst_port_low": 9000, "dst_port_high": 9100,
             "src_port_low": 1024, "src_port_high": 65535},
            {"app_id": 3, "protocol": 1}
        ]
    }"#;
    let snap: ConfigSnapshot = serde_json::from_str(json).expect("decode snapshot");
    assert_eq!(snap.app_catalog.len(), 3);
    assert_eq!(snap.app_catalog[0].app_id, 7);
    assert_eq!(snap.app_catalog[0].protocol, 6);
    assert_eq!(snap.app_catalog[0].dst_port_high, 443);
    assert_eq!(snap.app_catalog[1].src_port_high, 65535);
    // Protocol-only ICMP entry: ports default to 0.
    assert_eq!(snap.app_catalog[2].app_id, 3);
    assert_eq!(snap.app_catalog[2].protocol, 1);
    assert_eq!(snap.app_catalog[2].dst_port_low, 0);
}

// HA/upgrade compat: a snapshot from an OLD Go binary that does not know the
// app_catalog field must still decode (serde(default) -> empty vec), not abort
// the whole apply (the #1961 failure class).
#[test]
fn config_snapshot_decodes_without_app_catalog() {
    let json = r#"{
        "version": 3,
        "generation": 1,
        "generated_at": "2024-01-01T00:00:00Z",
        "summary": {"host_name":"h","dataplane_type":"userspace","interface_count":0,
                    "zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false}
    }"#;
    let snap: ConfigSnapshot = serde_json::from_str(json).expect("decode old snapshot");
    assert!(snap.app_catalog.is_empty(),
        "snapshot without app_catalog must decode to an empty catalog (HA/upgrade compat)");
}

// #3909 (MEDIUM, secret exposure): the SYN-cookie master key is the secret
// that makes XDP-generated SYN-ACK cookies unforgeable. It must be
// `skip_serializing`, exactly like the WireGuard private key / PSK, so it never
// lands in `state.json` (written world-readable 0644 by write_state). A local
// unprivileged reader of that file could otherwise forge valid SYN cookies and
// defeat SYN-flood source validation.
//
// FAIL-ON-REVERT: remove `skip_serializing` from
// ConfigSnapshot::syn_cookie_master_key and this test goes RED — the field name
// and the key bytes reappear in the serialized world-readable snapshot.
#[test]
fn syn_cookie_master_key_is_skipped_in_state_snapshot() {
    let snap = ConfigSnapshot {
        syn_cookie_master_key: "0badc0ffee0badc0ffee0badc0ffee42".into(),
        ..Default::default()
    };
    let json = serde_json::to_string(&snap).expect("serialize snapshot");
    assert!(
        !json.contains("syn_cookie_master_key"),
        "syn_cookie_master_key field must be skip_serializing, got: {json}"
    );
    assert!(
        !json.contains("0badc0ffee"),
        "syn_cookie_master_key value must not appear in the world-readable snapshot"
    );

    // Control-socket delivery (apply_snapshot) still populates the key via the
    // `default` path, so a valid key is present after a restart re-push — SYN
    // cookie source validation keeps working.
    let with_key = r#"{
        "version": 3,
        "generation": 1,
        "generated_at": "2024-01-01T00:00:00Z",
        "summary": {"host_name":"h","dataplane_type":"userspace","interface_count":0,
                    "zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false},
        "syn_cookie_master_key": "00112233445566778899aabbccddeeff"
    }"#;
    let parsed: ConfigSnapshot = serde_json::from_str(with_key).expect("decode snapshot with key");
    assert_eq!(
        parsed.syn_cookie_master_key, "00112233445566778899aabbccddeeff",
        "control-plane delivery must still populate the key on deserialize"
    );
}

// #2214 (HIGH, #1961-class): a NAT64 rule with no resolvable source pool makes
// the Go builder emit `pool_addresses:null` (nil slice, no `,omitempty`). Plain
// `#[serde(default)]` only fills an ABSENT key; an explicit null is still handed
// to `Vec<String>::deserialize`, which rejects it ("invalid type: null,
// expected a sequence") and aborts the ENTIRE ConfigSnapshot decode -> helper
// EOF -> enabled:false -> NO TRANSIT. These tests pin the null-tolerant decoder
// so a mixed-version Go binary that still emits null decodes cleanly.
//
// FAIL-ON-REVERT: drop the `deserialize_with = "crate::protocol::null_tolerant_vec"`
// attribute on NAT64RuleSnapshot.pool_addresses / FirewallFilterSnapshot.terms
// and the two `*_null` snapshot tests below fail with the serde "expected a
// sequence" error — i.e. the whole snapshot decode aborts, exactly the
// no-transit signature.
#[test]
fn nat64_rule_snapshot_tolerates_null_pool_addresses() {
    // An explicit null (not absent) must decode to an empty Vec, not error.
    let json = r#"{"name":"rs1","prefix":"64:ff9b::/96","pool_addresses":null}"#;
    let rule: NAT64RuleSnapshot =
        serde_json::from_str(json).expect("NAT64 rule with pool_addresses:null must decode (#2214)");
    assert_eq!(rule.name, "rs1");
    assert_eq!(rule.prefix, "64:ff9b::/96");
    assert!(
        rule.pool_addresses.is_empty(),
        "pool_addresses:null must decode to an empty Vec"
    );
    // Absent key (omitempty path) still works.
    let absent: NAT64RuleSnapshot =
        serde_json::from_str(r#"{"name":"rs1","prefix":"64:ff9b::/96"}"#)
            .expect("NAT64 rule with absent pool_addresses must decode");
    assert!(absent.pool_addresses.is_empty());
    // A populated array still round-trips.
    let full: NAT64RuleSnapshot = serde_json::from_str(
        r#"{"name":"rs1","prefix":"64:ff9b::/96","pool_addresses":["192.0.2.1","192.0.2.2"]}"#,
    )
    .expect("populated pool_addresses must decode");
    assert_eq!(full.pool_addresses, vec!["192.0.2.1", "192.0.2.2"]);
}

#[test]
fn firewall_filter_snapshot_tolerates_null_terms() {
    let json = r#"{"name":"EMPTY","family":"inet","terms":null}"#;
    let filter: FirewallFilterSnapshot =
        serde_json::from_str(json).expect("filter with terms:null must decode (#2214)");
    assert_eq!(filter.name, "EMPTY");
    assert_eq!(filter.family, "inet");
    assert!(filter.terms.is_empty(), "terms:null must decode to an empty Vec");
    // Absent key still works.
    let absent: FirewallFilterSnapshot =
        serde_json::from_str(r#"{"name":"EMPTY","family":"inet"}"#)
            .expect("filter with absent terms must decode");
    assert!(absent.terms.is_empty());
    // Populated terms still round-trip.
    let full: FirewallFilterSnapshot = serde_json::from_str(
        r#"{"name":"F","family":"inet","terms":[{"name":"t1","action":"accept"}]}"#,
    )
    .expect("populated terms must decode");
    assert_eq!(full.terms.len(), 1);
    assert_eq!(full.terms[0].name, "t1");
    assert_eq!(full.terms[0].action, "accept");
}

// The whole-snapshot guarantee: a ConfigSnapshot whose nat64_rules[].pool_addresses
// AND filters[].terms are both explicit null must STILL decode in full (no abort).
// This is the no-transit-prevention test — pre-fix this returned a serde error,
// which is exactly the failure the Go side sees as helper EOF / enabled:false.
#[test]
fn config_snapshot_decodes_with_null_collections_2214() {
    let json = r#"{
        "version": 3,
        "generation": 1,
        "generated_at": "2024-01-01T00:00:00Z",
        "summary": {"host_name":"h","dataplane_type":"userspace","interface_count":0,
                    "zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false},
        "nat64_rules": [
            {"name":"rs1","prefix":"64:ff9b::/96","pool_addresses":null}
        ],
        "filters": [
            {"name":"EMPTY","family":"inet","terms":null}
        ]
    }"#;
    let snap: ConfigSnapshot = serde_json::from_str(json)
        .expect("snapshot with null pool_addresses + null terms must decode in full (#2214 no-transit)");
    assert_eq!(snap.nat64_rules.len(), 1);
    assert!(snap.nat64_rules[0].pool_addresses.is_empty());
    assert_eq!(snap.filters.len(), 1);
    assert!(snap.filters[0].terms.is_empty());
}

#[test]
fn app_catalog_entry_roundtrip() {
    let e = AppCatalogEntry {
        app_id: 42,
        protocol: 17,
        dst_port_low: 53,
        dst_port_high: 53,
        src_port_low: 0,
        src_port_high: 0,
    };
    let v = serde_json::to_value(&e).expect("serialize");
    assert_eq!(v["app_id"], 42);
    assert_eq!(v["protocol"], 17);
    let back: AppCatalogEntry = serde_json::from_value(v).expect("deserialize");
    assert_eq!(back.app_id, 42);
    assert_eq!(back.dst_port_low, 53);
}

// ---------------------------------------------------------------------------
// #1325: differential wire-format invariant.
//
// Builds a fixed-shape JSON document by serializing
// `Default::default()` instances of every top-level wire type, and
// compares against a checked-in fixture at
// `tests/fixtures/protocol_wire_v1.json`. The fixture is committed
// alongside this test; a future wire-evolving PR has to either
// regenerate the fixture (XPF_PROTOCOL_WIRE_REGEN=1) and review the
// diff, or fail the test.
//
// Scope vs #1325 plan v3: the plan called for an exhaustive
// struct-literal-driven specimen tree. That approach hit ~1000
// LOC of boilerplate that proved fragile to incremental field
// changes mid-implementation. The simpler Default-based approach
// here detects:
//   - any #[serde(rename = ...)] field-key change (key set must match)
//   - any field added without `skip_serializing_if` (new key)
//   - any field removed (missing key)
// Residual gap (fields with `skip_serializing_if = "Option::is_none"`
// defaulting to None) is covered by the inline serde round-trip
// tests above (which DO populate the high-risk types) plus the Go
// control-plane consumption gate.
// ---------------------------------------------------------------------------

// #3651: the per-zone traffic block round-trips both directions and a
// default (no per-zone data) ProcessStatus omits the layout-version /
// overflow keys. The Go mirror lives in
// pkg/dataplane/userspace/zone_counters_status_test.go.
/// #6947: both per-zone blocks are OMITTED when empty and PRESENT when
/// populated.
///
/// The two halves are load-bearing together. "The key is absent" alone is
/// satisfied by a field that never serializes at all, so the populated half is
/// what proves the omission is conditional rather than total — that is the
/// difference between this fix and a silent wire regression that drops real
/// counters.
///
/// Before this, both fields carried `default` but not
/// `skip_serializing_if = "Vec::is_empty"`, so the helper put
/// `"zone_traffic_counters":[]` and `"zone_flood_counters":[]` on the shared
/// control socket on every 1/s status poll, forever, on a firewall that had
/// never populated either — while their sibling scalars in the same struct,
/// and both Go mirrors (`json:"...,omitempty"`), already omitted.
#[test]
fn zone_counter_blocks_omitted_when_empty_present_when_populated_6947() {
    let empty = serde_json::to_string(&ProcessStatus::default()).expect("serialize default");
    for key in ["zone_traffic_counters", "zone_flood_counters"] {
        assert!(
            !empty.contains(key),
            "default ProcessStatus still emits {key} — an empty array on the shared \
             control socket every poll, which the Go mirror already omits (#6947): {empty}"
        );
    }

    let mut status = ProcessStatus::default();
    status.zone_traffic_counters = vec![ZoneTrafficCounterStatus {
        zone_id: 40000,
        ingress_packets: 1,
        ingress_bytes: 2,
        egress_packets: 3,
        egress_bytes: 4,
    }];
    status.zone_flood_counters = vec![ZoneFloodCounterStatus::default()];
    let populated = serde_json::to_string(&status).expect("serialize populated");
    for key in ["zone_traffic_counters", "zone_flood_counters"] {
        assert!(
            populated.contains(key),
            "a POPULATED {key} was dropped from the wire. skip_serializing_if must be \
             conditional on emptiness; if it omits a non-empty block the fix has \
             become a counter-losing regression: {populated}"
        );
    }
}

#[test]
fn zone_traffic_counters_wire_roundtrip_and_default_omits() {
    // Default helper: no zone data -> version/overflow omitted from the wire.
    let default_status = ProcessStatus::default();
    let body = serde_json::to_string(&default_status).expect("serialize default ProcessStatus");
    assert!(
        !body.contains("zone_counter_layout_version"),
        "default ProcessStatus must omit zone_counter_layout_version: {body}"
    );
    assert!(
        !body.contains("zone_counter_overflow_active"),
        "default ProcessStatus must omit zone_counter_overflow_active: {body}"
    );

    // Populated block round-trips (Rust encode -> JSON -> Rust decode).
    let mut status = ProcessStatus::default();
    status.zone_counter_layout_version = 1;
    status.zone_counter_overflow_active = true;
    status.zone_traffic_counters = vec![ZoneTrafficCounterStatus {
        zone_id: 40000,
        ingress_packets: 10,
        ingress_bytes: 1500,
        egress_packets: 4,
        egress_bytes: 600,
    }];
    let json = serde_json::to_string(&status).expect("serialize populated ProcessStatus");
    let back: ProcessStatus = serde_json::from_str(&json).expect("deserialize ProcessStatus");
    assert_eq!(back.zone_counter_layout_version, 1);
    assert!(back.zone_counter_overflow_active);
    assert_eq!(back.zone_traffic_counters.len(), 1);
    let z = &back.zone_traffic_counters[0];
    assert_eq!(z.zone_id, 40000);
    assert_eq!(z.ingress_packets, 10);
    assert_eq!(z.ingress_bytes, 1500);
    assert_eq!(z.egress_packets, 4);
    assert_eq!(z.egress_bytes, 600);

    // A Go-style payload (zone fields injected into an otherwise-default
    // ProcessStatus so every required field is present) decodes into the zone
    // struct — mirrors the Go encode side / a mixed-version helper.
    let mut v = serde_json::to_value(ProcessStatus::default()).expect("default to value");
    v["zone_counter_layout_version"] = serde_json::json!(1);
    v["zone_traffic_counters"] = serde_json::json!([
        {"zone_id": 7, "ingress_packets": 2, "ingress_bytes": 200,
         "egress_packets": 1, "egress_bytes": 100}
    ]);
    let decoded: ProcessStatus =
        serde_json::from_value(v).expect("decode Go-style zone payload");
    assert_eq!(decoded.zone_counter_layout_version, 1);
    assert_eq!(decoded.zone_traffic_counters.len(), 1);
    assert_eq!(decoded.zone_traffic_counters[0].zone_id, 7);
    assert_eq!(decoded.zone_traffic_counters[0].egress_bytes, 100);
}

// #3651: the per-zone FLOOD block round-trips both directions and a default
// (no per-zone flood data) ProcessStatus omits the layout-version / overflow
// keys. The Go mirror lives in
// pkg/dataplane/userspace/zone_flood_counters_status_test.go.
#[test]
fn zone_flood_counters_wire_roundtrip_and_default_omits() {
    // Default helper: no flood data -> version/overflow omitted from the wire.
    let default_status = ProcessStatus::default();
    let body = serde_json::to_string(&default_status).expect("serialize default ProcessStatus");
    assert!(
        !body.contains("flood_counter_layout_version"),
        "default ProcessStatus must omit flood_counter_layout_version: {body}"
    );
    assert!(
        !body.contains("flood_counter_overflow_active"),
        "default ProcessStatus must omit flood_counter_overflow_active: {body}"
    );

    // Populated block round-trips (Rust encode -> JSON -> Rust decode).
    let mut status = ProcessStatus::default();
    status.flood_counter_layout_version = 1;
    status.flood_counter_overflow_active = true;
    status.zone_flood_counters = vec![ZoneFloodCounterStatus {
        zone_id: 40000,
        syn_flood_events: 11,
        icmp_flood_events: 22,
        udp_flood_events: 33,
    }];
    let json = serde_json::to_string(&status).expect("serialize populated ProcessStatus");
    assert!(
        json.contains("\"zone_flood_counters\""),
        "the populated flood block must be on the wire under its Go-facing key: {json}"
    );
    let back: ProcessStatus = serde_json::from_str(&json).expect("deserialize ProcessStatus");
    assert_eq!(back.flood_counter_layout_version, 1);
    assert!(back.flood_counter_overflow_active);
    assert_eq!(back.zone_flood_counters.len(), 1);
    let z = &back.zone_flood_counters[0];
    assert_eq!(z.zone_id, 40000);
    // Three DISTINCT values, so a decoder that crossed two families (or read
    // one field into all three) cannot pass.
    assert_eq!(z.syn_flood_events, 11);
    assert_eq!(z.icmp_flood_events, 22);
    assert_eq!(z.udp_flood_events, 33);

    // A Go-style payload (flood fields injected into an otherwise-default
    // ProcessStatus so every required field is present) decodes into the flood
    // struct — mirrors the Go encode side / a mixed-version helper.
    let mut v = serde_json::to_value(ProcessStatus::default()).expect("default to value");
    v["flood_counter_layout_version"] = serde_json::json!(1);
    v["zone_flood_counters"] = serde_json::json!([
        {"zone_id": 7, "syn_flood_events": 2, "icmp_flood_events": 3,
         "udp_flood_events": 4}
    ]);
    let decoded: ProcessStatus =
        serde_json::from_value(v).expect("decode Go-style flood payload");
    assert_eq!(decoded.flood_counter_layout_version, 1);
    assert_eq!(decoded.zone_flood_counters.len(), 1);
    assert_eq!(decoded.zone_flood_counters[0].zone_id, 7);
    assert_eq!(decoded.zone_flood_counters[0].syn_flood_events, 2);
    assert_eq!(decoded.zone_flood_counters[0].icmp_flood_events, 3);
    assert_eq!(decoded.zone_flood_counters[0].udp_flood_events, 4);

    // #[serde(default)] cross-version safety: a PRE-#3651 helper's status (no
    // flood keys at all) must still decode, reporting "no per-zone flood data"
    // rather than failing the whole status decode.
    let mut old = serde_json::to_value(ProcessStatus::default()).expect("default to value");
    old.as_object_mut()
        .expect("status object")
        .remove("zone_flood_counters");
    let old_decoded: ProcessStatus =
        serde_json::from_value(old).expect("a status with no flood keys must still decode");
    assert_eq!(old_decoded.flood_counter_layout_version, 0);
    assert!(old_decoded.zone_flood_counters.is_empty());
}

#[test]
fn wire_invariant_default_specimens() {
    use serde_json::{Map, Value};

    fn dump<T: serde::Serialize>(value: &T) -> Value {
        serde_json::to_value(value).expect("specimen serializes")
    }

    // Build the specimen map explicitly (no json! macro) to dodge
    // serde_json's recursion limit on a 60+ element literal. Order
    // is preserved by serde_json::Map (BTreeMap-backed), so the
    // fixture output is stable across runs.
    let mut s: Map<String, Value> = Map::new();
    s.insert("binding_control_request".into(), dump(&BindingControlRequest::default()));
    s.insert("binding_counters_snapshot".into(), dump(&BindingCountersSnapshot::default()));
    s.insert("binding_status".into(), dump(&BindingStatus::default()));
    s.insert("app_catalog_entry".into(), dump(&AppCatalogEntry::default()));
    s.insert("class_of_service_snapshot".into(), dump(&ClassOfServiceSnapshot::default()));
    s.insert("config_snapshot".into(), dump(&ConfigSnapshot::default()));
    s.insert("control_request".into(), dump(&ControlRequest::default()));
    s.insert("control_response".into(), dump(&ControlResponse::default()));
    // #8121: a POPULATED specimen, not a default one, and that is the point.
    //
    // `idle_leases` on ControlRequest/ControlResponse carries
    // `skip_serializing_if = "Vec::is_empty"`, and every specimen above is a
    // `::default()` — so an empty vec is omitted and this payload's field
    // spellings were invisible to the wire pin entirely. Four of its own
    // fields carry `skip_serializing_if` too, so even a non-empty vec of
    // defaults would hide them.
    //
    // That gap is not specific to this type: ANY field that is
    // `skip_serializing_if` on its default value is unpinned by a default
    // specimen. This one is pinned because the Go side (`IdleLeaseWire`,
    // pkg/dataplane/userspace/protocol.go) has to agree with it field for
    // field across the control socket, and nothing else asserts that.
    s.insert(
        "idle_lease_wire".into(),
        dump(&IdleLeaseWire {
            pool_name: "p1".into(),
            protocol: 6,
            src_ip: "10.0.61.102".into(),
            src_port: 40000,
            remote_ip: "8.8.8.8".into(),
            remote_port: 443,
            translated_ip: "172.16.80.7".into(),
            translated_port: 51400,
            address_only: true,
            remaining_ns: 123,
            timeout_ns: 300_000_000_000,
        }),
    );
    // #8615: the DISPLAY sibling, populated for the same reason — its own
    // `active_flows` and four inherited fields are `skip_serializing_if`, so a
    // default specimen would pin almost none of its spellings.
    s.insert(
        "display_lease_wire".into(),
        dump(&DisplayLeaseWire {
            pool_name: "p1".into(),
            protocol: 6,
            src_ip: "10.0.61.102".into(),
            src_port: 40000,
            remote_ip: "8.8.8.8".into(),
            remote_port: 443,
            translated_ip: "172.16.80.7".into(),
            translated_port: 51400,
            address_only: true,
            remaining_ns: 123,
            timeout_ns: 300_000_000_000,
            active_flows: 4,
        }),
    );
    s.insert("cos_active_flow_count_status".into(), dump(&CoSActiveFlowCountStatus::default()));
    s.insert("cos_dscp_classifier_entry_snapshot".into(), dump(&CoSDSCPClassifierEntrySnapshot::default()));
    s.insert("cos_dscp_classifier_snapshot".into(), dump(&CoSDSCPClassifierSnapshot::default()));
    s.insert("cos_dscp_rewrite_rule_entry_snapshot".into(), dump(&CoSDSCPRewriteRuleEntrySnapshot::default()));
    s.insert("cos_dscp_rewrite_rule_snapshot".into(), dump(&CoSDSCPRewriteRuleSnapshot::default()));
    s.insert("cos_forwarding_class_snapshot".into(), dump(&CoSForwardingClassSnapshot::default()));
    s.insert("cos_ieee8021_classifier_entry_snapshot".into(), dump(&CoSIEEE8021ClassifierEntrySnapshot::default()));
    s.insert("cos_ieee8021_classifier_snapshot".into(), dump(&CoSIEEE8021ClassifierSnapshot::default()));
    s.insert("cos_inet_precedence_classifier_entry_snapshot".into(), dump(&CoSINetPrecedenceClassifierEntrySnapshot::default()));
    s.insert("cos_inet_precedence_classifier_snapshot".into(), dump(&CoSINetPrecedenceClassifierSnapshot::default()));
    s.insert("cos_interface_status".into(), dump(&CoSInterfaceStatus::default()));
    s.insert("cos_queue_status".into(), dump(&CoSQueueStatus::default()));
    s.insert("cos_scheduler_map_entry_snapshot".into(), dump(&CoSSchedulerMapEntrySnapshot::default()));
    s.insert("cos_scheduler_map_snapshot".into(), dump(&CoSSchedulerMapSnapshot::default()));
    s.insert("cos_scheduler_snapshot".into(), dump(&CoSSchedulerSnapshot::default()));
    s.insert("destination_nat_rule_snapshot".into(), dump(&DestinationNATRuleSnapshot::default()));
    s.insert("exception_status".into(), dump(&ExceptionStatus::default()));
    s.insert("fabric_snapshot".into(), dump(&FabricSnapshot::default()));
    s.insert("firewall_filter_snapshot".into(), dump(&FirewallFilterSnapshot::default()));
    s.insert("firewall_filter_term_counter_status".into(), dump(&FirewallFilterTermCounterStatus::default()));
    s.insert("firewall_term_snapshot".into(), dump(&FirewallTermSnapshot::default()));
    s.insert("flow_export_snapshot".into(), dump(&FlowExportSnapshot::default()));
    s.insert("flow_snapshot".into(), dump(&FlowSnapshot::default()));
    s.insert("flow_tuple_status".into(), dump(&FlowTupleStatus::default()));
    s.insert("flow_worker_status".into(), dump(&FlowWorkerStatus::default()));
    s.insert("forwarding_control_request".into(), dump(&ForwardingControlRequest::default()));
    s.insert("ha_group_status".into(), dump(&HAGroupStatus::default()));
    s.insert("ha_state_update_request".into(), dump(&HAStateUpdateRequest::default()));
    s.insert("inject_packet_request".into(), dump(&InjectPacketRequest::default()));
    s.insert("interface_address_snapshot".into(), dump(&InterfaceAddressSnapshot::default()));
    s.insert("interface_snapshot".into(), dump(&InterfaceSnapshot::default()));
    s.insert("map_pins".into(), dump(&MapPins::default()));
    s.insert("mirror_config_snapshot".into(), dump(&MirrorConfigSnapshot::default()));
    s.insert("nat64_rule_snapshot".into(), dump(&NAT64RuleSnapshot::default()));
    s.insert("nat_rule_counter_status".into(), dump(&NatRuleCounterStatus::default()));
    s.insert("neighbor_snapshot".into(), dump(&NeighborSnapshot::default()));
    s.insert("nptv6_rule_snapshot".into(), dump(&Nptv6RuleSnapshot::default()));
    s.insert("packet_resolution".into(), dump(&PacketResolution::default()));
    s.insert("policer_snapshot".into(), dump(&PolicerSnapshot::default()));
    s.insert("policy_application_snapshot".into(), dump(&PolicyApplicationSnapshot::default()));
    s.insert("policy_rule_counter_status".into(), dump(&PolicyRuleCounterStatus::default()));
    s.insert("policy_rule_snapshot".into(), dump(&PolicyRuleSnapshot::default()));
    s.insert("process_status".into(), dump(&ProcessStatus::default()));
    s.insert("queue_control_request".into(), dump(&QueueControlRequest::default()));
    s.insert("queue_status".into(), dump(&QueueStatus::default()));
    s.insert("route_snapshot".into(), dump(&RouteSnapshot::default()));
    s.insert("screen_missing_profile_ref".into(), dump(&ScreenMissingProfileRef::default()));
    s.insert("screen_profile_snapshot".into(), dump(&ScreenProfileSnapshot::default()));
    s.insert("session_delta_drain_request".into(), dump(&SessionDeltaDrainRequest::default()));
    s.insert("session_delta_info".into(), dump(&SessionDeltaInfo::default()));
    s.insert("session_export_request".into(), dump(&SessionExportRequest::default()));
    s.insert("session_sync_request".into(), dump(&SessionSyncRequest::default()));
    s.insert("slow_path_status".into(), dump(&SlowPathStatus::default()));
    s.insert("snapshot_summary".into(), dump(&SnapshotSummary::default()));
    s.insert("source_nat_pool_status".into(), dump(&SourceNatPoolStatus::default()));
    s.insert("source_nat_rule_snapshot".into(), dump(&SourceNATRuleSnapshot::default()));
    s.insert("static_nat_rule_snapshot".into(), dump(&StaticNATRuleSnapshot::default()));
    s.insert("three_color_policer_snapshot".into(), dump(&ThreeColorPolicerSnapshot::default()));
    s.insert("three_color_policer_status".into(), dump(&ThreeColorPolicerStatus::default()));
    s.insert("tunnel_endpoint_snapshot".into(), dump(&TunnelEndpointSnapshot::default()));
    s.insert("userspace_capabilities".into(), dump(&UserspaceCapabilities::default()));
    s.insert("worker_runtime_status".into(), dump(&WorkerRuntimeStatus::default()));
    s.insert("zone_snapshot".into(), dump(&ZoneSnapshot::default()));
    s.insert("zone_flood_counter_status".into(), dump(&ZoneFloodCounterStatus::default()));
    s.insert("zone_traffic_counter_status".into(), dump(&ZoneTrafficCounterStatus::default()));
    let specimens = Value::Object(s);

    let actual = serde_json::to_string_pretty(&specimens)
        .expect("specimens serialize to pretty JSON");

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("protocol_wire_v1.json");

    if std::env::var("XPF_PROTOCOL_WIRE_REGEN").is_ok() {
        std::fs::create_dir_all(fixture_path.parent().unwrap())
            .expect("create fixtures dir");
        std::fs::write(&fixture_path, format!("{}\n", actual))
            .expect("write regenerated fixture");
        eprintln!("regenerated fixture at {}", fixture_path.display());
        return;
    }

    let baseline = std::fs::read_to_string(&fixture_path).unwrap_or_else(|e| {
        panic!(
            "wire fixture missing at {}: {}. Regenerate with \
             XPF_PROTOCOL_WIRE_REGEN=1 cargo test --bin xpf-userspace-dp \
             wire_invariant_default_specimens",
            fixture_path.display(),
            e
        )
    });

    if baseline.trim() != actual.trim() {
        let tmp = fixture_path.with_extension("json.actual");
        let _ = std::fs::write(&tmp, format!("{}\n", actual));
        panic!(
            "wire-format drift detected vs {}.\nActual written to {}.\n\
             Inspect: diff -u {} {}\n\
             If intentional, regenerate with \
             XPF_PROTOCOL_WIRE_REGEN=1 cargo test --bin xpf-userspace-dp \
             wire_invariant_default_specimens",
            fixture_path.display(),
            tmp.display(),
            fixture_path.display(),
            tmp.display(),
        );
    }
}

// #6459/#6463: cross-language wire-key contract for the two new fail-closed
// filter-term markers. The Go producer
// (pkg/dataplane/userspace/protocol_policies.go) marshals
// `ports_unrepresentable` / `address_unrepresentable` with omitempty; the Rust
// consumer (protocol/security.rs) decodes them with serde(default). A key
// rename on either side must fail a test here (Rust decode) or in the Go-side
// contract test (Go encode) instead of silently degrading to the pre-fix
// narrowing behavior.
#[test]
fn firewall_term_snapshot_unrepresentable_marker_wire_keys_6459_6463() {
    // Rust serialize: both markers set -> exact wire keys present and true.
    let term = FirewallTermSnapshot {
        ports_unrepresentable: true,
        address_unrepresentable: true,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&term).expect("serialize FirewallTermSnapshot");
    assert_eq!(value["ports_unrepresentable"], true);
    assert_eq!(value["address_unrepresentable"], true);

    // Go-style payload (only the two marker keys populated) decodes into the
    // marker fields — mirrors the Go encoder on the tolerant/HA-sync path.
    let decoded: FirewallTermSnapshot = serde_json::from_value(serde_json::json!({
        "name": "t",
        "action": "discard",
        "ports_unrepresentable": true,
        "address_unrepresentable": true
    }))
    .expect("decode Go-style marker payload");
    assert!(decoded.ports_unrepresentable);
    assert!(decoded.address_unrepresentable);

    // Legacy payload (keys absent — an older Go control plane, #1961) decodes
    // with both markers false, i.e. the pre-fix behavior window is explicit,
    // not a decode failure.
    let legacy: FirewallTermSnapshot = serde_json::from_value(serde_json::json!({
        "name": "t",
        "action": "discard"
    }))
    .expect("legacy payload without the markers decodes");
    assert!(!legacy.ports_unrepresentable);
    assert!(!legacy.address_unrepresentable);
}

// #1642: Rust→Go status-field parity. These serde tests pin the exact wire
// keys for the four field groups the Go side previously dropped on unmarshal
// (HAGroupStatus lease telemetry, CoSQueueStatus starvation/ring counters,
// BindingStatus post-drain backup drops, ProcessStatus event-stream
// connected/seq/acked). The matching Go decode tests live in
// pkg/dataplane/userspace/protocol_test.go (*Parity1642). A rename on this
// side is caught here; the Go side then fails to decode the renamed key.

#[test]
fn ha_group_status_lease_fields_wire_keys_1642() {
    let status = HAGroupStatus {
        rg_id: 1,
        active: true,
        watchdog_timestamp: 1,
        forwarding_active: true,
        lease_state: "owner".to_string(),
        lease_until: 9876543210,
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize HAGroupStatus");
    assert_eq!(value["forwarding_active"], true);
    assert_eq!(value["lease_state"], "owner");
    assert_eq!(value["lease_until"], 9876543210u64);
    let back: HAGroupStatus = serde_json::from_value(value).expect("deserialize HAGroupStatus");
    assert!(back.forwarding_active);
    assert_eq!(back.lease_state, "owner");
    assert_eq!(back.lease_until, 9876543210);
}

#[test]
fn cos_queue_status_starvation_counters_wire_keys_1642() {
    let status = CoSQueueStatus {
        root_token_starvation_parks: 11,
        queue_token_starvation_parks: 22,
        tx_ring_full_submit_stalls: 33,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize CoSQueueStatus");
    assert_eq!(value["root_token_starvation_parks"], 11u64);
    assert_eq!(value["queue_token_starvation_parks"], 22u64);
    assert_eq!(value["tx_ring_full_submit_stalls"], 33u64);
}

// #1829 Phase 1: round-trip + backward-compat pin for the sojourn
// telemetry trio. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus gauges
// `xpf_userspace_cos_sojourn_{ewma,peak,windowed_min}_ns` — a rename
// on either side must fail a test instead of silently decoding zero.
// `sojourn_windowed_min_ns` is the #1829 Phase-2 gate metric.
#[test]
fn cos_queue_status_sojourn_roundtrip_1829() {
    let status = CoSQueueStatus {
        sojourn_ewma_ns: 2_500_000,
        sojourn_peak_ns: 9_000_000,
        sojourn_windowed_min_ns: 1_750_000,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize CoSQueueStatus");
    assert_eq!(value["sojourn_ewma_ns"], 2_500_000u64);
    assert_eq!(value["sojourn_peak_ns"], 9_000_000u64);
    assert_eq!(value["sojourn_windowed_min_ns"], 1_750_000u64);
    let back: CoSQueueStatus = serde_json::from_value(value).expect("deserialize CoSQueueStatus");
    assert_eq!(back.sojourn_ewma_ns, 2_500_000);
    assert_eq!(back.sojourn_peak_ns, 9_000_000);
    assert_eq!(back.sojourn_windowed_min_ns, 1_750_000);

    // Pre-#1829 payload (keys absent) must decode with zero defaults.
    let mut legacy_value = serde_json::to_value(CoSQueueStatus::default())
        .expect("serialize default CoSQueueStatus");
    for key in [
        "sojourn_ewma_ns",
        "sojourn_peak_ns",
        "sojourn_windowed_min_ns",
    ] {
        legacy_value
            .as_object_mut()
            .expect("CoSQueueStatus serializes to an object")
            .remove(key)
            .unwrap_or_else(|| panic!("new key {key} present before strip"));
    }
    let legacy: CoSQueueStatus =
        serde_json::from_value(legacy_value).expect("pre-#1829 payload decodes");
    assert_eq!(legacy.sojourn_ewma_ns, 0);
    assert_eq!(legacy.sojourn_peak_ns, 0);
    assert_eq!(legacy.sojourn_windowed_min_ns, 0);
}

// #1830 (g): round-trip + backward-compat pin for the bucket-vs-flow
// occupancy telemetry. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus gauges
// `xpf_userspace_cos_flow_fair_buckets_occupied` /
// `xpf_userspace_cos_flow_fair_flows_active` — a rename on either side
// must fail a test instead of silently decoding zero.
#[test]
fn cos_queue_status_flow_fair_occupancy_roundtrip_1830() {
    let status = CoSQueueStatus {
        flow_fair_buckets_occupied: 9,
        flow_fair_flows_active: 12,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize CoSQueueStatus");
    assert_eq!(value["flow_fair_buckets_occupied"], 9u64);
    assert_eq!(value["flow_fair_flows_active"], 12u64);
    let back: CoSQueueStatus = serde_json::from_value(value).expect("deserialize CoSQueueStatus");
    assert_eq!(back.flow_fair_buckets_occupied, 9);
    assert_eq!(back.flow_fair_flows_active, 12);

    // Pre-#1830 payload (keys absent) must decode with zero defaults.
    let mut legacy_value = serde_json::to_value(CoSQueueStatus::default())
        .expect("serialize default CoSQueueStatus");
    for key in ["flow_fair_buckets_occupied", "flow_fair_flows_active"] {
        legacy_value
            .as_object_mut()
            .expect("CoSQueueStatus serializes to an object")
            .remove(key)
            .unwrap_or_else(|| panic!("new key {key} present before strip"));
    }
    let legacy: CoSQueueStatus =
        serde_json::from_value(legacy_value).expect("pre-#1830 payload decodes");
    assert_eq!(legacy.flow_fair_buckets_occupied, 0);
    assert_eq!(legacy.flow_fair_flows_active, 0);
}

#[test]
fn binding_status_post_drain_backup_cos_drops_wire_keys_1642() {
    let status = BindingStatus {
        post_drain_backup_cos_drops: 7,
        post_drain_backup_cos_drop_bytes: 4096,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus");
    assert_eq!(value["post_drain_backup_cos_drops"], 7u64);
    assert_eq!(value["post_drain_backup_cos_drop_bytes"], 4096u64);
    // These are binding-scoped: CoSQueueStatus must NOT also carry them.
    let cos: serde_json::Value = serde_json::to_value(CoSQueueStatus {
        post_drain_backup_bytes: 1,
        ..Default::default()
    })
    .expect("serialize CoSQueueStatus");
    assert!(cos.get("post_drain_backup_cos_drops").is_none());
    assert!(cos.get("post_drain_backup_cos_drop_bytes").is_none());
    assert_eq!(cos["post_drain_backup_bytes"], 1u64);
}

// #1946: wire key + roundtrip + omitempty pin for the FabricRedirect
// fail-closed drop counter. Feeds pkg/dataplane/userspace/protocol.go
// (FabricRedirectUnsendableDrops). A rename or skip-semantics change on
// either side must fail here instead of silently decoding empty; the
// `default` attribute keeps a mixed-version control socket (older helper
// omits the key) decoding to 0.
#[test]
fn binding_status_fabric_redirect_unsendable_drops_wire_key_1946() {
    let status = BindingStatus {
        fabric_redirect_unsendable_drops: 9,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize BindingStatus");
    assert_eq!(value["fabric_redirect_unsendable_drops"], 9u64);

    // Round-trip preserves the value.
    let decoded: BindingStatus =
        serde_json::from_value(value).expect("deserialize BindingStatus");
    assert_eq!(decoded.fabric_redirect_unsendable_drops, 9);

    // Mixed-version tolerance: an older helper that omits the key (but
    // still emits the required fields) decodes it to the default 0.
    let mut legacy_value =
        serde_json::to_value(BindingStatus::default()).expect("serialize default BindingStatus");
    legacy_value
        .as_object_mut()
        .expect("object")
        .remove("fabric_redirect_unsendable_drops");
    let legacy: BindingStatus =
        serde_json::from_value(legacy_value).expect("deserialize legacy BindingStatus");
    assert_eq!(legacy.fabric_redirect_unsendable_drops, 0);
}

#[test]
fn process_status_event_stream_fields_wire_keys_1642() {
    let status = ProcessStatus {
        event_stream_connected: true,
        event_stream_seq: 4242,
        event_stream_acked: 4200,
        event_stream_write_stalls: 17,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus");
    assert_eq!(value["event_stream_connected"], true);
    assert_eq!(value["event_stream_seq"], 4242u64);
    assert_eq!(value["event_stream_acked"], 4200u64);
    // #2381: stalled-consumer backlog counter must survive the wire under its
    // exact key so the Go status adapter can surface it.
    assert_eq!(value["event_stream_write_stalls"], 17u64);
}

#[test]
fn process_status_replay_evictions_wire_key_2382() {
    let status = ProcessStatus {
        event_stream_replay_evictions: 9,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus");
    // #2382: the replay-buffer eviction telemetry-loss counter must survive
    // the wire under its exact key so the Go status adapter and Prometheus
    // collector can surface it.
    assert_eq!(value["event_stream_replay_evictions"], 9u64);

    // Round-trip with the key absent (legacy helper) must default to 0, not
    // fail to decode (#[serde(default)]).
    let mut legacy = serde_json::to_value(ProcessStatus::default())
        .expect("serialize default ProcessStatus");
    legacy
        .as_object_mut()
        .expect("object")
        .remove("event_stream_replay_evictions");
    let decoded: ProcessStatus =
        serde_json::from_value(legacy).expect("decode legacy ProcessStatus");
    assert_eq!(decoded.event_stream_replay_evictions, 0);
}

// #1863 Step-0: round-trip + omitempty pin for the per-worker v8
// lease claim-flow vectors. The wire keys feed
// pkg/dataplane/userspace/protocol.go and the Prometheus counters
// `xpf_userspace_cos_lease_v8_{requested,granted}_bytes_total` — a
// rename or skip-semantics change on either side must fail here
// instead of silently decoding empty.
#[test]
fn cos_queue_status_lease_claim_flow_roundtrip_1863() {
    let status = CoSQueueStatus {
        lease_v8_worker_requested_bytes: vec![100, 0, 250],
        lease_v8_worker_granted_bytes: vec![90, 0, 200],
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize CoSQueueStatus");
    assert_eq!(
        value["lease_v8_worker_requested_bytes"],
        serde_json::json!([100, 0, 250])
    );
    assert_eq!(
        value["lease_v8_worker_granted_bytes"],
        serde_json::json!([90, 0, 200])
    );
    let back: CoSQueueStatus = serde_json::from_value(value).expect("deserialize CoSQueueStatus");
    assert_eq!(back.lease_v8_worker_requested_bytes, vec![100, 0, 250]);
    assert_eq!(back.lease_v8_worker_granted_bytes, vec![90, 0, 200]);

    // Legacy/non-v8 rows: empty vectors must be OMITTED from the wire
    // (byte-identical pre-#1863 encoding) and absent keys must decode
    // to empty defaults.
    let default_value = serde_json::to_value(CoSQueueStatus::default())
        .expect("serialize default CoSQueueStatus");
    let obj = default_value
        .as_object()
        .expect("CoSQueueStatus serializes to an object");
    assert!(!obj.contains_key("lease_v8_worker_requested_bytes"));
    assert!(!obj.contains_key("lease_v8_worker_granted_bytes"));
    let back: CoSQueueStatus =
        serde_json::from_value(default_value).expect("deserialize legacy CoSQueueStatus");
    assert!(back.lease_v8_worker_requested_bytes.is_empty());
    assert!(back.lease_v8_worker_granted_bytes.is_empty());
}

// #1865: round-trip + backward-compat + EMPTY-INVARIANT pins for the
// per-WG-tunnel telemetry rows. The wire keys feed
// pkg/dataplane/userspace/protocol.go (WgTunnelStatus) and the
// Prometheus family `xpf_userspace_wg_*`.
#[test]
fn process_status_wg_tunnels_roundtrip_and_compat() {
    // POPULATED round-trip (Codex plan-r1 F5: the Default-based wire
    // fixture cannot see skip-if-empty fields, so the populated pin is
    // the guard for this family). Every field nonzero/nonempty.
    let row = WgTunnelStatus {
        tunnel: "wg0".to_string(),
        tunnel_endpoint_id: 7,
        listen_port: 51820,
        local_pubkey_hex: "cd".repeat(32),
        peers: vec![crate::protocol::control::WgPeerStatus {
            peer_pubkey_hex: "ab".repeat(32),
            peer_endpoint: "192.0.2.10:51820".to_string(),
            session_confirmed: true,
        }],
        last_handshake_unix_secs: 1_770_000_000,
        hs_initiations_created: 1,
        hs_initiation_build_failures: 2,
        hs_responses_created: 3,
        hs_completions_initiator: 4,
        hs_rx_drops_mac1_mismatch: 5,
        hs_rx_drops_malformed: 6,
        hs_rx_drops_crypto: 7,
        hs_rx_drops_unknown_peer: 8,
        hs_rx_drops_stale_response: 9,
        hs_rx_drops_index_exhausted: 10,
        // #4092 handshake anti-replay rejects (off-ladder value; every
        // field must be nonzero for the wire-invariant populated pin).
        hs_rx_drops_replayed_init: 45,
        hs_rx_cookie_unsupported: 11,
        // #4094 PR-B initiator cookie-replies consumed (50, off-ladder).
        hs_rx_cookie_consumed: 50,
        // #4094 PR-A responder cookie / MAC2 under-load accounting
        // (46.. off-ladder, mirror of the Go-side series-set values).
        hs_cookie_replies_sent: 46,
        hs_rx_under_load_no_mac2: 47,
        hs_rx_under_load_mac2_ok: 48,
        hs_cookie_reply_budget_drops: 49,
        rx_unknown_type: 12,
        hs_send_errors: 13,
        hs_requests_armed: 14,
        decap_packets: 15,
        decap_bytes: 16,
        decap_keepalives: 17,
        decap_drops_malformed_header: 18,
        decap_drops_unknown_session: 19,
        decap_drops_counter_ceiling: 20,
        decap_drops_crypto: 21,
        decap_drops_replay: 22,
        decap_drops_allowed_ips: 23,
        decap_drops_malformed_inner: 24,
        decap_drops_buffer: 25,
        rx_unsteered_transport_drops: 55,
        encap_packets: 26,
        encap_bytes: 27,
        encap_drops_no_session: 28,
        encap_drops_unconfirmed: 29,
        encap_drops_rekey_required: 30,
        encap_drops_other: 31,
        encap_mtu_drops: 32,
        transport_send_errors: 33,
        tun_write_errors: 34,
        tun_rx_drops_no_endpoint: 35,
        // #1888 S5 timer telemetry (36.. continuing the ladder; mirror
        // of the Go-side TestEmitWireguardTelemetrySeriesSet values).
        encap_drops_expired: 36,
        decap_drops_expired: 37,
        sessions_expired: 38,
        rekeys_initiated_age: 39,
        rekeys_initiated_dead_peer: 40,
        rekeys_initiated_keepalive_no_session: 41,
        keepalives_tx_passive: 42,
        keepalives_tx_persistent: 43,
        pending_aborted_attempt_window: 44,
        // #7936 endpoint resolver (51.. — 45..50 are the cookie/under-load
        // fields asserted below, so the ladder continues past them).
        endpoint_resolve_ok: 51,
        endpoint_resolve_fail: 52,
        endpoint_family_mismatch: 53,
        endpoint_changed: 54,
        endpoint_last_error: "vpn.example.com: no AAAA for a v6 socket".to_string(),
    };
    let status = ProcessStatus {
        wg_tunnels: vec![row],
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus");
    let wire_row = &value["wg_tunnels"][0];
    assert_eq!(wire_row["tunnel"], "wg0");
    assert_eq!(wire_row["tunnel_endpoint_id"], 7);
    assert_eq!(wire_row["listen_port"], 51820);
    assert_eq!(wire_row["local_pubkey_hex"], "cd".repeat(32));
    // #1434: per-peer fields live in the `peers` slice.
    assert_eq!(wire_row["peers"][0]["peer_pubkey_hex"], "ab".repeat(32));
    assert_eq!(wire_row["peers"][0]["peer_endpoint"], "192.0.2.10:51820");
    assert_eq!(wire_row["peers"][0]["session_confirmed"], true);
    assert_eq!(wire_row["last_handshake_unix_secs"], 1_770_000_000u64);
    assert_eq!(wire_row["decap_keepalives"], 17);
    assert_eq!(wire_row["encap_drops_unconfirmed"], 29);
    assert_eq!(wire_row["encap_mtu_drops"], 32);
    assert_eq!(wire_row["sessions_expired"], 38);
    assert_eq!(wire_row["rekeys_initiated_age"], 39);
    assert_eq!(wire_row["keepalives_tx_persistent"], 43);
    assert_eq!(wire_row["hs_cookie_replies_sent"], 46);
    assert_eq!(wire_row["hs_rx_cookie_consumed"], 50);
    assert_eq!(wire_row["hs_rx_under_load_no_mac2"], 47);
    // #7936: the four counters AND the error string. The string is asserted
    // because it is the half a counter cannot carry — `endpoint_family_mismatch`
    // says how often, this says which name and which family, and only the pair
    // is actionable.
    assert_eq!(wire_row["endpoint_resolve_ok"], 51);
    assert_eq!(wire_row["endpoint_resolve_fail"], 52);
    assert_eq!(wire_row["endpoint_family_mismatch"], 53);
    assert_eq!(wire_row["endpoint_changed"], 54);
    assert_eq!(
        wire_row["endpoint_last_error"],
        "vpn.example.com: no AAAA for a v6 socket"
    );
    let back: ProcessStatus =
        serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.wg_tunnels.len(), 1);
    let b = &back.wg_tunnels[0];
    assert_eq!(b.tunnel, "wg0");
    assert_eq!(b.local_pubkey_hex, "cd".repeat(32));
    assert_eq!(b.peers.len(), 1);
    assert_eq!(b.peers[0].peer_pubkey_hex, "ab".repeat(32));
    assert!(b.peers[0].session_confirmed);
    assert_eq!(b.endpoint_resolve_ok, 51);
    assert_eq!(b.endpoint_resolve_fail, 52);
    assert_eq!(b.endpoint_family_mismatch, 53);
    assert_eq!(b.endpoint_changed, 54);
    assert_eq!(
        b.endpoint_last_error,
        "vpn.example.com: no AAAA for a v6 socket"
    );
    assert_eq!(b.hs_initiations_created, 1);
    assert_eq!(b.decap_drops_buffer, 25);
    assert_eq!(b.rx_unsteered_transport_drops, 55);
    assert_eq!(b.tun_rx_drops_no_endpoint, 35);
    assert_eq!(b.encap_drops_expired, 36);
    assert_eq!(b.decap_drops_expired, 37);
    assert_eq!(b.rekeys_initiated_keepalive_no_session, 41);
    assert_eq!(b.keepalives_tx_passive, 42);
    assert_eq!(b.pending_aborted_attempt_window, 44);
    assert_eq!(b.hs_rx_under_load_mac2_ok, 48);
    assert_eq!(b.hs_cookie_reply_budget_drops, 49);

    // EMPTY-INVARIANT: a ProcessStatus with no WG tunnels serializes
    // with NO `wg_tunnels` key at all — non-WG deployments stay
    // wire-byte-identical to pre-#1865 (plan §3.2).
    let empty_value = serde_json::to_value(ProcessStatus::default())
        .expect("serialize default ProcessStatus");
    assert!(
        empty_value.get("wg_tunnels").is_none(),
        "empty wg_tunnels must be omitted from the wire entirely"
    );

    // Pre-#1865 payload (key absent) must decode with an empty vec.
    let legacy: ProcessStatus =
        serde_json::from_value(empty_value).expect("pre-#1865 payload decodes");
    assert!(legacy.wg_tunnels.is_empty());

    // A pre-#1865 ROW shape is impossible (the whole array is new),
    // but a NEWER peer adding fields inside a row must not break us:
    // unknown keys are ignored by serde's default behavior.
    let future_row: WgTunnelStatus = serde_json::from_str(
        r#"{"tunnel":"wg9","future_field_from_s6":42}"#,
    )
    .expect("row with unknown future key decodes");
    assert_eq!(future_row.tunnel, "wg9");
    assert_eq!(future_row.hs_send_errors, 0);
}

// #1961: a full apply_snapshot ControlRequest carrying DSCP/code-point lists as
// numeric arrays must decode, and the three Vec<u8> fields must carry the
// values. The Go control plane emits these as numeric arrays via the
// WireUint8List type; before #1961 it emitted base64 strings, which serde
// rejects (the whole-request decode aborts — see the negative test below). The
// JSON is a full ControlRequest, not leaf structs, because the failure was at
// whole-request decode.
#[test]
fn apply_snapshot_decodes_numeric_dscp_lists_1961() {
    let json = r#"{
      "type": "apply_snapshot",
      "snapshot": {
        "version": 3,
        "generation": 7,
        "generated_at": "2026-06-18T00:00:00Z",
        "summary": {"host_name":"fw","dataplane_type":"userspace","interface_count":0,"zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false},
        "class_of_service": {
          "dscp_classifiers": [
            {"name": "dc", "entries": [{"forwarding_class": "ef", "dscp_values": [46, 10]}]}
          ],
          "ieee8021_classifiers": [
            {"name": "ic", "entries": [{"forwarding_class": "ef", "code_points": [5]}]}
          ]
        },
        "filters": [
          {"name": "f", "family": "inet", "terms": [
            {"name": "mark-ef", "protocols": [], "dscp_values": [46],
             "action": "accept", "count": "", "log": false, "policer": ""}
          ]}
        ]
      }
    }"#;
    let req: ControlRequest = serde_json::from_str(json).expect("full apply_snapshot decodes");
    assert_eq!(req.request_type, "apply_snapshot");
    let snap = req.snapshot.expect("snapshot present");
    let cos = snap.class_of_service.expect("class_of_service present");
    assert_eq!(cos.dscp_classifiers[0].entries[0].dscp_values, vec![46u8, 10]);
    assert_eq!(cos.ieee8021_classifiers[0].entries[0].code_points, vec![5u8]);
    assert_eq!(snap.filters[0].terms[0].dscp_values, vec![46u8]);
}

// #1961 negative: a base64 STRING for dscp_values (what Go's default []uint8
// marshaler emitted pre-fix) must FAIL the whole-request decode — this is the
// exact mechanism that left the helper disabled. Guards against anyone
// "helpfully" adding a base64 adapter on the Rust side instead of the numeric
// wire contract.
#[test]
fn apply_snapshot_rejects_base64_dscp_string_1961() {
    let json = r#"{
      "type": "apply_snapshot",
      "snapshot": {
        "version": 3, "generation": 7, "generated_at": "2026-06-18T00:00:00Z", "summary": {"host_name":"fw","dataplane_type":"userspace","interface_count":0,"zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false},
        "filters": [
          {"name": "f", "family": "inet", "terms": [
            {"name": "mark-ef", "protocols": [], "dscp_values": "Lg==",
             "action": "accept", "count": "", "log": false, "policer": ""}
          ]}
        ]
      }
    }"#;
    let err = serde_json::from_str::<ControlRequest>(json)
        .expect_err("base64 dscp_values string must be rejected");
    assert!(
        err.to_string().contains("expected a sequence")
            || err.to_string().contains("invalid type"),
        "unexpected error: {err}"
    );
}

// #1977: NUM_WIDTH sibling of #1961. FlowSnapshot/FlowExportSnapshot carry Go
// `int` fields that are Rust unsigned (u16/u32/u64). A max-range value must
// decode; a negative value must abort the whole apply_snapshot decode (the
// mechanism the Go-side build-boundary guard in flow.go defends against).
#[test]
fn apply_snapshot_decodes_max_range_flow_numbers_1977() {
    let json = r#"{
      "type": "apply_snapshot",
      "snapshot": {
        "version": 3, "generation": 1, "generated_at": "2026-06-18T00:00:00Z",
        "summary": {"host_name":"fw","dataplane_type":"userspace","interface_count":0,"zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false},
        "flow": {
          "tcp_mss_gre_in": 65535, "tcp_mss_all_tcp": 65535,
          "tcp_session_timeout": 9223372036, "udp_session_timeout": 9223372036,
          "icmp_session_timeout": 9223372036
        },
        "flow_export": {
          "collector_address": "10.0.0.1", "collector_port": 65535,
          "sampling_rate": 4294967295, "active_timeout": 4294967295,
          "inactive_timeout": 4294967295
        }
      }
    }"#;
    let req: ControlRequest = serde_json::from_str(json).expect("max-range flow numbers decode");
    let snap = req.snapshot.expect("snapshot present");
    assert_eq!(snap.flow.tcp_mss_gre_in, 65535);
    assert_eq!(snap.flow.tcp_session_timeout, 9_223_372_036);
    let fe = snap.flow_export.expect("flow_export present");
    assert_eq!(fe.sampling_rate, 4_294_967_295);
    assert_eq!(fe.collector_port, 65535);
    assert_eq!(fe.inactive_timeout, 4_294_967_295);
}

#[test]
fn apply_snapshot_rejects_negative_flow_number_1977() {
    let json = r#"{
      "type": "apply_snapshot",
      "snapshot": {
        "version": 3, "generation": 1, "generated_at": "2026-06-18T00:00:00Z",
        "summary": {"host_name":"fw","dataplane_type":"userspace","interface_count":0,"zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false},
        "flow": { "tcp_session_timeout": -1 }
      }
    }"#;
    let err = serde_json::from_str::<ControlRequest>(json)
        .expect_err("negative u64 session timeout must abort the whole-request decode");
    assert!(
        err.to_string().contains("invalid value") || err.to_string().contains("expected"),
        "unexpected error: {err}"
    );
}

// #1977: a collector_port exceeding u16 (what Go would emit pre-#1977 for a
// `port 70000` typo) must abort the whole apply_snapshot decode — the mechanism
// the Go-side skip-and-coerce guard defends against.
#[test]
fn apply_snapshot_rejects_oversize_collector_port_1977() {
    let json = r#"{
      "type": "apply_snapshot",
      "snapshot": {
        "version": 3, "generation": 1, "generated_at": "2026-06-18T00:00:00Z",
        "summary": {"host_name":"fw","dataplane_type":"userspace","interface_count":0,"zone_count":0,"policy_count":0,"scheduler_count":0,"ha_enabled":false},
        "flow_export": { "collector_address": "10.0.0.1", "collector_port": 70000, "sampling_rate": 1000 }
      }
    }"#;
    let err = serde_json::from_str::<ControlRequest>(json)
        .expect_err("collector_port > u16 max must abort the whole-request decode");
    assert!(
        err.to_string().contains("invalid value") || err.to_string().contains("expected"),
        "unexpected error: {err}"
    );
}

// #2170: the SessionSyncRequest install generation must round-trip as a
// numeric field, and a legacy payload that omits `generation` must decode to 0
// (serde default). Wire parity with the Go SessionSyncRequest.Generation field.
#[test]
fn session_sync_request_generation_roundtrip_2170() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        generation: 0x1122_3344_5566_7788,
        ..Default::default()
    };
    let json = serde_json::to_string(&req).expect("serialize SessionSyncRequest");
    let back: SessionSyncRequest =
        serde_json::from_str(&json).expect("deserialize SessionSyncRequest");
    assert_eq!(back.generation, req.generation, "generation must round-trip");

    // A legacy payload without the field decodes to 0 (serde default), so an
    // old peer's request falls back to unconditional behavior.
    let legacy: SessionSyncRequest =
        serde_json::from_str(r#"{"operation":"upsert","src_ip":"10.0.0.1"}"#)
            .expect("legacy SessionSyncRequest without generation decodes");
    assert_eq!(legacy.generation, 0, "missing generation must default to 0");
}

// #2785: the per-policy log flags must round-trip on the session-sync wire,
// and a legacy payload that omits them must decode to false (serde default)
// so an old peer falls back to no per-policy log (pre-#2785 behavior).
#[test]
fn session_sync_request_log_flags_roundtrip_2785() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        log_session_init: true,
        log_session_close: true,
        ..Default::default()
    };
    let json = serde_json::to_string(&req).expect("serialize SessionSyncRequest");
    let back: SessionSyncRequest =
        serde_json::from_str(&json).expect("deserialize SessionSyncRequest");
    assert!(back.log_session_init, "log_session_init must round-trip");
    assert!(back.log_session_close, "log_session_close must round-trip");

    let legacy: SessionSyncRequest =
        serde_json::from_str(r#"{"operation":"upsert","src_ip":"10.0.0.1"}"#)
            .expect("legacy SessionSyncRequest without log flags decodes");
    assert!(
        !legacy.log_session_init && !legacy.log_session_close,
        "missing log flags must default to false"
    );
}

// #3301: the admitting policy's firewall metadata (policy_id,
// policy_counter_idx, inactivity_timeout seconds) must round-trip on the
// session-sync wire, and a legacy payload that omits them must decode to 0
// (serde default) so an old peer falls back to unattributed / no counter /
// global timeout (pre-#3301 behavior, rolling-upgrade safe).
#[test]
fn session_sync_request_policy_fields_roundtrip_3301() {
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        policy_id: 42,
        policy_counter_idx: 7,
        inactivity_timeout: 30,
        ..Default::default()
    };
    let json = serde_json::to_string(&req).expect("serialize SessionSyncRequest");
    // Wire keys must match the Go SessionSyncRequest json tags exactly.
    assert!(json.contains("\"policy_id\":42"), "policy_id wire key/value");
    assert!(
        json.contains("\"policy_counter_idx\":7"),
        "policy_counter_idx wire key/value"
    );
    assert!(
        json.contains("\"inactivity_timeout\":30"),
        "inactivity_timeout wire key/value"
    );
    let back: SessionSyncRequest =
        serde_json::from_str(&json).expect("deserialize SessionSyncRequest");
    assert_eq!(back.policy_id, 42, "policy_id must round-trip");
    assert_eq!(back.policy_counter_idx, 7, "policy_counter_idx must round-trip");
    assert_eq!(back.inactivity_timeout, 30, "inactivity_timeout must round-trip");

    let legacy: SessionSyncRequest =
        serde_json::from_str(r#"{"operation":"upsert","src_ip":"10.0.0.1"}"#)
            .expect("legacy SessionSyncRequest without policy fields decodes");
    assert_eq!(legacy.policy_id, 0, "missing policy_id defaults to 0");
    assert_eq!(
        legacy.policy_counter_idx, 0,
        "missing policy_counter_idx defaults to 0"
    );
    assert_eq!(
        legacy.inactivity_timeout, 0,
        "missing inactivity_timeout defaults to 0"
    );
}

// --- #6855: the SYN-cookie master key must never render in Debug ---------

/// #4484 L-7 named `ConfigSnapshot` and `ControlRequest` as the carriers of a
/// latent Debug leak. #4757 fixed a THIRD struct (`ForwardingState`) and the
/// two named ones kept `#[derive(Debug)]` over the plaintext hex key.
///
/// Latent, not active: the only `{:?}` over these types was in a test. The
/// exposure is that any future `slog`/`tracing`/`dbg!` line formatting a
/// `ControlRequest` -- the obvious thing to add while debugging a control-socket
/// problem, which is exactly when someone reaches for it -- writes the key to
/// the journal. Journald is not a secret store, and this key is HA-WIDE: both
/// chassis derive the same one from the root secret plus cluster-id.
#[test]
fn syn_cookie_master_key_is_redacted_in_config_snapshot_debug_6855() {
    const KEY: &str = "0badc0ffee0badc0ffee0badc0ffee42";
    let snap = ConfigSnapshot {
        syn_cookie_master_key: KEY.to_string().into(),
        ..Default::default()
    };
    let rendered = format!("{snap:?}");
    assert!(
        !rendered.contains(KEY),
        "ConfigSnapshot Debug rendered the SYN-cookie master key: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "the key field must render as <redacted> so a reader can tell a key IS set; got: {rendered}"
    );
}

/// The transitive half. `ControlRequest` embeds `Option<ConfigSnapshot>`, so it
/// inherits the leak -- and it is the type someone actually formats when
/// debugging the control socket.
#[test]
fn syn_cookie_master_key_is_redacted_in_control_request_debug_6855() {
    const KEY: &str = "0badc0ffee0badc0ffee0badc0ffee42";
    let req = ControlRequest {
        snapshot: Some(ConfigSnapshot {
            syn_cookie_master_key: KEY.to_string().into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let rendered = format!("{req:?}");
    assert!(
        !rendered.contains(KEY),
        "ControlRequest Debug rendered the SYN-cookie master key transitively: {rendered}"
    );
}

/// PAIRED CONTROL, in two directions.
///
/// Without the first half, a `Debug` that printed "<redacted>" unconditionally
/// -- or printed nothing at all -- would satisfy the assertions above while
/// telling an operator nothing. Without the second, a wrapper whose `Debug`
/// happened to be empty for every value would also pass.
///
/// "There is no key" and "there is a key I will not show you" are different
/// facts, and the first is the one someone debugging a control-socket problem
/// actually needs.
#[test]
fn syn_cookie_master_key_debug_distinguishes_unset_from_set_6855() {
    let unset = SynCookieMasterKeyHex::default();
    assert_eq!(
        format!("{unset:?}"),
        "<unset>",
        "an empty key must render as <unset>, not as <redacted>: an operator \
         chasing a missing key needs to know it is missing"
    );

    let set = SynCookieMasterKeyHex::from("deadbeef".to_string());
    assert_eq!(format!("{set:?}"), "<redacted>");
}

/// The wrapper must not change the WIRE. `#[serde(transparent)]` means it
/// serializes and deserializes exactly as the bare `String` did, so a peer
/// running an older binary is unaffected -- a wire change at an unchanged
/// version number is two readers at one version.
#[test]
fn syn_cookie_master_key_wire_format_is_unchanged_6855() {
    const KEY: &str = "0badc0ffee0badc0ffee0badc0ffee42";

    // The wrapper serializes as a bare JSON string, not as an object.
    let wrapped = SynCookieMasterKeyHex::from(KEY.to_string());
    let json = serde_json::to_string(&wrapped).expect("serialize");
    assert_eq!(json, format!("\"{KEY}\""), "the wrapper must be transparent on the wire");

    // And round-trips from that same bare string.
    let back: SynCookieMasterKeyHex = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(&*back, KEY);

    // Read sites see a plain &str through Deref, unchanged.
    let as_str: &str = &wrapped;
    assert_eq!(as_str, KEY);
}

/// #6853: the `syslog` term field must be ADDITIVE in BOTH directions.
///
/// The claim this pins is mixed-version HA compatibility, and it is worth a
/// test rather than an appeal to `#[serde(default)]` alone — that attribute
/// only covers one of the two directions, and the other rests on the ABSENCE
/// of `deny_unknown_fields`, which is exactly the kind of property a later
/// hardening commit removes without realising what depended on it.
#[test]
fn firewall_term_syslog_is_additive_both_ways_6853() {
    use crate::protocol::security::FirewallTermSnapshot;

    // NEW reader, OLD payload: the field is absent and must default to false
    // rather than failing the whole snapshot parse.
    let old_payload = r#"{"name":"t","log":true}"#;
    let parsed: FirewallTermSnapshot =
        serde_json::from_str(old_payload).expect("an old payload without `syslog` must parse");
    assert!(parsed.log, "the old payload's own fields must survive");
    assert!(
        !parsed.syslog,
        "an absent `syslog` must default to false, not be an error or true"
    );

    // OLD reader, NEW payload: an unknown field must be IGNORED. Simulated by
    // parsing a payload carrying a field this struct does not declare, which
    // is precisely the shape an older helper sees when it receives `syslog`.
    let new_payload = r#"{"name":"t","log":true,"syslog":true,"a_field_from_the_future":42}"#;
    let parsed: FirewallTermSnapshot = serde_json::from_str(new_payload)
        .expect("an unknown field must be ignored, or every older helper breaks on upgrade");
    assert!(
        parsed.syslog,
        "a payload that carries syslog=true must be read as true"
    );
}

/// #8586: the DELETE-specific split of `worker_command_queue_drops` reaches the
/// wire under its own keys, and neither aliases onto the aggregate or onto each
/// other.
///
/// The aliasing assertions are the point. `dropped - repaired` is read as the
/// UNATTRIBUTED remainder — refused deletes nothing repaired — so a rename that
/// serialized both onto one key, or either onto the aggregate, would make that
/// subtraction report 0 for a box that is losing deletes and repairing none of
/// them. That is a value indistinguishable from healthy.
///
/// The three counters are given DISTINCT values so a swap between any pair is
/// visible; equal values would let a transposition pass.
#[test]
fn process_status_session_delete_replica_counters_roundtrip_8586() {
    let status = ProcessStatus {
        worker_command_queue_drops: 7,
        session_delete_replica_dropped: 5,
        session_delete_replica_drop_repaired: 2,
        ..Default::default()
    };
    let value: serde_json::Value =
        serde_json::to_value(&status).expect("serialize ProcessStatus to Value");
    assert_eq!(value["worker_command_queue_drops"], 7);
    assert_eq!(value["session_delete_replica_dropped"], 5);
    assert_eq!(value["session_delete_replica_drop_repaired"], 2);

    let back: ProcessStatus = serde_json::from_value(value).expect("deserialize ProcessStatus");
    assert_eq!(back.worker_command_queue_drops, 7);
    assert_eq!(back.session_delete_replica_dropped, 5);
    assert_eq!(back.session_delete_replica_drop_repaired, 2);
    assert_eq!(
        back.session_delete_replica_dropped - back.session_delete_replica_drop_repaired,
        3,
        "the unattributed remainder is a SUBTRACTION of two independently \
         carried fields; if either aliased onto the other it would read 0"
    );

    // Pre-#8586 payload (keys absent) must decode with zero defaults — an older
    // helper on one side of a rolling HA upgrade sends exactly that.
    let mut legacy_value = serde_json::to_value(ProcessStatus {
        session_delete_replica_dropped: 5,
        session_delete_replica_drop_repaired: 2,
        ..Default::default()
    })
    .expect("serialize ProcessStatus");
    let obj = legacy_value
        .as_object_mut()
        .expect("ProcessStatus serializes to an object");
    obj.remove("session_delete_replica_dropped")
        .expect("new key present before strip");
    obj.remove("session_delete_replica_drop_repaired")
        .expect("new key present before strip");
    let legacy: ProcessStatus =
        serde_json::from_value(legacy_value).expect("pre-#8586 payload decodes");
    assert_eq!(legacy.session_delete_replica_dropped, 0);
    assert_eq!(legacy.session_delete_replica_drop_repaired, 0);
}

/// #9521: the Go daemon sends `ConfigSnapshot.WgSteeredListenPort` as
/// `wg_steered_listen_port` (pinned Go-side by
/// TestSnapshotWgSteeredListenPortWireKey9521). A misspelling on either side
/// decodes as 0, and 0 makes every WireGuard control thread refuse kernel-path
/// transport, so the key is pinned from both sides.
#[test]
fn wg_steered_listen_port_wire_key_9521() {
    let mut value =
        serde_json::to_value(ConfigSnapshot::default()).expect("serialize a default snapshot");
    value["wg_steered_listen_port"] = serde_json::json!(51820);
    let snap: ConfigSnapshot = serde_json::from_value(value.clone()).expect("decode with the key");
    assert_eq!(snap.wg_steered_listen_port, 51820);
    value
        .as_object_mut()
        .expect("snapshot serializes as an object")
        .remove("wg_steered_listen_port");
    let absent: ConfigSnapshot = serde_json::from_value(value).expect("decode without the key");
    assert_eq!(
        absent.wg_steered_listen_port, 0,
        "a daemon that omits the key must decode to 0, which fails closed"
    );
}
