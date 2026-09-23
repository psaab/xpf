//! Row decoding, production-policy evaluation, and Rust-side emission.
//!
//! The generated corpus is intentionally not an authored oracle.  The Rust
//! result is computed from the same `PolicyState` parser used by the runtime;
//! the Go consumer independently compiles `config_set_lines` and compares its
//! `Match` result with this result.

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub(crate) const SEED_ROWS: &str =
    include_str!("../../../testdata/policy_generated_corpus/seed_rows.json");
pub(crate) const DIVERGENCES: &str =
    include_str!("../../../testdata/policy_generated_corpus/known_divergences.json");
pub(crate) const SEED_MANIFEST: &str =
    include_str!("../../../testdata/policy_generated_corpus/seed_manifest.json");

/// Fixed proptest seed for the cross-language emitter
/// (`strategy::emitted_configs`). Every `generated-NNN` row records this value
/// in `emitter_seed`, so an emitted evidence directory regenerates
/// byte-identically from the same sources.
pub(crate) const EMITTER_SEED: u64 = 10587;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct GeneratedRow {
    pub schema_version: u32,
    pub id: String,
    #[serde(default)]
    pub source_case: String,
    pub config_set_lines: Vec<String>,
    pub query: GeneratedQuery,
    #[serde(default)]
    pub go_verdict: Option<GeneratedVerdict>,
    pub rust_verdict: GeneratedVerdict,
    #[serde(default)]
    pub snapshot: Option<GeneratedSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emitter_seed: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct GeneratedQuery {
    pub from_zone: String,
    pub to_zone: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub src_port: u16,
    pub dst_port: u16,
    #[serde(default)]
    pub frag: bool,
    #[serde(default = "default_l4_present")]
    pub l4_present: bool,
    #[serde(default)]
    pub icmp_type: Option<u8>,
    #[serde(default)]
    pub icmp_code: Option<u8>,
}

fn default_l4_present() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct GeneratedVerdict {
    pub action: String,
    pub matched: bool,
    pub default_used: bool,
    #[serde(default)]
    pub unsupported_tuple_family: bool,
    #[serde(default)]
    pub policy_name: String,
    #[serde(default)]
    pub policy_id: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct GeneratedSnapshot {
    #[serde(default)]
    pub default_policy: String,
    #[serde(default)]
    pub rules: Vec<PolicyRuleSnapshot>,
    #[serde(default)]
    pub zones: Vec<ZoneSnapshot>,
    #[serde(default)]
    pub address_books: Vec<AddressBookSnapshot>,
}

#[derive(Clone, Debug, Deserialize)]
struct GeneratedCorpus {
    #[allow(dead_code)]
    schema_version: u32,
    rows: Vec<GeneratedRow>,
}

#[derive(Clone, Debug, Deserialize)]
struct DivergenceFile {
    #[allow(dead_code)]
    _note: Option<String>,
    #[serde(default)]
    divergences: Vec<GeneratedDivergence>,
}

#[derive(Clone, Debug, Deserialize)]
struct GeneratedDivergence {
    id: String,
    #[allow(dead_code)]
    issue: Option<String>,
}

pub(crate) fn seed_rows() -> Vec<GeneratedRow> {
    let corpus: GeneratedCorpus =
        serde_json::from_str(SEED_ROWS).expect("policy_generated_corpus/seed_rows.json parses");
    assert_eq!(corpus.schema_version, 1, "unsupported generated-row schema");
    corpus.rows
}

pub(crate) fn divergence_ids() -> BTreeMap<String, ()> {
    let file: DivergenceFile = serde_json::from_str(DIVERGENCES)
        .expect("policy_generated_corpus/known_divergences.json parses");
    file.divergences.into_iter().map(|d| (d.id, ())).collect()
}

#[derive(Clone, Debug, Deserialize)]
struct SeedManifest {
    #[allow(dead_code)]
    schema_version: u32,
    ids: Vec<String>,
}

pub(crate) fn manifest_ids() -> Vec<String> {
    let manifest: SeedManifest = serde_json::from_str(SEED_MANIFEST)
        .expect("policy_generated_corpus/seed_manifest.json parses");
    assert_eq!(
        manifest.schema_version, 1,
        "unsupported seed-manifest schema"
    );
    manifest.ids
}

fn protocol_number(name: &str) -> u8 {
    parse_protocol(name).unwrap_or_else(|| {
        name.parse::<u8>()
            .unwrap_or_else(|_| panic!("generated row uses unknown protocol {name:?}"))
    })
}

fn action_name(action: PolicyAction) -> &'static str {
    match action {
        PolicyAction::Permit => "permit",
        PolicyAction::Deny => "deny",
        PolicyAction::Reject => "reject",
    }
}

fn snapshot_state(snapshot: &GeneratedSnapshot) -> PolicyState {
    let zone_map = zone_name_to_id_from_snapshot(&snapshot.zones);
    parse_policy_state_with_counters(
        &snapshot.default_policy,
        &snapshot.rules,
        &zone_map,
        &snapshot.address_books,
        &PolicyCounterStore::default(),
    )
    .unwrap_or_else(|err| panic!("generated snapshot is refused by policy parser: {err:?}"))
}

pub(crate) fn evaluate_row(row: &GeneratedRow) -> GeneratedVerdict {
    let snapshot = row
        .snapshot
        .as_ref()
        .unwrap_or_else(|| panic!("row {} has no production snapshot", row.id));
    let state = snapshot_state(snapshot);
    let zones = zone_name_to_id_from_snapshot(&snapshot.zones);
    let from_id = zones.get(&row.query.from_zone).copied().unwrap_or(0);
    let src: IpAddr = row
        .query
        .src_ip
        .parse()
        .expect("generated source IP parses");
    let dst: IpAddr = row
        .query
        .dst_ip
        .parse()
        .expect("generated destination IP parses");
    let protocol = protocol_number(&row.query.protocol);
    let l4_present = row.query.l4_present && !row.query.frag;
    let (src_port, dst_port) = if l4_present {
        (row.query.src_port, row.query.dst_port)
    } else {
        (0, 0)
    };
    let packet_icmp = row
        .query
        .icmp_type
        .map(|typ| (typ, row.query.icmp_code.unwrap_or(0)));

    let (action, matched, default_used, policy_id) = if row.query.to_zone == JUNOS_HOST_ZONE_NAME {
        match evaluate_junos_host_policy_l3_aware(
            &state,
            from_id,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            packet_icmp,
            0,
            l4_present,
        ) {
            None => ("permit", false, false, 0),
            Some(result) => (
                action_name(result.action),
                result.policy_counter_idx != DEFAULT_POLICY_COUNTER_IDX
                    && result.policy_counter_idx != 0,
                result.policy_counter_idx == DEFAULT_POLICY_COUNTER_IDX,
                result.policy_id,
            ),
        }
    } else {
        let to_id = zones.get(&row.query.to_zone).copied().unwrap_or(0);
        let result = evaluate_policy_result_l3_aware(
            &state,
            from_id,
            to_id,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            packet_icmp,
            0,
            l4_present,
        );
        (
            action_name(result.action),
            result.policy_counter_idx != DEFAULT_POLICY_COUNTER_IDX
                && result.policy_counter_idx != 0,
            result.policy_counter_idx == DEFAULT_POLICY_COUNTER_IDX,
            result.policy_id,
        )
    };

    let policy_name = if matched {
        snapshot
            .rules
            .iter()
            .find(|rule| rule.policy_id == policy_id)
            .map(|rule| rule.name.clone())
            .unwrap_or_default()
    } else {
        String::new()
    };
    GeneratedVerdict {
        action: action.to_string(),
        matched,
        default_used,
        unsupported_tuple_family: false,
        policy_name,
        policy_id: if matched { policy_id } else { 0 },
    }
}

pub(crate) fn assert_row_oracle(row: &GeneratedRow) {
    let got = evaluate_row(row);
    assert_eq!(
        got, row.rust_verdict,
        "row {} has stale or incorrect rust_verdict (computed from production PolicyState)",
        row.id
    );
}

pub(crate) fn emit_seed_rows(dir: &Path) {
    fs::create_dir_all(dir).expect("create XPF_EMIT_POLICY_ROWS directory");
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("generated-")
                && name.to_string_lossy().ends_with(".json")
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    for mut row in seed_rows() {
        row.rust_verdict = evaluate_row(&row);
        let path = dir.join(format!("{}.json", row.id));
        let data = serde_json::to_vec_pretty(&row).expect("serialize generated policy row");
        fs::write(path, [data.as_slice(), b"\n"].concat()).expect("write generated policy row");
    }
}

pub(crate) fn emit_generated_rows(dir: &Path, cases: u32) {
    for (index, config) in super::strategy::emitted_configs(cases)
        .into_iter()
        .enumerate()
    {
        let mut row = GeneratedRow {
            schema_version: 1,
            id: format!("generated-{index:03}"),
            source_case: "generated-config".to_string(),
            config_set_lines: config.set_lines,
            query: config.query,

            go_verdict: None,
            rust_verdict: GeneratedVerdict::default(),
            snapshot: Some(config.snapshot),
            emitter_seed: Some(EMITTER_SEED),
        };
        row.rust_verdict = evaluate_row(&row);
        let path = dir.join(format!("{}.json", row.id));
        let data = serde_json::to_vec_pretty(&row).expect("serialize generated policy row");
        fs::write(path, [data.as_slice(), b"\n"].concat()).expect("write generated policy row");
    }
}
pub(crate) fn restamp_rows(dir: &Path) {
    let entries = fs::read_dir(dir).expect("read XPF_RESTAMP_POLICY_ROWS directory");
    for entry in entries {
        let path = entry.expect("read emitted row entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let data = fs::read(&path).expect("read emitted policy row");
        let mut row: GeneratedRow =
            serde_json::from_slice(&data).expect("decode emitted policy row");
        row.rust_verdict = evaluate_row(&row);
        let data = serde_json::to_vec_pretty(&row).expect("serialize restamped policy row");
        fs::write(path, [data.as_slice(), b"\n"].concat()).expect("write restamped policy row");
    }
}
