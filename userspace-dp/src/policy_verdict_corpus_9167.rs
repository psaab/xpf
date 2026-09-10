// #9167 — the Rust half of the shared policy-verdict corpus differential.
//
// See `testdata/policy_verdict_corpus.txt` for what the corpus is and why it
// exists. The short version: `show security match-policies` had no independent
// oracle. Where `pkg/policymatch` does not share code with the Go write path it
// mirrors THIS FILE'S tier walk by hand, and a hand mirror drifts — #6505
// taught the junos-host gate the #4569 fragment-associated deny by changing
// `policy.rs`, `policy_snapshot_error.rs`, `policy_tests.rs`, `_Log.md` and
// `docs/feature-gaps.md`, and NO Go at all. The Go simulator kept reporting
// PERMIT for a host-bound fragment the box DROPS, for 71 commits, until #6576
// wrote a SECOND hand mirror.
//
// THIS FILE AND `pkg/policymatch/policy_verdict_corpus_9167_test.go` READ THE
// SAME CORPUS. Neither language calls the other. Each drives its own
// implementation and compares to the corpus's authored expectation, so the two
// cannot agree by construction — which is the vacuity the issue names in the
// three shared-helper call sites.
//
// THE EXPECTATIONS REACH THIS SIDE FROM THE CORPUS TEXT, not through Go. The Go
// generator emits only the SNAPSHOT (it must — Go builds the snapshot in
// production, and this evaluator takes a snapshot, not a config). If Go also
// transcribed the expected verdicts, the oracle would arrive here through the
// implementation under test on the other side.
//
// WHAT A FAILURE HERE MEANS. This side disagreeing with the corpus is a defect
// in `policy.rs` or in the expectation. The Go side disagreeing is a defect in
// `pkg/policymatch`. A change to the Rust tier walk that the Go simulator does
// not follow now reds THIS file — which is precisely the event that went
// unnoticed in #6505.

use super::*;
use serde::Deserialize;
use std::net::IpAddr;

const CORPUS_TEXT: &str = include_str!("../../testdata/policy_verdict_corpus.txt");
const CORPUS_SNAPSHOTS: &str = include_str!("../../testdata/policy_verdict_corpus_snapshots.json");

#[derive(Deserialize)]
struct CorpusSnapshot {
    #[serde(default)]
    default_policy: String,
    #[serde(default)]
    rules: Vec<PolicyRuleSnapshot>,
    #[serde(default)]
    zones: Vec<ZoneSnapshot>,
    #[serde(default)]
    address_books: Vec<AddressBookSnapshot>,
}

#[derive(Deserialize)]
struct CorpusSnapshotFile {
    cases: FxHashMap<String, CorpusSnapshot>,
}

#[derive(Debug)]
struct CorpusQuery {
    from: String,
    to: String,
    src: String,
    dst: String,
    protocol: String,
    src_port: u16,
    dst_port: u16,
    want_action: String,
    want_policy: String,
    frag: bool,
    line: usize,
}

#[derive(Debug)]
struct CorpusCase {
    name: String,
    queries: Vec<CorpusQuery>,
}

/// Parse the corpus grammar. Deliberately re-implemented here rather than
/// shared with Go: a shared READER would be one more place the two sides depend
/// on the same code, and the grammar is four line-prefixes.
///
/// The `set` lines are ignored on this side — they are the Go generator's input,
/// and this side consumes the snapshot they produced.
fn corpus_cases() -> Vec<CorpusCase> {
    let mut out: Vec<CorpusCase> = Vec::new();
    let mut cur: Option<CorpusCase> = None;
    for (i, raw) in CORPUS_TEXT.lines().enumerate() {
        let line = raw.trim();
        let ln = i + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix("case ") {
            assert!(cur.is_none(), "line {ln}: `case` inside an unterminated case");
            cur = Some(CorpusCase { name: name.trim().to_string(), queries: Vec::new() });
        } else if line == "end" {
            let c = cur.take().unwrap_or_else(|| panic!("line {ln}: `end` with no open case"));
            assert!(!c.queries.is_empty(), "line {ln}: case {} asserts nothing", c.name);
            out.push(c);
        } else if let Some(q) = line.strip_prefix("q ") {
            let f: Vec<&str> = q.split_whitespace().collect();
            assert!(
                f.len() == 9 || (f.len() == 10 && f[9] == "frag"),
                "line {ln}: a query needs 9 fields (+ optional `frag`), got {}: {line}",
                f.len()
            );
            let c = cur.as_mut().unwrap_or_else(|| panic!("line {ln}: `q` outside a case"));
            c.queries.push(CorpusQuery {
                from: f[0].into(), to: f[1].into(), src: f[2].into(), dst: f[3].into(),
                protocol: f[4].into(),
                src_port: f[5].parse().unwrap_or_else(|_| panic!("line {ln}: bad sport")),
                dst_port: f[6].parse().unwrap_or_else(|_| panic!("line {ln}: bad dport")),
                want_action: f[7].into(), want_policy: f[8].into(), frag: f.len() == 10, line: ln,
            });
        } else if line.starts_with("set ") {
            // the Go generator's input; not this side's business
        } else {
            panic!("line {ln}: unrecognized corpus line {line:?}");
        }
    }
    assert!(cur.is_none(), "a case is never terminated by `end`");
    out
}

fn protocol_number(name: &str) -> u8 {
    match name {
        "tcp" => PROTO_TCP,
        "udp" => PROTO_UDP,
        "icmp" => PROTO_ICMP,
        "icmpv6" => PROTO_ICMPV6,
        other => other
            .parse()
            .unwrap_or_else(|_| panic!("corpus: unknown protocol {other:?}")),
    }
}

fn action_name(a: PolicyAction) -> &'static str {
    match a {
        PolicyAction::Permit => "permit",
        PolicyAction::Deny => "deny",
        PolicyAction::Reject => "reject",
    }
}

/// The shared-corpus differential.
///
/// FAIL-ON-REVERT / the acceptance the issue asks for: change the tier walk in
/// `policy.rs` — swap the zone-pair and global tier order, drop the
/// first-match-wins ordering, widen a scoped global to all zones — and this test
/// REDS while the Go half stays green. That is the differential reporting a
/// cross-language disagreement, which is the event #6505 produced and nothing
/// detected.
#[test]
fn policy_verdict_corpus_differential_9167() {
    let file: CorpusSnapshotFile = serde_json::from_str(CORPUS_SNAPSHOTS)
        .expect("testdata/policy_verdict_corpus_snapshots.json parses (regenerate with UPDATE_9167=1)");
    let cases = corpus_cases();

    // The corpus must be non-trivial. A differential whose corpus emptied passes
    // in BOTH languages and reports nothing — the same vacuity one layer up.
    let total_queries: usize = cases.iter().map(|c| c.queries.len()).sum();
    assert!(
        cases.len() >= 8 && total_queries >= 15,
        "the corpus collapsed to {} case(s) / {total_queries} query(ies)",
        cases.len()
    );

    for case in &cases {
        let snap = file.cases.get(&case.name).unwrap_or_else(|| {
            panic!(
                "no snapshot for corpus case {:?}. The committed snapshot file is stale — \
                 regenerate with `UPDATE_9167=1 go test ./pkg/dataplane/userspace/ -run 9167`.",
                case.name
            )
        });

        let zone_map = zone_name_to_id_from_snapshot(&snap.zones);
        let store = PolicyCounterStore::default();
        let state = parse_policy_state_with_counters(
            &snap.default_policy,
            &snap.rules,
            &zone_map,
            &snap.address_books,
            &store,
        )
        .unwrap_or_else(|e| {
            panic!(
                "case {:?}: the snapshot Go emits for a COMMITTABLE config was refused by the \
                 helper: {e:?}. Every corpus case is operator-committable, so this is a real \
                 Go/Rust disagreement about what a valid snapshot is.",
                case.name
            )
        });

        for q in &case.queries {
            let from_id = *zone_map
                .get(&q.from)
                .unwrap_or_else(|| panic!("case {:?} line {}: query from-zone {:?} is not in the snapshot", case.name, q.line, q.from));
            let src: IpAddr = q.src.parse().expect("corpus src ip");
            let dst: IpAddr = q.dst.parse().expect("corpus dst ip");
            let proto = protocol_number(&q.protocol);
            // A NON-FIRST FRAGMENT carries no L4 header: evaluate with
            // l4_present = false and zero ports, exactly as the flowless path does.
            let l4_present = !q.frag;
            let (sport, dport) = if q.frag { (0, 0) } else { (q.src_port, q.dst_port) };

            // (action, fell-through-to-default, matched policy id)
            let (got_action, is_default, got_policy_id) = if q.to == JUNOS_HOST_ZONE_NAME {
                // HOST-BOUND. `None` is local delivery — no host rule decided it.
                match evaluate_junos_host_policy_l3_aware(
                    &state, from_id, src, dst, proto, sport, dport, None, 0, l4_present,
                ) {
                    None => ("permit", true, 0),
                    Some(res) => (action_name(res.action), false, res.policy_id),
                }
            } else {
                let to_id = *zone_map
                    .get(&q.to)
                    .unwrap_or_else(|| panic!("case {:?} line {}: query to-zone {:?} is not in the snapshot", case.name, q.line, q.to));
                let res = evaluate_policy_result_l3_aware(
                    &state, from_id, to_id, src, dst, proto, sport, dport, None, 0, l4_present,
                );
                (
                    action_name(res.action),
                    res.policy_counter_idx == DEFAULT_POLICY_COUNTER_IDX,
                    res.policy_id,
                )
            };

            assert_eq!(
                got_action, q.want_action,
                "corpus line {}: case {:?} {} {}->{} {}:{}->{}:{}{}\n  \
                 Rust enforcer: {got_action}\n  corpus       : {}\n\
                 The corpus expectation is authored from the Junos semantics and produced by \
                 NEITHER implementation, so a disagreement here is a defect in policy.rs (or in \
                 the expectation, which is reviewed as part of changing it).",
                q.line, case.name, q.protocol, q.from, q.to, q.src, q.src_port, q.dst, q.dst_port,
                if q.frag { " [non-first fragment]" } else { "" },
                q.want_action
            );

            // MATCHED vs DEFAULT, and the POLICY IDENTITY when matched. The identity
            // check is what makes `RuntimePolicyIDs` a CHECKED shared helper: the id
            // Go stamps into the snapshot (and shows in `show security
            // match-policies`) is the id this evaluator resolves and enforces.
            if q.want_policy == "-" {
                assert!(
                    is_default,
                    "corpus line {}: case {:?} expected the default / local-delivery verdict, but \
                     the enforcer matched a rule (policy_id {got_policy_id})",
                    q.line, case.name
                );
            } else {
                assert!(
                    !is_default,
                    "corpus line {}: case {:?} expected policy {:?}, but the enforcer fell through \
                     to the default / local delivery",
                    q.line, case.name, q.want_policy
                );
                let want_rule = snap.rules.iter().find(|r| r.name == q.want_policy).unwrap_or_else(|| {
                    panic!(
                        "corpus line {}: case {:?} expects policy {:?}, which is not in the snapshot \
                         Go emitted — the corpus text and the committed snapshot disagree about this \
                         config (regenerate with UPDATE_9167=1)",
                        q.line, case.name, q.want_policy
                    )
                });
                assert_eq!(
                    got_policy_id, want_rule.policy_id,
                    "corpus line {}: case {:?} matched policy id {got_policy_id} but the rule named {:?} \
                     carries id {}. The Go simulator SHOWS the id on the right of this comparison; the \
                     enforcer ENFORCES the one on the left.",
                    q.line, case.name, q.want_policy, want_rule.policy_id
                );
            }
        }
    }
}
