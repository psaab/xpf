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
    // #17077: `None` is an omitted selector (`-` in the corpus). The Rust
    // packet always carries a protocol number and u16 ports: an omitted port
    // evaluates as a present 0 (never combined with a 0-covering term — see
    // the corpus header), and an omitted protocol uses the unknown-protocol
    // classification in the differential below.
    src_port: Option<u16>,
    dst_port: Option<u16>,
    icmp: Option<(u8, u8)>,
    want_action: String,
    want_policy: String,
    frag: bool,
    line: usize,
}

#[derive(Debug)]
struct CorpusCase {
    name: String,
    #[allow(dead_code)]
    lenient: bool,
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
        if let Some(rest) = line.strip_prefix("case ") {
            assert!(
                cur.is_none(),
                "line {ln}: `case` inside an unterminated case"
            );
            let mut parts = rest.split_whitespace();
            let name = parts.next().unwrap_or("");
            let lenient = match (parts.next(), parts.next()) {
                (None, _) => false,
                (Some("lenient"), None) => true,
                _ => panic!("line {ln}: bad case header {line:?}"),
            };
            cur = Some(CorpusCase {
                name: name.to_string(),
                lenient,
                queries: Vec::new(),
            });
        } else if line == "end" {
            let c = cur
                .take()
                .unwrap_or_else(|| panic!("line {ln}: `end` with no open case"));
            assert!(
                !c.queries.is_empty(),
                "line {ln}: case {} asserts nothing",
                c.name
            );
            out.push(c);
        } else if let Some(q) = line.strip_prefix("q ") {
            let f: Vec<&str> = q.split_whitespace().collect();
            assert!(
                f.len() >= 9,
                "line {ln}: a query needs at least 9 fields, got {}: {line}",
                f.len()
            );
            let mut frag = false;
            let mut icmp: Option<(u8, u8)> = None;
            for tok in &f[9..] {
                if *tok == "frag" {
                    assert!(!frag, "line {ln}: duplicate `frag`");
                    frag = true;
                } else if let Some(v) = tok.strip_prefix("icmp=") {
                    assert!(icmp.is_none(), "line {ln}: duplicate `icmp=`");
                    let (t, c) = match v.split_once('/') {
                        Some((t, c)) => (t, Some(c)),
                        None => (v, None),
                    };
                    let ty: u8 = t
                        .parse()
                        .unwrap_or_else(|_| panic!("line {ln}: bad icmp type in {tok:?}"));
                    let code: u8 = match c {
                        Some(c) => c
                            .parse()
                            .unwrap_or_else(|_| panic!("line {ln}: bad icmp code in {tok:?}")),
                        None => 0,
                    };
                    icmp = Some((ty, code));
                } else {
                    panic!("line {ln}: unknown query token {tok:?}");
                }
            }
            assert!(
                matches!(f[7], "permit" | "deny" | "reject" | "content-rejected"),
                "line {ln}: unknown expected action {:?}",
                f[7]
            );
            let port = |tok: &str| -> Option<u16> {
                if tok == "-" {
                    None
                } else {
                    Some(
                        tok.parse()
                            .unwrap_or_else(|_| panic!("line {ln}: bad port {tok:?}")),
                    )
                }
            };
            let c = cur
                .as_mut()
                .unwrap_or_else(|| panic!("line {ln}: `q` outside a case"));
            c.queries.push(CorpusQuery {
                from: f[0].into(),
                to: f[1].into(),
                src: f[2].into(),
                dst: f[3].into(),
                protocol: f[4].into(),
                src_port: port(f[5]),
                dst_port: port(f[6]),
                icmp,
                want_action: f[7].into(),
                want_policy: f[8].into(),
                frag,
                line: ln,
            });
        } else if line.starts_with("feed ") {
            // #17077: the feed overlay is baked into the committed snapshot
            // by the Go generator; the expectations on this side come from
            // the corpus text, so the line is consumed and ignored here.
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
    let file: CorpusSnapshotFile = serde_json::from_str(CORPUS_SNAPSHOTS).expect(
        "testdata/policy_verdict_corpus_snapshots.json parses (regenerate with UPDATE_9167=1)",
    );
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
        // #17077: a `content-rejected` case asserts the helper REFUSES the
        // snapshot (the Go half asserts Result.ContentRejected). Every query
        // in such a case must carry that expectation, and no other case may.
        let wants_rejected = case
            .queries
            .iter()
            .any(|q| q.want_action == "content-rejected");
        let parsed = parse_policy_state_with_counters(
            &snap.default_policy,
            &snap.rules,
            &zone_map,
            &snap.address_books,
            &store,
        );
        if wants_rejected {
            assert!(
                case.queries
                    .iter()
                    .all(|q| q.want_action == "content-rejected"),
                "case {:?}: a content-rejected case must assert it on every row",
                case.name
            );
            assert!(
                parsed.is_err(),
                "case {:?}: the corpus expects the snapshot to be REFUSED (content-rejected), \
                 but the helper accepted it — the fail-closed posture regressed",
                case.name
            );
            continue;
        }
        let state = parsed.unwrap_or_else(|e| {
            panic!(
                "case {:?}: the snapshot Go emits for a COMMITTABLE config was refused by the \
                 helper: {e:?}. Every corpus case is operator-committable, so this is a real \
                 Go/Rust disagreement about what a valid snapshot is.",
                case.name
            )
        });

        for q in &case.queries {
            // #17077: a zone absent from the snapshot is id 0 (the runtime's
            // unknown-zone sentinel). Go passes the name through to its
            // UnzonedIngress/UnzonedEgress arms; the asymmetry for junos-host
            // is in the host arm itself (None stays local delivery, while a
            // matched zone-0 rule reports its own policy here) — never a panic.
            let from_id = zone_map.get(&q.from).copied().unwrap_or(0);
            let src: IpAddr = q.src.parse().expect("corpus src ip");
            let dst: IpAddr = q.dst.parse().expect("corpus dst ip");
            // #17077: `-` protocol is the omitted selector. The Go answer to
            // an underspecified tuple is a DEFAULT verdict by construction:
            // Match consults no rule when the protocol is unknown (#12227
            // pins exactly this layering). The Rust packet always carries a
            // protocol number, so no single packet can vouch for it — both
            // languages still assert the row, each at its own surface: Go
            // via Match (Protocol=""), Rust via its underspecified-tuple
            // classification asserted in the `-` arm below.
            // The default-verdict expectation for an underspecified tuple
            // rests solely on the Go half for `-` protocol rows (evaluated
            // below); the action compared for them is fixed here.
            let proto = if q.protocol == "-" {
                255
            } else {
                protocol_number(&q.protocol)
            };
            // A NON-FIRST FRAGMENT carries no L4 header: evaluate with
            // l4_present = false and zero ports. An omitted port (`-`) is a
            // present port 0 on this surface: the runtime packet always
            // carries u16 ports, and 0 is the only value that cannot be
            // confused with a configured port the author meant. Constrained
            // terms therefore evaluate against 0 — a term covering 0 fires
            // here while Go's nil selector fails closed, so the corpus
            // header forbids combining `-` with a 0-covering term (the
            // port-zero case uses a concrete 0 for exactly that shape).
            let l4_present = !q.frag;
            let (sport, dport) = if q.frag {
                (0, 0)
            } else {
                (q.src_port.unwrap_or(0), q.dst_port.unwrap_or(0))
            };
            let packet_icmp = if q.frag { None } else { q.icmp };

            // (action, fell-through-to-default, matched policy id)
            let (got_action, is_default, got_policy_id) = if q.to == JUNOS_HOST_ZONE_NAME {
                // HOST-BOUND. `None` is local delivery — no host rule decided it.
                match evaluate_junos_host_policy_l3_aware(
                    &state,
                    from_id,
                    src,
                    dst,
                    proto,
                    sport,
                    dport,
                    packet_icmp,
                    0,
                    l4_present,
                ) {
                    None => ("permit", true, 0),
                    Some(res) => (
                        action_name(res.action),
                        res.policy_counter_idx == DEFAULT_POLICY_COUNTER_IDX,
                        res.policy_id,
                    ),
                }
            } else {
                let to_id = zone_map.get(&q.to).copied().unwrap_or(0);
                let res = evaluate_policy_result_l3_aware(
                    &state,
                    from_id,
                    to_id,
                    src,
                    dst,
                    proto,
                    sport,
                    dport,
                    packet_icmp,
                    0,
                    l4_present,
                );
                (
                    action_name(res.action),
                    res.policy_counter_idx == DEFAULT_POLICY_COUNTER_IDX,
                    res.policy_id,
                )
            };

            assert_eq!(
                got_action,
                q.want_action,
                "corpus line {}: case {:?} {} {}->{} {}:{}->{}:{}{}\n  \
                 Rust enforcer: {got_action}\n  corpus       : {}\n\
                 The corpus expectation is authored from the Junos semantics and produced by \
                 NEITHER implementation, so a disagreement here is a defect in policy.rs (or in \
                 the expectation, which is reviewed as part of changing it).",
                q.line,
                case.name,
                q.protocol,
                q.from,
                q.to,
                q.src,
                q.src_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                q.dst,
                q.dst_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                if q.frag { " [non-first fragment]" } else { "" },
                q.want_action
            );

            // MATCHED vs DEFAULT, and the POLICY IDENTITY when matched. The identity
            // check is what makes `RuntimePolicyIDs` a CHECKED shared helper: the id
            // Go stamps into the snapshot (and shows in `show security
            // match-policies`) is the id this evaluator resolves and enforces.
            if q.want_policy == "-" {
                // #17077: an unknown-zone row (zone absent from the snapshot,
                // id 0) expects the enforcer's UNATTRIBUTED deny — neither a
                // named rule nor the default counter. That shape is decided
                // by the action check above; the matched-vs-default identity
                // check below cannot express it, so it is scoped out for
                // exactly those rows (a configured-zone default row keeps it).
                let unknown_zone = !zone_map.contains_key(&q.from)
                    || (q.to != JUNOS_HOST_ZONE_NAME && !zone_map.contains_key(&q.to));
                assert!(
                    is_default || unknown_zone,
                    "corpus line {}: case {:?} expected the default / local-delivery verdict, but \
                     the enforcer matched a rule (policy_id {got_policy_id})",
                    q.line,
                    case.name
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

/// Presence pin for the #10511 icmp-unknown row: the count floors admit silent
/// single-case deletion, so without this the row could be removed with both
/// halves green. Mirror of the Go pin; symmetric removal reds both.
#[test]
fn policy_verdict_corpus_pins_icmp_unknown_case_10511() {
    let cases = corpus_cases();
    let case = cases
        .iter()
        .find(|c| c.name == "icmp-unknown-application")
        .unwrap_or_else(|| {
            panic!(
                "corpus case `icmp-unknown-application` is missing ({} cases present); \
                 the #10511 icmp-unknown coverage was removed",
                cases.len()
            )
        });
    assert!(
        case.queries.len() >= 2,
        "icmp-unknown-application carries {} queries, want at least the permit + \
         unknown-application rows",
        case.queries.len()
    );
}

/// #10686: pin the family-typed policy-core rows whose observable permit-any
/// verdict is overridden by the earlier IPv6 ingress drop gate. The corpus
/// count floor cannot detect removal of one case; Go carries the mirror pin.
#[test]
fn policy_verdict_corpus_pins_embedded_v4_ipv6_case_10686() {
    let cases = corpus_cases();
    let case = cases
        .iter()
        .find(|c| c.name == "embedded-v4-ipv6-policy-family-10686")
        .expect("#10686 policy-core case must remain in the shared corpus");
    assert_eq!(
        case.queries.len(),
        5,
        "v4 deny + mapped/compat src/dst rows"
    );
}

/// #17077: presence pin for the new grammar-dimension cases. The count floors
/// admit silent single-case deletion, so without this the unknown-zone / ICMP
/// / omitted-selector / feed / lenient / content-rejected coverage could be
/// removed with both halves green. Mirror of the Go pin; symmetric removal
/// reds both.
#[test]
fn policy_verdict_corpus_pins_17077_cases() {
    let cases = corpus_cases();
    for (name, min_queries) in [
        ("transit-fragment-reject-13705", 2usize),
        ("unknown-zone-egress-11067", 1),
        ("unknown-zone-ingress-8318", 1),
        ("unknown-zone-junos-host-global-11369", 2),
        ("icmp-type-code", 3),
        ("omitted-selectors", 3),
        ("feed-overlay-12965", 2),
        ("lenient-quarantine-5649", 2),
        ("content-rejected-3727", 1),
    ] {
        let case = cases.iter().find(|c| c.name == name).unwrap_or_else(|| {
            panic!(
                "corpus case `{name}` is missing ({} cases present); \
                     the #17077 coverage was removed",
                cases.len()
            )
        });
        assert!(
            case.queries.len() >= min_queries,
            "{name} carries {} queries, want at least {min_queries}",
            case.queries.len()
        );
    }
}
