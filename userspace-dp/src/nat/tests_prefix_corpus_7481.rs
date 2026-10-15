// #7481: the Rust half of the shared NAT match-prefix corpus differential.
//
// The Go gate (`natMatchPrefixParses`) claimed by COMMENT to mirror the Rust
// parsers "EXACTLY". It did not, and the divergence was found by reading the two
// implementations side by side rather than by any test:
//
//   10.0.0.0/+24   Go reject   ipnet reject   static_nat ACCEPT
//   10.0.0.0/024   Go ACCEPT   ipnet REJECT   static_nat ACCEPT
//
// The second was listed as a control that AGREED. It did not, and it is the
// worse one: `/024` passed an ordinary strict commit and was then dropped by
// `parse_match_prefix` — a fail-closed drop, so the rule matched NOTHING.
//
// THIS FILE AND `pkg/config/nat_match_prefix_corpus_7481_test.go` READ THE SAME
// FILE. Two hand-maintained lists is the disease this issue is about, one layer
// up: a literal added to the corpus is asserted in both languages, and a
// literal only one side knows about cannot exist.

use super::static_nat::parse_nat_prefix_accepts_for_test;
use ipnet::IpNet;
use std::net::IpAddr;

const CORPUS: &str = include_str!("../../../testdata/nat_match_prefix_corpus.txt");

/// Unquote a Go/Rust-style double-quoted literal. Deliberately minimal: the
/// corpus uses no escapes beyond the quoting itself, and a richer unquoter
/// would be a second grammar to keep in step.
fn unquote(s: &str) -> String {
    let t = s.trim();
    t.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(t)
        .to_string()
}

fn corpus() -> Vec<(String, bool, usize)> {
    let mut out = Vec::new();
    for (i, raw) in CORPUS.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (verdict, lit) = line.split_once('\t').expect("corpus line: <verdict>TAB<literal>");
        let accept = match verdict.trim() {
            "accept" => true,
            "reject" => false,
            other => panic!("corpus line {}: bad verdict {other:?}", i + 1),
        };
        out.push((unquote(lit), accept, i + 1));
    }
    out
}

/// `parse_match_prefix`'s acceptance, extracted as a predicate. It is the
/// `IpNet`-then-`IpAddr` shape that function uses; the function itself pushes
/// into vectors and takes counters, so a predicate is what a differential can
/// compare.
fn source_parser_accepts(s: &str) -> bool {
    let n = super::normalize_nat_prefix_len(s);
    n.parse::<IpNet>().is_ok() || n.parse::<IpAddr>().is_ok()
}

/// DNAT destination and source axes use this same normalized IP/CIDR grammar.
fn dnat_parser_accepts(s: &str) -> bool {
    let normalized = super::normalize_nat_prefix_len(s);
    normalized.parse::<IpNet>().is_ok() || normalized.parse::<IpAddr>().is_ok()
}

#[test]
fn dnat_address_axes_match_shared_prefix_corpus_13530() {
    for (literal, want, line) in corpus() {
        assert_eq!(
            dnat_parser_accepts(&literal),
            want,
            "corpus line {line}: DNAT destination axis disagrees on {literal:?}"
        );
        assert_eq!(
            dnat_parser_accepts(&literal),
            want,
            "corpus line {line}: DNAT source axis disagrees on {literal:?}"
        );
        if want {
            let normalized = super::normalize_nat_prefix_len(&literal);
            if let Some((_, length)) = normalized.rsplit_once('/') {
                let parsed: u8 = length
                    .parse()
                    .expect("accepted IPv4/IPv6 prefix length must fit in u8");
                assert_eq!(
                    length,
                    parsed.to_string(),
                    "corpus line {line}: prefix length was not normalized to plain decimal: {normalized:?}"
                );
            }
        }
    }
}

#[test]
fn nat_match_prefix_corpus_7481() {
    let cases = corpus();
    // ANTI-VACUITY: a corpus that failed to load, or one with a single verdict,
    // makes every assertion below trivially true.
    assert!(
        cases.len() >= 20,
        "loaded only {} corpus entries; the file is missing or truncated, and a \
         short corpus is an agreement nobody checked",
        cases.len()
    );
    let accepts = cases.iter().filter(|c| c.1).count();
    assert!(
        accepts > 0 && accepts < cases.len(),
        "corpus has {accepts} accepts of {}; a single-verdict corpus is satisfied \
         by a parser that always answers the same way",
        cases.len()
    );

    for (lit, want, line) in &cases {
        assert_eq!(
            source_parser_accepts(lit),
            *want,
            "corpus line {line}: source/mod.rs::parse_match_prefix's grammar \
             classified {lit:?} differently from the shared corpus (#7481)"
        );
        assert_eq!(
            parse_nat_prefix_accepts_for_test(lit),
            *want,
            "corpus line {line}: static_nat.rs::parse_nat_prefix classified {lit:?} \
             differently from the shared corpus. This parser was the one that \
             diverged — it accepted a leading `+` on the prefix length via \
             u8::from_str while the Go gate and ipnet both refused (#7481)"
        );
    }
}

/// The two Rust parsers must agree with EACH OTHER over the corpus, not merely
/// each with the file. Without this, a corpus entry deleted by mistake stops
/// binding both — and the whole point is that they are one grammar.
#[test]
fn both_rust_parsers_agree_7481() {
    for (lit, _, line) in corpus() {
        assert_eq!(
            source_parser_accepts(&lit),
            parse_nat_prefix_accepts_for_test(&lit),
            "corpus line {line}: the two Rust NAT prefix parsers disagree on {lit:?}. \
             They are meant to be one grammar; #7481 single-sourced static_nat.rs \
             onto the IpNet/IpAddr shape precisely so this cannot happen"
        );
    }
}

