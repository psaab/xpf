// #4555: parity between the AF_XDP shim's IPv6 extension-header walk and
// this crate's `walk_ipv6_ext_chain`.
//
// The shim's verdict decides whether a packet matches the session map and
// takes the XDP fast path; this crate's decides how the packet is actually
// forwarded. When they disagree the shim computes a session key userspace
// never installed, so every packet of that flow is redirected to userspace
// — fail-closed, but a permanent loss of the fast path. Two divergences
// existed before #4555: the resolvable chain length (6 vs 7) and the
// walked type set (#4517's Mobility/HIP/Shim6/experimental were missing).
//
// WHY THIS READS EMITTED FACTS AND MODELS NOTHING.
//
// The shim cannot be executed here: it is `no_std`, built for
// `bpfel-unknown-none`. Four successive versions of this test MODELLED it
// from source text, and every one leaked to a more ordinary edit:
//
//   1. classifying arm bodies by substring accepted an extra `+ 8` on the
//      generic advance;
//   2. it also accepted a prepended `if opt[1] == 0 { break; }` — which
//      rejects the ORDINARY 8-byte HbH/DestOpt, destroying parity for
//      essentially every real chain;
//   3. pinning whole arm bodies by token equality still ignored a
//      statement placed inside the walk loop but OUTSIDE the `match`;
//   4. pinning the TEXT `mem::size_of::<FragHdr>()` did not pin its
//      VALUE, so one added field changed the Fragment advance invisibly;
//   5. and the struct-layout resolver written to fix (4) split fields on
//      commas and skipped `//` fragments, so a COMMENT above a field hid
//      the field with it.
//
// Five leaks, each to a more innocuous edit than the last. Every fix was a
// better model, and a better model is still a model.
//
// The first inversion emitted three facts (`XPF_SHIM_FACTS`: `MAX_EXT_HDRS`,
// `size_of::<FragHdr>()`, the 256-entry class table), recorded by
// `make generate` in `pkg/dataplane/userspace_xdp_manifest.json`. That closed
// the tautology — a falsified manifest reds against the object — but it did NOT
// close the coverage, and claiming "nothing left to defeat" was wrong. Three
// scalars cannot witness the walk's BEHAVIOUR. Four edits to the shim left every
// test here green: changing the generic advance to `* 16`, changing the AH
// advance to `* 8`, adding `if offset > 200 { break; }` in the loop body outside
// the `match` (leak #3, verbatim), and — worst — DELETING the generic arm's
// post-advance bounds revalidation, the security property. Worse still, the one
// thing that did red was the #4977 freshness hash, whose message says the object
// may be stale and to run `make generate`; following it regenerates identical
// facts and ships the divergence.
//
// So the walk itself is now EXECUTED. `userspace-xdp/src/ipv6_ext_walk.rs`
// holds the shim's real walk in a module that depends only on `core`, the shim
// calls it, and this file `#[path]`-includes THAT FILE and runs it on real byte
// buffers alongside `walk_ipv6_ext_chain`. Advance arithmetic, bounds
// revalidation and resolvable chain length are outcomes compared over a corpus,
// not claims about source text. The emitted facts are kept for what they are
// uniquely good at: travelling with the ARTIFACT, so a consumer of a prebuilt
// object (the Debian packaging path never compiles the shim crate) can check
// them without a Rust toolchain.
//
// It also fixes a scope problem the source model could not: a compile-time
// assertion in the shim only runs when the shim crate is compiled, which
// the Debian packaging path never does (it runs `make build`, and the
// daemon embeds the tracked `.o`). Facts recorded in the manifest are
// checkable wherever a prebuilt object is consumed.
//
// No source-text check remains. The exhaustion semantics that make the shim
// resolve `MAX_EXT_HDRS` headers where this crate resolves
// `MAX_IPV6_EXT_HEADERS - 1` used to be the one property argued to be
// unemittable — "a shape, not a value". Executing the walk dissolves that:
// the corpus below walks chains of 0..=10 extension headers and compares
// verdicts, so the resolvable length is measured on both sides rather than
// asserted about either.

#![allow(unused_imports)]

use super::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

// IPv6 next-header values used throughout this file. TCP is the terminal
// every probe and corpus chain ends on.
const TCP: u8 = 6;
const HBH: u8 = 0;
const AH: u8 = 51;
const FRAG: u8 = 44;
const DEST: u8 = 60;
const MOBILITY: u8 = 135;
// The rest of the GENERIC class (`eh_class` in ipv6_ext_walk.rs). They share
// one `match` arm, so they share its advance and its revalidation — and an
// error keyed on ONE of them is invisible to a witness pair written for
// another. See `ARM_BOUNDARIES`.
const ROUTING: u8 = 43;
const HIP: u8 = 139;
const SHIM6: u8 = 140;
const EXP1: u8 = 253;
const EXP2: u8 = 254;

// Extension-header classes, mirroring EH_CLASS_* in
// userspace-xdp/src/lib.rs and pkg/dataplane/userspace_xdp_facts.go.
// These are the values carried in the emitted table.
const EH_CLASS_TERMINAL: u8 = 0;
const EH_CLASS_GENERIC: u8 = 1;
const EH_CLASS_AUTH: u8 = 2;
const EH_CLASS_FRAGMENT: u8 = 3;
const EH_CLASS_NONEXT: u8 = 4;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <repo>/userspace-dp.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The shim facts `make generate` recorded alongside the tracked object.
struct ShimFacts {
    max_ext_hdrs: usize,
    frag_hdr_size: usize,
    eh_classes: Vec<u8>,
}

/// Read the emitted facts out of the committed manifest.
///
/// Fails LOUDLY on a missing or unreadable manifest — never skips. A skip
/// would fail open on exactly the drift this exists to catch, the hole
/// `pkg/dataplane/userspace_xdp_manifest.go` calls out for
/// `TestMaxInterfacesMatchesCHeader`'s `t.Skipf`.
fn read_shim_facts() -> ShimFacts {
    let path = repo_root()
        .join("pkg")
        .join("dataplane")
        .join("userspace_xdp_manifest.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read the shim manifest at {}: {e}. It carries the shim's emitted #4555 \
             facts; run `make generate`. This guard must not be skipped.",
            path.display()
        )
    });

    let facts = json_object_field(&raw, "\"shim_facts\"").unwrap_or_else(|| {
        panic!(
            "the shim manifest has no `shim_facts` block — run `make generate` with a shim that \
             emits XPF_SHIM_FACTS (#4555). Refusing to fall back to modelling the shim's source."
        )
    });

    let max_ext_hdrs = json_number(&facts, "max_ext_hdrs");
    let frag_hdr_size = json_number(&facts, "frag_hdr_size");
    let eh_classes = json_hex_bytes(&facts, "eh_classes_hex");
    assert_eq!(
        eh_classes.len(),
        256,
        "shim_facts.eh_classes has {} entries, want one per IPv6 next-header value",
        eh_classes.len()
    );
    ShimFacts {
        max_ext_hdrs,
        frag_hdr_size,
        eh_classes,
    }
}

// Minimal JSON readers. The manifest is generated by `encoding/json` with
// a fixed shape, so a full parser would be a dependency for no benefit.
// Every helper panics rather than defaulting, so a shape change is loud.

fn json_object_field(src: &str, key: &str) -> Option<String> {
    let at = src.find(key)?;
    let open = src[at..].find('{')? + at;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[open..open + i + 1].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn json_number(obj: &str, key: &str) -> usize {
    let needle = format!("\"{key}\"");
    let at = obj
        .find(&needle)
        .unwrap_or_else(|| panic!("shim_facts has no `{key}` — run `make generate` (#4555)"));
    let rest = &obj[at + needle.len()..];
    let colon = rest.find(':').expect("malformed shim_facts JSON");
    let digits: String = rest[colon + 1..]
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits
        .parse()
        .unwrap_or_else(|e| panic!("shim_facts.{key} is not a number ({digits:?}): {e}"))
}

fn json_hex_bytes(obj: &str, key: &str) -> Vec<u8> {
    let needle = format!("\"{key}\"");
    let at = obj
        .find(&needle)
        .unwrap_or_else(|| panic!("shim_facts has no `{key}` — run `make generate` (#4555)"));
    let rest = &obj[at + needle.len()..];
    let colon = rest.find(':').expect("malformed shim_facts JSON");
    let tail = &rest[colon + 1..];
    let open = tail.find('"').expect("shim_facts hex string not found");
    let close = tail[open + 1..]
        .find('"')
        .expect("shim_facts hex string unterminated")
        + open
        + 1;
    let hex = &tail[open + 1..close];
    assert!(
        hex.len() % 2 == 0,
        "shim_facts.{key} has an odd hex length {}",
        hex.len()
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("shim_facts.{key} byte at {i}: {e}"))
        })
        .collect()
}

/// Classify one next-header value by RUNNING this crate's walker over a
/// probe packet. The probe is a 40-byte IPv6 header whose Next Header is
/// the value under test, followed by one header at offset 40 declaring
/// `HdrExtLen = 1` and `next = TCP`. The walking arms then land the
/// terminal L4 at three distinguishable offsets:
///   generic  → 40 + (1 + 1) * 8 = 56
///   AH       → 40 + (1 + 2) * 4 = 52
///   fragment → 40 + 8           = 48   (and records a Fragment sighting)
/// while a terminal value stops at 40 reporting itself, and 59 reports
/// `NoNextHeader`.
fn userspace_class(proto: u8) -> u8 {
    let mut buf = vec![0u8; 96];
    buf[0] = 0x60;
    buf[6] = proto;
    buf[40] = TCP;
    buf[41] = 1;
    let walk = walk_ipv6_ext_chain(&buf, 0);
    match walk.outcome {
        ExtChainOutcome::NoNextHeader => EH_CLASS_NONEXT,
        ExtChainOutcome::L4(40, p) => {
            assert_eq!(
                p, proto,
                "probe for next-header {proto} stopped at offset 40 reporting protocol {p}"
            );
            EH_CLASS_TERMINAL
        }
        ExtChainOutcome::L4(56, TCP) => EH_CLASS_GENERIC,
        ExtChainOutcome::L4(52, TCP) => EH_CLASS_AUTH,
        ExtChainOutcome::L4(48, TCP) => {
            assert!(
                walk.fragment.is_some(),
                "probe for next-header {proto} advanced 8 bytes without recording a Fragment \
                 sighting — the probe can no longer distinguish the Fragment arm"
            );
            EH_CLASS_FRAGMENT
        }
        other => panic!(
            "probe for next-header {proto} produced an unclassifiable outcome {other:?}; the \
             #4555 parity probe needs updating for the new walker shape"
        ),
    }
}

/// Bytes this crate's walker advances past a Fragment header, measured.
fn userspace_fragment_advance() -> usize {
    let mut buf = vec![0u8; 96];
    buf[0] = 0x60;
    buf[6] = FRAG;
    buf[40] = TCP;
    match walk_ipv6_ext_chain(&buf, 0).outcome {
        ExtChainOutcome::L4(off, TCP) => off - 40,
        other => panic!("the userspace fragment probe no longer resolves to TCP ({other:?})"),
    }
}

/// Build `n` chained 8-byte DestOpt headers terminated by TCP and report
/// whether this crate's walker resolves the terminal.
fn userspace_resolves_chain_of(n: usize) -> bool {
    let mut buf = vec![0u8; 40 + 8 * n + 20];
    buf[0] = 0x60;
    buf[6] = if n == 0 { TCP } else { DEST };
    for i in 0..n {
        let at = 40 + 8 * i;
        buf[at] = if i + 1 == n { TCP } else { DEST };
    }
    matches!(
        walk_ipv6_ext_chain(&buf, 0).outcome,
        ExtChainOutcome::L4(off, TCP) if off == 40 + 8 * n
    )
}

/// Longest chain this crate resolves, measured rather than read off the
/// constant.
fn userspace_max_resolvable_ext_headers() -> usize {
    for n in 0..64 {
        if !userspace_resolves_chain_of(n) {
            return n.saturating_sub(1);
        }
    }
    panic!("walk_ipv6_ext_chain resolved a 64-header chain; it is meant to be bounded");
}

fn class_name(c: u8) -> &'static str {
    match c {
        EH_CLASS_TERMINAL => "Terminal",
        EH_CLASS_GENERIC => "Generic",
        EH_CLASS_AUTH => "Auth",
        EH_CLASS_FRAGMENT => "Fragment",
        EH_CLASS_NONEXT => "NoNext",
        _ => "UNKNOWN",
    }
}

/// The load-bearing #4555 guard: the shim's EMITTED facts and this crate's
/// MEASURED behaviour must agree on the resolvable chain length, the
/// Fragment advance, and the classification of all 256 next-header values.
#[test]
fn shim_ipv6_ext_walk_matches_userspace_walker() {
    let facts = read_shim_facts();

    // Chain length. The bounds are ITERATION counts over loops that exit
    // differently: the shim spends one iteration per header and exits by
    // exhaustion carrying the resolved protocol into parse_l4, so it
    // resolves MAX_EXT_HDRS headers; walk_ipv6_ext_chain needs one FURTHER
    // iteration to return the terminal and folds exhaustion into the
    // fail-closed OverLimit verdict, so it resolves
    // MAX_IPV6_EXT_HEADERS - 1. The relation is therefore
    // `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1`, NOT numeric equality —
    // setting the shim to 8 would make it resolve chains this crate fails
    // closed on. What pins the exit semantics this reasoning rests on is the
    // corpus in `shim_walk_and_userspace_walk_agree_over_a_corpus`, which walks
    // chains of 0..=10 extension headers through BOTH walkers and compares
    // verdicts — so the resolvable length is measured on each side rather than
    // argued about either. (An earlier revision cited a source-text check named
    // `shim_walk_exits_by_exhaustion`; that test was deleted when the walk
    // became executable, and this sentence outlived it.)
    let userspace_max = userspace_max_resolvable_ext_headers();
    assert_eq!(
        facts.max_ext_hdrs, userspace_max,
        "#4555 IPv6 extension-header CHAIN-LENGTH drift: the shipped shim resolves chains of up \
         to {} extension headers (its emitted MAX_EXT_HDRS) but this crate's \
         walk_ipv6_ext_chain resolves up to {userspace_max} (MAX_IPV6_EXT_HEADERS = {}). A chain \
         length one side resolves and the other does not makes the two compute different session \
         keys for the same packet, so the flow's key never matches and every packet takes the \
         slow XSK path forever. Raising the shim's bound costs BPF verifier budget and is gated \
         by the #1864 verify-then-install run: change it, re-run `make generate`, and commit the \
         regenerated object and manifest.",
        facts.max_ext_hdrs, MAX_IPV6_EXT_HEADERS,
    );
    assert_eq!(
        facts.max_ext_hdrs,
        MAX_IPV6_EXT_HEADERS - 1,
        "#4555: emitted MAX_EXT_HDRS ({}) != MAX_IPV6_EXT_HEADERS - 1 ({})",
        facts.max_ext_hdrs,
        MAX_IPV6_EXT_HEADERS - 1,
    );

    // Fragment advance, compared as a VALUE on both sides: the shim's
    // emitted size_of::<FragHdr>() against this crate's measured advance.
    let userspace_frag = userspace_fragment_advance();
    assert_eq!(
        facts.frag_hdr_size, userspace_frag,
        "#4555 Fragment-header ADVANCE drift: the shipped shim advances {} bytes past a Fragment \
         header (its emitted size_of::<FragHdr>()) but this crate advances {userspace_frag}. \
         Every L4 offset in a fragmented IPv6 chain would differ between the two, so the shim's \
         session key points at the wrong bytes. The IPv6 Fragment header is fixed at 8 bytes \
         (RFC 8200 §4.5) — if FragHdr changed, that is the bug.",
        facts.frag_hdr_size,
    );

    // Every next-header value: emitted class vs measured class.
    let mut drift: Vec<String> = Vec::new();
    for proto in 0u16..=255 {
        let proto = proto as u8;
        let shim = facts.eh_classes[usize::from(proto)];
        let userspace = userspace_class(proto);
        if shim != userspace {
            drift.push(format!(
                "next-header {proto}: shim={} userspace={}",
                class_name(shim),
                class_name(userspace)
            ));
        }
    }
    assert!(
        drift.is_empty(),
        "#4555 IPv6 extension-header TYPE-SET drift between the shipped shim's emitted \
         classification and this crate's walk_ipv6_ext_chain: {drift:?}. A type one side walks \
         THROUGH and the other treats as terminal makes the two compute different session keys \
         for the same packet, so the flow never matches the XDP fast path. Change both walkers \
         together, and re-run `make generate` for the shim side.",
    );
}

/// NEGATIVE CONTROL for the mutation proof.
///
/// Touches NOTHING on the shim side — no manifest, no shim source. It
/// exercises only this crate's walker and the probe harness the guard
/// measures with, so it stays green under every shim-side mutation and
/// reds only if this crate's behaviour or the probes broke.
#[test]
fn shim_ext_parity_negative_control_unchanged_classifications() {
    for (proto, want) in [
        (0u8, EH_CLASS_GENERIC), // Hop-by-Hop
        (43, EH_CLASS_GENERIC),  // Routing
        (60, EH_CLASS_GENERIC),  // Destination Options
        (44, EH_CLASS_FRAGMENT), // Fragment
        (51, EH_CLASS_AUTH),     // Authentication Header
        (59, EH_CLASS_NONEXT),   // No Next Header
        (50, EH_CLASS_TERMINAL), // ESP — deliberately NOT walked
        (6, EH_CLASS_TERMINAL),  // TCP
        (17, EH_CLASS_TERMINAL), // UDP
        (58, EH_CLASS_TERMINAL), // ICMPv6
    ] {
        assert_eq!(
            userspace_class(proto),
            want,
            "userspace classification of next-header {proto} changed; this is pre-#4555 \
             behaviour the fix must not perturb"
        );
    }

    for n in [0usize, 1, 5] {
        assert!(
            userspace_resolves_chain_of(n),
            "userspace walker stopped resolving a {n}-header chain"
        );
    }
    assert!(
        !userspace_resolves_chain_of(16),
        "userspace walker resolved a 16-header chain; it is meant to fail closed"
    );
    assert_eq!(
        userspace_max_resolvable_ext_headers(),
        MAX_IPV6_EXT_HEADERS - 1,
        "the userspace walker's resolvable chain length no longer matches its own bound; the \
         #4555 measurement harness is broken, independently of the shim"
    );
    assert_eq!(
        userspace_fragment_advance(),
        8,
        "the userspace walker no longer advances 8 bytes past a Fragment header (RFC 8200 §4.5)"
    );
}

// ---------------------------------------------------------------------------
// #4555: BEHAVIOURAL parity — the shim's real walk, executed.
// ---------------------------------------------------------------------------
//
// `ipv6_ext_walk.rs` is the shim's own source. It is `#[path]`-included here and
// compiled for the host, so what runs below is the code the BPF object is built
// from — not a description of it. Everything the source models used to assert
// (advance arithmetic per arm, the post-advance bounds revalidation, the
// resolvable chain length, which types are walked) becomes an observable
// outcome of running it.
//
// PROVING THESE GUARDS FIRE: `make test-shim-ext-parity-lib` (#7766; ~40 min,
// it rebuilds the shim per mutant, so it is in no aggregate). It runs
// `test/mutation/shim-ext-parity-acceptance.sh`, which
// mutates `ipv6_ext_walk.rs` — each arm's advance arithmetic, each arm's
// post-advance revalidation (deleted, and weakened by one byte), the Fragment
// read length, the revalidation's L3 base, a statement inside the loop but
// outside the `match`, AND (#6920) the two constants #4555 actually delivered:
// `MAX_EXT_HDRS` in both directions and the `eh_class` generic arm — and
// requires the guards below to red on every one, plus a semantically null edit
// that must SURVIVE. It is not run by `make test` (each row is a full release
// rebuild); run it after changing either walker, or after narrowing anything
// the corpus compares. A guard is worth what its mutation matrix says it is
// worth.
//
// #6920, and read this before trusting the sentence above: until that change
// the enumeration omitted `MAX_EXT_HDRS` and `eh_class`, so "PROVING THESE
// GUARDS FIRE" overstated its own coverage — it did not exercise either half
// of what #4555 shipped. Worse, the harness could not COMPLETE a run: a
// mutation that panics rather than asserting left its reason unextractable
// once the toolchain began printing thread ids, and the extraction failure
// aborted the whole matrix at row 7, so rows 8-21 silently never ran.
//
// Both are fixed there. What is NOT fixed, and is tracked by #7766: this
// harness is wired into no gate — not `run-selftests.sh`, not any Makefile
// target, no CI — so its alarm is loud and nothing is listening, which is why
// the rot survived. `pkg/dataplane/userspace/link_cycle_acquisition_site_6871_test.go`
// states the general form: "A shipped comment asserting an enforcement that is
// absent is worse than no comment: it is the reason the next reader does not
// add the check." A comment asserting an enforcement that exists but never
// RUNS is the same defect one step out.
#[path = "../../../../userspace-xdp/src/ipv6_ext_walk.rs"]
mod shim_walk;

/// A verdict both walkers can be reduced to, so they can be compared directly.
///
/// This is EXACTLY what the shim's walk returns, renormalised — nothing more.
/// A previous revision widened it to a `WalkRecord` carrying `saw_fragment` and
/// `non_first_fragment` as well, which the shim's walk does not produce; the
/// test supplied them by hand-writing a SECOND walk loop and re-deriving them
/// with the same expression `walk_ipv6_ext_chain` uses. Every comparison of
/// those two columns was therefore `X == X` — no edit to the shim could move
/// them, and the widened corpus stayed green on the exact non-first-fragment
/// input it was widened to catch. A wide fake comparison is worse than a narrow
/// honest one, because it manufactures the belief that a regression is covered.
///
/// So the corpus compares the shim's real output against this crate's real
/// outcome, and the fragment state the shim CANNOT represent is handled where
/// it belongs: `shim_is_not_more_permissive` states that gap explicitly, runs
/// both real walkers to demonstrate it, and pins every sub-field of
/// `ExtChainFragment` on the side that has one.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// Resolved a terminal upper-layer header at this offset.
    L4(usize, u8),
    /// No-Next-Header (59): a valid terminal with no L4.
    NoL4,
    /// Still on an extension header at the iteration bound.
    ///
    /// This names the SHIM's observable state, not a shim behaviour: the shim's
    /// walk does not fail closed on exhaustion, it returns the last declared
    /// extension-header protocol and `parse_l4`'s catch-all
    /// (`userspace-xdp/src/lib.rs`) then yields ports 0/0 so the session key
    /// misses and the packet is redirected. `walk_ipv6_ext_chain` returns
    /// `OverLimit` for the same chain. The two are folded to one label so the
    /// chain-length boundary is comparable; the fold is a renaming of two
    /// observed outputs, not a claim about what either does next.
    OverLimit,
    /// Truncated / declared length overran the packet / offset overflow.
    FailClosed,
}

/// The SHIM's walk, run on a live slice, returning EXACTLY what it returns.
///
/// `parse_ipv6` calls it with the frame's `data`/`data_end` and the L3 offset
/// `parse_l2` computed; here the slice supplies its own bounds.
///
/// #6704: the return is no longer a bare `(u16, u8)`. The walk now also
/// reports `non_first_fragment` — set when ANY Fragment header it stepped over
/// carried non-zero offset bits — which is the field `shim_fragment_sighting`
/// below compares against this crate's `non_first_fragment_offset_seen`. Until
/// it existed, the fragment dimension could not be compared FROM THE TEST SIDE
/// at all: there was no shim-side state to read, and the previous attempt to
/// compare it re-derived the value with a hand-written copy of the loop, which
/// made the assertion `X == X`.
fn raw_shim_walk(buf: &[u8], l3: usize) -> Option<shim_walk::ExtWalk> {
    if buf.len() < l3 + 40 {
        return None;
    }
    let data = buf.as_ptr() as usize;
    let data_end = data + buf.len();
    shim_walk::walk_ipv6_ext_headers(data, data_end, l3 as u16, buf[l3 + 6], (l3 + 40) as u16)
}

/// Run the SHIM's walk on `buf` exactly as `parse_ipv6` does, as a `Verdict`.
fn shim_verdict(buf: &[u8], l3: usize) -> Verdict {
    match raw_shim_walk(buf, l3) {
        None => Verdict::FailClosed,
        Some(w) => match shim_walk::eh_class(w.protocol) {
            shim_walk::EH_CLASS_NONEXT => Verdict::NoL4,
            shim_walk::EH_CLASS_TERMINAL => Verdict::L4(w.offset as usize, w.protocol),
            // Loop exhausted while still on an extension header.
            _ => Verdict::OverLimit,
        },
    }
}

/// #6704: the shim's fragment sighting, or `None` when its walk refuses.
///
/// The counterpart on this side is `ExtChainWalk::non_first_fragment_offset_seen`
/// — the SAME every-sighting semantics, which is why the two can be compared
/// for equality rather than for an inequality that would have to be justified.
fn shim_fragment_sighting(buf: &[u8], l3: usize) -> Option<bool> {
    raw_shim_walk(buf, l3).map(|w| w.non_first_fragment)
}

fn userspace_verdict(buf: &[u8], l3: usize) -> Verdict {
    match walk_ipv6_ext_chain(buf, l3).outcome {
        ExtChainOutcome::L4(off, proto) => Verdict::L4(off, proto),
        ExtChainOutcome::NoNextHeader => Verdict::NoL4,
        ExtChainOutcome::OverLimit => Verdict::OverLimit,
        ExtChainOutcome::Truncated => Verdict::FailClosed,
    }
}

/// The L3 offsets the SHIM actually produces.
///
/// `parse_l2` (`userspace-xdp/src/lib.rs`) returns `size_of::<EthHdr>()` = 14
/// for untagged Ethernet, or 18 when an 802.1Q/802.1ad tag is present, and
/// `parse_ipv6` passes that value straight into `walk_ipv6_ext_headers` as
/// `l3_offset`; this crate's `frame_l3_offset` returns exactly the same two.
/// A corpus that only ever walks at `l3 = 0` cannot see the `l3_offset` term
/// in either arm's post-advance revalidation — replacing the base
/// `l3_offset as usize` with `0usize` is bit-identical at 0 and a fail-open of
/// exactly `l3` bytes at 14 and 18. 0 is kept because `walk_ipv6_ext_chain`'s
/// other callers pass an L3-relative slice.
///
/// Floor 5 in `parity_corpus` MEASURES the two non-zero values, by asking
/// `frame_l3_offset` where L3 starts in the prefixes `at_l3` builds. It cannot
/// measure `parse_l2` — see the block comment immediately below, "WHAT THIS
/// FILE ASSERTS ABOUT THE SHIM RATHER THAN RUNS", for why, and for the other
/// three claims in the same position.
const L3_OFFSETS: [usize; 3] = [0, 14, 18];

/// #7780: how many divergences the corpus parity assertion RETAINS for its
/// message. The count reported is always the true total; this bounds only the
/// sample, so the failure text stays readable and the allocation stays flat on
/// exactly the mutations that diverge most.
const MAX_DRIFT_REPORTED: usize = 20;

// WHAT THIS FILE ASSERTS ABOUT THE SHIM RATHER THAN RUNS — all of it.
//
// The walk itself is executed: `ipv6_ext_walk.rs` is `#[path]`-included and
// driven on real buffers. Its CALLERS are not, and cannot be. The shim crate is
// `#![no_std] #![no_main]` over `aya-ebpf`; building `userspace-xdp` for
// `x86_64-unknown-linux-gnu` fails with "unwinding panics are not supported
// without std" (and wants the `MAX_INTERFACES` build-time env var), so `lib.rs`
// cannot be linked into this host test binary at all. Nothing here can be run
// against it — measured, not assumed.
//
// A previous revision named `parse_l2` as "the one thing in this file still
// asserted rather than run". That was wrong by three, and naming one of four
// reads as a claim that the rest are covered. The complete list:
//
//   1. `parse_l2` produces L3 offsets 14 (untagged) and 18 (802.1Q/802.1ad),
//      the two non-zero values in `L3_OFFSETS`. Floor 5 measures that THIS
//      crate's `frame_l3_offset` produces them; that the shim's L2 parser
//      agrees is read off `lib.rs` and believed.
//   2. `parse_ipv6` calls the walk with `(data, data_end, l3_offset, ip6[6],
//      l3_offset + 40)`, which is what `raw_shim_walk` below reproduces.
//      Passing `TCP` in place of `protocol` at that call site would make
//      production treat every IPv6 packet as TCP at the initial offset while
//      every test in this file stayed green, because the direct call below is
//      unchanged by it.
//   3. `parse_l4` consumes the walk's `(offset, protocol)`, and its catch-all
//      arm — yielding ports 0/0 for a protocol it does not parse — is what the
//      `Verdict::OverLimit` fold rests on: the shim's walk does not fail closed
//      on exhaustion, it returns the last extension-header protocol and
//      `parse_l4` turns that into a session-key miss. The fold is a claim about
//      `parse_l4`'s behaviour, made from its source.
//   4. The manifest-to-OBJECT relationship. `read_shim_facts` parses
//      `userspace_xdp_manifest.json`; it never touches
//      `userspace_xdp_bpfel.o`. That the JSON describes the committed object is
//      covered on the Go side by
//      `TestUserspaceXDPShimObjectMatchesSourceManifest` (input hashes) and by
//      the #1864 verify-then-install ordering in `build-userspace-xdp.sh` — not
//      here.
//
// Closing any of these means running the shim's entry points, which means a
// host-buildable extraction of them in the shape of `ipv6_ext_walk.rs`. Until
// then this list is the honest scope.

/// One arm's boundary WITNESS PAIR, DECLARED here and VERIFIED by floor 1.
///
/// The pair is `(padded, tight)`: the same single-extension-header packet, cut
/// to exactly `target` bytes and to `target - 1`. Floor 1 requires this crate's
/// walker to resolve the terminal at exactly `target` on the padded twin and to
/// fail closed on the tight one.
///
/// That pairing is the whole point. "Fails closed" ALONE is a proxy: a 40-byte
/// packet declaring an arm also fails closed, at the arm's INITIAL two-byte
/// read, having never reached the advance or the post-advance revalidation —
/// so a corpus of such stubs satisfies a fail-closed count while every
/// boundary case has been deleted. The padded twin resolving AT `target` is
/// what proves the arm ran its advance and landed there; the tight twin then
/// attributes the refusal to the length check, because the two differ by one
/// trailing byte and nothing else.
struct ArmBoundary {
    /// Label used in floor 1's messages and in the corpus case names.
    arm: &'static str,
    /// Class `proto` must MEASURE as, via `userspace_class`. An entry that
    /// files a header under the wrong arm reds rather than mislabelling the
    /// coverage.
    class: u8,
    /// The single extension header the witness declares at offset 40.
    proto: u8,
    /// The header's second byte: HdrExtLen for GENERIC/AUTH, the Fragment
    /// header's `reserved` byte (which neither walker reads) for FRAGMENT.
    hdr_len: u8,
    /// L3-relative offset the arm advances to. NOT a model of the arithmetic:
    /// floor 1 runs `walk_ipv6_ext_chain` on the padded twin and requires the
    /// terminal at exactly this offset, so a wrong value here reds instead of
    /// quietly re-describing the advance this file exists to stop describing.
    target: usize,
}

/// GENERIC advances `(HdrExtLen + 1) * 8`, AUTH `(HdrExtLen + 2) * 4`
/// (RFC 4302), FRAGMENT reads and advances a fixed 8 (RFC 8200 §4.5).
///
/// Two DISTINCT declared lengths for the two length-parameterised arms, one
/// witness for the constant one — derived, not chosen. An arithmetic error in
/// a length-parameterised arm of the form `f'(l) = f(l) + a*l + b` is invisible
/// at a declared length where `a*l + b == 0`, and an affine expression that
/// vanishes at two distinct `l` is identically zero. So two distinct
/// `hdr_len` values are necessary and sufficient to exclude that family,
/// and floor 1 counts DISTINCT lengths rather than cases — two byte-identical
/// witnesses are one magnitude, which is what the previous per-arm count
/// missed. FRAGMENT's read and advance take no declared length, so ITS
/// family is the constant `f' = f + b` and one witness excludes it; a second
/// would be decoration.
///
/// THE PREMISE IS THE SCOPE, and this pair does not establish it. "Affine in
/// the declared length" is a property of the mutation, not of the arm, and
/// nothing here enforces it: an error keyed on a SINGLE magnitude — `+ 8` only
/// when `HdrExtLen == 4` — is not affine, is a real packet-classification
/// regression, and vanishes at all 255 other lengths including both witnesses.
/// The witness pair is therefore worth exactly its family; what excludes the
/// rest is floor 7's exhaustive declared-length sweeps, which leave no
/// unsampled magnitude for such an error to key on. Neither would be enough
/// alone: the sweeps do not isolate a one-byte boundary (that is the twins'
/// job), and the twins do not cover a non-affine error (that is the sweeps').
const ARM_BOUNDARIES: &[ArmBoundary] = &[
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: DEST,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: DEST,
        hdr_len: 5,
        target: 88,
    },
    ArmBoundary {
        arm: "AUTH",
        class: EH_CLASS_AUTH,
        proto: AH,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "AUTH",
        class: EH_CLASS_AUTH,
        proto: AH,
        hdr_len: 3,
        target: 60,
    },
    ArmBoundary {
        arm: "FRAGMENT",
        class: EH_CLASS_FRAGMENT,
        proto: FRAG,
        hdr_len: 0,
        target: 48,
    },
    // THE REST OF THE GENERIC CLASS, one boundary pair each.
    //
    // "Per-arm" coverage was per-arm-MEMBER coverage of exactly one member.
    // The generic `match` arm is entered by eight next-header values, and a
    // refusal keyed on one of them — a revalidation skipped only when
    // `protocol == ROUTING` — is a fail-open of exactly the same shape the
    // DestOpt pair exists to catch, invisible to it. The 256-value sweep does
    // not reach it either: those buffers carry 20 bytes of slack past the
    // advance target, and only a packet ENDING at or before the target can
    // observe a missing bounds check.
    //
    // One declared length each is deliberate. The length dimension is swept
    // exhaustively by floor 7 (on DestOpt); what these add is the BOUNDARY at
    // each member, which is a different dimension.
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: HBH,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: ROUTING,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: MOBILITY,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: HIP,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: SHIM6,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: EXP1,
        hdr_len: 0,
        target: 48,
    },
    ArmBoundary {
        arm: "GENERIC",
        class: EH_CLASS_GENERIC,
        proto: EXP2,
        hdr_len: 0,
        target: 48,
    },
];

/// Every next-header value the shim's `eh_class` files under GENERIC, so
/// floor 1 can require a boundary pair for EACH — not just for the one the
/// witnesses happened to be written with.
///
/// Kept as its own list rather than derived from `ARM_BOUNDARIES`: deriving it
/// from the table the floor checks would make the check `X == X`, which is the
/// defect this whole file is about. Floor 1 MEASURES each entry's class with
/// this crate's walker rather than reading the shim's `eh_class`, so the floors
/// stay shim-free and a new generic member without a witness reds.
const GENERIC_MEMBERS: [u8; 8] = [HBH, ROUTING, DEST, MOBILITY, HIP, SHIM6, EXP1, EXP2];

/// `IPv6 || (proto, hdr_len) || zeroes`, cut to exactly `total` bytes.
///
/// The declared next header is TCP, so a walk that reaches the advance target
/// resolves a TCP terminal there.
fn boundary_case(proto: u8, hdr_len: u8, total: usize) -> Vec<u8> {
    let mut b = vec![0u8; 40];
    b[0] = 0x60;
    b[6] = proto;
    b.extend_from_slice(&[TCP, hdr_len]);
    b.resize(total, 0);
    b
}

/// Prefix an L3-relative buffer with `l3` bytes of L2, so one corpus case can
/// be walked at every L3 offset the shim produces. Neither walker parses these
/// bytes — both take the L3 offset as a parameter — but a plausible header
/// keeps a failure dump readable.
fn at_l3(buf: &[u8], l3: usize) -> Vec<u8> {
    let mut out = vec![0u8; l3];
    if l3 == 14 {
        out[12] = 0x86;
        out[13] = 0xDD; // ETH_P_IPV6
    } else if l3 == 18 {
        out[12] = 0x81;
        out[13] = 0x00; // ETH_P_8021Q
        out[16] = 0x86;
        out[17] = 0xDD;
    }
    out.extend_from_slice(buf);
    out
}

/// Build `IPv6 || headers || 20 bytes of L4`, where each header is
/// `(type, hdr_ext_len)` and occupies `(hdr_ext_len + 1) * 8` bytes — the
/// generic encoding. `trailing` extra bytes may be trimmed to truncate.
fn chain(headers: &[(u8, u8)], terminal: u8, trim: usize) -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    buf[0] = 0x60;
    buf[6] = headers.first().map(|h| h.0).unwrap_or(terminal);
    for (i, (_, len)) in headers.iter().enumerate() {
        let next = headers.get(i + 1).map(|h| h.0).unwrap_or(terminal);
        let size = (usize::from(*len) + 1) * 8;
        let mut hdr = vec![0u8; size];
        hdr[0] = next;
        hdr[1] = *len;
        buf.extend_from_slice(&hdr);
    }
    buf.extend_from_slice(&[0u8; 20]);
    buf.truncate(buf.len().saturating_sub(trim));
    buf
}

/// The same bytes as `chain`, built INDEPENDENTLY, for the floors only.
///
/// Every floor below asks "is this exact buffer still in the corpus?". Round 7
/// answered that by calling `chain` — the corpus's own generator — and looking
/// the result up in a corpus `chain` produced. That is `X == X` at the level of
/// the generator: mutate `chain` to write TCP at byte 6 for every one-header
/// input and the corpus collapses to a single distinct next-header value, every
/// case resolves `L4(40, TCP)` on both walkers so no verdict moves, and floor 3
/// still reports all 256 present — because it rebuilt the same degenerate bytes
/// and found them. The cross-walker comparison catches a UNILATERAL
/// misclassification; it cannot catch a COMMON-MODE change to the inputs both
/// walkers are fed.
///
/// So the floors' expectations come from here. This is a second implementation,
/// not an oracle from another source: it defends against `chain` drifting
/// alone, which is the reachable failure (one function edited, the floors
/// unchanged), and it does NOT defend against someone editing both. That
/// residual is what the acceptance matrix's NEG-CTL row covers from the other side —
/// a semantically null edit must SURVIVE, so the guards are known to bind
/// behaviour rather than bytes.
///
/// Deliberately written with different mechanics (index arithmetic into one
/// grown buffer, rather than building each header as its own vector), so a
/// copy-paste of one into the other is visible in review.
fn expect_chain(headers: &[(u8, u8)], terminal: u8, trim: usize) -> Vec<u8> {
    let mut b = vec![0u8; 40];
    b[0] = 0x60;
    b[6] = if headers.is_empty() {
        terminal
    } else {
        headers[0].0
    };
    for i in 0..headers.len() {
        let len = headers[i].1;
        let next = if i + 1 < headers.len() {
            headers[i + 1].0
        } else {
            terminal
        };
        let at = b.len();
        b.resize(at + (usize::from(len) + 1) * 8, 0);
        b[at] = next;
        b[at + 1] = len;
    }
    b.resize(b.len() + 20, 0);
    b.truncate(b.len().saturating_sub(trim));
    b
}

/// `IPv6 || (AH, hdr_len) || pad to the AUTH arm's `(hdr_len + 2) * 4` advance
/// target || 20 bytes of L4`.
///
/// `chain` cannot build this. It lays every header out with the GENERIC
/// `(len + 1) * 8` encoding, so an AH header built by it ends somewhere other
/// than where the AUTH arm advances to, and the terminal is never AT the
/// target — which is what the declared-length sweep needs to observe.
fn ah_chain(hdr_len: u8) -> Vec<u8> {
    let mut b = vec![0u8; 40];
    b[0] = 0x60;
    b[6] = AH;
    b.extend_from_slice(&[TCP, hdr_len]);
    b.resize(40 + (usize::from(hdr_len) + 2) * 4, 0);
    b.extend_from_slice(&[0u8; 20]);
    b
}

/// The same bytes as `ah_chain`, built INDEPENDENTLY, for the floors only.
/// See `expect_chain` for why a floor must not rebuild with the generator that
/// produced the corpus. Different mechanics again: the final length is computed
/// first and every byte is written by index, rather than grown by `extend`.
fn expect_ah_chain(hdr_len: u8) -> Vec<u8> {
    let target = 40 + (usize::from(hdr_len) + 2) * 4;
    let mut b = vec![0u8; target + 20];
    b[0] = 0x60;
    b[6] = AH;
    b[40] = TCP;
    b[41] = hdr_len;
    b
}

/// `IPv6 || a COMPLETE 8-byte Fragment header || 20 bytes of L4`, with the
/// header's `reserved` byte set to `reserved` and a first-fragment offset word.
///
/// `reserved` is a byte NEITHER walker reads, which is exactly what makes it
/// the place a content-keyed advance can hide — see the sweep in
/// `parity_corpus`.
fn frag_reserved_case(reserved: u8) -> Vec<u8> {
    let mut b = vec![0u8; 40];
    b[0] = 0x60;
    b[6] = FRAG;
    // next, reserved, frag_off||M (0x0001 = offset 0, M set), identification.
    b.extend_from_slice(&[TCP, reserved, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF]);
    b.extend_from_slice(&[0u8; 20]);
    b
}

/// The same bytes as `frag_reserved_case`, built INDEPENDENTLY, for the floors
/// only. See `expect_chain`.
fn expect_frag_reserved_case(reserved: u8) -> Vec<u8> {
    let mut b = vec![0u8; 68];
    b[0] = 0x60;
    b[6] = FRAG;
    b[40] = TCP;
    b[41] = reserved;
    b[43] = 0x01;
    b[44] = 0xDE;
    b[45] = 0xAD;
    b[46] = 0xBE;
    b[47] = 0xEF;
    b
}

/// The corpus of L3-relative chains both walkers are run over.
///
/// Shared by `shim_walk_and_userspace_walk_agree_over_a_corpus` and
/// `shim_is_not_more_permissive` so the two cannot drift apart. Each buffer
/// starts at the IPv6 fixed header; `at_l3` prefixes it for the non-zero L3
/// offsets.
fn parity_corpus() -> Vec<(String, Vec<u8>)> {
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();

    // Chain lengths across the 7/8 resolvable boundary, minimum-size headers.
    for n in 0..=10usize {
        let hdrs: Vec<(u8, u8)> = (0..n).map(|_| (DEST, 0)).collect();
        cases.push((format!("{n} x DestOpt(len=0) -> TCP"), chain(&hdrs, TCP, 0)));
    }
    // Declared lengths: the generic advance is (len+1)*8, so these separate
    // `* 8` from any other multiplier.
    for len in [0u8, 1, 2, 5, 15] {
        cases.push((
            format!("HbH(len={len}) -> TCP"),
            chain(&[(HBH, len)], TCP, 0),
        ));
        cases.push((
            format!("HbH(len={len}) + DestOpt(len=1) -> TCP"),
            chain(&[(HBH, len), (DEST, 1)], TCP, 0),
        ));
    }
    // Offsets past 200 while still on an extension header — the shape a
    // statement inside the loop but outside the match perturbs.
    cases.push((
        "3 x DestOpt(len=15) -> TCP (offset passes 200 mid-walk)".into(),
        chain(&[(DEST, 15), (DEST, 15), (DEST, 15)], TCP, 0),
    ));
    cases.push((
        "5 x DestOpt(len=15) -> TCP".into(),
        chain(&[(DEST, 15); 5], TCP, 0),
    ));
    // Truncation: the declared length runs past the packet. Without the
    // post-advance revalidation the walk resolves an L4 offset outside the
    // buffer instead of failing closed.
    for trim in [1usize, 8, 20, 21, 40] {
        cases.push((
            format!("HbH(len=5) -> TCP, trimmed {trim}"),
            chain(&[(HBH, 5)], TCP, trim),
        ));
        cases.push((
            format!("DestOpt(len=15) -> TCP, trimmed {trim}"),
            chain(&[(DEST, 15)], TCP, trim),
        ));
    }
    // MINIMAL-LENGTH buffers, one per arm. The padded cases below cannot see a
    // deleted revalidation: with slack after the header the walk lands inside
    // the buffer either way. Two of the four acceptance mutations are only
    // observable when the packet ENDS at or before the advance target.
    //
    // AH-only, 42 bytes: `[TCP, 3]` at offset 40 and nothing after. AH advances
    // (3+2)*4 = 20 to offset 60, which is past the 42-byte packet — so the
    // revalidation is the only thing standing between this and an L4 offset
    // outside the buffer.
    let mut ah_min = vec![0u8; 40];
    ah_min[0] = 0x60;
    ah_min[6] = AH;
    ah_min.extend_from_slice(&[TCP, 3]);
    cases.push(("AH(len=3) minimal 42-byte packet".into(), ah_min));
    // Fragment declared but truncated to two bytes: the arm must read all eight
    // before advancing.
    let mut frag_min = vec![0u8; 40];
    frag_min[0] = 0x60;
    frag_min[6] = FRAG;
    frag_min.extend_from_slice(&[TCP, 0]);
    cases.push(("Fragment truncated to 2 bytes".into(), frag_min));
    // BOUNDARY WITNESS PAIRS, from `ARM_BOUNDARIES`. Each entry contributes the
    // same packet cut to exactly its advance target and to one byte short of
    // it. The rule is the arm's own (`ipv6_ext_walk.rs`): a case can observe a
    // weakened revalidation only when the packet ENDS at or before the advance
    // target, because with slack after the header the walk lands inside the
    // buffer either way.
    //
    // Having the pair on the GENERIC arm alone was not enough: an off-by-one in
    // the AUTH revalidation, and a Fragment read shortened 8 -> 7, both survived
    // the whole corpus while the identical off-by-one in the generic arm red.
    // The shortest AUTH case left 18 bytes of slack and the shortest FRAGMENT
    // case 6, so neither arm's bound was ever the thing under test. Each tight
    // twin is a genuine fail-open when the bound is weakened: a 47-byte buffer
    // goes from `None` to `Some((48, TCP))`, an L4 offset one byte past the
    // packet.
    //
    // Floor 1 verifies the pair semantics — padded resolves AT `target`, tight
    // fails closed — so these are the corpus's boundary coverage AND its own
    // evidence of being boundary coverage.
    for w in ARM_BOUNDARIES {
        for (name, total) in [
            ("exactly at target", w.target),
            ("one byte short of target", w.target - 1),
        ] {
            cases.push((
                format!(
                    "{} proto={} hdr_len={} buffer {name} {}",
                    w.arm, w.proto, w.hdr_len, w.target
                ),
                boundary_case(w.proto, w.hdr_len, total),
            ));
        }
    }
    // NON-FIRST fragment: frag_off bits set, so the bytes after the Fragment
    // header are payload, not an L4 header. Both walkers resolve the same
    // offset; only the fragment state distinguishes them, which is precisely
    // what comparing `.outcome` alone discarded.
    for frag_off in [0x0008u16, 0x0010, 0x0100] {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = FRAG;
        b.extend_from_slice(&[TCP, 0]);
        b.extend_from_slice(&frag_off.to_be_bytes());
        b.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        b.extend_from_slice(&[0x11; 20]);
        cases.push((format!("NON-FIRST Fragment(frag_off={frag_off:#06x}) -> TCP"), b));
    }

    // Fragment and AH have their own advance arithmetic.
    cases.push(("Fragment -> TCP".into(), chain(&[(FRAG, 0)], TCP, 0)));
    cases.push((
        "DestOpt + Fragment -> TCP".into(),
        chain(&[(DEST, 0), (FRAG, 0)], TCP, 0),
    ));
    for len in [0u8, 1, 3] {
        // AH advances (len+2)*4, which is NOT the generic size for most lens,
        // so build these buffers generously and let both walkers land where
        // they land.
        let mut buf = vec![0u8; 40];
        buf[0] = 0x60;
        buf[6] = AH;
        buf.extend_from_slice(&[TCP, len]);
        buf.extend_from_slice(&[0u8; 254]);
        cases.push((format!("AH(len={len}) -> TCP"), buf));
    }
    // #4517 types, and a terminal that must NOT be walked.
    cases.push((
        "Mobility -> TCP".into(),
        chain(&[(MOBILITY, 0)], TCP, 0),
    ));
    cases.push((
        "HbH + Mobility -> TCP".into(),
        chain(&[(HBH, 0), (MOBILITY, 0)], TCP, 0),
    ));
    // Every next-header value as the first header, one minimum-size header in
    // a 68-byte buffer.
    for p in 0u16..=255 {
        cases.push((format!("first={p}"), chain(&[(p as u8, 0)], TCP, 0)));
    }

    // --- EXHAUSTIVE DIMENSION SWEEPS ---------------------------------------
    //
    // The witness pairs above sample TWO declared lengths per length-driven arm
    // and derive from that pair that the arm's whole error family is excluded.
    // That derivation holds only for errors AFFINE in the declared length. An
    // error keyed on ONE value — "advance (len+1)*8 + 8 when HdrExtLen == 4" —
    // is not affine, is a real packet-classification regression, and was
    // invisible to every case here: the generic arm sampled declared lengths
    // {0,1,2,5,15} and the AUTH arm {0,1,3}, leaving 251 and 253 unsampled
    // magnitudes to hide in. The same held for two more dimensions no case
    // varied at all: every Fragment case carried `reserved == 0`, and EVERY
    // chain in the corpus declared TCP as its terminal, so the next-header byte
    // an extension header CARRIES (`opt[0]` in the shim's generic arm) only
    // ever took the four values the multi-header cases produce — a mutation
    // reading "propagate TCP whenever opt[0] is UDP" misclassifies real traffic
    // and moves nothing.
    //
    // A wider sample would only move the hiding place. These sweep each
    // dimension COMPLETELY, so within the shape swept there is no unsampled
    // value left to key on.
    //
    // THREE OF THE FOUR ARE MARGINAL, and that is a real limit, not a
    // formality: a sweep of dimension A with B held fixed says nothing about an
    // error conditioned on A AND B, which is invisible to it in exactly the way
    // the non-affine error was invisible to two sampled lengths. 256^4 is not
    // enumerable, so the choice is which pair to make JOINT.
    //
    // The generic sweep below is joint over (entering next-header x declared
    // length), because those are the two inputs the arm's own code reads: the
    // entering value selects the `match` arm, `opt[1]` feeds the advance, and
    // an error can be conditioned on both (`if entered == ROUTING && opt[1] ==
    // 4`). 8 x 256 is 2048 cases, which is affordable; the pair is therefore
    // covered exhaustively rather than sampled.
    //
    // NOT made joint, deliberately, and stated rather than left to be inferred:
    // (declared length x CARRIED next-header) is 256 x 256 = 65536 buffers of
    // up to 2 KB, and any 3-way interaction is larger still. Those combinations
    // are NOT covered. The corpus binds the four marginals plus the one pair
    // above; an error conditioned on `opt[0] == 17 && opt[1] == 4` survives it.
    // What measures whether that gap matters is the acceptance matrix, not a
    // bigger corpus.

    // GENERIC: every member of the arm x all 256 declared lengths. Packet ends
    // 20 bytes past the arm's `(len + 1) * 8` target, so each resolves TCP AT
    // the target.
    for proto in GENERIC_MEMBERS {
        for len in 0u16..=255 {
            cases.push((
                format!("GENERIC sweep proto={proto} len={len} -> TCP"),
                chain(&[(proto, len as u8)], TCP, 0),
            ));
        }
    }
    // AUTH: all 256 declared lengths, at the arm's own `(len + 2) * 4` target.
    for len in 0u16..=255 {
        cases.push((
            format!("AUTH sweep AH(len={len}) -> TCP"),
            ah_chain(len as u8),
        ));
    }
    // FRAGMENT has no declared length — its read and advance are a fixed 8 —
    // so there is no length dimension to sweep. Its `reserved` byte is the
    // analogous hiding place: a byte inside the header that neither walker
    // reads.
    for reserved in 0u16..=255 {
        cases.push((
            format!("FRAGMENT sweep reserved={reserved} -> TCP"),
            frag_reserved_case(reserved as u8),
        ));
    }
    // TERMINAL: all 256 values of the next-header byte an extension header
    // carries. Unlike the three above, most of these do NOT resolve — a
    // terminal that is itself an extension-header type continues the walk into
    // the 20 zero bytes and runs out of packet. That is the point: the floor
    // requires the buffers, and the cross-walker comparison requires the two
    // walkers to agree on whatever each one does with them.
    for t in 0u16..=255 {
        cases.push((
            format!("terminal sweep DestOpt(len=0) -> {t}"),
            chain(&[(DEST, 0)], t as u8, 0),
        ));
    }

    // --- NON-VACUITY FLOORS -------------------------------------------------
    //
    // Every assertion that CONSUMES this corpus is of the form "this collection
    // is empty" or "the loop visited every (offset, case) pair", and BOTH hold
    // trivially when the corpus is empty: an empty drift list is empty, an empty
    // permissive list is empty, and an empty visited set equals an empty cross
    // product. Emptying this function was measured to leave all five tests
    // reporting `ok` in 0.00s.
    //
    // Three earlier rounds of floors stood here and all were PROXIES.
    //
    //   Round 5 was a single `cases.len() >= 200` whose message promised that no
    //   assertion in the file could pass vacuously. The 256-entry sweep above
    //   clears 200 by itself with 56 to spare, so cutting the corpus down to
    //   that sweep AND deleting the generic arm's post-advance revalidation —
    //   the security property — was measured to leave all five tests `ok`.
    //
    //   Round 6 replaced it with five floors "each binding one shape". Three of
    //   them bound CORRELATES of their shape rather than the shape: per-arm
    //   coverage counted `b[6] == arm && fails_closed`, which a 40-byte packet
    //   satisfies by failing the arm's INITIAL read having never reached the
    //   boundary (and which two byte-identical 47-byte Fragment cases satisfied
    //   twice over, so the "more than one magnitude" claim was unbound); the
    //   chain-length floor counted a terminal OFFSET, which one `DestOpt(len=6)`
    //   header reaches; and the next-header floor read `b[6]` off buffers that
    //   need not be walked at all, which 256 seven-byte stubs satisfy. One
    //   corpus edit defeating all three while all five floors passed was
    //   measured, again with the generic revalidation deleted.
    //
    //   Round 7 fixed those three and then DELETED the surviving coverage floor
    //   (`handcrafted >= 40`), arguing the identity floors subsumed it. They do
    //   not. Between them floors 1-4 require ten boundary buffers, two
    //   chain-length twins and two long chains — 14 hand-written cases — so the
    //   intermediate chain lengths, the varied declared lengths, the truncation
    //   block, the minimal per-arm packets, the non-first fragments, the AH
    //   sweep and the #4517 Mobility cases were all deletable with every floor
    //   green. Measured: dropping the ten varied-length HbH cases and the ten
    //   truncation cases takes the hand-written count 55 -> 35, which the
    //   deleted floor caught and floors 1-5 do not. Floor 6 closes that, by
    //   BLOCK rather than by count — the old threshold was arbitrary, and a
    //   count is what had a degenerate satisfier twice already.
    //
    //   Round 8's floors 1-6 were sound but SAMPLED: the generic arm's
    //   declared length was covered at 5 magnitudes out of 256, AUTH's at 3,
    //   the Fragment `reserved` byte at 1, and the carried next-header at 4.
    //   Floor 1's two-witness derivation excludes only errors AFFINE in the
    //   declared length, so `+ 8 when HdrExtLen == 4` — a real
    //   packet-classification regression — was invisible to every case here.
    //   Floor 7 sweeps each of those four dimensions completely; within the
    //   shape swept there is no unsampled value left to key on.
    //
    // So each floor below binds its shape by CONSTRUCTION (the corpus must
    // contain a locally rebuilt reference buffer, byte for byte) and, where the
    // shape is behavioural, by MEASUREMENT with this crate's walker. A count of
    // cases satisfying a predicate is exactly what kept failing; a named buffer
    // that must be present, and must behave as claimed, does not have a
    // degenerate satisfier.
    //
    // The reference buffers come from `expect_chain`, NOT from the corpus's own
    // `chain`: rebuilding an expectation with the generator that produced the
    // corpus and then looking it up in that corpus is circular, and one edit to
    // `chain` defeats every floor built on it at once. See `expect_chain`.
    //
    // None of them claims the corpus is ADEQUATE: adequacy is not a property of
    // a floor, it is what `make test-shim-ext-parity-lib` measures (#7766;
    // ~40 min) by mutating the shim and requiring each guard to red. These floors exist
    // to stop a shape being DELETED between acceptance runs.
    //
    // #6920/#7766 — the caveat that sentence needs: "measures" is only true of
    // a run that COMPLETES, and until #6920 the harness aborted at row 7, so
    // two thirds of the matrix measured nothing. It is also in no gate, so
    // nothing forces a run at all. Treat the measurement as current only if
    // someone has run it since the last change to either walker.
    //
    // All of them read only the corpus bytes and this crate's walker. Nothing
    // here touches the shim, so no mutation the acceptance matrix applies can
    // move a floor — a floor red is always a corpus defect, never a shim
    // finding. Neither negative-control test calls this function, so a floor red
    // leaves both CONTROL columns `ok` and the harness's attributability rule
    // intact.
    let present: HashSet<&[u8]> = cases.iter().map(|(_, b)| b.as_slice()).collect();
    let contains = |b: &[u8]| present.contains(b);

    // 1. PER-ARM BOUNDARY WITNESS PAIRS.
    //
    //    For every `ARM_BOUNDARIES` entry the corpus must contain BOTH twins,
    //    and the pair must behave as a boundary witness:
    //      - the PADDED twin (exactly `target` bytes) resolves the terminal at
    //        exactly `target`, which can only happen if the arm ran its advance
    //        and landed there — this is what proves the boundary was REACHED;
    //      - the TIGHT twin (one byte shorter, identical otherwise) fails
    //        closed, which attributes the refusal to the length check at
    //        `target` rather than to an earlier read.
    //    Neither half alone is the property. Round 6 asserted only the
    //    fail-closed half, and a 40-byte packet declaring the arm satisfies that
    //    while failing the arm's first two-byte read.
    //
    //    Binds: per arm, that boundary coverage exists at >= `want` DISTINCT
    //    declared lengths (see `ARM_BOUNDARIES` for why 2/2/1 is derived rather
    //    than chosen), that the corpus still carries those exact buffers, that
    //    the header each entry names really is classified into the arm it
    //    claims, and that EVERY member of the generic class has a pair — eight
    //    next-header values enter that one `match` arm, and a refusal keyed on
    //    one of them is invisible to a witness written for another.
    //    Does NOT bind: boundary coverage of an arm reached as a LATER header in
    //    a multi-header chain — every witness here is a single-header packet, so
    //    an arm's bound is exercised only at offset 40 (plus the L3 prefix).
    //    Does NOT bind: any non-boundary shape (truncation, non-first fragment,
    //    over-long declared lengths); those are separate cases above, and only
    //    the acceptance matrix measures whether they are pulling their weight.
    //    Does NOT bind: an advance error keyed on a declared length OTHER than
    //    the two witnessed. Two points exclude an AFFINE family and nothing
    //    wider — see `ARM_BOUNDARIES` — which is what floor 7's exhaustive
    //    sweeps are for.
    for w in ARM_BOUNDARIES {
        let padded = boundary_case(w.proto, w.hdr_len, w.target);
        let tight = boundary_case(w.proto, w.hdr_len, w.target - 1);
        assert_eq!(
            userspace_class(w.proto),
            w.class,
            "#4555 corpus floor 1: ARM_BOUNDARIES files next-header {} under the {} arm, but this \
             crate classifies it as {}. The witness would report coverage of an arm it does not \
             exercise.",
            w.proto,
            w.arm,
            class_name(userspace_class(w.proto)),
        );
        assert_eq!(
            userspace_verdict(&padded, 0),
            Verdict::L4(w.target, TCP),
            "#4555 corpus floor 1: the {} witness (proto={}, hdr_len={}) does not resolve a \
             terminal at its declared advance target {} when the packet ends exactly there — it \
             gives {:?}. Either the target is wrong or the arm is not reached, and in both cases \
             the tight twin's fail-closed proves nothing about this arm's boundary.",
            w.arm,
            w.proto,
            w.hdr_len,
            w.target,
            userspace_verdict(&padded, 0),
        );
        // TWIN IDENTITY, asserted before the tight twin's verdict is read.
        // `FailClosed` is the FAILURE DEFAULT of `userspace_verdict` — a
        // buffer that is short, malformed, or built for a different arm
        // entirely also produces it — so on its own it attributes nothing.
        // It only means "the length check at `target` refused this" if the
        // tight twin is the padded one minus its last byte and nothing else,
        // which is what makes the pair a one-byte isolation rather than two
        // unrelated packets that happen to disagree. The padded twin's
        // `L4(target, TCP)` above is a POSITIVE observation and needs no such
        // support; this one does.
        assert_eq!(
            tight.len(),
            w.target - 1,
            "#4555 corpus floor 1: the {} tight witness is {} bytes, not target-1 = {}",
            w.arm,
            tight.len(),
            w.target - 1,
        );
        assert_eq!(
            tight[..],
            padded[..w.target - 1],
            "#4555 corpus floor 1: the {} tight witness is not the padded witness minus its last \
             byte. The two differ somewhere other than the final byte, so the tight twin's \
             fail-closed cannot be attributed to the post-advance length check at target {} — it \
             could be any earlier refusal.",
            w.arm,
            w.target,
        );
        assert_eq!(
            userspace_verdict(&tight, 0),
            Verdict::FailClosed,
            "#4555 corpus floor 1: the {} witness (proto={}, hdr_len={}) still resolves with the \
             packet one byte short of target {}. The pair no longer isolates the post-advance \
             length check to a single byte.",
            w.arm,
            w.proto,
            w.hdr_len,
            w.target,
        );
        assert!(
            contains(&padded) && contains(&tight),
            "#4555 corpus floor 1: the {} boundary witness pair (proto={}, hdr_len={}, target={}) \
             is no longer in the corpus. Only a packet ENDING at or before an arm's advance target \
             can observe a deleted or one-byte-weakened post-advance revalidation in that arm; a \
             padded case lands inside the buffer with or without the check.",
            w.arm,
            w.proto,
            w.hdr_len,
            w.target,
        );
    }
    for (arm, want) in [("GENERIC", 2usize), ("AUTH", 2), ("FRAGMENT", 1)] {
        let lens: BTreeSet<u8> = ARM_BOUNDARIES
            .iter()
            .filter(|w| w.arm == arm)
            .map(|w| w.hdr_len)
            .collect();
        assert!(
            lens.len() >= want,
            "#4555 corpus floor 1: the {arm} arm has boundary witnesses at only {} distinct \
             declared length(s) {lens:?}, want >= {want}. An arithmetic error of the form \
             `f(l) + a*l + b` is invisible wherever `a*l + b == 0`, so one magnitude cannot \
             exclude it; two distinct lengths can, because an affine expression vanishing at two \
             points is identically zero. Adding a SECOND witness at the SAME declared length does \
             not help, which is why this counts distinct lengths and not cases.",
            lens.len(),
        );
    }
    // EVERY MEMBER OF THE GENERIC CLASS HAS A BOUNDARY PAIR, not just the one
    // the witnesses were written with. The eight values below share a single
    // `match` arm, so they share its advance and its post-advance revalidation;
    // a refusal keyed on one of them is a fail-open of exactly the shape the
    // DestOpt pair exists to catch and is invisible to it. The 256-value sweep
    // cannot see it either — those buffers carry slack past the advance target,
    // and only a packet ENDING at or before the target observes a missing
    // bounds check.
    //
    // EVERY MEMBER OF EVERY ADVANCING ARM HAS A PAIR — the membership ENUMERATED
    // by measurement over all 256 next-header values, not asserted for the one
    // arm the defect was found in.
    //
    // "Per-arm coverage" was per-arm-MEMBER coverage of exactly one member.
    // Naming that for GENERIC and stopping there would repeat the mistake one
    // level up, so the classes are enumerated instead: for each of the 256
    // values, ask this crate's walker which class it lands in, and require a
    // boundary pair for every value that reaches an arm which ADVANCES. As of
    // this writing the answer is that GENERIC has 8 members (0, 43, 60, 135,
    // 139, 140, 253, 254), AUTH has exactly 1 (51) and FRAGMENT exactly 1 (44)
    // — so GENERIC was the only arm that could carry the defect — but that is
    // an OUTPUT of this loop, not an assumption in it. A ninth value added to
    // any advancing arm reds here.
    //
    // NONEXT (59) and TERMINAL (the other 244) are deliberately excluded: they
    // neither read nor advance, so there is no bound to weaken and a boundary
    // pair would witness nothing. Their property — stop here, report this
    // protocol — is what floor 3's 256-value sweep and
    // `shim_ext_parity_negative_control_unchanged_classifications` bind.
    //
    // Measured with this crate's classifier and not the shim's: every floor in
    // this function reads only corpus bytes and `walk_ipv6_ext_chain`, so no
    // shim-side mutation the acceptance matrix applies can move a floor — a
    // floor red is a corpus defect, never a shim finding, and both negative
    // controls stay attributable. That the two classifiers agree on all 256
    // values is not assumed here; it is what the 256-value sweep plus the
    // cross-walker comparison measure.
    let mut arm_members: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    for p in 0u16..=255 {
        let class = userspace_class(p as u8);
        if class == EH_CLASS_GENERIC || class == EH_CLASS_AUTH || class == EH_CLASS_FRAGMENT {
            arm_members.entry(class).or_default().push(p as u8);
        }
    }
    for (class, protos) in &arm_members {
        for proto in protos {
            assert!(
                ARM_BOUNDARIES.iter().any(|w| w.proto == *proto),
                "#4555 corpus floor 1: next-header {proto} enters the {} arm — which advances — \
                 but has no boundary witness pair. That arm's {} member(s) {protos:?} share one \
                 advance and one post-advance revalidation, so without a pair for THIS value its \
                 bound is exercised only through padded cases, which land inside the buffer with \
                 or without the check. A revalidation skipped for exactly this next-header value \
                 then resolves an L4 offset outside the packet with every guard in this file \
                 green.",
                class_name(*class),
                protos.len(),
            );
        }
    }
    // The hand-written list the sweeps iterate must agree with the measurement.
    // It is NOT derived from it — a sweep driven by the same enumeration the
    // floor checks would be `X == X` — so the two are cross-checked here.
    assert_eq!(
        arm_members.get(&EH_CLASS_GENERIC).map(Vec::as_slice),
        Some(&GENERIC_MEMBERS[..]),
        "#4555 corpus floor 1: GENERIC_MEMBERS (which the declared-length sweep iterates) no \
         longer matches the set of next-header values this crate classifies as generic. The \
         sweep would then be sweeping the wrong arm's membership."
    );

    // That count reads the ARM_BOUNDARIES TABLE, not decoded corpus bytes —
    // which would be a proxy if the table could name a buffer the corpus does
    // not have. It cannot: the loop above requires BOTH twins of every entry
    // present by byte identity, and each entry's `hdr_len` is byte 41 of the
    // buffer it just proved present. So the distinct lengths counted here are
    // distinct lengths of buffers the corpus is holding.

    // 2. THE RESOLVABLE-CHAIN-LENGTH BOUNDARY IS STRADDLED, BY CONSTRUCTION.
    //    `shim_ipv6_ext_walk_matches_userspace_walker` argues the shim's
    //    `MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1` relation rather than
    //    asserting numeric equality, and cites THIS corpus as what measures the
    //    exit semantics the argument rests on. That citation is only true while
    //    the corpus contains a chain of exactly the longest resolvable NUMBER OF
    //    HEADERS and one header more.
    //
    //    Counting header-count-by-terminal-offset was the round-6 defect: a
    //    single `DestOpt(len=6)` header also lands on `40 + 8 * (MAX - 1)`, so
    //    every seven-header case could be deleted while the floor reported a
    //    seven-header chain present. The two chains are therefore rebuilt here
    //    and required by byte identity, and their verdicts are measured so the
    //    boundary is observed rather than assumed.
    //    Does NOT bind: the intermediate lengths, nor chains built from
    //    non-minimum-size or non-DestOpt headers.
    let at_max_hdrs = MAX_IPV6_EXT_HEADERS - 1;
    let at_max = expect_chain(&vec![(DEST, 0); at_max_hdrs], TCP, 0);
    let over = expect_chain(&vec![(DEST, 0); at_max_hdrs + 1], TCP, 0);
    assert!(
        contains(&at_max) && contains(&over),
        "#4555 corpus floor 2: the corpus no longer contains BOTH the chain of exactly \
         {at_max_hdrs} minimum-size DestOpt headers (the longest this crate resolves) and the \
         chain of {} (the first it refuses). Without the pair, nothing here measures where either \
         walker stops, and the MAX_EXT_HDRS == MAX_IPV6_EXT_HEADERS - 1 relation asserted in \
         shim_ipv6_ext_walk_matches_userspace_walker is argued from a comment rather than \
         observed.",
        at_max_hdrs + 1,
    );
    assert_eq!(
        userspace_verdict(&at_max, 0),
        Verdict::L4(40 + 8 * at_max_hdrs, TCP),
        "#4555 corpus floor 2: this crate no longer resolves a chain of {at_max_hdrs} minimum-size \
         extension headers, so the corpus does not straddle the boundary it claims to"
    );
    assert_eq!(
        userspace_verdict(&over, 0),
        Verdict::OverLimit,
        "#4555 corpus floor 2: this crate no longer refuses a chain of {} minimum-size extension \
         headers; the over-limit side of the boundary is not in the corpus",
        at_max_hdrs + 1,
    );

    // 3. EVERY NEXT-HEADER VALUE IS PRESENTED AS A WALKED FIRST HEADER.
    //    The behavioural walked-type-set comparison — which values one walker
    //    steps THROUGH and the other treats as terminal — exists only where the
    //    corpus supplies that value in a buffer both walkers actually walk.
    //    (`shim_ipv6_ext_walk_matches_userspace_walker` covers all 256 against
    //    the EMITTED table, but that is the manifest's classification, not the
    //    executed walk's.)
    //
    //    Round 6 read `b[6]` off every case, which 256 seven-byte buffers
    //    satisfy — both walkers reject those before reading the fixed IPv6
    //    header, so no classifier ever runs. Here the canonical 68-byte case is
    //    rebuilt for each value and required by byte identity, and each is
    //    required NOT to fail closed, which is the direct statement that the
    //    walk got far enough to classify the value.
    //
    //    Round 7 rebuilt it with `chain`, the corpus's own generator, which is
    //    circular: making `chain` write TCP at byte 6 for every one-header
    //    input collapses the corpus to ONE distinct next-header value while
    //    this floor rebuilds the same degenerate bytes, finds them, and reports
    //    256 present. So the expectation is built by `expect_chain` (see its
    //    doc), which writes `p` at byte 6 itself.
    //
    //    That is also what makes the values DISTINCT, without a separate count:
    //    256 buffers differing at byte 6 are 256 different buffers, and each
    //    must be present byte for byte. A `distinct(b[6]) == 256` assertion on
    //    top of it would be `X == X` — the bytes it counts are the ones this
    //    loop just wrote — which is the shape of defect this whole file is
    //    about, so it is deliberately absent.
    //    Does NOT bind: that each value is presented in more than one position;
    //    only the first-header position is swept, at one declared length.
    //    Does NOT bind: that the classification is CORRECT. "Did not fail
    //    closed" is the weakest statement that the walk RAN — a value
    //    misclassified as terminal resolves `L4(40, p)`, which satisfies it.
    //    That is deliberate: this floor's job is non-vacuity, and correctness
    //    in this dimension is what the cross-walker comparison in
    //    `shim_walk_and_userspace_walk_agree_over_a_corpus` measures. Asserting
    //    a per-value expectation here would restate `userspace_class`, which
    //    `shim_ext_parity_negative_control_unchanged_classifications` already
    //    pins against a hand-written table.
    let mut missing: Vec<u16> = Vec::new();
    let mut unwalked: Vec<u16> = Vec::new();
    for p in 0u16..=255 {
        let want = expect_chain(&[(p as u8, 0)], TCP, 0);
        if !contains(&want) {
            missing.push(p);
        } else if userspace_verdict(&want, 0) == Verdict::FailClosed {
            unwalked.push(p);
        }
    }
    assert!(
        missing.is_empty() && unwalked.is_empty(),
        "#4555 corpus floor 3: {} of 256 next-header values have no canonical single-header case \
         ({missing:?}) and {} are present but fail closed before classification ({unwalked:?}). \
         The executed walked-type-set comparison is blind to both.",
        missing.len(),
        unwalked.len(),
    );

    // 4. A CHAIN WHOSE WALK REACHES LARGE INTERMEDIATE OFFSETS.
    //    A statement added inside the walk loop but OUTSIDE the `match` (leak
    //    #3, and acceptance row 10) perturbs nothing on a short chain: the
    //    concrete mutation is `if offset > 200 { break; }`, invisible until the
    //    walk is still on an extension header past that offset. Only a chain of
    //    several maximum-declared-length headers gets there.
    //    Binds: those two chains are still in the corpus.
    //    Does NOT bind: any particular offset threshold — the shape is "a
    //    multi-header chain that walks a long way", and a mutation guarded at a
    //    higher offset than these chains reach would survive. That is what the
    //    acceptance matrix measures, not this floor.
    for n in [3usize, 5] {
        let long = expect_chain(&vec![(DEST, 15); n], TCP, 0);
        assert!(
            contains(&long),
            "#4555 corpus floor 4: the chain of {n} x DestOpt(len=15) is gone. A statement placed \
             inside the walk loop but outside the `match` is observable only while the walk is \
             still on an extension header at a large offset, which needs a chain of several \
             maximum-length headers."
        );
    }

    // 5. THE CORPUS WALKS AT EVERY L3 OFFSET THIS CRATE'S L2 PARSER PRODUCES.
    //    `L3_OFFSETS.len() >= 3` stood here in round 5 and asserted a PROXY:
    //    `[0, 0, 0]` has length 3 and restores exactly the l3-blindness the
    //    message described. Round 6 replaced it with `any(!= 0)` and
    //    `contains(0)`, which `[0, 14, 14]` also satisfies while dropping the
    //    tagged offset entirely. So the offsets are MEASURED here: `at_l3`
    //    builds the untagged and 802.1Q prefixes, and `frame_l3_offset` — the
    //    function that computes the L3 offset the forwarding path walks at —
    //    says where L3 starts in each.
    //    Binds: every offset this crate's L2 parser produces is in the array,
    //    plus 0, the offset `walk_ipv6_ext_chain`'s other callers pass when they
    //    hand it an L3-relative slice.
    //    Does NOT bind: the SHIM's `parse_l2`, which is in the aya crate and
    //    cannot be linked here. That the two agree on 14/18 is a documented
    //    claim (see `L3_OFFSETS`), not something this floor measures.
    let probe = chain(&[], TCP, 0);
    for tag in [14usize, 18] {
        let framed = at_l3(&probe, tag);
        let measured = frame_l3_offset(&framed).unwrap_or_else(|| {
            panic!(
                "#4555 corpus floor 5: frame_l3_offset refused the {tag}-byte L2 prefix at_l3 \
                 builds; the floor cannot measure what it claims to"
            )
        });
        assert!(
            L3_OFFSETS.contains(&measured),
            "#4555 corpus floor 5: the L3 offsets ({L3_OFFSETS:?}) omit {measured}, an offset this crate's \
             frame_l3_offset produces (here from the {tag}-byte prefix). Replacing the \
             revalidation's base `l3_offset as usize` with `0usize` is BIT-IDENTICAL at l3 = 0 and \
             a fail-open of exactly l3 bytes at every non-zero offset, so an offset missing from \
             this array is a mutation nothing can see."
        );
    }
    assert!(
        L3_OFFSETS.contains(&0),
        "#4555 corpus floor 5: the L3 offsets ({L3_OFFSETS:?}) no longer include 0, the offset \
         `walk_ipv6_ext_chain`'s other callers pass when they hand it an L3-relative slice"
    );

    // 6. EVERY NAMED SHAPE BLOCK IS STILL HERE, BY CONSTRUCTION.
    //
    //    Floors 1-5 bind five shapes. Round 7 deleted a `handcrafted >= 40`
    //    count floor arguing they SUBSUMED it. They do not, and the gap is
    //    large: floors 1-4 require ten boundary buffers, the two chain-length
    //    twins and the two long chains — 14 hand-written cases before the 256
    //    sweep — so the intermediate chain lengths, the varied declared
    //    lengths, the truncation block, the minimal per-arm packets, the
    //    non-first fragments, the AH sweep and the #4517 Mobility cases could
    //    ALL be deleted with every floor still green. Measured: deleting the
    //    ten varied-length HbH cases and the ten truncation cases drops the
    //    hand-written count 55 -> 35, which the old `>= 40` floor would have
    //    caught and none of floors 1-5 does.
    //
    //    A count floor is the wrong repair — the old threshold was arbitrary,
    //    and a count has degenerate satisfiers (round 5's `cases.len() >= 200`
    //    was cleared by the 256-sweep alone). This binds the BLOCKS instead:
    //    each named category is rebuilt here with `expect_chain` / explicit
    //    bytes and required in the corpus in FULL, so deleting a whole category
    //    — or a single case out of one — names the category in the failure.
    //
    //    Binds: presence, byte for byte, of every hand-written case. Deliberate
    //    edits to the corpus must be mirrored here, which is the point: a
    //    deletion becomes a two-file change a reviewer sees rather than a
    //    silent narrowing between acceptance runs.
    //    Does NOT bind: that any of these shapes is PULLING ITS WEIGHT. Only
    //    `make test-shim-ext-parity-lib` measures that (#7766; ~40 min), by
    //    mutating the shim and requiring the guards to red. A block that never
    //    detects anything would still be required here; floors stop deletion,
    //    the matrix measures value.
    //    #6920/#7766: "the matrix measures value" holds only for a run that
    //    finishes and only if one has been run — it aborted at row 7 until
    //    #6920 and is wired into no gate.
    //    Does NOT bind: the 256-value sweep (floor 3), the boundary witness
    //    pairs (floor 1), or the four exhaustive dimension sweeps (floor 7),
    //    each bound where it is constructed. The chain-length and long-chain
    //    blocks below overlap floors 2 and 4; the overlap is kept so this list
    //    is the complete account of the HAND-WRITTEN corpus rather than the
    //    complement of four other floors. "Hand-written" is the scope: the
    //    generated sweeps are floors 3 and 7's, and between the three lists
    //    every case in this function is required by one of them.
    let ah_sweep_case = |len: u8| {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = AH;
        b.extend_from_slice(&[TCP, len]);
        b.extend_from_slice(&[0u8; 254]);
        b
    };
    let non_first_frag_case = |frag_off: u16| {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = FRAG;
        b.extend_from_slice(&[TCP, 0]);
        b.extend_from_slice(&frag_off.to_be_bytes());
        b.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        b.extend_from_slice(&[0x11; 20]);
        b
    };
    let stub_case = |proto: u8, second: u8| {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = proto;
        b.extend_from_slice(&[TCP, second]);
        b
    };
    let blocks: [(&str, Vec<Vec<u8>>, &str); 8] = [
        (
            "chain lengths 0..=10 across the resolvable boundary",
            (0..=10usize)
                .map(|n| expect_chain(&vec![(DEST, 0); n], TCP, 0))
                .collect(),
            "the only cases that walk each chain length; floor 2 pins just the two at the \
             boundary, so the rest can vanish without it noticing",
        ),
        (
            "declared lengths 0/1/2/5/15, alone and followed by DestOpt(len=1)",
            [0u8, 1, 2, 5, 15]
                .iter()
                .flat_map(|&len| {
                    [
                        expect_chain(&[(HBH, len)], TCP, 0),
                        expect_chain(&[(HBH, len), (DEST, 1)], TCP, 0),
                    ]
                })
                .collect(),
            "what separates the generic arm's `* 8` from any other multiplier: an advance \
             error `a*l + b` is invisible at a single declared length",
        ),
        (
            "long chains reaching large intermediate offsets",
            [3usize, 5]
                .iter()
                .map(|&n| expect_chain(&vec![(DEST, 15); n], TCP, 0))
                .collect(),
            "the only shape that observes a statement inside the walk loop but outside the \
             `match` (also floor 4)",
        ),
        (
            "truncation: declared length runs past the packet",
            [1usize, 8, 20, 21, 40]
                .iter()
                .flat_map(|&trim| {
                    [
                        expect_chain(&[(HBH, 5)], TCP, trim),
                        expect_chain(&[(DEST, 15)], TCP, trim),
                    ]
                })
                .collect(),
            "without the post-advance revalidation these resolve an L4 offset outside the \
             buffer instead of failing closed",
        ),
        (
            "minimal per-arm packets (AH 42-byte, Fragment truncated to 2)",
            vec![stub_case(AH, 3), stub_case(FRAG, 0)],
            "the padded cases cannot see a deleted revalidation; only a packet ending at or \
             before the advance target can",
        ),
        (
            "NON-FIRST fragments",
            [0x0008u16, 0x0010, 0x0100]
                .iter()
                .map(|&off| non_first_frag_case(off))
                .collect(),
            "the inputs behind the documented shim/userspace fragment-state asymmetry \
             (#6704); both walkers resolve the same offset and only the fragment state \
             differs",
        ),
        (
            "Fragment composition",
            vec![
                expect_chain(&[(FRAG, 0)], TCP, 0),
                expect_chain(&[(DEST, 0), (FRAG, 0)], TCP, 0),
            ],
            "the Fragment arm's fixed 8-byte advance, alone and reached as a LATER header",
        ),
        (
            "AH declared-length sweep and #4517 Mobility",
            vec![
                ah_sweep_case(0),
                ah_sweep_case(1),
                ah_sweep_case(3),
                expect_chain(&[(MOBILITY, 0)], TCP, 0),
                expect_chain(&[(HBH, 0), (MOBILITY, 0)], TCP, 0),
            ],
            "the AH arm's `(len+2)*4` at three lengths, and the #4517 types that were missing \
             from the shim's walked set entirely",
        ),
    ];
    for (name, want, why) in &blocks {
        let gone: Vec<usize> = want
            .iter()
            .enumerate()
            .filter(|(_, b)| !contains(b))
            .map(|(i, _)| i)
            .collect();
        assert!(
            gone.is_empty(),
            "#4555 corpus floor 6: the corpus block \"{name}\" has lost {} of its {} cases (index \
             {gone:?}). {why}. Floors 1-5 do not cover this block, so its deletion is invisible to \
             every other assertion in this file — which is exactly how the round-5 corpus was cut \
             to a 256-case sweep with the generic arm's revalidation deleted and all five tests \
             still reporting `ok`.",
            gone.len(),
            want.len(),
        );
    }

    // 7. THE EXHAUSTIVE DIMENSION SWEEPS ARE COMPLETE, AND LAND WHERE CLAIMED.
    //
    //    Floor 1's two-witness derivation is sound only for errors AFFINE in
    //    the declared length; the sweeps above are what excludes the rest of
    //    the family, and a sweep with a hole in it is the whole hole. So each
    //    is required here VALUE BY VALUE, rebuilt with the independent
    //    `expect_*` builders rather than the corpus's own, and — for the three
    //    dimensions where the arm's target is a function of the swept value —
    //    each value's buffer is MEASURED to resolve the terminal at exactly
    //    that arm's target. Presence alone would be satisfied by 256 buffers
    //    that all fail closed.
    //
    //    THE SHAPE OF THE SWEEP IS PART OF THE CLAIM. One dimension is joint
    //    and three are marginal; which is which is spelled out below, because
    //    "swept exhaustively" reads as a statement about the joint space and is
    //    not one.
    //
    //    Binds, JOINTLY: every (generic arm member x declared length) pair —
    //    8 x 256 — is present AND lands at `(len + 1) * 8`. That pair is joint
    //    rather than marginal because the entering value selects the `match`
    //    arm while `opt[1]` feeds its advance, so an error can be conditioned
    //    on both.
    //    Binds, MARGINALLY: all 256 AUTH declared lengths, present and landing
    //    at `(len + 2) * 4`; all 256 values of the Fragment `reserved` byte,
    //    present and still resolving at 48, so an advance keyed on that byte
    //    has nowhere to hide; all 256 values an extension header can CARRY,
    //    present.
    //
    //    Does NOT bind: ANY OTHER INTERACTION. A marginal sweep of A with B
    //    held fixed says nothing about an error conditioned on A and B — the
    //    same shape as the non-affine error two witnesses could not see, one
    //    level up. Specifically uncovered: (declared length x carried
    //    next-header), which is 256 x 256 = 65536 buffers of up to 2 KB and was
    //    judged not worth the corpus, and every 3-way combination. `opt[0] ==
    //    17 && opt[1] == 4` survives this floor. 256^4 is not enumerable, so
    //    the design is four marginals plus the one pair whose interaction the
    //    arm's own code makes reachable; what measures whether the rest matters
    //    is the acceptance matrix, not a bigger corpus.
    //    Does NOT bind: an arm reached as a LATER header — every sweep case is
    //    a single extension header at offset 40.
    //    Does NOT bind: the Fragment header's other unread bytes. `reserved` is
    //    swept; the fragment-offset word appears at four values (three
    //    non-first cases plus this sweep's first-fragment word) and the
    //    identification field at one, so an advance keyed on those still has
    //    somewhere to hide. `reserved` was swept and they were not because it
    //    is one byte and they are six.
    //    Does NOT bind: a verdict for the TERMINAL sweep. Most of its values
    //    are themselves extension-header types, whose walk continues into the
    //    trailing zeros and refuses, so there is no single expectation to
    //    state. What that sweep guarantees is that both walkers are FED all 256
    //    carried values; that they agree on each is the guard's job.
    let sweep_gaps = |build: &dyn Fn(u8) -> Vec<u8>| -> Vec<u16> {
        (0u16..=255)
            .filter(|&v| !contains(&build(v as u8)))
            .collect()
    };
    let sweep_misplaced = |build: &dyn Fn(u8) -> Vec<u8>, target: &dyn Fn(u8) -> usize| {
        (0u16..=255)
            .filter_map(|v| {
                let got = userspace_verdict(&build(v as u8), 0);
                (got != Verdict::L4(target(v as u8), TCP)).then_some((v, got))
            })
            .collect::<Vec<_>>()
    };
    // The GENERIC dimension is JOINT, so it is checked as a product rather than
    // through the per-value helper below: every (arm member, declared length)
    // pair must be present AND land at that arm's target. A marginal check here
    // would report the sweep complete while 7 of its 8 rows had been deleted.
    for proto in GENERIC_MEMBERS {
        let gaps: Vec<u16> = (0u16..=255)
            .filter(|&l| !contains(&expect_chain(&[(proto, l as u8)], TCP, 0)))
            .collect();
        assert!(
            gaps.is_empty(),
            "#4555 corpus floor 7: the GENERIC (next-header x declared length) sweep is missing \
             {} of the 256 lengths at proto={proto} ({:?}...). This pair is swept jointly because \
             the entering value selects the `match` arm and `opt[1]` feeds its advance, so an \
             error can be conditioned on both; a hole at one proto is a hole in the pair.",
            gaps.len(),
            &gaps[..gaps.len().min(8)],
        );
        let bad: Vec<(u16, Verdict)> = (0u16..=255)
            .filter_map(|l| {
                let got = userspace_verdict(&expect_chain(&[(proto, l as u8)], TCP, 0), 0);
                (got != Verdict::L4(generic_target(l as u8), TCP)).then_some((l, got))
            })
            .collect();
        assert!(
            bad.is_empty(),
            "#4555 corpus floor 7: {} of the GENERIC sweep's buffers at proto={proto} no longer \
             resolve a TCP terminal at `(len + 1) * 8` ({:?}...). Present but not observing the \
             arm — 256 cases that all fail closed would satisfy a presence check while measuring \
             nothing.",
            bad.len(),
            &bad[..bad.len().min(4)],
        );
    }

    for (dim, build, target, why) in [
        (
            "AUTH declared length",
            &expect_ah_chain as &dyn Fn(u8) -> Vec<u8>,
            Some(&auth_target as &dyn Fn(u8) -> usize),
            "same, for `(len + 2) * 4`; the corpus sampled 3 of 256 magnitudes before this",
        ),
        (
            "FRAGMENT reserved byte",
            &expect_frag_reserved_case as &dyn Fn(u8) -> Vec<u8>,
            Some(&frag_target as &dyn Fn(u8) -> usize),
            "the Fragment arm takes no declared length, so its analogous hiding place is a byte \
             inside the header that neither walker reads",
        ),
        (
            "TERMINAL carried next-header",
            &expect_chain_terminal as &dyn Fn(u8) -> Vec<u8>,
            None,
            "every other chain in this corpus declares TCP, so the byte an extension header \
             CARRIES took four values out of 256 and a mutation keyed on any other one moved \
             nothing",
        ),
    ] {
        let gaps = sweep_gaps(build);
        assert!(
            gaps.is_empty(),
            "#4555 corpus floor 7: the {dim} sweep is missing {} of its 256 values ({:?}...). \
             {why}.",
            gaps.len(),
            &gaps[..gaps.len().min(8)],
        );
        if let Some(target) = target {
            let bad = sweep_misplaced(build, target);
            assert!(
                bad.is_empty(),
                "#4555 corpus floor 7: {} of the {dim} sweep's 256 values no longer resolve a TCP \
                 terminal at this arm's advance target ({:?}...). The buffers are present but the \
                 sweep is not observing the arm — 256 cases that all fail closed would satisfy a \
                 presence check while measuring nothing.",
                bad.len(),
                &bad[..bad.len().min(4)],
            );
        }
    }

    cases
}

/// Each arm's advance target as a function of the swept value. Free functions
/// rather than closures so floor 7 can hold them in one table with the other
/// dimensions' builders. GENERIC has no builder here: its sweep is JOINT over
/// (next-header x declared length), so floor 7 checks it as a product rather
/// than through the single-argument helper the marginal dimensions use.
fn generic_target(hdr_len: u8) -> usize {
    40 + (usize::from(hdr_len) + 1) * 8
}

fn auth_target(hdr_len: u8) -> usize {
    40 + (usize::from(hdr_len) + 2) * 4
}

/// The FRAGMENT arm's advance is a fixed 8 and takes no parameter; the argument
/// is the swept `reserved` byte, which must not change where the arm lands.
fn frag_target(_reserved: u8) -> usize {
    48
}

/// Floor 7's rebuild of one TERMINAL sweep case: one minimum-size DestOpt
/// header CARRYING `terminal`.
fn expect_chain_terminal(terminal: u8) -> Vec<u8> {
    expect_chain(&[(DEST, 0)], terminal, 0)
}

/// The load-bearing behavioural guard: over a corpus of real chains, at every
/// L3 offset the shim produces, the shim's executed walk and this crate's
/// walker must reach the SAME verdict.
///
/// This is what replaces the deleted source models. It reds on an altered
/// advance (the offsets diverge), on a deleted or weakened bounds revalidation
/// in ANY of the three arms (a truncated chain resolves instead of failing
/// closed), on a statement added inside the loop but outside the `match` (the
/// chain length diverges), on a changed walked type set (a type resolves on one
/// side and terminates on the other), and on a revalidation whose base offset
/// stops accounting for the L3 offset (invisible at `l3 = 0`, a fail-open of
/// `l3` bytes at the 14 and 18 the shim actually passes).
///
/// What it does NOT compare is stated, not implied: the shim's walk returns
/// `(offset, protocol)` and no fragment state, so there is nothing on the shim
/// side to compare `ExtChainWalk::fragment` or `non_first_fragment_offset_seen`
/// against. `shim_is_not_more_permissive` covers that dimension explicitly.
/// Derive the compared-field list from `Verdict` and from the shim's own return
/// type rather than from this comment; a field the shim DOES produce that is
/// absent here is the defect class this file exists to close.
#[test]
fn shim_walk_and_userspace_walk_agree_over_a_corpus() {
    let cases = parity_corpus();
    // Distinct NAMES first: the visited-set check below is a set comparison, so
    // two cases sharing a name would collapse into one entry on both sides and
    // hide that one of them never ran.
    let names: BTreeSet<&str> = cases.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names.len(),
        cases.len(),
        "#4555: the corpus has {} cases but only {} distinct names; a duplicated name makes the \
         coverage accounting below collapse two cases into one",
        cases.len(),
        names.len(),
    );

    // #7780: the drift report is BOUNDED, and the bound is VISIBLE.
    //
    // This accumulated one format! per diverging pair over the whole corpus at
    // three L3 offsets. Measured: a walker that diverges everywhere produces
    // 9423 divergences over 9423 pairs, so the old code built 9423 Strings and
    // joined them into one — allocating hardest on exactly the mutations this
    // test exists to catch. Wiring the acceptance harness into a gate (#7766)
    // turns that from a slow failure nobody runs into a gate that dies on its
    // own subject matter, and an OOM presents as an environment problem rather
    // than as the finding it is.
    //
    // The TOTAL is counted separately from the SAMPLE that is kept. Reporting
    // the first N of an unknown total is a different defect wearing the same
    // green: a reader cannot distinguish 20-of-20 from 20-of-9423, and the
    // second is what says the two walkers diverged wholesale rather than one
    // case regressing.
    let mut drift: Vec<String> = Vec::new();
    let mut drift_total = 0usize;
    // What actually got COMPARED, recorded after the comparison. A counter
    // incremented inside these same loops is `X == X` — `compared += 1` and
    // the work it claims to count are the same statement sequence, so any edit
    // that skips one skips the other and the equality holds regardless. This
    // records the (offset, case) pair only once both walkers have been run on
    // it, and checks the result against the cross product built independently
    // from the two inputs.
    let mut visited: BTreeSet<(usize, &str)> = BTreeSet::new();
    // #6704 coverage accounting for the fragment dimension, kept separate
    // because a comparison that only ever sees `false == false` proves
    // nothing: the corpus carries NON-FIRST Fragment cases (frag_off 0x0008 /
    // 0x0010 / 0x0100) precisely so the axis VARIES, and `frag_true` is what
    // makes that measurable rather than assumed.
    let mut frag_compared: BTreeSet<(usize, &str)> = BTreeSet::new();
    let mut frag_true = 0usize;
    for l3 in L3_OFFSETS {
        for (name, base) in &cases {
            let buf = at_l3(base, l3);
            let s = shim_verdict(&buf, l3);
            let u = userspace_verdict(&buf, l3);
            if s != u {
                drift_total += 1;
                if drift.len() < MAX_DRIFT_REPORTED {
                    drift.push(format!("[l3={l3}] {name}: shim={s:?} userspace={u:?}"));
                }
            }
            // #6704: the FRAGMENT dimension, which could not be compared at
            // all until the shim's walk carried the sighting. Compared only
            // where the shim resolved — a refusal (`None`) has no sighting to
            // agree about, and the verdict comparison above already covers
            // that case.
            if let Some(shim_frag) = shim_fragment_sighting(&buf, l3) {
                let us_frag = walk_ipv6_ext_chain(&buf, l3).non_first_fragment_offset_seen;
                if shim_frag != us_frag {
                    drift_total += 1;
                    if drift.len() < MAX_DRIFT_REPORTED {
                        drift.push(format!(
                            "[l3={l3}] {name}: FRAGMENT sighting shim={shim_frag} \
                             userspace={us_frag}"
                        ));
                    }
                }
                frag_compared.insert((l3, name.as_str()));
                if shim_frag {
                    frag_true += 1;
                }
            }
            visited.insert((l3, name.as_str()));
        }
    }
    let expected: BTreeSet<(usize, &str)> = L3_OFFSETS
        .iter()
        .flat_map(|&l3| names.iter().map(move |&n| (l3, n)))
        .collect();
    assert!(
        frag_true >= L3_OFFSETS.len() * 3,
        "#6704: only {frag_true} (offset, case) pairs reported a NON-FIRST fragment sighting; the \
         corpus carries three such cases at each of {} L3 offsets, so the fragment comparison is \
         running over an all-`false` population and would stay green with the sighting hard-wired \
         to `false`",
        L3_OFFSETS.len(),
    );
    // Not equality: a case the shim REFUSES (`None`) has no sighting to
    // compare, and the corpus deliberately carries truncated/over-limit cases
    // that refuse. Subset + the `frag_true` floor above is the honest pair of
    // claims — every pair that was compared is one the verdict loop also
    // visited, and the population that was compared is not all-`false`.
    assert!(
        frag_compared.is_subset(&visited),
        "#6704: the fragment sighting was compared on {} (offset, case) pairs the verdict loop \
         never visited",
        frag_compared.difference(&visited).count()
    );
    assert_eq!(
        visited,
        expected,
        "the #4555 corpus loop did not run every case at every L3 offset: {} of {} pairs were \
         never compared",
        expected.difference(&visited).count(),
        expected.len(),
    );
    let compared = visited.len();
    // #7780: the count is the TOTAL, the list is a bounded sample, and the
    // message says which is which. "showing 20 of 20" and "showing 20 of 9423"
    // are different findings, and a message reporting only the sample could not
    // tell them apart.
    assert!(
        drift_total == 0,
        "#4555 BEHAVIOURAL parity drift between the shim's executed IPv6 extension-header walk \
         and this crate's walk_ipv6_ext_chain: {drift_total} divergence(s) over {compared} \
         chain/L3 pairs, showing the first {shown}. These are outcomes of running both walkers \
         on the same bytes, so a divergence here is a real packet-handling difference: the shim \
         would compute a session key from a different L4 offset (or accept a chain the \
         forwarding path refuses) and the flow would be mis-steered or dropped. \
         Divergences:\n  {}",
        drift.join("\n  "),
        shown = drift.len(),
    );
}

/// The KNOWN, UNCLOSED non-parity, stated rather than papered over — the
/// assertion the file has cited by name since #4555 round 5 without ever
/// containing it.
///
/// `walk_ipv6_ext_chain` returns an `ExtChainWalk`: outcome, PLUS the first
/// `ExtChainFragment` sighting (its 8 raw bytes, or `None` when the buffer
/// truncated them), PLUS `non_first_fragment_offset_seen`. Every one of those
/// is consumed — `ipv6_is_any_fragment` matches on the DECLARATION,
/// `ipv6_is_non_first_fragment` fails closed on unreadable bytes and refuses a
/// non-first fragment's payload as an L4 header, and the NAT64 path reads the
/// offset, the M flag and the 32-bit identification.
///
/// `walk_ipv6_ext_headers` returns `(offset, protocol)`. That is all of it.
///
/// A previous revision "closed" this by hand-writing a second walk loop inside
/// the test and re-deriving the two fragment columns with the same expression
/// `walk_ipv6_ext_chain` uses, then comparing the results. `X == X`: the
/// widened corpus stayed green on the very non-first-fragment input it was
/// widened to catch, and no shim-side edit could have moved either column. This
/// test replaces that with three things that are all measured by RUNNING both
/// real walkers:
///
///   1. the shim IS blind — two chains differing only in the Fragment header's
///      offset/M/identification bytes give the same shim result;
///   2. this crate is NOT — the same two chains give different `ExtChainWalk`s,
///      with every sub-field of `ExtChainFragment` pinned;
///   3. in the dimension the shim does represent, it is not more permissive:
///      over the whole corpus, at every L3 offset, a chain the shim resolves to
///      an L4 is resolved by this crate to the SAME L4.
///
/// NOT A SAFETY CLAIM, and NOT CLOSED — tracked as #6704, pre-existing and not
/// introduced by #4555. On `IPv6 || Fragment(frag_off != 0, next = TCP)` the
/// shim resolves `L4(48, TCP)` and hands offset 48 to `parse_l4`
/// (`userspace-xdp/src/lib.rs`), which reads the fragment PAYLOAD as a TCP
/// header — `sport = be16(b[48..50])`, `dport = be16(b[50..52])`,
/// `data_offset = (b[60] >> 4) * 4`. This crate refuses those bytes everywhere.
/// The shim's lookup can only HIT a session userspace INSTALLED, and userspace
/// never installs one from a non-first fragment; the residual risk is a
/// synthesised 5-tuple COINCIDING with a legitimate session, which then takes
/// that session's fast path with no policy evaluation of its own. This test
/// PINS the asymmetry so it cannot change unnoticed; it does not assert the
/// asymmetry is harmless. Closing it means making the shim's walk carry the
/// sighting — a shim change, `make generate`, and the #1864 verifier gate.
#[test]
fn shim_is_not_more_permissive() {
    // `IPv6 || Fragment(next=TCP, frag_off, ident) || 20 payload bytes`.
    // Byte 60 is the payload byte `parse_l4` would read as the TCP data offset,
    // set so the shim's TCP parse ACCEPTS these payload bytes as a header.
    let frag_chain = |frag_off: u16, ident: u32| -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b[0] = 0x60;
        b[6] = FRAG;
        b.extend_from_slice(&[TCP, 0]);
        b.extend_from_slice(&frag_off.to_be_bytes());
        b.extend_from_slice(&ident.to_be_bytes());
        b.extend_from_slice(&[0x11; 20]);
        b[48] = 0x04;
        b[49] = 0xD2; // "source port" 1234, chosen by the sender
        b[60] = 0x50; // data offset 5 words = 20 bytes, so parse_l4 accepts
        b
    };
    // frag_off bytes are the 13-bit offset in the top bits, then two reserved
    // bits, then M (RFC 8200 §4.5): 0x0001 is a FIRST fragment with more to
    // come; 0x0008 is fragment offset 1 — a NON-FIRST fragment.
    let first = frag_chain(0x0001, 0xDEAD_BEEF);
    let non_first = frag_chain(0x0008, 0x0BAD_F00D);

    // 1. The shim now DISTINGUISHES the two, MEASURED by running it — and its
    //    answer AGREES with this crate's, which is the property, rather than a
    //    literal that would encode which side is trusted.
    //
    //    This is the rewrite the previous revision of this test asked for in
    //    so many words ("if the shim now carries fragment state, the corpus
    //    must compare it and this test must be rewritten, not deleted"). It
    //    was rewritten, not deleted: #6704 taught `walk_ipv6_ext_headers` to
    //    report the sighting, so the asymmetry this test used to PIN as absent
    //    is now a symmetry it pins as present.
    let shim_first = raw_shim_walk(&first, 0).expect("the shim's walk must resolve a first fragment");
    let shim_non_first =
        raw_shim_walk(&non_first, 0).expect("the shim's walk must resolve a non-first fragment");
    let us_first = walk_ipv6_ext_chain(&first, 0);
    let us_non_first = walk_ipv6_ext_chain(&non_first, 0);
    assert_eq!(
        shim_first.non_first_fragment, us_first.non_first_fragment_offset_seen,
        "#6704: the two walkers disagree about a FIRST fragment's sighting"
    );
    assert_eq!(
        shim_non_first.non_first_fragment, us_non_first.non_first_fragment_offset_seen,
        "#6704: the two walkers disagree about a NON-FIRST fragment's sighting — the divergence \
         this test exists to make visible"
    );
    assert_ne!(
        shim_first.non_first_fragment, shim_non_first.non_first_fragment,
        "#6704: the shim's sighting did not MOVE between a first and a non-first fragment, so the \
         agreement asserted above holds for the wrong reason (both sides constant)"
    );
    assert_eq!(
        (shim_non_first.offset, shim_non_first.protocol),
        (48u16, TCP),
        "#4555: the shim resolved something other than L4(48, TCP) on a non-first fragment; the \
         documented divergence below is stated against that exact outcome"
    );
    // The bytes the shim's parse_l4 would read as a TCP source port at offset
    // 48 are fragment payload the sender chose, not a header.
    assert_eq!(
        u16::from_be_bytes([non_first[48], non_first[49]]),
        1234,
        "#4555: the L4 offset the shim resolved does not point at the payload bytes this case \
         planted, so the divergence below is being demonstrated on the wrong bytes"
    );

    // 2. This crate is not blind, and every sub-field of `ExtChainFragment` is
    //    pinned — the readable/unreadable discriminant, the 13-bit offset, the
    //    M flag and the 32-bit identification. `.is_some()` alone (what the
    //    previous revision compared) collapses all of it to one bit.
    let (uf, un) = (us_first, us_non_first);
    assert_ne!(
        uf, un,
        "#4555: walk_ipv6_ext_chain stopped distinguishing a first from a non-first fragment; the \
         NAT64 and embedded-ICMP consumers depend on that distinction"
    );
    assert_eq!(
        uf.fragment.and_then(|f| f.bytes),
        Some([TCP, 0, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF]),
        "#4555: the recorded first-fragment bytes changed (next/reserved/offset+M/identification)"
    );
    assert_eq!(
        un.fragment.and_then(|f| f.bytes),
        Some([TCP, 0, 0x00, 0x08, 0x0B, 0xAD, 0xF0, 0x0D]),
        "#4555: the recorded non-first-fragment bytes changed"
    );
    assert!(!uf.non_first_fragment_offset_seen);
    assert!(un.non_first_fragment_offset_seen);
    assert!(!ipv6_is_non_first_fragment(&first));
    assert!(
        ipv6_is_non_first_fragment(&non_first),
        "#4555: this crate stopped refusing a non-first fragment's payload as an L4 header, which \
         is the ONLY thing standing between the shim's L4(48, TCP) and the forwarding path"
    );

    // The readable/unreadable discriminant, on a DECLARED-but-truncated header.
    // This is where the two sides legitimately describe a refusal differently:
    // this crate records the declaration with `bytes: None` (so
    // `ipv6_is_any_fragment` still matches, pre-#6435 semantics) while the
    // shim's 8-byte read fails and the whole walk returns None. Both refuse; the
    // corpus compares the refusal, this pins the description.
    let mut truncated = vec![0u8; 40];
    truncated[0] = 0x60;
    truncated[6] = FRAG;
    truncated.extend_from_slice(&[TCP, 0]);
    let ut = walk_ipv6_ext_chain(&truncated, 0);
    assert_eq!(
        ut.fragment.map(|f| f.bytes),
        Some(None),
        "#4555: a declared-but-truncated Fragment header must be RECORDED with unreadable bytes"
    );
    assert!(ipv6_is_any_fragment(&truncated));
    assert!(!ipv6_is_non_first_fragment(&truncated));
    assert!(
        raw_shim_walk(&truncated, 0).is_none(),
        "#4555: the shim must fail its 8-byte Fragment read rather than advance past a truncated \
         header"
    );
    // `None` is `raw_shim_walk`'s FAILURE DEFAULT: a buffer too short for the
    // fixed 40-byte header returns it before the walk starts, as does any other
    // refusal. So pair it with the shortest buffer that DOES resolve — the same
    // packet with the Fragment header's remaining 6 bytes present. That the
    // 42-byte form refuses and the 48-byte form resolves attributes the refusal
    // to the 8-byte Fragment read specifically, which is the invariant acceptance
    // rows 7 and 8 (`read 8 -> 2`, `read 8 -> 7`) mutate.
    let mut whole_frag_hdr = truncated.clone();
    whole_frag_hdr.extend_from_slice(&[0u8; 6]);
    assert_eq!(
        whole_frag_hdr.len(),
        48,
        "#4555: the companion case is not a complete 8-byte Fragment header"
    );
    assert_eq!(
        raw_shim_walk(&whole_frag_hdr, 0).map(|w| (w.offset, w.protocol, w.non_first_fragment)),
        Some((48u16, TCP, false)),
        "#4555: the shim no longer resolves a COMPLETE 8-byte Fragment header at offset 48, so \
         the refusal asserted above cannot be attributed to the missing 6 bytes — every buffer \
         would refuse and the assertion would hold for the wrong reason"
    );

    // 3. In the dimension the shim DOES represent, it is not more permissive.
    //    The corpus asserts equality in both directions; this states the
    //    security direction on its own, because that is the half a future
    //    narrowing of the corpus would have to preserve.
    let cases = parity_corpus();
    let mut permissive: Vec<String> = Vec::new();
    for l3 in L3_OFFSETS {
        for (name, base) in &cases {
            let buf = at_l3(base, l3);
            if let Verdict::L4(off, proto) = shim_verdict(&buf, l3) {
                let u = userspace_verdict(&buf, l3);
                if u != Verdict::L4(off, proto) {
                    permissive.push(format!(
                        "[l3={l3}] {name}: shim resolved L4({off}, {proto}) but this crate says \
                         {u:?}"
                    ));
                }
            }
        }
    }
    assert!(
        permissive.is_empty(),
        "#4555: the shim resolved an L4 the forwarding path does not, on {} of {} chain/L3 pairs. \
         The shim would build a session key for a packet userspace refuses to forward the same \
         way. Cases:\n  {}",
        permissive.len(),
        cases.len() * L3_OFFSETS.len(),
        permissive.join("\n  ")
    );
}

/// NEGATIVE CONTROL for the behavioural corpus.
///
/// Every SHIM-side expectation here must be invariant under the mutations the
/// corpus defends against, or this is a co-signer rather than a control. An
/// earlier draft asserted that the shim resolves one minimum-size DestOpt at
/// offset 48 — which the `* 8` → `* 16` mutation changes to 56, so it went red
/// alongside the corpus and proved nothing about it. That assertion is now
/// userspace-only.
///
/// What is left on the shim side executes no arm body any mutation touches:
///   - a chain with NO extension headers does enter the walk loop — it runs
///     the classifier once, takes the `match`'s terminal catch-all and breaks —
///     but that path has no advance arithmetic, no post-advance revalidation
///     and no header read to perturb. The acceptance matrix's added
///     `if offset > 200 { break; }` (the statement-inside-the-loop row) IS
///     executed here, at offset 40, where it is false: the statement runs and
///     changes nothing, which is precisely what makes this a control rather
///     than a co-signer. An earlier revision claimed the packet "never enters
///     a `match` arm", which is not what the loop does;
///   - a buffer too short for the fixed 40-byte header fails closed before the
///     walk starts, so no iteration runs at all.
/// Both outcomes are fixed by RFC 8200 and unchanged by any mutation to the
/// walk, so a red here means the corpus harness or this crate's walker broke.
#[test]
fn shim_walk_corpus_negative_control() {
    // No extension headers: L4 sits immediately after the fixed 40-byte header.
    let plain = chain(&[], TCP, 0);
    assert_eq!(userspace_verdict(&plain, 0), Verdict::L4(40, TCP));
    assert_eq!(shim_verdict(&plain, 0), Verdict::L4(40, TCP));
    // A buffer too short for the fixed header fails closed on both sides.
    // `FailClosed` is the failure default on both, so it is paired with the
    // shortest buffer that does NOT fail: exactly 40 bytes, one byte more than
    // the longest refusal. The pair attributes the refusal to the fixed
    // header's length rather than to "everything refuses".
    let stub = vec![0u8; 12];
    assert_eq!(userspace_verdict(&stub, 0), Verdict::FailClosed);
    assert_eq!(shim_verdict(&stub, 0), Verdict::FailClosed);
    let mut short_by_one = vec![0u8; 39];
    short_by_one[0] = 0x60;
    short_by_one[6] = TCP;
    assert_eq!(userspace_verdict(&short_by_one, 0), Verdict::FailClosed);
    assert_eq!(shim_verdict(&short_by_one, 0), Verdict::FailClosed);
    let mut exactly_40 = vec![0u8; 40];
    exactly_40[0] = 0x60;
    exactly_40[6] = TCP;
    assert_eq!(
        userspace_verdict(&exactly_40, 0),
        Verdict::L4(40, TCP),
        "a buffer of exactly the fixed 40-byte header must resolve its declared terminal; \
         without this the fail-closed assertions above hold for any walker that refuses \
         everything"
    );
    assert_eq!(
        shim_verdict(&exactly_40, 0),
        Verdict::L4(40, TCP),
        "the shim must resolve a buffer of exactly the fixed 40-byte header"
    );
    // Userspace-only: asserting the shim's offset here would track the generic
    // advance and co-sign mutation 1.
    let one = chain(&[(DEST, 0)], TCP, 0);
    assert_eq!(userspace_verdict(&one, 0), Verdict::L4(48, TCP));
}

// ---------------------------------------------------------------------------
// #6923: the OVER-LIMIT refusal, end to end.
//
// Everything above compares the two WALKS. This section is about what happens
// after one of them gives up, because that is where the walk's own doc comment
// makes a claim it cannot see: exhausting `MAX_EXT_HDRS` "returns the last
// declared next-header value, ... the session key misses, and the packet is
// redirected to userspace — the fail-closed path for an over-limit chain."
//
// The miss is not a property of the shim. It is a property of the session MAP,
// which userspace writes. The claim is only true if no writer can produce
// `(AF_INET6, <a next-header the walk traverses>, src, dst, 0, 0)` — and before
// #6923 the ORDINARY packet path could: `metadata_tuple_complete` accepted every
// non-TCP/UDP metadata tuple, so the residual extension-header protocol with
// ports 0/0 became a `SessionFlow`, `flow.is_none()` went false, the #4743
// over-limit drop was skipped, an `application any` permit matched (no ports to
// fail on), and the resulting key was installed and published. The next packet
// of that chain then HIT.
//
// These tests run the REAL shim walk to build the fixture — the chain length is
// derived from the shim's own `MAX_EXT_HDRS` and the residual protocol is
// whatever the shim actually returns, not a hand-written 60 — and then drive the
// production flow parser the install path uses.
// ---------------------------------------------------------------------------

/// Every next-header value the walk TRAVERSES, taken from the SHIM's classifier
/// rather than restated: `eh_class` files exactly these under GENERIC / AUTH /
/// FRAGMENT. No-Next-Header (59) is excluded because it is a terminal verdict on
/// both sides, not a header either walker steps past.
fn shim_traversable_protocols() -> Vec<u8> {
    (0u8..=255)
        .filter(|p| {
            matches!(
                shim_walk::eh_class(*p),
                EH_CLASS_GENERIC | EH_CLASS_AUTH | EH_CLASS_FRAGMENT
            )
        })
        .collect()
}

const WITNESS_SRC: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11,
];
const WITNESS_DST: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22,
];

/// A full Ethernet frame — `eth(14) || IPv6 || n × 8-byte `proto` header || TCP`
/// — carrying real routable-looking addresses and a correct `payload_len`, so
/// the production parsers accept it as an ordinary transit packet and only the
/// chain length is unusual.
///
/// Each of the `n` headers is `[next, 0, 0, 0, 0, 0, 0, 0]`, which is the minimum
/// 8-byte form of ALL THREE traversable arms at once: GENERIC reads
/// `HdrExtLen = 0` and advances `(0 + 1) * 8`, AUTH reads `len = 0` and advances
/// `(0 + 2) * 4`, Fragment advances its fixed 8 with offset/M zero (so it is a
/// FIRST fragment and no fragment predicate diverts the packet). One generator
/// therefore builds a real chain for every member of the traversable set.
fn ext_chain_frame(proto: u8, n: usize) -> Vec<u8> {
    let mut frame = vec![0u8; 14];
    frame[12] = 0x86;
    frame[13] = 0xDD;
    let payload_len = (n * 8 + 20) as u16;
    let mut ip6 = vec![0u8; 40];
    ip6[0] = 0x60;
    ip6[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip6[6] = if n == 0 { TCP } else { proto };
    ip6[7] = 64;
    ip6[8..24].copy_from_slice(&WITNESS_SRC);
    ip6[24..40].copy_from_slice(&WITNESS_DST);
    frame.extend_from_slice(&ip6);
    for i in 0..n {
        let next = if i + 1 == n { TCP } else { proto };
        frame.extend_from_slice(&[next, 0, 0, 0, 0, 0, 0, 0]);
    }
    // A syntactically valid 20-byte TCP header: ports 0x1234/0x5678 and a data
    // offset of 5 words, which is what the shim's `parse_l4` requires before it
    // will report ports. A resolvable chain therefore yields REAL ports, so the
    // within-limit control below is a genuine flow and not another 0/0 tuple.
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&0x5678u16.to_be_bytes());
    tcp[12] = 0x50;
    frame.extend_from_slice(&tcp);
    frame
}

/// The metadata the SHIM stamps for `frame`, MEASURED by running its walk and
/// then applying `parse_l4` the way `parse_ipv6` does — `l4_offset` and
/// `protocol` are the walk's own return values, and the ports are `parse_l4`'s
/// catch-all `(l4_offset, 0, 0, 0, 0)` for anything that is not TCP/UDP/ICMP.
///
/// Nothing here is a model of the shim: the two fields the finding turns on come
/// out of `walk_ipv6_ext_headers` itself.
fn shim_meta_for(frame: &[u8], l3: usize) -> UserspaceDpMeta {
    let walk = raw_shim_walk(frame, l3).expect("the shim's walk must not refuse");
    let (l4_offset, protocol) = (walk.offset, walk.protocol);
    let (src_port, dst_port) = match protocol {
        TCP => (0x1234u16, 0x5678u16),
        // `parse_l4`'s catch-all: no ports are read for any other protocol.
        _ => (0, 0),
    };
    UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol,
        l3_offset: l3 as u16,
        l4_offset,
        flow_src_addr: WITNESS_SRC,
        flow_dst_addr: WITNESS_DST,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        ..UserspaceDpMeta::default()
    }
}

/// The key the SHIM probes `USERSPACE_SESSIONS` with for `meta` — the same six
/// fields `session_map_key` (`afxdp/bpf_map/mod.rs`) copies verbatim out of the
/// `SessionKey` the install path publishes, so a `SessionKey` equal to this one
/// IS a hit.
fn shim_probe_key(meta: UserspaceDpMeta) -> SessionKey {
    SessionKey {
        addr_family: meta.addr_family,
        protocol: meta.protocol,
        src_ip: IpAddr::V6(Ipv6Addr::from(meta.flow_src_addr)),
        dst_ip: IpAddr::V6(Ipv6Addr::from(meta.flow_dst_addr)),
        src_port: meta.flow_src_port,
        dst_port: meta.flow_dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

/// #6923 — the blocking one. For EVERY next-header value the shim's walk
/// traverses, a chain one longer than the shim can resolve must not become a
/// session flow.
///
/// The chain length comes from `shim_walk::MAX_EXT_HDRS`, so this fixture is
/// over-limit by construction and stays over-limit if the bound moves; the
/// residual protocol comes from the shim's own walk, so the key asserted about
/// is the key the shim will really probe with.
///
/// Fails on revert with "must NOT become a session flow" — before #6923
/// `parse_session_flow_from_bytes` returned `Some` here, keyed on the residual
/// extension-header protocol with ports 0/0.
#[test]
fn over_limit_chain_never_becomes_a_session_flow() {
    let traversable = shim_traversable_protocols();
    assert_eq!(
        traversable.len(),
        10,
        "#6923: the shim's traversable set changed size; the sweep below is only as wide as \
         `eh_class` says it is, so a new member must be understood before this test is retuned"
    );
    for proto in traversable {
        let n = shim_walk::MAX_EXT_HDRS + 1;
        let frame = ext_chain_frame(proto, n);
        let meta = shim_meta_for(&frame, 14);

        // The fixture really is over-limit: the shim EXHAUSTED its loop and is
        // still holding an extension-header type, and this crate's independent
        // walker agrees. Without this pair the refusal below could be a
        // refusal of a truncated or malformed packet instead.
        assert_ne!(
            shim_walk::eh_class(meta.protocol),
            EH_CLASS_TERMINAL,
            "#6923: proto={proto}: the shim resolved a terminal for a chain of {n} headers, so \
             this fixture does not exceed MAX_EXT_HDRS and proves nothing about the over-limit \
             path"
        );
        assert_eq!(
            walk_ipv6_ext_chain(&frame, 14).outcome,
            ExtChainOutcome::OverLimit,
            "#6923: proto={proto}: this crate's walker must call a {n}-header chain OverLimit"
        );

        // The metadata arm CAN still build the colliding key — the shim really
        // does hand up a complete-looking tuple, and this states which key it
        // is rather than leaving it implied.
        assert_eq!(
            parse_session_flow_from_meta(meta).map(|f| f.forward_key),
            Some(shim_probe_key(meta)),
            "#6923: proto={proto}: the metadata tuple the shim stamps is not the key it probes \
             with, so this test is not demonstrating the collision it claims"
        );
        assert_eq!(
            meta.flow_src_port, 0,
            "#6923: proto={proto}: parse_l4's catch-all must leave the ports at 0/0"
        );
        assert_eq!(meta.flow_dst_port, 0);

        // THE BINDING ASSERTION: the production entry point the install path
        // calls must refuse it, so `flow.is_none()` holds and the #4743 gate
        // fires.
        assert_eq!(
            parse_session_flow_from_bytes(&frame, meta),
            None,
            "#6923: proto={proto}: an over-limit IPv6 extension-header chain must NOT become a \
             session flow. It did, keyed on protocol {} with ports 0/0 — the exact key the shim \
             probes for the next packet of this chain, so the over-limit refusal the walk \
             documents becomes conditional on policy instead of unconditional",
            meta.protocol
        );
        assert!(
            ipv6_ext_chain_over_limit(&frame, libc::AF_INET6 as u8),
            "#6923: proto={proto}: with no flow derived, the #4743 drop gate must recognise the \
             chain as over-limit — otherwise the packet is forwarded flowless instead of dropped"
        );
    }
}

/// NEGATIVE CONTROL for the refusal above, and the proof that the pipeline it
/// drives is the one that publishes session keys.
///
/// The same generator, one header SHORTER — the longest chain the shim resolves
/// — must still produce a flow, and that flow's `forward_key` must be exactly
/// the key the shim probes with. So the machinery under test genuinely turns a
/// shim-stamped tuple into a published session identity; the over-limit case
/// above is a refusal, not a dead pipeline.
///
/// Stays GREEN under the #6923 revert: nothing here is over-limit.
#[test]
fn at_limit_chain_still_publishes_the_key_the_shim_probes() {
    for proto in shim_traversable_protocols() {
        let n = shim_walk::MAX_EXT_HDRS;
        let frame = ext_chain_frame(proto, n);
        let meta = shim_meta_for(&frame, 14);
        assert_eq!(
            meta.protocol, TCP,
            "#6923: proto={proto}: the shim must resolve a chain of exactly MAX_EXT_HDRS ({n}) \
             headers to its terminal; if it does not, the control is not at the limit"
        );
        // #10729 X2-F6: AH chains are flowless by design (AH identity), so
        // the at-limit control expects None for proto 51 — the shim still
        // resolves the terminal above, but userspace declines the flow.
        if proto == 51 {
            assert_eq!(
                parse_session_flow_from_bytes(&frame, meta),
                None,
                "#10729: proto=51 at-limit chain must be flowless"
            );
            continue;
        }
        let flow = parse_session_flow_from_bytes(&frame, meta).unwrap_or_else(|| {
            panic!(
                "#6923: proto={proto}: a resolvable {n}-header chain must still produce a session \
                 flow — the over-limit refusal must not over-reach onto chains at the bound"
            )
        });
        assert_eq!(
            flow.forward_key,
            shim_probe_key(meta),
            "#6923: proto={proto}: the published key must be the key the shim probes with"
        );
        assert_eq!(flow.forward_key.src_port, 0x1234);
        assert_eq!(flow.forward_key.dst_port, 0x5678);
    }
}

/// OVER-REACH GUARD: the refusal is scoped to the traversable set on IPv6, and
/// to nothing else. Every one of these stays GREEN under the #6923 revert —
/// that is what makes it a guard rather than a restatement of the fix.
#[test]
fn over_limit_refusal_does_not_over_reach() {
    // (a) ESP (50) is deliberately NOT traversable on either side: the payload
    //     is encrypted and the inner next-header unreadable, so it is a
    //     RESOLVED terminal. An IPsec flow must keep its metadata tuple.
    assert_eq!(
        shim_walk::eh_class(50),
        EH_CLASS_TERMINAL,
        "#6923: ESP must stay a terminal on the shim side"
    );
    let esp = ext_chain_frame(DEST, 1);
    let mut esp_meta = shim_meta_for(&esp, 14);
    esp_meta.protocol = 50;
    esp_meta.flow_src_port = 0;
    esp_meta.flow_dst_port = 0;
    // #6837 changed what happens to ESP here, but NOT for a reason this guard
    // is about. ESP is now refused because the shim resolves no L4 identity for
    // it and its 0/0 ports are a placeholder — the same rule that refuses GRE
    // and OSPF. The over-reach this test guards is different and still absent:
    // ESP must never be refused for being an unresolved IPv6 CHAIN, because it
    // is a resolved terminal on both sides.
    //
    // Asserting that directly is also stronger than the session-flow row it
    // replaces, which could not distinguish the two reasons: `None` looked the
    // same either way. Teaching either walker that ESP is traversable reds
    // here; #6837's portless rule cannot make this assertion fire.
    assert!(
        !crate::afxdp::ipv6_ext_header_is_traversable(50),
        "#6923: ESP is a resolved terminal, so the unresolved-chain refusal must not reach it"
    );
    // And the refusal that DOES apply is the portless one, which is scoped to
    // the metadata tuple rather than to the chain — pinned over all 256 values
    // by `metadata_tuple_complete_refuses_unresolved_ipv6_ext_protocols_even_with_ports`
    // and `metadata_tuple_complete_matches_the_shim_resolved_set_6837`.
    assert_eq!(
        parse_session_flow_from_bytes(&esp, esp_meta).map(|f| f.forward_key.protocol),
        None,
        "#6837: ESP has no shim-resolved L4 identity, so its placeholder tuple is refused"
    );

    // (b) No-Next-Header (59) is a terminal verdict, not a traversed header.
    assert_eq!(shim_walk::eh_class(59), EH_CLASS_NONEXT);
    let mut nonext_meta = esp_meta;
    nonext_meta.protocol = 59;
    // Same split as (a): 59 is refused by #6837's portless rule, never by the
    // unresolved-chain rule. The chain property is what this guard owns.
    assert!(
        !crate::afxdp::ipv6_ext_header_is_traversable(59),
        "#6923: No-Next-Header is a terminal verdict on both sides, not a traversed header"
    );
    assert_eq!(
        parse_session_flow_from_bytes(&esp, nonext_meta).map(|f| f.forward_key.protocol),
        None,
        "#6837: No-Next-Header carries no L4 identity, so its placeholder tuple is refused"
    );

    // (c) IPv4 is untouched: 0/43/44/51/60/135/... are ordinary IPv4 protocol
    //     numbers with no extension-header meaning, and the same values must
    //     still form complete IPv4 metadata tuples.
    for proto in shim_traversable_protocols() {
        let mut v4 = vec![0u8; 14];
        v4[12] = 0x08;
        v4[13] = 0x00;
        let mut ip4 = vec![0u8; 20];
        ip4[0] = 0x45;
        ip4[2..4].copy_from_slice(&24u16.to_be_bytes());
        ip4[8] = 64;
        ip4[9] = proto;
        ip4[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip4[16..20].copy_from_slice(&[192, 0, 2, 2]);
        v4.extend_from_slice(&ip4);
        v4.extend_from_slice(&[0u8; 4]);
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET as u8,
            protocol: proto,
            l3_offset: 14,
            l4_offset: 34,
            flow_src_addr: {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&[192, 0, 2, 1]);
                a
            },
            flow_dst_addr: {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&[192, 0, 2, 2]);
                a
            },
            ..UserspaceDpMeta::default()
        };
        // #6923's point here was that the ext-header refusal is IPv6-scoped.
        // After #6837 these values are refused on IPv4 too — but by the
        // PORTLESS rule, which applies to both families equally, so the
        // IPv6-scoping of the ext-header rule is untouched. What this row can
        // still say is that IPv4 is judged by the #6837 rule and nothing else.
        assert_eq!(
            parse_session_flow_from_bytes(&v4, meta).map(|f| f.forward_key.protocol),
            None,
            "#6837: IPv4 protocol {proto} has no shim-resolved L4 identity, so its placeholder \
             tuple is refused — by the portless rule, not by an ext-header rule that must stay \
             IPv6-scoped"
        );

        // NON-VACUITY CONTROL. Without it this loop asserts `None` for every
        // row and would pass just as happily if `parse_session_flow_from_bytes`
        // started refusing EVERYTHING. A TCP tuple on the same IPv4 fixture
        // must still resolve.
        let mut tcp_meta = meta;
        tcp_meta.protocol = TCP;
        tcp_meta.flow_src_port = 0x1234;
        tcp_meta.flow_dst_port = 0x5678;
        assert_eq!(
            parse_session_flow_from_bytes(&v4, tcp_meta).map(|f| f.forward_key.protocol),
            Some(TCP),
            "control: a resolved IPv4 TCP tuple on the same fixture must still produce a flow"
        );
    }
}

/// The refused set and the shim's traversable set are the SAME set, checked
/// against `eh_class` over all 256 values.
///
/// This is what makes the class set load-bearing in both directions: teaching
/// either walker a new extension-header type without teaching
/// `ipv6_ext_header_is_traversable` about it reds here, and so does the reverse.
/// Without it the refusal could silently stop covering a type the shim keeps
/// walking past — which is exactly the shape of the defect it fixes.
#[test]
fn refused_protocol_set_equals_the_shim_traversable_set() {
    for proto in 0u8..=255 {
        let shim_traverses = matches!(
            shim_walk::eh_class(proto),
            EH_CLASS_GENERIC | EH_CLASS_AUTH | EH_CLASS_FRAGMENT
        );
        assert_eq!(
            crate::afxdp::ipv6_ext_header_is_traversable(proto),
            shim_traverses,
            "#6923: proto={proto}: the set userspace refuses as an unresolved IPv6 chain must be \
             exactly the set the shim's walk traverses ({}), or an over-limit chain of this type \
             still mints an installable key",
            class_name(shim_walk::eh_class(proto))
        );
    }
}

/// #6886: every protocol the SHIM classifies as non-terminal is one userspace
/// refuses to build a session flow for — so a shim-built key carrying an
/// extension-header type in its `protocol` field can never HIT.
///
/// This is the trace the issue asked for and explicitly did not do. The shim's
/// `classify_native_gre_inner_ipv6` builds a `UserspaceSessionKey` from the
/// inner IPv6 header and probes `USERSPACE_SESSIONS` with it. Before #6886 its
/// bail-out hand-listed `HOP|ROUTING|DEST|AUTH|FRAGMENT`, so the six types it
/// missed — Mobility (135), HIP (139), Shim6 (140), the two experimental
/// values (253/254) added by #4517, and No-Next-Header (59) — fell through and
/// built a key whose `protocol` was an extension header rather than an L4.
///
/// The issue's open question was whether such a key is merely a MISS or can
/// actually match something. It can only match if userspace ever installs a
/// session under an EH protocol, and this sweep is what forecloses that: the
/// shim's non-terminal set is a subset of the set userspace declines. A miss
/// routes the packet to userspace for full policy evaluation, which is the
/// fail-closed direction.
///
/// Note the guarantee is NEWER than the issue: before #6837 (merged 2026-08-27)
/// `metadata_tuple_complete` ended in `_ => true` and WOULD have installed a
/// zero-ported session under protocol 135, which the shim's mis-built key
/// matches exactly. So this was reachable, not merely theoretical, and the two
/// fixes are complementary — this sweep fails if either regresses.
#[test]
fn shim_non_terminal_protocols_are_never_installable_by_userspace_6886() {
    let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x11));
    let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x22));

    let mut non_terminal = 0usize;
    let mut terminal_installable = 0usize;
    for proto in 0u8..=255 {
        let flow = SessionFlow {
            src_ip: src,
            dst_ip: dst,
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: proto,
                src_ip: src,
                dst_ip: dst,
                // The shim leaves these 0 for any protocol that is not
                // TCP/UDP/ICMPv6 — exactly the key shape under test.
                src_port: 0,
                dst_port: 0,
                            discriminator: Default::default(),
                            routing_domain: 0,
            },
        };
        let meta = UserspaceDpMeta {
            addr_family: libc::AF_INET6 as u8,
            protocol: proto,
            ..UserspaceDpMeta::default()
        };
        let userspace_accepts = metadata_tuple_complete(meta, &flow);

        if shim_walk::eh_class(proto) != shim_walk::EH_CLASS_TERMINAL {
            non_terminal += 1;
            assert!(
                !userspace_accepts,
                "#6886: proto={proto} is NON-TERMINAL to the shim, so its GRE-inner classify \
                 must never find a session under it — but userspace would install one. A \
                 shim-built key carrying an extension-header protocol would then HIT and take \
                 the fast path on a mis-parsed identity"
            );
        } else if userspace_accepts {
            terminal_installable += 1;
        }
    }

    // Non-vacuity, both directions. Without these the sweep passes if the class
    // table went all-terminal (zero assertions run) or if userspace refused
    // EVERYTHING (the assertion holds for a reason that is not the property).
    assert_eq!(
        non_terminal, 11,
        "#6886: the shim's non-terminal set changed size; this sweep is calibrated to it \
         (HOP/ROUTING/DEST/MOBILITY/HIP/SHIM6/EXP1/EXP2/AUTH/FRAGMENT/NONEXT) and would \
         otherwise assert over fewer rows than it claims"
    );
    assert!(
        terminal_installable > 0,
        "#6886: no terminal protocol is installable at all — the sweep above then holds \
         vacuously rather than because EH types specifically are refused"
    );
}

/// #6886 anti-drift: the GRE-inner bail-out must DEFER to `eh_class`, not
/// restate the extension-header set.
///
/// This site drifted precisely because #4517 swept the walker and not the
/// shortcut, leaving a hand-written list that was complete when written. A
/// second hand-written list — here, or in the shim — would drift the same way,
/// so the guard is on the SHAPE of the code rather than on its membership.
///
/// Comments are stripped first: the fix's own comment names the very types and
/// identifiers this scans for, so an unstripped scan would be satisfied by the
/// documentation instead of by the code (the #6885 lesson).
#[test]
fn gre_inner_v6_bailout_defers_to_the_shim_classifier_6886() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../userspace-xdp/src/lib.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let code_only: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let start = code_only
        .find("fn classify_native_gre_inner_ipv6(")
        .expect("#6886: classify_native_gre_inner_ipv6 not found — this bind has rotted; fix it");
    let body = &code_only[start..];
    let end = body.find("\n}").expect("#6886: could not bound the function body");
    let body = &body[..end];

    assert!(
        body.contains("eh_class(protocol) != EH_CLASS_TERMINAL"),
        "#6886: the GRE-inner IPv6 classify must gate on `eh_class(protocol) != \
         EH_CLASS_TERMINAL`. Deferring to the shim's single classifier is what stops this \
         site drifting from the walker again the next time a next-header type is added"
    );
    for hand_listed in [
        "NEXTHDR_HOP",
        "NEXTHDR_ROUTING",
        "NEXTHDR_DEST",
        "NEXTHDR_AUTH",
        "NEXTHDR_FRAGMENT",
    ] {
        assert!(
            !body.contains(hand_listed),
            "#6886: `{hand_listed}` is hand-listed in the GRE-inner classify again. That list \
             was complete when written and stopped being complete when #4517 added five types \
             to the walker; re-introducing it re-introduces the drift"
        );
    }
}

/// #7494: the shim's non-first-fragment sentinel must not collide with the set
/// userspace-dp reads as "the shim gave up mid-chain".
///
/// This is the assertion the enumeration behind #7494 showed was needed. 253
/// and 254 ARE members of that set and sit one step from the chosen value, so a
/// sentinel picked as "some high unused number" would silently reclassify every
/// non-first fragment as an exhausted walk -- and
/// `traversable_predicate_matches_walker_behaviour_over_all_256_values` would
/// have codified the mistake rather than caught it, because 254 is a legitimate
/// member.
///
/// The value's safety currently rests on two facts that live in different
/// crates, which is exactly the shape that rots. This file already
/// `#[path]`-includes the shim's shared module AND can call userspace-dp's
/// predicate, so it is the only place the two can be checked against each
/// other. It fails if either side moves.
#[test]
fn shim_fragment_sentinel_is_not_a_traversable_next_header() {
    use crate::afxdp::frame::inspect::ipv6_ext_header_is_traversable;

    let sentinel = shim_walk::PROTO_FRAGMENT_NO_L4;

    assert!(
        !ipv6_ext_header_is_traversable(sentinel),
        "the #7494 fragment sentinel ({sentinel}) is a member of the traversable \
         set, which userspace-dp reads as \"the shim gave up mid-chain\". A \
         fragment would be reclassified as an exhausted walk. 253 and 254 are \
         real members -- pick a value outside the set."
    );

    // The neighbours, asserted positively, so this cell fails if the traversable
    // set itself is narrowed and the hazard silently stops existing. A guard
    // whose premise has evaporated should be re-examined, not left passing.
    assert!(
        ipv6_ext_header_is_traversable(253) && ipv6_ext_header_is_traversable(254),
        "253/254 are no longer traversable; the collision hazard this cell \
         guards has changed shape and the sentinel's justification needs \
         re-reading"
    );
}
