//! #16579: the SESSION_CREATE documentation contract must stay aligned
//! with the #15946/#16303 behaviour (create for every fresh admission,
//! [135] per-policy syslog gate, [148:152] egress ifindex, flowexport
//! consumes the open). These source-text guards fail if the stale
//! pre-#15946 premise ("no flowexport consumer of session opens" /
//! producer-gated / always-set gate byte) is reintroduced into the
//! cited docs or comments. Historical records (docs/log, _Log.md,
//! issue-history) are deliberately NOT scanned — they describe the
//! contract as it was when written.

const README: &str = include_str!("../README.md");
const RT_FLOW_RS: &str = include_str!("../rt_flow.rs");
const CODEC_RT_FLOW_RS: &str = include_str!("../codec/rt_flow.rs");
const WIRE_RS: &str = include_str!("../codec/wire.rs");
const SESSION_DELTA_RS: &str = include_str!("../../afxdp/session_delta.rs");
const INSTALL_RS: &str = include_str!("../../session/install.rs");

const STALE_PHRASES: &[&str] = &[
    "no flowexport consumer",
    "no flow-export consumer",
    "producer-gated",
    "producer gated",
    "only emitted for `log session-init`",
    "only when the admitting policy requested",
    "always sets the gate byte",
    "always set (producer-gated)",
    "leaves the #2749 [144:152] class-of-service block zero",
    "only the session_close frame populates these",
];

#[test]
fn session_create_docs_carry_no_stale_premise_16579() {
    for (name, src) in [
        ("event_stream/README.md", README),
        ("event_stream/rt_flow.rs", RT_FLOW_RS),
        ("event_stream/codec/rt_flow.rs", CODEC_RT_FLOW_RS),
        ("event_stream/codec/wire.rs", WIRE_RS),
        ("afxdp/session_delta.rs", SESSION_DELTA_RS),
        ("session/install.rs", INSTALL_RS),
    ] {
        let lower = src.to_lowercase();
        for phrase in STALE_PHRASES {
            assert!(
                !lower.contains(phrase),
                "{name} reintroduced stale SESSION_CREATE premise {phrase:?} (#16579)"
            );
        }
    }
}

#[test]
fn session_create_docs_state_current_contract_16579() {
    // Positive pins: the corrected contract must actually be stated, so
    // deleting the stale sentence without replacing it also fails.
    assert!(
        README.contains("EVERY fresh admission"),
        "README must state CREATE is emitted for every fresh admission (#16579)"
    );
    assert!(
        README.contains("[148:152]"),
        "README must state the create egress-ifindex slot (#16579)"
    );
    assert!(
        RT_FLOW_RS.contains("every fresh admission"),
        "rt_flow.rs must state the every-fresh-admission contract (#16579)"
    );
    assert!(
        CODEC_RT_FLOW_RS.contains("flowexport-only open"),
        "codec/rt_flow.rs must state the flowexport-only gate-clear case (#16579)"
    );
    assert!(
        WIRE_RS.contains("every\n// fresh admission") || WIRE_RS.contains("every fresh admission"),
        "wire.rs must state the every-fresh-admission contract (#16579)"
    );
}
