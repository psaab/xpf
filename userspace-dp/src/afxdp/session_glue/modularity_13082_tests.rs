//! #13082 (D5-15): structural pin — the seven subsystems formerly fused
//! into `session_glue/mod.rs` live in focused sibling modules, and the
//! packet-path resolver no longer shares a file with the control-plane
//! worker-command dispatcher.

#[test]
fn session_glue_is_split_into_focused_sibling_modules() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/session_glue");
    for name in ["resolution.rs", "worker_commands.rs", "revalidation.rs", "tx_cancel.rs", "resolve.rs"] {
        let src = std::fs::read_to_string(base.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(src.lines().count() < 2000, "{name} exceeds file ceiling");
    }
    let root = std::fs::read_to_string(base.join("mod.rs")).unwrap();
    assert!(root.lines().count() < 500, "session_glue/mod.rs remains a monolith");
    let resolve = std::fs::read_to_string(base.join("resolve.rs")).unwrap();
    assert!(resolve.contains("resolve_flow_session_decision_with_conntrack_and_payload"));
    assert!(!resolve.contains("apply_worker_commands"), "packet path still fused with control-plane dispatch");
}

#[test]
fn shared_ops_is_split_into_focused_sibling_modules() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/shared_ops");
    for name in ["mod.rs", "store.rs", "lookup.rs", "reverse_synth.rs"] {
        let src = std::fs::read_to_string(base.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(src.lines().count() < 2000, "shared_ops/{name} exceeds file ceiling");
    }
    let lookup = std::fs::read_to_string(base.join("lookup.rs")).unwrap();
    assert!(lookup.contains("lookup_session_across_scopes_with_shared"));
    let synth = std::fs::read_to_string(base.join("reverse_synth.rs")).unwrap();
    assert!(synth.contains("synthesize") || synth.contains("build_reverse_session_from_forward_match"));
}
