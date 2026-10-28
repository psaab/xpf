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
    assert!(resolve.contains("resolve_flow_session_decision_with_conntrack_and_payload_and_ack"));
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

#[test]
fn session_glue_readme_and_commands_doc_match_the_tree_17079() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/session_glue");
    let readme = std::fs::read_to_string(base.join("README.md")).unwrap();
    // Every non-test session_glue/*.rs must appear in the README Files table.
    for entry in std::fs::read_dir(&base).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".rs") || name.contains("tests") {
            continue;
        }
        let needle = format!("`{name}`");
        assert!(readme.contains(&needle), "README Files table omits session_glue/{name}");
    }
    // commands/ handlers are a directory entry, not per-file rows.
    assert!(readme.contains("`commands/`"), "README Files table omits commands/");
    let commands_doc = std::fs::read_to_string(base.join("commands/mod.rs")).unwrap();
    assert!(
        commands_doc.contains("worker_commands.rs"),
        "commands/mod.rs must name worker_commands.rs as the dispatcher home"
    );
    assert!(
        !commands_doc.contains("`session_glue/mod.rs` matches"),
        "commands/mod.rs still claims the dispatcher lives in session_glue/mod.rs"
    );
    let worker = std::fs::read_to_string(base.join("worker_commands.rs")).unwrap();
    assert!(
        worker.contains("pub(in crate::afxdp) fn apply_worker_commands"),
        "apply_worker_commands no longer lives in worker_commands.rs"
    );
}
#[test]
fn session_glue_worker_command_arms_are_extracted_18144() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp/session_glue");
    let commands_dir = base.join("commands");
    let commands_doc = std::fs::read_to_string(commands_dir.join("mod.rs")).unwrap();
    for name in [
        "query_session_counters",
        "list_sessions_by_policy",
        "upsert_local",
        "delete_policy_batch",
        "delete_synced_if_table_unknown",
        "worker_command_helpers",
        "worker_command_drain",
        "worker_command_dispatch",
    ] {
        let source = std::fs::read_to_string(commands_dir.join(format!("{name}.rs")))
            .unwrap_or_else(|e| panic!("commands/{name}.rs: {e}"));
        assert!(
            source.lines().count() <= 200,
            "commands/{name}.rs exceeds the 200-line ceiling"
        );
        assert!(
            commands_doc.contains(&format!("mod {name};")),
            "commands/mod.rs does not register {name}.rs"
        );
    }

    let worker = std::fs::read_to_string(base.join("worker_commands.rs")).unwrap();
    let apply_start = worker
        .find("pub(in crate::afxdp) fn apply_worker_commands")
        .expect("apply_worker_commands remains the public entry point");
    let apply_end = worker[apply_start..]
        .find("/// Dispatch one position-ready transition-debt op")
        .map(|offset| apply_start + offset)
        .expect("apply_worker_commands ends before the debt dispatcher");
    assert!(
        worker[apply_start..apply_end].lines().count() <= 200,
        "apply_worker_commands exceeds the 200-line ceiling"
    );

    let dispatch =
        std::fs::read_to_string(commands_dir.join("worker_command_dispatch.rs")).unwrap();
    let dispatch_lines: Vec<_> = dispatch.lines().collect();
    let arms: Vec<_> = dispatch_lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("            WorkerCommand::"))
        .collect();
    assert!(!arms.is_empty(), "worker command dispatch match is missing");
    for (index, (start, arm)) in arms.iter().enumerate() {
        let end = arms
            .get(index + 1)
            .map(|(next, _)| *next)
            .unwrap_or(dispatch_lines.len());
        assert!(
            end - start <= 15,
            "inline WorkerCommand arm exceeds 15 lines: {arm}"
        );
    }
}
