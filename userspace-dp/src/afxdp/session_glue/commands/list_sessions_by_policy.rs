use super::super::*;

/// Apply `WorkerCommand::ListSessionsByPolicy`: collect this worker's
/// policy-tagged session rows into the shared collector.
///
/// Extracted verbatim from the `apply_worker_commands` dispatcher
/// (#18144); no behaviour change.
pub(in crate::afxdp::session_glue) fn handle_list_sessions_by_policy(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    request: crate::protocol::SessionPolicyListRequest,
    collected: Arc<Mutex<PolicyReadCollector>>,
    overflow: Arc<std::sync::atomic::AtomicBool>,
    errors: Arc<Mutex<Vec<String>>>,
    pending: &std::sync::atomic::AtomicUsize,
) {
    let wanted = |policy_id: u32| {
        policy_id != 0
            && request
                .policy_ids
                .iter()
                .any(|candidate| *candidate == policy_id)
    };
    let family_allowed = |family: u8| {
        request.families.is_empty()
            || request
                .families
                .iter()
                .any(|candidate| *candidate == family)
    };
    let class_allowed = |is_reverse: bool| {
        request.classes.is_empty()
            || request.classes.iter().any(|class| {
                (is_reverse && class == "reverse") || (!is_reverse && class == "forward")
            })
    };
    if request.mode == "legacy" && request.before_secs.is_none() {
        errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push("legacy-before-secs-missing".to_string());
    } else {
        sessions.iter_with_identity(|key, decision, metadata, origin, created_ns, session_id| {
            let family = crate::afxdp::ha::policy_wire_family(key.addr_family);
            if !family_allowed(family) || !class_allowed(metadata.is_reverse) {
                return;
            }
            let Some(policy_id) =
                policy_id_for_list_request(forwarding, metadata, origin, &request.mode)
            else {
                return;
            };
            if !wanted(policy_id) {
                return;
            }
            // Legacy time fence (#6948): keep sessions admitted
            // at or before the activation stamp (old numbering).
            // `Some(0)` is explicitly UNBOUNDED — Go sends the
            // raw activation stamp, and 0 means "boundary
            // unknown" (clear every matching id), never a real
            // timestamp. `None` in legacy mode is a caller bug
            // and is rejected above, not silently unbounded.
            if request.mode == "legacy"
                && request
                    .before_secs
                    .map(|before| before != 0 && created_ns / 1_000_000_000 > before)
                    .unwrap_or(true)
            {
                return;
            }
            if session_id == 0 {
                errors
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(format!("identity-missing:{}:{}", key.src_ip, key.dst_ip));
                return;
            }
            // Shared admission: skip fast past the cap (no
            // lock), else reserve (dedups cross-worker
            // replicas) BEFORE building the row. The build
            // below runs unlocked; only reserve and push take
            // the collector lock.
            if overflow.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            let admitted = collected
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .reserve(overflow.as_ref(), key.clone(), session_id);
            if !admitted {
                return;
            }
            let Some(mut row) = crate::afxdp::ha::policy_match_from_parts(
                key,
                metadata,
                decision.nat,
                session_id,
                created_ns,
            ) else {
                errors
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push("unsupported-address-family".to_string());
                return;
            };
            row.policy_id = policy_id;
            if let Some((companion_key, _, companion_id)) =
                sessions.policy_companion(key, decision.nat)
            {
                if companion_id == 0 {
                    errors
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(format!(
                            "companion-identity-missing:{}:{}",
                            key.src_ip, key.dst_ip
                        ));
                    return;
                }
                row.reverse_key = crate::afxdp::ha::policy_tuple_from_key(&companion_key);
                if row.reverse_key.is_none() {
                    errors
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push("unsupported-companion-family".to_string());
                    return;
                }
                row.expected_companion_rt_flow_session_id = companion_id;
            }
            collected
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(row);
        });
    }
    pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
}
