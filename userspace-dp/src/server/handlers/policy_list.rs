use crate::protocol::{ControlResponse, SessionPolicyListRequest};
use crate::afxdp::SessionDomain;

/// #10512: read-only policy invalidation discovery. The request is handled on
/// the session socket without taking ServerState; callers perform deletes in a
/// later phase after the config publication boundary.
pub(super) fn handle(
    domain: &SessionDomain,
    request: Option<SessionPolicyListRequest>,
    response: &mut ControlResponse,
) {
    let Some(request) = request else {
        response.ok = false;
        response.error = "missing session policy list request".to_string();
        return;
    };
    let (matches, complete, errors, continuation) = domain.list_sessions_by_policy(&request);
    response.session_policy_matches = matches;
    response.session_policy_complete = complete;
    response.session_policy_continuation = continuation;
    response.session_policy_per_worker_errors = errors;
}
