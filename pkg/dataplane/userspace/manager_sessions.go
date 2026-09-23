package userspace

// Session-table mutation entry points for the userspace dataplane: the
// dataplane.DataPlane install/delete/batch/clear verbs, the #5305
// transactional cluster-synced install (BPF pre-image snapshot + rollback on
// mirror failure), the chunked authoritative helper deletes, and the bulk
// event-stream session export. Each writes the BPF mirror and mirrors the
// change to the authoritative Rust helper.

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
)

const (
	// Helper pages stay below the control-response cap, while Go retains at
	// most four pages for one commit-time invalidation capture.
	policyReadPageMatchCap = 65536
	policyReadMatchCap     = 262144
	policyReadByteCap      = 48 * 1024 * 1024
	policyReadDeadline     = 30 * time.Second
	policyDeleteDeadline   = 30 * time.Second
	// Plan §2.4 micro-batch caps: the helper acquires all of one batch's
	// gate keys together, so Go packs forward matches and their captured
	// companions under both ceilings.
	policyDeleteBatchMatches = 64
	policyDeleteBatchKeys    = 128
	// Consecutive helper-determined batch failures before the driver stops
	// issuing batches: sustained systemic failure (contention, overload)
	// fails fast instead of burning the deadline batch by batch. Isolated
	// failures (one corrupt batch among clean ones) continue past.
	policyDeleteSemanticBreaker = 3
)
// ListSessionsByPolicy performs the #10512 READ phase against the helper-owned
// session authority. It deliberately uses the control socket: this request is
// the commit-time discovery boundary and must not be accepted on the dedicated
// session socket, whose allowlist is limited to sync_session/ping/HA refresh.
// Continuation pages share one absolute 30-second capture deadline. A complete
// response with no continuation is the only authoritative result.
func (m *Manager) ListSessionsByPolicy(req SessionPolicyListRequest) (ControlResponse, error) {
	deadline := time.Now().Add(policyReadDeadline)
	pageReq := req
	seenContinuations := map[string]struct{}{}
	var aggregate ControlResponse
	aggregate.OK = true
	for {
		if time.Now().After(deadline) {
			return ControlResponse{}, fmt.Errorf("policy session READ deadline exceeded after %s", policyReadDeadline)
		}
		m.mu.Lock()
		page, err := m.requestDetailedLocked(ControlRequest{
			Type:              "list_sessions_by_policy",
			SuppressStatus:    true,
			SessionPolicyList: &pageReq,
		})
		m.mu.Unlock()
		if time.Now().After(deadline) {
			return ControlResponse{}, fmt.Errorf("policy session READ deadline exceeded after %s", policyReadDeadline)
		}
		if err != nil {
			return ControlResponse{}, err
		}
		if len(page.SessionPolicyMatches) > policyReadPageMatchCap {
			return ControlResponse{}, fmt.Errorf(
				"policy session READ page exceeds %d matches", policyReadPageMatchCap)
		}
		if len(page.SessionPolicyMatches) != 0 {
			encoded, err := json.Marshal(page.SessionPolicyMatches)
			if err != nil {
				return ControlResponse{}, fmt.Errorf("policy session READ page encode: %w", err)
			}
			if len(encoded) > policyReadByteCap {
				return ControlResponse{}, fmt.Errorf(
					"policy session READ page exceeds %d encoded bytes", policyReadByteCap)
			}
		}
		if len(aggregate.SessionPolicyMatches)+len(page.SessionPolicyMatches) > policyReadMatchCap {
			return ControlResponse{}, fmt.Errorf(
				"policy session READ exceeds %d matches", policyReadMatchCap)
		}
		aggregate.SessionPolicyMatches = append(
			aggregate.SessionPolicyMatches, page.SessionPolicyMatches...)
		aggregate.SessionPolicyPerWorkerErrors = append(
			aggregate.SessionPolicyPerWorkerErrors, page.SessionPolicyPerWorkerErrors...)
		if page.SessionPolicyContinuation == "" {
			if !page.SessionPolicyComplete {
				return ControlResponse{}, fmt.Errorf(
					"policy session READ incomplete without continuation")
			}
			aggregate.SessionPolicyComplete = true
			return aggregate, nil
		}
		if _, duplicate := seenContinuations[page.SessionPolicyContinuation]; duplicate {
			return ControlResponse{}, fmt.Errorf(
				"policy session READ repeated continuation token")
		}
		seenContinuations[page.SessionPolicyContinuation] = struct{}{}
		pageReq.Continuation = page.SessionPolicyContinuation
	}
	}

// PolicyDeleteResult records helper outcomes for one policy READ capture.
// Stale rows are successful conditional no-ops; partial companion outcomes
// remove the forward row but retain a replacement companion and therefore
// remain visible to the caller.
type PolicyDeleteResult struct {
	Applied int
	Stale   int
	Partial int
}

// DeletePolicySessions performs helper-first, identity-conditional deletes for
// the matches returned by ListSessionsByPolicy. The helper owns both the
// authoritative table and the bare-key mirror repair; this method never uses a
// Go-side mirror delete that could destroy a colliding survivor.
//
// Plan §2.4 micro-batches: at most 64 matches and 128 gate keys (forward plus
// captured companion) per helper round trip, so a full 262144-match capture
// costs at most 4096 round trips — never one per match. Batches share one
// absolute 30-second delete deadline; at the deadline, on a batch transport
// failure, or on an incomplete batch answer, it stops issuing new batches and
// returns the partial counts with an error. The remainder is a SURFACED
// PERSISTENT GAP, not a retryable backlog: the commit already activated the
// new config, so no recommit re-captures these matches (§2.4: no cross-commit
// retention) — the survivors forward until idle timeout unless the operator
// clears sessions or recommits an touching change. Callers join the error
// into the commit result (#5578) rather than reporting success.
func (m *Manager) DeletePolicySessions(matches []SessionPolicyMatch) (PolicyDeleteResult, error) {
	var result PolicyDeleteResult
	if len(matches) == 0 {
		return result, nil
	}
	for _, match := range matches {
		if match.ExpectedRTFlowSessionID == 0 {
			return result, fmt.Errorf("policy session delete: identity-missing")
		}
		if match.ExpectedCompanionRTFlowSessionID != 0 && match.ReverseKey == nil {
			return result, fmt.Errorf("policy session delete: companion-identity-missing")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return result, errSessionHelperUnreachable
	}
	startProcGen := m.procGen
	deadline := time.Now().Add(policyDeleteDeadline)
	var firstErr error
	confirmed := 0
	consecutiveSemantic := 0
	for start := 0; start < len(matches); {
		if time.Now().After(deadline) {
			return result, policyDeleteGapError(
				fmt.Errorf("deadline exceeded after %s", policyDeleteDeadline),
				result, confirmed, len(matches))
		}
		if m.proc == nil || m.procGen != startProcGen {
			// Helper churned mid-invalidation (crash/restart/upgrade): the
			// capture predates the new incarnation, whose rebuilt tables may
			// carry reminted identities. Never evaluate a stale capture
			// against fresh tables — gap loud and let a touching recommit
			// re-capture (precedent: owner_rg_export_paging_9344 procGen fence).
			return result, policyDeleteGapError(
				fmt.Errorf("helper churned mid-invalidation (procGen %d -> %d)", startProcGen, m.procGen),
				result, confirmed, len(matches))
		}
		end := start + policyDeleteBatchMatches
		if end > len(matches) {
			end = len(matches)
		}
		// Shrink to the 128 gate-key cap: each match costs its forward key
		// plus its captured companion when one is expected.
		for end > start && policyDeleteBatchKeysOf(matches[start:end]) > policyDeleteBatchKeys {
			end--
		}
		batch := matches[start:end]
		req := SessionSyncRequest{
			Operation:     "mirror_delete_policy_batch",
			PolicyMatches: batch,
			// Stable content identity across attempts and epochs: retries
			// and restarts reconcile the SAME logical batch instead of
			// minting a new one per attempt. OperationID stays per attempt
			// (stamped once below and reused by the transport retry).
			MutationID: policyDeleteBatchMutationID(batch),
		}
		// Stamp once so the transport retry below reuses identical
		// identities (the send path only fills empty fields).
		m.stampSessionMutationLocked(&req)
		resp, err := m.syncSessionRequestResponseLocked(req)
		if err != nil && errors.Is(err, errSessionHelperUnreachable) {
			// Fence the retry: the send dropped m.mu, so the helper may have
			// churned (crash/restart) during I/O. Never resend a pre-churn
			// capture against rebuilt tables (reminted identities would
			// all-stale-count a live revocation), and never hand a fresh
			// helper generation a pre-churn request at all.
			if m.proc == nil || m.procGen != startProcGen {
				return result, policyDeleteGapError(
					fmt.Errorf("helper churned during batch send (procGen %d -> %d)", startProcGen, m.procGen),
					result, confirmed, len(matches))
			}
			// Transport-unknown outcome (lost request/response, slow
			// helper): resend ONCE with identical identities — the helper
			// replays the recorded outcome if it executed, or executes
			// first-time if the request never arrived (exactly-once per
			// attempt pair).
			resp, err = m.syncSessionRequestResponseLocked(req)
		}
		if err != nil {
			if errors.Is(err, errSessionHelperUnreachable) {
				// Helper down/hung (both attempts failed transport): #5380
				// fast-fail — stop issuing batches rather than burning the
				// deadline on a dead helper.
				return result, policyDeleteGapError(err, result, confirmed, len(matches))
			}
			// Semantic determination (helper refused/failed this batch):
			// record and CONTINUE — other batches carry different content
			// and may succeed (revocation-maximizing). The breaker below
			// stops sustained systemic failure fast.
			if firstErr == nil {
				firstErr = err
			}
			consecutiveSemantic++
			if consecutiveSemantic >= policyDeleteSemanticBreaker {
				return result, policyDeleteGapError(firstErr, result, confirmed, len(matches))
			}
			start = end
			continue
		}
		if len(resp.PolicyDeleteOutcomes) != len(batch) || !resp.PolicyDeleteComplete {
			// Contract breach (not a determination): the helper answered OK
			// with an unusable batch result. Every batch would breach
			// identically (same helper version) — stop fast.
			return result, policyDeleteGapError(
				fmt.Errorf("incomplete batch answer (%d outcomes for %d matches, complete=%v, errors=%v)",
					len(resp.PolicyDeleteOutcomes), len(batch),
					resp.PolicyDeleteComplete, resp.PolicyDeleteErrors),
				result, confirmed, len(matches))
		}
		for _, outcome := range resp.PolicyDeleteOutcomes {
			switch outcome {
			case "applied":
				result.Applied++
			case "stale_forward", "refused_identity":
				// Nothing removed; the live state differs from the capture.
				// Refused (capture stale about the companion) and stale
				// (forward gone or replaced) both mean "no-op, session live
				// under a different incarnation".
				result.Stale++
			case "partial_companion":
				result.Applied++
				result.Partial++
			default:
				// Unknown token (helper newer than Go): contract breach — stop.
				return result, policyDeleteGapError(
					fmt.Errorf("unknown batch outcome %q", outcome),
					result, confirmed, len(matches))
			}
		}
		confirmed += len(batch)
		consecutiveSemantic = 0
		start = end
	}
	if firstErr != nil {
		return result, policyDeleteGapError(firstErr, result, confirmed, len(matches))
	}
	if result.Partial != 0 {
		return result, fmt.Errorf(
			"policy session delete: %d partial companion outcome(s)", result.Partial)
	}
	return result, nil
}

// policyDeleteGapError reports a partial policy invalidation as the persistent
// gap it is: `confirmed` counts only fully-resolved batches (a later success
// never jumps over an earlier failed range), and every unconfirmed match will
// NOT be re-captured by a recommit (the config is already active). Survivors
// among them persist until idle timeout. Loud by construction (#5578).
func policyDeleteGapError(err error, result PolicyDeleteResult, confirmed, total int) error {
	return fmt.Errorf(
		"policy session delete INCOMPLETE: %v (applied %d, stale %d, partial %d of %d matches, %d without confirmed outcomes; "+
			"survivors persist until idle timeout — recommit does not re-capture; "+
			"clear sessions or recommit an touching change to force)",
		err, result.Applied, result.Stale, result.Partial, total, total-confirmed)
}

// policyDeleteBatchFallback numbers the unreachable digest fallback below.
var policyDeleteBatchFallback atomic.Uint64

// policyDeleteBatchMutationID derives the batch's stable content identity: the
// ordered matches hashed (FNV-1a over the canonical JSON encoding — field
// order fixed, no maps — so future fields join automatically) and hex-encoded.
// Same batch content in the same order (any attempt, any epoch) yields the
// same mutation ID, so the helper reconciles retries, re-sends, and restarts
// instead of treating every attempt as a new logical batch. The "pb:" prefix
// distinguishes batch digests from tuple mutations and op-derived fallbacks.
func policyDeleteBatchMutationID(batch []SessionPolicyMatch) string {
	encoded, err := json.Marshal(batch)
	if err != nil {
		// Unreachable for this struct shape (no maps/channels/functions);
		// unique-per-call preserves correctness (no false reconcile).
		return "pb:unencodable-" + strconv.FormatUint(policyDeleteBatchFallback.Add(1), 10)
	}
	sum := fnv.New64a()
	sum.Write(encoded)
	return "pb:" + strconv.FormatUint(sum.Sum64(), 16)
}

// policyDeleteBatchKeysOf counts the gate keys one micro-batch would acquire:
// each match's forward key plus its captured companion when one is expected.
func policyDeleteBatchKeysOf(batch []SessionPolicyMatch) int {
	keys := 0
	for _, match := range batch {
		keys++
		if match.ReverseKey != nil {
			keys++
		}
	}
	return keys
}

// ExportAllSessionsViaEventStream tells the Rust helper to push all current
// sessions through the event stream as Open events. The Go daemon receives
// them via handleEventStreamDelta and queues them to the peer automatically.
// This replaces the old BulkSync path that iterated BPF maps from Go.
func (m *Manager) ExportAllSessionsViaEventStream() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return errors.New("userspace dataplane helper not running")
	}
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "export_all_sessions"}, &status); err != nil {
		return err
	}
	return m.applyHelperStatusLocked(&status)
}

func (m *Manager) SetSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return errSessionHelperUnreachable
	}
	op := "mirror_upsert"
	if val.IsReverse != 0 {
		op = "mirror_publish_only"
	}
	if err := m.syncSessionV4Locked(op, key, &val); err != nil {
		m.noteSyncedMirrorFailureLocked(err)
		return fmt.Errorf("mirror v4 session to userspace helper: %w", err)
	}
	m.recordSessionMirrorSuccessLocked()
	return nil
}

// mirrorSessionV4 mirrors a locally installed forward session to the Rust
// helper. ONE upsert, not two (#8015).
//
// It used to send the forward AND an explicitly built `is_reverse=1` companion
// (#310, "the Rust worker must have the companion before RG activation"). That
// second request was redundant: `upsert_synced_session`
// (`userspace-dp/src/afxdp/ha/session_import.rs`) calls
// `synthesized_synced_reverse_entry` for EVERY non-reverse import — a total
// function, `Some` on every forward — and publishes both halves through
// `publish_shared_session`, which is why the #5674 aggregate ENTRY cap is sized
// at 2x the logical session ceiling. So a single forward upsert already leaves
// a complete pair, and it leaves a BETTER one: the helper resolves the
// companion's egress/FIB, fabric/tunnel and owner-RG against live node-local
// state, where this side could only copy the forward's (#5698). Synthesis also
// happens AT IMPORT, which is strictly earlier than this pre-install, so #310's
// invariant is satisfied by the request that remains.
//
// What the second request added was a failure mode. If the helper REFUSED the
// forward (a semantic refusal such as `RejectedCapacity`, not a transport
// failure — those abort the batch) the explicit reverse still went out and
// published alone: a reverse-only entry with no forward, which no later forward
// delete removes because `delete_synced_session_gen` derives the companion from
// the STORED forward and there is none. Sending one request removes that state
// rather than reporting it; the helper additionally REFUSES a standalone
// `is_reverse=1` upsert now, so the shape cannot be reintroduced from any
// sender.
//
// With one request the #5007 single-snapshot build and the #5698 contiguous
// transmit are both vacuous — there is no second half to resolve against a
// different `m.lastSnapshot` or to be interleaved away from — so this takes the
// ordinary per-request path. The mirror stays best-effort: the IPC error is
// dropped because the periodic session sync reconciles a transient miss, and a
// single request can no longer half-apply.
func (m *Manager) mirrorSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return
	}
	op := "mirror_upsert"
	if val.IsReverse != 0 {
		op = "mirror_publish_only"
	}
	_ = m.syncSessionV4Locked(op, key, &val)
}

func (m *Manager) SetClusterSyncedSessionV4(key dataplane.SessionKey, val dataplane.SessionValue) error {
	installVal := val
	installVal.ScrubNodeLocal()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return errSessionHelperUnreachable
	}
	op := "mirror_upsert"
	if val.IsReverse != 0 {
		op = "mirror_publish_only"
	}
	if err := m.syncSessionV4Locked(op, key, &installVal); err != nil {
		m.noteSyncedMirrorFailureLocked(err)
		return fmt.Errorf("mirror synced v4 session to userspace helper: %w", err)
	}
	m.recordSessionMirrorSuccessLocked()
	return nil
}


func (m *Manager) SetSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return errSessionHelperUnreachable
	}
	op := "mirror_upsert"
	if val.IsReverse != 0 {
		op = "mirror_publish_only"
	}
	if err := m.syncSessionV6Locked(op, key, &val); err != nil {
		m.noteSyncedMirrorFailureLocked(err)
		return fmt.Errorf("mirror v6 session to userspace helper: %w", err)
	}
	m.recordSessionMirrorSuccessLocked()
	return nil
}

func (m *Manager) SetClusterSyncedSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) error {
	installVal := val
	installVal.ScrubNodeLocal()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return errSessionHelperUnreachable
	}
	op := "mirror_upsert"
	if val.IsReverse != 0 {
		op = "mirror_publish_only"
	}
	if err := m.syncSessionV6Locked(op, key, &installVal); err != nil {
		m.noteSyncedMirrorFailureLocked(err)
		return fmt.Errorf("mirror synced v6 session to userspace helper: %w", err)
	}
	m.recordSessionMirrorSuccessLocked()
	return nil
}

func bpfSessionReadAbsent(err error) bool {
	return dataplane.IsKeyNotFound(err)
}

// mirrorSessionV6 is retained as a narrow test seam for helper-first mirroring.
func (m *Manager) mirrorSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return
	}
	op := "mirror_upsert"
	if val.IsReverse != 0 {
		op = "mirror_publish_only"
	}
	_ = m.syncSessionV6Locked(op, key, &val)
}


func shouldMirrorUserspaceSession(isReverse uint8) bool {
	return isReverse == 0
}

// deleteScopeVal returns the minimal SessionValue that carries ONLY a routing
// domain onto a "delete" sync request, or nil when there is no domain to name.
//
// #9146: a delete built with a nil value carries routing_domain 0, which the
// helper reads as WIRE_ABSENT and resolves by PROBING every routing instance for
// the bare 5-tuple. When two tenants hold that tuple the probe is ambiguous and
// the helper REFUSES the delete (#8636). Naming the domain the session was
// installed under makes the exact delete land, so the probe never runs.
//
// It is deliberately minimal rather than the whole value: a delete needs the key
// and the domain, and forwarding a full value would put zone/NAT/ifindex fields
// on a request that has no use for them.
func deleteScopeVal(routingDomain uint32) *dataplane.SessionValue {
	if routingDomain == 0 {
		return nil
	}
	return &dataplane.SessionValue{RoutingDomain: routingDomain}
}

// deleteScopeValV6 is the IPv6 analogue of deleteScopeVal (#9146/#9364).
//
// #9146 wrote its V6 scope inline in syncDeleteV6Locked; #9364 needs the same
// derivation from a second call site, and two copies of "nil at 0, else a
// domain-only value" is the drift the one-formula rule exists to prevent.
func deleteScopeValV6(routingDomain uint32) *dataplane.SessionValueV6 {
	if routingDomain == 0 {
		return nil
	}
	return &dataplane.SessionValueV6{RoutingDomain: routingDomain}
}

// scopedWireDomain encodes a scoped-delete domain for the HA wire (#10512):
// the scoped verb always STATES its domain (never absent), so domain 0
// rides as Rust's WIRE_DEFAULT_INSTANCE marker (1, DEFAULT stated) rather
// than 0 (ABSENT, derive/probe — which could probe another tenant's row
// on a collision). Nonzero domains ride raw.
func scopedWireDomain(domain uint32) uint32 {
	if domain == 0 {
		return 1
	}
	return domain
}

func (m *Manager) DeleteSession(key dataplane.SessionKey) error {
	// Read the value BEFORE asking the helper to delete so the request names the
	// session's routing domain and can also delete its pre-installed reverse
	// companion (#9146).
	val, valErr := m.bpfShim.GetSessionV4(key)

	// The Rust helper owns forwarding state; the BPF map is only its read model.
	m.mu.Lock()
	if m.proc == nil || m.proc.Process == nil {
		m.mu.Unlock()
		return errSessionHelperUnreachable
	}
	err := m.syncDeleteV4Locked(key, val, valErr == nil)
	m.mu.Unlock()
	if err != nil {
		return fmt.Errorf("delete v4 session from userspace helper: %w", err)
	}
	return nil
}

// syncDeleteV4Locked sends the helper deletes for a removed v4 session: the
// forward key, and the reverse companion SetSessionV4 pre-installed. Both name
// the session's routing domain when one is known.
//
// It is a named function rather than four lines inside DeleteSession so the
// scope derivation can be driven by a cell. DeleteSession itself reads and
// writes real BPF maps, so a cell for it skips wherever CAP_BPF is unavailable —
// and a skipping cell scores a mutation as survived, which is the reading that
// argues for deleting a guard doing its job.
func (m *Manager) syncDeleteV4Locked(key dataplane.SessionKey, val dataplane.SessionValue, haveVal bool) error {
	if m.proc == nil {
		return nil
	}
	scope := (*dataplane.SessionValue)(nil)
	if haveVal {
		scope = deleteScopeVal(val.RoutingDomain)
	}
	req := m.buildSessionSyncRequestV4("mirror_delete", key, scope)
	if err := m.syncSessionRequestLocked(req); err != nil {
		return err
	}
	return nil
}


// syncDeleteV4LockedMarked is syncDeleteV4Locked with the #9714 peer mark set on
// both helper requests (the key and its reverse companion). It reports whether the
// helper REFUSED the marked delete of the key; a refused key keeps its reverse
// companion, so that request is not sent.
func (m *Manager) syncDeleteV4LockedMarkedErr(key dataplane.SessionKey, val dataplane.SessionValue, haveVal, peer, forwardOnly bool) (bool, error) {
	if m.proc == nil {
		return false, errSessionHelperUnreachable
	}
	scope := (*dataplane.SessionValue)(nil)
	if haveVal {
		scope = deleteScopeVal(val.RoutingDomain)
	}
	req := m.buildSessionSyncRequestV4("mirror_delete", key, scope)
	req.PeerDelete = peer
	req.ForwardOnly = forwardOnly
	err := m.syncSessionRequestLocked(req)
	if err != nil {
		if peer && peerDeleteRefused(err) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (m *Manager) syncDeleteV4LockedMarked(key dataplane.SessionKey, val dataplane.SessionValue, haveVal, peer, forwardOnly bool) bool {
	refused, _ := m.syncDeleteV4LockedMarkedErr(key, val, haveVal, peer, forwardOnly)
	return refused
}

func (m *Manager) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	// See DeleteSession: retain the mirror until the authoritative helper
	// deletion succeeds, so a transient IPC failure remains retryable.
	val, valErr := m.bpfShim.GetSessionV6(key)
	m.mu.Lock()
	if m.proc == nil || m.proc.Process == nil {
		m.mu.Unlock()
		return errSessionHelperUnreachable
	}
	err := m.syncDeleteV6Locked(key, val, valErr == nil)
	m.mu.Unlock()
	if err != nil {
		return fmt.Errorf("delete v6 session from userspace helper: %w", err)
	}
	return nil
}

// syncDeleteV6Locked is the IPv6 analogue of syncDeleteV4Locked (#9146).
func (m *Manager) syncDeleteV6Locked(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, haveVal bool) error {
	if m.proc == nil {
		return nil
	}
	scope := (*dataplane.SessionValueV6)(nil)
	if haveVal {
		scope = deleteScopeValV6(val.RoutingDomain)
	}
	req := m.buildSessionSyncRequestV6("mirror_delete", key, scope)
	if err := m.syncSessionRequestLocked(req); err != nil {
		return err
	}
	return nil
}


// syncDeleteV6LockedMarked is the IPv6 analogue of syncDeleteV4LockedMarked (#9714).
func (m *Manager) syncDeleteV6LockedMarkedErr(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, haveVal, peer, forwardOnly bool) (bool, error) {
	if m.proc == nil {
		return false, errSessionHelperUnreachable
	}
	scope := (*dataplane.SessionValueV6)(nil)
	if haveVal {
		scope = deleteScopeValV6(val.RoutingDomain)
	}
	req := m.buildSessionSyncRequestV6("mirror_delete", key, scope)
	req.PeerDelete = peer
	req.ForwardOnly = forwardOnly
	err := m.syncSessionRequestLocked(req)
	if err != nil {
		if peer && peerDeleteRefused(err) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (m *Manager) syncDeleteV6LockedMarked(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, haveVal, peer, forwardOnly bool) bool {
	refused, _ := m.syncDeleteV6LockedMarkedErr(key, val, haveVal, peer, forwardOnly)
	return refused
}

// DeletePeerSyncedSession deletes a session on behalf of the PEER (#9714). The
// helper answers FIRST, marked so it can refuse the delete for a live local session
// whose owner RG is locally active; a refused delete keeps the BPF mirror row and
// reports true. The mirror row may already be gone (the store calls this when its
// lookup found nothing), and the helper is asked all the same: before this, the
// failed mirror delete returned before the helper was contacted, so a helper-only
// stale session was never retracted.
func (m *Manager) DeletePeerSyncedSession(key dataplane.SessionKey, forwardOnly bool) (bool, error) {
	val, valErr := m.bpfShim.GetSessionV4(key)
	m.mu.Lock()
	if m.proc == nil || m.proc.Process == nil {
		m.mu.Unlock()
		return false, errSessionHelperUnreachable
	}
	defer m.mu.Unlock()
	refused, err := m.syncDeleteV4LockedMarkedErr(key, val, valErr == nil, true, forwardOnly)
	if err != nil {
		return false, err
	}
	if refused {
		return true, nil
	}
	return false, nil
}

// DeletePeerSyncedSessionScoped deletes the session row carrying the
// expected RT_FLOW identity on behalf of the PEER (#10512). The helper
// answers FIRST with the explicit domain + identity (no local mirror
// probe gates it — a probe could misattribute a colliding tuple); it
// deletes only the matching incarnation and refuses otherwise (keeping
// rows, reporting true). Scope comes from the wire (authoritative).
func (m *Manager) DeletePeerSyncedSessionScoped(key dataplane.SessionKey, domain uint32, expectedID uint64) (bool, error) {
	m.mu.Lock()
	if m.proc == nil || m.proc.Process == nil {
		m.mu.Unlock()
		return false, errSessionHelperUnreachable
	}
	defer m.mu.Unlock()
	refused, err := m.syncDeleteScopedV4Locked(key, domain, expectedID)
	if err != nil {
		return false, err
	}
	if refused {
		return true, nil
	}
	return false, nil
}

// syncDeleteScopedV4Locked issues one identity-conditional peer delete
// (#10512) via the distinct mirror_delete_scoped verb with req.session_id
// = the expected originator identity (NOT the local mirror's id) and
// scope from the wire domain (NOT a local probe, which could name another
// tenant's row). A distinct verb, not a mirror_delete flag: the builder
// already stamps session_id from local values on every request, so
// presence-gating would condition all peer deletes on the wrong id.
// ForwardOnly false: the peer derives its own reverse.
func (m *Manager) syncDeleteScopedV4Locked(key dataplane.SessionKey, domain uint32, expectedID uint64) (bool, error) {
	if m.proc == nil {
		return false, errSessionHelperUnreachable
	}
	req := m.buildSessionSyncRequestV4("mirror_delete_scoped", key, deleteScopeVal(domain))
	req.PeerDelete = true
	req.RTFlowSessionID = expectedID
	req.RoutingDomain = scopedWireDomain(domain)
	err := m.syncSessionRequestLocked(req)
	if err != nil {
		if peerDeleteRefused(err) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// DeletePeerSyncedSessionV6 is the IPv6 analogue of DeletePeerSyncedSession (#9714).
func (m *Manager) DeletePeerSyncedSessionV6(key dataplane.SessionKeyV6, forwardOnly bool) (bool, error) {
	val, valErr := m.bpfShim.GetSessionV6(key)
	m.mu.Lock()
	if m.proc == nil || m.proc.Process == nil {
		m.mu.Unlock()
		return false, errSessionHelperUnreachable
	}
	defer m.mu.Unlock()
	refused, err := m.syncDeleteV6LockedMarkedErr(key, val, valErr == nil, true, forwardOnly)
	if err != nil {
		return false, err
	}
	if refused {
		return true, nil
	}
	return false, nil
}

// DeletePeerSyncedSessionScopedV6 is the IPv6 analogue of DeletePeerSyncedSessionScoped (#10512).
func (m *Manager) DeletePeerSyncedSessionScopedV6(key dataplane.SessionKeyV6, domain uint32, expectedID uint64) (bool, error) {
	m.mu.Lock()
	if m.proc == nil || m.proc.Process == nil {
		m.mu.Unlock()
		return false, errSessionHelperUnreachable
	}
	defer m.mu.Unlock()
	refused, err := m.syncDeleteScopedV6Locked(key, domain, expectedID)
	if err != nil {
		return false, err
	}
	if refused {
		return true, nil
	}
	return false, nil
}

// syncDeleteScopedV6Locked is the IPv6 analogue of syncDeleteScopedV4Locked (#10512).
func (m *Manager) syncDeleteScopedV6Locked(key dataplane.SessionKeyV6, domain uint32, expectedID uint64) (bool, error) {
	if m.proc == nil {
		return false, errSessionHelperUnreachable
	}
	req := m.buildSessionSyncRequestV6("mirror_delete_scoped", key, deleteScopeValV6(domain))
	req.PeerDelete = true
	req.RTFlowSessionID = expectedID
	req.RoutingDomain = scopedWireDomain(domain)
	err := m.syncSessionRequestLocked(req)
	if err != nil {
		if peerDeleteRefused(err) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// sessionHelperDeleteChunk bounds how many per-session helper "delete" IPCs the
// batch/clear session paths transmit under a single control-socket unlock so a
// large clear stays cooperative and cannot monopolize the shared control socket
// (#5096). syncSessionRequestsLocked drops and reacquires m.mu once per chunk,
// giving a concurrent snapshot publish a window between chunks, and takes
// m.sessionMu once per REQUEST so live session installs can interleave INSIDE a
// chunk. A chunk this large deliberately stays interleavable: holding
// m.sessionMu across 256 round trips would starve live session installs for
// minutes (#5380).
const sessionHelperDeleteChunk = 256

// BatchDeleteSessions deletes a batch of IPv4 sessions from the BPF mirror AND
// issues an authoritative "delete" to the Rust helper for every key (#5096).
//
// The LegacyDataPlaneAdapter embeds the bpfShim as its dataplane.DataPlane, so
// without this method Go promotion would dispatch a batch delete to the mirror
func (m *Manager) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	scoped := make([]dataplane.ScopedSessionKey, 0, len(keys))
	for _, key := range keys {
		scoped = append(scoped, dataplane.ScopedSessionKey{Key: key})
	}
	var applied []dataplane.ScopedSessionKey
	if err := m.deleteHelperSessionsScopedV4Marked(scoped, false, false, nil, &applied); err != nil {
		return len(applied), err
	}
	return len(applied), nil
}

// BatchDeleteSessionsScoped is the #9364 domain-carrying batch delete.
//
// The BPF mirror has no domain axis (#7160), so it takes the bare keys exactly as
// before; the domain matters only on the HELPER wire, where a bare 5-tuple is
// resolved by probing every routing instance and REFUSED when two tenants match
// (#8636). The domain-carrying path is used by conntrack GC and commit-time
// policy invalidation; it now also surfaces helper failures so an authoritative
// row left behind by the BPF-first order cannot masquerade as a clean delete
// (#10513, #5578).
func (m *Manager) BatchDeleteSessionsScoped(scoped []dataplane.ScopedSessionKey) (int, error) {
	var applied []dataplane.ScopedSessionKey
	if helperErr := m.deleteHelperSessionsScopedV4Marked(scoped, false, false, nil, &applied); helperErr != nil {
		return len(applied), surfaceScopedHelperDeleteError("v4", helperErr)
	}
	return len(applied), nil
}

// BatchDeleteSessionsScopedV6 is the IPv6 analogue (#9364).
func (m *Manager) BatchDeleteSessionsScopedV6(scoped []dataplane.ScopedSessionKeyV6) (int, error) {
	var applied []dataplane.ScopedSessionKeyV6
	if helperErr := m.deleteHelperSessionsScopedV6Marked(scoped, false, false, nil, &applied); helperErr != nil {
		return len(applied), surfaceScopedHelperDeleteError("v6", helperErr)
	}
	return len(applied), nil
}

// surfaceScopedHelperDeleteError preserves the helper classification at the
// scoped batch boundary without exposing a transport cause such as unix.ENOENT
// to errors.Is. The session-store batch treats ENOENT as an ordinary mirror
// not-found and retries per key; if the helper dial's ENOENT crosses that
// boundary, the retry loop discards the helper error and reports success
// (#10513). Keep the detailed cause in the message while unwrapping only the
// stable helper-unreachable sentinel. Application-level helper refusals retain
// their original error for callers that need the response text.
func surfaceScopedHelperDeleteError(family string, err error) error {
	if errors.Is(err, errSessionHelperUnreachable) {
		return fmt.Errorf("delete %s sessions from userspace helper: %w (%v)",
			family, errSessionHelperUnreachable, err)
	}
	return fmt.Errorf("delete %s sessions from userspace helper: %w", family, err)
}

// peerDeleteRefusedLocalOwned is the helper's in-band answer to a #9714 peer delete
// it refused: SYNCED_DELETE_REFUSED_PREFIX plus the reason
// (userspace-dp/src/server/handlers/sync_session.rs).
const peerDeleteRefusedLocalOwned = "synced-delete-refused:peer-delete-local-owned"

// peerDeleteRefused reports whether err is the helper's refusal of a peer delete.
// requestSessionSyncLocked returns an in-band answer verbatim and wraps every
// transport failure as errSessionHelperUnreachable, so a transport error never
// reads as a refusal.
func peerDeleteRefused(err error) bool {
	return err != nil && err.Error() == peerDeleteRefusedLocalOwned
}

// BatchDeletePeerSyncedSessionsScoped is BatchDeleteSessionsScoped for deletes made
// on behalf of the PEER (#9714). The helper answers FIRST: every request is marked
// PeerDelete, and a key the helper refuses (a live local session whose owner RG is
// locally active) is returned in refused and keeps its BPF mirror row. The other
// keys' mirror rows go one at a time, so a row already gone does not strand the
// rest. The peer-marked helper IPC error remains best-effort because the refused
// and applied sets explicitly protect every mirror row whose outcome is known;
// unlike the unmarked scoped batch, this path has a distinct #9714 contract.
func (m *Manager) BatchDeletePeerSyncedSessionsScoped(scoped []dataplane.ScopedSessionKey, forwardOnly bool) (int, []dataplane.ScopedSessionKey, error) {
	var refused, applied []dataplane.ScopedSessionKey
	err := m.deleteHelperSessionsScopedV4Marked(scoped, true, forwardOnly, &refused, &applied)
	if err != nil {
		return len(applied), refused, err
	}
	return len(applied), refused, nil
}

// BatchDeletePeerSyncedSessionsScopedV6 is the IPv6 analogue (#9714).
func (m *Manager) BatchDeletePeerSyncedSessionsScopedV6(scoped []dataplane.ScopedSessionKeyV6, forwardOnly bool) (int, []dataplane.ScopedSessionKeyV6, error) {
	var refused, applied []dataplane.ScopedSessionKeyV6
	err := m.deleteHelperSessionsScopedV6Marked(scoped, true, forwardOnly, &refused, &applied)
	if err != nil {
		return len(applied), refused, err
	}
	return len(applied), refused, nil
}

func deleteAppliedMirrorRows[K comparable](applied []K, del func(K) error) (int, error) {
	deleted := 0
	var firstErr error
	for _, key := range applied {
		if err := del(key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		deleted++
	}
	return deleted, firstErr
}

func bareKeysV4(scoped []dataplane.ScopedSessionKey) []dataplane.SessionKey {
	keys := make([]dataplane.SessionKey, 0, len(scoped))
	for _, sk := range scoped {
		keys = append(keys, sk.Key)
	}
	return keys
}

func bareKeysV6(scoped []dataplane.ScopedSessionKeyV6) []dataplane.SessionKeyV6 {
	keys := make([]dataplane.SessionKeyV6, 0, len(scoped))
	for _, sk := range scoped {
		keys = append(keys, sk.Key)
	}
	return keys
}

// BatchDeleteSessionsV6 is the IPv6 analogue of BatchDeleteSessions (#5096).
func (m *Manager) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	scoped := make([]dataplane.ScopedSessionKeyV6, 0, len(keys))
	for _, key := range keys {
		scoped = append(scoped, dataplane.ScopedSessionKeyV6{Key: key})
	}
	var applied []dataplane.ScopedSessionKeyV6
	if err := m.deleteHelperSessionsScopedV6Marked(scoped, false, false, nil, &applied); err != nil {
		return len(applied), err
	}
	return len(applied), nil
}

// ClearAllSessions clears the BPF mirror AND issues an authoritative "delete" to
// the Rust helper for every session so an operator `clear security flow session
// all` actually stops forwarding under revoked decisions (#5096). The helper
// exposes no bulk-clear verb (only the per-session "delete" the singular path
// uses), so every mirror key — forward AND reverse conntrack entries — must be
// deleted on the helper too.
//
// The keys are NOT snapshotted here. Enumerating the full v4+v6 mirror into
// wrapper-owned slices while the shim's own clear snapshots them AGAIN (plus the
// dynamic-DNAT key lists) stacked ~1 GB of duplicate key slices in RSS on a
// max-loaded 10M/family table — enough for the recovery command to stall or
// OOM-kill the daemon (#5304). Instead the shim's ClearAllSessionsChunked drives
// a per-chunk callback: it collects a bounded chunk, deletes it from the mirror,
// and hands that same bounded chunk here for deletion on the helper, so neither
// side ever holds more than one chunk of keys. deleteHelperSessions{V4,V6} keeps
// the #5096 chunked-transmission behaviour (sessionHelperDeleteChunk).
//
// The Rust helper is AUTHORITATIVE in userspace mode — it owns packet
// lookup/forwarding while the BPF mirror is a read model. A helper-delete IPC
// failure therefore means a session the operator asked to revoke may still be
// forwarding, even though the mirror was emptied. Losing that error (as the
// pre-#5881 void callbacks did) let `clear security flow session all` report
// success while sessions lived on — a security bug. So the first helper-delete
// error is captured across chunks and, when the mirror clear itself succeeded,
// surfaced as ClearAllSessions's returned error. The bpf mirror's partial
// (v4, v6) counts are still returned alongside the error, matching the #5882
// non-atomic clear-all reporting contract, so a caller learns what the mirror
// side revoked while also learning the authoritative revocation is unconfirmed.
// A mirror-side error still takes precedence and is returned as before.
//
// #5380 residual: the per-chunk callbacks skip the helper delete once a
// transport failure is recorded, so a full clear-all under a hung helper pays
// ~one round-trip deadline total rather than one per 4096-key mirror chunk.
// See the helperDown guard below.
func (m *Manager) ClearAllSessions() (int, int, error) {
	v4, v6 := m.bpfShim.SessionCount()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil || m.proc.Process == nil {
		return v4, v6, errSessionHelperUnreachable
	}
	req := SessionSyncRequest{Operation: "mirror_clear_chunk"}
	for {
		resp, err := m.syncSessionRequestResponseLocked(req)
		if err != nil {
			return v4, v6, fmt.Errorf("clear-all: authoritative helper session revocation failed: %w", err)
		}
		if resp.SessionMirrorV4Count != 0 || resp.SessionMirrorV6Count != 0 {
			v4, v6 = int(resp.SessionMirrorV4Count), int(resp.SessionMirrorV6Count)
		}
		if resp.SessionMirrorComplete || resp.SessionMirrorContinuation == "" {
			return v4, v6, nil
		}
		req.ClearFenceID = resp.SessionMirrorFenceID
		req.ClearContinuation = resp.SessionMirrorContinuation
	}
}

// deleteHelperSessionsV4 tells the Rust helper to delete every key so the batch
// and clear session paths converge the helper's authoritative session table
// with the BPF mirror (#5096). Requests are transmitted in bounded chunks (see
// sessionHelperDeleteChunk) so a large clear does not monopolize the shared
// control socket. A "delete" request built with a nil value carries only the
// 5-tuple, so no snapshot read happens under m.mu.
//
// It returns the FIRST helper IPC error across all chunks (nil if all
// succeeded, or if there is no live helper). Bare batch callers discard it
// (#5096); scoped batch callers propagate the equivalent scoped-helper result
// (#10513); ClearAllSessions propagates it so a failed authoritative
// revocation is reported rather than reported as success (#5881).
func (m *Manager) deleteHelperSessionsV4(keys []dataplane.SessionKey) error {
	// #9364: the BARE form, kept for the callers that genuinely have no value —
	// ClearAllSessions, which is exactly the caller #8636's ambiguous-delete
	// refusal was designed for. It maps onto the scoped implementation with
	// domain 0 rather than duplicating the chunking, so the #5380 fast-fail and
	// the #5448 contract cannot drift between the two forms.
	scoped := make([]dataplane.ScopedSessionKey, 0, len(keys))
	for _, k := range keys {
		scoped = append(scoped, dataplane.ScopedSessionKey{Key: k})
	}
	return m.deleteHelperSessionsScopedV4(scoped)
}

// deleteHelperSessionsScopedV4 is the #9364 domain-carrying helper delete.
func (m *Manager) deleteHelperSessionsScopedV4(keys []dataplane.ScopedSessionKey) error {
	return m.deleteHelperSessionsScopedV4Marked(keys, false, false, nil, nil)
}

// deleteHelperSessionsScopedV4Marked is deleteHelperSessionsScopedV4 with the
// #9714 peer mark set on every request it builds.
//
// refused, when non-nil, collects the keys the helper refused as peer deletes.
// applied, when non-nil, collects the keys the helper CONFIRMED it deleted.
//
// The two are not complements, and that is the whole point (#9714 review round 2,
// finding 1). A key can also be transport-failed, or never sent at all once the
// batch aborts on an unreachable helper. Only `applied` licenses the caller to
// destroy anything.
func (m *Manager) deleteHelperSessionsScopedV4Marked(keys []dataplane.ScopedSessionKey, peer, forwardOnly bool, refused, applied *[]dataplane.ScopedSessionKey) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return nil
	}
	var firstErr error
	for start := 0; start < len(keys); start += sessionHelperDeleteChunk {
		end := start + sessionHelperDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		reqs := make([]SessionSyncRequest, 0, end-start)
		for i := start; i < end; i++ {
			// #9364: name the domain the row was installed under, so the
			// helper does not have to probe for it and cannot refuse the delete
			// as ambiguous. deleteScopeVal returns nil at domain 0, which is the
			// pre-#9364 bare request, bit-identical.
			req := m.buildSessionSyncRequestV4(
				"mirror_delete_batch", keys[i].Key, deleteScopeVal(keys[i].RoutingDomain))
			req.PeerDelete = peer
			req.ForwardOnly = forwardOnly
			reqs = append(reqs, req)
		}
		// #9714: every request's outcome, not only the first error, so a key the
		// helper refused as a peer delete is known by name. A refusal answers the
		// request; it is not a failure of it.
		var err error
		for i, outcome := range m.syncSessionRequestOutcomesLocked(reqs...) {
			switch {
			case outcome == nil:
				// The helper ANSWERED and applied it. This arm used to be
				// empty, so the one fact that licenses destroying Go-side
				// state was computed and then thrown away, leaving every
				// caller to re-derive it as "not refused" — a strictly
				// larger set that also contains transport failures and
				// requests never sent at all.
				if applied != nil {
					*applied = append(*applied, keys[start+i])
				}
			case peer && refused != nil && peerDeleteRefused(outcome):
				*refused = append(*refused, keys[start+i])
			case err == nil:
				err = outcome
			}
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: stop chunking. Every remaining chunk
			// would fast-fail identically, so a large clear (10M keys ≈ 40K
			// chunks) does not spend one round-trip deadline PER chunk (#5380).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

// deleteHelperSessionsV6 is the IPv6 analogue of deleteHelperSessionsV4 (#5096).
func (m *Manager) deleteHelperSessionsV6(keys []dataplane.SessionKeyV6) error {
	// #9364: the BARE form — see deleteHelperSessionsV4.
	scoped := make([]dataplane.ScopedSessionKeyV6, 0, len(keys))
	for _, k := range keys {
		scoped = append(scoped, dataplane.ScopedSessionKeyV6{Key: k})
	}
	return m.deleteHelperSessionsScopedV6(scoped)
}

// deleteHelperSessionsScopedV6 is the IPv6 analogue of
// deleteHelperSessionsScopedV4 (#9364).
func (m *Manager) deleteHelperSessionsScopedV6(keys []dataplane.ScopedSessionKeyV6) error {
	return m.deleteHelperSessionsScopedV6Marked(keys, false, false, nil, nil)
}

// deleteHelperSessionsScopedV6Marked is the IPv6 analogue of
// deleteHelperSessionsScopedV4Marked (#9714). Same `refused` / `applied`
// contract, and the same reason it matters: the two are NOT complements, and only
// `applied` licenses the caller to destroy anything.
func (m *Manager) deleteHelperSessionsScopedV6Marked(keys []dataplane.ScopedSessionKeyV6, peer, forwardOnly bool, refused, applied *[]dataplane.ScopedSessionKeyV6) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return nil
	}
	var firstErr error
	for start := 0; start < len(keys); start += sessionHelperDeleteChunk {
		end := start + sessionHelperDeleteChunk
		if end > len(keys) {
			end = len(keys)
		}
		reqs := make([]SessionSyncRequest, 0, end-start)
		for i := start; i < end; i++ {
			// #9364: name the domain — see the V4 twin.
			req := m.buildSessionSyncRequestV6(
				"mirror_delete_batch", keys[i].Key, deleteScopeValV6(keys[i].RoutingDomain))
			req.PeerDelete = peer
			req.ForwardOnly = forwardOnly
			reqs = append(reqs, req)
		}
		// #9714: every request's outcome, not only the first error, so a key the
		// helper refused as a peer delete is known by name. A refusal answers the
		// request; it is not a failure of it.
		var err error
		for i, outcome := range m.syncSessionRequestOutcomesLocked(reqs...) {
			switch {
			case outcome == nil:
				// The helper ANSWERED and applied it. This arm used to be
				// empty, so the one fact that licenses destroying Go-side
				// state was computed and then thrown away, leaving every
				// caller to re-derive it as "not refused" — a strictly
				// larger set that also contains transport failures and
				// requests never sent at all.
				if applied != nil {
					*applied = append(*applied, keys[start+i])
				}
			case peer && refused != nil && peerDeleteRefused(outcome):
				*refused = append(*refused, keys[start+i])
			case err == nil:
				err = outcome
			}
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Helper unreachable/hung: stop chunking (see deleteHelperSessionsV4).
			if errors.Is(err, errSessionHelperUnreachable) {
				break
			}
		}
	}
	return firstErr
}

// ErrSessionCountersUnsupported reports that the running helper does not
// implement the #7919 `session_counters` verb.
//
// THIS IS NOT "ZERO". An older helper answers an unknown verb with
// `unknown request type <verb>` (server/handlers/mod.rs), and a caller that
// treated that as an empty result would record "no worker holds this session"
// — which is one of the two states the query exists to distinguish, and would
// manufacture exactly the evidence it is meant to gather. In a rolling upgrade
// the two nodes run different binaries, so this path is reachable in normal
// operation, not just in test.
var ErrSessionCountersUnsupported = errors.New("helper does not support the session_counters verb")

// unknownVerbPrefix is the helper's wording for an unimplemented verb. Matching
// on text is unpleasant and it is the ONLY signal an already-released helper
// gives — that binary cannot be changed retroactively. The current helper's
// exact wording is pinned by a test on the Rust side so a reword breaks the
// build rather than silently turning "unsupported" into a generic error.
const unknownVerbPrefix = "unknown request type"

// QuerySessionCounters asks the helper what EACH worker's own session table
// holds for one 5-tuple (#7919).
//
// READ-ONLY and DIAGNOSTIC-ONLY. It broadcasts a command to every worker and
// waits (bounded, helper-side) for their replies, so it must never be issued on
// a poll: the control socket is shared with the status poll, HA sync, session
// installs and snapshot sync, and a caller above ~1 Hz starves session installs
// during bulk sync.
func (m *Manager) QuerySessionCounters(q SessionCounterQuery) ([]SessionCounterRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:                "session_counters",
		SuppressStatus:      true,
		SessionCounterQuery: &q,
	})
	return sessionCountersFromResponse(resp, err)
}

// sessionCountersFromResponse turns one control exchange into the caller's
// answer. EXTRACTED from QuerySessionCounters rather than left inline because
// the request path has no test seam, and an inline choice cannot be bound by a
// test — the classification below is the whole contract of this verb on the Go
// side, and it must be exercisable without a live helper.
//
// The distinction it enforces: an UNSUPPORTED verb is an error, never an empty
// result. Returning `nil, nil` for an old helper would tell the caller that no
// worker holds the session, which is one of the two states the query exists to
// separate — the failure would look exactly like a finding.
func sessionCountersFromResponse(resp ControlResponse, err error) ([]SessionCounterRow, error) {
	if err != nil {
		if isUnknownVerbError(err) {
			return nil, ErrSessionCountersUnsupported
		}
		return nil, err
	}
	return resp.SessionCounters, nil
}

// isUnknownVerbError reports whether the helper refused the verb because it does
// not implement it, as opposed to failing while executing it. The two must not
// be conflated: the first means "ask a newer helper", the second means the
// answer is genuinely unavailable and retrying will not help.
func isUnknownVerbError(err error) bool {
	return err != nil && strings.Contains(err.Error(), unknownVerbPrefix)
}
