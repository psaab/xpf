package api

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// sessionWalkLimiter is the shared admission gate for the full-table
// session-scan handlers (list, summary, zone-pairs). It aliases the
// process-wide diagcmd.SessionWalkLimiter (capacity
// diagcmd.MaxConcurrentSessionWalks), the SAME instance the gRPC
// GetSessions/GetSessionSummary handlers use — so a mix of REST and gRPC
// scrapers draws from one aggregate budget and a gRPC caller cannot bypass
// this bound (#5708). It reuses the diagcmd fixed-capacity counting semaphore
// (the same fail-fast idiom the diagnostic ping/traceroute handlers use,
// #5057): Acquire is non-blocking, so an over-cap request is rejected
// immediately with HTTP 429 rather than queued into an unbounded backlog. Each
// walk holds per-bucket BPF-map locks across the whole v4+v6 conntrack table,
// contending with the live dataplane session-sync path (#5318, #5433). It is a
// package var so a test can swap in a fresh small-capacity limiter without
// mutating the process-wide instance.
var sessionWalkLimiter = diagcmd.SessionWalkLimiter

// defaultSessionCountCap bounds how many matching sessions the offset list
// walk counts before it stops and reports Total as an approximate lower
// bound instead of forcing a full v4+v6 table scan for an EXACT Total on
// every page (#5318). It is set well above any realistic non-attack session
// table so the common case keeps its exact, byte-identical Total; only a
// multi-million-session table degrades to an approximate count.
const defaultSessionCountCap = 1_000_000

// sessionCountCap is the live cap value. A package var so a test can shrink
// it and exercise the approximate-Total path without a million-row fixture.
var sessionCountCap = defaultSessionCountCap

// sessionCursorIterator is the optional cursor-based session iteration
// surface. The production runtime dataplane (the userspace
// LegacyDataPlaneAdapter wrapping *dataplane.Manager) implements it; REST
// type-asserts s.dp to it for stable page_token pagination and falls back
// to the offset/limit path when it is not available. This mirrors the
// gRPC sessionCursorIterator (pkg/grpcapi/runtime.go) (#3421 H4).
type sessionCursorIterator interface {
	IterateSessionsFrom(*dataplane.SessionKey, func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(*dataplane.SessionKeyV6, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// sessionWalkCancelInterval is how many conntrack entries a session map walk
// visits between request-context cancellation samples. Each iter.Next holds a
// per-bucket BPF-map lock, so a REST client that has disconnected
// (r.Context() cancelled) should stop the full-table walk promptly to release
// that lock back to the live dataplane session-sync path (#5233). Sampling
// once per batch keeps the mutex-guarded ctx.Err() read off the per-session
// hot path — probing every single entry would itself add lock traffic across a
// multi-million-entry table.
const sessionWalkCancelInterval = 1024

// newRequestCancelSampler returns a predicate reporting whether ctx has been
// cancelled, inspecting ctx.Err() only once per `every` calls and latching
// true once observed. Session iterator callbacks call it at the top of each
// invocation so a long conntrack map walk aborts (the callback returns false,
// breaking IterateSessions) within one sampling window of a client disconnect,
// without paying ctx.Err() per session (#5233). On the normal, non-cancelled
// path it never returns true, so output and ordering are unchanged.
func newRequestCancelSampler(ctx context.Context, every int) func() bool {
	if every < 1 {
		every = 1
	}
	n := 0
	cancelled := false
	return func() bool {
		if cancelled {
			return true
		}
		n++
		if n >= every {
			n = 0
			cancelled = ctx.Err() != nil
		}
		return cancelled
	}
}

func (s *Server) sessionsHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	// Admission bound (#5318): a session list is a full conntrack-table walk
	// that contends with the live dataplane session-sync path for per-bucket
	// BPF-map locks. Acquire a slot fail-fast BEFORE the walk (and before the
	// peer fan-out) so a concurrent-scrape flood is rejected with HTTP 429
	// rather than each driving its own simultaneous walk. Release on every
	// exit path via defer. This covers both the offset and cursor paths. The
	// limiter is shared with the summary/zone-pair scans (#5433).
	//
	// #5880: acquire once at THIS external trust boundary and re-stamp the
	// request context with the returned in-process admission lease. The
	// include_peer fan-out (writeSessionList) delegates to the in-process gRPC
	// session service on r.Context(), so re-stamping r propagates the lease and
	// that nested call REUSES this slot instead of re-acquiring the same limiter
	// and self-rejecting at capacity.
	release, walkCtx, err := sessionWalkLimiter.AcquireCtx(r.Context())
	if err != nil {
		writeError(w, http.StatusTooManyRequests,
			"session list concurrency limit reached; retry shortly")
		return
	}
	defer release()
	r = r.WithContext(walkCtx)

	view := s.buildSessionView()
	q, errMsg := buildSessionQuery(r, view)
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}

	// include_peer is an opt-in HA flag (#3423 M5): when set the local list
	// is augmented with the cluster peer's sessions. Validate it here so a
	// malformed value fails closed (HTTP 400) rather than being silently
	// ignored — mirroring the other boolean filters.
	if _, ok := sessionIncludePeer(r); !ok {
		writeError(w, http.StatusBadRequest, "invalid include_peer: "+r.URL.Query().Get("include_peer"))
		return
	}

	// page_size>0 selects cursor-based pagination over a stable page_token,
	// matching the gRPC contract (page_size triggers getSessionsCursor).
	// The offset path remains for backward compatibility but is best-effort:
	// the backend iterates helper map order, so an offset against a fresh
	// traversal can skip/duplicate rows when sessions expire or insert
	// between pages (#3421 H4). queryIntStrict fails closed on a malformed
	// or negative value (#3421 M8).
	pageSize, ok := queryIntStrict(r, "page_size", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page_size: "+r.URL.Query().Get("page_size"))
		return
	}
	if pageSize > 10000 {
		pageSize = 10000
	}
	if pageSize > 0 {
		if iterDP, cursorOK := s.dpProbe().(sessionCursorIterator); cursorOK {
			s.sessionsCursor(w, r, iterDP, &q, view, pageSize)
			return
		}
		// Cursor iteration unsupported by this dataplane (test/edge
		// configurations); fall through to the offset/limit path so the
		// request still succeeds, mirroring the gRPC fallback.
	}

	s.sessionsOffset(w, r, &q, view)
}

// sessionsOffset serves the backward-compatible limit/offset pagination
// path. limit/offset parse fail-closed on malformed/negative input (#3421
// M8); an iterator error fails the request rather than returning a partial
// list as success (#2469). Rows are enriched and reverse-counter-merged
// identically to the cursor path (#3419).
func (s *Server) sessionsOffset(w http.ResponseWriter, r *http.Request, q *sessionQuery, view sessionView) {
	limit, ok := queryIntStrict(r, "limit", 100)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid limit: "+r.URL.Query().Get("limit"))
		return
	}
	if limit > 10000 {
		limit = 10000
	}
	offset, ok := queryIntStrict(r, "offset", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid offset: "+r.URL.Query().Get("offset"))
		return
	}
	// #8597 (muse-004 K25): `offset` needs a ceiling, and its sibling `limit`
	// three lines above has had one all along. Without it the countCap raise
	// below — which exists so an explicitly requested deep window is not
	// truncated — is driven by an unbounded query parameter, so `offset` past
	// sessionCountCap RESTORES the full v4+v6 table walk per page that #5318
	// exists to prevent. One query string turns the bound off.
	//
	// REJECTED rather than clamped, unlike `limit`, and the difference is
	// deliberate: a clamped limit returns fewer rows than asked for, which a
	// paging client handles, whereas a clamped offset returns a DIFFERENT PAGE
	// than asked for — a client walking pages would loop on it forever. Past
	// this cap the offset path has nothing meaningful to return anyway: it is
	// documented above as best-effort because the backend iterates helper map
	// order, and Total is already only a lower bound there. The cursor path
	// (`page_token`) is the stable deep-pagination surface and the error names
	// it.
	if offset > sessionCountCap {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"offset %d exceeds the maximum offset-pagination depth (%d); "+
				"use page_token cursor pagination for deep pages", offset, sessionCountCap))
		return
	}

	now := monotonicSeconds()
	all := make([]SessionEntry, 0)
	matched := 0
	capped := false

	// Bound the Total-counting walk (#5318). The exact-Total contract used to
	// force a FULL v4+v6 table walk on EVERY page just to report Total —
	// O(table) work per 100-row page, repeated per poll, contending with the
	// live session-sync path on a multi-million-session firewall. Cap the
	// count: walk at most countCap matching rows. UNDER the cap Total is EXACT
	// and the response is byte-identical to before (total_approximate omitted);
	// past the cap the walk stops and Total is reported as an approximate lower
	// bound (total_approximate=true). countCap is raised to cover an explicitly
	// requested deep window (offset+limit) so a page is never truncated below
	// the requested limit; only the count degrades on a huge table.
	countCap := sessionCountCap
	if need := offset + limit; need > countCap {
		countCap = need
	}

	// Abort the walk if the client disconnects: on a multi-million-session
	// firewall the offset scan otherwise runs holding per-bucket BPF-map
	// locks even though the response is discarded, contending with the live
	// dataplane session-sync path (#5237/#5233). Sampled per batch so the
	// check costs nothing per session.
	cancelled := newRequestCancelSampler(r.Context(), sessionWalkCancelInterval)

	// IPv4 sessions. A backend iterator failure (e.g. helper restart
	// mid-scan) must fail the request rather than returning HTTP 200 with
	// a partial/zero session list as a healthy result (#2469).
	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if cancelled() {
			return false
		}
		if !q.matchV4(key, val) {
			return true
		}
		if matched >= offset && len(all) < limit {
			all = append(all, s.enrichSessionV4(key, val, now, view))
		}
		matched++
		// Strictly-greater so a table of EXACTLY countCap matches still
		// completes and reports an exact Total; only countCap+1 trips the cap.
		if matched > countCap {
			capped = true
			return false
		}
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
		return
	}

	// IPv6 sessions — skipped entirely once the v4 walk already hit the cap.
	if !capped {
		if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if cancelled() {
				return false
			}
			if !q.matchV6(key, val) {
				return true
			}
			if matched >= offset && len(all) < limit {
				all = append(all, s.enrichSessionV6(key, val, now, view))
			}
			matched++
			if matched > countCap {
				capped = true
				return false
			}
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
			return
		}
	}

	s.writeSessionList(w, r, SessionListResponse{
		Total:            matched,
		TotalApproximate: capped,
		Limit:            limit,
		Offset:           offset,
		Sessions:         all,
	})
}

// sessionsCursor serves cursor-based pagination using the same stable
// page_token machinery as gRPC: it iterates v4 then v6 from the cursor,
// emitting up to page_size matching rows and a next_page_token that resumes
// exactly after the last row. Because IterateSessionsFrom resumes AFTER the
// cursor key, pages never skip or duplicate rows across map mutation the way
// the offset path can (#3421 H4). Rows use the SAME #3419 enrichment +
// reverse-counter merge as the offset path, so cursor and offset modes
// report identical rows and counters. An iterator error fails the request
// (#2469).
func (s *Server) sessionsCursor(w http.ResponseWriter, r *http.Request, iterDP sessionCursorIterator, q *sessionQuery, view sessionView, pageSize int) {
	startV4 := true
	startV6 := false
	var cursorV4 *dataplane.SessionKey
	var cursorV6 *dataplane.SessionKeyV6

	if token := r.URL.Query().Get("page_token"); token != "" {
		kind, keyBytes, err := parseSessionPageToken(token)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid page_token: "+err.Error())
			return
		}
		switch kind {
		case "v4":
			k, err := decodeSessionKeyV4(keyBytes)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid v4 page_token: "+err.Error())
				return
			}
			cursorV4 = &k
		case "v6start":
			startV4 = false
			startV6 = true
		case "v6":
			startV4 = false
			startV6 = true
			k, err := decodeSessionKeyV6(keyBytes)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid v6 page_token: "+err.Error())
				return
			}
			cursorV6 = &k
		}
	}

	now := monotonicSeconds()
	all := make([]SessionEntry, 0, pageSize)
	var lastV4 dataplane.SessionKey
	var lastV6 dataplane.SessionKeyV6

	// Abort the walk when the REST client disconnects (#5233). A SELECTIVE or
	// no-match cursor query never fills the page, so without this the callback
	// runs the remainder of a multi-million-entry conntrack table holding
	// per-bucket BPF-map locks for a page nobody will read — contending with the
	// live dataplane session-sync path. The non-cursor sessionsOffset /
	// summary / zone-pair walks already sample this (same helper); the cursor
	// path was the residual (#5233 closeout). Sampled per batch off the
	// per-session hot path; r.Context().Err() is re-checked directly at each
	// phase boundary (cheap, once per phase) so a disconnect neither launches
	// the second full walk nor writes a misleading terminal envelope.
	cancelled := newRequestCancelSampler(r.Context(), sessionWalkCancelInterval)

	// Phase 1: v4 from cursor.
	if startV4 {
		if err := iterDP.IterateSessionsFrom(cursorV4, func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if cancelled() {
				return false
			}
			if len(all) >= pageSize {
				return false
			}
			if !q.matchV4(key, val) {
				return true
			}
			all = append(all, s.enrichSessionV4(key, val, now, view))
			lastV4 = key
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
			return
		}
		// A full page is a complete, valid result — emit it even though the
		// callback may have observed cancellation on its final probe (the client
		// being gone only means the write is discarded).
		if len(all) >= pageSize {
			s.writeSessionList(w, r, SessionListResponse{
				PageSize:      pageSize,
				NextPageToken: encodePageTokenV4(lastV4),
				Sessions:      all,
			})
			return
		}
		startV6 = true
	}

	// Phase 2: v6. The direct r.Context().Err() check gates BOTH the v4->v6
	// transition and the v6-start-token path: never launch a second full-table
	// walk for a client that has already disconnected, and never emit a
	// (misleading) partial/terminal envelope to a dead connection (#5233).
	if startV6 {
		if r.Context().Err() != nil {
			return
		}
		if err := iterDP.IterateSessionsV6From(cursorV6, func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if cancelled() {
				return false
			}
			if len(all) >= pageSize {
				return false
			}
			if !q.matchV6(key, val) {
				return true
			}
			all = append(all, s.enrichSessionV6(key, val, now, view))
			lastV6 = key
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
			return
		}
		if len(all) >= pageSize {
			s.writeSessionList(w, r, SessionListResponse{
				PageSize:      pageSize,
				NextPageToken: encodePageTokenV6(lastV6),
				Sessions:      all,
			})
			return
		}
	}

	// Both families exhausted — last page, empty next_page_token. Suppress the
	// terminal envelope if the client disconnected during the final walk: a
	// "last page, no next token" reply would misrepresent iteration state.
	if r.Context().Err() != nil {
		return
	}
	s.writeSessionList(w, r, SessionListResponse{
		PageSize: pageSize,
		Sessions: all,
	})
}

// enrichSessionV4 merges the companion reverse entry's counters into the
// forward entry (full bidirectional volume, #3419 H3) and renders the
// enriched REST row (#3419). Shared by the offset and cursor paths so they
// report identical rows and counters.
func (s *Server) enrichSessionV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64, view sessionView) SessionEntry {
	if rev, err := s.dp.GetSessionV4(val.ReverseKey); err == nil {
		val.RevPackets += rev.RevPackets
		val.RevBytes += rev.RevBytes
		val.FwdPackets += rev.FwdPackets
		val.FwdBytes += rev.FwdBytes
	}
	return sessionEntryV4(key, val, now, view)
}

// enrichSessionV6 is the IPv6 companion to enrichSessionV4.
func (s *Server) enrichSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64, view sessionView) SessionEntry {
	if rev, err := s.dp.GetSessionV6(val.ReverseKey); err == nil {
		val.RevPackets += rev.RevPackets
		val.RevBytes += rev.RevBytes
		val.FwdPackets += rev.FwdPackets
		val.FwdBytes += rev.FwdBytes
	}
	return sessionEntryV6(key, val, now, view)
}

// sessionIncludePeer parses the include_peer query flag, returning the value
// and whether it was well-formed (an absent flag is valid and defaults to
// false). The handlers fail closed (HTTP 400) on a malformed value rather
// than silently ignoring an opt-in HA request (#3423 M5).
func sessionIncludePeer(r *http.Request) (value bool, ok bool) {
	v := r.URL.Query().Get("include_peer")
	if v == "" {
		return false, true
	}
	b, err := strconv.ParseBool(v)
	return b, err == nil
}

// writeSessionList stamps the local node identity on a REST session list and,
// when include_peer=true and an HA-aware session service is wired, augments it
// with the cluster peer's sessions (#3423 M5). The local list reports the
// LOCAL table only; node_id tells a dashboard which node it observes, and the
// optional peer set keeps it from understating total HA state.
//
// The peer's FULL table is attached only on the FIRST page — cursor mode's
// first page (no page_token) AND offset mode's first window (offset==0). A
// client paginating either way and summing peer.sessions across pages would
// OVER-COUNT the peer if the whole peer table were re-attached on every page
// (the offset path never sets a page_token, so a page_token-only guard let it
// through). page_token additionally encodes node-local map keys meaningless to
// the peer.
func (s *Server) writeSessionList(w http.ResponseWriter, r *http.Request, resp SessionListResponse) {
	resp.NodeID = s.nodeID()
	if includePeer, _ := sessionIncludePeer(r); includePeer && sessionFirstPage(r) {
		if svc := s.clusterSession(); svc != nil {
			// #5968: PeerSessions, not GetSessions — the local list is already
			// built above and the delegate's own local walk was thrown away.
			//
			// #7294: the error is CLASSIFIED, not discarded. `if err == nil`
			// returned 200 with the peer table silently absent, which an
			// operator cannot tell from a peer that genuinely has no
			// sessions. The summary and zone-pair surfaces already do this;
			// the list surface was the one that did not.
			pr, err := svc.PeerSessions(r.Context(), peerSessionsRequest(r))
			if err != nil {
				resp.PeerStatus = peerFetchErrorStatus(err)
				resp.PeerError = err.Error()
			} else {
				if peer := pr.GetPeer(); peer != nil {
					resp.Peer = sessionListFromPB(peer)
				}
				// #8308: the residual #8306 recorded here is closed.
				// GetSessionsResponse now carries peer_status, so this
				// surface reports what the SERVER classified instead of
				// asserting "ok" locally — which meant only "the fetch
				// succeeded" and could not distinguish a peer that returned
				// an empty table from a standalone node.
				//
				// The local fallback survives for one case and one only: a
				// server that predates the field sends UNSPECIFIED, which
				// peerFetchStatusString maps to "". The fetch DID succeed, so
				// reporting nothing would be a regression against #8306 on
				// exactly the rolling-upgrade window this field was added
				// carefully for.
				if ps := peerFetchStatusString(pr.GetPeerStatus()); ps != "" {
					resp.PeerStatus = ps
				} else {
					resp.PeerStatus = "ok"
				}
				if pe := pr.GetPeerError(); pe != "" {
					resp.PeerError = pe
				}
			}
		} else {
			resp.PeerStatus = "not-applicable"
		}
	}
	writeOK(w, resp)
}

// sessionFirstPage reports whether this list request is the first page, on
// BOTH pagination modes: cursor mode's first page carries no page_token, and
// offset mode's first window has offset==0. A non-first page must NOT re-attach
// the peer table (#3423 — avoids over-counting the peer across pages). The
// offset/page_token query values are already validated by the caller
// (sessionsOffset / sessionsCursor) before writeSessionList runs, so a lenient
// re-parse here cannot mask a malformed value.
func sessionFirstPage(r *http.Request) bool {
	q := r.URL.Query()
	if q.Get("page_token") != "" {
		return false
	}
	if off, err := strconv.Atoi(q.Get("offset")); err == nil && off > 0 {
		return false
	}
	return true
}

// peerSessionsRequest maps the REST session filter query parameters onto a
// protobuf GetSessionsRequest with IncludePeer set, so the peer applies the
// SAME filters the local list did. Values are read leniently — the caller has
// already validated them (buildSessionQuery / the include_peer guard) before a
// peer fetch is attempted, and the peer re-validates on its own surface.
func peerSessionsRequest(r *http.Request) *pb.GetSessionsRequest {
	q := r.URL.Query()
	req := &pb.GetSessionsRequest{
		IncludePeer:       true,
		Protocol:          q.Get("protocol"),
		SourcePrefix:      q.Get("source_prefix"),
		DestinationPrefix: q.Get("destination_prefix"),
		Application:       q.Get("application"),
		InterfaceFilter:   q.Get("interface"),
		SourceNatPool:     q.Get("source_nat_pool"),
	}
	if z, err := strconv.ParseUint(q.Get("zone"), 10, 16); err == nil {
		req.Zone = uint32(z)
	}
	if p, err := strconv.ParseUint(q.Get("source_port"), 10, 16); err == nil {
		req.SourcePort = uint32(p)
	}
	if p, err := strconv.ParseUint(q.Get("destination_port"), 10, 16); err == nil {
		req.DestinationPort = uint32(p)
	}
	if b, err := strconv.ParseBool(q.Get("nat_only")); err == nil {
		req.NatOnly = b
	}
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		req.Limit = int32(l)
	}
	// Forward cursor-mode page_size so the peer fan-out honors the SAME page
	// bound the local list did (#4920). A cursor-mode REST caller sends
	// page_size WITHOUT limit; without this the peer gRPC request carried
	// Limit==0 AND PageSize==0, so getSessionsLegacy defaulted the peer list to
	// 100 sessions and the first REST page attached at most 100 peer sessions —
	// silently undercounting the peer whenever it held >100 sessions. The value
	// is read leniently (the caller validated page_size via queryIntStrict
	// before a peer fetch is attempted); the peer's gRPC surface re-clamps it to
	// the 10000 ceiling. page_token is intentionally NOT forwarded — tokens
	// encode node-local map keys and the peer fetch only runs on the first page.
	if p, err := strconv.Atoi(q.Get("page_size")); err == nil && p > 0 {
		req.PageSize = int32(p)
	}
	return req
}

// sessionListFromPB maps a protobuf session-list response (the peer node's
// view) onto the REST SessionListResponse shape (#3423 M5).
func sessionListFromPB(p *pb.GetSessionsResponse) *SessionListResponse {
	out := &SessionListResponse{
		Total:         int(p.GetTotal()),
		Limit:         int(p.GetLimit()),
		Offset:        int(p.GetOffset()),
		NextPageToken: p.GetNextPageToken(),
		NodeID:        int(p.GetNodeId()),
		Sessions:      make([]SessionEntry, 0, len(p.GetSessions())),
	}
	for _, e := range p.GetSessions() {
		out.Sessions = append(out.Sessions, sessionEntryFromPB(e))
	}
	return out
}

// sessionEntryFromPB maps one protobuf SessionEntry onto the REST shape.
func sessionEntryFromPB(e *pb.SessionEntry) SessionEntry {
	return SessionEntry{
		SrcAddr:          e.GetSrcAddr(),
		DstAddr:          e.GetDstAddr(),
		SrcPort:          uint16(e.GetSrcPort()),
		DstPort:          uint16(e.GetDstPort()),
		Protocol:         e.GetProtocol(),
		State:            e.GetState(),
		PolicyID:         e.GetPolicyId(),
		PolicyName:       e.GetPolicyName(),
		IngressZoneName:  e.GetIngressZoneName(),
		EgressZoneName:   e.GetEgressZoneName(),
		InZone:           uint16(e.GetIngressZone()),
		OutZone:          uint16(e.GetEgressZone()),
		IngressInterface: e.GetIngressInterface(),
		EgressInterface:  e.GetEgressInterface(),
		Application:      e.GetApplication(),
		FwdPackets:       e.GetFwdPackets(),
		FwdBytes:         e.GetFwdBytes(),
		RevPackets:       e.GetRevPackets(),
		RevBytes:         e.GetRevBytes(),
		NAT:              e.GetNat(),
		NATSrcAddr:       e.GetNatSrcAddr(),
		NATSrcPort:       uint16(e.GetNatSrcPort()),
		NATDstAddr:       e.GetNatDstAddr(),
		NATDstPort:       uint16(e.GetNatDstPort()),
		Age:              e.GetAgeSeconds(),
		Idle:             e.GetIdleSeconds(),
		Timeout:          e.GetTimeoutSeconds(),
		SessionID:        e.GetSessionId(),
		HAActive:         e.GetHaActive(),
	}
}

// sessionSummaryFromPB maps a protobuf session summary (the peer node's view)
// onto the REST SessionSummary shape (#3423 M5). The peer carries its OWN
// max_sessions (#5323); its peer_status is not recursed (the peer leg is
// local-only).
func sessionSummaryFromPB(p *pb.GetSessionSummaryResponse) *SessionSummary {
	return &SessionSummary{
		TotalEntries: int(p.GetTotalEntries()),
		ForwardOnly:  int(p.GetForwardOnly()),
		Established:  int(p.GetEstablished()),
		IPv4Sessions: int(p.GetIpv4Sessions()),
		IPv6Sessions: int(p.GetIpv6Sessions()),
		SNATSessions: int(p.GetSnatSessions()),
		DNATSessions: int(p.GetDnatSessions()),
		NodeID:       int(p.GetNodeId()),
		MaxSessions:  p.GetMaxSessions(),
	}
}

// peerFetchStatusString renders the protobuf PeerFetchStatus enum as the REST
// JSON string surfaced on SessionSummary / ZonePairSummaryResponse (#5320). The
// UNSPECIFIED zero value renders "" (omitted) so an older/absent gRPC server
// does not fabricate a status.
// peerFetchErrorStatus classifies a FAILED peer fetch.
//
// Not every failure is a partition. An admission refusal means the peer is
// reachable and we declined to ask — folding that into "unreachable" sends an
// operator debugging a fabric problem after a network fault that is not there.
// The gRPC surfaces map an over-cap peer fetch to codes.ResourceExhausted
// (peer_only_5968.go), so the distinction is already on the error and only
// needed carrying through.
//
// Scoped residual: pb.PeerFetchStatus has no BUSY member, so a gRPC client
// still sees UNREACHABLE for a refusal. Adding an enum value is a wire change
// whose rolling-upgrade behaviour (an older cli rendering an unknown number)
// deserves its own decision rather than riding along here. This corrects the
// surface an operator actually reads.
func peerFetchErrorStatus(err error) string {
	if status.Code(err) == codes.ResourceExhausted {
		return "busy"
	}
	return "unreachable"
}

func peerFetchStatusString(s pb.PeerFetchStatus) string {
	switch s {
	case pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE:
		return "not-applicable"
	case pb.PeerFetchStatus_PEER_FETCH_STATUS_OK:
		return "ok"
	case pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE:
		return "unreachable"
	case pb.PeerFetchStatus_PEER_FETCH_STATUS_BUSY:
		// #8308: same word peerFetchErrorStatus already returns, so the two
		// routes into this surface cannot disagree about the same event.
		return "busy"
	default:
		// Includes UNSPECIFIED, which means "this server does not report it"
		// (an older peer, or a field it never set) rather than any outcome.
		// Rendering it as a word would assert something the wire did not say.
		return ""
	}
}

func (s *Server) sessionSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	// include_peer opt-in HA flag (#3423 M5); fail closed on a bad value.
	includePeer, ok := sessionIncludePeer(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid include_peer: "+r.URL.Query().Get("include_peer"))
		return
	}

	// Admission bound (#5433): the summary is an EXACT aggregate over the whole
	// v4+v6 conntrack table, so — like the list handler (#5318) — it holds
	// per-bucket BPF-map locks that contend with the live session-sync path.
	// An exact aggregate genuinely needs the full walk (no sessionCountCap: a
	// capped summary would change the response contract), so the gate alone is
	// the fix. Acquire fail-fast BEFORE the walk (and the peer fan-out); an
	// over-cap request is rejected with HTTP 429 instead of driving its own
	// simultaneous walk. Release on every exit path via the deferred idempotent
	// release; nothing is released on the ErrBusy path (release is nil there).
	//
	// #5880: acquire once at this boundary and re-stamp r with the in-process
	// admission lease so the include_peer delegation to the in-process gRPC
	// GetSessionSummary reuses this slot rather than re-acquiring.
	release, walkCtx, err := sessionWalkLimiter.AcquireCtx(r.Context())
	if err != nil {
		writeError(w, http.StatusTooManyRequests,
			"session scan concurrency limit reached; retry shortly")
		return
	}
	defer release()
	r = r.WithContext(walkCtx)

	var summary SessionSummary

	// Stop the full-table walk if the client disconnects mid-scan so we do
	// not keep holding per-bucket BPF-map locks for a summary nobody will
	// read (#5233); sampled per batch (see newRequestCancelSampler).
	cancelled := newRequestCancelSampler(r.Context(), sessionWalkCancelInterval)

	// A partial scan yields an under-count that looks like a healthy
	// summary — fail the request instead of publishing it (#2469).
	if err := s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		if cancelled() {
			return false
		}
		summary.TotalEntries++
		if val.IsReverse == 0 {
			summary.ForwardOnly++
			summary.IPv4Sessions++
			if val.State == dataplane.SessStateEstablished {
				summary.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				summary.SNATSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				summary.DNATSessions++
			}
		}
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
		return
	}

	if err := s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if cancelled() {
			return false
		}
		summary.TotalEntries++
		if val.IsReverse == 0 {
			summary.ForwardOnly++
			summary.IPv6Sessions++
			if val.State == dataplane.SessStateEstablished {
				summary.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				summary.SNATSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				summary.DNATSessions++
			}
		}
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
		return
	}

	summary.NodeID = s.nodeID()

	// #5323: the dataplane's dynamic session-table capacity, fetched from the
	// live helper status (0 = unknown when no userspace status surface exists).
	if st := fetchUserspaceStatus(s.dp); st != nil {
		summary.MaxSessions = st.MaxSessions
	}

	// Default peer-status: a summary without include_peer makes no claim about
	// a peer (#5320). The include_peer path below overrides this with the gRPC
	// server's authoritative classification.
	summary.PeerStatus = "not-applicable"

	// Augment with the cluster peer's summary when the operator opted in and
	// an HA-aware service is wired (#3423 M5): the local summary alone
	// understates total HA state. #5320: surface the peer-fetch completeness so
	// an unreachable peer (LOCAL-ONLY totals) is distinguishable from a healthy
	// standalone node rather than silently leaving Peer nil.
	if includePeer {
		if svc := s.clusterSession(); svc != nil {
			// #5968: PeerSessionSummary, not GetSessionSummary — the local
			// summary is already computed above and the delegate's own local
			// walk was discarded.
			pr, err := svc.PeerSessionSummary(r.Context())
			if err != nil {
				summary.PeerStatus = peerFetchErrorStatus(err)
				summary.PeerError = err.Error()
			} else {
				if peer := pr.GetPeer(); peer != nil {
					summary.Peer = sessionSummaryFromPB(peer)
				}
				summary.PeerStatus = peerFetchStatusString(pr.GetPeerStatus())
				summary.PeerError = pr.GetPeerError()
			}
		}
	}

	writeOK(w, summary)
}

func (s *Server) clearSessionsHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	// REST clear is an unconditional clear-ALL of the local table. gRPC
	// supports a FILTERED clear (source/destination prefix, protocol, zone,
	// ports, application, interface, nat-only, source-nat-pool); this
	// handler does not. Silently ignoring filter parameters would degrade a
	// client's intended-narrow clear into a full-table wipe — so reject any
	// query string or request body with HTTP 400 rather than performing an
	// unexpected clear-all (#3421 H6). A parameterless clear (the documented
	// contract) proceeds. Test against r.URL.RawQuery (not url.Query(),
	// which silently drops un-decodable pairs like `?%zz` and could let a
	// non-empty query proceed to clear-all — SMR); a non-zero ContentLength
	// (including the chunked-transfer -1 sentinel) also rejects so a
	// body-carrying request cannot be misread as clear-all.
	if r.URL.RawQuery != "" || r.ContentLength != 0 {
		writeError(w, http.StatusBadRequest,
			"filtered clear not supported on this endpoint; it clears all local sessions and accepts no parameters")
		return
	}

	// In an HA cluster the clear MUST also reach the peer: a local-only
	// clear leaves the peer/synced sessions, which can reappear as active
	// state on failover (#3423 H5). When the HA-aware session service is
	// wired (the gRPC server), delegate the clear-all to it so REST shares
	// the SAME service-layer path gRPC uses: local clear + peer propagation
	// (clearPeerSessions, x-peer-forwarded recursion guard) + partial-
	// failure summary. A nil service (standalone build / unit test) falls
	// back to the local-only clear — the pre-#3423 behavior.
	if svc := s.clusterSession(); svc != nil {
		resp, err := svc.ClearSessions(r.Context(), &pb.ClearSessionsRequest{})
		if err != nil {
			// #9142: CLASSIFY the delegate's gRPC status instead of flattening
			// every failure to 500. The delegate is the in-process
			// *grpcapi.Server, and its ClearSessions handler refuses an
			// over-cap clear with codes.ResourceExhausted from the SAME
			// process-wide sessionWalkLimiter the local-only fallback below
			// acquires — where the refusal answers 429. So before this, the
			// identical condition answered 429 on a standalone node and 500 on
			// a node with an HA session service wired, and a client keyed on
			// the status class (back off on 429, page a human on 5xx) behaved
			// differently based only on whether HA was wired.
			//
			// The message uses status.Convert(err).Message(), not err.Error():
			// the latter emits the gRPC FRAMING ("rpc error: code = ... desc =
			// ...") into a REST JSON body, which is an internal transport
			// detail of a delegation the REST caller cannot see. Convert also
			// handles a NON-status error — it yields codes.Unknown and the
			// error's own text, so the default 500 arm loses nothing.
			//
			// This is the same distinction peerFetchErrorStatus (#7294/#8308)
			// already draws on the neighbouring peer-fetch surfaces: an
			// admission refusal is not a fault.
			st := status.Convert(err)
			code := http.StatusInternalServerError
			switch st.Code() {
			case codes.ResourceExhausted:
				code = http.StatusTooManyRequests
			case codes.Unavailable:
				// The dp-loaded guard at the top of this handler already
				// answers 503, so this arm is reachable only through a
				// sub-millisecond TOCTOU (or a future Unavailable from the
				// delegate). Mapping it keeps the two routes to the same
				// condition from disagreeing.
				code = http.StatusServiceUnavailable
			}
			writeError(w, code, st.Message())
			return
		}
		writeOK(w, ClearSessionsResult{
			IPv4Cleared:    int(resp.GetIpv4Cleared()),
			IPv6Cleared:    int(resp.GetIpv6Cleared()),
			NodeID:         s.nodeID(),
			Failures:       int(resp.GetFailures()),
			FailureSummary: resp.GetFailureSummary(),
		})
		return
	}

	// Admission bound (#5779): this local-only fallback drives a full-table
	// chunked clear-all walk (ClearAllSessions), holding per-bucket BPF-map
	// locks like the read scans. Gate it through the SAME shared limiter;
	// over-cap gets HTTP 429. The HA-delegated path above is already gated by
	// the gRPC ClearSessions handler, so gating ONLY this fallback avoids a
	// double-acquire on one clear. Release on every exit path via defer.
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		writeError(w, http.StatusTooManyRequests,
			"session clear concurrency limit reached; retry shortly")
		return
	}
	defer release()

	// Chunked clear-all is NON-atomic (#5882): ClearAllSessions clears the
	// IPv4 table then the IPv6 table, so a failure can leave IPv4 already
	// deleted while returning PARTIAL v4/v6 counts alongside the error.
	// Surface those counts (with a Failures>0 / FailureSummary marker)
	// instead of discarding them behind a bare HTTP 500 — mirroring the
	// gRPC ClearSessions clear-all branch and the HA-delegated path above,
	// so an operator learns what was actually revoked and whether a retry
	// need only target the unfinished family.
	v4, v6, err := s.dp.ClearAllSessions()
	if err != nil {
		writeOK(w, ClearSessionsResult{
			IPv4Cleared:    v4,
			IPv6Cleared:    v6,
			NodeID:         s.nodeID(),
			Failures:       1,
			FailureSummary: "clear-all: " + err.Error(),
		})
		return
	}
	writeOK(w, ClearSessionsResult{IPv4Cleared: v4, IPv6Cleared: v6, NodeID: s.nodeID()})
}

// sessionZonePairHandler serves the zone-pair session breakdown. Like the
// /sessions/summary sibling it stamps node_id so an operator knows which node
// the counts came from (#3423 M5) and now also supports include_peer cross-node
// fan-out (#3592): when an operator sets include_peer=true the handler forwards
// to the gRPC GetZonePairSummary RPC and attaches the cluster peer's OWN
// breakdown under the nested `peer` field. This mirrors sessionSummaryHandler;
// the breakdown is a SUMMARY (not a paginated list), so there is no first-page
// gate — the whole peer breakdown attaches whenever include_peer is set, just
// as /sessions/summary attaches the whole peer summary.
func (s *Server) sessionZonePairHandler(w http.ResponseWriter, r *http.Request) {
	// include_peer opt-in HA flag; fail closed on a bad value (HTTP 400) before
	// any work so a malformed opt-in is never silently ignored (#3592).
	includePeer, ok := sessionIncludePeer(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid include_peer: "+r.URL.Query().Get("include_peer"))
		return
	}

	if s.dp == nil || !s.dp.IsLoaded() {
		writeOK(w, ZonePairSummaryResponse{NodeID: s.nodeID(), ZonePairs: []ZonePairSessionSummary{}})
		return
	}

	// Admission bound (#5433): the zone-pair breakdown is an EXACT aggregate
	// over the whole v4+v6 conntrack table, holding per-bucket BPF-map locks
	// that contend with the live session-sync path (same as the list handler,
	// #5318). An exact breakdown needs the full walk (no sessionCountCap: a
	// capped breakdown would change the response contract), so the gate alone
	// is the fix. Acquire fail-fast BEFORE the walk (and the peer fan-out);
	// over-cap requests get HTTP 429 instead of driving their own simultaneous
	// walk. Gate after the not-loaded early return, which serves an empty
	// breakdown without walking. Release on every exit path via the deferred
	// idempotent release; nothing is released on the ErrBusy path.
	//
	// #5880: acquire once at this boundary and re-stamp r with the in-process
	// admission lease so the include_peer delegation to the in-process gRPC
	// GetZonePairSummary reuses this slot rather than re-acquiring.
	release, walkCtx, err := sessionWalkLimiter.AcquireCtx(r.Context())
	if err != nil {
		writeError(w, http.StatusTooManyRequests,
			"session scan concurrency limit reached; retry shortly")
		return
	}
	defer release()
	r = r.WithContext(walkCtx)

	// Build zone ID -> name reverse map
	zoneNames := make(map[uint16]string)
	if cr := s.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
	}

	type zpKey struct{ from, to uint16 }
	counts := make(map[zpKey]*ZonePairSessionSummary)

	countSession := func(inZone, outZone uint16, proto uint8) {
		k := zpKey{inZone, outZone}
		zp, ok := counts[k]
		if !ok {
			zp = &ZonePairSessionSummary{
				FromZone: zoneNames[inZone],
				ToZone:   zoneNames[outZone],
			}
			if zp.FromZone == "" {
				zp.FromZone = fmt.Sprintf("zone-%d", inZone)
			}
			if zp.ToZone == "" {
				zp.ToZone = fmt.Sprintf("zone-%d", outZone)
			}
			counts[k] = zp
		}
		switch proto {
		case 6:
			zp.TCP++
		case 17:
			zp.UDP++
		case 1, dataplane.ProtoICMPv6:
			zp.ICMP++
		default:
			zp.Other++
		}
		zp.Total++
	}

	// Stop the full-table walk if the client disconnects mid-scan so the
	// per-bucket BPF-map locks are released back to the live dataplane
	// instead of finishing a breakdown nobody will read (#5233); sampled
	// per batch (see newRequestCancelSampler).
	cancelled := newRequestCancelSampler(r.Context(), sessionWalkCancelInterval)

	// A partial scan produces a misleading zone-pair breakdown — fail
	// the request rather than serving an incomplete table as OK (#2469).
	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if cancelled() {
			return false
		}
		if val.IsReverse == 0 {
			countSession(val.IngressZone, val.EgressZone, key.Protocol)
		}
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
		return
	}
	if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if cancelled() {
			return false
		}
		if val.IsReverse == 0 {
			countSession(val.IngressZone, val.EgressZone, key.Protocol)
		}
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
		return
	}

	result := make([]ZonePairSessionSummary, 0, len(counts))
	for _, zp := range counts {
		result = append(result, *zp)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FromZone != result[j].FromZone {
			return result[i].FromZone < result[j].FromZone
		}
		return result[i].ToZone < result[j].ToZone
	})

	resp := ZonePairSummaryResponse{NodeID: s.nodeID(), ZonePairs: result, PeerStatus: "not-applicable"}

	// Augment with the cluster peer's zone-pair breakdown when the operator
	// opted in and an HA-aware service is wired (#3592): the local breakdown
	// alone understates total HA state. The gRPC RPC computes the peer's OWN
	// breakdown (x-peer-forwarded recursion guard) and returns it under Peer; a
	// standalone node / unreachable peer leaves Peer nil. This mirrors
	// sessionSummaryHandler — the breakdown is not paginated, so there is no
	// first-page gate.
	if includePeer {
		if svc := s.clusterSession(); svc != nil {
			// #5968: PeerZonePairSummary, not GetZonePairSummary — the local
			// breakdown is already computed above and the delegate's own local
			// walk was discarded.
			pr, err := svc.PeerZonePairSummary(r.Context())
			if err != nil {
				// #5320: a failed local RPC still leaves the breakdown
				// incomplete — mark it unreachable rather than silently OK.
				resp.PeerStatus = peerFetchErrorStatus(err)
				resp.PeerError = err.Error()
			} else {
				if peer := pr.GetPeer(); peer != nil {
					resp.Peer = zonePairSummaryFromPB(peer)
				}
				resp.PeerStatus = peerFetchStatusString(pr.GetPeerStatus())
				resp.PeerError = pr.GetPeerError()
			}
		}
	}

	writeOK(w, resp)
}

// zonePairSummaryFromPB maps a protobuf zone-pair summary (the peer node's
// view) onto the REST ZonePairSummaryResponse shape (#3592). The peer carries
// its OWN node_id and zone-pair breakdown; its nested Peer is not recursed
// (the gRPC peer leg never sets include_peer on the forwarded request).
func zonePairSummaryFromPB(p *pb.GetZonePairSummaryResponse) *ZonePairSummaryResponse {
	out := &ZonePairSummaryResponse{
		NodeID:    int(p.GetNodeId()),
		ZonePairs: make([]ZonePairSessionSummary, 0, len(p.GetZonePairs())),
	}
	for _, zp := range p.GetZonePairs() {
		out.ZonePairs = append(out.ZonePairs, ZonePairSessionSummary{
			FromZone: zp.GetFromZone(),
			ToZone:   zp.GetToZone(),
			TCP:      int(zp.GetTcp()),
			UDP:      int(zp.GetUdp()),
			ICMP:     int(zp.GetIcmp()),
			Other:    int(zp.GetOther()),
			Total:    int(zp.GetTotal()),
		})
	}
	return out
}

// --- Session helper functions ---

func sessionStateName(state uint8) string {
	switch state {
	case dataplane.SessStateNone:
		return "None"
	case dataplane.SessStateNew:
		return "New"
	case dataplane.SessStateSynSent:
		return "SYN_SENT"
	case dataplane.SessStateSynRecv:
		return "SYN_RECV"
	case dataplane.SessStateEstablished:
		return "Established"
	case dataplane.SessStateFINWait:
		return "FIN_WAIT"
	case dataplane.SessStateCloseWait:
		return "CLOSE_WAIT"
	case dataplane.SessStateTimeWait:
		return "TIME_WAIT"
	case dataplane.SessStateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// uint32ToIP converts a dataplane IPv4 field to net.IP. Session-map
// values hold IP bytes in network order read as a NATIVE-endian u32
// (the Rust helper publishes u32::from_ne_bytes(octets)); BigEndian
// here reversed NAT addresses in the REST session view on
// little-endian hosts (#1827 PR-3 r1, AGY finding).
func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, v)
	return ip
}

// sessionEgressKey identifies a FIB-resolved egress interface (ifindex +
// VLAN), mirroring the gRPC sessionEgressKey used to resolve a session's
// egress interface name (#3419 M4).
type sessionEgressKey struct {
	ifindex uint32
	vlanID  uint16
}

// sessionView holds the enrichment context shared across a single session
// list/iteration: zone/policy/app name maps, the zone->first-interface and
// FIB->interface resolution tables, the active config, and the local HA
// active state. It mirrors the maps the gRPC sessionFilter precomputes
// (#3419 M1/M4/M6) so the REST session view exposes the same fields.
type sessionView struct {
	zoneNames   map[uint16]string
	policyNames map[uint32]string
	appNames    map[uint16]string
	// zoneIfaces holds EVERY interface bound to a zone, not just the first
	// (#6960): collapsing a multi-interface zone to zone.Interfaces[0] made
	// the ingress arm of the interface filter independent of the session, so
	// an interface-scoped REST query reported — and the same reduction on the
	// gRPC surface DELETED — sessions on every sibling interface of the zone.
	zoneIfaces   map[uint16][]string
	egressIfaces map[sessionEgressKey]string
	cfg          *config.Config
	haActive     bool
}

// buildSessionView precomputes the enrichment maps from the last apply
// result and the active config, mirroring grpcapi buildSessionFilter
// (#3419). It is safe to call when the store/apply result is absent (the
// maps stay empty and the view degrades to numeric ids).
func (s *Server) buildSessionView() sessionView {
	v := sessionView{
		zoneNames:    make(map[uint16]string),
		zoneIfaces:   make(map[uint16][]string),
		egressIfaces: make(map[sessionEgressKey]string),
		haActive:     true, // standalone default
	}
	if s.store != nil {
		v.cfg = s.store.ActiveConfig()
	}
	if s.haActiveFn != nil {
		v.haActive = s.haActiveFn()
	}
	cr := s.applyResult()
	if cr != nil {
		for name, id := range cr.ZoneIDs {
			v.zoneNames[id] = name
		}
		v.policyNames = cr.PolicyNames
		v.appNames = cr.AppNames
	}
	if v.cfg != nil && cr != nil {
		for zoneName, zone := range v.cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			if zid, ok := cr.ZoneIDs[zoneName]; ok && len(zone.Interfaces) > 0 {
				// #6960: keep EVERY bound interface (mirrors grpcapi).
				v.zoneIfaces[zid] = append(v.zoneIfaces[zid], zone.Interfaces...)
			}
		}
		v.egressIfaces = buildSessionIfaceNames(v.cfg, s.ifindexLookup())
	}
	return v
}

// ifindexLookup returns the netdev-name -> kernel-ifindex resolver used to
// build the session {ifindex, VLAN} -> interface-name table. Tests inject a
// fixed table; a nil field means the real kernel lookup (mirrors grpcapi).
func (s *Server) ifindexLookup() func(string) (int, error) {
	if s != nil && s.ifindexByName != nil {
		return s.ifindexByName
	}
	return func(name string) (int, error) {
		link, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return link.Index, nil
	}
}

// buildSessionIfaceNames maps a session's {parent netdev ifindex, 802.1Q VLAN
// id} to the Junos config name of that logical unit. BOTH directions of the
// session filter read it: the egress side keys on the recorded FIB result, the
// ingress side on the recorded ingress binding (#6960). Mirrors grpcapi.
//
// RangeInterfaces/RangeUnits skip present-but-nil InterfaceConfig/
// InterfaceUnit slots admitted by the tolerant load / HA config-sync path
// (#3494/#5068); a raw range nil-derefs and panics the in-process daemon
// during a REST session query (#5813).
func buildSessionIfaceNames(cfg *config.Config, lookupIfindex func(string) (int, error)) map[sessionEgressKey]string {
	names := make(map[sessionEgressKey]string)
	config.RangeInterfaces(cfg, func(ifName string, ifc *config.InterfaceConfig) {
		resolvedParent := config.LinuxIfName(strings.SplitN(cfg.ResolveReth(ifName), ".", 2)[0])
		parentIfindex, err := lookupIfindex(resolvedParent)
		if err != nil {
			return
		}
		config.RangeUnits(ifc, func(_ int, unit *config.InterfaceUnit) {
			displayName := ifName
			if unit.Number != 0 || unit.VlanID != 0 {
				displayName = fmt.Sprintf("%s.%d", ifName, unit.Number)
			}
			vlanID := uint16(unit.VlanID)
			if vlanID == 0 && unit.Number > 0 {
				vlanID = uint16(unit.Number)
			}
			key := sessionEgressKey{ifindex: uint32(parentIfindex), vlanID: vlanID}
			if _, exists := names[key]; !exists {
				names[key] = displayName
			}
		})
	})
	return names
}

// sessionQuery holds the parsed REST session filter predicates. It mirrors
// the gRPC sessionFilter subset that applies to the REST surface: zone,
// protocol, application, interface, nat-only and source-nat-pool (#3419
// M1/M3/M4). Pagination (limit/offset) is handled by the caller and is out
// of scope here (separate from #3421/#3423).
type sessionQuery struct {
	zone         uint16
	proto        string
	natOnly      bool
	app          string
	iface        string
	snatPool     string
	snatPoolNets []*net.IPNet
	// source/destination prefix + port filters (#3421 M2), mirroring the
	// gRPC sessionFilter src/dst predicates. A nil net / zero port means
	// "no filter" on that dimension.
	srcNet  *net.IPNet
	dstNet  *net.IPNet
	srcPort uint16
	dstPort uint16
	view    sessionView
}

// buildSessionQuery parses and validates the session filter query
// parameters. A non-empty but malformed/unresolved filter FAILS CLOSED
// with an error message (the caller emits HTTP 400) rather than silently
// matching every session — mirroring the gRPC sessionFilter.validate
// contract (#2934/#3439, and source-nat-pool not-found per #3419 M3).
func buildSessionQuery(r *http.Request, view sessionView) (sessionQuery, string) {
	q := sessionQuery{view: view}
	zoneFilter, ok := queryUint16Strict(r, "zone", 0)
	if !ok {
		return q, "invalid zone filter: " + r.URL.Query().Get("zone")
	}
	q.zone = zoneFilter
	q.proto = r.URL.Query().Get("protocol")
	if q.proto != "" {
		if _, ok := appid.ProtocolNumberLenient(q.proto); !ok {
			return q, "invalid protocol filter: " + q.proto
		}
	}
	q.app = r.URL.Query().Get("application")
	q.iface = r.URL.Query().Get("interface")
	q.snatPool = r.URL.Query().Get("source_nat_pool")
	if v := r.URL.Query().Get("nat_only"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return q, "invalid nat_only filter: " + v
		}
		q.natOnly = b
	}
	if q.snatPool != "" {
		if view.cfg == nil {
			return q, "source NAT pool " + q.snatPool + " not found"
		}
		nets, ok := config.SourceNATPoolNets(&view.cfg.Security.NAT, q.snatPool)
		if !ok {
			return q, "source NAT pool " + q.snatPool + " not found"
		}
		q.snatPoolNets = nets
	}

	// Source/destination prefix + port filters (#3421 M2). These FAIL
	// CLOSED on a malformed value (HTTP 400) rather than zeroing the
	// predicate and widening the query — matching the gRPC sessionFilter
	// contract.
	if sp := r.URL.Query().Get("source_prefix"); sp != "" {
		n, err := parseSessionPrefix(sp)
		if err != nil {
			return q, "invalid source_prefix filter: " + sp
		}
		q.srcNet = n
	}
	if dp := r.URL.Query().Get("destination_prefix"); dp != "" {
		n, err := parseSessionPrefix(dp)
		if err != nil {
			return q, "invalid destination_prefix filter: " + dp
		}
		q.dstNet = n
	}
	srcPort, ok := queryUint16Strict(r, "source_port", 0)
	if !ok {
		return q, "invalid source_port filter: " + r.URL.Query().Get("source_port")
	}
	q.srcPort = srcPort
	dstPort, ok := queryUint16Strict(r, "destination_port", 0)
	if !ok {
		return q, "invalid destination_port filter: " + r.URL.Query().Get("destination_port")
	}
	q.dstPort = dstPort

	return q, ""
}

// parseSessionPrefix parses an operator prefix filter — a CIDR or a bare IP
// (bare IPs become host networks). Mirrors pkg/grpcapi parseSessionPrefix.
func parseSessionPrefix(prefix string) (*net.IPNet, error) {
	cidr := prefix
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	return n, err
}

func (q *sessionQuery) matchV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if val.IsReverse != 0 {
		return false
	}
	if q.zone != 0 && val.IngressZone != q.zone && val.EgressZone != q.zone {
		return false
	}
	if q.proto != "" && !protoFilterMatches(key.Protocol, q.proto) {
		return false
	}
	if q.srcNet != nil && !q.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if q.dstNet != nil && !q.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if q.srcPort != 0 && ntohs(key.SrcPort) != q.srcPort {
		return false
	}
	if q.dstPort != 0 && ntohs(key.DstPort) != q.dstPort {
		return false
	}
	if q.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if q.app != "" && !appid.SessionMatches(q.app, q.view.appNames, q.view.cfg,
		key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID) {
		return false
	}
	if q.iface != "" {
		inIfs := resolveSessionIngressIfaces(val.IngressIfindex, val.IngressVlanID, val.IngressZone, q.view.zoneIfaces, q.view.egressIfaces)
		outIfs := resolveSessionEgressIfaces(val.FibIfindex, val.FibVlanID, val.EgressZone, q.view.zoneIfaces, q.view.egressIfaces)
		if !sessionIfaceMatchesAny(q.iface, inIfs) && !sessionIfaceMatchesAny(q.iface, outIfs) {
			return false
		}
	}
	if q.snatPool != "" {
		if val.Flags&dataplane.SessFlagSNAT == 0 || !config.IPInNets(uint32ToIP(val.NATSrcIP), q.snatPoolNets) {
			return false
		}
	}
	return true
}

func (q *sessionQuery) matchV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if val.IsReverse != 0 {
		return false
	}
	if q.zone != 0 && val.IngressZone != q.zone && val.EgressZone != q.zone {
		return false
	}
	if q.proto != "" && !protoFilterMatches(key.Protocol, q.proto) {
		return false
	}
	if q.srcNet != nil && !q.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if q.dstNet != nil && !q.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if q.srcPort != 0 && ntohs(key.SrcPort) != q.srcPort {
		return false
	}
	if q.dstPort != 0 && ntohs(key.DstPort) != q.dstPort {
		return false
	}
	if q.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if q.app != "" && !appid.SessionMatches(q.app, q.view.appNames, q.view.cfg,
		key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID) {
		return false
	}
	if q.iface != "" {
		inIfs := resolveSessionIngressIfaces(val.IngressIfindex, val.IngressVlanID, val.IngressZone, q.view.zoneIfaces, q.view.egressIfaces)
		outIfs := resolveSessionEgressIfaces(val.FibIfindex, val.FibVlanID, val.EgressZone, q.view.zoneIfaces, q.view.egressIfaces)
		if !sessionIfaceMatchesAny(q.iface, inIfs) && !sessionIfaceMatchesAny(q.iface, outIfs) {
			return false
		}
	}
	if q.snatPool != "" {
		if val.Flags&dataplane.SessFlagSNAT == 0 || !config.IPInNets(net.IP(val.NATSrcIP[:]), q.snatPoolNets) {
			return false
		}
	}
	return true
}

// sessionIfaceMatches matches a session interface against an operator
// filter, accepting either the exact unit name or a base-interface prefix
// (mirrors grpcapi).
func sessionIfaceMatches(filter, ifName string) bool {
	if ifName == "" {
		return false
	}
	return ifName == filter || strings.HasPrefix(ifName, filter+".")
}

// sessionIfaceMatchesAny reports whether ANY candidate interface name matches
// the operator's filter. A zone binds more than one interface, so a single
// name could only ever answer for the first (#6960). Mirrors grpcapi.
func sessionIfaceMatchesAny(filter string, ifNames []string) bool {
	for _, ifName := range ifNames {
		if sessionIfaceMatches(filter, ifName) {
			return true
		}
	}
	return false
}

// zoneBindsIface reports whether zoneMembers names the same logical interface
// as ifName. A zone binds "ge-0/0/0.0" where the {ifindex, VLAN} name map
// renders unit 0 as the bare "ge-0/0/0", and a zone may bind a PARENT to
// cover all of its units, so the comparison is the parent/unit equivalence
// sessionIfaceMatches uses, in both directions. Mirrors grpcapi.
func zoneBindsIface(zoneMembers []string, ifName string) bool {
	if ifName == "" {
		return false
	}
	for _, member := range zoneMembers {
		if member == "" {
			continue
		}
		if member == ifName ||
			strings.HasPrefix(member, ifName+".") ||
			strings.HasPrefix(ifName, member+".") {
			return true
		}
	}
	return false
}

// sessionIngressIfaceIdentity resolves the interface name a session's RECORDED
// ingress identity ({IngressIfindex, IngressVlanID}, stamped by the dataplane
// at install — #4983) names in the CURRENT interface table, and reports whether
// the session's own recorded ingress zone CORROBORATES it.
//
// The halves come from different points in time: the ifindex was recorded at
// install, the name map is rebuilt from the current config and current kernel
// ifindexes on every query. A kernel ifindex is RECYCLED — a tunnel or VLAN
// unit is destroyed and its number handed to another interface — so a stale
// ifindex can HIT the rebuilt map and name an interface the session never
// arrived on (#6987). An uncorroborated hit is not treated as fact.
//
// A rezoned interface produces the same disagreement as a recycled ifindex and
// the row cannot tell them apart. Because the filter feeds `clear` on the gRPC
// twin of this code, the tie breaks toward NOT acting on the name: an
// uncorroborated hit is a MISS and the zone answers instead. Mirrors grpcapi.
func sessionIngressIfaceIdentity(ingressIfindex uint32, ingressVlanID uint16, ingressZone uint16, zoneIfaces map[uint16][]string, egressIfaces map[sessionEgressKey]string) (string, bool) {
	if ingressIfindex == 0 {
		return "", false
	}
	ifName := egressIfaces[sessionEgressKey{ifindex: ingressIfindex, vlanID: ingressVlanID}]
	if ifName == "" {
		return "", false
	}
	return ifName, zoneBindsIface(zoneIfaces[ingressZone], ifName)
}

// resolveSessionIngressIfaces resolves a session's candidate INGRESS interface
// names for filter matching: the single interface a corroborated identity
// names, else EVERY interface bound to the ingress zone. Ingress identity 0
// (the reverse companion, an HA peer-synced row, the host-outbound GRE path),
// an ifindex the config cannot name, and an uncorroborated hit all take that
// fallback. Mirrors grpcapi.
func resolveSessionIngressIfaces(ingressIfindex uint32, ingressVlanID uint16, ingressZone uint16, zoneIfaces map[uint16][]string, egressIfaces map[sessionEgressKey]string) []string {
	if ifName, corroborated := sessionIngressIfaceIdentity(ingressIfindex, ingressVlanID, ingressZone, zoneIfaces, egressIfaces); corroborated {
		return []string{ifName}
	}
	return zoneIfaces[ingressZone]
}

// resolveSessionEgressIfaces resolves a session's candidate EGRESS interface
// names from its FIB result, falling back to EVERY interface bound to the
// egress zone (#6960). Mirrors grpcapi.
func resolveSessionEgressIfaces(fibIfindex uint32, fibVlanID uint16, egressZone uint16, zoneIfaces map[uint16][]string, egressIfaces map[sessionEgressKey]string) []string {
	if fibIfindex != 0 {
		if ifName, ok := egressIfaces[sessionEgressKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
			return []string{ifName}
		}
	}
	return zoneIfaces[egressZone]
}

// sessionIngressIfaceDisplay resolves the single interface name to REPORT for a
// session's ingress, or "" when no name is defensible and the caller should
// report the zone instead. Reporting is stricter than filtering: a name in an
// interface field is read as fact, so it is printed only for a corroborated
// identity or for a zone that binds exactly one interface. An UNCORROBORATED
// hit prints nothing even then — the row carries positive evidence that the
// interface table and the recorded zone disagree (#6987). Mirrors grpcapi.
func sessionIngressIfaceDisplay(ingressIfindex uint32, ingressVlanID uint16, ingressZone uint16, zoneIfaces map[uint16][]string, egressIfaces map[sessionEgressKey]string) string {
	ifName, corroborated := sessionIngressIfaceIdentity(ingressIfindex, ingressVlanID, ingressZone, zoneIfaces, egressIfaces)
	if corroborated {
		return ifName
	}
	// An UNCORROBORATED hit reports nothing, even when the zone binds exactly
	// one interface: the row carries positive evidence that the interface
	// table and its own recorded ingress zone disagree, which is the one case
	// where a confident name is most likely to be the wrong one (#6987).
	if ifName != "" {
		return ""
	}
	return zoneDisplayIface(zoneIfaces[ingressZone])
}

// sessionEgressIfaceDisplay is the egress counterpart: the FIB-resolved name,
// else the egress zone's single bound interface, else "". Mirrors grpcapi.
func sessionEgressIfaceDisplay(fibIfindex uint32, fibVlanID uint16, egressZone uint16, zoneIfaces map[uint16][]string, egressIfaces map[sessionEgressKey]string) string {
	if fibIfindex != 0 {
		if ifName, ok := egressIfaces[sessionEgressKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
			return ifName
		}
	}
	return zoneDisplayIface(zoneIfaces[egressZone])
}

// zoneDisplayIface is the zone-derived interface name to report when a session
// carries no usable identity: the zone's interface when it binds exactly ONE,
// else "" so the caller reports the zone.
//
// With one member the zone approximation has exactly one answer, so it is not
// an approximation. With two or more, naming the first is one interface
// answering for all of its siblings — the reporting counterpart of the #6960
// filter defect, and a claim the row does not support (#6987).
func zoneDisplayIface(zoneMembers []string) string {
	if len(zoneMembers) == 1 {
		return zoneMembers[0]
	}
	return ""
}

func sessionEntryV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64, view sessionView) SessionEntry {
	inIf := sessionIngressIfaceDisplay(val.IngressIfindex, val.IngressVlanID, val.IngressZone, view.zoneIfaces, view.egressIfaces)
	if inIf == "" {
		inIf = view.zoneNames[val.IngressZone]
	}
	outIf := sessionEgressIfaceDisplay(val.FibIfindex, val.FibVlanID, val.EgressZone, view.zoneIfaces, view.egressIfaces)
	if outIf == "" {
		outIf = view.zoneNames[val.EgressZone]
	}
	se := SessionEntry{
		SrcAddr:  net.IP(key.SrcIP[:]).String(),
		DstAddr:  net.IP(key.DstIP[:]).String(),
		SrcPort:  ntohs(key.SrcPort),
		DstPort:  ntohs(key.DstPort),
		Protocol: protoName(key.Protocol),
		State:    sessionStateName(val.State),
		PolicyID: val.PolicyID,
		// #4626: reserved ids must not be resolved through the compiled map.
		PolicyName:       dataplane.SessionPolicyName(view.policyNames, val.PolicyID),
		IngressZoneName:  view.zoneNames[val.IngressZone],
		EgressZoneName:   view.zoneNames[val.EgressZone],
		InZone:           val.IngressZone,
		OutZone:          val.EgressZone,
		IngressInterface: inIf,
		EgressInterface:  outIf,
		Application:      appid.ResolveSessionName(view.appNames, view.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID),
		FwdPackets:       val.FwdPackets,
		FwdBytes:         val.FwdBytes,
		RevPackets:       val.RevPackets,
		RevBytes:         val.RevBytes,
		Timeout:          val.Timeout,
		SessionID:        val.SessionID,
		HAActive:         view.haActive,
	}
	if val.Created > 0 && now > val.Created {
		se.Age = int64(now - val.Created)
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.Idle = int64(now - val.LastSeen)
	}
	var natParts []string
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("SNAT %s:%d", uint32ToIP(val.NATSrcIP), ntohs(val.NATSrcPort)))
		se.NATSrcAddr = uint32ToIP(val.NATSrcIP).String()
		se.NATSrcPort = ntohs(val.NATSrcPort)
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("DNAT %s:%d", uint32ToIP(val.NATDstIP), ntohs(val.NATDstPort)))
		se.NATDstAddr = uint32ToIP(val.NATDstIP).String()
		se.NATDstPort = ntohs(val.NATDstPort)
	}
	se.NAT = strings.Join(natParts, "; ")
	return se
}

func sessionEntryV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64, view sessionView) SessionEntry {
	inIf := sessionIngressIfaceDisplay(val.IngressIfindex, val.IngressVlanID, val.IngressZone, view.zoneIfaces, view.egressIfaces)
	if inIf == "" {
		inIf = view.zoneNames[val.IngressZone]
	}
	outIf := sessionEgressIfaceDisplay(val.FibIfindex, val.FibVlanID, val.EgressZone, view.zoneIfaces, view.egressIfaces)
	if outIf == "" {
		outIf = view.zoneNames[val.EgressZone]
	}
	se := SessionEntry{
		SrcAddr:  net.IP(key.SrcIP[:]).String(),
		DstAddr:  net.IP(key.DstIP[:]).String(),
		SrcPort:  ntohs(key.SrcPort),
		DstPort:  ntohs(key.DstPort),
		Protocol: protoName(key.Protocol),
		State:    sessionStateName(val.State),
		PolicyID: val.PolicyID,
		// #4626: reserved ids must not be resolved through the compiled map.
		PolicyName:       dataplane.SessionPolicyName(view.policyNames, val.PolicyID),
		IngressZoneName:  view.zoneNames[val.IngressZone],
		EgressZoneName:   view.zoneNames[val.EgressZone],
		InZone:           val.IngressZone,
		OutZone:          val.EgressZone,
		IngressInterface: inIf,
		EgressInterface:  outIf,
		Application:      appid.ResolveSessionName(view.appNames, view.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID),
		FwdPackets:       val.FwdPackets,
		FwdBytes:         val.FwdBytes,
		RevPackets:       val.RevPackets,
		RevBytes:         val.RevBytes,
		Timeout:          val.Timeout,
		SessionID:        val.SessionID,
		HAActive:         view.haActive,
	}
	if val.Created > 0 && now > val.Created {
		se.Age = int64(now - val.Created)
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.Idle = int64(now - val.LastSeen)
	}
	var natParts []string
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("SNAT [%s]:%d", net.IP(val.NATSrcIP[:]).String(), ntohs(val.NATSrcPort)))
		se.NATSrcAddr = net.IP(val.NATSrcIP[:]).String()
		se.NATSrcPort = ntohs(val.NATSrcPort)
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("DNAT [%s]:%d", net.IP(val.NATDstIP[:]).String(), ntohs(val.NATDstPort)))
		se.NATDstAddr = net.IP(val.NATDstIP[:]).String()
		se.NATDstPort = ntohs(val.NATDstPort)
	}
	se.NAT = strings.Join(natParts, "; ")
	return se
}

// monotonicSeconds returns the current monotonic clock in seconds,
// matching BPF's bpf_ktime_get_ns() / 1e9.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// protoFilterMatches matches a session protocol against an operator filter
// string: a case-insensitive protocol name (tcp/udp/icmp/icmpv6/...) OR a
// numeric IP protocol number ("6" matches TCP, "47" matches GRE). This
// mirrors the gRPC (pkg/grpcapi server_sessions.go protoFilterMatches) and
// CLI (pkg/cli monitor) contract; REST previously did a case-SENSITIVE
// string compare with no numeric form, so protocol=tcp and protocol=6
// silently returned an empty result (#2935).
func protoFilterMatches(p uint8, filter string) bool {
	if strings.EqualFold(protoName(p), filter) {
		return true
	}
	if n, err := strconv.Atoi(filter); err == nil {
		return n == int(p)
	}
	return false
}

// protoName renders an IP protocol number for the REST surface. The named
// protocol SET is owned by appid.ProtocolName (the #2949 SSOT shared with gRPC
// and the catalog) so a NAMED `protocol=gre` REST filter matches and GRE/ESP/
// IPIP/IPv6 sessions display named instead of numeric. Casing is a REST-local
// concern: REST has always rendered upper-case (TCP/UDP/ICMP/ICMPv6), so the
// canonical lowercase name is upper-cased here. ICMPv6 keeps its mixed-case
// spelling to match the historical REST rendering.
func protoName(p uint8) string {
	name := appid.ProtocolName(p)
	if name == "" {
		return fmt.Sprintf("%d", p)
	}
	if p == dataplane.ProtoICMPv6 {
		return "ICMPv6"
	}
	return strings.ToUpper(name)
}

// --- Cursor page-token codec (#3421 H4) ---
//
// Token format mirrors the gRPC surface (pkg/grpcapi/server_sessions.go):
//
//	"v4:<hex-key>"  — resume v4 iteration after this key, then v6
//	"v6:<hex-key>"  — v4 done, resume v6 iteration after this key
//	"v6start"       — v4 done, start v6 from the beginning
//
// The blob is base64url(rawkind+":"+hex(key-bytes)). Tokens encode local
// session-map keys and are only meaningful on the node that issued them;
// they are opaque to clients.

func encodePageTokenV4(key dataplane.SessionKey) string {
	// Emit exactly binary.Size(key) bytes so the token is byte-identical to the
	// gRPC surface's canonical key layout (#5649): the trailing pad bytes are
	// zero-filled by make and the decoder requires this exact length.
	b := make([]byte, binary.Size(key))
	copy(b[0:4], key.SrcIP[:])
	copy(b[4:8], key.DstIP[:])
	binary.NativeEndian.PutUint16(b[8:10], key.SrcPort)
	binary.NativeEndian.PutUint16(b[10:12], key.DstPort)
	b[12] = key.Protocol
	// pad bytes b[13:16]
	return base64.RawURLEncoding.EncodeToString([]byte("v4:" + hex.EncodeToString(b)))
}

func encodePageTokenV6(key dataplane.SessionKeyV6) string {
	// Emit exactly binary.Size(key) bytes — see encodePageTokenV4 (#5649).
	b := make([]byte, binary.Size(key))
	copy(b[0:16], key.SrcIP[:])
	copy(b[16:32], key.DstIP[:])
	binary.NativeEndian.PutUint16(b[32:34], key.SrcPort)
	binary.NativeEndian.PutUint16(b[34:36], key.DstPort)
	b[36] = key.Protocol
	// pad bytes b[37:40]
	return base64.RawURLEncoding.EncodeToString([]byte("v6:" + hex.EncodeToString(b)))
}

// maxPageTokenLen caps the encoded page_token before any base64/hex decode
// (#5649, C181-C11 — ported from the gRPC surface). The longest legitimate
// token is "v6:" plus the hex of a SessionKeyV6 (base64 of ~83 bytes, under
// 128); anything larger is noncanonical. Without this cap a caller could send a
// token near the HTTP body limit and force transient base64/hex allocations
// many times the key size before the ABI prefix decode discards the excess. 256
// leaves ample headroom for the real formats while rejecting the amplification.
const maxPageTokenLen = 256

// parseSessionPageToken returns the token kind ("v4", "v6", "v6start") and
// the raw key bytes (nil for "v6start").
func parseSessionPageToken(token string) (kind string, keyBytes []byte, err error) {
	if len(token) > maxPageTokenLen {
		return "", nil, fmt.Errorf("page_token too long: %d bytes", len(token))
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", nil, fmt.Errorf("invalid page_token encoding: %w", err)
	}
	str := string(raw)
	if str == "v6start" {
		return "v6start", nil, nil
	}
	switch {
	case strings.HasPrefix(str, "v4:"):
		b, err := hex.DecodeString(str[3:])
		if err != nil {
			return "", nil, fmt.Errorf("invalid v4 page_token hex: %w", err)
		}
		return "v4", b, nil
	case strings.HasPrefix(str, "v6:"):
		b, err := hex.DecodeString(str[3:])
		if err != nil {
			return "", nil, fmt.Errorf("invalid v6 page_token hex: %w", err)
		}
		return "v6", b, nil
	}
	return "", nil, fmt.Errorf("invalid page_token prefix")
}

func decodeSessionKeyV4(b []byte) (dataplane.SessionKey, error) {
	var key dataplane.SessionKey
	// #5649 (C181-C11, ported from gRPC): require the EXACT ABI key length. A `<`
	// check accepted trailing bytes, so many distinct oversized tokens hex-decoded
	// to the same cursor (a noncanonical opaque token) and amplified allocations.
	// The encoder always emits exactly binary.Size(key) bytes.
	if len(b) != binary.Size(key) {
		return key, fmt.Errorf("v4 key wrong length: %d (want %d)", len(b), binary.Size(key))
	}
	copy(key.SrcIP[:], b[0:4])
	copy(key.DstIP[:], b[4:8])
	key.SrcPort = binary.NativeEndian.Uint16(b[8:10])
	key.DstPort = binary.NativeEndian.Uint16(b[10:12])
	key.Protocol = b[12]
	return key, nil
}

func decodeSessionKeyV6(b []byte) (dataplane.SessionKeyV6, error) {
	var key dataplane.SessionKeyV6
	// #5649 (C181-C11, ported from gRPC): exact ABI key length — see
	// decodeSessionKeyV4.
	if len(b) != binary.Size(key) {
		return key, fmt.Errorf("v6 key wrong length: %d (want %d)", len(b), binary.Size(key))
	}
	copy(key.SrcIP[:], b[0:16])
	copy(key.DstIP[:], b[16:32])
	key.SrcPort = binary.NativeEndian.Uint16(b[32:34])
	key.DstPort = binary.NativeEndian.Uint16(b[34:36])
	key.Protocol = b[36]
	return key, nil
}
