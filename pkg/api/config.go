package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// restConfigSessionHeader carries the server-generated identity of a REST
// configuration session (#6197). POST /config/enter allocates a distinct,
// unguessable token for each session and returns it as session_id; subsequent
// holder-scoped requests must echo it in this header. Keeping the identity in
// a header gives bodyless operations (commit/confirm/exit) and JSON-body
// operations one uniform contract.
const restConfigSessionHeader = "X-Config-Session"

const (
	restConfigSessionPrefix     = "rest-"
	restConfigSessionTokenBytes = 16
)

// newRESTConfigSessionID creates a holder identity in a namespace that cannot
// collide with gRPC's conn-* identities. crypto/rand makes accidental sharing
// between independent REST clients negligible and prevents one client from
// guessing another client's holder token.
func newRESTConfigSessionID() (string, error) {
	var token [restConfigSessionTokenBytes]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate REST config session: %w", err)
	}
	return restConfigSessionPrefix + hex.EncodeToString(token[:]), nil
}

func validRESTConfigSessionID(sessionID string) bool {
	if !strings.HasPrefix(sessionID, restConfigSessionPrefix) {
		return false
	}
	raw := strings.TrimPrefix(sessionID, restConfigSessionPrefix)
	if len(raw) != restConfigSessionTokenBytes*2 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

// restConfigSessionID reads and validates the holder identity supplied by a
// follow-up REST config request. Missing/malformed identities fail closed
// before the store is called, so they can never reach its sessionID==""
// internal/system bypass.
func restConfigSessionID(w http.ResponseWriter, r *http.Request) (string, bool) {
	sessionID := strings.TrimSpace(r.Header.Get(restConfigSessionHeader))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "missing "+restConfigSessionHeader+" header")
		return "", false
	}
	if !validRESTConfigSessionID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid "+restConfigSessionHeader+" header")
		return "", false
	}
	return sessionID, true
}

// writeConfigMutationError maps a config-store mutation error to an HTTP
// status. A holder-lock conflict (ErrConfigLockedByOther) — a REST mutation
// attempted while a CLI/gRPC session owns the shared candidate (#5870) — is a
// 409 Conflict, matching configEnterHandler's lock response; every other error
// (parse/validation/not-in-config-mode) stays a 400 Bad Request.
func writeConfigMutationError(w http.ResponseWriter, err error) {
	if errors.Is(err, configstore.ErrConfigLockedByOther) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func (s *Server) configHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, nil)
		return
	}
	writeOK(w, cfg)
}
func (s *Server) mutationPlantClass(r *http.Request) (string, error) {
	p, ok := authorizedMutationPrincipal(r)
	if !ok {
		return "", errors.New("authorized mutation principal is unavailable")
	}
	if p.Superuser {
		return config.EventPlantClassSuperuser, nil
	}
	if p.Class == "" {
		return "", errors.New("authenticated principal has no login class")
	}
	return p.Class, nil
}

func (s *Server) configEnterHandler(w http.ResponseWriter, r *http.Request) {
	// An absent header starts a new session. Supplying the token returned by an
	// earlier successful enter re-enters that same session and refreshes its
	// idle lease; a different token remains a conflicting entrant.
	sessionID := strings.TrimSpace(r.Header.Get(restConfigSessionHeader))
	if sessionID == "" {
		var err error
		sessionID, err = newRESTConfigSessionID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else if !validRESTConfigSessionID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid "+restConfigSessionHeader+" header")
		return
	}

	if err := s.store.EnterConfigureSession(sessionID); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok", "session_id": sessionID})
}

func (s *Server) configExitHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	// Release only the candidate held by this REST session. A stale or foreign
	// token cannot clear another client's work.
	s.store.ExitConfigureSession(sessionID)
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configStatusHandler(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, ConfigModeStatus{
		InConfigMode:   s.store.InConfigMode(),
		Dirty:          s.store.IsDirty(),
		ConfirmPending: s.store.IsConfirmPending(),
	})
}

func (s *Server) configSetHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	plantClass, err := s.mutationPlantClass(r)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	if err := s.store.SetFromInputAsPlantClass(sessionID, plantClass, req.Input); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}
func (s *Server) configDeleteHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	plantClass, err := s.mutationPlantClass(r)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	if err := s.store.DeleteFromInputAsPlantClass(sessionID, plantClass, req.Input); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

// configDeactivateHandler marks a candidate node inactive (#2051), the REST
// equivalent of the interactive `deactivate <path>` verb. The request body's
// Input is the bare path (no verb), mirroring configSetHandler. It routes
// through DeactivateFromInput so the verb logic stays in the store's
// applyEditLine switch and the path is never mangled into a junk "set" node.
func (s *Server) configDeactivateHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	plantClass, err := s.mutationPlantClass(r)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	if err := s.store.DeactivateFromInputAsPlantClass(sessionID, plantClass, req.Input); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

// configActivateHandler clears the inactive marker on a candidate node
// (#2051), the REST equivalent of the interactive `activate <path>` verb.
func (s *Server) configActivateHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Input == "" {
		writeError(w, http.StatusBadRequest, "input required")
		return
	}
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	plantClass, err := s.mutationPlantClass(r)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	if err := s.store.ActivateFromInputAsPlantClass(sessionID, plantClass, req.Input); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	// #5870: only the config-lock holder may commit the shared candidate. Reject
	// a REST commit before it can confirm/apply another (CLI/gRPC) session's
	// pending work — the empty-session commit path previously let a stateless
	// REST caller smuggle another operator's staged edits into an applied
	// commit. Mirrors the gRPC Commit gate (pkg/grpcapi/server_config.go).
	// #6808: mint the commit AUTHORITY under the same store-lock acquisition
	// that verifies the holder, and carry it into the callback. The previous
	// form verified the holder here and then invoked a callback carrying NO
	// identity, so the lock could turn over in between — the holder exits,
	// disconnects, or is reclaimed on its idle lease, another session enters and
	// stages different edits — and this already-authorized commit would promote
	// the NEW holder's candidate. The authority is re-verified against the live
	// holder epoch at promotion, under the store lock.
	authority, err := s.store.AuthorizeCommit(sessionID)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}

	// Bare commit during a pending commit-confirmed window (#4000). Confirm
	// the pending config only when the candidate is UNCHANGED; new staged
	// edits fall through to the normal commit below, where commitFn applies
	// them AND clears the timer (#3861), so they are committed rather than
	// silently dropped.
	if s.store.IsConfirmPending() && !s.store.IsDirty() {
		if err := s.store.ConfirmCommitAs(sessionID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w, map[string]string{"status": "ok"})
		return
	}

	if s.commitFn == nil {
		writeError(w, http.StatusInternalServerError, "commit handler not wired")
		return
	}
	compiled, err := s.commitFn(r.Context(), authority, "")
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			writeError(w, http.StatusServiceUnavailable, "commit busy: "+err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeOK(w, commitResponseFromConfig(compiled))
}

func (s *Server) configCommitCheckHandler(w http.ResponseWriter, _ *http.Request) {
	compiled, err := s.store.CommitCheck()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, commitResponseFromConfig(compiled))
}

func (s *Server) configRollbackHandler(w http.ResponseWriter, r *http.Request) {
	var req ConfigRollbackRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	// #4589 A8-01: mirror the gRPC Rollback guard. n==0 = revert to active
	// (valid); a negative n reaches history.Get(<0) and surfaces the opaque
	// "history position -1 out of range" store error. Reject up front.
	if req.N < 0 {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("invalid n %d: rollback index must be non-negative (0 = revert to active)", req.N))
		return
	}
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	// #5870: rollback replaces the candidate, so it runs under the REST holder
	// identity and is rejected when a CLI/gRPC session owns the candidate.
	plantClass, err := s.mutationPlantClass(r)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	if err := s.store.RollbackAsPlantClass(sessionID, plantClass, req.N); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configShowHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	target := r.URL.Query().Get("target")

	// #9324: an ABSENT ?target renders the ACTIVE configuration.
	//
	// It used to fall through to the CANDIDATE, so a PermView caller that
	// omitted the parameter read another session's uncommitted work — and on an
	// idle box got an empty string, so a config-backup client written without
	// `?target=active` archived either nothing or somebody's draft and could not
	// tell which. GET /api/v1/config/export already always renders ACTIVE, which
	// is the in-tree precedent for what the default should be, and operational
	// `show configuration` on Junos renders the committed configuration.
	//
	// Unlike the gRPC twin this surface CAN distinguish absent from explicit —
	// `?target` is a string, not a proto3 enum whose zero value is CANDIDATE —
	// so the default is fixed here rather than only priced. An explicit
	// `?target=candidate` is still a legitimate request and still works; it now
	// requires PermConfig (readAuthz, pkg/api/authz.go).
	//
	// An UNRECOGNISED target is refused rather than silently treated as one of
	// them: falling through on `?target=activ` is the same fail-open shape as
	// the default this fixes.
	var output string
	switch target {
	case "", "active":
		switch format {
		case "set":
			output = s.store.ShowActiveSetRedacted(nil)
		case "json":
			output = s.store.ShowActiveJSONRedacted(nil)
		case "xml":
			output = s.store.ShowActiveXMLRedacted(nil)
		default:
			output = s.store.ShowActiveRedacted(nil)
		}
	case "candidate":
		switch format {
		case "set":
			output = s.store.ShowCandidateSetRedacted(nil)
		case "json":
			output = s.store.ShowCandidateJSONRedacted(nil)
		case "xml":
			output = s.store.ShowCandidateXMLRedacted(nil)
		default:
			output = s.store.ShowCandidateRedacted(nil)
		}
	default:
		writeError(w, http.StatusBadRequest,
			"unsupported target: "+target+"; use active or candidate")
		return
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configExportHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "set"
	}
	var output string
	switch format {
	case "set":
		output = s.store.ShowActiveSetRedacted(nil)
	case "text":
		output = s.store.ShowActiveRedacted(nil)
	case "json":
		output = s.store.ShowActiveJSONRedacted(nil)
	case "xml":
		output = s.store.ShowActiveXMLRedacted(nil)
	default:
		writeError(w, http.StatusBadRequest, "unsupported format: "+format+"; use set, text, json, or xml")
		return
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configCompareHandler(w http.ResponseWriter, r *http.Request) {
	// #3443: rollback is a change-control selector — fail closed on a
	// malformed/negative value instead of silently defaulting to 0
	// (candidate-vs-active), which would compare the wrong target. An
	// absent parameter keeps the documented default of 0.
	rollbackN, ok := queryIntStrict(r, "rollback", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid rollback parameter: must be a non-negative integer")
		return
	}
	if rollbackN > 0 {
		diff, err := s.store.ShowCompareRollbackRedacted(rollbackN)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeOK(w, TextResponse{Output: diff})
		return
	}
	writeOK(w, TextResponse{Output: s.store.ShowCompareRedacted()})
}

func (s *Server) configHistoryHandler(w http.ResponseWriter, _ *http.Request) {
	entries := s.store.ListHistory()
	result := make([]HistoryEntry, len(entries))
	for i, e := range entries {
		result[i] = HistoryEntry{
			Index:     i + 1,
			Timestamp: e.Timestamp.Format("2006-01-02 15:04:05"),
		}
	}
	writeOK(w, result)
}

// maxConfigSearchQueryLen bounds the search substring. No real config token is
// anywhere near this long, so a longer q is a malformed/abusive request rather
// than a legitimate search — reject it instead of running an O(q × lines)
// Contains scan for every line of the render (#5250 A8-b1 F2).
const maxConfigSearchQueryLen = 256

// maxConfigSearchResults caps the number of matching lines configSearchHandler
// returns. A broad query (e.g. a single space) over a large ≤16 MiB render
// would otherwise build an unbounded result slice and spike RSS/GC. When the
// cap is reached the response carries an X-Result-Truncated: true header so the
// caller can tell the match set was clipped (#5250 A8-b1 F2).
const maxConfigSearchResults = 500

// searchConfigLines returns up to maxResults ConfigSearchResults whose line
// contains query, and reports whether more matches existed past the cap.
func searchConfigLines(text, query string, maxResults int) (results []ConfigSearchResult, truncated bool) {
	for i, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, query) {
			continue
		}
		if len(results) >= maxResults {
			// At least one more match exists beyond the cap.
			return results, true
		}
		results = append(results, ConfigSearchResult{LineNumber: i + 1, Line: line})
	}
	return results, false
}

func (s *Server) configSearchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeError(w, http.StatusBadRequest, "missing q parameter")
		return
	}
	if len(query) > maxConfigSearchQueryLen {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("q too long: %d bytes (max %d)", len(query), maxConfigSearchQueryLen))
		return
	}
	// Search over the redacted render so a matching line never returns a
	// cleartext secret in its snippet (#4051).
	text := s.store.ShowActiveRedacted(nil)
	results, truncated := searchConfigLines(text, query, maxConfigSearchResults)
	if truncated {
		w.Header().Set("X-Result-Truncated", "true")
	}
	writeOK(w, results)
}

func (s *Server) configLoadHandler(w http.ResponseWriter, r *http.Request) {
	// Bound the request body (M-7 shared decoder, 16 MiB -> 413) so an
	// oversized config-load payload is rejected at the transport before it
	// reaches the parser (H-2). configstore.LoadOverride/LoadMerge/LoadSet
	// re-check the decoded content against MaxConfigSize (also 16 MiB), the
	// transport-independent parser-layer ceiling.
	var req ConfigLoadRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content required")
		return
	}
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	plantClass, err := s.mutationPlantClass(r)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	switch req.Mode {
	case "override":
		if err := s.store.LoadOverrideAsPlantClass(sessionID, plantClass, req.Content); err != nil {
			writeConfigMutationError(w, err)
			return
		}
	case "merge", "":
		if err := s.store.LoadMergeAsPlantClass(sessionID, plantClass, req.Content); err != nil {
			writeConfigMutationError(w, err)
			return
		}
	case "set":
		count, err := s.store.LoadSetAsPlantClass(sessionID, plantClass, req.Content)
		if err != nil {
			writeConfigMutationError(w, err)
			return
		}
		slog.Info("load set applied", "commands", count)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown load mode: %s (use 'override', 'merge', or 'set')", req.Mode))
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitConfirmedHandler(w http.ResponseWriter, r *http.Request) {
	var req CommitConfirmedRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	// #5870: only the config-lock holder may commit the shared candidate.
	// Mirrors the gRPC CommitConfirmed gate.
	// #6808: mint the commit AUTHORITY under the same store-lock acquisition
	// that verifies the holder, and carry it into the callback. The previous
	// form verified the holder here and then invoked a callback carrying NO
	// identity, so the lock could turn over in between — the holder exits,
	// disconnects, or is reclaimed on its idle lease, another session enters and
	// stages different edits — and this already-authorized commit would promote
	// the NEW holder's candidate. The authority is re-verified against the live
	// holder epoch at promotion, under the store lock.
	authority, err := s.store.AuthorizeCommit(sessionID)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	if s.commitConfirmedFn == nil {
		writeError(w, http.StatusInternalServerError, "commit-confirmed handler not wired")
		return
	}
	compiled, err := s.commitConfirmedFn(r.Context(), authority, req.Minutes)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			writeError(w, http.StatusServiceUnavailable, "commit busy: "+err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeOK(w, commitResponseFromConfig(compiled))
}

func (s *Server) configConfirmHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	// #5870: confirming a pending commit-confirmed is a holder-scoped op — only
	// the REST-held candidate may be confirmed from REST; a CLI/gRPC holder's
	// pending window is rejected (ErrConfigLockedByOther → 409).
	if err := s.store.ConfirmCommitAs(sessionID); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configShowRollbackHandler(w http.ResponseWriter, r *http.Request) {
	// #3443: n selects a 1-based rollback slot. Fail closed on a
	// malformed/negative value instead of silently defaulting to slot 1,
	// which would show a different rollback than the operator asked for.
	n, ok := queryIntStrict(r, "n", 1)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid n parameter: must be a non-negative integer")
		return
	}
	// #4556 M-01: n selects a 1-based rollback slot. 0 is a canonical
	// non-negative uint that clears queryIntStrict but then maps to
	// history.Get(n-1) = history.Get(-1) → the opaque store error
	// "history position -1 out of range". Reject n<=0 up front with a
	// clear positive-integer message (queryIntStrict already fails a
	// negative literal, so in practice this catches n=0), mirroring the
	// gRPC ShowRollback leg and the ShowCompare rollback_n guard.
	if n <= 0 {
		writeError(w, http.StatusBadRequest, "invalid n parameter: rollback index must be a positive integer")
		return
	}
	format := r.URL.Query().Get("format")

	var output string
	var err error
	if format == "set" {
		output, err = s.store.ShowRollbackSetRedacted(n)
	} else {
		output, err = s.store.ShowRollbackRedacted(n)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) configAnnotateHandler(w http.ResponseWriter, r *http.Request) {
	var req AnnotateRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Path == "" || req.Comment == "" {
		writeJSON(w, http.StatusBadRequest, Response{Error: "path and comment are required"})
		return
	}
	sessionID, ok := restConfigSessionID(w, r)
	if !ok {
		return
	}
	pathParts := strings.Fields(req.Path)
	// #5870: annotate mutates the candidate, so it runs under the REST holder
	// identity and is rejected when a CLI/gRPC session owns the candidate. A
	// holder conflict maps to 409 Conflict; other errors stay 400.
	if err := s.store.AnnotateAs(sessionID, pathParts, req.Comment); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, configstore.ErrConfigLockedByOther) {
			status = http.StatusConflict
		}
		writeJSON(w, status, Response{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, Response{Success: true})
}

type configCommitResponse struct {
	Status   string   `json:"status"`
	Warnings []string `json:"warnings,omitempty"`
}

func commitResponseFromConfig(cfg *config.Config) configCommitResponse {
	resp := configCommitResponse{Status: "ok"}
	if cfg != nil && len(cfg.Warnings) > 0 {
		resp.Warnings = append([]string(nil), cfg.Warnings...)
	}
	return resp
}
