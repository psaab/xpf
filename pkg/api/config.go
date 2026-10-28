package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/authz"
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

// restSessionBindingKey is the identity a REST config-session token is bound
// to at mint (#16069). It is derived server-side from the authorized principal
// — never from caller-supplied data — so two principals are distinct even when
// they share a login class, and the same principal re-derives the same key on
// every request. Without this binding the 128-bit token alone was the holder
// identity: any equally-privileged insider who obtained another operator's
// token could commit or release that operator's candidate. The gRPC twin
// never had the hole because its holder is the kernel connection identity.
func restSessionBindingKey(p authz.Principal) string {
	if p.Superuser {
		if p.Username != "" {
			return fmt.Sprintf("%s|uid=%d|user=%s|superuser", p.Source.String(), p.UID, p.Username)
		}
		return fmt.Sprintf("%s|uid=%d|superuser", p.Source.String(), p.UID)
	}
	return fmt.Sprintf("%s|uid=%d|user=%s|class=%s", p.Source.String(), p.UID, p.Username, p.Class)
}

// restSessionOwner resolves the binding key for the current request. Mutation
// routes are gated by the authz middleware, which installs the principal; a
// missing principal fails closed instead of binding to a shared empty key.
func restSessionOwner(r *http.Request) (string, bool) {
	p, ok := authorizedMutationPrincipal(r)
	if !ok {
		return "", false
	}
	return restSessionBindingKey(p), true
}

// restSessionBinding is the recorded mint of one REST config-session token:
// the binding key of the principal that minted it plus the store holder
// epoch observed immediately after that mint acquired/re-affirmed the
// holder. The epoch makes release generation-checked: an exit that
// releases holder generation N may only erase a binding minted at
// generation N, never a binding a concurrent re-entry installed for a
// later generation of the same token.
type restSessionBinding struct {
	owner string
	epoch uint64
}

// bindRESTSessionLocked records that sessionID is held by owner at store
// holder epoch epoch. Callers MUST hold restSessionsMu and MUST call this
// under the same lock hold as the store EnterConfigureSession that
// acquired/re-affirmed the holder, so the binding and the store holder
// change atomically with respect to every other bind/unbind/verify.
func (s *Server) bindRESTSessionLocked(sessionID, owner string, epoch uint64) {
	if s.restSessions == nil {
		s.restSessions = make(map[string]restSessionBinding)
	}
	s.restSessions[sessionID] = restSessionBinding{owner: owner, epoch: epoch}
}

// unbindRESTSessionLocked drops the binding for sessionID only when it is
// still the exact binding (owner AND holder generation) the caller
// observed before releasing the store holder. Callers MUST hold
// restSessionsMu across the store ExitConfigureSession and this call: a
// concurrent same-token re-entry that installed a newer-generation
// binding is therefore never erased by a stale exit. Returns whether a
// binding was erased.
func (s *Server) unbindRESTSessionLocked(sessionID, owner string, epoch uint64) bool {
	bound, ok := s.restSessions[sessionID]
	if !ok || bound.owner != owner || bound.epoch != epoch {
		return false
	}
	delete(s.restSessions, sessionID)
	return true
}

// verifyRESTSessionOwner reports whether owner minted sessionID. A session
// with no binding (entered directly in the store by a CLI/gRPC/internal path
// or a test fixture) carries no REST owner to check against — the store's own
// holder check remains the gate there, exactly as for the conn-* identities.
// A bound session presented by a different principal is denied before the
// store is called.
func (s *Server) verifyRESTSessionOwner(sessionID, owner string) bool {
	s.restSessionsMu.Lock()
	defer s.restSessionsMu.Unlock()
	return s.verifyRESTSessionOwnerLocked(sessionID, owner)
}

// verifyRESTSessionOwnerLocked is verifyRESTSessionOwner for callers that
// already hold restSessionsMu (enter/exit, which hold it across the store
// holder transition).
func (s *Server) verifyRESTSessionOwnerLocked(sessionID, owner string) bool {
	bound, ok := s.restSessions[sessionID]
	if !ok {
		return true
	}
	return bound.owner == owner
}

// restConfigSessionID reads and validates the holder identity supplied by a
// follow-up REST config request. Missing/malformed identities fail closed
// before the store is called, so they can never reach its sessionID==""
// internal/system bypass. #16069: the format-valid token must also have been
// minted by the same principal that presents it — a stolen token presented by
// another equally-privileged principal is denied with 403 before any store
// mutation, commit, or release can run.
func (s *Server) restConfigSessionID(w http.ResponseWriter, r *http.Request) (string, bool) {
	sessionID := strings.TrimSpace(r.Header.Get(restConfigSessionHeader))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "missing "+restConfigSessionHeader+" header")
		return "", false
	}
	if !validRESTConfigSessionID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid "+restConfigSessionHeader+" header")
		return "", false
	}
	owner, ok := restSessionOwner(r)
	if !ok {
		writeError(w, http.StatusForbidden, "config session principal unavailable")
		return "", false
	}
	if !s.verifyRESTSessionOwner(sessionID, owner) {
		writeError(w, http.StatusForbidden, "config session token not bound to this principal")
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
	if errors.Is(err, configstore.ErrCommitCheckBusy) {
		writeError(w, http.StatusTooManyRequests, err.Error())
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

// journalPrincipalForRequest renders the already-authorized REST principal
// without logging the bearer-like config-session token itself.
func journalPrincipalForRequest(r *http.Request, sessionID string) string {
	p, ok := authorizedMutationPrincipal(r)
	if !ok {
		return configstore.UnknownPrincipal
	}
	return configstore.FormatJournalPrincipal(p.Source.String(), p.UID, p.Username, p.Class, sessionID)
}

// bindCommitGate attaches the #16611 priced-gate binding captured by
// the REST middleware (priceRESTCommitGate16611) to authority. Absent
// a priced snapshot — a direct handler call or an unrestricted
// class — the authority is left unbound.
func (s *Server) bindCommitGate(r *http.Request, authority configstore.CommitAuthority) configstore.CommitAuthority {
	price, ok := restCommitGatePriceFrom(r)
	if !ok {
		return authority
	}
	return authority.WithCommitGate(price.cfg, price.class, price.candidateGen, price.active)
}

func (s *Server) configEnterHandler(w http.ResponseWriter, r *http.Request) {
	// #16069: the minting principal is bound to the token before the store is
	// entered, and every follow-up request must present the same principal.
	owner, ok := restSessionOwner(r)
	if !ok {
		writeError(w, http.StatusForbidden, "config session principal unavailable")
		return
	}
	// An absent header starts a new session. Supplying the token returned by an
	// earlier successful enter re-enters that same session and refreshes its
	// idle lease; a different token remains a conflicting entrant. A token
	// supplied for re-entry must already belong to this principal (#16069).
	sessionID := strings.TrimSpace(r.Header.Get(restConfigSessionHeader))
	fresh := sessionID == ""
	if fresh {
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

	// Hold restSessionsMu across BOTH the store holder transition and the
	// binding update, and read the holder epoch inside that same lock hold.
	// That serializes this enter against a concurrent exit of the same
	// token: the exit can no longer interleave between the store releasing
	// the holder and a re-entry restoring the binding (then have its stale
	// erase delete the new mint), nor between the store acquiring the holder
	// and the binding being recorded. The epoch captured here is the
	// generation this binding belongs to; a later exit may erase the
	// binding only for that exact generation (see configExitHandler).
	s.restSessionsMu.Lock()
	if !fresh && !s.verifyRESTSessionOwnerLocked(sessionID, owner) {
		s.restSessionsMu.Unlock()
		writeError(w, http.StatusForbidden, "config session token not bound to this principal")
		return
	}
	if err := s.store.EnterConfigureSession(sessionID); err != nil {
		s.restSessionsMu.Unlock()
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	// A same-session re-entry does not advance the store holder epoch, so
	// refreshing the recorded epoch to the current one keeps one live
	// generation per token; a takeover (stale-lease reclaim or
	// release-then-re-enter) observes the advanced epoch and binds the new
	// generation to the current owner.
	s.bindRESTSessionLocked(sessionID, owner, s.store.HolderEpoch())
	s.restSessionsMu.Unlock()
	writeOK(w, map[string]string{"status": "ok", "session_id": sessionID})
}

func (s *Server) configExitHandler(w http.ResponseWriter, r *http.Request) {
	// Parse + format-check the token without the full owner-checked helper:
	// the owner check, the store release, and the unbind must share one
	// restSessionsMu hold (below), so checking first via restConfigSessionID
	// and releasing later would reopen exactly the race this handler closes.
	sessionID := strings.TrimSpace(r.Header.Get(restConfigSessionHeader))
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "missing "+restConfigSessionHeader+" header")
		return
	}
	if !validRESTConfigSessionID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid "+restConfigSessionHeader+" header")
		return
	}
	owner, ok := restSessionOwner(r)
	if !ok {
		writeError(w, http.StatusForbidden, "config session principal unavailable")
		return
	}
	// Release only the candidate held by this REST session, and only for
	// the principal that minted it (#5870 holder check in the store, #16069
	// binding here). Hold restSessionsMu across the owner check, the store
	// release, and the unbind so no concurrent same-token re-entry can slip
	// a new binding in between the release and the erase: the unbind is
	// generation-checked against the (owner, epoch) observed under this
	// lock hold, so it erases only the generation that was just released —
	// a binding restored by a re-entry for a later generation survives.
	s.restSessionsMu.Lock()
	if !s.verifyRESTSessionOwnerLocked(sessionID, owner) {
		s.restSessionsMu.Unlock()
		writeError(w, http.StatusForbidden, "config session token not bound to this principal")
		return
	}
	bound, boundKnown := s.restSessions[sessionID]
	released := s.store.ExitConfigureSession(sessionID)
	if released && boundKnown {
		// The binding erased here is the one observed above under this
		// same lock hold; holding restSessionsMu across the whole sequence
		// means no re-entry can have replaced it in between, and the
		// (owner, epoch) comparison refuses to erase anything else.
		s.unbindRESTSessionLocked(sessionID, bound.owner, bound.epoch)
	}
	s.restSessionsMu.Unlock()
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
	sessionID, ok := s.restConfigSessionID(w, r)
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
	sessionID, ok := s.restConfigSessionID(w, r)
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
	sessionID, ok := s.restConfigSessionID(w, r)
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
	sessionID, ok := s.restConfigSessionID(w, r)
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
	sessionID, ok := s.restConfigSessionID(w, r)
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
	authority, err := s.store.AuthorizeCommitAs(sessionID, journalPrincipalForRequest(r, sessionID))
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	authority = s.bindCommitGate(r, authority)

	// Bare commit during a pending commit-confirmed window (#4000). Confirm
	// the pending config only when the candidate is UNCHANGED; new staged
	// edits fall through to the normal commit below, where commitFn applies
	// them AND clears the timer (#3861), so they are committed rather than
	// silently dropped.
	if s.store.ConfirmOnly() {
		if err := s.store.ConfirmCommitPrincipalAs(sessionID, journalPrincipalForRequest(r, sessionID)); err != nil {
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
		writeCommitError(w, compiled, err)
		return
	}
	writeOK(w, commitResponseFromConfig(compiled))
}

func (s *Server) configCommitCheckHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := s.restConfigSessionID(w, r)
	if !ok {
		return
	}
	// #16070: only the config-lock holder may check the shared candidate.
	// The previous handler ignored the request entirely, so any PermConfig
	// non-holder could obtain compile diagnostics about another session's
	// staged candidate and trigger repeatable full compiles at will.
	// CommitCheckAs enforces the holder under the store lock (409 for a
	// non-holder via writeConfigMutationError) and bounds concurrent
	// compiles to a single slot (429 when busy). The mandatory session
	// header also closes the sessionID=="" internal bypass: a missing or
	// malformed token fails closed above, before the store is called.
	compiled, err := s.store.CommitCheckAs(sessionID)
	if err != nil {
		writeConfigMutationError(w, err)
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
	sessionID, ok := s.restConfigSessionID(w, r)
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
	// #15657 V48-02: ?path= selects the subtree (space-separated, the
	// gRPC ShowConfigRequest.Path twin); absent = whole tree.
	path := strings.Fields(r.URL.Query().Get("path"))

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
	//
	// #15657 V48-02: an UNRECOGNISED format is likewise refused (400)
	// instead of silently rendering hierarchical text; "inheritance"
	// renders the groups-expanded form like gRPC ShowConfig.
	// #15995 fold: render the priced snapshot when the gate ran.
	snaps, hasSnaps := restConfigReadSnapshotsFrom(r)
	var output string
	switch target {
	case "", "active":
		switch format {
		case "", "text":
			if hasSnaps && snaps.Present {
				output = configstore.RenderShowRedacted(snaps.Primary, path, "text")
			} else {
				output = s.store.ShowActiveRedacted(path)
			}
		case "set":
			if hasSnaps && snaps.Present {
				output = configstore.RenderShowRedacted(snaps.Primary, path, "set")
			} else {
				output = s.store.ShowActiveSetRedacted(path)
			}
		case "json":
			if hasSnaps && snaps.Present {
				output = configstore.RenderShowRedacted(snaps.Primary, path, "json")
			} else {
				output = s.store.ShowActiveJSONRedacted(path)
			}
		case "xml":
			if hasSnaps && snaps.Present {
				output = configstore.RenderShowRedacted(snaps.Primary, path, "xml")
			} else {
				output = s.store.ShowActiveXMLRedacted(path)
			}
		case "inheritance":
			var inh string
			var err error
			if hasSnaps && snaps.Present {
				inh, err = configstore.RenderShowInheritanceRedacted(snaps.Primary, path, snaps.NodeID)
			} else {
				inh, err = s.store.ShowActiveInheritanceRedacted(path)
			}
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			output = inh
		default:
			writeError(w, http.StatusBadRequest,
				"unsupported format: "+format+"; use text, set, json, xml, or inheritance")
			return
		}
	case "candidate":
		switch format {
		case "", "text":
			if hasSnaps && snaps.Present {
				output = configstore.RenderShowRedacted(snaps.Primary, path, "text")
			} else {
				output = s.store.ShowCandidateRedacted(path)
			}
		case "set":
			if hasSnaps && snaps.Present {
				output = configstore.RenderShowRedacted(snaps.Primary, path, "set")
			} else {
				output = s.store.ShowCandidateSetRedacted(path)
			}
		case "json":
			if hasSnaps && snaps.Present {
				output = configstore.RenderShowRedacted(snaps.Primary, path, "json")
			} else {
				output = s.store.ShowCandidateJSONRedacted(path)
			}
		case "xml":
			if hasSnaps && snaps.Present {
				output = configstore.RenderShowRedacted(snaps.Primary, path, "xml")
			} else {
				output = s.store.ShowCandidateXMLRedacted(path)
			}
		case "inheritance":
			var inh string
			var err error
			if hasSnaps && snaps.Present {
				inh, err = configstore.RenderShowInheritanceRedacted(snaps.Primary, path, snaps.NodeID)
			} else {
				inh, err = s.store.ShowCandidateInheritanceRedacted(path)
			}
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			output = inh
		default:
			writeError(w, http.StatusBadRequest,
				"unsupported format: "+format+"; use text, set, json, xml, or inheritance")
			return
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
	// #15994 fold2-2: render the snapshot the gate priced (active),
	// not a second live-store read.
	snaps, hasSnaps := restConfigReadSnapshotsFrom(r)
	var output string
	switch format {
	case "set":
		if hasSnaps && snaps.Present {
			output = configstore.RenderShowRedacted(snaps.Primary, nil, "set")
		} else {
			output = s.store.ShowActiveSetRedacted(nil)
		}
	case "text":
		if hasSnaps && snaps.Present {
			output = configstore.RenderShowRedacted(snaps.Primary, nil, "text")
		} else {
			output = s.store.ShowActiveRedacted(nil)
		}
	case "json":
		if hasSnaps && snaps.Present {
			output = configstore.RenderShowRedacted(snaps.Primary, nil, "json")
		} else {
			output = s.store.ShowActiveJSONRedacted(nil)
		}
	case "xml":
		if hasSnaps && snaps.Present {
			output = configstore.RenderShowRedacted(snaps.Primary, nil, "xml")
		} else {
			output = s.store.ShowActiveXMLRedacted(nil)
		}
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
	// #15994 fold2-1/2: render the arms the gate priced (?rollback?
	// selects slot-vs-candidate; absent selects candidate-vs-active),
	// never a second live-store read.
	if snaps, has := restConfigReadSnapshotsFrom(r); has && snaps.Present {
		// #17215: the slot error and the no-candidate mode error
		// travel inside the gate capture; surface them before the
		// "renders nothing" branch so a missing slot / absent
		// candidate never reads as 200 "" ("no diff").
		if snaps.SlotErr != nil {
			writeError(w, http.StatusBadRequest, snaps.SlotErr.Error())
			return
		}
		if rollbackN > 0 && snaps.NoCandidate {
			writeError(w, http.StatusBadRequest, "not in configuration mode")
			return
		}
		if !snaps.Renders {
			// rollback=0 with no candidate: the store compare
			// renders "" (not in configuration mode).
			writeOK(w, TextResponse{Output: ""})
			return
		}
		writeOK(w, TextResponse{Output: configstore.RenderCompareRedacted(snaps.Primary, snaps.Other, nil, true)})
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
	// #15994 fold2-2: search over the priced (active) snapshot.
	text := s.store.ShowActiveRedacted(nil)
	if snaps, has := restConfigReadSnapshotsFrom(r); has && snaps.Present {
		text = configstore.RenderShowRedacted(snaps.Primary, nil, "text")
	}
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
	if req.Content == "" && req.Mode != "rescue" {
		writeError(w, http.StatusBadRequest, "content required")
		return
	}
	if req.Mode == "rescue" && req.Content != "" {
		writeError(w, http.StatusBadRequest, "load rescue does not accept content")
		return
	}
	sessionID, ok := s.restConfigSessionID(w, r)
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
	case "rescue":
		if err := s.store.LoadRescueAsPlantClass(sessionID, plantClass); err != nil {
			writeConfigMutationError(w, err)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown load mode: %s (use 'rescue', 'override', 'merge', or 'set')", req.Mode))
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configCommitConfirmedHandler(w http.ResponseWriter, r *http.Request) {
	var req CommitConfirmedRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Minutes < 0 {
		writeError(w, http.StatusBadRequest, "commit confirmed: timeout must be non-negative")
		return
	}
	sessionID, ok := s.restConfigSessionID(w, r)
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
	authority, err := s.store.AuthorizeCommitAs(sessionID, journalPrincipalForRequest(r, sessionID))
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	authority = s.bindCommitGate(r, authority)
	if s.commitConfirmedFn == nil {
		writeError(w, http.StatusInternalServerError, "commit-confirmed handler not wired")
		return
	}
	compiled, err := s.commitConfirmedFn(r.Context(), authority, req.Minutes)
	if err != nil {
		writeCommitError(w, compiled, err)
		return
	}
	writeOK(w, commitResponseFromConfig(compiled))
}

func (s *Server) configConfirmHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := s.restConfigSessionID(w, r)
	if !ok {
		return
	}
	// #5870: confirming a pending commit-confirmed is a holder-scoped op — only
	// the REST-held candidate may be confirmed from REST; a CLI/gRPC holder's
	// pending window is rejected (ErrConfigLockedByOther → 409).
	if err := s.store.ConfirmCommitPrincipalAs(sessionID, journalPrincipalForRequest(r, sessionID)); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) configShowRollbackHandler(w http.ResponseWriter, r *http.Request) {
	// #3443: n selects a rollback slot. Fail closed on a
	// malformed/negative value instead of silently defaulting to slot 1,
	// which would show a different rollback than the operator asked for.
	n, ok := queryIntStrict(r, "n", 1)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid n parameter: must be a non-negative integer")
		return
	}
	// #15657 V45-03: n == 0 is the active configuration (Junos rollback
	// 0), superseding the #4556 M-01 zero rejection on this show path;
	// only negative values are refused. queryIntStrict already fails a
	// negative literal, so this catches a signed value that cleared it.
	if n < 0 {
		writeError(w, http.StatusBadRequest, "invalid n parameter: rollback index must be non-negative (0 = active configuration)")
		return
	}
	format := r.URL.Query().Get("format")
	// #15657 V48-02: ?path= subtree selector, as on /config/show.
	path := strings.Fields(r.URL.Query().Get("path"))

	// #15995 fold: render the priced slot snapshot when the gate ran.
	// Fold 3: captured nil Primary = slot absent at pricing — surface
	// the captured SlotErr (#17215), never render a later live slot.
	if snaps, ok := restConfigReadSnapshotsFrom(r); ok && snaps.Present && snaps.Primary == nil {
		if snaps.SlotErr != nil {
			writeError(w, http.StatusBadRequest, snaps.SlotErr.Error())
			return
		}
	}
	if snaps, ok := restConfigReadSnapshotsFrom(r); ok && snaps.Present {
		var snapOut string
		var snapErr error
		switch format {
		case "", "text":
			snapOut = configstore.RenderShowRedacted(snaps.Primary, path, "text")
		case "set":
			snapOut = configstore.RenderShowRedacted(snaps.Primary, path, "set")
		case "json":
			snapOut = configstore.RenderShowRedacted(snaps.Primary, path, "json")
		case "xml":
			snapOut = configstore.RenderShowRedacted(snaps.Primary, path, "xml")
		case "inheritance":
			snapOut, snapErr = configstore.RenderShowInheritanceRedacted(snaps.Primary, path, snaps.NodeID)
		default:
			writeError(w, http.StatusBadRequest,
				"unsupported format: "+format+"; use text, set, json, xml, or inheritance")
			return
		}
		if snapErr != nil {
			writeError(w, http.StatusBadRequest, snapErr.Error())
			return
		}
		writeOK(w, TextResponse{Output: snapOut})
		return
	}

	var output string
	var err error
	switch format {
	case "", "text":
		output, err = s.store.ShowRollbackRedactedPath(n, path)
	case "set":
		output, err = s.store.ShowRollbackSetRedactedPath(n, path)
	case "json":
		output, err = s.store.ShowRollbackJSONRedactedPath(n, path)
	case "xml":
		output, err = s.store.ShowRollbackXMLRedactedPath(n, path)
	case "inheritance":
		output, err = s.store.ShowRollbackInheritanceRedactedPath(n, path)
	default:
		writeError(w, http.StatusBadRequest,
			"unsupported format: "+format+"; use text, set, json, xml, or inheritance")
		return
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
	sessionID, ok := s.restConfigSessionID(w, r)
	if !ok {
		return
	}
	pathParts := strings.Fields(req.Path)
	plantClass, err := s.mutationPlantClass(r)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	// #5870: annotate mutates the candidate, so it runs under the REST holder
	// identity and is rejected when a CLI/gRPC session owns the candidate. A
	// holder conflict maps to 409 Conflict; other errors stay 400.
	// #14710: use AnnotateAsPlantClass like every sibling mutation handler
	// (and the gRPC annotate path) so the annotation is not planted with
	// empty (superuser) attribution, defeating the #9939/#9984 recheck.
	if err := s.store.AnnotateAsPlantClass(sessionID, plantClass, pathParts, req.Comment); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, configstore.ErrConfigLockedByOther) {
			status = http.StatusConflict
		}
		writeJSON(w, status, Response{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, Response{Success: true})
}

// commitCommittedResponse is the REST body for a commit that WAS promoted
// and persisted. It is deliberately NOT the success envelope: Success stays
// false and the HTTP status is 503, so existing clients that only check
// success/status do not mistake it for a clean commit — but Data.committed=
// true plus the preserved error text let a client distinguish a committed
// config from a 400 config reject (compiled == nil). Two committed classes
// share this shape with distinct Status strings (#15281, #16828):
// "committed_with_error" (live; only a non-fatal tail/peer step failed) and
// "committed_not_applied" (promoted+persisted but the apply aborted before
// publication; live on a later apply or boot, not now). This mirrors the
// gRPC commitApplyStatus classification (#5742), which the REST handlers
// previously lacked: they blanket-mapped every non-context error to 400
// success:false, indistinguishable from a reject, while the config was
// committed.
type commitCommittedResponse struct {
	Status    string   `json:"status"`
	Committed bool     `json:"committed"`
	Error     string   `json:"error"`
	Warnings  []string `json:"warnings,omitempty"`
}

// writeCommitError maps a non-nil commit-callback error (commitFn /
// commitConfirmedFn) to the REST response. The structural classification
// is shared with gRPC via configstore.ClassifyCommitError (#16156,
// #5742):
//
//   - CommitErrCommittedNotApplied (#16828): the store promoted+
//     persisted the config but the apply aborted before publication.
//     503 with committed:true and status committed_not_applied — the
//     client must learn the config WAS committed (active; live on a
//     later apply or boot), not edit/abandon it as a 400 reject.
//   - context.Canceled / DeadlineExceeded (PRE-promotion only; a
//     post-promotion abort carries ErrCommittedNotApplied): 503
//     "commit busy: ..." — unchanged from the pre-#15281 mapping.
//   - compiled != nil (tail): the daemon committed+persisted the
//     config and returned it alongside a non-fatal tail/peer error.
//     503 with committed:true and the error text — retryable, NOT a
//     reject.
//   - compiled == nil (default): a real config reject. 400 — unchanged,
//     fail-safe: an unclassifiable error is never told "committed".
func writeCommitError(w http.ResponseWriter, compiled *config.Config, err error) {
	switch configstore.ClassifyCommitError(compiled, err) {
	case configstore.CommitErrCommittedNotApplied:
		resp := commitCommittedResponse{
			Status:    "committed_not_applied",
			Committed: true,
			Error:     err.Error(),
			Warnings:  configstore.WarningsOf(compiled),
		}
		writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: resp, Error: err.Error()})
	case configstore.CommitErrCanceled, configstore.CommitErrDeadlineExceeded:
		writeError(w, http.StatusServiceUnavailable, "commit busy: "+err.Error())
	case configstore.CommitErrCommittedTail:
		resp := commitCommittedResponse{
			Status:    "committed_with_error",
			Committed: true,
			Error:     err.Error(),
			Warnings:  configstore.WarningsOf(compiled),
		}
		writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: resp, Error: err.Error()})
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

type configCommitResponse struct {
	Status   string   `json:"status"`
	Warnings []string `json:"warnings,omitempty"`
}

func commitResponseFromConfig(cfg *config.Config) configCommitResponse {
	return configCommitResponse{Status: "ok", Warnings: configstore.WarningsOf(cfg)}
}
