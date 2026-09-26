package api

import (
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/denyaudit"
)

// AuthConfig holds authentication credentials for the API middleware.
type AuthConfig struct {
	Users   map[string]string // username -> password
	APIKeys map[string]bool   // valid API key tokens
}

// AuthForRetainedListener returns the credential set that may be published while
// some live listener is RETAINED at an address the committed config does not
// name — the fail-safe state a failed (re)bind leaves behind, and the window a
// make-before-break rebind passes through (#5561 round 12).
//
// It is the intersection: a credential survives only if the SAME value was
// already accepted on that listener AND the committed config still carries it.
// Both halves matter and they close opposite holes:
//
//   - Dropping what the committed config no longer carries is the REVOCATION
//     half (#5561 round 7). The retained listener must stop honouring a secret
//     the operator replaced, and it must stop immediately rather than whenever
//     some later reconcile happens to bind — that deferral was not a race window
//     but a permanent one.
//
//   - Withholding what was NOT already accepted there is the GRANT half. The
//     credential set the operator committed is authorized in the context of the
//     endpoint committed alongside it; when that endpoint fails to bind,
//     publishing the whole set hands a credential to a listener the config never
//     asked to keep serving. The sharp case is a commit that moves management
//     from an off-box address to loopback AND introduces a credential: the new
//     secret was meant to be reachable only from the box, and a failed rebind
//     would otherwise expose it on the routable address the operator was trying
//     to retire. Rotation is the same shape — revoking A tightens, granting B
//     does not.
//
// A nil `live` is the UNIVERSAL set, not the empty one: a nil snapshot is
// dynamicAuthMiddleware's pass-through, so that listener already accepts every
// caller and `next` is unambiguously a tightening. Returning `next` whole there
// (as a COPY — see below) is what lets a commit that moves a bind off-loopback
// AND adds the credential the #4047/#5127 clamp requires publish that credential
// BEFORE the new socket serves (#5561 round 9).
//
// The result can be EMPTY (non-nil with no credentials), and that is deliberate:
// dynamicAuthMiddleware rejects every non-exempt request against an empty set,
// so a commit that replaces the credentials wholesale AND fails to move the
// endpoint leaves the retained listener refusing everyone until a later reconcile
// converges. That is the direction this file has consistently chosen —
// over-restrict and wait for the next commit, never under-restrict — and the
// REST API is not the box's lifeline (console/SSH and the local CLI are
// untouched).
//
// "Wait for the next commit" is load-bearing, and it is a constraint on the
// CALLER, not on this function. The empty set is ABSORBING here: the loop keeps
// only values already present in `live`, so ∅ ∩ X = ∅ for every X, and no later
// rotation can re-introduce a credential through this path. What restores
// access is a commit that makes every serving listener sit at an address the
// config names, after which reconcileTo publishes the committed set WHOLE
// instead of calling this. A caller that can enter the intersection in a state
// whose endpoint can never converge therefore creates a lockout with no exit —
// which is exactly what `rebinding && len(errs) == 0` did before #5561 round 13
// (it intersected on a failed leg ENABLE, where nothing is retained anywhere).
// The gate is now mgmtEndpoint.everyLiveLegNamedBy, so ∅ is reachable only while
// a listener really is serving an unnamed address, and both exits from that —
// converge the bind, or commit the address that is actually serving — are a
// single commit away.
//
// Both exits are specific to the ∅ THIS function produces, which is the
// intersection on the NON-NIL direction: that config carries a credential, so
// committing the address that is actually serving is not re-clamped and
// everyLiveLegNamedBy then reads true. The OTHER empty set in this system — the
// deny-all that publishNilDirectionLocked publishes while a live leg is
// off-loopback — is not reachable through here and does not share the second
// exit: its config has no api-auth at all, so the #4047/#5127 clamp pulls any
// off-loopback bind it names straight back to loopback
// (Daemon.resolveAPIBinds), and re-committing the serving address is a no-op.
// Its exits are to converge the loopback bind, or to re-add api-auth.
//
// The state is LOGGED but not otherwise operator-visible: reconcileTo warns with
// the withheld count, but `show system services` shows the retained leg as
// `Listening` (it is serving), has no HTTPS row at all, and the commit itself
// reports success. Do not weaken the exit argument by appealing to
// diagnosability.
//
// Secrets are compared with ==, not crypto/subtle: both operands are configured
// values from the daemon's own config store, never attacker-supplied request
// content, so there is no request-timing channel to close here (the
// constant-time comparisons live in checkAuthorization, against the presented
// credential).
func AuthForRetainedListener(live, next *AuthConfig) *AuthConfig {
	if next == nil {
		return nil
	}
	// A fresh value on EVERY non-nil path: never alias (or mutate) either
	// operand, so the published snapshot cannot change under a later edit of the
	// config it came from. The universal-`live` shortcut used to return `next`
	// itself, which made the no-alias property conditional on a branch the test
	// for it never took (#5561 round 14).
	out := &AuthConfig{Users: map[string]string{}, APIKeys: map[string]bool{}}
	if live == nil {
		for user, pw := range next.Users {
			out.Users[user] = pw
		}
		for key, ok := range next.APIKeys {
			if ok {
				out.APIKeys[key] = true
			}
		}
		return out
	}
	for user, pw := range next.Users {
		// Match on the PAIR. A same-username secret rotation is a revocation
		// plus a grant, and the grant half is withheld like any other.
		if was, ok := live.Users[user]; ok && was == pw {
			out.Users[user] = pw
		}
	}
	for key, ok := range next.APIKeys {
		if ok && live.APIKeys[key] {
			out.APIKeys[key] = true
		}
	}
	return out
}

// CredentialCount reports how many credentials a snapshot carries. A nil
// snapshot means no authentication at all, which is not a count of credentials;
// the management reconciler uses this only to log how much of a committed set it
// had to withhold from a retained listener.
//
// API keys are counted BY VALUE rather than by len, because an APIKeys entry
// mapped to false is a key the auth check rejects outright
// (constantTimeAPIKeyMatch skips `!valid`) and AuthForRetainedListener does not
// copy it. Counting it would inflate the reconciler's `withheld` subtraction on
// one side only, reporting a credential as withheld when neither snapshot could
// ever have honoured it. Log-only, no authorization effect — but a warning that
// over-reports is one an operator has to go and disprove (#5561 round 19,
// finding 3).
func CredentialCount(a *AuthConfig) int {
	if a == nil {
		return 0
	}
	// Count only users that can actually authenticate. checkAuthorization
	// rejects `expected == ""`, so a `user bob { password ""; }` row
	// authenticates nobody — exactly like the disabled/empty API keys filtered
	// below. Counting it inflated the "withheld" warning on the user side only,
	// which is an asymmetry an operator has to go and disprove (#6645).
	n := 0
	for _, secret := range a.Users {
		if secret != "" {
			n++
		}
	}
	for key, ok := range a.APIKeys {
		// constantTimeAPIKeyMatch skips `!valid || key == ""`, so both a
		// disabled key and an empty-string key authenticate nobody and neither
		// is a credential. Mirror BOTH of its conditions rather than only the
		// valid flag: a count that includes an unusable key is one an operator
		// has to go and disprove.
		if ok && key != "" {
			n++
		}
	}
	return n
}

// authMiddleware wraps an http.Handler with Basic Auth / Bearer / X-API-Key
// checks. /health always bypasses authentication (it exposes no sensitive data
// and is a liveness probe). /metrics bypasses authentication only when
// metricsRequireAuth is false for a literal loopback bind, the standard
// Prometheus posture. NewServer derives it independently from the configured
// address of each enabled HTTP or HTTPS listener. A routable, wildcard,
// hostname, malformed, or otherwise unprovable bind requires credentials for
// /metrics like every other endpoint (#4162).
func authMiddleware(cfg AuthConfig, metricsRequireAuth bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authCheck(cfg, metricsRequireAuth, r) {
			next.ServeHTTP(w, r)
			return
		}
		logRESTAPIAuthFailure(r)
		writeAuthChallenge(w)
	})
}

// logRESTAPIAuthFailure records each failed REST credential check while
// rate-limiting WARN output. Its fixed key prevents caller-controlled credentials,
// paths, or addresses from multiplying log volume or limiter state.
func logRESTAPIAuthFailure(r *http.Request) {
	if emit, suppressed := denyaudit.Note(denyaudit.SurfaceRESTAPIAuthFail, "rest-api-auth-failure"); emit {
		slog.Warn("api: REST authentication failed",
			"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr,
			"suppressed_since_last", suppressed,
			"denials_total", denyaudit.Total(denyaudit.SurfaceRESTAPIAuthFail))
		return
	}
	slog.Debug("api: REST authentication failed",
		"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
}

// authCheck reports whether a request is authorized under cfg (or exempt). It is
// the shared core of the static authMiddleware and the live-swap
// dynamicAuthMiddleware (#5866), so both enforce identical semantics — the
// /health + loopback-/metrics exemptions and the #4157/#5636 constant-time,
// empty-secret-rejecting credential checks.
func authCheck(cfg AuthConfig, metricsRequireAuth bool, r *http.Request) bool {
	// /health is always exempt; /metrics is exempt only when this listener has a
	// literal loopback bind.
	if r.URL.Path == "/health" || (r.URL.Path == "/metrics" && !metricsRequireAuth) {
		return true
	}
	if auth := r.Header.Get("Authorization"); auth != "" && checkAuthorization(auth, cfg) {
		return true
	}
	if key := r.Header.Get("X-API-Key"); key != "" && constantTimeAPIKeyMatch(cfg, key) {
		return true
	}
	return false
}

// writeAuthChallenge emits the 401 + WWW-Authenticate response for an
// unauthorized request.
func writeAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="xpf API"`)
	writeJSON(w, http.StatusUnauthorized, Response{
		Success: false,
		Error:   "authentication required",
	})
}

// checkAuthorization validates an Authorization header value.
func checkAuthorization(auth string, cfg AuthConfig) bool {
	// Bearer token
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		return constantTimeAPIKeyMatch(cfg, token)
	}

	// Basic auth
	if strings.HasPrefix(auth, "Basic ") {
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			return false
		}
		user, pass, ok := strings.Cut(string(payload), ":")
		if !ok {
			return false
		}
		// Look up the expected password, but ALWAYS run the constant-time
		// compare — even for an unknown user — so response timing does not
		// reveal whether the username exists (#4157). Early-returning on
		// !exists would skip the compare entirely, a large and measurable
		// timing gap between a known and an unknown username.
		expected, exists := cfg.Users[user]
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(expected)) == 1
		// #5636: an EMPTY configured password is not a valid credential —
		// reject it regardless of what the request presents. A quoted-empty
		// api-auth secret can slip through a lenient config load; without this
		// guard `username:` (empty password) matches an empty stored secret and
		// authenticates, an auth bypass on an off-loopback bind. The
		// constant-time compare above still runs unconditionally, so the
		// known/unknown-user timing profile from #4157 is preserved. The added
		// `expected != ""` check is an O(1) length test whose cost does not
		// vary with the secret's content or length; the attacker-supplied
		// username does select WHICH configured `expected` is tested, but the
		// branch reveals only whether that (already `exists`-gated) user has a
		// non-empty configured secret — never any secret content — so it adds
		// no request-content-dependent timing signal.
		return exists && expected != "" && passMatch
	}

	return false
}

// constantTimeAPIKeyMatch reports whether presented equals any configured API
// key. It compares presented against EVERY configured key with
// crypto/subtle.ConstantTimeCompare and OR-s the per-key results, never
// short-circuiting on the first match. This closes the timing side channel of
// the previous plain map lookup (`cfg.APIKeys[presented]`), whose latency
// varied with hash-bucket collisions and key presence and could leak whether a
// submitted token/prefix was valid to a network-timing attacker on an
// interface-bound API (#4157).
//
// ConstantTimeCompare returns 0 immediately when the two byte slices differ in
// length; that reveals only length, not content, which is acceptable here. The
// loop count is the number of configured keys — a deployment constant, not
// attacker-controllable per request — so it does not leak the secret. Not
// short-circuiting means WHICH key matched is not leaked by timing either.
func constantTimeAPIKeyMatch(cfg AuthConfig, presented string) bool {
	presentedBytes := []byte(presented)
	match := 0
	for key, valid := range cfg.APIKeys {
		// #5636: never match an EMPTY configured api-key. An empty api-key is
		// not a valid credential — matching it would authenticate a request
		// presenting an empty Bearer / X-API-Key token. The skip is keyed only
		// on the configured key set (a deployment constant), so it does not add
		// a request-dependent timing signal (#4157).
		if !valid || key == "" {
			continue
		}
		match |= subtle.ConstantTimeCompare(presentedBytes, []byte(key))
	}
	return match == 1
}

// isLoopbackBindAddr reports whether the API listen address binds only the
// loopback interface (#4162). It parses host:port and returns true only for a
// literal loopback IP (127.0.0.0/8 or ::1). Anything else — a routable IP, the
// wildcard bind (":8080" / "0.0.0.0" / "::"), an empty/unparseable host, or a
// hostname — is treated as NON-loopback (returns false), the conservative
// default: when in doubt, gate /metrics behind auth rather than expose it.
func isLoopbackBindAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port (e.g. a bare host). Try the whole string as an IP.
		host = addr
	}
	if host == "" {
		// Wildcard bind (":8080") — listens on all interfaces.
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// A hostname or malformed address — cannot prove it is loopback.
		return false
	}
	return ip.IsLoopback()
}
