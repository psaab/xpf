package api

import (
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/denyaudit"
)

// AuthConfig holds hashed REST credentials plus their authorization scope.
type AuthConfig struct {
	Users         map[string]string // username -> tagged bcrypt verifier
	UserClasses   map[string]string
	UserExpires   map[string]time.Time
	APIKeys       map[string]bool // tagged bcrypt verifier -> enabled
	APIKeyNames   map[string]string
	APIKeyClasses map[string]string
	APIKeyExpires map[string]time.Time
}

var dummyAPIAuthVerifier = func() string {
	hash, _ := config.HashAPIAuthSecret("xpf-internal-dummy-api-auth-value")
	return hash
}()

// AuthForRetainedListener returns the credential set that may be published while
// some live listener is RETAINED at an address the committed config does not
// name — the fail-safe state a failed (re)bind leaves behind, and the window a
// make-before-break rebind passes through (#5561 round 12).
//
// A retained listener keeps only credentials whose secret AND authorization
// scope are unchanged. Scope changes (class or expiry) are withheld as grants;
// once every serving leg reaches its committed address, the full next snapshot
// can be published.
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
	out := &AuthConfig{
		Users:         map[string]string{},
		UserClasses:   map[string]string{},
		UserExpires:   map[string]time.Time{},
		APIKeys:       map[string]bool{},
		APIKeyNames:   map[string]string{},
		APIKeyClasses: map[string]string{},
		APIKeyExpires: map[string]time.Time{},
	}
	if live == nil {
		for user, pw := range next.Users {
			out.Users[user] = pw
			copyAuthUserMetadata(out, next, user)
		}
		for key, ok := range next.APIKeys {
			if ok {
				out.APIKeys[key] = true
				copyAuthKeyMetadata(out, next, key)
			}
		}
		return out
	}
	for user, pw := range next.Users {
		// Match on the secret AND effective scope. A same-username secret
		// rotation or scope change is a revocation plus a grant.
		if was, ok := live.Users[user]; ok && was == pw &&
			sameAuthUserScope(live, next, user) {
			out.Users[user] = pw
			copyAuthUserMetadata(out, next, user)
		}
	}
	for key, ok := range next.APIKeys {
		if ok && live.APIKeys[key] && sameAuthKeyScope(live, next, key) {
			out.APIKeys[key] = true
			copyAuthKeyMetadata(out, next, key)
		}
	}
	return out
}

func sameAuthUserScope(live, next *AuthConfig, user string) bool {
	return resolvedCredentialClass(live.UserClasses[user]) ==
		resolvedCredentialClass(next.UserClasses[user]) &&
		live.UserExpires[user].Equal(next.UserExpires[user])
}

func sameAuthKeyScope(live, next *AuthConfig, key string) bool {
	return resolvedCredentialClass(live.APIKeyClasses[key]) ==
		resolvedCredentialClass(next.APIKeyClasses[key]) &&
		live.APIKeyExpires[key].Equal(next.APIKeyExpires[key])
}

func copyAuthUserMetadata(dst, src *AuthConfig, user string) {
	if class := src.UserClasses[user]; class != "" {
		dst.UserClasses[user] = class
	}
	if expires := src.UserExpires[user]; !expires.IsZero() {
		dst.UserExpires[user] = expires
	}
}

func copyAuthKeyMetadata(dst, src *AuthConfig, key string) {
	if name := src.APIKeyNames[key]; name != "" {
		dst.APIKeyNames[key] = name
	}
	if class := src.APIKeyClasses[key]; class != "" {
		dst.APIKeyClasses[key] = class
	}
	if expires := src.APIKeyExpires[key]; !expires.IsZero() {
		dst.APIKeyExpires[key] = expires
	}
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
	throttle := newAuthFailureTracker(nil)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized, retryAfter := throttledAuthCheck(throttle, cfg, metricsRequireAuth, r)
		if authorized {
			next.ServeHTTP(w, r)
			return
		}
		logRESTAPIAuthFailure(r)
		if retryAfter > 0 {
			writeAuthLockedOut(w, retryAfter)
			return
		}
		writeAuthChallenge(w)
	})
}

// throttledAuthCheck applies the #10825 per-source and per-source+account
// budgets before invoking the credential verifier. An active lockout skips
// verification entirely, which is important once Basic checks use bcrypt.
func throttledAuthCheck(throttle *authFailureTracker, cfg AuthConfig, metricsRequireAuth bool, r *http.Request) (authorized bool, retryAfter time.Duration) {
	return throttledAuthCheckWithCheck(throttle, cfg, metricsRequireAuth, r, authCheckCredential)
}

// throttledAuthCheckWithCheck admits a request atomically before invoking the
// verifier. The checker is injectable only to let bounded tests hold verifier
// work behind a barrier and observe the admission limit.
func throttledAuthCheckWithCheck(throttle *authFailureTracker, cfg AuthConfig, metricsRequireAuth bool, r *http.Request, check func(AuthConfig, bool, *http.Request) (bool, string)) (authorized bool, retryAfter time.Duration) {
	if r.URL.Path == "/health" || (r.URL.Path == "/metrics" && !metricsRequireAuth) {
		return true, 0
	}
	source, claimed := throttleIdentity(r)
	reservation, retryAfter := throttle.reserve(source, claimed)
	if retryAfter > 0 {
		return false, retryAfter
	}
	authorized, verified := check(cfg, metricsRequireAuth, r)
	throttle.complete(&reservation, authorized, verified)
	return authorized, 0
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
	authorized, _ := authCheckCredential(cfg, metricsRequireAuth, r)
	return authorized
}

// authCheckCredential reports the verified account bucket along with the
// authorization decision so throttling clears both a Basic username claimed
// before verification and the identity that actually supplied the credential.
func authCheckCredential(cfg AuthConfig, metricsRequireAuth bool, r *http.Request) (bool, string) {
	if r.URL.Path == "/health" || (r.URL.Path == "/metrics" && !metricsRequireAuth) {
		return true, ""
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		if account, ok := checkAuthorizationIdentity(auth, cfg); ok {
			return true, account
		}
	}
	if key := r.Header.Get("X-API-Key"); key != "" && constantTimeAPIKeyMatch(cfg, key) {
		return true, authThrottleAPIKeyAccount
	}
	return false, ""
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
	_, matched := checkAuthorizationIdentity(auth, cfg)
	return matched
}

func checkAuthorizationIdentity(auth string, cfg AuthConfig) (verified string, matched bool) {
	if strings.HasPrefix(auth, "Bearer ") {
		if constantTimeAPIKeyMatch(cfg, strings.TrimPrefix(auth, "Bearer ")) {
			return authThrottleAPIKeyAccount, true
		}
		return "", false
	}
	if !strings.HasPrefix(auth, "Basic ") {
		return "", false
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", false
	}
	user, pass, ok := strings.Cut(string(payload), ":")
	if !ok {
		return "", false
	}
	expected, exists := cfg.Users[user]
	verifier := expected
	if !exists || verifier == "" {
		// Every unknown-user attempt still pays the bcrypt cost of a known
		// credential. The REST throttle runs first, bounding this CPU.
		verifier = dummyAPIAuthVerifier
	}
	passMatch := verifyAuthSecret(verifier, pass)
	if !exists || expected == "" || !credentialExpiryActive(cfg.UserExpires[user]) || !passMatch {
		return "", false
	}
	return authThrottleBasicAccountPrefix + user, true
}

func verifyAuthSecret(encoded, presented string) bool {
	if config.IsAPIAuthSecretHash(encoded) {
		return config.VerifyAPIAuthSecret(encoded, presented)
	}
	if strings.HasPrefix(encoded, "$xpf-bcrypt$") || strings.HasPrefix(encoded, "$xpf-invalid$") {
		// Reserved-tag corruption is a hard denial, but still pays the normal
		// verifier cost so it does not create an account-existence timing signal.
		_ = config.VerifyAPIAuthSecret(dummyAPIAuthVerifier, presented)
		return false
	}
	// AuthConfig is also an embedding API used by tests and external callers.
	// The daemon only populates it from compiled tagged verifiers.
	return subtle.ConstantTimeCompare([]byte(presented), []byte(encoded)) == 1
}

func credentialExpiryActive(expires time.Time) bool {
	return expires.IsZero() || time.Now().Before(expires)
}

func resolvedCredentialClass(class string) string {
	if class == "" {
		return "read-only"
	}
	return class
}

// constantTimeAPIKeyMatch reports whether presented matches exactly one
// configured API key. Every enabled key is checked; ambiguity between two key
// identities fails closed rather than selecting a privilege class by map order.
func constantTimeAPIKeyMatch(cfg AuthConfig, presented string) bool {
	_, _, matched := matchAPIKeyIdentity(cfg, presented)
	return matched
}

func matchAPIKeyIdentity(cfg AuthConfig, presented string) (name, class string, matched bool) {
	matches := 0
	for key, valid := range cfg.APIKeys {
		if !valid || key == "" {
			continue
		}
		equal := verifyAuthSecret(key, presented)
		if !equal || !credentialExpiryActive(cfg.APIKeyExpires[key]) {
			continue
		}
		matches++
		if matches == 1 {
			name = cfg.APIKeyNames[key]
			class = resolvedCredentialClass(cfg.APIKeyClasses[key])
		}
	}
	return name, class, matches == 1
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
