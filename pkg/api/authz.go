package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// authz.go enforces per-principal authorization on the REST mutation surface
// (#5561).
//
// Before this, every state-changing endpoint on 127.0.0.1:8080 — including
// `POST /api/v1/config/set`, `/config/load` and the commit family — ran with no
// per-caller identity at all. The only gates were the #4047/#5127 loopback
// clamp (a location, not an identity), the optional api-auth credential (off by
// default on a loopback bind: dynamicAuthMiddleware passes every request
// through when the snapshot is nil) and the #5055 cross-site guard (a browser
// CSRF defense that a non-browser client passes trivially, by design). Since
// the daemon provisions every `system login user` a real shell account, a
// `read-only` class holder could `curl` a commit and the CLI's client-side RBAC
// never ran. The gRPC surface had the same hole and closed it the same way
// (#5278, pkg/grpcapi/authz.go); the authorization decision itself lives in
// pkg/authz so both surfaces reach the same verdict.
//
// # Shape of the gate
//
// The table below is an ALLOW-list keyed by the exact "METHOD /path" a route
// was registered under. A non-safe method that is not in the table is denied.
// That is the property the issue's scope note asks for — no mutating route
// defaults open — and it holds for routes that do not exist yet: adding a
// `mux.HandleFunc("POST ...")` without a table entry produces a route that
// denies, not a route that is unguarded. TestEveryMutatingRouteHasAPermission_5561
// turns that from a runtime surprise into a test failure by reading the route
// registrations out of server.go and requiring table coverage in both
// directions.
//
// Safe methods (GET/HEAD/OPTIONS/TRACE — isSafeHTTPMethod, shared with the
// cross-site guard) are not gated here at all: read-only endpoints, /health and
// /metrics keep exactly their previous access rules, which the #4162 metrics
// gate and the api-auth middleware continue to enforce.

// restMutationPermissions is the fail-closed route -> required-permission table
// for every state-changing REST route.
//
// Permissions mirror pkg/cli/permissions.go requiredPermission so an operator
// gets the same answer from `curl` as from the CLI: the clear family is
// PermClear, ping/traceroute are PermView (they are `show`-tier operational
// verbs on Junos), and everything under /config is PermConfig — including
// commit-check, which reads the candidate a caller must already hold the
// configure permission to have staged.
//
// `POST /api/v1/system/action` is gated at PermMaint, the permission `request
// system reboot`/`halt` require and that no non-super class holds (#4108 F21).
// The route multiplexes on a body field, and one of its verbs
// (`clear-config-lock`) is a non-destructive recovery action the CLI would gate
// at PermControl — but the middleware deliberately does not consume the request
// body to find out, so the route is gated at the highest permission any of its
// verbs needs. The effect is that an `operator`-class principal cannot clear a
// wedged config lock over REST; it over-restricts rather than under-restricts,
// and splitting enforcement between the middleware and the handler to recover
// that one verb would put half the authorization decision somewhere a future
// route could forget to make.
// restReadPermissions is the authorization policy for the SAFE (read) routes
// under /api/v1 (#6660).
//
// #5561 authorized the 19 MUTATING routes and deliberately scoped reads out.
// The read surface stayed open: any local process could GET /api/v1/config and
// the rest without being identified, and no login-class permission was
// consulted.
//
// WHAT IS AND IS NOT DISCLOSED, measured rather than assumed. GET
// /api/v1/config json-encodes the COMPILED *config.Config, so #2053's
// config.Secret marshaller applies and no operator secret is rendered in
// cleartext -- verified by marshalling a populated ControlLinkAuthKey and
// checking the output. So this is NOT credential disclosure. What it is, is
// full CONFIGURATION disclosure: zones, policies, NAT rules, interface
// addressing, routing neighbours -- a complete map of the firewall, to any
// local uid, including one with no `system login user` entry at all. On a
// firewall that is reconnaissance, which is why every one of these routes is a
// `show`-equivalent and Junos gates `show` on `view`.
//
// EVERY ROUTE IS PermView, deliberately, rather than a per-route tier. These
// are all show verbs; inventing finer tiers here would be a policy the CLI's
// own table does not have, and the two would drift. The finer question the
// issue raises -- whether a read should be REDACTED by class rather than
// denied -- is a different contract and is left open.
//
// /health and /metrics are NOT here and stay open. They carry no configuration,
// authCheck already exempts them, and the in-tree harnesses read /metrics
// (test/incus/*.sh) -- a sweep of every in-tree consumer found those two and
// nothing else touching REST at all, so gating the /api/v1 surface breaks no
// shipped tooling.
//
// WHY THIS IS NOT A NO-BRICK PROBLEM. PrincipalForUID returns a SUPERUSER
// principal for uid 0 unconditionally, with no login model required, so
// root-run monitoring and support tooling on a box that never adopted RBAC
// keeps working byte-for-byte. What changes is a NON-root local uid outside the
// login model -- which is exactly the population this issue exists to stop
// reading the configuration.
var restReadPermissions = map[string]config.LoginClassPermission{
	// Configuration reads. The disclosure this issue is about.
	"GET /api/v1/config":               config.PermView,
	"GET /api/v1/config/compare":       config.PermView,
	"GET /api/v1/config/export":        config.PermView,
	"GET /api/v1/config/history":       config.PermView,
	"GET /api/v1/config/search":        config.PermView,
	"GET /api/v1/config/show":          config.PermView,
	"GET /api/v1/config/show-rollback": config.PermView,
	"GET /api/v1/config/status":        config.PermView,
	"GET /api/v1/show-text":            config.PermView,

	// Operational state.
	"GET /api/v1/status":                               config.PermView,
	"GET /api/v1/system/info":                          config.PermView,
	"GET /api/v1/system/buffers":                       config.PermView,
	"GET /api/v1/interfaces":                           config.PermView,
	"GET /api/v1/interfaces/detail":                    config.PermView,
	"GET /api/v1/routes":                               config.PermView,
	"GET /api/v1/routing/bgp":                          config.PermView,
	"GET /api/v1/routing/ospf":                         config.PermView,
	"GET /api/v1/dhcp/identifiers":                     config.PermView,
	"GET /api/v1/dhcp/leases":                          config.PermView,
	"GET /api/v1/events/stream":                        config.PermView,
	"GET /api/v1/logs/stream":                          config.PermView,
	"GET /api/v1/statistics/global":                    config.PermView,
	"GET /api/v1/statistics/interfaces":                config.PermView,
	"GET /api/v1/statistics/zones":                     config.PermView,
	"GET /api/v1/services/flow-exporters":              config.PermView,
	"GET /api/v1/security/events":                      config.PermView,
	"GET /api/v1/security/ipsec/sa":                    config.PermView,
	"GET /api/v1/security/match":                       config.PermView,
	"GET /api/v1/security/nat/destination":             config.PermView,
	"GET /api/v1/security/nat/deterministic":           config.PermView,
	"GET /api/v1/security/nat/pools":                   config.PermView,
	"GET /api/v1/security/nat/rules":                   config.PermView,
	"GET /api/v1/security/nat/source":                  config.PermView,
	"GET /api/v1/security/policies":                    config.PermView,
	"GET /api/v1/security/screen":                      config.PermView,
	"GET /api/v1/security/sessions":                    config.PermView,
	"GET /api/v1/security/sessions/summary":            config.PermView,
	"GET /api/v1/security/sessions/summary/zone-pairs": config.PermView,
	"GET /api/v1/security/vrrp":                        config.PermView,
	"GET /api/v1/security/zones":                       config.PermView,
}

var restMutationPermissions = map[string]config.LoginClassPermission{
	// Operational clear verbs.
	"POST /api/v1/security/sessions/clear": config.PermClear,
	"POST /api/v1/security/counters/clear": config.PermClear,
	"POST /api/v1/dhcp/identifiers/clear":  config.PermClear,

	// Diagnostics. POST-shaped, but `ping`/`traceroute` are view-tier verbs on
	// Junos and in the CLI's own table.
	"POST /api/v1/diagnostics/ping":       config.PermView,
	"POST /api/v1/diagnostics/traceroute": config.PermView,

	// Configuration: candidate lifecycle, mutation, and commit.
	"POST /api/v1/config/enter":            config.PermConfig,
	"POST /api/v1/config/exit":             config.PermConfig,
	"POST /api/v1/config/set":              config.PermConfig,
	"POST /api/v1/config/delete":           config.PermConfig,
	"POST /api/v1/config/deactivate":       config.PermConfig,
	"POST /api/v1/config/activate":         config.PermConfig,
	"POST /api/v1/config/load":             config.PermConfig,
	"POST /api/v1/config/commit":           config.PermConfig,
	"POST /api/v1/config/commit-check":     config.PermConfig,
	"POST /api/v1/config/commit-confirmed": config.PermConfig,
	"POST /api/v1/config/confirm":          config.PermConfig,
	"POST /api/v1/config/rollback":         config.PermConfig,
	"POST /api/v1/config/annotate":         config.PermConfig,

	// Destructive maintenance (reboot / halt) plus the config-lock recovery
	// verb, folded up to the destructive floor — see the doc comment.
	"POST /api/v1/system/action": config.PermMaint,
}

// Per-route ceilings on the request body the gate will hold buffered
// (#5561 round 10, finding 2).
//
// The gate reads a mutating request's body BEFORE the verdict the handler runs
// under (mutationAuthzGuard says why). That read is the one step of the gate a
// CALLER controls outright, so its cost has to be bounded in three dimensions:
// per request (here), in aggregate across every request in flight
// (mutationBodyBudgetBytes), and per privilege tier within that aggregate
// (mutationBodyTierCeilings), so the bound is not itself a denial lever —
// within the scope mutationBodyTierCeilings states, which is the SYSTEM-DEFINED
// login classes and not a custom one (#6954).
// A blanket maxRequestBodyBytes served none of the three — 16 MiB is the
// ceiling the ONE route that carries a whole candidate configuration needs, and
// applying it to `POST /api/v1/diagnostics/ping` let the cheapest permission on
// the surface (PermView, a `read-only` shell account) buffer in the same units
// as a configure-authorized commit.
const (
	// mutationBodyNone marks a route that consumes NO request body. The gate
	// does not buffer for these AT ALL: their handlers answer from the request
	// LINE and its headers, so there is no caller-controlled block between the
	// gate and the mutation and nothing for the second adjudication to get in
	// front of. Buffering them was pure cost — it turned an immediate answer
	// into a read the caller could stall for the whole apiReadTimeout, and it
	// charged the aggregate budget for a body nobody was going to look at.
	//
	// Membership is a fact about the handler, not a judgement:
	// TestNoBodyClassMatchesTheHandlersThatDecode_5561 asks every guarded route
	// for a malformed body and requires the set that DECODES it to be exactly
	// the complement of this class, so a handler that starts reading — or stops
	// — fails the build rather than silently changing what the gate does.
	mutationBodyNone int64 = 0
	// mutationBodySmall fits a JSON object of scalar options — a ping target
	// plus counts, a system action verb. Orders of magnitude above the real
	// payloads, small enough that the cheapest permissions cannot crowd the
	// aggregate budget.
	mutationBodySmall int64 = 64 << 10 // 64 KiB
	// mutationBodyEdit fits a configuration EDIT: one `set`/`delete` input, a
	// commit log message, a rollback index, an annotation.
	mutationBodyEdit int64 = 1 << 20 // 1 MiB
	// mutationBodyLoad is the whole-candidate-configuration ceiling, unchanged
	// from the handler-side maxRequestBodyBytes it replaces on this route.
	mutationBodyLoad int64 = maxRequestBodyBytes // 16 MiB
)

// restMutationBodyLimits is the per-route buffer ceiling. It is keyed exactly
// like restMutationPermissions and must cover the same routes:
// TestEveryGuardedRouteDeclaresABodyLimit_5561 fails if the two key sets ever
// diverge, so a new mutating route cannot silently inherit the largest cap.
// A route absent from the table anyway falls back to mutationBodySmall (the
// tightest cap that still preserves the two-pass ordering), never to the
// largest.
var restMutationBodyLimits = map[string]int64{
	// Operational clear verbs. sessions/counters are parameterless by contract
	// and their handlers never touch the body — one rejects a non-zero
	// ContentLength outright (#3421 H6), the other ignores the request entirely
	// — so there is no caller-controlled block for the gate to get in front of
	// and nothing to buffer.
	"POST /api/v1/security/sessions/clear": mutationBodyNone,
	"POST /api/v1/security/counters/clear": mutationBodyNone,
	// NOTE the DHCP clear below is deliberately NOT here even though it too
	// answers without a body when no DHCP client is running: that early return
	// is a property of the daemon's state, not of the route, and the handler
	// decodes as soon as a client exists.
	// The DHCP clear is NOT in that class despite its name: #4794 made it
	// DECODE an optional {"interface":...} body whenever ContentLength is
	// non-zero, so its handler does block on the caller and must keep the
	// buffered-body ordering. Its payload is one interface name.
	//
	// OPERATOR-VISIBLE CHANGE: this route used to 413 only past the handler's
	// own MaxBytesReader (maxRequestBodyBytes, 16 MiB, pkg/api/dhcp.go); the
	// gate now answers 413 above 64 KiB. Nothing legitimate is affected — the
	// body is one interface name — but the threshold moved by three orders of
	// magnitude, so it is stated here and in pkg/api/README.md rather than left
	// for an operator to discover from a 413.
	"POST /api/v1/dhcp/identifiers/clear": mutationBodySmall,

	// Diagnostics: a target plus a handful of scalars.
	"POST /api/v1/diagnostics/ping":       mutationBodySmall,
	"POST /api/v1/diagnostics/traceroute": mutationBodySmall,

	// The candidate LIFECYCLE verbs, and the commit family that acts on
	// whatever the candidate already holds. Every one of these is addressed by
	// the X-Config-Session header alone — enter mints or re-enters a session,
	// exit/commit/confirm name one, and commit-check takes no request at all
	// (its handler's signature is `_ *http.Request`). None of them reads a byte
	// of body, so none of them is buffered.
	"POST /api/v1/config/enter":        mutationBodyNone,
	"POST /api/v1/config/exit":         mutationBodyNone,
	"POST /api/v1/config/commit":       mutationBodyNone,
	"POST /api/v1/config/commit-check": mutationBodyNone,
	"POST /api/v1/config/confirm":      mutationBodyNone,

	// Configuration edits: the routes that really do carry one.
	"POST /api/v1/config/set":              mutationBodyEdit,
	"POST /api/v1/config/delete":           mutationBodyEdit,
	"POST /api/v1/config/deactivate":       mutationBodyEdit,
	"POST /api/v1/config/activate":         mutationBodyEdit,
	"POST /api/v1/config/commit-confirmed": mutationBodyEdit,
	"POST /api/v1/config/rollback":         mutationBodyEdit,
	"POST /api/v1/config/annotate":         mutationBodyEdit,

	// The only route that legitimately carries a whole configuration.
	"POST /api/v1/config/load": mutationBodyLoad,

	// Destructive maintenance: an action verb and its options.
	"POST /api/v1/system/action": mutationBodySmall,
}

// mutationBodyLimit returns the buffer ceiling for a guarded route.
func mutationBodyLimit(route string) int64 {
	if n, ok := restMutationBodyLimits[route]; ok {
		return n
	}
	return mutationBodySmall
}

type peerIdentityKey struct{}

// peerLookupTimeout bounds how long a CONNECTION's peer lookup may take. It only
// elapses if the socket-table read is wedged; expiry yields no identity, which
// denies.
//
// The deadline is per connection, not per request: it is stamped when the lookup
// starts at accept, so a wedged table costs one connection at most this long in
// total rather than this long on every request the connection makes.
const peerLookupTimeout = 5 * time.Second

// peerWaitersInFlight counts requests currently PARKED in pendingPeer.wait
// inside the mutation gate — i.e. requests that have reached authorizeInputs and
// are blocked on their connection's accept-time lookup.
//
// It is the other half of the pair peerLookupSlots already forms: that gauge
// counts lookups in flight on the ACCEPT side, this one counts requests waiting
// on them on the REQUEST side, and a wedge shows up as both pinned at once.
//
// It also gives a test a genuine happens-before edge for the ordering
// authorizeInputs exists to enforce. Everything the gate reads is read after the
// wait, so "a waiter is parked" is the only externally observable moment at
// which a test can know the gate has started and has not yet read anything —
// which is exactly the window a commit has to land in to prove the ordering.
// Without it a test can only sleep and hope, and a sleep that lands early makes
// the DEFECT look fixed. One atomic add per mutating request, on a surface that
// answers a handful of operator actions per second.
var peerWaitersInFlight atomic.Int64

// PeerIdentityWaitersForTest reports how many requests are parked awaiting their
// connection's peer lookup. Test-only.
func PeerIdentityWaitersForTest() int { return int(peerWaitersInFlight.Load()) }

// pendingPeer is a connection's peer identity, resolved once, asynchronously,
// starting at accept.
//
// client and server are the connection's own addresses, kept because
// http.Request exposes RemoteAddr only as a string and no local address at all —
// and the credential row has to re-derive locality from them (see principal()).
type pendingPeer struct {
	done           chan struct{}
	deadline       time.Time
	client, server net.Addr
	id             authz.PeerIdentity
}

// wait blocks until the lookup finishes, the request context is cancelled, or
// the connection's lookup deadline passes. ok=false means no identity is
// available and the caller must deny.
func (p *pendingPeer) wait(ctx context.Context) (authz.PeerIdentity, bool) {
	select {
	case <-p.done:
		return p.id, true
	default:
	}
	remaining := time.Until(p.deadline)
	if remaining <= 0 {
		return authz.PeerIdentity{}, false
	}
	t := time.NewTimer(remaining)
	defer t.Stop()
	select {
	case <-p.done:
		return p.id, true
	case <-ctx.Done():
		return authz.PeerIdentity{}, false
	case <-t.C:
		return authz.PeerIdentity{}, false
	}
}

// connContext is the http.Server ConnContext hook (wired by buildHTTPServer /
// buildHTTPSServer). It STARTS the peer lookup for this connection, at accept,
// and hands every request on the connection the same pending result.
//
// Why it is started at accept rather than at the authorization check: the first
// version deferred it, reasoning that the client is blocked awaiting a response
// and so its socket is established for exactly the window that matters. That
// assumed a COOPERATIVE client and was wrong — `shutdown(fd, SHUT_WR)` leaves
// ESTABLISHED while still letting the caller read the response, so the caller
// could choose the moment of the lookup and choose to make it fail. Starting it
// at accept takes that choice away: the inputs are fixed when the connection is
// established, which is the SO_PEERCRED semantic this stands in for.
//
// Why it runs in a goroutine rather than inline: ConnContext executes SERIALLY
// in http.Server's accept loop, and a peer whose socket is not found costs a
// full walk of the socket table. Connection churn would then serialize those
// walks behind Accept and fill the listen backlog — locking out remote
// administrators before api-auth is even evaluated. Off the accept path, the
// listener keeps accepting; a request that arrives before its lookup finishes
// simply waits for it, and a wedged lookup denies rather than hangs. The
// ESTABLISHED guarantee is unaffected: the lookup is started at accept, not at
// request time, so its timing is still outside the caller's control.
//
// authz.LookupPeer reads the socket table for EVERY peer — it used to skip the
// read for one it classified off-box, but that made a cached address answer
// decisive on the only row a credential may speak for. The single-flight batcher
// in socketscan.go is what makes the unconditional read affordable: 120
// concurrent fresh connections cost 3 table reads.
func (s *Server) connContext(ctx context.Context, c net.Conn) context.Context {
	client, server := c.RemoteAddr(), c.LocalAddr()
	p := &pendingPeer{
		done:     make(chan struct{}),
		deadline: time.Now().Add(peerLookupTimeout),
		client:   client,
		server:   server,
	}
	// Bound the in-flight lookups (#5561 round 7, MAJOR-5b).
	//
	// The request-side deadline (pendingPeer.wait) stops the REQUEST waiting; it
	// does not stop this goroutine, and nothing else does either. The wedge that
	// motivates the bound is inside localAddrsFn() holding localAddrCache.mu, so
	// a context would not unblock it — cancellation is not available here, only
	// admission control. Without a cap, continued connections against a wedged
	// enumeration accumulate goroutines and their captured addresses without
	// limit, which an unauthenticated caller can drive.
	//
	// Past the cap the connection is resolved IMMEDIATELY to an unattributable
	// LOCAL identity, which denies — the same answer a timed-out lookup produces,
	// reached without spawning anything.
	// #6974: the pool is chosen by whether this connection can reach the
	// enumeration the budget bounds. The ACQUIRE STAYS HERE, at accept, and the
	// slot is still held across s.lookupPeer — which is what calls
	// authz.LookupPeer and therefore the wedge. Moving the acquire later (after
	// authentication, say) would move it past the thing it protects and bound
	// nothing; what moves here is only WHICH bounded pool a connection draws on.
	pool := peerLookupPoolFor(client, server)
	select {
	case pool <- struct{}{}:
		go func() {
			// #6977: ORDER IS THE INVARIANT (defers are LIFO) — pkg/api/README.md.
			defer close(p.done)
			defer func() { <-pool }()
			p.id = s.lookupPeer(client, server)
		}()
	default:
		p.id = authz.PeerIdentity{
			Local:  true,
			Detail: "peer-identity lookup capacity exhausted; refusing to queue another",
		}
		close(p.done)
	}
	return context.WithValue(ctx, peerIdentityKey{}, p)
}

// peerIsLocalNow re-derives the caller's locality at the moment a credential is
// about to speak for it — see principal(). Config.PeerLocalityFn overrides the
// kernel-backed answer so a test can state an off-box premise its real loopback
// listener contradicts; production leaves it nil.
func (s *Server) peerIsLocalNow(p *pendingPeer) bool {
	if fn := s.peerLocalityFn; fn != nil {
		return fn(p.client, p.server)
	}
	return authz.PeerCouldBeLocalNow(p.client, p.server)
}

// requestIdentity is the half of the authorization inputs that is FIXED for the
// life of ONE request: the connection's peer identity (resolved once, starting
// at accept) and — on the credential row only — the locality re-derivation.
//
// It exists because mutationAuthzGuard adjudicates TWICE, once before it reads
// the caller's body and once after (see that function). Re-deriving these on the
// second pass would buy nothing and cost something: a connection's client and
// server addresses are fixed at accept and its kernel-reported UID with them, so
// both passes would read the same answer, while peerIsLocalNow drives a full
// interface enumeration. The LIVE half — the config snapshot and the api-auth
// credential, the two things a commit can change underneath an in-flight
// request — is deliberately NOT memoized and is re-read on every pass.
//
// The residual this fixes in place rather than closing: locality is answered
// from an enumeration started on the FIRST pass, so an address added to this
// host while the body was being read is not seen. That is the same direction
// pkg/api/README.md "Residuals" already names for the accept-time snapshot (a
// scan cannot observe an address that arrives after it), widened from the
// snapshot's TTL to the body window. It is not a new direction of failure, and
// the alternative — an enumeration per pass — makes every credentialed mutation
// pay twice for an answer about addresses that did not change.
type requestIdentity struct {
	pending      *pendingPeer
	id           authz.PeerIdentity
	localityDone bool
	local        bool
}

// isLocalNow answers the credential row's locality question for ri, driving at
// most ONE enumeration per request however many passes ask.
func (s *Server) isLocalNow(ri *requestIdentity) bool {
	if ri.localityDone {
		return ri.local
	}
	ri.local = s.peerIsLocalNow(ri.pending)
	ri.localityDone = true
	return ri.local
}

// lookupPeer resolves the peer identity through the injected resolver
// (Config.PeerLookupFn) or pkg/authz's kernel lookup, normalizing the result.
//
// The normalization exists because an injected resolver is not bound by
// LookupPeer's invariants and could report the nonsensical (OK, !Local): an
// attributed peer is local by construction — we read its UID out of THIS host's
// socket table. Left unnormalized, that state would reach the precedence rule as
// "attributed but off-box", a combination the policy has no row for.
func (s *Server) lookupPeer(client, server net.Addr) authz.PeerIdentity {
	fn := s.peerLookupFn
	if fn == nil {
		fn = authz.LookupPeer
	}
	id := fn(client, server)
	if id.OK {
		id.Local = true
	}
	return id
}

func peerIdentityFrom(ctx context.Context) (*pendingPeer, bool) {
	p, ok := ctx.Value(peerIdentityKey{}).(*pendingPeer)
	return p, ok
}

// activeConfig returns the active config snapshot the login model is read from,
// or nil when the store is unwired or no config is active yet (early boot).
//
// A nil snapshot does not fail the box open: pkg/authz resolves UID 0 without
// consulting it, and every other principal resolves to "not a configured login
// user", which denies.
func (s *Server) activeConfig() *config.Config {
	if s.store == nil {
		return nil
	}
	return s.store.ActiveConfig()
}

// authorizeInputs resolves BOTH inputs to the authorization decision — the
// caller's principal and the config snapshot that principal is evaluated
// against — in an order that keeps the snapshot fresh (#5561 round 9, finding 1).
//
// The order is the point. mutationAuthzGuard used to read the snapshot first
// and then call principal(), whose FIRST action is pendingPeer.wait — the only
// unbounded block in the gate, up to peerLookupTimeout (5s). The decision was
// therefore evaluated against a config captured up to five seconds before it,
// and a commit landing inside that window did not reach it: a `super-user`
// demoted to `read-only`, or deleted from `system login user` outright, kept
// its old authority for every request whose peer lookup was slow — and a caller
// can make its own lookup slow by connecting while the socket table is
// contended. Reading the snapshot AFTER the wait means the window between the
// read and Authorize() contains no blocking call at all.
//
// The residual is stated rather than papered over: on the peer-UID row a
// /etc/passwd read still separates the two (bounded, local, no lock held), and
// on the credential row a locality re-derivation does (~32 µs, single-flighted)
// — which is why the credential is RE-VALIDATED after it, see principalFrom.
// A config snapshot and a decision cannot be made simultaneous without holding
// the store's lock across the whole gate; they can be made adjacent, and that
// is what this ordering buys.
// A nil third return means the request denied before any connection-fixed
// identity was established, so there is nothing for a later pass to re-derive
// against; the caller must refuse without re-adjudicating.
func (s *Server) authorizeInputs(r *http.Request) (*config.Config, authz.Principal, *requestIdentity) {
	pending, ok := peerIdentityFrom(r.Context())
	if !ok {
		// No ConnContext ran for this connection, so we cannot even tell whether
		// the caller is local — and therefore cannot tell whether a credential
		// is allowed to speak for it. Refuse rather than guess.
		return s.activeConfig(), authz.Unauthenticated("connection identity was not captured at accept"), nil
	}
	// THE BLOCKING STEP. Nothing that feeds the decision may be read before it.
	peerWaitersInFlight.Add(1)
	id, resolved := pending.wait(r.Context())
	peerWaitersInFlight.Add(-1)
	if !resolved {
		return s.activeConfig(),
			authz.Unauthenticated("peer identity lookup did not complete for this connection"),
			nil
	}
	ri := &requestIdentity{pending: pending, id: id}
	cfg := s.activeConfig()
	return cfg, s.principalFrom(r, cfg, ri), ri
}

// reauthorizeInputs re-derives the decision's LIVE half — a fresh config
// snapshot and a fresh credential validation — against the connection-fixed
// identity authorizeInputs already resolved.
//
// It is the second pass of mutationAuthzGuard's two-pass adjudication, and the
// only reason it is a separate function is that the first pass's blocking steps
// (the peer wait, the interface enumeration) must NOT run again: repeating them
// would re-answer questions whose inputs are fixed at accept while paying their
// full cost on every mutating request. What it does repeat is exactly what a
// concurrent commit can change — s.activeConfig() and s.auth — so a demotion, a
// deletion from `system login user`, or an api-auth revocation that lands while
// the caller is still sending its body reaches the verdict that admits the
// mutation.
func (s *Server) reauthorizeInputs(r *http.Request, ri *requestIdentity) (*config.Config, authz.Principal) {
	cfg := s.activeConfig()
	return cfg, s.principalFrom(r, cfg, ri)
}

// principalFrom derives the caller's server-side identity for one request (#5561).
//
// The precedence rule is: IF THE CALLER IS ON THIS HOST, THE LOGIN MODEL IS THE
// ONLY AUTHORITY. An api-auth credential may speak only for a caller that is not
// local.
//
// This has been narrowed twice, each time because a weaker version had a hole
// the claim above did not admit to:
//
//   - v1 used the peer UID when the lookup SUCCEEDED and fell back to the
//     credential otherwise. The caller controlled whether it succeeded
//     (half-close), so a `read-only` account holding the shared secret reached
//     full power.
//   - v2 denied an UNATTRIBUTABLE local caller but still let the credential
//     speak for an ATTRIBUTED one that was not a configured `system login user`.
//     That is the population #5561 exists to constrain, and it made the
//     per-principal gate optional for anyone holding the password. The operator
//     doc already said such a caller is denied; the code did not.
//
// So the four outcomes are:
//
//  1. Local, attributed to a configured `system login user` — that class decides.
//  2. Local, attributed to an account the login model does not cover — DENIED.
//     Grant it a class if it needs access; that is the one place access is
//     supposed to be written down.
//  3. Local, not attributable — DENIED.
//  4. Not on this host — a remote administrator, which is exactly what the
//     api-auth credential exists to identify (#4047 requires one for any
//     off-loopback bind).
//
// Rows 1-3 collapse to: a caller this host CAN PLACE never reaches s.credential.
//
// "Can place", not "local" — the two differ and the difference is a residual,
// not a quibble. Placement is namespace-scoped (a container on this box has its
// own /proc/net/tcp and its own interface list, so it is local to the machine and
// unplaceable by this daemon) and time-scoped (an address can arrive or leave
// between the two observations). A caller this host cannot place IS governed by
// the api-auth credential, which is what #4047 makes that credential for. See
// pkg/api/README.md "Residuals".
//
// Row 4 carries one more obligation, because it is the only row that ADMITS on
// the strength of a negative. The accept-time verdict "not on this host" is
// drawn from a cached interface-address snapshot that lags an address ADD by up
// to authz's localAddrTTL, so a caller connecting from an address added to this
// host within the last second reaches row 4 while genuinely being local. The row
// therefore re-derives locality from a fresh enumeration before honoring the
// credential (peerIsLocalNow). That re-derivation can only move a caller from
// row 4 to a denial — never the other way — so it narrows row 4 without widening
// anything. It closes the direction that motivated it (an address ADDED since the
// snapshot); it cannot close the reverse, because a scan cannot observe an address
// that is already gone.
//
// The ORDER in which its two inputs are obtained — the peer wait and the config
// read — is argued on authorizeInputs, which is the only caller.
func (s *Server) principalFrom(r *http.Request, cfg *config.Config, ri *requestIdentity) authz.Principal {
	// The listener's OWN authentication gate is evaluated exactly once, by
	// dynamicAuthMiddleware, before this middleware is entered — which is
	// before the caller has supplied its body. Re-evaluate it HERE so the
	// gate's second pass answers to the LIVE snapshot (#5561 round 10,
	// finding 1).
	//
	// Without this, only the credential row below re-validated, and it is the
	// row a local caller never reaches. So an attributed LOCAL administrator
	// could hold the window open with a withheld body while another session
	// rotated the credential it had presented, and the mutation still ran on
	// the revoked secret: pass 2 refreshed the login class and nothing else.
	// The nil -> non-nil direction is the same hole in its worst spelling — a
	// request admitted while the listener had NO api-auth policy stayed
	// credentialless after a commit ADDED one, so a tightening the operator
	// committed did not reach the request it was committed to stop.
	//
	// It is routed through credentialPrincipalUser rather than authCheck
	// because authCheck's two exemptions (/health always, /metrics on a
	// loopback bind) are GET-only paths that isSafeHTTPMethod already returned
	// before the gate ran; on a mutating route the two are the same predicate.
	//
	// A nil snapshot is not a failure: it means this listener has no api-auth
	// policy at all, which the #4047/#5127 clamp confines to a loopback bind.
	// The denial is a 403 rather than the middleware's 401 because it is the
	// gate that writes it; a caller racing a credential change gets a refusal
	// with a reason either way.
	if a := s.auth.Load(); a != nil {
		if _, ok := credentialPrincipalUser(*a, r); !ok {
			return authz.Unauthenticated(
				"api-auth credential was revoked, rotated, or newly required while this " +
					"request was being adjudicated")
		}
	}
	id := ri.id
	if id.OK {
		// (1) and (2). PrincipalForUID yields an unresolved principal for an
		// account outside the login model, which Authorize denies — and no
		// credential is consulted on the way there.
		return authz.PrincipalForUID(cfg, id.UID)
	}
	if id.Local {
		return authz.Unauthenticated("caller is local but could not be identified: " + id.Detail)
	}
	if _, ok := s.credential(r); ok {
		// (4), but only once the off-box verdict is confirmed against an
		// enumeration started by THIS request. The verdict that got us here was
		// cached at accept and lags an address add; a caller that is in fact on
		// this host must be denied even holding a valid credential, which is the
		// precedence rule this function states.
		//
		// The position is deliberate and load-bearing: INSIDE the credential
		// branch, so a request that presents no valid credential drives no
		// interface enumeration. State the scope precisely, because an earlier
		// version of this comment did not and the test written from it was
		// vacuous. On a listener that HAS api-auth, dynamicAuthMiddleware
		// (server.go listenerHandler) already answers a missing or wrong
		// credential with a 401 and this function is never reached — so the
		// ordering buys nothing there. It matters on a listener with NO api-auth
		// snapshot, where the middleware passes everything through, s.credential
		// fails here on the nil snapshot, and hoisting this check would enumerate
		// once per request for any caller that can open a socket.
		// TestUncredentialedCallerDrivesNoLocalityRecheck_5561 and
		// TestOffLoopbackCredentialRowEnumeratesOnlyOnce_5561 both fail if it is
		// hoisted, and both fail if it is removed.
		//
		// Memoized on ri so the gate's second pass (reauthorizeInputs) reuses the
		// verdict rather than enumerating again — see requestIdentity.
		if s.isLocalNow(ri) {
			return authz.Unauthenticated("caller is local but could not be identified: " +
				"peer address is assigned to this host, so an api-auth credential may not speak for it")
		}
		// DERIVE the principal from the LIVE snapshot, here, rather than from the
		// one that opened this branch (#5561 round 9, finding 2).
		//
		// The check above answers only "does this caller hold a valid credential
		// at all", which is what gates the enumeration; the principal it built is
		// deliberately discarded. That principal is a VALUE, and ReplaceAuth
		// swaps a pointer — it cannot reach anything already constructed — so
		// returning it would let a rotated or revoked credential finish a request
		// it no longer authorizes. That is not a theoretical nanosecond:
		// peerIsLocalNow sits between the two and BLOCKS, taking hostAddrScan's
		// single-flight, so a request can wait out another goroutine's whole
		// interface enumeration in that gap. An operator revoking a LEAKED secret
		// is entitled to have it stop working, and the whole point of ReplaceAuth
		// (#5866) is that revocation needs no listener bounce.
		//
		// Re-checking the credential rather than comparing snapshot POINTERS is
		// deliberate: reconcileTo republishes on every commit, so pointer
		// identity would 403 a valid caller for an unrelated commit. This denies
		// exactly when the presented credential no longer satisfies the live
		// policy, and it costs one more constant-time compare on a row that has
		// already proven it holds a valid secret.
		live, still := s.credential(r)
		if !still {
			return authz.Unauthenticated(
				"api-auth credential was revoked or rotated while this request was being adjudicated")
		}
		return live
	}
	return authz.Unauthenticated(id.Detail)
}

// credential returns the principal for a valid api-auth credential on r, if the
// listener has an auth policy and the request satisfies it.
func (s *Server) credential(r *http.Request) (authz.Principal, bool) {
	a := s.auth.Load()
	if a == nil {
		return authz.Principal{}, false
	}
	user, ok := credentialPrincipalUser(*a, r)
	if !ok {
		return authz.Principal{}, false
	}
	return authz.CredentialPrincipal(user), true
}

// credentialPrincipalUser reports whether r presented a VALID configured
// api-auth credential, and the Basic username it authenticated as ("" for a
// Bearer / X-API-Key token, which names no user).
//
// It routes through the same checkAuthorization / constantTimeAPIKeyMatch
// helpers the auth middleware uses, so the #4157 constant-time and #5636
// empty-secret properties are the middleware's, not a second implementation of
// them. The username is read back only AFTER the credential validated, so a
// wrong password never yields a name.
func credentialPrincipalUser(cfg AuthConfig, r *http.Request) (string, bool) {
	if auth := r.Header.Get("Authorization"); auth != "" && checkAuthorization(auth, cfg) {
		if !strings.HasPrefix(auth, "Basic ") {
			return "", true // Bearer token — authenticated, names no user
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			// Unreachable: checkAuthorization already decoded it.
			return "", true
		}
		user, _, _ := strings.Cut(string(payload), ":")
		return user, true
	}
	if key := r.Header.Get("X-API-Key"); key != "" && constantTimeAPIKeyMatch(cfg, key) {
		return "", true
	}
	return "", false
}

// mutationAuthzGuard rejects a state-changing request whose caller the server
// cannot authorize (#5561). Safe methods pass through untouched.
// readAuthz adjudicates a SAFE (read) request against restReadPermissions
// (#6660) and either serves it or refuses it.
//
// It is deliberately SIMPLER than the mutation path above, and the difference is
// the point rather than an omission. The mutation gate adjudicates TWICE and
// drains the body between the two passes, because a caller owns its body and can
// hold an authorization open for the whole read timeout. A GET has no body to
// withhold: the handler is entered immediately, so there is no window between
// the verdict and the action for a revocation to fall into. One pass is the
// whole decision here.
//
// An UNGUARDED safe route is served, not refused -- the opposite of the mutation
// gate's fail-closed default. That asymmetry is deliberate too. /health and
// /metrics are safe routes with no entry in the table and must keep serving:
// authCheck already exempts them, the in-tree incus harnesses read /metrics, and
// a fail-closed default here would break them at the first request. The cost is
// that a NEW read route added without a table entry serves unauthenticated --
// which is why TestEveryReadRouteHasAPermission_6660 enumerates the mux and
// fails on any /api/v1 GET the table does not cover, moving that risk from
// runtime to the test suite.
// readPermissionFor resolves the permission guarding a SAFE request, keyed on
// (method, path), and adjudicates a non-GET safe method against the GET entry.
//
// #9134: HEAD WAS A COMPLETE AUTHORIZATION BYPASS ON ALL 40 GUARDED READ ROUTES.
// isSafeHTTPMethod admits HEAD, the lookup was keyed on `r.Method + " " + path`,
// and restReadPermissions holds 40 `"GET "` keys and ZERO `"HEAD "` keys. An
// unknown key is the deliberate fail-OPEN arm (so /health and /metrics keep
// serving), so every HEAD landed there and was handed straight to the mux --
// which routes HEAD to the GET pattern DIRECTLY, no redirect. The handler ran
// with no authorization decision at all:
//
//	GET  /api/v1/config         403  permission denied ... class ""
//	HEAD /api/v1/config         200  handler executed
//	HEAD /api/v1/config/export  200  clen=168   exact body SIZE disclosed
//	HEAD /api/v1/routing/ospf   200  clen=55    the FRR handler ran
//
// A response to HEAD carries no body, but Content-Length is the body's exact
// size and the status code separates "exists and you may not see it" from
// "exists"; both are read access to information the GET was refused.
//
// FIXING IT BY ADDING 40 "HEAD " KEYS WOULD BE THE WRONG SHAPE. The table would
// then have to be edited twice per route forever, and the next safe method Go's
// mux learns to alias reopens the hole. Resolving the alias HERE means the table
// stays keyed on the route as it is served, and a route added with only a GET
// entry is guarded under every safe method that can reach its handler.
//
// The fall-through for a genuinely unknown path is unchanged: /health and
// /metrics have no entry and must keep serving.
func readPermissionFor(method, path string) (config.LoginClassPermission, bool) {
	if required, known := restReadPermissions[method+" "+path]; known {
		return required, true
	}
	// A safe method other than GET reaches the GET handler through the mux, so
	// it is the GET entry that governs it.
	if method != http.MethodGet && isSafeHTTPMethod(method) {
		if required, known := restReadPermissions[http.MethodGet+" "+path]; known {
			return required, true
		}
	}
	return 0, false
}

// candidateConfigReadPermission returns the permission a request requires when
// it selects the CANDIDATE configuration, and ok=false otherwise (#9324).
//
// The (method, path) table cannot express this: one route serves both targets,
// and the target is in the query string. Resolving it HERE keeps the table
// keyed on the route as it is served — the same reasoning the #9134 HEAD-alias
// fix records above — instead of asking every config handler to remember its
// own authorization.
//
// Reading a candidate costs PermConfig: it is another session's uncommitted
// work, and on Junos seeing a candidate is a configure-mode activity that a
// class without `configure` cannot reach.
func candidateConfigReadPermission(r *http.Request) (config.LoginClassPermission, bool) {
	switch r.URL.Path {
	case "/api/v1/config/compare":
		// compare renders candidate-vs-active (or candidate-vs-rollback): both
		// branches read s.candidate, so work-in-progress is the only thing this
		// route can produce. There is no target parameter that would make the
		// answer right for a view-only caller, so the route is priced, not
		// defaulted.
		return config.PermConfig, true
	case "/api/v1/config/show":
		if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("target")), "candidate") {
			return config.PermConfig, true
		}
	}
	return 0, false
}

func (s *Server) readAuthz(w http.ResponseWriter, r *http.Request, next http.Handler) {
	required, known := readPermissionFor(r.Method, r.URL.Path)
	if !known {
		next.ServeHTTP(w, r)
		return
	}
	// #9324: a candidate-configuration read is priced above the route's table
	// entry. Applied after the lookup so an unguarded route stays unguarded
	// (/health, /metrics) and a guarded one can only get STRICTER here.
	if candidatePerm, isCandidateRead := candidateConfigReadPermission(r); isCandidateRead {
		required = candidatePerm
	}
	cfg, p, _ := s.authorizeInputs(r)
	if err := authz.Authorize(cfg, p, required); err != nil {
		// Debug, not Warn: caller-driven and reachable unauthenticated, so a
		// Warn here is a log-amplification lever -- the same reasoning the
		// mutation denial states.
		slog.Debug("api: refused unauthorized read",
			"method", r.Method, "path", r.URL.Path,
			"principal", p.String(), "source", p.Source.String(),
			"required", authz.PermissionName(required), "err", err)
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	// #9952: the class's `deny-commands` / `allow-commands` regexes. This
	// surface consulted NONE of them — the coarse bit and the
	// `*-configuration` pair were the whole of REST authorization, while
	// docs/system-login.md claimed all four were enforced. See
	// authz_command_regex_9952.go for the route -> canonical command table and
	// why an unmapped route denies.
	if err := s.authorizeRESTCommand(r, cfg, p); err != nil {
		slog.Debug("api: refused read denied by the class's command regexes",
			"method", r.Method, "path", r.URL.Path,
			"principal", p.String(), "err", err)
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	// #9051: the verdict above is a point-in-time answer, and an SSE handler
	// runs indefinitely. Keep checking for as long as the handler runs, so a
	// revoked principal loses the feed rather than keeping it until it
	// disconnects. Cheap and inert for an ordinary GET, which returns long
	// before the first tick.
	r, stop := s.watchReadAuthorization(r, required)
	defer stop()
	next.ServeHTTP(w, r)
}

func (s *Server) mutationAuthzGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeHTTPMethod(r.Method) {
			s.readAuthz(w, r, next)
			return
		}
		// Exact match on the registered pattern. The path is NOT cleaned or
		// normalized first: cleaning can only widen what matches, and a
		// non-canonical spelling of a guarded route must fail closed here
		// rather than reach the mux's redirect.
		route := r.Method + " " + r.URL.Path
		required, known := restMutationPermissions[route]
		if !known {
			// Debug for the same reason as the denial below: caller-driven and
			// unauthenticated, so a Warn here is a log-amplification lever.
			slog.Debug("api: refused unguarded mutating request",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			writeError(w, http.StatusForbidden,
				"permission denied: no authorization policy is defined for this mutating endpoint")
			return
		}

		// ONE config snapshot for BOTH the principal's class and the
		// authorization decision (#5561 round 7), read AFTER the peer wait
		// (#5561 round 9).
		//
		// These used to be two independent ActiveConfig() reads. A commit landing
		// between them meant the class was copied out of config A while the
		// decision was evaluated against config B — so a `super-user` demoted to
		// `read-only`, or deleted from `system login user` outright, kept the
		// authority its old class carried for the duration of an in-flight
		// request. Authorize() re-validates p.Class against the cfg it is given
		// (ResolveClassPermissions + ClassHasPermission), so reading once and
		// passing the same pointer to both makes a revoked or demoted principal
		// evaluate against the config that revoked it. No test caught this
		// because every authorization fixture holds its store immutable for the
		// whole request.
		//
		// Round 7 made the two reads one, but left the one read BEFORE the gate's
		// blocking peer wait, which reopened the same demotion window at up to
		// peerLookupTimeout wide. authorizeInputs does the wait first and reads
		// the snapshot after it — see its doc comment.
		//
		// # Why the decision is made TWICE
		//
		// Ordering the gate's own blocking steps is not sufficient, because the
		// gate is not the last thing that blocks before the mutation runs. The
		// handler is, and it blocks on the one input the CALLER owns outright:
		// its request body. `decodeJSONBody` reads it after this middleware has
		// already returned its verdict, for as long as apiReadTimeout allows
		// (30s), and the caller chooses how long that takes. So
		//
		//	send headers for POST /api/v1/system/action, withhold the body
		//	  -> gate authorizes, handler entered, handler parks in Decode
		//	another session revokes the credential / demotes the class
		//	  -> nothing re-reads it
		//	supply {"action":"reboot"}
		//	  -> the box reboots on an authorization made 30 seconds ago
		//
		// That is the same TOCTOU the ordering above closes, one layer later, and
		// it is the layer that matters: an authorization is a statement about the
		// moment the action runs, not about the moment the headers arrived.
		//
		// So the body is drained HERE, between two adjudications:
		//
		//	pass 1  fail-fast, and the reason it comes FIRST is availability, not
		//	        authorization. Buffering before deciding would let any caller
		//	        that can open a socket park the daemon's memory behind a 30s
		//	        read timeout. With the check first, only a principal already
		//	        authorized for THIS route can make the daemon hold a buffer.
		//	        Authorization is a necessary bound and not a sufficient one,
		//	        though — the cheapest permission on the surface (PermView, a
		//	        `read-only` shell account, on /diagnostics/ping) is still a
		//	        principal — so the drain is ALSO bounded per route, in
		//	        aggregate, and by privilege tier within that aggregate, the
		//	        last of these because a shared bound is itself something an
		//	        authorized caller can spend to deny someone above it. See
		//	        restMutationBodyLimits, mutationBodyBudgetBytes and
		//	        mutationBodyTierCeilings.
		//	drain   the caller-controlled block, moved in front of the verdict
		//	        that admits the mutation.
		//	pass 2  the verdict the handler actually runs under. It re-reads the
		//	        config snapshot and re-validates the credential (the live
		//	        half); the connection-fixed half is reused — requestIdentity
		//	        says why.
		//
		// The residual is stated, not papered over: a handler that reads the body
		// in pieces, or blocks on something else of the caller's choosing after
		// the decode, reopens a window this cannot see. Every mutating handler
		// today decodes once, up front, through decodeJSONBody (or the equivalent
		// MaxBytesReader+Decode in dhcp.go) before it acts.
		deny := func(p authz.Principal, err error) {
			// Debug, not Warn: this fires once per DENIED request, and a
			// keep-alive loop from an unauthenticated caller is exactly the
			// cheapest way to drive it. The project's logging rule forbids
			// per-request Info/Warn on a caller-driven path (CLAUDE.md).
			slog.Debug("api: denied mutating request",
				"method", r.Method, "path", r.URL.Path,
				"principal", p.String(), "source", p.Source.String(),
				"required", authz.PermissionName(required), "err", err)
			writeError(w, http.StatusForbidden, err.Error())
		}

		cfg, p, ri := s.authorizeInputs(r)
		if err := authz.Authorize(cfg, p, required); err != nil {
			deny(p, err)
			return
		}
		if ri == nil {
			// Unreachable: authorizeInputs returns a nil identity only on paths
			// whose principal is Unauthenticated, which Authorize just denied.
			// Fail closed rather than serve a mutation whose verdict cannot be
			// re-made after the body.
			deny(p, errors.New("permission denied: connection identity is unavailable for re-adjudication"))
			return
		}

		// The drain is bounded in every dimension a caller controls: this
		// route's own ceiling, the aggregate across every request in flight,
		// and — because an aggregate is a shared resource and a shared resource
		// is a denial lever — the share of that aggregate this route's tier may
		// reach. The availability argument above needs all three: a per-request
		// cap says nothing about how many requests a caller opens, and an
		// undivided aggregate says nothing about WHOSE request gets refused
		// when it runs out.
		budget := bodyBudget{ceiling: mutationBodyTierCeiling(required)}
		defer budget.release()
		if !bufferMutationBody(w, r, mutationBodyLimit(route), &budget) {
			return
		}

		cfg, p = s.reauthorizeInputs(r, ri)
		if err := authz.Authorize(cfg, p, required); err != nil {
			deny(p, err)
			return
		}
		// #9154: the class's `*-configuration` regexes — see
		// authz_config_regex_9154.go for why this surface consulted none.
		if err := s.authorizeRESTConfigMutation(r, cfg, p); err != nil {
			deny(p, err)
			return
		}
		// #9892: `load` and `rollback` are adjudicated by CONTENT, not by a
		// path field — see restConfigContentRoutes.
		if err := s.authorizeRESTConfigLoad(r, cfg, p); err != nil {
			deny(p, err)
			return
		}
		// #9952: the operational command regexes, on the mutating side. The
		// config-mode routes are DECLARED as having no operational command —
		// they are governed by the `*-configuration` pair just above — so this
		// charges the clear, diagnostic and system-action endpoints, which is
		// exactly the matrix the issue names (POST /api/v1/system/action
		// reaches reboot and halt).
		if err := s.authorizeRESTCommand(r, cfg, p); err != nil {
			deny(p, err)
			return
		}
		slog.Debug("api: authorized mutating request",
			"method", r.Method, "path", r.URL.Path,
			"principal", p.String(), "required", authz.PermissionName(required))
		next.ServeHTTP(w, r)
	})
}

// mutationBodyWaitersInFlight counts requests parked reading a mutating
// request's body inside the gate — i.e. requests that have passed the first
// adjudication and have not yet reached the second.
//
// Same role as peerWaitersInFlight, for the other blocking step: it is the only
// externally observable moment at which a test knows the gate is inside the
// window a revocation has to land in, so the guard for that window does not have
// to sleep and hope. One atomic add per mutating request that carries a body, on
// a surface that answers a handful of operator actions per second.
var mutationBodyWaitersInFlight atomic.Int64

// MutationBodyWaitersForTest reports how many mutating requests are parked
// reading their caller's body between the gate's two adjudications. Test-only.
func MutationBodyWaitersForTest() int { return int(mutationBodyWaitersInFlight.Load()) }

// mutationBodyBudgetBytes bounds the TOTAL request-body bytes the gate holds
// buffered across every mutating request in flight (#5561 round 10, finding 2;
// re-denominated and tiered in round 11).
//
// The per-route ceiling above bounds ONE request; it says nothing about a
// thousand. The gate holds its buffer for as long as the caller takes to send
// the body, which is up to apiReadTimeout (30s) and entirely the caller's
// choice, so per-request caps alone leave the daemon's heap a function of how
// many connections a caller opens: 64 half-sent 16 MiB posts from ONE
// `read-only` shell account would be a gigabyte of resident memory.
//
// This is the bound that makes the availability argument in mutationAuthzGuard
// true rather than merely intended: past it a request is REFUSED (429) instead
// of admitted to buffer, so the memory a caller can make the daemon hold is
// capped no matter how many sockets it opens.
//
// # What the number counts
//
// Bytes the gate has ALLOCATED, charged as the body arrives — not bytes the
// caller declared. That distinction is the whole of round 11's finding 1. A
// Content-Length is a promise; the memory only exists once the bytes do. The
// first shape of this budget charged the declaration and held it for the
// request's lifetime, which meant a caller could buy 64 KiB of budget with one
// byte of traffic — a 65536x amplification — and 1026 such sockets emptied the
// whole 64 MiB for about a kilobyte. bufferMutationBody therefore grows its
// charge with its buffer: a half-open request holds one small allocation and is
// charged for one small allocation.
//
// The number bounds PEAK resident bytes, not settled ones: a grow holds the old
// allocation and the new one at once and is charged for both. Sized against the
// real payloads rather than the ceilings — the largest configuration this
// daemon actually carries is well under a megabyte, so the 48 MiB the configure
// tier may drive is on the order of twenty concurrent `config/load`s, far above
// operator concurrency on a surface answering a handful of actions per second.
// At the pathological extreme, where a caller really does send a 16 MiB
// candidate, that same 48 MiB holds two at once and refuses the third with a
// 429 rather than growing the heap. Two rather than three because the PEAK a
// 16 MiB body drives is 24 MiB, not 16: the buffer's last doubling holds 8 MiB
// and 16 MiB at once across the copy. That 1.5x is why the ladder's steps below
// are sized in peak bytes rather than in body bytes (#5561 round 19, finding 1).
const mutationBodyBudgetBytes int64 = 64 << 20 // 64 MiB

// mutationBodyTierCeilings partitions that budget by the permission the ROUTE
// requires, so exhausting one tier does not refuse the tiers above it (#5561
// round 11, finding 1). Under the SYSTEM-DEFINED login classes that is the same
// statement as "exhausting it is not a way to deny someone more privileged than
// you", which is how this comment used to put it, unqualified. Under a CUSTOM
// login class the two come apart; the scope section below says exactly where,
// and why no assignment of the numbers in this table repairs it (#6954).
//
// A single undivided pool is a bound in one dimension and a denial lever in
// another. Pass 1 guarantees only that a buffering caller is authorized for the
// route it is calling, and the cheapest permission on this surface (PermView,
// held by a `read-only` shell account, on /diagnostics/ping) is authorized for
// something. With one pool, that account's traffic and a super-user's `commit`
// draw on the same bytes, so the view tier could take all of them and 429 the
// configure tier off the entire mutating surface.
//
// The ladder fixes that the way a filesystem reserves blocks for root: a
// request may be admitted only while the running total is within ITS tier's
// share, and the shares increase with privilege. Whatever the view tier takes,
// it stops at 8 MiB — so 56 MiB is permanently out of its reach; the clear tier
// stops at 16 MiB, leaving 48 MiB that belongs to the configure tier; and the
// configure tier in turn cannot take the last 16 MiB the maintenance verbs
// need. The total across every tier is still mutationBodyBudgetBytes, so the
// memory bound is unchanged.
//
// The guarantee is one-directional, and deliberately so. Each ceiling is tested
// against the AGGREGATE, so a tier is protected from every tier below it and
// from none above it: a configure-tier flood can push the total past 16 MiB and
// refuse view-tier traffic outright. That is the correct asymmetry — a
// privileged action crowding out a cheap one is scheduling, a cheap one
// crowding out a privileged one is a denial primitive — and it is the whole
// reason the shares are ordered rather than equal. "Privileged" and "cheap"
// there are properties of the TIER; the premise that makes them properties of
// the CALLER is examined in the scope section below.
//
// Which is exactly why VIEW gets half of what clear gets, rather than the same
// 16 MiB round 11 first gave view, clear and control alike (#5561 round 18,
// finding 1). An aggregate-tested ceiling means a tier is only protected from the tiers
// STRICTLY BELOW it, and equal shares put no tier below any other: driven to
// its own 16 MiB, the view tier left the clear tier nothing, so 383 sockets on
// POST /api/v1/diagnostics/ping from a `read-only` account (PermView) made a
// super-user's 24-byte POST /api/v1/dhcp/identifiers/clear (PermClear) answer
// 429. `read-only` holds PermView and `operator` holds PermView + PermClear +
// PermControl (config.LoginClassPermissions), so that is a cheap permission
// denying a privileged one — the primitive this table exists to remove — and
// the round-11 split CREATED it, because before the split there was no budget
// to exhaust.
//
// The step sizes are chosen so every privilege step reserves the PEAK CHARGE of
// the largest body the tier above it can legitimately carry. Peak, not body
// size, and the distinction is load-bearing: bufferMutationBody charges what the
// buffer holds, a doubling holds the old allocation and the new one across the
// copy, so a body that steps to a route's limit L peaks at 1.5L. Round 18 stated
// these steps in BODY bytes, which left configure - clear one byte short of what
// a 16 MiB config/load really drove — the clear tier at its own ceiling made a
// super-user's config/load answer 429, which is precisely the primitive this
// table removes (#5561 round 19, finding 1).
//
//	clear - view          16 - 8 = 8 MiB   >= 96 KiB (peak of mutationBodySmall,
//	                                       the dhcp clear; the other clear verbs
//	                                       are mutationBodyNone and are never
//	                                       charged)
//	configure - view      48 - 8 = 40 MiB  >= 24 MiB (peak of mutationBodyLoad)
//	configure - clear     48 - 16 = 32 MiB >= 24 MiB (peak of mutationBodyLoad)
//	maint - view          64 - 8 = 56 MiB  >= 96 KiB (peak of mutationBodySmall)
//	maint - clear         64 - 16 = 48 MiB >= 96 KiB (peak of mutationBodySmall)
//
// Those five are exactly the steps tierLadderSteps() DERIVES, and the step loop
// checks each. The list above used to read "maint - configure 64 - 48" instead
// of the two maint rows, which inverted the truth in both directions: configure
// -> maint is NOT derived, because no built-in class holds PermConfig without
// PermMaint (super-user reaches both through PermAll; operator, read-only and
// config-viewer hold neither), so someClassSeparates is false and the loop never
// sees that pair — while maint - view and maint - clear ARE derived and were
// missing from the list.
//
// The configure -> maint reservation is still checked, just not here: a
// standalone assertion in authz_bodybudget_fairness_5561_test.go requires the
// budget's free space above the configure ceiling to cover the peak charge of a
// max-size `POST /api/v1/system/action` body (mutationBodySmall). It is NOT a
// max-size load: budget-configure is 64-48 = 16 MiB, while needFor(
// mutationBodyLoad) peaks at 24 MiB, so the load form would be false. The
// mutationBodyLoad assertions in that file are quantified over view and clear
// only.
// Keep this list in step with what the derivation produces — a table that names
// a step the loop cannot see reads as coverage that does not exist.
//
// and 8 MiB still holds 127 concurrent max-size view-route bodies (64 KiB
// each — the 128th cannot reach 64 KiB, its own last doubling would peak at
// 96 KiB), or ~16k of the few-hundred-byte ping and traceroute payloads the
// routes really carry, on a surface that answers a handful of operator actions
// per second — so the smaller share is not itself an availability regression.
// TestBodyBudgetTiersLeaveThePrivilegedTiersUnreachable_5561 derives both of
// those checks from the route tables rather than restating the numbers, and
// MEASURES the peak by driving bufferMutationBody rather than restating 1.5x.
//
// Keying on the ROUTE's required permission rather than on the CALLER's class
// is deliberate: it is the action that is being protected, and pass 1 has
// already established that only a principal holding that permission can reach
// this point. A super-user's pings draw on the view tier, exactly like anyone
// else's, and cannot crowd out that same super-user's commit.
//
// # What "more privileged" means here, and where it stops being true (#6954)
//
// Everything above is about TIERS: a flood confined to one tier cannot push the
// aggregate past the ceiling of a tier with a larger share. Making that a
// statement about PRINCIPALS takes one more premise — that the tiers a
// principal can reach GROW with its privilege, so holding a high permission
// implies holding every permission whose tier sits below it. Granted that, "the
// tiers above mine" and "the tiers of someone more privileged than me" are one
// set, and this comment's old opening sentence follows.
//
// That premise is a property of config.LoginClassPermissions, not of the
// permission model. The shipped classes are nested — read-only's tiers are a
// subset of operator's, and both of super-user's — and
// TestTierLadderProtectsPrivilegeOverSystemClasses_6954 asserts the guarantee
// over exactly those classes, pair by pair, through ClassHasPermission and this
// table rather than by restating it.
//
// A CUSTOM `system login class` need not be nested, and one that is not leaves
// the ordering entirely — mapJunosPermissions maps each token through its own
// arm, so
//
//	set system login class configure-only permissions configure
//	set system login user cfgonly class configure-only
//
// compiles to MappedPermissions = [PermConfig] — configure WITHOUT view — and
// commits (validateLoginClassRef accepts a class defined in the same candidate;
// ResolveClassPermissions honours it at runtime). That principal reaches the
// 48 MiB configure tier while holding a STRICT SUBSET of what a `permissions
// [ configure view ]` class holds, and its flood refuses the richer principal's
// view-tier traffic — on a route the flooder is itself answered 403 on. It
// costs 8 MiB, not the 48 MiB its own ceiling allows: what has to be cleared is
// the VICTIM's lowest tier, not the flooder's own.
//
// No assignment of the numbers below removes that: the ladder is a total order
// over single permissions, and the object it must represent is the subset order
// over permission SETS, which is partial. A fix has to change what the
// reservation is KEYED on — the principal's permission set, given a share
// strictly monotone in the subset order, or the principal itself, given a
// bounded share per identity — and either gives up the property route-keying
// has and those do not: a super-user's pings draw on the view tier like anyone
// else's, so they cannot crowd out that same super-user's commit. Not made here.
//
// Feeding the ORDERING DERIVATION a custom-class config is NOT a fix and is
// recorded so it is not proposed again: strictlyBelow would then separate no
// pair at all, so the step set comes back EMPTY and every requirement
// quantified over it passes for want of anything to check. See tierLadderSteps.
//
// The gap is narrow — the flooder must hold a real login class and
// authenticate, no built-in class reaches it, and the flood is still bounded by
// its own tier ceiling — and it is BOUNDED here, not fixed.
// TestCustomClassEscapesTheTierLaddersPrivilegeOrder_6954 and
// TestCustomClassSubsetRefusesItsSupersetOverREST_6954 hold this section
// against production; the reachability walk-through is in that file's header.
// If either starts failing the ladder has been re-keyed and this section must
// go with it rather than be left claiming less than the code delivers.
//
// PermControl is deliberately ABSENT (#5561 round 19, finding 2). Round 11 gave
// it a share equal to the clear tier's, but no route in restMutationPermissions
// requires it and mutationBodyTierCeiling is only ever called with a route's
// required permission — so the row was never consulted, and there was nothing on
// the tier for it to protect or to protect against. Listing a share for a tier
// that owns no work does not fail closed, it just states a number nobody
// derived. The unlisted-permission fallback below assigns the SMALLEST share, so
// a PermControl route added later is bounded from the moment it exists; and
// TestEveryGuardedRouteDeclaresABodyTier_5561 fails the moment one is added, so
// its real share gets chosen deliberately rather than inherited.
var mutationBodyTierCeilings = map[config.LoginClassPermission]int64{
	config.PermView:   mutationBodyBudgetBytes / 8,     // 8 MiB
	config.PermClear:  mutationBodyBudgetBytes / 4,     // 16 MiB
	config.PermConfig: mutationBodyBudgetBytes * 3 / 4, // 48 MiB
	config.PermMaint:  mutationBodyBudgetBytes,         // 64 MiB
}

// mutationBodyTierCeiling returns how far the running total may be driven by a
// route requiring `required`.
//
// An unlisted permission gets the SMALLEST share: a new route whose tier nobody
// thought about must not be able to starve the tiers that were thought about.
// TestEveryGuardedRouteDeclaresABodyTier_5561 fails if a guarded route's
// permission is missing from the table, so the fallback is a safety net rather
// than a routine path.
func mutationBodyTierCeiling(required config.LoginClassPermission) int64 {
	if n, ok := mutationBodyTierCeilings[required]; ok {
		return n
	}
	smallest := mutationBodyBudgetBytes
	for _, n := range mutationBodyTierCeilings {
		if n < smallest {
			smallest = n
		}
	}
	return smallest
}

// mutationBodyBytesAdmitted is the live sum of every in-flight charge.
var mutationBodyBytesAdmitted atomic.Int64

// MutationBodyBytesAdmittedForTest reports the bytes currently charged against
// the gate's aggregate body budget. Test-only.
func MutationBodyBytesAdmittedForTest() int64 { return mutationBodyBytesAdmitted.Load() }

// MutationBodyBudgetForTest reports the aggregate budget. Test-only.
func MutationBodyBudgetForTest() int64 { return mutationBodyBudgetBytes }

// mutationBodyInitialBuf is the first allocation a buffered read makes, and so
// the whole cost of a request whose caller sends (almost) nothing. It matches
// io.ReadAll's own starting size — the read loop below is io.ReadAll with the
// growth steps charged.
const mutationBodyInitialBuf int64 = 512

// bodyBudget is ONE request's live charge against mutationBodyBytesAdmitted.
//
// It is not a reservation taken up front: `held` tracks what the request has
// actually allocated, moving with the buffer as the caller's bytes arrive. The
// gate defers release for the whole request because the buffer it stands for is
// handed to the handler and lives until the handler returns — releasing when
// the read finished would under-count exactly the memory being bounded.
type bodyBudget struct {
	// ceiling is this request's tier share (mutationBodyTierCeilings).
	ceiling int64
	held    int64
}

// resize moves this request's charge to want, refusing a GROWTH that would push
// the aggregate past the request's tier ceiling. A shrink always succeeds — the
// memory is already gone, and refusing to account for that would leak.
//
// A CAS loop rather than a mutex: the update is a load and an add on a path
// that goes on to do IO, and a failed CAS means another request moved the
// total, which is exactly when the ceiling must be re-tested.
func (b *bodyBudget) resize(want int64) bool {
	for {
		cur := mutationBodyBytesAdmitted.Load()
		delta := want - b.held
		if delta > 0 && cur+delta > b.ceiling {
			return false
		}
		if mutationBodyBytesAdmitted.CompareAndSwap(cur, cur+delta) {
			b.held = want
			return true
		}
	}
}

// release returns everything this request holds. Idempotent, so the gate can
// defer it unconditionally.
func (b *bodyBudget) release() {
	if b.held == 0 {
		return
	}
	mutationBodyBytesAdmitted.Add(-b.held)
	b.held = 0
}

// refuseMutationBody writes the 429 a charge that would breach the tier ceiling
// answers with.
func refuseMutationBody(w http.ResponseWriter, r *http.Request, want int64) {
	// Debug, not Warn: caller-driven, so a Warn here is a log-amplification
	// lever (CLAUDE.md).
	slog.Debug("api: refused mutating request body admission",
		"method", r.Method, "path", r.URL.Path, "want", want,
		"admitted", mutationBodyBytesAdmitted.Load())
	writeError(w, http.StatusTooManyRequests,
		"request body admission limit reached; retry shortly")
}

// bufferMutationBody reads a mutating request's body to completion and replaces
// r.Body with the buffered copy, so the handler's later decode cannot block on
// the caller — see mutationAuthzGuard. It returns false when it has already
// written an error response.
//
// limit is the route's ceiling (restMutationBodyLimits). A limit of
// mutationBodyNone means the route consumes no body: the gate buffers NOTHING
// and the handler answers whatever it answers today (the parameterless-clear
// contract's own 400), which is what it did before the gate started reading
// bodies at all.
//
// Otherwise it reads at most limit+1 bytes — the route's whole limit into the
// buffer, and one more into a scratch byte that only has to answer "is there
// more?". An oversized body is answered 413 HERE, on every route, with the
// same status and the same body decodeJSONBody writes (measured byte-identical
// on the wire). A body under the limit is handed over whole, so decode
// behaviour — including which malformed inputs produce 400 — is unchanged; the
// 400/413 split lands exactly on limit.
//
// What is NOT preserved, and an earlier revision of this comment wrongly said
// was: the HTTP-message disposition. http.MaxBytesReader marks the
// ResponseWriter requestTooLarge, so the pre-gate 413 carried `Connection:
// close`; this one does not, because the gate consumed the whole body (limit
// into the buffer, one into scratch) and answers it itself. A pipelining client
// that used to see the connection closed now gets a reusable one. Operationally
// benign, and it is NOT a consequence of moving the probe byte into scratch —
// the divergence dates from the gate's first commit, where an explicit
// over-limit check already took the write away from MaxBytesReader. Verified by
// substituting the pre-scratch bufferMutationBody and driving the same request:
// same result.
//
// The clause "the body reached the handler long enough for its own
// MaxBytesReader to trip" described a mechanism that does not execute at all —
// on this path the handler never runs. Do not restore either claim without
// driving a real request through both shapes and comparing the response
// headers, not just the status and payload.
//
// The over-limit byte lands in SCRATCH rather than in the buffer because the
// buffer's growth is what the budget charges (#5561 round 19, finding 1). Making
// room for it meant one more doubling, and a doubling charges the old allocation
// and the new one at once, so a body that exactly filled the route's limit
// peaked at 2*limit+1 — twice the buffer it ever actually needed. The tier
// ladder above reserves its steps against the LARGEST BODY the tier above can
// carry, so that doubling was spending a reserve that was never sized for it:
// configure - clear is 32 MiB, one byte short of the 33554433 a 16 MiB
// config/load then drove, and a PermClear flood at its own ceiling made a
// super-user's config/load answer 429. Reading the probe into scratch keeps the
// peak at the buffer's own high-water mark (one doubling below the limit, plus
// the limit, across the copy).
//
// The read is io.ReadAll with its growth steps charged against b, which is what
// makes the aggregate budget a statement about memory rather than about
// promises: nothing is taken for a declared Content-Length, and a caller that
// declares a route's whole ceiling and then sends one byte is charged for the
// one small buffer that byte actually lives in. A grow that would push the
// aggregate past the request's tier ceiling answers 429 and the handler never
// runs.
func bufferMutationBody(w http.ResponseWriter, r *http.Request, limit int64, b *bodyBudget) bool {
	if r.Body == nil || r.Body == http.NoBody || limit == mutationBodyNone {
		return true
	}
	first := mutationBodyInitialBuf
	if first > limit {
		first = limit
	}
	if !b.resize(first) {
		refuseMutationBody(w, r, first)
		return false
	}
	buf := make([]byte, 0, first)

	// Counted from AFTER the first charge succeeds: a request refused before it
	// read anything never parked on its caller, and the waiter count is the edge
	// a test uses to know the gate is inside the window a revocation has to land
	// in.
	mutationBodyWaitersInFlight.Add(1)
	defer mutationBodyWaitersInFlight.Add(-1)

	atEOF := false
	for !atEOF && int64(len(buf)) < limit {
		if len(buf) == cap(buf) {
			next := int64(cap(buf)) * 2
			// Never past the route's limit. The buffer is sized for the body
			// this route ADMITS; the byte that detects one over it is read into
			// scratch below, so a body that legitimately fills the whole limit
			// is not charged for a doubling it needs one byte of.
			if next > limit {
				next = limit
			}
			// Both allocations are live across the copy, so both are charged;
			// the budget bounds peak resident bytes, not settled ones.
			if !b.resize(int64(cap(buf)) + next) {
				refuseMutationBody(w, r, int64(cap(buf))+next)
				return false
			}
			grown := make([]byte, len(buf), next)
			copy(grown, buf)
			buf = grown
			b.resize(next) // a shrink cannot fail
		}
		n, err := r.Body.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			atEOF = true
		} else if err != nil {
			return refuseUnreadableBody(w, r, err)
		}
	}

	// The buffer holds the route's whole limit and the caller has not finished:
	// the body is oversized iff one more byte arrives. One stack byte answers
	// that, and is not charged — see the note above on why it must not be the
	// buffer that grows to hold it.
	if !atEOF && int64(len(buf)) == limit {
		var probe [1]byte
		for {
			n, err := r.Body.Read(probe[:])
			if n > 0 {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return false
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return refuseUnreadableBody(w, r, err)
			}
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return true
}

// refuseUnreadableBody writes the 400 a body the gate could not finish reading
// answers: the caller hung up, timed out, or sent a malformed chunked body. Not
// an authorization outcome, and the handler never runs. Always returns false, so
// bufferMutationBody's read paths can `return refuseUnreadableBody(...)`.
func refuseUnreadableBody(w http.ResponseWriter, r *http.Request, err error) bool {
	slog.Debug("api: could not read mutating request body",
		"method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusBadRequest, "could not read request body")
	return false
}
