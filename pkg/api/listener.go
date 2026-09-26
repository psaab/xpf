package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// listenerLeg is one independently-managed listening socket + its serve
// goroutine (#5866). The HTTP and HTTPS listeners each run in their own leg so a
// day-2 change to one (TLS enable/disable, an HTTPS-bind change, or an HTTP-bind
// change) rebinds ONLY that leg — the sibling keeps serving without a bounce and
// without the EADDRINUSE that a whole-server rebuild hit when the two legs
// shared no socket but the rebuild still re-bound the unchanged one.
type listenerLeg struct {
	srv      *http.Server
	ln       net.Listener
	stopCh   chan struct{}
	stopOnce sync.Once
	// slot is THIS leg's view of the credential policy (#5561 round 14). While
	// the leg is live it FOLLOWS the server-wide snapshot, so a ReplaceAuth is
	// enforced on the very next request exactly as before. When the leg is
	// RETIRED (stopLegLocked) the slot is PINNED to what this address was
	// serving at that instant, and from then on only ever tightens — see
	// authSlot and Server.ReplaceAuth.
	slot *authSlot
	// drained is set by the serve goroutine after its body and its drain have
	// finished, so a retired leg can be reaped from Server.retiring without
	// joining it. Atomic for the same lock-ordering reason as dead.
	//
	// It is NOT the goroutine's last act, and the difference is observable
	// (#6827 round 8): the defers run LIFO — `defer s.wg.Done()` is registered
	// first, `defer leg.drained.Store(true)` second — so this store happens
	// BEFORE wg.Done. A reader that sees drained cannot conclude the goroutine
	// has returned; it can conclude the exit path and the drain are complete,
	// which is what every caller here actually needs. Server.Wait, which waits
	// on wg.Done, is the strictly stronger barrier and is what the tests use
	// where they can.
	//
	// It means "nothing this leg accepted is still being served" — no further
	// request can be admitted AND no response is still in flight (#6827 round 8;
	// round 7 stated only the first half, which is the half Shutdown alone
	// already provides, so it understated what the flag has to promise).
	// WITHOUT QUALIFICATION since #7011: hijacked connections used to be
	// excluded here, and drainLeg now closes them too, so this no longer needs
	// a "modulo" clause for a reader to reason around.
	// Server.pruneRetiredLocked spends it as exactly that: a drained leg stops
	// being tightened by ReplaceAuth because there is nothing left for a
	// revocation to reach. That reading is only true because EVERY exit path now
	// runs drainLeg before this store (#6827 round 7). Before it, the
	// unexpected-exit arm returned without calling Shutdown at all: Serve closes
	// the LISTENER on its way out, but the HTTP/1 keep-alive and HTTP/2
	// connections it had already accepted kept being served — so the flag went up
	// with live connections behind it, the prune dropped the leg, and its pinned
	// slot stopped tightening while those connections were still presenting
	// credentials on it.
	drained atomic.Bool
	// dead is set when the leg's serve loop exits UNEXPECTEDLY — the listener
	// terminated on its own, not via a requested shutdown (stopLegLocked /
	// rootCtx). EffectiveHTTPAddr treats a dead leg as not-serving so `show
	// system services` reports the HTTP listener Failed rather than Listening on
	// a dead socket, symmetric with the gRPC serve-exit clear (#6401).
	//
	// It is an atomic (NOT lifeMu-guarded): the serve goroutine still holds its
	// wg count when it sets this on exit, and Server.Wait holds lifeMu ACROSS
	// wg.Wait — so if the marker needed lifeMu, an exit racing a shutdown Wait
	// would deadlock (Wait holds lifeMu waiting on the goroutine's wg.Done; the
	// goroutine waits on lifeMu before it can return -> Done). Storing atomically
	// with no lock breaks that lock-ordering cycle (#6401 round-3 fix).
	dead atomic.Bool
	// stopping is set the moment a graceful drain BEGINS — before Shutdown, not
	// after the goroutine returns. A flag stored only when the goroutine RETURNS
	// would stay false for the whole drain window, up to legDrainTimeout (#6827
	// round 5).
	//
	// It marks INTENT, and the socket state trails it by a hair: it is stored
	// just before the drain, which is what closes the listener, and requests
	// already accepted keep being served until they finish or the drain severs
	// them. So a `stopping` leg is not instantaneously silent — and NOT within a
	// wall-clock bound either (legDrainTimeout is a poll deadline, not a
	// ceiling; see its doc). It is still the right answer to
	// "is a certificate in front of clients right now?", which is a question
	// about whether to warn an operator: this leg is on its way out, no new
	// client will reach it, and a staleness warning about it is noise. Callers
	// that want "what address is this leg finishing on" (EffectiveHTTPAddr)
	// deliberately do not consult it.
	stopping atomic.Bool
}

// serving reports whether this leg is the one in front of clients right now: it
// exists, holds a listener, and its serve goroutine has neither self-terminated
// (`dead`) nor begun a graceful drain (`stopping`). It is a state question, not
// an instantaneous claim that no byte is in flight — a leg that has just entered
// its drain can still be finishing accepted requests (see `stopping`).
//
// A non-nil leg pointer is NOT that question (#6827). An unexpected serve exit
// sets `dead` and leaves the leg INSTALLED in s.httpsLeg; a root-context
// shutdown sets `stopping` (never `dead`) and also leaves it installed. In both
// states the pointer is live and the socket is not. A caller that reads the leg
// to answer "what is this box serving?" must test the state, not the pointer.
//
// It tests `stopping` rather than `stopCh` on purpose. A requested retirement
// (stopLegLocked) is not observable through s.httpsLeg — but not for the reason
// the shape of ReconcileHTTPS suggests. Its disable arm retires FIRST and clears
// the field second (stopLegLocked(s.httpsLeg), then s.httpsLeg = nil), so the
// interleaved state is written; what makes it unobservable is that the whole
// switch runs under ONE lifeMu hold and every serving() caller takes lifeMu
// (Server.HTTPSServing, Server.WarnStaleMgmtCertForHostName), so a reader lands
// before the retirement or after the clear, never between. The rebind arm needs
// no such argument: it installs the replacement before retiring the old leg, so
// the leg being retired is never the installed one. So a stopCh test would be an
// arm for a state that cannot occur — while the state that DOES occur,
// root-context shutdown, closes no stopCh and would slip past it.
// `stopping` is set at the TOP of both drain arms — requested retirement and
// root-context shutdown — before Shutdown runs, so it covers that path from the
// moment the listener closes through the goroutine's return. Together with
// `dead` (self-termination) every exit is covered, so this predicate needs no
// further flag.
//
// `drained` is NOT a candidate here even though it is set on every exit
// (#5561 round 14). It is stored from a defer after the exit path and the drain
// have run — not as the goroutine's last act, since `defer s.wg.Done()` is
// registered first and therefore runs after it — which makes it the right
// answer to "has this leg finished draining, so retiring can reap it?"
// and the wrong answer to this one: throughout the drain — the whole window
// in which the socket is already closed but the goroutine has not returned — it
// still reads false. A predicate built on it would call a closing listener live
// for the entire window that matters.
//
// Deliberately stricter than EffectiveHTTPAddr's inline check, which tests nil
// / ln / dead only: that one answers `show system services`, where a leg
// finishing a graceful drain should still report the address it is on. This one
// answers "is there a certificate in front of clients right now?" The two
// questions differ, so they are not folded into one predicate.
func (l *listenerLeg) serving() bool {
	return l != nil && l.ln != nil && !l.dead.Load() && !l.stopping.Load()
}

// legDrainTimeout is how long the connections a leg already accepted have to
// finish GRACEFULLY once that leg is on its way out, on every exit — requested
// retirement, root-context shutdown, and an unexpected serve-loop exit.
//
// It bounds NEITHER the drain nor even the Shutdown in wall-clock terms, and
// round 8's "it bounds the Shutdown" was the second wrong version of this
// sentence (#6827 round 9). It is a POLL deadline, consulted between quiescence
// checks, and both phases put serial per-connection closes in front of it:
//
//   - INSIDE Shutdown: the loop calls closeIdleConns() and only reaches its
//     `select { case <-ctx.Done() }` if that returns false. closeIdleConns walks
//     s.activeConn under s.mu calling c.rwc.Close() one at a time, so a batch of
//     stalled IDLE peers overruns the context before the context is ever read.
//   - AFTER it: http.Server.Close takes no context at all and closes
//     s.activeConn serially too.
//
// On an HTTPS leg each of those closes is a *tls.Conn whose Close sends
// close_notify under a five-second write deadline of its OWN (crypto/tls
// conn.go closeNotify), so a peer that stalls its receive window costs up to
// five seconds EACH, one after another, in both phases. The worst case grows
// with the number of such connections and has no fixed ceiling. The knock-on is
// worth knowing before someone rediscovers it as a
// hang: Server.Wait holds lifeMu across the drain, and
// WarnStaleMgmtCertForHostName holds staleCertMu while waiting for lifeMu, so a
// `set system host-name` racing daemon shutdown waits for whatever the drain
// takes. Bounding the sever phase for real needs per-connection tracking with
// concurrent deadlined closes, which is a larger change than #6827; what is
// claimed here is only what is true.
//
// A var, not a const, so a test can reach the DEADLINE arm — the one where
// Shutdown gives up and drainLeg severs what is left — without spending five
// seconds in every case (#6827 round 8). Production never assigns it, and
// TestLegDrainTimeoutDefault_6827 pins the shipped value so a leaked override
// cannot retune it silently.
var legDrainTimeout = 5 * time.Second

// drainLeg takes srv out of service and does not return until nothing it
// accepted is still being served: no further request can be admitted, and any
// response still in flight has been severed — hijacked connections included
// since #7011, which is what removed the exception this sentence used to make.
//
// None of what follows weakens why the drain exists at all. The defect that
// motivated it (#6827 round 7) was an exit arm that called NO Shutdown
// WHATSOEVER: with keep-alives never disabled, a connection accepted before the
// listener died went on serving FURTHER requests under a credential the
// operator had since revoked. "Shutdown stops further requests" and "that arm
// was serving further requests" are both true, because that arm was not
// calling Shutdown.
//
// Shutdown delivers the FIRST half and not the second, and that split is
// the whole reason Close is here (#6827 round 8 — round 7 asserted the same
// conclusion from the wrong mechanism, which is worse than useless because the
// next reader reasons from the stated mechanism and this one would tell them
// the Close is redundant).
//
// Measured, not argued:
//
//   - FURTHER REQUESTS, on HTTP/1: Shutdown sets `inShutdown`, which makes
//     `doKeepAlives()` false. Idle connections are closed outright, and a
//     connection Shutdown is still waiting on finishes its current response and
//     then closes rather than reading another request. So a surviving HTTP/1
//     connection cannot serve a second request — Shutdown alone is sufficient
//     for that half. On HTTP/2 it is weaker (#6827 round 9): the shutdown
//     callbacks are asynchronous, so an already-established h2 connection can
//     open another stream in the window before GOAWAY reaches it. Close is what
//     makes that answer the same on both protocols.
//   - THE RESPONSE ALREADY IN FLIGHT: Shutdown does not terminate it. It WAITS
//     for it, and when the deadline expires it returns ctx.Err() and leaves the
//     response open and still streaming. This server deliberately runs with no
//     WriteTimeout (SSE streams and large scrapes must not be severed), so an
//     in-flight response has no upper bound of its own: a subscribed event
//     stream outlives the deadline indefinitely, still writing to its client, on
//     a leg the box has already marked `drained`. Close is what ends it.
//
// Both halves matter, for different reasons. The request half is the credential
// story: a leg's policy stops being maintained the moment it drains
// (listenerLeg.drained, Server.pruneRetiredLocked), so a request admitted after
// that is judged by a snapshot no ReplaceAuth will ever tighten again. The
// in-flight half is the data story: a response authorized under the old policy
// goes on delivering after the box believes the socket is gone.
//
// HIJACKED CONNECTIONS ARE IN SCOPE SINCE #7011, and that is what removed the
// caveat this paragraph used to carry. Go excludes them from BOTH calls —
// Shutdown "does not attempt to close nor wait for hijacked connections", Close
// "does not even know about" them, and a hijacked conn is removed from
// srv.activeConn — so neither can reach one. The ConnState hook can: it fires
// with StateHijacked and hands over the net.Conn at the moment the server loses
// track of it. Every leg constructor installs that hook (trackHijackedConns)
// and this function closes what it recorded, so `drained` is true outright.
//
// The previous approach was a tripwire that ENUMERATED hijacking types and
// asserted none was reachable from this package. It was defeated three times —
// golang.org/x/net/websocket, http2/h2c, and net/rpc, a STANDARD LIBRARY
// hijacker. The last one is why the enumeration was retired rather than
// re-keyed: the hijacker set is a function of the TOOLCHAIN, not of go.mod, so
// the corpus it was derived over moved with nothing in the repository changing.
//
// WHAT THIS DOES NOT CLAIM: the connection is closed, not the goroutine the
// hijacking handler started. Nothing can join that — the handler owns it and
// exposes no handle. The guarantee is about what is still being SERVED on
// connections this leg accepted, and a closed conn serves nothing, which is the
// same standard Close already meets for the non-hijacked in-flight case.
//
// It returns the Shutdown error so a caller that reports one can keep doing so
// (Server.serveBound). The leg paths discard it deliberately: a leg's exit is
// not something anybody returns, and a drain that reached its deadline and
// severed is not a failure to report — the connections are gone either way.
func drainLeg(srv *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), legDrainTimeout)
	defer cancel()
	err := srv.Shutdown(ctx)
	if err != nil {
		// Deadline (or a listener-close error): stop asking and sever. NOT
		// optional and NOT redundant — see above, and
		// TestInFlightResponseIsSeveredOnEveryLegExit_6827, which reds if this
		// line goes.
		_ = srv.Close()
	}
	// #7011: sever the HIJACKED connections too. Neither Shutdown nor Close
	// reaches them — a hijacked conn is removed from srv.activeConn and the
	// server no longer knows about it — so this is the only place they can be
	// closed, and it runs on BOTH the graceful and the deadline path because
	// the guarantee ("nothing this leg accepted is still being served") is the
	// same either way. Unconditional rather than under the error branch: a
	// Shutdown that returned nil still left a hijacked conn open.
	if n := hijackTrackerFor(srv).closeAll(); n > 0 {
		slog.Warn("api: severed hijacked connections at leg drain",
			"addr", srv.Addr, "count", n)
	}
	releaseHijackTracker(srv)
	return err
}

// serveLegLocked launches srv on ln in a background goroutine registered on the
// server wait group, and returns the leg. The goroutine serves until (a) the
// listener terminates on its own, (b) the leg is explicitly retired
// (stopLegLocked), or (c) the daemon root context is cancelled — then it runs a
// graceful drain (drainLeg) and joins. Every one of the three ends in
// that drain: (a) closes the listener but not the connections behind it, so it
// needs the drain for exactly the same reason the other two do.
// Caller holds lifeMu (so rootCtx is set and reads are consistent).
// slot is the credential slot srv's handler was built with (buildHTTPServer /
// buildHTTPSServer); every production call site supplies the same one, so the
// leg's pin and the handler's reads are the same object. A nil is substituted
// rather than stored, so ReplaceAuth's walk over retiring legs can never meet
// one.
func (s *Server) serveLegLocked(plan legPlan, ln net.Listener, isTLS bool) *listenerLeg {
	// #6734: no slot parameter and no substitution. The leg's slot IS the one
	// the plan's handler closes over, because they were allocated together —
	// so pin / tighten can never operate on an object no request reads.
	srv := plan.srv
	leg := &listenerLeg{srv: srv, ln: ln, stopCh: make(chan struct{}), slot: plan.slot}
	rootCtx := s.rootCtx
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer leg.drained.Store(true)

		serveErr := make(chan error, 1)
		go func() {
			if isTLS {
				// The selector validates the current in-memory pair on every
				// handshake, including clients that omit SNI.
				serveErr <- srv.ServeTLS(ln, "", "")
			} else {
				serveErr <- srv.Serve(ln)
			}
		}()

		var rootDone <-chan struct{}
		if rootCtx != nil {
			rootDone = rootCtx.Done()
		}
		select {
		case err := <-serveErr:
			// The listener terminated on its own (not a requested shutdown), so
			// the LISTENING socket is already closed — but the connections it
			// accepted before it died are not (#6827 round 7). They are still
			// being served, by this srv, under this leg's credential slot.
			if err != nil && err != http.ErrServerClosed {
				slog.Error("API listener terminated unexpectedly", "addr", srv.Addr, "tls", isTLS, "err", err)
			}
			// #6401: an UNEXPECTED serve exit means this leg is no longer
			// serving. Mark it dead ATOMICALLY — NOT under lifeMu: the goroutine
			// still holds its wg count here, and Server.Wait holds lifeMu across
			// wg.Wait, so acquiring lifeMu here would deadlock a shutdown that
			// raced this exit (round-3 fix). EffectiveHTTPAddr then stops
			// reporting the dead listener's address and `show system services`
			// renders the HTTP listener Failed, mirroring the gRPC serve-exit
			// clear. A leg already retired/replaced by a reconcile takes the
			// stopCh path below instead, so this only fires on a genuine
			// self-termination.
			//
			// Stored BEFORE the drain, not after: serving() must flip the instant
			// the socket dies so a reconcile can rebuild the leg, rather than a
			// whole drain timeout later.
			leg.dead.Store(true)
			// Then take the accepted connections down. Without this the flag said
			// the leg was gone while it was still answering requests, and
			// `drained` — set by the defer immediately below — told
			// pruneRetiredLocked there was nothing left for a ReplaceAuth to
			// tighten (#6827 round 7).
			_ = drainLeg(srv)
			return
		case <-leg.stopCh:
		case <-rootDone:
		}
		leg.stopping.Store(true)
		_ = drainLeg(srv)
		<-serveErr // join the Serve goroutine before the leg is considered drained
	}()
	return leg
}

// stopLegLocked idempotently requests a leg's graceful retirement. The leg's
// goroutine drains + joins in the background; wg.Wait (Server.Wait) joins it on
// daemon shutdown. Caller holds lifeMu.
//
// Retirement is ASYNCHRONOUS and that is the point of the auth pin (#5561 round
// 14). Closing stopCh only WAKES the serve goroutine; the socket keeps accepting
// until that goroutine reaches Shutdown, and connections it already accepted are
// served for the whole drain. ReconcileHTTP/ReconcileHTTPS return as soon
// as this call does, and the management reconciler then publishes the committed
// credential set — so without the pin a credential the commit authorized for the
// NEW address became valid on the address that same commit retired. Pinning the
// leg here to what it was already serving makes that impossible: from this
// moment the retiring listener's policy can only tighten (Server.ReplaceAuth
// intersects it), never gain a value it did not already accept.
func (s *Server) stopLegLocked(leg *listenerLeg) {
	if leg == nil {
		return
	}
	leg.stopOnce.Do(func() {
		// Pin BEFORE the wake-up so there is no interval in which the leg is
		// retired but still following the server-wide snapshot.
		s.trackRetiring(leg)
		close(leg.stopCh)
	})
}

// trackRetiring pins a retired leg's policy and registers it so ReplaceAuth can
// keep tightening it while it drains, reaping the ones that have finished.
//
// The pin and the registration happen under ONE hold of retireMu so no
// revocation can slip between them: a ReplaceAuth that lands before this pins at
// the value it published, and one that lands after finds the leg on the list and
// intersects it. The bookkeeping takes its own mutex rather than lifeMu because
// Server.Wait holds lifeMu across wg.Wait — a ReplaceAuth racing daemon
// shutdown would otherwise block for the whole drain. Callers hold lifeMu, so
// the order is always lifeMu -> retireMu.
func (s *Server) trackRetiring(leg *listenerLeg) {
	s.retireMu.Lock()
	defer s.retireMu.Unlock()
	leg.slot.pin(s.auth.Load())
	s.retiring = append(s.pruneRetiredLocked(), leg)
}

// pruneRetiredLocked compacts s.retiring down to the legs that are still
// draining and returns it. Caller holds retireMu.
//
// Dropping a leg here ENDS the tightening ReplaceAuth would otherwise keep
// applying to its pinned slot, so the reap is only sound while `drained` means
// what serveLegLocked now makes it mean: every connection the leg accepted has
// been finished or severed (drainLeg), so there is no longer anyone for a
// revocation to reach.
func (s *Server) pruneRetiredLocked() []*listenerLeg {
	live := s.retiring[:0]
	for _, leg := range s.retiring {
		if !leg.drained.Load() {
			live = append(live, leg)
		}
	}
	s.retiring = live
	return live
}

// Start binds the configured listeners and serves each in its own leg (#5866),
// returning once they are live. HTTP is the primary listener: a bind failure
// returns an error with nothing serving (the caller logs it non-fatally and the
// next commit retries via ReconcileHTTP). HTTPS is best-effort at boot — a bind
// failure leaves the HTTP plane up (fail-safe, management not down) and the next
// reconcile retries the HTTPS leg. Wait blocks until every leg (live + retiring)
// has drained.
func (s *Server) Start(ctx context.Context) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	s.rootCtx = ctx

	if s.httpServer != nil {
		ln, err := s.listen("tcp", s.httpServer.Addr)
		if err != nil {
			return fmt.Errorf("api: bind HTTP listener %q: %w", s.httpServer.Addr, err)
		}
		s.httpLeg = s.serveLegLocked(s.httpLegPlan(), ln, false)
		slog.Info("HTTP API server listening", "addr", s.httpServer.Addr)
	}
	if s.httpsServer != nil {
		ln, err := s.listen("tcp", s.httpsServer.Addr)
		if err != nil {
			slog.Error("api: HTTPS listener bind failed at start; HTTPS disabled until the next reconcile",
				"addr", s.httpsServer.Addr, "err", err)
		} else {
			s.httpsLeg = s.serveLegLocked(s.httpsLegPlan(), ln, true)
			slog.Info("HTTPS API server listening", "addr", s.httpsServer.Addr)
		}
	}
	s.startManagementTLSCertificateMonitor(ctx)
	return nil
}

// Wait blocks until every serve goroutine (live + retiring legs) has fully
// exited. It takes lifeMu so no concurrent reconcile can register a new leg
// (WaitGroup Add) once the join has begun; leg drains do not need lifeMu, so
// they complete while Wait holds it. Call after the root context is cancelled.
func (s *Server) Wait() {
	s.lifeMu.Lock()
	s.wg.Wait()
	monitorCancel := s.tlsMonitorCancel
	s.lifeMu.Unlock()
	if monitorCancel != nil {
		monitorCancel()
	}
	s.tlsMonitorWG.Wait()
}

// EffectiveHTTPAddr returns the ACTUAL bound address of the live HTTP leg, or ""
// when no HTTP leg is serving. It reads the listener's own Addr, so an ephemeral
// `:0` request resolves to its concrete port and a wildcard/hostname bind is
// normalized — the address the socket is truly on, not the requested one. The
// #6385/#6401 `show system services` effective-listener snapshot reads it (via
// managementReconciler.effectiveHTTPListener), mirroring the grpcapi.Server
// EffectiveListener pattern.
func (s *Server) EffectiveHTTPAddr() string {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	// httpLeg / ln are swapped only under lifeMu, so read them here; dead is
	// atomic (set without lifeMu by the serve goroutine to avoid a shutdown
	// lock-ordering deadlock — see listenerLeg.dead).
	if s.httpLeg == nil || s.httpLeg.ln == nil || s.httpLeg.dead.Load() {
		return ""
	}
	return s.httpLeg.ln.Addr().String()
}

// HTTPSServing reports whether an HTTPS leg is bound and serving right now
// (#5561 round 14 / #6827 round 5 — both rounds arrived at this predicate
// independently, for the same reason). Start() deliberately returns SUCCESS when
// the HTTPS bind fails — HTTPS is best-effort at boot so a failure leaves the
// HTTP plane up — which means a caller cannot infer from Start's error that
// HTTPS came up. The management reconciler that records a converged HTTPS
// fingerprint on that assumption pins itself to a listener that does not exist,
// so the leg-changed test is false on every subsequent unchanged commit and
// ReconcileHTTPS is never called again: the boot failure is permanent and
// silent.
//
// The answer is listenerLeg.serving(), not `!= nil && !dead`: a leg that is
// draining is not carrying traffic either, and a caller asking "did the bind
// land?" must not be told yes by a leg on its way out.
// EffectiveHTTPSAddr is the HTTPS counterpart of EffectiveHTTPAddr (#8597 K86).
// It returns the ACTUAL bound HTTPS address, or "" when no HTTPS leg is bound
// or the leg is dead — the same three-way read EffectiveHTTPAddr performs, for
// the same reason: the reconciler's converged fingerprint records what the last
// successful reconcile bound, which is not evidence the socket is still up.
//
// It exists because the management status surface reported the HTTP leg only,
// so an HTTPS leg that died to an unexpected serve exit read as healthy
// everywhere while serving nothing.
func (s *Server) EffectiveHTTPSAddr() string {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if !s.httpsLeg.serving() {
		return ""
	}
	return s.httpsLeg.ln.Addr().String()
}

func (s *Server) HTTPSServing() bool {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.httpsLeg.serving()
}

// HTTPServing reports whether the HTTP leg is bound and still serving. It is the
// exact counterpart of HTTPSServing and exists for the same reason (#6803): the
// reconciler's converged-fingerprint records what the last SUCCESSFUL reconcile
// bound, which is not evidence that the socket is still up. An unexpected serve
// exit marks the leg dead and leaves it INSTALLED (listenerLeg.dead — it cannot
// be removed under lifeMu without deadlocking a shutdown that races the exit),
// so a fingerprint-only gate matches on every later commit and never rebinds.
// #6827 round 6 gave HTTPS this question; the HTTP leg never got it.
func (s *Server) HTTPServing() bool {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.httpLeg.serving()
}

// ReconcileHTTP make-before-break rebinds ONLY the HTTP listener to addr (#5866),
// leaving the HTTPS leg untouched. A same-addr call is a no-op. The new listener
// is bound and serving BEFORE the old is retired (no unreachable HTTP window). A
// bind failure retains the previous HTTP listener (fail-closed) and returns the
// error so the caller records retry debt.
func (s *Server) ReconcileHTTP(addr string) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if addr == "" {
		return fmt.Errorf("api: refusing to reconcile the HTTP listener to an empty bind address")
	}
	// The same-address short circuit requires the leg to still be SERVING, the
	// way ReconcileHTTPS's does (#6803). Without the serving() half, a leg whose
	// serve loop exited unexpectedly — dead, but still installed — satisfied the
	// address compare, so a rebind to the same endpoint returned nil having done
	// nothing and the management API stayed down until a daemon restart.
	if s.httpLeg.serving() && s.httpLeg.srv.Addr == addr {
		return nil
	}
	plan := s.planHTTPLeg(addr)
	ln, err := s.listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("api: bind HTTP listener %q: %w", addr, err)
	}
	old := s.httpLeg
	s.httpLeg = s.serveLegLocked(plan, ln, false)
	s.stopLegLocked(old) // retire the previous HTTP listener only after the new one is serving
	return nil
}

// ReconcileHTTPS enables, disables, or make-before-break rebinds ONLY the HTTPS
// listener (#5866), leaving the live HTTP listener untouched — this is the fix
// for the whole-server rebuild that re-bound the still-held HTTP socket on a
// TLS-enable (EADDRINUSE). useTLS=false or addr=="" disables HTTPS. A same-addr
// call over a leg that is actually SERVING is a no-op. On enable/rebind the new
// listener with a validated current certificate is bound and serving BEFORE any
// old one is retired. A cert or bind failure retains the previous HTTPS state
// (fail-closed) and returns the error for retry debt.
//
// The default arm BINDS BEFORE IT BUILDS (#7041) — see the comment on that arm
// for why, and for the two consequences it carries (the listener is closed if
// the build then fails; the bind error wins when both fail).
//
// The same-addr no-op tests listenerLeg.serving(), NOT a non-nil pointer
// (#6827 round 6). An unexpected serve exit marks the leg `dead` and leaves it
// INSTALLED in s.httpsLeg, so a pointer test called that address converged and
// returned nil — a same-address reconcile could never resurrect HTTPS, and
// neither could any other commit, because the reconciler above it never even
// reached this call (its own converged fingerprint still matched). The dead leg
// was a permanent, restart-only dead end on an UNCHANGED configuration. Asking
// whether a socket is really carrying traffic makes the rebind the recovery
// path it was always documented to be.
func (s *Server) ReconcileHTTPS(useTLS bool, addr string) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	want := useTLS && addr != ""
	s.tlsDesired.Store(want)
	switch {
	case !want:
		if s.httpsLeg != nil {
			s.stopLegLocked(s.httpsLeg)
			s.httpsLeg = nil
		}
		return nil
	case s.httpsLeg.serving() && s.httpsLeg.srv.Addr == addr:
		return nil
	default:
		// Bind before resolving the certificate so repeated bind failures do not
		// emit certificate diagnostics for a listener that cannot serve. After
		// binding, build from the latest validated pair; a build failure closes
		// this socket before returning.
		ln, err := s.listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("api: bind HTTPS listener %q: %w", addr, err)
		}
		plan, err := s.planHTTPSLeg(addr)
		if err != nil {
			// The socket is already held. Closing it is not tidiness: a retained
			// listener keeps the port, so every later retry would fail
			// EADDRINUSE and a transient cert fault would become a permanent
			// bind failure — manufacturing exactly the never-converging state
			// this reordering exists to stop.
			ln.Close()
			return fmt.Errorf("api: generate HTTPS certificate for %q: %w", addr, err)
		}
		old := s.httpsLeg
		s.httpsLeg = s.serveLegLocked(plan, ln, true)
		s.stopLegLocked(old)
		return nil
	}
}
