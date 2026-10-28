package grpcapi

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// #9051: re-authorize a long-lived stream while it runs.
//
// THE DEFECT. principalStreamInterceptor adjudicated once, at stream open, and
// then handed the stream to a handler that loops until the client disconnects
// or xpfd restarts. A principal demoted or deleted mid-stream kept its
// PermView-tier feed -- POLICY_DENY / SCREEN_DROP records, log lines, interface
// counters -- for the life of the connection. Unary RPCs on the SAME connection
// were already re-adjudicated on every call (authorizeRPC re-reads the active
// config and the passwd database), so the gap was stream-only.
//
// WHY THE ONE-PASS DESIGN LOOKED SOUND. The REST twin's own doc explains it:
// "A GET has no body to withhold: the handler is entered immediately, so there
// is no window between the verdict and the action for a revocation to fall
// into." That is true of an ordinary GET and false of a stream, whose handler
// runs indefinitely -- the justification was a property streaming does not
// have. This package already treats the class as a defect worth fixing: the
// #5561 round-7 note calls "a super-user demoted to read-only ... kept the
// authority its old class carried for the duration of an in-flight request" a
// defect and shipped a two-pass fix for it.
//
// WHY THE INTERCEPTOR AND NOT THE HANDLERS' OWN LOOPS. The issue suggested
// re-checking on each loop's existing tick. That works for the four streams
// that exist and silently omits the fifth: a new streaming RPC would get its
// OPEN adjudicated by this interceptor and its CONTINUATION by nothing, and
// nothing about adding one would prompt the author to remember. Putting it at
// the same choke point that does the initial check makes the two impossible to
// separate.
//
// COST. One authz evaluation per stream per tick, against a recorded load of
// single-digit concurrent streams. authorizeRPC re-reads the active config and
// the passwd database, which is the same work every unary RPC already does, and
// this runs 12x per minute per stream rather than per call.
// A var, not a const, ONLY so a test can shorten it; production never writes
// it. Tests must restore it with t.Cleanup.
var streamReauthInterval9051 = 5 * time.Second

// authzRecvStream defers the request-dependent half of stream
// authorization to the first RecvMsg (#17175).
//
// The generated server-streaming wrapper decodes the request by calling
// RecvMsg on the stream the interceptor handed it, BEFORE invoking the
// handler body. Wrapping that stream lets the interceptor run the full
// authorizeRPCContext with the decoded message at exactly that point —
// before any handler logic, before any Send — and retain ONLY that
// first message so the #9051 tick re-prices the same arguments instead
// of nil. For a request-independent stream the wrapper starts
// undecided like any other: its first RecvMsg runs the (request-
// independent) full authorization and retains the decoded message,
// so ticks price that retained message. Later RecvMsg calls
// (unreachable in production: the generated wrapper receives exactly
// once) neither re-authorize nor replace the retained message.
//
// retained/authCtx are written by the handler goroutine (first RecvMsg)
// and read by the watcher goroutine (tick); mu guards both. Context()
// returns the authorized context once the first message is admitted;
// before that it returns baseCtx. baseCtx is parented on the open-time
// authorizedCtx (authorizeStreamContinuously), so before the first
// message it carries the open-time authorizedPrincipalKey{} and after
// admission the first-message principal. The next interceptor in the
// primary chain (peerMarkerStreamInterceptor) captures Context()
// before any RecvMsg and freezes that value into the stream the
// handler sees, so in production a handler re-reading stream.Context()
// still sees the pre-message (open-time) context — the authCtx swap
// is observable only on this wrapper itself. No stream handler today
// reads authorizedPrincipalFromContext, so that freeze is harmless;
// it is documented here rather than silently implied.
type authzRecvStream struct {
	grpc.ServerStream
	s          *Server
	fullMethod string
	baseCtx    context.Context

	mu       sync.Mutex
	decided  bool
	retained any
	authCtx  context.Context
}

func (w *authzRecvStream) Context() context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.authCtx != nil {
		return w.authCtx
	}
	return w.baseCtx
}

// RecvMsg runs the deferred full authorization on the first message
// and retains it for the re-auth tick. For a request-independent
// stream that verdict decides identically for the decoded message
// and the typed empty request (census-enforced), so the duplicate of
// the open-time verdict changes nothing. A denied first message
// returns the PermissionDenied verdict from RecvMsg, which the
// generated wrapper propagates before the handler body runs — the
// client sees the denial, never stream output.
func (w *authzRecvStream) RecvMsg(m any) error {
	if err := w.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	w.mu.Lock()
	already := w.decided
	if !already {
		w.decided = true
		w.retained = m
	}
	w.mu.Unlock()
	if already {
		return nil
	}
	authorizedCtx, err := w.s.authorizeRPCContext(w.baseCtx, w.fullMethod, m)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.authCtx = authorizedCtx
	w.mu.Unlock()
	return nil
}

// retainedRequest returns the retained request and whether the first
// message has been decided. The retained request is the decoded first
// message (nil before it arrives) for every stream kind.
func (w *authzRecvStream) retainedRequest() (any, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.retained, w.decided
}

// authorizeStreamContinuously runs handler with a context that is cancelled as
// soon as the principal stops being authorized for fullMethod.
//
// The returned error is the AUTHZ error, not context.Canceled: a client whose
// class was revoked must be told that, and a bare cancellation is
// indistinguishable from an ordinary shutdown. When revocation and a handler
// error are co-present, the revocation wins: the watcher records it before
// cancelling, so a handler returning *because of* the revocation reports it
// deterministically (#9903 F-128). A handler-only failure still returns the
// handler's own (more specific) error.
func (s *Server) authorizeStreamContinuously(
	srv any,
	ss grpc.ServerStream,
	fullMethod string,
	handler grpc.StreamHandler,
	authorizedCtx context.Context,
) error {
	// Parent on authorizedCtx, not ss.Context(): authorizedCtx carries
	// the open-time authorizedPrincipalKey{} (authorizeStreamOpenContext
	// / authorizeRPCContext), while ss.Context() is its sibling and
	// carries no such value. Cancelling ctx still cancels the stream.
	ctx, cancel := context.WithCancel(authorizedCtx)
	defer cancel()

	revoked := make(chan error, 1)
	done := make(chan struct{})
	defer close(done)

	// Buffered so the watcher never blocks on send if the handler returned
	// first and nobody is reading -- a leaked goroutine parked on an unread
	// channel is exactly the kind of slow resource loss a per-stream watcher
	// must not introduce.
	// #9903 GPT-1: capture the tick interval BEFORE spawning the watcher.
	// The test helper shortens the package var and restores it on cleanup;
	// a watcher that read the var at its own (unscheduled) start would race
	// the restore across sequential runs. All var reads are now sequenced
	// in the interceptor body.
	interval := streamReauthInterval9051

	// #17175: wrap the stream so its first RecvMsg retains the decoded
	// message and runs the full authorization there. The watcher below
	// re-prices the RETAINED message on each tick — never nil, and
	// never the typed empty request: ticks price exactly what the
	// client sent, for request-independent streams too (their verdict
	// decides identically for any message, census-enforced).
	recv := &authzRecvStream{
		ServerStream: ss,
		s:            s,
		fullMethod:   fullMethod,
		baseCtx:      ctx,
	}

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				var tickErr error
				if req, decided := recv.retainedRequest(); decided && req != nil {
					// Re-price the retained decoded first message —
					// never nil (#17175).
					_, tickErr = s.authorizeRPCContext(ctx, fullMethod, req)
				} else {
					// No message yet: nothing has been served, but
					// the class may have been revoked wholesale
					// (#9051). Re-check the open price (the full
					// typed-empty verdict for a request-
					// independent stream, the coarse floor
					// otherwise); the full verdict on the decoded
					// message still runs on the first RecvMsg
					// against the then-current config, so a
					// principal revoked before its first message
					// is denied before any output.
					_, tickErr = s.authorizeStreamOpenContext(ctx, fullMethod)
				}
				if tickErr != nil {
					slog.Warn("gRPC stream terminated: the principal is no longer "+
						"authorized for this method (#9051)",
						"method", fullMethod, "reason", tickErr.Error())
					revoked <- tickErr
					cancel()
					return
				}
			}
		}
	}()

	herr := handler(srv, recv)
	// #9903 F-128: consult the revocation BEFORE the handler error. The
	// watcher sends to revoked (buffered) BEFORE cancelling, so when the
	// handler returns *because of* the revocation, revoked is already
	// populated and the client deterministically learns PermissionDenied.
	// Pre-fix the handler's own ctx error won, and identical revocations
	// surfaced as PermissionDenied or Canceled/Unavailable by timing, so
	// the client retried instead of surfacing the authorization event. A
	// handler-only failure (revoked empty) still returns herr, and a clean
	// return with no revocation still returns nil — only the co-present
	// case changes precedence, and revocation is terminal anyway.
	// "Deterministically" is scoped to the because-of shape: the watcher
	// populates revoked before cancelling, so a handler returning BECAUSE
	// of this cancellation always finds it. A concurrent INDEPENDENT
	// failure (revoked still empty at return) takes the select-default arm
	// and returns the retryable herr — and revocation DETECTION itself has
	// a tick of latency by design, which no ordering removes. (This orders
	// the SIGNAL only; the wrapper overrides Context, not the transport's
	// blocked Send/Recv.)
	select {
	case err := <-revoked:
		return err
	default:
	}
	if herr != nil {
		return herr
	}
	return nil
}
