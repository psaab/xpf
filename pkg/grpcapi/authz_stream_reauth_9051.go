package grpcapi

import (
	"context"
	"log/slog"
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

// reauthServerStream re-parents a stream's context so the re-authorization
// goroutine can cancel it. grpc.ServerStream has no setter; embedding and
// overriding Context() is the standard shape (same as peerMarkerServerStream).
type reauthServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s reauthServerStream) Context() context.Context { return s.ctx }

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
) error {
	ctx, cancel := context.WithCancel(ss.Context())
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
				if err := s.authorizeRPC(ctx, fullMethod, nil); err != nil {
					slog.Warn("gRPC stream terminated: the principal is no longer "+
						"authorized for this method (#9051)",
						"method", fullMethod, "reason", err.Error())
					revoked <- err
					cancel()
					return
				}
			}
		}
	}()

	herr := handler(srv, reauthServerStream{ServerStream: ss, ctx: ctx})
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
