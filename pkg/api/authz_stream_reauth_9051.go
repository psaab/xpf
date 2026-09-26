package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #9051: keep re-authorizing a read whose handler runs indefinitely.
//
// readAuthz's own doc gave the rationale for adjudicating once:
//
//	A GET has no body to withhold: the handler is entered immediately, so
//	there is no window between the verdict and the action for a revocation to
//	fall into.
//
// True of an ordinary GET. **SSE is a GET whose handler runs forever**, which
// is exactly the window that sentence says cannot exist, and both SSE routes
// (/events/stream and /logs/stream) sit behind that gate. The one-pass design
// was justified by a property server-sent events do not have.
//
// So a principal demoted or deleted mid-stream kept receiving PermView-tier
// feeds -- POLICY_DENY / SCREEN_DROP records, log lines -- until it
// disconnected or xpfd restarted. No config, no secrets, no mutation: it is a
// revocation-response gap rather than an access bypass, which is what bounds
// the severity. Note there is no written revocation SLA anywhere in this tree,
// so "how long is acceptable" was undefined; this makes it one tick.
//
// WHY HERE AND NOT IN THE TWO HANDLERS. Re-checking inside each SSE loop covers
// the two routes that exist today and silently omits the third: a new streaming
// route would get its ENTRY adjudicated by readAuthz and its CONTINUATION by
// nothing, and nothing about adding one would prompt the author to remember.
// Wrapping the request context at the same place that makes the initial
// decision means the two cannot drift apart -- and every handler already
// selects on r.Context().Done(), so no handler needs to know this exists.
//
// The watcher only runs for a request that a permission actually guards, so an
// unguarded route (/health, /metrics) pays nothing.
// A var, not a const, ONLY so a test can shorten it; production never writes
// it. Tests must restore it with t.Cleanup.
var readReauthInterval9051 = 5 * time.Second

// watchReadAuthorization returns a request whose context is cancelled as soon
// as the full REST read policy stops authorizing it, plus a stop func the
// caller must defer. The same predicate gates the initial read and each tick.
//
// A cancelled context is all an SSE handler needs: every one of them selects on
// r.Context().Done() to notice a disconnected client, so revocation lands on
// the identical path as a hangup. The response is already committed to
// text/event-stream by then, so there is no status code left to send -- which
// is why the log line below is the record that this happened.
func (s *Server) watchReadAuthorization(r *http.Request, required config.LoginClassPermission) (*http.Request, func()) {
	ctx, cancel := context.WithCancel(r.Context())
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(readReauthInterval9051)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				// Re-read BOTH inputs, not just the principal: a class can be
				// demoted in the config without the principal changing at all,
				// which is the likelier revocation and the one a
				// principal-only re-check would miss.
				p, err := s.authorizeRESTRead(r, required)
				if err != nil {
					slog.Warn("api: terminating a stream whose principal is no "+
						"longer authorized (#9051)",
						"method", r.Method, "path", r.URL.Path,
						"principal", p.String(),
						"required", authz.PermissionName(required), "err", err)
					cancel()
					return
				}
			}
		}
	}()
	return r.WithContext(ctx), func() { close(done); cancel() }
}
