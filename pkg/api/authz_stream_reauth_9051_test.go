package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// authzTestConfigRevoked9051 is authzTestConfig with the read-only user's class
// removed. Every other user is identical, so the only thing that changed is
// opsuser's authority.
const authzTestConfigRevoked9051 = `
system {
    host-name authz-test;
    login {
        user adminuser {
            class super-user;
        }
    }
}
`

const authzTestConfigStreamView10829 = `
system {
    host-name authz-test;
    login {
        class stream-view {
            permissions [ view ];
        }
        user opsuser {
            class stream-view;
        }
        user adminuser {
            class super-user;
        }
    }
}
`

const authzTestConfigDenyShowLog10829 = `
system {
    host-name authz-test;
    login {
        class stream-view {
            permissions [ view ];
            deny-commands "show log";
        }
        user opsuser {
            class stream-view;
        }
        user adminuser {
            class super-user;
        }
    }
}
`

func shortenReadReauth9051(t *testing.T) {
	t.Helper()
	old := readReauthInterval9051
	readReauthInterval9051 = 15 * time.Millisecond
	t.Cleanup(func() { readReauthInterval9051 = old })
}

// runGuardedRead9051 drives readAuthz — the guard itself, which is where the
// defect lived — with a handler shaped like an SSE handler: it blocks on the
// request context until something cancels it, exactly as eventStreamHandler and
// logStreamHandler do.
//
// This binds the WIRING. Calling watchReadAuthorization directly would prove
// the watcher works while leaving readAuthz free to never call it, which is
// precisely the state this fixes.
func runGuardedRead9051(t *testing.T, s *Server, path string) (entered, finished chan struct{}, r *http.Request) {
	t.Helper()
	entered, finished = make(chan struct{}), make(chan struct{})
	// The peer identity is attached by connContext at ACCEPT, not by the
	// request, so build it the way production does rather than synthesizing a
	// value -- a hand-made identity would be testing my fixture.
	connCtx := s.connContext(context.Background(), slotConn{
		client: tcpAddr6974("127.0.0.1", 40051),
		server: tcpAddr6974("127.0.0.1", 8080),
	})
	ctx, cancel := context.WithCancel(connCtx)
	t.Cleanup(cancel)
	r = httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	next := http.HandlerFunc(func(_ http.ResponseWriter, rr *http.Request) {
		close(entered)
		<-rr.Context().Done()
	})
	go func() {
		defer close(finished)
		s.readAuthz(httptest.NewRecorder(), r, next)
	}()
	return entered, finished, r
}

// #9051: readAuthz adjudicated once, and its own doc justified that with
// "there is no window between the verdict and the action for a revocation to
// fall into". SSE is a GET whose handler runs indefinitely — the window that
// sentence says cannot exist. A principal demoted mid-stream kept its feed
// until it disconnected or xpfd restarted.
func TestSSEReadIsTerminatedWhenThePrincipalIsRevoked9051(t *testing.T) {
	usePasswdFixture(t)
	shortenReadReauth9051(t)
	store := authzStore(t, authzTestConfig)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242),
	})

	entered, finished, _ := runGuardedRead9051(t, s, "/api/v1/events/stream")

	// REFERENCE ARM: the read must be ADMITTED. A fix that refused every
	// guarded read would satisfy the termination assertion below while
	// deleting the feature.
	select {
	case <-entered:
	case <-finished:
		t.Fatal("the read was refused at entry, so nothing below is being measured")
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never ran")
	}

	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(authzTestConfigRevoked9051); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()

	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the stream outlived the revocation: a demoted principal keeps " +
			"its PermView feed until it disconnects, which is #9051")
	}
}

// NARROWNESS. An authorized principal's stream must NOT be torn down. Without
// this row, "cancel the stream" is satisfied by cancelling every stream — which
// passes the case above and breaks SSE entirely.
func TestAnAuthorizedSSEReadIsNotTerminated9051(t *testing.T) {
	usePasswdFixture(t)
	shortenReadReauth9051(t)
	s, _ := authzServer(t, Config{
		Addr:  "127.0.0.1:0",
		Store: authzStore(t, authzTestConfig), PeerLookupFn: fixedPeerUID(4242),
	})

	entered, finished, _ := runGuardedRead9051(t, s, "/api/v1/events/stream")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never ran")
	}

	select {
	case <-finished:
		t.Fatalf("an authorized read was terminated within %v; the watcher is "+
			"cancelling streams it should leave alone", 20*readReauthInterval9051)
	case <-time.After(20 * readReauthInterval9051):
	}
}

// TestSSEReadIsTerminatedWhenShowLogIsDenied10829 covers the residual after
// #9051 on both SSE routes. The before/after configs differ only by
// `deny-commands "show log"`, so coarse permission stays unchanged.
func TestSSEReadIsTerminatedWhenShowLogIsDenied10829(t *testing.T) {
	usePasswdFixture(t)
	oldInterval := readReauthInterval9051
	readReauthInterval9051 = 50 * time.Millisecond
	t.Cleanup(func() { readReauthInterval9051 = oldInterval })

	for _, tc := range []struct {
		name string
		path string
	}{
		{"events", "/api/v1/events/stream"},
		{"logs", "/api/v1/logs/stream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := authzStore(t, authzTestConfigStreamView10829)
			s, _ := authzServer(t, Config{
				Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242),
			})

			entered, finished, r := runGuardedRead9051(t, s, tc.path)
			select {
			case <-entered:
			case <-finished:
				t.Fatal("the read was refused at entry, so nothing below is being measured")
			case <-time.After(5 * time.Second):
				t.Fatal("the handler never ran")
			}

			// PREMISE: the initial class has coarse view and no command regex,
			// so both feeds are admitted before the policy changes.
			cfg, p, _ := s.authorizeInputs(r)
			if err := authz.Authorize(cfg, p, config.PermView); err != nil {
				t.Fatalf("initial fixture does not grant coarse view: %v", err)
			}
			if _, ok, err := config.OperationalLoginRegexesFor(cfg, "stream-view"); err != nil || ok {
				t.Fatalf("initial fixture unexpectedly has command regexes (ok=%v err=%v)", ok, err)
			}
			if err := s.authorizeRESTCommand(r, cfg, p); err != nil {
				t.Fatalf("initial fixture denies the stream command: %v", err)
			}

			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := store.LoadOverride(authzTestConfigDenyShowLog10829); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			store.ExitConfigure()
			committedAt := time.Now()
			reauthDeadline := 3 * readReauthInterval9051

			select {
			case <-finished:
				if elapsed := time.Since(committedAt); elapsed > reauthDeadline {
					t.Fatalf("SSE stream closed after %v, more than 3 re-auth ticks", elapsed)
				}
			case <-time.After(reauthDeadline):
				t.Fatalf("the %s SSE stream outlived the deny-commands revocation; "+
					"the watcher must re-run the command regex gate (#10829)", tc.name)
			}

			// POSTCONDITION: view remains granted and the route's canonical
			// command is denied, proving the watcher closed the stream for the
			// regex change rather than a coarse permission revocation.
			cfg = store.ActiveConfig()
			if err := authz.Authorize(cfg, p, config.PermView); err != nil {
				t.Fatalf("committed fixture removed coarse view permission: %v", err)
			}
			if err := s.authorizeRESTCommand(r, cfg, p); err == nil ||
				!strings.Contains(err.Error(), `denies "show log"`) {
				t.Fatalf("committed fixture does not deny the stream's canonical command: %v", err)
			}
		})
	}
}
