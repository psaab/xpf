package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #13249 (D6-09): authorizeRESTCommand must resolve the class's regexes
// BEFORE touching the request body.
type trackingReadCloser13249 struct {
	*bytes.Reader
	reads int
}

func (t *trackingReadCloser13249) Read(p []byte) (int, error) {
	t.reads++
	return t.Reader.Read(p)
}
func (t *trackingReadCloser13249) Close() error { return nil }

func TestAuthorizeRESTCommandDoesNotReadBodyWithoutRegexes13249(t *testing.T) {
	cfg := cmdCfg9952(t)
	s := &Server{}
	body := &trackingReadCloser13249{Reader: bytes.NewReader([]byte(`{"action":"reboot"}`))}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/action", body)
	if err := s.authorizeRESTCommand(req, cfg, authz.Principal{Class: "wideopen"}); err != nil {
		t.Fatalf("class without regexes must be unaffected, got: %v", err)
	}
	if body.reads != 0 {
		t.Fatalf("authorizeRESTCommand read the body %d time(s) for a class with no "+
			"operational regexes; regex resolution must precede any body read (#13249)",
			body.reads)
	}
}

// The command mapping for diagnostics/ping does not depend on its JSON body.
// A denied request therefore must be rejected in pass 1, before the mutation
// guard buffers even its bounded body.
func TestMutationGuardRejectsBodyIndependentCommandBeforeBuffer13249(t *testing.T) {
	usePasswdFixture(t)
	const cfgText = `
system {
    host-name authz-13249;
    login {
        class limited {
            permissions [ view ];
            deny-commands "ping";
        }
        user opsuser {
            class limited;
        }
    }
}
`
	store := authzStore(t, cfgText)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242),
	})
	if _, ok, err := config.OperationalLoginRegexesFor(store.ActiveConfig(), "limited"); err != nil || !ok {
		t.Fatalf("fixture premise: limited must carry operational regexes (ok=%v err=%v)", ok, err)
	}

	body := &trackingReadCloser13249{Reader: bytes.NewReader([]byte(`{"target":"192.0.2.1"}`))}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/ping", body)
	req.RemoteAddr = "198.51.100.10:54321"
	pending := &pendingPeer{
		done: make(chan struct{}),
		id:   authz.PeerIdentity{OK: true, Local: true, UID: 4242},
	}
	close(pending.done)
	req = req.WithContext(context.WithValue(req.Context(), peerIdentityKey{}, pending))
	rec := httptest.NewRecorder()
	s.mutationAuthzGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler ran for a command-denied request")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied ping -> %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if body.reads != 0 {
		t.Fatalf("mutation guard read the body %d time(s) before denying the "+
			"body-independent command (#13249)", body.reads)
	}
}
