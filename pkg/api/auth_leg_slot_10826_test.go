package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRetiringHTTPAuthSlotKeepsInFlightRequestRevoked10826(t *testing.T) {
	const apiKey = "same-key-survives-on-https-10826"
	verifier, err := config.HashAPIAuthSecret(apiKey)
	if err != nil {
		t.Fatalf("hash test API key: %v", err)
	}
	auth := &AuthConfig{APIKeys: map[string]bool{verifier: true}}

	for _, transition := range []bool{false, true} {
		name := "control-without-listener-transition"
		if transition {
			name = "deny-http-before-republishing-https-credential"
		}
		t.Run(name, func(t *testing.T) {
			usePasswdFixture(t)
			store := authzStore(t, authzTestConfig)
			srv := NewServer(Config{
				Addr:         "127.0.0.1:0",
				Store:        store,
				Auth:         auth,
				PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
			})
			ctx, cancel := context.WithCancel(context.Background())
			if err := srv.Start(ctx); err != nil {
				cancel()
				t.Fatalf("Start: %v", err)
			}
			t.Cleanup(func() {
				cancel()
				srv.Wait()
				waitForGateQuiescent(t)
			})

			waitForGateQuiescent(t)
			parked := MutationBodyWaitersForTest()
			req := openWithheldBody(t, "http://"+srv.EffectiveHTTPAddr(),
				"POST /api/v1/config/set", map[string]string{"X-API-Key": apiKey})
			waitForNewMutationBodyWaiter(t, parked)

			if transition {
				// This is management.reconcileTo's safety ordering: deny requests
				// on clear HTTP, retire that leg, then publish the same credential
				// for the surviving HTTPS listener. The old request must keep the
				// retired HTTP slot, not borrow the server-wide HTTPS policy.
				srv.ReplaceAuth(&AuthConfig{})
				if err := srv.ReconcileHTTP(""); err != nil {
					t.Fatalf("disable HTTP: %v", err)
				}
				srv.ReplaceAuth(auth)
			}

			status, message := req.finish(t)
			if transition {
				if status != http.StatusForbidden {
					t.Fatalf("retired HTTP request got %d (%q), want 403 after its listener policy was tightened", status, message)
				}
				return
			}
			if status == http.StatusForbidden || status == http.StatusUnauthorized {
				t.Fatalf("control request was refused (%d, %q) without a policy transition", status, message)
			}
		})
	}
}
