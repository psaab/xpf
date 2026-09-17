package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
)

func TestRESTMutationCarriesAuthenticatedPlantClass9984(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigureSession(testRESTConfigSessionID); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	s := &Server{store: store}
	for _, input := range []string{
		`event-options policy p events ping_test_failed`,
		`event-options policy p then change-configuration commands "set system host-name stamped"`,
	} {
		body, err := json.Marshal(ConfigSetRequest{Input: input})
		if err != nil {
			t.Fatalf("marshal config set: %v", err)
		}
		req := httptest.NewRequest("POST", "/api/v1/config/set", strings.NewReader(string(body)))
		withRESTConfigSession(req, testRESTConfigSessionID)
		*req = *req.WithContext(context.WithValue(req.Context(), authorizedMutationPrincipalKey{}, authz.Principal{Class: "planter"}))
		rr := httptest.NewRecorder()
		s.configSetHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("config set %q: status=%d body=%s", input, rr.Code, rr.Body.String())
		}
	}
	cfg, err := store.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate: %v", err)
	}
	for _, policy := range cfg.EventOptions {
		if policy != nil && policy.Name == "p" {
			if policy.PlantClass != "planter" {
				t.Fatalf("REST planted class=%q, want planter", policy.PlantClass)
			}
			return
		}
	}
	t.Fatal("REST candidate did not contain event policy p")
}
