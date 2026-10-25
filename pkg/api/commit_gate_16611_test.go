package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #16611 wiring cell (REST twin): the middleware prices the candidate;
// configCommitHandler must carry that pricing into promotion via a
// gate-bound CommitAuthority, so a same-session apply-groups landing
// between the gate and promotion is refused instead of adopted by the
// daemon's re-snapshot loop. commitFn mirrors commitWithGenBinding.
//
// FAIL-ON-REVERT: drop priceRESTCommitGate16611's stash (or
// bindCommitGate in config.go) and the interleaved cell REDS.

func gateStoreREST16611(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"system login class limited permissions [ configure view ]",
		`system login class limited deny-configuration "system domain-name"`,
		"groups G system domain-name evil16611",
		"system host-name base16611",
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("seed %q: %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	s.ExitConfigure()
	return s
}

const restSession16611 = testRESTConfigSessionID

func restCommitReq16611() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/config/commit", strings.NewReader("{}"))
	r.Header.Set(restConfigSessionHeader, restSession16611)
	return r.WithContext(context.WithValue(r.Context(), authorizedMutationPrincipalKey{}, authz.Principal{Class: "limited", Username: "opuser"}))
}

func TestRESTCommitGateTOCTOU16611(t *testing.T) {
	// Defect cell.
	store := gateStoreREST16611(t)
	if err := store.EnterConfigureSession(restSession16611); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	srv := &Server{store: store}
	r := restCommitReq16611()
	pricedReq, err := srv.priceRESTCommitGate16611(r, store.ActiveConfig(), authz.Principal{Class: "limited"})
	if err != nil {
		t.Fatalf("gate must admit the clean candidate: %v", err)
	}
	if err := store.SetAs(restSession16611, []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("interleaved apply-groups: %v", err)
	}
	srv.commitFn = func(_ context.Context, a configstore.CommitAuthority, _ string) (*config.Config, error) {
		_, gen, cerr := store.CompileCandidateGen()
		if cerr != nil {
			return nil, cerr
		}
		return store.CommitWithDescriptionGenAs(a, "", gen)
	}
	rec := httptest.NewRecorder()
	srv.configCommitHandler(rec, pricedReq)
	if rec.Code == http.StatusOK {
		t.Fatalf("REST Commit promoted a candidate changed after the gate priced it (#16611); body=%s", rec.Body.String())
	}
	if got := store.ShowActiveSet(); strings.Contains(got, "set system domain-name evil16611") {
		t.Fatalf("denied group content promoted to active:\n%s", got)
	}

	// Twin: unchanged candidate commits.
	store2 := gateStoreREST16611(t)
	if err := store2.EnterConfigureSession(restSession16611); err != nil {
		t.Fatalf("EnterConfigureSession (twin): %v", err)
	}
	srv2 := &Server{store: store2}
	pricedReq2, err := srv2.priceRESTCommitGate16611(restCommitReq16611(), store2.ActiveConfig(), authz.Principal{Class: "limited"})
	if err != nil {
		t.Fatalf("gate must admit the clean candidate (twin): %v", err)
	}
	srv2.commitFn = func(_ context.Context, a configstore.CommitAuthority, _ string) (*config.Config, error) {
		if !a.GateBound() {
			t.Error("restricted REST commit authority must be gate-bound (#16611)")
		}
		_, gen, cerr := store2.CompileCandidateGen()
		if cerr != nil {
			return nil, cerr
		}
		return store2.CommitWithDescriptionGenAs(a, "", gen)
	}
	rec2 := httptest.NewRecorder()
	srv2.configCommitHandler(rec2, pricedReq2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("unchanged REST Commit refused: code=%d body=%s", rec2.Code, rec2.Body.String())
	}
}
