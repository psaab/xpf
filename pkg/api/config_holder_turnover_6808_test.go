package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #6808 REST WIRING cells.
//
// pkg/configstore proves the store REFUSES a promotion whose authority has gone
// stale. That proves nothing about these handlers unless they actually mint a
// BOUND authority and hand it over: passing configstore.InternalCommitter()
// instead still compiles, still type-checks, and restores the defect in full —
// an internal authority satisfies every turnover check by design.
//
// So the assertion here is on the authority the handler PASSES, not on the
// store's reaction to it. That is the difference between binding the wiring and
// binding the function the wiring calls.

// restHolderStore returns a store in config mode held by the REST session the
// test helpers use, with one staged edit so a commit has something to promote.
func restHolderStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigureSession(testRESTConfigSessionID); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	if err := store.SetFromInputAs(testRESTConfigSessionID, "system host-name staged-by-rest"); err != nil {
		t.Fatalf("SetFromInputAs: %v", err)
	}
	return store
}

// TestRESTCommitPassesBoundAuthority_6808 pins that the plain-commit handler
// hands the callback an authority BOUND to the REST session that passed the
// gate.
//
// FAIL-ON-REVERT: change the handler to pass configstore.InternalCommitter()
// (which compiles) and this REDS on IsInternal — the commit would then promote
// whatever candidate exists at promotion time, which is the whole defect.
func TestRESTCommitPassesBoundAuthority_6808(t *testing.T) {
	store := restHolderStore(t)

	var got configstore.CommitAuthority
	var called bool
	s := &Server{
		store: store,
		commitFn: func(_ context.Context, a configstore.CommitAuthority, _ string) (*config.Config, error) {
			called, got = true, a
			return store.Commit()
		},
	}

	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
	s.configCommitHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("REST commit as the holder: status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if !called {
		t.Fatal("commitFn was never invoked, so this cell asserts nothing about the authority")
	}
	if got.IsInternal() {
		t.Error("the REST commit handler passed an INTERNAL commit authority. An internal " +
			"authority satisfies every holder-turnover check, so the commit would still " +
			"promote whatever candidate exists at promotion time — the #6808 defect, intact")
	}
	if got.SessionID() != testRESTConfigSessionID {
		t.Errorf("commit authority SessionID = %q, want %q — the authority must be bound to "+
			"the session that passed the gate, or it binds nothing",
			got.SessionID(), testRESTConfigSessionID)
	}
	if got.JournalPrincipal() == configstore.UnknownPrincipal {
		t.Error("REST commit authority lost the already-authorized transport principal")
	}
}

// TestRESTCommitConfirmedPassesBoundAuthority_6808 is the commit-confirmed half.
// It is a SEPARATE cell because the two handlers mint their authority
// independently; one cell covering only the plain path would report the
// confirmed path as guarded when it is not.
//
// FAIL-ON-REVERT: pass configstore.InternalCommitter() in
// configCommitConfirmedHandler and this REDS.
func TestRESTCommitConfirmedPassesBoundAuthority_6808(t *testing.T) {
	store := restHolderStore(t)

	var got configstore.CommitAuthority
	var called bool
	s := &Server{
		store: store,
		commitConfirmedFn: func(_ context.Context, a configstore.CommitAuthority, _ int) (*config.Config, error) {
			called, got = true, a
			return store.CommitConfirmed(5)
		},
	}

	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit-confirmed",
			strings.NewReader(`{"minutes":5}`)), testRESTConfigSessionID)
	s.configCommitConfirmedHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("REST commit-confirmed as the holder: status = %d, want 200; body: %s",
			rr.Code, rr.Body.String())
	}
	if !called {
		t.Fatal("commitConfirmedFn was never invoked, so this cell asserts nothing")
	}
	if got.IsInternal() {
		t.Error("the REST commit-CONFIRMED handler passed an INTERNAL authority; a substituted " +
			"commit-confirmed also arms an auto-rollback timer against work its author never " +
			"approved (#6808)")
	}
	if got.SessionID() != testRESTConfigSessionID {
		t.Errorf("commit-confirmed authority SessionID = %q, want %q",
			got.SessionID(), testRESTConfigSessionID)
	}
	if got.JournalPrincipal() == configstore.UnknownPrincipal {
		t.Error("REST commit-confirmed authority lost the already-authorized transport principal")
	}
}

// TestRESTCommitRefusedWhenHolderTurnsOverMidCommit_6808 is the end-to-end cell:
// the substitution R69 describes, driven through the real handler with the
// turnover performed INSIDE the commit callback — i.e. exactly in the window
// between the holder gate returning nil and the promotion landing.
//
// The staged edits are distinguishable per session on purpose. Asserting only
// "an error came back" would pass against a handler that refuses everything, and
// asserting only "something was promoted" cannot tell A's work from B's.
//
// FAIL-ON-REVERT: pass InternalCommitter() from the handler, or drop
// verifyCommitAuthorityLocked from CommitWithDescriptionGenAs, and this REDS with
// the intruder's host-name active.
func TestRESTCommitRefusedWhenHolderTurnsOverMidCommit_6808(t *testing.T) {
	store := restHolderStore(t)

	s := &Server{
		store: store,
		commitFn: func(_ context.Context, a configstore.CommitAuthority, comment string) (*config.Config, error) {
			// The lock turns over while this commit is in flight. On REST this
			// models an idle-lease reclaim or an explicit /config/exit; on gRPC
			// an ordinary disconnect reaches the same state with no adversary.
			if !store.ExitConfigureSession(testRESTConfigSessionID) {
				t.Fatal("fixture: could not release the REST session's lock")
			}
			if err := store.EnterConfigureSession("intruder"); err != nil {
				t.Fatalf("fixture: intruder could not enter: %v", err)
			}
			if err := store.SetFromInputAs("intruder", "system host-name staged-by-intruder"); err != nil {
				t.Fatalf("fixture: intruder set: %v", err)
			}
			_, gen, cerr := store.CompileCandidateGen()
			if cerr != nil {
				t.Fatalf("fixture: CompileCandidateGen: %v", cerr)
			}
			return store.CommitWithDescriptionGenAs(a, comment, gen)
		},
	}

	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
	s.configCommitHandler(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("REST commit SUCCEEDED after the config lock turned over mid-commit; "+
			"the intruder's staged edits were applied under the original session's "+
			"authorization (#6808). body: %s", rr.Body.String())
	}
	if active := store.ActiveConfig(); active != nil && active.System.HostName == "staged-by-intruder" {
		t.Fatalf("the intruder's candidate was PROMOTED (host-name=%q) under the REST "+
			"session's authority", active.System.HostName)
	}
}

// TestRESTCommitStillWorksWithoutTurnover_6808 is the control for the two cells
// above: with the holder unchanged, a REST commit must still succeed AND
// actually promote.
//
// Without it, "refuse every commit" satisfies the refusal cells — and refusing
// every commit is a configuration outage, strictly worse than the defect. The
// host-name assertion is what makes it load-bearing: a control checking only the
// status code would pass against a fixture that never reached promotion.
func TestRESTCommitStillWorksWithoutTurnover_6808(t *testing.T) {
	store := restHolderStore(t)

	s := &Server{
		store: store,
		commitFn: func(_ context.Context, a configstore.CommitAuthority, comment string) (*config.Config, error) {
			_, gen, cerr := store.CompileCandidateGen()
			if cerr != nil {
				t.Fatalf("CompileCandidateGen: %v", cerr)
			}
			return store.CommitWithDescriptionGenAs(a, comment, gen)
		},
	}

	rr := httptest.NewRecorder()
	req := withRESTConfigSession(
		httptest.NewRequest("POST", "/api/v1/config/commit", nil), testRESTConfigSessionID)
	s.configCommitHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("REST commit with an UNCHANGED holder: status = %d, want 200; body: %s",
			rr.Code, rr.Body.String())
	}
	active := store.ActiveConfig()
	if active == nil || active.System.HostName != "staged-by-rest" {
		got := ""
		if active != nil {
			got = active.System.HostName
		}
		t.Fatalf("host-name after the control commit = %q, want %q — the control must reach "+
			"promotion, or it cannot distinguish 'accepted' from 'never got there'",
			got, "staged-by-rest")
	}
	// The turnover sentinel must never surface on the happy path.
	if errors.Is(errFromBody(rr), configstore.ErrConfigHolderTurnover) {
		t.Error("a turnover error surfaced on an unchanged-holder commit")
	}
}

// errFromBody is a tiny helper so the control can assert the turnover sentinel
// is absent without depending on the error-rendering shape.
func errFromBody(rr *httptest.ResponseRecorder) error {
	if rr.Code == http.StatusOK {
		return nil
	}
	return errors.New(rr.Body.String())
}
