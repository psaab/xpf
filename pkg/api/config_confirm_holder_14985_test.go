package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14985 (D36-05, surviving leg): POST /api/v1/config/confirm must require a
// HELD config lock. ConfirmCommitAs delegates to ensureHolderLocked, whose
// two documented bypasses — !configDir and empty-effective-holder — let a
// caller that never entered (or has already exited) configuration mode
// confirm another operator's pending commit-confirmed window.
//
// Measured mechanism: owner enters, stages, commit-confirmed (which keeps
// configDir=true and the owner as holder), then EXITS config mode. The
// pending window survives the exit (ExitConfigure does not clear it), but
// configDir is now false, so ensureHolderLocked short-circuits and a
// well-formed REST session token that never held the lock confirms the
// window — cancelling the auto-rollback and making a config permanent
// that its author never confirmed.
//
// RED on master: the stranger confirm returns 200 and IsConfirmPending
// flips false. GREEN after the fix: 409 and the window stays pending.
// Control: the owner confirming while still holding the lock returns 200
// and clears the window.
//
// RED-on-revert: dropping the held-lock gate from ConfirmCommitAs (back to
// bare ensureHolderLocked) makes the stranger case return 200 again.
func TestRESTConfigConfirmRequiresHeldLock_14985(t *testing.T) {
	armOwnerConfirmed := func(t *testing.T) (*configstore.Store, string) {
		t.Helper()
		store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
		const owner = "owner-session-14985"
		if err := store.EnterConfigureSession(owner); err != nil {
			t.Fatalf("EnterConfigureSession(owner): %v", err)
		}
		if err := store.SetFromInputAs(owner, "system host-name base-14985"); err != nil {
			t.Fatalf("owner SetFromInputAs(base): %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("owner Commit: %v", err)
		}
		if err := store.SetFromInputAs(owner, "system host-name confirmed-14985"); err != nil {
			t.Fatalf("owner SetFromInputAs(confirmed): %v", err)
		}
		if _, err := store.CommitConfirmed(10); err != nil {
			t.Fatalf("owner CommitConfirmed: %v", err)
		}
		if !store.IsConfirmPending() {
			t.Fatal("premise: no pending confirm window after CommitConfirmed")
		}
		return store, owner
	}

	confirmViaREST := func(s *Server) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := withRESTConfigSession(
			httptest.NewRequest("POST", "/api/v1/config/confirm", nil),
			testRESTConfigSessionID)
		s.configConfirmHandler(rr, req)
		return rr
	}

	// Stranger case: the owner has EXITED config mode (the realistic
	// post-commit-confirmed state — the operator disconnects or leaves
	// config mode while the rollback window runs), so configDir is false
	// and the unheld bypass applies. A REST caller that never held the
	// lock must not be able to confirm.
	t.Run("StrangerAfterOwnerExit", func(t *testing.T) {
		store, owner := armOwnerConfirmed(t)
		if !store.ExitConfigureSession(owner) {
			t.Fatal("premise: owner ExitConfigureSession returned false")
		}
		if store.InConfigMode() {
			t.Fatal("premise: config mode still active after owner exit")
		}
		if !store.IsConfirmPending() {
			t.Fatal("premise: pending window did not survive owner exit")
		}

		s := &Server{store: store}
		rr := confirmViaREST(s)
		if rr.Code != http.StatusConflict {
			t.Fatalf("REST confirm by non-holder after owner exit: status = %d, want 409; body: %s",
				rr.Code, rr.Body.String())
		}
		if !store.IsConfirmPending() {
			t.Fatal("stranger confirm cleared the pending window; the unconfirmed " +
				"config is now permanent and its auto-rollback is cancelled")
		}
		if got := store.ActiveConfig().System.HostName; got != "confirmed-14985" {
			t.Fatalf("active host-name = %q, want the still-pending confirmed-14985", got)
		}
	})

	// Control: the owner confirming while STILL holding the lock (has not
	// exited config mode) succeeds and clears the window. This is the
	// legitimate neighbouring behaviour that must stay green.
	t.Run("OwnerWhileHoldingLock", func(t *testing.T) {
		store, _ := armOwnerConfirmed(t)
		// The REST layer addresses its holder by its own token namespace;
		// the owner here is the store-level session, so confirm at the
		// store level with that exact identity — the REST stranger case
		// above exercises the handler, this cell pins the legitimate
		// holder path the fix must not break.
		if err := store.ConfirmCommitAs("owner-session-14985"); err != nil {
			t.Fatalf("owner ConfirmCommitAs while holding lock: %v", err)
		}
		if store.IsConfirmPending() {
			t.Fatal("owner confirm must clear the pending window")
		}
	})

	// Control: REST holder confirms its own window end-to-end through the
	// handler — enter via REST, stage, commit-confirmed via the store
	// under the REST identity, then confirm via the handler without
	// exiting. Must stay 200.
	t.Run("RESTHolderConfirmsOwnWindow", func(t *testing.T) {
		store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
		s := &Server{store: store}
		sessionID := enterRESTConfigSession(t, s, "")
		if err := store.SetFromInputAs(sessionID, "system host-name rest-base-14985"); err != nil {
			t.Fatalf("REST holder Set(base): %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("REST holder Commit: %v", err)
		}
		if err := store.SetFromInputAs(sessionID, "system host-name rest-confirmed-14985"); err != nil {
			t.Fatalf("REST holder Set(confirmed): %v", err)
		}
		if _, err := store.CommitConfirmed(10); err != nil {
			t.Fatalf("REST holder CommitConfirmed: %v", err)
		}
		if !store.IsConfirmPending() {
			t.Fatal("premise: no pending window for REST holder")
		}
		rr := httptest.NewRecorder()
		req := withRESTConfigSession(
			httptest.NewRequest("POST", "/api/v1/config/confirm", nil), sessionID)
		s.configConfirmHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("REST holder confirm own window: status = %d, want 200; body: %s",
				rr.Code, rr.Body.String())
		}
		if store.IsConfirmPending() {
			t.Fatal("REST holder confirm must clear its own pending window")
		}
		if !strings.Contains(store.ActiveConfig().System.HostName, "rest-confirmed") {
			t.Fatalf("active = %q, want rest-confirmed-14985", store.ActiveConfig().System.HostName)
		}
	})
}
