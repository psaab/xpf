package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6808 gRPC WIRING cells.
//
// R69's title says "REST commit", but the identical gate-then-unscoped-callback
// shape is in gRPC Commit / CommitConfirmed, and gRPC additionally has a
// NON-ADVERSARIAL trigger REST lacks: configLockStatsHandler.HandleConn
// auto-releases the config lock on ConnEnd from a separate goroutine, with no
// coordination with an in-flight commit. Its comment says the release is
// "guarded ... by the store's holder check" — true of a DIFFERENT hazard
// (releasing someone else's lock), and silent about releasing the committer's
// own lock mid-commit. So an ordinary disconnect while a commit waits on the
// apply semaphore reaches the substitution with no attacker timing at all.
//
// These cells assert the authority the handler PASSES. Passing
// configstore.InternalCommitter() instead compiles and restores the defect in
// full, so asserting the store's behaviour alone would not catch it.

// grpcHolderStore returns a store in config mode held by sessionID with one
// staged edit, so a commit has something to promote.
func grpcHolderStore(t *testing.T, sessionID string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigureSession(sessionID); err != nil {
		t.Fatalf("EnterConfigureSession(%s): %v", sessionID, err)
	}
	if err := store.SetFromInputAs(sessionID, "system host-name staged-by-holder"); err != nil {
		t.Fatalf("SetFromInputAs: %v", err)
	}
	return store
}

// TestGRPCCommitPassesBoundAuthority_6808 pins that gRPC Commit hands the
// callback an authority bound to the connection session that passed the gate.
//
// FAIL-ON-REVERT: pass configstore.InternalCommitter() in Commit (it compiles)
// and this REDS on IsInternal.
func TestGRPCCommitPassesBoundAuthority_6808(t *testing.T) {
	ctx := clientCtx(4141)
	sessionID := connSessionID(ctx)
	store := grpcHolderStore(t, sessionID)

	var got configstore.CommitAuthority
	var called bool
	s := &Server{
		store: store,
		commitFn: func(_ context.Context, a configstore.CommitAuthority, _ string) (*config.Config, error) {
			called, got = true, a
			return store.Commit()
		},
	}

	if _, err := s.Commit(ctx, &pb.CommitRequest{}); err != nil {
		t.Fatalf("Commit as the holder: %v", err)
	}
	if !called {
		t.Fatal("commitFn was never invoked, so this cell asserts nothing about the authority")
	}
	if got.IsInternal() {
		t.Error("gRPC Commit passed an INTERNAL commit authority. An internal authority " +
			"satisfies every holder-turnover check, so a connection that drops mid-commit " +
			"would still promote whichever candidate exists at promotion time (#6808)")
	}
	if got.SessionID() != sessionID {
		t.Errorf("commit authority SessionID = %q, want %q — it must bind the session that "+
			"passed the gate", got.SessionID(), sessionID)
	}
	if got.JournalPrincipal() == configstore.UnknownPrincipal {
		t.Error("gRPC commit authority lost the already-authorized transport principal")
	}
}

// TestGRPCCommitConfirmedPassesBoundAuthority_6808 is the commit-confirmed half.
// Separate cell: the two RPCs mint their authority independently.
//
// FAIL-ON-REVERT: pass configstore.InternalCommitter() in CommitConfirmed and
// this REDS.
func TestGRPCCommitConfirmedPassesBoundAuthority_6808(t *testing.T) {
	ctx := clientCtx(4242)
	sessionID := connSessionID(ctx)
	store := grpcHolderStore(t, sessionID)

	var got configstore.CommitAuthority
	var called bool
	s := &Server{
		store: store,
		commitConfirmedFn: func(_ context.Context, a configstore.CommitAuthority, _ int) (*config.Config, error) {
			called, got = true, a
			return store.CommitConfirmed(5)
		},
	}

	if _, err := s.CommitConfirmed(ctx, &pb.CommitConfirmedRequest{Minutes: 5}); err != nil {
		t.Fatalf("CommitConfirmed as the holder: %v", err)
	}
	if !called {
		t.Fatal("commitConfirmedFn was never invoked, so this cell asserts nothing")
	}
	if got.IsInternal() {
		t.Error("gRPC CommitConfirmed passed an INTERNAL authority; a substituted " +
			"commit-confirmed also arms an auto-rollback timer against work its author " +
			"never approved (#6808)")
	}
	if got.SessionID() != sessionID {
		t.Errorf("commit-confirmed authority SessionID = %q, want %q", got.SessionID(), sessionID)
	}
	if got.JournalPrincipal() == configstore.UnknownPrincipal {
		t.Error("gRPC commit-confirmed authority lost the already-authorized transport principal")
	}
}

// TestGRPCCommitRefusedWhenConnectionDropsMidCommit_6808 models the
// non-adversarial trigger end to end: the committing session's lock is released
// the way HandleConn releases it on ConnEnd — by session id, from outside the
// commit — while the commit is in flight, and another session then enters and
// stages different work.
//
// It uses the same release entry point HandleConn uses (ExitConfigureSession by
// session id) rather than reaching into the stats handler, so the cell exercises
// the state transition that matters without depending on gRPC transport
// plumbing to deliver a ConnEnd.
//
// FAIL-ON-REVERT: pass InternalCommitter() from Commit, or drop
// verifyCommitAuthorityLocked from CommitWithDescriptionGenAs, and this REDS with
// the intruder's host-name active.
func TestGRPCCommitRefusedWhenConnectionDropsMidCommit_6808(t *testing.T) {
	ctx := clientCtx(4343)
	sessionID := connSessionID(ctx)
	store := grpcHolderStore(t, sessionID)

	s := &Server{
		store: store,
		commitFn: func(_ context.Context, a configstore.CommitAuthority, comment string) (*config.Config, error) {
			// The committer's connection ends here — exactly what HandleConn
			// does on ConnEnd, from its own goroutine, with no coordination
			// with this in-flight commit.
			if !store.ExitConfigureSession(sessionID) {
				t.Fatal("fixture: could not release the committing session's lock")
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

	if _, err := s.Commit(ctx, &pb.CommitRequest{}); err == nil {
		t.Fatal("gRPC Commit SUCCEEDED after the committing connection's lock was released " +
			"mid-commit; the intruder's staged edits were applied under the original " +
			"session's authorization (#6808)")
	}
	if active := store.ActiveConfig(); active != nil && active.System.HostName == "staged-by-intruder" {
		t.Fatalf("the intruder's candidate was PROMOTED (host-name=%q) under the dropped "+
			"session's authority", active.System.HostName)
	}
}

// TestGRPCCommitStillWorksWithoutTurnover_6808 is the control: an unchanged
// holder must still commit AND actually promote.
//
// Without it, "refuse every commit" satisfies both refusal cells, and refusing
// every commit is a configuration outage. The host-name assertion keeps the
// control from being satisfiable by a fixture that never reaches promotion.
func TestGRPCCommitStillWorksWithoutTurnover_6808(t *testing.T) {
	ctx := clientCtx(4444)
	sessionID := connSessionID(ctx)
	store := grpcHolderStore(t, sessionID)

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

	if _, err := s.Commit(ctx, &pb.CommitRequest{}); err != nil {
		t.Fatalf("Commit with an UNCHANGED holder = %v, want nil — the fix must not refuse "+
			"legitimate commits", err)
	}
	active := store.ActiveConfig()
	if active == nil || active.System.HostName != "staged-by-holder" {
		got := ""
		if active != nil {
			got = active.System.HostName
		}
		t.Fatalf("host-name after the control commit = %q, want %q — the control must reach "+
			"promotion, or it cannot distinguish 'accepted' from 'never got there'",
			got, "staged-by-holder")
	}
}
