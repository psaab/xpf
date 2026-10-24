package grpcapi

// #16156: the gRPC bare-commit confirm-only branch now routes through
// the shared configstore ConfirmOnly predicate, and the commit RPCs
// project warnings via configstore.WarningsOf. The structural
// classifier corpus is pinned in pkg/configstore
// (TestClassifyCommitError16156) and through these RPCs in
// TestCommitErrorClassification_5742; warnings transport is pinned by
// commit_advisory_warnings_6515_test.go. This file pins the two
// confirm-window behaviours the predicate swap could silently change:
//
//   - unchanged candidate: bare Commit confirms only (commitFn NOT
//     invoked, window cleared);
//   - dirty candidate: bare Commit falls through to commitFn so the
//     staged edits are committed, not dropped (#4000).
//
// FAIL-ON-REVERT: drop the dirty conjunct from ConfirmOnly and the
// dirty cell REDS (commitFn never called, staged edit dropped).

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// armGRPCConfirmWindow16156 returns a store with a pending confirm
// window and a clean candidate, plus a Commit handler whose commitFn
// records whether it was invoked.
func armGRPCConfirmWindow16156(t *testing.T) (*configstore.Store, *Server, *bool) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("set system host-name Base16156"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("set system host-name Confirmed16156"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	if !store.IsConfirmPending() || store.IsDirty() {
		t.Fatal("premise: want pending window with clean candidate")
	}
	called := false
	s := &Server{
		store: store,
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			called = true
			return store.Commit()
		},
	}
	return store, s, &called
}

func TestGRPCBareCommitConfirmOnly16156(t *testing.T) {
	t.Run("UnchangedConfirmsWithoutCommitFn", func(t *testing.T) {
		store, s, called := armGRPCConfirmWindow16156(t)
		if _, err := s.Commit(context.Background(), &pb.CommitRequest{}); err != nil {
			t.Fatalf("bare Commit (unchanged): %v", err)
		}
		if *called {
			t.Fatal("commitFn invoked for an unchanged candidate during a confirm window; want confirm-only")
		}
		if store.IsConfirmPending() {
			t.Fatal("confirm-only bare Commit must clear the pending window")
		}
	})

	t.Run("DirtyFallsThroughToCommitFn", func(t *testing.T) {
		store, s, called := armGRPCConfirmWindow16156(t)
		if _, err := store.LoadSet("set system host-name Edited16156"); err != nil {
			t.Fatal(err)
		}
		if !store.IsDirty() {
			t.Fatal("premise: candidate must be dirty after staging an edit")
		}
		if _, err := s.Commit(context.Background(), &pb.CommitRequest{}); err != nil {
			t.Fatalf("bare Commit (dirty): %v", err)
		}
		if !*called {
			t.Fatal("commitFn not invoked for a dirty candidate during a confirm window; staged edits would be silently dropped (#4000)")
		}
		if got := store.ActiveConfig().System.HostName; !strings.Contains(got, "Edited16156") {
			t.Fatalf("active host-name = %q, want Edited16156", got)
		}
		if store.IsConfirmPending() {
			t.Fatal("dirty bare Commit must clear the pending window (#3861)")
		}
	})
}
