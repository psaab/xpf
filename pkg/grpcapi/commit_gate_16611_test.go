package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16611 wiring cell (gRPC): the interceptor prices the candidate for
// the restricted class; Server.Commit must carry that pricing into
// promotion via a gate-bound CommitAuthority, so a same-holder
// copy/apply-groups landing between the gate and promotion — while
// the daemon commit waits on applySem and then re-snapshots — is
// refused instead of adopted. The commitFn below mirrors
// commitWithGenBinding's re-snapshot-and-promote loop.
//
// FAIL-ON-REVERT: drop Server.bindCommitGate (or the WithCommitGate
// call in Commit/CommitConfirmed) and the interleaved cell REDS —
// the denied group content is promoted.

func gateStoreGRPC16611(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"system login class ops permissions [ configure view ]",
		`system login class ops deny-configuration "system domain-name"`,
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

func gateCfgGRPC16611() *config.Config {
	return loginCfg9633(&config.LoginClass{
		Name: "ops", Permissions: []string{"all"},
		DenyConfiguration: "system domain-name", DenyLeavesPresent: []string{"deny-configuration"},
	})
}

// enterHolder16611 enters config mode as the connection session the
// handler will derive from ctx, and returns that ctx.
func enterHolder16611(t *testing.T, s *configstore.Store) context.Context {
	t.Helper()
	ctx := context.WithValue(context.Background(), authorizedPrincipalKey{}, authz.Principal{
		Source: authz.SourcePeerUID, UID: 1001, Username: "opuser", Class: "ops",
	})
	sessionID := connSessionID(ctx)
	if err := s.EnterConfigureSession(sessionID); err != nil {
		t.Fatalf("EnterConfigureSession(%q): %v", sessionID, err)
	}
	return ctx
}

func TestGRPCCommitGateTOCTOU16611(t *testing.T) {
	cfg := gateCfgGRPC16611()

	// Defect cell: gate prices a clean candidate, then a same-holder
	// apply-groups lands before promotion.
	store := gateStoreGRPC16611(t)
	ctx := enterHolder16611(t, store)
	srv := &Server{store: store}
	var err error
	ctx, err = srv.authorizeRPCCommitGate16611(ctx, cfg, "ops", method9633("Commit"), &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("gate must admit the clean candidate: %v", err)
	}
	// Interleaved same-session mutation (the copy/rename class the
	// literal gate delegates to the commit gate).
	if err := store.SetAs(connSessionID(ctx), []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("interleaved apply-groups: %v", err)
	}
	srv.commitFn = func(_ context.Context, a configstore.CommitAuthority, comment string) (*config.Config, error) {
		// bound authority is asserted in the twin cell below
		_, gen, cerr := store.CompileCandidateGen()
		if cerr != nil {
			return nil, cerr
		}
		return store.CommitWithDescriptionGenAs(a, comment, gen)
	}
	if _, err := srv.Commit(ctx, &pb.CommitRequest{}); err == nil {
		t.Fatal("Commit promoted a candidate changed after the gate priced it (#16611)")
	}
	if got := store.ShowActiveSet(); strings.Contains(got, "set system domain-name evil16611") {
		t.Fatalf("denied group content promoted to active:\n%s", got)
	}

	// CommitConfirmed half.
	store2 := gateStoreGRPC16611(t)
	ctx2 := enterHolder16611(t, store2)
	srv2 := &Server{store: store2}
	ctx2, err = srv2.authorizeRPCCommitGate16611(ctx2, cfg, "ops", method9633("CommitConfirmed"), &pb.CommitConfirmedRequest{})
	if err != nil {
		t.Fatalf("gate must admit the clean candidate (confirmed): %v", err)
	}
	if err := store2.SetAs(connSessionID(ctx2), []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("interleaved apply-groups (confirmed): %v", err)
	}
	srv2.commitConfirmedFn = func(_ context.Context, a configstore.CommitAuthority, minutes int) (*config.Config, error) {
		_, gen, cerr := store2.CompileCandidateGen()
		if cerr != nil {
			return nil, cerr
		}
		return store2.CommitConfirmedGenAs(a, minutes, gen)
	}
	if _, err := srv2.CommitConfirmed(ctx2, &pb.CommitConfirmedRequest{Minutes: 5}); err == nil {
		t.Fatal("CommitConfirmed promoted a candidate changed after the gate priced it (#16611)")
	}
	if store2.IsConfirmPending() {
		t.Fatal("refused commit-confirmed must not arm the confirm timer")
	}

	// Twin: unchanged candidate commits.
	store3 := gateStoreGRPC16611(t)
	ctx3 := enterHolder16611(t, store3)
	srv3 := &Server{store: store3}
	var err3 error
	ctx3, err3 = srv3.authorizeRPCCommitGate16611(ctx3, cfg, "ops", method9633("Commit"), &pb.CommitRequest{})
	if err3 != nil {
		t.Fatalf("gate must admit the clean candidate (twin): %v", err3)
	}
	srv3.commitFn = func(_ context.Context, a configstore.CommitAuthority, comment string) (*config.Config, error) {
		if !a.GateBound() {
			t.Error("restricted commit authority must be gate-bound (#16611)")
		}
		_, gen, cerr := store3.CompileCandidateGen()
		if cerr != nil {
			return nil, cerr
		}
		return store3.CommitWithDescriptionGenAs(a, comment, gen)
	}
	if _, err := srv3.Commit(ctx3, &pb.CommitRequest{}); err != nil {
		t.Fatalf("unchanged-candidate Commit refused: %v", err)
	}

	// Before-commit copy still refused at the gate itself.
	store4 := gateStoreGRPC16611(t)
	_ = enterHolder16611(t, store4)
	if err := store4.SetAs(connSessionID(enterHolderCtx(t, store4)), []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("apply-groups (before-commit): %v", err)
	}
	srv4 := &Server{store: store4}
	if err := srv4.authorizeRPCConfigMutation(cfg, "ops", method9633("Commit"), &pb.CommitRequest{}); err == nil {
		t.Fatal("before-commit denied candidate ALLOWED at the gate (control broken)")
	}
}

func enterHolderCtx(t *testing.T, s *configstore.Store) context.Context {
	t.Helper()
	// The session was already entered by enterHolder16611; rebuild the
	// same ctx shape for SetAs addressing.
	return context.WithValue(context.Background(), authorizedPrincipalKey{}, authz.Principal{
		Source: authz.SourcePeerUID, UID: 1001, Username: "opuser", Class: "ops",
	})
}

// TestGRPCCommitGateSamplesBeforeSameHolderMutation17676 places a
// same-holder apply-groups exactly after the atomic (candidate, generation,
// active) sample but before adjudication/stamping. The old split reads priced
// the clean tree and then captured the post-mutation generation, which let the
// denied inherited path pass verifyGateBindingLocked's equality fast path.
func TestGRPCCommitGateSamplesBeforeSameHolderMutation17676(t *testing.T) {
	cfg := gateCfgGRPC16611()
	store := gateStoreGRPC16611(t)
	ctx := enterHolder16611(t, store)
	srv := &Server{store: store}
	sampledMutation := false
	store.SetAfterCandidateGateSampleForTesting(func() {
		sampledMutation = true
		if err := store.SetAs(connSessionID(ctx), []string{"apply-groups", "G"}); err != nil {
			t.Errorf("same-holder apply-groups in snapshot/pricing gap: %v", err)
		}
	})
	defer store.SetAfterCandidateGateSampleForTesting(nil)

	var err error
	ctx, err = srv.authorizeRPCCommitGate16611(ctx, cfg, "ops", method9633("Commit"), &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("pre-mutation candidate should pass the gate: %v", err)
	}
	if !sampledMutation {
		t.Fatal("atomic candidate-gate sample hook did not run; the priced tree and generation were not captured together")
	}
	srv.commitFn = func(_ context.Context, authority configstore.CommitAuthority, comment string) (*config.Config, error) {
		_, gen, compileErr := store.CompileCandidateGen()
		if compileErr != nil {
			return nil, compileErr
		}
		return store.CommitWithDescriptionGenAs(authority, comment, gen)
	}
	if _, err := srv.Commit(ctx, &pb.CommitRequest{}); err == nil {
		t.Fatal("Commit promoted the denied candidate mutated after the atomic sample (#17676)")
	}
	if got := store.ShowActiveSet(); strings.Contains(got, "set system domain-name evil16611") {
		t.Fatalf("denied group content promoted to active:\n%s", got)
	}

	// Named control: an unchanged candidate priced and promoted by the same
	// path commits, so the new generation binding is not a blanket refusal.
	control := gateStoreGRPC16611(t)
	controlCtx := enterHolder16611(t, control)
	controlServer := &Server{store: control}
	controlCtx, err = controlServer.authorizeRPCCommitGate16611(controlCtx, cfg, "ops", method9633("Commit"), &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("unchanged control candidate gate: %v", err)
	}
	controlServer.commitFn = func(_ context.Context, authority configstore.CommitAuthority, comment string) (*config.Config, error) {
		_, gen, compileErr := control.CompileCandidateGen()
		if compileErr != nil {
			return nil, compileErr
		}
		return control.CommitWithDescriptionGenAs(authority, comment, gen)
	}
	if _, err := controlServer.Commit(controlCtx, &pb.CommitRequest{}); err != nil {
		t.Fatalf("unchanged control candidate refused: %v", err)
	}

	// Named gate control: the same denied inherited path present before the
	// sample is rejected by the authorization verdict, not by promotion.
	preDenied := gateStoreGRPC16611(t)
	preDeniedCtx := enterHolder16611(t, preDenied)
	if err := preDenied.SetAs(connSessionID(preDeniedCtx), []string{"apply-groups", "G"}); err != nil {
		t.Fatalf("apply-groups before gate: %v", err)
	}
	if _, err := (&Server{store: preDenied}).authorizeRPCCommitGate16611(preDeniedCtx, cfg, "ops", method9633("Commit"), &pb.CommitRequest{}); err == nil {
		t.Fatal("pre-sample denied candidate control passed the gate")
	}
}

func TestGRPCCommitConfirmedGateSamplesBeforeSameHolderMutation17676(t *testing.T) {
	cfg := gateCfgGRPC16611()
	store := gateStoreGRPC16611(t)
	ctx := enterHolder16611(t, store)
	srv := &Server{store: store}
	sampledMutation := false
	store.SetAfterCandidateGateSampleForTesting(func() {
		sampledMutation = true
		if err := store.SetAs(connSessionID(ctx), []string{"apply-groups", "G"}); err != nil {
			t.Errorf("same-holder apply-groups in snapshot/pricing gap: %v", err)
		}
	})
	ctx, err := srv.authorizeRPCCommitGate16611(ctx, cfg, "ops", method9633("CommitConfirmed"), &pb.CommitConfirmedRequest{})
	store.SetAfterCandidateGateSampleForTesting(nil)
	if err != nil {
		t.Fatalf("pre-mutation candidate should pass the CommitConfirmed gate: %v", err)
	}
	if !sampledMutation {
		t.Fatal("atomic candidate-gate sample hook did not run for CommitConfirmed")
	}
	srv.commitConfirmedFn = func(_ context.Context, authority configstore.CommitAuthority, minutes int) (*config.Config, error) {
		_, gen, compileErr := store.CompileCandidateGen()
		if compileErr != nil {
			return nil, compileErr
		}
		return store.CommitConfirmedGenAs(authority, minutes, gen)
	}
	if _, err := srv.CommitConfirmed(ctx, &pb.CommitConfirmedRequest{Minutes: 5}); err == nil {
		store.CancelConfirmTimerForTesting()
		t.Fatal("CommitConfirmed promoted the denied candidate mutated after the atomic sample (#17676)")
	}
	if store.IsConfirmPending() {
		t.Fatal("refused gate-bound CommitConfirmed armed the confirm timer")
	}
	if got := store.ShowActiveSet(); strings.Contains(got, "set system domain-name evil16611") {
		t.Fatalf("denied group content promoted to active by CommitConfirmed:\n%s", got)
	}
}
