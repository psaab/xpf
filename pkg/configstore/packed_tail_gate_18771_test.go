package configstore

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const packedTailStoreDrop18771 = `interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } }`

func packedTailStoreDiagnostics18771(cfg *config.Config) (out []config.Diagnostic) {
	if cfg == nil {
		return nil
	}
	for _, d := range cfg.Diagnostics {
		if d.Gate == "packedTailGate18771" {
			out = append(out, d)
		}
	}
	return out
}

func packedTailStoreLogs18771(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func packedTailStage18771(t *testing.T, nodeID int) *Store {
	t.Helper()
	s := newTestStore(t)
	s.SetNodeID(nodeID)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.ExitConfigure() })
	if err := s.LoadOverride(packedTailStoreDrop18771); err != nil {
		t.Fatalf("stage packed tail: %v", err)
	}
	return s
}

func TestPackedTailGate18771Cell08PeerDeliveryAndCommitEligibility(t *testing.T) {
	t.Run("check-config-and-preflight-are-zero-twin", func(t *testing.T) {
		logs := packedTailStoreLogs18771(t)
		cfg, err := CheckText(packedTailStoreDrop18771, -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(cfg)) != 0 {
			t.Fatal("CheckText ran the commit-only gate")
		}
		s := packedTailStage18771(t, -1)
		snapshot, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(snapshot)) != 0 {
			t.Fatal("CompileCandidateGen ran twins")
		}
		if _, err = s.CommitCheck(); err != nil {
			t.Fatal(err)
		}
		if _, err = s.CompileCandidate(); err != nil {
			t.Fatal(err)
		}
		completion, ok := s.CandidateConfigForCompletion()
		if !ok {
			t.Fatal("completion fixture did not compile; zero-twin assertion would be vacuous")
		}
		if len(packedTailStoreDiagnostics18771(completion)) != 0 {
			t.Fatal("completion ran twins")
		}
		promoted, err := s.CommitWithDescriptionGen("promote", gen)
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(promoted)) != 1 {
			t.Fatalf("promotion gate diagnostics = %d, want 1", len(packedTailStoreDiagnostics18771(promoted)))
		}
		if got := strings.Count(logs.String(), "packedTailGate18771"); got != 1 {
			t.Fatalf("one standalone promotion produced %d gated views, want 1", got)
		}
	})

	t.Run("peer-warnings-are-slog-only-and-three-view", func(t *testing.T) {
		logs := packedTailStoreLogs18771(t)
		s := packedTailStage18771(t, 0)
		snapshot, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(snapshot)) != 0 {
			t.Fatal("cluster snapshot ran twins")
		}
		promoted, err := s.CommitWithDescriptionGen("cluster promote", gen)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(packedTailStoreDiagnostics18771(promoted)); got != 1 {
			t.Fatalf("commit response carries %d gate findings, want local only 1", got)
		}
		logText := logs.String()
		if got := strings.Count(logText, "packedTailGate18771"); got != 3 {
			t.Fatalf("cluster promotion gated views = %d, want 3", got)
		}
		if !strings.Contains(logText, "node=node0") || !strings.Contains(logText, "node=node1") {
			t.Fatalf("peer gate logs are not node-labelled: %s", logText)
		}
	})

	t.Run("genuine-conflict-retry-has-one-eligible-invocation", func(t *testing.T) {
		logs := packedTailStoreLogs18771(t)
		s := packedTailStage18771(t, 0)
		_, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name retry18771"); err != nil {
			t.Fatal(err)
		}
		if _, err = s.CommitWithDescriptionGen("stale", gen); !errors.Is(err, ErrCandidateGenerationConflict) {
			t.Fatalf("stale promotion = %v, want generation conflict", err)
		}
		if got := strings.Count(logs.String(), "packedTailGate18771"); got != 0 {
			t.Fatalf("conflicting attempt ran %d eligible views", got)
		}
		_, fresh, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.CommitWithDescriptionGen("retry", fresh); err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(logs.String(), "packedTailGate18771"); got != 3 {
			t.Fatalf("whole conflict/retry sequence ran %d gated views, want exactly one 3-view promotion", got)
		}
	})

	t.Run("commit-confirmed-is-the-other-promotion", func(t *testing.T) {
		logs := packedTailStoreLogs18771(t)
		s := packedTailStage18771(t, -1)
		cfg, err := s.CommitConfirmed(1)
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(cfg)) != 1 {
			t.Fatal("commit-confirmed did not run its one local gate")
		}
		if got := strings.Count(logs.String(), "packedTailGate18771"); got != 1 {
			t.Fatalf("commit-confirmed views = %d, want 1", got)
		}
	})

	t.Run("boot-sync-and-exported-peer-wrapper-are-zero-twin", func(t *testing.T) {
		logs := packedTailStoreLogs18771(t)
		s := newTestStore(t)
		cfg, err := s.SyncApply(packedTailStoreDrop18771, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(cfg)) != 0 {
			t.Fatal("SyncApply ran the commit-only gate")
		}
		tree, parseErrors := config.NewParser(packedTailStoreDrop18771).Parse()
		if len(parseErrors) > 0 {
			t.Fatal(parseErrors)
		}
		if err := config.ValidatePeerEffectiveStrict(tree, 0); err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(logs.String(), "packedTailGate18771"); got != 0 {
			t.Fatalf("tolerant/default peer paths emitted %d gate findings", got)
		}
	})
}
