package configstore

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const packedTailStoreDrop18771 = `interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } }`
const packedTailStoreBraced18771 = `interfaces { ge-0/0/0 { unit 0 { family inet6 { dad-disable; } } } }`
const packedTailStorePeerDrop18771 = `groups { node0 { } node1 { interfaces { ge-0/0/0 { unit 0 { family inet6 dad-disable; } } } } } apply-groups "${node}";`

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
	return packedTailStageText18771(t, nodeID, packedTailStoreDrop18771)
}

func packedTailStageText18771(t *testing.T, nodeID int, text string) *Store {
	t.Helper()
	s := newTestStore(t)
	s.SetNodeID(nodeID)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.ExitConfigure() })
	if err := s.LoadOverride(text); err != nil {
		t.Fatalf("stage packed tail: %v", err)
	}
	return s
}

func TestPackedTailGate18771Cell08PeerDeliveryAndCommitEligibility(t *testing.T) {
	t.Run("check-config-diagnoses-preflight-is-zero-twin", func(t *testing.T) {
		logs := packedTailStoreLogs18771(t)
		// CheckText and CommitCheck report the DROP without refusing; the
		// pre-flight, candidate and completion compiles stay zero-twin.
		cfg, err := CheckText(packedTailStoreDrop18771, -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(cfg)) != 1 {
			t.Fatalf("CheckText gate diagnostics = %d, want 1", len(packedTailStoreDiagnostics18771(cfg)))
		}
		s := packedTailStage18771(t, -1)
		snapshot, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(snapshot)) != 0 {
			t.Fatal("CompileCandidateGen ran twins")
		}
		checked, err := s.CommitCheck()
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(checked)) != 1 {
			t.Fatal("CommitCheck did not surface the DROP diagnostic")
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
		if promoted, err := s.CommitWithDescriptionGen("promote", gen); err == nil ||
			!strings.Contains(err.Error(), "packed-tail statement(s) would be silently dropped") {
			t.Fatalf("packed-tail promotion = (%v, %v), want enforcement refusal", promoted, err)
		}
		if got := strings.Count(logs.String(), "packedTailGate18771"); got != 3 {
			t.Fatalf("standalone sequence produced %d gated views, want 3 (CheckText + CommitCheck + refused promotion)", got)
		}
	})

	t.Run("peer-warnings-are-slog-only-local-clean-commit-succeeds", func(t *testing.T) {
		logs := packedTailStoreLogs18771(t)
		s := newTestStore(t)
		s.SetNodeID(0)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.ExitConfigure() })
		if err := s.LoadOverride(packedTailStorePeerDrop18771); err != nil {
			t.Fatalf("stage peer-view DROP: %v", err)
		}
		snapshot, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		if len(packedTailStoreDiagnostics18771(snapshot)) != 0 {
			t.Fatal("cluster snapshot ran twins")
		}
		promoted, err := s.CommitWithDescriptionGen("peer-view drop", gen)
		if err != nil {
			t.Fatalf("local-CLEAN commit was refused for a peer-view DROP: %v", err)
		}
		if got := len(packedTailStoreDiagnostics18771(promoted)); got != 0 {
			t.Fatalf("commit response carries %d findings, want no local or peer findings", got)
		}
		logText := logs.String()
		if got := strings.Count(logText, "packedTailGate18771"); got != 2 {
			t.Fatalf("peer promotion gated views = %d, want 2 peer-only views", got)
		}
		if !strings.Contains(logText, "node=node1") || strings.Contains(logText, "node=node0") {
			t.Fatalf("peer-only gate logs are not node-labelled/local-only: %s", logText)
		}
	})

	t.Run("genuine-conflict-retry-refuses-only-after-one-eligible-invocation", func(t *testing.T) {
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
		if _, err = s.CommitWithDescriptionGen("retry", fresh); err == nil ||
			!strings.Contains(err.Error(), "packed-tail statement(s) would be silently dropped") {
			t.Fatalf("fresh promotion = %v, want packed-tail refusal", err)
		}
		if got := strings.Count(logs.String(), "packedTailGate18771"); got != 3 {
			t.Fatalf("whole conflict/refusal sequence ran %d gated views, want one three-view HA promotion", got)
		}
	})

	t.Run("commit-confirmed-refuses", func(t *testing.T) {
		logs := packedTailStoreLogs18771(t)
		s := packedTailStage18771(t, -1)
		if _, err := s.CommitConfirmed(1); err == nil ||
			!strings.Contains(err.Error(), "packed-tail statement(s) would be silently dropped") {
			t.Fatalf("commit-confirmed = %v, want packed-tail refusal", err)
		}
		if s.IsConfirmPending() {
			t.Fatal("refused commit-confirmed armed a rollback timer")
		}
		if got := strings.Count(logs.String(), "packedTailGate18771"); got != 1 {
			t.Fatalf("commit-confirmed views = %d, want 1 refused local gate", got)
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

// #18771 enforcement cells (design v3 Q7). Production posture is read
// via config.PackedTailGateEnforce18771(). Refusal cells drive public Store
// promotion entry points unconditionally, so reverting the const turns them
// red rather than skip-green.
func TestPackedTailEnforce18771CommitCheckDiagnosesNoRefuse(t *testing.T) {
	s := packedTailStage18771(t, -1)
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatal(err)
	}
	if len(packedTailStoreDiagnostics18771(cfg)) != 1 {
		t.Fatalf("commit check diagnostics = %d, want 1", len(packedTailStoreDiagnostics18771(cfg)))
	}
}

func TestPackedTailEnforce18771StrictRefusalMatrix(t *testing.T) {
	t.Run("description-gen-refusal-is-atomic-and-braced-retry-succeeds", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.ExitConfigure() })
		if err := s.LoadOverride("system { host-name baseline18771; }"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit clean baseline: %v", err)
		}
		if err := s.LoadOverride(packedTailStoreDrop18771); err != nil {
			t.Fatal(err)
		}
		candidateBefore, candidateGen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		candidateText := s.ShowCandidateSet()
		activeBefore, activeText, activeGen := s.ActiveConfigAndText()
		_, err = s.CommitWithDescriptionGen("must refuse", candidateGen)
		if err == nil || !strings.Contains(err.Error(), "packed-tail statement(s) would be silently dropped") {
			t.Fatalf("CommitWithDescriptionGen = %v, want packed-tail refusal", err)
		}
		for _, part := range []string{"site ", "inet6/dad-disable at 1:", "standalone"} {
			if !strings.Contains(err.Error(), part) {
				t.Errorf("refusal omits %q: %v", part, err)
			}
		}
		activeAfter, afterText, afterGen := s.ActiveConfigAndText()
		if activeAfter == nil || activeBefore == nil ||
			config.ConfigFingerprint(activeAfter) != config.ConfigFingerprint(activeBefore) ||
			afterText != activeText || afterGen != activeGen {
			t.Fatal("refused commit changed active config, persisted text, or active generation")
		}
		candidateAfter, afterCandidateGen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatalf("compile retained candidate after refusal: %v", err)
		}
		if afterCandidateGen != candidateGen || s.CandidateGeneration() != candidateGen ||
			s.ShowCandidateSet() != candidateText ||
			config.ConfigFingerprint(candidateAfter) != config.ConfigFingerprint(candidateBefore) {
			t.Fatal("refused commit changed or discarded its candidate/generation")
		}

		if err := s.LoadOverride(packedTailStoreBraced18771); err != nil {
			t.Fatal(err)
		}
		_, retryGen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatalf("compile braced retry: %v", err)
		}
		retried, err := s.CommitWithDescriptionGen("braced retry", retryGen)
		if err != nil {
			t.Fatalf("braced retry refused: %v", err)
		}
		if len(packedTailStoreDiagnostics18771(retried)) != 0 {
			t.Fatalf("braced retry carried gate diagnostics: %v", packedTailStoreDiagnostics18771(retried))
		}
		_, activeText, _ = s.ActiveConfigAndText()
		if !strings.Contains(activeText, "family inet6 {") {
			t.Fatal("braced retry did not become active")
		}
	})

	t.Run("commit-confirmed-refusal-is-atomic", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.ExitConfigure() })
		if err := s.LoadOverride("system { host-name baseline18771; }"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit clean baseline: %v", err)
		}
		if err := s.LoadOverride(packedTailStoreDrop18771); err != nil {
			t.Fatal(err)
		}
		candidateGen := s.CandidateGeneration()
		activeBefore, activeText, activeGen := s.ActiveConfigAndText()
		if _, err := s.CommitConfirmed(1); err == nil ||
			!strings.Contains(err.Error(), "packed-tail statement(s) would be silently dropped") {
			t.Fatalf("CommitConfirmed = %v, want packed-tail refusal", err)
		}
		activeAfter, afterText, afterGen := s.ActiveConfigAndText()
		if activeAfter == nil || activeBefore == nil ||
			config.ConfigFingerprint(activeAfter) != config.ConfigFingerprint(activeBefore) ||
			afterText != activeText || afterGen != activeGen ||
			s.CandidateGeneration() != candidateGen || s.IsConfirmPending() {
			t.Fatal("refused CommitConfirmed changed active/candidate state or armed a rollback")
		}
	})
}

func TestPackedTailEnforce18771NeverRefusesSkippedOrPartial(t *testing.T) {
	t.Run("33-site-cap", func(t *testing.T) {
		var text strings.Builder
		for i := range 33 {
			fmt.Fprintf(&text, "interfaces { ge-0/0/%d { unit 0 { family inet6 dad-disable; } } }\n", i)
		}
		s := packedTailStageText18771(t, -1, text.String())
		_, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := s.CommitWithDescriptionGen("over cap", gen)
		if err != nil {
			t.Fatalf("33-site SKIPPED-CAP commit refused: %v", err)
		}
		verdicts := packedTailStoreVerdicts18771(cfg)
		if len(verdicts) != 1 || verdicts[0] != "SKIPPED-CAP" {
			t.Fatalf("33-site commit findings = %v, want only SKIPPED-CAP", verdicts)
		}
	})

	t.Run("group-fanout-provenance-skip", func(t *testing.T) {
		const fanout = `groups { g { interfaces { <*> { unit 0 { family inet6 dad-disable; } } } } }
apply-groups g;
interfaces { ge-0/0/0 { description first; } ge-0/0/1 { description second; } }
`
		s := packedTailStageText18771(t, -1, fanout)
		_, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := s.CommitWithDescriptionGen("fanout", gen)
		if err != nil {
			t.Fatalf("SKIPPED-PROVENANCE commit refused: %v", err)
		}
		verdicts := packedTailStoreVerdicts18771(cfg)
		if len(verdicts) != 2 || verdicts[0] != "SKIPPED-PROVENANCE" || verdicts[1] != "SKIPPED-PROVENANCE" {
			t.Fatalf("fanout commit findings = %v, want two SKIPPED-PROVENANCE findings", verdicts)
		}
	})

	t.Run("indeterminate-is-warning-only", func(t *testing.T) {
		const partial = `interfaces { ge-0/0/1 { unit 0 { family inet { address 192.0.2.2/24 vrrp-group 1 authentication-type simple; } } } }`
		s := packedTailStageText18771(t, -1, partial)
		_, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := s.CommitWithDescriptionGen("partial", gen)
		if err != nil {
			t.Fatalf("INDETERMINATE commit refused: %v", err)
		}
		verdicts := packedTailStoreVerdicts18771(cfg)
		if len(verdicts) != 1 || verdicts[0] != "INDETERMINATE" {
			t.Fatalf("indeterminate commit findings = %v, want INDETERMINATE", verdicts)
		}
	})
}

func TestPackedTailEnforce18771SecretAndRollbackSurfaces(t *testing.T) {
	t.Run("refusal-does-not-leak-secret-or-tail", func(t *testing.T) {
		const secret = "DISTINCTIVE-18771-SECRET"
		text := `system { services { web-management { api-auth { expires 2099-01-01; user admin { password "` + secret + `"; } api-key machine-generated-key-alpha; } } } }
` + packedTailStoreDrop18771
		logs := packedTailStoreLogs18771(t)
		s := packedTailStageText18771(t, -1, text)
		_, gen, err := s.CompileCandidateGen()
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.CommitWithDescriptionGen("secret fixture", gen)
		if err == nil || !strings.Contains(err.Error(), "packed-tail statement(s) would be silently dropped") {
			t.Fatalf("secret fixture commit = %v, want packed-tail refusal", err)
		}
		for surface, content := range map[string]string{"error": err.Error(), "logs": logs.String()} {
			if strings.Contains(content, secret) || strings.Contains(content, strconv.Quote(secret)) ||
				strings.Contains(content, "dad-disable;") {
				t.Errorf("%s leaked the secret or raw packed tail: %s", surface, content)
			}
		}
	})

	t.Run("confirmed-timeout-restores-packed-config", func(t *testing.T) {
		s := packedTailBootstrapStore18771(t, packedTailStoreDrop18771)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.LoadOverride("system { host-name confirmed-clean18771; }"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CommitConfirmed(1); err != nil {
			t.Fatalf("clean CommitConfirmed: %v", err)
		}
		gen := s.ConfirmGenForTesting()
		s.InvokeRollbackTimerForTesting(gen)
		if cfg := s.ActiveConfig(); cfg == nil || !hasPackedTailVerdict18771(cfg, "DROP") {
			t.Fatalf("timeout rollback did not restore bootstrapped DROP config: %v", cfg)
		}
	})

	t.Run("rollback-n-pre-upgrade-config-refuses-on-commit", func(t *testing.T) {
		s := packedTailBootstrapStore18771(t, packedTailStoreDrop18771)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.LoadOverride("system { host-name post-upgrade18771; }"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatalf("commit clean post-upgrade config: %v", err)
		}
		if err := s.Rollback(1); err != nil {
			t.Fatalf("rollback 1: %v", err)
		}
		if !strings.Contains(s.ShowCandidateSet(), "dad-disable") {
			t.Fatal("rollback 1 did not stage the pre-upgrade packed configuration")
		}
		gen := s.CandidateGeneration()
		if _, err := s.CommitWithDescriptionGen("restore old packed config", gen); err == nil ||
			!strings.Contains(err.Error(), "packed-tail statement(s) would be silently dropped") {
			t.Fatalf("commit after rollback 1 = %v, want packed-tail refusal", err)
		}
		if s.CandidateGeneration() != gen || !strings.Contains(s.ShowCandidateSet(), "dad-disable") {
			t.Fatal("refused rollback commit did not retain the staged packed candidate")
		}
	})
}

func packedTailBootstrapStore18771(t *testing.T, text string) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride(text); err != nil {
		t.Fatal(err)
	}
	bootstrap := InternalCommitterAs(BootstrapPrincipal)
	_, gen, err := s.CompileCandidateGenAs(bootstrap)
	if err != nil {
		t.Fatalf("bootstrap pre-flight: %v", err)
	}
	if _, err := s.CommitWithDescriptionGenAs(bootstrap, "", gen); err != nil {
		t.Fatalf("bootstrap promotion: %v", err)
	}
	s.ExitConfigure()
	return s
}

func packedTailStoreVerdicts18771(cfg *config.Config) (out []string) {
	for _, d := range packedTailStoreDiagnostics18771(cfg) {
		fields := strings.Fields(d.Prose)
		if len(fields) > 1 {
			out = append(out, fields[1])
		}
	}
	return out
}

func hasPackedTailVerdict18771(cfg *config.Config, want string) bool {
	for _, got := range packedTailStoreVerdicts18771(cfg) {
		if got == want {
			return true
		}
	}
	return false
}
