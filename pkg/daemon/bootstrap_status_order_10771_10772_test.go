package daemon

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/bootstrapshow"
	"github.com/psaab/xpf/pkg/config"
)

func loadDay0CredentialFixtureConfig(t *testing.T, f *credentialTailFixture6790) {
	t.Helper()
	configFile := filepath.Join(t.TempDir(), "xpf.conf")
	if err := os.WriteFile(configFile, []byte("system { host-name bootstrap-test; }\n"), 0o600); err != nil {
		t.Fatalf("write day-0 config: %v", err)
	}
	f.d.opts.ConfigFile = configFile
	if failClosed, err := f.d.loadAndBootstrapConfig(); err != nil || failClosed {
		t.Fatalf("loadAndBootstrapConfig() = (%v, %v); want (false, nil)", failClosed, err)
	}
	f.cfg = f.d.store.ActiveConfig()
	if f.cfg == nil {
		t.Fatal("day-0 config import did not produce an active config")
	}
}

func TestRunStartupWithEventBufferCapturesPhaseOneBootstrapFailure10772(t *testing.T) {
	d := &Daemon{}
	if d.eventBuf != nil {
		t.Fatal("test premise: startup event buffer must not be pre-seeded")
	}

	eventBuf, err := d.runStartupWithEventBuffer(context.Background(), []startupPhase{
		{"config-load-bootstrap", func(context.Context) error {
			d.recordBootstrapImport(bootstrapImportFailed, "commit: parse error")
			return nil
		}},
	}, func(err error) error { return err })
	if err != nil {
		t.Fatalf("runStartupWithEventBuffer: %v", err)
	}
	if eventBuf != d.eventBuf {
		t.Fatal("startup phases and event consumers must share the same event buffer")
	}
	events := eventBuf.Latest(16)
	if len(events) != 1 || events[0].Type != "BOOTSTRAP_IMPORT_FAILED" || events[0].Reason != "commit: parse error" {
		t.Fatalf("startup phase events = %+v, want one BOOTSTRAP_IMPORT_FAILED event with its reason", events)
	}
}

func TestBootstrapImportShowsPendingUntilCredentialApplyCompletes10771(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	loadDay0CredentialFixtureConfig(t, f)

	pending := f.d.bootstrapShowSnapshot()
	if pending.Status != bootstrapImportPending || pending.Failed {
		t.Fatalf("after import, before credential apply = %+v, want pending and not failed", pending)
	}
	var out bytes.Buffer
	bootstrapshow.Render(&out, pending)
	if !strings.Contains(out.String(), "credential-apply-pending") || strings.Contains(out.String(), "Status:   ok") {
		t.Fatalf("show before credential apply must not report ok:\n%s", out.String())
	}

	if err := f.tail(); err != nil {
		t.Fatalf("healthy initial credential apply: %v", err)
	}
	completed := f.d.bootstrapShowSnapshot()
	if completed.Status != bootstrapImportOK || completed.Failed {
		t.Fatalf("after healthy credential apply = %+v, want ok", completed)
	}
}

func TestBootstrapImportReportsCredentialApplyFailure10771(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	loadDay0CredentialFixtureConfig(t, f)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	// `id` reports the account missing and `useradd` then refuses, reproducing
	// a day-0 login credential that could not be provisioned.
	runCommandTimeout = func(string, ...string) ([]byte, error) {
		return []byte("simulated: refused"), os.ErrPermission
	}

	if err := f.tail(); err == nil {
		t.Fatal("credential apply unexpectedly succeeded despite user creation refusal")
	}
	got := f.d.bootstrapShowSnapshot()
	if got.Status != bootstrapImportCredentialFailed || !got.Failed {
		t.Fatalf("after failed credential apply = %+v, want credential-apply-failed", got)
	}
	if got.Error == "" || strings.Contains(got.Error, "simulated: refused") {
		t.Fatalf("credential failure must have a useful, secret-free explanation, got %q", got.Error)
	}
	var out bytes.Buffer
	bootstrapshow.Render(&out, got)
	if !strings.Contains(out.String(), "configured access may be incomplete") ||
		strings.Contains(out.String(), "NOT the one on the day-0 medium") {
		t.Fatalf("credential failure should explain partial access without claiming import was absent:\n%s", out.String())
	}
}
