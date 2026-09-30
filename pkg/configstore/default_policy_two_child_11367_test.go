package configstore

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const twoChildDefaultPolicySync11367 = `
security {
  policies {
    default-policy {
      permit-all;
      deny-all;
    }
  }
}
`

const twoChildDefaultPolicyDiagnostic11367 = "security policies default-policy: expected exactly one block value, found 2 children"

func TestSyncApplyRejectsAmbiguousDefaultPolicy11367(t *testing.T) {
	s := newTestStore(t)
	compiled, err := s.SyncApply(twoChildDefaultPolicySync11367, nil)
	if err == nil {
		if compiled == nil {
			t.Fatal("SyncApply returned neither a config nor an error for two policy choices")
		}
		t.Fatalf("SyncApply accepted two default-policy choices as action %d", compiled.Security.DefaultPolicy)
	}
	if !strings.Contains(err.Error(), twoChildDefaultPolicyDiagnostic11367) {
		t.Fatalf("SyncApply error = %v, want diagnostic containing %q", err, twoChildDefaultPolicyDiagnostic11367)
	}
	if compiled != nil {
		t.Fatalf("SyncApply returned a compiled config with error: %+v", compiled.Security.DefaultPolicy)
	}
}

func TestCheckTextRejectsAmbiguousDefaultPolicy11367(t *testing.T) {
	compiled, err := CheckText(twoChildDefaultPolicySync11367, -1)
	if err == nil {
		if compiled == nil {
			t.Fatal("CheckText returned neither a config nor an error for two policy choices")
		}
		t.Fatalf("CheckText accepted two default-policy choices as action %d", compiled.Security.DefaultPolicy)
	}
	if !strings.Contains(err.Error(), twoChildDefaultPolicyDiagnostic11367) {
		t.Fatalf("CheckText error = %v, want diagnostic containing %q", err, twoChildDefaultPolicyDiagnostic11367)
	}
	if compiled != nil {
		t.Fatalf("CheckText returned a compiled config with error: %+v", compiled.Security.DefaultPolicy)
	}
}

func TestLoadRejectsAmbiguousDefaultPolicy11367(t *testing.T) {
	s := newTestStore(t)
	tree, parseErrors := config.NewParser(twoChildDefaultPolicySync11367).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("two-child default-policy fixture parse errors: %v", parseErrors)
	}
	if err := s.db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	err := s.Load()
	if err == nil {
		cfg := s.ActiveConfig()
		if cfg == nil {
			t.Fatal("Load accepted ambiguous default-policy without an error or active config")
		}
		t.Fatalf("Load accepted two default-policy choices as action %d", cfg.Security.DefaultPolicy)
	}
	if !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Load error = %v, want ErrConfigCompile", err)
	}
	if !strings.Contains(err.Error(), twoChildDefaultPolicyDiagnostic11367) {
		t.Fatalf("Load error = %v, want diagnostic containing %q", err, twoChildDefaultPolicyDiagnostic11367)
	}
	if cfg := s.ActiveConfig(); cfg != nil {
		t.Fatalf("Load published a compiled config despite rejecting ambiguity: %+v", cfg.Security.DefaultPolicy)
	}
}
