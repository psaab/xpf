package configstore

import (
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

func assertAmbiguousDefaultPolicyBootsDenied11367(t *testing.T, compiled *config.Config) {
	t.Helper()
	if compiled == nil {
		t.Fatal("tolerant ingress returned a nil config")
	}
	if compiled.Security.DefaultPolicy != config.PolicyDeny {
		t.Fatalf("tolerant default-policy = %v, want PolicyDeny", compiled.Security.DefaultPolicy)
	}
	for _, warning := range compiled.Warnings {
		if strings.Contains(warning, twoChildDefaultPolicyDiagnostic11367) &&
			strings.Contains(warning, "#11367") {
			return
		}
	}
	t.Fatalf("tolerant ingress omitted the #11367 warning: %v", compiled.Warnings)
}

func TestSyncApplyWarnsAndDefaultsDenyOnAmbiguousDefaultPolicy11367(t *testing.T) {
	compiled, err := newTestStore(t).SyncApply(twoChildDefaultPolicySync11367, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected the persisted ambiguous default-policy: %v", err)
	}
	assertAmbiguousDefaultPolicyBootsDenied11367(t, compiled)
}

func TestCheckTextRejectsAmbiguousDefaultPolicy11367(t *testing.T) {
	compiled, err := CheckText(twoChildDefaultPolicySync11367, -1)
	if err == nil || !strings.Contains(err.Error(), twoChildDefaultPolicyDiagnostic11367) {
		t.Fatalf("CheckText error = %v, want strict ambiguous default-policy rejection", err)
	}
	if compiled != nil {
		t.Fatalf("CheckText returned a compiled config despite rejection: %+v", compiled.Security.DefaultPolicy)
	}
}

func TestLoadWarnsAndDefaultsDenyOnAmbiguousDefaultPolicy11367(t *testing.T) {
	s := newTestStore(t)
	tree, parseErrors := config.NewParser(twoChildDefaultPolicySync11367).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("two-child default-policy fixture parse errors: %v", parseErrors)
	}
	if err := s.db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load rejected an already-persisted ambiguous default-policy: %v", err)
	}
	assertAmbiguousDefaultPolicyBootsDenied11367(t, s.ActiveConfig())
}
