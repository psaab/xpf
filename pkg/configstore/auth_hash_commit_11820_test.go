package configstore

import (
	"strings"
	"testing"
)

func TestCommitWarnsWhenShortInactiveAPIAuthSecretIsDenied11820(t *testing.T) {
	const (
		secret       = "M4x7-only"
		expectedPath = `system services web-management api-auth user "legacy" password`
	)

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system services web-management api-auth user legacy password " + secret); err != nil {
		t.Fatalf("SetFromInput short API-auth password: %v", err)
	}
	if err := s.DeactivateFromInput("system services web-management api-auth"); err != nil {
		t.Fatalf("DeactivateFromInput API-auth: %v", err)
	}
	if err := s.SetFromInput("system host-name unrelated-change"); err != nil {
		t.Fatalf("SetFromInput unrelated change: %v", err)
	}

	compiled, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	warnings := strings.Join(compiled.Warnings, "\n")
	if !strings.Contains(warnings, expectedPath) || !strings.Contains(warnings, "#11820") {
		t.Fatalf("Commit warnings do not name the denied API-auth leaf: %q", warnings)
	}
	if strings.Count(warnings, "#11820") != 1 {
		t.Fatalf("Commit emitted duplicate short-secret advisories: %q", warnings)
	}
	if strings.Contains(warnings, secret) || strings.Contains(warnings, "$xpf-invalid$") {
		t.Fatalf("Commit warning exposes API-auth secret material: %q", warnings)
	}

	persisted, _, err := s.db.ReadActiveMeta()
	if err != nil {
		t.Fatalf("ReadActiveMeta: %v", err)
	}
	persistedText := persisted.Format()
	if strings.Contains(persistedText, secret) || !strings.Contains(persistedText, "$xpf-invalid$") {
		t.Fatalf("short credential was not safely stored as a denied marker:\n%s", persistedText)
	}

	if err := s.SetFromInput("system host-name after-denied-secret"); err != nil {
		t.Fatalf("SetFromInput second unrelated change: %v", err)
	}
	repeated, err := s.Commit()
	if err != nil {
		t.Fatalf("second Commit with stored marker: %v", err)
	}
	if warnings := strings.Join(repeated.Warnings, "\n"); strings.Contains(warnings, "#11820") {
		t.Fatalf("stored denied marker was warned again: %q", warnings)
	}
}
