package configstore

import (
	"strings"
	"testing"
)

func TestCommitRejectsArchivalURLPassword11774(t *testing.T) {
	const password = "ARCHIVE-COMMIT-SECRET"
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	input := `system archival configuration archive-sites "scp://alice:` + password + `@archive.example/configs"`
	if err := s.SetFromInput(input); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}

	checks := []struct {
		name string
		run  func() error
	}{
		{
			name: "CommitCheck",
			run: func() error {
				_, err := s.CommitCheck()
				return err
			},
		},
		{
			name: "Commit",
			run: func() error {
				_, err := s.Commit()
				return err
			},
		},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("accepted archival URL with inline password")
			}
			message := err.Error()
			if !strings.Contains(message, "inline URL password") ||
				!strings.Contains(message, "SSH key authentication") ||
				!strings.Contains(message, "archive.example") {
				t.Fatalf("error lacks safe rejection guidance: %v", err)
			}
			if strings.Contains(message, password) || strings.Contains(message, "alice:") {
				t.Fatalf("error exposed archival URL credentials: %v", err)
			}
		})
	}
}
