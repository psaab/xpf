package configstore

import (
	"strings"
	"testing"
)

func TestCommitCheckRejectsNestedNameCompactTail12092(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	input := `firewall {
    family inet {
        filter F {
            term { T from destination-port 22 { then { accept; } } }
            term deny { then discard; }
        }
    }
}`
	if err := s.LoadOverride(input); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("LoadOverride + CommitCheck accepted P05; the nameless nested term must be rejected")
	}
	if !strings.Contains(err.Error(), "nameless") ||
		!strings.Contains(err.Error(), "#10294") ||
		!strings.Contains(err.Error(), "#12092") ||
		!strings.Contains(err.Error(), `"T"`) {
		t.Fatalf("CommitCheck error = %q, want nameless #10294/#12092 rejection naming T", err)
	}
}
