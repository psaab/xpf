package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCopyStagedResumeRefusesTamperedVersionDir10727 is the A10-F7
// fail-on-revert guard: a same-generation resume skip must re-verify version-dir
// bytes against the pinned staged source. Tampering one managed binary (cli —
// the non-lockstep binary the flip repoints with no other content gate) after
// the copy lands must make the resume REFUSE instead of silently adopting the
// bytes. The intact control pins that an untampered resume still skips clean.
func TestCopyStagedResumeRefusesTamperedVersionDir10727(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	genid := publishStagedGen(t, r)
	j := &Journal{TargetVersion: "2.0.0", State: StateStaged, SourceGeneration: genid}
	if err := r.copyStaged(j); err != nil {
		t.Fatalf("initial copyStaged: %v", err)
	}
	// Intact resume skips without error (the control).
	if err := r.copyStaged(j); err != nil {
		t.Fatalf("intact resume must skip clean, got: %v", err)
	}
	// Tamper one flipped binary behind the stamp's back.
	tamperPath := filepath.Join(cfg.VersionsDir, "2.0.0", "cli")
	if err := os.WriteFile(tamperPath, []byte("TAMPERED-not-the-staged-cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := r.copyStaged(j)
	if err == nil {
		t.Fatal("tampered resume must REFUSE; got nil (unverified bytes would flip)")
	}
	if !strings.Contains(err.Error(), "REFUSE") || !strings.Contains(err.Error(), "cli") {
		t.Fatalf("refusal must name the offending binary, got: %v", err)
	}
}
