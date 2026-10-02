package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/internal/testfixture"
	"github.com/psaab/xpf/pkg/frr"
)

func TestApplyToDataplaneGlobalFRRParity11455(t *testing.T) {
	cfg := testfixture.GlobalFallbackFRR11455()
	confPath := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	manager := frr.NewForTest(confPath, &frr.RecordingExecutor{})
	defer manager.Stop()
	if err := (&CLI{frr: manager}).applyToDataplane(cfg); err != nil {
		t.Fatalf("legacy CLI apply: %v", err)
	}
	got, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testfixture.ExpectedGlobalFallbackFRR11455 {
		t.Fatalf("legacy CLI FRR bytes differ from daemon's global/instance contract\nwant:\n%s\ngot:\n%s",
			testfixture.ExpectedGlobalFallbackFRR11455, got)
	}
}
