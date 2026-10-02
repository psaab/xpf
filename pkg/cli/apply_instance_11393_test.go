package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/internal/testfixture"
	"github.com/psaab/xpf/pkg/frr"
)

func TestApplyToDataplaneInstanceProtocolsAndIPv6Statics11393(t *testing.T) {
	cfg := testfixture.RoutingInstanceFRR11393()

	cliPath := filepath.Join(t.TempDir(), "cli.conf")
	if err := os.WriteFile(cliPath, []byte("log syslog informational\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	cliManager := frr.NewForTest(cliPath, &frr.RecordingExecutor{})
	defer cliManager.Stop()
	if err := (&CLI{frr: cliManager}).applyToDataplane(cfg); err != nil {
		t.Fatalf("legacy CLI apply: %v", err)
	}
	cliConf, err := os.ReadFile(cliPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(cliConf) != testfixture.ExpectedFRRInstanceConfig11393 {
		t.Fatalf("legacy CLI FRR bytes differ from daemon's shared byte contract\nwant:\n%s\ngot:\n%s",
			testfixture.ExpectedFRRInstanceConfig11393, cliConf)
	}
}
