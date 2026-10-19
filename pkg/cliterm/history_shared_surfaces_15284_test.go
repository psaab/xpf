package cliterm_test

// Both interactive surfaces (pkg/cli local console and cmd/cli remote client)
// must construct readline through the same cliterm history wiring, or the
// #15284 fix can silently apply to only one of them (the exact divergence
// class pkg/cliterm exists to prevent, #6548). These tests pin the shared
// call shape in source: ConfigureReadlineHistory present, the old
// DisableReadlineHistoryAutoSave helper absent, and history seeding +
// per-line recording wired at each surface's main loop.

import (
	"os"
	"strings"
	"testing"
)

func mustContain(t *testing.T, path string, wants ...string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(data)
	for _, w := range wants {
		if !strings.Contains(src, w) {
			t.Errorf("%s does not contain %q", path, w)
		}
	}
	return src
}

func TestBothSurfacesShareHistoryWiring_15284(t *testing.T) {
	for _, path := range []string{"../cli/cli.go", "../../cmd/cli/main.go"} {
		src := mustContain(t, path,
			"cliterm.ConfigureReadlineHistory(&readline.Config{",
			"cliterm.ReadHistorySeed(historyFile)",
			"cliterm.SeedHistory(",
			"cliterm.RecordHistoryLine(",
		)
		if strings.Contains(src, "DisableReadlineHistoryAutoSave") {
			t.Errorf("%s still uses DisableReadlineHistoryAutoSave", path)
		}
		if strings.Contains(src, "HistoryFile:") && strings.Contains(src, "ConfigureReadlineHistory") {
			// HistoryFile must not be passed alongside the filtered wiring;
			// ConfigureReadlineHistory clears it, but a literal at the call
			// site means a future edit could bypass the clear unnoticed.
			t.Errorf("%s passes HistoryFile at the readline call site", path)
		}
	}
}
