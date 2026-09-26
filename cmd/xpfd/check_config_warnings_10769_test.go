package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCheckConfigMain10769(t *testing.T, config string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "day0.conf")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalArgs, originalStdout, originalStderr := os.Args, os.Stdout, os.Stderr
	t.Cleanup(func() {
		os.Args, os.Stdout, os.Stderr = originalArgs, originalStdout, originalStderr
	})
	os.Args = []string{"xpfd", "check-config", "-node-id", "0", path}
	os.Stdout, os.Stderr = stdoutW, stderrW
	main()
	_ = stdoutW.Close()
	_ = stderrW.Close()
	os.Stdout, os.Stderr = originalStdout, originalStderr
	stdout, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatal(err)
	}
	return string(stdout), string(stderr)
}

func TestCheckConfigPrintsCompilerWarnings10769(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "examples", "deploy", "ha-pair.conf"))
	if err != nil {
		t.Fatal(err)
	}
	stdout, _ := runCheckConfigMain10769(t, string(content))
	if !strings.Contains(stdout, "PASS ") {
		t.Fatalf("accepted config has no PASS result:\n%s", stdout)
	}
	for _, warning := range []string{
		"warning: chassis cluster authentication-key matches a published placeholder",
		"warning: chassis cluster is configured but `system ntp server` is empty",
		"warning: chassis cluster fabric zone stamp",
	} {
		if !strings.Contains(stdout, warning) {
			t.Errorf("check-config output omitted advisory %q:\n%s", warning, stdout)
		}
	}
}
