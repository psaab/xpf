package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryUpgradeStatusCommandReportsStagedRunningSkew12143(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	data := "format=1\n" +
		"staged_version=v2\n" +
		"running_version=v1\n" +
		"reason=cut-failed\n" +
		"recovery=xpfd upgrade\n" +
		"recorded_at=2026-10-08T12:00:00Z\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := runBinaryUpgradeStatusSubcommand(&output, nil, path); err != nil {
		t.Fatalf("runBinaryUpgradeStatusSubcommand: %v", err)
	}
	for _, want := range []string{
		"Pending:        yes — staged v2, running v1",
		"Failure:        cut-failed",
		"Recovery:       xpfd upgrade",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("upgrade status output missing %q:\n%s", want, output.String())
		}
	}
}

func TestBinaryUpgradeStatusCommandRejectsOperands12143(t *testing.T) {
	if err := runBinaryUpgradeStatusSubcommand(&bytes.Buffer{}, []string{"extra"}, ""); err == nil {
		t.Fatal("status accepted an unexpected operand")
	}
}

func TestUpgradeStatusProductionDispatch12143(t *testing.T) {
	const childEnv = "XPF_TEST_UPGRADE_STATUS_DISPATCH"
	const pathEnv = "XPF_TEST_UPGRADE_STATUS_PATH"
	if os.Getenv(childEnv) == "1" {
		binaryUpgradeStatusPath = os.Getenv(pathEnv)
		runUpgradeSubcommand([]string{"status"})
		return
	}

	path := filepath.Join(t.TempDir(), "upgrade-deferred")
	if err := os.WriteFile(path, []byte(
		"format=1\n"+
			"staged_version=v2\n"+
			"running_version=v1\n"+
			"reason=cut-failed\n"+
			"recovery=xpfd upgrade\n"+
			"recorded_at=2026-10-08T12:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestUpgradeStatusProductionDispatch12143$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", pathEnv+"="+path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production `xpfd upgrade status` dispatch failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "Pending:        yes — staged v2, running v1") {
		t.Fatalf("production status dispatch did not render the record:\n%s", output)
	}
}
