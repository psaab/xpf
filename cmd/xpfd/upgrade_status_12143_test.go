package main

import (
	"bytes"
	"os"
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
