package sysinfo

import (
	"strings"
	"testing"
)

func TestWriteProcessesSummaryUsesPSOutput(t *testing.T) {
	var got strings.Builder
	WriteProcessesSummary(&got, []byte("PID USER PRI NI VSZ RSS STAT TIME %CPU COMMAND\n42 root 20 0 2048 1024 R 00:01 12.5 fixture\n"))
	for _, want := range []string{
		"load averages:",
		" processes:",
		"CPU:",
		"Mem:",
		"Swap:",
		"  PID USERNAME",
		"42 root",
		"fixture",
	} {
		if !strings.Contains(got.String(), want) {
			t.Errorf("summary output missing %q:\n%s", want, got.String())
		}
	}
}
