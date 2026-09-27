package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestInputBarrierCommand10751(t *testing.T) {
	if got := classifyCommand([]string{"xpfd", "input-barrier"}); got != cmdInputBarrier {
		t.Fatalf("classifyCommand input-barrier = %d, want %d", got, cmdInputBarrier)
	}
	for _, args := range [][]string{{}, {"open"}, {"close", "extra"}, {"remove", "extra"}} {
		if err := parseInputBarrierArgs(args); err == nil {
			t.Errorf("parseInputBarrierArgs(%q) unexpectedly succeeded", args)
		}
	}
	for _, args := range [][]string{{"close"}, {"remove"}} {
		if err := parseInputBarrierArgs(args); err != nil {
			t.Errorf("parseInputBarrierArgs(%q): %v", args, err)
		}
	}
}

func TestInputBarrierCommandReportsInstallAndRemoveResults10751(t *testing.T) {
	oldInstall, oldRemove := earlyInputBarrierInstall, earlyInputBarrierRemove
	t.Cleanup(func() {
		earlyInputBarrierInstall, earlyInputBarrierRemove = oldInstall, oldRemove
	})

	var stdout, stderr bytes.Buffer
	var installs, removes int
	earlyInputBarrierInstall = func() error { installs++; return nil }
	earlyInputBarrierRemove = func() error { removes++; return nil }
	if code := runInputBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != 0 {
		t.Fatalf("successful install exit code = %d (stderr=%q)", code, stderr.String())
	}
	if installs != 1 || !strings.Contains(stdout.String(), "early input barrier installed") || stderr.Len() != 0 {
		t.Fatalf("successful install: calls=%d stdout=%q stderr=%q", installs, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	installErr := errors.New("nftables permission denied")
	earlyInputBarrierInstall = func() error { installs++; return installErr }
	if code := runInputBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed install exit code = %d, want 1", code)
	}
	if installs != 2 || !strings.Contains(stderr.String(), installErr.Error()) || stdout.Len() != 0 {
		t.Fatalf("failed install: calls=%d stdout=%q stderr=%q", installs, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runInputBarrierSubcommand([]string{"remove"}, &stdout, &stderr); code != 0 {
		t.Fatalf("successful remove exit code = %d (stderr=%q)", code, stderr.String())
	}
	if removes != 1 || !strings.Contains(stdout.String(), "early input barrier removed") || stderr.Len() != 0 {
		t.Fatalf("successful remove: calls=%d stdout=%q stderr=%q", removes, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	removeErr := errors.New("nftables delete denied")
	earlyInputBarrierRemove = func() error { removes++; return removeErr }
	if code := runInputBarrierSubcommand([]string{"remove"}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed remove exit code = %d, want 1", code)
	}
	if removes != 2 || !strings.Contains(stderr.String(), removeErr.Error()) || stdout.Len() != 0 {
		t.Fatalf("failed remove: calls=%d stdout=%q stderr=%q", removes, stdout.String(), stderr.String())
	}
}
