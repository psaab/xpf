package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestTransitBarrierCommand9852 pins the boot subcommand's routing and its
// narrow argument contract. Reverting the top-level registration or changing
// the required `close` operand makes this fail before any daemon/config path
// can accidentally run.
func TestTransitBarrierCommand9852(t *testing.T) {
	if got := classifyCommand([]string{"xpfd", "transit-barrier"}); got != cmdTransitBarrier {
		t.Fatalf("classifyCommand transit-barrier = %d, want %d", got, cmdTransitBarrier)
	}
	for _, args := range [][]string{{}, {"open"}, {"close", "extra"}, {"remove", "extra"}, {"--close"}} {
		if err := parseTransitBarrierArgs(args); err == nil {
			t.Errorf("parseTransitBarrierArgs(%q) unexpectedly succeeded", args)
		}
	}
	for _, args := range [][]string{{"close"}, {"remove"}} {
		if err := parseTransitBarrierArgs(args); err != nil {
			t.Errorf("parseTransitBarrierArgs(%q): %v", args, err)
		}
	}
}

func TestTransitBarrierRemoveCommand10733(t *testing.T) {
	orig := transitBarrierRemove
	t.Cleanup(func() { transitBarrierRemove = orig })

	var stdout, stderr bytes.Buffer
	calls := 0
	transitBarrierRemove = func() error {
		calls++
		return nil
	}
	if code := runTransitBarrierSubcommand([]string{"remove"}, &stdout, &stderr); code != 0 {
		t.Fatalf("successful barrier removal exit code = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if calls != 1 || !strings.Contains(stdout.String(), "transit barrier removed") || stderr.Len() != 0 {
		t.Fatalf("successful barrier removal: calls=%d stdout=%q stderr=%q", calls, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	calls = 0
	injected := errors.New("netlink permission denied")
	transitBarrierRemove = func() error {
		calls++
		return injected
	}
	if code := runTransitBarrierSubcommand([]string{"remove"}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed barrier removal exit code = %d, want 1", code)
	}
	if calls != 1 || !strings.Contains(stderr.String(), injected.Error()) || stdout.Len() != 0 {
		t.Fatalf("failed barrier removal: calls=%d stdout=%q stderr=%q", calls, stdout.String(), stderr.String())
	}
}

// TestTransitBarrierCommandInstallAndFailure9852 is the fail-on-revert proof
// for the side-effect boundary. The success cell proves exactly one installer
// call and a useful journal line; the failure cell proves an install error is
// returned to systemd as exit status 1 rather than swallowed (which would let
// networkd start without the bridge barrier).
func TestTransitBarrierCommandInstallAndFailure9852(t *testing.T) {
	orig := transitBarrierInstall
	t.Cleanup(func() { transitBarrierInstall = orig })

	var stdout, stderr bytes.Buffer
	calls := 0
	transitBarrierInstall = func() error {
		calls++
		return nil
	}
	if code := runTransitBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != 0 {
		t.Fatalf("successful barrier install exit code = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("successful barrier install calls = %d, want exactly 1", calls)
	}
	if !strings.Contains(stdout.String(), "inet + bridge") {
		t.Fatalf("success output does not identify both barrier families: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful barrier install wrote stderr: %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	calls = 0
	injected := errors.New("bridge netlink permission denied")
	transitBarrierInstall = func() error {
		calls++
		return injected
	}
	if code := runTransitBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed barrier install exit code = %d, want 1", code)
	}
	if calls != 1 {
		t.Fatalf("failed barrier install calls = %d, want exactly 1", calls)
	}
	if !strings.Contains(stderr.String(), injected.Error()) {
		t.Fatalf("failure output does not preserve install error: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("failed barrier install wrote success output: %q", stdout.String())
	}
}

// TestTransitBarrierBridgeFailureClassification9852 pins the bridge-family
// degradation boundary. A kernel without bridge nf_tables support still gets
// the inet barrier and must let networkd proceed with a warning; a real bridge
// error or any inet error remains fatal.
func TestTransitBarrierBridgeFailureClassification9852(t *testing.T) {
	orig := transitBarrierInstall
	t.Cleanup(func() { transitBarrierInstall = orig })

	tests := []struct {
		name       string
		err        error
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "bridge family unsupported degrades",
			err:        fmt.Errorf("%w: simulated EOPNOTSUPP", xnft.ErrTransitBarrierBridgeUnsupported),
			wantCode:   0,
			wantStdout: "bridge family unavailable",
			wantStderr: "degraded",
		},
		{
			name:       "bridge real failure is fatal",
			err:        errors.New("bridge netlink permission denied"),
			wantCode:   1,
			wantStderr: "bridge netlink permission denied",
		},
		{
			name: "inet failure with bridge unsupported is fatal",
			err: errors.Join(
				errors.New("inet netlink permission denied"),
				fmt.Errorf("%w: simulated EOPNOTSUPP", xnft.ErrTransitBarrierBridgeUnsupported),
			),
			wantCode:   1,
			wantStderr: "inet netlink permission denied",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			transitBarrierInstall = func() error { return test.err }
			if code := runTransitBarrierSubcommand([]string{"close"}, &stdout, &stderr); code != test.wantCode {
				t.Fatalf("exit code = %d, want %d (stdout=%q stderr=%q)", code, test.wantCode, stdout.String(), stderr.String())
			}
			if test.wantStdout != "" {
				if !strings.Contains(stdout.String(), test.wantStdout) {
					t.Fatalf("stdout = %q, want substring %q", stdout.String(), test.wantStdout)
				}
			} else if stdout.Len() != 0 {
				t.Fatalf("fatal install wrote success output: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), test.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), test.wantStderr)
			}
		})
	}
}
