package main

import (
	"testing"

	"github.com/psaab/xpf/pkg/cliterm"
)

// #15775 remote: `fence-status` is a leaf of `show chassis cluster`
// itself (handled in handleShow before the subsystem dispatch), unknown
// cluster subsystems / trailing tokens must error (not fall through to
// `show chassis cluster`), and extra tokens after leaf views must error.
// The subsystem grammar lives in cliterm (#17225).

func TestClusterSubsystemViewFenceStatus15775(t *testing.T) {
	// fence-status is not a subsystem: the shared view rejects it, and
	// handleShow's dedicated leaf arm (arity-checked there) owns it.
	if _, _, err := cliterm.ClusterSubsystemView("fence-status", nil); err == nil {
		t.Error("fence-status as subsystem: expected error")
	}
	if _, _, err := cliterm.ClusterSubsystemView("fence-status", []string{"extra"}); err == nil {
		t.Error("fence-status with trailing token: expected error")
	}
	if _, _, err := cliterm.ClusterSubsystemView("bogus", nil); err == nil {
		t.Error("unknown subsystem: expected error")
	}
}
