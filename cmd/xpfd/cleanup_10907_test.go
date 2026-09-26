package main

import (
	"errors"
	"testing"
)

func TestCleanupSummaryFRRClearFailure10907(t *testing.T) {
	got := cleanupSummary(errors.New("FRR reload failed"))
	want := "all pinned BPF state removed; FRR managed routes may remain active until the next xpfd start reapplies FRR"
	if got != want {
		t.Fatalf("cleanupSummary(FRR clear failure) = %q, want %q", got, want)
	}
}

func TestCleanupSummaryFRRClearSuccess10907(t *testing.T) {
	got := cleanupSummary(nil)
	want := "all pinned BPF state and managed routes removed"
	if got != want {
		t.Fatalf("cleanupSummary(nil) = %q, want %q", got, want)
	}
}
