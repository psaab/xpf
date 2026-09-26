package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestReportCleanupFRRResult10907(t *testing.T) {
	clearErr := errors.New("FRR reload failed")
	for _, tt := range []struct {
		name       string
		clearErr   error
		wantStdout string
		wantStderr string
	}{
		{
			name:       "clear failure",
			clearErr:   clearErr,
			wantStdout: "all pinned BPF state removed; FRR managed routes may remain active until the next xpfd start reapplies FRR\n",
			wantStderr: "cleanup: FRR managed-section clear: FRR reload failed\n" +
				"  frr.conf was rewritten without the managed section, but the running\n" +
				"  FRR config may retain it until the next xpfd start reapplies FRR.\n",
		},
		{
			name:       "clear success",
			wantStdout: "all pinned BPF state and managed routes removed\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			reportCleanupFRRResult(&stdout, &stderr, tt.clearErr)
			if got := stdout.String(); got != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", got, tt.wantStdout)
			}
			if got := stderr.String(); got != tt.wantStderr {
				t.Errorf("stderr = %q, want %q", got, tt.wantStderr)
			}
		})
	}
}
