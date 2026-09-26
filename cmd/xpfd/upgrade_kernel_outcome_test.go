package main

import (
	"testing"

	"github.com/psaab/xpf/pkg/upgrade"
)

func TestKernelPromoteMessageReportsActualOutcome(t *testing.T) {
	tests := []struct {
		name    string
		outcome upgrade.KernelRollOutcome
		want    string
	}{
		{
			name:    "promoted",
			outcome: upgrade.KernelRollOutcome{Outcome: upgrade.RollOutcomePromoted},
			want:    "kernel candidate promoted",
		},
		{
			name: "discarded on known-good",
			outcome: upgrade.KernelRollOutcome{
				Outcome: upgrade.RollOutcomeDiscarded,
				Reason:  "BootCurrent=0003 != candidate slot 0004 — already on known-good, no reboot",
			},
			want: "kernel candidate discarded (already on known-good): " +
				"BootCurrent=0003 != candidate slot 0004 — already on known-good, no reboot",
		},
		{
			name: "ordinary no-op boot",
			want: "no armed kernel candidate; nothing to promote",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kernelPromoteMessage(tt.outcome); got != tt.want {
				t.Fatalf("kernelPromoteMessage(%+v) = %q, want %q", tt.outcome, got, tt.want)
			}
		})
	}
}
