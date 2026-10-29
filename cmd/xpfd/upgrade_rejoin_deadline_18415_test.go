package main

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/upgrade"
)

func TestUpgradeRejoinDeadlineDefaultAndOverride18415(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "rolling upgrade", args: []string{"--rolling"}},
		{name: "rolling rollback", args: []string{"--rollback", "--rolling"}},
	}
	for _, tc := range cases {
		t.Run(tc.name+" default", func(t *testing.T) {
			flags, err := parseUpgradeArgs(tc.args)
			if err != nil {
				t.Fatalf("parse default args: %v", err)
			}
			if flags.rejoinDeadline != upgrade.DefaultRejoinDeadline {
				t.Fatalf("CLI default rejoin deadline = %s, want %s", flags.rejoinDeadline, upgrade.DefaultRejoinDeadline)
			}
			if got := newUpgradeConfig(flags).RejoinDeadline; got != upgrade.DefaultRejoinDeadline {
				t.Fatalf("runner config rejoin deadline = %s, want %s", got, upgrade.DefaultRejoinDeadline)
			}
		})

		t.Run(tc.name+" override", func(t *testing.T) {
			args := append(append([]string(nil), tc.args...), "--rejoin-deadline=45s")
			flags, err := parseUpgradeArgs(args)
			if err != nil {
				t.Fatalf("parse override args: %v", err)
			}
			const want = 45 * time.Second
			if flags.rejoinDeadline != want {
				t.Fatalf("CLI rejoin deadline = %s, want %s", flags.rejoinDeadline, want)
			}
			if got := newUpgradeConfig(flags).RejoinDeadline; got != want {
				t.Fatalf("runner config rejoin deadline = %s, want %s", got, want)
			}
		})
	}
}
