package main

import (
	"strings"
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

// #18415 review fold: --rejoin-deadline is validated at parse time, before
// NewRunner and so long before ForceSecondary. The deadline is consulted only
// AFTER the irreversible cut, so a value that guarantees a timeout must never
// get that far.
func TestUpgradeRejoinDeadlineValidation18415(t *testing.T) {
	accept := []struct {
		args []string
		want time.Duration
	}{
		{[]string{"--rolling"}, upgrade.DefaultRejoinDeadline},
		{[]string{"--rolling", "--rejoin-deadline=0"}, upgrade.DefaultRejoinDeadline},
		{[]string{"--rollback", "--rolling", "--rejoin-deadline=0s"}, upgrade.DefaultRejoinDeadline},
		{[]string{"--rolling", "--rejoin-deadline=" + upgrade.MinRejoinDeadline.String()}, upgrade.MinRejoinDeadline},
		{[]string{"--rolling", "--rejoin-deadline=10m"}, 10 * time.Minute},
		// Omitted on a standalone cut: nothing to validate.
		{nil, upgrade.DefaultRejoinDeadline},
		{[]string{"--rollback"}, upgrade.DefaultRejoinDeadline},
	}
	for _, tc := range accept {
		flags, err := parseUpgradeArgs(tc.args)
		if err != nil {
			t.Errorf("parseUpgradeArgs(%v) = %v; want accepted", tc.args, err)
			continue
		}
		if flags.rejoinDeadline != tc.want {
			t.Errorf("parseUpgradeArgs(%v) rejoin deadline = %s, want %s", tc.args, flags.rejoinDeadline, tc.want)
		}
	}

	refuse := []struct {
		args []string
		want string
	}{
		{[]string{"--rejoin-deadline=45s"}, "only valid with --rolling"},
		{[]string{"--rollback", "--rejoin-deadline=45s"}, "only valid with --rolling"},
		// Even the default value, spelled out, is refused without --rolling:
		// the operator expected a bound that a standalone cut never applies.
		{[]string{"--rejoin-deadline=" + upgrade.DefaultRejoinDeadline.String()}, "only valid with --rolling"},
		{[]string{"--rolling", "--rejoin-deadline=-5s"}, "is negative"},
		{[]string{"--rolling", "--rejoin-deadline=1ns"}, "below the " + upgrade.MinRejoinDeadline.String() + " minimum"},
		{[]string{"--rollback", "--rolling", "--rejoin-deadline=29s"}, "below the " + upgrade.MinRejoinDeadline.String() + " minimum"},
	}
	for _, tc := range refuse {
		_, err := parseUpgradeArgs(tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parseUpgradeArgs(%v) = %v; want an error containing %q", tc.args, err, tc.want)
		}
	}
}
