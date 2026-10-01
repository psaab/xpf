package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func unknownThenActionTree11357(t *testing.T, then string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set firewall family inet filter f term t from source-address 10.0.0.0/8",
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t then " + then,
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set path %q: %v", cmd, err)
		}
	}
	return tree
}

func TestUnknownFilterThenActionFailsClosedInSnapshot11357(t *testing.T) {
	for _, tc := range []struct {
		then  string
		token string
	}{
		{then: "next-ip 1.2.3.4", token: "next-ip"},
		{then: "next-interface ge-0/0/0", token: "next-interface"},
		{then: "frobnicate", token: "frobnicate"},
	} {
		t.Run(tc.token, func(t *testing.T) {
			cfg, err := config.CompileConfigLenient(unknownThenActionTree11357(t, tc.then))
			if err != nil {
				t.Fatalf("lenient compile must remain bootable: %v", err)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), tc.token) {
				t.Fatalf("lenient compile must retain an operator-visible warning for %q: %v", tc.token, cfg.Warnings)
			}
			filter := cfg.Firewall.FiltersInet["f"]
			if filter == nil || len(filter.Terms) != 1 {
				t.Fatalf("expected compiled filter f with one term, got %+v", filter)
			}
			if got := filter.Terms[0].Action; got != "discard" {
				t.Fatalf("unknown then action compiled as %q, want fail-closed discard", got)
			}

			snapshots := buildFirewallFilterSnapshots(cfg)
			if len(snapshots) != 1 || len(snapshots[0].Terms) != 1 {
				t.Fatalf("expected one filter snapshot term, got %+v", snapshots)
			}
			snap := snapshots[0].Terms[0]
			if snap.Action != "discard" || snap.NextTerm {
				t.Fatalf("unknown action must snapshot as terminating discard, got action=%q next_term=%t", snap.Action, snap.NextTerm)
			}
			if len(snap.SourceAddresses) != 1 || snap.SourceAddresses[0] != "10.0.0.0/8" || len(snap.Protocols) != 1 || snap.Protocols[0] != "tcp" {
				t.Fatalf("known match constraints must be preserved with the fail-closed action, got %+v", snap)
			}
		})
	}
}

func TestUnknownFilterThenActionDoesNotChangeModifierFallThrough11357(t *testing.T) {
	tree := unknownThenActionTree11357(t, "count c1")
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("modifier-only term must remain loadable: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	if term.Action != "" || len(term.UnknownActions) != 0 {
		t.Fatalf("valid modifier-only term changed unexpectedly: %+v", term)
	}
	snap := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if !snap.NextTerm {
		t.Fatalf("valid modifier-only term must still fall through: %+v", snap)
	}
}
