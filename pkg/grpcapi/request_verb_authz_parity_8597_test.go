package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 K47. The two `request` verbs added for remote parity must be priced the
// way pkg/cli prices them, or the parity fix creates a NEW divergence: a verb
// the console runs at one tier and the remote surface at another.
//
// pkg/cli charges the `request` family's PermControl for both. Neither is in
// requestSubcommandIsMaintenance's destructive set (`request system
// {reboot,halt,power-off,zeroize}` and `request chassis cluster failover ...`,
// plus `request system software in-service-upgrade`), so neither elevates.
//
// THIS IS ONE HALF OF AN AGREEMENT, NOT THE AGREEMENT. pkg/grpcapi cannot
// import pkg/cli (pkg/cli imports pkg/grpcapi), and the CLI's permission
// resolver is unexported, so the two tiers cannot be compared in one process
// without a new export. The other half is
// TestRequestVerbTiersMatchTheRemoteSurface_8597 in pkg/cli, which pins the
// console side of the same three commands. Either half going red means the two
// surfaces have parted; each names the other.

func TestPoliciesCheckTopicCostsWhatTheConsoleCharges_8597(t *testing.T) {
	perm, mapped := showTextTopicPermission("policies-check")
	if !mapped {
		t.Fatal("the policies-check topic is unmapped, so it falls to the " +
			"unmapped default rather than being priced deliberately")
	}
	if perm != config.PermControl {
		t.Errorf("policies-check costs %v, want %v — `request security policies "+
			"check` is a plain `request` verb on the console, so pricing it at the "+
			"view tier makes the remote surface LOOSER and pricing it higher makes "+
			"it STRICTER (#8597 K47)", perm, config.PermControl)
	}
	// The contrast that makes the number meaningful: a `show` topic really is
	// view-tier, so this is not "everything is PermControl".
	if p, _ := showTextTopicPermission("policies-detail"); p == config.PermControl {
		t.Errorf("the neighbouring `show security policies detail` topic also costs " +
			"PermControl, so the assertion above distinguishes nothing")
	}
}

func TestRescueVerbsCostWhatTheConsoleCharges_8597(t *testing.T) {
	for _, verb := range []string{"rescue-save", "rescue-delete"} {
		if _, listed := systemActionPermissions[verb]; !listed {
			t.Errorf("%s is absent from systemActionPermissions, so it falls to the "+
				"PermMaint default — STRICTER than the console, which charges the "+
				"`request` family's PermControl. An absent entry is the same parity "+
				"defect this row is about, in the other direction (#8597 K47)", verb)
			continue
		}
		if got := systemActionPermission(verb); got != config.PermControl {
			t.Errorf("%s costs %v, want %v (#8597 K47)", verb, got, config.PermControl)
		}
	}
	// The contrast: a destructive verb is still PermMaint.
	if got := systemActionPermission("zeroize"); got == config.PermControl {
		t.Error("zeroize costs PermControl, so the assertions above distinguish nothing")
	}
}

// The canonical command strings are what the #7172 deny-commands gate matches
// against. A wrong one silently prices the verb under a command the operator
// never typed.
func TestTheNewVerbsCanonicalCommands_8597(t *testing.T) {
	if got := showTextTopicCommand["policies-check"]; got != "request security policies check" {
		t.Errorf("policies-check maps to %q, want %q", got, "request security policies check")
	}
	for verb, want := range map[string]string{
		"rescue-save":   "request system configuration rescue save",
		"rescue-delete": "request system configuration rescue delete",
	} {
		if got := systemActionVerbCommand[verb]; got != want {
			t.Errorf("%s maps to %q, want %q", verb, got, want)
		}
	}
}

func TestDynamicAddressShrinkAcknowledgementCostsConfigure(t *testing.T) {
	const verb = "dynamic-address-shrink-ack"
	if got := systemActionPermission(verb); got != config.PermConfig {
		t.Fatalf("%s costs %v, want %v", verb, got, config.PermConfig)
	}
	const want = "request security dynamic-address acknowledge-shrink"
	if got := systemActionVerbCommand[verb]; got != want {
		t.Fatalf("%s maps to %q, want %q", verb, got, want)
	}
}
