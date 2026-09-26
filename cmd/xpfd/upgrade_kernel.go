package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/upgrade/lock"
)

// runUpgradeKernelSubcommand implements `xpfd upgrade kernel ...` — the LANE-1
// verify-gated in-place kernel channel (#1930 INC-1). Sub-verbs:
//
//	xpfd upgrade kernel arm <version>   — preflight + install the candidate +
//	    arm the one-shot A/B slot boot + reboot. On success the host reboots
//	    into the candidate (this command does not return).
//	xpfd upgrade kernel promote         — the candidate-boot promotion gate,
//	    invoked by the promotion oneshot systemd unit. PASS -> promote (durable
//	    BootOrder reorder), FAIL -> revert (exit 3 so the oneshot reboots to the
//	    known-good slot).
//	xpfd upgrade kernel status          — print the kernel-channel journal state.
//
// Exit codes: 0 success/clean, 1 error, 2 channel-unavailable (use LANE 2),
// 3 candidate REVERTED (promote path — the oneshot reboots to known-good).
func runUpgradeKernelSubcommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: xpfd upgrade kernel {arm <version>|promote|status|drain|rejoin} [flags]")
		os.Exit(1)
	}
	verb := args[0]
	fs := flag.NewFlagSet("upgrade kernel "+verb, flag.ContinueOnError)
	// REFUSED for `arm` since #6631; diagnostic-only for the other kernel verbs.
	// The boot-time promotion gate is a systemd oneshot with a hardcoded
	// ExecStart and no way to be told a journal path, so it always reads the
	// compiled-in default — as does the arm-record sidecar beside it. A
	// candidate armed against a non-default journal is therefore structurally
	// unpromotable: it boots, runs unverified, and the next reboot reverts it,
	// with the gate logging an ordinary boot.
	//
	// upgrade.KernelRunner.Arm now REFUSES that rather than accepting it
	// (ErrKernelJournalUnpromotable), so the failure lands in the operator's
	// terminal at the moment they ask instead of as a silent non-promotion one
	// reboot later. The flag stays defined here because the read-only verbs
	// (status) and the crash-recovery verbs legitimately take one, and because
	// removing it would break the diagnostic use the tests rely on.
	journalPath := fs.String("journal", upgrade.DefaultKernelJournalPath,
		"crash-safe kernel-channel journal path (`arm` REFUSES a non-default "+
			"value: the boot-time promotion gate always reads "+
			upgrade.DefaultKernelJournalPath+", so a candidate armed against a "+
			"different journal could never be verified or promoted)")
	strictWatchdog := fs.Bool("strict-watchdog", false,
		"Path-D1: refuse to arm unless a verified-persistent watchdog is present "+
			"(default Path-D2: BootNext still closes the boot-loop; an early hang "+
			"needs one external reset)")
	beaconDeadline := fs.Duration("beacon-deadline", 20*time.Second,
		"forward-health-beacon deadline on the candidate boot (promote)")
	drainDeadline := fs.Duration("drain-deadline", 30*time.Second,
		"deadline for the STRONG drain predicate (drain) / rejoin confirm (rejoin)")
	allowMixedHA := fs.Bool("allow-mixed-ha", false,
		"relax the drain HA-protocol-compatible precheck (the LANE-2 image-roll "+
			"mixed-base gate already validated window-compat; the exact-equality "+
			"check would otherwise abort a legitimate in-window mixed-base roll)")
	unit := fs.String("unit", "xpfd", "systemd unit (cluster gRPC target)")
	if err := fs.Parse(args[1:]); err != nil {
		os.Exit(1)
	}

	// #5322: reject leftover positional operands per verb BEFORE taking the
	// upgrade lock or building the runner. Like #4869's `xpfd upgrade`,
	// flag.FlagSet.Parse stops at the first non-flag token, so before this
	// guard a stray operand on a no-arg verb (e.g. `xpfd upgrade kernel promote
	// g0-typo`, or `drain`/`rejoin` with a fat-fingered extra) was silently
	// dropped and the privileged BootOrder-reorder / drain still ran. `arm`
	// legitimately takes exactly one operand (the target kernel version);
	// promote/status/drain/rejoin take none.
	if err := validateKernelVerbArgs(verb, fs.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Serialize the MUTATING kernel sub-verbs (arm/promote/drain/rejoin)
	// against every other host-local upgrade mutator via the host-wide
	// upgrade lock (#1965). `status` is read-only and stays lock-free.
	// Release on every return path; note that `arm` reboots on success and
	// does not return — the reboot clears /run tmpfs so the lock is gone
	// either way.
	switch verb {
	case "arm", "promote", "drain", "rejoin":
		target := ""
		if verb == "arm" && len(fs.Args()) == 1 {
			target = fs.Args()[0]
		}
		h, lerr := lock.Acquire("upgrade kernel "+verb, target)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel %s: %v\n", verb, lerr)
			os.Exit(1)
		}
		defer func() { _ = h.Release() }()
	}

	cfg := newKernelConfig(*journalPath, *strictWatchdog, *beaconDeadline)
	r, err := upgrade.NewKernelRunner(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upgrade kernel: %v\n", err)
		os.Exit(1)
	}

	switch verb {
	case "arm":
		// Arity validated up-front by validateKernelVerbArgs (exactly one
		// operand: the target kernel version).
		if err := r.Arm(fs.Args()[0]); err != nil {
			if errors.Is(err, upgrade.ErrKernelChannelUnavailable) {
				fmt.Fprintf(os.Stderr, "upgrade kernel arm: %v\n", err)
				os.Exit(2)
			}
			fmt.Fprintf(os.Stderr, "upgrade kernel arm: %v\n", err)
			os.Exit(1)
		}
		// Arm() reboots on success and does not return; reaching here means a
		// test/no-op reboot surface — report and exit 0.
		fmt.Println("kernel candidate armed; reboot pending")

	case "promote":
		outcome, err := r.Promote()
		if err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel promote: %v\n", err)
			// A REVERT is the expected "candidate failed the gate" outcome:
			// exit 3 so the promotion oneshot reboots to the known-good slot.
			// Any OTHER error (journal/firmware/BootOrder-write failure) is a
			// genuine infra error: exit 1 (the oneshot must NOT treat it as a
			// clean revert) — r1 Codex High.
			if errors.Is(err, upgrade.ErrKernelReverted) {
				os.Exit(3)
			}
			os.Exit(1)
		}
		fmt.Println(kernelPromoteMessage(outcome))

	case "status":
		// Report the durable promotion marker too — the external HA orchestrator
		// (INC-2) polls this post-reboot to confirm "this node promoted version
		// X" (the journal is cleared on promote, so the marker is the durable
		// signal). Machine-parseable: "promoted=<uname>" / "promoted=none".
		promoted, perr := cfg.Sys.ReadPromotionMarker()
		if perr != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel status: read promotion marker: %v\n", perr)
			os.Exit(1)
		}
		if promoted == "" {
			fmt.Println("promoted=none")
		} else {
			fmt.Printf("promoted=%s\n", promoted)
		}
		armed, j, err := r.IsArmed()
		if err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel status: %v\n", err)
			os.Exit(1)
		}
		if !armed {
			fmt.Println("armed=none")
			return
		}
		fmt.Printf("armed=true candidate=%s known-good=%s active-slot=%s inactive-slot=%s state=%s\n",
			j.CandidateVersion, j.KnownGoodVersion, j.ActiveSlot, j.InactiveSlot, j.State)

	case "drain":
		// Non-interactive drain for the external HA roll (r1 Codex Critical:
		// `cli -c 'request system ... in-service-upgrade'` cannot confirm in a
		// non-TTY, and the cli path needs interactive confirmation). This drives
		// the SAME automation path #1917 rolling uses (ForceSecondary via the
		// gRPC SystemAction) and CONFIRMS the STRONG drain predicate (peer holds
		// the RGs + sync clean) before reporting success — so the orchestrator
		// never arms+reboots an undrained primary.
		cl, err := upgrade.NewCLICluster(*unit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel drain: %v\n", err)
			os.Exit(1)
		}
		if err := upgrade.DrainAndConfirm(cl, *drainDeadline, *allowMixedHA); err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel drain: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("drained (peer holds all RGs, sync clean)")

	case "rejoin":
		// Non-interactive rejoin: clear manual failover on all RGs and confirm
		// the node is back as an eligible cluster member with sync re-established
		// (so the orchestrator never advances to the peer until this node is
		// fully rejoined — r1 Codex Critical "never both down").
		cl, err := upgrade.NewCLICluster(*unit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel rejoin: %v\n", err)
			os.Exit(1)
		}
		if err := upgrade.RejoinAndConfirm(cl, *drainDeadline); err != nil {
			fmt.Fprintf(os.Stderr, "upgrade kernel rejoin: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("rejoined (manual failover cleared, sync re-established)")

	default:
		fmt.Fprintf(os.Stderr, "upgrade kernel: unknown verb %q (want arm|promote|status|drain|rejoin)\n", verb)
		os.Exit(1)
	}
}

// kernelPromoteMessage keeps the success output tied to the gate's actual
// result. A nil Promote error also covers an ordinary no-op boot and a
// known-good cleanup; neither means the candidate was promoted.
func kernelPromoteMessage(outcome upgrade.KernelRollOutcome) string {
	switch outcome.Outcome {
	case upgrade.RollOutcomePromoted:
		return "kernel candidate promoted"
	case upgrade.RollOutcomeDiscarded:
		if outcome.Reason == "" {
			return "kernel candidate discarded (already on known-good)"
		}
		return fmt.Sprintf("kernel candidate discarded (already on known-good): %s", outcome.Reason)
	case "":
		return "no armed kernel candidate; nothing to promote"
	default:
		return fmt.Sprintf("kernel promotion completed with outcome %q", outcome.Outcome)
	}
}

// validateKernelVerbArgs enforces the per-verb positional arity for `xpfd
// upgrade kernel <verb>` (#5322). `arm` takes exactly one operand (the target
// kernel version); promote/status/drain/rejoin take none. An unknown verb is
// left to the dispatch's own default case (returns nil here), so its existing
// "unknown verb" error is preserved. Extracted so the leftover-arg rejection is
// unit-testable without the os.Exit / lock / real-runner side effects.
func validateKernelVerbArgs(verb string, positionals []string) error {
	switch verb {
	case "arm":
		if len(positionals) != 1 {
			return fmt.Errorf("usage: xpfd upgrade kernel arm <version>")
		}
	case "promote", "status", "drain", "rejoin":
		if len(positionals) != 0 {
			return fmt.Errorf("upgrade kernel %s: unexpected argument(s) %v; "+
				"this verb takes no positional arguments", verb, positionals)
		}
	}
	return nil
}

// newKernelConfig assembles the production KernelConfig for the kernel
// promote/rollback channel.
//
// Factored out of the verb function so the WIRING is bindable (#6607): the Gate
// 4 dataplane probe is the whole point of that change, and a test that only
// exercised realKernelSystem.ForwardBeacon directly would stay green if this
// site were reverted to upgrade.NewKernelSystem(). It mirrors newUpgradeConfig,
// which the binary channel factored out for exactly the same reason (#5286).
func newKernelConfig(journalPath string, strictWatchdog bool, beaconDeadline time.Duration) upgrade.KernelConfig {
	return upgrade.KernelConfig{
		JournalPath:    journalPath,
		StrictWatchdog: strictWatchdog,
		BeaconDeadline: beaconDeadline,
		// #6607: wire Gate 4's dataplane-liveness probe. Without it the beacon
		// can only assert that xpfd is up, which a Type=simple unit reports
		// while its helper is down, stale or crash-looping and NOT forwarding —
		// the exact state a kernel change is most likely to cause and the one
		// Gate 4 exists to catch.
		//
		// Routed through the same package-level seams the binary channel uses
		// (upgradeHelperStatus / upgradeControlSock) so there is ONE adapter per
		// primitive rather than a second copy for the kernel channel, and so a
		// test can inject fakes.
		//
		// The socket is resolved from upgrade.DefaultConfigDBDir: the kernel
		// verbs carry no --configdb-dir flag (they run from
		// xpf-kernel-promote.service, not an operator command line), and
		// upgradeControlSock already falls back to the default socket path when
		// that dir is absent or unreadable.
		//
		// #7157: config.IsManagementIfName is the beacon's management-interface
		// classifier — the #7515 SSOT already shared by the vrf-mgmt binder, the
		// networkd `VRF=` emitter and the ip-monitoring next-hop validator, so
		// this is a fourth CONSUMER of one rule rather than a fourth copy of it.
		Sys: upgrade.NewKernelSystemWithHelperStatus(
			func(ctx context.Context) (bool, error) {
				return upgradeUnitActive(ctx, upgrade.DefaultUnit)
			},
			upgradeHelperStatus,
			upgradeControlSock(upgrade.DefaultConfigDBDir),
			config.IsManagementIfName,
		),
		Logf: func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}
}
