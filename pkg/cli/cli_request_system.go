package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/grpcapi"
)

func (c *CLI) handleRequestSystem(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children))
		return nil
	}

	switch args[0] {
	case "reboot":
		fmt.Print("Reboot the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Reboot cancelled")
			return nil
		}
		fmt.Println("System going down for reboot NOW!")
		cmd := exec.Command("systemctl", "reboot")
		return cmd.Run()

	case "halt":
		fmt.Print("Halt the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Halt cancelled")
			return nil
		}
		fmt.Println("System halting NOW!")
		cmd := exec.Command("systemctl", "halt")
		return cmd.Run()

	case "power-off":
		fmt.Print("Power off the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Power-off cancelled")
			return nil
		}
		fmt.Println("System powering off NOW!")
		cmd := exec.Command("systemctl", "poweroff")
		return cmd.Run()

	case "zeroize":
		fmt.Println("WARNING: This will erase all configuration and return to factory defaults.")
		fmt.Print("Zeroize the system? [yes,no] (no) ")
		c.rl.SetPrompt("")
		line, err := c.rl.Readline()
		c.rl.SetPrompt(c.operationalPrompt())
		if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
			fmt.Println("Zeroize cancelled")
			return nil
		}

		// #5890: run the FULL factory-reset wipe by delegating to the shared
		// grpcapi.PerformZeroizeWipe primitive (see performConsoleZeroize). The
		// pre-fix console called only zeroizeConfigState, which erased the config
		// DB + archive but LEFT tls/, rendered service configs (frr/swanctl/kea),
		// and provisioned login accounts (shadow/authorized_keys/sudoers.d/xpf-*)
		// on disk — secret residue that let a re-tenanted device recover the prior
		// tenant's HTTPS key, routing-auth/IKE PSKs, and interactive login.
		if err := c.performConsoleZeroize(); err != nil {
			return err
		}

		fmt.Println("System zeroized. Configuration erased.")
		fmt.Println("Reboot to complete factory reset.")
		return nil

	case "configuration":
		return c.handleRequestSystemConfiguration(args[1:])

	case "software":
		return c.handleRequestSystemSoftware(args[1:])

	case "dynamic-dns":
		return c.handleRequestSystemDynamicDNS(args[1:])

	default:
		return fmt.Errorf("unknown request system command: %s", args[0])
	}
}

// zeroizeConfigRoot resolves the CONFIGURED config root the CLI factory-reset
// wipe must erase — the directory and base name of the store's `-config` path
// (configstore.Store.ConfigPath), the SAME path the daemon loads config from
// and persists the .configdb SSOT / master.key / numbered text rollback slots /
// audit journal to. This is the local-CLI twin of grpcapi (*Server).
// zeroizeConfigRoot (#5280): the interactive CLI runs in-process with the daemon
// and shares its store, so it resolves the root the same way instead of
// hardcoding /etc/xpf (#5554) — a daemon started with `-config /srv/xpf/site.conf`
// then erases /srv/xpf, not /etc/xpf.
//
// Fail CLOSED: if the store is absent or carries no config path we cannot know
// which root holds the prior tenant's secrets, so return an error rather than
// wiping the wrong directory (or nothing) while reporting a clean factory reset.
func (c *CLI) zeroizeConfigRoot() (configDir, configBase string, err error) {
	if c.store == nil {
		return "", "", fmt.Errorf("zeroize: config store unavailable; cannot determine configured config root to erase")
	}
	p := c.store.ConfigPath()
	if p == "" {
		return "", "", fmt.Errorf("zeroize: config store has no config path; cannot determine configured config root to erase")
	}
	dir := filepath.Dir(p)
	// #5684: refuse if the resolved root is a shared/parent/system directory. A
	// custom -config placed directly in a shared directory (or a directory-shaped
	// -config, where filepath.Dir climbs to the PARENT) would otherwise turn the
	// factory reset into a broad deletion of *.conf / .configdb / tls siblings xpf
	// does not own. Fail CLOSED (the shared FactoryResetConfigDir primitive guards
	// again, but stopping here gives the earliest, clearest operator error).
	// #9897 F-040: validate the RESOLVED root, not just the lexical path — a
	// link into a forbidden directory must be refused at this early gate too.
	// The ORIGINAL path is still returned (the shared wipe primitive
	// re-resolves authoritatively), so ordinary callers observe
	// byte-identical roots.
	if _, err := configstore.ResolveFactoryResetRoot(dir); err != nil {
		return "", "", err
	}
	return dir, filepath.Base(p), nil
}

// zeroizeFullWipe is the shared factory-reset primitive the console delegates to
// (#5890) — a package var so a test can spy the delegation without wiping real
// system paths. It defaults to grpcapi.PerformZeroizeWipe, the SAME primitive the
// gRPC zeroize path runs.
// cliZeroizeArchiveDir returns the archive directory the CONSOLE zeroize path
// erases (#7173).
//
// The console path is a recovery surface: it runs when the daemon may be down
// and the committed config may be unreadable, so it cannot ask the store what
// `system archival archive-dir` was set to. It therefore erases the xpf-owned
// DEFAULT, which is provably safe, and a custom archive dir is left for the
// operator — the same disposition FactoryResetArchiveDir would reach anyway,
// since it refuses to erase a directory whose ownership it cannot prove.
//
// The difference from the gRPC path is honest and worth stating: there, the
// configured directory is known and a skip is reported as an incomplete reset.
// Here it is not known, so a custom archive is not merely skipped but never
// seen. An operator who zeroizes from the console with a custom archive-dir
// must erase it by hand.
func cliZeroizeArchiveDir() string {
	return configstore.DefaultArchiveDir
}

var zeroizeFullWipe = grpcapi.PerformZeroizeWipe

// zeroizeStopDaemon stops xpfd so it releases interface/dataplane state; a
// package var so a test can neutralize the real systemctl call. Best-effort: the
// reboot completes the factory reset regardless.
var zeroizeStopDaemon = func() error {
	return exec.Command("systemctl", "stop", "xpfd").Run()
}

// performConsoleZeroize runs the FULL factory-reset wipe for the interactive
// console. #5890: it DELEGATES to grpcapi.PerformZeroizeWipe (via the
// zeroizeFullWipe seam) — the exact primitive the gRPC zeroize path runs — so
// the console and remote paths erase an IDENTICAL, single-source-of-truth
// OWNED-artifact set (config state + tls/ + rendered service configs
// [frr/swanctl/kea] + provisioned login accounts + config archive + BPF pins +
// networkd) and can never diverge again. The pre-#5890 console called only
// zeroizeConfigState, which erased the config DB + archive but LEFT tls/,
// rendered secrets, and login accounts on disk.
//
// The wipe target is resolved+validated from the store's CONFIGURED config root
// (zeroizeConfigRoot, #5554/#5684), failing CLOSED if it cannot be determined,
// so a non-default `-config` erases the right directory (never a hardcoded
// /etc/xpf). It then stops the daemon.
//
// #5871: the wipe runs THROUGH the daemon's coordinated factory-reset
// transaction (factoryResetFn -> daemon.factoryReset, the SAME gate the gRPC
// ZeroizeFn path uses) so the console gets IDENTICAL fencing: the transaction
// acquires the daemon apply semaphore (draining any in-flight apply, blocking a
// concurrent one) and enters the terminal reset generation BEFORE erasing, so no
// commit / HA-sync / reconcile re-persists the erased .configdb SSOT or
// re-renders the wiped secrets. The pre-#5871 console called zeroizeFullWipe
// DIRECTLY (ungated), so a concurrent writer could re-create just-erased state
// while the console reported a clean reset — the security bug this closes.
func (c *CLI) performConsoleZeroize() error {
	configDir, configBase, err := c.zeroizeConfigRoot()
	if err != nil {
		return err
	}
	// The shared full factory-reset wipe primitive (config state + tls/ +
	// rendered service configs [frr/swanctl/kea] + provisioned login accounts +
	// config archive + BPF pins + networkd), #5890.
	wipe := func() error { return zeroizeFullWipe(configDir, configBase, cliZeroizeArchiveDir()) }

	// Route through the daemon's coordinated transaction when wired. When it is
	// nil the CLI is spawned OUTSIDE the daemon (offline recovery / unit test) —
	// no reconcile loop is running to race, so the ungated direct wipe is the
	// honest fallback, mirroring grpcapi.runZeroize's zeroizeFn==nil path. Either
	// way the wipe/transaction error is surfaced fail-CLOSED (never discarded) and
	// the daemon is stopped ONLY on a fully-successful reset.
	run := wipe
	if c.factoryResetFn != nil {
		run = func() error { return c.factoryResetFn(context.Background(), wipe) }
	}
	if err := run(); err != nil {
		return fmt.Errorf("zeroize: factory reset did not fully complete: %w", err)
	}
	_ = zeroizeStopDaemon()
	return nil
}

// handleRequestSystemDynamicDNS implements `request system dynamic-dns
// update|check` (#3276): an operator force-now / check-now verb that triggers an
// immediate DDNS publish out-of-band of the poll cycle. `update` re-asserts
// every owned record now (force); `check` re-observes and publishes only changed
// records. Both honor the per-RG owner gate — on a node that masters no RG the
// daemon returns a clear "not the active node" message and takes no action.
func (c *CLI) handleRequestSystemDynamicDNS(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system dynamic-dns:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["dynamic-dns"].Children))
		return nil
	}
	if c.surfaceADDNSForceFn == nil {
		return fmt.Errorf("dynamic-dns: DDNS engine not running")
	}
	switch args[0] {
	case "update":
		_, msg := c.surfaceADDNSForceFn(true)
		fmt.Println(msg)
		return nil
	case "check":
		_, msg := c.surfaceADDNSForceFn(false)
		fmt.Println(msg)
		return nil
	default:
		return fmt.Errorf("unknown request system dynamic-dns command: %s", args[0])
	}
}

func (c *CLI) handleRequestSystemSoftware(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system software:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["software"].Children))
		return nil
	}

	if args[0] != "in-service-upgrade" {
		return fmt.Errorf("unknown request system software command: %s", args[0])
	}

	if c.cluster == nil {
		fmt.Println("Cluster not configured")
		return nil
	}

	fmt.Println("WARNING: This will force this node to secondary for all redundancy groups.")
	fmt.Print("Proceed with in-service upgrade? [yes,no] (no) ")
	c.rl.SetPrompt("")
	line, err := c.rl.Readline()
	c.rl.SetPrompt(c.operationalPrompt())
	if err != nil || strings.TrimSpace(strings.ToLower(line)) != "yes" {
		fmt.Println("ISSU cancelled")
		return nil
	}

	if err := c.cluster.ForceSecondary(); err != nil {
		return fmt.Errorf("ISSU: %v", err)
	}

	c.reportInServiceUpgradeDrain()
	return nil
}

// reportInServiceUpgradeDrain fences the drain-complete message on an OBSERVED
// peer takeover before telling the operator it is safe to stop this node
// (#5039). ForceSecondary only sets desired state and enqueues a droppable
// election event; the actual handoff happens asynchronously and can lag, so
// the command waits (bounded) to see the peer own primary before printing stop
// instructions, and otherwise warns and withholds them. Split out so the
// rendering is unit-testable without driving the interactive confirmation
// prompt.
func (c *CLI) reportInServiceUpgradeDrain() {
	ctx, cancel := context.WithTimeout(context.Background(), cluster.DefaultUpgradeHandoffTimeout)
	defer cancel()
	confirmed := c.cluster.WaitForUpgradeHandoff(ctx, cluster.DefaultUpgradeHandoffPoll)
	printISSUDrainReport(confirmed)
}

// printISSUDrainReport writes the honest ISSU drain report to stdout.
func printISSUDrainReport(handoffConfirmed bool) {
	for _, line := range cluster.UpgradeDrainReport(handoffConfirmed) {
		fmt.Println(line)
	}
}

func (c *CLI) handleRequestSystemConfiguration(args []string) error {
	if len(args) == 0 {
		fmt.Println("request system configuration:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["configuration"].Children))
		return nil
	}

	if args[0] != "rescue" {
		return fmt.Errorf("unknown request system configuration command: %s", args[0])
	}

	if len(args) < 2 {
		fmt.Println("request system configuration rescue:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["system"].Children["configuration"].Children["rescue"].Children))
		return nil
	}

	switch args[1] {
	case "save":
		if err := c.store.SaveRescueConfig(); err != nil {
			return err
		}
		fmt.Println("Rescue configuration saved")
		return nil

	case "delete":
		if err := c.store.DeleteRescueConfig(); err != nil {
			return err
		}
		fmt.Println("Rescue configuration deleted")
		return nil

	default:
		return fmt.Errorf("unknown request system configuration rescue command: %s", args[1])
	}
}
