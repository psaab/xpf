// Package daemon — #1922 SAFE-BOOTSTRAP daemon state (M1b Items 2-4).
//
// This file owns the explicit bootstrap mode, the five-case boot predicate,
// the PCI-keyed management lifeline record, and the protected-set resolution
// that keeps the daemon from ever locking an operator out of a remote box it
// manages. None of this is hot-path: it runs at startup and on the Item-1b
// first-commit rollback only.
package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// loadErrorClass categorizes a Store.Load error for the boot path (#1917 D1
// fatal-on-parse + #1960 fail-closed-on-compile). Keeping the classification
// in one pure helper makes the boot decision unit-testable without standing
// up the whole daemon.
type loadErrorClass int

const (
	// loadOK — Load returned nil (absent DB start-fresh, or a valid loaded
	// config). The caller proceeds with bootstrapFromFile / normal boot.
	loadOK loadErrorClass = iota
	// loadFatalUnreadable — ErrConfigDBUnreadable (#1917 D1): present but
	// unparseable/too-new bytes. The daemon must FAIL CLOSED by exiting Run,
	// so the unreadable DB is never overwritten by a blind bootstrap.
	loadFatalUnreadable
	// loadCompileFailed — ErrConfigCompile (#1960): present, valid bytes,
	// previously committed, but the tree no longer compiles. The daemon must
	// NOT exit (that strands mgmt too) and must NOT positional-claim-all;
	// instead it enters the #1922 bootstrap/lifeline safe state.
	loadCompileFailed
	// loadOtherError — any other Load error (logged as a warning; the daemon
	// proceeds and the boot predicate decides bootstrap vs normal as usual).
	loadOtherError
)

// classifyLoadError maps a Store.Load error to its boot-path class. err==nil
// returns loadOK.
func classifyLoadError(err error) loadErrorClass {
	switch {
	case err == nil:
		return loadOK
	case errors.Is(err, configstore.ErrConfigDBUnreadable):
		return loadFatalUnreadable
	case errors.Is(err, configstore.ErrConfigCompile):
		return loadCompileFailed
	default:
		return loadOtherError
	}
}

// shouldBootstrapFromFile reports whether Run should import the text config
// file (xpf.conf) after Store.Load. The import runs only when there is no
// active config to boot from AND the Load did not fail closed on a compile
// error.
//
// #1960: the `!configCompileFailed` clause is load-bearing, not cosmetic. On a
// compile-failed load ActiveConfig() is nil (compiled stayed nil), so without
// this guard the import would fire — silently swapping a DIFFERENT config
// (whatever xpf.conf holds) in over the broken committed DB and then taking
// over interfaces from it, defeating the fail-closed intent. This predicate is
// the single source of truth for that decision (daemon_run.go calls it) so the
// guard cannot be dropped without TestShouldBootstrapFromFile failing.
func shouldBootstrapFromFile(hasActiveConfig, configCompileFailed bool) bool {
	return !hasActiveConfig && !configCompileFailed
}

// lifelineRecordFile persists the management-NIC identity (PCI bus address +
// MAC) so the protected set (Item 4) survives the rename that turns the
// recorded kernel name (enp5s0) into fxp0, AND survives daemon restarts and
// rollback-to-bootstrap. Keyed by PCI address, NOT name (a name-keyed record
// goes stale the instant the rename runs — AGY #1879 r2 Critical).
const lifelineRecordFile = "/etc/xpf/lifeline-interface"

// defaultMgmtInterface is the conventional management interface name. It is
// always a member of the protected set unless an explicit non-fxp0
// `system management-interface` leaf narrows it off (Item 4 / OQ-D escape
// valve).
const defaultMgmtInterface = "fxp0"

// applianceMarkerFile marks a host that was PROVISIONED FROM THE XPF APPLIANCE
// IMAGE. `scripts/image/bake.py` writes it into the baked root filesystem; the
// .deb postinst NEVER does, so a foreign host that merely has the package
// installed can never carry it, and neither can a `xpf-deploy` push.
//
// It is the discriminator the #1922 bootstrap lifeline was missing (#7114).
// The lifeline refuses to touch any NIC when it cannot identify a management
// interface, and on a FOREIGN host that refusal is right: xpf is a guest there
// and the operator's own network configuration is the thing keeping the box
// reachable. On the appliance image xpf is the ONLY network manager — the bake
// purges cloud-init and deletes every netplan / interfaces.d file — so at a
// factory boot there is no default route, no address, and no `.network` file
// anywhere: there is nothing to preserve, and refusing leaves every NIC down
// and unrenamed, reachable only from the hypervisor console. The image's
// vNIC#1 -> fxp0 factory contract (docs/install-images.md; PR #1906) makes
// mgmt-is-enumeration-index-0 a property of the ARTIFACT, so on this host —
// and only on this host — the first enumerated NIC is a safe lifeline.
//
// A var, not a const, so tests can repoint the probe at a scratch tree.
var applianceMarkerFile = "/etc/xpf/appliance"

// Lifeline provenance strings, used for logging and as the chooser's verdict
// discriminator.
const (
	lifelineSourceDefaultRoute     = "default-route"
	lifelineSourceApplianceFactory = "appliance-factory-boot"
)

// isApplianceFactoryBoot is the pure gate for the #7114 appliance factory
// bootstrap. BOTH conditions are load-bearing:
//
//   - markerPresent: the host was provisioned from the xpf appliance image, so
//     xpf owns every NIC on it (see applianceMarkerFile). Without this a
//     foreign-host .deb install would claim the operator's NICs — the exact
//     lockout #1922 closed.
//   - !everCommitted: this is a genuinely FACTORY box — no configuration has
//     ever been committed on it. A box that HAS been configured can also be in
//     bootstrap mode, via the #1960 fail-closed path (a committed config that
//     no longer compiles). There the operator's intended interface bindings are
//     unknown-but-real — possibly a device-map that never wants an auto-fxp0 —
//     and claiming NIC 0 as fxp0 would be precisely the mis-binding #1960
//     refuses to perform. The Item-1b first-commit rollback leaves
//     everCommitted false, which is correct: that box is factory-equivalent.
func isApplianceFactoryBoot(markerPresent, everCommitted bool) bool {
	return markerPresent && !everCommitted
}

// chooseBootstrapLifeline is the pure NIC-selection core of
// setupBootstrapLifeline (#7114). The default route wins whenever one exists —
// including on the appliance, where a committed-then-rolled-back box may still
// carry addressing — because it is the direct evidence of where the operator
// actually reaches the box. The appliance factory fallback applies only when
// there is no default route at all. Anything else selects nothing, which is
// the #1922 console-only refusal.
func chooseBootstrapLifeline(routeIface, firstNIC string, applianceFactory bool) (name, source string, ok bool) {
	if routeIface != "" {
		return routeIface, lifelineSourceDefaultRoute, true
	}
	if applianceFactory && firstNIC != "" {
		return firstNIC, lifelineSourceApplianceFactory, true
	}
	return "", "", false
}

// userspaceShimLinkPinDir carries the pinned XDP links that survive a daemon
// restart. Pins are a CHEAP PRE-FILTER ONLY (#1993 review): their presence
// proves "an XDP link is attached", NOT "forwarding is live". On a graceful
// hitless shutdown the pins are intentionally preserved while forwarding is
// STOPPED (dp.Close → helper Close leaves pinned maps/links for reuse), so a
// pin-only guard would wrongly preserve FRR on a graceful restart and recreate
// the blackhole. Absence of pins is still a reliable "definitely not live"
// signal (a cold reboot clears the bpffs tmpfs), so it short-circuits to CLEAR
// without the socket probe. The authoritative live-forwarding decision for the
// pins-present case is failClosedBootForwardingArmed below.
const userspaceShimLinkPinDir = "/sys/fs/bpf/xpf/links"

// failClosedBootArmedProbeTimeout bounds the early-boot control-socket probe.
// Short on purpose: a surviving helper answers status in well under a second,
// and on a cold boot the socket is absent (immediate ENOENT) — boot must not
// stall waiting on a dead path.
const failClosedBootArmedProbeTimeout = 2 * time.Second

var failClosedBootHasPinnedXDPLinks = detectFailClosedBootPinnedXDPLinks

func detectFailClosedBootPinnedXDPLinks() (bool, error) {
	entries, err := os.ReadDir(userspaceShimLinkPinDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "xdp_") {
			return true, nil
		}
	}
	return false, nil
}

// failClosedBootForwardingArmed reports whether a PRE-EXISTING userspace helper
// is reachable on its control socket AND reports Enabled && ForwardingArmed —
// i.e. forwarding is genuinely LIVE right now. This is the authoritative
// restart-preserve signal (#1993 review MAJOR): unlike the pin pre-filter, it
// distinguishes a daemon CRASH (helper survives, still forwarding) from a
// graceful hitless STOP (pins remain, forwarding off). A package-var seam so
// unit tests drive the decision without a real helper.
//
// The control socket is resolved exactly as the runtime Manager resolves it
// (DefaultControlSocketPath → deriveUserspaceConfig). At a compile-failed boot
// the active config is nil, so this is the default path — which matches a
// surviving helper from a default-config deployment. A deployment that set a
// custom control-socket path resolves to the default here (config is
// uncompilable), the probe finds nothing, and the caller fails toward CLEARING
// FRR — the safe direction (treat unknown as not-forwarding).
var failClosedBootForwardingArmed = detectFailClosedBootForwardingArmed

func detectFailClosedBootForwardingArmed() (bool, error) {
	// Active config is nil on a compile-failed boot; DefaultControlSocketPath
	// returns the default control-socket path in that case. A surviving helper
	// that the previous (now-uncompilable) config had pointed at a NON-default
	// control-socket path is therefore not probed here and reads as not-armed,
	// which CLEARS FRR. That is the fail-safe direction (peers fail over rather
	// than blackhole): this can only over-clear on an exotic custom-socket
	// config, never wrongly preserve FRR for a dead dataplane.
	sock := dpuserspace.DefaultControlSocketPath(nil)
	return dpuserspace.ProbeForwardingArmed(sock, failClosedBootArmedProbeTimeout)
}

// bootClass is the result of the #1922 five-case boot predicate. Each value
// maps to exactly one of {bootstrap, normal, fail-safe}.
type bootClass int

const (
	// bootClassNormal — a valid active config exists (case 2 day-0/preseeded
	// import, case 3 valid active.json) OR the operator committed an empty
	// config (case 5 committed-empty). Full takeover; zero behavior change
	// from pre-#1922.
	bootClassNormal bootClass = iota
	// bootClassBootstrap — fresh/no config (case 1) or never-committed
	// (case 5 never-committed, incl. the post-first-commit-rollback state).
	// No NIC rename beyond the lifeline path, no link cycles, no networkd
	// takeover, no dataplane arm, no FRR managed-section, no boot-time apply.
	bootClassBootstrap
	// bootClassFailSafe — corrupt/too-new active.json (case 4). #1917 D1
	// makes this fatal BEFORE this predicate is consulted; it is represented
	// here only for completeness and the predicate never returns it on a
	// reachable path (Load already returned ErrConfigDBUnreadable and Run
	// exited fatally).
	bootClassFailSafe
)

func (c bootClass) String() string {
	switch c {
	case bootClassNormal:
		return "normal"
	case bootClassBootstrap:
		return "bootstrap"
	case bootClassFailSafe:
		return "fail-safe"
	default:
		return "unknown"
	}
}

// hasNodeIDFile reports whether the install-time-stable HA signal
// (/etc/xpf/node-id) is present. The cluster short-circuit (C2/C8) keys on
// this FILE, NOT on the config-derived clusterMode (which is false until a
// cluster config loads and so cannot pre-empt the predicate).
func hasNodeIDFile() bool {
	_, err := os.Stat(nodeIDFile)
	return err == nil
}

// computeBootClass implements the #1922 five-case boot predicate. It is
// computed ONCE at startup (after Store.Load + bootstrapFromFile have
// resolved) and again on rollback-to-bootstrap. It is deterministic and
// stable across restarts given the same on-disk state.
//
// Inputs (all already resolved by the caller in daemon_run.go):
//   - hasActiveConfig: store.ActiveConfig() != nil — a compiled config is
//     loaded (case 2 import-clean or case 3 valid-active.json).
//   - everCommitted: store.EverCommitted() — the #1922 step-0 marker.
//   - nodeID: /etc/xpf/node-id presence (the HA-node guard, C2/C8).
//   - configCompileFailed: a PRESENT, previously-committed active.json
//     read+parsed fine but no longer COMPILES (#1960, Store.Load returned
//     ErrConfigCompile). This is the highest-priority signal — see below.
//
// Case 4 (corrupt/too-new) is handled by #1917 D1 fatal-on-parse in Run
// BEFORE this is called, so it never reaches here.
func computeBootClass(hasActiveConfig, everCommitted, nodeIDPresent, configCompileFailed bool) bootClass {
	// #1960 fail-closed (checked FIRST, before the HA-node guard): a config
	// that was previously committed but no longer compiles must NEVER drive a
	// full takeover. With everCommitted=true and ActiveConfig()==nil (compiled
	// stayed nil), every other branch below resolves to bootClassNormal —
	// positional claim-all interface naming on a box whose intended config is
	// unknown. That can mis-bind interfaces and strand management. Refusing
	// takeover (bootstrap mode + lifeline + protected set) keeps mgmt
	// reachable and leaves the control plane up so the operator can fix the
	// config. This overrides EVEN the HA-node guard: claiming all NICs on a
	// broken config is the exact lockout this issue closes, and an HA node
	// with an uncompilable config is safer in the lifeline state than
	// mis-binding (HA availability was already not promised in that state).
	if configCompileFailed {
		return bootClassBootstrap
	}

	// HA-node guard (C2 + C8): a node with /etc/xpf/node-id is HA-managed.
	// It resolves NOT-bootstrap via its own DB/xpf.conf (case 2/3). If it
	// has node-id but NEITHER a DB nor an importable xpf.conf, it is
	// fail-safe-with-loud-error and HA availability is NOT promised — but it
	// still must not enter bootstrap mode (which would refuse takeover and
	// silently break HA on a normal deploy). The loud-error logging happens
	// at the call site; here we resolve it to normal so takeover proceeds
	// (an HA node with no config does nothing harmful — empty config, the
	// protected set still shields mgmt).
	if nodeIDPresent {
		return bootClassNormal
	}

	// The step-0 marker (everCommitted) is checked BEFORE hasActiveConfig.
	// This is load-bearing (AGY r1 CRITICAL): after an Item-1b first-commit
	// rollback the DB holds an EMPTY tree with committed=0. On the next
	// restart Store.Load compiles that empty tree into a NON-nil
	// *config.Config, so hasActiveConfig is TRUE even though the box was
	// never successfully committed. Checking hasActiveConfig first would
	// then misclassify the rolled-back box as normal and take over
	// interfaces on an empty config — exactly the lockout this issue closes.
	//
	//   - everCommitted == false → fresh/no-config (case 1) OR
	//     never-committed incl. post-first-commit-rollback (case 5) →
	//     bootstrap.
	//   - everCommitted == true  → a real commit/sync happened, OR a
	//     legacy/older-build DB (migration rule C3 defaults committed=true),
	//     OR operator-committed-empty (case 5 committed-empty) → normal
	//     (cases 2/3, and the operator-meant-it empty case; the protected
	//     set still shields mgmt). hasActiveConfig is implied here for
	//     cases 2/3 and not required for the decision, but is retained in
	//     the signature for the call-site log/HA-guard diagnostics.
	if !everCommitted {
		return bootClassBootstrap
	}
	_ = hasActiveConfig
	return bootClassNormal
}

// inBootstrap reports whether the daemon is currently in bootstrap mode.
// Read from many goroutines (gate checks, commit gate); written once at
// startup and at most once more on rollback-to-bootstrap, so an atomic is
// sufficient and avoids taking a lock on every gate check.
func (d *Daemon) inBootstrap() bool {
	return d.bootstrapMode.Load()
}

// exitBootstrapMode clears bootstrap mode (one-way for the daemon's
// lifetime). Called when the FIRST non-empty config is applied to the store
// — a local confirmed commit (Item 1 / the 4-gate) OR a cluster SyncApply
// from the primary (C2 belt-and-suspenders). The caller is responsible for
// running the full normal reconcile (rename, networkd, dataplane, FRR) after
// this returns; exitBootstrapMode only flips the flag.
func (d *Daemon) exitBootstrapMode(reason string) {
	if d.bootstrapMode.CompareAndSwap(true, false) {
		slog.Info("exiting bootstrap mode; full interface/dataplane takeover will proceed",
			"reason", reason)
	}
}

// enterBootstrapMode rolls the daemon back to bootstrap mode after a failed
// first takeover (#1922 Item 1b / the enterBootstrapMode cleanup sequence).
// A normal applyConfig(empty) is WRONG — the userspace apply path ensures
// the helper exists, i.e. it would resurrect the dataplane bootstrap promises
// not to run. Instead this performs explicit cleanup, in order:
//
//  1. set bootstrap mode (re-suppress takeover for the daemon's lifetime),
//  2. remove xpf-written takeover .network/.link files EXCEPT the lifeline
//     fxp0 .network and the .link files, then networkctl reload,
//  3. clear the FRR managed section,
//  4. detach the dataplane (inverse of Start; the helper object is kept so a
//     later confirmed commit can re-arm it).
//
// Renames persist deliberately — reverting them would link-cycle a degraded
// box for cosmetic benefit. Post-rollback state = renamed NICs + lifeline
// fxp0 .network + zero config-driven claims. The caller holds d.applySem.
//
// #5868: the teardown is best-effort — every step is ATTEMPTED regardless of
// earlier failures — but failures are NO LONGER discarded. Each failing step
// is logged at ERROR with its name, and the aggregated error is returned to
// the caller. When any step fails the daemon reports the rollback as DEGRADED
// (config-driven takeover state may remain PARTIALLY live) rather than
// falsely logging "rollback complete". A nil return means every step
// converged and the box is cleanly back in bootstrap mode.
func (d *Daemon) enterBootstrapMode() error {
	d.bootstrapMode.Store(true)

	// #2114: stop and DISCARD the NAT pool-alarm monitor. It may have been
	// started on a prior successful bootstrap-exit arm; rolling back to
	// bootstrap means a later corrected commit can re-enter
	// runBootstrapExitStartup and, on an arm failure, clear the dataplane
	// cell. Codex PR #6743 r4-F5: that is NOT a data race — the cell is an
	// atomic.Pointer, so a concurrent sampler load against the clear is
	// well-defined and the sampler would simply observe nil. The reason to
	// stop the monitor is that a survivor keeps SAMPLING a backend this
	// rollback has just torn down, issuing control-socket work against
	// detached state. Discard (not
	// just Stop) because natpoolalarm.Monitor is not restartable after
	// Stop(); the next successful re-arm builds a fresh one via
	// maybeStartNATPoolAlarm. Placed BEFORE the applyBodyForTest seam return
	// so the lifecycle is exercised by the rollback unit tests too (it is a
	// no-op when no monitor is running). Runs under the caller's d.applySem.
	d.stopAndDiscardNATPoolAlarm()

	// #6742: relinquish cluster mastership and stop cluster comms BEFORE the
	// teardown below detaches the dataplane, and the order is the whole point.
	//
	// A node that rolls back into bootstrap is logically unconfigured — but
	// nothing here stopped VRRP, the heartbeat or session sync, so it kept
	// advertising, could hold or win RG mastership, and answered for the RETH
	// VIPs with a dataplane the teardown then detached. The peer saw a healthy
	// node throughout. That is the bootstrap-with-live-cluster hybrid.
	//
	// Resigning while this node can STILL forward makes the handover a planned
	// failover (priority-0 burst, peer takes over in ~1ms) instead of a
	// blackhole the peer discovers a heartbeat interval later. Doing it after
	// the dataplane detach would invert that.
	//
	// Placed BEFORE the seam branch below for the same reason
	// stopAndDiscardNATPoolAlarm is: the lifecycle then runs on every path,
	// including the rollback unit tests that stub the apply body. It is a no-op
	// on a standalone node.
	clusterSteps := d.relinquishClusterForBootstrap()

	var steps []bootstrapTeardownStep
	switch {
	case d.bootstrapTeardownForTest != nil:
		// #5868 test seam: inject synthetic per-step outcomes to exercise the
		// aggregation + honest-reporting wiring below without touching the
		// real filesystem / networkctl / FRR / dataplane.
		steps = d.bootstrapTeardownForTest()
	case d.applyBodyForTest != nil:
		// Existing unit-test seam (#2114 et al.): when the apply body is
		// stubbed, skip the real fs / networkctl / FRR / dataplane teardown —
		// those touch /etc/systemd/network and run external commands. No steps
		// executed ⇒ the rollback summarizes as clean, matching what those
		// tests expect. The bootstrap-mode flip above is the observable
		// behavior under test.
	default:
		steps = d.runBootstrapTeardownSteps()
	}

	// The cluster relinquish ran before the seam, so its outcomes are folded in
	// FIRST — a failed resign is part of the same honest report, not a separate
	// channel that a stubbed teardown could hide.
	steps = append(clusterSteps, steps...)

	// #5868: aggregate the per-step outcomes and report HONESTLY. A partial
	// teardown must never be logged/returned as a clean rollback.
	aggErr, degraded := summarizeBootstrapTeardown(steps)
	if degraded {
		for _, s := range steps {
			if s.err != nil {
				slog.Error("bootstrap rollback: teardown step FAILED",
					"step", s.name, "err", s.err)
			}
		}
		slog.Error("bootstrap rollback DEGRADED: one or more teardown steps failed; the "+
			"management lifeline is preserved but config-driven takeover state "+
			"(networkd/FRR/dataplane) may remain PARTIALLY LIVE — the config rolled back "+
			"FROM is not fully retired. 'commit confirmed' a corrected config and verify "+
			"interfaces/routes/dataplane are clean",
			"err", aggErr)
		return aggErr
	}

	slog.Warn("bootstrap rollback complete: takeover removed, management lifeline preserved; " +
		"system is back in bootstrap mode — 'commit confirmed' a corrected config")
	return nil
}

// bootstrapTeardownStep records the outcome of one best-effort teardown step
// in the first-confirmed-commit bootstrap rollback (#5868). name identifies
// the step for attributable logging; err is non-nil when that step did not
// converge. Every step is ATTEMPTED regardless of earlier failures.
type bootstrapTeardownStep struct {
	name string
	err  error
}

// summarizeBootstrapTeardown aggregates the per-step outcomes of a bootstrap
// rollback teardown (#5868). It returns a joined error naming every failed
// step (nil when all steps converged) and a degraded flag. degraded is true
// iff any step failed. The caller MUST report the rollback as DEGRADED and
// MUST NOT log or persist "rollback complete" while degraded is true — a
// partial teardown leaves config-driven takeover state (networkd/FRR/
// dataplane) potentially live.
func summarizeBootstrapTeardown(steps []bootstrapTeardownStep) (err error, degraded bool) {
	var errs []error
	for _, s := range steps {
		if s.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.name, s.err))
		}
	}
	if len(errs) == 0 {
		return nil, false
	}
	return errors.Join(errs...), true
}

// runBootstrapTeardownSteps performs the real, best-effort teardown of the
// first-confirmed-commit bootstrap rollback (#5868) and returns the per-step
// outcomes for the caller to aggregate. EVERY step is attempted regardless of
// earlier failures — a bootstrap rollback tears down as much as it can — but
// failures are captured (not discarded) so the caller can report DEGRADED.
// Runs under the caller's d.applySem.
// relinquishClusterForBootstrap resigns every redundancy group this node holds
// and stops cluster comms, so a node that has rolled back into bootstrap mode
// cannot keep acting clustered while logically unconfigured (#6742).
//
// It is a no-op on a standalone node (no cluster manager, or no VRRP manager).
//
// It deliberately does NOT call vrrp.Manager.Stop(). That method is
// single-shot: its own contract says the daemon does "Start-once at init and
// Stop-once at shutdown, never concurrently" (#2625), and it closes the event
// channel and cancels the manager context. Bootstrap rollback is RECOVERABLE —
// the next compilable `commit confirmed` (or a cluster SyncApply) re-arms the
// node — so tearing the manager down permanently would trade a hybrid state for
// a node that can never run VRRP again until xpfd restarts. ResignRG is the
// restartable path, the same one manual failover and a weight drop use.
//
// Each resign is awaited on its barrier so the virtual addresses are physically
// off the interface before the caller detaches the dataplane; a barrier that
// does not complete is reported as a failed step rather than waited on forever,
// because a wedged VRRP instance must not block the rollback that is trying to
// make this node safe.
//
// Runs under the caller's d.applySem. stopClusterComms takes clusterCommsMu,
// which is the same order the apply tail already uses when a transport change
// restarts comms (daemon_apply_tail.go), so there is no new lock edge.
func (d *Daemon) relinquishClusterForBootstrap() []bootstrapTeardownStep {
	if d.cluster == nil {
		return nil
	}
	var steps []bootstrapTeardownStep

	// Enumerate the RGs from the LIVE state machines, not from the config: the
	// config that defined them is exactly what this rollback is discarding.
	d.rgStatesMu.RLock()
	rgIDs := make([]int, 0, len(d.rgStates))
	for id := range d.rgStates {
		rgIDs = append(rgIDs, id)
	}
	d.rgStatesMu.RUnlock()
	sort.Ints(rgIDs)

	for _, rgID := range rgIDs {
		barrier := d.resignRethRG(rgID)
		if barrier == nil {
			// Nothing to release for this RG — no RETH tenure to hand over.
			continue
		}
		timeout := d.rethVIPReleaseTimeout
		if timeout <= 0 {
			timeout = rethVIPReleaseTimeout
		}
		timer := time.NewTimer(timeout)
		select {
		case <-barrier.Done():
			if err := barrier.Err(); err != nil {
				steps = append(steps, bootstrapTeardownStep{
					name: fmt.Sprintf("resign redundancy group %d", rgID),
					err:  err,
				})
			}
		case <-timer.C:
			steps = append(steps, bootstrapTeardownStep{
				name: fmt.Sprintf("resign redundancy group %d", rgID),
				err: fmt.Errorf("timed out after %s waiting for virtual addresses to be released",
					timeout),
			})
		}
		timer.Stop()
	}

	// Stop heartbeats, session sync and the fabric refresh loops. Until this
	// runs the peer keeps seeing a healthy node and keeps syncing sessions to
	// one whose dataplane is about to be detached.
	d.stopClusterComms()
	// #7901: this teardown does NOT restart. Without the mark, recovery depends
	// on the corrected commit happening to move a transport endpoint.
	d.markClusterCommsRestartNeeded()
	slog.Info("bootstrap rollback: cluster comms stopped and redundancy groups resigned",
		"redundancy_groups", len(rgIDs))
	return steps
}

func (d *Daemon) runBootstrapTeardownSteps() []bootstrapTeardownStep {
	steps := make([]bootstrapTeardownStep, 0, 3)

	// (2) Remove xpf-written takeover .network files (NOT the lifeline fxp0
	// .network and NOT the .link rename files — those keep mgmt reachable and
	// the rename stable). The lifeline .network is the bootstrap fxp0 file.
	lifelineNetwork := linkPrefix + "fxp0.network"
	entries, err := os.ReadDir(linkDir)
	if err != nil {
		// The directory could not be enumerated — the takeover .network files
		// (if any) are NOT removed. Surface it; still attempt FRR + dataplane
		// teardown below.
		steps = append(steps, bootstrapTeardownStep{name: "read link dir", err: err})
	} else {
		removed := false
		var rmErrs []error
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, linkPrefix) {
				continue
			}
			// Keep .link files (rename persistence) and the lifeline .network.
			if strings.HasSuffix(name, ".link") || name == lifelineNetwork {
				continue
			}
			if strings.HasSuffix(name, ".network") {
				if err := os.Remove(filepath.Join(linkDir, name)); err != nil {
					// Best-effort: record the failure and keep removing the rest.
					rmErrs = append(rmErrs, fmt.Errorf("%s: %w", name, err))
					continue
				}
				removed = true
				slog.Info("bootstrap rollback: removed takeover .network file", "file", name)
			}
		}
		if len(rmErrs) > 0 {
			steps = append(steps, bootstrapTeardownStep{
				name: "remove takeover .network files",
				err:  errors.Join(rmErrs...),
			})
		}
		// Reload if we removed at least one file — a partial removal still
		// changes the desired networkd state.
		if removed {
			if err := networkctlReload(); err != nil {
				steps = append(steps, bootstrapTeardownStep{name: "networkctl reload", err: err})
			}
		}
	}

	// (3) Clear the FRR managed section.
	if d.frr != nil {
		if err := d.frr.Clear(); err != nil {
			steps = append(steps, bootstrapTeardownStep{name: "clear FRR managed section", err: err})
		}
	}

	// (4) Detach the dataplane (inverse of Start). Keep the object so a later
	// confirmed commit re-arms it via runBootstrapExitStartup.
	if rt := d.dataplane(); rt != nil {
		if err := rt.Teardown(); err != nil {
			steps = append(steps, bootstrapTeardownStep{name: "dataplane teardown", err: err})
		}
	}
	// #5275: the detach above UN-ARMS this node — the shim is no longer
	// attached, so nothing adjudicates transit. Close the kernel transit
	// path to match, and drop the armed flag so the transit gate stays
	// closed at the next apply tail (applyKernelTuning), whatever link count
	// it reads. Unconditional: a rollback that found no published backend is
	// equally unarmed, and the write is a no-op when the knobs are already
	// closed. The bootstrap-exit arm, when a corrected commit re-arms the
	// retained object, reopens nothing by itself: the gate reopens only when
	// a re-evaluation finds the dataplane armed with a live attached link.
	d.markDataplaneNotArmed("bootstrap rollback",
		"dataplane detached; first commit confirmed timed out")

	return steps
}

// clearFRRForFailClosedBoot is the #1993 fail-closed boot refinement: on a
// boot where the previously-committed config no longer COMPILES (the #1960
// fail-closed tuple — ActiveConfig()==nil + everCommitted=true →
// bootClassBootstrap), the last-good `! BEGIN/END BPFRX MANAGED CONFIG`
// section may still be on disk in /etc/frr/frr.conf. FRR is an independent
// systemd service: if the node comes up with NO live dataplane attachments, it
// starts from that persisted file, forms BGP/OSPF/IS-IS peerings, and
// re-advertises last-good prefixes for routes this unarmed node cannot
// forward — a silent transit blackhole. Clearing ONLY the managed section
// drops those peerings so upstream/peers fail over to the HA partner instead
// of routing transit into a blackhole.
//
// This deliberately runs JUST the FRR-clear step of enterBootstrapMode()'s
// teardown — NOT the .network/.link removal or the link-cycle. The cold-boot
// fail-closed path is intentionally freeze-in-last-known-good for MANAGEMENT
// reachability (#1960): the operator stays connected on the existing mgmt IP.
// Removing networkd files / link-cycling toward bootstrap fxp0-DHCP here could
// change the mgmt IP out from under a connected operator, so it is excluded.
//
// Reversibility: the first compilable `commit confirmed` (or a cluster
// SyncApply) re-renders FRR through applyConfigLocked → applyFRRConfig, which
// re-installs the managed section. So this clear is fully reversible.
//
// Scope: gated on compileFailed AND on LIVE FORWARDING. The restart-preserve
// decision requires the helper to be genuinely forwarding, not merely
// "pins exist" (#1993 review MAJOR): on a graceful hitless shutdown the pins
// are preserved while forwarding is STOPPED, so a pin-only guard would wrongly
// preserve FRR and recreate the blackhole. The decision is therefore two-stage:
//
//  1. Pins are a CHEAP PRE-FILTER. No pins (e.g. a cold reboot cleared the
//     bpffs tmpfs) ⇒ no surviving dataplane ⇒ CLEAR, and skip the socket probe.
//     A pin-probe error is conservatively treated as "may have pins" → fall
//     through to the authoritative socket probe rather than guessing.
//  2. With pins present, query the helper control socket
//     (failClosedBootForwardingArmed): PRESERVE FRR only if it reports
//     Enabled && ForwardingArmed (a genuine crash-survivor still forwarding).
//     In EVERY other case — socket missing / connect-refused / timeout /
//     Enabled=false / ForwardingArmed=false / probe error — CLEAR. An
//     unarmed/unknown helper means no live forwarding, so peers must fail over
//     (fail toward clearing).
//
// A fresh/no-config bootstrap (which has no last-good managed section) and every
// NORMAL boot are byte-identical to before. The d.frr != nil guard tolerates
// NoDataplane daemons (FRR is constructed only inside the !NoDataplane
// manager-init block).
//
// A degraded reload (ErrFRRReloadDegraded, e.g. frr-reload.py unavailable) is
// LOGGED, not fatal: Clear() has already written the empty managed section to
// disk (so a later FRR restart converges) and the degraded-retry loop
// re-attempts. Management reachability beats a perfectly-clean FRR reload, so
// boot must proceed regardless.
func (d *Daemon) clearFRRForFailClosedBoot(compileFailed bool) {
	if !compileFailed || d.frr == nil {
		return
	}
	if !d.failClosedBootShouldClearFRR() {
		return
	}
	if err := d.frr.Clear(); err != nil {
		// Includes ErrFRRReloadDegraded — log, do not abort boot.
		slog.Warn("fail-closed boot: failed to clear FRR managed section; node may still "+
			"advertise last-good routes to peers until the operator fixes the config and "+
			"'commit confirmed'; if the managed section was already stripped on disk, a later "+
			"FRR restart will still converge",
			"err", err, "pin_dir", userspaceShimLinkPinDir)
		return
	}
	slog.Warn("fail-closed boot: cleared FRR managed section so peers fail over to the HA " +
		"partner instead of blackholing transit to this unarmed node. The first compilable " +
		"'commit confirmed' re-installs the managed section.")
}

// failClosedBootShouldClearFRR is the pure two-stage decision behind
// clearFRRForFailClosedBoot (extracted so the exact #1993-review gap — pins
// present but forwarding NOT live — is unit-testable without touching frr.conf).
// Returns true to CLEAR, false to PRESERVE.
//
// Stage 1 (cheap pre-filter): no pinned XDP links ⇒ no surviving dataplane ⇒
// CLEAR (and skip the control-socket probe). A pin-probe error does NOT itself
// preserve FRR — it is conservatively treated as "pins may exist" and falls
// through to the authoritative socket probe (fail toward the live check, not
// toward a stale guess).
//
// Stage 2 (authoritative): with pins present, PRESERVE only if the helper
// control socket reports forwarding is genuinely live (Enabled &&
// ForwardingArmed). Every other outcome — unreachable socket, timeout, probe
// error, or armed=false — CLEARS, because an unarmed/unknown helper is not
// forwarding and peers must fail over.
func (d *Daemon) failClosedBootShouldClearFRR() bool {
	pinnedXDPLinks, pinErr := failClosedBootHasPinnedXDPLinks()
	if pinErr != nil {
		slog.Warn("fail-closed boot: pinned-XDP pre-filter probe failed; "+
			"falling through to the control-socket armed probe",
			"pin_dir", userspaceShimLinkPinDir, "err", pinErr)
	} else if !pinnedXDPLinks {
		slog.Info("fail-closed boot: no pinned XDP links — last-known-good dataplane is "+
			"gone (e.g. cold reboot); clearing FRR managed section",
			"pin_dir", userspaceShimLinkPinDir)
		return true
	}

	armed, armErr := failClosedBootForwardingArmed()
	if armErr != nil {
		// Unreachable socket / timeout / decode error: NOT live forwarding.
		// Fail toward clearing so peers fail over rather than blackhole.
		slog.Warn("fail-closed boot: control-socket forwarding-armed probe failed; "+
			"treating the dataplane as NOT forwarding and clearing FRR managed section",
			"err", armErr)
		return true
	}
	if armed {
		slog.Info("fail-closed boot: helper reports forwarding is live (enabled+armed); " +
			"preserving FRR managed section across the restart")
		return false
	}
	slog.Info("fail-closed boot: helper is reachable but reports forwarding NOT armed; " +
		"clearing FRR managed section so peers fail over")
	return true
}

// lifelineRecord is the persisted management-NIC identity.
type lifelineRecord struct {
	PCIAddr string // PCI bus address (e.g. "0000:05:00.0"); primary key
	MAC     string // MAC address (tiebreaker for non-PCI NICs)
}

// lifelineRecordFileForTest overrides lifelineRecordFile in tests (the real
// path is /etc, not writable in the test sandbox). Empty => use the const.
var lifelineRecordFileForTest string

func lifelinePath() string {
	if lifelineRecordFileForTest != "" {
		return lifelineRecordFileForTest
	}
	return lifelineRecordFile
}

// writeLifelineRecord persists the lifeline identity. Keyed by PCI address so
// it survives the rename to fxp0 and daemon restarts (invariant 2). The file
// lives outside .configdb so it is config-independent (Item 4 invariant 3)
// and survives rollback-to-bootstrap.
func writeLifelineRecord(rec lifelineRecord) error {
	return writeLifelineRecordAt(lifelinePath(), rec)
}

func writeLifelineRecordAt(path string, rec lifelineRecord) error {
	content := fmt.Sprintf("# Managed by xpfd — #1922 management lifeline identity\npci=%s\nmac=%s\n",
		rec.PCIAddr, rec.MAC)
	// DurableState: the lifeline identity must survive a power cut (and a
	// rollback-to-bootstrap) so the daemon can always recover the
	// management NIC. MkdirAllDurable persists the directory entry itself,
	// not just the record file's entry within it (#1922).
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create lifeline record dir: %w", err)
	}
	if err := fsatomic.WriteFileDurable(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write lifeline record: %w", err)
	}
	return nil
}

// readLifelineRecord loads the persisted lifeline identity. Returns
// (zero, false) when the record is absent or unparseable (no lifeline pinned
// — the protected set then falls back to fxp0 + any management-interface
// leaf only).
func readLifelineRecord() (lifelineRecord, bool) {
	return readLifelineRecordAt(lifelinePath())
}

func readLifelineRecordAt(path string) (lifelineRecord, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return lifelineRecord{}, false
	}
	var rec lifelineRecord
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "pci":
			rec.PCIAddr = strings.TrimSpace(v)
		case "mac":
			rec.MAC = strings.TrimSpace(v)
		}
	}
	if rec.PCIAddr == "" && rec.MAC == "" {
		return lifelineRecord{}, false
	}
	return rec, true
}

// detectLifelineInterface picks the management lifeline NIC for a bootstrap
// boot (Item 3, lifeline-identification path).
//
// Resolution ladder (OQ-C resolution): the interface carrying the active
// IPv4 default route, else the active IPv6 default route, else none
// (refuse takeover, stay bootstrap, console-only). The default-route
// interface is "the NIC the operator reaches the box on" in the common
// single-homed case. A multi-homed / policy-routed mgmt box is the residual
// the operator resolves with an explicit `system management-interface` leaf
// once a config exists; the genuinely-fresh box has no leaf yet, so the
// default-route signal is the only config-independent option.
//
// detectLifelineInterfaceFn / enumeratePCINICsFn are injectable seams for the
// world-reading half of setupBootstrapLifeline, so the #7114 selection wiring
// is testable without a live netlink/sysfs stack. Production leaves them
// pointing at the real detectors.
var (
	detectLifelineInterfaceFn = detectLifelineInterface
	enumeratePCINICsFn        = enumeratePCINICs
)

// applianceFactoryBoot reports whether this bootstrap boot is a FACTORY boot of
// an xpf appliance image: the bake-written marker is present AND nothing has
// ever been committed on this box. See isApplianceFactoryBoot for why both
// halves are required. Called only from the bootstrap naming path, after
// Store.Load has resolved, so EverCommitted() is stable.
func (d *Daemon) applianceFactoryBoot() bool {
	if _, err := os.Stat(applianceMarkerFile); err != nil {
		return false
	}
	return d.store != nil && isApplianceFactoryBoot(true, d.store.EverCommitted())
}

// Returns the current kernel name of the lifeline NIC and ok=false when no
// default route exists.
func detectLifelineInterface() (name string, ok bool, err error) {
	var (
		sawDefaultRoute bool
		firstErr        error
	)
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, rerr := lifelineRouteList(nil, family)
		if rerr != nil {
			// #6789: RECORDED, not swallowed. A failed dump returns a nil
			// slice, which is byte-for-byte what "this box has no default
			// route" looks like — and the caller BRANCHES on that distinction.
			if firstErr == nil {
				firstErr = fmt.Errorf("route list family %d: %w", family, rerr)
			}
			continue
		}
		for i := range routes {
			r := &routes[i]
			// A default route has a nil/zero-length destination.
			if r.Dst != nil && len(r.Dst.IP) != 0 && !r.Dst.IP.IsUnspecified() {
				continue
			}
			if r.LinkIndex <= 0 {
				continue
			}
			sawDefaultRoute = true
			link, lerr := lifelineLinkByIndex(r.LinkIndex)
			if lerr != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("link by index %d: %w", r.LinkIndex, lerr)
				}
				continue
			}
			// A resolved default route is POSITIVE identification. Report it
			// even if an earlier dump errored: the error only matters when it
			// could have hidden the answer, and here the answer was found.
			return link.Attrs().Name, true, nil
		}
	}
	if firstErr != nil {
		// Either a dump failed, or every default route we saw had an
		// unresolvable link. Both leave "is there a default route, and on
		// which NIC" UNKNOWN — never report that as a confident "none".
		return "", false, firstErr
	}
	_ = sawDefaultRoute
	return "", false, nil
}

// pciAddrForInterface resolves the PCI bus address + MAC for a kernel
// interface name via sysfs (the same source enumeratePCINICs uses). A
// non-PCI NIC (virtio, bond, VLAN sub-interface, or other paravirtual /
// overlay device with no `/sys/class/net/<name>/device` PCI symlink) still
// yields a MAC-only record — PCI resolution failing must NOT short-circuit
// the MAC lookup, per the lifelineRecord format's own documented contract
// ("MAC (tiebreaker for non-PCI NICs)", #4815). Reports not-found only when
// NEITHER identity can be resolved.
func pciAddrForInterface(name string) (lifelineRecord, bool) {
	var pciAddr string
	if devReal, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", name, "device")); err == nil {
		pciAddr = extractPCIAddr(devReal)
	}
	var mac string
	if link, err := netlink.LinkByName(name); err == nil {
		mac = link.Attrs().HardwareAddr.String()
	}
	return lifelineRecordFromParts(pciAddr, mac)
}

// lifelineRecordFromParts is the pure core of pciAddrForInterface, factored
// out so the non-PCI MAC-fallback logic is unit-testable without sysfs or a
// real netlink link (#4815). Reports not-found only when neither a PCI
// address nor a MAC was resolved.
func lifelineRecordFromParts(pciAddr, mac string) (lifelineRecord, bool) {
	if pciAddr == "" && mac == "" {
		return lifelineRecord{}, false
	}
	return lifelineRecord{PCIAddr: pciAddr, MAC: mac}, true
}

// resolveLifelineCurrentName resolves the persisted lifeline record to the
// device's CURRENT kernel name (post-rename). It walks every NIC and matches
// on PCI address first (stable across rename), then MAC. Returns ("", false)
// when no record is pinned or it resolves to no present device.
func resolveLifelineCurrentName() (string, bool) {
	rec, ok := readLifelineRecord()
	if !ok {
		return "", false
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		if cur, ok := pciAddrForInterface(name); ok {
			if rec.PCIAddr != "" && cur.PCIAddr == rec.PCIAddr {
				return name, true
			}
		}
		if rec.MAC != "" {
			if link, err := netlink.LinkByName(name); err == nil &&
				strings.EqualFold(link.Attrs().HardwareAddr.String(), rec.MAC) {
				return name, true
			}
		}
	}
	return "", false
}

// protectedInterfaces returns the management protected set (Item 4): the
// union of the explicit `system management-interface` leaf (when set), the
// default fxp0 (unless narrowed off by an explicit non-fxp0 leaf), and the
// lifeline-recorded interface resolved from its PCI address to the current
// name. Members are NEVER marked Unmanaged / always-down / address-stripped
// by the reconcile path, regardless of the active config (config-independent;
// invariant 3).
//
// mgmtLeaf is the configured `system management-interface` value ("" when
// unset). The OQ-D escape valve: an explicit non-fxp0 leaf NARROWS fxp0 out
// of the auto-protection so an operator can repurpose fxp0 as a revenue port.
func protectedInterfaces(mgmtLeaf string) map[string]bool {
	lifeline, ok := resolveLifelineCurrentName()
	if !ok {
		lifeline = ""
	}
	return protectedInterfacesWith(mgmtLeaf, lifeline)
}

// protectedInterfacesWith is the pure core of protectedInterfaces, taking the
// already-resolved lifeline name (or "") so the OQ-D narrowing is unit
// testable without sysfs.
func protectedInterfacesWith(mgmtLeaf, lifeline string) map[string]bool {
	set := make(map[string]bool)
	// narrowFxp0 is the OQ-D escape valve: an explicit non-fxp0
	// management-interface leaf removes fxp0 from the auto-protection so the
	// operator can repurpose fxp0 as a revenue port. It must apply to BOTH
	// the leaf/default contribution AND the lifeline-record union — the
	// persisted lifeline record can resolve to fxp0 and would otherwise
	// silently re-add it (Codex r3 BLOCKER).
	narrowFxp0 := mgmtLeaf != "" && mgmtLeaf != defaultMgmtInterface
	if mgmtLeaf != "" {
		set[mgmtLeaf] = true
	} else {
		set[defaultMgmtInterface] = true
	}
	if lifeline != "" && !(narrowFxp0 && lifeline == defaultMgmtInterface) {
		set[lifeline] = true
	}
	return set
}

// setupBootstrapLifeline runs the Item-3 lifeline-gated path in place of the
// full rename loop when the daemon boots into bootstrap mode. It:
//
//  1. detects the management lifeline NIC (default-route interface),
//  2. records its PCI identity to /etc/xpf/lifeline-interface so the
//     protected set survives rename/restart/rollback,
//  3. if (and only if) that NIC is enumeration index 0 — i.e. it WOULD
//     become fxp0 in a normal rename — renames JUST that NIC to fxp0 and
//     writes a lifeline-aware bootstrap .network that snapshots its current
//     addressing (DHCP or static) so the link cycle restores reachability,
//  4. otherwise touches NO interface (refuse takeover, stay reachable on the
//     un-renamed kernel name), logs loudly, and requires the operator to
//     re-wire or set `system management-interface` + commit.
//
// No other NIC is renamed, cycled, or reconfigured in bootstrap mode.
//
// #7114 amends step 1: when there is no default route AND this host is a
// factory boot of the xpf appliance image (isApplianceFactoryBoot), the first
// enumerated NIC is selected instead of refusing. Steps 2-4 are unchanged and
// run identically for either provenance.
func (d *Daemon) setupBootstrapLifeline() {
	routeIface, _, routeErr := detectLifelineInterfaceFn()
	if routeIface == "" && routeErr != nil {
		// #6789: the route observation FAILED, so "which NIC carries the
		// default route" is UNKNOWN — not "there is none". The distinction is
		// load-bearing because the very next line BRANCHES on it: an empty
		// routeIface is what arms the #7114 appliance fallback, which claims
		// the first enumerated NIC and RENAMES it (renameInterface does an
		// explicit LinkSetDown -> LinkSetName -> LinkSetUp, so the rename IS
		// the NIC cycle). A box whose real management NIC is not enumeration
		// index 0 would have the wrong NIC claimed and cycled, on the strength
		// of a netlink error.
		//
		// Claim NOTHING instead. That is the same console-only refusal
		// chooseBootstrapLifeline documents for "cannot identify a management
		// NIC", and it is what every other observation failure in this
		// function already does.
		slog.Warn("bootstrap lifeline: could not enumerate routes, so it is UNKNOWN whether this "+
			"box has a default route or which NIC carries it. Claiming NOTHING and staying in "+
			"bootstrap with NO interface changes — an unreadable route table must never be read "+
			"as 'no default route', because that is what arms the appliance first-NIC fallback. "+
			"Reach the box via its console and 'commit confirmed' a config.",
			"err", routeErr)
		return
	}

	// #7114: the appliance image's factory boot has no default route to find —
	// the bake purges cloud-init and netplan, so nothing but xpfd ever brings a
	// NIC up. Enumerate a fallback there, and ONLY there.
	//
	// #6789: reachable only when the route observation SUCCEEDED and genuinely
	// found nothing (the unknown case returned above), so the factory contract
	// is unchanged for every box whose route state is actually known.
	firstNIC := ""
	applianceFactory := routeIface == "" && d.applianceFactoryBoot()
	if applianceFactory {
		nics, err := enumeratePCINICsFn()
		if err != nil {
			slog.Warn("bootstrap lifeline: appliance factory boot, but NIC enumeration "+
				"failed; no interface claimed", "err", err)
			applianceFactory = false
		} else if len(nics) > 0 {
			firstNIC = nics[0].name
		}
	}

	lifeline, source, ok := chooseBootstrapLifeline(routeIface, firstNIC, applianceFactory)
	if !ok {
		slog.Warn("bootstrap lifeline: no IPv4/IPv6 default route found; cannot identify a " +
			"management NIC. Staying in bootstrap with NO interface changes — reach the box " +
			"via its hypervisor/physical console and 'commit confirmed' a config.")
		return
	}
	if source == lifelineSourceApplianceFactory {
		slog.Info("bootstrap lifeline: no default route, but this host carries the xpf "+
			"appliance-image marker and has never committed a configuration; claiming the "+
			"first enumerated NIC as the fxp0 factory management interface (DHCP), per the "+
			"image's vNIC#1 -> fxp0 contract",
			"interface", lifeline, "marker", applianceMarkerFile)
	}

	// Record PCI identity (keyed by PCI, MAC tiebreaker) so the protected
	// set resolves the lifeline to its post-rename name (Item 4).
	if rec, ok := pciAddrForInterface(lifeline); ok {
		if err := writeLifelineRecord(rec); err != nil {
			slog.Warn("bootstrap lifeline: failed to persist lifeline record", "err", err)
		} else {
			slog.Info("bootstrap lifeline: recorded management NIC identity",
				"interface", lifeline, "pci", rec.PCIAddr, "mac", rec.MAC)
		}
	} else {
		slog.Warn("bootstrap lifeline: management NIC has no PCI address and no resolvable "+
			"MAC; no lifeline record written, protected set will fall back to fxp0 only",
			"interface", lifeline)
	}

	// Determine the enumeration index of the lifeline NIC. Only index 0
	// becomes fxp0; renaming a higher-index NIC would not match the mgmt
	// convention and risks cutting off management.
	nics, err := enumeratePCINICsFn()
	if err != nil {
		slog.Warn("bootstrap lifeline: NIC enumeration failed; no rename performed", "err", err)
		return
	}
	idx := -1
	for i, nic := range nics {
		if nic.name == lifeline {
			idx = i
			break
		}
	}
	if idx != 0 {
		slog.Warn("bootstrap lifeline: management default-route NIC is NOT enumeration index 0, "+
			"so it would not become fxp0. Refusing to rename/cycle any interface; staying in "+
			"bootstrap. Re-wire the management NIC to the first PCI slot, or set "+
			"'system management-interface' and 'commit confirmed'.",
			"interface", lifeline, "enum_index", idx)
		return
	}

	// The lifeline NIC would become fxp0. Snapshot its current addressing
	// into the bootstrap .network BEFORE the rename, so the link cycle
	// restores the same reachability under the fxp0 name.
	// #6789: an INCOMPLETE addressing observation aborts here, before the .link
	// write, the rename and the reload — i.e. before anything is mutated. Every
	// other observation failure in this function already refuses that way (no
	// default route, NIC enumeration failed, not enumeration index 0); this was
	// the one that GUESSED instead, substituting `DHCP=yes` and proceeding to
	// cycle the link. Refusing leaves the NIC under its kernel name with its
	// live addressing untouched, which is the #1922 console-only posture
	// chooseBootstrapLifeline documents as "selects nothing".
	if _, err := writeBootstrapLifelineNetwork(lifeline, source == lifelineSourceDefaultRoute); err != nil {
		slog.Error("bootstrap lifeline: could not observe the management NIC's addressing, so the "+
			"bootstrap fxp0 .network cannot be written correctly. Refusing to rename/cycle any "+
			"interface; staying in bootstrap with NO interface changes so management keeps its "+
			"current name and addressing. Reach the box via its console and 'commit confirmed' "+
			"a config.",
			"interface", lifeline, "err", err)
		return
	}

	// Rename just this one NIC to fxp0 (writes the .link + renames).
	original := recoverOriginalName(lifeline)
	if _, err := writeLinkFile(defaultMgmtInterface, original); err != nil {
		// #5842: the bootstrap lifeline .link is the file that keeps the
		// management NIC named fxp0 across the next boot. Log it loudly rather
		// than discarding — this path has no error channel to return on, so
		// the log IS the signal, and it must not be the one it was: none.
		slog.Error("bootstrap: failed to write the management lifeline .link; the management "+
			"NIC may come up under its kernel name on the next boot",
			"interface", defaultMgmtInterface, "original", original, "err", err)
	}
	if lifeline != defaultMgmtInterface {
		if err := renameInterfaceFn(lifeline, defaultMgmtInterface); err != nil {
			slog.Warn("bootstrap lifeline: rename to fxp0 failed; mgmt stays on original name",
				"from", lifeline, "err", err)
		} else {
			slog.Info("bootstrap lifeline: renamed management NIC to fxp0", "from", lifeline)
		}
	}
	if err := networkctlReloadFn(); err != nil {
		slog.Warn("bootstrap lifeline: networkctl reload failed", "err", err)
	}
}

// writeBootstrapLifelineNetwork writes the bootstrap fxp0 .network, snapshotting
// the lifeline NIC's CURRENT addressing so the rename's link cycle restores
// reachability. DHCP-managed lifelines get a plain DHCP .network (matching the
// historical writeBootstrapFxp0Network); a statically-addressed lifeline gets
// Address=/Gateway= lines. Returns true if the file changed.
func writeBootstrapLifelineNetwork(lifeline string, hasRouteEvidence bool) (bool, error) {
	path := filepath.Join(linkDir, linkPrefix+"fxp0.network")

	// Snapshot the lifeline's addressing ONCE. #6789: an observation FAILURE is
	// returned, never folded into "no addresses" — the address-less case takes
	// the DHCP branch below, so a failed read that returned empty would write
	// `DHCP=yes` over a statically-addressed management NIC and then cycle it.
	//
	// hasRouteEvidence scopes that refusal to the case where it means anything.
	// A lifeline chosen because it carries a DEFAULT ROUTE is positive evidence
	// that the NIC has live addressing which the rename must reproduce under the
	// fxp0 name, so failing to read it is a real loss of information and the
	// caller must refuse. The #7114 appliance factory lifeline is chosen
	// precisely when there is NO default route — the bake purges cloud-init and
	// netplan, so nothing has brought a NIC up and there is no addressing to
	// reproduce. DHCP is that image's documented vNIC#1 -> fxp0 contract, and a
	// failed observation cannot change a single byte of what gets written, so
	// refusing there would break the factory boot to guard information that was
	// never going to be used.
	snap, err := snapshotLifelineAddrs(lifeline)
	if err != nil {
		if hasRouteEvidence {
			return false, err
		}
		slog.Warn("bootstrap lifeline: addressing observation failed on an appliance factory "+
			"boot; writing the image's factory DHCP .network, which is what an empty "+
			"observation would have produced anyway",
			"interface", lifeline, "err", err)
		snap = lifelineAddrSnapshot{}
	}
	v4, v6, gw4, gw6 := snap.v4, snap.v6, snap.gw4, snap.gw6
	var content string
	if snap.dhcpManaged || (len(v4) == 0 && len(v6) == 0) {
		content = "# Managed by xpfd — #1922 bootstrap lifeline (DHCP)\n" +
			"[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nUseDNS=yes\nUseRoutes=yes\n"
	} else {
		var b strings.Builder
		b.WriteString("# Managed by xpfd — #1922 bootstrap lifeline (static snapshot)\n")
		b.WriteString("[Match]\nName=fxp0\n\n[Network]\n")
		for _, a := range v4 {
			fmt.Fprintf(&b, "Address=%s\n", a)
		}
		for _, a := range v6 {
			fmt.Fprintf(&b, "Address=%s\n", a)
		}
		if gw4 != "" {
			fmt.Fprintf(&b, "Gateway=%s\n", gw4)
		}
		if gw6 != "" {
			fmt.Fprintf(&b, "Gateway=%s\n", gw6)
		}
		content = b.String()
	}

	existing, readErr := os.ReadFile(path)
	if readErr == nil && string(existing) == content {
		return false, nil
	}
	// AtomicGeneratedConfig: a bootstrap .network snapshot regenerated from
	// the lifeline state; a torn file is unacceptable but a power-cut loss
	// is re-derived next boot.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		slog.Warn("bootstrap lifeline: failed to write fxp0 .network", "path", path, "err", err)
		return false, nil
	}
	slog.Info("bootstrap lifeline: wrote fxp0 bootstrap .network", "source_interface", lifeline)
	return true, nil
}

// resolveProtectedInterfaces is the daemon's #1922 Item 4 protected-set
// provider, registered with the dataplane compiler via
// SetProtectedInterfaceResolver. It returns the union of fxp0 (the default),
// the explicit `system management-interface` leaf when set, and the
// lifeline-recorded NIC resolved to its current name. Config-independent: it
// reads the persisted lifeline record + the active config's optional leaf,
// so the protection holds under an empty/absent/rolled-back config.
func (d *Daemon) resolveProtectedInterfaces() map[string]bool {
	mgmtLeaf := ""
	if cfg := d.store.ActiveConfig(); cfg != nil {
		mgmtLeaf = cfg.System.ManagementInterface
	}
	return protectedInterfaces(mgmtLeaf)
}

// Injectable netlink seams for the lifeline addressing snapshot (#6789). The
// snapshot decides whether the bootstrap fxp0 .network is written as DHCP or as
// a static address snapshot, and getting that wrong cycles the management NIC
// onto the wrong addressing — so its failure modes must be reachable from a
// test rather than only from real hardware.
var (
	lifelineLinkByName  = netlink.LinkByName
	lifelineLinkByIndex = netlink.LinkByIndex
	lifelineAddrList    = netlink.AddrList
	lifelineRouteList   = netlink.RouteList
)

// lifelineAddrSnapshot is a COMPLETE observation of a lifeline NIC's
// addressing. It is only ever constructed by snapshotLifelineAddrs, and only
// returned alongside a nil error — an incomplete observation has no
// representation, which is the point (#6789).
type lifelineAddrSnapshot struct {
	v4, v6   []string
	gw4, gw6 string
	// dhcpManaged reports a global address with a FINITE valid lifetime, the
	// heuristic for "this address came from DHCP". Folded into the snapshot so
	// the DHCP-vs-static decision and the address list come from ONE netlink
	// walk: they used to be two walks over the same state (interfaceAddrSnapshot
	// and isDHCPManaged) that FAILED IN OPPOSITE DIRECTIONS, which is what made
	// the defect below possible.
	dhcpManaged bool
}

// snapshotLifelineAddrs observes name's global addresses, default gateways and
// DHCP-lease heuristic. It returns an error when ANY observation failed, and
// the caller MUST treat that as "unknown", never as "none" (#6789).
//
// THE DEFECT THIS CLOSES. The two predecessors read the same netlink state and
// disagreed on fail direction. isDHCPManaged was documented to return false on
// any uncertainty so the writer would snapshot static addresses — the SAFE
// direction, and deliberately so. interfaceAddrSnapshot returned empty slices
// on a LinkByName failure and discarded the AddrList error entirely. The writer
// then asked `isDHCPManaged(x) || (len(v4) == 0 && len(v6) == 0)`, so the very
// failure that made isDHCPManaged fail SAFE also emptied the address list and
// drove the OR into the DHCP branch. A statically-addressed management NIC
// whose netlink read failed was written a `DHCP=yes` .network and then renamed
// — a link cycle that dropped its static address on a box reachable only over
// that NIC, in bootstrap, with no committed config to roll back to.
//
// WHY EVERY ERROR IS PROPAGATED, AND WHY THE ROUTE ONE IS SCOPED. A LinkByName
// or AddrList failure is always fatal to the snapshot: the DHCP-vs-static
// decision reads exactly that state, so an error there means the decision
// cannot be made at all. A RouteList failure is fatal only when the snapshot
// HAS addresses in that family — i.e. only when a `Gateway=` line for it would
// have been written, and its absence would leave management reachable on-link
// only. Failing the snapshot because the v6 route dump errored on a box with no
// v6 addresses would refuse a lifeline over an observation that could not have
// changed a single byte of the output.
func snapshotLifelineAddrs(name string) (lifelineAddrSnapshot, error) {
	var snap lifelineAddrSnapshot
	link, err := lifelineLinkByName(name)
	if err != nil {
		return snap, fmt.Errorf("link %s: %w", name, err)
	}
	addrs, err := lifelineAddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return snap, fmt.Errorf("address list %s: %w", name, err)
	}
	for i := range addrs {
		ip := addrs[i].IPNet
		if ip == nil || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() {
			continue
		}
		// A DHCP lease carries a finite ValidLft; a static address is
		// typically permanent (ValidLft == 0xffffffff / forever).
		if addrs[i].ValidLft > 0 && addrs[i].ValidLft != 0xffffffff {
			snap.dhcpManaged = true
		}
		if ip.IP.To4() != nil {
			snap.v4 = append(snap.v4, ip.String())
		} else {
			snap.v6 = append(snap.v6, ip.String())
		}
	}
	// Default-route gateways for this link.
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := lifelineRouteList(link, family)
		if err != nil {
			haveAddrs := len(snap.v4) > 0
			if family == netlink.FAMILY_V6 {
				haveAddrs = len(snap.v6) > 0
			}
			if haveAddrs {
				return lifelineAddrSnapshot{}, fmt.Errorf("route list %s family %d: %w", name, family, err)
			}
			continue
		}
		for i := range routes {
			r := &routes[i]
			if r.Dst != nil && len(r.Dst.IP) != 0 && !r.Dst.IP.IsUnspecified() {
				continue
			}
			if r.Gw == nil {
				continue
			}
			if r.Gw.To4() != nil && snap.gw4 == "" {
				snap.gw4 = r.Gw.String()
			} else if r.Gw.To4() == nil && snap.gw6 == "" {
				snap.gw6 = r.Gw.String()
			}
		}
	}
	return snap, nil
}
