// Package daemon — #1922 SAFE-BOOTSTRAP daemon state (M1b Items 2-4).
//
// This file owns the explicit bootstrap mode, the five-case boot predicate,
// the PCI-keyed management lifeline record, and the protected-set resolution
// that keeps the daemon from ever locking an operator out of a remote box it
// manages. None of this is hot-path: it runs at startup and on the Item-1b
// first-commit rollback only.
package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/netname"
	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
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
	// loadAbsentWithHistory — ErrConfigAbsentWithHistory (#10297): active.json
	// is ABSENT but rollback/.configdb markers survive, proving a prior
	// commit. Like loadCompileFailed, the daemon must NOT exit (that strands
	// mgmt too), must NOT blind-import the day-0 text config (that commit
	// would delete the surviving history), and must NOT run positional
	// claim-all; instead it enters the #1922 bootstrap/lifeline safe state
	// with history loaded for explicit in-band recovery.
	loadAbsentWithHistory
	// loadRescueFallback — a valid saved rescue config is available in a
	// never-committed empty state; it remains file-only until explicit
	// candidate staging. The daemon stays in bootstrap/lifeline mode.
	loadRescueFallback
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
	case errors.Is(err, configstore.ErrConfigAbsentWithHistory):
		return loadAbsentWithHistory
	case errors.Is(err, configstore.ErrConfigRescueFallback):
		return loadRescueFallback
	default:
		return loadOtherError
	}
}

// shouldBootstrapFromFile reports whether Run should import the text config
// file (xpf.conf) after Store.Load. A first-commit rollback leaves a compiled
// empty config with EverCommitted=false; it is still eligible for import.
// ActiveConfig alone would misread that Item-1b state as already configured.
//
// #1960/#10297/#11802: the failClosedLoad clause is load-bearing. A
// compile-failed present DB, absent DB with recovery markers, or valid rescue
// fallback keeps ActiveConfig() nil; without this guard xpf.conf would be
// imported over state that must remain in the bootstrap/lifeline path.
func shouldBootstrapFromFile(hasActiveConfig, everCommitted, failClosedLoad bool) bool {
	return (!hasActiveConfig || !everCommitted) && !failClosedLoad
}

const (
	day0RejectMarkerName    = ".day0-config-rejected"
	day0RejectMarkerContent = "commit-check-rejected"
	day0RejectImportDetail  = "day-0 config REJECTED by commit-check; see the xpf-day0-config journal for validation details"
)

// day0RejectMarkerDetail translates the loader's private signal into the
// bootstrap-import vocabulary. The marker deliberately carries no config
// bytes or validation output; the loader journal retains those details.
func day0RejectMarkerDetail(configFile string) string {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(configFile), day0RejectMarkerName))
	if err != nil || strings.TrimSpace(string(data)) != day0RejectMarkerContent {
		return ""
	}
	return day0RejectImportDetail
}

// lifelineRecordFile persists the management-NIC identity (PCI bus address +
// MAC) so the protected set (Item 4) survives the rename that turns the
// recorded kernel name (enp5s0) into fxp0, AND survives daemon restarts and
// rollback-to-bootstrap. Keyed by PCI address, NOT name (a name-keyed record
// goes stale the instant the rename runs — AGY #1879 r2 Critical).
const lifelineRecordFile = "/etc/xpf/lifeline-interface"

// defaultMgmtInterface is the conventional management interface name. It is
// always a member of the protected set unless an explicit non-fxp0 value in
// the internal `system management-interface` field narrows it off (Item 4 /
// OQ-D escape valve; config-mode grammar is deferred).
const defaultMgmtInterface = "fxp0"

const bootstrapLifelineNetworkMarker = "# Managed by xpfd — #1922 bootstrap lifeline"

const bootstrapLifelineSnapshotBase = ".xpf-first-commit-lifeline.snapshot"

// maxBootstrapLifelineSnapshotSize bounds the boot-path snapshot reads: the
// record is a generation hash plus one .network file; 1 MiB is generous
// without risking memory on a runaway file (#12155 census follow-up).
const maxBootstrapLifelineSnapshotSize = 1 << 20

// readBootstrapLifelineSnapshot reads the pre-takeover snapshot with a size
// cap and non-regular refusal: a FIFO here must not hang boot nor a runaway
// file exhaust memory (same hazard class as the #8597 configstore census).
func readBootstrapLifelineSnapshot(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular lifeline snapshot %s", path)
	}
	return io.ReadAll(io.LimitReader(f, maxBootstrapLifelineSnapshotSize+1))
}

type bootstrapLifelineSnapshotRecord struct {
	Generation string `json:"generation"`
	Network    []byte `json:"network"`
	// Present distinguishes a captured pre-takeover file from a captured
	// absence (#14993). Absent in old records decodes false, which the
	// restore gate rejects without authentic provenance.
	Present bool `json:"present"`
	// LifelineKernelName / LifelineLogicalName record the pre-takeover
	// kernel name of a non-index-0 foreign-host lifeline and the logical
	// name bootstrap-exit positional naming renamed it to (#16675).
	// Empty on old records and whenever the lifeline was index-0 fxp0
	// (that path is covered by the .network restore above).
	LifelineKernelName  string `json:"lifeline_kernel_name,omitempty"`
	LifelineLogicalName string `json:"lifeline_logical_name,omitempty"`
}

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

// hasNodeIDFileFn reports whether the install-time-stable HA signal
// (/etc/xpf/node-id) is present. Tests replace it to exercise config-less HA
// startup without creating a host-global file.
var hasNodeIDFileFn = func() bool {
	_, err := os.Stat(nodeIDFile)
	return err == nil
}

// hasNodeIDFile reports whether the install-time-stable HA signal is present.
func hasNodeIDFile() bool {
	return hasNodeIDFileFn()
}

// computeBootClass implements the #1922 five-case boot predicate. It is
// computed ONCE at startup (after Store.Load + bootstrapFromFile have
// resolved) and again on rollback-to-bootstrap. It is deterministic and
// stable across restarts given the same on-disk state.
//
// Inputs (all already resolved by the caller in daemon_run.go):
//   - everCommitted: store.EverCommitted() — the #1922 step-0 marker.
//   - nodeIDPresent: /etc/xpf/node-id presence (the HA-node guard, C2/C8).
//   - failClosedLoad: boot resolution found a state that must not drive takeover:
//     either a PRESENT active.json that no longer compiles (#1960,
//     ErrConfigCompile), an ABSENT active.json with surviving rollback markers
//     (#10297, ErrConfigAbsentWithHistory), or a valid rescue fallback in a
//     never-committed empty state (#11802). This is the highest-priority signal.
//
// Case 4 (corrupt/too-new) is handled by #1917 D1 fatal-on-parse in Run
// BEFORE this is called, so it never reaches here.
func computeBootClass(everCommitted, nodeIDPresent, failClosedLoad bool) bootClass {
	// #1960/#10297/#11802 fail-closed (checked FIRST, before the HA-node guard):
	// an unavailable previously-committed state OR a selected rescue fallback
	// in a never-committed empty state must NEVER drive a full takeover.
	// For a previously-committed state, with everCommitted=true and
	// ActiveConfig()==nil (compiled stayed nil or active.json was absent),
	// every other branch below resolves to bootClassNormal — positional
	// claim-all interface naming on a box whose intended config is unknown.
	// That can mis-bind interfaces and strand management. Refusing takeover
	// (bootstrap mode + lifeline + protected set) keeps mgmt reachable and
	// leaves the control plane up so the operator can fix or explicitly recover.
	if failClosedLoad {
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

	// The step-0 marker (everCommitted) determines whether the system has ever
	// completed a successful commit. A compiled empty tree after first-commit
	// rollback is not evidence of a commit and must remain in bootstrap mode.
	if !everCommitted {
		return bootClassBootstrap
	}
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
	d.bootstrapFromRefusedRollback.Store(false)
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
//  1. set bootstrap mode,
//  2. retire the abandoned config's LAN-facing service claims — withdraw the
//     Router Advertisement senders (lifetime-0 goodbye), stop the Kea DHCP
//     server units, and stop the DHCP relay (#16678),
//  3. retire xpf-written takeover .network files, preserving a validated
//     bootstrap lifeline or restoring its exact pre-takeover content on the
//     first-commit path only, then networkctl reload,
//  4. clear the FRR managed section,
//  5. detach the dataplane (inverse of Start; the helper object is kept so a
//     later confirmed commit can re-arm it).
//
// Renames persist deliberately — reverting them would link-cycle a degraded
// box for cosmetic benefit. The ONE exception is the non-fxp0 lifeline
// rename (#16675): on a foreign host that NIC's addressing lives in the
// host's own kernel-name-keyed config, so keeping the rename keeps the
// lockout. The first-commit path renames that NIC back and removes its
// takeover .link (see restoreBootstrapLifelineRename). Post-rollback
// state = renamed NICs (lifeline excepted) + no abandoned networkd
// addresses + the validated bootstrap lifeline when available + zero
// config-driven claims. The caller holds d.applySem.
//
// #12154: the lifeline .network restore is scoped to the FIRST-commit rollback
// (the recorded confirmPrevFirst flag, not prevCfg==nil — a retry after an
// Item-1b rollback carries a non-nil compiled empty target). A snapshot
// captured during bootstrap exit must never be used by a later safe-state
// entry on a committed box (#1960 freeze-in-last-known-good).
// #5868: teardown is best-effort and reports DEGRADED if any step fails rather
// than falsely logging "rollback complete".
func (d *Daemon) enterBootstrapMode() error {
	return d.enterBootstrapModeWithLifeline(false)
}

func (d *Daemon) enterBootstrapModeWithLifeline(restoreLifeline bool) error {
	// #16665: a generic bootstrap entry (first-commit rollback, nil
	// target) is not the refused-target provenance. The #9615 branch
	// re-sets the flag after this returns; clearing here prevents a
	// stale refused provenance from surviving a later generic entry.
	d.bootstrapFromRefusedRollback.Store(false)
	d.bootstrapMode.Store(true)

	// #15054: discharge any config-apply debt. A failed auto-rollback or
	// boot apply may have latched it before this rollback to the safe state;
	// the teardown below deliberately does NOT apply the active (possibly
	// #9615-refused) target, so leaving the debt owed would let the #9811
	// retry owner re-apply it in bootstrap mode and take over with no
	// commit. The retry is also gated on inBootstrap, but the debt itself
	// must not survive: convergence from here is owned by the authorized
	// commit/sync/rollback that exits bootstrap and applies in full.
	d.dischargeConfigApplyDebt()

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
	// #16678: relinquishClusterForBootstrap resigns the RGs (their demote edge
	// clears shared-identity RA senders silently and re-derives Kea), but in
	// standalone mode nothing runs at all, and in cluster mode the node-local
	// RA/Kea state survives derived from the abandoned config. Withdraw the
	// abandoned config's remaining service claims explicitly, and fold any
	// failure into the same honest DEGRADED aggregation as every other step.
	serviceSteps := d.withdrawAbandonedServicesForBootstrap()

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
		steps = d.runBootstrapTeardownSteps(restoreLifeline)
	}

	// The cluster relinquish ran before the seam, so its outcomes are folded in
	// FIRST — a failed resign is part of the same honest report, not a separate
	// channel that a stubbed teardown could hide.
	steps = append(clusterSteps, steps...)
	steps = append(serviceSteps, steps...)

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
			"config-driven takeover state "+
			"(networkd/FRR/dataplane) may remain PARTIALLY LIVE — the config rolled back "+
			"FROM is not fully retired. 'commit confirmed' a corrected config and verify "+
			"interfaces/routes/dataplane are clean",
			"err", aggErr)
		return aggErr
	}

	slog.Warn("bootstrap rollback complete: config-driven takeover removed; " +
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
// withdrawAbandonedServicesForBootstrap retires the abandoned config's
// LAN-facing service claims on entry to the bootstrap safe state (#16678):
// the Router Advertisement senders, the Kea DHCP server units and the DHCP
// relay. Those owners are otherwise reached only from the config-apply path
// (daemon_apply_routing.go / daemon_apply_tail.go) and from shutdown, and
// the first-commit / nil-target rollback branch returns without an apply —
// so without this step the box kept advertising itself as an IPv6 default
// router and kept leasing DHCP with itself as gateway on segments it no
// longer forwards for, while logging "config-driven takeover removed".
//
// RA: Withdraw emits the lifetime-0 goodbye and stops every sender
// (RFC 4861 §6.2.5, the same terminal the apply path uses when RA is
// removed, #5092). In cluster mode the RG resign above has already
// stopped the shared-stable-identity senders silently via the demote
// edge, so the senders left for Withdraw are the node-local and
// per-node-source ones, for which the goodbye is correct. The cluster
// reconcile digest is cleared so a later commit re-derives RA instead
// of matching the abandoned set's digest (inert empty after withdrawal).
//
// Kea: stopped with Apply(nil), the same synchronous clear the
// factory-reset quiesce uses — the Kea units outlive xpfd, so they must
// be stopped explicitly (pkg/dhcpserver README, #6787). Shutdown() is
// NOT used because it latches and would prevent a corrected commit
// from restarting Kea without an xpfd restart.
//
// Relay: reconciled through the usual helper with an empty config; a bounded
// join timeout is returned and joined into the bootstrap DEGRADED steps.
//
// Each failure is returned as a teardown step so the caller reports the
// rollback DEGRADED instead of claiming "config-driven takeover removed".
// Runs under the caller's d.applySem.
func (d *Daemon) withdrawAbandonedServicesForBootstrap() []bootstrapTeardownStep {
	var steps []bootstrapTeardownStep
	if d.ra != nil {
		if err := d.ra.Withdraw(); err != nil {
			steps = append(steps, bootstrapTeardownStep{
				name: "withdraw router advertisements",
				err:  err,
			})
		}
		d.raReconcileMu.Lock()
		d.lastRAReconcileHash = ""
		d.lastStandaloneRAHash = ""
		d.raReconcileMu.Unlock()
	}
	if d.dhcpServer != nil {
		d.dhcpServer.SetLeaseSyncEnabled(false)
		if err := d.dhcpServer.Apply(nil); err != nil {
			steps = append(steps, bootstrapTeardownStep{
				name: "stop DHCP server",
				err:  err,
			})
		}
	}
	if err := d.reconcileDHCPRelay(&config.Config{}); err != nil {
		steps = append(steps, bootstrapTeardownStep{
			name: "stop DHCP relay",
			err:  err,
		})
	}
	return steps
}

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

// isBootstrapLifelineNetwork recognizes only the file written by the bootstrap
// lifeline path. A filename alone cannot distinguish that snapshot from
// networkd.Apply's later config-driven winner.
func isBootstrapLifelineNetwork(content []byte) bool {
	return bytes.HasPrefix(content, []byte(bootstrapLifelineNetworkMarker))
}

// captureBootstrapLifelineNetwork snapshots the exact pre-takeover fxp0 file,
// including an absent or unmarked file. The first-commit window scopes use of
// the snapshot; marker validation alone cannot distinguish console-only state
// from a lifeline that was lost after takeover. It runs after startup takeover
// and before the first config's networkd reconciliation can overwrite it.
//
// The memory snapshot (#12154, live-path) is always captured. The durable
// record (#12155) is persisted alongside so a crash between PromoteRollback
// and the daemon teardown still restores on restart; the boot consumer gates
// it on the abandoned GuardedHash. The Store generation is read BEFORE taking
// bootstrapLifelineMu — the confirm hook takes this mutex under Store.mu, and
// reversing that order deadlocked the daemon (NEW-MAJOR-A).
//
// #16675: the non-fxp0 lifeline rename pair is captured BEFORE exit by
// captureBootstrapLifelineRenamePreExit and persisted in the same
// generation-bound record, so the first-commit rollback can remove the
// takeover .link and rename back.
func (d *Daemon) captureBootstrapLifelineNetwork() {
	// NEW-MAJOR-A: read the Store generation BEFORE taking
	// bootstrapLifelineMu (the confirm hook takes this mutex under
	// Store.mu). Never call into the Store while holding it.
	var generation string
	if d.store != nil {
		generation = d.store.ActiveConfigGeneration()
	}
	d.bootstrapLifelineMu.Lock()
	defer d.bootstrapLifelineMu.Unlock()
	if d.bootstrapLifelineCaptured {
		// P1: two FIRST windows in one process. Window 1 rolled back (memory
		// snapshot kept, durable record bound to window 1). If a second
		// bootstrap exit runs under a NEW generation, re-persist the same
		// captured state — present bytes or absence (#14993) — under the new
		// generation, otherwise a window-2 expiry-across-restart gates it
		// against the wrong generation and sticks the box DEGRADED.
		if generation != "" && generation != d.bootstrapLifelineGeneration {
			if !d.bootstrapLifelinePresent {
				d.persistAbsentBootstrapLifelineSnapshotLocked(generation)
			} else if isBootstrapLifelineNetwork(d.bootstrapLifelineNetwork) {
				d.persistBootstrapLifelineSnapshotLocked(d.bootstrapLifelineNetwork, generation)
			}
			if d.bootstrapLifelineGeneration == generation {
				slog.Debug("bootstrap exit: re-persisted pre-takeover lifeline under a new generation",
					"generation", generation, "issue", "#14993")
			}
		}
		return
	}
	path := filepath.Join(linkDir, linkPrefix+"fxp0.network")
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		d.bootstrapLifelineCaptured = true
		d.bootstrapLifelinePresent = false
		// #14993: persist the captured ABSENCE generation-bound, so a
		// first-commit expiry across a daemon restart can prove the
		// post-takeover file is xpfd's own and remove it. Without this
		// the restart consumer has no provenance and fails closed with
		// the management network stranded.
		d.persistAbsentBootstrapLifelineSnapshotLocked(generation)
		slog.Debug("bootstrap exit: no pre-takeover management network file existed",
			"path", path)
		return
	}
	if err != nil {
		slog.Warn("bootstrap exit: could not snapshot the pre-takeover management network; "+
			"first-commit rollback may be degraded", "path", path, "err", err)
		return
	}
	d.bootstrapLifelineCaptured = true
	d.bootstrapLifelinePresent = true
	d.bootstrapLifelineNetwork = content
	if !isBootstrapLifelineNetwork(content) {
		slog.Debug("bootstrap exit: captured an unmarked pre-takeover fxp0 network file",
			"path", path)
		// #16675: even an unmarked fxp0 file must not suppress the durable
		// record when a non-fxp0 rename was captured — otherwise the
		// across-restart rollback loses rename-back provenance. The
		// restore gate rejects a non-marker Present record as before.
		if d.bootstrapLifelineKernelName != "" {
			d.persistBootstrapLifelineSnapshotLocked(content, generation)
		}
		return
	}
	d.persistBootstrapLifelineSnapshotLocked(content, generation)
	slog.Debug("bootstrap exit: captured pre-takeover management lifeline network",
		"path", path)
}

// captureBootstrapLifelineRenamePreExit records, BEFORE bootstrap-exit
// naming runs, whether the recorded lifeline NIC will be renamed to a
// non-fxp0 logical name by positional naming (#16675). It must be called
// before runBootstrapExitStartup: after the rename the lifeline record
// resolves to the logical name and the pre-takeover kernel name is lost.
//
// Only positional mode is captured: device-map mode never claims an
// unmapped lifeline, and its strand pre-flight already refuses a rename
// that would strand management. Index-0 lifelines rename to fxp0 and are
// covered by the fxp0 .network restore, so they record nothing.
//
// The logical name is computed with the same assignName the positional
// pass will use (same nodeID/clusterMode derivation), so the recorded
// pair matches the .link the takeover actually writes. Any observation
// failure records nothing — the exit then proceeds exactly as before and
// the rollback keeps its prior (fxp0-only) behaviour rather than guessing.
func (d *Daemon) captureBootstrapLifelineRenamePreExit(cfg *config.Config) {
	if d.opts.NoDataplane || cfg == nil || deviceMapNamingActive(cfg) {
		return
	}
	kernelName, ok := resolveLifelineCurrentNameFn()
	if !ok || kernelName == "" || kernelName == defaultMgmtInterface {
		return
	}
	if isPositionalLogicalName(kernelName) {
		return
	}
	nics, err := enumeratePCINICsFn()
	if err != nil || len(nics) == 0 {
		return
	}
	idx := -1
	for i, nic := range nics {
		if nic.name == kernelName {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return
	}
	nodeID, clusterMode, _, _, _ := namingParamsFromConfig(cfg)
	fpc := 0
	if clusterMode && nodeID == 1 {
		fpc = 7
	}
	logical := assignName(idx, fpc, clusterMode)
	if logical == "" || logical == kernelName || logical == defaultMgmtInterface {
		return
	}
	d.bootstrapLifelineMu.Lock()
	d.bootstrapLifelineKernelName = kernelName
	d.bootstrapLifelineLogicalName = logical
	d.bootstrapLifelineMu.Unlock()
	slog.Info("bootstrap exit: recorded non-fxp0 lifeline rename for first-commit rollback",
		"kernel", kernelName, "logical", logical, "issue", "#16675")
}

// isPositionalLogicalName reports whether name is one positional naming
// can assign (fxp0, em0, or ge-<fpc>-0-<n>).
func isPositionalLogicalName(name string) bool {
	if name == defaultMgmtInterface || name == "em0" {
		return true
	}
	if !strings.HasPrefix(name, "ge-") {
		return false
	}
	rest := strings.TrimPrefix(name, "ge-")
	fpcStr, tail, ok := strings.Cut(rest, "-0-")
	if !ok || fpcStr == "" || tail == "" {
		return false
	}
	for _, c := range fpcStr + tail {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// bootstrapLifelineRenamePair returns the captured (kernel, logical) pair.
func (d *Daemon) bootstrapLifelineRenamePair() (kernel, logical string) {
	d.bootstrapLifelineMu.Lock()
	defer d.bootstrapLifelineMu.Unlock()
	return d.bootstrapLifelineKernelName, d.bootstrapLifelineLogicalName
}

// resolveLifelineCurrentNameFn is a seam so the pre-exit capture is
// testable without sysfs/netlink. Production is resolveLifelineCurrentName.
var resolveLifelineCurrentNameFn = resolveLifelineCurrentName

// persistBootstrapLifelineSnapshotLocked writes the generation-bound durable
// snapshot record (#12155). Caller holds bootstrapLifelineMu and passes the
// generation read BEFORE taking it (never call into the Store here).
// Best-effort: persist failure degrades to memory-only (warned), never fails
// bootstrap exit.
func (d *Daemon) persistBootstrapLifelineSnapshotLocked(content []byte, generation string) {
	if generation == "" {
		slog.Warn("bootstrap exit: active config generation unavailable; lifeline provenance is memory-only",
			"issue", "#12155")
		return
	}
	d.bootstrapLifelineGeneration = generation
	record, err := json.Marshal(bootstrapLifelineSnapshotRecord{
		Generation:          d.bootstrapLifelineGeneration,
		Network:             content,
		Present:             true,
		LifelineKernelName:  d.bootstrapLifelineKernelName,
		LifelineLogicalName: d.bootstrapLifelineLogicalName,
	})
	if err == nil {
		record = append(record, '\n')
		err = fsatomic.WriteFileDurable(filepath.Join(linkDir, bootstrapLifelineSnapshotBase), record, 0o600)
	}
	if err != nil {
		slog.Warn("bootstrap exit: could not persist authentic management lifeline snapshot; "+
			"first-commit rollback may be degraded", "path",
			filepath.Join(linkDir, bootstrapLifelineSnapshotBase), "err", err, "issue", "#12155")
		return
	}
}

// persistAbsentBootstrapLifelineSnapshotLocked writes the generation-bound
// durable record for a captured pre-takeover ABSENCE (#14993). Caller holds
// bootstrapLifelineMu and passes the generation read BEFORE taking it.
// Best-effort like the present-bytes variant: a persist failure degrades
// to memory-only (the live rollback still works) and is warned.
func (d *Daemon) persistAbsentBootstrapLifelineSnapshotLocked(generation string) {
	if generation == "" {
		slog.Warn("bootstrap exit: active config generation unavailable; absent lifeline provenance is memory-only",
			"issue", "#14993")
		return
	}
	d.bootstrapLifelineGeneration = generation
	record, err := json.Marshal(bootstrapLifelineSnapshotRecord{
		Generation:          generation,
		Present:             false,
		LifelineKernelName:  d.bootstrapLifelineKernelName,
		LifelineLogicalName: d.bootstrapLifelineLogicalName,
	})
	if err == nil {
		record = append(record, '\n')
		err = fsatomic.WriteFileDurable(filepath.Join(linkDir, bootstrapLifelineSnapshotBase), record, 0o600)
	}
	if err != nil {
		slog.Warn("bootstrap exit: could not persist absent management lifeline snapshot; "+
			"first-commit rollback across restart may be degraded", "path",
			filepath.Join(linkDir, bootstrapLifelineSnapshotBase), "err", err, "issue", "#14993")
	}
}
func (d *Daemon) clearBootstrapLifelineNetwork() {
	// Live-path only: drop the in-memory snapshot. The durable file is
	// #12155's (it clears its own debt on teardown completion); removing it
	// here would steal #12155's crash-recovery evidence on confirm.
	d.bootstrapLifelineMu.Lock()
	d.bootstrapLifelineCaptured = false
	d.bootstrapLifelinePresent = false
	d.bootstrapLifelineNetwork = nil
	d.bootstrapLifelineKernelName = ""
	d.bootstrapLifelineLogicalName = ""
	d.bootstrapLifelineMu.Unlock()
}

// loadBootstrapLifelineSnapshot reads the durable pre-takeover record
// (#12155). Tri-state (N2): absent (ok=false, unreadable=false) vs
// present-but-bad (ok=false, unreadable=true: oversized, FIFO/symlink,
// corrupt JSON) vs decoded (ok=true, with present reporting whether a
// pre-takeover file existed — #14993). The caller must treat
// present-but-bad as DEGRADED with debt retained — never as the
// absent-absent no-op. The abandoned-generation binding is checked by
// the caller against FirstCommitTeardownGeneration. No mutex: callers
// hold it or are single-threaded boot; never call into the Store here
// (NEW-MAJOR-A).
func (d *Daemon) loadBootstrapLifelineSnapshot() (snapshot []byte, generation string, present, ok, unreadable bool) {
	// Bounded read (#8597 census): a FIFO here must not hang boot nor a
	// runaway file exhaust memory.
	data, err := readBootstrapLifelineSnapshot(filepath.Join(linkDir, bootstrapLifelineSnapshotBase))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", false, false, false
		}
		return nil, "", false, false, true
	}
	if len(data) > maxBootstrapLifelineSnapshotSize {
		return nil, "", false, false, true
	}
	var record bootstrapLifelineSnapshotRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, "", false, false, true
	}
	return append([]byte(nil), record.Network...), record.Generation, record.Present, true, false
}

// loadBootstrapLifelineRename reads ONLY the #16675 rename pair from the
// durable record, with the same generation binding the .network restore
// enforces. Returns ("","") when there is no authentic pair: no record,
// unreadable record, generation mismatch, or a half-empty pair. The
// caller treats "" as "no rename to undo" — but see
// restoreBootstrapLifelineRename, which fails closed when a takeover
// .link for the lifeline exists without provenance.
func (d *Daemon) loadBootstrapLifelineRename() (kernel, logical string) {
	if d.store == nil || !d.store.FirstCommitTeardownOwed() {
		return "", ""
	}
	data, err := readBootstrapLifelineSnapshot(filepath.Join(linkDir, bootstrapLifelineSnapshotBase))
	if err != nil || len(data) > maxBootstrapLifelineSnapshotSize {
		return "", ""
	}
	var record bootstrapLifelineSnapshotRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return "", ""
	}
	if record.Generation == "" || record.Generation != d.store.FirstCommitTeardownGeneration() {
		return "", ""
	}
	if record.LifelineKernelName == "" || record.LifelineLogicalName == "" ||
		record.LifelineKernelName == record.LifelineLogicalName {
		return "", ""
	}
	return record.LifelineKernelName, record.LifelineLogicalName
}

// bootstrapLifelineRenameForTeardown resolves the rename pair for this
// teardown: the in-memory capture on the live path, else the durable
// generation-bound record on the across-restart path.
func (d *Daemon) bootstrapLifelineRenameForTeardown() (kernel, logical string) {
	if k, l := d.bootstrapLifelineRenamePair(); k != "" && l != "" && k != l {
		return k, l
	}
	// Adopt the durable pair into memory so a retry in this process (and
	// the confirmed-clear) sees the same provenance.
	k, l := d.loadBootstrapLifelineRename()
	if k != "" {
		d.bootstrapLifelineMu.Lock()
		if d.bootstrapLifelineKernelName == "" {
			d.bootstrapLifelineKernelName, d.bootstrapLifelineLogicalName = k, l
		}
		k2, l2 := d.bootstrapLifelineKernelName, d.bootstrapLifelineLogicalName
		d.bootstrapLifelineMu.Unlock()
		return k2, l2
	}
	return "", ""
}

// lifelineLinkOriginal parses the OriginalName= recorded in the takeover
// .link for logical. Returns "" when the file is absent, unreadable, or
// records no OriginalName (MAC-form / name-only claims carry none).
func lifelineLinkOriginal(logical string) string {
	data, err := os.ReadFile(filepath.Join(linkDir, linkPrefix+logical+".link"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "OriginalName=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "OriginalName="))
		}
	}
	return ""
}

// restoreBootstrapLifelineRename undoes the bootstrap-exit positional
// rename of a non-fxp0 lifeline (#16675): it removes the takeover .link
// and renames the NIC back to its pre-takeover kernel name so the host's
// own kernel-name-keyed config (netplan `[Match] Name=enp6s0`, ifupdown,
// networkd Name=) matches again.
//
// Provenance is fail-closed. The pair must come from the captured record
// (memory or generation-bound durable), AND the takeover .link — when
// present — must record OriginalName=<kernel>. A .link that disagrees,
// or a logical .link present with no captured pair at all, is reported
// as an error with BOTH the file and the live name retained: guessing a
// rename-back target is how a rollback strands a different NIC.
//
// Ordering (load-bearing): rename FIRST, remove the .link only after the
// rename succeeds. Removing the file first and then failing the rename
// would leave the NIC under its logical name with no record of its
// kernel name — the exact lockout being fixed, minus the evidence.
//
// Returns (renamed, err). renamed is true when a live rename ran (the
// caller then owes a networkctl reload in addition to any .network one).
func (d *Daemon) restoreBootstrapLifelineRename() (bool, error) {
	kernel, logical := d.bootstrapLifelineRenameForTeardown()
	linkName := ""
	if logical != "" {
		linkName = linkPrefix + logical + ".link"
	}
	if kernel == "" || logical == "" {
		// No captured pair. If the lifeline record still resolves and a
		// takeover .link claims that logical name with a kernel
		// OriginalName, that is a rename we cannot provenance — fail
		// closed rather than silently keeping it. We can only see this
		// shape when the live name is logical; check every candidate
		// .link whose OriginalName is a non-logical kernel name and
		// whose target resolves as the lifeline would be a guess, so
		// the check is scoped: a .link is suspect only when the
		// lifeline currently wears its Name=. resolveLifelineCurrentName
		// reads sysfs; in unit tests with no record it returns false
		// and this stays a no-op (the index-0 cells' premise).
		if cur, ok := resolveLifelineCurrentNameFn(); ok && isPositionalLogicalName(cur) && cur != defaultMgmtInterface {
			if orig := lifelineLinkOriginal(cur); orig != "" && orig != cur {
				return false, fmt.Errorf(
					"bootstrap rollback: lifeline wears %s claimed by %s (OriginalName=%s) but no captured pre-takeover rename provenance is available; retaining the .link and the live name",
					cur, linkPrefix+cur+".link", orig)
			}
		}
		return false, nil
	}
	// A captured pair exists. Verify the takeover .link agrees when it
	// is present; a mismatch means the file on disk is not the rename
	// we recorded (replaced, or another NIC's claim) — retain and fail.
	linkPath := filepath.Join(linkDir, linkName)
	if _, err := os.Stat(linkPath); err == nil {
		if orig := lifelineLinkOriginal(logical); orig != kernel {
			return false, fmt.Errorf(
				"bootstrap rollback: takeover .link %s records OriginalName=%q, want captured kernel name %q; retaining the .link and the live name",
				linkName, orig, kernel)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("bootstrap rollback: inspect takeover .link %s: %w", linkName, err)
	}
	renamed := false
	cur, curOK := resolveLifelineCurrentNameFn()
	switch {
	case curOK && cur == logical:
		if err := renameInterfaceFn(logical, kernel); err != nil {
			return false, fmt.Errorf("bootstrap rollback: rename lifeline %s -> %s: %w", logical, kernel, err)
		}
		renamed = true
		slog.Info("bootstrap rollback: renamed lifeline back to its pre-takeover kernel name",
			"from", logical, "to", kernel, "issue", "#16675")
	case curOK && cur == kernel:
		// Already back (a prior teardown renamed it, or it never took
		// effect). Fall through to reclaim the .link idempotently.
	case curOK:
		// The lifeline resolves to some other name entirely — not the
		// logical we recorded and not its kernel name. Renaming that
		// device, or deleting the .link, on this evidence could strand
		// a different NIC. Retain both and fail closed.
		return false, fmt.Errorf(
			"bootstrap rollback: lifeline currently wears %q, neither the captured logical %q nor its kernel name %q; retaining the .link and the live name",
			cur, logical, kernel)
	default:
		// Lifeline device not present (removed, or unresolvable in a
		// unit sandbox). No live rename is possible; reclaiming the
		// .link is still correct — it must not re-claim the name at
		// the next boot — and is not an error.
		slog.Info("bootstrap rollback: lifeline device not present; reclaiming its takeover .link without a live rename",
			"logical", logical, "kernel", kernel, "issue", "#16675")
	}
	// Rename succeeded (or was unnecessary): now reclaim the .link.
	if err := os.Remove(linkPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return renamed, fmt.Errorf("bootstrap rollback: remove takeover .link %s: %w", linkName, err)
	}
	slog.Info("bootstrap rollback: removed takeover lifeline .link",
		"file", linkName, "issue", "#16675")
	return renamed, nil
}

// restoreBootstrapLifelineNetwork restores exact pre-takeover bytes: from the
// in-memory snapshot on the live path (#12154), or from the durable record
// when teardown debt is owed and this process has no snapshot (#12155 boot
// consumer). A durable rollback requires a generation-matched snapshot; a
// marker-shaped file regenerated from abandoned runtime addresses is not
// provenance. Unknown files are never removed without a captured absent-state.
func (d *Daemon) restoreBootstrapLifelineNetwork() (bool, error) {
	name := linkPrefix + "fxp0.network"
	path := filepath.Join(linkDir, name)
	d.bootstrapLifelineMu.Lock()
	snapshot := d.bootstrapLifelineNetwork
	captured, present := d.bootstrapLifelineCaptured, d.bootstrapLifelinePresent
	generation := d.bootstrapLifelineGeneration
	d.bootstrapLifelineMu.Unlock()
	content, err := os.ReadFile(path)
	// #12155: a crash between PromoteRollback and the daemon teardown loses
	// the in-memory snapshot. Recover the durable record when teardown debt
	// is owed. The Store read happens OUTSIDE bootstrapLifelineMu
	// (NEW-MAJOR-A: the confirm hook takes this mutex under Store.mu).
	// N2: a present-but-unreadable record (oversized, FIFO/symlink, corrupt
	// JSON) is evidence a lifeline existed — DEGRADED with debt retained,
	// never the absent-absent no-op.
	unreadableRecord := false
	if !captured && d.store != nil && d.store.FirstCommitTeardownOwed() {
		if loaded, loadedGen, loadedPresent, ok, bad := d.loadBootstrapLifelineSnapshot(); ok {
			snapshot, generation, captured, present = loaded, loadedGen, true, loadedPresent
		} else if bad {
			unreadableRecord = true
		}
	}
	if unreadableRecord {
		slog.Warn("bootstrap rollback: pre-takeover lifeline snapshot is present but unreadable; "+
			"retaining teardown debt", "file", bootstrapLifelineSnapshotBase, "issue", "#12155")
		return false, fmt.Errorf("%s: pre-takeover lifeline snapshot present but unreadable; teardown debt retained",
			name)
	}
	if captured && d.store != nil && d.store.FirstCommitTeardownOwed() {
		// #14993: a captured ABSENCE is authentic provenance too — it
		// carries no bytes and no marker, only the generation binding.
		// Old-format records (no Present field) with empty Network fail
		// this gate exactly as before.
		if generation == "" || generation != d.store.FirstCommitTeardownGeneration() ||
			(present && (len(snapshot) == 0 || !isBootstrapLifelineNetwork(snapshot))) ||
			(!present && len(snapshot) != 0) {
			return false, fmt.Errorf("%s has no authentic pre-takeover snapshot for the abandoned generation",
				name)
		}
	}
	if !captured {
		if err == nil && isBootstrapLifelineNetwork(content) {
			return false, nil
		}
		// #12155 absent-absent rule (debt-owed boots only): no snapshot
		// anywhere (memory, durable, or live file) means no lifeline was
		// ever taken over — a no-op, not DEGRADED. The live path keeps
		// #12154's fail-closed read error (a restart inside the window
		// with no snapshot and no file reports DEGRADED).
		if errors.Is(err, os.ErrNotExist) && d.store != nil && d.store.FirstCommitTeardownOwed() {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("%s: read management lifeline: %w", name, err)
		}
		return false, fmt.Errorf(
			"%s no longer contains a bootstrap lifeline and no pre-takeover snapshot is available",
			name)
	}
	if !present {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("%s: inspect pre-takeover-absent network: %w", name, err)
		}
		if !bytes.HasPrefix(content, []byte("# Managed by xpfd — do not edit\n")) {
			return false, fmt.Errorf(
				"%s appeared after a pre-takeover-absent snapshot but is not xpfd-generated; preserving unknown content",
				name)
		}
		if err := os.Remove(path); err != nil {
			return false, fmt.Errorf("%s: remove post-takeover network: %w", name, err)
		}
		return true, nil
	}
	if err == nil && bytes.Equal(content, snapshot) {
		return false, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("%s: inspect management network: %w", name, err)
	}
	if err := fsatomic.WriteFileAtomic(path, snapshot, 0644); err != nil {
		return false, fmt.Errorf("%s: restore management lifeline: %w", name, err)
	}
	return true, nil
}

func (d *Daemon) clearBootstrapLifelineSnapshot(generation string) {
	path := filepath.Join(linkDir, bootstrapLifelineSnapshotBase)
	data, err := readBootstrapLifelineSnapshot(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		slog.Warn("could not read cleared bootstrap lifeline snapshot",
			"path", path, "err", err, "issue", "#12155")
		return
	}
	var record bootstrapLifelineSnapshotRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Generation != generation {
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("could not remove cleared bootstrap lifeline snapshot",
			"path", path, "err", err, "issue", "#12155")
		return
	}
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil {
		slog.Warn("could not durably remove bootstrap lifeline snapshot",
			"path", path, "err", err, "issue", "#12155")
		return
	}
	d.bootstrapLifelineNetwork = nil
	d.bootstrapLifelineGeneration = ""
	d.bootstrapLifelineKernelName = ""
	d.bootstrapLifelineLogicalName = ""
}

func (d *Daemon) runBootstrapTeardownSteps(restoreLifeline bool) []bootstrapTeardownStep {
	steps := make([]bootstrapTeardownStep, 0, 3)

	// (2) Retire xpf-written takeover .network files. Keep .link files so names
	// remain stable; the fxp0 file is handled separately by content, not name.
	// The one exception is the non-fxp0 lifeline's takeover .link, undone by
	// the #16675 rename restore below (first-commit path only).
	lifelineNetwork := linkPrefix + "fxp0.network"
	networkReloadOwed := d.firstCommitNetworkdReloadOwed
	entries, err := os.ReadDir(linkDir)
	networkChanged := false
	if err != nil {
		// The directory could not be enumerated — the takeover .network files
		// (if any) are NOT removed. Surface it, but still attempt to restore the
		// management lifeline below.
		steps = append(steps, bootstrapTeardownStep{name: "read link dir", err: err})
	} else {
		var rmErrs []error
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, linkPrefix) ||
				strings.HasSuffix(name, ".link") ||
				name == lifelineNetwork ||
				!strings.HasSuffix(name, ".network") {
				continue
			}
			if err := os.Remove(filepath.Join(linkDir, name)); err != nil {
				// Best-effort: record the failure and keep removing the rest.
				rmErrs = append(rmErrs, fmt.Errorf("%s: %w", name, err))
				continue
			}
			networkChanged = true
			slog.Info("bootstrap rollback: removed takeover .network file", "file", name)
		}
		if len(rmErrs) > 0 {
			steps = append(steps, bootstrapTeardownStep{
				name: "remove takeover .network files",
				err:  errors.Join(rmErrs...),
			})
		}
	}

	if restoreLifeline {
		if changed, err := d.restoreBootstrapLifelineNetwork(); err != nil {
			steps = append(steps, bootstrapTeardownStep{
				name: "restore management lifeline network",
				err:  err,
			})
		} else if changed {
			networkChanged = true
			slog.Info("bootstrap rollback: restored management lifeline network",
				"file", lifelineNetwork)
		}
		// #16675: undo the bootstrap-exit rename of a non-fxp0 lifeline.
		// Runs only on this first-commit path — restoreLifeline is the
		// recorded confirmPrevFirst scope (#12154), so a later safe-state
		// entry on a committed box never renames a NIC back.
		if renamed, err := d.restoreBootstrapLifelineRename(); err != nil {
			steps = append(steps, bootstrapTeardownStep{
				name: "restore lifeline kernel name",
				err:  err,
			})
		} else if renamed {
			networkChanged = true
		}
	}
	// Reload after removing or restoring any networkd file; a lifeline-only
	// restoration also changes networkd's desired state.
	// The debt is separate from the filesystem scan: a previous reload can
	// fail after the removed files are already gone, so retry it on the next
	// teardown pass even when networkChanged is false.
	if networkChanged {
		networkReloadOwed = true
	}
	if networkReloadOwed {
		if err := networkctlReload(); err != nil {
			d.firstCommitNetworkdReloadOwed = true
			steps = append(steps, bootstrapTeardownStep{name: "networkctl reload", err: err})
		} else {
			d.firstCommitNetworkdReloadOwed = false
		}
	}

	// (3) Clear the FRR managed section.
	if d.frr != nil {
		if err := d.frr.Clear(); err != nil {
			steps = append(steps, bootstrapTeardownStep{name: "clear FRR managed section", err: err})
		}
	}

	// Close before teardown: Teardown may destroy the final XDP link and no
	// daemon-side writer is complete enough to make that ordering safe. The
	// periodic census still covers unknown kernel changes, but rollback should
	// not deliberately enter the teardown with transit open.
	d.markDataplaneNotArmed("bootstrap rollback",
		"dataplane detaching; first commit confirmed timed out")

	// (4) Detach the dataplane (inverse of Start). Keep the object so a later
	// confirmed commit re-arms it via runBootstrapExitStartup.
	if rt := d.dataplane(); rt != nil {
		if err := rt.Teardown(); err != nil {
			steps = append(steps, bootstrapTeardownStep{name: "dataplane teardown", err: err})
		}
	}

	return steps
}

// clearFRRForFailClosedBoot is the #1993 fail-closed boot refinement: on a
// boot where the previously-committed config is unavailable for takeover or a
// valid never-committed rescue fallback is selected (#11802), the last-good
// `! BEGIN/END BPFRX MANAGED CONFIG` section is stored in persisted `frr.conf`
// and read by the independent FRR systemd service. If the node has NO live
// dataplane attachments, it starts from that file, forms BGP/OSPF/IS-IS
// peerings, and re-advertises last-good prefixes for routes this unarmed
// node cannot forward — a silent transit blackhole. Clearing ONLY the managed
// section drops those peerings so upstream/peers fail over to the HA partner
// instead of routing transit into a blackhole.
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
// Scope: gated on failClosedLoad AND on LIVE FORWARDING. The restart-preserve
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
// A fresh/no-config bootstrap with NO valid saved rescue (which has no
// last-good managed section) and every NORMAL boot are byte-identical to before.
// A selected valid rescue is failClosedLoad and intentionally runs these
// fail-closed safeguards, although the rescue itself remains uninstalled.
// The d.frr != nil guard tolerates NoDataplane daemons (FRR is constructed
// only inside the !NoDataplane manager-init block).
//
// A degraded reload (ErrFRRReloadDegraded, e.g. frr-reload.py unavailable) is
// LOGGED, not fatal: Clear() has already written the empty managed section to
// disk (so a later FRR restart converges) and the degraded-retry loop
// re-attempts. Management reachability beats a perfectly-clean FRR reload, so
// boot must proceed regardless.
func (d *Daemon) clearFRRForFailClosedBoot(failClosedLoad bool) {
	if !failClosedLoad || d.frr == nil {
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
// (refuse takeover, stay bootstrap, console-only). The default-route interface
// is "the NIC the operator reaches the box on" in the common single-homed
// case. A multi-homed / policy-routed mgmt box is the residual that requires
// manual console-side recovery; the intended `system management-interface`
// override cannot currently be set in config mode because its parser grammar
// is deferred.
//
// detectLifelineInterfaceFn / enumeratePCINICsFn are injectable seams for the
// world-reading half of setupBootstrapLifeline, so the #7114 selection wiring
// is testable without a live netlink/sysfs stack. Production leaves them
// pointing at the real detectors.
//
// networkdActiveFn is injectable so the bootstrap lifeline refuses to mutate
// an interface unless systemd-networkd is active.
var (
	detectLifelineInterfaceFn = detectLifelineInterface
	enumeratePCINICsFn        = enumeratePCINICs
	networkdActiveFn          = systemdNetworkdActive
)

// systemdNetworkdActive reports whether systemd-networkd is running.
func systemdNetworkdActive() error {
	output, err := execCommand("systemctl", "is-active", "systemd-networkd.service")
	state := strings.TrimSpace(output)
	if err != nil {
		return fmt.Errorf("systemd-networkd is not active (state %q): %w", state, err)
	}
	if state != "active" {
		return fmt.Errorf("systemd-networkd is not active (state %q)", state)
	}
	return nil
}

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
// isDefaultRoute reports whether r is a true default route: a nil
// destination, or an unspecified destination with prefix length 0
// (0.0.0.0/0 or ::/0). A split-default route such as 0.0.0.0/1 or ::/1
// carries an unspecified address but a non-zero mask, so it is NOT a
// default route (#15220). Checking only IsUnspecified admitted such
// tunnel routes as the management lifeline.
func isDefaultRoute(r *netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	if len(r.Dst.IP) == 0 {
		return true
	}
	if !r.Dst.IP.IsUnspecified() {
		return false
	}
	ones, _ := r.Dst.Mask.Size()
	return ones == 0
}

func detectLifelineInterface() (name string, ok bool, err error) {
	var firstErr error
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
			if !isDefaultRoute(r) {
				continue
			}
			if r.LinkIndex <= 0 {
				continue
			}
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
	return "", false, nil
}

// pciAddrForInterface resolves the PCI bus address + MAC for a kernel
// interface name via sysfs (the same source enumeratePCINICs uses). A
// non-PCI NIC (USB behind a host controller, virtio-mmio, bond, VLAN
// sub-interface, or other paravirtual /
// overlay device with no `/sys/class/net/<name>/device` PCI symlink) still
// yields a MAC-only record — PCI resolution failing must NOT short-circuit
// the MAC lookup, per the lifelineRecord format's own documented contract
// ("MAC (tiebreaker for non-PCI NICs)", #4815). Reports not-found only when
// NEITHER identity can be resolved.
func pciAddrForInterface(name string) (lifelineRecord, bool) {
	var pciAddr string
	if devReal, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", name, "device")); err == nil {
		pciAddr = netname.PCIAddrFromDevicePath(devReal)
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
// union of the `system management-interface` field (when internally set), the
// default fxp0 (unless narrowed off by an explicit non-fxp0 field), and the
// lifeline-recorded interface resolved from its PCI address to the current
// name. Members are NEVER marked Unmanaged / always-down / address-stripped
// by the reconcile path, regardless of the active config (config-independent;
// invariant 3).
//
// mgmtLeaf is the configured `system management-interface` value ("" when
// unset). An explicit non-fxp0 value narrows fxp0 out of the auto-protection.
// The field has no config-mode parser grammar yet, so operators cannot
// currently use this behavior to repurpose fxp0 as a revenue port.
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
	// management-interface field removes fxp0 from auto-protection so it may
	// be repurposed. Config-mode parser grammar is deferred. It must apply to
	// both the leaf/default contribution and the lifeline-record union: the
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
// full rename loop when the daemon boots into bootstrap mode. It first refuses
// all interface changes unless systemd-networkd is active, then:
//
//  1. detects the management lifeline NIC (default-route interface),
//  2. records its PCI identity to /etc/xpf/lifeline-interface so the
//     protected set survives rename/restart/rollback,
//  3. if (and only if) that NIC is enumeration index 0 — i.e. it WOULD
//     become fxp0 in a normal rename — renames JUST that NIC to fxp0 and
//     writes a lifeline-aware bootstrap .network that snapshots its current
//     addressing (DHCP or static) so the link cycle restores reachability,
//  4. otherwise touches NO interface (refuse takeover, stay reachable on the
//     un-renamed kernel name) and logs loudly. For a higher-index PCI NIC, it
//     directs the operator to rewire it to index 0; for a non-PCI management
//     route, it directs the operator to move that route onto a PCI NIC. Restart
//     xpfd or reboot after the change. The `system management-interface`
//     config-mode grammar is deferred and is not a supported remedy.
//
// No other NIC is renamed, cycled, or reconfigured in bootstrap mode.
//
// #7114 amends step 1: when there is no default route AND this host is a
// factory boot of the xpf appliance image (isApplianceFactoryBoot), the first
// enumerated NIC is selected instead of refusing. Steps 2-4 are unchanged and
// run identically for either provenance.
func (d *Daemon) setupBootstrapLifeline() {
	if err := networkdActiveFn(); err != nil {
		slog.Warn("bootstrap lifeline: systemd-networkd is not active; refusing all management "+
			"interface changes and staying in bootstrap",
			"err", err)
		return
	}
	// but proceed regardless — bootstrap is explicit recovery and the
	// management lifeline takes precedence over the barrier (the #1960 order).
	// A failed reinstall is already loud inside the ensure call.
	var bootstrapCfg *config.Config
	if d.store != nil {
		bootstrapCfg = d.store.ActiveConfig()
	}
	_ = ensureEarlyInputProtectionForNaming(bootstrapCfg)

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

	// #16671: on a committed box the main-table default route is the WAN
	// (fxp0 lives in vrf-mgmt, which networkd renders without a main-table
	// gateway), so route detection must NEVER overwrite the verified
	// persisted lifeline record — nor rename the WAN to fxp0. Only a
	// never-committed box may learn its lifeline from route detection.
	everCommitted := d.store != nil && d.store.EverCommitted()
	if everCommitted {
		slog.Warn("bootstrap lifeline: box has committed before; refusing to overwrite the "+
			"persisted lifeline record or rename from main-table default-route detection "+
			"(on a committed xpf box the main-table default is the WAN, not management)",
			"interface", lifeline)
		return
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
	index0Name, index0PCI := "", ""
	if len(nics) > 0 {
		// The warning identifies the currently first PCI device so an operator
		// can distinguish it from the management path without reconstructing
		// the virtio-first, then PCI-address and hardware-port enumeration order.
		index0Name, index0PCI = nics[0].name, nics[0].busAddr
	}
	if len(nics) == 0 {
		slog.Warn("bootstrap lifeline: no PCI NIC enumerated; this can occur on a "+
			"VMBus-only host. No PCI NIC can be selected to become fxp0. Refusing "+
			"to rename/cycle any interface; staying in bootstrap with NO interface "+
			"changes. Reach the host via its console and attach/configure a PCI NIC "+
			"for management before restarting xpfd or rebooting. The `system "+
			"management-interface` leaf is not implemented in config mode and would "+
			"be silently ignored.",
			"interface", lifeline, "enum_index", idx)
		return
	}
	if idx == -1 {
		slog.Warn("bootstrap lifeline: management default-route interface is not present in "+
			"the PCI NIC enumeration (common for a bond, VLAN, or bridge), so rewiring that "+
			"interface cannot make it enumeration index 0. From the console, move the "+
			"management default route and its addressing onto the NIC identified by "+
			"index0_interface and index0_pci. Restart xpfd or reboot after the change. "+
			"The `system management-interface` leaf is not implemented in config mode "+
			"and would be silently ignored.",
			"interface", lifeline, "enum_index", idx,
			"index0_interface", index0Name, "index0_pci", index0PCI)
		return
	}
	if idx != 0 {
		slog.Warn("bootstrap lifeline: management default-route NIC is NOT enumeration index 0, "+
			"so it would not become fxp0. Refusing to rename/cycle any interface; staying in "+
			"bootstrap. From the console, move the management default route and its addressing "+
			"onto the NIC identified by index0_interface and index0_pci. Virtio-first "+
			"enumeration keeps its virtio NIC at index 0, so recabling cannot make the PCI "+
			"management NIC index 0 and recabling alone can strand management. Alternatively, from "+
			"the console, enter `set chassis device-map interface fxp0 pci <mgmt PCI>` and then "+
			"`commit confirmed`. Restart xpfd or reboot after the change. The `system "+
			"management-interface` leaf is not implemented in config mode and would be silently "+
			"ignored.",
			"interface", lifeline, "enum_index", idx,
			"index0_interface", index0Name, "index0_pci", index0PCI)
		return
	}

	// #16682: a FAILED fxp0 .network write refuses here too — before the
	// .link write, the rename and the reload, before anything further is
	// mutated. Until now the writer laundered that failure into
	// (false, nil) (the #5842 shape), so a storage fault
	// (ENOSPC/EROFS/EIO) left no fxp0 .network for the renamed NIC and
	// the rename's link cycle flushed the default route on a bootstrap
	// box with no committed config to roll back to: console-only on a
	// storage fault, when the documented posture is to change nothing.
	// The caller log covers BOTH error sources (observation and write);
	// both mean the same thing — the .network cannot be produced
	// correctly, so nothing may proceed on the strength of it.

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
		slog.Error("bootstrap lifeline: could not observe the management NIC's addressing or could not "+
			"write the bootstrap fxp0 .network, so the .network cannot be produced correctly. "+
			"Refusing to rename/cycle any interface; staying in bootstrap with NO interface "+
			"changes so management keeps its current name and addressing. Reach the box via its "+
			"console and 'commit confirmed' a config.",
			"interface", lifeline, "err", err)
		return
	}

	// Rename just this one NIC to fxp0 (writes the .link + renames). A
	// 10-xpf .link with Name=<lifeline> and no OriginalName= identifies a
	// logical current name: when the lifeline is already fxp0 that file is
	// retained rather than persisted as OriginalName=; when it must rename,
	// both the own link and any stale fxp0.link are checked by MAC ownership
	// before deletion, and the required rename still runs (#12156/F1).
	original, originalOK := positionalOriginalNameFor(lifeline, defaultMgmtInterface)
	if !originalOK {
		if lifeline == defaultMgmtInterface {
			switch verdict := verifyRetainedMACLink(lifeline); verdict {
			case retainedMACMismatch, retainedMACUnreadable:
				name := linkPrefix + lifeline + ".link"
				if err := neutralizeResurrectableLink(name); err != nil {
					slog.Error("bootstrap: retained MAC-form .link "+verdict.reason()+
						"; could not remove the file, so it may still claim fxp0 on a later boot",
						"interface", lifeline, "file", name, "err", err)
				} else {
					slog.Error("bootstrap: retained MAC-form .link "+verdict.reason()+
						"; removed the file so it cannot claim fxp0 on a later boot",
						"interface", lifeline)
				}
			}
		}
		logUnknownOriginalLinkSkip("bootstrap", lifeline, defaultMgmtInterface)
		if lifeline != defaultMgmtInterface {
			// MAJOR-1 (same fail-open as the positional path): the lifeline
			// is renaming to fxp0 without a verifiable kernel name. Its own
			// claims could each resurrect an identity next boot; remove claims
			// belonging to this NIC and preserve foreign or unverifiable MACs.
			// No error channel here: the log IS the signal (ERROR, not Info).
			neutralized := true
			for _, name := range []string{linkPrefix + lifeline + ".link", linkPrefix + defaultMgmtInterface + ".link"} {
				if _, err := neutralizeResurrectableLinkForNIC(name, lifeline); err != nil {
					neutralized = false
					slog.Error("bootstrap: failed to neutralize resurrectable .link",
						"file", name, "err", err)
				}
			}
			if neutralized {
				slog.Error("bootstrap: unknown-original lifeline renamed to fxp0 without a "+
					"verifiable kernel name; neutralized retained .link claims (preserving "+
					"claims with a foreign or unverifiable MAC) so the next boot falls back to kernel names",
					"from", lifeline)
			}
		}
	} else if _, err := writeLinkFile(defaultMgmtInterface, original); err != nil {
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
// reachability. A lifeline with no static address in either family — the
// address-less appliance factory boot, or DHCP-managed in every present family
// — gets the historical plain-DHCP .network (matching writeBootstrapFxp0Network)
// so a factory-box restart re-derives byte-identical content and the
// existing==content gate below skips the rewrite (and the networkctl reload
// reconfigure). A lifeline with a static address in some family gets that
// family's Address=/Gateway= lines plus a DHCP= directive for any other family
// classified as DHCP-managed by the finite-lifetime heuristic.
// Returns true if the file changed. A write FAILURE is returned as an
// error (#16682): (false, nil) already means "already correct", so
// laundering a failed write into it left the caller unable to distinguish
// a converged boot from one whose fxp0 .network never landed — and the
// caller renames (cycles) the management NIC on the strength of it.
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
	static4 := len(v4) > 0 && !snap.dhcpV4
	static6 := len(v6) > 0 && !snap.dhcpV6
	if !static4 && !static6 {
		content = bootstrapLifelineNetworkMarker + " (DHCP)\n" +
			"[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nUseDNS=yes\nUseRoutes=yes\n"
	} else {
		var b strings.Builder
		b.WriteString(bootstrapLifelineNetworkMarker + " (address snapshot)\n")
		b.WriteString("[Match]\nName=fxp0\n\n[Network]\n")
		// Both-dynamic routes through the factory arm above (static4 and
		// static6 are both false there): inside this branch at most one
		// dhcp flag can be true (GLM round-1 F1), so no DHCP=yes case.
		switch {
		case snap.dhcpV4:
			b.WriteString("DHCP=ipv4\n")
		case snap.dhcpV6:
			b.WriteString("DHCP=ipv6\n")
		}
		if !snap.dhcpV4 {
			for _, a := range v4 {
				fmt.Fprintf(&b, "Address=%s\n", a)
			}
			if gw4 != "" {
				fmt.Fprintf(&b, "Gateway=%s\n", gw4)
			}
		}
		if !snap.dhcpV6 {
			for _, a := range v6 {
				fmt.Fprintf(&b, "Address=%s\n", a)
			}
			if gw6 != "" {
				fmt.Fprintf(&b, "Gateway=%s\n", gw6)
			}
		}
		if snap.dhcpV4 {
			b.WriteString("\n[DHCPv4]\nUseDNS=yes\nUseRoutes=yes\n")
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
		return false, fmt.Errorf("write fxp0 .network %s: %w", path, err)
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
	// dhcpV4 / dhcpV6 report a global address with a FINITE valid lifetime in
	// that family, the existing heuristic for a DHCP-managed address. Keeping
	// the decision per-family prevents a finite IPv6 SLAAC lifetime from
	// suppressing a static IPv4 address and gateway in the generated networkd
	// configuration.
	dhcpV4, dhcpV6 bool
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
		// typically permanent (ValidLft == 0xffffffff / forever). Record the
		// heuristic for the matching family only: IPv6 SLAAC addresses also
		// have finite lifetimes, but must not turn static IPv4 into DHCP.
		dhcpManaged := addrs[i].ValidLft > 0 && addrs[i].ValidLft != 0xffffffff
		if ip.IP.To4() != nil {
			snap.v4 = append(snap.v4, ip.String())
			if dhcpManaged {
				snap.dhcpV4 = true
			}
		} else {
			snap.v6 = append(snap.v6, ip.String())
			if dhcpManaged {
				snap.dhcpV6 = true
			}
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
			if !isDefaultRoute(r) {
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
