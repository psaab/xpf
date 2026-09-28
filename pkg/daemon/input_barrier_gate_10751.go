package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"golang.org/x/sys/unix"
)

// ensureEarlyInputProtectionForNaming verifies the #10751 pre-networkd input
// guard is present before xpfd performs link activation. Interface renames
// bring links up (renameInterface ends with LinkSetUp), which makes kernel
// IPv6 link-locals reachable — the xpf-input-closed unit Requires xpfd so a
// failed barrier install blocks the daemon under systemd, and this gate covers
// direct starts (manual runs, raw-binary harnesses) that bypass unit
// dependencies. Returns true to proceed with activation. All installs use the
// lifeline-admitting variant so any later retention admits recovery.
//
//   - present → converge to the lifeline variant (best-effort) and return
//     true; the standing table still protects if the converge fails.
//   - absent + variant install succeeds → true (self-healed).
//   - absent + install fails + nftables unusable → true with a loud warning
//     (unenforceable platform — never brick boot where no enforcement is
//     possible, matching the pre-barrier posture).
//   - absent + install fails + nftables usable → false (fail closed).
//
// A presence-readback error warns and proceeds: the gate blocks on KNOWN-
// absent protection, not on observability failure (the subsequent barrier
// operations fail loudly on their own).
func ensureEarlyInputProtectionForNaming(cfg *config.Config) bool {
	present, err := nftInstaller.EarlyInputBarrierPresent()
	if err != nil {
		slog.Warn("cannot attest early host-input barrier before link activation; proceeding",
			"err", tagNftInstallErr(err))
		return true
	}
	lifelines := resolveEarlyInputGuardLifelines(cfg)
	if !present {
		// Bind to a named var: the refusal log below sits outside the
		// if/else-if chain, so an if-scoped shadow would read the outer
		// (nil-at-this-point) err and log err=<nil> on a real failure.
		installErr := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(lifelines)
		if installErr == nil {
			slog.Warn("early host-input barrier missing before link activation; installed lifeline guard",
				"lifelines", lifelines)
			return true
		} else if nftProbeAvailable() != nil {
			slog.Warn("early host-input barrier missing and nftables is unusable; proceeding without input protection",
				"err", tagNftInstallErr(installErr))
			return true
		}
		slog.Error("early host-input barrier missing and guard install failed; refusing link activation",
			"lifelines", lifelines, "err", tagNftInstallErr(installErr))
		return false
	}
	// Present (global unit form or an older guard): converge to the current
	// lifeline variant so any later retention admits recovery. Best-effort:
	// the standing table still protects on failure; the first apply retries.
	if err := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(lifelines); err != nil {
		slog.Warn("cannot converge early barrier to lifeline guard before link activation; proceeding with standing table",
			"lifelines", lifelines, "err", tagNftInstallErr(err))
	}
	return true
}

// lifelineRecordNameFn resolves the persisted lifeline record to its current
// kernel name. A package var so resolver tests can pin record-present/absent
// without sysfs.
var lifelineRecordNameFn = resolveLifelineCurrentName

// resolveEarlyInputGuardLifelines computes the iifname admit set for the
// pre-handoff lifeline guard, from most- to least-verified identity:
//
//   - Canonical defaults: em0, fab0, fab1, the vrf-mgmt master, and fxp0
//     unless an explicit non-fxp0 management leaf narrows it out (OQ-D: a
//     repurposed fxp0 is revenue, not management). vrf-mgmt is admitted
//     because Linux VRF receive switches skb->dev to the master for
//     ordinary local delivery on enslaved interfaces — slave names alone
//     need not match (B4); both master and slaves stay listed so either
//     observed path matches.
//   - Verified protected set (B6): the persisted lifeline record plus the
//     explicit management-interface leaf, via the same pure core the fence
//     builders use — record/leaf over name guesses.
//   - Detected default-route NIC: recovery fallback ONLY when no verified
//     distinct identity exists (no leaf and no resolved record). Otherwise
//     an unlisted detected NIC is data until proven management and stays
//     closed. With zero identity the NIC is the only recovery hint; admit
//     it whole and document the caveat (a static-default-via-data boot
//     opens that NIC for the bootstrap window — inherent without config;
//     the first commit converges to configured policy).
//
// The returned set is sorted and deduplicated. Whole-NIC (not
// destination-scoped) admits are deliberate: daddr scoping from a live
// snapshot goes stale on DHCP renewal, while no config exists to tell
// revenue IPs from management IPs on one NIC — interface identity plus
// narrowing is the finest verifiable boundary available pre-config.
func resolveEarlyInputGuardLifelines(cfg *config.Config) []string {
	mgmtLeaf := ""
	if cfg != nil {
		mgmtLeaf = cfg.System.ManagementInterface
	}
	set := map[string]bool{}
	for _, d := range []string{"em0", "fab0", "fab1", config.ManagementVRFDeviceName} {
		set[d] = true
	}
	if mgmtLeaf == "" || mgmtLeaf == defaultMgmtInterface {
		set[defaultMgmtInterface] = true
	}
	recordName, recordOK := "", false
	if name, ok := lifelineRecordNameFn(); ok && name != "" {
		recordName, recordOK = name, true
	}
	for name := range protectedInterfacesWith(mgmtLeaf, recordName) {
		set[name] = true
	}
	if name, found, err := detectLifelineInterfaceFn(); err != nil {
		slog.Warn("lifeline detection failed; guard admits resolved identities and defaults only", "err", err)
	} else if found && name != "" && !set[name] {
		if mgmtLeaf == "" && !recordOK {
			set[name] = true
		} else {
			slog.Info("default-route NIC is not a verified management identity; excluding it from the input guard",
				"interface", name)
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// requireEarlyInputProtectionPreApply converges the pre-handoff lifeline
// guard before an apply performs link-affecting mutations. Called at apply
// entry (before any reconcile) and at the host-inbound tail top (covering
// direct tail callers); both are no-op atomic checks post-handoff. A failed
// install fails the apply closed with STALE recorded.
func (d *Daemon) requireEarlyInputProtectionPreApply(cfg *config.Config) error {
	if d.earlyInputHandoffDone.Load() {
		return nil
	}
	// Doing pre-handoff work proves this process has not handed off; drop a
	// stale marker from a previous process so the CLI guard stays accurate.
	clearEarlyInputHandoffMarker()

	if err := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(resolveEarlyInputGuardLifelines(cfg)); err != nil {
		err = tagNftInstallErr(err)
		d.noteHostInboundApplyFailed(time.Now())
		return fmt.Errorf("install early host-input guard before first handoff: %w", err)
	}
	return nil
}

// ensureEarlyInputBootstrapGuard replaces the #10751 global pre-networkd
// barrier with the lifeline-admitting variant when the daemon runs in
// bootstrap mode (no committed configuration, or a fail-closed load).
// Bootstrap suppresses the ordinary apply that would hand the barrier off,
// while remote recovery itself needs management connections the global
// barrier blocks — but lifting the barrier entirely would reopen data and
// link-local ingress the fail-closed fences do not cover (fence discovery
// or install can fail, and fences exclude link-locals). The variant keeps
// all non-lifeline ingress DROP-closed while the management lifeline stays
// reachable for recovery. Same table name, so the first ordinary apply
// removes it through the unchanged handoff path (handoffDone stays false
// until then). A variant-install failure retains the global barrier (fail
// closed) and is LOUD — the console remains for recovery.
func (d *Daemon) ensureEarlyInputBootstrapGuard() {
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	lifelines := resolveEarlyInputGuardLifelines(cfg)
	// Bootstrap runs once per process start, always pre-handoff: drop any
	// stale marker for the same invariant as above.
	clearEarlyInputHandoffMarker()

	if err := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(lifelines); err != nil {
		d.earlyInputGuardSwapFailed.Store(true)
		slog.Error("bootstrap cannot install lifeline-admitting input guard; global barrier retained — use the console if management is unreachable",
			"lifelines", lifelines, "err", tagNftInstallErr(err))
		return
	}
	d.earlyInputGuardSwapFailed.Store(false)
	slog.Warn("bootstrap swapped the global input barrier for a lifeline-admitting guard; data-interface services stay closed until the first commit",
		"lifelines", lifelines)
}

// sampleHostInboundSnapshots samples the interface address rows for the
// host-inbound apply path. A package var so handoff-race tests can script
// address transitions between the install sample, the handoff re-sample,
// and the post-removal re-sample; production always samples the kernel.
var sampleHostInboundSnapshots = dpuserspace.BuildInterfaceSnapshots

// hostInboundHasPendingEnforcingIntentFromSnapshots reports whether any
// configured enforcement scope is still unresolved in snaps: a zone with
// interfaces but no address yet (coarse, zone-level), or a specific
// interface-unit/family with a DHCP client but no lease (fine-grained:
// mixed zones, sequential v4/v6 acquisition). Consulted ONLY pre-handoff,
// over the handoff re-sample, to retain the early barrier until every
// intended scope installs its own protection — otherwise an unrelated or
// first-family handoff lifts the global guard while pending ingress stays
// unprotected until a later apply.
func hostInboundHasPendingEnforcingIntentFromSnapshots(cfg *config.Config, snaps []dpuserspace.InterfaceSnapshot) bool {
	return dpuserspace.HostInboundPendingIntentFromSnapshots(cfg, snaps)
}

// hostInboundCoverageNewcomers renders the desired host-inbound destinations
// from snaps and returns those NOT covered by installed — the destination
// set the standing enforcement was rendered from (#10751 R5-B). Unlike raw
// snapshot comparison, this proves coverage: lifeline-withheld and
// unscoping rows never appear in a rendered set, so they can neither hide
// a real newcomer (a bare-IP baseline hit is not a rendered-destination
// hit) nor force a spurious retry. Sorted bare hosts for stable messages.
func hostInboundCoverageNewcomers(cfg *config.Config, installed map[string]struct{}, snaps []dpuserspace.InterfaceSnapshot) []string {
	views := dpuserspace.BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	u4, u6 := dpuserspace.BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	v4, v6 := hostInboundUncoveredDropAddrs(views, u4, u6, installed)
	out := append(append([]string{}, v4...), v6...)
	sort.Strings(out)
	return out
}

// removeEarlyInputBarrierAtHandoff removes the barrier for a first handoff
// after re-attesting it. Entry-time attestation leaves a TOCTOU across the
// tail: a privileged flush between enforcement install and this removal
// wipes both the new tables and the barrier, and absent-removal success
// would then record a handoff over wiped enforcement. Closing it:
//
//   - barrier present → remove (normal path).
//   - barrier missing → reinstall the guard and FAIL WITHOUT removing (the
//     just-installed enforcement is suspect; the restored guard keeps the
//     box closed and the next apply retries the whole handoff).
//   - readback error → reinstall, then REFUSE as well: an unreadable
//     readback cannot prove the just-installed enforcement survived, so a
//     concurrent flush plus broken list would otherwise record a handoff
//     over wiped tables. Retry the entire apply before any removal.
//
// expectedTables names the enforcement tables this handoff installed and now
// relies on (main table, plus the gap table when one stands). After a
// successful removal the helper re-reads their ENFORCEMENT SHAPE, not bare
// presence (#10751 R4-5/R7-D): a flush interleaved between the install and
// the removal wipes enforcement while absent-removal still succeeds, and a
// surgical flush-to-shell keeps a present-but-open table — so shape must
// be re-proven AFTER the removal, not just before. A missing/empty table
// (or an unreadable readback) reinstalls the guard and refuses WITHOUT
// recording handoff-done. The teardown path passes nil — intended-empty
// needs no readback. A flush AFTER this readback is an accepted residual
// (no kernel-side transaction couples the two syscalls; the window is one
// list round-trip).
//
// installedCovered is the destination set the standing enforcement was
// rendered from: S1 real desired scope on the real path, the
// actually-installed fence coverage on cold-boot fallback, joint
// retained∪gap coverage on the gap branch, nil for teardown. After the
// enforcement-shape re-read, the helper samples once more and proves that
// coverage still includes every fresh desired destination (#10751 R5-B)
// — an address landing after the last pre-removal sample is otherwise
// absent from both the installed ruleset and the finished newcomer
// comparison when the barrier is removed. Drift reinstalls the guard and
// refuses.
//
// Post-handoff calls remove idempotently (barrier expected absent — e.g.
// ExecReload residue cleanup); no attestation there. Install success implies
// exact shape: the installer flushes one atomic nf_tables batch, so success
// leaves no partial table to verify.
func (d *Daemon) removeEarlyInputBarrierAtHandoff(cfg *config.Config, expectedTables []string, installedCovered map[string]struct{}) error {
	if d.earlyInputHandoffDone.Load() {
		return nftInstaller.RemoveEarlyInputBarrier()
	}
	present, err := nftInstaller.EarlyInputBarrierPresent()
	if err == nil && present {
		if removeErr := nftInstaller.RemoveEarlyInputBarrier(); removeErr != nil {
			return removeErr
		}
		for _, table := range expectedTables {
			ok, readErr := nftInstaller.TableEnforcing(table)
			if readErr == nil && ok {
				continue
			}
			if readErr != nil {
				slog.Warn("cannot re-verify enforcement after barrier removal; reinstalling guard and refusing handoff",
					"table", table, "err", tagNftInstallErr(readErr))
			} else {
				slog.Warn("enforcement table missing after barrier removal (concurrent flush?); guard reinstalled, handoff refused",
					"table", table)
			}
			if installErr := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(resolveEarlyInputGuardLifelines(cfg)); installErr != nil {
				return fmt.Errorf("reinstall early guard at handoff: %w", tagNftInstallErr(installErr))
			}
			if readErr != nil {
				return fmt.Errorf("enforcement table %s unreadable after barrier removal; guard reinstalled, handoff refused", table)
			}
			return fmt.Errorf("enforcement table %s missing after barrier removal; guard reinstalled, handoff refused", table)
		}
		// #10751 R5-B: close the S2→removal interval. Sample AFTER removal
		// and prove the installed coverage still includes every fresh
		// desired destination; an address landing after the last
		// pre-removal sample is absent from both the installed ruleset
		// and the finished newcomer comparison, so without this the
		// removal would expose it. On drift, reinstall the guard and
		// refuse — detect-and-reclose. Anything landing after this
		// sample is post-handoff-equivalent steady state (healed by
		// lease-triggered re-apply).
		if drift := hostInboundCoverageNewcomers(cfg, installedCovered, sampleHostInboundSnapshots(cfg)); len(drift) > 0 {
			slog.Warn("fresh addresses not covered by installed enforcement after barrier removal; reinstalling guard and refusing handoff",
				"newcomers", strings.Join(drift, ","))
			if installErr := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(resolveEarlyInputGuardLifelines(cfg)); installErr != nil {
				return fmt.Errorf("reinstall early guard at handoff: %w", tagNftInstallErr(installErr))
			}
			return fmt.Errorf("host-inbound addresses changed after barrier removal; retry: %s", strings.Join(drift, ","))
		}
		return nil
	}
	if err != nil {
		slog.Warn("cannot re-attest early barrier at handoff; reinstalling guard and refusing handoff",
			"err", tagNftInstallErr(err))
	} else {
		slog.Warn("early barrier missing at handoff (concurrent flush wiped enforcement?); guard reinstalled, handoff refused")
	}
	if installErr := nftInstaller.InstallEarlyInputBarrierWithLifelineAdmit(resolveEarlyInputGuardLifelines(cfg)); installErr != nil {
		return fmt.Errorf("reinstall early guard at handoff: %w", tagNftInstallErr(installErr))
	}
	if err != nil {
		return errors.New("early barrier state unreadable at handoff; guard reinstalled, handoff refused")
	}
	return errors.New("early barrier missing at handoff; guard reinstalled, handoff refused")
}

// hostInboundHandoffExpectedTables names the enforcement tables a fallback
// handoff relies on: the main table, plus the gap table when one stands
// beside it.
func hostInboundHandoffExpectedTables(gapActive bool) []string {
	if gapActive {
		return []string{xnft.HostInboundTableName, xnft.HostInboundGapTableName}
	}
	return []string{xnft.HostInboundTableName}
}

// errEarlyInputProtectionRefused marks an activation refusal: the early
// barrier is known-absent and cannot be reinstalled while nftables is
// usable. Callers match it with errors.Is to abort link activation while
// letting unrelated naming failures keep their historical handling.
var errEarlyInputProtectionRefused = errors.New("early host-input barrier missing and reinstall failed")

// EarlyInputHandoffMarkerPath records a completed first handoff on disk so
// the `xpfd input-barrier` command (which cannot see the daemon's in-memory
// latch) refuses a post-handoff reinstall. /run is tmpfs: the marker starts
// absent on every boot. A package var so tests redirect it to a temp dir.
var EarlyInputHandoffMarkerPath = "/run/xpf/early-input-handoff.done"

// setEarlyInputHandoffDone records a completed first handoff in memory and
// on disk. The marker write is DURABLE, not best-effort: memory is marked
// only after the write succeeds, so a failed write blocks handoff
// completion (the commit fails and the next apply retries) instead of
// leaving memory-true with the marker absent — a state in which a later
// barrier-unit start would install global DROP into a live handed-off
// daemon (#10751 R5-C). Post-handoff idempotent refreshes stay best-effort
// (already durable from the first handoff; the ensure command also
// re-checks live enforcement, so a deleted marker cannot inject). It also
// clears a latched bootstrap swap failure: the barrier is gone and
// enforcement is live, so a recovered box must not keep reporting
// swap-failed (#10751 R4-7).
func (d *Daemon) setEarlyInputHandoffDone() error {
	first := !d.earlyInputHandoffDone.Load()
	if err := os.MkdirAll(filepath.Dir(EarlyInputHandoffMarkerPath), 0755); err != nil {
		slog.Warn("cannot record early-input handoff marker", "err", err)
		if !first {
			return nil
		}
		return fmt.Errorf("record early-input handoff marker: %w", err)
	}
	if err := writeMarkerLocked(EarlyInputHandoffMarkerPath, "handed-off\n", &earlyInputHandoffLockFile); err != nil {
		slog.Warn("cannot record early-input handoff marker", "err", err)
		if !first {
			return nil
		}
		return fmt.Errorf("record early-input handoff marker: %w", err)
	}
	d.earlyInputHandoffDone.Store(true)
	d.earlyInputGuardSwapFailed.Store(false)
	return nil
}

// EarlyInputHandoffMarked reports whether the handoff marker file exists
// (a previous handoff completed in this boot).
func EarlyInputHandoffMarked() bool {
	_, err := os.Stat(EarlyInputHandoffMarkerPath)
	return err == nil
}

// clearEarlyInputHandoffMarker removes a stale marker when a new process
// starts pre-handoff work, restoring the "marker ⟺ current process handed
// off" invariant after a restart. Best-effort; failures are silent (a stale
// marker only makes the CLI conservative until the next handoff).
func clearEarlyInputHandoffMarker() {
	releaseMarkerLock(&earlyInputHandoffLockFile)
	_ = os.Remove(EarlyInputHandoffMarkerPath)
}

// Marker ownership locks (#10751 M2/Sec9): a marker file proves nothing by
// itself — a prior process's markers can survive a failed best-effort
// cleanup, and root can plant one. The daemon therefore holds an
// exclusive flock on each marker from its write until death; `ensure`
// treats a marker as live ownership only while a live EXCLUSIVE holder
// exists (lockable, shared-only-held, or unreadable = stale/orphaned =
// install fail-closed).
//
// Separation: markers are 0600 root-only. flock requires opening the
// file, so an unprivileged UID cannot even attempt a lock (open fails),
// which closes LOCK_SH liveness forgery outright — error discrimination
// alone could not, since SH contention yields the same EWOULDBLOCK as
// EX. The directory stays 0755: traversal without write lets the control
// socket and upgrade-lock consumers work while still denying non-root
// marker open/replace/delete (any remaining interference is fail-closed
// DoS at worst, never fail-open forgery). Pre-existing 0644 files are
// tightened to 0600 on the next write.
//
// Publish discipline (the #1875 lesson, cf. pkg/upgrade/lock): the lock
// is acquired BEFORE the content is published (open O_CREAT|O_RDWR,
// flock, ftruncate, write, fsync on the held fd), so no unlocked marker
// file is ever observable — a polling SH loop cannot pre-position on the
// write-then-lock gap. Truncate precedes the write so a shorter rewrite
// cannot leave a stale tail.
var (
	markerLockMu                  sync.Mutex
	earlyInputHandoffLockFile     *os.File
	hostInboundFirstApplyLockFile *os.File
)

// flockFn performs a BSD advisory lock operation. A package var so tests
// inject flock errors (ENOLCK) the kernel never produces for tmpfs.
var flockFn = func(fd int, how int) error { return unix.Flock(fd, how) }

// writeMarkerLocked publishes content to path under a process-lifetime
// exclusive lock, acquiring before writing (see above). If this process
// already holds the path (same inode), the write is a no-op success —
// content is constant per marker. A held-but-diverged slot (path deleted
// or replaced under us) is dropped and re-acquired. Lock contention
// retries briefly (a concurrent `ensure` probe holds microseconds);
// persistent contention returns an error for the caller to handle per
// its durability contract (handoff blocks, first-apply warns).
func writeMarkerLocked(path, content string, slot **os.File) error {
	markerLockMu.Lock()
	defer markerLockMu.Unlock()
	if *slot != nil {
		if fi, err := (*slot).Stat(); err == nil {
			if pi, perr := os.Stat(path); perr == nil && os.SameFile(fi, pi) {
				return nil
			}
		}
		_ = (*slot).Close()
		*slot = nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	var lerr error
	for i := range 3 {
		if i > 0 {
			time.Sleep(10 * time.Millisecond)
		}
		if lerr = flockFn(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); lerr == nil {
			break
		}
		if !isFlockContended(lerr) {
			break
		}
	}
	if lerr != nil {
		_ = f.Close()
		return lerr
	}
	// Tighten pre-existing group/other bits (a 0644 file from before the
	// 0600 discipline); best-effort — a failure here must not wedge the
	// commit, and the narrow leftover is logged loudly.
	if err := f.Chmod(0600); err != nil {
		slog.Warn("cannot tighten enforcement-ownership marker to 0600", "path", path, "err", err)
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	*slot = f
	return nil
}

// releaseMarkerLock drops a held ownership lock (if any) before removing
// the marker, so a later re-creation starts absent rather than shadowing
// a lock on an unlinked inode.
func releaseMarkerLock(slot **os.File) {
	markerLockMu.Lock()
	defer markerLockMu.Unlock()
	if *slot != nil {
		_ = (*slot).Close()
		*slot = nil
	}
}

// isFlockContended reports whether a flock error is lock contention
// (another holder) as opposed to a real failure. Only contention may
// ever read as live ownership — and then only after the SH discriminator
// below rules out a shared-only holder.
func isFlockContended(err error) bool {
	return errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN)
}

// markerLockedByLiveProcess reports whether some process currently holds
// an EXCLUSIVE flock on path. Absent, unopenable, lockable, or
// shared-only-held reads false (not live-owned — `ensure` installs
// fail-closed); so does any unexpected flock error. A denied EXCLUSIVE
// try-lock retries once: a racing transient holder (another concurrent
// `ensure` probe, microseconds) must not read as a steady owner.
func markerLockedByLiveProcess(path string) bool {
	for i := 0; ; i++ {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return false
		}
		exErr := flockFn(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if exErr == nil {
			_ = f.Close()
			return false
		}
		if !isFlockContended(exErr) {
			_ = f.Close()
			return false
		}
		// Contended: is the holder EXCLUSIVE (live daemon) or SHARED
		// (forgery attempt or stale SH)? A shared try-lock succeeds
		// iff NO exclusive owner exists.
		shErr := flockFn(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
		_ = f.Close()
		if shErr == nil {
			return false
		}
		if !isFlockContended(shErr) {
			return false
		}
		if i >= 1 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// EarlyInputHandoffLive reports whether the handoff marker is held by a
// live process (current ownership), as opposed to merely present (a stale
// restore a later `ensure` must not trust).
func EarlyInputHandoffLive() bool { return markerLockedByLiveProcess(EarlyInputHandoffMarkerPath) }

// HostInboundFirstApplyLive reports whether the first-apply marker is held
// by a live process. See EarlyInputHandoffLive.
func HostInboundFirstApplyLive() bool {
	return markerLockedByLiveProcess(HostInboundFirstApplyMarkerPath)
}

// HostInboundFirstApplyMarkerPath records that THIS boot's daemon installed
// host-inbound enforcement (real table or cold-boot fence) at least once.
// The `ensure` command combines it with DROP-proof table shape plus xpfd
// active state to prove a live table is current daemon ownership — not a
// stale restore from before xpfd started (#10751 R7-A). /run is tmpfs and
// the daemon clears it at startup, so it can only exist after this process
// installed. A package var so
// tests redirect it to a temp dir.
var HostInboundFirstApplyMarkerPath = "/run/xpf/host-inbound-applied.done"

// HostInboundFirstApplyMarked reports whether this boot's daemon installed
// host-inbound enforcement at least once.
func HostInboundFirstApplyMarked() bool {
	_, err := os.Stat(HostInboundFirstApplyMarkerPath)
	return err == nil
}

// clearHostInboundFirstApplyMarker removes a stale first-apply marker.
// Best-effort and silent: absence only makes `ensure` install fail-closed.
func clearHostInboundFirstApplyMarker() {
	releaseMarkerLock(&hostInboundFirstApplyLockFile)
	_ = os.Remove(HostInboundFirstApplyMarkerPath)
}

// noteHostInboundInstalled records a successful host-inbound enforcement
// install (real table or cold-boot fence). Best-effort by design: a failed
// write merely leaves `ensure` conservative (it installs the barrier,
// which the next apply hands off), so it must never fail the commit.
// Retried on every successful install, healing any earlier failure.
func noteHostInboundInstalled() {
	if err := os.MkdirAll(filepath.Dir(HostInboundFirstApplyMarkerPath), 0755); err != nil {
		slog.Warn("cannot record host-inbound first-apply marker", "err", err)
		return
	}
	if err := writeMarkerLocked(HostInboundFirstApplyMarkerPath, "applied\n", &hostInboundFirstApplyLockFile); err != nil {
		slog.Warn("cannot record host-inbound first-apply marker", "err", err)
		return
	}
}

// EarlyInputGuardSwapFailed reports whether the latest bootstrap
// lifeline-guard swap failed (global barrier retained instead). Feeds the
// xpf_early_input_guard_swap_failed gauge and /health.
func (d *Daemon) EarlyInputGuardSwapFailed() bool {
	if d == nil {
		return false
	}
	return d.earlyInputGuardSwapFailed.Load()
}
