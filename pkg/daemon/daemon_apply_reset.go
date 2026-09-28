package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/ipsec"
)

// errDaemonResetting is returned by every config-write entry point once a
// factory reset (zeroize) has entered its terminal reset generation (#5281). It
// is not surfaced to an operator on the normal path — resetting is only ever
// set true by factoryReset while the daemon is being wiped and stopped — so its
// job is purely to make a racing commit / HA-sync / rollback / reconcile abort
// instead of re-creating the just-erased state.
var errDaemonResetting = errors.New("factory reset in progress: configuration writes are rejected")

// Reset ownership stores are package vars only to let reset unit tests keep
// their proof checks inside a disposable tree.
var (
	resetDDNSLeaseStatePath = ddns.DefaultLeaseStatePath()
	resetDDNSSurfaceAPath   = ddns.DefaultSurfaceAStatePath()
	resetIPsecStatePath     = ipsec.DefaultConnStatePath
	// Identity files the wipe overwrites and a failed reset must restore.
	// (The hostname seam is the existing hostnamePath in daemon_system.go.)
	// Package vars only for test isolation.
	resetHostsPath      = "/etc/hosts"
	resetResolvConfPath = "/etc/resolv.conf"
	resetKnownHostsPath = "/etc/ssh/ssh_known_hosts"
	// Canonical Kea lease files the post-wipe verification re-checks.
	resetKeaLeaseCurrents = []string{dhcpserver.DefaultKeaLeaseFile4Path, dhcpserver.DefaultKeaLeaseFile6Path}
)

// isResetting reports whether a factory reset has entered the terminal reset
// generation (#5281). Config writers check it under applySem to short-circuit.
func (d *Daemon) isResetting() bool { return d.resetting.Load() }

// enterResetGeneration marks the daemon as being factory-reset. Called by
// factoryReset while it holds applySem, BEFORE the wipe, so any writer that
// later acquires applySem re-renders nothing (#5281). It is left set for the
// daemon's remaining lifetime on a successful wipe (the daemon is stopped
// moments later) and cleared again only if the wipe FAILED (exitResetGeneration).
func (d *Daemon) enterResetGeneration() { d.resetting.Store(true) }

// exitResetGeneration leaves the reset generation. Called only on a FAILED wipe
// so the box stays recoverable and normal config work resumes (#5281).
func (d *Daemon) exitResetGeneration() { d.resetting.Store(false) }

// quiesceDDNSForReset fences new reconcile launches and joins both guarded
// manager passes. Factory reset must not race a publish/withdraw with its
// manager-owned withdrawal or erase the durable ownership files underneath an
// in-flight provider call.
func (d *Daemon) quiesceDDNSForReset() error {
	// runGuarded* holds this mutex through goroutine launch. The reset bit was
	// set first, so crossing the mutex proves no new pass can start.
	d.ddnsResetMu.Lock()
	d.ddnsResetMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*ddnsReconcileTimeout)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for d.ddnsReconcileInFlight.Load() || d.surfaceA.reconcileInFlight.Load() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("factory reset: timed out draining DDNS reconcile passes: %w", ctx.Err())
		case <-ticker.C:
		}
	}
	return nil
}

// withdrawDDNSForReset removes every provably-owned published RR before the
// factory-reset wipe may erase its cleanup authority. BackendFingerprint is
// checked by each manager; any mismatch, missing endpoint, degraded store, or
// provider failure retains the state and aborts reset before config is erased.
func (d *Daemon) withdrawDDNSForReset() error {
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*ddnsReconcileTimeout)
	defer cancel()

	var errs []error
	var dhcpCfg *config.DHCPServerConfig
	var catalog map[string]*config.DDNSProvider
	if cfg != nil {
		dhcpCfg = &cfg.System.DHCPServer
		if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
			catalog = cfg.System.Services.DynamicDNS.Providers
		}
	}
	if d.ddns != nil {
		if err := d.ddns.WithdrawForReset(ctx, dhcpCfg); err != nil {
			errs = append(errs, err)
		}
	}
	if d.surfaceA.mgr != nil {
		if err := d.surfaceA.mgr.WithdrawForReset(ctx, catalog); err != nil {
			errs = append(errs, err)
		}
	}
	// A manager that was not constructed (NoDataplane) cannot prove or
	// withdraw non-empty durable ownership. These checks also catch residual
	// records left by a partial manager withdrawal, corrupt/degraded state, and
	// quarantined ownership.
	if err := ddns.CheckStateEmpty(resetDDNSLeaseStatePath); err != nil {
		errs = append(errs, err)
	}
	if err := ddns.CheckStateEmpty(resetDDNSSurfaceAPath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// quiesceDHCPForReset fences queued applies, then synchronously clears the
// active Kea configuration. The reset generation blocks every later enqueue.
func (d *Daemon) quiesceDHCPForReset() error {
	d.ddnsResetMu.Lock()
	defer d.ddnsResetMu.Unlock()
	if d.dhcpServer == nil {
		return nil
	}
	d.dhcpServer.SetLeaseSyncEnabled(false)
	return d.dhcpServer.Apply(nil)
}

func (d *Daemon) restoreDHCPAfterFailedReset() error {
	if d.dhcpServer == nil {
		return nil
	}
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	d.dhcpServer.SetLeaseSyncEnabled(d.dhcpLeaseSyncEnabled(cfg))
	if cfg == nil {
		return d.dhcpServer.Apply(nil)
	}
	masters := d.snapshotRethMasterState()
	authority := d.nextDHCPLeaseApplyAuthority(cfg, masters)
	if cfg.Chassis.Cluster != nil {
		return d.dhcpServer.ApplyWithLeaseAuthority(d.desiredClusterDHCPConfigWithMasters(cfg, masters), authority)
	}
	desired := desiredStandaloneDHCPConfig(cfg)
	return d.dhcpServer.ApplyWithLeaseAuthority(&desired, authority)
}

func (d *Daemon) clearIPsecForReset() error {
	if d.ipsec != nil {
		if err := d.ipsec.Clear(); err != nil {
			return fmt.Errorf("clear IPsec connections for factory reset: %w", err)
		}
	}
	if err := ipsec.CheckConnStateEmpty(resetIPsecStatePath); err != nil {
		return fmt.Errorf("IPsec connection ownership remains: %w", err)
	}
	return nil
}

func (d *Daemon) restoreIPsecAfterFailedReset() error {
	if d.ipsec == nil {
		return nil
	}
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	return d.applyIPsecTracked(cfg)
}

// resetIdentityFile records one pre-wipe identity path: its bytes and mode,
// its symlink target, or its absence.
type resetIdentityFile struct {
	data   []byte
	mode   os.FileMode
	absent bool
	link   bool
	target string
}

// snapshotResetIdentity reads the identity paths the wipe overwrites
// (/etc/hostname, /etc/hosts, /etc/resolv.conf, /etc/ssh/ssh_known_hosts) so
// a failed reset can restore them byte-for-byte. Links are snapshotted as
// links (Lstat/Readlink): reading through a foreign resolver symlink and
// restoring regular bytes over it would convert the pre-wipe link. A read
// failure fails the reset BEFORE anything is wiped: without a snapshot
// there is no restore.
func snapshotResetIdentity() (map[string]resetIdentityFile, error) {
	snap := make(map[string]resetIdentityFile)
	for _, path := range []string{hostnamePath, resetHostsPath, resetResolvConfPath, resetKnownHostsPath} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			snap[path] = resetIdentityFile{absent: true}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("snapshot %s for factory reset: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return nil, fmt.Errorf("snapshot symlink %s for factory reset: %w", path, err)
			}
			snap[path] = resetIdentityFile{link: true, target: target}
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s for factory reset: %w", path, err)
		}
		snap[path] = resetIdentityFile{data: data, mode: info.Mode().Perm()}
	}
	return snap, nil
}

// restoreResetIdentity writes a snapshot back after a failed wipe. It writes
// unconditionally: the previous recovery called applyHostname, which returns
// early when the kernel name already equals the configured name and left the
// wiped xpf value on disk (#10769 d05-F6). Links are restored as links and
// absences as absences, so a foreign resolver symlink the wipe replaced is
// put back untouched rather than converted to regular bytes.
func restoreResetIdentity(snap map[string]resetIdentityFile) error {
	var errs []error
	for path, file := range snap {
		if file.absent {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("restore absence of %s after failed factory reset: %w", path, err))
			}
			continue
		}
		if file.link {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("restore symlink %s after failed factory reset: %w", path, err))
				continue
			}
			if err := os.Symlink(file.target, path); err != nil {
				errs = append(errs, fmt.Errorf("restore symlink %s after failed factory reset: %w", path, err))
			}
			continue
		}
		if err := fsatomic.WriteFileDurable(path, file.data, file.mode); err != nil {
			errs = append(errs, fmt.Errorf("restore %s after failed factory reset: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

// verifyKeaLeasesErasedForReset re-checks the lease wipe set after the wipe
// reports success. The wipe verifies post-unlink itself, but a lease writer
// in flight across the reset boundary (a VRRP pre-seed that started before
// the reset generation) could re-persist between that check and here. Any
// reappearance fails the reset closed so a retry re-runs the erasure.
func verifyKeaLeasesErasedForReset() error {
	for _, current := range resetKeaLeaseCurrents {
		for _, path := range dhcpserver.KeaLeaseWipePaths(current) {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("factory reset: Kea lease file %s reappeared after the wipe", path)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("factory reset: inspect Kea lease file %s: %w", path, err)
			}
		}
	}
	return nil
}

// eraseKeaLeasesForReset removes any Kea lease files present, syncing their
// parents. It runs only to repair a post-wipe reappearance before the reset
// reports failure: with the pending markers already cleared and the config
// wiped, leaving the rows would hand prior leases to the next tenant's Kea
// with no boot gate left to force another pass.
func eraseKeaLeasesForReset() error {
	var errs []error
	synced := make(map[string]bool)
	for _, current := range resetKeaLeaseCurrents {
		for _, path := range dhcpserver.KeaLeaseWipePaths(current) {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("factory reset: re-erase Kea lease file %s: %w", path, err))
				continue
			}
			synced[filepath.Dir(path)] = true
		}
	}
	for dir := range synced {
		if err := fsatomic.SyncDir(dir); err != nil {
			errs = append(errs, fmt.Errorf("factory reset: sync Kea lease directory %s: %w", dir, err))
		}
	}
	return errors.Join(errs...)
}

// factoryReset runs a gRPC-initiated zeroize under the SAME global writer gate
// (d.applySem) that commit / apply / HA-sync serialize on, then enters the
// terminal reset generation so no concurrent or subsequent config writer can
// re-persist the erased .configdb SSOT or re-render the wiped secrets before the
// daemon is stopped (#5281). It is wired into the gRPC server as Config.ZeroizeFn
// and receives the pkg/grpcapi factory-reset primitive as wipe (kept there so
// the wipe stays testable via the performZeroizeWipe seam).
//
// Sequence (fail-CLOSED, wipe-then-stop):
//  1. Acquire applySem — this DRAINS any in-flight apply and BLOCKS a concurrent
//     one for the duration of the wipe. If ctx is cancelled before acquisition
//     (client disconnect), nothing has been erased yet, so aborting is safe.
//  2. Enter the terminal reset generation BEFORE the wipe, so a writer that
//     acquires applySem AFTER this returns (a periodic reconciler, a late
//     commit, a shutdown-time apply) short-circuits on errDaemonResetting.
//     2a. Quiesce config archival (#5869) and rescue.conf saves (#10769):
//     the reset generation gates daemon writers but not configstore-owned
//     writers that bypass applySem. Fence + JOIN them before the wipe so
//     neither the archive directory nor rescue.conf can be recreated after
//     it is erased.
//  3. Run the wipe while holding applySem.
//     - On FAILURE: exit the reset generation and release applySem (deferred)
//     so the half-reset box is recoverable and a retry can run, and return
//     the error. The caller must NOT stop the daemon — a stop here would
//     strand a box whose secrets are still on disk.
//     - On SUCCESS: stay in the reset generation (never cleared) and return nil;
//     the caller stops xpfd. applySem is released on return, but the resetting
//     flag keeps every later writer from re-rendering during the stop window.
func (d *Daemon) factoryReset(ctx context.Context, wipe func() error) error {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer d.applySem.Release(1)
	d.enterResetGeneration()
	// #5869: fence + drain the async config-archive writers BEFORE the wipe
	// erases /var/lib/xpf/archive. Auto-archive launches a fire-and-forget
	// configstore goroutine per commit that the #5281 reset generation does NOT
	// cover: a commit's writer that resumes after FactoryResetArchiveDir removed
	// the archive dir would MkdirAll it again and drop a config-<ts>.<seq>.conf
	// snapshot of the PRIOR tenant's full config text (cleartext IKE PSKs,
	// WireGuard keys, SNMP communities) — zeroize secret residue on a
	// re-tenanted device. QuiesceArchival sets the archive fence (new /
	// not-yet-written writers no-op) and JOINS any in-flight writer, so once it
	// returns no writer can recreate the archive the wipe is about to erase.
	// (Nil-store guard: unit tests drive factoryReset on a bare Daemon.)
	if d.store != nil {
		// #10769 d05-F8: rescueAction's SaveRescueConfig bypasses applySem,
		// so the daemon generation cannot fence it. Fence and join that
		// store-owned writer before the wipe erases rescue.conf.
		d.store.QuiesceRescueWrites()
		d.store.QuiesceArchival()
	}
	dhcpMayNeedRestore := false
	ipsecMayNeedRestore := false
	wipeStarted := false
	wipeSucceeded := false
	var identity map[string]resetIdentityFile
	kernelBeforeReset := ""
	resetFailed := func(err error) error {
		errs := []error{err}
		// Restore the pre-wipe identity files only when the wipe itself ran
		// and did not complete: after a completed wipe the config is gone and
		// the fresh identity is the correct state for the wiped box.
		if wipeStarted && !wipeSucceeded && identity != nil {
			if restoreErr := restoreResetIdentity(identity); restoreErr != nil {
				errs = append(errs, restoreErr)
			}
		}
		// The wipe moves the live kernel name with /etc/hostname; move it
		// back on the same failed-wipe path (empty when the pre-wipe read
		// failed, in which case there is nothing to restore to).
		if wipeStarted && !wipeSucceeded && kernelBeforeReset != "" {
			if rerr := sethostname([]byte(kernelBeforeReset)); rerr != nil {
				errs = append(errs, fmt.Errorf("restore kernel hostname after failed factory reset: %w", rerr))
			}
		}
		if ipsecMayNeedRestore {
			if restoreErr := d.restoreIPsecAfterFailedReset(); restoreErr != nil {
				errs = append(errs, fmt.Errorf("restore IPsec after failed factory reset: %w", restoreErr))
			}
		}
		if dhcpMayNeedRestore {
			if restoreErr := d.restoreDHCPAfterFailedReset(); restoreErr != nil {
				errs = append(errs, fmt.Errorf("restore DHCP after failed factory reset: %w", restoreErr))
			}
		}
		if d.store != nil {
			d.store.ResumeArchival()
			d.store.ResumeRescueWrites()
		}
		d.exitResetGeneration()
		return errors.Join(errs...)
	}
	// Snapshot the identity files the wipe overwrites before any destructive
	// step. A snapshot failure aborts here, with nothing wiped.
	snap, err := snapshotResetIdentity()
	if err != nil {
		return resetFailed(err)
	}
	identity = snap
	// Snapshot the live kernel name the wipe moves with /etc/hostname.
	// Best-effort: unlike the files, a failed read must not block the reset
	// (there is simply nothing to restore to on failure).
	if kernel, kerr := osHostname(); kerr != nil {
		slog.Warn("factory reset: cannot snapshot kernel hostname; live name will not be restored on failure", "err", kerr)
	} else {
		kernelBeforeReset = kernel
	}
	if err := d.quiesceDDNSForReset(); err != nil {
		return resetFailed(err)
	}
	// DNS RRs are external state. Withdraw them through the managers before
	// their durable ownership records or the config containing backend
	// credentials can be erased.
	if err := d.withdrawDDNSForReset(); err != nil {
		return resetFailed(err)
	}
	dhcpMayNeedRestore = d.dhcpServer != nil
	if err := d.quiesceDHCPForReset(); err != nil {
		return resetFailed(fmt.Errorf("quiesce DHCP for factory reset: %w", err))
	}
	ipsecMayNeedRestore = d.ipsec != nil
	if err := d.clearIPsecForReset(); err != nil {
		return resetFailed(err)
	}
	wipeStarted = true
	// Hold ddnsResetMu across the wipe and its post-wipe lease verification.
	// The VRRP pre-seed crosses this mutex around its direct memfile writes,
	// so no pre-seed can land between the wipe's unlink and the verification
	// stat: a writer ordered before the wipe has its output erased by it, and
	// one ordered after aborts on the reset bit (or re-seeds correctly after
	// a failed reset clears it). The DHCP enqueue and DDNS reconcile launches
	// cross the same mutex and likewise serialize here.
	d.ddnsResetMu.Lock()
	wipeErr := wipe()
	var verifyErr error
	if wipeErr == nil {
		wipeSucceeded = true
		verifyErr = verifyKeaLeasesErasedForReset()
		if verifyErr != nil {
			// The wipe already cleared the pending markers, so a bare
			// failure here would strand reappeared leases with no boot
			// gate and a wiped config. Re-erase under the still-held
			// fence and re-verify: the reset still reports failure
			// (a reappearance is a fence-escaper bug signal, never a
			// clean outcome) but every leg stays idempotent, so a retry
			// — or a reboot into the day-0 path — converges cleanly.
			if rerr := eraseKeaLeasesForReset(); rerr != nil {
				verifyErr = errors.Join(verifyErr, rerr)
			} else if rerr := verifyKeaLeasesErasedForReset(); rerr != nil {
				verifyErr = errors.Join(verifyErr, rerr)
			}
		}
	}
	d.ddnsResetMu.Unlock()
	if wipeErr != nil {
		return resetFailed(wipeErr)
	}
	if verifyErr != nil {
		return resetFailed(verifyErr)
	}
	return nil
}
