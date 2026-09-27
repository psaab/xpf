package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
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
	resetFailed := func(err error) error {
		errs := []error{err}
		if wipeStarted && d.store != nil {
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applyHostname(cfg)
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
	if err := wipe(); err != nil {
		return resetFailed(err)
	}
	return nil
}
