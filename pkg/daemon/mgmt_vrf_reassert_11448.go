package daemon

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

var mgmtVRFReassertInterval = 30 * time.Second

// mgmtVRFReassertLoop is the persistent owner of published management-interface
// membership in vrf-mgmt. networkd reloads, driver resets, and out-of-band
// `ip link set nomaster` can remove the binding between config applies.
func (d *Daemon) mgmtVRFReassertLoop(ctx context.Context) {
	t := time.NewTicker(mgmtVRFReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertMgmtVRFOnce(ctx)
		}
	}
}

// reassertMgmtVRFOnce restores drifted members under applySem, then refreshes
// their DHCP routes in the management table. Its quick gate also watches the
// active transport's sticky binding mismatch, since kernel drift may already
// have been repaired before the background pass runs. #16842: a fab1-debt
// epoch whose fab1 has become resolvable also passes the gate, so the
// background tick — not only the next commit — performs the one dual
// upgrade; a fab1-debt epoch whose fab1 is still unaddressed does NOT
// pass, which is what stops the 30 s teardown/rebuild churn.
func (d *Daemon) reassertMgmtVRFOnce(ctx context.Context) {
	if d.applySem == nil {
		return
	}
	active := d.activeTransport()
	bindingChanged := active.BindingChanged
	fab1Ready := d.fab1DebtUpgradeReady(active)
	missing := d.routing != nil && d.mgmtVRFMissing()
	var drifted []string
	if d.routing != nil && !missing {
		drifted = d.mgmtVRFInterfacesOutsideVRF()
	}
	if !missing && len(drifted) == 0 && !bindingChanged && !fab1Ready {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)

	// #15223: re-create a deleted vrf-mgmt before deriving drift, so the
	// bind pass below runs against the new device index in the same tick.
	recreated := false
	if d.routing != nil && d.mgmtVRFMissing() {
		if !d.ensureVRFDeviceForReassert(routing.VRFSpec{
			Name: config.ManagementVRFInstanceName, TableID: config.ManagementVRFTableID,
		}) {
			return
		}
		recreated = true
	}
	active = d.activeTransport()
	bindingChanged = active.BindingChanged
	fab1Ready = d.fab1DebtUpgradeReady(active)
	drifted = nil
	if d.routing != nil {
		drifted = d.mgmtVRFInterfacesOutsideVRF()
	}
	if len(drifted) == 0 && !bindingChanged && !fab1Ready {
		if recreated {
			d.restartSNMPForVRFRecreate()
		}
		return
	}
	rebound := false
	for _, name := range drifted {
		slog.Warn("management interface outside the management VRF — re-binding",
			"interface", name)
		if err := d.routing.BindInterfaceToVRF(name, config.ManagementVRFInstanceName); err != nil {
			slog.Error("management-VRF bind failed; will retry",
				"interface", name, "err", err)
			continue
		}
		rebound = true
		slog.Info("management interface bound to the management VRF", "interface", name)
	}
	if rebound || bindingChanged || fab1Ready {
		var cfg *config.Config
		if d.store != nil {
			cfg = d.store.ActiveConfig()
		}
		if cfg != nil && cfg.Chassis.Cluster != nil && !d.inBootstrap() {
			d.reconcileClusterTransportBinding(cfg, false)
		}
	}
	if len(drifted) > 0 {
		routeErr := mgmtVRFRouteReconcileFn(d)
		d.noteMgmtRouteReconcileResult(routeErr)
	}
	if recreated {
		d.restartSNMPForVRFRecreate()
	}
}

// fab1DebtUpgradeReady reports whether active carries fab1 debt (#16842)
// and the store's current config now resolves fab1, so a reassert tick
// should perform the single upgrade restart. Nil store / no cluster
// config is not ready; reconcile's config-change comparison owns those.
func (d *Daemon) fab1DebtUpgradeReady(active clusterTransportKey) bool {
	if !active.Fab1Debt || d.store == nil {
		return false
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return false
	}
	return fab1UpgradeReady(cfg)
}

// restartSNMPForVRFRecreate rebinds the SNMP listener after vrf-mgmt was
// re-created (#16626). The old socket's SO_BINDTODEVICE resolved to the
// dead ifindex; the name alone (snmpConfigHash / snmpVRFDevice) is
// unchanged, so reconcileSNMP would no-op on the next commit. Restart
// only when a listener is actually pinned to vrf-mgmt; a main-table
// listener or a stopped agent needs no bounce. The restart goes through
// reconcileSNMP, whose ifindex check performs the teardown+start and,
// on a bind failure, leaves the hash unrecorded so the next commit
// retries (#5110 contract).
func (d *Daemon) restartSNMPForVRFRecreate() {
	d.snmpReconMu.Lock()
	running := d.snmpAgent != nil && d.snmpVRFDevice == config.ManagementVRFDeviceName
	d.snmpReconMu.Unlock()
	if !running {
		return
	}
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || !snmpEnabled(cfg) {
		return
	}
	if d.reconcileSNMP(cfg) {
		slog.Info("SNMP agent restarted after management VRF re-create", "issue", "#16626")
	}
}

// mgmtVRFMissing reports whether the last apply managed vrf-mgmt (the
// published set is non-empty) but its device is now absent — deleted out
// of band (#15223). With no published set the device is not desired and
// must never be created here.
func (d *Daemon) mgmtVRFMissing() bool {
	if len(d.mgmtVRFIfaceSet()) == 0 {
		return false
	}
	return d.vrfDeviceMissing(config.ManagementVRFDeviceName)
}

// mgmtVRFInterfacesOutsideVRF reports published management interfaces whose
// kernel master differs from vrf-mgmt. Missing member links are left to
// their normal owners; healthy links cause no writes. A missing VRF device
// yields no drift here — reassertMgmtVRFOnce handles it via mgmtVRFMissing
// and re-derives drift after re-creating the device (#15223).
func (d *Daemon) mgmtVRFInterfacesOutsideVRF() []string {
	mgmtSet := d.mgmtVRFIfaceSet()
	if len(mgmtSet) == 0 {
		return nil
	}
	vrf, err := d.fabricLinkByName(config.ManagementVRFDeviceName)
	if err != nil || vrf == nil || vrf.Attrs() == nil {
		return nil
	}

	var drifted []string
	for name := range mgmtSet {
		link, err := d.fabricLinkByName(name)
		if err != nil || link == nil || link.Attrs() == nil {
			continue
		}
		if link.Attrs().MasterIndex != vrf.Attrs().Index {
			drifted = append(drifted, name)
		}
	}
	sort.Strings(drifted)
	return drifted
}
