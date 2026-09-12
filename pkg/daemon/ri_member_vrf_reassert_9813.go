package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9813, tenant half. A routing-instance `interface` list member is bound to
// vrf-<instance> only on the apply path: step 0a (bindRoutingInstanceMembers)
// and the #6805 late pass (rebindRoutingInstanceMembers) at apply step 2.7.
// Nothing re-asserts that membership between applies, so a member netdev
// re-created outside an apply — a driver re-probe, a VF reset — or unbound out
// of band with `ip link set nomaster` forwards in the DEFAULT table until the
// next apply of any kind. The fabric half of this issue fixed the same shape
// for fab0/fab1 and vrf-mgmt.
//
// Two properties keep this loop from fighting the code that owns these binds:
//
//   - It binds only a member whose master is NOT its VRF. BindInterfaceToVRF
//     logs at Info on every call, so re-running the apply's bind loop on every
//     tick would log on every tick of a healthy node (CLAUDE.md forbids that)
//     and re-drive netlink for nothing.
//   - It skips a tunnel that carries its own `routing-instance` stanza. Those
//     are the tunnel manager's claim: it binds them in reconcileVRFClaimLocked
//     case 1 and records the claim in appliedRI ONLY from its own successful
//     bind, so a daemon-side bind would move the master with the claim
//     bookkeeping left behind. List members are step 0a's — the #1884 case-2
//     veto says so in as many words — and they are what this loop re-asserts.

// riMemberVRFReassertInterval paces the re-assert, matching its siblings
// (fabricIPVLANReassertLoop, proxyARPReassertLoop, raDeadSenderReassertLoop).
var riMemberVRFReassertInterval = 30 * time.Second

// riMemberVRFReassertLoop is the always-on owner of routing-instance list-member
// VRF membership between applies. It re-reads the active config every tick, so
// an instance or member added by a later commit is picked up without a restart.
func (d *Daemon) riMemberVRFReassertLoop(ctx context.Context) {
	t := time.NewTicker(riMemberVRFReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertRIMemberVRFOnce(ctx)
		}
	}
}

// reassertRIMemberVRFOnce binds one round of drifted list members.
//
// It takes applySem BEFORE the config read that drives the binding (#4001, the
// reason the proxy-ARP and #6791 loops do the same): a tick that acted on a
// config read outside the semaphore could bind a member a concurrent commit has
// just removed from its instance. The cheap gate runs first, outside the
// semaphore, so a healthy node never queues behind a commit for nothing, and
// the pass re-derives its work inside, because the commit it queued behind may
// have bound everything already.
func (d *Daemon) reassertRIMemberVRFOnce(ctx context.Context) {
	if d.store == nil || d.routing == nil {
		return
	}
	if cfg := d.store.ActiveConfig(); cfg == nil || len(d.riMembersOutsideTheirVRF(cfg)) == 0 {
		return // cheap path: nothing configured, or every member is where it belongs
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return // ctx cancelled (daemon shutdown) — do not reconcile.
	}
	defer d.applySem.Release(1)

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	d.rebindRIMembersOutsideTheirVRF(cfg)
}

// rebindRIMembersOutsideTheirVRF binds every configured list member that sits
// outside the VRF its instance names. A failure is logged, and the next tick
// retries it.
func (d *Daemon) rebindRIMembersOutsideTheirVRF(cfg *config.Config) {
	for _, m := range d.riMembersOutsideTheirVRF(cfg) {
		slog.Warn("routing-instance member outside its VRF — re-binding",
			"interface", m.linuxName, "instance", m.instance)
		if err := d.routing.BindInterfaceToVRF(m.linuxName, m.instance); err != nil {
			slog.Error("routing-instance member VRF bind failed; will retry",
				"interface", m.linuxName, "instance", m.instance, "err", err)
		}
	}
}

// riMember names one routing-instance list member and the instance it belongs to.
type riMember struct {
	linuxName string
	instance  string
}

// riMembersOutsideTheirVRF returns the configured list members that exist but
// sit outside the VRF their instance names.
//
// Name resolution goes through riMemberLinuxName with cfg.TunnelNameMap(),
// exactly as step 0a resolves it, so this loop and the apply reason about ONE
// name set — the same reason #6805 gave for sharing one bind implementation.
// The netlink reads go through the shared fabricLinkByName seam, so a test can
// drive this against a synthetic link table.
//
// A member absent on this chassis is skipped silently: a routing instance may
// legitimately name an interface this chassis does not have, and step 0a
// already treats that as best-effort rather than an error.
func (d *Daemon) riMembersOutsideTheirVRF(cfg *config.Config) []riMember {
	if cfg == nil {
		return nil
	}
	stanza := tunnelsWithTheirOwnRIStanza(cfg)
	tunMap := cfg.TunnelNameMap()
	var out []riMember
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" || config.IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		vrf, err := d.fabricLinkByName("vrf-" + ri.Name)
		if err != nil || vrf == nil || vrf.Attrs() == nil {
			continue // no VRF device on the box: ReconcileVRFs owns creating it
		}
		for _, ifaceName := range ri.Interfaces {
			linuxName := riMemberLinuxName(cfg, tunMap, ifaceName)
			if stanza[linuxName] {
				continue // the tunnel manager's claim, not step 0a's
			}
			link, err := d.fabricLinkByName(linuxName)
			if err != nil || link == nil || link.Attrs() == nil {
				continue // absent on this chassis
			}
			if link.Attrs().MasterIndex == vrf.Attrs().Index {
				continue // already a member
			}
			out = append(out, riMember{linuxName: linuxName, instance: ri.Name})
		}
	}
	return out
}

// tunnelsWithTheirOwnRIStanza names the tunnel devices whose config carries a
// `routing-instance` stanza. The tunnel manager binds those itself and records
// the claim, so this loop leaves them alone.
func tunnelsWithTheirOwnRIStanza(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	for _, tc := range collectAppliedTunnels(cfg) {
		if tc != nil && tc.RoutingInstance != "" {
			out[tc.Name] = true
		}
	}
	return out
}
