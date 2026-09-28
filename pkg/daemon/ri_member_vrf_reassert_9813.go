package daemon

import (
	"context"
	"log/slog"
	"sort"
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
// Three properties keep this loop from fighting the code that owns these binds:
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
//   - It skips a Linux device claimed by multiple RI list members. Strict
//     commits reject the ambiguity (#11060), but an older persisted config
//     must still boot on the tolerant path. There is no unique intended owner
//     for its link, so reasserting it would alternate the master on every tick.

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

// rebindRIMembersOutsideTheirVRF binds list members that sit outside their VRF
// and detaches quarantined devices only when their current master is one of the
// conflicting VRFs. Unrelated masters are never detached.
func (d *Daemon) rebindRIMembersOutsideTheirVRF(cfg *config.Config) {
	for _, m := range d.riMembersOutsideTheirVRF(cfg) {
		if m.conflict != nil {
			d.detachRIMemberDeviceConflict(*m.conflict)
			continue
		}
		slog.Warn("routing-instance member outside its VRF — re-binding",
			"interface", m.linuxName, "instance", m.instance)
		if err := d.routing.BindInterfaceToVRF(m.linuxName, m.instance); err != nil {
			slog.Error("routing-instance member VRF bind failed; will retry",
				"interface", m.linuxName, "instance", m.instance, "err", err)
		}
	}
}

// riMember names one routing-instance list member that needs reconciliation.
// A non-nil conflict requests a safe detach rather than a bind.
type riMember struct {
	linuxName string
	instance  string
	conflict  *config.RoutingInstanceMemberDeviceConflict
}

// riMemberDeviceConflicts combines freshly derived ambiguity with evidence
// retained by the tolerant compiler after it has removed the bad memberships.
// The latter is essential: kernel state can still carry the old VRF master even
// though the sanitized config no longer contains either claimant.
func riMemberDeviceConflicts(cfg *config.Config) []config.RoutingInstanceMemberDeviceConflict {
	if cfg == nil {
		return nil
	}
	byDevice := make(map[string]map[string]config.RoutingInstanceMemberClaim)
	add := func(conflict config.RoutingInstanceMemberDeviceConflict) {
		if conflict.LinuxName == "" {
			return
		}
		claims := byDevice[conflict.LinuxName]
		if claims == nil {
			claims = make(map[string]config.RoutingInstanceMemberClaim)
			byDevice[conflict.LinuxName] = claims
		}
		for _, claim := range conflict.Claims {
			claims[claim.Instance+"\x00"+claim.Member] = claim
		}
	}
	for _, conflict := range cfg.QuarantinedRIMemberDeviceConflicts {
		add(conflict)
	}
	for _, conflict := range config.RoutingInstanceMemberDeviceConflicts(cfg, cfg.TunnelNameMap()) {
		add(conflict)
	}
	devices := make([]string, 0, len(byDevice))
	for device := range byDevice {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	out := make([]config.RoutingInstanceMemberDeviceConflict, 0, len(devices))
	for _, device := range devices {
		claimKeys := make([]string, 0, len(byDevice[device]))
		for key := range byDevice[device] {
			claimKeys = append(claimKeys, key)
		}
		sort.Strings(claimKeys)
		conflict := config.RoutingInstanceMemberDeviceConflict{LinuxName: device}
		for _, key := range claimKeys {
			conflict.Claims = append(conflict.Claims, byDevice[device][key])
		}
		out = append(out, conflict)
	}
	return out
}

// riMembersOutsideTheirVRF returns list members requiring reconciliation.
// Quarantined conflicts produce detach actions only while they remain mastered
// by one of their claimant VRFs; unrelated or already-default links stay alone.
func (d *Daemon) riMembersOutsideTheirVRF(cfg *config.Config) []riMember {
	if cfg == nil {
		return nil
	}
	conflicts := riMemberDeviceConflicts(cfg)
	conflictByDevice := make(map[string]config.RoutingInstanceMemberDeviceConflict, len(conflicts))
	var out []riMember
	for _, conflict := range conflicts {
		conflictByDevice[conflict.LinuxName] = conflict
		if !d.riMemberConflictNeedsDetach(conflict) {
			continue
		}
		c := conflict
		out = append(out, riMember{linuxName: conflict.LinuxName, conflict: &c})
	}

	stanza := tunnelsWithTheirOwnRIStanza(cfg)
	tunMap := cfg.TunnelNameMap()
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.InstanceType == "forwarding" || config.IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		vrf, err := d.fabricLinkByName("vrf-" + ri.Name)
		if err != nil || vrf == nil || vrf.Attrs() == nil {
			continue // no VRF device on the box: ReconcileVRFs owns creating it
		}
		for _, key := range config.RoutingInstanceMemberDeviceKeysForInstance(cfg, tunMap, ri) {
			linuxName := key.LinuxName
			if _, found := conflictByDevice[linuxName]; found {
				continue // #11060: quarantine owns this device, never bind it
			}
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

func (d *Daemon) riMemberConflictNeedsDetach(conflict config.RoutingInstanceMemberDeviceConflict) bool {
	link, err := d.fabricLinkByName(conflict.LinuxName)
	if err != nil || link == nil || link.Attrs() == nil || link.Attrs().MasterIndex == 0 {
		return false
	}
	for _, claim := range conflict.Claims {
		if claim.Instance == "" || config.IsReservedRoutingInstanceName(claim.Instance) {
			continue
		}
		vrf, err := d.fabricLinkByName("vrf-" + claim.Instance)
		if err == nil && vrf != nil && vrf.Attrs() != nil &&
			link.Attrs().MasterIndex == vrf.Attrs().Index {
			return true
		}
	}
	return false
}

func (d *Daemon) detachRIMemberDeviceConflict(conflict config.RoutingInstanceMemberDeviceConflict) {
	if d.routing == nil {
		return
	}
	instances := make([]string, 0, len(conflict.Claims))
	seen := make(map[string]struct{}, len(conflict.Claims))
	for _, claim := range conflict.Claims {
		if claim.Instance == "" || config.IsReservedRoutingInstanceName(claim.Instance) {
			continue
		}
		if _, found := seen[claim.Instance]; found {
			continue
		}
		seen[claim.Instance] = struct{}{}
		instances = append(instances, claim.Instance)
	}
	detached, err := d.routing.UnbindInterfaceFromVRFs(conflict.LinuxName, instances)
	if err != nil {
		slog.Error("quarantined routing-instance member detach failed; will retry",
			"interface", conflict.LinuxName, "claims", instances, "err", err, "issue", "#11060")
		return
	}
	if detached {
		slog.Warn("quarantined routing-instance member detached to default routing context",
			"interface", conflict.LinuxName, "claims", instances, "issue", "#11060")
	}
}

// tunnelsWithTheirOwnRIStanza names every configured tunnel device with an
// explicit routing-instance stanza. The tunnel manager owns those bindings;
// list-member reconciliation must not bind or reassert them.
func tunnelsWithTheirOwnRIStanza(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	if cfg == nil {
		return out
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if tc := ifc.Tunnel; tc != nil && tc.RoutingInstance != "" && tc.Name != "" {
			out[tc.Name] = true
		}
		for _, unit := range ifc.Units {
			if unit == nil || unit.Tunnel == nil || unit.Tunnel.RoutingInstance == "" {
				continue
			}
			name := unit.Tunnel.Name
			if ifc.Tunnel != nil && ifc.Tunnel.Mode == "wireguard" && ifc.Tunnel.Name != "" {
				name = ifc.Tunnel.Name
			}
			if name != "" {
				out[name] = true
			}
		}
	}
	return out
}
