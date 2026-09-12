package daemon

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// fabricIPVLANReassertInterval paces the fabric-overlay retry owner (#6791).
//
// 30s matches proxyARPReassertLoop and raDeadSenderReassertLoop. The fabric
// overlay carries cluster heartbeat and session sync, so a faster cadence is
// tempting — but the cluster's own 2s reconcile already re-drives a great deal,
// and the gap this loop exists to close is a boot-time netlink failure that
// otherwise persists until an operator commits. Minutes of exposure become
// seconds; a tighter tick would buy little and cost a netlink read per fab
// device per tick forever.
var fabricIPVLANReassertInterval = 30 * time.Second

// fabricEnsureFn is the overlay-creation entry point, overridable in tests so
// the retry owner can be observed without a real IPVLAN. Package-level rather
// than a Daemon field because ensureFabricIPVLAN is a package function and the
// apply path calls it directly; routing BOTH through one seam is what makes the
// re-drive assertable.
var fabricEnsureFn = ensureFabricIPVLAN

// fabricIPVLANRetryDelay spaces applyFabricIPVLAN's in-line retries. A var so a
// test can drive the retries-exhausted path without five real seconds of sleep;
// production keeps 1s.
var fabricIPVLANRetryDelay = time.Second

// fabricIPVLANReassertLoop is the persistent recovery owner the fabric overlay
// did not have (#6791).
//
// applyFabricIPVLAN retries five times at 1s and then gives up. Standalone and
// cluster nodes alike apply the fabric overlay ONLY from a config apply, so a
// netlink failure that outlasts those five seconds — a parent NIC still being
// renamed after a power cycle is the motivating case — left fab0/fab1 absent
// until an operator happened to commit. The node then had no cluster heartbeat
// and no session-sync transport, having reported (before this change) a
// successful commit.
//
// It is also the only owner that can cover the DEFERRED overlays: when the
// userspace dataplane is active, creation is postponed to the OnXSKBound
// callback, which runs after the apply has returned, so its failure cannot
// reach the commit result at all.
//
// Always-on and mode-agnostic, mirroring the two sibling loops: it re-reads the
// active config each tick rather than capturing one at start, so a fabric
// interface added or removed by a later commit is picked up without a restart.
func (d *Daemon) fabricIPVLANReassertLoop(ctx context.Context) {
	t := time.NewTicker(fabricIPVLANReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertFabricIPVLANOnce(ctx)
		}
	}
}

// missingFabricOverlays returns the configured fabric overlays that are absent
// or down, as (parent, name, addrs) triples ready for ensureFabricIPVLAN.
//
// This is the CHEAP gate. On a healthy node it is one netlink name lookup per
// configured fab device — at most two — and returns nothing, so the loop costs
// effectively nothing when everything is up. It deliberately does NOT verify
// the parent index, MTU or addresses: those are ensureFabricIPVLAN's job and
// re-running it for a cosmetic drift would restart a working overlay every
// tick. The gate answers only "is there a usable fab device at all".
func (d *Daemon) missingFabricOverlays(cfg *config.Config) []deferredIPVLAN {
	var out []deferredIPVLAN
	config.RangeInterfaces(cfg, func(ifName string, ifCfg *config.InterfaceConfig) {
		if ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
			return
		}
		fabLinux := config.LinuxIfName(ifName)
		link, err := d.fabricLinkByName(fabLinux)
		if err == nil && link != nil && link.Attrs() != nil &&
			link.Attrs().Flags&net.FlagUp != 0 {
			return // present and administratively up — nothing to do
		}
		var addrs []string
		if unit, ok := config.LookupUnit(ifCfg, 0); ok {
			addrs = unit.Addresses
		}
		out = append(out, deferredIPVLAN{
			parent: config.LinuxIfName(ifCfg.LocalFabricMember),
			name:   fabLinux,
			addrs:  addrs,
		})
	})
	return out
}

// staleFabricOverlays returns fabric IPVLANs that EXIST on the box but which
// the active config does not name.
//
// #8372: the reassert loop only ever CREATED. `reassertFabricIPVLANOnce` had
// zero deletes, and the two mechanisms that look like they should reap a stale
// overlay do not: `CleanupFabricIPVLANs` is reachable only from the
// `xpfd cleanup` subcommand -- the daemon never removes these links when it
// exits -- and the stale-overlay sweep inside `applyInterfaces` runs on the
// next interface apply, i.e. the next COMMIT.
//
// So a fabric IPVLAN recreated by the deferred `OnXSKBound` closure after a
// later apply dropped it persisted for the daemon's lifetime and past it,
// healable only by an operator action. That is HA-relevant: it carries the
// fabric / session-sync address, possibly on a parent the config no longer
// designates.
//
// #6791 designated this loop the persistent recovery owner; it owned only the
// create half. This is the other half, and it re-reads the active config every
// 30 s, which is exactly the information needed.
func (d *Daemon) staleFabricOverlays(cfg *config.Config) []netlink.Link {
	configured := make(map[string]bool)
	config.RangeInterfaces(cfg, func(ifName string, ifCfg *config.InterfaceConfig) {
		if ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
			return
		}
		configured[config.LinuxIfName(ifName)] = true
	})
	var out []netlink.Link
	for _, name := range fabricOverlayNames() {
		if configured[name] {
			continue
		}
		link, err := d.fabricLinkByName(name)
		if err != nil || link == nil {
			continue // absent is the desired state
		}
		// Only ever an IPVLAN we could have made. A same-named device of
		// another type is not ours, and deleting it would be this reaper
		// causing the outage it exists to prevent.
		if _, ok := link.(*netlink.IPVlan); !ok {
			continue
		}
		out = append(out, link)
	}
	return out
}

// reassertFabricIPVLANOnce re-creates one round of missing fabric overlays and
// reaps one round of stale ones.
//
// It takes applySem BEFORE reading ActiveConfig, for the reason #4001 gave the
// proxy-ARP loop: reading the config outside the semaphore lets a tick capture a
// PRE-commit snapshot and re-assert state a concurrent commit has just removed —
// here, re-creating a fab device for a fabric interface the operator had just
// deleted, which the commit's own stale-overlay sweep had torn down moments
// before.
//
// The gate is re-run INSIDE the semaphore. The pre-check outside it is only an
// optimisation to avoid queueing behind a commit for nothing; a commit that
// lands in between may already have created the overlay, and re-running
// ensureFabricIPVLAN then would be a gratuitous rebuild of a working device.
func (d *Daemon) reassertFabricIPVLANOnce(ctx context.Context) {
	if d.store == nil {
		return
	}
	// #8372: the cheap-path gate must consider BOTH directions. A stale overlay
	// is an EXTRA device, not a missing one, so `len(missing) == 0` is exactly
	// the state a stale overlay produces -- gating on it alone would make the
	// reaper unreachable in the only case it exists for.
	// #9813: the same holds for an overlay that exists outside the management
	// VRF: it is neither missing nor stale.
	if cfg := d.store.ActiveConfig(); cfg == nil ||
		(len(d.missingFabricOverlays(cfg)) == 0 && len(d.staleFabricOverlays(cfg)) == 0 &&
			len(d.fabricOverlaysOutsideMgmtVRF(cfg)) == 0) {
		return // cheap path: nothing configured, nothing extra, nothing unbound
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return // ctx cancelled (daemon shutdown) — do not reconcile.
	}
	defer d.applySem.Release(1)

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	for _, ov := range d.missingFabricOverlays(cfg) {
		slog.Warn("fabric IPVLAN missing — re-asserting",
			"parent", ov.parent, "name", ov.name)
		if err := fabricEnsureFn(ov.parent, ov.name, ov.addrs); err != nil {
			slog.Error("fabric IPVLAN re-assert failed; will retry",
				"parent", ov.parent, "name", ov.name, "err", err)
			continue
		}
		slog.Info("fabric IPVLAN re-asserted", "parent", ov.parent, "name", ov.name)
	}

	// #9813: bind AFTER the ensure, so an overlay this pass just re-created is
	// bound in the same pass. ensureFabricIPVLAN sets no master, and an overlay
	// can also lose its master without being re-created.
	d.rebindFabricOverlaysToMgmtVRF(cfg)

	// Reap AFTER the ensure, in the same pass and under the same semaphore.
	//
	// Ordering matters for the race the issue warns about. `OnXSKBound` runs on
	// its own goroutine and can be creating an overlay concurrently, so a reap
	// can in principle delete a link that path is mid-way through building. The
	// ordering does not prevent that -- nothing can, without joining a
	// goroutine nobody joins -- but it makes the outcome CONVERGENT rather than
	// oscillating: the set is re-derived from the current config on every pass,
	// so a configured overlay deleted by a racing reap is recreated by the next
	// ensure 30 s later, and a stale one recreated by a racing closure is reaped
	// by the next pass. The closure fires ONCE per manager lifetime
	// (`xskBoundNotified`), so the race window is the startup one and does not
	// recur.
	for _, link := range d.staleFabricOverlays(cfg) {
		name := ""
		if link.Attrs() != nil {
			name = link.Attrs().Name
		}
		slog.Warn("fabric IPVLAN present but not in the active config — reaping",
			"name", name)
		if err := d.fabricLinkDel(link); err != nil {
			slog.Error("fabric IPVLAN reap failed; will retry",
				"name", name, "err", err)
			continue
		}
		slog.Info("fabric IPVLAN reaped", "name", name)
	}
}
