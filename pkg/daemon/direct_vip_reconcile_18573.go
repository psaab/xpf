package daemon

import (
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vipstamp"
)

// Direct-mode VIP address reconcile (#18573).
//
// Before #18573 the direct path (private-RG election / no-reth-vrrp, the
// compiler default) derived BOTH its add set and its remove set from the
// active config at call time and recorded nothing about what it had
// installed. A commit that renumbered a RETH unit (.10 -> .42) therefore
// left .10 on the RG owner indefinitely: the owner pass only added the new
// set, the demotion pass only removed the new set, and the netlink address
// reconcile skips RETH netdevs. The owner kept answering ARP for .10, and
// the userspace snapshot — built from the kernel listing — kept offering it
// to interface-mode SNAT.
//
// Ownership is now recorded in the kernel on the address itself (IFA_PROTO,
// pkg/vipstamp): every address this path installs is stamped. One function
// serves both directions:
//
//   - every call deletes each stamped LEFTOVER (vipstamp.Leftover: stamped,
//     and the config assigns no such address to that netdev). That is
//     config-only, so it is the same verdict on the owner and the
//     non-owner, and it covers a renumber, a removed unit or RETH, a moved
//     VLAN id and a unit disabled by commit alike;
//   - want=true (the RG owner) adds every configured VIP that is absent and
//     stamps one that is present but unstamped (installed by a pre-#18573
//     xpf), so a later renumber of it is also caught;
//   - want=false (not the owner, demotion, shutdown) deletes every
//     configured VIP of the RG, stamped or not — the pre-#18573 contract.
//
// Never deleted: an unstamped address that is not a configured VIP of this
// RG (DHCP lease, kernel or stable link-local, another daemon's address),
// and a stamped address the config still assigns to its netdev.

// Seams over the netlink side effects so the executor is drivable without a
// kernel. Production leaves them at the vipstamp implementations.
var (
	directVIPAddrDumpFn    = vipstamp.Dump
	directVIPAddrAddFn     = vipstamp.Add
	directVIPAddrDelFn     = vipstamp.Del
	directVIPLinkByIndexFn = netlink.LinkByIndex
	// wakeInterfaceLinkSnapshotFn is the seam over the refresher wake, so a
	// cell can observe which netdevs a reconcile republishes.
	wakeInterfaceLinkSnapshotFn = wakeInterfaceLinkSnapshot
)

// directVIPAddrOp is one configured VIP on one netdev.
type directVIPAddrOp struct {
	Netdev string
	CIDR   string // config spelling, for logs
	Prefix netip.Prefix
}

// directVIPDel is one planned delete and why.
type directVIPDel struct {
	Row    vipstamp.Row
	Netdev string
	Reason string
}

const (
	directVIPDelLeftover = "no-longer-configured"
	directVIPDelNotOwner = "not-owner"
)

// resolvedAddrRow is a dump row with its netdev name. Netdev is "" when the
// executor did not (or could not) resolve the link; such a row is never acted
// on.
type resolvedAddrRow struct {
	vipstamp.Row
	Netdev string
}

// directVIPPlanInput is everything the pure planner reads.
type directVIPPlanInput struct {
	Want bool
	// Desired is this RG's configured VIPs per netdev (RethVIPsForRG).
	Desired map[string][]string
	// Configured is config.AddressIdentitiesByNetdev: every address the
	// config assigns, per netdev, across every RG and plain interface.
	Configured map[string]map[string]bool
	Rows       []resolvedAddrRow
}

// directVIPPlan is the netlink actuation one reconcile owes.
type directVIPPlan struct {
	Del []directVIPDel
	// Add is the configured VIPs absent from the kernel (want only).
	Add []directVIPAddrOp
	// Present is the configured VIPs already on the kernel (want only).
	// After any delete they are re-asserted: deleting an IPv4 primary
	// without promote_secondaries also deletes its subnet's secondaries.
	Present []directVIPAddrOp
	// Adopt is the subset of Present that carries no stamp.
	Adopt []directVIPAddrOp
	// Invalid is configured VIPs that do not parse.
	Invalid []directVIPAddrOp
}

// planDirectVIPAddrs is the pure decision. Deterministic: deletes follow row
// order; adds/adopts follow sorted netdev, then config order.
func planDirectVIPAddrs(in directVIPPlanInput) directVIPPlan {
	var plan directVIPPlan
	desiredIDs := make(map[string]map[string]bool, len(in.Desired))
	var ordered []directVIPAddrOp
	netdevs := make([]string, 0, len(in.Desired))
	for netdev := range in.Desired {
		netdevs = append(netdevs, netdev)
	}
	sort.Strings(netdevs)
	for _, netdev := range netdevs {
		for _, cidr := range in.Desired[netdev] {
			p, ok := config.ParseVRRPVIP(cidr)
			if !ok {
				plan.Invalid = append(plan.Invalid, directVIPAddrOp{Netdev: netdev, CIDR: cidr})
				continue
			}
			id := config.PrefixIdentity(p)
			if desiredIDs[netdev] == nil {
				desiredIDs[netdev] = make(map[string]bool)
			}
			if desiredIDs[netdev][id] {
				continue
			}
			desiredIDs[netdev][id] = true
			ordered = append(ordered, directVIPAddrOp{Netdev: netdev, CIDR: cidr, Prefix: p})
		}
	}

	present := make(map[string]map[string]bool)
	unstamped := make(map[string]map[string]bool)
	for _, row := range in.Rows {
		if row.Netdev == "" {
			continue
		}
		id := row.Identity()
		if desiredIDs[row.Netdev][id] {
			if !in.Want {
				plan.Del = append(plan.Del, directVIPDel{Row: row.Row, Netdev: row.Netdev, Reason: directVIPDelNotOwner})
				continue
			}
			if present[row.Netdev] == nil {
				present[row.Netdev] = make(map[string]bool)
				unstamped[row.Netdev] = make(map[string]bool)
			}
			present[row.Netdev][id] = true
			if !row.Stamped() {
				unstamped[row.Netdev][id] = true
			}
			continue
		}
		if vipstamp.Leftover(row.Row, row.Netdev, in.Configured) {
			plan.Del = append(plan.Del, directVIPDel{Row: row.Row, Netdev: row.Netdev, Reason: directVIPDelLeftover})
		}
	}

	if !in.Want {
		return plan
	}
	for _, op := range ordered {
		id := config.PrefixIdentity(op.Prefix)
		if !present[op.Netdev][id] {
			plan.Add = append(plan.Add, op)
			continue
		}
		plan.Present = append(plan.Present, op)
		if unstamped[op.Netdev][id] {
			plan.Adopt = append(plan.Adopt, op)
		}
	}
	return plan
}

// reconcileDirectVIPAddrs converges the kernel to the direct-mode VIP set for
// rgID (see the file comment). added counts addresses created; removed counts
// this RG's configured VIPs deleted by a not-owner pass. A leftover delete is
// NOT counted: it belongs to no RG, and applyDirectVIPOwnership feeds removed
// into the RG's service edge (`prev || removed > 0` -> clearRethServicesForRG),
// which a leftover found by, say, the RG0 pass must not drive.
//
// If the ownership dump fails the call degrades to the pre-#18573 behaviour
// (add every configured VIP, or delete every configured VIP), stamping what it
// adds: it never deletes on a readback it does not have, and it never does less
// than the old code did.
//
// Every netdev on which it deletes a leftover is queued for a userspace
// snapshot refresh, so a reconcile-path removal republishes the interface rows
// without waiting for a commit or an RG move (#18573).
func (d *Daemon) reconcileDirectVIPAddrs(rgID int, want bool) (added, removed int) {
	if d.store == nil {
		return 0, 0
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return 0, 0
	}
	in := directVIPPlanInput{
		Want:       want,
		Desired:    cfg.RethVIPsForRG(rgID),
		Configured: cfg.AddressIdentitiesByNetdev(),
	}
	linkByName := d.linkByNameFn
	if linkByName == nil {
		linkByName = netlink.LinkByName
	}

	rows, err := directVIPAddrDumpFn()
	if err != nil {
		if d.directVIPDumpFailing.CompareAndSwap(false, true) {
			slog.Warn("direct VIP reconcile: address dump failed; adding/removing configured VIPs only, leftover-VIP removal paused until the dump succeeds",
				"rg", rgID, "err", err)
		}
		return d.directVIPBlindReconcile(in, linkByName)
	}
	if d.directVIPDumpFailing.CompareAndSwap(true, false) {
		slog.Info("direct VIP reconcile: address dump recovered", "rg", rgID)
	}

	// Resolve AFTER the dump: a row whose link vanished or was recreated in
	// between carries a dead ifindex, so its delete fails harmlessly (ENODEV)
	// instead of landing on a new link of the same name.
	ifindex := make(map[string]int, len(in.Desired))
	byIndex := make(map[int]string, len(in.Desired))
	for netdev := range in.Desired {
		link, err := linkByName(netdev)
		if err != nil || link == nil || link.Attrs() == nil {
			continue
		}
		ifindex[netdev] = link.Attrs().Index
		byIndex[link.Attrs().Index] = netdev
	}
	resolved := make([]resolvedAddrRow, 0, len(rows))
	for _, row := range rows {
		r := resolvedAddrRow{Row: row, Netdev: byIndex[row.LinkIndex]}
		if r.Netdev == "" && row.Stamped() {
			// A stamped address off this RG's VIP netdevs: resolve its name
			// so the leftover predicate can judge it. On any failure it stays
			// unresolved and is never deleted this pass.
			if link, err := directVIPLinkByIndexFn(row.LinkIndex); err == nil && link != nil && link.Attrs() != nil {
				r.Netdev = link.Attrs().Name
			}
		}
		resolved = append(resolved, r)
	}
	in.Rows = resolved
	plan := planDirectVIPAddrs(in)

	leftoverGone := make(map[string]bool)
	for _, op := range plan.Invalid {
		if d.directVIPLogFirst("bad|" + op.Netdev + "|" + op.CIDR) {
			slog.Warn("directAddVIPs: bad address", "rg", rgID, "iface", op.Netdev, "addr", op.CIDR)
		}
	}
	deleted := 0
	for _, del := range plan.Del {
		if err := directVIPAddrDelFn(del.Row); err != nil {
			if !vipstamp.GoneErr(err) && d.directVIPLogFirst("del|"+del.Netdev+"|"+del.Row.Prefix.String()) {
				slog.Warn("direct VIP reconcile: failed to remove VIP",
					"rg", rgID, "iface", del.Netdev, "addr", del.Row.Prefix.String(),
					"reason", del.Reason, "err", err)
			}
			continue
		}
		deleted++
		if del.Reason == directVIPDelLeftover {
			leftoverGone[del.Netdev] = true
		} else {
			removed++
		}
		slog.Info("direct VIP reconcile: removed VIP",
			"rg", rgID, "iface", del.Netdev, "addr", del.Row.Prefix.String(),
			"reason", del.Reason, "stamped", del.Row.Stamped())
	}

	if want {
		for netdev := range in.Desired {
			if _, ok := ifindex[netdev]; ok {
				d.clearVIPWarning(netdev)
			} else if d.shouldWarnVIPIface(netdev) {
				slog.Warn("directAddVIPs: interface not found", "rg", rgID, "iface", netdev)
			}
		}
		toAdd := plan.Add
		if deleted > 0 {
			toAdd = append(append([]directVIPAddrOp(nil), plan.Add...), plan.Present...)
		}
		created := make(map[directVIPAddrOp]bool, len(toAdd))
		for _, op := range toAdd {
			idx, ok := ifindex[op.Netdev]
			if !ok {
				continue
			}
			if err := directVIPAddrAddFn(idx, op.Prefix, false); err != nil {
				if !errors.Is(err, syscall.EEXIST) && d.directVIPLogFirst("add|"+op.Netdev+"|"+op.CIDR) {
					slog.Warn("directAddVIPs: failed to add", "rg", rgID, "iface", op.Netdev, "addr", op.CIDR, "err", err)
				}
				continue
			}
			created[op] = true
			added++
			slog.Info("directAddVIPs: added VIP", "rg", rgID, "iface", op.Netdev, "addr", op.CIDR)
		}
		for _, op := range plan.Adopt {
			idx, ok := ifindex[op.Netdev]
			if !ok || created[op] {
				continue
			}
			// Both lines are latched per (netdev, VIP) until the next commit:
			// a REPLACE that keeps failing, or a kernel that accepts it
			// without recording IFA_PROTO, would otherwise log every tick.
			if err := directVIPAddrAddFn(idx, op.Prefix, true); err != nil {
				if d.directVIPLogFirst("adopt-fail|" + op.Netdev + "|" + op.CIDR) {
					slog.Warn("direct VIP reconcile: failed to stamp pre-existing VIP",
						"rg", rgID, "iface", op.Netdev, "addr", op.CIDR, "err", err)
				}
				continue
			}
			if d.directVIPLogFirst("adopt|" + op.Netdev + "|" + op.CIDR) {
				slog.Info("direct VIP reconcile: stamped pre-existing VIP as xpf-owned",
					"rg", rgID, "iface", op.Netdev, "addr", op.CIDR)
			}
		}
	}
	d.queueDirectVIPSnapshotRefresh(leftoverGone)
	return added, removed
}

// queueDirectVIPSnapshotRefresh wakes the debounced interface-link snapshot
// refresher (daemon_interface_link_refresh.go) for every netdev on which the
// reconcile deleted a LEFTOVER. It runs under directVIPMu (via
// applyDirectVIPOwnership), so it uses the lock-free wakeInterfaceLinkSnapshot
// and leaves the relevance check to the refresher goroutine instead of taking
// the userspace manager's m.mu here. The refresher rebuilds rows from the desired
// config, publishes only a differing snapshot, and bumps the FIB generation,
// so a removal outside a commit reaches the helper — in particular when the
// commit's own build could not filter the leftover (its ownership dump
// failed). Adds and not-owner removals do not queue: a configured address is
// merged into its row whether or not the kernel holds it, so neither can
// change the published rows, and a demotion must not buy a snapshot rebuild
// under applySem. Non-blocking; a nil wake (refresher not started, tests) is
// a no-op.
func (d *Daemon) queueDirectVIPSnapshotRefresh(changed map[string]bool) {
	if len(changed) == 0 {
		return
	}
	wake := d.interfaceLinkRefreshWake.Load()
	if wake == nil {
		return
	}
	netdevs := make([]string, 0, len(changed))
	for netdev := range changed {
		netdevs = append(netdevs, netdev)
	}
	sort.Strings(netdevs)
	for _, netdev := range netdevs {
		wakeInterfaceLinkSnapshotFn(*wake, netdev)
	}
}

// directVIPLogFirst reports whether the latched direct-VIP log line keyed by
// key has not been emitted since the last commit, and records it. The
// reconcile runs every 2 s per RG; a per-(netdev, VIP) failure or adoption
// must log once, not per tick (logging rules: no Warn/Info per poll tick).
// resetVIPWarnings clears the latch on every commit, so a new config gets
// fresh diagnostics.
func (d *Daemon) directVIPLogFirst(key string) bool {
	d.vipWarnedMu.Lock()
	defer d.vipWarnedMu.Unlock()
	if d.directVIPLogged == nil {
		d.directVIPLogged = make(map[string]bool)
	}
	if d.directVIPLogged[key] {
		return false
	}
	d.directVIPLogged[key] = true
	return true
}

// directVIPBlindReconcile is the no-readback floor: exactly the pre-#18573
// add-all / remove-all over the configured set, stamping adds.
func (d *Daemon) directVIPBlindReconcile(in directVIPPlanInput, linkByName func(string) (netlink.Link, error)) (added, removed int) {
	netdevs := make([]string, 0, len(in.Desired))
	for netdev := range in.Desired {
		netdevs = append(netdevs, netdev)
	}
	sort.Strings(netdevs)
	for _, netdev := range netdevs {
		link, err := linkByName(netdev)
		if err != nil || link == nil || link.Attrs() == nil {
			if in.Want && d.shouldWarnVIPIface(netdev) {
				slog.Warn("directAddVIPs: interface not found", "iface", netdev, "err", err)
			}
			continue
		}
		if in.Want {
			d.clearVIPWarning(netdev)
		}
		idx := link.Attrs().Index
		for _, cidr := range in.Desired[netdev] {
			p, ok := config.ParseVRRPVIP(cidr)
			if !ok {
				if d.directVIPLogFirst("bad|" + netdev + "|" + cidr) {
					slog.Warn("directAddVIPs: bad address", "addr", cidr)
				}
				continue
			}
			if in.Want {
				if err := directVIPAddrAddFn(idx, p, false); err != nil {
					if !errors.Is(err, syscall.EEXIST) {
						slog.Warn("directAddVIPs: failed to add", "iface", netdev, "addr", cidr, "err", err)
					}
					continue
				}
				added++
				slog.Info("directAddVIPs: added VIP", "iface", netdev, "addr", cidr)
				continue
			}
			if err := directVIPAddrDelFn(vipstamp.Row{LinkIndex: idx, Prefix: p}); err != nil {
				if !vipstamp.GoneErr(err) {
					slog.Warn("directRemoveVIPs: failed to remove", "iface", netdev, "addr", cidr, "err", err)
				}
				continue
			}
			removed++
			slog.Info("directRemoveVIPs: removed VIP", "iface", netdev, "addr", cidr)
		}
	}
	return added, removed
}
