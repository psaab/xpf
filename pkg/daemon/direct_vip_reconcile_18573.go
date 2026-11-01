package daemon

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
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
	// ensurePromoteSecondariesFn is the seam over the per-netdev
	// promote_secondaries sysctl write (review Z1 on #18579).
	ensurePromoteSecondariesFn = ensurePromoteSecondaries
)

// ensurePromoteSecondaries sets net.ipv4.conf.<netdev>.promote_secondaries=1
// unless it already is (review Z1 on #18579). With 0, deleting an IPv4
// PRIMARY makes the kernel delete every secondary of the same subnet —
// including a foreign, unstamped one this reconcile promised never to touch.
// With 1 the kernel promotes the next secondary instead. The appliance
// already gets 1 from systemd's 50-default.conf for interfaces created after
// boot-time sysctl, but xpf never set it and a netdev that predates it (or a
// host without that drop-in) can carry 0. Only called on a netdev where the
// reconcile is about to delete an IPv4 address. The path is per-netns (the
// calling thread's), so it is the netdev the delete targets.
func ensurePromoteSecondaries(netdev string) error {
	if netdev == "" || strings.ContainsAny(netdev, "/\x00") {
		return errors.New("invalid netdev name")
	}
	path := "/proc/sys/net/ipv4/conf/" + netdev + "/promote_secondaries"
	if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	return os.WriteFile(path, []byte("1"), 0)
}

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
	plan.Del = d.guardIPv4PrimaryCascade(rgID, plan.Del, resolved, in.Desired)

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
		d.directVIPLogClear("del|" + del.Netdev + "|" + del.Row.Prefix.String())
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
			d.directVIPLogClear("add|" + op.Netdev + "|" + op.CIDR)
			slog.Info("directAddVIPs: added VIP", "rg", rgID, "iface", op.Netdev, "addr", op.CIDR)
		}
		var written []directVIPAddrOp
		for op := range created {
			written = append(written, op)
		}
		for _, op := range plan.Adopt {
			idx, ok := ifindex[op.Netdev]
			if !ok || created[op] {
				continue
			}
			if d.directVIPStampUnsupported.Load() {
				// Review Z1: a kernel that ignores IFA_PROTO would take a
				// REPLACE every tick for every VIP and never record it.
				break
			}
			// Both lines are latched per (netdev, VIP): a REPLACE that keeps
			// failing would otherwise log every tick. The failure latch
			// re-arms on the next success or commit; a kernel that accepts
			// REPLACE without recording IFA_PROTO is caught by
			// verifyDirectVIPStamps instead.
			if err := directVIPAddrAddFn(idx, op.Prefix, true); err != nil {
				if d.directVIPLogFirst("adopt-fail|" + op.Netdev + "|" + op.CIDR) {
					slog.Warn("direct VIP reconcile: failed to stamp pre-existing VIP",
						"rg", rgID, "iface", op.Netdev, "addr", op.CIDR, "err", err)
				}
				continue
			}
			written = append(written, op)
			d.directVIPLogClear("adopt-fail|" + op.Netdev + "|" + op.CIDR)
			if d.directVIPLogFirst("adopt|" + op.Netdev + "|" + op.CIDR) {
				slog.Info("direct VIP reconcile: stamped pre-existing VIP as xpf-owned",
					"rg", rgID, "iface", op.Netdev, "addr", op.CIDR)
			}
		}
		d.verifyDirectVIPStamps(rgID, written, ifindex)
	}
	d.queueDirectVIPSnapshotRefresh(cfg, leftoverGone)
	return added, removed
}

// queueDirectVIPSnapshotRefresh wakes the debounced interface-link snapshot
// refresher (daemon_interface_link_refresh.go) for every netdev on which the
// reconcile deleted a LEFTOVER. It runs under directVIPMu (via
// applyDirectVIPOwnership), so it uses the lock-free wakeInterfaceLinkSnapshot
// and checks relevance with the pure dpuserspace.ConfiguredInterfaceLinkName
// against cfg (this reconcile's own config) instead of taking the userspace
// manager's m.mu. The refresher rebuilds rows from the desired
// config, publishes only a differing snapshot, and bumps the FIB generation,
// so a removal outside a commit reaches the helper — in particular when the
// commit's own build could not filter the leftover (its ownership dump
// failed). Adds and not-owner removals do not queue: a configured address is
// merged into its row whether or not the kernel holds it, so neither can
// change the published rows, and a demotion must not buy a snapshot rebuild
// under applySem. Non-blocking; a nil wake (refresher not started, tests) is
// a no-op.
func (d *Daemon) queueDirectVIPSnapshotRefresh(cfg *config.Config, changed map[string]bool) {
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
		// Review Z2 on #18579: the refresher keeps only the newest name and a
		// name with no configured row publishes nothing, so waking it for one
		// (a leftover on a unit the commit removed) would displace a pending
		// relevant refresh and clear its retry debt unpublished. The check is
		// the pure config predicate, against this reconcile's own config, so
		// no manager lock is taken under directVIPMu.
		if !dpuserspace.ConfiguredInterfaceLinkName(cfg, netdev) {
			continue
		}
		wakeInterfaceLinkSnapshotFn(*wake, netdev)
	}
}

// directVIPLogClear re-arms one latched diagnostic after its operation
// succeeds (review Z2 on #18579), the #7532 clearVIPWarning pattern: a VIP add
// or remove that fails again on a later failover, with no commit in between,
// must warn again rather than stay silent.
func (d *Daemon) directVIPLogClear(key string) {
	d.vipWarnedMu.Lock()
	defer d.vipWarnedMu.Unlock()
	delete(d.directVIPLogged, key)
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
			d.directVIPLogClear("del|" + netdev + "|" + p.String())
			slog.Info("directRemoveVIPs: removed VIP", "iface", netdev, "addr", cidr)
		}
	}
	return added, removed
}

// guardIPv4PrimaryCascade makes "an unstamped address is never deleted" hold
// whatever promote_secondaries the netdev carries (review Z1 on #18579).
// Before the first IPv4 delete on a netdev it ensures promote_secondaries=1.
// If that fails, an IPv4 delete is dropped from this pass when its subnet
// holds an address that is neither being deleted nor one of this RG's
// configured VIPs (those are re-asserted after any delete): deleting a primary
// there could cascade onto a foreign secondary. Warned once per netdev and VIP.
func (d *Daemon) guardIPv4PrimaryCascade(rgID int, dels []directVIPDel, rows []resolvedAddrRow, desired map[string][]string) []directVIPDel {
	if len(dels) == 0 {
		return dels
	}
	deleting := make(map[string]map[netip.Prefix]bool)
	for _, del := range dels {
		if deleting[del.Netdev] == nil {
			deleting[del.Netdev] = make(map[netip.Prefix]bool)
		}
		deleting[del.Netdev][del.Row.Prefix] = true
	}
	ensured := make(map[string]bool)
	out := dels[:0:0]
	for _, del := range dels {
		if !del.Row.Prefix.Addr().Is4() {
			out = append(out, del)
			continue
		}
		ok, seen := ensured[del.Netdev]
		if !seen {
			err := ensurePromoteSecondariesFn(del.Netdev)
			ok = err == nil
			ensured[del.Netdev] = ok
			if err != nil && d.directVIPLogFirst("promote|"+del.Netdev) {
				slog.Warn("direct VIP reconcile: cannot set promote_secondaries=1; IPv4 VIP deletes that could cascade onto a foreign secondary are skipped",
					"rg", rgID, "iface", del.Netdev, "err", err)
			}
		}
		// Review Z2: only a leftover delete may be skipped. A not-owner delete
		// keeps the pre-#18573 contract (the demoting node must drop the VIP
		// the peer now owns, or both nodes hold it); the sysctl write above
		// was still attempted for it.
		if ok || del.Reason != directVIPDelLeftover || !foreignSubnetPeer(del, rows, deleting[del.Netdev], desired[del.Netdev]) {
			out = append(out, del)
			continue
		}
		if d.directVIPLogFirst("cascade|" + del.Netdev + "|" + del.Row.Prefix.String()) {
			slog.Warn("direct VIP reconcile: not removing IPv4 VIP: promote_secondaries is 0 and its subnet holds an address xpf does not own",
				"rg", rgID, "iface", del.Netdev, "addr", del.Row.Prefix.String(), "reason", del.Reason)
		}
	}
	return out
}

// foreignSubnetPeer reports whether del's netdev holds another IPv4 address
// in the same subnet (same mask and network: the kernel's cascade set) that
// is neither being deleted nor one of this RG's configured VIPs.
func foreignSubnetPeer(del directVIPDel, rows []resolvedAddrRow, deleting map[netip.Prefix]bool, desired []string) bool {
	want := make(map[string]bool, len(desired))
	for _, vip := range desired {
		if p, ok := config.ParseVRRPVIP(vip); ok {
			want[config.PrefixIdentity(p)] = true
		}
	}
	target := del.Row.Prefix.Masked()
	for _, row := range rows {
		if row.Netdev != del.Netdev || row.LinkIndex != del.Row.LinkIndex || !row.Prefix.Addr().Is4() {
			continue
		}
		if row.Prefix.Bits() != target.Bits() || row.Prefix.Masked() != target {
			continue
		}
		if deleting[row.Prefix] || want[row.Identity()] {
			continue
		}
		return true
	}
	return false
}

// verifyDirectVIPStamps reads back the addresses this pass just stamped
// (created or adopted) and latches directVIPStampUnsupported when one reads
// back with proto 0 (review Z1 on #18579): a kernel that drops IFA_PROTO
// (pre-6.3 parses it as an unknown attribute) accepts the add and records 0,
// so the leftover removal of #18573 would be a silent no-op and every tick
// would REPLACE every VIP to adopt it. Warned once; adoption then stops. The
// first stamp that reads back intact latches directVIPStampVerified instead
// (review Z2), so the extra dump is paid once per process, not on every
// promotion's GARP path. An address missing from the readback (removed in
// between), or carrying some other non-zero proto (another writer), proves
// nothing about the kernel and is ignored.
func (d *Daemon) verifyDirectVIPStamps(rgID int, written []directVIPAddrOp, ifindex map[string]int) {
	if len(written) == 0 || d.directVIPStampUnsupported.Load() || d.directVIPStampVerified.Load() {
		return
	}
	rows, err := directVIPAddrDumpFn()
	if err != nil {
		return
	}
	for _, op := range written {
		idx := ifindex[op.Netdev]
		for _, row := range rows {
			if row.LinkIndex != idx || row.Prefix != op.Prefix {
				continue
			}
			switch {
			case row.Stamped():
				// Review Z2: one verified read-back settles the kernel's
				// capability for the process; later writing passes (every
				// promotion) skip the extra dump on the GARP path.
				d.directVIPStampVerified.Store(true)
			case row.Proto == 0 && d.directVIPStampUnsupported.CompareAndSwap(false, true):
				slog.Warn("direct VIP reconcile: a VIP stamped with IFA_PROTO read back with proto 0; this kernel does not record the ownership stamp, so leftover-VIP removal after a renumber cannot work on this node and adoption is disabled (see docs/in-place-upgrade.md \"Honest limits\")",
					"rg", rgID, "iface", op.Netdev, "addr", op.CIDR)
			}
			// A different non-zero proto means another writer replaced the
			// address in between: inconclusive about the kernel, ignored.
			break
		}
		if d.directVIPStampVerified.Load() {
			return
		}
		if d.directVIPStampUnsupported.Load() {
			return
		}
	}
}
