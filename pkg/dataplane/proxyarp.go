package dataplane

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProxyARPAdded describes a newly added proxy ARP/NDP entry (for GARP).
//
// Family is the address family of the installed entry (unix.AF_INET or
// unix.AF_INET6). The caller uses it to gate the gratuitous-ARP send:
// SendGratuitousARP is IPv4-only, so a v6 (AF_INET6) added entry must not be
// handed to it (#2197 item 1, risk R1). The v6 proxy-NDP responder works
// without an unsolicited Neighbor Advertisement, so v6 entries simply skip the
// GARP step rather than emitting a v6 equivalent.
type ProxyARPAdded struct {
	Ifindex int
	IP      net.IP
	Iface   string
	Family  int
}

// netlink seams. The neighbor list/set/del operations are wrapped in package
// vars so unit tests can exercise the family-correct install/stale-removal
// logic (#2197 item 1) without CAP_NET_ADMIN.
//
// #9087 renamed the list seam from neighListSeam to neighProxyListSeam. The old
// name was not cosmetic: it described the wrong netlink call, it matched the
// wrong production wiring underneath it, and every reader who checked "does the
// seam list neighbours? yes" agreed with it. The table this reconcile cares
// about is the PROXY table, and the name now says so. Production wiring is the real
// vishvananda/netlink calls; the kernel handles both AF_INET and AF_INET6
// NTF_PROXY entries through the same RTM_NEWNEIGH/RTM_DELNEIGH (Family-aware,
// To4()/To16() serialized), so no library-side family branching is required.
var (
	// #9087: NeighProxyList, NOT NeighList — and the difference is the whole
	// defect. The two are one field apart in the dump request:
	//
	//	NeighList      -> Ndmsg{Family, Index}                 (Flags 0)
	//	NeighProxyList -> Ndmsg{Family, Index, Flags: NTF_PROXY}
	//
	// The kernel keeps proxy entries in a SEPARATE table (pneigh) and dumps it
	// only when the request carries NTF_PROXY; a plain RTM_GETNEIGH dump
	// returns the ordinary ARP/ND table and no pneigh entry at all. So this
	// listed a table the entries were never in, `existing` came back empty on
	// every pass, and the two loops it feeds both broke, in opposite
	// directions:
	//
	//   - the STALE-REMOVAL loop iterates `existing`, so it removed NOTHING,
	//     EVER. The #8297 standby kept answering proxy-ARP for the pool address
	//     indefinitely — one IP at two RETH virtual MACs — no matter how
	//     correctly the ownership gate fired above it. That is #9087.
	//   - the ADD loop treats every desired key as missing, so it re-issued a
	//     NeighSet on every 30s pass forever. Measured on the loss cluster with
	//     the entry demonstrably present in `ip neigh show proxy`:
	//     `proxy-arp reconciled added=1 removed=0`, every 30 seconds,
	//     indefinitely. A converged reconcile reports added=0.
	//
	// WHY THE UNIT TESTS COULD NOT SEE IT: they replace this seam with a fake
	// that returns whatever the case wants, so in every test the seam behaves
	// like NeighProxyList. The fake was the only NeighProxyList in the tree.
	// The #8597 note further down describes a DIFFERENT cause of the same
	// never-converging symptom (a 4-in-6 key-form mismatch) and was fixed;
	// fixing it removed the error log that made the non-convergence visible
	// while the `added=1` every 30s continued, so nothing prompted a re-look.
	neighProxyListSeam = netlink.NeighProxyList
	neighSetSeam       = netlink.NeighSet
	neighDelSeam       = netlink.NeighDel
	// linkByIndexSeam resolves an ifindex to its link so the procfs name for
	// the proxy responder sysctl can be derived. Wrapped as a package var so
	// the #6536 test can inject a transient resolution failure without
	// deleting a real netdev mid-test. It is also the fetch seam behind
	// CompileResult.cachedLinkByIndex (#9841): first attempt and uncached
	// retry share it so tests script both through one surface.
	linkByIndexSeam = netlink.LinkByIndex
)

// proxyARPSysctlSeam wraps the per-interface procfs writes that toggle the
// kernel's proxy-responder for the families we install neighbor entries for.
// It exists as a package var so unit tests can capture the writes without
// touching real procfs (the production writer is a best-effort os.WriteFile).
// The enable bool selects the value written: true → "1" (enable), false →
// "0" (disable). The disable direction is the #2475 teardown cleanup — a
// day-2 commit removing proxy-arp from an interface must drive the leaked
// sysctl back to 0, mirroring the enable path.
//
// #2160: installing an NTF_PROXY neighbor entry is necessary but, depending
// on the route topology of the proxied address, often not sufficient. The
// Linux kernel has two distinct ARP-proxy reply paths (net/ipv4/arp.c):
//
//  1. the pneigh (NTF_PROXY) reply branch (arp.c:863-868), which fires when
//     forwarding is on, the target's addr_type is RTN_UNICAST, and the route
//     to the target leaves a *different* device than the one the request
//     arrived on (rt.dst.dev != dev) — this branch does NOT consult the
//     per-interface proxy_arp sysctl; and
//  2. the arp_fwd_proxy path, which is gated by net.ipv4.conf.<if>.proxy_arp
//     (and answers for any forwarded-out-a-different-iface target, not only
//     installed pneigh entries).
//
// So whether enabling the sysctl is load-bearing is route-topology dependent:
// for an external address that is on the SAME L2 subnet as the ingress
// interface (rt.dst.dev == dev) neither path answers, and for an address
// routed OUT a different interface the pneigh branch may already answer
// without the sysctl. The empirical #2160 observation (sysctl=0 → no reply
// for the static-NAT external address) is real, so enabling the sysctl is the
// correct fix; we set net.ipv4.conf.<if>.proxy_arp (ARP) and
// net.ipv6.conf.<if>.proxy_ndp (NDP) on every interface with a desired proxy
// entry to guarantee a reply regardless of the topology.
//
// Breadth tradeoff: with the default medium_id=0, per-interface proxy_arp=1
// makes the kernel (path 2 above) answer ARP on that interface for ANY target
// IP that routes out a DIFFERENT interface — not only the configured
// static-NAT external address. This is BROADER than Junos `proxy-arp`, which
// proxies only the listed addresses. It is an operator-opted-in tradeoff (they
// configured proxy-arp on this interface), but the breadth matters on a
// WAN/untrust interface. Narrowing to per-address (Junos parity) is tracked in
// follow-up #2197.
var proxyARPSysctlSeam = writeProxyResponderSysctl

// writeProxyResponderSysctl toggles the kernel proxy responder for the given
// interface and address family. enable selects the written value: true → "1",
// false → "0". Best-effort: a failure (read-only procfs, interface vanished)
// is logged by the caller, never fatal — matching the surrounding proxy-ARP
// reconcile's best-effort posture.
func writeProxyResponderSysctl(iface string, family int, enable bool) error {
	var path string
	switch family {
	case unix.AF_INET:
		path = fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", iface)
	case unix.AF_INET6:
		path = fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface)
	default:
		return fmt.Errorf("proxy-arp: unsupported family %d", family)
	}
	val := []byte("0")
	if enable {
		val = []byte("1")
	}
	return os.WriteFile(path, val, 0644)
}

// enableProxyResponders enables the per-interface proxy responder sysctl for
// every (interface, family) pair that has at least one desired proxy entry.
// Pure decision logic over the resolved iface-name→family set so it is unit
// testable; the actual procfs writes go through proxyARPSysctlSeam. Returns
// the number of writes that succeeded.
//
// ifaceFamilies maps an interface NAME (the kernel/procfs name, matching the
// interface the neighbor entry is installed on) to the set of address
// families that have a desired proxy entry on that interface. The sysctl is
// enabled idempotently (the kernel no-ops a write of the already-set value),
// so we always write rather than read-modify-write. A deterministic key sort
// keeps logging stable.
func enableProxyResponders(ifaceFamilies map[string]map[int]struct{}) int {
	return toggleProxyResponders(ifaceFamilies, true)
}

// proxyResponderSysctlEnabledFor reports whether the per-interface kernel proxy
// responder sysctl should be turned ON for a family, given that this interface
// has a desired proxy entry.
//
// #8637: IPv4 is NO. The `proxy_arp` sysctl was added by #2160 and it never did
// the job it was added for.
//
// #2160's own example is `proxy-arp ge-0/0/1 address 10.0.2.50/32`, and
// `ge-0-0-1` carries `10.0.2.10/24` — so the proxied address is inside the
// CONNECTED SUBNET of the very interface the ARP request arrives on. For that
// topology `rt->dst.dev == dev`, and every arm of `arp_process`'s proxy branch
// declines: `arp_fwd_proxy` returns 0 on its FIRST line before it ever reads
// this sysctl, the `pneigh_lookup` arm is guarded by `rt->dst.dev != dev`, and
// only `arp_fwd_pvlan` could answer — which #2160 names parenthetically and
// which nothing sets. The issue was closed on a change that cannot have fixed
// it; the same-L2 case was genuinely fixed only by #8621's userspace responder.
//
// MEASURED on the loss userspace cluster, with the pneigh entry installed
// manually so the #8621 responder could not confound the reading:
//
//	target routed out a DIFFERENT device, entry present:
//	    proxy_arp=1 -> answered      proxy_arp=0 -> STILL ANSWERED
//	target routed out a DIFFERENT device, NO entry:
//	    proxy_arp=1 -> ANSWERED      proxy_arp=0 -> silent
//
// The first row is the pneigh arm, which has no sysctl term and needs none. The
// second row is the sysctl's ONLY distinct contribution: answering for
// addresses nobody configured. That is the over-answer #2197 item 3 asked to
// remove for Junos parity, and it is on by default in every config that uses
// `proxy-arp` at all — including WAN and untrust interfaces.
//
// So turning it off loses nothing that ever worked and removes an unbounded
// ARP-answering posture. Per-address behaviour is now carried by the pneigh
// entries (different-device) and by the #8621 responder (same-device), both of
// which answer only for configured addresses.
//
// IPv6 is YES and the asymmetry has a reason. `ndisc_recv_ns` gates on
// `forwarding && proxy_ndp && pndisc_is_router(...)` — a REQUIRED CONJUNCT, not
// an alternative path — so clearing `proxy_ndp` would break v6 proxy NDP
// entirely. v4's pneigh arm has no sysctl term; v6's does. #2197 item 3 already
// scoped itself v4-only; this is why.
func proxyResponderSysctlEnabledFor(family int) bool {
	return family == unix.AF_INET6
}

// disableProxyResponders writes "0" to the per-interface proxy responder
// sysctl for every (interface, family) pair in ifaceFamilies. It is the
// #2475 teardown cleanup: a day-2 commit that removes proxy-arp from an
// interface must drive net.ipv4.conf.<if>.proxy_arp /
// net.ipv6.conf.<if>.proxy_ndp back to 0, otherwise the kernel keeps
// proxy-ARPing for any target routed out a different interface (an
// over-broad responder leaked across config changes — see the
// proxyARPSysctlSeam breadth note). It mirrors enableProxyResponders
// exactly (same iteration, same best-effort/never-fatal posture, same
// deterministic v4-before-v6 order) so the disable is symmetric with the
// enable. Returns the number of writes that succeeded.
func disableProxyResponders(ifaceFamilies map[string]map[int]struct{}) int {
	return toggleProxyResponders(ifaceFamilies, false)
}

// toggleProxyResponders is the shared body of enableProxyResponders /
// disableProxyResponders: it writes the proxy responder sysctl (value chosen
// by enable) for every (interface, family) pair, in a deterministic
// interface-name order with v4 before v6. A per-write failure is logged and
// skipped (best-effort) without aborting the remaining writes.
func toggleProxyResponders(ifaceFamilies map[string]map[int]struct{}, enable bool) int {
	count := 0
	names := make([]string, 0, len(ifaceFamilies))
	for iface := range ifaceFamilies {
		names = append(names, iface)
	}
	sort.Strings(names)
	for _, iface := range names {
		fams := ifaceFamilies[iface]
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			if _, ok := fams[family]; !ok {
				continue
			}
			// #8637: v4 is driven to 0 even on the ENABLE pass. Not merely
			// "stop setting it" — an upgrade from a build that set it would
			// otherwise leave a stale proxy_arp=1 on every interface already
			// carrying a proxy-arp entry, so the over-answer would survive the
			// change on exactly the deployments that have it today.
			want := enable && proxyResponderSysctlEnabledFor(family)
			if err := proxyARPSysctlSeam(iface, family, want); err != nil {
				verb := "enable"
				if !want {
					verb = "disable"
				}
				slog.Warn("proxy-arp: failed to "+verb+" proxy responder sysctl",
					"iface", iface, "family", family, "err", err)
				continue
			}
			count++
		}
	}
	return count
}

// ReconcileProxyARP reconciles proxy ARP neighbor entries for NAT addresses.
// It adds NTF_PROXY neighbor entries for configured addresses and removes
// stale ones from managed interfaces.
//
// Returns:
//   - the newly added entries so the caller can send GARPs (avoids an import
//     cycle with the cluster package);
//   - the (interface name → enabled families) set the per-interface proxy
//     responder sysctl was enabled for this pass. The caller (the daemon)
//     remembers this set across commits and disables the sysctl on any
//     interface that drops out of it on a later commit — the #2475 teardown
//     cleanup. ReconcileProxyARP itself is stateless across calls (it only
//     sees the current config), so the enabled set is the seam the stateful
//     disable-on-removal is built on.
//
// priorIfaceMap is the (interface name → ifindex) set that proxy-arp was
// installed on by a PRIOR commit (the daemon's remembered state). Its
// ifindexes are folded into the managed listing set so NTF_PROXY neighbor
// entries are also swept off interfaces that have since dropped out of the
// config: without this the entries are orphaned in the kernel and keep
// answering ARP/NDP for the removed target (#4955, distinct from the #2475
// sysctl-only teardown). Because such interfaces are absent from the desired
// set, every NTF_PROXY entry found on them is stale and NeighDel'd. Pass nil
// when there is no prior state to sweep.
//
// ifaceNames maps each ifindex in ifaceMap to the Linux netdev name the
// CALLER resolved it from. It is the fallback the enabled-set keys are built
// on when netlink cannot resolve the ifindex back to a link (#6536).
//
// #6536 — WHY A FALLBACK NAME AND NOT A DROPPED ENTRY. The returned enabled
// set is the daemon's memory of the interfaces whose responder sysctl it must
// eventually tear down, and the ONLY input to that teardown diff: an interface
// that drops out of the set is disabled (a destructive sysctl write) and
// forgotten (so the #4955 NTF_PROXY sweep loses it too). Both are correct for
// "no longer configured" and both are wrong for "still configured, but the
// ifindex would not resolve this pass" — netlink can fail transiently
// (ENOBUFS on a busy dump, EMFILE, a VLAN netdev being re-created), and a
// pre-#6536 LinkByIndex error folded that case into "not configured" and
// disabled a live responder. Every ifindex reaching the sysctl step came from
// the config, so it is ALWAYS still configured; the caller already resolved
// its name to obtain the ifindex, so passing that name down means a failed
// netlink lookup degrades to "re-assert under the known name" instead of
// "tear down". A nil/absent ifaceNames entry leaves the old behaviour (log and
// drop) for callers that have no name to offer.
//
// On a partial NeighSet failure the add loop is best-effort (logs and
// continues) and still returns the computed enabled set plus the first error,
// rather than aborting with a nil enabled set — otherwise the daemon would
// forget the interfaces it just tried to manage and never tear them down
// (#4955 secondary).
func ReconcileProxyARP(cfg *config.Config, ifaceMap, priorIfaceMap map[string]int, ifaceNames map[int]string) ([]ProxyARPAdded, map[string]map[int]struct{}, error) {
	type proxyKey struct {
		ifindex int
		ip      netip.Addr
	}

	// Build desired set from config.
	desired := make(map[proxyKey]struct{})
	var managedIfindexes []int

	// ifindexFamilies records, per interface ifindex, the set of address
	// families that have at least one desired proxy entry. Used to enable
	// the per-interface kernel proxy responder sysctl (#2160). The NTF_PROXY
	// neighbor entry alone answers only via the kernel's pneigh reply branch,
	// which is route-topology dependent (it requires the target to route out a
	// different device than the request arrived on — see the proxyARPSysctlSeam
	// doc); setting net.ipv4.conf.<if>.proxy_arp / proxy_ndp guarantees a reply
	// regardless of topology, which is what #2160 needed.
	// Keyed by ifindex so the procfs interface name resolves from the same
	// link the neighbor entry is installed on (handles VLAN sub-interface
	// renaming consistently with the install).
	ifindexFamilies := make(map[int]map[int]struct{})
	recordFamily := func(ifindex, family int) {
		fams := ifindexFamilies[ifindex]
		if fams == nil {
			fams = make(map[int]struct{})
			ifindexFamilies[ifindex] = fams
		}
		fams[family] = struct{}{}
	}

	var cfgEntries []*config.ProxyARPEntry
	if cfg != nil {
		cfgEntries = cfg.Security.NAT.ProxyARP
	}
	for _, entry := range cfgEntries {
		ifindex, ok := ifaceMap[entry.Interface]
		if !ok {
			// #9087: this fires for TWO different reasons and used to name only
			// one of them. "Not found" is true when the netdev did not resolve;
			// it is FALSE and misleading when the caller deliberately dropped
			// the interface because this node must not answer for it (#8297
			// ownership suppression) — the interface was found, and the entry
			// is expected to be swept, not installed. A reader chasing a
			// "not found" warning on a healthy standby is chasing the wrong
			// thing, and the sweep that should follow is in priorIfaceMap's
			// hands, not this loop's.
			slog.Debug("proxy-arp: no ifindex for a configured entry on this pass; "+
				"either the netdev did not resolve or this node is not the owner "+
				"and the entry is a sweep target rather than an install",
				"iface", entry.Interface, "issue", "#9087")
			continue
		}
		managedIfindexes = append(managedIfindexes, ifindex)
		for _, cidr := range entry.Addresses {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				slog.Warn("proxy-arp: invalid address", "addr", cidr, "err", err)
				continue
			}
			// #8597 (muse-004 K21): UNMAP. A `::ffff:a.b.c.d` literal parses to
			// a 4-in-6 `netip.Addr` (16 bytes), while the kernel's v4 NeighList
			// pass below builds its key from `n.IP.To4()` (4 bytes). `netip.Addr`
			// equality distinguishes the two forms, so the desired key never
			// matched the existing key and the add loop re-installed the entry on
			// EVERY reconcile pass — a NeighSet and an error log every 30s,
			// forever, with the entry never recognised as converged.
			//
			// The comment below and `keyFamily` both reason correctly about the
			// FAMILY of a 4-in-6 literal and are silent about its KEY FORM, which
			// is why this read as handled. Unmapping at parse makes both axes
			// agree: a v4-mapped literal is v4 in family AND in key form, and
			// `Unmap` is a no-op on a genuine v6 address.
			addr := prefix.Addr().Unmap()
			// #2197 item 1: install an NTF_PROXY neighbor entry for v6
			// addresses too (the v6 analogue of `ip -6 neigh add proxy
			// <addr> dev <if>`). Unlike v4 — where the broad arp_fwd_proxy
			// path can answer without a pneigh entry — IPv6 proxy-NDP is
			// gated on pneigh_lookup itself (net/ipv6/ndisc.c): the kernel
			// answers a v6 NS only if a matching v6 pneigh entry exists
			// (plus forwarding + proxy_ndp). So the v6 install is the
			// necessary-and-sufficient piece per listed address, and there
			// is no v6 over-answer breadth (the #2197 narrowing follow-up is
			// v4-only). A ::ffff:0:0/96 v4-mapped literal classifies as v4
			// (Is4In6) so it takes the v4 install path, never a v6 NeighSet.
			family := unix.AF_INET
			if addr.Is6() && !addr.Is4In6() {
				family = unix.AF_INET6
			}
			desired[proxyKey{ifindex, addr}] = struct{}{}
			recordFamily(ifindex, family)
		}
	}

	// Collect existing NTF_PROXY entries on managed interfaces.
	existing := make(map[proxyKey]struct{})
	managedSet := make(map[int]bool)
	for _, idx := range managedIfindexes {
		managedSet[idx] = true
	}
	// #4955: also list interfaces that a PRIOR commit installed proxy-arp on
	// but that have since dropped out of the config. They contribute no desired
	// entries, so any NTF_PROXY entry still on them is stale and swept below —
	// closing the orphan where a removed interface kept answering ARP/NDP.
	for _, idx := range priorIfaceMap {
		managedSet[idx] = true
	}

	// keyFamily derives the netlink address family for a key from its IP so
	// the add/remove netlink.Neigh carries the correct family. A v4-mapped v6
	// literal (Is4In6) is treated as v4 — consistent with the desired-set
	// classification above.
	keyFamily := func(ip netip.Addr) int {
		if ip.Is6() && !ip.Is4In6() {
			return unix.AF_INET6
		}
		return unix.AF_INET
	}

	// List existing NTF_PROXY entries for BOTH families on each managed
	// interface. The netip.Addr key keeps v4 and v6 disjoint, and each
	// NeighList(family) pass already only returns that family's entries, so a
	// v4-mapped form cannot be double-counted (#2197 item 1, risk R2).
	for idx := range managedSet {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			neighs, err := neighProxyListSeam(idx, family)
			if err != nil {
				slog.Warn("proxy-arp: failed to list neighbors",
					"ifindex", idx, "family", family, "err", err)
				continue
			}
			for _, n := range neighs {
				if n.Flags&unix.NTF_PROXY == 0 {
					continue
				}
				if n.IP == nil {
					continue
				}
				var addr netip.Addr
				var ok bool
				if family == unix.AF_INET6 {
					// Skip v4-mapped entries surfaced on the v6 pass; the
					// v4 pass owns them via To4().
					if n.IP.To4() != nil {
						continue
					}
					addr, ok = netip.AddrFromSlice(n.IP.To16())
				} else {
					addr, ok = netip.AddrFromSlice(n.IP.To4())
				}
				if !ok {
					continue
				}
				existing[proxyKey{idx, addr}] = struct{}{}
			}
		}
	}

	// Add missing entries (family derived from the key — v4 and v6 share the
	// same NTF_PROXY install path; #2197 item 1).
	//
	// #4955: the add loop is best-effort. A NeighSet failure is logged and the
	// remaining installs still proceed, and the function returns the computed
	// enabled set (below) plus the first error instead of bailing out with a
	// nil enabled set. Aborting here previously made the daemon overwrite its
	// remembered state with nil, so it forgot every interface it had managed
	// and never disabled the sysctl or swept the neighbor entries on a later
	// removal.
	var added []ProxyARPAdded
	var addErr error
	for key := range desired {
		if _, ok := existing[key]; ok {
			continue
		}
		family := keyFamily(key.ip)
		neigh := &netlink.Neigh{
			LinkIndex: key.ifindex,
			IP:        key.ip.AsSlice(),
			Flags:     unix.NTF_PROXY,
			Family:    family,
		}
		if err := neighSetSeam(neigh); err != nil {
			slog.Warn("proxy-arp: failed to add entry",
				"ip", key.ip, "ifindex", key.ifindex, "err", err)
			if addErr == nil {
				addErr = fmt.Errorf("proxy-arp: add %s on ifindex %d: %w", key.ip, key.ifindex, err)
			}
			continue
		}
		// #6536 deliberately does NOT apply the ifaceNames fallback here: an
		// unresolved name only costs this entry its gratuitous ARP (the caller
		// skips the GARP on an empty Iface), which is transient and self-heals
		// on the next reconcile. The enabled-set resolution above is the one
		// whose failure is DESTRUCTIVE (a sysctl disable on a live responder),
		// so the fallback is scoped to it.
		ifaceName := ""
		if link, err := linkByIndexSeam(key.ifindex); err == nil {
			ifaceName = link.Attrs().Name
		}
		added = append(added, ProxyARPAdded{
			Ifindex: key.ifindex,
			IP:      net.IP(key.ip.AsSlice()),
			Iface:   ifaceName,
			Family:  family,
		})
	}

	// Remove stale entries on managed interfaces (both families now listed).
	var removed int
	for key := range existing {
		if _, ok := desired[key]; ok {
			continue
		}
		neigh := &netlink.Neigh{
			LinkIndex: key.ifindex,
			IP:        key.ip.AsSlice(),
			Flags:     unix.NTF_PROXY,
			Family:    keyFamily(key.ip),
		}
		if err := neighDelSeam(neigh); err != nil {
			slog.Warn("proxy-arp: failed to remove stale entry",
				"ip", key.ip, "ifindex", key.ifindex, "err", err)
		} else {
			removed++
		}
	}

	// Enable the per-interface kernel proxy responder sysctl for every
	// interface that has a desired proxy entry (#2160). The pneigh entry
	// installed above only answers via a route-topology-dependent kernel path
	// (see proxyARPSysctlSeam); the sysctl guarantees a reply. Resolve the
	// procfs interface name from the same ifindex the neighbor entry was
	// installed on so VLAN sub-interface naming stays consistent with the
	// install.
	ifaceFamilies := make(map[string]map[int]struct{}, len(ifindexFamilies))
	for ifindex, fams := range ifindexFamilies {
		name := ""
		link, err := linkByIndexSeam(ifindex)
		if err == nil {
			name = link.Attrs().Name
		} else if fallback, ok := ifaceNames[ifindex]; ok && fallback != "" {
			// #6536: the ifindex is still CONFIGURED — it was just built from
			// cfg above — so a netlink resolution failure must not be reported
			// as "no longer configured". Re-assert under the name the caller
			// resolved this ifindex from and keep the interface in the enabled
			// set, so the teardown diff never disables a live responder and the
			// #4955 sweep does not forget the interface.
			slog.Warn("proxy-arp: ifindex did not resolve to a link; falling back to the "+
				"caller-resolved interface name for the proxy responder sysctl",
				"ifindex", ifindex, "iface", fallback, "err", err, "issue", "#6536")
			name = fallback
		} else {
			slog.Warn("proxy-arp: cannot resolve interface name for proxy responder sysctl",
				"ifindex", ifindex, "err", err)
			continue
		}
		ifaceFamilies[name] = fams
	}
	enableProxyResponders(ifaceFamilies)

	if len(added) > 0 || removed > 0 {
		slog.Info("proxy-arp reconciled", "added", len(added), "removed", removed)
	}

	return added, ifaceFamilies, addErr
}

// DisableProxyResponders writes "0" to the per-interface proxy responder
// sysctl for every (interface name → families) pair in ifaceFamilies. It is
// the exported #2475 teardown entry point the daemon calls for interfaces
// that had the sysctl enabled on a prior commit but are no longer in the
// desired set (proxy-arp removed from that interface). Best-effort and
// never fatal, matching ReconcileProxyARP. Returns the number of successful
// writes.
func DisableProxyResponders(ifaceFamilies map[string]map[int]struct{}) int {
	return disableProxyResponders(ifaceFamilies)
}
