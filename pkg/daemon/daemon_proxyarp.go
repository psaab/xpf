package daemon

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// proxyARPReassertInterval is the cadence of the always-on proxy-ARP/NDP
// re-assert loop (#2197 item 2). Proxy-ARP is not latency sensitive, so a
// worst-case ~30s lag re-asserting net.ipv4.conf.<if>.proxy_arp /
// net.ipv6.conf.<if>.proxy_ndp (and the NTF_PROXY entries) after a non-commit
// link cycle is acceptable. The reconcile is netlink + procfs only (no helper
// control socket), so a 30s cadence keeps load trivial and stays well clear of
// the >1/s control-socket contention rule. A package var (not a const) so the
// loop test can shorten it.
var proxyARPReassertInterval = 30 * time.Second

// proxyARPReconcileFn is the function the re-assert loop invokes each tick. It
// is a package var so the loop test can substitute a counting fake without
// touching netlink/procfs; production wiring is (*Daemon).reconcileProxyARP.
var proxyARPReconcileFn = (*Daemon).reconcileProxyARP

// proxyARPDisableFn is the disable-on-removal sink the reconcile invokes for
// the stale (interface → families) set (#2475). It is a package var so the
// fail-on-revert test can capture the teardown writes without touching real
// procfs; production wiring is dataplane.DisableProxyResponders.
var proxyARPDisableFn = dataplane.DisableProxyResponders

// proxyARPApplyFn is the dataplane reconcile the daemon drives each commit. It
// is a package var so the #4955 test can assert the daemon feeds the
// prior-interface set through to the NTF_PROXY sweep without touching netlink;
// production wiring is dataplane.ReconcileProxyARP.
var proxyARPApplyFn = dataplane.ReconcileProxyARP

// ifaceIndexByName resolves a Linux interface name to its kernel ifindex. It
// is a package var so the RETH-resolution unit test can drive
// proxyARPIfaceMap without real interfaces; production wiring is
// net.InterfaceByName.
var ifaceIndexByName = func(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// proxyARPIfaceMap maps each configured proxy-arp interface name to its kernel
// ifindex via cfg.ResolveKernelIfName — the centralized Junos-ref → Linux
// netdev resolver. This resolves a RETH name to its physical member (the #2195
// fix) AND a VLAN sub-interface (reth0.50, ge-0/0/0.100) to its OWN VLAN netdev
// (ge-0-0-0.<vlan-id>), not the parent (#3010). The latter is essential because
// Linux proxy_arp/proxy_ndp are per-netdev: a VLAN sub-interface is a distinct
// netdev with its own sysctl path and neighbor scope, so storing the parent
// ifindex would write the sysctl on the parent and leave the sub-interface
// silent. ResolveKernelIfName maps a tagged unit to its VLAN ID (which can
// differ from the unit number), collapses unit 0 onto the bare parent, and
// preserves the st<N>/IRB/tunnel special cases — strictly more correct than the
// old RethToPhysical + LinuxIfName(base) path that dropped the unit suffix.
// Extracted so the resolution stays unit-testable independently of the netlink
// install (regression guard against dropping the per-netdev resolution in the
// apply-path extraction).
//
// It returns three things:
//   - byJunos: the Junos interface name → ifindex map the dataplane reconcile
//     consumes;
//   - names: the reverse ifindex → Linux netdev name mapping, handed to
//     ReconcileProxyARP as the #6536 fallback for the responder-sysctl keys
//     when netlink cannot resolve the ifindex back to a link;
//   - unresolved: the Linux netdev names of CONFIGURED entries whose ifindex
//     did not resolve at all.
//
// #6536: unresolved is the debt channel. A name in it is still configured for
// proxy-arp — the reconcile simply could not find its kernel identity this
// pass — so the caller must NOT let it fall out of the enabled set, where the
// #2475 teardown diff would read the absence as "proxy-arp was removed from
// this interface" and write the responder sysctl to 0 on a live interface.
// Before #6536 the resolution failure was logged and dropped, and those two
// conditions were indistinguishable to every downstream consumer.
func proxyARPIfaceMap(cfg *config.Config) (byJunos map[string]int, names map[int]string, unresolved []string) {
	return proxyARPIfaceMapFiltered(cfg, nil)
}

// proxyARPIfaceMapFiltered is proxyARPIfaceMap with the #8297 ownership gate.
//
// `suppress` reports whether THIS node must not answer for an entry's
// interface; a nil predicate keeps the pre-#8297 behaviour (answer for
// everything), which is what the non-daemon callers want.
//
// A suppressed entry is dropped from `byJunos`/`names` and NOT added to
// `unresolved`: the two mean different things and conflating them would be the
// #6536 bug. Unresolved means "we could not find the netdev, retain its
// responder state as debt"; suppressed means "we found it and this node must
// not answer", so its entry must be actively torn down by the reconcile sweep
// rather than retained.
func proxyARPIfaceMapFiltered(
	cfg *config.Config,
	suppress func(ifaceRef string) bool,
) (byJunos map[string]int, names map[int]string, unresolved []string) {
	byJunos = make(map[string]int)
	names = make(map[int]string)
	seenUnresolved := make(map[string]bool)
	for _, entry := range cfg.Security.NAT.ProxyARP {
		if _, ok := byJunos[entry.Interface]; ok {
			continue
		}
		// #8297: the standby must not answer for a pool address on an RG it
		// does not own — the upstream otherwise sees one IP at two RETH virtual
		// MACs and pool-mode return traffic lands on the wrong node. Measured:
		// owner TX +7, standby helper RX +7, all seven a session miss there.
		//
		// This suppresses ONLY on an affirmative not-owner. #8314 suppressed on
		// !AllVRRPMaster, which also fires when ownership is UNKNOWN, and
		// silenced both nodes (#8342: fw0=0 fw1=0).
		if suppress != nil && suppress(entry.Interface) {
			slog.Info("proxy-arp: suppressing responder for an interface this node does not own",
				"iface", entry.Interface, "issue", "#8297")
			continue
		}
		linuxName := cfg.ResolveKernelIfName(entry.Interface)
		idx, err := ifaceIndexByName(linuxName)
		if err != nil {
			slog.Warn("proxy-arp: interface not found; retaining its responder state as debt "+
				"for the next reconcile rather than tearing it down",
				"iface", entry.Interface, "linux", linuxName, "err", err, "issue", "#6536")
			if !seenUnresolved[linuxName] {
				seenUnresolved[linuxName] = true
				unresolved = append(unresolved, linuxName)
			}
			continue
		}
		byJunos[entry.Interface] = idx
		names[idx] = linuxName
	}
	return byJunos, names, unresolved
}

// priorProxyARPIfaceMap resolves the interfaces proxy-arp was installed on by a
// PRIOR commit — the Linux netdev names remembered in d.proxyARPEnabled (which
// ReconcileProxyARP keys by link.Attrs().Name) — to their current kernel
// ifindexes. The dataplane reconcile folds these into its managed listing set
// so it sweeps orphaned NTF_PROXY neighbor entries off interfaces that have
// since dropped out of the config (#4955). A name that no longer resolves (its
// netdev was deleted) is skipped: its neighbor entries went away with the
// netdev, so there is nothing left to sweep.
func priorProxyARPIfaceMap(priorNames []string) map[string]int {
	m := make(map[string]int, len(priorNames))
	for _, name := range priorNames {
		idx, err := ifaceIndexByName(name)
		if err != nil {
			continue
		}
		m[name] = idx
	}
	return m
}

// reconcileProxyARP reconciles the kernel proxy-ARP/NDP responder state
// (NTF_PROXY neighbor entries + the per-interface proxy_arp/proxy_ndp sysctls)
// for the configured `security nat proxy-arp` addresses. It is a no-op when no
// proxy-arp entries are configured.
//
// This is the apply-path reconcile (formerly inline in applyConfigLocked step
// 2.6c) extracted so the always-on periodic loop can re-run the identical
// reconcile after a non-commit link cycle (an HA RETH member flap or the
// programRethMAC link-DOWN/UP fallback) re-defaults the per-interface sysctl
// to its parent value (#2197 item 2). The reconcile is idempotent (it diffs
// desired vs existing entries and re-writes the sysctl, which the kernel
// no-ops when already set) and best-effort (a netlink/sysctl failure is logged
// and never fatal), so re-running it on a steady config causes no churn.
//
// The interface resolution (RETH name → physical member, #2195; VLAN
// sub-interface → its own VLAN netdev, #3010) is performed by proxyARPIfaceMap
// via cfg.ResolveKernelIfName; losing it would re-break proxy-arp on RETH or
// VLAN-tagged interfaces.
func (d *Daemon) reconcileProxyARP(cfg *config.Config) {
	// #2475/#4955: a commit that REMOVES proxy-arp (cfg now has zero entries)
	// must still run so the reconcile can (a) drive the leaked proxy_arp /
	// proxy_ndp sysctl back to 0 and (b) NeighDel the orphaned NTF_PROXY
	// entries on the interfaces a prior commit installed them on. Only skip the
	// expensive netlink reconcile + iface resolution when there is also nothing
	// to tear down, preserving the "no-op on configs that never use proxy-arp"
	// property the always-on loop relies on.
	hasEntries := cfg != nil && len(cfg.Security.NAT.ProxyARP) > 0

	// #8621: keep the userspace ARP responders in step with the config.
	//
	// The kernel entries this function installs CANNOT answer for a pool
	// address inside its own egress interface's connected subnet — every arm of
	// arp_process's proxy branch is gated on the route egressing a DIFFERENT
	// device than the request arrived on. Without a responder the configuration
	// compiles, installs, reports success and answers nothing.
	//
	// FIRST, above the early return below. That return fires when there is
	// nothing configured AND nothing installed, and a responder still running
	// then would answer for an address this node no longer proxies. Placing the
	// sync above it means "no config" always reaches "stop everything".
	//
	// Driven by the UNFILTERED interface map on purpose. `ifaceMap` further
	// down is filtered by `proxyARPEntrySuppressed`, which is right for
	// installing kernel entries and wrong here: a responder started only while
	// this node owns the group would not EXIST at the moment ownership arrives,
	// and would not start until the next 30s reassert. Instead one runs for
	// every configured interface and consults ownership per REQUEST, so a
	// failover takes effect on the next frame.
	d.syncProxyARPResponders(cfg, proxyARPResponderTargets(cfg))

	// Snapshot the interfaces a prior commit installed proxy-arp on so the
	// stateless dataplane reconcile can sweep entries that dropped out of the
	// config (#4955). Keys are Linux netdev names (ReconcileProxyARP keys its
	// enabled set by link.Attrs().Name), so they resolve directly via
	// ifaceIndexByName without cfg.ResolveKernelIfName.
	d.proxyARPEnabledMu.Lock()
	priorNames := make([]string, 0, len(d.proxyARPEnabled))
	for iface := range d.proxyARPEnabled {
		priorNames = append(priorNames, iface)
	}
	d.proxyARPEnabledMu.Unlock()

	if !hasEntries && len(priorNames) == 0 {
		// #7685: nothing configured and nothing installed — no debt is possible,
		// so clear any retained from a prior config. Without this a commit that
		// REMOVES proxy-arp leaves the gauge latched on an interface nobody is
		// asking for any more.
		d.setProxyARPUnresolved(nil)
		return
	}

	priorIfaceMap := priorProxyARPIfaceMap(priorNames)
	ifaceMap := map[string]int{}
	ifaceNames := map[int]string{}
	var unresolved []string
	// #9087: the interfaces this pass SUPPRESSED, kept so the sweep does not
	// lose sight of them.
	//
	// proxyARPIfaceMapFiltered's own doc says a suppressed entry "must be
	// actively torn down by the reconcile sweep rather than retained" — and the
	// sweep can only reach an interface that is in `ifaceMap` or in
	// `priorIfaceMap`. A suppressed entry is in neither after the FIRST
	// suppressed pass, because that pass writes an `enabled` set with the
	// interface gone, so `priorNames` is empty on every pass after it. The
	// teardown therefore had exactly ONE chance to happen, on the pass that ran
	// during demotion — which is precisely when programRethMAC's link DOWN/UP
	// makes the netdev hardest to resolve.
	//
	// Measured on the loss cluster: fw1 in secondary-hold, logging
	// "suppressing responder for an interface this node does not own" every 30s
	// AND still holding the kernel NTF_PROXY entry for the pool address, with
	// fw0 holding it too — the #8297 two-MAC state, indefinitely, not for a
	// 30-second window.
	var suppressed []string
	if hasEntries {
		ifaceMap, ifaceNames, unresolved = proxyARPIfaceMapFiltered(cfg, func(ref string) bool {
			if !d.proxyARPEntrySuppressed(cfg, ref) {
				return false
			}
			if linux := cfg.ResolveKernelIfName(ref); linux != "" {
				suppressed = append(suppressed, linux)
			}
			return true
		})
	}
	// #7685: retain the debt this pass observed. Set on EVERY completing pass,
	// including the teardown pass where hasEntries is false and unresolved is
	// therefore empty, so the value always describes the latest reconcile rather
	// than the last one that happened to find something.
	d.setProxyARPUnresolved(unresolved)

	// Always run the reconcile: even with zero configured entries it sweeps the
	// orphaned NTF_PROXY entries on the prior interfaces (desired is empty
	// there, so every entry found is stale and deleted) and returns a non-nil
	// enabled set so the diff below tears down the sysctl.
	added, enabled, err := proxyARPApplyFn(cfg, ifaceMap, priorIfaceMap, ifaceNames)
	if err != nil {
		slog.Warn("failed to reconcile proxy ARP", "err", err)
	}

	// #2475 teardown: disable the per-interface proxy responder sysctl on every
	// (interface, family) that was enabled by a prior commit but is no longer
	// in the freshly-enabled set. Without this the over-broad proxy_arp /
	// proxy_ndp knob leaks on across the config removal until reboot. The diff
	// is computed under proxyARPEnabledMu so the apply path and the always-on
	// re-assert loop cannot race the remembered state.
	//
	// #6536: an interface whose kernel identity did not resolve this pass is
	// still CONFIGURED, so it is carried forward into the enabled set BEFORE
	// the diff. Without that carry-forward the absence reads as "proxy-arp was
	// removed from this interface" and the diff disables a live responder —
	// and the interface is forgotten, so the #4955 orphan sweep loses it too.
	d.proxyARPEnabledMu.Lock()
	enabled = retainUnresolvedProxyResponders(enabled, d.proxyARPEnabled, unresolved)
	// #9087: a SUPPRESSED interface stays in the remembered set for as long as
	// the config names it, so every later pass still carries it in
	// priorIfaceMap and the sweep keeps deleting any NTF_PROXY entry that
	// reappears there. Without this the teardown is a ONE-SHOT it can miss.
	//
	// This is not the #6536 retention above and must not be folded into it:
	// that one retains an UNRESOLVED interface so its responder is not
	// disabled, i.e. it protects a live responder. This one retains a
	// SUPPRESSED interface so its entry keeps being SWEPT — the opposite
	// intent, on interfaces whose responder must stay off.
	enabled = retainSuppressedProxySweepTargets(enabled, d.proxyARPEnabled, suppressed)
	stale := diffProxyResponders(d.proxyARPEnabled, enabled)
	d.proxyARPEnabled = enabled
	d.proxyARPEnabledMu.Unlock()
	if len(stale) > 0 {
		proxyARPDisableFn(stale)
	}

	for _, a := range added {
		// SendGratuitousARP is IPv4-only; a v6 (AF_INET6) proxy-NDP entry
		// needs no unsolicited NA to start answering, so skip the GARP for
		// v6 added entries (#2197 item 1). Failover invalidation is separate:
		// announceProxyARPPoolAddresses sends a pool-target NA on RG ownership
		// change (#12172), refreshing upstream neighbor bindings.
		if a.Iface != "" && a.Family != unix.AF_INET6 {
			if err := cluster.SendGratuitousARP(a.Iface, a.IP, 1); err != nil {
				slog.Warn("proxy-arp: GARP failed", "ip", a.IP, "iface", a.Iface, "err", err)
			}
		}
	}

}

// proxyARPResponderTargets maps kernel netdev name -> Junos interface ref for
// every interface with proxy-ARP configured, resolved but NOT ownership
// filtered. Nil cfg yields an empty set, which stops every responder.
func proxyARPResponderTargets(cfg *config.Config) map[string]string {
	want := map[string]string{}
	if cfg == nil || len(cfg.Security.NAT.ProxyARP) == 0 {
		return want
	}
	byJunos, names, _ := proxyARPIfaceMap(cfg)
	for junosRef, idx := range byJunos {
		if n := names[idx]; n != "" {
			want[n] = junosRef
		}
	}
	return want
}

// retainUnresolvedProxyResponders carries the PRIOR responder state of every
// interface in unresolved forward into the freshly-enabled set (#6536).
//
// unresolved holds the Linux netdev names of interfaces that are STILL
// configured for proxy-arp but whose ifindex did not resolve on this pass. The
// reconcile therefore could not enable (or even name) their responder, so they
// are absent from enabled — the same shape a removed interface has. Feeding
// that absence to diffProxyResponders would disable the responder sysctl on an
// interface the operator still has configured, and drop it from the remembered
// state so no later pass could ever tear it down. Retaining the prior families
// keeps the interface as debt: the next reconcile that CAN resolve it either
// re-asserts it (still configured) or, once it really leaves the config, tears
// it down through the normal diff.
//
// An unresolved interface with no prior state contributes nothing: there is no
// responder to preserve and nothing was forgotten. enabled is returned
// unmodified in that case, and is never aliased to prior.
// retainSuppressedProxySweepTargets keeps a SUPPRESSED interface in the
// remembered proxy-responder set so the next reconcile still sweeps it (#9087).
//
// The families are carried from the prior set when there is one; an interface
// suppressed before it was ever installed contributes nothing and is skipped,
// because there is no entry of ours to sweep.
//
// The entry it preserves is a SWEEP TARGET, not an enabled responder: the same
// pass that records it also computed an empty desired set for it, so the
// dataplane reconcile deletes rather than installs. The distinction matters
// because the map is named for the enabled set — see the call site.
func retainSuppressedProxySweepTargets(enabled, prior map[string]map[int]struct{}, suppressed []string) map[string]map[int]struct{} {
	for _, iface := range suppressed {
		priorFams := prior[iface]
		if len(priorFams) == 0 {
			continue
		}
		if _, ok := enabled[iface]; ok {
			continue
		}
		if enabled == nil {
			enabled = make(map[string]map[int]struct{}, 1)
		}
		retained := make(map[int]struct{}, len(priorFams))
		for family := range priorFams {
			retained[family] = struct{}{}
		}
		enabled[iface] = retained
	}
	return enabled
}

func retainUnresolvedProxyResponders(enabled, prior map[string]map[int]struct{}, unresolved []string) map[string]map[int]struct{} {
	for _, iface := range unresolved {
		priorFams := prior[iface]
		if len(priorFams) == 0 {
			continue
		}
		if _, ok := enabled[iface]; ok {
			// Resolved after all through another config entry — the fresh
			// state wins over the retained one.
			continue
		}
		if enabled == nil {
			enabled = make(map[string]map[int]struct{}, 1)
		}
		retained := make(map[int]struct{}, len(priorFams))
		for family := range priorFams {
			retained[family] = struct{}{}
		}
		enabled[iface] = retained
		slog.Warn("proxy-arp: retaining the responder state of a still-configured interface "+
			"whose ifindex did not resolve; not disabling it",
			"iface", iface, "issue", "#6536")
	}
	return enabled
}

// diffProxyResponders returns the (interface name → families) entries that
// were in prev (the last-enabled proxy responder set) but are NOT in cur (the
// freshly-enabled set) — i.e. the interfaces/families whose proxy_arp /
// proxy_ndp sysctl must be disabled because proxy-arp was removed from them
// (#2475). An interface that keeps some families but drops others yields only
// the dropped families. The returned map is safe to hand to
// dataplane.DisableProxyResponders (a fresh map, never aliasing prev/cur).
func diffProxyResponders(prev, cur map[string]map[int]struct{}) map[string]map[int]struct{} {
	if len(prev) == 0 {
		return nil
	}
	stale := make(map[string]map[int]struct{})
	for iface, fams := range prev {
		curFams := cur[iface]
		for family := range fams {
			if _, ok := curFams[family]; ok {
				continue
			}
			if stale[iface] == nil {
				stale[iface] = make(map[int]struct{})
			}
			stale[iface][family] = struct{}{}
		}
	}
	return stale
}

// proxyARPReassertLoop is an always-on periodic re-assert of the proxy-ARP/NDP
// state (#2197 item 2). The apply-path reconcile only runs on a config commit;
// a kernel link DOWN/UP outside a commit (HA RETH flap, programRethMAC link
// cycle) re-defaults the per-interface proxy_arp/proxy_ndp sysctl and leaves
// the interface silent until the next operator commit. This loop re-asserts the
// desired state on a low-frequency ticker so a non-commit link cycle self-heals
// within proxyARPReassertInterval.
//
// It is the only proxy-ARP re-assert hook that covers both standalone and
// cluster modes: reconcileRGStateLoop is cluster-only and monitorLinkState is
// SNMP-gated, so this is a dedicated, unconditionally-started loop. The
// reconcile is a no-op when no proxy-arp entries are configured, so the loop is
// cheap on configs that do not use proxy-arp.
//
// Each tick runs the reconcile under d.applySem (see reassertProxyARPOnce) so a
// re-assert can never interleave with a concurrent commit/config reconcile
// (#4001).
//
// #9087: the loop also wakes on an RG OWNERSHIP CHANGE, and without that the
// ticker alone is the whole latency budget. Proxy-ARP ownership is decided per
// redundancy group, but nothing drove the reconcile when that ownership MOVED —
// the apply path runs on a commit, and a failover is not a commit. So for up to
// proxyARPReassertInterval after a failover the new owner had not installed the
// entry and the old owner had not swept it: measured on the loss cluster
// immediately after a crash-failover plus manual failback as `fw0=0 fw1=1`, the
// only answerer being the node that no longer owns the address. That is a
// pool-mode NAT mis-steer for the length of the window, not a cosmetic lag.
//
// The nudge is edge-driven from both sides of the transition
// (applyRethServicesForRG on MASTER, clearRethServicesForRG on BACKUP) because
// the two halves fix different ends of the same window: the promote side
// installs, the demote side sweeps.
func (d *Daemon) proxyARPReassertLoop(ctx context.Context) {
	t := time.NewTicker(proxyARPReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reassertProxyARPOnce(ctx)
		case <-d.proxyARPNudgeCh:
			d.reassertProxyARPOnce(ctx)
		}
	}
}

// nudgeProxyARPReassert requests an immediate proxy-ARP re-assert (#9087).
//
// Non-blocking depth-1 send that coalesces a burst, and non-blocking is
// load-bearing rather than tidy: the callers are on the VRRP event loop, and
// reassertProxyARPOnce acquires applySem. A synchronous reconcile there would
// block every subsequent VRRP event behind a commit, and the RG transition that
// needs the reconcile is exactly when the apply path is busiest. Safe before the
// loop starts and safe on a nil channel (a Daemon built without the loop).
func (d *Daemon) nudgeProxyARPReassert() {
	if d.proxyARPNudgeCh == nil {
		return
	}
	select {
	case d.proxyARPNudgeCh <- struct{}{}:
	default:
	}
}

// reassertProxyARPOnce runs one proxy-ARP reconcile under the apply semaphore.
//
// #4001: the earlier version read d.store.ActiveConfig() and ran the reconcile
// WITHOUT holding d.applySem — the same semaphore the commit/config-apply path
// holds across store.Commit + applyConfigLocked (which calls reconcileProxyARP).
// That let a tick interleave with a commit that REMOVES a proxy-arp responder:
// the loop could capture the pre-commit ActiveConfig (still listing the removed
// responder) and, after the commit's reconcile had already torn the responder
// down, re-install it from that stale snapshot — the diff then remembered it as
// enabled, so the firewall kept proxying ARP for a removed/moved VIP until the
// next commit (an HA blackhole / mis-steer when the VIP had moved to the peer).
//
// Acquiring applySem before reading ActiveConfig closes the window two ways: the
// tick blocks behind any in-flight commit, and the config it reconciles is
// always the post-commit ActiveConfig, so it can never re-add a just-removed
// responder. The reconcile is netlink + procfs only (no helper control socket)
// and runs on a 30s cadence, so holding applySem for it does not starve the
// commit path.
//
// Lock order matches the commit path: applySem is acquired FIRST, then
// reconcileProxyARP takes proxyARPEnabledMu internally (applySem ->
// proxyARPEnabledMu). reconcileProxyARP never re-acquires applySem, so there is
// no self-deadlock. On shutdown the loop ctx is cancelled and Acquire returns an
// error, so a blocked tick unwinds promptly without reconciling.
func (d *Daemon) reassertProxyARPOnce(ctx context.Context) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return // ctx cancelled (daemon shutdown) — do not reconcile.
	}
	defer d.applySem.Release(1)
	if cfg := d.store.ActiveConfig(); cfg != nil {
		proxyARPReconcileFn(d, cfg)
	}
}

// setProxyARPUnresolved records the configured proxy-arp interfaces whose
// kernel identity did not resolve on this reconcile pass (#7685). Copies rather
// than aliasing the caller's slice: `unresolved` is reused by
// retainUnresolvedProxyResponders on the same pass, and a retained alias would
// let the published debt change under a reader.
func (d *Daemon) setProxyARPUnresolved(unresolved []string) {
	d.proxyARPEnabledMu.Lock()
	if len(unresolved) == 0 {
		d.proxyARPUnresolved = nil
	} else {
		d.proxyARPUnresolved = append([]string(nil), unresolved...)
	}
	d.proxyARPEnabledMu.Unlock()
}

// proxyARPUnresolvedNames returns those interfaces, sorted, for the operator
// signal. Allocation-free on the healthy path (nil debt returns nil).
func (d *Daemon) proxyARPUnresolvedNames() []string {
	d.proxyARPEnabledMu.Lock()
	defer d.proxyARPEnabledMu.Unlock()
	if len(d.proxyARPUnresolved) == 0 {
		return nil
	}
	out := append([]string(nil), d.proxyARPUnresolved...)
	sort.Strings(out)
	return out
}
