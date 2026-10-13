// Released-NIC tuning teardown (#6801).
//
// # The ownership hole this closes
//
// Two per-interface tuning knobs are applied to the mlx5 NICs that the
// userspace dataplane binds AF_XDP on — the D3 RSS indirection table
// (rss_indirection.go) and interrupt coalescence (coalescence.go). Both
// derive their target set from ONE allowlist,
// dpuserspace.UserspaceBoundLinuxInterfaces(cfg), recomputed from the
// *new* compiled config on every reconcile.
//
// That made both reconcilers blind to a SHRINKING allowlist. With config
// A binding {ge-0-0-1, ge-0-0-2} and config B binding only {ge-0-0-1},
// every loop walks the new set — so ge-0-0-2 kept xpf's concentrated RSS
// table and its adaptive-off / pinned-usecs coalescence even though xpf
// no longer owned it. The coalescence capture was restored only at daemon
// shutdown; the RSS table was never restored at all. A NIC handed back to
// the host stack (or to another dataplane) stayed limited to the old
// AF_XDP queue subset with latency-oriented coalescence until xpfd
// stopped or an operator ran ethtool by hand.
//
// # The invariant
//
// Every host/NIC mutation must be reverted when the interface leaves xpf
// ownership — not only when the process exits. This file implements that
// as a level-triggered `owned - current` teardown:
//
//	release: for each iface in owned but NOT in the current allowlist,
//	         restore the default RSS indirection table and the captured
//	         pre-xpfd coalescence, then drop ownership.
//	claim:   union the current allowlist's mlx5 members into the owned
//	         set (claim-before-touch; see claimNICTunableOwnership).
//
// The released and retained sets are disjoint by construction, so the
// release is order-independent with respect to both the claim and the
// re-apply. It is placed first anyway, mirroring the managed->unmapped
// teardown that pkg/daemon/device_map.go runs before networkd.Apply: a
// NIC leaving xpf's ownership is handed back before xpf spends
// bounded-but-real ethtool round-trips on the set it keeps.
//
// # Why an EMPTY allowlist is not, by itself, a withdrawal
//
// UserspaceBoundLinuxInterfaces degrades to nil when its snapshot build
// fails (see its #2514 comment) and when its xfrm-device dump hard-fails
// (#12580), and applyTailReconciles still runs the tunable step on a
// commit whose dataplane apply failed. Treating "no names" as "release
// everything" would therefore let a transient derivation error rip xpf's
// tuning off NICs the dataplane is still forwarding on — and `ethtool -X
// ... default` mid-traffic re-steers in-flight flows onto different RX
// queues. So the withdrawal trigger is the CONFIG signal (`userspaceDP ==
// false`, a pure config read with no error path), never an empty list.
// With userspace-dp still enabled and an empty list, ownership is
// retained untouched — the same refusal to act on an empty allowlist that
// applyRSSIndirection and applyCoalescence already make.
//
// The refusal DEFERS the hand-back; it does not lose it. The xfrm-dump
// degrade lands on a commit that otherwise SUCCEEDS (a build error also
// rejects the commit; a dump failure only narrows the apply snapshot's
// secure-tunnel exclusion to configuration ownership), so a NIC released
// on that commit keeps xpf's RSS table and coalescence until the next
// apply derives a non-empty allowlist — nothing retries sooner. The
// allowlist's WARN is the operator's record of the skip.
//
// # Retry debt (#5114 shape)
//
// Ownership is dropped only after the restore write SUCCEEDS. A failed
// `ethtool -X`/`-C` keeps the interface in the owned/capture map, so the
// next reconcile recomputes the same released set and retries. No timer
// is needed: the release is driven purely by `owned - current`, and a
// released name stays outside the allowlist until it is re-bound.
//
// # Interface disappearance
//
// If a released name is no longer an mlx5 netdev — unplugged, renamed by
// a .link change, or rebound to another driver — the tuning went with it
// (a driver rebind resets ring and coalescence configuration). Ownership
// is dropped WITHOUT an ethtool call: that both honors the Codex H1
// invariant (never invoke ethtool on a non-mlx5 netdev) and stops the
// retry debt from growing without bound on a NIC that can never accept
// the restore.
package daemon

import (
	"log/slog"
	"sort"
)

// releasedNICTunableOwners returns, in deterministic (sorted) order, the
// interfaces xpf still holds tuning ownership of that are ABSENT from
// the current userspace-dp allowlist.
//
// Ownership is the union of two independent records, because the two
// knobs can diverge on error paths: prior.rssOwned (the RSS indirection
// claim) and prior.mlx5Adaptive (the coalescence capture, which only
// exists when the `ethtool -c` probe parsed). An interface in either is
// an interface xpf must hand back.
//
// A nil prior yields nil. An empty `current` yields every owned name —
// that is the userspace-dataplane-disabled case, a withdrawal of the
// full prior set, and it is deliberately not special-cased.
func releasedNICTunableOwners(prior *priorHostTunables, current []string) []string {
	if prior == nil {
		return nil
	}
	if len(prior.rssOwned) == 0 && len(prior.mlx5Adaptive) == 0 {
		return nil
	}
	keep := make(map[string]struct{}, len(current))
	for _, iface := range current {
		keep[iface] = struct{}{}
	}
	seen := make(map[string]struct{}, len(prior.rssOwned)+len(prior.mlx5Adaptive))
	out := make([]string, 0, len(prior.rssOwned)+len(prior.mlx5Adaptive))
	collect := func(iface string) {
		if _, held := keep[iface]; held {
			return
		}
		if _, dup := seen[iface]; dup {
			return
		}
		seen[iface] = struct{}{}
		out = append(out, iface)
	}
	for iface := range prior.rssOwned {
		collect(iface)
	}
	for iface := range prior.mlx5Adaptive {
		collect(iface)
	}
	sort.Strings(out)
	return out
}

// releaseUnboundNICTunables reverts xpf's RSS and coalescence changes on
// every interface that has left the userspace-dp allowlist, then drops
// ownership of the ones that restored successfully.
//
// Best-effort by contract, like every other tunable path: it never
// returns an error and a failure never blocks a commit. A failure is
// instead RETAINED as ownership so the next reconcile retries it.
//
// `userspaceDP` is the config signal, not a derived one: it is the only
// thing that authorises a FULL withdrawal. When it is true but `current`
// is empty the allowlist derivation may simply have failed, so this is a
// no-op and ownership is retained — see the file header.
//
// Mutates prior's maps in place; the caller is responsible for holding
// whatever lock guards the snapshot (applyStep0TunablesWith runs under
// d.applySem, matching the existing capture/restore discipline).
func releaseUnboundNICTunables(prior *priorHostTunables, current []string, userspaceDP bool, execer rssExecutor) {
	if userspaceDP && len(current) == 0 {
		slog.Debug("linksetup: released-NIC teardown skipped (userspace-dp enabled with an empty allowlist)")
		return
	}
	released := releasedNICTunableOwners(prior, current)
	if len(released) == 0 {
		return
	}
	for _, iface := range released {
		_, rssHeld := prior.rssOwned[iface]
		coalesce, coalesceHeld := prior.mlx5Adaptive[iface]

		// The netdev must still be the mlx5 NIC we tuned. If it is gone
		// or rebound, its ring/coalescence configuration went with it —
		// drop ownership rather than accruing debt we can never settle.
		if drv := execer.readDriver(iface); drv != mlx5Driver {
			delete(prior.rssOwned, iface)
			delete(prior.mlx5Adaptive, iface)
			slog.Info("linksetup: released interface is no longer an mlx5 netdev, dropping tuning ownership",
				"iface", iface, "driver", drv)
			continue
		}

		if rssHeld {
			if err := restoreDefaultRSSIndirectionOne(iface, execer); err != nil {
				slog.Warn("linksetup: released interface rss restore failed, retaining ownership for retry",
					"iface", iface, "err", err)
			} else {
				delete(prior.rssOwned, iface)
				slog.Info("linksetup: released interface restored to default rss indirection",
					"iface", iface)
			}
		}
		if coalesceHeld {
			if err := restoreMlx5Coalesce(iface, coalesce, execer); err != nil {
				slog.Warn("linksetup: released interface coalescence restore failed, retaining capture for retry",
					"iface", iface, "err", err)
			} else {
				delete(prior.mlx5Adaptive, iface)
			}
		}
	}
}

// claimNICTunableOwnership records every mlx5 member of the current
// userspace-dp allowlist as an interface whose RSS indirection table xpf
// may have moved away from the kernel default.
//
// The claim is CONFIG-derived, not touch-derived, and is deliberately a
// superset of "reprogrammed this reconcile":
//
//   - It is claim-before-touch. An apply that dies partway through still
//     leaves the NIC owned, so the next reconcile can hand it back.
//   - Over-claiming costs at most one extra `ethtool -X <iface> default`
//     on release. That call is idempotent and is exactly what the
//     rss-indirection kill switch already issues on exactly this set, so
//     it can never leave the NIC in a worse state.
//   - Under-claiming is the actual defect (#6801): a NIC whose table xpf
//     concentrated but did not record is never handed back.
//
// It is a UNION, not a replacement: releaseUnboundNICTunables has already
// removed the names it restored and kept the names whose restore failed,
// and that retry debt must survive the claim.
//
// Scope is unchanged from the reconcilers this mirrors: `lo` is skipped
// and every name passes the same mlx5 driver guard, so no netdev outside
// the userspace-dp binding allowlist is ever recorded.
func claimNICTunableOwnership(prior *priorHostTunables, current []string, execer rssExecutor) {
	if prior == nil || len(current) == 0 {
		return
	}
	for _, iface := range current {
		if iface == "lo" {
			continue
		}
		if execer.readDriver(iface) != mlx5Driver {
			continue
		}
		prior.claimRSSOwnership(iface)
	}
}
