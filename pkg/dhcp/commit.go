package dhcp

import (
	"net/netip"
	"slices"
	"time"
)

// This file holds the shared lease-commit path and the pure decision
// helpers behind it (#1777). Before #1777 the run loops committed a
// lease only on the initial-acquisition path; a successful T1 renew /
// T2 rebind dead-assigned the result and `continue`d into a fresh full
// DORA / Solicit, discarding the renewal. Both run loops now commit
// every successful exchange through commitLease and return to the T1
// wait; only failure at both T1 and T2 falls back to re-acquisition.
//
// Wire-behavior note (#2994): the T1/T2 attempts now run the
// RFC-correct renewal exchange, not a full re-acquisition. At T1 the v4
// client unicasts a RENEWING DHCPREQUEST to the granting server (ciaddr
// set to the held address, no DISCOVER) and the v6 client sends a RENEW
// echoing the held IA_NA/IA_PD with the granting server's DUID; at T2
// the v4 client broadcasts a REBINDING DHCPREQUEST and the v6 client
// multicasts a REBIND (no server DUID). Only lease expiry (both renew
// and rebind failed) falls back to a full DISCOVER/SOLICIT. The RFC 2131
// §4.4.5 / RFC 8415 §18.2.4-5 citations now describe both the
// TIMER-AND-FALLBACK structure (T1 → T2 → re-acquire) and the wire
// messages. A renew that nonetheless lands on a different server is
// handled by the address-move path below. This supersedes the pre-#2994
// force-DORA / Rapid-Solicit behavior (the old #1832 review note).
//
// The decision helpers live here as directly testable functions (see
// commit_test.go). The run-loop state machine itself — the
// acquire→renew→rebind→re-acquire transitions and lease preservation —
// is exercised through the doV4ExchangeForTest / doV6ExchangeForTest /
// afterForTest / waitLinkLocalForTest seams (#2994); the real run loops
// otherwise open AF_PACKET/UDP sockets via nclient4/nclient6 and clamp
// the T1 wait to 30s. The wire builders (buildV4RenewRequest,
// v4RenewDest, buildV6RenewMessage in renew.go) are pure and
// unit-tested directly — see renew_test.go.

// renewalTimers computes the two waits of one renewal cycle from a lease
// duration, following the RFC 2131 §4.4.5 / RFC 8415 §18.2.4 schedule:
// t1 is the wait until the renew (RENEWING) attempt at 50% of the lease,
// and t2Remaining is the ADDITIONAL wait from T1 to the rebind
// (REBINDING) attempt at 87.5% of the lease (87.5% − 50% = 37.5% of the
// lease). ok reports whether the lease is a usable finite lease; a
// non-positive leaseTime is invalid and the caller must fail closed into
// re-acquisition rather than schedule a renewal (see below).
//
// No fixed minimum is applied. A fixed 30s T1 / 1s T2 floor previously
// clamped both waits (#5795): for any finite lease shorter than 60s that
// pushed T1 past the RFC half-life, and for a lease shorter than 30s it
// scheduled the renew attempt AT OR AFTER lease expiry — the run loop
// kept using the address while it waited, so a short-lease WAN could
// forward on an already-expired binding and then churn into
// re-acquisition instead of renewing on time. The RFC ratios are
// themselves proportional to the lease, so they are their own floor: for
// the smallest lease the wire can express (1 second — DHCP/DHCPv6 lease
// times are whole seconds) t1 is 500ms and t2Remaining is 375ms, both
// strictly before expiry, and T1 (50%) < T2 (87.5%) < 100% holds for
// every positive lease. A non-positive lease is rejected via ok=false
// instead of being clamped to a manufactured 30s schedule.
//
// The remainder is computed as leaseTime/8*3 (divide-before-multiply)
// rather than the algebraically equal leaseTime*7/8 - leaseTime/2: the
// latter overflows int64 for a lease above ~41.8yr (MaxInt64/7 ns) —
// notably the 0xFFFFFFFF-second RFC infinite sentinel — wrapping negative
// and clamping T2 low (#4526). The divide-first form has no intermediate
// above the lease itself, so the infinite sentinel yields a sane 3/8
// remainder. For every whole-second lease the two forms are bit-identical
// (1e9 ns is divisible by 8, so no rounding divergence). The split is
// extracted here so both v4/v6 run loops share one definition and tests
// can pin the schedule.
func renewalTimers(leaseTime time.Duration) (t1, t2Remaining time.Duration, ok bool) {
	if leaseTime <= 0 {
		// RFC 2131 lease time 0 is NOT the infinite sentinel (that is
		// 0xFFFFFFFF); a zero or negative lifetime is unusable. Signal
		// invalid so the run loop re-acquires instead of scheduling a
		// renewal that would fire at or after an already-lapsed lease.
		return 0, 0, false
	}
	t1 = leaseTime / 2
	t2Remaining = leaseTime / 8 * 3
	return t1, t2Remaining, true
}

// reacquireBackstop paces DHCP re-acquisition after a server grants a
// lease with a non-positive lifetime (see renewalTimers). Such a lease is
// unusable, so the run loop abandons the renewal cycle and re-acquires
// rather than scheduling a renewal past an already-lapsed lease. The wait
// keeps a misbehaving server that repeatedly grants a 0-second lease from
// turning re-acquisition into a tight DISCOVER/SOLICIT loop (#5795). It is
// a re-acquisition pace, not a renewal timer — it never governs a valid
// lease.
const reacquireBackstop = 10 * time.Second

// leaseContentChanged reports whether two leases differ in any field a
// downstream consumer reads or that controls the renewal binding (address,
// gateway, DNS, classless static routes, and server identity). Obtained and
// LeaseTime are excluded: they change on every successful renewal and feed
// only the run loop's own T1/T2 timers, never compiled state.
func leaseContentChanged(prev, next *Lease) bool {
	return prev.Address != next.Address ||
		prev.Gateway != next.Gateway ||
		!slices.Equal(prev.DNS, next.DNS) ||
		!slices.Equal(prev.ClasslessRoutes, next.ClasslessRoutes) ||
		prev.serverID != next.serverID ||
		!sameDUID(prev.v6ServerDUID, next.v6ServerDUID)
}

// delegatedPrefixesChanged reports whether the delegated-prefix set
// differs in prefix value or lifetimes. Obtained is excluded (refreshed
// on every reply). Lifetimes are included so a server that decays
// remaining lifetimes still propagates them to the RA sender — for the
// common fixed-lifetime server they are stable across renewals and do
// not fire. The compare is order-sensitive: servers return IA_PD
// prefixes in stable order, and a spurious fire on reorder is harmless
// (Reconcile keys on config identity, never lease state).
func delegatedPrefixesChanged(prev, next []DelegatedPrefix) bool {
	if len(prev) != len(next) {
		return true
	}
	for i := range next {
		if prev[i].Prefix != next[i].Prefix ||
			prev[i].PreferredLifetime != next[i].PreferredLifetime ||
			prev[i].ValidLifetime != next[i].ValidLifetime {
			return true
		}
	}
	return false
}

// reconcileDelegatedPDs applies RFC 8415 per-prefix IA_PD withdrawal
// semantics (#4874 B). Given the currently-held prefixes (prior), the
// live prefixes in a reply (valid-lifetime > 0) and the explicitly
// withdrawn ones (valid-lifetime 0):
//
//   - no live AND no withdrawn → an absent/empty IA_PD is SILENCE, not a
//     withdrawal: retain prior unchanged (apply=false), the #1844
//     anti-outage rule (a server that omits the IA_PD on a renew must not
//     drop the delegation).
//   - otherwise → (prior \ withdrawn) ∪ live, apply=true. The reconcile is
//     per-prefix, never a blunt clear-all (Codex F5): a prefix the reply
//     neither renewed nor withdrew (co-held, merely omitted) is retained.
//     Live prefixes are authoritative — on a RENEW servers echo every held
//     PD, so live is normally the whole set and carries fresh lifetimes.
//
// apply reports whether the caller should write result to the stored PD
// set (and delete the map entry when result is empty). When apply is false
// the result equals prior and the stored set must be left untouched.
func reconcileDelegatedPDs(prior, live, withdrawn []DelegatedPrefix) (result []DelegatedPrefix, apply bool) {
	if len(live) == 0 && len(withdrawn) == 0 {
		return prior, false
	}
	withdrawnSet := make(map[netip.Prefix]struct{}, len(withdrawn))
	for _, w := range withdrawn {
		withdrawnSet[w.Prefix] = struct{}{}
	}
	liveSet := make(map[netip.Prefix]struct{}, len(live))
	for _, l := range live {
		liveSet[l.Prefix] = struct{}{}
	}
	// Retain co-held prefixes the reply neither withdrew nor renewed; a
	// renewed prefix is re-added below with the reply's fresh lifetimes.
	for _, p := range prior {
		if _, w := withdrawnSet[p.Prefix]; w {
			continue
		}
		if _, l := liveSet[p.Prefix]; l {
			continue
		}
		result = append(result, p)
	}
	result = append(result, live...)
	return result, true
}

// commitLease installs a freshly acquired or renewed lease as the
// active one for key. It is the single commit path shared by initial
// acquisition, T1 renew, and T2 rebind (#1777), so a renewal result
// gets exactly the same address-apply / store / notify treatment as a
// fresh DORA or Solicit result.
//
//   - If the server moved the address (renewed lease's address differs
//     from prev), the previous address is removed before the new one is
//     applied — re-acquisition-equivalent handling; applyAddress's
//     AddrReplace only installs the new address and would leave the old
//     one lingering on the interface.
//   - The lease record is stored for Leases() consumers. For DHCPv6, the
//     delegated-prefix set is updated only when applyPDs is true: prefixes
//     holds the already-reconciled set (see reconcileDelegatedPDs) and is
//     written verbatim, deleting the map entry when it is empty (an
//     explicit all-withdrawn reply, #4874 B). applyPDs is false for v4 and
//     for a v6 reply that carried no IA_PD information, which leaves the
//     previously delegated prefixes in place (the #1844 retain-on-silence
//     rule); v4 must never touch the iface-keyed PD map that a co-resident
//     v6 client owns.
//   - The debounced onAddressChange callback fires only when lease
//     content actually changed. The callback re-enters the daemon's
//     applyConfig (full recompile) and thus Reconcile; an
//     unchanged-content renewal must not trigger that every T1
//     interval. Reconcile keys strictly on config identity (#1793), so
//     firing is never a restart-loop hazard — only recompile churn.
//
// prev is the lease currently applied to the interface (nil on first
// acquisition); prevPDs the delegated prefixes currently stored (for the
// change-detection compare). prefixes is the already-reconciled PD set to
// store when applyPDs is true. On error (address apply failed) nothing is
// stored and the caller falls back to re-acquisition.
func (m *Manager) commitLease(key clientKey, lease, prev *Lease, prefixes, prevPDs []DelegatedPrefix, applyPDs bool) error {
	if lease.Address.IsValid() {
		if prev != nil && prev.Address.IsValid() && prev.Address != lease.Address {
			m.removeAddress(key.iface, prev)
		}
		if err := m.applyAddress(key.iface, lease); err != nil {
			return err
		}
	}

	m.mu.Lock()
	m.leases[key] = lease
	if applyPDs {
		if len(prefixes) > 0 {
			m.delegatedPDs[key.iface] = prefixes
		} else {
			// An explicit all-withdrawn reply: drop the delegation so
			// DelegatedPrefixesForRA() stops advertising it (#4874 B).
			delete(m.delegatedPDs, key.iface)
		}
	}
	m.mu.Unlock()

	// #1844: gateway-change hook for ip-monitoring interface-typed
	// next-hops. Strictly narrower than leaseContentChanged —
	// address/DNS-only deltas do not fire. Fired outside m.mu (see
	// fireGatewayChange) and undebounced: the consumer is the ipmon
	// engine's dirty-bit + debounce/throttle queue, which absorbs it.
	if prev == nil || prev.Gateway != lease.Gateway {
		m.fireGatewayChange()
	}

	// A PD change (including a withdrawal that empties the set) must
	// re-render RA. Gate on applyPDs so a retain-on-silence commit does not
	// diff against an empty prefixes arg and spuriously fire (#4874 B).
	pdChanged := applyPDs && delegatedPrefixesChanged(prevPDs, prefixes)
	if prev == nil || leaseContentChanged(prev, lease) || pdChanged {
		m.scheduleRecompile()
	}
	return nil
}
