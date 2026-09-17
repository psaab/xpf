// dhcpv6.go holds the DHCPv6 client: the solicit/renew/rebind run
// loop, the single-exchange primitive, IA_NA/IA_PD reply parsing,
// DUID/ORO modifier construction, and prefix-delegation helpers.
// Split verbatim from dhcp.go (#6430).
package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/nclient6"
	"github.com/vishvananda/netlink"
)

// errV6AddrInvalidated signals that a DHCPv6 Reply EXPLICITLY invalidated the
// held IA_NA address: the reply carried IA_NA IAADDR option(s) that were ALL
// valid-lifetime 0 (RFC 8415 §18.2.10.1 — the address is no longer valid and
// MUST be discarded), with no live IA_NA address and no live delegated prefix
// to fall back to. It is DISTINCT from the generic "no usable IA_NA / live
// IA_PD" error, which means the reply carried NO usable IAADDR at all (an
// ABSENT / transient reply — server omission or packet loss). The
// discriminator is errors.Is(err, errV6AddrInvalidated): on an EXPLICIT
// invalidation the renew/rebind loop DECONFIGURES the held address and
// re-acquires (§18.2.10.1); on the ABSENT/transient error it KEEPS the address
// and retries (T1→T2→solicit), the correct #4874/#1844 anti-outage behavior.
// Fail SAFE toward keep-and-retry: the sentinel is returned ONLY when a
// present-but-0 IAADDR is positively observed (#5927).
var errV6AddrInvalidated = errors.New("DHCPv6 reply explicitly invalidated the held IA_NA address (valid-lifetime 0)")

// runDHCPv6 runs the DHCPv6 solicit/request cycle with retries and
// renewal. Initial acquisition is a Rapid-Solicit (or Information-Request
// in stateless mode). At T1 the loop sends an RFC 8415 §18.2.4 RENEW to
// the granting server (echoing the assigned IA_NA / IA_PD with the
// server's DUID) and at T2 an §18.2.5 REBIND (multicast, no server DUID)
// — NOT a fresh Solicit (#2994). A successful renew/rebind commits the
// renewed lease (and any delegated prefixes) via commitLease and returns
// to the T1 wait (#1777); only when both attempts fail (lease expiry)
// does the loop fall back to a fresh solicit. Stateless mode has no
// binding, so every refresh is an Information-Request regardless of mode.
func (m *Manager) runDHCPv6(ctx context.Context, ifaceName string) {
	key := clientKey{iface: ifaceName, family: AFInet6}
	backoff := time.Second

	m.mu.Lock()
	v6opts := m.v6opts[ifaceName]
	m.mu.Unlock()

	stateless := v6opts != nil && v6opts.Stateless

	// Wait for link-local address
	if err := m.waitLinkLocal(ctx, ifaceName, 30*time.Second); err != nil {
		slog.Warn("DHCPv6: no link-local address, aborting",
			"interface", ifaceName, "err", err)
		return
	}

	// committed / committedPDs track the lease and delegated prefixes
	// currently applied (nil/empty until the first success). In
	// stateless mode the lease never carries an address, so commitLease
	// skips the address apply/remove paths via Address.IsValid().
	var (
		committed    *Lease
		committedPDs []DelegatedPrefix
	)

	for {
		if ctx.Err() != nil {
			return
		}

		if stateless {
			slog.Info("DHCPv6: starting information-request", "interface", ifaceName)
		} else {
			slog.Info("DHCPv6: starting solicit", "interface", ifaceName)
		}

		result, err := m.v6Exchange(ctx, ifaceName, exchangeAcquire, nil, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("DHCPv6: solicit failed, retrying",
				"interface", ifaceName, "err", err, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, 60*time.Second)
			continue
		}

		backoff = time.Second

		// #1715: DNS install is not done here. lease.DNS is stored by
		// commitLease and the daemon's reconcileDNS reads it from
		// Leases(); the debounced onAddressChange callback (fired by
		// commitLease when lease content changed) drives the reconcile.
		// Reconcile the delegated-prefix set: store live prefixes, remove
		// explicitly-withdrawn (valid-lifetime 0) ones, retain the held set
		// on an absent/empty IA_PD (#4874 B, #1844 anti-outage).
		reconciledPDs, applyPDs := reconcileDelegatedPDs(committedPDs, result.prefixes, result.withdrawnPDs)
		if err := m.commitLease(key, result.lease, committed, reconciledPDs, committedPDs, applyPDs); err != nil {
			slog.Warn("DHCPv6: failed to apply address",
				"interface", ifaceName, "err", err)
			continue
		}
		committed = result.lease
		committedPDs = reconciledPDs

		if stateless {
			slog.Info("DHCPv6: stateless options obtained",
				"interface", ifaceName,
				"dns", committed.DNS)
		} else {
			slog.Info("DHCPv6: lease obtained",
				"interface", ifaceName,
				"address", committed.Address,
				"delegated_prefixes", len(result.prefixes),
				"lease_time", committed.LeaseTime)
		}

		// Renewal cycle: stay in this loop while T1 renews / T2 rebinds
		// keep succeeding; break out only to re-acquire from scratch.
		for {
			t1, t2Remaining, ok := renewalTimers(committed.LeaseTime)
			if !ok {
				// See runDHCPv4: a non-positive lease time is invalid and
				// must not schedule a renewal past an already-lapsed lease.
				// Abandon the cycle and re-acquire, paced by
				// reacquireBackstop (#5795).
				slog.Warn("DHCPv6: non-positive lease time, re-acquiring",
					"interface", ifaceName, "lease_time", committed.LeaseTime)
				select {
				case <-m.after(reacquireBackstop):
				case <-ctx.Done():
					if committed.Address.IsValid() {
						m.removeAddress(ifaceName, committed)
					}
					m.mu.Lock()
					delete(m.leases, key)
					delete(m.delegatedPDs, ifaceName)
					m.mu.Unlock()
					return
				}
				break
			}

			// Wait for T1
			select {
			case <-m.after(t1):
				slog.Info("DHCPv6: T1 expired, renewing", "interface", ifaceName)
			case <-ctx.Done():
				if committed.Address.IsValid() {
					m.removeAddress(ifaceName, committed)
				}
				m.mu.Lock()
				delete(m.leases, key)
				delete(m.delegatedPDs, ifaceName)
				m.mu.Unlock()
				return
			}

			// T1 renewal attempt — RENEW to the granting server, NOT a
			// fresh Solicit (#2994).
			renewed, rerr := m.v6Exchange(ctx, ifaceName, exchangeRenew, committed, committedPDs)
			if rerr == nil {
				reconciledPDs, applyPDs := reconcileDelegatedPDs(committedPDs, renewed.prefixes, renewed.withdrawnPDs)
				if cerr := m.commitLease(key, renewed.lease, committed, reconciledPDs, committedPDs, applyPDs); cerr != nil {
					slog.Warn("DHCPv6: failed to apply renewed lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					break
				}
				committed = renewed.lease
				committedPDs = reconciledPDs
				slog.Info("DHCPv6: lease renewed",
					"interface", ifaceName,
					"address", committed.Address,
					"delegated_prefixes", len(renewed.prefixes),
					"lease_time", committed.LeaseTime)
				continue
			}
			if errors.Is(rerr, errV6AddrInvalidated) {
				// #5927: the server EXPLICITLY invalidated the held IA_NA
				// address (valid-lifetime 0). RFC 8415 §18.2.10.1: stop using
				// it NOW — deconfigure + re-acquire, do NOT keep it and wait for
				// T2 (which would keep a server-withdrawn address in service).
				// This is the IA_NA analog of the IA_PD withdrawal reconcile
				// above. A merely absent/transient renew reply keeps the
				// generic error and the keep-and-wait-T2 path below (#4874).
				slog.Info("DHCPv6: server invalidated held address (valid-lifetime 0), deconfiguring and re-acquiring",
					"interface", ifaceName, "address", committed.Address)
				if committed.Address.IsValid() {
					m.removeAddress(ifaceName, committed)
				}
				m.mu.Lock()
				delete(m.leases, key)
				delete(m.delegatedPDs, ifaceName)
				m.mu.Unlock()
				break // re-acquire from a fresh solicit
			}
			slog.Warn("DHCPv6: T1 renewal failed, waiting for T2",
				"interface", ifaceName, "err", rerr)

			// Wait for T2 (87.5% of lease) — remaining time after T1
			select {
			case <-m.after(t2Remaining):
			case <-ctx.Done():
				if committed.Address.IsValid() {
					m.removeAddress(ifaceName, committed)
				}
				m.mu.Lock()
				delete(m.leases, key)
				delete(m.delegatedPDs, ifaceName)
				m.mu.Unlock()
				return
			}

			// T2 rebind attempt — REBIND (multicast, no server DUID) (#2994).
			renewed, rerr = m.v6Exchange(ctx, ifaceName, exchangeRebind, committed, committedPDs)
			if rerr == nil {
				reconciledPDs, applyPDs := reconcileDelegatedPDs(committedPDs, renewed.prefixes, renewed.withdrawnPDs)
				if cerr := m.commitLease(key, renewed.lease, committed, reconciledPDs, committedPDs, applyPDs); cerr != nil {
					slog.Warn("DHCPv6: failed to apply rebound lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					break
				}
				committed = renewed.lease
				committedPDs = reconciledPDs
				slog.Info("DHCPv6: lease rebound",
					"interface", ifaceName,
					"address", committed.Address,
					"delegated_prefixes", len(renewed.prefixes),
					"lease_time", committed.LeaseTime)
				continue
			}
			if errors.Is(rerr, errV6AddrInvalidated) {
				// #5927: explicit invalidation on REBIND too — deconfigure the
				// held address before falling back to a fresh solicit (the
				// generic rebind-failure break below keeps it in service until
				// re-acquire, which is correct only for a transient failure).
				slog.Info("DHCPv6: server invalidated held address on rebind (valid-lifetime 0), deconfiguring and re-acquiring",
					"interface", ifaceName, "address", committed.Address)
				if committed.Address.IsValid() {
					m.removeAddress(ifaceName, committed)
				}
				m.mu.Lock()
				delete(m.leases, key)
				delete(m.delegatedPDs, ifaceName)
				m.mu.Unlock()
				break
			}
			slog.Warn("DHCPv6: T2 rebind failed, lease will expire, re-acquiring",
				"interface", ifaceName, "err", rerr)
			break // fall back to a fresh solicit
		}
	}
}

// dhcpv6Result holds results from a DHCPv6 exchange including both IA_NA and IA_PD.
type dhcpv6Result struct {
	lease *Lease
	// prefixes holds the LIVE delegated prefixes (valid-lifetime > 0).
	prefixes []DelegatedPrefix
	// withdrawnPDs holds prefixes the reply carried with valid-lifetime 0
	// — an RFC 8415 §12.1 explicit withdrawal (#4874 B). They are never
	// stored or re-advertised; the commit-path reconcile removes them from
	// the held set rather than re-granting them at the RA sender's 30-day
	// defaults. Distinguishing an explicit withdrawal from an absent/empty
	// IA_PD (silence) keeps the #1844 anti-outage retain-on-silence rule.
	withdrawnPDs []DelegatedPrefix
}

// doDHCPv6 performs a single DHCPv6 exchange for the given mode.
// exchangeAcquire runs a Rapid-Solicit (or Information-Request in
// stateless mode); exchangeRenew sends an RFC 8415 §18.2.4 RENEW to the
// granting server (server DUID echoed) and exchangeRebind an §18.2.5
// REBIND (no server DUID), both echoing the assigned IA_NA / IA_PD from
// prev / prevPDs (#2994). Stateless mode ignores the mode (no binding to
// renew — every refresh is an Information-Request).
func (m *Manager) doDHCPv6(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease, prevPDs []DelegatedPrefix) (*dhcpv6Result, error) {
	if mode != exchangeAcquire && !leaseInterfaceMatches(ifaceName, prev) {
		if prev == nil {
			return nil, fmt.Errorf("DHCPv6 %s without a prior lease", mode)
		}
		return nil, fmt.Errorf("DHCPv6 %s lease belongs to interface %q, not %q",
			mode, prev.Interface, ifaceName)
	}
	client, err := nclient6.New(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("create DHCPv6 client: %w", err)
	}
	defer client.Close()

	exCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	m.mu.Lock()
	v6opts := m.v6opts[ifaceName]
	m.mu.Unlock()

	// Build modifiers — use persistent DUID if configured
	mods := m.buildDHCPv6Modifiers(ifaceName, v6opts)

	stateless := v6opts != nil && v6opts.Stateless

	// Stateless mode: send Information-Request (no IA_NA/IA_PD). There is
	// no lease binding, so renew/rebind collapse to the same refresh.
	if stateless {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 new message: %w", err)
		}
		msg.MessageType = dhcpv6.MessageTypeInformationRequest
		// Apply modifiers (DUID, ORO options)
		for _, mod := range mods {
			mod(msg)
		}
		// Always request DNS
		oro := msg.Options.RequestedOptions()
		hasDNS := false
		for _, code := range oro {
			if code == dhcpv6.OptionDNSRecursiveNameServer {
				hasDNS = true
				break
			}
		}
		if !hasDNS {
			dhcpv6.WithRequestedOptions(dhcpv6.OptionDNSRecursiveNameServer)(msg)
		}

		resp, err := client.SendAndRead(exCtx, nclient6.AllDHCPRelayAgentsAndServers, msg, nil)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 information-request: %w", err)
		}

		lease := &Lease{
			Interface: ifaceName,
			Family:    AFInet6,
			Obtained:  time.Now(),
			LeaseTime: 3600 * time.Second, // 1-hour refresh for stateless
		}
		if dnsOpt := resp.Options.DNS(); len(dnsOpt) > 0 {
			for _, dns := range dnsOpt {
				if a, ok := netip.AddrFromSlice(dns); ok {
					lease.DNS = append(lease.DNS, a)
				}
			}
		}
		return &dhcpv6Result{lease: lease}, nil
	}

	var adv *dhcpv6.Message
	switch mode {
	case exchangeRenew, exchangeRebind:
		rebind := mode == exchangeRebind
		// Renew/rebind echo the actual held IA_NA/IA_PD, so use only the
		// client-id + ORO modifiers — NOT the acquisition IA_PD hint
		// (which would merge a hint prefix into our real IA_PD).
		renewMods := m.buildDHCPv6RenewModifiers(ifaceName, v6opts)
		msg, err := buildV6RenewMessage(client.InterfaceAddr(), prev, prevPDs, rebind, renewMods)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 build %s: %w", mode, err)
		}
		adv, err = client.SendAndRead(exCtx, nclient6.AllDHCPRelayAgentsAndServers, msg,
			v6RenewMatcher(m, msg, prev, rebind))
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 %s: %w", mode, err)
		}
	default:
		adv, err = client.RapidSolicit(exCtx, mods...)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 solicit: %w", err)
		}
	}

	return m.parseV6Reply(ctx, ifaceName, adv, v6opts)
}

// selectIANAAddress chooses a single, deterministic IA_NA address from a
// DHCPv6 reply. RFC 8415 §21.4 permits an IA_NA to carry more than one
// IAADDR option, and a reply may carry more than one IA_NA; xpf's lease
// model holds exactly one address, so enumeration order must NOT decide
// which one is installed (#4383). The previous last-wins overwrite kept
// whichever IAADDR enumerated last and paired the lease lifetime with
// that address's valid-lifetime, so a deprecated address could win over a
// preferred one and the lease could carry a stale lifetime.
//
// Selection is deterministic:
//   - skip any IAADDR with valid-lifetime 0 — RFC 8415 §12.1 treats a
//     zero valid-lifetime as an expired/declined address (F-264);
//   - among the rest, prefer the longest preferred-lifetime;
//   - ties are broken by first-seen (option order).
//
// The returned valid-lifetime belongs to the CHOSEN address, so the
// caller pairs lease.LeaseTime with the right lifetime rather than a
// stale one from a different IAADDR. Returns an invalid Addr and zero
// duration when the reply carries no usable IA_NA address.
//
// The third return, sawZeroLifetime, reports whether the reply carried an
// IA_NA IAADDR option with valid-lifetime 0 (an explicit stop-using directive,
// RFC 8415 §18.2.10.1). Combined with an invalid returned Addr (no positive
// address selectable), it lets the caller distinguish an EXPLICIT invalidation
// (present-but-0 → discard the held address) from an ABSENT IA_NA (no IAADDR
// at all → keep + retry). A reply with both a 0-lifetime and a positive IAADDR
// still selects the positive one (valid Addr) — not an invalidation. (#5927)
func selectIANAAddress(adv *dhcpv6.Message) (addr netip.Addr, validLT time.Duration, sawZeroLifetime bool) {
	var (
		best      netip.Addr
		bestValid time.Duration
		bestPref  time.Duration
		found     bool
		sawZero   bool
	)
	for _, opt := range adv.Options.Options {
		ianaOpt, ok := opt.(*dhcpv6.OptIANA)
		if !ok {
			continue
		}
		for _, subOpt := range ianaOpt.Options.Options {
			iaaddr, ok := subOpt.(*dhcpv6.OptIAAddress)
			if !ok {
				continue
			}
			// Expired/declined address — never install it (F-264). Record
			// that a present-but-0 IAADDR was seen so the caller can tell an
			// EXPLICIT invalidation from an absent IA_NA (#5927).
			if iaaddr.ValidLifetime == 0 {
				sawZero = true
				continue
			}
			a, ok := netip.AddrFromSlice(iaaddr.IPv6Addr)
			if !ok {
				continue
			}
			// Strict greater-than keeps the FIRST address at the maximum
			// preferred-lifetime (first-seen tie-break).
			if !found || iaaddr.PreferredLifetime > bestPref {
				best = a
				bestValid = iaaddr.ValidLifetime
				bestPref = iaaddr.PreferredLifetime
				found = true
			}
		}
	}
	return best, bestValid, sawZero
}

// parseV6Reply extracts the lease (IA_NA address, lifetime, DNS, gateway)
// and any delegated prefixes (IA_PD) from a DHCPv6 Reply/Advertise. It is
// shared by the solicit, renew, and rebind paths (#2994); the server DUID
// is captured so the next RENEW can echo it.
func (m *Manager) parseV6Reply(ctx context.Context, ifaceName string, adv *dhcpv6.Message, v6opts *DHCPv6Options) (*dhcpv6Result, error) {
	result := &dhcpv6Result{}
	now := time.Now()

	// Determine which IA types to look for
	wantNA := true
	wantPD := false
	if v6opts != nil && len(v6opts.IATypes) > 0 {
		wantNA = false
		for _, t := range v6opts.IATypes {
			switch t {
			case "ia-na":
				wantNA = true
			case "ia-pd":
				wantPD = true
			}
		}
	}

	// Extract the IA_NA address. A reply may carry multiple IAADDR
	// options (and multiple IA_NA options); selectIANAAddress chooses one
	// deterministically — longest preferred-lifetime, tie-broken by
	// first-seen, expired valid-lifetime-0 addresses skipped — and returns
	// that address's own valid-lifetime so the lease lifetime is never
	// paired with a stale value from a different address (#4383).
	var addr netip.Addr
	var validLT time.Duration
	// iaNAExplicitlyInvalidated: the reply carried IA_NA IAADDR(s) that were
	// ALL valid-lifetime 0 (no positive address selectable) — the server's
	// RFC 8415 §18.2.10.1 "stop using this address" directive (#5927). Kept
	// distinct from an absent IA_NA so the caller can discard vs keep+retry.
	var iaNAExplicitlyInvalidated bool

	if wantNA {
		var sawZeroLifetime bool
		addr, validLT, sawZeroLifetime = selectIANAAddress(adv)
		iaNAExplicitlyInvalidated = !addr.IsValid() && sawZeroLifetime
	}

	// Extract IA_PD delegated prefixes, split into live and (RFC 8415
	// §12.1) explicitly-withdrawn valid-lifetime-0 prefixes (#4874 B).
	if wantPD {
		result.prefixes, result.withdrawnPDs = extractDelegatedPrefixes(adv, ifaceName, now)
		for _, dp := range result.prefixes {
			slog.Info("DHCPv6: received delegated prefix",
				"interface", ifaceName,
				"prefix", dp.Prefix,
				"preferred", dp.PreferredLifetime,
				"valid", dp.ValidLifetime)
		}
		for _, dp := range result.withdrawnPDs {
			slog.Info("DHCPv6: server withdrew delegated prefix (valid-lifetime 0)",
				"interface", ifaceName, "prefix", dp.Prefix)
		}
	}

	// A usable reply must yield either an IA_NA address or at least one
	// LIVE delegated prefix. Count live PDs regardless of wantNA so a
	// PD-only client (wantNA=false) whose reply carried only withdrawn
	// (valid-lifetime 0) prefixes is treated as an acquisition/renew
	// FAILURE and retried, not settled into an empty 1h lease (#4874 B,
	// Codex F6). The trailing wantNA||wantPD guard keeps a degenerate
	// no-IA config on its prior no-reject path.
	if !addr.IsValid() && len(result.prefixes) == 0 && (wantNA || wantPD) {
		// #5927: distinguish an EXPLICIT invalidation (the reply carried an
		// IA_NA whose IAADDR(s) were all valid-lifetime 0 — RFC 8415
		// §18.2.10.1, stop using the address) from an ABSENT / transient reply
		// (no usable IAADDR at all). Only the former returns the
		// errV6AddrInvalidated sentinel, on which the renew/rebind loop
		// deconfigures the held address; the generic error keeps it + retries.
		if iaNAExplicitlyInvalidated {
			return nil, fmt.Errorf("DHCPv6 reply on %s: %w", ifaceName, errV6AddrInvalidated)
		}
		return nil, fmt.Errorf("no usable IA_NA address or live IA_PD prefix in DHCPv6 reply on %s", ifaceName)
	}

	lease := &Lease{
		Interface: ifaceName,
		Family:    AFInet6,
		Obtained:  now,
	}

	// Server identifier (DUID) — echoed in the next RENEW so the original
	// server matches our binding (#2994).
	lease.v6ServerDUID = adv.Options.ServerID()

	if addr.IsValid() {
		lease.Address = netip.PrefixFrom(addr, 128)
		lease.LeaseTime = validLT
	} else if len(result.prefixes) > 0 {
		// PD-only mode: use the first prefix's lifetime for renewal
		lease.LeaseTime = result.prefixes[0].ValidLifetime
	}

	// A sane default for the DEGENERATE no-IA config (wantNA=false &&
	// wantPD=false), the only shape that reaches here with LeaseTime 0: a
	// selected IA_NA address and a live IA_PD prefix both carry a positive
	// lifetime (selectIANAAddress skips valid-lifetime-0 IAADDRs, #4383;
	// extractDelegatedPrefixes routes valid-lifetime-0 prefixes to
	// withdrawnPDs). This is NOT the explicit-0 invalidation path — that is
	// handled upstream at the "no usable IA_NA / live IA_PD" guard, which
	// returns errV6AddrInvalidated so the renew/rebind loop deconfigures the
	// held address (RFC 8415 §18.2.10.1, #5927), never reaching this floor.
	if lease.LeaseTime == 0 {
		lease.LeaseTime = 3600 * time.Second
	}

	// Extract DNS
	if dnsOpt := adv.Options.DNS(); len(dnsOpt) > 0 {
		for _, dns := range dnsOpt {
			if a, ok := netip.AddrFromSlice(dns); ok {
				lease.DNS = append(lease.DNS, a)
			}
		}
	}

	// DHCPv6 doesn't provide a default router — discover it from the
	// kernel's IPv6 neighbor table (entries learned via Router Advertisements).
	if gw := m.discoverIPv6Router(ctx, ifaceName); gw.IsValid() {
		lease.Gateway = gw
	}

	result.lease = lease
	return result, nil
}

// buildDHCPv6RenewModifiers constructs the modifiers for a RENEW/REBIND
// message: the persistent client-id and the requested-option list, but
// NOT the IA_NA/IA_PD options (the renew echoes the held bindings, which
// buildV6RenewMessage adds explicitly). Reusing buildDHCPv6Modifiers here
// would merge the acquisition IA_PD hint into our real IA_PD (#2994).
func (m *Manager) buildDHCPv6RenewModifiers(ifaceName string, opts *DHCPv6Options) []dhcpv6.Modifier {
	var mods []dhcpv6.Modifier
	if duid, err := m.getDUID(ifaceName); err == nil {
		mods = append(mods, dhcpv6.WithClientID(duid))
	}
	if opts == nil {
		return mods
	}
	var oroCodes []dhcpv6.OptionCode
	for _, opt := range opts.ReqOptions {
		switch opt {
		case "dns-server":
			oroCodes = append(oroCodes, dhcpv6.OptionDNSRecursiveNameServer)
		case "domain-name":
			oroCodes = append(oroCodes, dhcpv6.OptionDomainSearchList)
		}
	}
	if len(oroCodes) > 0 {
		mods = append(mods, dhcpv6.WithRequestedOptions(oroCodes...))
	}
	return mods
}

// pdHintPrefixLength bounds the configured IA_PD prefix-length hint at the
// point of USE, and reports whether a hint should be sent at all.
//
// #8597 K51. `net.CIDRMask(n, 128)` returns a NIL mask for any n outside
// [0,128], and `net.IPMask(nil).Size()` is (0, 0) — so an out-of-range
// preferred-prefix-length did not fail, it silently became an IAPREFIX on the
// wire with prefix-length 0. The operator asked for a /56 delegation and we
// SOLICITed a degenerate hint instead: worse than sending no hint, because a
// hint of 0 is a positive statement to the upstream server rather than an
// absent preference.
//
// The schema bounds this leaf to 0..128 (`preferred-prefix-length`, added in
// 2e02fc995), and that closes the operator-facing half: a strict `commit`
// rejects 999 with "integer out of range [0..128]". It does NOT close this
// one. Store.Load and Store.SyncApply compile through compileTreeLenient,
// which DOWNGRADES a typed-leaf violation to a slog.Warn and continues
// (#1319) — deliberately, so a stale persisted config cannot blackout-boot the
// node and a peer-pushed config cannot alarm-loop HA sync. parseIntLeaf then
// accepts 999 happily, since it only rejects non-integers. Measured: a tree
// carrying preferred-prefix-length 999 fails SchemaValidate and still arrives
// here as PrefixDelegatingPrefixLen=999. A schema ceiling is a commit gate, not
// an invariant; anything downstream that would be UNSOUND on a violating value
// has to bound it itself.
//
// This is the outbound twin of the #6531 guard ~60 lines below, which rejects
// the same degenerate mask arriving from the upstream server. That one already
// treats a nil mask as untrusted input; this one had not, even though the value
// reaches us over the same tolerant path.
//
// Fall back to "no hint" rather than clamping to 128 (the #8642 doctrine): a
// clamp invents an operator intent we cannot know, while 0/absent is the
// sentinel this leaf already documents for "not set", and IA_PD without a hint
// is well-formed — the server picks the length.
func pdHintPrefixLength(ifaceName string, prefLen int) (int, bool) {
	if prefLen <= 0 {
		// The documented "not set" sentinel. Not an error; send no hint.
		return 0, false
	}
	if prefLen > 128 {
		slog.Warn("DHCPv6: ignoring out-of-range IA_PD preferred-prefix-length; sending no length hint",
			"interface", ifaceName, "preferred-prefix-length", prefLen,
			"valid", "0..128", "issue", "#8597")
		return 0, false
	}
	return prefLen, true
}

// buildDHCPv6Modifiers constructs DHCPv6 message modifiers from interface options.
func (m *Manager) buildDHCPv6Modifiers(ifaceName string, opts *DHCPv6Options) []dhcpv6.Modifier {
	var mods []dhcpv6.Modifier

	// The client DUID MUST stay stable across every DHCPv6 message for the
	// lifetime of the client (RFC 8415 §11): the server binds the lease to
	// the DUID, so the initial SOLICIT/REQUEST and its later RENEW/REBIND
	// must present byte-identical client IDs. Always attach the persistent
	// DUID — even when no DHCPv6 options are configured (opts == nil, the
	// bare-acquisition path). Otherwise dhcpv6.NewSolicit (via RapidSolicit)
	// falls back to a default DUID-LLT stamped with GetTime() at send, while
	// the renew path (buildDHCPv6RenewModifiers) always uses the persistent
	// getDUID (DUID-LL): the two paths present different DUIDs, the server
	// treats the renewal as a new client, and the original lease is not
	// renewed (#5711).
	if duid, err := m.getDUID(ifaceName); err == nil {
		mods = append(mods, dhcpv6.WithClientID(duid))
	}

	if opts == nil {
		return mods
	}

	// Add IA_PD if requested
	for _, iaType := range opts.IATypes {
		if iaType == "ia-pd" {
			var hintPrefix *dhcpv6.OptIAPrefix
			if n, ok := pdHintPrefixLength(ifaceName, opts.PDPrefLen); ok {
				hintPrefix = &dhcpv6.OptIAPrefix{
					Prefix: &net.IPNet{
						IP:   net.IPv6zero,
						Mask: net.CIDRMask(n, 128),
					},
				}
			}
			iaid := [4]byte{0, 0, 0, 1} // default IAID for PD
			if hintPrefix != nil {
				mods = append(mods, dhcpv6.WithIAPD(iaid, hintPrefix))
			} else {
				mods = append(mods, dhcpv6.WithIAPD(iaid))
			}
		}
	}

	// Add requested options (ORO)
	var oroCodes []dhcpv6.OptionCode
	for _, opt := range opts.ReqOptions {
		switch opt {
		case "dns-server":
			oroCodes = append(oroCodes, dhcpv6.OptionDNSRecursiveNameServer)
		case "domain-name":
			oroCodes = append(oroCodes, dhcpv6.OptionDomainSearchList)
		}
	}
	if len(oroCodes) > 0 {
		mods = append(mods, dhcpv6.WithRequestedOptions(oroCodes...))
	}

	return mods
}

// extractDelegatedPrefixes parses IA_PD options from a DHCPv6 reply,
// partitioning the prefixes into live (valid-lifetime > 0) and explicitly
// withdrawn (valid-lifetime 0) sets. A zero valid-lifetime IA_PD is an RFC
// 8415 §12.1 withdrawal: it must never be stored or re-advertised — this
// mirrors selectIANAAddress's skip of a valid-lifetime-0 IAADDR (#4383).
// The caller uses the withdrawn set to remove the prefix from the held set
// (per-prefix, so a co-held prefix the reply merely omitted is retained)
// rather than keeping it and re-granting it at the RA sender's 30-day
// defaults (#4874 B).
//
// An IAPREFIX whose decoded mask is degenerate (wire prefix-length 0 or
// > 128, or a non-contiguous mask) is dropped and enters NEITHER set — a
// > 128 length otherwise decodes to a /0 that would be advertised on-link
// to the LAN (#6531).
func extractDelegatedPrefixes(msg *dhcpv6.Message, ifaceName string, now time.Time) (live, withdrawn []DelegatedPrefix) {
	for _, opt := range msg.Options.Options {
		iapdOpt, ok := opt.(*dhcpv6.OptIAPD)
		if !ok {
			continue
		}
		for _, prefix := range iapdOpt.Options.Prefixes() {
			if prefix.Prefix == nil {
				continue
			}
			// Reject a degenerate IAPREFIX mask (untrusted input — the
			// upstream WAN server, hostile or merely buggy). The library
			// decodes the wire prefix-length byte as
			// net.CIDRMask(length, 128), which returns a NIL mask for any
			// length > 128, and net.IPMask(nil).Size() is (0, 0). Reading
			// only `ones` and discarding `bits` therefore turned a crafted
			// length of 129..255 into a <ip>/0, which survives IsValid() and
			// DeriveSubPrefix and reaches the RA sender — advertising a /0 to
			// the downstream LAN as on-link + autonomous and hijacking every
			// SLAAC host's on-link determination (#6531).
			//
			// `bits != 128` is the arm that catches it: a nil mask and a
			// non-contiguous mask both report bits 0. `ones == 0` is
			// belt-and-braces for a genuine all-zero 128-bit mask, which the
			// wire decoder cannot currently produce (it maps a length of 0 to
			// a nil Prefix, skipped above) but an in-process constructor can.
			//
			// Skip the offending IAPREFIX rather than refusing the whole
			// reply: an IA_PD is a multi-element container, so this matches
			// the RFC 3442 classless-route loop in leaseFromACKv4's sibling
			// (which likewise skips a route whose mask reports bits != 32).
			// leaseFromACKv4 itself refuses the entire message only because a
			// v4 ACK carries exactly one address+mask, so there is nothing to
			// salvage. Skipping cannot smuggle the bad prefix through — it
			// never becomes a DelegatedPrefix, so it reaches neither the live
			// set, the withdrawn set, nor the RA sender — while a sibling
			// prefix in the same IA_PD is exactly what a correct server would
			// have sent on its own.
			//
			// When the skip empties BOTH sets the outcome depends on what
			// else the reply carried. Neither branch can yield a /0, but they
			// are NOT the same branch (#6581 review):
			//
			//   - No IA_NA address either: parseV6Reply's "no usable IA_NA
			//     address or live IA_PD prefix" guard rejects the reply and
			//     the acquire/renew loop retries.
			//   - A valid IA_NA address: parsing SUCCEEDS — that guard fires
			//     only when BOTH are missing — so a mixed ia-na + ia-pd
			//     client installs the address and simply carries no new PD.
			//     Empty live+withdrawn then reads as SILENCE to
			//     reconcileDelegatedPDs, which returns (prior, apply=false),
			//     so a previously held delegation is retained untouched (the
			//     #1844 anti-outage rule). A malformed IAPREFIX therefore
			//     cannot clear the held set either.
			//
			// Pinned by TestIAPDPrefixLen6531_MixedIANAReplyStaysUsable.
			ones, bits := prefix.Prefix.Mask.Size()
			if bits != 128 || ones == 0 {
				slog.Warn("DHCPv6: refusing IA_PD prefix with invalid mask",
					"interface", ifaceName,
					"ip", prefix.Prefix.IP,
					"mask", prefix.Prefix.Mask,
					"detail", "wire prefix-length 0 or > 128, or non-contiguous mask")
				continue
			}
			ip, ok := netip.AddrFromSlice(prefix.Prefix.IP)
			if !ok {
				continue
			}
			dp := DelegatedPrefix{
				Interface:         ifaceName,
				Prefix:            netip.PrefixFrom(ip, ones),
				PreferredLifetime: prefix.PreferredLifetime,
				ValidLifetime:     prefix.ValidLifetime,
				Obtained:          now,
			}
			if prefix.ValidLifetime == 0 {
				withdrawn = append(withdrawn, dp)
			} else {
				live = append(live, dp)
			}
		}
	}
	return live, withdrawn
}

// discoverIPv6Router finds the link-local address of an IPv6 router on the
// given interface by inspecting the kernel neighbor table for entries with
// the NTF_ROUTER flag (learned from Router Advertisements).
// Retries a few times since RAs may not have been processed yet.
func (m *Manager) discoverIPv6Router(ctx context.Context, ifaceName string) netip.Addr {
	if m.nlHandle == nil {
		return netip.Addr{}
	}
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return netip.Addr{}
	}

	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			// Context-aware: Reconcile cancels clients and waits on
			// done while applyConfigLocked holds applySem — a blind
			// 10x1s sleep here wedged every commit for up to 10s
			// (AGY review on PR #1815).
			select {
			case <-ctx.Done():
				return netip.Addr{}
			case <-time.After(time.Second):
			}
		}

		neighbors, err := m.nlHandle.NeighList(link.Attrs().Index, netlink.FAMILY_V6)
		if err != nil {
			continue
		}

		for _, n := range neighbors {
			// NTF_ROUTER = 0x80 (linux/neighbour.h)
			if n.Flags&0x80 != 0 && n.IP.IsLinkLocalUnicast() {
				if a, ok := netip.AddrFromSlice(n.IP); ok {
					return a
				}
			}
		}
	}

	slog.Warn("DHCPv6: no IPv6 router found in neighbor table",
		"interface", ifaceName)
	return netip.Addr{}
}

// waitForLinkLocal waits until the interface has a link-local IPv6 address.
func (m *Manager) waitForLinkLocal(ctx context.Context, ifaceName string, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for link-local on %s", ifaceName)
		case <-ticker.C:
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				if ipNet.IP.To4() == nil && ipNet.IP.IsLinkLocalUnicast() {
					return nil
				}
			}
		}
	}
}

// DeriveSubPrefix derives a sub-prefix from a delegated prefix for RA advertisement.
// If subPrefLen is 0 or equal to the delegated prefix length, the prefix is returned as-is.
// Otherwise, the first sub-prefix of the requested length is derived (e.g., /48 → first /64).
// Returns an invalid prefix if the sub-prefix length is shorter than the delegated prefix.
func DeriveSubPrefix(delegated netip.Prefix, subPrefLen int) netip.Prefix {
	bits := delegated.Bits()
	if subPrefLen == 0 || subPrefLen == bits {
		return delegated
	}
	if subPrefLen < bits {
		// Can't derive a shorter prefix from a longer one
		return netip.Prefix{}
	}
	// Mask the address to the delegated prefix boundary, then re-prefix at subPrefLen.
	// This gives us the first sub-prefix (e.g., 2001:db8:1000::/48 → 2001:db8:1000::/64).
	masked := delegated.Masked()
	return netip.PrefixFrom(masked.Addr(), subPrefLen)
}
