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
	"github.com/insomniacslk/dhcp/iana"

	"github.com/psaab/xpf/pkg/config"
)

// errV6AddrInvalidated signals that a DHCPv6 Reply EXPLICITLY invalidated the
// held IA_NA address: the reply carried IA_NA IAADDR option(s) that were ALL
// valid-lifetime 0 (RFC 8415 §18.2.10.1 — the address is no longer valid and
// MUST be discarded), with no live IA_NA address to replace it. Co-held IA_PD
// prefixes do NOT suppress the sentinel (#14998): the address must be
// discarded even when a delegation survives, otherwise the kernel WAN
// address is orphaned and renewal timers derive from the PD lifetime. It is DISTINCT from the generic "no usable IA_NA / live
// IA_PD" error, which means the reply carried NO usable IAADDR at all (an
// ABSENT / transient reply — server omission or packet loss). The
// discriminator is errors.Is(err, errV6AddrInvalidated): on an EXPLICIT
// invalidation the renew/rebind loop DECONFIGURES the held address and
// re-acquires (§18.2.10.1); on the ABSENT/transient error it KEEPS the address
// and retries (T1→T2→solicit), the correct #4874/#1844 anti-outage behavior.
// Fail SAFE toward keep-and-retry: the sentinel is returned ONLY when a
// present-but-0 IAADDR is positively observed (#5927).
var errV6AddrInvalidated = errors.New("DHCPv6 reply explicitly invalidated the held IA_NA address (valid-lifetime 0)")

// errV6NoBinding signals that the granting server answered a Renew/Rebind
// with Status NoBinding for the held IA_NA (#15071, RFC 8415 §18.2.4: the
// client MUST send a Request to re-establish the binding). It is distinct
// from a silent IA_NA omission, which keeps the held address via
// carry-forward until its valid expiry (#1844 anti-outage).
var errV6NoBinding = errors.New("DHCPv6 server has no binding for the held IA_NA (Status NoBinding)")

// runDHCPv6 runs the DHCPv6 solicit/request cycle with retries and
// renewal. Initial acquisition is a Rapid-Solicit (or Information-Request
// in stateless mode). At T1 the loop sends an RFC 8415 §18.2.4 RENEW to
// the granting server (echoing the assigned IA_NA / IA_PD with the
// server's DUID) and at T2 an §18.2.5 REBIND (multicast, no server DUID)
// — NOT a fresh Solicit (#2994). A successful renewal commits the lease
// (and any delegated prefixes) via commitLease and returns to the T1 wait
// (#1777). After generic T2 failure, stateful clients re-acquire while the
// existing binding remains active through its absolute deadline. Stateless
// mode sends an Information-Request for every refresh; its synthetic
// LeaseTime is only a refresh interval, not an option-expiry deadline.
func (m *Manager) runDHCPv6(ctx context.Context, ifaceName string) {
	key := clientKey{iface: ifaceName, family: AFInet6}
	backoff := time.Second

	m.mu.Lock()
	v6opts := m.v6opts[ifaceName]
	m.mu.Unlock()

	stateless := v6opts != nil && v6opts.Stateless

	// Wait for link-local address. #15070: a terminal 30s timeout here
	// previously returned and killed the client until an unrelated
	// config apply — a firewall booting faster than its ONT/modem lost
	// DHCPv6 (WAN address + delegated prefix) indefinitely. Instead,
	// pace a ctx-bound backoff and re-wait: the wait itself re-polls
	// every 500ms, so as soon as the link-local appears the next wait
	// succeeds and Solicit proceeds. Cancellation (Reconcile removal /
	// Renew / StopAll) still terminates promptly.
	for {
		err := m.waitLinkLocal(ctx, ifaceName, 30*time.Second)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		slog.Warn("DHCPv6: no link-local address, retrying",
			"interface", ifaceName, "err", err, "backoff", terminalRetryBackoff)
		select {
		case <-m.after(terminalRetryBackoff):
		case <-ctx.Done():
			return
		}
	}

	// committed / committedPDs track the lease and delegated prefixes
	// currently applied (nil/empty until the first success). Only stateful
	// bindings receive an absolute expiry during failed reacquisition.
	var (
		committed          *Lease
		committedPDs       []DelegatedPrefix
		leaseExpiryAt      time.Time
		leaseExpiryPending bool
	)

	for {
		if ctx.Err() != nil {
			return
		}
		if !stateless && leaseExpiryPending && !time.Now().Before(leaseExpiryAt) {
			m.abandonLeaseAfterExpiry(key, committed)
			committed = nil
			committedPDs = nil
			leaseExpiryPending = false
		}

		if stateless {
			slog.Info("DHCPv6: starting information-request", "interface", ifaceName)
		} else {
			slog.Info("DHCPv6: starting solicit", "interface", ifaceName)
		}

		// Bound each stateful Solicit and retry backoff by the original lease
		// deadline. Stateless Information-Requests have no binding expiry.
		acquireCtx := ctx
		var cancelAcquire context.CancelFunc
		var expiryDone <-chan struct{}
		if !stateless && leaseExpiryPending {
			acquireCtx, cancelAcquire = context.WithDeadline(ctx, leaseExpiryAt)
			expiryDone = acquireCtx.Done()
		}
		result, err := m.v6Exchange(acquireCtx, ifaceName, exchangeAcquire, nil, nil)
		if err != nil {
			if ctx.Err() != nil {
				if cancelAcquire != nil {
					cancelAcquire()
				}
				return
			}
			if !stateless && leaseExpiryPending && !time.Now().Before(leaseExpiryAt) {
				if cancelAcquire != nil {
					cancelAcquire()
				}
				m.abandonLeaseAfterExpiry(key, committed)
				committed = nil
				committedPDs = nil
				leaseExpiryPending = false
				continue
			}
			slog.Warn("DHCPv6: solicit failed, retrying",
				"interface", ifaceName, "err", err, "backoff", backoff)
			// Keep reacquisition backoff on the production timer: unlike T1/T2,
			// it is also the pacing boundary that lets an expiring held lease
			// be withdrawn before another Solicit.
			retryWait := time.After(backoff)
			if committed != nil {
				var waited bool
				committed, waited = m.waitForIPv6TimerOrRA(acquireCtx, retryWait, key, ifaceName, committed)
				if !waited {
					if ctx.Err() != nil {
						if cancelAcquire != nil {
							cancelAcquire()
						}
						return
					}
					m.abandonLeaseAfterExpiry(key, committed)
					committed = nil
					committedPDs = nil
					leaseExpiryPending = false
					if cancelAcquire != nil {
						cancelAcquire()
					}
					continue
				}
			} else {
				select {
				case <-retryWait:
				case <-ctx.Done():
					if cancelAcquire != nil {
						cancelAcquire()
					}
					return
				case <-expiryDone:
					if ctx.Err() != nil {
						if cancelAcquire != nil {
							cancelAcquire()
						}
						return
					}
					m.abandonLeaseAfterExpiry(key, committed)
					committed = nil
					committedPDs = nil
					leaseExpiryPending = false
					if cancelAcquire != nil {
						cancelAcquire()
					}
					continue
				}
			}
			if cancelAcquire != nil {
				cancelAcquire()
			}
			backoff = min(backoff*2, 60*time.Second)
			continue
		}

		if ctx.Err() != nil {
			if cancelAcquire != nil {
				cancelAcquire()
			}
			if committed != nil && committed.Address.IsValid() {
				m.removeAddress(ifaceName, committed)
			}
			m.mu.Lock()
			delete(m.leases, key)
			delete(m.delegatedPDs, ifaceName)
			m.mu.Unlock()
			return
		}
		if !stateless && leaseExpiryPending &&
			(acquireCtx.Err() != nil || !time.Now().Before(leaseExpiryAt)) {
			if cancelAcquire != nil {
				cancelAcquire()
			}
			m.abandonLeaseAfterExpiry(key, committed)
			committed = nil
			committedPDs = nil
			leaseExpiryPending = false
			continue
		}
		if cancelAcquire != nil {
			cancelAcquire()
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
		if result.pdRefused {
			reconciledPDs, applyPDs = nil, true
		}
		if err := m.commitLease(key, result.lease, committed, reconciledPDs, committedPDs, applyPDs); err != nil {
			slog.Warn("DHCPv6: failed to apply address",
				"interface", ifaceName, "err", err)
			continue
		}
		committed = result.lease
		committedPDs = reconciledPDs
		leaseExpiryPending = false

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
	renewalLoop:
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
				break renewalLoop
			}

			deadline := committed.Obtained.Add(committed.LeaseTime)
			if !stateless && !time.Now().Before(deadline) {
				m.abandonLeaseAfterExpiry(key, committed)
				committed = nil
				committedPDs = nil
				break renewalLoop
			}
			leaseCtx := ctx
			cancelLease := func() {}
			if !stateless {
				leaseCtx, cancelLease = context.WithDeadline(ctx, deadline)
			}

			// #14998 Path A: anchor T1/T2 to absolute instants derived from
			// Obtained so a PD-expiry prune resumes with the remaining time,
			// never a fresh full-tier wait. Past-expiry safety stays bounded
			// by the lease deadline (leaseCtx) — unchanged.
			t1At := committed.Obtained.Add(t1)
			t2At := t1At.Add(t2Remaining)

			// #14598: wake at the earliest PD expiry as well as T1. A PD
			// prune loops (re-derive timers, recompute T1 wait) without
			// renewing the still-live IA_NA lease or abandoning it. Loop
			// with a fresh T1 wait until T1 actually expires.
		t1WaitLoop:
			for {
				t1Wait := m.after(remainingTimer(t1At, time.Now()))
				var outcome pdWaitOutcome
				committed, committedPDs, outcome = m.waitForIPv6TimerOrRAWithPD(
					leaseCtx, t1Wait, key, ifaceName, committed, committedPDs,
				)
				switch outcome {
				case waitOutcomePDExpired:
					continue t1WaitLoop
				case waitOutcomeTimer:
					break t1WaitLoop
				default: // waitOutcomeDone
					if ctx.Err() != nil {
						cancelLease()
						if committed.Address.IsValid() {
							m.removeAddress(ifaceName, committed)
						}
						m.mu.Lock()
						delete(m.leases, key)
						delete(m.delegatedPDs, ifaceName)
						m.mu.Unlock()
						return
					}
					m.abandonLeaseAfterExpiry(key, committed)
					committed = nil
					committedPDs = nil
					cancelLease()
					break renewalLoop
				}
			}
			slog.Info("DHCPv6: T1 expired, renewing", "interface", ifaceName)
			// T1 renewal attempt — RENEW to the granting server, NOT a
			// fresh Solicit (#2994).
			renewed, rerr := m.v6Exchange(leaseCtx, ifaceName, exchangeRenew, committed, committedPDs)
			if rerr == nil {
				if ctx.Err() != nil {
					cancelLease()
					if committed.Address.IsValid() {
						m.removeAddress(ifaceName, committed)
					}
					m.mu.Lock()
					delete(m.leases, key)
					delete(m.delegatedPDs, ifaceName)
					m.mu.Unlock()
					return
				}
				if !stateless && leaseCtx.Err() != nil {
					m.abandonLeaseAfterExpiry(key, committed)
					committed = nil
					committedPDs = nil
					cancelLease()
					break renewalLoop
				}
				reconciledPDs, applyPDs := reconcileDelegatedPDs(committedPDs, renewed.prefixes, renewed.withdrawnPDs)
				if renewed.pdRefused {
					reconciledPDs, applyPDs = nil, true
				}
				if cerr := m.commitLease(key, renewed.lease, committed, reconciledPDs, committedPDs, applyPDs); cerr != nil {
					slog.Warn("DHCPv6: failed to apply renewed lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					if !stateless {
						leaseExpiryAt = deadline
						leaseExpiryPending = true
					}
					cancelLease()
					break renewalLoop
				}
				committed = renewed.lease
				committedPDs = reconciledPDs
				leaseExpiryPending = false
				cancelLease()
				slog.Info("DHCPv6: lease renewed",
					"interface", ifaceName,
					"address", committed.Address,
					"delegated_prefixes", len(renewed.prefixes),
					"lease_time", committed.LeaseTime)
				continue
			}
			if ctx.Err() == nil && leaseCtx.Err() != nil {
				m.abandonLeaseAfterExpiry(key, committed)
				committed = nil
				committedPDs = nil
				cancelLease()
				break renewalLoop
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
				m.abandonLeaseAfterExpiry(key, committed)
				committed = nil
				committedPDs = nil
				leaseExpiryPending = false
				cancelLease()
				break renewalLoop
			}
			if errors.Is(rerr, errV6NoBinding) {
				// #15071: the granting server has no binding for the held
				// IA_NA (RFC 8415 §18.2.4) — send Request via a fresh
				// Solicit/Request cycle. The held address stays installed
				// until re-acquisition replaces it or its kernel/lease
				// lifetime expires; do not wait for T2 against a server
				// that has already said it holds no binding.
				slog.Info("DHCPv6: server reports NoBinding for held IA_NA, re-acquiring via Request",
					"interface", ifaceName, "address", committed.Address)
				if !stateless {
					leaseExpiryAt = deadline
					leaseExpiryPending = true
				}
				cancelLease()
				break renewalLoop
			}
			slog.Warn("DHCPv6: T1 renewal failed, waiting for T2",
				"interface", ifaceName, "err", rerr)

			// Keep RA state current until T2; also wake at PD expiry (#14598).
			// #14998: resume with remainingTimer(t2At), not a fresh t2Remaining.
		t2WaitLoop:
			for {
				t2Wait := m.after(remainingTimer(t2At, time.Now()))
				var outcome pdWaitOutcome
				committed, committedPDs, outcome = m.waitForIPv6TimerOrRAWithPD(
					leaseCtx, t2Wait, key, ifaceName, committed, committedPDs,
				)
				switch outcome {
				case waitOutcomePDExpired:
					continue t2WaitLoop
				case waitOutcomeTimer:
					break t2WaitLoop
				default:
					if ctx.Err() != nil {
						cancelLease()
						if committed.Address.IsValid() {
							m.removeAddress(ifaceName, committed)
						}
						m.mu.Lock()
						delete(m.leases, key)
						delete(m.delegatedPDs, ifaceName)
						m.mu.Unlock()
						return
					}
					m.abandonLeaseAfterExpiry(key, committed)
					committed = nil
					committedPDs = nil
					cancelLease()
					break renewalLoop
				}
			}

			// T2 rebind attempt — REBIND (multicast, no server DUID) (#2994),
			// bounded by the absolute lease deadline.
			renewed, rerr = m.v6Exchange(leaseCtx, ifaceName, exchangeRebind, committed, committedPDs)
			if rerr == nil {
				if ctx.Err() != nil {
					cancelLease()
					if committed.Address.IsValid() {
						m.removeAddress(ifaceName, committed)
					}
					m.mu.Lock()
					delete(m.leases, key)
					delete(m.delegatedPDs, ifaceName)
					m.mu.Unlock()
					return
				}
				if !stateless && leaseCtx.Err() != nil {
					m.abandonLeaseAfterExpiry(key, committed)
					committed = nil
					committedPDs = nil
					cancelLease()
					break renewalLoop
				}
				reconciledPDs, applyPDs := reconcileDelegatedPDs(committedPDs, renewed.prefixes, renewed.withdrawnPDs)
				if renewed.pdRefused {
					reconciledPDs, applyPDs = nil, true
				}
				if cerr := m.commitLease(key, renewed.lease, committed, reconciledPDs, committedPDs, applyPDs); cerr != nil {
					slog.Warn("DHCPv6: failed to apply rebound lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					if !stateless {
						leaseExpiryAt = deadline
						leaseExpiryPending = true
					}
					cancelLease()
					break renewalLoop
				}
				committed = renewed.lease
				committedPDs = reconciledPDs
				leaseExpiryPending = false
				cancelLease()
				slog.Info("DHCPv6: lease rebound",
					"interface", ifaceName,
					"address", committed.Address,
					"delegated_prefixes", len(renewed.prefixes),
					"lease_time", committed.LeaseTime)
				continue
			}
			if ctx.Err() == nil && leaseCtx.Err() != nil {
				m.abandonLeaseAfterExpiry(key, committed)
				committed = nil
				committedPDs = nil
				cancelLease()
				break renewalLoop
			}
			if errors.Is(rerr, errV6AddrInvalidated) {
				// #5927: explicit invalidation on REBIND too — deconfigure the
				// held address before falling back to a fresh solicit (the
				// generic rebind-failure break below keeps it in service until
				// re-acquire, which is correct only for a transient failure).
				slog.Info("DHCPv6: server invalidated held address on rebind (valid-lifetime 0), deconfiguring and re-acquiring",
					"interface", ifaceName, "address", committed.Address)
				m.abandonLeaseAfterExpiry(key, committed)
				committed = nil
				committedPDs = nil
				leaseExpiryPending = false
				cancelLease()
				break renewalLoop
			}
			if errors.Is(rerr, errV6NoBinding) {
				// #15071: NoBinding on REBIND — same Request re-acquisition
				// as at T1; the generic break below already re-acquires,
				// this arm only makes the reason explicit in the log.
				slog.Info("DHCPv6: server reports NoBinding for held IA_NA on rebind, re-acquiring via Request",
					"interface", ifaceName, "address", committed.Address)
			}
			if stateless {
				slog.Warn("DHCPv6: T2 information-request failed, retrying options",
					"interface", ifaceName, "err", rerr)
			} else {
				slog.Warn("DHCPv6: T2 rebind failed, lease will expire, re-acquiring",
					"interface", ifaceName, "err", rerr)
				leaseExpiryAt = deadline
				leaseExpiryPending = true
			}
			cancelLease()
			break renewalLoop
		}
	}
}

// dhcpv6Result holds results from a DHCPv6 exchange including both IA_NA and IA_PD.
type dhcpv6Result struct {
	lease *Lease
	// prefixes holds the LIVE delegated prefixes (valid-lifetime > 0).
	prefixes []DelegatedPrefix
	// withdrawnPDs holds prefixes the reply carried with valid-lifetime 0
	// — an RFC 8415 §12.1 explicit withdrawal (#4874 B) — plus, when
	// pdRefused is set, a refusal marker for held prefixes.
	withdrawnPDs []DelegatedPrefix
	// pdRefused is true when the reply's IA_PD carried a non-Success
	// status (e.g. NoPrefixAvail): the server refused the delegation, so
	// held PDs must not be extended past their own lifetimes (#14598).
	pdRefused bool
	// routers is the complete observation from this exchange's RS/RA window.
	routers   []observedRouter
	raSampled bool
}

// doDHCPv6 performs one DHCPv6 exchange. Acquisition attempts rapid commit
// and otherwise collects Advertises before Requesting the highest-preference
// server. Renew/rebind retain their RFC 8415 binding behavior.
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

		resp, err := client.SendAndRead(exCtx, nclient6.AllDHCPRelayAgentsAndServers, msg, v6StatelessMatcher(msg))
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 information-request: %w", err)
		}

		lease := &Lease{
			Interface: ifaceName,
			Family:    AFInet6,
			Obtained:  time.Now(),
			LeaseTime: time.Hour,
		}
		if dnsOpt := resp.Options.DNS(); len(dnsOpt) > 0 {
			for _, dns := range dnsOpt {
				if a, ok := netip.AddrFromSlice(dns); ok {
					lease.DNS = append(lease.DNS, a)
				}
			}
		}

		routers := m.observedRouterAdvertisements(ctx, ifaceName)
		return &dhcpv6Result{lease: lease, routers: routers, raSampled: true}, nil
	}

	var adv *dhcpv6.Message
	switch mode {
	case exchangeRenew, exchangeRebind:
		rebind := mode == exchangeRebind
		// Renew/rebind echo the actual held IA_NA/IA_PD, so use only the
		// client-id + ORO modifiers — NOT the acquisition IA_PD hint
		// (which would merge a hint prefix into our real IA_PD). When no
		// PD is held but ia-pd is configured, buildV6RenewMessage
		// re-requests the delegation with an empty IA_PD carrying this
		// hint instead (#15069).
		renewMods := m.buildDHCPv6RenewModifiers(ifaceName, v6opts)
		var (
			iaTypes []string
			pdHint  *dhcpv6.OptIAPrefix
		)
		if v6opts != nil {
			iaTypes = v6opts.IATypes
			if n, ok := pdHintPrefixLength(ifaceName, v6opts.PDPrefLen); ok {
				pdHint = &dhcpv6.OptIAPrefix{
					Prefix: &net.IPNet{
						IP:   net.IPv6zero,
						Mask: net.CIDRMask(n, 128),
					},
				}
			}
		}
		msg, err := buildV6RenewMessage(client.InterfaceAddr(), prev, prevPDs, rebind, renewMods, iaTypes, pdHint)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 build %s: %w", mode, err)
		}
		adv, err = client.SendAndRead(exCtx, nclient6.AllDHCPRelayAgentsAndServers, msg,
			v6RenewMatcher(m, msg, prev, rebind))
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 %s: %w", mode, err)
		}
	default:
		adv, err = v6Acquire(exCtx, client, mods)
		if err != nil {
			return nil, fmt.Errorf("DHCPv6 solicit: %w", err)
		}
	}

	wantNA := v6IANAIAID(client.InterfaceAddr())
	result, err := m.parseV6ReplyChecked(ctx, ifaceName, adv, v6opts, &wantNA, &v6IAPDIAID, prev)
	if err != nil {
		return nil, err
	}
	result.routers = m.observedRouterAdvertisements(ctx, ifaceName)
	result.raSampled = true
	return result, nil
}

const v6AdvertiseCollectionTime = time.Second

var v6IAPDIAID = [4]byte{0, 0, 0, 1}

func v6IANAIAID(hwaddr net.HardwareAddr) [4]byte {
	var iaid [4]byte
	if len(hwaddr) >= len(iaid) {
		copy(iaid[:], hwaddr[len(hwaddr)-len(iaid):])
	}
	return iaid
}

func v6StatusOK(status *dhcpv6.OptStatusCode) bool {
	return status == nil || status.StatusCode == iana.StatusSuccess
}

// v6IANAStatusCode returns the StatusCode option inside the IA_NA
// matching expectedIAID, or nil when there is no such IA_NA or it
// carries no status. Used to distinguish a server NoBinding (#15071:
// send Request) from a silent omission (#1844: keep + retry via
// carry-forward).
func v6IANAStatusCode(adv *dhcpv6.Message, expectedIAID *[4]byte) *dhcpv6.OptStatusCode {
	if adv == nil {
		return nil
	}
	for _, opt := range adv.Options.Options {
		ianaOpt, ok := opt.(*dhcpv6.OptIANA)
		if !ok {
			continue
		}
		if expectedIAID != nil && ianaOpt.IaId != *expectedIAID {
			continue
		}
		return ianaOpt.Options.Status()
	}
	return nil
}

// carryForwardV6IANA returns a lease that keeps the held IA_NA address
// when a Renew/Rebind Reply carried no usable IA_NA (#15071). The
// returned lease preserves prev's Address, LeaseTime and Obtained so
// buildV6RenewMessage keeps echoing the held binding until its valid
// expiry; the run loop then re-acquires at the absolute deadline
// (leaseCtx) if the server never restores the IA_NA. ok=false when
// there is no held address or it has already expired at now.
func carryForwardV6IANA(prev *Lease, now time.Time) (carried *Lease, ok bool) {
	if prev == nil || !prev.Address.IsValid() {
		return nil, false
	}
	if exp := prev.ExpiresAt(); !exp.IsZero() && !now.Before(exp) {
		return nil, false
	}
	carried = &Lease{
		Interface:          prev.Interface,
		Family:             prev.Family,
		Address:            prev.Address,
		LeaseTime:          prev.LeaseTime,
		Obtained:           prev.Obtained,
		leaseExpiryApplies: prev.leaseExpiryApplies,
		v6ServerDUID:       prev.v6ServerDUID,
	}
	return carried, true
}

// kernelAddrLifetimes converts a lease's remaining lifetimes at now
// into netlink ValidLft/PreferedLft seconds for AddrReplace (#15071).
// A finite lease installs its remaining lifetime so the kernel expires
// the address even if userspace removal is missed; the RFC 8415
// infinite sentinel installs as 0xffffffff (forever); an expired or
// zero-lifetime lease installs no lifetime attribute (0,0), matching
// netlink's "only set cacheinfo when non-zero" encoding where 0/0
// leaves the address permanent — callers must not applyAddress an
// expired lease.
func kernelAddrLifetimes(lease *Lease, now time.Time) (valid, pref int) {
	if lease == nil {
		return 0, 0
	}
	p, v := lease.RemainingLifetimes(now)
	if v <= 0 {
		return 0, 0
	}
	if v >= infiniteLifetime {
		return 0xffffffff, 0xffffffff
	}
	return int(v / time.Second), int(p / time.Second)
}

func v6MessageStatusOK(msg *dhcpv6.Message) bool {
	return msg != nil && v6StatusOK(msg.Options.Status())
}

func v6MessageStatusError(msg *dhcpv6.Message) error {
	if msg == nil {
		return errors.New("nil DHCPv6 message")
	}
	if status := msg.Options.Status(); status != nil && status.StatusCode != iana.StatusSuccess {
		return fmt.Errorf("DHCPv6 %s message status %s: %s", msg.MessageType, status.StatusCode, status.StatusMessage)
	}
	return nil
}

// v6HasSuccessfulRequestedIA requires a successful IA matching at least one
// of the requested IAIDs. An unsuccessful IA cannot carry usable sub-options.
func v6HasSuccessfulRequestedIA(req, resp *dhcpv6.Message) bool {
	if req == nil || resp == nil {
		return false
	}
	found := false
	for _, expected := range req.Options.IANA() {
		for _, got := range resp.Options.IANA() {
			if got.IaId == expected.IaId && v6StatusOK(got.Options.Status()) {
				found = true
			}
		}
	}
	for _, expected := range req.Options.IAPD() {
		for _, got := range resp.Options.IAPD() {
			if got.IaId == expected.IaId && v6StatusOK(got.Options.Status()) {
				found = true
			}
		}
	}
	return found
}

func v6ReplyMatches(req, resp *dhcpv6.Message, expectedServer dhcpv6.DUID) bool {
	if req == nil || resp == nil ||
		resp.MessageType != dhcpv6.MessageTypeReply ||
		resp.TransactionID != req.TransactionID ||
		req.Options.ClientID() == nil ||
		!sameDUID(resp.Options.ClientID(), req.Options.ClientID()) ||
		!v6MessageStatusOK(resp) ||
		!v6HasSuccessfulRequestedIA(req, resp) {
		return false
	}
	serverID := resp.Options.ServerID()
	if serverID == nil {
		return false
	}
	return expectedServer == nil || sameDUID(serverID, expectedServer)
}

func v6StatelessMatcher(req *dhcpv6.Message) nclient6.Matcher {
	return func(resp *dhcpv6.Message) bool {
		return req != nil && resp != nil &&
			resp.MessageType == dhcpv6.MessageTypeReply &&
			resp.TransactionID == req.TransactionID &&
			req.Options.ClientID() != nil &&
			sameDUID(resp.Options.ClientID(), req.Options.ClientID()) &&
			resp.Options.ServerID() != nil &&
			v6MessageStatusOK(resp)
	}
}

func v6AdvertiseMatches(req, adv *dhcpv6.Message) bool {
	if req == nil || adv == nil ||
		adv.MessageType != dhcpv6.MessageTypeAdvertise ||
		adv.TransactionID != req.TransactionID ||
		req.Options.ClientID() == nil ||
		!sameDUID(adv.Options.ClientID(), req.Options.ClientID()) ||
		adv.Options.ServerID() == nil ||
		!v6MessageStatusOK(adv) {
		return false
	}
	return v6HasSuccessfulRequestedIA(req, adv)
}

func v6AdvertisePreference(adv *dhcpv6.Message) uint8 {
	if adv == nil {
		return 0
	}
	opt, ok := adv.Options.GetOne(dhcpv6.OptionPreference).(*dhcpv6.OptionGeneric)
	if !ok || len(opt.OptionData) != 1 {
		return 0
	}
	return opt.OptionData[0]
}

func v6SelectAdvertise(advertises []*dhcpv6.Message) *dhcpv6.Message {
	var best *dhcpv6.Message
	var bestPreference uint8
	for _, adv := range advertises {
		preference := v6AdvertisePreference(adv)
		if best == nil || preference > bestPreference {
			best, bestPreference = adv, preference
		}
	}
	return best
}

// v6Acquire attempts rapid commit first, then collects ordinary Advertises
// for RFC 8415 Preference selection. Preference 255 is an immediate choice;
// otherwise the one-second collection window lets slower servers compete.
func v6Acquire(ctx context.Context, client *nclient6.Client, modifiers []dhcpv6.Modifier) (*dhcpv6.Message, error) {
	solicit, err := dhcpv6.NewSolicit(client.InterfaceAddr(), modifiers...)
	if err != nil {
		return nil, fmt.Errorf("build SOLICIT: %w", err)
	}
	dhcpv6.WithRapidCommit(solicit)
	var advertises []*dhcpv6.Message
	matcher := func(resp *dhcpv6.Message) bool {
		if v6ReplyMatches(solicit, resp, nil) {
			return true
		}
		if !v6AdvertiseMatches(solicit, resp) {
			return false
		}
		advertises = append(advertises, resp)
		return v6AdvertisePreference(resp) == 255
	}
	collectCtx, cancel := context.WithTimeout(ctx, v6AdvertiseCollectionTime)
	adv, err := client.SendAndRead(collectCtx, nclient6.AllDHCPRelayAgentsAndServers, solicit, matcher)
	cancel()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err == nil && adv.MessageType == dhcpv6.MessageTypeReply {
		return adv, nil
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	best := v6SelectAdvertise(advertises)
	if best == nil {
		return nil, nclient6.ErrNoResponse
	}
	request, err := dhcpv6.NewRequestFromAdvertise(best, modifiers...)
	if err != nil {
		return nil, fmt.Errorf("build REQUEST from selected ADVERTISE: %w", err)
	}
	return client.SendAndRead(ctx, nclient6.AllDHCPRelayAgentsAndServers, request,
		func(resp *dhcpv6.Message) bool {
			return v6ReplyMatches(request, resp, best.Options.ServerID())
		})
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
//   - discard any IAADDR whose preferred-lifetime exceeds its
//     valid-lifetime — RFC 8415 §21.6: "The client MUST discard any
//     addresses for which the preferred lifetime is greater than the
//     valid lifetime." Without this, ranking by preferred-lifetime lets
//     a pref=0xFFFFFFFF/valid=1s candidate beat every usable sibling
//     (#14185);
//   - skip any IAADDR that is not acceptable as a host address on the
//     interface: the same global-unicast-only class policy IA_PD already
//     enforces via config.DelegatedIPv6PrefixRefusalReason on the /128
//     (loopback, link-local, multicast, unspecified, ULA, documentation,
//     IPv4-compatible/mapped, site-local are all refused) and any
//     address overlapping a protected (configured interface / RA /
//     NAT64) prefix in protected (#10856 parity, #14185). A rogue or
//     buggy server must not make the firewall bind ::1, fe80::1, or a
//     LAN/configured address on its WAN interface;
//   - among the rest, prefer the longest preferred-lifetime;
//   - ties are broken by first-seen (option order).
//
// Each refused IAADDR is skipped independently, so a usable sibling is
// salvaged — the same per-element policy extractDelegatedPrefixes
// applies to IAPREFIX options. A refused address is NOT a withdrawal:
// it never sets sawZeroLifetime, so it cannot deconfigure a held
// address; when every candidate is refused the caller sees the generic
// absent/transient failure and keeps + retries.
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
//
// expectedIAID, when non-nil, restricts selection to that IA_NA.
// protected is the snapshot from Manager.protectedIPv6Prefixes (nil
// refuses nothing on overlap — the class policy still applies).
func selectIANAAddress(adv *dhcpv6.Message, expectedIAID *[4]byte, protected []netip.Prefix) (addr netip.Addr, validLT time.Duration, sawZeroLifetime bool) {
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
		if expectedIAID != nil && ianaOpt.IaId != *expectedIAID {
			continue
		}
		if !v6StatusOK(ianaOpt.Options.Status()) {
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
			// RFC 8415 §21.6: discard any address whose preferred lifetime
			// exceeds its valid lifetime, before ranking (#14185).
			if iaaddr.PreferredLifetime > iaaddr.ValidLifetime {
				continue
			}
			a, ok := netip.AddrFromSlice(iaaddr.IPv6Addr)
			if !ok || !a.Is6() || a.Is4In6() {
				continue
			}
			// #14185: the IA_NA address is installed on the firewall
			// itself, so it needs at least the validation IA_PD already
			// gets (#10856): global-unicast-only class policy on the /128
			// plus no overlap with protected configured space. Skip only
			// the offending IAADDR; a usable sibling is salvaged.
			candidate := netip.PrefixFrom(a, 128)
			if reason := config.DelegatedIPv6PrefixRefusalReason(candidate); reason != "" {
				slog.Warn("DHCPv6: refusing IA_NA address with blocked address class",
					"address", a,
					"reason", reason)
				continue
			}
			if hit := overlappingProtectedPrefix(candidate, protected); hit.IsValid() {
				slog.Warn("DHCPv6: refusing IA_NA address overlapping configured prefix",
					"address", a,
					"configured", hit)
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

// parseV6Reply extracts DHCPv6 options for unit callers that do not have an
// interface IAID. Production exchanges use parseV6ReplyChecked below.
func (m *Manager) parseV6Reply(ctx context.Context, ifaceName string, adv *dhcpv6.Message, v6opts *DHCPv6Options) (*dhcpv6Result, error) {
	result, err := m.parseV6ReplyChecked(ctx, ifaceName, adv, v6opts, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	result.routers = m.observedRouterAdvertisements(ctx, ifaceName)
	result.raSampled = true
	result.lease = applyIPv6RouterAdvertisements(nil, result.lease, result.routers, time.Now())
	return result, nil
}

// parseV6ReplyChecked parses a Reply. prev is the held lease on a
// Renew/Rebind exchange (nil on acquisition): when the Reply carries no
// usable IA_NA but the client holds an unexpired IA_NA, the held address
// is carried forward (#15071) instead of committing an address-less lease
// that stops echoing the binding. prev must NOT carry forward on an
// explicit valid-lifetime-0 invalidation (#5927) or a NoBinding status
// (RFC 8415 §18.2.4 — the caller sends Request via errV6NoBinding).
func (m *Manager) parseV6ReplyChecked(ctx context.Context, ifaceName string, adv *dhcpv6.Message, v6opts *DHCPv6Options, expectedNA, expectedPD *[4]byte, prev ...*Lease) (*dhcpv6Result, error) {
	if err := v6MessageStatusError(adv); err != nil {
		return nil, err
	}

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
		addr, validLT, sawZeroLifetime = selectIANAAddress(adv, expectedNA, m.protectedIPv6Prefixes())
		iaNAExplicitlyInvalidated = !addr.IsValid() && sawZeroLifetime
	}

	// Extract IA_PD delegated prefixes, split into live and (RFC 8415
	// §12.1) explicitly-withdrawn valid-lifetime-0 prefixes (#4874 B).
	if wantPD {
		// #10856: extraction also refuses IA_PD prefixes that overlap
		// configured space. The daemon keeps the protected snapshot current
		// (SetProtectedIPv6Prefixes on every apply), so a renewal after a
		// config change re-validates a previously accepted delegation
		// against the new configuration.
		result.prefixes, result.withdrawnPDs, result.pdRefused = extractDelegatedPrefixes(adv, ifaceName, now, m.protectedIPv6Prefixes(), expectedPD)
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

	// #14998: an explicitly invalidated IA_NA fires the sentinel even when
	// the same Reply carries a live IA_PD prefix. Returning a success
	// address-less lease here would orphan the held kernel WAN address
	// (commitLease's address handling keyed on the new lease's address)
	// and re-derive T1/T2/deadline from the PD lifetime / 3600s floor.
	if iaNAExplicitlyInvalidated {
		return nil, fmt.Errorf("DHCPv6 reply on %s: %w", ifaceName, errV6AddrInvalidated)
	}

	// #15071: a Renew/Rebind Reply whose IA_NA carries Status NoBinding
	// means the server has lost the binding — RFC 8415 §18.2.4 requires
	// the client to send a Request (re-acquire). Surface it distinctly so
	// the run loop re-acquires instead of carrying the address forward.
	// selectIANAAddress skips a non-Success IA_NA, so addr is invalid here
	// whenever this fires. Only when a held lease exists (renew/rebind):
	// on acquisition prev is nil and the generic guard below applies.
	var held *Lease
	if len(prev) > 0 {
		held = prev[0]
	}
	if wantNA && !addr.IsValid() && held != nil {
		if st := v6IANAStatusCode(adv, expectedNA); st != nil && st.StatusCode == iana.StatusNoBinding {
			return nil, fmt.Errorf("DHCPv6 reply on %s: %w", ifaceName, errV6NoBinding)
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
		return nil, fmt.Errorf("no usable IA_NA address or live IA_PD prefix in DHCPv6 reply on %s", ifaceName)
	}

	lease := &Lease{
		Interface:          ifaceName,
		Family:             AFInet6,
		Obtained:           now,
		leaseExpiryApplies: true,
	}

	// Server identifier (DUID) — echoed in the next RENEW so the original
	// server matches our binding (#2994).
	lease.v6ServerDUID = adv.Options.ServerID()

	if addr.IsValid() {
		lease.Address = netip.PrefixFrom(addr, 128)
		lease.LeaseTime = validLT
		// #14598: IA_NA present — LeaseTime stays the IA_NA lifetime for
		// T1/T2. PD expiry is tracked per-prefix (ExpiresAt, pruning,
		// earliest-expiry recompile wake), not by shortening this lease.
	} else if wantNA {
		// #15071: no usable IA_NA in this Reply (absent, or only refused
		// IAADDRs) but a live PD (or degenerate config) let us reach here.
		// On a renew/rebind, carry the held IA_NA forward so the committed
		// lease keeps echoing it until its valid expiry — never commit an
		// address-less successor over an addressed lease. The carried
		// lease preserves Address/LeaseTime/Obtained; DNS/routers/PDs from
		// this Reply still apply via the fields set below and the caller.
		if carried, ok := carryForwardV6IANA(held, now); ok {
			lease.Address = carried.Address
			lease.LeaseTime = carried.LeaseTime
			lease.Obtained = carried.Obtained
		} else if len(result.prefixes) > 0 {
			lease.LeaseTime = result.prefixes[0].ValidLifetime
			for _, dp := range result.prefixes[1:] {
				if dp.ValidLifetime < lease.LeaseTime {
					lease.LeaseTime = dp.ValidLifetime
				}
			}
		}
	} else if len(result.prefixes) > 0 {
		// PD-only mode: the lease deadline must not outlive the shortest
		// delegated prefix (#14598) — previously only prefixes[0] was used,
		// so a short second prefix outlived its valid lifetime.
		lease.LeaseTime = result.prefixes[0].ValidLifetime
		for _, dp := range result.prefixes[1:] {
			if dp.ValidLifetime < lease.LeaseTime {
				lease.LeaseTime = dp.ValidLifetime
			}
		}
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

	// Router Advertisements are sampled by the exchange wrapper and applied
	// with the prior lease there so silence can retain a live gateway.

	result.lease = lease
	return result, nil
}

// buildDHCPv6RenewModifiers constructs the modifiers for a RENEW/REBIND
// message: the persistent client-id and the requested-option list, but
// NOT the IA_NA/IA_PD options (buildV6RenewMessage adds the held-binding
// echo, or the empty re-request IA_PD when no delegation is held and
// ia-pd is configured, #15069). Reusing buildDHCPv6Modifiers here
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
//
// #10856: an IAPREFIX is also refused unless it is global-unicast space
// (DelegatedIPv6PrefixRefusalReason: ULA, documentation, link-local,
// multicast, loopback, unspecified, IPv4-compatible/mapped, site-local are
// all refused — there is no pin mechanism yet, #12533 tracks one) and unless
// it overlaps no protected prefix — the configured interface, RA, and NAT64
// prefixes the daemon injects via SetProtectedIPv6Prefixes. Like the mask
// arm, both refusals skip only the offending IAPREFIX, so a usable sibling
// is salvaged. A prefix refused here is NOT withdrawn either: the server
// did not revoke it, and manufacturing a withdrawal would let a spoofed
// reply tear down an unrelated held delegation.
func extractDelegatedPrefixes(msg *dhcpv6.Message, ifaceName string, now time.Time, protected []netip.Prefix, expectedIAID ...*[4]byte) (live, withdrawn []DelegatedPrefix, pdRefused bool) {
	for _, opt := range msg.Options.Options {
		iapdOpt, ok := opt.(*dhcpv6.OptIAPD)
		if !ok {
			continue
		}
		if len(expectedIAID) > 0 && expectedIAID[0] != nil && iapdOpt.IaId != *expectedIAID[0] {
			continue
		}
		if !v6StatusOK(iapdOpt.Options.Status()) {
			// #14598: a non-Success IA_PD (e.g. NoPrefixAvail) is an explicit
			// refusal, not silence. It authorises withdrawing held prefixes
			// of this IA; stray IAPREFIX sub-options are ignored (the
			// #10858 stray-option rule). The matcher already authenticated
			// this Reply, so this cannot be spoofed into a teardown.
			pdRefused = true
			withdrawn = append(withdrawn, DelegatedPrefix{Interface: ifaceName, Obtained: now})
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
			delegated := netip.PrefixFrom(ip, ones)
			if reason := config.DelegatedIPv6PrefixRefusalReason(delegated); reason != "" {
				slog.Warn("DHCPv6: refusing IA_PD prefix with blocked address class",
					"interface", ifaceName,
					"prefix", delegated,
					"reason", reason)
				continue
			}
			// #10856: a delegation overlapping CONFIGURED space (interface
			// addresses, static RA prefixes, NAT64 prefixes) must not be
			// accepted either: re-advertising it on-link + autonomous on the
			// LAN collides SLAAC hosts with the configured segment. No pin
			// mechanism exists yet (#12533), so every overlap is refused.
			if hit := overlappingProtectedPrefix(delegated, protected); hit.IsValid() {
				slog.Warn("DHCPv6: refusing IA_PD prefix overlapping configured prefix",
					"interface", ifaceName,
					"prefix", delegated,
					"configured", hit)
				continue
			}
			dp := DelegatedPrefix{
				Interface:         ifaceName,
				Prefix:            delegated,
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
	return live, withdrawn, pdRefused
}

// overlappingProtectedPrefix returns the first protected prefix that shares
// any address with delegated, or the zero Prefix when there is no overlap.
// Host bits are ignored on both sides (IPv6PrefixesOverlap), so a delegation
// is refused whether it contains, is contained by, or straddles configured
// space.
func overlappingProtectedPrefix(delegated netip.Prefix, protected []netip.Prefix) netip.Prefix {
	for _, p := range protected {
		if config.IPv6PrefixesOverlap(delegated, p) {
			return p
		}
	}
	return netip.Prefix{}
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
