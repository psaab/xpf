// dhcpv4.go holds the DHCPv4 client: the DORA/renew/rebind run
// loop, the single-exchange primitive, and ACK/classless-route
// parsing. Split verbatim from dhcp.go (#6430).
package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"

	"github.com/psaab/xpf/pkg/config"
)

// runDHCPv4 runs the DHCPv4 acquisition and renewal cycle. The initial
// acquisition is a full DORA (Discover→Offer→Request→Ack). At T1 the
// loop sends a true RFC 2131 §4.3.6 RENEWING DHCPREQUEST — unicast to
// the granting server (the stored server-identifier), ciaddr set to the
// current address, NO DISCOVER — and at T2 a REBINDING broadcast
// DHCPREQUEST (#2994). A successful renew/rebind commits via commitLease
// and returns to the T1 wait (#1777); only when both fail (lease
// expiry) does the loop fall back to a fresh full DORA acquisition.
func (m *Manager) runDHCPv4(ctx context.Context, ifaceName string) {
	key := clientKey{iface: ifaceName, family: AFInet}

	m.mu.Lock()
	opts := m.v4opts[ifaceName]
	m.mu.Unlock()

	// #8642: the schema leaf here is `ValidateIntegerMin(1)` — no ceiling at
	// all — so this is the one site in the sweep reachable from an ORDINARY
	// STRICT commit, without the tolerant-ingress argument. The harm is bounded
	// (`backoff = min(backoff*2, 60s)` climbs out in ~27 doublings, so it is a
	// microsecond-scale burst rather than a storm), which is why it is fixed
	// here rather than by adding a schema ceiling that would reject configs the
	// runtime handles.
	baseBackoff := time.Second
	if opts != nil {
		baseBackoff = config.SecondsToDuration(opts.RetransmissionInterval, time.Second)
	}
	maxAttempts := 0 // unlimited
	if opts != nil && opts.RetransmissionAttempt > 0 {
		maxAttempts = opts.RetransmissionAttempt
	}

	backoff := baseBackoff
	attempt := 0

	// committed is the lease currently applied to the interface (nil
	// until the first successful acquisition). commitLease compares
	// against it to detect address moves and content changes.
	var committed *Lease

	for {
		if ctx.Err() != nil {
			return
		}

		slog.Info("DHCPv4: starting discovery", "interface", ifaceName)

		lease, err := m.v4Exchange(ctx, ifaceName, exchangeAcquire, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			attempt++
			if maxAttempts > 0 && attempt >= maxAttempts {
				slog.Warn("DHCPv4: max retransmission attempts reached",
					"interface", ifaceName, "attempts", attempt)
				return
			}
			slog.Warn("DHCPv4: discovery failed, retrying",
				"interface", ifaceName, "err", err, "backoff", backoff,
				"attempt", attempt)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, 60*time.Second)
			continue
		}

		backoff = baseBackoff // reset on success
		attempt = 0

		if err := m.commitLease(key, lease, committed, nil, nil, false); err != nil {
			slog.Warn("DHCPv4: failed to apply address",
				"interface", ifaceName, "err", err)
			continue
		}
		committed = lease

		slog.Info("DHCPv4: lease obtained",
			"interface", ifaceName,
			"address", lease.Address,
			"gateway", lease.Gateway,
			"lease_time", lease.LeaseTime)

		// Renewal cycle: stay in this loop while T1 renews / T2 rebinds
		// keep succeeding; break out only to re-acquire from scratch.
		for {
			t1, t2Remaining, ok := renewalTimers(committed.LeaseTime)
			if !ok {
				// A non-positive lease time is invalid (RFC 2131 lease 0 is
				// not the infinite sentinel). The lease is unusable: do not
				// schedule a renewal that would fire after it has already
				// lapsed — abandon it and re-acquire, paced by
				// reacquireBackstop so a server that keeps granting a
				// 0-second lease does not become a tight loop (#5795).
				slog.Warn("DHCPv4: non-positive lease time, re-acquiring",
					"interface", ifaceName, "lease_time", committed.LeaseTime)
				select {
				case <-m.after(reacquireBackstop):
				case <-ctx.Done():
					m.removeAddress(ifaceName, committed)
					m.mu.Lock()
					delete(m.leases, key)
					m.mu.Unlock()
					return
				}
				break
			}

			// Wait for T1 (50% of lease time) for renewal
			select {
			case <-m.after(t1):
				slog.Info("DHCPv4: T1 expired, renewing", "interface", ifaceName)
			case <-ctx.Done():
				m.removeAddress(ifaceName, committed)
				m.mu.Lock()
				delete(m.leases, key)
				m.mu.Unlock()
				return
			}

			// T1 renewal attempt — unicast RENEW to the granting server,
			// NOT a fresh DISCOVER (#2994).
			renewed, rerr := m.v4Exchange(ctx, ifaceName, exchangeRenew, committed)
			if rerr == nil {
				if cerr := m.commitLease(key, renewed, committed, nil, nil, false); cerr != nil {
					slog.Warn("DHCPv4: failed to apply renewed lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					break
				}
				committed = renewed
				slog.Info("DHCPv4: lease renewed",
					"interface", ifaceName, "address", renewed.Address,
					"lease_time", renewed.LeaseTime)
				continue
			}
			// A DHCPNAK from the granting server is an explicit lease
			// revocation: the address is no longer valid (reassigned /
			// moved subnet). Per RFC 2131 §4.4.5 abandon it immediately and
			// return to INIT (fresh DISCOVER) — do NOT keep using it until
			// T2 (#3956). A genuine renew TIMEOUT still falls through to
			// the T2 rebind. Wrong-server NAKs are filtered by
			// v4RenewMatcher and remain ordinary timeouts.
			if errors.Is(rerr, errDHCPNAK) {
				slog.Warn("DHCPv4: RENEWING NAK — lease revoked, deconfiguring and restarting DISCOVER",
					"interface", ifaceName)
				m.abandonLeaseAfterNAK(key, committed)
				committed = nil
				break // outer loop → fresh DORA from INIT
			}
			slog.Warn("DHCPv4: T1 renewal failed, waiting for T2",
				"interface", ifaceName, "err", rerr)

			// Wait for T2 (87.5% of lease) — remaining time after T1
			select {
			case <-m.after(t2Remaining):
			case <-ctx.Done():
				m.removeAddress(ifaceName, committed)
				m.mu.Lock()
				delete(m.leases, key)
				m.mu.Unlock()
				return
			}

			// T2 rebind attempt — broadcast REBIND (#2994).
			renewed, rerr = m.v4Exchange(ctx, ifaceName, exchangeRebind, committed)
			if rerr == nil {
				if cerr := m.commitLease(key, renewed, committed, nil, nil, false); cerr != nil {
					slog.Warn("DHCPv4: failed to apply rebound lease, re-acquiring",
						"interface", ifaceName, "err", cerr)
					break
				}
				committed = renewed
				slog.Info("DHCPv4: lease rebound",
					"interface", ifaceName, "address", renewed.Address,
					"lease_time", renewed.LeaseTime)
				continue
			}
			// A DHCPNAK from the granting server in REBINDING is also a
			// revocation (RFC 2131 §4.4.5): deconfigure now and re-DISCOVER
			// from INIT with no prior lease. A rebind TIMEOUT is left to the
			// lease-expiry fallback, retaining the address until re-acquire
			// replaces it (#1844). Only an explicit granting-server NAK
			// forces immediate abandon; off-server NAKs never match.
			if errors.Is(rerr, errDHCPNAK) {
				slog.Warn("DHCPv4: REBINDING NAK — lease revoked, deconfiguring and restarting DISCOVER",
					"interface", ifaceName)
				m.abandonLeaseAfterNAK(key, committed)
				committed = nil
				break // outer loop → fresh DORA from INIT
			}
			slog.Warn("DHCPv4: T2 rebind failed, lease will expire, re-acquiring",
				"interface", ifaceName, "err", rerr)
			break // fall back to a fresh DORA
		}
	}
}

// errDHCPNAK is returned (wrapped) by doDHCPv4 when the granting server
// answers a RENEWING/REBINDING DHCPREQUEST with a DHCPNAK. It is a sentinel so
// the run loop can distinguish an explicit lease REVOCATION (RFC 2131 §4.4.5:
// stop using the address immediately and return to INIT) from a renew TIMEOUT
// (which still falls through to the T2 rebind). The discriminator is
// errors.Is(err, errDHCPNAK); see runDHCPv4 (#3956). A NAK from any other
// server is rejected by v4RenewMatcher and never reaches this branch.
var errDHCPNAK = errors.New("DHCPv4 granting server sent NAK")

// abandonLeaseAfterNAK deconfigures the interface and drops the lease record
// after a DHCPNAK revoked the lease (RFC 2131 §4.4.5). The client must stop
// using the address immediately and return to INIT — it must NOT wait for T2.
// This mirrors finishClient's removal ordering (the established
// lease-record-removal owner): remove the kernel address, delete the lease
// record under m.mu, then fire the gateway-change hook OUTSIDE m.mu so the
// ip-monitoring overlay withdraws its resolved next-hop in lock-step with the
// address (#1844 coupling rule).
// Callers hold no lock. committed may be nil (nothing to remove).
func (m *Manager) abandonLeaseAfterNAK(key clientKey, committed *Lease) {
	if committed != nil && committed.Address.IsValid() {
		m.removeAddress(key.iface, committed)
	}
	m.mu.Lock()
	delete(m.leases, key)
	m.mu.Unlock()
	m.fireGatewayChange()
	// #4874 A2: withdraw the FRR default/classless routes in lock-step with
	// the address. onGatewayChange only nudges the ip-monitoring overlay; the
	// base DHCP default route is re-rendered by applyConfig (recompile) from
	// Leases(), so scheduling the recompile covers the route, not just the
	// kernel address.
	m.scheduleRecompile()
}

// doDHCPv4 performs a single DHCPv4 exchange for the given mode:
// exchangeAcquire runs a full DORA; exchangeRenew sends a unicast
// RENEWING DHCPREQUEST to the server that granted prev; exchangeRebind
// sends a broadcast REBINDING DHCPREQUEST (#2994). prev is the currently
// committed lease (nil only for acquire).
func (m *Manager) doDHCPv4(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease) (*Lease, error) {
	if mode != exchangeAcquire {
		if prev == nil {
			return nil, fmt.Errorf("DHCPv4 %s without a prior lease", mode)
		}
		if !leaseInterfaceMatches(ifaceName, prev) {
			return nil, fmt.Errorf("DHCPv4 %s lease belongs to interface %q, not %q",
				mode, prev.Interface, ifaceName)
		}
	}
	client, err := nclient4.New(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("create DHCPv4 client: %w", err)
	}
	defer client.Close()

	// Use a timeout context for the exchange
	exCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Build modifiers from per-interface DHCPv4 options
	var mods []dhcpv4.Modifier
	m.mu.Lock()
	opts := m.v4opts[ifaceName]
	m.mu.Unlock()
	if opts != nil && opts.LeaseTime > 0 {
		mods = append(mods, dhcpv4.WithLeaseTime(uint32(opts.LeaseTime)))
	}

	var ack *dhcpv4.DHCPv4
	switch mode {
	case exchangeRenew, exchangeRebind:
		if prev == nil || !prev.Address.IsValid() {
			return nil, fmt.Errorf("DHCPv4 renew without a prior lease")
		}
		rebind := mode == exchangeRebind
		req, err := buildV4RenewRequest(client.InterfaceAddr(), prev, mods)
		if err != nil {
			return nil, fmt.Errorf("DHCPv4 build renew request: %w", err)
		}
		dest := v4RenewDest(prev, rebind)
		resp, err := client.SendAndRead(exCtx, dest, req,
			v4RenewMatcher(m, req, prev, rebind))
		if err != nil {
			return nil, fmt.Errorf("DHCPv4 %s: %w", mode, err)
		}
		if resp.MessageType() == dhcpv4.MessageTypeNak {
			// A granting-server NAK is kept distinct from an ACK so the
			// run loop can revoke the lease and return to INIT. A NAK from
			// any other server never reaches this branch: v4RenewMatcher
			// rejects it before SendAndRead returns.
			return nil, fmt.Errorf("DHCPv4 %s: %w", mode, errDHCPNAK)
		}
		ack = resp
	default:
		dhcpLease, err := client.Request(exCtx, mods...)
		if err != nil {
			return nil, fmt.Errorf("DHCPv4 request: %w", err)
		}
		ack = dhcpLease.ACK
	}

	return leaseFromACKv4(ifaceName, ack)
}

// leaseFromACKv4 parses a DHCPv4 ACK into a Lease, capturing the
// server-identifier needed to unicast a later RENEW (#2994). Shared by
// the acquire, renew, and rebind paths.
func leaseFromACKv4(ifaceName string, ack *dhcpv4.DHCPv4) (*Lease, error) {
	yourIP := ack.YourIPAddr
	if yourIP == nil || yourIP.IsUnspecified() {
		return nil, fmt.Errorf("no IP in DHCP ACK")
	}

	// Subnet mask
	mask := ack.SubnetMask()
	if mask == nil {
		mask = net.CIDRMask(24, 32) // fallback
	}
	ones, bits := net.IPMask(mask).Size()

	// Reject a degenerate subnet mask (untrusted input). net.IPMask.Size()
	// returns ones=0 for a zero mask (0.0.0.0 → /0) and (0,0) for a
	// non-contiguous mask (e.g. 255.255.0.255). Either would make the lease
	// YourIP/0 and cause the kernel to install an on-link 0.0.0.0/0 connected
	// route on this interface — blackholing/hijacking ALL IPv4 forwarding
	// until the lease is replaced. A rogue or broken server can force this
	// with a single crafted ACK, so refuse the lease rather than commit it.
	// leaseFromACKv4's error propagates through v4Exchange → runDHCPv4, which
	// retries a fresh DISCOVER (acquire) or falls through to T2/expiry keeping
	// the existing valid lease (renew/rebind) — no YourIP/0 is ever installed.
	// RFC 2131 requires option 1 to carry a valid subnet mask.
	if bits != 32 || ones == 0 {
		return nil, fmt.Errorf(
			"DHCP ACK has invalid subnet mask %v on %s — refusing lease (would blackhole IPv4)",
			net.IP(mask), ifaceName)
	}

	addr, ok := netip.AddrFromSlice(yourIP.To4())
	if !ok {
		return nil, fmt.Errorf("invalid IP in DHCP ACK: %v", yourIP)
	}

	lease := &Lease{
		Interface: ifaceName,
		Family:    AFInet,
		Address:   netip.PrefixFrom(addr, ones),
		Obtained:  time.Now(),
	}

	// Server identifier — the unicast destination for the next RENEW.
	if sid := ack.ServerIdentifier(); sid != nil {
		if s, ok := netip.AddrFromSlice(sid.To4()); ok {
			lease.serverID = s
		}
	}

	// RFC 3442 classless static routes (option 121, or the legacy
	// Microsoft option 249). When either is present it SUPERSEDES the
	// option-3 Router option: RFC 3442 requires the client to ignore
	// option 3 entirely and install the option-121 routes instead. The
	// 0.0.0.0/0 entry (if any) is the option-121 way to express the
	// default gateway and populates lease.Gateway (so every existing
	// gateway consumer — FRR default route, neighbor resolution,
	// ip-monitoring next-hop — keeps working); more-specific routes are
	// held on the lease and programmed/withdrawn alongside it. Only when
	// option 121/249 is absent do we fall back to option 3.
	if classless, defGW, present := classlessStaticRoutes(ack); present {
		lease.ClasslessRoutes = classless
		if defGW.IsValid() {
			lease.Gateway = defGW
		}
	} else {
		// Gateway (option 3) — honored only when option 121/249 is absent.
		routers := ack.Router()
		if len(routers) > 0 {
			if gw, ok := netip.AddrFromSlice(routers[0].To4()); ok {
				lease.Gateway = gw
			}
		}
	}

	// DNS
	dnsServers := ack.DNS()
	for _, dns := range dnsServers {
		if a, ok := netip.AddrFromSlice(dns.To4()); ok {
			lease.DNS = append(lease.DNS, a)
		}
	}

	// Lease time
	lt := ack.IPAddressLeaseTime(3600 * time.Second) // default 1 hour
	lease.LeaseTime = lt

	return lease, nil
}

// classlessStaticRoutes parses RFC 3442 classless static routes from a
// DHCPv4 ACK. It prefers option 121 (the standard code) and falls back to
// the legacy Microsoft option 249 — both share the identical
// {mask-length, significant-prefix-octets, gateway} wire encoding, so the
// same dhcpv4.Routes decoder handles either.
//
// It returns the non-default routes separately from the default-route
// gateway (the 0.0.0.0/0 entry, if the server included one). present is
// true whenever either option was found — per RFC 3442 the caller MUST
// then IGNORE the option-3 Router option, even if the option carried no
// 0.0.0.0/0 entry (in which case defaultGW is the zero Addr and no default
// route is installed — the server's explicit choice). A malformed entry
// (bad mask, short buffer) is skipped rather than failing the whole lease.
func classlessStaticRoutes(ack *dhcpv4.DHCPv4) (routes []LeaseRoute, defaultGW netip.Addr, present bool) {
	// #6756: PRESENCE is whether the server RETURNED the option, not whether it
	// parsed. RFC 3442 is explicit — "If the DHCP server returns both a Classless
	// Static Routes option and a Router option, the DHCP client MUST ignore the
	// Router option" — and it conditions that on the option being RETURNED. A
	// zero-length or malformed option 121/249 is still returned.
	//
	// Deriving presence from len(parsedRoutes) != 0 collapsed three distinct
	// cases — absent, present-but-empty, present-but-unparseable — into one
	// false, so the caller fell through to option 3 in exactly the situations
	// the RFC forbids it. A server that means "no default route via option 3"
	// and emits a malformed 121 got the router honoured anyway.
	//
	// Read the raw option slots directly. gopacket-style accessors cannot
	// express "present but unusable": ClasslessStaticRoute() maps any per-entry
	// error to nil, and the option-249 branch below discards its parse error.
	_, has121 := ack.Options[uint8(dhcpv4.OptionClasslessStaticRoute)]
	_, has249 := ack.Options[249]
	present = has121 || has249

	libRoutes := ack.ClasslessStaticRoute() // option 121
	if len(libRoutes) == 0 {
		// Legacy option 249 (Microsoft), identical RFC 3442 encoding.
		if raw := ack.Options.Get(dhcpv4.GenericOptionCode(249)); len(raw) > 0 {
			var r dhcpv4.Routes
			if err := r.FromBytes(raw); err != nil {
				// #6756: previously discarded silently. The option is still
				// PRESENT, so option 3 stays suppressed either way — but an
				// operator whose default route vanished deserves to know the
				// server sent something unparseable rather than nothing.
				slog.Warn("dhcp: classless-static-route option 249 is malformed; ignoring its contents (option 3 stays suppressed per RFC 3442)",
					"err", err, "len", len(raw))
			} else {
				libRoutes = r
			}
		}
	}
	if !present {
		return nil, netip.Addr{}, false
	}
	if len(libRoutes) == 0 {
		// Present but yielding nothing usable. Return present=true so the caller
		// does NOT fall back to option 3.
		slog.Warn("dhcp: classless-static-route option present but yielded no usable routes; option 3 (router) is suppressed per RFC 3442",
			"option_121", has121, "option_249", has249)
		return nil, netip.Addr{}, true
	}
	for _, lr := range libRoutes {
		if lr == nil || lr.Dest == nil {
			continue
		}
		ones, bits := lr.Dest.Mask.Size()
		if bits != 32 {
			continue // not an IPv4 mask; RFC 3442 is IPv4-only
		}
		gw, ok := netip.AddrFromSlice(lr.Router.To4())
		if !ok {
			continue
		}
		dst, ok := netip.AddrFromSlice(lr.Dest.IP.To4())
		if !ok {
			continue
		}
		if ones == 0 {
			// Default-route entry — supplies lease.Gateway (RFC 3442's way
			// to express the default gateway). First one wins, matching the
			// single-gateway model of the option-3 path (routers[0]).
			if !defaultGW.IsValid() {
				defaultGW = gw
			}
			continue
		}
		routes = append(routes, LeaseRoute{
			Destination: netip.PrefixFrom(dst, ones).Masked(),
			Gateway:     gw,
		})
	}
	return routes, defaultGW, present
}
