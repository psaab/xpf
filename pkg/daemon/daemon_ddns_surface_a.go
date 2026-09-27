package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
)

// daemon_ddns_surface_a.go: the Surface A (router/interface-address) DDNS
// reconcile loop + the address-observation layer + the per-RG HA gate (#2691
// P2, plan §5.3/§5.5/§5.6).
//
// This MIRRORS the Surface B lease loop (daemon_ddns.go): an always-on guarded
// background goroutine, 30s cadence + nudge, per-pass context timeout. It does
// NETLINK + DHCP-client-lease reads + DNS network only — it NEVER touches the
// userspace-helper control socket (the CLAUDE.md rule), so it cannot starve
// session installs or status polls.
//
// The engine itself lives in pkg/ddns (SurfaceAManager). This file supplies the
// three daemon-owned seams the engine cannot reach into: the SCOPE LIST (from
// the committed per-interface bindings + the provider catalog), the ADDRESS
// OBSERVER (netlink / pkg/dhcp.LeaseFor), and the per-RG HA GATE
// (snapshotRethMasterState). Keeping these out of pkg/ddns is the same
// dependency-inversion the LeaseParser seam uses for Surface B.

const (
	// surfaceAReconcileInterval is the Surface A poll cadence. Like the lease
	// loop it is far above the 1/s control-socket throttle (which it never
	// touches). Address changes are immediate via the nudge channel (the #1844
	// DHCP gateway/address-change hook + commit + MASTER takeover).
	surfaceAReconcileInterval = 30 * time.Second
	// surfaceAReconcileTimeout bounds one whole Surface A reconcile pass.
	surfaceAReconcileTimeout = 60 * time.Second
	// surfaceACheckIPTimeout bounds a single external check-IP fetch (#2691 P3,
	// opt-in behind-NAT source). Well under the per-pass timeout so a slow
	// checkip endpoint fails one scope, not the whole pass.
	surfaceACheckIPTimeout = 10 * time.Second
)

// surfaceAState groups the always-on Surface A (router/interface-address) DDNS
// state — increment 5 of the #4407 Daemon god-struct decomposition. Pure field
// grouping, no behavior/locking change: every field keeps its exact type and
// its access contract, reached as d.surfaceA.<field>. It is a NAMED sub-field
// (not an embed) like increments 1–4: every access site is bounded to this file
// (the reconcile-loop owner) plus the construct/gate sites in daemon_run.go, so
// the explicit d.surfaceA. qualifier is clearer than field promotion. It is a
// value field of the never-copied *Daemon, so the atomic.Bool / sync.Map
// members are safe (never copied after first use). The DHCP-lease Surface B
// manager (d.ddns*) stays flat — a different DDNS mechanism.
type surfaceAState struct {
	// mgr is the Surface A manager (#2691 P2). It publishes THIS firewall's own
	// learned interface addresses (DHCP-lease / static / netlink) as configured
	// FQDNs through the `system services dynamic-dns` provider catalog, reusing
	// the pkg/ddns spine (the same Backend, record, ScopeKey, durable-state
	// primitives). Constructed unconditionally so a binding removal always has a
	// running loop to withdraw; the loop is netlink + DNS-network only (no
	// control socket), gated to the RG-MASTER per scope, nudged on commit + the
	// #1844 DHCP gateway/address-change hook + MASTER transition. nil when the
	// dataplane is disabled (NoDataplane).
	mgr *ddns.SurfaceAManager
	// reconcileNowCh / reconcileInFlight mirror the ddns* pair: a depth-1 nudge
	// channel + a no-freeze skip-if-in-flight guard.
	reconcileNowCh    chan struct{}
	reconcileInFlight atomic.Bool
	// checkIPAllowlistWarned dedups the once-per-(provider,allowlist) runtime log
	// emitted when ddns.ParseAllowlistChecked drops a malformed checkip-allowlist
	// token (#2839). The observer runs per poll-tick, so the drop must not log
	// every tick. Keyed by "<provider>\x00<allowlist-string>" so a corrected
	// commit re-arms the warning.
	checkIPAllowlistWarned sync.Map
	// checkIPSourceBindWarned dedups the once-per-(provider,bind-error) runtime
	// log emitted when the checkip probe fails CLOSED because the provider's
	// configured source-address failed to parse (#3733). That parse failure is
	// the ONLY bind-resolution error CheckIPClient returns; a dead
	// destination-interface / VRF surfaces later as a dial error inside CheckIP
	// (already ok=false), not here. The observer runs per poll-tick, so a
	// persistent misconfig must not log every tick. Keyed by
	// "<provider>\x00<bind-error>" so a corrected commit re-arms the warning.
	checkIPSourceBindWarned sync.Map
	// checkIPProbeWarned dedups the once-per-(provider,probe-error) runtime log
	// emitted when the checkip probe itself FAILS — a malformed checkip-url, an
	// unreachable/refused endpoint, a non-2xx status, or a redirect the shared
	// policy refuses (a cross-host Location, #6545). Before this the failure
	// collapsed into a bare ok=false with NO log line, so a permanently
	// misconfigured checkip-url was an indistinguishable "transient observation
	// failure" forever (the #2773/#3737 class). Distinct from the ordinary
	// dual-stack miss (endpoint answered, no address of this family), which
	// stays silent. Keyed by "<provider>\x00<probe-error>" so a corrected
	// commit — or a different failure — re-arms the warning.
	//
	// SECURITY: the probe error is both LOGGED and used as this map's KEY, so
	// every error pkg/ddns can return on the checkip path must already be
	// credential-free — a checkip-url routinely carries an API key in its query,
	// its PATH, its userinfo or its fragment. pkg/ddns holds that end up:
	// validateCheckIPURL prints NO part of the URL (it does NOT rely on
	// config.RedactURL, which has known holes — #6609), every URL-bearing error
	// renders through scrubURLError, which emits at most scheme://host, and the
	// redirect refusals name only hostnames. The invariant is gated in
	// pkg/ddns/url_render_class_6545_test.go. Never build this key (or any log
	// attr) from a raw provider URL.
	checkIPProbeWarned sync.Map
	// checkIPNoURLWarned dedups the once-per-provider runtime log emitted when a
	// binding selects `address-source checkip` but the referenced provider
	// carries no checkip-url (#4423 H08). Before the fix the runtime silently
	// fell back to the interface address (publishing the WRONG address); now the
	// source stays checkip and the observer skips (fail-closed) while surfacing
	// this WARN once per provider so the operator sees why nothing publishes.
	// Keyed by the provider name so a corrected commit (url added) re-arms it.
	checkIPNoURLWarned sync.Map
}

// runSurfaceADDNSReconcileLoop is the supervised Surface A reconcile loop. It
// runs for the daemon's lifetime (joined via wg) and exits on ctx cancel.
func (d *Daemon) runSurfaceADDNSReconcileLoop(ctx context.Context) {
	if d.surfaceA.mgr == nil {
		return
	}
	// Immediate first pass so a restart re-publishes / withdraws without
	// waiting a full tick (the durable store + current addresses drive it).
	d.runGuardedSurfaceADDNSReconcile(ctx)

	ticker := time.NewTicker(surfaceAReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.runGuardedSurfaceADDNSReconcile(ctx)
		case <-d.surfaceA.reconcileNowCh:
			d.runGuardedSurfaceADDNSReconcile(ctx)
		}
	}
}

// runGuardedSurfaceADDNSReconcile dispatches one pass into a guarded goroutine
// (skip-if-in-flight), mirroring the lease loop — a hung DNS server leaks at
// most one goroutine and the loop keeps servicing ctx + the nudge channel.
func (d *Daemon) runGuardedSurfaceADDNSReconcile(ctx context.Context) {
	if d.surfaceA.mgr == nil {
		return
	}
	d.ddnsResetMu.Lock()
	defer d.ddnsResetMu.Unlock()
	if d.isResetting() {
		return
	}
	if !d.surfaceA.reconcileInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.surfaceA.reconcileInFlight.Store(false)
		d.reconcileSurfaceAOnce(ctx)
	}()
}

// reconcileSurfaceAOnce runs one Surface A reconcile pass under the node-level
// HA writer gate fast-path (the same one the lease loop uses). When the gate is
// CLOSED (BACKUP for all RGs) the node STOPS writing entirely — but it does NOT
// withdraw valid records (the peer MASTER owns them and keeps them fresh; a
// withdraw would blackhole, plan §5.6). The per-scope gate below makes the
// publish decision PER RG so a node MASTER for one RG and BACKUP for another
// publishes only its own RG's records.
func (d *Daemon) reconcileSurfaceAOnce(ctx context.Context) {
	if d.surfaceA.mgr == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.ddnsWriterGateOpen() {
		slog.Debug("ddns surface-a: skipping reconcile — node is not MASTER for any RG")
		return
	}
	scopes, _ := d.buildSurfaceAScopes(cfg)
	rctx, cancel := context.WithTimeout(ctx, surfaceAReconcileTimeout)
	defer cancel()
	observe := d.surfaceAObserver(cfg)
	gate := d.surfaceAGate()
	// The provider catalog lets the engine REBUILD the publish backend to
	// withdraw a removed-binding record (#2691 P2 MAJOR-2) — the owned record
	// carries only the provider NAME (scope.PolicyID), so the live credentials/
	// server come from the still-committed catalog.
	var catalog map[string]*config.DDNSProvider
	if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		catalog = cfg.System.Services.DynamicDNS.Providers
	}
	// #5070: thread the SSOT Junos→kernel interface-name resolver so a
	// per-binding destination-interface resolves to the local node's real kernel
	// device (reth→member, unit-0 collapse, unit≠vlan-id) before SO_BINDTODEVICE.
	if err := d.surfaceA.mgr.Reconcile(rctx, scopes, observe, gate, catalog, cfg.ResolveKernelIfName); err != nil {
		slog.Warn("ddns surface-a: reconcile pass had errors (retrying next cycle)", "err", err)
	}
}

// buildSurfaceAScopes walks the committed interfaces and materializes one
// ddns.SurfaceAScope per per-interface per-family `dynamic-dns` binding (#2691
// P2, plan §5.9). It resolves the referenced provider-catalog entry, applies a
// per-binding source-address override, and attributes the scope to its owning
// redundancy group (so the per-RG HA gate keys on it).
//
// A binding with no hostname, no provider, or an unresolved provider can build
// no scope (it cannot publish), but it does NOT vanish: it is returned in the
// second result as a synthesized `invalid` status row (#4423 M09) so a broken
// binding stays visible in `show system services dynamic-dns` instead of being
// silently omitted (the commit warning was previously its only trace).
//
// The returned scope slice is sorted by a deterministic key (#4423 M12) so the
// reconcile order — and any behavior that depends on it, e.g. two scopes that
// target the same FQDN — is reproducible rather than Go-map-iteration-random.
func (d *Daemon) buildSurfaceAScopes(cfg *config.Config) ([]ddns.SurfaceAScope, []ddns.SurfaceAStatusView) {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil, nil
	}
	var catalog map[string]*config.DDNSProvider
	var forced, backoff time.Duration
	if cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		dd := cfg.System.Services.DynamicDNS
		catalog = dd.Providers
		// #8642: assessed — plain seconds ints behind a `> 0` guard, so the
		// family applies. Out-of-range falls back to the caller's existing
		// default rather than clamping.
		if d := config.SecondsToDuration(dd.ForcedRefreshSeconds, 0); d > 0 {
			forced = d
		}
		if d := config.SecondsToDuration(dd.ErrorBackoffMaxSeconds, 0); d > 0 { // #8642
			backoff = d
		}
	}

	var out []ddns.SurfaceAScope
	var invalid []ddns.SurfaceAStatusView
	noteInvalid := func(ifName string, un int, family ddns.Family, b *config.InterfaceDynamicDNSConfig, reason string) {
		invalid = append(invalid, ddns.SurfaceAStatusView{
			Interface: ifName,
			Unit:      un,
			Family:    int(family),
			FQDN:      b.Hostname,
			Provider:  b.Provider,
			State:     ddns.SurfaceAStateInvalid,
			LastError: reason,
		})
	}
	add := func(ifName string, ifc *config.InterfaceConfig, un int, family ddns.Family, b *config.InterfaceDynamicDNSConfig) {
		if b == nil {
			return
		}
		if b.Hostname == "" || b.Provider == "" {
			// #4423 M09: structurally incomplete — no scope can be built, but keep
			// the binding visible on the status surface (do not silently drop it).
			switch {
			case b.Hostname == "" && b.Provider == "":
				noteInvalid(ifName, un, family, b, "binding has no hostname and no provider set; nothing will be published")
			case b.Hostname == "":
				noteInvalid(ifName, un, family, b, "binding has no hostname set; nothing will be published")
			default:
				noteInvalid(ifName, un, family, b, "binding has no provider set; nothing will be published")
			}
			return
		}
		prov, ok := catalog[b.Provider]
		if !ok || prov == nil {
			slog.Debug("ddns surface-a: binding references undefined provider; skipping",
				"iface", ifName, "unit", un, "family", int(family), "provider", b.Provider)
			// #4423 M09: surface the undefined-provider binding instead of omitting it.
			noteInvalid(ifName, un, family, b, fmt.Sprintf(
				"references undefined provider %q (define it under system services dynamic-dns provider)", b.Provider))
			return
		}
		// A per-binding source-address overrides the provider's default.
		p := *prov
		if b.SourceAddress != "" {
			p.SourceAddress = b.SourceAddress
		}
		src := ddns.AddressSourceInterface
		switch b.AddressSource {
		case string(ddns.AddressSourceDHCP):
			src = ddns.AddressSourceDHCP
		case string(ddns.AddressSourceCheckIP):
			// #4423 H08: the operator EXPLICITLY selected the checkip source. Honor
			// that selection even when the provider carries no checkip-url — do NOT
			// silently fall back to the interface address. The interface address is
			// exactly what a behind-NAT / multi-WAN deployment must NOT publish (it
			// is the private or wrong-WAN address, not the checkip-discovered public
			// IP). With the source kept as checkip, the observer's missing-url guard
			// returns a TRANSIENT observation (ok=false): the scope is skipped (no
			// publish, never a withdraw) and surfaces as pending rather than
			// publishing the wrong address. The observer logs the missing-url
			// condition once per provider, and the commit-time validator warns too
			// (validateSurfaceADDNSWarnings).
			src = ddns.AddressSourceCheckIP
		}
		ttl := b.TTLSeconds
		key := ddns.ScopeKey{
			Family:          family,
			Interface:       ifName,
			Unit:            un,
			RoutingInstance: prov.RoutingInstance,
			RGOwner:         ifc.RedundancyGroup,
			PolicyID:        b.Provider,
			// The published NAME is part of the Surface A scope identity (#2903):
			// changing the configured hostname is a NEW scope (old name withdrawn,
			// new name published) rather than an in-place overwrite that orphans the
			// old RR. The scope's FQDN must equal SurfaceAScope.FQDN below.
			FQDN: b.Hostname,
		}
		out = append(out, ddns.SurfaceAScope{
			Key:             key,
			FQDN:            b.Hostname,
			TTL:             ttl,
			Source:          src,
			Provider:        &p,
			ForcedRefresh:   forced,
			ErrorBackoffMax: backoff,
		})
	}

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for un, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			add(ifName, ifc, un, ddns.FamilyV4, unit.DynamicDNSInet)
			add(ifName, ifc, un, ddns.FamilyV6, unit.DynamicDNSInet6)
		}
	}
	// #4423 M12: the interface/unit walk above iterates a Go map, so `out` arrives
	// in a random order. Reconcile processes scopes in slice order, and where two
	// scopes publish the SAME FQDN the processing order decides which address ends
	// up live at the provider — a nondeterministic winner. Sort by a total key so
	// the reconcile order (and its logs/tests) is reproducible.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Key, out[j].Key
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		if a.Unit != b.Unit {
			return a.Unit < b.Unit
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.PolicyID != b.PolicyID {
			return a.PolicyID < b.PolicyID
		}
		return a.FQDN < b.FQDN
	})
	return out, invalid
}

// surfaceAObserver builds the AddressObserver for one reconcile pass (plan
// §5.3). It observes a scope's CURRENT address per its configured source:
//
//   - dhcp:      pkg/dhcp.Manager.LeaseFor(linuxIfName, af) — the authoritative
//     learned WAN address (fed by the #1844 gateway-change hook as a nudge).
//   - interface: netlink address on the bound interface/unit/family, falling
//     back to the configured static address — covers static + DHCP-applied +
//     PD-derived + reth/VIP addresses.
//
// ok=false (returned by the engine's contract) means "could not observe this
// cycle" (transient) — the engine then leaves the scope untouched (no withdraw
// on a transient, the never-blackhole rule). A valid-but-Invalid Addr means
// "definitively no address" (interface down / lease gone) — the engine
// withdraws.
func (d *Daemon) surfaceAObserver(cfg *config.Config) ddns.AddressObserver {
	return func(ctx context.Context, scope ddns.SurfaceAScope) (ddns.AddressObservation, bool) {
		ifName := scope.Key.Interface
		un := scope.Key.Unit
		af4 := scope.Key.Family == ddns.FamilyV4
		var unit *config.InterfaceUnit
		if ifc, ok := cfg.Interfaces.Interfaces[ifName]; ok && ifc != nil {
			unit = ifc.Units[un]
		}
		linuxName := surfaceALinuxIfName(cfg, ifName, unit)

		switch scope.Source {
		case ddns.AddressSourceCheckIP:
			// Opt-in external check-IP source (behind-NAT deployments, #2691 P3).
			// The provider carries the checkip-url + (optionally) a bogus-IP
			// allowlist. A fetch failure is a TRANSIENT observation failure
			// (ok=false) — never a withdraw.
			if scope.Provider == nil || scope.Provider.CheckIPURL == "" {
				// #4423 H08: the operator selected `address-source checkip` but the
				// provider has no checkip-url, so there is nothing to probe. FAIL
				// CLOSED (transient ok=false) — do NOT publish the interface address
				// (that silent fallback published the WRONG address). Surface it once
				// per provider so the running daemon shows why nothing publishes (the
				// commit validator also warns). Skip the log when Provider is nil (an
				// unresolved provider is already covered by the invalid-binding row).
				if scope.Provider != nil {
					if _, dup := d.surfaceA.checkIPNoURLWarned.LoadOrStore(scope.Provider.Name, struct{}{}); !dup {
						slog.Warn("ddns surface-a: address-source checkip selected but provider has no "+
							"checkip-url; skipping (fail-closed, NOT falling back to the interface address)",
							"provider", scope.Provider.Name, "fqdn", scope.FQDN)
					}
				}
				return ddns.AddressObservation{}, false
			}
			// Bound the single probe by surfaceACheckIPTimeout BUT derive it from
			// the reconcile ctx, not context.Background() (#3736): a daemon
			// shutdown / pass-deadline cancel now aborts an in-flight checkip
			// promptly instead of hanging up to the full 10s. The engine already
			// runs this observer with the manager mutex released, so a slow probe
			// no longer blocks StatusViews/Stats/other scopes either.
			ctx, cancel := context.WithTimeout(ctx, surfaceACheckIPTimeout)
			defer cancel()
			allow, badAllow := ddns.ParseAllowlistChecked(scope.Provider.CheckIPAllowlist)
			if len(badAllow) > 0 {
				// A malformed checkip-allowlist token (operator typo) is dropped so
				// the valid entries still gate, but a silent drop shrinks the bogus-IP
				// safety gate (#2839). The commit-time warning already named the token;
				// log once per (provider, allowlist-string) so the running daemon also
				// surfaces it without flooding the per-tick observer.
				key := scope.Provider.Name + "\x00" + scope.Provider.CheckIPAllowlist
				if _, dup := d.surfaceA.checkIPAllowlistWarned.LoadOrStore(key, struct{}{}); !dup {
					slog.Warn("ddns surface-a: ignoring malformed checkip-allowlist token(s); "+
						"bogus-IP allowlist is smaller than configured",
						"provider", scope.Provider.Name, "tokens", badAllow)
				}
			}
			// Bind the checkip probe to the provider's configured source-address /
			// interface / VRF (#2846) so it egresses from the same source as the
			// DDNS updates — not the kernel default route. Reuse the manager's
			// cached per-binding HTTP client (#2904) so the recurring checkip probe
			// shares the keep-alive connection pool with the DNS-update path instead
			// of rebuilding a transport every reconcile pass.
			client, berr := d.surfaceA.mgr.CheckIPClient(scope.Provider)
			if berr != nil {
				// FAIL-CLOSED (#3733): berr means the provider's configured
				// source-address failed to parse (netip.ParseAddr) — it is the
				// ONLY bind-resolution error CheckIPClient returns. A dead
				// destination-interface / VRF does NOT surface here; that becomes
				// a DIAL error inside CheckIPBound → CheckIP, already ok=false. So
				// berr specifically = a malformed configured source-address the
				// bind could not honor. checkip is an address oracle — falling back
				// to the kernel default route would egress via a DIFFERENT WAN and
				// return the WRONG WAN's public IP, republishing the wrong-WAN
				// class #2846 closed. CheckIPBound (below) refuses to probe when
				// berr != nil and returns ok=false: a TRANSIENT observation (no
				// publish, never a withdraw). Log once per (provider, bind-error)
				// so a persistent misconfig surfaces without flooding the per-tick
				// observer.
				key := scope.Provider.Name + "\x00" + berr.Error()
				if _, dup := d.surfaceA.checkIPSourceBindWarned.LoadOrStore(key, struct{}{}); !dup {
					slog.Warn("ddns surface-a: checkip source bind unusable; "+
						"skipping probe (fail-closed, not falling back to default route)",
						"provider", scope.Provider.Name, "err", berr)
				}
			}
			a, ok, cerr := ddns.CheckIPBound(ctx, client, scope.Provider.CheckIPURL, af4, allow, berr)
			if !ok {
				// A probe FAILURE (cerr != nil) is not the same thing as "the
				// endpoint answered but carried no address of this family"
				// (cerr == nil — the ordinary dual-stack miss, correctly
				// silent). Several failure causes are PERMANENT configuration
				// errors: a malformed checkip-url, an endpoint that 30x's to a
				// DIFFERENT host (refused since #6545), a checkip-url whose
				// host no longer resolves. Collapsing those into a bare
				// ok=false made them indistinguishable, undiagnosable, forever
				// "transient" observation failures with no operator-visible
				// signal at all — the class #2773/#3737 were filed to
				// eliminate, and the publish path already surfaces the same
				// causes by name. Log once per (provider, error) so a
				// persistent misconfig surfaces without flooding the per-tick
				// observer, matching checkIPSourceBindWarned above. berr is
				// skipped here because that branch has already logged it with
				// its own (more specific, fail-closed) message.
				if cerr != nil && berr == nil {
					key := scope.Provider.Name + "\x00" + cerr.Error()
					if _, dup := d.surfaceA.checkIPProbeWarned.LoadOrStore(key, struct{}{}); !dup {
						slog.Warn("ddns surface-a: checkip probe failed; no address observed "+
							"(publishing is suppressed until it succeeds)",
							"provider", scope.Provider.Name, "err", cerr)
					}
				}
				return ddns.AddressObservation{}, false
			}
			return ddns.AddressObservation{Addr: a, Source: ddns.AddressSourceCheckIP}, true

		case ddns.AddressSourceDHCP:
			if d.dhcp == nil {
				return ddns.AddressObservation{}, false
			}
			af := dhcp.AFInet
			if !af4 {
				af = dhcp.AFInet6
			}
			lease := d.dhcp.LeaseFor(linuxName, af)
			if lease == nil {
				// #4423 M10: distinguish a TRANSIENT manager gap from a definitive
				// loss. When the unit is STILL DHCP-configured for this family, a
				// missing lease is a bring-up / renewal / client-RESTART gap — the DHCP
				// manager stops and restarts the client on any option change
				// (dhcp.Manager.Reconcile), removing the address and deleting the lease
				// for the whole DORA re-acquire window. Treating that as a definitive
				// loss WITHDRAWS the public record on every benign DHCP option change
				// and re-publishes seconds later — a blackhole flap. Treat it as a
				// TRANSIENT observation (ok=false): leave the scope untouched (never
				// withdraw on transient — the never-blackhole rule). Only when the unit
				// is no longer DHCP-configured for this family (interface reconfigured
				// away from DHCP) is the absence definitive → withdraw. Reading the
				// committed config flag is race-free (unlike probing the live client
				// registry, which has a stop→start window during a restart).
				// Shared with the #6555 `interface`-source guard via
				// unitRunsDHCPForFamily: the two sources ask the SAME question, and
				// a divergence between them would always be a bug.
				dhcpConfigured := unitRunsDHCPForFamily(unit, af4)
				if dhcpConfigured {
					return ddns.AddressObservation{}, false
				}
				// No lease and the unit no longer runs DHCP for this family:
				// definitively no address. Withdraw any previously-published record.
				return ddns.AddressObservation{Source: ddns.AddressSourceDHCP}, true
			}
			a := lease.Address.Addr().Unmap()
			if !a.IsValid() {
				return ddns.AddressObservation{Source: ddns.AddressSourceDHCP}, true
			}
			// Public-address gate (#3732): a DHCP-learned WAN address is NOT
			// guaranteed globally routable. CGNAT (100.64/10), RFC1918, ULA
			// (fc00::/7), documentation, and other IANA special-purpose ranges
			// are all legitimately handed out over DHCP. Publishing one to a
			// public DNS provider leaks internal addressing AND points the
			// A/AAAA record at an unroutable address. The interface
			// (selectInterfaceAddr), static (staticUnitAddr), and checkip
			// (parseCheckIPBody) sources all apply this SAME ddns.IsPublicAddr
			// gate — the DHCP source was the one Surface A source that skipped
			// it. A non-public lease is a DEFINITIVE "no publishable address of
			// this family" (matching the interface source's non-public
			// handling), so the engine WITHDRAWS any previously-published
			// record rather than leaving a stale public one — never publish a
			// non-public address, never blackhole.
			if !ddns.IsPublicAddr(a) {
				slog.Warn("surface-a: skipping non-public dhcp lease address",
					"address", a.String(), "interface", linuxName)
				return ddns.AddressObservation{Source: ddns.AddressSourceDHCP}, true
			}
			return ddns.AddressObservation{Addr: a, Source: ddns.AddressSourceDHCP}, true

		default: // interface
			a, ok := d.observeInterfaceAddr(linuxName, af4, unit)
			if !ok {
				// netlink read failed (transient): leave the scope untouched.
				return ddns.AddressObservation{}, false
			}
			return ddns.AddressObservation{Addr: a, Source: ddns.AddressSourceInterface}, true
		}
	}
}

// surfaceALinuxIfName maps a configured interface/unit to the kernel device
// name the address lives on. RETH names resolve to the local physical member;
// the unit's VLAN id appends a ".<vlan>" sub-interface suffix (the same
// derivation pkg/dhcp keys its leases on, DHCPLeaseIfName).
func surfaceALinuxIfName(cfg *config.Config, ifName string, unit *config.InterfaceUnit) string {
	resolved := ifName
	if cfg != nil {
		resolved = cfg.ResolveReth(ifName)
	}
	return config.DHCPLeaseIfName(resolved, unit)
}

// netlinkLinkByName and netlinkAddrList are the netlink read seams for
// observeInterfaceAddr. They are package vars so tests can inject a synthetic
// link/address list (and a read FAILURE) without touching the real kernel
// netlink socket — the same dependency-inversion pattern #2294/#2775 use.
var (
	netlinkLinkByName = netlink.LinkByName
	netlinkAddrList   = netlink.AddrList
)

// observeInterfaceAddr reads the current publishable address of the given family
// on a kernel interface via netlink (selection policy in selectInterfaceAddr:
// prefer an RFC 4862 preferred address over a deprecated one, never a
// tentative/dadfailed/optimistic one, public-gated via ddns.IsPublicAddr).
//
// Contract (the engine relies on the (addr, ok) distinction, plan §5.3):
//
//   - (addr, true)  — a definitive observation. A valid addr publishes it; an
//     invalid/zero addr means "definitively no address of this family"
//     (interface present but addressless and no usable static) → the engine
//     WITHDRAWS any previously-published record.
//   - (zero, false) — the interface could NOT be read this cycle (a transient
//     LinkByName / AddrList netlink failure: interface absent during a rename,
//     reth/HA churn, a netlink hiccup), OR the family has NO address at all on a
//     unit the committed config still runs DHCP for (#6555 — the DHCP client's
//     stop/restart flush window). The engine leaves the scope UNTOUCHED
//     (no publish, no withdraw; retry next pass) — the never-blackhole rule.
//
// The configured static address is a fallback ONLY on the present-but-addressless
// path (the legitimate static-use case: a successful read returned no usable
// dynamic address). It is NEVER returned on a link-READ error — publishing a
// configured static when we could not read the interface at all would point DNS
// at a "configured" address that may not be "active" in the kernel data plane
// (the #2840 transient-vs-definitive distinction). On a read error we cannot
// tell present-but-addressless from absent, so the only safe answer is the
// transient (zero, false).
func (d *Daemon) observeInterfaceAddr(linuxName string, af4 bool, unit *config.InterfaceUnit) (netip.Addr, bool) {
	link, err := netlinkLinkByName(linuxName)
	if err != nil {
		// Link read failed (interface absent during a rename / reth churn /
		// netlink hiccup): we cannot distinguish present-but-addressless from
		// genuinely-down, so this is a TRANSIENT observation. Do NOT publish the
		// configured static here — return (zero, false) so the engine leaves the
		// scope untouched and retries next pass (#2840).
		return netip.Addr{}, false
	}
	family := netlink.FAMILY_V4
	if !af4 {
		family = netlink.FAMILY_V6
	}
	addrs, err := netlinkAddrList(link, family)
	if err != nil {
		// Address read failed for an otherwise-present link: still transient
		// (we did not get a definitive address list). Leave the scope untouched
		// rather than fall back to the static (#2840).
		return netip.Addr{}, false
	}
	if best, ok := selectInterfaceAddr(addrs, af4); ok {
		return best, true
	}
	// Interface read SUCCEEDED but yielded no usable dynamic address: this is the
	// legitimate present-but-addressless case. Fall back to a configured static
	// address (still gated through ddns.IsPublicAddr in staticUnitAddr).
	if a, ok := staticUnitAddr(unit, af4); ok {
		return a, true
	}
	// #6555: the unit is STILL DHCP-configured for this family and the kernel
	// reports NO address of that family at all — that is the DHCP client's
	// stop/restart flush window, not a definitive loss. The DHCP manager stops
	// and restarts the client on any option change (dhcp.Manager.Reconcile),
	// and finishClient removes the leased address for the whole DORA re-acquire
	// window; the removal then fires onDHCPAddressChange -> a Surface A nudge
	// about 2s later, landing a pass squarely INSIDE that window. Treating it as
	// definitive WITHDRAWS the public A/AAAA record on every benign DHCP option
	// change and republishes seconds later — an externally-visible blackhole
	// flap on the DEFAULT address source, from routine operation with no
	// attacker.
	//
	// This is the same guard the `dhcp` source already carries (#4423 M10,
	// surfaceAObserver's dhcp arm): both read the COMMITTED config flag rather
	// than probing the live client registry, which has a stop->start window of
	// its own and would race the very restart being detected. Returning
	// (zero, false) marks the observation TRANSIENT: the engine leaves the scope
	// untouched and retries — never withdraw on transient.
	//
	// Deliberately gated on len(addrs) == 0, NOT on "selectInterfaceAddr found
	// nothing usable". Those are different states, and only the first is the
	// restart window. If the family HAS an address that was rejected as
	// non-public/tentative/deprecated, the observation stays DEFINITIVE exactly
	// as it is today — which also matches the dhcp source, where a non-public
	// lease is a definitive withdraw rather than a transient. Widening this to
	// the rejected-candidate case would be a separate behaviour choice about
	// CGNAT/tentative addresses, not this fix.
	if len(addrs) == 0 && unitRunsDHCPForFamily(unit, af4) {
		return netip.Addr{}, false
	}
	// Interface is up but has no address of this family and no usable static:
	// definitively none → the engine withdraws.
	return netip.Addr{}, true
}

// unitRunsDHCPForFamily reports whether the COMMITTED config still has this unit
// running a DHCP client for the requested family. It is the shared predicate
// behind both #4423 M10 (the `dhcp` address source) and #6555 (the `interface`
// source): a missing address/lease means "transient, retry" while this is true
// and "definitive, withdraw" once the unit has been reconfigured away from DHCP.
//
// Reading the committed flag is race-free in a way that probing the live client
// registry is not — the registry has a stop->start gap during exactly the
// restart these callers must not mistake for a loss.
func unitRunsDHCPForFamily(unit *config.InterfaceUnit, af4 bool) bool {
	if unit == nil {
		return false
	}
	if af4 {
		return unit.DHCP
	}
	return unit.DHCPv6
}

// selectInterfaceAddr chooses the address to publish from a kernel interface's
// netlink address list for the requested family. It is the pure (no-netlink-I/O)
// core of observeInterfaceAddr so the selection policy can be exercised
// directly with synthetic IFA_F_* flag combinations.
//
// Selection policy (RFC 4862 address states + the Surface A publishability gate):
//
//   - NEVER select an address whose DAD has not succeeded:
//     IFA_F_TENTATIVE (DAD in progress), IFA_F_DADFAILED (duplicate detected),
//     or IFA_F_OPTIMISTIC (RFC 4429 optimistic DAD — usable for some traffic but
//     not yet DAD-confirmed, so not safe to publish to global DNS). Publishing
//     one risks a duplicate/black-holed answer.
//   - NEVER select an RFC 4941/8981 SLAAC privacy/temporary address
//     (IFA_F_TEMPORARY, #2975). It is an outbound-only ephemeral identifier that
//     rotates on a short timer; publishing it leaks the privacy identifier and
//     black-holes inbound reachability when it rotates. The stable permanent
//     address (which privacy extensions keep for inbound service) is preferred.
//   - NEVER select a non-globally-meaningful address (loopback / link-local
//     uni+multicast / multicast / unspecified, AND every IANA special-purpose
//     range) — the SAME ddns.IsPublicAddr gate the static fallback (#2776) and
//     the checkip source use. A preferred-but-ULA address is still rejected.
//   - PREFER an RFC 4862 `preferred` address over a `deprecated` one
//     (IFA_F_DEPRECATED). A deprecated address is being phased out (renumber /
//     PD churn / privacy-address rotation) and will soon become invalid, so
//     publishing it black-holes inbound reachability. The first eligible
//     preferred address wins; a deprecated address is remembered only as a
//     fallback used IFF no preferred address exists (never blackhole — a
//     deprecated-but-still-valid address is better than no answer).
//
// netlink returns a stable order, so "first eligible" is deterministic.
func selectInterfaceAddr(addrs []netlink.Addr, af4 bool) (netip.Addr, bool) {
	deprecated := netip.Addr{}
	for _, ad := range addrs {
		ip, ok := netip.AddrFromSlice(ad.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if af4 != ip.Is4() {
			continue
		}
		// Skip addresses whose DAD has not succeeded — they may be duplicate or
		// not yet usable. tentative/dadfailed/optimistic are never publishable.
		//
		// Also skip RFC 4941/8981 SLAAC privacy/temporary addresses
		// (IFA_F_TEMPORARY, #2975). A temporary address is an outbound-only
		// ephemeral identifier that rotates on a short timer; publishing one to
		// public DNS leaks the privacy identifier AND black-holes inbound
		// reachability as soon as it rotates (the record points at an address
		// that no longer exists). The stable permanent address on the same
		// interface — which privacy extensions are designed to KEEP for inbound
		// service — is the correct publication target.
		if ad.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED|unix.IFA_F_OPTIMISTIC|unix.IFA_F_TEMPORARY) != 0 {
			continue
		}
		// Globally-routable-unicast gate (#2776): reject link-local, loopback,
		// unspecified, multicast, ULA, CGNAT, documentation, and every other
		// IANA special-purpose range. A preferred-but-ULA address is rejected.
		if !ddns.IsPublicAddr(ip) {
			continue
		}
		if ad.Flags&unix.IFA_F_DEPRECATED != 0 {
			// Remember the first deprecated candidate as a no-blackhole fallback.
			if !deprecated.IsValid() {
				deprecated = ip
			}
			continue
		}
		// First eligible preferred address wins.
		return ip, true
	}
	if deprecated.IsValid() {
		return deprecated, true
	}
	return netip.Addr{}, false
}

// staticUnitAddr returns the first configured static address of the given
// family on a unit (CIDR → bare addr), if any.
//
// The candidate is gated through ddns.IsPublicAddr (#2776), the SAME
// globally-routable-unicast predicate the netlink and checkip address sources
// use. Without this gate the fallback applied only a loopback/link-local/
// unspecified filter and could publish a multicast, ULA, CGNAT, documentation,
// or otherwise-reserved configured address as the router's A/AAAA record when
// the kernel interface is absent/addressless. A mis-scoped static address is
// skipped and surfaced at WARN rather than silently published (never-blackhole:
// a bad static address must not masquerade as a usable answer).
func staticUnitAddr(unit *config.InterfaceUnit, af4 bool) (netip.Addr, bool) {
	if unit == nil {
		return netip.Addr{}, false
	}
	for _, cidr := range unit.Addresses {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		a := p.Addr().Unmap()
		if a.Is4() != af4 {
			continue
		}
		if !ddns.IsPublicAddr(a) {
			slog.Warn("surface-a: skipping non-public static address",
				"address", a.String(), "cidr", cidr)
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}

// surfaceAGate builds the per-RG HA writer gate for one reconcile pass (#2664,
// plan §5.6). It REUSES the same per-RG master snapshot the lease loop uses. A
// scope on an RG-owned (reth) interface is writable IFF this node is MASTER for
// that RG. An RG 0 scope (a non-HA interface) is bound to RG0 — the
// control-plane redundancy group — so exactly the RG0-primary node publishes it
// (#2972). Standalone (no cluster) returns nil so the engine admits every scope.
//
// Why RG0/non-HA scopes need their own gate (#2972): unlike DHCP-lease DDNS
// (where each node's Kea memfile is rendered master-filtered per RG, so the two
// nodes' lease input sets are disjoint), Surface A scopes are built directly
// from the active config + the interface observer. BOTH nodes build the
// IDENTICAL RG0 scope. The node-level writer gate (ddnsWriterGateOpen) opens on
// ANY-RG mastership, so in active-active HA (node0 masters RG1, node1 masters
// RG2) BOTH nodes pass it AND — before this fix — both admitted every RGOwner==0
// scope, double-writing the same configured FQDN. If the two nodes observe
// different WAN addresses the public A/AAAA record flaps. Tying RGOwner==0 to
// RG0 ownership yields a single writer that follows RG0 failover.
func (d *Daemon) surfaceAGate() ddns.ScopeGate {
	if d.cluster == nil {
		return nil
	}
	master := d.snapshotRethMasterState()
	rg0Writer := d.surfaceARG0Writer(master)
	return func(s ddns.ScopeKey) bool {
		if s.RGOwner == 0 {
			return rg0Writer
		}
		return master[s.RGOwner]
	}
}

// surfaceARG0Writer reports whether THIS node is the single writer for
// RG0/non-HA Surface A scopes in a cluster (#2972). RG0 is the control-plane
// redundancy group (the config-authority group, daemon_ha.go RG0 handling):
// exactly one node is RG0 primary at any time, so binding the non-HA scopes to
// RG0 ownership gives a deterministic single writer that follows RG0 failover.
//
//   - RG0 tracked (the standard cluster, RG0 configured): the per-RG master
//     snapshot is authoritative — admit IFF this node masters RG0.
//   - RG0 NOT tracked (a non-standard cluster with only data RGs, or the brief
//     window before the first RG0 election settles): master[0] is absent. Fall
//     back to a deterministic single writer — the lowest node ID (node 0) — so
//     the non-HA scopes are still written by exactly one node and never
//     double-written. (A standalone node returns nil from surfaceAGate and never
//     reaches here.)
func (d *Daemon) surfaceARG0Writer(master map[int]bool) bool {
	if d.cluster == nil {
		return true
	}
	if isMaster, tracked := master[0]; tracked {
		return isMaster
	}
	return d.cluster.NodeID() == 0
}

// nudgeSurfaceADDNSReconcile requests an immediate Surface A reconcile pass
// (config commit / DHCP address change / MASTER takeover). Non-blocking depth-1
// send: coalesces a burst into one pending wakeup.
func (d *Daemon) nudgeSurfaceADDNSReconcile() {
	if d.surfaceA.reconcileNowCh == nil {
		return
	}
	select {
	case d.surfaceA.reconcileNowCh <- struct{}{}:
	default:
	}
}

// ForceDDNSUpdate is the operator force-now verb (#3276, the daemon half of
// `request system dynamic-dns update`). When force is true it arms the Surface A
// force-now latch (re-assert every owned scope's wire record on the next pass,
// bypassing change-detection + the forced-refresh floor) and nudges an immediate
// reconcile; when force is false it only nudges a re-observe/publish-if-changed
// pass (the `check` verb). Both honor the per-RG HA writer gate via the SAME
// node-level fast path the reconcile loops use: on a node that masters NO RG
// (the backup) it takes NO action and returns ok=false with a clear message, so
// the verb never double-writes from the standby (the RG owner publishes, #2972).
// A standalone node (no cluster) is always the writer. Returns (ok, message)
// for the operator surface.
func (d *Daemon) ForceDDNSUpdate(force bool) (bool, string) {
	if d.surfaceA.mgr == nil && d.ddns == nil {
		return false, "dynamic-dns: DDNS engine not running (dataplane disabled)"
	}
	// Per-RG owner gate (#2972): only a node that masters at least one RG may
	// publish. The backup must not re-assert records the peer master owns — that
	// would double-write the same FQDN (and flap the public record if the two
	// nodes observe different addresses). The per-scope gate inside Reconcile
	// further restricts a multi-RG-active node to only its own RGs' scopes.
	if !d.ddnsWriterGateOpen() {
		return false, "dynamic-dns: this node is not the active writer for any " +
			"redundancy group; the redundancy-group owner publishes (no action " +
			"taken on the backup)"
	}
	if force {
		// Arm BOTH engines' force-now latch so the explicit request re-asserts
		// every owned record onto the wire even when content is unchanged: Surface
		// A router records AND Surface B DHCP-lease records (#5710 M37 — the DHCP
		// surface was previously only re-observed, so an unchanged DHCP record was
		// never re-published and a drifted/deleted wire RR could not be repaired).
		if d.surfaceA.mgr != nil {
			d.surfaceA.mgr.ForceRefresh()
		}
		if d.ddns != nil {
			d.ddns.ForceRefresh()
		}
	}
	// Nudge both DDNS reconcile loops immediately (Surface A router records and
	// the DHCP-lease Surface B path) so the forced/checked pass runs now rather
	// than waiting for the next 30s tick.
	d.nudgeSurfaceADDNSReconcile()
	d.nudgeDDNSReconcile()
	if force {
		return true, "dynamic-dns: forced an immediate update of all DDNS " +
			"records owned by this node"
	}
	return true, "dynamic-dns: triggered an immediate DDNS check on this node " +
		"(publishes only changed records)"
}

// SurfaceAStats returns the Surface A counter snapshot for the API collector /
// show command, or nil when the manager is not constructed (NoDataplane).
func (d *Daemon) SurfaceAStats() *ddns.SurfaceAStats {
	if d.surfaceA.mgr == nil {
		return nil
	}
	st := d.surfaceA.mgr.Stats()
	return &st
}

// SurfaceAStatus returns the per-scope last-published views for `show` (the
// operator surface, plan §5.5). Empty when the manager is absent.
func (d *Daemon) SurfaceAStatus() []ddns.SurfaceAStatusView {
	if d.surfaceA.mgr == nil {
		return nil
	}
	// Materialize the CURRENTLY configured scopes so the status surfaces every
	// configured scope — including ones that never published or are erroring —
	// not just the durably-owned ones (#2843). A nil cfg yields only the
	// withdraw-pending (orphaned-ownership) rows.
	var scopes []ddns.SurfaceAScope
	var invalid []ddns.SurfaceAStatusView
	if cfg := d.store.ActiveConfig(); cfg != nil {
		scopes, invalid = d.buildSurfaceAScopes(cfg)
	}
	views := d.surfaceA.mgr.StatusViews(scopes)
	if len(invalid) > 0 {
		// #4423 M09: fold the structurally-invalid bindings (no hostname / no
		// provider / undefined provider) into the operator status so a broken
		// binding stays visible. They build no scope, so the engine's StatusViews
		// never sees them. Re-sort the combined set with the SAME total-order
		// comparator the engine uses so the output stays byte-stable (#4423 M11).
		views = append(views, invalid...)
		ddns.SortSurfaceAStatusViews(views)
	}
	return views
}
