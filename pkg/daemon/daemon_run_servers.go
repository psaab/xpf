package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/grpcapi"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/sysservices"
	"github.com/psaab/xpf/pkg/webmgmt"
)

// effectiveListeners builds the daemon-owned snapshot of the EFFECTIVE
// management-listener STATE `show system services` reports (#6385/#6401). BOTH
// renderers — the remote gRPC path (Config.ListenersFn) and the local console
// CLI (SetListenersFn) — read this ONE method, so the two surfaces can never
// disagree (the divergence that dropped the #6384 A10-b2-F5 attempt).
//
//   - gRPC: the primary gRPC listener's state (EffectiveListener) — Listening
//     with the actual bound address, Failed on a bind failure / serve exit, or
//     Listening on the requested --grpc-addr in the brief pre-bind window.
//     Before the server is even constructed, report the requested address as
//     Listening (pre-bind).
//   - HTTP REST: the reconciler's state (effectiveHTTPListener) — Listening with
//     the actual bound address, Failed on a boot bind failure, or Disabled when
//     the reconciler is absent (empty --api-addr, listener never started).
func (d *Daemon) effectiveListeners() sysservices.Listeners {
	var ls sysservices.Listeners
	if d.grpcSrv != nil {
		ls.GRPC = d.grpcSrv.EffectiveListener()
	} else {
		// Server not yet constructed — the pre-bind startup window. gRPC always
		// binds on loopback, so report the requested address as Listening.
		ls.GRPC = sysservices.Listener{Addr: d.opts.GRPCAddr, State: sysservices.StateListening}
	}
	ls.HTTP = d.mgmt.Load().effectiveHTTPListener()
	ls.HTTPS = d.mgmt.Load().effectiveHTTPSListener()
	return ls
}

// #5054/#5961: transport commit-wiring seams.
//
// The gRPC, HTTP/REST, and local-shell commit handlers must ALL route an
// operator commit through commitAndApplyOperator / commitConfirmedAndApplyOperator
// so the peer-sync decision is derived from RG0 ownership
// (rg0ConfigSyncAuthority) and is transport-independent — the #5054 invariant.
// Before #5054 only gRPC synced the peer; a REST/shell commit left the standby
// on stale config.
//
// These closures were inlined at each transport's construction site, so no test
// could exercise the wiring: reverting one transport back to
// commitAndApply(ctx, comment, peerSyncNever) left every test green (#5961). They are
// extracted here as three named per-transport seams — one method pair per
// transport — so each transport's wiring is independently reachable from a test
// and independently fail-on-revert covered (configsync_transport_5054_test.go).
// They are intentionally identical: the whole point of #5054 is that every
// transport resolves peer-sync the same way; keeping a distinct named seam per
// transport is what lets a single-transport regression turn a single test case
// RED instead of staying silent.

func (d *Daemon) grpcCommitFn() func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
	return func(ctx context.Context, authority configstore.CommitAuthority, comment string) (*config.Config, error) {
		return d.commitAndApplyOperator(ctx, authority, comment)
	}
}

func (d *Daemon) grpcCommitConfirmedFn() func(context.Context, configstore.CommitAuthority, int) (*config.Config, error) {
	return func(ctx context.Context, authority configstore.CommitAuthority, minutes int) (*config.Config, error) {
		return d.commitConfirmedAndApplyOperator(ctx, authority, minutes)
	}
}

func (d *Daemon) restCommitFn() func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
	return func(ctx context.Context, authority configstore.CommitAuthority, comment string) (*config.Config, error) {
		return d.commitAndApplyOperator(ctx, authority, comment)
	}
}

func (d *Daemon) restCommitConfirmedFn() func(context.Context, configstore.CommitAuthority, int) (*config.Config, error) {
	return func(ctx context.Context, authority configstore.CommitAuthority, minutes int) (*config.Config, error) {
		return d.commitConfirmedAndApplyOperator(ctx, authority, minutes)
	}
}

// shellCommitFn is the in-process shell CLI's commit seam. The local shell
// carries no config-lock session id, so it commits as an EXPLICIT internal
// committer (#6808) rather than by omitting the authority — "this caller has no
// holder" must be a written statement, not a zero value.
func (d *Daemon) shellCommitFn() func(context.Context, string) (*config.Config, error) {
	return func(ctx context.Context, comment string) (*config.Config, error) {
		return d.commitAndApplyOperator(ctx, configstore.InternalCommitter(), comment)
	}
}

func (d *Daemon) shellCommitConfirmedFn() func(context.Context, int) (*config.Config, error) {
	return func(ctx context.Context, minutes int) (*config.Config, error) {
		return d.commitConfirmedAndApplyOperator(ctx, configstore.InternalCommitter(), minutes)
	}
}

// grpcRunErrIsFatal reports whether an error from grpcapi Server.Run must END
// the daemon rather than be logged and survived (#8233).
//
// Named rather than inlined at the call site so it can be bound by a test: an
// `errors.Is` buried in a goroutine can be deleted without changing anything a
// test observes, and the condition it selects for is the whole point of #8233.
//
// Only the management-port-held case. Every other Run error stays non-fatal,
// which is the pre-#8233 behaviour and is correct for the faults the listener
// supervisor exists to ride out.
func grpcRunErrIsFatal(err error) bool {
	return errors.Is(err, grpcapi.ErrManagementPortHeld)
}

// startGRPCServer constructs and launches the gRPC API server goroutine.
// Extracted verbatim from Run()'s PHASE 5 (#4662 Increment 2); the leaf
// startup block carries no ordering dependency (same code, same call point).
func (d *Daemon) startGRPCServer(ctx context.Context, wg *sync.WaitGroup, eventBuf *logging.EventBuffer, fwdSampler *fwdstatus.Sampler) {
	// #2114 (r4): wire the LIVE indirection, not a startup snapshot of the
	// published backend. grpcapi.Server keeps its Config.DP for the daemon's
	// lifetime (pkg/grpcapi/server.go NewServer), so handing it the interface
	// value here made every later setDataplane(nil) invisible to gRPC — the
	// server kept dispatching `show`/`clear` into a backend the daemon had
	// disowned. liveDataPlane re-reads the cell per call (daemon_dp_live.go).
	// It satisfies the local grpcDataPlane probe (runtime_probes.go) —
	// structurally identical to pkg/grpcapi's package-private grpcRuntime
	// (pkg/grpcapi/runtime.go, #1516/#1554). Go duck-types the assignment to
	// grpcapi.Config.DP at this site; signature drift surfaces as a compile
	// error here and at the daemon_dp_live.go assertions.
	var grpcDP grpcDataPlane
	if live, ok := d.liveDataplane(); ok {
		grpcDP = live
	}
	grpcSrv := grpcapi.NewServer(d.opts.GRPCAddr, grpcapi.Config{
		Store:      d.store,
		DP:         grpcDP,
		EventBuf:   eventBuf,
		GC:         d.gc,
		Routing:    d.routing,
		FRR:        d.frr,
		IPsec:      d.ipsec,
		Cluster:    d.cluster,
		DHCP:       d.dhcp,
		DHCPServer: d.dhcpServer,
		// #6495: the #1930 kernel-channel state for `show system
		// kernel-upgrade`. Same assembly the in-process CLI reads
		// (daemon_run.go SetKernelUpgradeStatusFn).
		KernelUpgradeStatusFn: d.kernelUpgradeStatus,
		// #6496: the day-0 config-import verdict for `show system
		// bootstrap-import`. Same recorded snapshot /health reports below and
		// the in-process CLI reads (daemon_run.go SetBootstrapImportFn), so
		// the three surfaces cannot disagree about whether a day-0 config
		// applied. Unlike /health this path renders b.Error: it is
		// authenticated, and the failure REASON is the entire point of the
		// command (#5031 withholds it from /health because that endpoint is
		// unauthenticated, which is a different question from privilege).
		BootstrapImportFn: d.bootstrapShowSnapshot,
		// #7181: the APPLIED state of the host-inbound nft surface, so `show
		// security zones` reports what the kernel enforces rather than only what
		// the config asks for.
		HostInboundAppliedFn: func() grpcapi.HostInboundApplied {
			st := d.HostInboundApplied()
			return grpcapi.HostInboundApplied{
				Known:           true,
				Established:     st.Established,
				Generation:      st.Generation,
				LastApplyFailed: st.LastApplyFailed,
				GapFenceActive:  st.GapFenceActive,
			}
		},
		RPMResultsFn: func() []*rpm.ProbeResult {
			if d.rpm != nil {
				return d.rpm.Results()
			}
			return nil
		},
		IPMonStatusFn: func() []ipmon.PolicyStatus {
			if d.ipmon != nil {
				return d.ipmon.Status()
			}
			return nil
		},
		// #2079: active NAT pool-utilization alarms for
		// `show security alarms`.
		NATPoolAlarmsFn: d.natPoolAlarms,
		FeedsFn: func() map[string]feeds.FeedInfo {
			if d.feeds != nil {
				return d.feeds.AllFeeds()
			}
			return nil
		},
		// #3042: live feed-prefix overlay so the gRPC MatchPolicies
		// simulator resolves feed-backed address-names to their live
		// CIDRs, matching what the AF_XDP helper enforces.
		FeedOverlayFn: func() map[string][]string {
			return d.feedSnapshotsForConfig(d.store.ActiveConfig())
		},
		LLDPNeighborsFn: func() []*lldp.Neighbor {
			if d.lldpMgr != nil {
				return d.lldpMgr.Neighbors()
			}
			return nil
		},
		// #1387 inc-2: DHCP dynamic-DNS status sources for the
		// `show ... dhcp-server dynamic-dns` ShowText topics.
		DDNSStatsFn:          d.DDNSStats,
		SurfaceADDNSStatsFn:  d.SurfaceAStats,
		SurfaceADDNSStatusFn: d.SurfaceAStatus,
		SurfaceADDNSForceFn:  d.ForceDDNSUpdate,
		DDNSOwnedRecordsFn:   d.OwnedDDNSRecords,
		// #2464: per-collector NetFlow v9 / IPFIX write-health for
		// `show services flow-monitoring statistics`.
		FlowCollectorHealthFn: d.FlowCollectorHealth,
		// gRPC commits sync to the cluster peer atomically inside
		// the apply lock so the peer can never observe an apply
		// that hasn't yet been propagated. #5054: the RG0-ownership
		// peer-sync decision now lives in commitAndApplyOperator,
		// shared with the REST and local-shell commit paths so every
		// transport converges identically. Wiring lives in the
		// grpcCommitFn / grpcCommitConfirmedFn seams so it is
		// fail-on-revert covered (#5961).
		CommitFn:          d.grpcCommitFn(),
		CommitConfirmedFn: d.grpcCommitConfirmedFn(),
		// #5281: a gRPC zeroize runs the wipe under the SAME apply gate as
		// commit/sync and enters a terminal reset generation so no concurrent
		// or later config writer re-creates the erased state before the daemon
		// stops. The grpcapi handler passes its performZeroizeWipe primitive.
		ZeroizeFn: d.factoryReset,
		VRRPMgr:   d.vrrpMgr,
		RAMgr:     d.ra,
		Version:   d.opts.Version,
		FabricPeerAddrFn: func() []string {
			var addrs []string
			if d.syncPeerAddr != "" {
				addrs = append(addrs, d.syncPeerAddr)
			} else {
				d.fabricMu.RLock()
				if d.fabricPeerIP != nil {
					addrs = append(addrs, d.fabricPeerIP.String())
				}
				d.fabricMu.RUnlock()
			}
			if d.syncPeerAddr1 != "" {
				addrs = append(addrs, d.syncPeerAddr1)
			} else {
				d.fabricMu.RLock()
				if d.fabricPeerIP1 != nil {
					addrs = append(addrs, d.fabricPeerIP1.String())
				}
				d.fabricMu.RUnlock()
			}
			return addrs
		},
		FabricVRFDevice: func() string {
			if c := d.store.ActiveConfig(); c != nil && c.Chassis.Cluster != nil {
				cc := c.Chassis.Cluster
				if cc.ControlInterface != "" || cc.FabricInterface != "" {
					return config.ManagementVRFDeviceName
				}
			}
			return ""
		}(),
		FwdSampler: fwdSampler,
		// #6385: the remote gRPC `show system services` renderer reports the
		// EFFECTIVE post-bind listener addresses from this daemon-owned snapshot,
		// the SAME source the local console CLI reads (shell.SetListenersFn), so
		// the two surfaces can never diverge.
		ListenersFn: d.effectiveListeners,
	})
	d.grpcSrv = grpcSrv
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := grpcSrv.Run(ctx); err != nil {
			slog.Error("gRPC server error", "err", err)
			// #8233: a management port held by another xpfd is not a fault to
			// log and survive. Running on means a second daemon writing to the
			// same host and the same epoch files with every gRPC-driven surface
			// dead and no external signal (#8195). Everything else Run can
			// return stays non-fatal, exactly as before.
			if grpcRunErrIsFatal(err) {
				d.signalFatal(err)
			}
		}
	}()
	slog.Info("gRPC API server started", "addr", d.opts.GRPCAddr)
}

// startHTTPServer constructs and launches the HTTP REST API server goroutine
// (bind-interface resolution, TLS, API auth, and loopback clamping). Extracted
// verbatim from Run()'s PHASE 5 (#4662 Increment 3); a leaf startup block with
// no ordering dependency (same code, same call point, still guarded by the
// d.opts.APIAddr check in Run).
func (d *Daemon) startHTTPServer(ctx context.Context, wg *sync.WaitGroup, eventBuf *logging.EventBuffer) {
	apiCfg := d.apiServerConfig(eventBuf)
	// #5866: the management HTTP/HTTPS listener is owned by
	// managementReconciler. apiCfg here carries only the runtime deps; the
	// reconciler re-derives the bind/port/TLS/auth from each ACTIVE config
	// (resolveAPIBinds) so it can start the listener now AND, on every day-2
	// commit, reconcile the live listener + authentication snapshot without a
	// restart — make-before-break rebind on a bind/port/TLS change, live auth
	// swap on an unchanged bind. Before #5866 the server was constructed once
	// here and never reconciled, so a committed bind/TLS/port/auth change (e.g.
	// a revoked credential) sat inert until a daemon restart.
	// #6719: publish the reconciler ATOMICALLY, and BEFORE start() runs. The
	// readers are already live — startClusterComms is ~190 lines earlier in Run,
	// so a peer sync can reach reconcileWebManagement before this line. The
	// atomic makes that read safe; publishing before start() also means such a
	// reconcile finds a non-nil reconciler and is merely no-opped by the
	// `m.srv == nil` gate rather than dropped at the daemon level — and start()
	// then derives its snapshot from the store UNDER m.mu, so the promotion that
	// reconcile carried is picked up rather than lost. (#6827 round 5 published
	// this under staleCertMu; the atomic supersedes that and covers every
	// reader, not just the stale-cert path.)
	mgmt := newManagementReconciler(d, apiCfg)
	d.mgmt.Store(mgmt)
	if err := mgmt.start(ctx); err != nil {
		// A boot bind failure is non-fatal (matches the pre-#5866 async
		// srv.Run error log): the daemon keeps running and the next commit's
		// reconcileWebManagement retries the bind.
		slog.Error("HTTP API server initial start failed", "err", err)
	}
	// #6827: the boot config apply (startup phase 4) runs BEFORE this
	// constructor, so a `system host-name` applied at boot reached a nil
	// reconciler and parked itself. Deliver it now that an HTTPS leg may be
	// serving — this is the earliest point at which the diagnostic has a real
	// certificate to judge, and the name is still the one the operator set.
	d.deliverStaleMgmtCertDiagnosis()
	// Drain the management serve goroutines on daemon shutdown: ctx cancel
	// triggers the api.Server graceful drain (5s deadline, not a wall-clock
	// bound — see api.legDrainTimeout), and wait() joins every
	// live + retiring listener goroutine so none leak past Run.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		d.mgmt.Load().wait()
	}()
	slog.Info("HTTP API server started", "addr", d.opts.APIAddr)
}

// resolveAPIBinds finalizes the HTTP/HTTPS listen addresses, TLS flag, and
// api-auth on apiCfg from the active web-management config, then applies the
// #4047/#5127 loopback fail-safe clamp. It is split out of startHTTPServer so
// the bind/auth/clamp decision is unit-testable without opening a socket.
//
// cfg is the active config; it may be nil or lack a `system services
// web-management` stanza. The KEY invariant (#5127): the loopback clamp runs
// UNCONDITIONALLY — even when no web-management block exists — because
// apiCfg.Addr defaults to the `--api-addr` flag, which an operator can point
// off-loopback with no web-management stanza at all. Before #5127 the clamp
// lived INSIDE the web-management block, so that flag path bound the mutating
// REST/config API (set / commit / rollback / DHCP / system-action) to the
// network UNAUTHENTICATED, defeating the #4047 fail-safe.
func (d *Daemon) resolveAPIBinds(apiCfg *api.Config, cfg *config.Config) {
	if cfg != nil && cfg.System.Services != nil &&
		cfg.System.Services.WebManagement != nil {
		wm := cfg.System.Services.WebManagement
		// #5715: an explicitly configured `web-management http` binds the
		// canonical Junos J-Web port TCP/80 (webmgmt SSOT — the SAME port the
		// host-inbound `http` service token admits, so the listener and the
		// admission agree), on the configured interface address or loopback.
		// With NO `web-management http` stanza (wm.HTTP false — e.g. an
		// api-auth-only block) apiCfg.Addr is left untouched at the -api-addr
		// default (127.0.0.1:8080), a loopback-only diagnostic path that is never
		// host-inbound-admitted; that path must NOT be silently moved to port 80.
		if wm.HTTP {
			httpBindIP := "127.0.0.1"
			if wm.HTTPInterface != "" {
				httpBindIP = resolveInterfaceAddr(cfg, wm.HTTPInterface, "127.0.0.1")
			}
			// net.JoinHostPort (not string-concat) so an IPv6 interface
			// address is bracketed ("[2001:db8::1]:80") — a bare
			// "2001:db8::1:80" is unparseable by net.SplitHostPort (the
			// clamp below) and net.Listen, blackholing an IPv6-only mgmt bind.
			apiCfg.Addr = net.JoinHostPort(httpBindIP, webmgmt.HTTPPortString())
			slog.Info("HTTP web-management bound", "interface", wm.HTTPInterface, "addr", apiCfg.Addr)
		}
		// Enable HTTPS if configured — bind the canonical TCP/443 (webmgmt SSOT).
		if wm.HTTPS {
			httpsBindIP := "127.0.0.1"
			if wm.HTTPSInterface != "" {
				httpsBindIP = resolveInterfaceAddr(cfg, wm.HTTPSInterface, "127.0.0.1")
			}
			apiCfg.TLS = true
			apiCfg.HTTPSAddr = net.JoinHostPort(httpsBindIP, webmgmt.HTTPSPortString())
			slog.Info("HTTPS web-management bound", "interface", wm.HTTPSInterface, "addr", apiCfg.HTTPSAddr)
		}
		// API authentication
		if wm.APIAuth != nil && (len(wm.APIAuth.Users) > 0 || len(wm.APIAuth.APIKeys) > 0) {
			authCfg := &api.AuthConfig{
				Users:   make(map[string]string),
				APIKeys: make(map[string]bool),
			}
			// #5636: never wire an EMPTY Basic password or empty api-key into
			// the runtime AuthConfig. A quoted-empty secret parses as a real
			// credential row but is not a valid credential — wiring it would let
			// a request presenting `username:` (no password) or an empty
			// Bearer / X-API-Key token authenticate, an auth bypass on an
			// off-loopback bind. The commit gate rejects such a config, but an
			// already-persisted / peer-synced config is lenient-loaded (#1960),
			// so drop the empty credential here too (defense in depth; the
			// middleware also rejects an empty configured secret).
			for _, u := range wm.APIAuth.Users {
				if pw := u.Password.Reveal(); pw != "" {
					authCfg.Users[u.Username] = pw
				}
			}
			for _, k := range wm.APIAuth.APIKeys {
				if key := k.Reveal(); key != "" {
					authCfg.APIKeys[key] = true
				}
			}
			// Only enable auth when at least one USABLE credential survived; an
			// all-empty api-auth stanza leaves apiCfg.Auth nil so the #4047
			// runtime clamp still pulls a non-loopback bind back to loopback.
			if len(authCfg.Users) > 0 || len(authCfg.APIKeys) > 0 {
				apiCfg.Auth = authCfg
				slog.Info("HTTP API authentication enabled", "users", len(authCfg.Users), "api_keys", len(authCfg.APIKeys))
			} else {
				slog.Warn("HTTP API api-auth configured with only empty secrets; ignoring (no valid credential) — #5636")
			}
		}
	}

	// #4047 part B / #5127: runtime fail-safe clamp, applied on EVERY path
	// (whether or not a web-management stanza exists). The commit gate
	// (validateWebManagementAuthStrict, pkg/config) rejects a NEW web-management
	// config that binds the unauthenticated REST/config API off-loopback without
	// api-auth, but an ALREADY-PERSISTED such config is lenient-loaded (warn, no
	// brick — #1960), AND the `--api-addr` flag has no commit gate at all
	// (#5127). Either can bind non-loopback UNAUTHENTICATED, exposing the
	// mutating config endpoints (set / commit / rollback / DHCP / system-action)
	// to the network. clampBindToLoopback is a no-op when the bind is already
	// loopback OR api-auth is configured, so the default 127.0.0.1:8080 path and
	// an authenticated off-loopback web-management bind are unaffected; it only
	// pulls a non-loopback + no-auth bind back to a same-family loopback and
	// WARNs. The daemon still boots and the web API stays reachable on loopback,
	// with the console/SSH the lifeline (device-map §9.6 posture) until the
	// operator adds api-auth (which restores the non-loopback bind).
	hasAuth := apiCfg.Auth != nil
	if clamped, ok := clampBindToLoopback(apiCfg.Addr, hasAuth); ok {
		slog.Warn("HTTP API bind is non-loopback without api-auth; clamping to loopback (add `set system services web-management api-auth` to bind off-loopback) — #4047/#5127",
			"requested", apiCfg.Addr, "clamped", clamped)
		apiCfg.Addr = clamped
	}
	if apiCfg.TLS {
		if clamped, ok := clampBindToLoopback(apiCfg.HTTPSAddr, hasAuth); ok {
			slog.Warn("HTTPS API bind is non-loopback without api-auth; clamping to loopback — #4047/#5127",
				"requested", apiCfg.HTTPSAddr, "clamped", clamped)
			apiCfg.HTTPSAddr = clamped
		}
	}
}

// helperCrashEpisodes reports how many userspace-dataplane helper crash
// episodes this daemon has recovered from, for #8397's
// xpf_dataplane_helper_crash_episodes_total.
//
// Returns 0 when the userspace manager is absent — a daemon with no helper has
// had no helper crashes, and 0 is the honest answer rather than a missing
// series. An absent series reads as healthy to an alert, which is the same
// failure this metric exists to correct.
func (d *Daemon) helperCrashEpisodes() int {
	// Reuses the same adapter assertion the #8121 lease sync uses; the
	// userspace Manager is reachable only through the published dataplane.
	mgr := d.persistentNatLeaseManager()
	if mgr == nil {
		return 0
	}
	_, total := mgr.HelperCrashHistory()
	return total
}

// forwardingSupported reports whether the userspace dataplane is forwarding
// transit, for #8447's xpf_dataplane_forwarding_supported.
//
// Returns TRUE when there is no userspace manager. That is the deliberate
// choice and it is worth stating: this metric answers "has a capability gate
// disarmed forwarding", and a daemon with no userspace manager has no such
// gate. Reporting 0 there would fire the alert on every config-only daemon and
// on every moment before the dataplane is published, which is how a signal
// gets muted.
//
// The metric is omitted entirely when the accessor is not wired (see
// collectForwardingSupported), so "we cannot see" and "forwarding is live"
// stay distinguishable at the surface even though both are true here.
func (d *Daemon) forwardingSupported() bool {
	mgr := d.persistentNatLeaseManager()
	if mgr == nil {
		return true
	}
	return mgr.ForwardingSupported()
}

// apiServerConfig builds the api.Config the HTTP API server runs with. It is its
// own method so TestAPIServerConfigBindsEveryHook_9443 can see every hook
// assignment: while the literal lived inline in startHTTPServer, which no test
// calls, deleting any one hook still compiled and failed no test (#9443). Keep
// every api.Config hook assigned HERE; the test fails on any func field left nil
// that is not a documented injection seam.
func (d *Daemon) apiServerConfig(eventBuf *logging.EventBuffer) api.Config {
	// #2114 (r4): the LIVE indirection, for the same reason as gRPC above —
	// api.Server keeps Config.DP for the daemon's lifetime, so a startup
	// snapshot outlived every setDataplane(nil). liveDataPlane satisfies the
	// local apiDataPlane probe (runtime_probes.go) — structurally identical
	// to pkg/api's package-private apiRuntimeDataPlane. Go duck-types the
	// assignment to api.Config.DP at this site; signature drift surfaces as a
	// compile error here and at the daemon_dp_live.go assertions.
	var apiDP apiDataPlane
	if live, ok := d.liveDataplane(); ok {
		apiDP = live
	}
	return api.Config{
		Addr:     d.opts.APIAddr,
		Store:    d.store,
		DP:       apiDP,
		EventBuf: eventBuf,
		GC:       d.gc,
		Routing:  d.routing,
		FRR:      d.frr,
		IPsec:    d.ipsec,
		DHCP:     d.dhcp,
		VRRPMgr:  d.vrrpMgr,
		// #5054: HTTP/REST commits sync to the peer on the SAME
		// RG0-ownership policy as gRPC/local-shell. Peer convergence
		// is transport-independent (decided in commitAndApplyOperator),
		// so a REST commit no longer leaves the standby on stale config
		// until an unrelated transport-disconnect reverse-sync. Wiring
		// lives in the restCommitFn / restCommitConfirmedFn seams so it
		// is fail-on-revert covered (#5961).
		CommitFn:          d.restCommitFn(),
		CommitConfirmedFn: d.restCommitConfirmedFn(),
		// #758: surface compile state so /health returns 503
		// when the dataplane has never compiled successfully.
		CompileHealthFn: func() api.CompileHealthSnapshot {
			h := d.CompileHealthSnapshot()
			return api.CompileHealthSnapshot{
				EverSucceeded:    h.EverSucceeded,
				FailureCount:     h.FailureCount,
				LastError:        h.LastError,
				LastErrorUnixSec: h.LastErrorUnixSec,
			}
		},
		// #4184: surface the day-0 / bootstrap config-import outcome so a
		// failed import is visible on /health, not just a boot-time WARN.
		// #7181: same applied state on the REST surface.
		HostInboundAppliedFn: func() api.HostInboundAppliedSnapshot {
			st := d.HostInboundApplied()
			snap := api.HostInboundAppliedSnapshot{
				Known:           true,
				Established:     st.Established,
				Generation:      st.Generation,
				LastApplyFailed: st.LastApplyFailed,
				GapFenceActive:  st.GapFenceActive,
			}
			if !st.LastFailureAt.IsZero() {
				snap.LastFailureUnixSec = st.LastFailureAt.Unix()
			}
			return snap
		},
		BootstrapImportFn: func() api.BootstrapImportSnapshot {
			b := d.BootstrapImportSnapshot()
			return api.BootstrapImportSnapshot{
				Status:  b.Status,
				Error:   b.Error,
				UnixSec: b.UnixSec,
				Failed:  b.Failed,
			}
		},
		// #1780 Path A: expose the per-phase age of the Go periodic
		// neighbor-maintenance loop so a wedged guarded goroutine
		// (stuck netlink/probe syscall) is observable as a climbing
		// gauge before it manifests as the cold-connect hang.
		NeighborPhaseAgeFn: d.NeighborPeriodicPhaseAges,
		// #1880: 1 while the last applied FRR reload fell back to
		// the additive vtysh -f path (stale-config removal deferred
		// to the in-manager retry loop).
		FRRReloadDegradedFn: func() bool {
			if d.frr == nil {
				return false
			}
			return d.frr.ReloadDegraded()
		},
		// #6807: how many route-maps the last rendered managed section
		// replaced with a bounded explicit DENY because the policy would
		// overflow FRR's sequence ceiling. Non-zero is an ongoing route
		// WITHDRAWAL on every BGP neighbor carrying such an attachment —
		// FRR denies a route-map name it cannot resolve — and before this
		// the only signal was one slog.Warn at render time, which nothing
		// alerts on.
		FRRQuarantinedRouteMapsFn: func() []string {
			if d.frr == nil {
				return nil
			}
			return d.frr.QuarantinedRouteMaps()
		},
		// #8363: BGP policy-chain attachments filtered by LESS than the
		// operator authored, because a chain member names an undefined
		// policy-statement. Not a withdrawal, so it is its own series rather
		// than part of the quarantine gauge. The DenySafe subset is the shape
		// for which a synthesized deny would be safe (undefined members form a
		// suffix); the complement is the shape where a deny would delete the
		// surviving members outright.
		FRRNarrowedPolicyChainsFn: func() []string {
			if d.frr == nil {
				return nil
			}
			return d.frr.NarrowedPolicyChains()
		},
		FRRNarrowedPolicyChainsDenySafeFn: func() []string {
			if d.frr == nil {
				return nil
			}
			return d.frr.NarrowedPolicyChainsSuffixShape()
		},
		// #7640: NAT rules the tolerant load / peer-sync / rollback path
		// admitted despite the strict terminal-action cardinality gate. Read
		// from the ACTIVE config, so it tracks what the node is actually
		// running and clears the moment a fixed config is committed — an alert
		// that keeps firing after the fix gets muted, and a muted alert is how
		// the next real one is missed.
		NATLenientTerminalActionRulesFn: func() []string {
			if d.store == nil {
				return nil
			}
			cfg := d.store.ActiveConfig()
			if cfg == nil {
				return nil
			}
			out := make([]string, 0, len(cfg.LenientNATTerminalActionRules))
			for _, r := range cfg.LenientNATTerminalActionRules {
				out = append(out, r.String())
			}
			return out
		},
		// #4899: 1 while the last DHCP-lease-change IPsec rebind
		// failed and swanctl local_addrs are still bound to a stale
		// lease address (the retry loop has not reconverged), so the
		// operator sees a tunnel that cannot re-establish instead of a
		// silently-dropped reload error.
		IPsecRebindPendingFn: d.IPsecRebindPending,
		// #6802: surface a FAILED host-inbound conntrack revocation. The
		// failure is fail-open — a now-denied host service stays reachable
		// over its established kernel connection — and before #6802 it left
		// no trace at all, so an operator had no way to see that a service
		// they had just removed was still being served.
		HostInboundConntrackRevocationOwedFn: d.HostInboundConntrackRevocationOwed,
		HostInboundConntrackFlushFailuresFn:  d.HostInboundConntrackFlushFailures,
		// #6800: surface the managed-service reload debt so
		// xpf_managed_service_reload_pending reads 1 (and
		// xpf_managed_service_reload_failures_total climbs) while a service
		// whose configuration file has already converged on disk is still
		// running the PREVIOUS ruleset. Without this the retry owner is
		// invisible: a node can re-drive a failing `systemctl restart rsyslog`
		// for hours while every dashboard shows a firewall that committed
		// cleanly, which is the blindness the retry owner exists to end.
		ManagedServiceReloadOwedFn:     d.ManagedServiceReloadOwed,
		ManagedServiceReloadFailuresFn: d.ManagedServiceReloadFailures,
		// #7615: the remaining debt-driven retry owners on the same surface.
		// An accessor with no production caller leaves the operator exactly as
		// blind as before (#6852), which is why these assignments are pinned by
		// a source-level cell.
		RADeadSenderPendingFn:    d.RADeadSenderPending,
		ProxyARPUnresolvedFn:     d.ProxyARPUnresolved,
		FabricOverlayMissingFn:   d.FabricOverlayMissing,
		ManagementListenerDownFn: d.ManagementListenerDown,
		// #8195: the SAME snapshot `show system services` renders, deliberately
		// — the metric and the CLI must not be able to disagree about a
		// listener's state. It also carries the gRPC leg, which
		// ManagementListenerDownFn above cannot: that reads the HTTP listener
		// only, and the gRPC listener's failure is the one an operator cannot
		// observe by other means, because `show system services` is reached
		// OVER it.
		ManagementListenersFn: d.effectiveListeners,
		// #3780: surface scheduler republish-failure so
		// xpf_scheduler_republish_failed reads 1 (and
		// xpf_scheduler_republish_stale_seconds climbs) while a
		// scheduler window transition's republish has not converged —
		// otherwise stale enforcement past the window is invisible to
		// monitoring.
		SchedulerRepublishFailedFn:       d.SchedulerRepublishFailed,
		HelperCrashEpisodesFn:            d.helperCrashEpisodes,
		ForwardingSupportedFn:            d.forwardingSupported,
		SchedulerRepublishStaleSecondsFn: d.SchedulerRepublishStaleSeconds,
		// #5669: surface the bounded-age fail-closed escalation so
		// xpf_scheduler_republish_fail_closed reads 1 once a persistently
		// failing republish has crossed the bounded age and the scheduler has
		// forced scheduled policies inactive (deny) — a crisp alarm distinct
		// from the climbing stale-seconds age.
		SchedulerRepublishFailClosedFn: d.SchedulerRepublishFailClosed,
		// #1827: ip-monitoring policy state for the xpf_ipmon_*
		// metric family.
		IPMonStatusFn: func() []ipmon.PolicyStatus {
			if d.ipmon != nil {
				return d.ipmon.Status()
			}
			return nil
		},
		// #4423 L: ip-monitoring actuation-failure counter
		// (xpf_ipmon_actuation_failures_total) — surfaces the silent
		// #3757 self-heal retry loop so a degraded failover is visible.
		// #7437: the kernel route-listener pair. See the field doc on
		// Daemon for why both halves are needed to read either.
		RouteListenerMarksFn:       d.RouteListenerMarks,
		RouteListenerRepublishesFn: d.RouteListenerRepublishes,
		IPMonActuationFailuresFn: func() uint64 {
			if d.ipmon != nil {
				return d.ipmon.ActuationFailures()
			}
			return 0
		},
		// #2157: event-options remediation action counters for the
		// xpf_event_actions_* / xpf_event_action_queue_depth family.
		EventActionStatsFn: func() eventengine.Stats {
			if d.eventEngine != nil {
				return d.eventEngine.Stats()
			}
			return eventengine.Stats{}
		},
		// #1895: currently-failed RPM probe-pin installs (tests
		// holding state on ErrProbeSetup instead of probing the
		// default path).
		RPMPinFailedFn: func() float64 {
			if d.rpm != nil {
				return float64(d.rpm.PinInstallFailureCount())
			}
			return 0
		},
		// #1799: surface configstore persist-degraded state so
		// /health returns 503 (and xpf_daemon_config_persist_degraded
		// reads 1) while the running active config is not durable on
		// disk (failed HA sync / auto-rollback persist, retry pending).
		ConfigPersistDegradedFn: d.store.ConfigPersistDegraded,
		// #8321 finding 15: the REST /vrrp handler needs the same
		// per-RG priority source the gRPC surface uses so it can report
		// RETH VRRP instances on a chassis cluster.
		VRRPLocalPrioritiesFn: func() map[int]int {
			if d.cluster == nil {
				return nil
			}
			return d.cluster.LocalPriorities()
		},
		// #3441: surface configstore rollback-history-degraded state so
		// /health reports it (non-fatal) and
		// xpf_config_rollback_persist_degraded reads 1 while the most
		// recent commit failed to durably persist its text rollback
		// files. The active config is durable; this flags a degraded
		// recovery aid, so it does not 503.
		RollbackHistoryDegradedFn: d.store.RollbackHistoryDegraded,
		// #2050: surface dynamic-address feed staleness so the
		// xpf_feed_seconds_since_last_success / xpf_feed_stale gauges
		// read live status. A frozen enforced address set (retain-forever
		// default) is otherwise invisible to monitoring.
		FeedsFn: func() map[string]feeds.FeedInfo {
			if d.feeds != nil {
				return d.feeds.AllFeeds()
			}
			return nil
		},
		// #9165: surface per-collector remote-syslog drop counters. Until
		// this call site existed, all three SyslogClient drop accessors had
		// zero production readers — a counted drop reached an operator only
		// through the package's own rate-limited slog.Warn, and a warning
		// that has been rate-limited away leaves nothing behind. Syslog is
		// where an operator looks after an incident; a dead collector means
		// that record does not exist while `show` still renders it present.
		SyslogDropsFn: d.syslogDropStats,
		// #3042: live feed-prefix overlay so the REST match-policies
		// simulator resolves feed-backed address-names to their live
		// CIDRs, matching what the AF_XDP helper enforces.
		FeedOverlayFn: func() map[string][]string {
			return d.feedSnapshotsForConfig(d.store.ActiveConfig())
		},
		// #3104: live per-scheduler active-state so the REST
		// match-policies simulator skips a scheduler-inactive policy
		// exactly like the runtime, instead of returning a verdict the
		// dataplane disagrees with. Sourced from the same daemon-local
		// accessor the CLI/gRPC show surfaces use
		// (Manager.PolicySchedulerActiveState via the dataplane adapter).
		// ok=false when the dataplane is absent (NoDataplane); the simulator
		// then fails closed and treats scheduled policies as inactive (#3414),
		// matching the dataplane's nil-state behavior rather than certifying
		// an as-if-active verdict it is skipping.
		PolicySchedulerActiveStateFn: func() (map[string]bool, bool) {
			// #2114: one dataplane snapshot per request (plan §5.3
			// rule 7).
			rt := d.dataplane()
			if rt == nil {
				return nil, false
			}
			p, ok := rt.(interface {
				PolicySchedulerActiveState() map[string]bool
			})
			if !ok {
				return nil, false
			}
			return p.PolicySchedulerActiveState(), true
		},
		// #1387 inc-2: DHCP dynamic-DNS counters for the
		// xpf_dhcp_ddns_* metric family. Returns nil when the
		// manager is absent (NoDataplane), omitting the family.
		DDNSStatsFn:     d.DDNSStats,
		SurfaceAStatsFn: d.SurfaceAStats,
		// #2464: per-collector NetFlow v9 / IPFIX write-health for the
		// xpf_flow_export_collector_* family + /services/flow-exporters.
		FlowCollectorHealthFn: d.FlowCollectorHealth,
		// #9166: per-family flow-export BUILD health. The write-health family
		// above is omitted when its slice is empty, which is exactly what a
		// failed build produces — so on its own it reports a dead exporter and
		// an unconfigured box identically.
		FlowExportBuildStateFn: d.FlowExportBuildStates,
		// #3747: per-exporter pending-batch queue depth / high-water /
		// dropped-at-capacity count for the xpf_flow_export_batch_* family.
		FlowExportBatchStatsFn: d.FlowExportBatchStats,
		// #3419 M6: report whether this node is the active cluster member
		// for RG0 so the REST session view's ha_active field matches the
		// gRPC contract (server_sessions.go IsLocalPrimary(0)). Standalone
		// (no cluster) reports active.
		HAActiveFn: func() bool {
			if d.cluster == nil {
				return true
			}
			return d.cluster.IsLocalPrimary(0)
		},
		// #3423 M5: stamp this node's cluster id on the REST session
		// list/summary/clear responses so a dashboard knows WHICH node it
		// observed. Standalone (no cluster) reports node 0.
		NodeIDFn: func() int {
			if d.cluster == nil {
				return 0
			}
			return d.cluster.NodeID()
		},
		// #3423 H5/M5: hand the REST session handlers the live gRPC
		// server, which is HA-aware — its ClearSessions fans out the
		// clear to the cluster peer (clearPeerSessions, x-peer-forwarded
		// recursion guard) and its GetSessions/GetSessionSummary stamp the
		// peer's table when include_peer is set. Resolved lazily so the
		// closure can reference the gRPC server constructed below this
		// block; guarded so a nil server resolves to a nil interface (not
		// a non-nil typed-nil), keeping REST local-only until the gRPC
		// server is up.
		ClusterSessionFn: func() api.ClusterSessionService {
			if d.grpcSrv == nil {
				return nil
			}
			return d.grpcSrv
		},
	}
}
