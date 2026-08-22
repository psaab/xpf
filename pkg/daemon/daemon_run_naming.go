package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// setupInterfaceNaming enumerates and renames the PCI NICs to vSRX-style names
// (fxp0, em0, ge-X-0-Y), sets up the bootstrap lifeline, and applies the #801
// step-0 host tunables — all before any manager creation or dataplane load.
// Extracted verbatim from Run()'s PHASE 2 (#4662 Increment 6); a self-contained
// block with no crossing output, no early return, and no ordering change.
func (d *Daemon) setupInterfaceNaming() {
	// Enumerate PCI NICs and assign vSRX-style names (fxp0, em0, ge-X-0-Y)
	// before any manager creation or BPF load.
	if !d.opts.NoDataplane {
		clusterMode := false
		nodeID := 0
		userspaceWorkers := 0
		// D3 (#797): default enabled. Operators opt out via
		// `set system dataplane rss-indirection disable`.
		rssEnabled := true
		var rssAllowed []string
		// #801 Phase-B Step-0 tunables: host-scope governor + netdev
		// budget; per-iface mlx5 coalescence. Host-scope knobs are
		// GATED by `claim-host-tunables true` (B1). Per-iface knobs
		// (rx-usecs/tx-usecs) follow the D3 allowlist and are applied
		// whenever coalescence is configured.
		var (
			governor          string
			netdevBudget      int
			coalesceEnable    bool
			coalesceRX        int
			coalesceTX        int
			userspaceDP       bool
			coalesceExplicit  bool
			claimHostTunables bool
		)
		if cfg := d.store.ActiveConfig(); cfg != nil {
			if cfg.Chassis.Cluster != nil {
				clusterMode = true
				nodeID = cfg.Chassis.Cluster.NodeID
			}
			// D3 (#785): pass userspace-dp worker count so linksetup can
			// reshape mlx5 RSS indirection before any AF_XDP bind. Zero
			// when userspace dataplane is not in use — applyRSSIndirection
			// treats that as a no-op.
			if dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace &&
				cfg.System.UserspaceDataplane != nil {
				userspaceDP = true
				userspaceWorkers = cfg.System.UserspaceDataplane.Workers
				if cfg.System.UserspaceDataplane.RSSIndirectionDisabled {
					rssEnabled = false
				}
				// Codex H1: scope D3 to only interfaces that
				// userspace-dp actually binds AF_XDP sockets on.
				rssAllowed = dpuserspace.UserspaceBoundLinuxInterfaces(cfg)
				// #801 knobs.
				claimHostTunables = cfg.System.UserspaceDataplane.ClaimHostTunables
				governor = cfg.System.UserspaceDataplane.CPUGovernor
				netdevBudget = cfg.System.UserspaceDataplane.NetdevBudget
				coalesceExplicit = cfg.System.UserspaceDataplane.CoalescenceAdaptiveExplicit
				// coalesceEnable stays false by default — the Step-0
				// finding is "adaptive=on causes pp99 latency jitter",
				// so default-off is what the issue asks for. An
				// explicit `adaptive enable` inverts this.
				if coalesceExplicit &&
					!cfg.System.UserspaceDataplane.CoalescenceAdaptiveDisabled {
					coalesceEnable = true
				}
				coalesceRX = cfg.System.UserspaceDataplane.CoalescenceRXUsecs
				coalesceTX = cfg.System.UserspaceDataplane.CoalescenceTXUsecs
			}
		}
		if d.inBootstrap() {
			// #1922 Item 2/3: bootstrap mode suppresses the full rename loop
			// and host tunables. Instead, the lifeline-gated path identifies
			// the management NIC by its default route, records its PCI
			// identity, and (only if it would become fxp0) renames JUST that
			// NIC + snapshots its addressing into the bootstrap .network so
			// the operator stays reachable. No other NIC is touched.
			d.setupBootstrapLifeline()
		} else {
			// #1956: device-map mode (opt-in) renames ONLY mapped NICs by
			// stable identity and leaves the rest alone. Positional mode
			// (no device-map) is bit-identical to pre-#1956.
			if err := applyStartupNamingPolicy(d.store.ActiveConfig(), nodeID, clusterMode,
				userspaceWorkers, rssEnabled, rssAllowed, d.resolveProtectedInterfaces()); err != nil {
				// Log stays generic: helper already selected device-map vs
				// positional; callers care only that startup naming failed.
				slog.Warn("interface naming failed", "err", err)
			}
			// #801: host tunables + coalescence. Runs after the interface
			// rename but still before the dataplane is loaded — matches
			// the D3 "before any AF_XDP bind" invariant. Best-effort: any
			// failure logs and continues.
			//
			// B1 opt-in gate: host-scope knobs (governor + netdev_budget +
			// adaptive-rx/tx flip) only apply when `claim-host-tunables
			// true` is set. This keeps xpfd from stepping on shared hosts
			// silently. D3 and per-iface rx-usecs/tx-usecs continue to run
			// as before — both are interface-scoped.
			d.applyStep0Tunables(userspaceDP, claimHostTunables, governor, netdevBudget,
				coalesceExplicit, coalesceEnable, coalesceRX, coalesceTX, rssAllowed)
		}
	}
}

// namingParamsFromConfig derives the startup-naming inputs from a config: the
// cluster node ID and mode (from the chassis cluster stanza) and the
// userspace-dp RSS-indirection knobs. Shared by the boot naming site, the
// bootstrap-exit takeover, and the #4179 config-arrival re-naming so all three
// derive naming identically from the SAME config.
func namingParamsFromConfig(cfg *config.Config) (nodeID int, clusterMode bool, userspaceWorkers int, rssEnabled bool, rssAllowed []string) {
	rssEnabled = true
	if cfg == nil {
		return
	}
	if cfg.Chassis.Cluster != nil {
		clusterMode = true
		nodeID = cfg.Chassis.Cluster.NodeID
	}
	if dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace &&
		cfg.System.UserspaceDataplane != nil {
		userspaceWorkers = cfg.System.UserspaceDataplane.Workers
		if cfg.System.UserspaceDataplane.RSSIndirectionDisabled {
			rssEnabled = false
		}
		rssAllowed = dpuserspace.UserspaceBoundLinuxInterfaces(cfg)
	}
	return
}

// applyStartupNamingForConfig runs the startup naming policy (positional or
// device-map) for a given config, deriving the naming inputs from that config.
// It is the shared naming action used by the bootstrap-exit takeover and the
// #4179 config-arrival re-naming. It does NOT arm the dataplane or enable
// forwarding — those are the caller's concern (the config-arrival path is NOT
// bootstrap, so the dataplane was already armed at boot).
func (d *Daemon) applyStartupNamingForConfig(cfg *config.Config) error {
	if d.opts.NoDataplane {
		return nil
	}
	nodeID, clusterMode, userspaceWorkers, rssEnabled, rssAllowed := namingParamsFromConfig(cfg)
	return applyStartupNamingPolicy(cfg, nodeID, clusterMode, userspaceWorkers,
		rssEnabled, rssAllowed, d.resolveProtectedInterfaces())
}

// maybeReapplyConfigArrivalNaming re-runs startup naming exactly once, when a
// config-less HA node (emptyHANamingPending, set on the #4179 HA-guard
// EMPTY-takeover boot) receives its FIRST non-empty config. That boot named the
// NICs with STANDALONE names because the nil active config carried no cluster
// stanza; the arriving config finally supplies the node's cluster identity, so
// the NICs must be renamed to em0 + ge-<fpc>-0-X (the names the config
// references) instead of stranding on standalone names until a restart.
//
// It mirrors the bootstrap-exit re-naming but WITHOUT re-arming the dataplane
// (this node is NOT in bootstrap mode — the dataplane was armed at boot). The
// caller places it BEFORE the reconcile so the config is wired onto the
// correctly-named links. The config-less node forwards no real traffic yet
// (empty config at boot), so the mid-apply rename is safe. Returns true if
// naming was re-run AND succeeded (the one-shot flag was consumed). An empty
// config does NOT consume the flag — naming waits for the real cluster config.
//
// The flag is consumed only on SUCCESS: if applyStartupNamingForConfig errors
// (a transient NIC enumeration / netlink failure), the flag STAYS SET so the
// next config apply retries. Otherwise a single transient error would strand
// the config-less HA node on standalone names forever. The retry is bounded to
// once per config apply (a commit / SyncApply, not a hot loop); a persistently
// failing enumeration re-attempts on each commit, which is acceptable and
// logged. Both call sites run under d.applySem, so applies are serialized and
// the success path cannot double-run.
func (d *Daemon) maybeReapplyConfigArrivalNaming(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return false
	}
	if !d.emptyHANamingPending.Load() {
		return false
	}
	_, clusterMode, _, _, _ := namingParamsFromConfig(cfg)
	slog.Info("config-arrival interface naming: a config-less HA node received its first "+
		"non-empty config; re-running startup naming with the config's cluster identity",
		"cluster_mode", clusterMode)
	if err := d.applyStartupNamingForConfig(cfg); err != nil {
		// Leave the flag SET so the next config apply retries — a transient
		// enumeration/netlink error must not permanently strand this node on
		// standalone names.
		slog.Warn("config-arrival interface naming failed; will retry on the next config apply",
			"err", err)
		return false
	}
	// Consume the one-shot flag only now that naming succeeded.
	d.emptyHANamingPending.Store(false)
	return true
}

// runBootstrapExitStartup performs the one-time startup TAKEOVER steps that
// bootstrap mode suppressed at boot — interface rename, IP forwarding, and
// dataplane arm — when the daemon leaves bootstrap on its first non-empty
// config apply (#1922 Item 2). It runs under d.applySem (the apply caller
// holds it) and strictly BEFORE the reconcile that wires the config onto
// these subsystems. It mirrors the boot block in Run; bootstrap exit is
// one-way, so this runs at most once.
func (d *Daemon) runBootstrapExitStartup(cfg *config.Config) {
	if d.opts.NoDataplane {
		return
	}

	nodeID, _, _, _, _ := namingParamsFromConfig(cfg)

	// Full rename loop — the lifeline-gated path only renamed fxp0 (or
	// nothing). Now claim the NICs per the active naming policy.
	//
	// #1956 R-4: bootstrap-exit (the FIRST real commit) is exactly when a
	// device-map first appears, so this site must branch too — otherwise
	// day-0 bare metal claims every NIC positionally before the map ever
	// applies.
	if err := d.applyStartupNamingForConfig(cfg); err != nil {
		slog.Warn("bootstrap exit: interface naming failed", "err", err)
	}

	// Enable IP forwarding (suppressed in bootstrap).
	enableForwarding()

	// Arm the dataplane (AF_XDP attach) — the backend object was
	// constructed at boot (C1) but never started in bootstrap mode.
	d.armBootstrapExitDataplane(nodeID)
	slog.Info("bootstrap exit: startup takeover complete; applying first config")
}

// armBootstrapExitDataplane arms the runtime dataplane on bootstrap exit:
// the backend object was constructed at boot (C1) but never started in
// bootstrap mode. Split from runBootstrapExitStartup (#2114) so the
// dataplane-cell race tests can drive the REAL arm/nil-on-failure writer
// without the netlink/sysctl takeover steps. On success the NAT
// port/session seeds run and the #2079 pool-alarm monitor starts.
//
// On a Start failure the cell is cleared, so nothing can ACQUIRE the
// unarmed backend afterwards and the daemon forwards nothing. That is
// "config-only" for the forwarding path and for every consumer that
// re-reads the cell — which, since #6743 r4, includes gRPC, REST and the
// console CLI (they hold liveDataPlane, so the clear makes their
// dataplane surface report unavailable immediately). It is NOT a claim
// that every consumer is severed: the conntrack GC and cluster
// SessionSync were wired from DECOMPOSED domain handles taken before this
// point and keep them (daemon_dp_live.go documents why), so their loops
// run until their own contexts end. Codex PR #6743 r7: the userspace
// event-stream loop is NO LONGER in that list — it re-resolves the
// provider, the stream and the session-delta drainer from the cell on
// every tick, so this clear stops it draining within one tick.
func (d *Daemon) armBootstrapExitDataplane(nodeID int) {
	// #2114: ONE snapshot feeds the nil-check, Start, and the seeder
	// (plan §5.3 rule 3); the cell is cleared only on the failure branch.
	rt := d.dataplane()
	if rt == nil {
		return
	}
	if err := rt.Start(d.daemonCtx); err != nil {
		slog.Warn("bootstrap exit: failed to start dataplane, running in config-only mode",
			"err", err)
		d.setDataplane(nil)
		// #5275: runBootstrapExitStartup just called enableForwarding in
		// anticipation of this arm. The arm failed, so the node has no
		// policy enforcement and must not carry transit — close the knobs
		// again, before the reconcile this exit precedes.
		d.markDataplaneArmFailed("bootstrap exit: dataplane start failed",
			"check `journalctl -u xpfd` for the shim/AF_XDP attach error, then "+
				"correct the config and re-commit, or restart xpfd", err)
		return
	}
	// #5275: the RE-ARM path. Boot left the knobs closed (bootstrap is
	// transit-off), so recovery has to re-open them here — otherwise the
	// first good commit would leave a correctly-armed node forwarding
	// nothing until a daemon restart.
	d.markDataplaneArmed("bootstrap exit")
	if seeder, ok := rt.(natSeeder); ok {
		seeder.SeedNATPortCounters()
		seeder.SeedSessionIDCounter(nodeID)
	}
	// #2114: start the NAT pool-alarm monitor now that the dataplane
	// is armed and the published dataplane is stable. It was suppressed
	// at boot in bootstrap mode; exitBootstrapMode already flipped
	// bootstrapMode=false in applyConfigLocked before calling this,
	// so maybeStartNATPoolAlarm's !inBootstrap() gate passes. Runs
	// under the apply caller's d.applySem; the monitor sampler reads the
	// dataplane through the atomic dataplane() accessor. Idempotent.
	d.maybeStartNATPoolAlarm()
}
