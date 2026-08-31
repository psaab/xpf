package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/vrrp"
)

// applyTailReconciles runs steps 8–21 of applyConfigLocked — the tail of the
// commit/apply pipeline that dispatches to independent subsystems after the
// ordering-entangled head (VRF/tunnel/IPVLAN/dataplane/RETH-MAC/networkd/FRR,
// steps 0–7). Each step reads only the compiled config (+ nil-guarded
// subsystems); none feeds a later head step, so grouping them here is a
// behavior-preserving mechanical move (#4407 Phase A). The helper runs
// synchronously in the caller's goroutine under d.applySem (the caller holds
// it), so the lock discipline of the inline body is preserved; the few
// intentionally-async callbacks the apply body spawns all live in the head,
// not here.
//
// Error-join contract: the deferred reconcile errors accumulate across the
// whole apply body but are joined only at this tail (fail-closed — every step
// still runs). networkdErr/applyErr/dhcpServerErr/ipsecErr/ifaceErr originate in
// the head and are threaded in as parameters (applyErr is the #5679 ordinary
// non-abort dataplane-apply failure that must fail the commit while the OLD
// policy stays live); routeLeakErr is the #5696 route-leak snapshot
// republish/FIB-bump failure (also head-produced, threaded in like ifaceErr);
// vrrpErr originates in step 8 below when runtime identity validation rejects
// the desired set (#5083); vrfErr is the #5700 VRF-device-setup (ReconcileVRFs)
// failure and routingRuleErr/mgmtRouteErr are threaded from the caller;
// lo0Err/hostInboundErr originate in step 9.5, dnsErr in step 9 (#6792), and
// the five host-credential errors (loginErr/sudoersErr/absentUsersErr/
// sshConfigErr/rootAuthErr) in steps 11–13 (#6790). The returned errors.Join
// preserves the explicit operand order
// (#1778/#2987/#4433/#5083/#5310/#5679/#5696/#5700/#6790/#6792).
func (d *Daemon) applyTailReconciles(cfg *config.Config, networkdErr, applyErr, dhcpServerErr, ipsecErr, ifaceErr, routeLeakErr, routingRuleErr, mgmtRouteErr, vrfErr error, fabricErr error) error {
	// 8. Apply VRRP config — merge user VRRP + RETH VRRP instances
	var vrrpErr error
	vrrpInstances := vrrp.CollectInstances(cfg)
	if d.cluster != nil {
		localPri := d.cluster.LocalPriorities()
		vrrpInstances = append(vrrpInstances, vrrp.CollectRethInstances(cfg, localPri)...)
	}
	if d.vrrpMgr == nil {
		// #6739 (work item G, the half that is provable on master TODAY).
		//
		// Store.Load recovers a STILL-LIVE commit-confirmed window by re-arming
		// time.AfterFunc(time.Until(deadline)). An ALREADY-EXPIRED window is
		// handled synchronously in an earlier branch and never reaches that
		// re-arm, so the remaining duration here is strictly positive — but it
		// is bounded below only by how close the boot is to the deadline, and
		// can be arbitrarily small. A box that reboots shortly before its
		// deadline (`commit confirmed 1` and a ~55s boot) arms a timer with
		// seconds on it.
		//
		// That timer is armed in startup PHASE 1 (loadAndBootstrapConfig); the
		// rollback executor is registered before the phase list even starts;
		// and vrrpMgr is not constructed until PHASE 3 (initManagers). Nothing
		// holds applySem across the phases. So when the remaining duration
		// elapses before phase 3 completes, the timer goroutine reaches this
		// line with vrrpMgr still nil and the daemon panics AT BOOT.
		//
		// Measured, not argued — and the first mechanism I wrote here was
		// WRONG: I recorded an unclamped negative duration firing immediately,
		// then found the synchronous expired-window branch that makes that
		// impossible. The panic is real (see
		// TestRecoveredRollbackDoesNotPanicBeforeManagers6739); the route to it
		// is a race against phases 2-3, not an instantaneous fire.
		//
		// Deliberately NOT "skip the update and carry on". This site is already
		// a fail-closed gate one line below for exactly one reason: reporting a
		// successful apply while the manager does not hold the requested
		// instance set claims HA coverage for a family or segment that is not
		// running. A nil manager holds NO instance set at all, which is the
		// strongest form of that same condition, so it fails closed too.
		//
		// This is deliberately NOT work item G's startup-readiness gate. G
		// releases recovery at end-of-phase-5, and #6739 records that landing
		// that without work item H converts this short pre-manager window into
		// a post-manager bootstrap-with-live-cluster hybrid — a worse state.
		// Guarding the dereference moves no dispatch point and creates no such
		// hybrid; it converts a boot panic into a reported apply failure and
		// leaves G/H/H2 entirely to their unresolved convergence.
		vrrpErr = errors.New("update VRRP instances: VRRP manager not initialized " +
			"(apply reached the VRRP reconcile before daemon startup constructed it)")
		slog.Error("VRRP reconcile ran before the VRRP manager exists; failing the apply "+
			"closed rather than claiming HA coverage", "issue", "#6739")
	} else if err := d.vrrpMgr.UpdateInstances(vrrpInstances); err != nil {
		slog.Warn("failed to update VRRP instances", "err", err)
		// Identity/family validation is a fail-closed runtime gate. Returning a
		// successful commit while the manager retained the old instance set
		// would claim HA coverage for a family/segment that is not running.
		vrrpErr = fmt.Errorf("update VRRP instances: %w", err)
	}

	// 9. Apply system DNS and NTP configuration.
	//
	// #1715: a single locked reconcileDNS owns /etc/resolv.conf as a
	// managed plain file (resolved disabled+masked), merging static
	// `system name-server` with live DHCP-learned servers. It replaces
	// the prior applySystemDNS (resolved drop-in + restart) and
	// applyDNSService (disable resolved) pair, whose apply order
	// (write-drop-in-then-disable) was a self-inflicted race that left
	// /etc/resolv.conf a dangling symlink. bootEmptyRepairOnly is set
	// before DHCP clients start so the first apply does not blank a good
	// resolv.conf when no static name-server is configured yet.
	// #6792: joined into the commit result, not swallowed at WARN. Its two
	// siblings in this same function — applyLo0Filter and
	// applyHostInboundFilter — are both captured and joined; reconcileDNS sat
	// between them as a bare statement and was the ONLY reconciler here whose
	// error could not propagate. A failed disable+mask leaves systemd-resolved
	// as a second resolver owner (and xpf's own networkd .network files carry
	// UseDNS=yes, so a surviving resolved is independently fed DHCP
	// nameservers); a failed write leaves /etc/resolv.conf stale AFTER the mask
	// and drop-in removal have already run. Both reported a successful commit.
	// The remaining apply steps still run, matching the lo0/host-inbound
	// pattern: management/SSH reconcile is never skipped by a DNS failure.
	dnsErr := d.reconcileDNSLocked(cfg, !d.dnsBootDone)
	d.applySystemNTP(cfg)

	// 9.5. Apply system hostname, timezone, and kernel tuning
	d.applyHostname(cfg)
	d.applyTimezone(cfg)
	d.applyKernelTuning(cfg)
	// #3392: the lo0 input filter is host-protection control-plane enforcement,
	// so an apply/teardown failure must fail the commit closed rather than be
	// swallowed at WARN — the same fail-open #3333 fixed for host-inbound. The
	// error is joined into the commit result at the tail (alongside networkdErr /
	// dhcpServerErr / hostInboundErr); the remaining apply steps still run so
	// management/SSH reconcile is never skipped by an lo0 nft failure.
	lo0Err := d.applyLo0Filter(cfg)
	// #3333: host-inbound is the kernel-nftables PRIMARY enforcement of the
	// host-inbound contract, so an apply/teardown failure must fail the commit
	// closed rather than be swallowed at WARN. The error is joined into the
	// commit result at the tail (alongside networkdErr / dhcpServerErr); the
	// remaining apply steps still run so management/SSH reconcile is never
	// skipped by a host-inbound nft failure.
	hostInboundErr := d.applyHostInboundFilter(cfg)

	// 9.6. Write SSH known hosts file
	d.applySSHKnownHosts(cfg)

	// 10. Apply system syslog forwarding
	d.applySystemSyslog(cfg)

	// Steps 11–13 are the login/credential reconcilers. They return their
	// accumulated failures (#5874) and, since #6790, the NORMAL apply path
	// CAPTURES those returns and joins them into the commit result — exactly
	// like their siblings in this same function (applyLo0Filter #3392,
	// applyHostInboundFilter #3333, reconcileDNSLocked #6792).
	//
	// They were previously discarded as `_ =` on the argument that the next
	// boot re-renders login / sudoers / SSH / root-auth from the active config,
	// so a transient failure converges (the #2926 next-boot contract). That
	// argument does not hold for these five owners:
	//
	//   - It is a REVOCATION window, not a rendering delay. `delete system
	//     login user bob` that fails to lock bob's password or remove his
	//     authorized_keys reported a SUCCESSFUL commit, so the operator
	//     believes bob is deprovisioned NOW. The credential stays live until
	//     the next reboot — unbounded on an appliance that is expected to run
	//     for months — and nothing retries in between: there is no dirty-retry
	//     owner, no ticker, and no metric for these reconcilers.
	//   - The same commit is the one that ADVANCES the durable config, so the
	//     next boot renders from a config that already says bob is gone while
	//     the box still grants him access. A green commit is the operator's
	//     only signal, and it was unconditional.
	//   - The #5874 cancel closeout exists precisely because these five do not
	//     converge on their own; it made them RETURN their failures but only
	//     the daemon-stop path collected them. The normal path — the one an
	//     operator actually uses to revoke access — kept discarding them.
	//
	// Fail-closed, same discipline as lo0/host-inbound/DNS: every step below
	// still RUNS (no early return), so an sshd reload failure never skips
	// root-auth reconciliation; only the commit RESULT changes.
	//
	// Note the asymmetry with the void-returning steps around them
	// (applySystemNTP, applyHostname, applySyslogFiles, ...): those really do
	// re-render from the active config on the next apply or boot and hold no
	// revocation semantics.

	// 11. Apply system login users (create OS accounts, SSH keys)
	loginErr := d.applySystemLogin(cfg)

	// 11b. Reconcile super-user sudo grants against the CURRENT config so a
	// class downgrade or user removal REVOKES the stale NOPASSWD grant
	// (#3889). Runs unconditionally — applySystemLogin returns early when
	// there are no users, which is exactly the "all users removed" case
	// that must still sweep stale grants.
	sudoersErr := d.reconcileSudoers(cfg)

	// 11c. Revoke host credentials for any xpf-provisioned login account that
	// was removed from config (#5128). reconcileSudoers above only revokes the
	// sudo grant; without this a deprovisioned operator keeps their password
	// and authorized_keys and can still SSH in. Like reconcileSudoers it MUST
	// run unconditionally — the "all users removed" case must still revoke.
	absentUsersErr := d.reconcileAbsentLoginUsers(cfg)

	// 12. Apply SSH service configuration (root-login)
	sshConfigErr := d.applySSHConfig(cfg)

	// 13. Apply root authentication (encrypted-password + SSH keys)
	rootAuthErr := d.applyRootAuth(cfg)

	// 14. Apply syslog file destinations (rsyslog configs)
	d.applySyslogFiles(cfg)

	// 14b. Update security log syslog clients + zone name mapping
	if d.eventReader != nil {
		d.applySyslogConfig(d.eventReader, cfg)
	}

	// 15. Archive config to remote sites if transfer-on-commit is enabled
	d.archiveConfig(cfg)

	// 15b. Configure local archival settings for auto-archive on commit
	if cfg.System.Archival != nil {
		dir := cfg.System.Archival.ArchiveDir
		if dir == "" {
			dir = "/var/lib/xpf/archive"
		}
		max := cfg.System.Archival.MaxArchives
		if max <= 0 {
			max = 10
		}
		d.store.SetArchiveConfig(dir, max)
	} else {
		d.store.SetArchiveConfig("", 0)
	}

	// 15c. Reconcile the periodic configuration-archival timer (#4078). Junos
	// `transfer-interval N` archives the running config to the archive-sites
	// every N minutes, independent of transfer-on-commit. Hash-gated so an
	// unrelated commit never bounces a healthy timer; re-armed on daemon
	// restart via this same boot apply; stopped when the leaf is removed.
	d.reconcileArchiveTimer(cfg)

	// 16. Update flow traceoptions (trace file + filters)
	d.updateFlowTrace(cfg)

	// 16b. Reconcile the NetFlow v9 / IPFIX exporters (#2075). Before
	// this, the exporters were only started at boot and stopped at
	// shutdown, so forwarding-options sampling / flow-monitoring config
	// changes were ignored until a daemon restart (and flow export
	// added in a later commit never started). Hash-gated per family so
	// an unrelated commit never bounces a healthy exporter. Placed
	// below the dataplane-apply abort (consistent with reconcileRPM /
	// applySyslogConfig): an aborting commit defers the exporter change
	// to the next clean commit.
	d.reconcileFlowExporters(cfg)

	// 16c. Reconcile the DHCP relay (#2348). Before this the relay was
	// applied only at boot (daemon_run.go), so a day-2 commit that added,
	// removed, or changed a `forwarding-options dhcp-relay` group was
	// ignored until a daemon restart. Manager.Apply diffs desired-vs-running
	// per interface (start added, stop removed, restart changed, leave
	// unchanged) and a nil relay config stops all relays. Bound to
	// d.daemonCtx so the relay goroutines outlive this apply call.
	d.reconcileDHCPRelay(cfg)

	// 16d. Reconcile the LLDP service (#2372). Before this, LLDP was applied
	// only at boot (daemon_run.go), so a day-2 commit that enabled, disabled,
	// or changed `protocols lldp` (interface set, transmit-interval,
	// hold-multiplier) was silently ignored until a daemon restart. reconcileLLDP
	// lazily instantiates the manager on the first enable and Apply()s the new
	// config; a disabled/empty stanza stops the running service. Bound to
	// d.daemonCtx so the TX/RX goroutines outlive this apply call.
	d.reconcileLLDP(cfg)

	// 17. Reconcile event-options policies (RPM-driven failover). Before
	// #3752 this was a bare `if d.eventEngine != nil { Apply }`, and the
	// engine was constructed at boot ONLY when the boot config already had
	// policies — so committing the FIRST event-options policy on a running
	// daemon (day-2) left d.eventEngine nil and the policy inert until a
	// restart. The engine is now constructed unconditionally at boot
	// (daemon_run.go, mirroring LLDP/dhcpRelay); reconcileEventOptions runs
	// here on every day-2 commit so a first-enable takes effect immediately.
	d.reconcileEventOptions(cfg)

	// 17b. Reconcile RPM probes (#1827 PR-1a). Config-hash-gated: the
	// probe set (and the probe next-hop pin rules) is re-applied only
	// when the rendered RPM stanza actually changed, so unrelated
	// commits never wipe probe state.
	d.reconcileRPM(cfg)

	// 17c. Reconcile the ip-monitoring engine (#1827 PR-1b): install
	// the committed policy set (preserving FAIL state across unrelated
	// commits) and seed it with current probe results.
	d.reconcileIPMon(cfg)

	// 18. Update chassis cluster interface monitors
	if d.routing != nil && cfg.Chassis.Cluster != nil &&
		len(cfg.Chassis.Cluster.RedundancyGroups) > 0 {
		d.routing.ApplyInterfaceMonitors(cfg.Chassis.Cluster.RedundancyGroups)
	}

	// 19. Update chassis cluster state machine
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		d.cluster.UpdateConfig(cfg.Chassis.Cluster)
		// #7164: UpdateConfig above rewrote the desired heartbeat
		// interval/threshold, but a running heartbeat snapshotted the OLD ones
		// at StartHeartbeat and nothing restarted it for a timing change —
		// RestartHeartbeat's only production caller was the VRF-rebind path. So
		// `set chassis cluster heartbeat-interval` never reached the wire.
		//
		// Placed HERE rather than in step 20 on purpose. Step 20 restarts comms
		// on a transport-key change, which does rebuild the heartbeat as a side
		// effect — but heartbeat timing is not part of clusterTransportKey, so a
		// timing-only commit never reaches that branch. This is a direct
		// consequence of the UpdateConfig on the line above, and belongs with
		// it. The call is a no-op when the timing is unchanged or no heartbeat
		// is running, so an ordinary commit costs one lock and two comparisons.
		d.cluster.ApplyCommittedHeartbeatTiming()
		// Feed interface monitor statuses into cluster weight calculation
		if d.routing != nil {
			monStatuses := d.routing.InterfaceMonitorStatuses()
			for rgID, statuses := range monStatuses {
				for _, st := range statuses {
					d.cluster.SetMonitorWeight(rgID, st.Interface, !st.Up, st.Weight)
				}
			}
		}

		// RETH GARP is handled by native VRRP (VRRP-backed RETH).
		// No manual GARP registration needed.
	}

	// 20. Detect cluster transport config changes and restart comms (#87).
	// Only restart if comms were previously started (activeClusterTransport
	// is non-zero) and the new config differs.
	if d.cluster != nil && d.daemonCtx != nil {
		newTransport := clusterTransportFromConfig(cfg)
		// #6290: ONE guarded snapshot. The boot startClusterComms writes this
		// field holding neither applySem nor clusterCommsMu, and a DHCP
		// lease-change callback re-enters this step on a goroutine started
		// before that write — see setActiveTransportIfCurrent for the full
		// ordering.
		active := d.activeTransport()
		if active != (clusterTransportKey{}) && newTransport != active {
			// #7073: the pairs are derived from clusterTransportKey, the same
			// struct the comparison above compares whole. Writing them out by
			// hand had already dropped the two fab1 fields, so a fab1-only
			// change logged four identical old/new pairs.
			slog.Info("cluster: transport config changed, restarting comms",
				transportChangeLogArgs(active, newTransport)...)
			d.stopClusterComms()
			// #6878: through the seam so a test can bind restart COMPLETION.
			// stopClusterComms bumps clusterCommsGen first, so the generation
			// alone cannot tell a completed restart from a teardown that never
			// came back up.
			start := d.startClusterCommsFn
			if start == nil {
				start = d.startClusterComms
			}
			start(d.daemonCtx)
		}

		// #4647 BUG-B: reconcile the #2239 DHCP lease-sync push loop against
		// the just-committed `dhcp-lease-synchronization` knob. Without this a
		// runtime knob-ON commit on a running cluster was a silent no-op (the
		// loop was launched only from the connect-time block) — counters stayed
		// 0/0 until an xpfd restart. ensureDHCPLeaseSyncLoop is idempotent, so a
		// knob-unchanged commit is a no-op, a knob-ON commit (re)launches the
		// loop against the live comms context, and a knob-OFF commit stops it.
		d.ensureDHCPLeaseSyncLoop(d.dhcpLeaseSyncEnabled(cfg))

		// #6628: reconcile the AUTHENTICATION posture of any established
		// session-sync connection against the just-committed control-link key.
		//
		// This is the one thing the transport-key comparison above
		// deliberately cannot do. clusterTransportKey EXCLUDES the auth key —
		// pinned by TestAuthKeyChangeDoesNotRestartClusterComms_5078, because
		// the established connection is what carries the key to a read-only
		// secondary — so committing a key never reaches the restart branch and
		// the stream stays unauthenticated indefinitely. ReconcileConnectionAuth
		// upgrades it IN PLACE instead: it only ever promotes, and never closes
		// a connection, so the #5078 rationale is untouched.
		//
		// Level-triggered and called on EVERY commit, not only a key change:
		// the staleness test lives inside (the connection records the PSK it
		// authenticated under), so an unrelated commit costs two pointer reads
		// and a bytes.Equal per connection. An edge test here would have to
		// duplicate that state and could miss the edge that matters — a commit
		// that lands while the connection is mid-reconnect.
		if ss := d.getSessionSync(); ss != nil {
			// #7441: publish the operator-declared strict session-auth posture
			// BEFORE reconciling, so this pass's reconcile — which also
			// evaluates the eviction — sees the value just committed rather
			// than the previous one. The value is read from the COMPILED local
			// config, which is the copy preserveNodeLocalChassis pinned, not
			// whatever a peer last pushed.
			ss.SetStrictSessionAuth(strictSessionAuthEnabled(cfg))
			ss.ReconcileConnectionAuth("config-apply")
		}
	}

	// 21. Re-apply D3 RSS indirection on config change (#797 HIGH #2).
	// Worker count can change via commit (e.g. `set system dataplane
	// workers 6`), and the D3 disable knob can flip; either requires
	// re-running the reshape (or restore) against the current HW state.
	// Idempotent: matching tables skip the write. Non-mlx5 interfaces
	// are skipped at the per-interface guard. The allowlist is
	// recomputed from the *new* compiled config so interface-set
	// changes (added/removed zoned mlx5 interfaces, fabric interface
	// changes) take effect on the same commit.
	if !d.opts.NoDataplane {
		rssEnabled := true
		workers := 0
		var rssAllowed []string
		// #801: mirror the startup site so a commit that changes any
		// of the Step-0 knobs takes effect without a restart.
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
		if dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace &&
			cfg.System.UserspaceDataplane != nil {
			userspaceDP = true
			workers = cfg.System.UserspaceDataplane.Workers
			if cfg.System.UserspaceDataplane.RSSIndirectionDisabled {
				rssEnabled = false
			}
			rssAllowed = dpuserspace.UserspaceBoundLinuxInterfaces(cfg)
			claimHostTunables = cfg.System.UserspaceDataplane.ClaimHostTunables
			governor = cfg.System.UserspaceDataplane.CPUGovernor
			netdevBudget = cfg.System.UserspaceDataplane.NetdevBudget
			coalesceExplicit = cfg.System.UserspaceDataplane.CoalescenceAdaptiveExplicit
			if coalesceExplicit &&
				!cfg.System.UserspaceDataplane.CoalescenceAdaptiveDisabled {
				coalesceEnable = true
			}
			coalesceRX = cfg.System.UserspaceDataplane.CoalescenceRXUsecs
			coalesceTX = cfg.System.UserspaceDataplane.CoalescenceTXUsecs
		}
		reapplyRSSIndirection(rssEnabled, workers, rssAllowed)
		// #801 B1 + B2: opt-in gate + restore-on-disable.
		d.applyStep0Tunables(userspaceDP, claimHostTunables, governor, netdevBudget,
			coalesceExplicit, coalesceEnable, coalesceRX, coalesceTX, rssAllowed)
	}
	// #1778 + #2987 + #4433 + #5083 + #5310 + #5679 + #5696: deferred reconcile failures —
	// every reconcile step above has run; surface the networkd write failure, the
	// ordinary (non-abort) dataplane-apply failure (#5679 — the new policy is
	// NOT on the wire, the old one still is), the Kea restart/stop failure, the
	// IPsec render/reload failure, the interface-reconcile failure
	// (xfrmi/bond/tunnel/legacy-reth create/up/delete — #5310), and the route-leak
	// snapshot republish/FIB-bump failure (#5696 — a stale inter-VRF leak would
	// otherwise survive on a "successful" commit) through the commit so a step
	// that left stale or missing kernel/swanctl/dataplane state fails the commit
	// (fail-closed) instead of reporting success. #6790 adds the five
	// host-credential reconcilers (login / sudoers / absent-user revocation /
	// sshd / root-auth), whose failures were discarded here — a commit that did
	// not actually revoke a removed operator's password or authorized_keys is
	// not a successful commit. All are joined so none masks the other.
	return errors.Join(networkdErr, applyErr, dhcpServerErr, hostInboundErr, lo0Err, dnsErr,
		loginErr, sudoersErr, absentUsersErr, sshConfigErr, rootAuthErr,
		ipsecErr, ifaceErr, routeLeakErr, routingRuleErr, mgmtRouteErr, vrfErr, fabricErr, vrrpErr)
}

// reconcileDHCPRelay re-applies the DHCP relay config on every commit (#2348).
// The relay Manager is created at boot (daemon_run.go) regardless of whether a
// relay was configured then, so a relay added on a day-2 commit starts here and
// a relay removed here stops. Manager.Apply diffs desired-vs-running per
// interface (start added / stop removed / restart changed / leave unchanged),
// and a nil relay config stops all relays. The relay goroutines bind to
// d.daemonCtx (the daemon lifetime) — NOT a request-scoped context — so they
// survive past this apply call and are torn down only at daemon stop. Guarded
// on d.dhcpRelay so a daemon constructed without a relay Manager (e.g. a test
// harness or NoDataplane boot that skipped the boot wiring) is a safe no-op.
func (d *Daemon) reconcileDHCPRelay(cfg *config.Config) {
	if d.dhcpRelay == nil {
		return
	}
	ctx := d.daemonCtx
	if ctx == nil {
		ctx = context.Background()
	}
	d.dhcpRelay.Apply(ctx, cfg.ForwardingOptions.DHCPRelay)
}

// effectiveLLDPConfig translates the typed `protocols lldp` stanza into the
// lldp.LLDPConfig the manager consumes, or returns nil when LLDP is disabled,
// empty, or absent (the "stop the service" signal). It is the single mapping
// used by both boot and the day-2 reconcile, so the diff-guard in reconcileLLDP
// compares like-for-like.
func effectiveLLDPConfig(cfg *config.Config) *lldp.LLDPConfig {
	if cfg == nil || cfg.Protocols.LLDP == nil ||
		cfg.Protocols.LLDP.Disable || len(cfg.Protocols.LLDP.Interfaces) == 0 {
		return nil
	}
	lldpIfaces := make([]lldp.LLDPInterface, 0, len(cfg.Protocols.LLDP.Interfaces))
	for _, iface := range cfg.Protocols.LLDP.Interfaces {
		lldpIfaces = append(lldpIfaces, lldp.LLDPInterface{
			Name:    iface.Name,
			Disable: iface.Disable,
		})
	}
	return &lldp.LLDPConfig{
		Interfaces:     lldpIfaces,
		Interval:       cfg.Protocols.LLDP.Interval,
		HoldMultiplier: cfg.Protocols.LLDP.HoldMultiplier,
		SystemName:     cfg.System.HostName,
	}
}

// reconcileLLDP re-applies the LLDP service config on every commit (#2372). It
// is the single source of truth for LLDP lifecycle — daemon_run.go calls it at
// boot, and applyConfigLocked calls it on every day-2 commit, so a change to
// `protocols lldp` takes effect without a daemon restart.
//
// The manager itself is constructed exactly once at boot (daemon_run.go),
// mirroring d.dhcpRelay. reconcileLLDP NEVER reassigns the d.lldpMgr pointer —
// it only calls Apply()/Stop() on the already-constructed manager. This keeps
// the lock-free d.lldpMgr reads on the `show lldp neighbors` handler goroutines
// race-free against a concurrent commit (finding 3): the pointer is written
// once, before any handler can run.
//
// Change-guarded (finding 6): lldp.Manager.Apply unconditionally Stop()s the
// current generation — closing every per-interface socket, joining goroutines,
// AND wiping the neighbor table — before rebuilding. Calling it on every commit
// would blank `show lldp neighbors` and churn sockets on any unrelated day-2
// commit (e.g. a firewall-policy change) while neighbors re-learn. So Apply (or
// Stop) is invoked only when the effective LLDP config actually changed from the
// last-applied one, matching the diff discipline of the adjacent
// reconcileDHCPRelay (#2348). The first call (boot) always applies.
//
// The manager is bound to d.daemonCtx (the daemon lifetime) — NOT a
// request-scoped context — so the TX/RX/expiry goroutines survive past this
// apply call and are torn down only at daemon stop (or the next reconcile that
// disables LLDP).
func (d *Daemon) reconcileLLDP(cfg *config.Config) {
	if d.lldpMgr == nil {
		// Defensive: a test harness or a boot path that skipped the construct-
		// once wiring leaves the manager nil. Nothing to reconcile.
		return
	}

	want := effectiveLLDPConfig(cfg)

	// Skip when the effective config is unchanged since the last reconcile, so
	// an unrelated commit never bounces a healthy LLDP generation (sockets +
	// neighbor table). The first reconcile (boot) always runs.
	//
	// #6794: "unchanged config" is not sufficient on its own. Manager.Apply is
	// PARTIAL — it brings each interface up independently and skips the ones it
	// cannot resolve — so a generation can be live for some interfaces and dark
	// for others while the config is entirely unchanged. The desired config used
	// to be recorded as applied BEFORE Apply ran, so an incomplete generation
	// was indistinguishable from a healthy one and every later reconcile took
	// this early return. Recovery then required a change to `protocols lldp` or
	// a daemon restart — on a box where the only thing wrong was that a NIC
	// showed up a moment after boot.
	//
	// lldpRecoveryDue re-tests exactly the interfaces the last Apply could not
	// resolve. It gates on the WORLD having changed in a way that could fix
	// them, not on time or on a retry counter, so a permanently-absent
	// interface (a typo in the config) never resolves, never triggers a retry,
	// and cannot churn the generation on every commit — which is the #2372
	// finding-6 regression this guard exists to prevent.
	if d.lldpApplyInit && lldpConfigEqual(d.lldpApplied, want) && !d.lldpRecoveryDue() {
		return
	}

	if want == nil {
		// Disabled / empty: stop the running service (idempotent if already
		// stopped). Stop cannot partially fail, so there is no unresolved set
		// to carry: record convergence directly.
		d.lldpMgr.Stop()
		d.lldpApplyInit = true
		d.lldpApplied = want
		d.lldpUnresolved = nil
		return
	}

	ctx := d.daemonCtx
	if ctx == nil {
		ctx = context.Background()
	}
	// Record what the apply ACHIEVED, and record it AFTER the apply. The
	// unresolved set is the ground truth that makes an incomplete generation
	// distinguishable from a converged one.
	unresolved := d.lldpMgr.Apply(ctx, want)
	d.lldpApplyInit = true
	d.lldpApplied = want
	d.lldpUnresolved = unresolved
	if len(unresolved) > 0 {
		slog.Warn("LLDP: generation is INCOMPLETE — these configured interfaces could not be "+
			"resolved and are dark; they will be retried automatically as soon as they appear, "+
			"without needing a config change",
			"interfaces", unresolved)
	}
}

// lldpRecoveryDue reports whether any interface the last Apply could not
// RESOLVE now resolves, i.e. whether re-applying could bring a dark interface
// up (#6794).
//
// This is the whole reason the unchanged-config guard is safe to keep. It gates
// the retry on an observable change in the world rather than on time or a
// counter, so:
//
//   - a NIC that showed up after boot (renamed by a .link file, created as a
//     VLAN/tunnel, brought up late) resolves on the next reconcile and the
//     generation is rebuilt — recovery on an UNCHANGED config, which is what
//     #6794 is about; and
//   - an interface that is permanently absent (a typo, a NIC that was removed)
//     never resolves, so this never fires and an unrelated commit never bounces
//     a generation that is as complete as it can be.
//
// It deliberately re-tests only the previously-UNRESOLVED names. Testing the
// whole desired set would fire on nothing, and testing the interfaces that
// failed at the SOCKET layer would retry a condition that does not self-heal
// (see Manager.Apply).
func (d *Daemon) lldpRecoveryDue() bool {
	for _, name := range d.lldpUnresolved {
		if lldp.InterfaceResolvable(name) {
			return true
		}
	}
	return false
}

// initEventEngine constructs the event-options engine and registers the RPM
// event callback (#3752). Like the LLDP manager and the DHCP relay manager, it
// is created UNCONDITIONALLY at boot — not gated on the boot config already
// carrying an event-options policy — so:
//
//   - the d.eventEngine pointer is written exactly ONCE at boot and read-only
//     thereafter, keeping the lock-free reads on the `Stats()` metric/CLI
//     handler goroutines race-free (the same pointer-race discipline #2372
//     established for d.lldpMgr); and
//   - a day-2 commit enabling the FIRST event-options policy takes effect
//     immediately via reconcileEventOptions, instead of being inert until a
//     daemon restart (the #3752 defect).
//
// The engine routes its remediation commit through d.commitAndApply so it
// serializes with HTTP/gRPC commits under d.applySem (#846). Event-options
// changes do not sync to the peer — the engine fires independently on each
// node from that node's local RPM events. Idempotent: a second call is a no-op.
func (d *Daemon) initEventEngine() {
	if d.eventEngine != nil {
		return
	}
	d.eventEngine = eventengine.New(d.store, func(ctx context.Context, comment string) (*config.Config, error) {
		// #6808: the event engine is an autonomous system committer with no
		// config-lock session, so it states that explicitly. It must never be
		// the zero authority, which is rejected.
		return d.commitAndApply(ctx, configstore.InternalCommitter(), comment, peerSyncNever)
	})
	if d.rpm != nil {
		d.rpm.SetEventCallback(d.eventEngine.HandleEvent)
	}
	slog.Info("event-options engine constructed")
}

// reconcileEventOptions applies the committed event-options policy set to the
// engine on every commit (#3752). The engine is constructed once at boot
// (initEventEngine); this only ever calls Apply, which RECONCILES per-policy
// runtime state (carrying cooldown/window memory forward for unchanged
// policies, #2140). It NEVER reassigns the pointer. A nil cfg (or empty policy
// set) applies zero policies — a no-op that also clears a removed set.
func (d *Daemon) reconcileEventOptions(cfg *config.Config) {
	if d.eventEngine == nil {
		// Defensive: boot wiring constructs the engine before any reconcile.
		return
	}
	var policies []*config.EventPolicy
	if cfg != nil {
		policies = cfg.EventOptions
	}
	d.eventEngine.Apply(policies)
}

// lldpConfigEqual reports whether two effective LLDP configs are equivalent for
// reconcile purposes (both nil, or deeply equal). nil means "service stopped".
func lldpConfigEqual(a, b *lldp.LLDPConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.DeepEqual(a, b)
}

func (d *Daemon) publishInitialPolicySchedulerStateLocked(cfg *config.Config, activeState map[string]bool, applyResult *dataplane.ApplyResult) {
	rt := d.dataplane()
	if rt == nil || activeState == nil || applyResult == nil {
		return
	}
	if _, isUserspace := rt.(userspaceRuntimeModeReporter); isUserspace {
		return
	}
	// #3780: initial (eBPF-path) publish rides the apply transaction; a
	// failure here is surfaced via the same republish-failure metric so
	// it is not silently swallowed. The retired eBPF updater always
	// reports success, so this is a no-op there today.
	d.recordSchedulerRepublishResult(d.updatePolicyScheduleStateLocked(cfg, activeState))
}

// strictSessionAuthEnabled reads the #7441 node-local posture off a compiled
// config, nil-safe at every level so a config with no chassis-cluster stanza
// reports the pre-#7441 default (off).
func strictSessionAuthEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.Chassis.Cluster != nil && cfg.Chassis.Cluster.StrictSessionAuth
}
