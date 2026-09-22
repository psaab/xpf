package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initControlPlaneDescriptors() {
	c.neighborPeriodicAge = prometheus.NewDesc(
		"xpf_daemon_neighbor_periodic_last_success_age_seconds",
		"Seconds since each Go periodic neighbor-maintenance phase "+
			"last completed. A monotonically climbing value means that "+
			"phase's guarded goroutine is wedged on a stuck netlink/probe "+
			"syscall (#1780).",
		[]string{"phase"}, nil,
	)
	c.frrReloadDegraded = prometheus.NewDesc(
		"xpf_frr_reload_degraded",
		"1 while the last applied FRR reload fell back to the additive "+
			"vtysh -f path (full frr-reload.py diff failed) and the "+
			"in-manager retry has not yet converged; stale-config "+
			"removal is deferred while set (#1880). Alert if 1 for >10m "+
			"(twice the 5m slow retry; paired with a failed commit, #9947).",
		nil, nil,
	)
	c.frrPolicyChainsNarrowed = prometheus.NewDesc(
		"xpf_frr_policy_chains_narrowed",
		"Number of BGP policy-chain attachments in the last rendered FRR "+
			"managed section whose applied chain is a strict, non-empty subset "+
			"of what the operator authored, because some member names an "+
			"undefined policy-statement (#8363). Non-zero means those neighbors "+
			"are still filtered but by LESS than was configured — routes are "+
			"NOT withdrawn, which is why this is separate from "+
			"xpf_frr_route_maps_quarantined. Alert on > 0.",
		nil, nil,
	)
	c.frrPolicyChainsNarrowedDenySafe = prometheus.NewDesc(
		"xpf_frr_policy_chains_narrowed_deny_safe",
		"Subset of xpf_frr_policy_chains_narrowed whose undefined members form "+
			"a SUFFIX of the authored chain. For those a synthesized deny would "+
			"be safe; for the complement it would DELETE the surviving members, "+
			"because FRR's composed route-map stops at the first member with a "+
			"terminating default action (#8363). Published to size that decision "+
			"on how often the safe shape occurs. Not an alert on its own.",
		nil, nil,
	)
	c.frrPolicyChainsNarrowedShape = prometheus.NewDesc(
		"xpf_frr_policy_chains_narrowed_shape",
		"Number of narrowed BGP policy-chain attachments in the last rendered "+
			"FRR managed section by survivor-body shape (#10129). Shapes are "+
			"fall-through, empty, terminating-default, match-all, quarantined, "+
			"or unknown; the existing xpf_frr_policy_chains_narrowed gauge "+
			"remains the total population.",
		[]string{"shape"}, nil,
	)
	c.frrRouteMapsQuarantined = prometheus.NewDesc(
		"xpf_frr_route_maps_quarantined",
		"Number of route-maps in the last rendered FRR managed section that "+
			"were replaced with a bounded explicit DENY because the policy's "+
			"expansion would overflow FRR's sequence ceiling (#5701/#5732/"+
			"#6807). Non-zero means every route on the BGP neighbors carrying "+
			"those attachments is being WITHDRAWN — FRR denies a route-map "+
			"name it cannot otherwise resolve — until the policy is reduced "+
			"or detached. Alert on > 0.",
		nil, nil,
	)
	c.natRulesLenientTerminalAction = prometheus.NewDesc(
		"xpf_nat_rules_lenient_terminal_action",
		"Number of NAT rules in the ACTIVE config that the tolerant load / "+
			"peer-sync / rollback path admitted despite the strict "+
			"terminal-action cardinality gate rejecting them (#5628/#7640). "+
			"Non-zero means this node is running a rule a commit would refuse: "+
			"an ACTIONLESS rule installs no translation and (source NAT) does "+
			"not stop rule evaluation, so matching traffic falls through to any "+
			"later broader rule; a CONTRADICTORY rule has all but one action "+
			"discarded by a fixed precedence the operator did not write. The "+
			"warning that reports this at compile time reaches an operator only "+
			"through a commit response, which a tolerant LOAD does not have — "+
			"so before this gauge the surviving rules were invisible for the "+
			"life of the node. Alert on > 0; `show security nat source rule "+
			"detail` names them.",
		nil, nil,
	)
	c.ipsecRebindPending = prometheus.NewDesc(
		"xpf_ipsec_rebind_pending",
		"1 while the last DHCP-lease-change IPsec rebind failed and has "+
			"not yet reconverged (#4899): a DHCP renewal moved the kernel "+
			"address an IPsec gateway is dynamically bound to "+
			"(external-interface, no explicit local-address), but the "+
			"swanctl re-render/reload failed, so strongSwan keeps binding "+
			"the STALE lease address and the tunnel cannot re-establish. "+
			"The daemon retries the rebind autonomously; 0 once swanctl "+
			"local_addrs reconverge on the current lease.",
		nil, nil,
	)
	// #6802: a failed host-inbound conntrack revocation is deliberately NOT a
	// commit failure — the nft table is already applied, so enforcement for NEW
	// connections holds, and rolling the commit back over a transient conntrack
	// error would discard correct enforcement. But before #6802 it was not
	// anything ELSE either: no return value, no dirty flag, no counter, no
	// metric and no retry owner. These two series are that missing signal.
	c.hostInboundConntrackRevocationPending = prometheus.NewDesc(
		"xpf_host_inbound_conntrack_revocation_pending",
		"1 while a host-inbound kernel-conntrack revocation has failed and "+
			"has not yet been re-driven (#6802). The failure is fail-OPEN: an "+
			"established direct-kernel connection to a service the operator "+
			"has REMOVED keeps riding the host-inbound chain's leading "+
			"`ct state established,related accept`, so a now-denied host "+
			"service stays reachable on that connection. The daemon re-drives "+
			"the owed revocation autonomously every 30s; 0 once it succeeds.",
		nil, nil,
	)
	c.hostInboundConntrackRevocationFailures = prometheus.NewDesc(
		"xpf_host_inbound_conntrack_revocation_failures_total",
		"Total host-inbound kernel-conntrack revocation failures (#6802). "+
			"Counts every failed attempt including retries, so a value that "+
			"climbs while xpf_host_inbound_conntrack_revocation_pending stays "+
			"1 means the retry owner is running but not converging.",
		nil, nil,
	)
	// #6800: an xpf-managed service configuration file converges on disk and the
	// applier then gates its RUNTIME reload on "did the on-disk set change".
	// That gate erased the debt of a FAILED reload — the file was already
	// converged, so every later apply saw no change and skipped the reload — and
	// the node kept serving the previous ruleset with no signal anywhere. These
	// two series are that missing signal; the retry owner is the other half.
	c.managedServiceReloadPending = prometheus.NewDesc(
		"xpf_managed_service_reload_pending",
		"1 while an xpf-managed service configuration file has converged on "+
			"disk but the RUNTIME reload that would load it has not succeeded "+
			"(#6800). Labelled by service: `rsyslog` means the managed "+
			"/etc/rsyslog.d drop-ins are on disk but rsyslog has not re-read "+
			"them, so records may still be flowing to a destination the "+
			"operator REMOVED; `chrony-sources` and `chrony-threshold` mean "+
			"chrony is still running the previous server set or "+
			"logchange/maxchange. The daemon re-drives the owed reload "+
			"autonomously every 30s; 0 once it succeeds.",
		[]string{"service"}, nil,
	)
	c.managedServiceReloadFailures = prometheus.NewDesc(
		"xpf_managed_service_reload_failures_total",
		"Total failed runtime-reload attempts per xpf-managed service (#6800). "+
			"Counts retries too, so a value that climbs while "+
			"xpf_managed_service_reload_pending stays 1 means the retry owner "+
			"is running but not converging — a masked or failed unit, say — "+
			"rather than a single transient failure already paid.",
		[]string{"service"}, nil,
	)
	// #7615: the remaining debt-driven retry owners. Two siblings already
	// publish (#6800, #6802); these complete the family. Proxy-ARP joined in
	// #7685 — not by a drift predicate, which reports a routine self-corrected
	// event, but by the debt its reconcile already held.
	c.raDeadSenderPending = prometheus.NewDesc(
		"xpf_ra_dead_sender_pending",
		"1 while a router-advertisement sender's asynchronous conn open has "+
			"failed and has not yet been rebuilt (#6793). While set, that "+
			"interface is advertising NOTHING and hosts on the segment get no "+
			"default route from this firewall — on a node whose commit reported "+
			"success. The daemon rebuilds it autonomously every 30s; 0 once it "+
			"succeeds.",
		nil, nil,
	)
	c.proxyARPUnresolved = prometheus.NewDesc(
		"xpf_proxy_arp_unresolved_pending",
		"1 while a CONFIGURED proxy-arp interface failed to resolve to a Linux "+
			"netdev on the most recent reconcile (#7685). While set, proxy-arp "+
			"is configured on that interface and the responder is NOT answering "+
			"— the reconcile could not enable it and retains its prior state as "+
			"debt rather than tearing it down (#6536) — on a node whose commit "+
			"reported success. Unlike a drifted sysctl, which the always-on loop "+
			"re-asserts on its next tick, this does not clear until the "+
			"interface exists. 0 once it resolves or proxy-arp is unconfigured.",
		nil, nil,
	)
	c.fabricOverlayMissing = prometheus.NewDesc(
		"xpf_fabric_overlay_missing",
		"1 while a configured fabric IPVLAN (fab0/fab1) is absent or down "+
			"(#6791). While set the node has NO cluster heartbeat and no "+
			"session-sync transport, so a peer cannot distinguish it from a dead "+
			"node. The daemon re-creates it autonomously every 30s; 0 once the "+
			"overlay is present and admin-up.",
		nil, nil,
	)
	c.managementListenerDown = prometheus.NewDesc(
		"xpf_management_listener_down",
		"1 while a management listener the configuration asks for is not "+
			"serving (#6803). This is the failure an operator is least able to "+
			"observe by other means, because the channel they would use to look "+
			"is the channel that is down. The daemon rebinds it autonomously "+
			"every 30s; 0 once it is serving.",
		nil, nil,
	)
	// #8195: the state of EACH management listener, with its address.
	//
	// xpf_management_listener_down above is kept exactly as it is — dashboards
	// and alerts already reference it — and this ADDS what it cannot express.
	// Three things it cannot:
	//
	//   1. It is a bare 0/1 with NO ADDRESS, so an operator cannot tell WHICH
	//      endpoint failed to bind, which is the first question asked.
	//   2. It reads the HTTP leg only (mgmtListenerDown ->
	//      effectiveHTTPListener), so the gRPC listener is absent entirely.
	//   3. It collapses three states into two. StateDisabled — a listener the
	//      configuration deliberately turned off — is indistinguishable from
	//      StateListening at 0, and telling a genuinely-off listener from a
	//      serving one is the distinction `show system services` already draws.
	//
	// The gRPC leg is the one this exists for. Its state's only consumer today
	// is `show system services`, reachable over the gRPC listener itself — so
	// when it fails, the surface that reports the failure is the surface that
	// is down. That circularity is why a metric, scraped over the SEPARATE
	// HTTP listener, is the right shape rather than another CLI verb.
	//
	// Emitted as a state set: one series per (surface, state) with value 1 for
	// the current state and 0 for the others, the standard Prometheus encoding
	// for an enum. A single gauge with a numeric state would make
	// `listener_state == 2` a magic constant in every alert.
	c.managementListenerState = prometheus.NewDesc(
		"xpf_management_listener_state",
		"1 for the management listener's CURRENT state, 0 for its other states "+
			"(#8195). Labelled by surface (grpc/http), the bind address, and the "+
			"state (listening/failed/disabled). Complements "+
			"xpf_management_listener_down, which is HTTP-only, address-less and "+
			"cannot distinguish a deliberately disabled listener from a serving "+
			"one. The gRPC row is the load-bearing one: its only other consumer "+
			"is `show system services`, which is reached OVER the gRPC listener.",
		[]string{"surface", "address", "state"}, nil,
	)
	// #8397: helper crash episodes recovered from. A COUNTER, not a gauge, and
	// that is the whole point: `restartHelperAfterCrash` wipes the crash record
	// on success, so every gauge-shaped view of crash state reads clean the
	// moment the helper is healthy again. A helper that crashed four times in
	// the last hour and is running now presents a spotless surface to every
	// other signal here.
	//
	// A counter is also what crosses a DAEMON restart, which the in-process
	// history ring deliberately does not: the ring answers "what happened" for
	// an operator in session, the counter answers "is this recurring" for an
	// alert over a window. `rate()` on this is the alert; the ring is the
	// follow-up once the alert fires.
	c.helperCrashEpisodesTotal = prometheus.NewDesc(
		"xpf_dataplane_helper_crash_episodes_total",
		"Total unexpected userspace-dataplane-helper exits this daemon has "+
			"RECOVERED from (#8397). Monotonic within a daemon lifetime and "+
			"reset by a daemon restart, like any process-scoped counter. This "+
			"is the only crash signal that survives a successful restart: the "+
			"helper crash record is wiped on recovery, so a recurring crasher "+
			"is invisible to every other field once it is healthy again. "+
			"Per-episode detail is on `show chassis forwarding`.",
		nil, nil,
	)
	// #8447: whether the userspace dataplane is FORWARDING at all.
	//
	// A capability gate can set ForwardingSupported=false and disarm every
	// binding, which takes rx to 0 while the interfaces stay up and the config
	// commits cleanly. What was missing is any signal an ALERT could key on --
	// the only surface was a line inside a `show` nobody runs when the symptom
	// is "the link went down", and #8447 spent five rounds of cluster
	// measurement rediscovering it.
	//
	// #8573 REMOVED the case this gauge was written around. Persistent-NAT on a
	// chassis cluster used to disarm on the #1449 reasoning that leases are
	// helper-local and not HA-synchronized; measured on the loss userspace
	// cluster, they reach the standby, survive an RG0 failover, and are honoured
	// after failback, so the disarm is gone. This gauge is unchanged and is
	// MORE load-bearing for it: the remaining reasons are rarer, so a disarm is
	// now something an operator is even less likely to be looking for.
	//
	// A gauge rather than a state set, because the states are exhaustive and
	// binary: 1 and 0 are both carried by the one series, so there is no
	// absent-series-reads-as-healthy hazard here. The REASONS are not labels --
	// they are an unbounded operator-facing list, and a label set that grows
	// with config content is a cardinality problem. They are on
	// `show chassis forwarding` and in the #8503 disarm warning.
	c.forwardingSupported = prometheus.NewDesc(
		"xpf_dataplane_forwarding_supported",
		"1 when the userspace dataplane is forwarding transit, 0 when a "+
			"capability gate has disarmed it (#8447). 0 means the interfaces are "+
			"up and the config committed cleanly and NO transit is being "+
			"processed -- the failure presents as a connectivity problem rather "+
			"than a configuration one. The reasons are on "+
			"`show chassis forwarding` and in the disarm warning; they are "+
			"unsupported-configuration verdicts such as a color-aware "+
			"three-color policer or a SYN-cookie screen profile without "+
			"root-authentication material.",
		nil, nil,
	)
	c.ipsecCaptureActorActive = prometheus.NewDesc(
		"xpf_ipsec_capture_actor_active",
		"1 when the authenticated S5 capture actor is active; omitted when no product-owned actor witness is available (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCapturePermitState = prometheus.NewDesc(
		"xpf_ipsec_capture_permit_state",
		"1 for the current S5 permit state and 0 for the other enum states; labels join the Rust s5_reinject status block (#10478).",
		[]string{"run_id", "generation", "permit_epoch", "state"}, nil,
	)
	c.ipsecCaptureConsumedTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_consumed_total",
		"Capture frames received by the S5 actor boundary (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureAdjudicatedTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_adjudicated_total",
		"Capture frames entering S5 q0 adjudication (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureReinjectedTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_reinjected_total",
		"Frames with a terminal q0 Written outcome; this is not downstream delivery (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureWrittenTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_written_total",
		"Terminal q0 Written completions attributed by the Go actor; exported beside reinjected to prove the attribution live (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureUncertainTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_uncertain_total",
		"Completions the Go actor could not attribute to a terminal q0 outcome: lease or byte-count mismatch, advisory outcome, submit loss, completion-drain error, terminal-sink error, or ack timeout; timeouts are also counted here, so do not sum Timeouts on top (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureLateCompletionsTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_late_completions_total",
		"Completions arriving for unknown or already-retired request IDs; never counted as reinjected (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureTimeoutsTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_timeouts_total",
		"Held q0 requests retired by ack timeout before any completion resolved them (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureStaleTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_stale_total",
		"Terminal completions refused as stale or fenced (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureCancelledTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_cancelled_total",
		"Terminal completions classified as cancelled by the Go actor after q0 cancellation (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureRefusedTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_refused_total",
		"Frames refused by lease minting, admission, or a terminal q0 refused/denied completion (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureD11SuppressedTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_suppressed_total",
		"D11 selected frames suppressed after a terminal WouldPermit completion (#10484).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureD11Deny52Total = prometheus.NewDesc(
		"xpf_ipsec_capture_deny_events_total",
		"D11 deny events emitted for evaluator-unavailable reason 52 (#10484).",
		[]string{"run_id", "generation", "permit_epoch", "reason"}, nil,
	)
	c.ipsecCaptureDeliveredAvail = prometheus.NewDesc(
		"xpf_ipsec_capture_delivered_available",
		"1 only when an independent product-owned witness downstream of the TUN write exists; never inferred from Written (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.ipsecCaptureDeliveredTotal = prometheus.NewDesc(
		"xpf_ipsec_capture_delivered_total",
		"Independent downstream delivery witness; omitted as a count when unavailable (#10478).",
		[]string{"run_id", "generation", "permit_epoch"}, nil,
	)
	c.schedulerRepublishFailed = prometheus.NewDesc(
		"xpf_scheduler_republish_failed",
		"1 while the most recent scheduler-driven policy republish "+
			"failed and has not yet converged (#3780): stale "+
			"enforcement is live past a schedule window — a scheduled "+
			"permit may still be forwarding after its window closed, or "+
			"a scheduled block never engaged. The daemon retries the "+
			"transition autonomously on each scheduler tick; 0 when the "+
			"enforcement snapshot is in sync with the schedule state.",
		nil, nil,
	)
	c.schedulerRepublishStale = prometheus.NewDesc(
		"xpf_scheduler_republish_stale_seconds",
		"Seconds since the current scheduler-republish failure streak "+
			"began (#3780); 0 when healthy. A climbing value means "+
			"enforcement has been out of sync with the schedule window "+
			"for that long while the daemon retries.",
		nil, nil,
	)
	c.schedulerRepublishFailClosed = prometheus.NewDesc(
		"xpf_scheduler_republish_fail_closed",
		"1 while the scheduler-republish failure streak has persisted past "+
			"the bounded age and the scheduler has escalated to FAIL-CLOSED "+
			"(#5669): scheduled policies are forced inactive (deny) so a "+
			"scheduled permit stops forwarding past its window close instead "+
			"of relying on an eventual republish recovery. 0 when healthy or "+
			"still inside the bounded retry window (xpf_scheduler_republish_"+
			"failed=1, xpf_scheduler_republish_stale_seconds climbing).",
		nil, nil,
	)
	c.configPersistDegraded = prometheus.NewDesc(
		"xpf_daemon_config_persist_degraded",
		"1 while configuration persistence is degraded: the running "+
			"active config failed to persist and the background retry "+
			"has not yet succeeded (a restart would load a stale config, "+
			"#1799), or a resolved commit-confirmed record's removal is "+
			"not yet durable (#5835), or boot recovery could not read "+
			"confirm.json and the pending rollback window was lost "+
			"(#8566); 0 when config persistence is healthy.",
		nil, nil,
	)
	c.rollbackHistoryDegraded = prometheus.NewDesc(
		"xpf_config_rollback_persist_degraded",
		"1 while the most recent commit failed to durably persist its "+
			"text rollback-history files (the canonical rollback "+
			"history, #3441); 0 when healthy. The commit still "+
			"succeeded and the active config is durable (#1799) — this "+
			"flags a degraded recovery aid, not a forwarding outage.",
		nil, nil,
	)
	c.journalPermsDegraded = prometheus.NewDesc(
		"xpf_config_journal_perms_degraded",
		"1 while journal permission repair is degraded: a pre-existing "+
			"segment could not be tightened to owner-only 0600 and "+
			"world-readable history (which may carry operator free text) "+
			"may still be exposed (#9898 F-113); 0 when repair is clean. "+
			"Appends continue — a confidentiality exposure on a recovery "+
			"aid, not a forwarding outage.",
		nil, nil,
	)
	c.userspacePolicyContentRejected = prometheus.NewDesc(
		"xpf_userspace_policy_content_rejected",
		"1 while the most recently built userspace snapshot carries "+
			"unrepresentable policy content (a policy names an "+
			"application protocol/port or address the matcher cannot "+
			"represent) that the helper integrity preflight rejects "+
			"(#3261). The helper stays armed and retains the "+
			"previous-good policy state (a fresh boot lands on "+
			"default-deny) — it never fails open to the kernel. Nonzero "+
			"means the running dataplane policy is NOT the committed "+
			"config; edit out the offending application/address and "+
			"re-commit. 0 when the last build was fully representable.",
		nil, nil,
	)
	c.userspaceZoneIDCollision = prometheus.NewDesc(
		"xpf_userspace_zone_id_collision",
		"1 while the most recently built userspace snapshot QUARANTINED "+
			"one or more security zones because two zone names fold to the "+
			"same StableZoneID (#3719). The strict commit path rejects a "+
			"collision; this fires only on the lenient / HA-sync / "+
			"pre-#3075-persisted path, where the later-sorting zone is "+
			"dropped from the dataplane (its interfaces unzoned, its "+
			"traffic denied) so two zones never share an id. The dataplane "+
			"is fail-closed, but zone isolation is DEGRADED (the "+
			"quarantined zone forwards nothing) until an operator renames "+
			"one zone and re-commits. 0 when every zone has a distinct id.",
		nil, nil,
	)
	c.rpmPinInstallFailures = prometheus.NewDesc(
		"xpf_rpm_probe_pin_install_failures",
		"Number of RPM next-hop probe pins whose kernel fwmark rule / "+
			"pinned route failed to install. Affected tests hold their "+
			"prior state (ErrProbeSetup) instead of probing the default "+
			"path, so a nonzero value means those uplinks are NOT being "+
			"health-checked (#1895).",
		nil, nil,
	)
}
