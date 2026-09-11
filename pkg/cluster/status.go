package cluster

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// FormatStatus returns a Junos-style status string for all RGs.
func (m *Manager) FormatStatus() string {
	states := m.GroupStates()
	m.mu.RLock()
	peerAlive := m.peerAlive
	peerNodeID := m.peerNodeID
	localVersion := m.localSoftwareVersion
	peerVersion := m.peerSoftwareVersion
	localProtocol := normalizeHAProtocolVersion(m.localHAProtocolVersion)
	peerProtocol := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
	configSyncFailing := m.configSyncFailing // #6387: node-global CF annotation
	takeoverHold := m.takeoverHoldTime       // #103: hold is part of eligibility
	// #6495: read the REASON, not just the flag. The daemon sets this one flag
	// for two materially different conditions (an armed candidate, and the
	// #5682 fail-closed unreadable-journal hold) whose remedies differ, so
	// rendering "held" without saying WHICH is the same blindness one layer in.
	// Guarded on the flag: the reason field is only meaningful while held.
	kernelHold := ""
	if m.kernelUpgradeHold {
		kernelHold = m.kernelUpgradeHoldReason
	}
	rgForwardingFn := m.rgForwardingFn
	peerGroups := make(map[int]PeerGroupState, len(m.peerGroups))
	for k, v := range m.peerGroups {
		peerGroups[k] = v
	}
	m.mu.RUnlock()

	var b strings.Builder
	fmt.Fprintln(&b, "Monitor Failure codes:")
	fmt.Fprintln(&b, "    CS  Cold Sync monitoring        FL  Fabric Connection monitoring")
	fmt.Fprintln(&b, "    IF  Interface monitoring        IP  IP monitoring")
	fmt.Fprintln(&b, "    CF  Config Sync monitoring")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Cluster ID: %d\n", m.clusterID)
	fmt.Fprintf(&b, "Node name: node%d\n", m.nodeID)
	// #6495: a node parked SECONDARY by the kernel-candidate promotion gate is
	// otherwise INDISTINGUISHABLE from one demoted by a monitor failure or a
	// manual failover. That is the wrong ambiguity to leave during a kernel
	// roll, which is exactly when an operator is deciding whether what they
	// are looking at is the expected gate or a real problem.
	//
	// NODE-scoped, so it is rendered ONCE here and not per-RG: the hold holds
	// the whole node SECONDARY regardless of how many redundancy groups exist,
	// and a node with no RGs configured yet would show nothing at all from
	// inside the per-RG loop.
	//
	// Position is load-bearing. deploy_rolling_secondary_node
	// (test/incus/deploy-lib.sh) picks the RG0 secondary by awk-matching
	// $1 == "node0" INSIDE a "Redundancy group: N" block. This line sits above
	// every such header (so no RG is in scope when awk reads it) and its first
	// field is "Held", not a node token — a line that could be read as a node
	// row would steer a rolling cluster deploy into restarting the PRIMARY
	// first (#4009).
	if kernelHold != "" {
		fmt.Fprintf(&b, "Held secondary: %s\n", kernelHold)
	}
	fmt.Fprintln(&b)
	if localVersion != "" {
		fmt.Fprintf(&b, "Software version: %s\n", localVersion)
	}
	fmt.Fprintf(&b, "HA protocol version: %d\n", localProtocol)
	// #7990: the session-sync WIRE version is a SEPARATE counter from the HA
	// protocol version (#7925), and the LANE-1 rolling drain gate reads these
	// lines to decide whether a handover can carry sessions. Rendered next to
	// the HA lines because an operator comparing two nodes needs both, and
	// because they are exactly the pair the mixed-base image gate compares.
	fmt.Fprintf(&b, "Session-sync wire version: %d\n", SessionSyncWireVersion)
	if peerAlive {
		if peerVersion == "" {
			peerVersion = "unknown"
		}
		fmt.Fprintf(&b, "Peer software version: %s\n", peerVersion)
		fmt.Fprintf(&b, "Peer HA protocol version: %d\n", peerProtocol)
		// 0 renders as "unknown" rather than "0": there is no valid sync wire
		// version 0, so printing the number would invite a reader (or a parser)
		// to compare it as one. A peer that advertises nothing predates #7990.
		if pw := m.PeerSessionSyncWireVersion(); pw == 0 {
			fmt.Fprintf(&b, "Peer session-sync wire version: unknown\n")
		} else {
			fmt.Fprintf(&b, "Peer session-sync wire version: %d\n", pw)
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "%-6s %-8s %-14s %-8s %-8s %s\n",
		"Node", "Priority", "Status", "Preempt", "Manual", "Monitor-failures")
	fmt.Fprintln(&b)

	for _, rg := range states {
		fmt.Fprintf(&b, "Redundancy group: %d , Failover count: %d\n",
			rg.GroupID, rg.FailoverCount)
		preempt := "no"
		if rg.Preempt {
			preempt = "yes"
		}
		manual := "no"
		if rg.ManualFailover {
			manual = "yes"
		}
		monFails := "None"
		if len(rg.MonitorFails) > 0 {
			monFails = strings.Join(rg.MonitorFails, ", ")
		}
		// #6387: fold the node-global CF config-sync monitor-failure into the
		// Monitor-failures column for every RG row. It is a dedicated manager
		// field (not an rg.MonitorFails entry) so reconcileMonitorDebtsLocked
		// cannot wipe it on the next UpdateConfig.
		if configSyncFailing {
			if monFails == "None" {
				monFails = "CF"
			} else {
				monFails += ", CF"
			}
		}
		// #103 item 5: report the property ELECTION gates on
		// (IsReadyForTakeover), not the weaker rg.Ready. Inside the
		// takeover-hold window the RG is Ready but every election gate still
		// declines to promote it, so a bare "yes" here would contradict the
		// election with nothing naming the hold. With takeover-hold-time
		// unset (the default 0) this branch never fires and the line is
		// unchanged.
		readyStr := "yes"
		if !rg.Ready {
			readyStr = "no"
			if len(rg.ReadinessReasons) > 0 {
				readyStr = "no (" + strings.Join(rg.ReadinessReasons, ", ") + ")"
			}
		} else if hold := rg.TakeoverHoldRemaining(takeoverHold); hold > 0 {
			readyStr = fmt.Sprintf("no (takeover hold: %s of %s remaining)",
				hold.Round(time.Millisecond), takeoverHold)
		}
		transferReadyStr := "yes"
		if !rg.TransferReady {
			transferReadyStr = "no"
			if len(rg.TransferReadinessReasons) > 0 {
				transferReadyStr = "no (" + strings.Join(rg.TransferReadinessReasons, ", ") + ")"
			}
		}
		// Local node line.
		fmt.Fprintf(&b, "%-6s %-8d %-14s %-8s %-8s %s\n",
			fmt.Sprintf("node%d", m.nodeID),
			rg.LocalPriority, rg.State, preempt, manual, monFails)
		fmt.Fprintf(&b, "  Takeover ready: %s\n", readyStr)
		fmt.Fprintf(&b, "  Transfer ready: %s\n", transferReadyStr)
		// #7367: the forwarding sub-line. Placed AFTER the local node row and
		// the two existing sub-lines, and indented, because the render is parsed
		// by whole-line regexes: test-failover.sh does
		// `grep -A1 "Redundancy group: $rg" | grep -q "node0.*primary"`, so a
		// line inserted BETWEEN the header and the node row would consume the -A1
		// window and break the smoke. Its first field is "Forwarding:", not a node
		// token, for the same reason "Held secondary:" is (#4009).
		if rgForwardingFn != nil {
			if fwd, ok := rgForwardingFn(rg.GroupID); ok {
				fmt.Fprintf(&b, "  Forwarding: %s\n",
					FormatRGForwarding(rg.State == StatePrimary, fwd))
			}
		}
		// Peer node line (if alive).
		if peerAlive {
			if pg, ok := peerGroups[rg.GroupID]; ok {
				// #7367: when THIS node substituted the peer's state, say so.
				// Rendering the substituted value bare makes a locally-forced
				// secondary-hold identical to one the peer reported, which is
				// how an RG-ownership divergence can show as a healthy cluster
				// on both nodes at once.
				peerState := fmt.Sprintf("%v", pg.State)
				if pg.StateOverriddenLocally {
					reason := pg.OverrideReason
					if reason == "" {
						reason = "local override"
					}
					peerState = fmt.Sprintf("%v (local: %s)", pg.State, reason)
				}
				fmt.Fprintf(&b, "%-6s %-8d %-14s %-8s %-8s %s\n",
					fmt.Sprintf("node%d", peerNodeID),
					pg.Priority, peerState, preempt, "no", "None")
			}
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}

// FormatInformation returns detailed cluster information matching vSRX output.
func (m *Manager) FormatInformation() string {
	m.mu.RLock()
	peerAlive := m.peerAlive
	peerNodeID := m.peerNodeID
	localVersion := m.localSoftwareVersion
	peerVersion := m.peerSoftwareVersion
	localProtocol := normalizeHAProtocolVersion(m.localHAProtocolVersion)
	peerProtocol := normalizeHAProtocolVersion(m.peerHAProtocolVersion)
	// #5081: report what the heartbeat is ACTUALLY running with. The
	// committed interval/threshold are not applied to a running heartbeat
	// (nothing restarts it for a timing change), so rendering the desired
	// values told the operator the new timing was in effect when the wire
	// was still on the old one. When they differ the pending values are
	// named on their own line instead of silently replacing the live ones.
	interval, threshold := m.liveHeartbeatTimingLocked()
	desiredInterval := m.hbInterval
	desiredThreshold := m.hbThreshold
	controlIface := m.controlInterface
	configSyncFailing := m.configSyncFailing   // #6387
	configSyncReason := m.configSyncFailReason // #6387
	takeoverHold := m.takeoverHoldTime         // #103
	// #6495: the hold REASON, not just the flag (see FormatStatus).
	kernelHold := ""
	if m.kernelUpgradeHold {
		kernelHold = m.kernelUpgradeHoldReason
	}
	m.mu.RUnlock()

	states := m.GroupStates()

	var b strings.Builder

	// Redundancy mode.
	mode := "active-passive"
	if len(states) > 1 {
		// If different RGs have different primaries, it's active-active.
		primary0 := false
		secondary0 := false
		for _, rg := range states {
			if rg.State == StatePrimary {
				primary0 = true
			} else {
				secondary0 = true
			}
		}
		if primary0 && secondary0 {
			mode = "active-active"
		}
	}
	fmt.Fprintf(&b, "Redundancy mode: %s\n\n", mode)

	// Cluster configuration.
	fmt.Fprintln(&b, "Cluster configuration:")
	fmt.Fprintf(&b, "  Cluster ID: %d\n", m.clusterID)
	fmt.Fprintf(&b, "  Node ID: %d\n", m.nodeID)
	fmt.Fprintf(&b, "  Heartbeat interval: %d ms\n", interval.Milliseconds())
	fmt.Fprintf(&b, "  Heartbeat threshold: %d\n", threshold)
	if desiredInterval != interval || desiredThreshold != threshold {
		fmt.Fprintf(&b, "  Heartbeat pending restart: configured interval %d ms, threshold %d (not applied to the running heartbeat)\n",
			desiredInterval.Milliseconds(), desiredThreshold)
	}
	if takeoverHold > 0 {
		// #103 item 5: an operator cannot reason about a hold they cannot see.
		// Omitted at the default 0, where the hold contributes nothing.
		fmt.Fprintf(&b, "  Takeover hold time: %s\n", takeoverHold)
	}
	if controlIface != "" {
		fmt.Fprintf(&b, "  Control interface: %s\n", controlIface)
	}
	if localVersion != "" {
		fmt.Fprintf(&b, "  Software version: %s\n", localVersion)
	}
	fmt.Fprintf(&b, "  HA protocol version: %d\n", localProtocol)
	if peerAlive {
		if peerVersion == "" {
			peerVersion = "unknown"
		}
		fmt.Fprintf(&b, "  Peer software version: %s\n", peerVersion)
		fmt.Fprintf(&b, "  Peer HA protocol version: %d\n", peerProtocol)
	}
	fmt.Fprintf(&b, "  Sync transport: %s\n", m.SyncTransport())
	fmt.Fprintln(&b)

	// Node health.
	localHealth := "healthy"
	// #6387: a persistent config-sync apply failure degrades node health
	// node-wide (same annotate-only semantics as a monitor-failure, but it
	// never perturbs Weight/election).
	if configSyncFailing {
		localHealth = "degraded"
	}
	for _, rg := range states {
		if len(rg.MonitorFails) > 0 || rg.Weight < 255 {
			localHealth = "degraded"
			break
		}
	}
	remoteHealth := "lost"
	if peerAlive {
		remoteHealth = fmt.Sprintf("healthy (node%d)", peerNodeID)
	}
	fmt.Fprintln(&b, "Node health:")
	fmt.Fprintf(&b, "  Local node: %s\n", localHealth)
	fmt.Fprintf(&b, "  Remote node: %s\n", remoteHealth)
	// #6495: name the kernel-upgrade election hold here too. It does NOT
	// degrade node health — the node is fine, it is deliberately not eligible —
	// so it is its own line rather than folded into localHealth, which would
	// tell the operator something false about the node.
	if kernelHold != "" {
		fmt.Fprintf(&b, "  Held secondary: %s\n", kernelHold)
	}
	fmt.Fprintln(&b)

	// Per-RG details with event history.
	for _, rg := range states {
		fmt.Fprintf(&b, "Redundancy group %d:\n", rg.GroupID)
		fmt.Fprintf(&b, "  Local priority: %d\n", rg.LocalPriority)
		fmt.Fprintf(&b, "  Peer priority: %d\n", rg.PeerPriority)
		fmt.Fprintf(&b, "  Local state: %s\n", rg.State)
		fmt.Fprintf(&b, "  Weight: %d/255 (threshold: 0)\n", rg.Weight)
		fmt.Fprintf(&b, "  Effective priority: %d\n", EffectivePriority(rg.LocalPriority, rg.Weight))
		preempt := "no"
		if rg.Preempt {
			preempt = "yes"
		}
		fmt.Fprintf(&b, "  Preempt: %s\n", preempt)
		fmt.Fprintf(&b, "  Failover count: %d\n", rg.FailoverCount)
		if hold := rg.TakeoverHoldRemaining(takeoverHold); hold > 0 {
			// Ready, but election still declines: name the hold and how much
			// of it is left rather than reporting a "yes" the election
			// contradicts (#103 item 5).
			fmt.Fprintf(&b, "  Takeover ready: no (takeover hold: %s of %s remaining, ready since %s)\n",
				hold.Round(time.Millisecond), takeoverHold, rg.ReadySince.Format("15:04:05"))
		} else if rg.Ready {
			fmt.Fprintf(&b, "  Takeover ready: yes (since %s)\n", rg.ReadySince.Format("15:04:05"))
		} else {
			reasons := "none"
			if len(rg.ReadinessReasons) > 0 {
				reasons = strings.Join(rg.ReadinessReasons, ", ")
			}
			fmt.Fprintf(&b, "  Takeover ready: no (%s)\n", reasons)
		}
		if rg.TransferReady {
			fmt.Fprintf(&b, "  Transfer ready: yes\n")
		} else {
			reasons := "none"
			if len(rg.TransferReadinessReasons) > 0 {
				reasons = strings.Join(rg.TransferReadinessReasons, ", ")
			}
			fmt.Fprintf(&b, "  Transfer ready: no (%s)\n", reasons)
		}
		if len(rg.MonitorFails) > 0 {
			fmt.Fprintf(&b, "  Monitor failures: %s\n", strings.Join(rg.MonitorFails, ", "))
		}

		// RG event history.
		rgEvents := m.history.Events(EventRG)
		var rgFiltered []HistoryEvent
		for _, ev := range rgEvents {
			if ev.GroupID == rg.GroupID {
				rgFiltered = append(rgFiltered, ev)
			}
		}
		if len(rgFiltered) > 0 {
			fmt.Fprintln(&b, "  Event history:")
			for _, ev := range rgFiltered {
				fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
			}
		}
		fmt.Fprintln(&b)
	}

	// Control link statistics.
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "  Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "  Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "  Heartbeat packet errors:    %d\n", hbStats.SendErrors+hbStats.RecvErrors)
	fmt.Fprintf(&b, "  Heartbeats without epoch:   %d%s\n", hbStats.EpochlessAdmitted,
		epochlessExposureNote(hbStats))
	fmt.Fprintf(&b, "  Epoch downgrades rejected:  %d\n", hbStats.EpochDowngradeRejected)
	fmt.Fprintf(&b, "  Epoch session collisions:   %d\n", hbStats.EpochSessionCollision)
	fmt.Fprintf(&b, "  Epoch out-of-band rejected: %d\n", hbStats.EpochOutOfBandRejected)
	fmt.Fprintf(&b, "  Epoch raises declined:      %d%s\n",
		hbStats.EpochRaiseDeclinedAheadOfClock, epochRaiseDeclineNote(hbStats))
	fmt.Fprintln(&b)

	// Sync link statistics.
	syncLabel := "Fabric link statistics:"
	if m.SyncTransport() == "control-link" {
		syncLabel = "Sync link statistics (control-link):"
	}
	fmt.Fprintln(&b, syncLabel)
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		connected := "Down"
		if m.IsSyncConnected() {
			connected = "Up"
		}
		fmt.Fprintf(&b, "  Status: %s\n", connected)
		fmt.Fprintf(&b, "  Errors: %d\n", syncStats.Errors)
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	fabEvents := m.history.Events(EventFabric)
	if len(fabEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range fabEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	fmt.Fprintln(&b)

	// Cold synchronization.
	fmt.Fprintln(&b, "Cold synchronization:")
	if syncStats != nil {
		startNano := syncStats.BulkSyncStartTime
		endNano := syncStats.BulkSyncEndTime
		bulkCount := syncStats.BulkSyncs
		if startNano > 0 {
			startTime := time.Unix(0, startNano)
			if endNano > 0 {
				endTime := time.Unix(0, endNano)
				dur := endTime.Sub(startTime)
				fmt.Fprintf(&b, "  Last bulk sync: %s (duration: %s, sessions: %d)\n",
					endTime.Format("Jan 02 15:04:05"), dur.Round(time.Millisecond), syncStats.BulkSyncSessions)
			} else {
				fmt.Fprintf(&b, "  Bulk sync in progress since %s (sessions: %d)\n",
					startTime.Format("Jan 02 15:04:05"), syncStats.BulkSyncSessions)
			}
		}
		fmt.Fprintf(&b, "  Bulk syncs completed: %d\n", bulkCount)
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	coldEvents := m.history.Events(EventColdSync)
	if len(coldEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range coldEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	fmt.Fprintln(&b)

	// Install fence (barrier-based cutover).
	if syncStats != nil && syncStats.LastFenceSeq > 0 {
		fmt.Fprintln(&b, "Install fence:")
		fmt.Fprintf(&b, "  Last fence sequence: %d\n", syncStats.LastFenceSeq)
		if syncStats.LastFenceAckAt > 0 {
			ackTime := time.Unix(0, syncStats.LastFenceAckAt)
			fmt.Fprintf(&b, "  Last fence ack:      %s\n", ackTime.Format("Jan 02 15:04:05.000"))
		} else {
			fmt.Fprintln(&b, "  Last fence ack:      pending")
		}
		fmt.Fprintln(&b)
	}

	// Peer fencing (#72). DISTINCT from the "Install fence" block above:
	// that one is the bulk-sync install barrier, this is the disable-rg
	// message the surviving node sends to a peer that stopped heartbeating
	// (heartbeat_manager.go handlePeerTimeout). Rendered off FenceStatus so
	// the configured action AND every fence attempt/result is visible in
	// `show chassis cluster information` on both the local CLI and the gRPC
	// remote CLI (both render this same function). Suppressed entirely when
	// fencing was never configured and never fired, matching the
	// conditional style of the sections around it.
	b.WriteString(m.formatStartupSyncHold())

	fenceAction, fenceEvents := m.FenceStatus()
	if fenceAction != "" || len(fenceEvents) > 0 {
		fmt.Fprintln(&b, "Peer fencing:")
		action := fenceAction
		if action == "" {
			// History outlives the config: a fence fired, then the operator
			// removed `peer-fencing`. Report the CURRENT action, not the one
			// the events were recorded under.
			action = "disabled"
		}
		fmt.Fprintf(&b, "  Action: %s\n", action)
		// #7147: under the acknowledged policy the counters are the only place
		// the guarantee's actual delivery rate is visible. An operator who
		// selected `disable-rg-confirmed` gets a fail-open takeover whenever
		// the ack does not arrive, and without this line a cluster that failed
		// open on EVERY takeover renders identically to one that was confirmed
		// every time — the "Attempts:" history would have to be read line by
		// line to tell them apart. Shown whenever the policy is armed or any
		// ack traffic has ever happened, so a disarmed-but-used history keeps
		// its numbers.
		if syncStats != nil && (fenceAction == PeerFencingDisableRGConfirmed ||
			syncStats.FenceAcksSent > 0 || syncStats.FenceAcksReceived > 0 ||
			syncStats.FenceAcksTimedOut > 0) {
			fmt.Fprintf(&b, "  Confirmations: received %d, timed out %d, sent to peer %d\n",
				syncStats.FenceAcksReceived, syncStats.FenceAcksTimedOut, syncStats.FenceAcksSent)
		}
		if len(fenceEvents) == 0 {
			fmt.Fprintln(&b, "  Attempts: none")
		} else {
			fmt.Fprintln(&b, "  Attempts:")
			for _, ev := range fenceEvents {
				fmt.Fprintf(&b, "    %s  %s\n",
					ev.Time.Format("Jan 02 15:04:05"), ev.Message)
			}
		}
		fmt.Fprintln(&b)
	}

	// Interface monitoring events.
	monEvents := m.history.Events(EventMonitor)
	if len(monEvents) > 0 {
		fmt.Fprintln(&b, "Interface monitoring events:")
		for _, ev := range monEvents {
			rgStr := ""
			if ev.GroupID >= 0 {
				rgStr = fmt.Sprintf(" (rg%d)", ev.GroupID)
			}
			fmt.Fprintf(&b, "  %s%s  %s\n", ev.Time.Format("Jan 02 15:04:05"), rgStr, ev.Message)
		}
		fmt.Fprintln(&b)
	}

	// Configuration synchronization.
	fmt.Fprintln(&b, "Configuration synchronization:")
	if syncStats != nil {
		configNano := syncStats.LastConfigSyncTime
		if configNano > 0 {
			configTime := time.Unix(0, configNano)
			fmt.Fprintf(&b, "  Last config sync: %s (size: %d bytes)\n",
				configTime.Format("Jan 02 15:04:05"), syncStats.LastConfigSyncSize)
		}
		fmt.Fprintf(&b, "  Configs sent:     %d\n", syncStats.ConfigsSent)
		fmt.Fprintf(&b, "  Configs received: %d\n", syncStats.ConfigsReceived)
		if syncStats.ConfigsStaleIgnored > 0 {
			fmt.Fprintf(&b, "  Configs stale-dropped: %d\n", syncStats.ConfigsStaleIgnored)
		}
		if syncStats.ConfigsApplyFailed > 0 {
			fmt.Fprintf(&b, "  Configs apply-failed:  %d\n", syncStats.ConfigsApplyFailed)
		}
		// #6785: surface the helper's semantic import refusals. Rendered only
		// when non-zero, unlike the peer boot incarnation: zero is the ordinary
		// state and carries no diagnostic value, whereas a non-zero count means
		// the peer believes it synced sessions this node does not hold.
		if syncStats.ImportsRefusedByHelper > 0 {
			fmt.Fprintf(&b, "  Imports refused by helper: %d\n", syncStats.ImportsRefusedByHelper)
		}
		// #6778: a config that never reached the ordered apply queue. Rendered
		// beside apply-failed because the operator consequence is identical —
		// this node is running a config older than the primary's committed one
		// — but the cause is different (receive-edge saturation, not a compile
		// or promote failure), so it gets its own line rather than being folded
		// into apply-failed.
		if syncStats.ConfigsQueueFullDropped > 0 {
			fmt.Fprintf(&b, "  Configs queue-full-dropped: %d\n", syncStats.ConfigsQueueFullDropped)
		}
		// #7328/#6778: nacks this node ACCEPTED from the peer, i.e. generations
		// we pushed that the peer did not apply. Surfaced because it is the
		// sender-side half of the queue-full / apply-failure recovery loop: a
		// peer whose queue-full drops climb while this counter stays at zero has
		// no working re-push driver.
		if syncStats.ConfigApplyNacksReceived > 0 {
			fmt.Fprintf(&b, "  Config apply-nacks received: %d\n", syncStats.ConfigApplyNacksReceived)
		}
		// #5084: the peer boot incarnation, rendered ALWAYS rather than only
		// when non-empty. "none" is the operationally interesting value — it
		// means the fence is in its fail-open state against this peer — and a
		// line that disappears in exactly that case would hide it.
		//
		// A status line plus counters, deliberately NOT a health annotation: an
		// un-incarnated peer is the expected steady state of a rolling upgrade,
		// not a fault, and raising cluster health for it would make every
		// upgrade look degraded. #6387 set the precedent in the other direction
		// by making a config-sync APPLY FAILURE diagnostic-only so it never
		// gates failover; a less severe condition must not be louder.
		fmt.Fprintf(&b, "  Peer boot incarnation: %s\n", syncStats.PeerBootIncarnation)
		if syncStats.BulkPrimesWithoutIncarnation > 0 {
			fmt.Fprintf(&b, "  Primes without incarnation: %d\n", syncStats.BulkPrimesWithoutIncarnation)
		}
		if syncStats.ConfigsDeadIncarnationDropped > 0 {
			fmt.Fprintf(&b, "  Configs dead-incarnation-dropped: %d\n", syncStats.ConfigsDeadIncarnationDropped)
		}
		// #9174 V013: same posture as the two lines above — a refusal the
		// operator can see. A nonzero value means a BulkEnd from a retired peer
		// boot was stopped from completing a live transfer.
		if syncStats.BulkEndsDeadIncarnationDropped > 0 {
			fmt.Fprintf(&b, "  Bulk ends dead-incarnation-dropped: %d\n", syncStats.BulkEndsDeadIncarnationDropped)
		}
		// #9716: the connection fence, and the fail-open completions it covers.
		// Same posture: counters an operator can see, not a health annotation.
		if syncStats.BulkEndsForeignConnDropped > 0 {
			fmt.Fprintf(&b, "  Bulk ends foreign-connection-dropped: %d\n", syncStats.BulkEndsForeignConnDropped)
		}
		if syncStats.BulkEndsEpochOnlyMatched > 0 {
			fmt.Fprintf(&b, "  Bulk ends matched on epoch alone: %d\n", syncStats.BulkEndsEpochOnlyMatched)
		}
	} else {
		fmt.Fprintln(&b, "  Not configured")
	}
	// #6387: surface the node-global CF config-sync health beside the
	// apply-failed counter so an operator sees WHY the standby is stuck
	// `Transfer ready: no` (e.g. host-inbound apply hard-failing) instead of
	// only the terse status string.
	if configSyncFailing {
		reason := configSyncReason
		if reason == "" {
			reason = "config-sync apply failing"
		}
		fmt.Fprintf(&b, "  Config sync: failing (%s)\n", reason)
	}
	cfgEvents := m.history.Events(EventConfigSync)
	if len(cfgEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range cfgEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	// Heartbeat event history.
	hbEvents := m.history.Events(EventHeartbeat)
	if len(hbEvents) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Heartbeat events:")
		for _, ev := range hbEvents {
			fmt.Fprintf(&b, "  %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	return b.String()
}

// FormatStatistics returns cluster statistics matching vSRX output.
func (m *Manager) FormatStatistics() string {
	var b strings.Builder

	// Control link statistics.
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "    Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "    Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "    Heartbeat packet errors:    %d\n", hbStats.SendErrors+hbStats.RecvErrors)
	fmt.Fprintf(&b, "    Heartbeats without epoch:   %d%s\n", hbStats.EpochlessAdmitted,
		epochlessExposureNote(hbStats))
	fmt.Fprintf(&b, "    Epoch downgrades rejected:  %d\n", hbStats.EpochDowngradeRejected)
	fmt.Fprintf(&b, "    Epoch session collisions:   %d\n", hbStats.EpochSessionCollision)
	fmt.Fprintf(&b, "    Epoch out-of-band rejected: %d\n", hbStats.EpochOutOfBandRejected)
	fmt.Fprintf(&b, "    Epoch raises declined:      %d%s\n",
		hbStats.EpochRaiseDeclinedAheadOfClock, epochRaiseDeclineNote(hbStats))
	fmt.Fprintln(&b)

	// Services synchronized table.
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		fmt.Fprintln(&b, "Services Synchronized:")
		fmt.Fprintf(&b, "    %-32s %-12s %s\n", "Service name", "Sent", "Received")
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session create",
			syncStats.SessionsSent, syncStats.SessionsReceived)
		// #7842: the mirror-sweep SUB-TOTAL of the line above, so an operator
		// can tell a duplicate backstop copy from an authoritative delta.
		fmt.Fprintf(&b, "    %-32s %-12d %s\n", "  of which mirror sweep",
			syncStats.SweepSessionsSent, "")
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session close",
			syncStats.DeletesSent, syncStats.DeletesReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Config",
			syncStats.ConfigsSent, syncStats.ConfigsReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "IPsec SA",
			syncStats.IPsecSASent, syncStats.IPsecSAReceived)
		fmt.Fprintf(&b, "    %-32s %-12d %d\n", "DHCP leases",
			syncStats.DHCPLeasesSent, syncStats.DHCPLeasesReceived)
		if syncStats.DHCPLeasesSeeded > 0 {
			fmt.Fprintf(&b, "    %-32s %-12s %d\n", "DHCP leases seeded",
				"", syncStats.DHCPLeasesSeeded)
		}
		// #7176 (C179-077): BulkSyncs is an OUTBOUND-only counter — sync_bulk.go
		// increments it once per bulk sync this node SENT, after writing
		// syncMsgBulkEnd. There is no inbound counterpart, so printing it in the
		// Received column too invented a number. Rendered like "Sessions
		// installed" below: the value in its real column, the other left blank.
		// Every neighbouring row here is a genuine Sent/Received pair, which is
		// exactly why the duplicate read as data rather than as a bug.
		fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Bulk syncs (sent)",
			syncStats.BulkSyncs, "")
		fmt.Fprintf(&b, "    %-32s %-12s %d\n", "Sessions installed",
			"", syncStats.SessionsInstalled)
		fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Errors",
			syncStats.Errors, "")
		if syncStats.LastFenceSeq > 0 {
			fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Install fence seq",
				syncStats.LastFenceSeq, "")
		}
	} else {
		fmt.Fprintln(&b, "Session sync not configured")
	}

	return b.String()
}

// FormatControlPlaneStatistics returns control-plane (heartbeat) statistics.
func (m *Manager) FormatControlPlaneStatistics() string {
	var b strings.Builder
	hbStats := m.HeartbeatStats()
	fmt.Fprintln(&b, "Control link statistics:")
	fmt.Fprintf(&b, "    Heartbeat packets sent:     %d\n", hbStats.Sent)
	fmt.Fprintf(&b, "    Heartbeat packets received: %d\n", hbStats.Received)
	fmt.Fprintf(&b, "    Heartbeat send errors:      %d\n", hbStats.SendErrors)
	fmt.Fprintf(&b, "    Heartbeat receive errors:   %d\n", hbStats.RecvErrors)
	fmt.Fprintf(&b, "    Heartbeats without epoch:   %d%s\n", hbStats.EpochlessAdmitted,
		epochlessExposureNote(hbStats))
	fmt.Fprintf(&b, "    Epoch downgrades rejected:  %d\n", hbStats.EpochDowngradeRejected)
	fmt.Fprintf(&b, "    Epoch session collisions:   %d\n", hbStats.EpochSessionCollision)
	fmt.Fprintf(&b, "    Epoch out-of-band rejected: %d\n", hbStats.EpochOutOfBandRejected)
	fmt.Fprintf(&b, "    Epoch raises declined:      %d%s\n",
		hbStats.EpochRaiseDeclinedAheadOfClock, epochRaiseDeclineNote(hbStats))
	fmt.Fprintf(&b, "    Authentication:             %s\n", m.controlLinkAuthStatus())
	// #6630: the rotation line appears ONLY while an additional key is
	// configured. A permanent line reading "no rotation in progress" would be
	// noise on every `show` a cluster ever prints, and the operator question
	// it answers exists only inside the window.
	if line := m.controlLinkRotationStatus(); line != "" {
		fmt.Fprintf(&b, "    Key rotation:               %s\n", line)
	}
	return b.String()
}

// controlLinkAuthStatus summarizes the #4107 control-link authentication
// posture for the operator (#4484 L-9). Before this surface existed, nothing
// revealed whether the control link's HMAC authentication was actually
// ENGAGED (frames are verified and an unauthenticated peer is rejected) or had
// silently degraded to DUAL-ACCEPT (an unauthenticated peer is still
// accepted) — the rolling-upgrade grace #4107 deliberately keeps open. The
// posture is derived from the SAME two facts heartbeatAuthDecision gates on —
// the local key (ControlLinkAuthKey) and the sticky peer-authenticated flag
// (HeartbeatPeerAuthSeen) — so for the HEARTBEAT this string tracks the real
// enforcement decision rather than a separate estimate.
//
// It does NOT track the session-sync channel. #5078 removed peerAuthSeen from
// syncAuthDecision, so sync admission no longer consults the sticky flag this
// string is built from; naming syncAuthDecision here would assert a coupling
// that no longer exists. pkg/cluster/README.md, "Rolling it onto a live
// unkeyed cluster", scopes the operator-facing line accordingly — it does not
// tell you whether an existing session-sync connection predates the key.
//
// It only inspects len(key) and never renders the secret.
func (m *Manager) controlLinkAuthStatus() string {
	keyConfigured := len(m.ControlLinkAuthKey()) > 0
	switch {
	case !keyConfigured:
		// No local key: this node cannot verify a peer and may be the
		// not-yet-keyed side of a rolling upgrade — dual-accept grace.
		return "dual-accept (no control-link key configured)"
	case m.HeartbeatPeerAuthSeen():
		// Both nodes are known-keyed and the peer has proven it: an
		// unauthenticated frame is now rejected as a downgrade attack.
		return "engaged (peer authenticated; unauthenticated frames rejected)"
	default:
		// Local key set but the peer has not authenticated yet (peer still
		// upgrading / not signing): grace is still open.
		return "dual-accept (key configured; peer not yet authenticated)"
	}
}

// controlLinkRotationStatus renders the #6630 rotation line, or "" when no
// additional key is configured (no window open).
//
// It answers the ONE question a rotation raises that nothing else can: is it
// safe to finalize? "Both configs say key B" is a statement about two files;
// "the peer is currently SIGNING with B" is a statement about the running
// system, and only the second makes retiring the old key safe. Retiring it
// while the peer still signs the old one reopens the dual-master window the
// overlap exists to close.
//
// It renders KEY IDS, never keys. An id is HMAC-SHA256(key, domain tag)
// truncated to 32 bits (controlLinkKeyID) — derivable identically on both
// nodes with no exchange, which is what lets the operator compare a `show` on
// each node, and useless for recovering the key.
//
// The unknown case is reported as unknown rather than as "not safe": no
// authenticated peer frame has been seen at all, which during a rotation
// usually means the peer is down, and telling an operator "not safe to
// finalize" when the real answer is "your peer is not talking to you" sends
// them to the wrong problem.
func (m *Manager) controlLinkRotationStatus() string {
	signing, additional := m.ControlLinkKeyIDs()
	if additional == "" {
		return ""
	}
	peer := m.PeerControlKeyID()
	switch {
	case peer == "":
		return fmt.Sprintf("in progress (signing %s, also accepting %s); peer key UNKNOWN — "+
			"no authenticated peer frame seen, do NOT finalize", signing, additional)
	case peer == signing:
		return fmt.Sprintf("in progress (signing %s, also accepting %s); peer is signing %s — "+
			"safe to finalize: `delete chassis cluster additional-authentication-key`",
			signing, additional, peer)
	default:
		return fmt.Sprintf("in progress (signing %s, also accepting %s); peer is still signing "+
			"%s — do NOT finalize, the peer has not moved yet", signing, additional, peer)
	}
}

// FormatDataPlaneStatistics returns data-plane (session sync) statistics.
func (m *Manager) FormatDataPlaneStatistics() string {
	var b strings.Builder
	syncStats := m.GetSyncStats()
	if syncStats == nil {
		fmt.Fprintln(&b, "Session sync not configured")
		return b.String()
	}

	fmt.Fprintln(&b, "Services Synchronized:")
	fmt.Fprintf(&b, "    %-32s %-12s %s\n", "Service name", "Sent", "Received")
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session create",
		syncStats.SessionsSent, syncStats.SessionsReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %s\n", "  of which mirror sweep",
		syncStats.SweepSessionsSent, "")
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Session close",
		syncStats.DeletesSent, syncStats.DeletesReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "Config",
		syncStats.ConfigsSent, syncStats.ConfigsReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "IPsec SA",
		syncStats.IPsecSASent, syncStats.IPsecSAReceived)
	fmt.Fprintf(&b, "    %-32s %-12d %d\n", "DHCP leases",
		syncStats.DHCPLeasesSent, syncStats.DHCPLeasesReceived)
	if syncStats.DHCPLeasesSeeded > 0 {
		fmt.Fprintf(&b, "    %-32s %-12s %d\n", "DHCP leases seeded",
			"", syncStats.DHCPLeasesSeeded)
	}
	// #7176 (C179-077): outbound-only; see the sibling render above.
	fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Bulk syncs (sent)",
		syncStats.BulkSyncs, "")
	fmt.Fprintf(&b, "    %-32s %-12s %d\n", "Sessions installed",
		"", syncStats.SessionsInstalled)
	fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Errors",
		syncStats.Errors, "")
	if syncStats.LastFenceSeq > 0 {
		fmt.Fprintf(&b, "    %-32s %-12d %s\n", "Install fence seq",
			syncStats.LastFenceSeq, "")
	}
	return b.String()
}

// FormatDataPlaneInterfaces returns fabric interface status.
func (m *Manager) FormatDataPlaneInterfaces() string {
	var b strings.Builder
	if m.SyncTransport() == "control-link" {
		fmt.Fprintln(&b, "Sync link (control-link):")
	} else {
		fmt.Fprintln(&b, "Fabric link:")
	}
	if m.IsSyncConnected() {
		fmt.Fprintln(&b, "  Status: Up")
	} else {
		fmt.Fprintln(&b, "  Status: Down")
	}
	syncStats := m.GetSyncStats()
	if syncStats != nil {
		fmt.Fprintf(&b, "  Errors: %d\n", syncStats.Errors)
	}
	fabEvents := m.history.Events(EventFabric)
	if len(fabEvents) > 0 {
		fmt.Fprintln(&b, "  Events:")
		for _, ev := range fabEvents {
			fmt.Fprintf(&b, "    %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}
	return b.String()
}

// FormatIPMonitoringStatus returns per-RG IP monitoring probe status.
func (m *Manager) FormatIPMonitoringStatus() string {
	m.mu.RLock()
	mon := m.monitor
	m.mu.RUnlock()

	states := m.GroupStates()
	var b strings.Builder
	fmt.Fprintln(&b, "IP monitoring status:")
	fmt.Fprintln(&b)

	hasIP := false
	for _, rg := range states {
		// #7338: split ip-monitoring debts by CLASS, using the shared
		// discriminator, not a raw "ip:" prefix.
		//
		// Global-threshold mode installs a SINGLE aggregate debt under
		// ipAggregateMonitorName, which deliberately does not carry the "ip:"
		// prefix (monitor.go) -- and installs NO per-target debts by design.
		// The old prefix filter therefore matched nothing for an RG that
		// ip-monitoring had actively DEMOTED, and this renderer printed "No IP
		// monitoring failures" on the primary failover diagnostic.
		//
		// That is a false negative on a diagnostic, which is worse than a wrong
		// number: an operator reads it as EVIDENCE and rules ip-monitoring out,
		// during the post-mortem of the very failover its global-weight
		// demotion may have caused. Global-threshold mode is the vSRX-parity
		// mode, i.e. the one an operator following Junos documentation
		// configures.
		//
		// isIPMonitorName's own doc says any code reconciling ONE class must
		// use it to avoid clobbering the other. This renderer is such code and
		// never got it.
		var ipFails []string
		aggregateFailed := false
		for _, f := range rg.MonitorFails {
			if !isIPMonitorName(f) {
				continue
			}
			if f == ipAggregateMonitorName {
				aggregateFailed = true
				continue
			}
			ipFails = append(ipFails, f)
		}
		// Show IP monitor section regardless (config-driven).
		if len(ipFails) > 0 || true {
			// We always show the section for each RG if any monitors are configured.
			fmt.Fprintf(&b, "Redundancy group %d:\n", rg.GroupID)
			switch {
			case aggregateFailed:
				// Render the CROSSING, not an address. In this mode there is no
				// per-address debt, so naming one would invent a target.
				if mon != nil {
					if threshold, weight, ok := mon.IPGlobalThreshold(rg.GroupID); ok {
						fmt.Fprintf(&b, "  %-20s Status: global threshold crossed "+
							"(threshold %d, weight %d applied)\n",
							"ip-monitoring", threshold, weight)
					} else {
						fmt.Fprintf(&b, "  %-20s Status: global threshold crossed\n",
							"ip-monitoring")
					}
				} else {
					fmt.Fprintf(&b, "  %-20s Status: global threshold crossed\n",
						"ip-monitoring")
				}
				fmt.Fprintln(&b, "  (global-threshold mode installs one aggregate debt and no")
				fmt.Fprintln(&b, "   per-target debts, so individual targets are not listed here)")
				// A per-target debt cannot normally coexist with the aggregate,
				// but print any that do rather than hiding them behind the
				// mode -- the two classes share one structure (#5080).
				for _, f := range ipFails {
					addr := strings.TrimPrefix(f, "ip:")
					fmt.Fprintf(&b, "  %-20s Status: unreachable\n", addr)
				}
			case len(ipFails) > 0:
				for _, f := range ipFails {
					addr := strings.TrimPrefix(f, "ip:")
					fmt.Fprintf(&b, "  %-20s Status: unreachable\n", addr)
				}
			default:
				fmt.Fprintln(&b, "  No IP monitoring failures")
			}
			fmt.Fprintln(&b)
			hasIP = true
		}
	}

	if !hasIP {
		fmt.Fprintln(&b, "No IP monitoring configured")
	}

	// #6589: clamped ip-monitoring weights. Unlike the interface-monitor
	// class, this one reached no surface at all — not even journald — so a
	// weight the runtime silently bounded to 0 owed no election debt and the
	// RG never demoted on probe failure.
	if mon != nil {
		if clamped := mon.ClampedIPMonitorWeights(); len(clamped) > 0 {
			fmt.Fprintln(&b)
			fmt.Fprintln(&b, "Clamped IP monitoring weights:")
			for _, c := range clamped {
				what := "global-weight"
				if c.Target != "" {
					what = c.Target
				}
				fmt.Fprintf(&b, "  Redundancy group %d: %-20s configured %d, effective %d (CLAMPED)\n",
					c.RGID, what, c.Configured, c.Effective)
			}
			fmt.Fprintln(&b, "  A weight clamped to 0 adds no election debt, so the group will")
			fmt.Fprintln(&b, "  NOT demote when that target fails. Re-commit the weight to fix it.")
		}
	}

	// Events.
	monEvents := m.history.Events(EventMonitor)
	var ipEvents []HistoryEvent
	for _, ev := range monEvents {
		if strings.HasPrefix(ev.Message, "IP ") {
			ipEvents = append(ipEvents, ev)
		}
	}
	if len(ipEvents) > 0 {
		fmt.Fprintln(&b, "IP monitoring events:")
		for _, ev := range ipEvents {
			fmt.Fprintf(&b, "  %s  %s\n", ev.Time.Format("Jan 02 15:04:05"), ev.Message)
		}
	}

	return b.String()
}

// InterfaceMonitorInfo holds per-interface monitor state for display.
type InterfaceMonitorInfo struct {
	Interface       string
	Weight          int
	Up              bool // physical link state
	RedundancyGroup int
	// ConfiguredWeight is the weight as WRITTEN in the config, before
	// ClampInterfaceMonitorWeight bounded it, and Clamped says whether that
	// bounding actually happened (#6589).
	//
	// Every renderer already called the clamp and threw the signal away
	// (`w, _ := ...`), so it printed a plausible 0 or 255 that is
	// indistinguishable from an operator-authored one. A monitor clamped to 0
	// contributes NO election debt: the RG never demotes when that link fails,
	// and the operator discovers it during a failover that does not happen.
	// The clamp itself is reachable only from a persisted config or a peer
	// push (the strict commit gate rejects an out-of-range weight outright),
	// which is exactly the population an operator cannot see by re-reading
	// what they typed.
	//
	// Zero values mean "not clamped", so a producer that does not set them
	// renders exactly as before.
	ConfiguredWeight int
	Clamped          bool
}

// RethInfo holds RETH interface status for display.
type RethInfo struct {
	Name            string
	RedundancyGroup int
	Status          string // "Up" or "Down"
	Members         []string
}

// InterfacesInput provides the data needed to format cluster interfaces output.
type InterfacesInput struct {
	ControlInterface string
	FabricInterface  string
	FabricMembers    []string // bond member interfaces (e.g. fab0-m0, fab0-m1)
	Fabric1Interface string   // secondary fabric interface (e.g. "fab1")
	Fabric1Members   []string // secondary fabric bond members (if any)
	Reths            []RethInfo
	Monitors         []InterfaceMonitorInfo
	PeerMonitors     []InterfaceMonitorInfo
}

// FormatInterfaces returns cluster interface information matching vSRX output.
func (m *Manager) FormatInterfaces(input InterfacesInput) string {
	var b strings.Builder

	m.mu.RLock()
	peerAlive := m.peerAlive
	m.mu.RUnlock()

	// Control link status.
	controlStatus := "Up"
	if !peerAlive {
		controlStatus = "Down"
	}
	fmt.Fprintf(&b, "Control link status: %s\n", controlStatus)
	fmt.Fprintln(&b)

	// Control interfaces table.
	if input.ControlInterface != "" {
		fmt.Fprintln(&b, "Control interfaces:")
		fmt.Fprintf(&b, "    %-8s%-12s%-21s%-14s%s\n", "Index", "Interface", "Monitored-Status", "Internal-SA", "Security")
		monStatus := "Up"
		if !peerAlive {
			monStatus = "Down"
		}
		fmt.Fprintf(&b, "    %-8d%-12s%-21s%-14s%s\n", 0, input.ControlInterface, monStatus, "Disabled", "Disabled")
		fmt.Fprintln(&b)
	}

	// Sync link status.
	fabricUp := m.IsSyncConnected()
	fabricStatus := "Up"
	if !fabricUp {
		fabricStatus = "Down"
	}
	if m.SyncTransport() == "control-link" {
		fmt.Fprintf(&b, "Sync link status (control-link): %s\n", fabricStatus)
	} else {
		fmt.Fprintf(&b, "Fabric link status: %s\n", fabricStatus)
	}
	fmt.Fprintln(&b)

	// Fabric interfaces table.
	if input.FabricInterface != "" || input.Fabric1Interface != "" {
		fmt.Fprintln(&b, "Fabric interfaces:")
		fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", "Name", "Child-interface", "Status", "Security")
		fmt.Fprintf(&b, "    %-8s%-19s%s\n", "", "", "(Physical/Monitored)")
		physStatus := "Up"
		if !fabricUp {
			physStatus = "Down"
		}
		statusStr := fmt.Sprintf("%s  /  %s", physStatus, physStatus)
		if input.FabricInterface != "" {
			if len(input.FabricMembers) > 0 {
				for i, member := range input.FabricMembers {
					name := ""
					if i == 0 {
						name = input.FabricInterface
					}
					fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", name, member, statusStr, "Disabled")
				}
			} else {
				fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", input.FabricInterface, input.FabricInterface, statusStr, "Disabled")
			}
		}
		if input.Fabric1Interface != "" {
			if len(input.Fabric1Members) > 0 {
				for i, member := range input.Fabric1Members {
					name := ""
					if i == 0 {
						name = input.Fabric1Interface
					}
					fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", name, member, statusStr, "Disabled")
				}
			} else {
				fmt.Fprintf(&b, "    %-8s%-19s%-26s%s\n", input.Fabric1Interface, input.Fabric1Interface, statusStr, "Disabled")
			}
		}
		fmt.Fprintln(&b)
	}

	// Redundant-ethernet Information.
	if len(input.Reths) > 0 {
		fmt.Fprintln(&b, "Redundant-ethernet Information:")
		fmt.Fprintf(&b, "    %-13s%-12s%s\n", "Name", "Status", "Redundancy-group")
		for _, r := range input.Reths {
			fmt.Fprintf(&b, "    %-13s%-12s%d\n", r.Name, r.Status, r.RedundancyGroup)
		}
		fmt.Fprintln(&b)
	}

	// Interface Monitoring — merge local + peer monitors and sort by RG then name.
	allMonitors := make([]InterfaceMonitorInfo, 0, len(input.Monitors)+len(input.PeerMonitors))
	allMonitors = append(allMonitors, input.Monitors...)
	allMonitors = append(allMonitors, input.PeerMonitors...)
	if len(allMonitors) > 0 {
		sort.Slice(allMonitors, func(i, j int) bool {
			if allMonitors[i].RedundancyGroup != allMonitors[j].RedundancyGroup {
				return allMonitors[i].RedundancyGroup < allMonitors[j].RedundancyGroup
			}
			return allMonitors[i].Interface < allMonitors[j].Interface
		})
		fmt.Fprintln(&b, "Interface Monitoring:")
		fmt.Fprintf(&b, "    %-18s%-10s%-26s%s\n", "Interface", "Weight", "Status", "Redundancy-group")
		fmt.Fprintf(&b, "    %-18s%-10s%s\n", "", "", "(Physical/Monitored)")
		clampedAny := false
		for _, mon := range allMonitors {
			physStatus := "Up"
			if !mon.Up {
				physStatus = "Down"
			}
			// Physical and monitored status are the same (link-state based).
			statusStr := fmt.Sprintf("%s  /  %s", physStatus, physStatus)
			// #6589: a clamped weight renders as "<effective> (cfg <written>)"
			// so the operator can see the two differ. Printing the effective
			// weight alone — which is what every renderer did — is correct but
			// silently indistinguishable from a monitor configured that way.
			weightCol := fmt.Sprintf("%d", mon.Weight)
			if mon.Clamped {
				weightCol = fmt.Sprintf("%d (cfg %d)", mon.Weight, mon.ConfiguredWeight)
				clampedAny = true
			}
			fmt.Fprintf(&b, "    %-18s%-10s%-26s%d\n",
				mon.Interface, weightCol, statusStr, mon.RedundancyGroup)
		}
		if clampedAny {
			fmt.Fprintln(&b, "    NOTE: a weight shown as \"N (cfg M)\" was CLAMPED to the")
			fmt.Fprintln(&b, "          [0,255] election domain. A monitor clamped to 0 adds no")
			fmt.Fprintln(&b, "          election debt, so its redundancy group will NOT demote")
			fmt.Fprintln(&b, "          when that link fails. Re-commit the weight to fix it.")
		}
	}

	return b.String()
}

// epochlessExposureNote annotates the #6169 epoch-less heartbeat counter so the
// number is actionable without the operator having to know what it means.
//
// An authenticated heartbeat with no boot epoch is admitted on the bounded
// session ring alone — the mechanism that stops working past
// heartbeatReplaySessions captured incarnations. A non-zero count is expected
// mid-rollout (the peer is still on a pre-#6169 build), but once BOTH nodes are
// upgraded it means either a node was left behind or someone is replaying
// pre-upgrade captures. Rotating the control-link PSK is what retires an
// attacker's archive; see "Operating the control-link PSK" in
// pkg/cluster/README.md.
//
// The note is suppressed once the downgrade latch has armed, because at that
// point the historical count is a record of the migration rather than live
// exposure.
//
// It reads the LATCH (HeartbeatStats.PeerEpochLatched), not the rejection
// counter. The counter was used as a proxy and is not one: it only moves when a
// later epoch-less frame is actually refused, so a receiver that admitted some
// epoch-less frames and then saw its first epoch-bearing one is latched with
// the counter still at 0 — and reported "replay protection is ring-only" when
// it was not. The exposure the note describes ends when the latch arms, so the
// latch is what it must test.
// epochRaiseDeclineNote carries the operator guidance that used to travel on
// the REJECTION reason string for this arm (#6969 F5). The frame is no longer
// rejected — declining the raise while admitting the frame is the fix — so the
// reason string is gone, and the counter is the only place the diagnosis can
// live. Rendering it bare would lose the one thing an operator needs from it:
// this is a CLOCK fault, and reading it as a replay sends them hunting an
// on-link attacker during an NTP problem.
func epochRaiseDeclineNote(s HeartbeatStats) string {
	if s.EpochRaiseDeclinedAheadOfClock == 0 {
		return ""
	}
	return "  (peer boot epoch is more than bootEpochMaxSkew ahead of THIS node's " +
		"clock — check NTP on BOTH nodes; the frames are still admitted, only the " +
		"floor is held)"
}

func epochlessExposureNote(s HeartbeatStats) string {
	if s.EpochlessAdmitted == 0 {
		return ""
	}
	if s.PeerEpochLatched {
		// "the latch is armed", NOT "the peer now signs boot epochs". They are
		// not the same statement, and only the first is something this node
		// knows. An ARCHIVED epoch-bearing frame replayed after a restart arms
		// the latch just as a live one does (README residual 5), so the latch
		// can be armed while the peer currently on the wire is a rolled-back,
		// epoch-less build being refused.
		//
		// AND IT REPORTS THE LATCH RATHER THAN ITS CONSEQUENCE, deliberately.
		// An earlier revision said "epoch-less frames now refused", promoting
		// the armed latch into a statement about what this node is enforcing
		// RIGHT NOW. The latch does not survive that promotion, because it is
		// not the last gate: heartbeatAuthDecision short-circuits to
		// dual-accept whenever no local key is configured, and UpdateConfig
		// clears controlAuthKey WITHOUT resetting hbAuth. So the reachable
		// production sequence — load a legacy unkeyed config leniently, add the
		// key under `commit confirmed`, accumulate an epoch-less count and arm
		// the latch, then let the confirmation time out and restore the unkeyed
		// config in the SAME daemon — leaves epochSeen true while every frame,
		// epoch-less included, is admitted unverified. Measured: the note still
		// read "now refused" while heartbeatAuthDecision returned accept=true.
		//
		// The latch being armed is a fact about this node's state; what it
		// enforces depends on the live key. Report the fact.
		return "  (downgrade latch armed; count is historical)"
	}
	return "  (peer not signing boot epochs - replay protection is ring-only; rotate the control-link PSK once both nodes are upgraded)"
}

// SetStartupSyncHoldStatus records the startup promotion-hold state for
// `show chassis cluster information` (#7162).
//
// The hold mechanisms live outside this package — vrrp.Manager for RETH VRRP
// mode, the daemon for no-reth-vrrp / private-rg-election — so this is a
// reporting mirror rather than the state itself. `mode` names which one, `active`
// is whether it is still holding, and `reason` is why it ended
// ("bulk-sync-complete" or "timeout-degraded"), empty while it is still active.
//
// Both paths report here because before #7162 neither was visible: the VRRP hold
// had recorded a reason since #466 and rendered it nowhere, so an operator could
// not distinguish "startup sync completed normally" from "sync never arrived and
// we promoted degraded" — which is exactly the distinction that explains a flow
// reset after a boot.
func (m *Manager) SetStartupSyncHoldStatus(mode string, active bool, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startupHoldMode = mode
	m.startupHoldActive = active
	if reason != "" {
		m.startupHoldReason = reason
	}
}

// StartupSyncHoldStatus returns the recorded startup hold state.
func (m *Manager) StartupSyncHoldStatus() (mode string, active bool, reason string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.startupHoldMode, m.startupHoldActive, m.startupHoldReason
}

// formatStartupSyncHold renders the startup promotion hold block, or nothing
// when no hold was ever armed (this node is standalone, or predates the arming
// path) — matching the conditional style of the sections around it.
func (m *Manager) formatStartupSyncHold() string {
	mode, active, reason := m.StartupSyncHoldStatus()
	if mode == "" {
		return ""
	}
	var b strings.Builder
	fmt.Fprintln(&b, "Startup promotion hold:")
	fmt.Fprintf(&b, "  Mode: %s\n", mode)
	switch {
	case active:
		fmt.Fprintln(&b, "  State: HOLDING (waiting for bulk session sync)")
	case reason == "timeout-degraded":
		fmt.Fprintln(&b, "  State: released DEGRADED (bulk sync did not complete "+
			"within the hold; promotion proceeded without synced session state)")
	case reason != "":
		fmt.Fprintf(&b, "  State: released (%s)\n", reason)
	default:
		fmt.Fprintln(&b, "  State: released")
	}
	fmt.Fprintln(&b)
	return b.String()
}
