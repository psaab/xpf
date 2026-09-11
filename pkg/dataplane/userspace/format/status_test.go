package format

import (
	"fmt"
	"strings"
	"testing"
	"time"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestFormatStatusSummary(t *testing.T) {
	now := time.Now().UTC()
	status := userspace.ProcessStatus{
		PID:                    1234,
		HelperMode:             "rust-bootstrap",
		ForwardingArmed:        false,
		Workers:                2,
		RingEntries:            2048,
		LastSnapshotGeneration: 7,
		LastFIBGeneration:      3,
		LastSnapshotAt:         now.Add(-2 * time.Second),
		InterfaceAddresses:     6,
		NeighborEntries:        9,
		NeighborCacheCapacity:  64,
		SessionTableEntries:    77,
		MaxSessions:            100,
		FlowCacheCapacity:      8192,
		RouteEntries:           4,
		HAGroups: []userspace.HAGroupStatus{
			{RGID: 0, Active: true, WatchdogTimestamp: 100},
			{RGID: 1, Active: false, WatchdogTimestamp: 0},
			{RGID: 2, Active: false, WatchdogTimestamp: 0},
		},
		Fabrics: []userspace.FabricSnapshot{
			{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7, OverlayLinux: "fab0", OverlayIfindex: 17, RXQueues: 4, PeerAddress: "10.99.1.2"},
		},
		LastResolution: &userspace.PacketResolution{
			Disposition:   "forward_candidate",
			EgressIfindex: 11,
			NextHop:       "172.16.50.1",
			NeighborMAC:   "00:10:db:ff:10:01",
		},
		WorkerHeartbeats: []time.Time{now.Add(-500 * time.Millisecond), now.Add(-700 * time.Millisecond)},
		Queues: []userspace.QueueStatus{
			{QueueID: 0, Armed: false, Ready: true},
			{QueueID: 1, Armed: false, Ready: false},
		},
		Bindings: []userspace.BindingStatus{
			{Slot: 0, Armed: false, Ready: true, Bound: true, XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, SharedUMEMMode: "cross-nic", SharedUMEMSocketRole: "owner", SharedUMEMGroup: "cross-nic:w0:ge-0-0-1,ge-0-0-2", RXPackets: 10, ValidatedPackets: 8, ExceptionPackets: 1, ScreenDrops: 2, SYNCookieChallenges: 3, SYNCookieSecretUnavailable: 1, SYNCookieAckValid: 5, SYNCookieAckInvalid: 7, SYNCookieBypass: 11, TXPackets: 3, TXBytes: 420, TXCompletions: 2, MirroredPackets: 4, MirroredBytes: 512, MirrorDropsNoFrame: 1, KernelRXDropped: 9, KernelRXInvalidDescs: 1, DirectTXPackets: 2, InPlaceTXPackets: 1, InPlaceVLANPushDescPackets: 8, InPlaceVLANPopDescPackets: 9, InPlaceVLANPushNoHeadroomPackets: 10, InPlaceL2MemmoveFallbackPackets: 11, DirectTXNoFrameFallbackPackets: 5, DirectTXBuildFallbackPackets: 6, DebugPendingFillFrames: 10, DebugSpareFillFrames: 11, DebugFreeTXFrames: 12, DebugPendingTXPrepared: 13, DebugPendingTXLocal: 14, DebugOutstandingTX: 15, DebugInFlightRecycles: 16},
			{Slot: 1, Armed: false, Ready: false, Bound: true, XSKRegistered: false, RXPackets: 5, ValidatedPackets: 4, ExceptionPackets: 2, ScreenDrops: 4, SYNCookieChallenges: 13, SYNCookieAckValid: 17, SYNCookieAckInvalid: 19, SYNCookieBypass: 23, TXErrors: 1, TXSharedRecycleUnknownSlotDrops: 1, TXCompletions: 3, MirroredPackets: 6, MirroredBytes: 768, MirrorDropsNoBinding: 2, MirrorDropsQueueFull: 3, KernelRXDropped: 4, KernelRXInvalidDescs: 2, CopyTXPackets: 4, InPlaceVLANPushDescPackets: 3, InPlaceVLANPopDescPackets: 4, InPlaceVLANPushNoHeadroomPackets: 5, InPlaceL2MemmoveFallbackPackets: 6, DirectTXDisallowedFallbackPackets: 7, DebugPendingFillFrames: 20, DebugSpareFillFrames: 21, DebugFreeTXFrames: 22, DebugPendingTXPrepared: 23, DebugPendingTXLocal: 24, DebugOutstandingTX: 25, DebugInFlightRecycles: 26},
		},
		RecentExceptions: []userspace.ExceptionStatus{
			{Timestamp: now, Slot: 1, QueueID: 0, Interface: "ge-0-0-2", Reason: "metadata_parse", PacketLength: 128},
		},
		EventStreamSent:                 101,
		EventStreamDropped:              7,
		EventStreamSessionCloseSent:     90,
		EventStreamSessionCloseDropped:  3,
		EventStreamSessionCreateSent:    12,
		EventStreamSessionCreateDropped: 1,
		EventStream: &userspace.EventStreamStatus{
			FramesRead:          11,
			FramesWritten:       5,
			DecodeErrors:        2,
			SeqGaps:             3,
			PolicyDenyEvents:    13,
			ScreenDropEvents:    17,
			ScreenAlarmEvents:   23,
			FilterLogEvents:     19,
			SessionCloseEvents:  29,
			SessionCreateEvents: 31,
			PolicyDenyDrops:     1,
			ScreenDropDrops:     4,
			FilterLogDrops:      9,
			SessionCloseDrops:   7,
			SessionCreateDrops:  8,
			UnknownFrameDrops:   6,
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"Userspace dataplane helper:",
		"PID:",
		"Forwarding armed:          false",
		"Last FIB generation:       3",
		"Interface addresses:       6",
		"Neighbor entries:          9",
		"Neighbor cache capacity:   64",
		"Session table entries:     77/100",
		"Flow cache capacity:       8192",
		"Route entries:             4",
		"Local HA forwarding role:  active",
		"HA groups:                 rg0 active=true watchdog=100; rg1 active=false watchdog=0; rg2 active=false watchdog=0",
		"Fabric links:              fab0 parent=ge-0-0-0 peer=10.99.1.2",
		"Last resolution:           forward_candidate egress-ifindex=11 next-hop=172.16.50.1 mac=00:10:db:ff:10:01",
		"Bound bindings:            2/2",
		"XSK-registered bindings:   1/2",
		"Zerocopy bindings:         1/2",
		"Shared UMEM bindings:      1/2",
		"Armed queues:              0/2",
		"Ready queues:              1/2",
		"Armed bindings:            0/2",
		"Ready bindings:            1/2",
		"RX packets:                15",
		"Validated packets:         12",
		"Exception packets:         3",
		"TX packets:                3",
		"TX bytes:                  420",
		"TX errors:                 1",
		"Screen drops:              6",
		"SYN-cookie counters:       challenges=16 unavailable=1 syn_ack_sent=0 ack_rst_sent=0 budget_drops=0 ack_valid=22 ack_invalid=26 bypass=34",
		"TX shared recycle unk:     1",
		"TX completions:            5",
		"Mirrored packets:          10",
		"Mirrored bytes:            1280",
		"Mirror drops:              no-frame=1 tx-frame-reserve=0 no-binding=2 queue-full=3",
		"Kernel RX dropped:         13",
		"Kernel RX invalid descs:   3",
		"Direct TX packets:         2",
		"Copy-path TX packets:      4",
		"In-place TX packets:       1",
		"In-place VLAN push desc:   11",
		"In-place VLAN pop desc:    13",
		"In-place VLAN no-headroom: 15",
		"In-place L2 memmove fb:    17",
		"Direct TX no-frame fb:     5",
		"Direct TX build-none fb:   6",
		"Direct TX disallowed fb:   7",
		"Event stream frames:       read=11 written=5 decode_errors=2 seq_gaps=3",
		"Event stream producer:     sent=101 dropped=7",
		"Event stream rt_flow:      session_close[sent=90 dropped=3] session_create[sent=12 dropped=1]",
		"Event stream events:       policy_deny=13 screen_drop=17 screen_alarm=23 filter_log=19 session_close=29 session_create=31 unknown_drops=6",
		"Event stream drops:        policy_deny=1 screen_drop=4 filter_log=9 session_close=7 session_create=8",
		"Pending fill frames:       30",
		"Spare fill frames:         32",
		"Free TX frames:            34",
		"Pending TX prepared:       36",
		"Pending TX local:          38",
		"Outstanding TX:            40",
		"In-flight recycles:        42",
		"Recent exceptions:         1",
		"Worker 0 heartbeat age:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestFormatStatusSummaryShowsTheForwardingDisarmReason(t *testing.T) {
	// A SPECIMEN reason, not a pinned constant. This used to inline the
	// unexported persistentSourceNATHAUnsupportedReason from the parent
	// userspace package; #8573 deleted that constant along with the gate that
	// produced it, after measuring its premise ("leases are not
	// HA-synchronized") false on the loss userspace cluster. The formatter only
	// echoes whatever UnsupportedReasons string the manager supplies, so any
	// reason exercises it — and pinning a particular one is what tied this cell
	// to a gate that then went away.
	const specimenReason = "userspace three-color policers require color-blind mode and then discard"
	status := userspace.ProcessStatus{
		Capabilities: userspace.UserspaceCapabilities{
			ForwardingSupported: false,
			UnsupportedReasons:  []string{specimenReason},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"Forwarding supported:      false",
		"Forwarding blocked by:     " + specimenReason,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestFormatStatusSummaryShowsDegradedPathCounters(t *testing.T) {
	status := userspace.ProcessStatus{
		DegradedPathCounters: map[string]uint64{
			"transit_drop":  5,
			"ctrl_disabled": 1,
			"redirect_err":  3,
		},
	}

	out := FormatStatusSummary(status)
	want := "Degraded path counters:    ctrl_disabled=1 redirect_err=3 transit_drop=5"
	if !strings.Contains(out, want) {
		t.Fatalf("summary missing degraded path counters %q:\n%s", want, out)
	}
	if strings.Contains(out, "fallback_counters") {
		t.Fatalf("summary exposed legacy fallback_counters field:\n%s", out)
	}
}

// #2161: the status summary surfaces a per-binding-summed NAT64 translations
// row alongside SNAT/DNAT, so an operator can see live NAT64 activity (the
// counter previously read 0 even while translated traffic flowed).
func TestFormatStatusSummaryShowsNAT64Translations(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{Slot: 0, Nat64Translations: 12},
			{Slot: 1, Nat64Translations: 30},
		},
	}

	out := FormatStatusSummary(status)
	want := "NAT64 translations:        42"
	if !strings.Contains(out, want) {
		t.Fatalf("summary missing NAT64 translations row %q:\n%s", want, out)
	}
}

// #4520: the status summary surfaces the transient NAT64 pool-exhaustion drop
// counter as a distinct row from the config/empty no-source-pool drops, so a
// full pool under load (add capacity) is distinguishable from a misconfigured
// or empty pool (fix config) — opposite remedies.
func TestFormatStatusSummaryShowsNAT64PoolExhausted(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{Slot: 0, Nat64NoSourcePool: 3, Nat64PoolExhausted: 5},
			{Slot: 1, Nat64NoSourcePool: 0, Nat64PoolExhausted: 9},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"NAT64 no-source-pool drops:3",
		"NAT64 pool-exhausted drops:14",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing NAT64 drop row %q:\n%s", want, out)
		}
	}
}

// #2562: the status summary surfaces the fail-closed NAT64 fragment-drop
// counter (a non-first fragment or a real ICMP/ICMPv6 fragment that cannot be
// safely translated) as its own row, summed across bindings, so an operator
// can see fragmented-NAT64 drops. The stateful frag-association cache (#3291
// stage 4) that would let real fragments traverse is deferred.
func TestFormatStatusSummaryShowsNAT64FragDropped(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{Slot: 0, Nat64FragDropped: 4},
			{Slot: 1, Nat64FragDropped: 7},
		},
	}

	out := FormatStatusSummary(status)
	if !strings.Contains(out, "NAT64 fragment drops:      11") {
		t.Fatalf("summary missing NAT64 fragment drop row (want 11):\n%s", out)
	}
}

// #5625: the status summary surfaces the fail-closed NAT64 extension-header
// ineligibility counter — a v6→v4 forward translation rejected because the
// IPv6 packet carried an Authentication Header, an active Routing header
// (Segments Left > 0), or a Mobility/HIP/Shim6 header (RFC 7915 §5.1/§5.1.1)
// — as its own row, summed across bindings, distinct from the source/pool/
// fragment NAT64 drop counters.
func TestFormatStatusSummaryShowsNAT64ExthdrIneligible(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{Slot: 0, Nat64ExthdrIneligible: 6, Nat64IneligibleProtocol: 4, Nat64TunnelEncapUnsupported: 2},
			{Slot: 1, Nat64ExthdrIneligible: 9, Nat64IneligibleProtocol: 8, Nat64TunnelEncapUnsupported: 5},
		},
	}

	out := FormatStatusSummary(status)
	if !strings.Contains(out, "NAT64 ext-header ineligible drops:15") {
		t.Fatalf("summary missing NAT64 ext-header ineligible drop row (want 15):\n%s", out)
	}
	// #8890: the tunnel-encap drop must AGGREGATE across bindings like its
	// siblings, not report one worker's value. The two slots carry 2 and 5, so
	// a row reading 2 or 5 would be a per-binding read that happens to look
	// plausible; only 7 distinguishes summing from picking.
	if !strings.Contains(out, "NAT64 tunnel encap unsupported drops:7") {
		t.Fatalf("summary missing aggregated NAT64 tunnel-encap-unsupported row (want 7 = 2+5):\n%s", out)
	}
	// #8670: the protocol-ineligibility row aggregates across bindings like its
	// siblings. A DISTINCT total (12, not 15) so a row that accidentally
	// rendered the ext-header aggregate cannot pass this.
	if !strings.Contains(out, "NAT64 ineligible-protocol drops:12") {
		t.Fatalf("summary missing NAT64 ineligible-protocol drop row (want 12):\n%s", out)
	}
}

// #6475: the status summary surfaces the fail-closed NAT64 destination
// ineligibility counter — a NAT64-prefix-matched destination whose embedded
// IPv4 is non-global per RFC 6052 §3.1 (0.0.0.0/8, 127.0.0.0/8,
// 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 — e.g. 64:ff9b::127.0.0.1, which
// would otherwise LocalDeliver to the localhost-only control plane) — as its
// own row, summed across bindings, distinct from the source/pool/fragment
// NAT64 drop counters.
func TestFormatStatusSummaryShowsNAT64IneligibleDest(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{Slot: 0, Nat64IneligibleDest: 5},
			{Slot: 1, Nat64IneligibleDest: 8},
		},
	}

	out := FormatStatusSummary(status)
	if !strings.Contains(out, "NAT64 ineligible-destination drops:13") {
		t.Fatalf("summary missing NAT64 ineligible-destination drop row (want 13):\n%s", out)
	}
}

// #3657 (H13/H14) / #3661 (M02): the status summary surfaces the per-source
// reject reply SUCCESS ("Generated-reply sent"), the TX-frame reply-budget
// suppression ("Generated-reply budget drops"), and the rate-limit
// suppression ("Generated-reply rate-limited") counters wired onto
// BindingStatus by #3615/#3661, alongside the existing egress output-filter
// "Generated-reply drops" line. Before this the sent/budget/rate-limit legs
// were aggregated nowhere and never printed — a docs-contract violation
// (junos-cli-reference.md promises reject suppression is counted per source in
// `show ... status`). Reverting the formatter drops the new lines and turns
// this test RED.
func TestFormatStatusSummaryShowsRejectObservability(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{
				Slot:                          0,
				PolicyRejectSent:              5,
				FilterRejectSent:              2,
				PolicyRejectReplyBudgetDrops:  3,
				FilterRejectReplyBudgetDrops:  1,
				PolicyRejectOutputFilterDrops: 7,
				FilterRejectOutputFilterDrops: 4,
				PolicyRejectRateLimitDrops:    13,
				FilterRejectRateLimitDrops:    15,
			},
			{
				Slot:                          1,
				PolicyRejectSent:              6,
				FilterRejectSent:              8,
				PolicyRejectReplyBudgetDrops:  9,
				FilterRejectReplyBudgetDrops:  10,
				PolicyRejectOutputFilterDrops: 11,
				FilterRejectOutputFilterDrops: 12,
				PolicyRejectRateLimitDrops:    17,
				FilterRejectRateLimitDrops:    19,
			},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		// #3615 output-filter leg (policy=18 filter=16) must remain split.
		"Generated-reply drops:     time_exceeded=0 policy_reject=18 filter_reject=16 syn_cookie=0 ptb=0 classify_parse_errors=0",
		// #3657 new SUCCESS line (policy=11 filter=10).
		"Generated-reply sent:      policy_reject=11 filter_reject=10",
		// #3657 new TX-frame budget suppression line (policy=12 filter=11).
		"Generated-reply budget drops: policy_reject=12 filter_reject=11",
		// #3661 new rate-limit drop line (policy=13+17=30 filter=15+19=34).
		// Reverting the source split (rate-limit drop stays source-neutral)
		// or dropping the formatter line turns this RED.
		"Generated-reply rate-limited: policy_reject=30 filter_reject=34",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing reject observability %q:\n%s", want, out)
		}
	}
}

// #3657: the sent and budget-drop lines are suppressed entirely when their
// counters are all zero, so a quiet firewall does not print noise rows (same
// zero-suppression discipline as the SYN-cookie and output-filter lines).
func TestFormatStatusSummaryHidesZeroRejectObservability(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{{Slot: 0}},
	}
	out := FormatStatusSummary(status)
	if strings.Contains(out, "Generated-reply sent:") {
		t.Fatalf("summary printed reject sent row for all-zero counters:\n%s", out)
	}
	if strings.Contains(out, "Generated-reply budget drops:") {
		t.Fatalf("summary printed reject budget-drop row for all-zero counters:\n%s", out)
	}
	if strings.Contains(out, "Generated-reply rate-limited:") {
		t.Fatalf("summary printed reject rate-limit row for all-zero counters:\n%s", out)
	}
}

func TestFormatSYNCookieCounterRows(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{
				SYNCookieChallenges:        3,
				SYNCookieSecretUnavailable: 5,
				SYNCookieSynAckSent:        7,
				SYNCookieAckRstSent:        11,
				SYNCookieReplyBudgetDrops:  13,
				SYNCookieAckValid:          17,
				SYNCookieAckInvalid:        19,
				SYNCookieBypass:            23,
			},
			{
				SYNCookieChallenges:        17,
				SYNCookieSecretUnavailable: 19,
				SYNCookieSynAckSent:        29,
				SYNCookieAckRstSent:        31,
				SYNCookieReplyBudgetDrops:  37,
				SYNCookieAckValid:          41,
				SYNCookieAckInvalid:        43,
				SYNCookieBypass:            47,
			},
		},
	}

	rows := FormatSYNCookieCounterRows(SumSYNCookieCounters(status))
	for _, want := range []string{
		fmt.Sprintf("  %-30s %s\n", "Userspace SYN-cookie scope", "all bindings"),
		fmt.Sprintf("  %-30s %d\n", "SYN-cookie challenges", 20),
		fmt.Sprintf("  %-30s %d\n", "SYN-cookie secret unavailable", 24),
		fmt.Sprintf("  %-30s %d\n", "SYN-cookie SYN-ACK sent", 36),
		fmt.Sprintf("  %-30s %d\n", "SYN-cookie ACK RST sent", 42),
		fmt.Sprintf("  %-30s %d\n", "SYN-cookie budget drops", 50),
		fmt.Sprintf("  %-30s %d\n", "SYN-cookie ACK valid", 58),
		fmt.Sprintf("  %-30s %d\n", "SYN-cookie ACK invalid", 62),
		fmt.Sprintf("  %-30s %d\n", "SYN-cookie bypass", 70),
	} {
		if !strings.Contains(rows, want) {
			t.Fatalf("SYN-cookie rows missing %q:\n%s", want, rows)
		}
	}
	if got := FormatSYNCookieCounterRows(SYNCookieCounters{}); got != "" {
		t.Fatalf("zero SYN-cookie counters rendered rows: %q", got)
	}
}

func TestFormatStatusSummaryWorkerRuntimeRolling60sColumn(t *testing.T) {
	// Three workers: w0 has a fully-populated window (45s CPU over 60s = 75%);
	// w1 has only cumulative data and no rotation yet (window_ns=0, show "-");
	// w2 is dead (windowed column suppressed by DEAD row).
	status := userspace.ProcessStatus{
		WorkerRuntime: []userspace.WorkerRuntimeStatus{
			{
				WorkerID:       0,
				TID:            111,
				WallNS:         3600 * 1_000_000_000,
				ActiveNS:       1800 * 1_000_000_000,
				IdleSpinNS:     900 * 1_000_000_000,
				IdleBlockNS:    900 * 1_000_000_000,
				ThreadCPUNS:    1800 * 1_000_000_000,
				WallNS60s:      60 * 1_000_000_000,
				ActiveNS60s:    30 * 1_000_000_000,
				ThreadCPUNS60s: 45 * 1_000_000_000,
				WindowNS:       60 * 1_000_000_000,
			},
			{
				WorkerID:    1,
				TID:         222,
				WallNS:      10 * 1_000_000_000,
				ActiveNS:    1 * 1_000_000_000,
				ThreadCPUNS: 1 * 1_000_000_000,
			},
			{
				WorkerID:     2,
				TID:          333,
				Dead:         true,
				PanicMessage: "boom",
			},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"CPU%60s",
		"75.0", // 45/60 = 75% on worker 0's rolling window
		"DEAD - panicked: boom",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("worker runtime row missing %q:\n%s", want, out)
		}
	}
	// Worker 1: WindowNS=0 → literal "-" placeholder in the CPU%60s column.
	// Asserting the exact row prefix through the CPU%60s slot pins the
	// column position so a future column reorder can't silently move "-"
	// elsewhere.
	wantRow := "  1      222      10.0     0.0      0.0        10.0     -        "
	if !strings.Contains(out, wantRow) {
		t.Fatalf("expected '-' placeholder in CPU%%60s column for WindowNS=0 worker (looking for %q), got:\n%s", wantRow, out)
	}
}

func TestFormatStatusSummaryIncludesThreeColorPolicerCounters(t *testing.T) {
	status := userspace.ProcessStatus{
		ThreeColorPolicerCounters: []userspace.ThreeColorPolicerStatus{
			{
				ID:            2,
				Name:          "wan-egress",
				Mode:          "single-rate",
				ColorBlind:    true,
				GreenPackets:  10,
				GreenBytes:    1000,
				YellowPackets: 3,
				YellowBytes:   300,
				RedPackets:    2,
				RedBytes:      200,
				DropPackets:   2,
				DropBytes:     200,
			},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"Three-color policers:",
		"GreenPkts",
		"wan-egress",
		"single-rate",
		"true",
		"10",
		"3",
		"2",
		"1000",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing three-color policer field %q:\n%s", want, out)
		}
	}
}

func TestFormatStatusSummaryReportsStandbyArmedRole(t *testing.T) {
	status := userspace.ProcessStatus{
		ForwardingArmed: true,
		HAGroups: []userspace.HAGroupStatus{
			{RGID: 0, Active: false, WatchdogTimestamp: 100},
			{RGID: 1, Active: false, WatchdogTimestamp: 0},
			{RGID: 2, Active: false, WatchdogTimestamp: 0},
		},
	}

	out := FormatStatusSummary(status)
	if !strings.Contains(out, "Local HA forwarding role:  standby (armed for failover)") {
		t.Fatalf("summary missing standby armed role:\n%s", out)
	}
}

func TestFormatStatusSummaryDoesNotCountDisabledSharedUMEMFallback(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{
				SharedUMEMMode:           "cross-nic",
				SharedUMEMSocketRole:     "owner",
				SharedUMEMDisabledReason: "shared UMEM bind failed; using private UMEM",
			},
			{
				SharedUMEMMode:       "cross-nic",
				SharedUMEMSocketRole: "secondary",
			},
		},
	}

	out := FormatStatusSummary(status)
	if !strings.Contains(out, "Shared UMEM bindings:      1/2") {
		t.Fatalf("summary counted disabled shared UMEM fallback:\n%s", out)
	}
}

func TestFormatStatusSummaryAttributesCoSAdmissionTXErrors(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{TXErrors: 100, DbgCoSQueueOverflow: 50},
		},
		CoSInterfaces: []userspace.CoSInterfaceStatus{
			{
				Queues: []userspace.CoSQueueStatus{
					{AdmissionFlowShareDrops: 3, AdmissionBufferDrops: 2, AdmissionEcnMarked: 7},
					{AdmissionFlowShareDrops: 1, AdmissionBufferDrops: 4, AdmissionEcnMarked: 11},
				},
			},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"TX errors:                 100",
		"TX errors non-admission:   50",
		"CoS queue drops lifetime:  50",
		"CoS admission drops:       10",
		"CoS flow-share drops:      4",
		"CoS buffer drops:          6",
		"CoS ECN marked:            18",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestFormatStatusSummaryUsesBindingLifetimeForCoSErrorResidual(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{TXErrors: 100, DbgCoSQueueOverflow: 80},
		},
		CoSInterfaces: []userspace.CoSInterfaceStatus{
			{
				Queues: []userspace.CoSQueueStatus{
					{AdmissionFlowShareDrops: 5, AdmissionBufferDrops: 5},
				},
			},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"TX errors:                 100",
		"TX errors non-admission:   20",
		"CoS queue drops lifetime:  80",
		"CoS admission drops:       10",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing binding-lifetime attribution %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "TX errors non-admission:   90") {
		t.Fatalf("summary used current-runtime CoS reason counters for lifetime residual:\n%s", out)
	}
}

func TestFormatStatusSummarySaturatesCoSAdmissionAttribution(t *testing.T) {
	status := userspace.ProcessStatus{
		Bindings: []userspace.BindingStatus{
			{TXErrors: 1, DbgCoSQueueOverflow: 2},
		},
		CoSInterfaces: []userspace.CoSInterfaceStatus{
			{
				Queues: []userspace.CoSQueueStatus{
					{AdmissionFlowShareDrops: ^uint64(0) - 1, AdmissionBufferDrops: 10},
				},
			},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"TX errors non-admission:   0",
		"CoS queue drops lifetime:  2",
		"CoS admission drops:       18446744073709551615",
		"CoS flow-share drops:      18446744073709551614",
		"CoS buffer drops:          10",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing saturated attribution %q:\n%s", want, out)
		}
	}
}

func TestFormatFairnessRSS(t *testing.T) {
	status := userspace.ProcessStatus{
		CoSActiveFlowCountsTruncated: true,
		Bindings: []userspace.BindingStatus{
			{Interface: "reth0", Ifindex: 80},
		},
		CoSActiveFlowCounts: []userspace.CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: 4, WorkerID: 1, ActiveFlowCount: 3},
			{Ifindex: 80, QueueID: 4, WorkerID: 2, ActiveFlowCount: 0},
			{Ifindex: 80, QueueID: 5, WorkerID: 0, ActiveFlowCount: 2},
			{Ifindex: 80, QueueID: 5, WorkerID: 1, ActiveFlowCount: 2},
		},
	}

	out := FormatFairnessRSS(status, []userspace.FairnessRSSExpectation{
		{Interface: "reth0", QueueID: 4, RSSExpectation: "balanced"},
		{Interface: "reth0", QueueID: 5, RSSExpectation: "max-worker-flow-share:50%"},
	})
	for _, want := range []string{
		"Userspace fairness RSS structure:",
		"warning: CoS active-flow snapshot truncated",
		"Ifindex",
		"Queue",
		"ActiveFlows",
		"Cstruct",
		"80       4       4           2             0.577350   75.00%",
		"80       5       4           2             0.000000   50.00%",
		"RSS expectations:",
		"Interface",
		"reth0",
		// #9369: the snapshot is truncated, so both constrained expectations are
		// INDETERMINATE rather than a PASS/FAIL computed from a partial prefix.
		"Result",
		"balanced                     INDETERMINATE",
		"max-worker-flow-share:0.5    INDETERMINATE",
		"indeterminate: CoS active-flow snapshot truncated",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("fairness output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatFairnessRSSShowsExpectationsWithoutRows(t *testing.T) {
	status := userspace.ProcessStatus{
		Workers:  4,
		Bindings: []userspace.BindingStatus{{Interface: "reth0", Ifindex: 80}},
	}
	out := FormatFairnessRSS(status, []userspace.FairnessRSSExpectation{
		{Interface: "reth0", QueueID: 4, RSSExpectation: "cstruct-max:0.25"},
	})
	for _, want := range []string{
		"Userspace fairness RSS structure:",
		"  none",
		"RSS expectations:",
		"reth0",
		"cstruct-max:0.25",
		"FAIL",
		"cstruct-max: no active flows observed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("fairness output missing %q:\n%s", want, out)
		}
	}
}

// #9369: the RSS expectations table renders a tri-state verdict. PASS and FAIL
// come from a complete snapshot; INDETERMINATE only from a truncated one.
func TestFormatFairnessRSSRendersTriStateVerdict_9369(t *testing.T) {
	complete := userspace.ProcessStatus{
		Workers:  2,
		Bindings: []userspace.BindingStatus{{Interface: "reth0", Ifindex: 80}},
		CoSActiveFlowCounts: []userspace.CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 5},
			{Ifindex: 80, QueueID: 4, WorkerID: 1, ActiveFlowCount: 5},
		},
	}
	out := FormatFairnessRSS(complete, []userspace.FairnessRSSExpectation{
		{Interface: "reth0", QueueID: 4, RSSExpectation: "balanced"},
		{Interface: "reth0", QueueID: 4, RSSExpectation: "max-worker-flow-share:0.4"},
	})
	for _, want := range []string{"balanced                     PASS", "max-worker-flow-share:0.4    FAIL"} {
		if !strings.Contains(out, want) {
			t.Fatalf("complete snapshot missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "INDETERMINATE") {
		t.Fatalf("a complete snapshot must never render INDETERMINATE:\n%s", out)
	}
	truncated := complete
	truncated.CoSActiveFlowCountsTruncated = true
	out = FormatFairnessRSS(truncated, []userspace.FairnessRSSExpectation{
		{Interface: "reth0", QueueID: 4, RSSExpectation: "balanced"},
	})
	if !strings.Contains(out, "balanced                     INDETERMINATE") {
		t.Fatalf("truncated snapshot must render INDETERMINATE:\n%s", out)
	}
}

func TestFormatFlowWorkerMap(t *testing.T) {
	cosQueue := uint8(4)
	dscpRewrite := uint8(46)
	status := userspace.ProcessStatus{
		FlowWorkerMapTruncated: true,
		FlowWorkerMap: []userspace.FlowWorkerStatus{
			{
				Slot:           3,
				QueueID:        2,
				WorkerID:       1,
				Interface:      "ge-0-0-2",
				Ifindex:        80,
				IngressIfindex: 70,
				EgressIfindex:  80,
				TxIfindex:      80,
				CoSQueueID:     &cosQueue,
				DSCPRewrite:    &dscpRewrite,
				AgeEpochs:      7,
				ObservedBytes:  123456,
				SessionKey: userspace.FlowTupleStatus{
					Protocol: 6,
					SrcIP:    "172.16.80.10",
					SrcPort:  40000,
					DstIP:    "172.16.80.200",
					DstPort:  5201,
				},
				ForwardWireKey: userspace.FlowTupleStatus{
					Protocol: 6,
					SrcIP:    "172.16.80.10",
					SrcPort:  40000,
					DstIP:    "172.16.80.200",
					DstPort:  5201,
				},
				ReverseCanonicalKey: userspace.FlowTupleStatus{
					Protocol: 6,
					SrcIP:    "172.16.80.200",
					SrcPort:  5201,
					DstIP:    "172.16.80.10",
					DstPort:  40000,
				},
			},
			{
				Slot:     1,
				QueueID:  1,
				WorkerID: 0,
				SessionKey: userspace.FlowTupleStatus{
					Protocol: 17,
					SrcIP:    "2001:db8::1",
					SrcPort:  12345,
					DstIP:    "2001:db8::2",
					DstPort:  5201,
				},
			},
		},
	}

	out := FormatFlowWorkerMap(status, 1)
	for _, want := range []string{
		"Userspace flow-worker map:",
		"warning: helper flow-worker snapshot truncated",
		"showing first 1 of 2 rows",
		"Worker",
		"Queue",
		"Session",
		"0      1      1",
		"udp [2001:db8::1]:12345->[2001:db8::2]:5201",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("flow-worker output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "172.16.80.10") {
		t.Fatalf("flow-worker output exceeded limit:\n%s", out)
	}

	allOut := FormatFlowWorkerMap(status, flowWorkerMapAllLimit)
	if strings.Contains(allOut, "showing first") {
		t.Fatalf("flow-worker all output should not be bounded:\n%s", allOut)
	}
	for _, want := range []string{
		"172.16.80.10:40000->172.16.80.200:5201",
		"wire=tcp 172.16.80.10:40000->172.16.80.200:5201",
		"reverse=tcp 172.16.80.200:5201->172.16.80.10:40000",
		"observed-bytes=123456",
	} {
		if !strings.Contains(allOut, want) {
			t.Fatalf("flow-worker all output missing %q:\n%s", want, allOut)
		}
	}
}

func TestParseFlowWorkerMapLimitSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    int
		wantErr bool
	}{
		{name: "default", spec: "", want: 0},
		{name: "all", spec: "all", want: flowWorkerMapAllLimit},
		{name: "bare limit", spec: "256", want: 256},
		{name: "limit keyword", spec: "limit 4096", want: 4096},
		{name: "limit equals", spec: "limit=1024", want: 1024},
		{name: "zero", spec: "limit 0", wantErr: true},
		{name: "negative", spec: "-1", wantErr: true},
		{name: "extra", spec: "limit 1 extra", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFlowWorkerMapLimitSpec(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseFlowWorkerMapLimitSpec(%q) succeeded, want error", tt.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFlowWorkerMapLimitSpec(%q) error = %v", tt.spec, err)
			}
			if got != tt.want {
				t.Fatalf("ParseFlowWorkerMapLimitSpec(%q) = %d, want %d", tt.spec, got, tt.want)
			}
		})
	}
}

func TestFormatBindings(t *testing.T) {
	status := userspace.ProcessStatus{
		Fabrics: []userspace.FabricSnapshot{
			{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7, OverlayLinux: "fab0", OverlayIfindex: 17, RXQueues: 4, PeerAddress: "10.99.1.2"},
		},
		Queues: []userspace.QueueStatus{
			{QueueID: 0, WorkerID: 0, Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Registered: true, Armed: false, Ready: false},
		},
		Bindings: []userspace.BindingStatus{
			{Slot: 0, QueueID: 0, WorkerID: 0, Registered: true, Armed: false, Ready: false, Bound: true, XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, Ifindex: 5, Interface: "ge-0-0-1", SharedUMEMMode: "cross-nic", SharedUMEMSocketRole: "owner", SharedUMEMGroup: "cross-nic:w0:ge-0-0-1,ge-0-0-2", RXPackets: 99, TXPackets: 7, DirectTXPackets: 5, CopyTXPackets: 1, InPlaceTXPackets: 1, ExceptionPackets: 3},
			{Slot: 1, QueueID: 0, WorkerID: 0, Registered: true, Armed: false, Ready: false, Bound: true, XSKRegistered: false, Ifindex: 6, Interface: "ge-0-0-2", ExceptionPackets: 1, LastError: "xsk map update failed"},
		},
		RecentExceptions: []userspace.ExceptionStatus{
			{Timestamp: time.Unix(0, 0).UTC(), Slot: 1, QueueID: 0, Interface: "ge-0-0-2", Reason: "fib_generation_mismatch", PacketLength: 512, AddrFamily: 10, Protocol: 6, ConfigGeneration: 11, FIBGeneration: 9, RuleName: "snat-a", PoolName: "pool-a"},
		},
	}

	out := FormatBindings(status)
	for _, want := range []string{
		"Userspace queues:",
		"Userspace fabric links:",
		"fab0",
		"Userspace bindings:",
		"ge-0-0-1,ge-0-0-2",
		"ge-0-0-1",
		"ge-0-0-2",
		"zerocopy",
		"TXPkts",
		"DirTx",
		"CopyTx",
		"InPlTx",
		"shared=cross-nic",
		"role=owner",
		"group=cross-nic:w0:ge-0-0-1,ge-0-0-2",
		"xsk map update failed",
		"Recent userspace exceptions:",
		"fib_generation_mismatch",
		"rule=snat-a",
		"pool=pool-a",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("bindings output missing %q:\n%s", want, out)
		}
	}
}
