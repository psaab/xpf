package format

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// updateGolden regenerates the byte-identity golden fixtures instead of
// comparing against them. Run with `go test ... -update` after a deliberate,
// reviewed change to the FormatStatusSummary output.
var updateGolden = flag.Bool("update", false, "regenerate status-summary golden fixtures")

// goldenStatusSummaryFixture builds a ProcessStatus that exercises every
// conditional section of FormatStatusSummary so the golden pins the full,
// byte-for-byte rendered output. It deliberately avoids wall-clock-relative
// fields (LastSnapshotAt / non-zero WorkerHeartbeats) whose rendering depends
// on time.Now(); those durations are covered by the substring tests in
// status_test.go. Everything here renders deterministically.
func goldenStatusSummaryFixture() userspace.ProcessStatus {
	return userspace.ProcessStatus{
		PID:                    4242,
		HelperMode:             "rust-native",
		IOUringActive:          true,
		IOUringMode:            "sqpoll",
		IOUringLastError:       "transient EAGAIN",
		Enabled:                true,
		ForwardingArmed:        true,
		Workers:                3,
		RingEntries:            4096,
		LastSnapshotGeneration: 12,
		LastFIBGeneration:      5,
		InterfaceAddresses:     8,
		NeighborEntries:        14,
		NeighborCacheCapacity:  128,
		NeighborGeneration:     6,
		SessionTableEntries:    321,
		MaxSessions:            1000,
		FlowCacheCapacity:      16384,
		RouteEntries:           9,
		Capabilities: userspace.UserspaceCapabilities{
			ForwardingSupported: false,
			UnsupportedReasons:  []string{"reason-a", "reason-b"},
		},
		HAGroups: []userspace.HAGroupStatus{
			{RGID: 0, Active: true, WatchdogTimestamp: 100},
			{RGID: 1, Active: false, WatchdogTimestamp: 0},
		},
		Fabrics: []userspace.FabricSnapshot{
			{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7, OverlayLinux: "fab0", OverlayIfindex: 17, RXQueues: 4, PeerAddress: "10.99.1.2"},
		},
		DegradedPathCounters: map[string]uint64{
			"transit_drop":  5,
			"ctrl_disabled": 1,
		},
		LastResolution: &userspace.PacketResolution{
			Disposition:    "forward_candidate",
			IngressIfindex: 70,
			LocalIfindex:   71,
			EgressIfindex:  80,
			NextHop:        "172.16.50.1",
			NeighborMAC:    "00:10:db:ff:10:01",
			SrcIP:          "172.16.80.10",
			SrcPort:        40000,
			DstIP:          "172.16.80.200",
			DstPort:        5201,
			FromZone:       "trust",
			ToZone:         "untrust",
		},
		Queues: []userspace.QueueStatus{
			{QueueID: 0, WorkerID: 0, Registered: true, Armed: true, Ready: true},
			{QueueID: 1, WorkerID: 1, Registered: true, Armed: false, Ready: false},
		},
		Bindings: []userspace.BindingStatus{
			{
				Slot: 0, Armed: true, Ready: true, Bound: true, XSKRegistered: true, ZeroCopy: true,
				SharedUMEMMode: "cross-nic", SharedUMEMSocketRole: "owner",
				RXPackets: 100, ValidatedPackets: 90, ForwardCandidatePkts: 80,
				FlowlessForwardPkts: 7, FlowlessForwardBytes: 700,
				RouteMissPackets: 2, MartianDropped: 1, IPv6ExtHeaderDropped: 4,
				NeighborMissPackets: 1, ExceptionPackets: 3,
				FlowCacheHits: 40, FlowCacheMisses: 10, FlowCacheEvictions: 1,
				SessionHits: 50, SessionMisses: 12, SessionCreates: 8, SessionExpires: 4,
				SessionDeltaPending: 2, SessionDeltaGenerated: 6, SessionDeltaDropped: 1, SessionDeltaDrained: 5,
				PolicyDeniedPackets: 7, ScreenDrops: 9,
				SYNCookieChallenges: 3, SYNCookieSecretUnavailable: 1, SYNCookieSynAckSent: 2, SYNCookieAckRstSent: 1,
				SYNCookieReplyBudgetDrops: 1, SYNCookieAckValid: 5, SYNCookieAckInvalid: 2, SYNCookieBypass: 4,
				TimeExceededOutputFilterDrops: 1, PolicyRejectOutputFilterDrops: 2, FilterRejectOutputFilterDrops: 3,
				SYNCookieOutputFilterDrops: 1, PTBOutputFilterDrops: 1, GeneratedReplyClassifyParseErrors: 1,
				PolicyRejectSent: 5, FilterRejectSent: 2,
				PolicyRejectReplyBudgetDrops: 3, FilterRejectReplyBudgetDrops: 1,
				PolicyRejectRateLimitDrops: 4, FilterRejectRateLimitDrops: 6,
				SNATPackets: 30, DNATPackets: 20,
				Nat64Translations: 12, Nat64NoSourcePool: 3, Nat64PoolExhausted: 5, Nat64FragDropped: 2, Nat64IneligibleSource: 4, Nat64IneligibleDest: 6, Nat64ExthdrIneligible: 7, Nat64IneligibleProtocol: 11, Nat64TunnelEncapUnsupported: 13,
				NatFragUntranslatedDropped: 9,
				FragOverlapDropped:         14, FragOverlapOverflowDropped: 15, FragOverlapShardFullDropped: 16, FragOverlapPostNATDropped: 17, FragOverlapMaxLifetimeEvictions: 18,
				TXPackets: 70, TXBytes: 9000, TXErrors: 100, DbgCoSQueueOverflow: 40,
				TXSharedRecycleUnknownSlotDrops: 1, TXCompletions: 65,
				MirroredPackets: 4, MirroredBytes: 512, MirrorDropsNoFrame: 1, MirrorDropsTXFrameReserve: 1,
				MirrorDropsNoBinding: 1, MirrorDropsQueueFull: 2, MirrorDropsQueueFullSameWorker: 1, MirrorDropsQueueFullCrossWorker: 1,
				KernelRXDropped: 9, KernelRXInvalidDescs: 1,
				DirectTXPackets: 40, CopyTXPackets: 20, InPlaceTXPackets: 10,
				InPlaceVLANPushDescPackets: 5, InPlaceVLANPopDescPackets: 6, InPlaceVLANPushNoHeadroomPackets: 1, InPlaceL2MemmoveFallbackPackets: 2,
				DirectTXNoFrameFallbackPackets: 3, DirectTXBuildFallbackPackets: 2, DirectTXDisallowedFallbackPackets: 1,
				DebugPendingFillFrames: 10, DebugSpareFillFrames: 11, DebugFreeTXFrames: 12,
				DebugPendingTXPrepared: 13, DebugPendingTXLocal: 14, DebugOutstandingTX: 15, DebugInFlightRecycles: 16,
				SlowPathPackets: 6, SlowPathLocalDeliveryPackets: 2, SlowPathMissingNeighborPackets: 1,
				SlowPathNoRoutePackets: 1, SlowPathNextTablePackets: 1, SlowPathForwardBuildPackets: 1, SlowPathDrops: 2,
			},
		},
		EventStream: &userspace.EventStreamStatus{
			FramesRead: 11, FramesWritten: 5, DecodeErrors: 2, SeqGaps: 3,
			PolicyDenyEvents: 13, ScreenDropEvents: 17, ScreenAlarmEvents: 23, FilterLogEvents: 19,
			SessionCloseEvents: 29, SessionCreateEvents: 31, UnknownFrameDrops: 6,
			PolicyDenyDrops: 1, ScreenDropDrops: 4, FilterLogDrops: 9, SessionCloseDrops: 7, SessionCreateDrops: 8,
		},
		EventStreamSent: 101, EventStreamDropped: 7, EventStreamWriteStalls: 2,
		EventStreamReplayEvictions: 1, EventStreamInvalidAcks: 0,
		EventStreamSessionCloseSent: 90, EventStreamSessionCloseDropped: 3,
		EventStreamSessionCreateSent: 12, EventStreamSessionCreateDropped: 1,
		SourceNATPools: []userspace.SourceNATPoolStatus{
			{PoolName: "pool-a", RuleName: "rule-a", PersistentNAT: true, PersistentNATPermit: "target-host", LiveFlows: 3, MaxTrackedFlows: 64, UsedPorts: 30, PersistentLeases: 2, AllocationsTotal: 10, ReusesTotal: 4, ExhaustionTotal: 1},
		},
		CoSInterfaces: []userspace.CoSInterfaceStatus{
			{
				Queues: []userspace.CoSQueueStatus{
					{AdmissionFlowShareDrops: 3, AdmissionBufferDrops: 2, AdmissionEcnMarked: 7},
				},
			},
		},
		ThreeColorPolicerCounters: []userspace.ThreeColorPolicerStatus{
			{ID: 2, Name: "wan-egress", Mode: "single-rate", ColorBlind: true, GreenPackets: 10, YellowPackets: 3, RedPackets: 2, DropPackets: 2, GreenBytes: 1000, YellowBytes: 300, RedBytes: 200, DropBytes: 200},
		},
		SlowPath: userspace.SlowPathStatus{
			Active: true, Degraded: true, LiveMTU: 1400, DeviceName: "slow0", Mode: "tap",
			QueuedPackets: 4, InjectedPackets: 100, InjectedBytes: 20000, DroppedPackets: 2, DroppedBytes: 400,
			RateLimitedPackets: 1, QueueFullPackets: 1, MTUDroppedPackets: 1, WriteErrors: 1, LastError: "write EIO",
		},
		SlowPathDelegated: userspace.SlowPathStatus{
			Active: true, Degraded: true, LiveMTU: 1500, DeviceName: "slow1", Mode: "sync",
			QueuedPackets: 5, InjectedPackets: 70, InjectedBytes: 14000, DroppedPackets: 3, DroppedBytes: 600,
			RateLimitedPackets: 2, QueueFullPackets: 1, MTUDroppedPackets: 2, WriteErrors: 2, LastError: "delegated EIO",
		},
		RecentExceptions: []userspace.ExceptionStatus{
			{Slot: 0, QueueID: 0, Interface: "ge-0-0-2", Reason: "metadata_parse", PacketLength: 128},
		},
		WorkerHeartbeats: []time.Time{{}, {}},
		WorkerRuntime: []userspace.WorkerRuntimeStatus{
			{
				WorkerID: 0, TID: 111,
				WallNS:      3600 * 1_000_000_000,
				ActiveNS:    1800 * 1_000_000_000,
				IdleSpinNS:  900 * 1_000_000_000,
				IdleBlockNS: 900 * 1_000_000_000,
				ThreadCPUNS: 1800 * 1_000_000_000,
				WorkLoops:   1000, IdleLoops: 2000,
				WindowNS: 60 * 1_000_000_000, ThreadCPUNS60s: 45 * 1_000_000_000,
			},
			{WorkerID: 1, TID: 222, WorkLoops: 3, IdleLoops: 4},
			{WorkerID: 2, TID: 333, Dead: true, PanicMessage: "boom"},
		},
	}
}

func TestFormatStatusSummaryGolden(t *testing.T) {
	got := FormatStatusSummary(goldenStatusSummaryFixture())
	goldenPath := filepath.Join("testdata", "status_summary.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to generate): %v", err)
	}
	if got != string(want) {
		t.Fatalf("FormatStatusSummary output diverged from golden.\n--- got ---\n%s\n--- want ---\n%s", got, string(want))
	}
}
