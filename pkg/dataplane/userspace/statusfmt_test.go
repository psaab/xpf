package userspace

import (
	"strings"
	"testing"
	"time"
)

func TestFormatStatusSummary(t *testing.T) {
	now := time.Now().UTC()
	status := ProcessStatus{
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
		RouteEntries:           4,
		HAGroups: []HAGroupStatus{
			{RGID: 0, Active: true, WatchdogTimestamp: 100},
			{RGID: 1, Active: false, WatchdogTimestamp: 0},
			{RGID: 2, Active: false, WatchdogTimestamp: 0},
		},
		Fabrics: []FabricSnapshot{
			{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7, OverlayLinux: "fab0", OverlayIfindex: 17, RXQueues: 4, PeerAddress: "10.99.1.2"},
		},
		LastResolution: &PacketResolution{
			Disposition:   "forward_candidate",
			EgressIfindex: 11,
			NextHop:       "172.16.50.1",
			NeighborMAC:   "00:10:db:ff:10:01",
		},
		WorkerHeartbeats: []time.Time{now.Add(-500 * time.Millisecond), now.Add(-700 * time.Millisecond)},
		Queues: []QueueStatus{
			{QueueID: 0, Armed: false, Ready: true},
			{QueueID: 1, Armed: false, Ready: false},
		},
		Bindings: []BindingStatus{
			{Slot: 0, Armed: false, Ready: true, Bound: true, XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, SharedUMEMMode: "cross-nic", SharedUMEMSocketRole: "owner", SharedUMEMGroup: "cross-nic:w0:ge-0-0-1,ge-0-0-2", RXPackets: 10, ValidatedPackets: 8, ExceptionPackets: 1, TXPackets: 3, TXBytes: 420, TXCompletions: 2, MirroredPackets: 4, MirroredBytes: 512, MirrorDropsNoFrame: 1, KernelRXDropped: 9, KernelRXInvalidDescs: 1, DirectTXPackets: 2, InPlaceTXPackets: 1, InPlaceVLANPushDescPackets: 8, InPlaceVLANPopDescPackets: 9, InPlaceVLANPushNoHeadroomPackets: 10, InPlaceL2MemmoveFallbackPackets: 11, DirectTXNoFrameFallbackPackets: 5, DirectTXBuildFallbackPackets: 6, DebugPendingFillFrames: 10, DebugSpareFillFrames: 11, DebugFreeTXFrames: 12, DebugPendingTXPrepared: 13, DebugPendingTXLocal: 14, DebugOutstandingTX: 15, DebugInFlightRecycles: 16},
			{Slot: 1, Armed: false, Ready: false, Bound: true, XSKRegistered: false, RXPackets: 5, ValidatedPackets: 4, ExceptionPackets: 2, TXErrors: 1, TXSharedRecycleUnknownSlotDrops: 1, TXCompletions: 3, MirroredPackets: 6, MirroredBytes: 768, MirrorDropsNoBinding: 2, MirrorDropsQueueFull: 3, KernelRXDropped: 4, KernelRXInvalidDescs: 2, CopyTXPackets: 4, InPlaceVLANPushDescPackets: 3, InPlaceVLANPopDescPackets: 4, InPlaceVLANPushNoHeadroomPackets: 5, InPlaceL2MemmoveFallbackPackets: 6, DirectTXDisallowedFallbackPackets: 7, DebugPendingFillFrames: 20, DebugSpareFillFrames: 21, DebugFreeTXFrames: 22, DebugPendingTXPrepared: 23, DebugPendingTXLocal: 24, DebugOutstandingTX: 25, DebugInFlightRecycles: 26},
		},
		RecentExceptions: []ExceptionStatus{
			{Timestamp: now, Slot: 1, QueueID: 0, Interface: "ge-0-0-2", Reason: "metadata_parse", PacketLength: 128},
		},
		EventStreamSent:    101,
		EventStreamDropped: 7,
		EventStream: &EventStreamStatus{
			FramesRead:        11,
			FramesWritten:     5,
			DecodeErrors:      2,
			SeqGaps:           3,
			PolicyDenyEvents:  13,
			ScreenDropEvents:  17,
			FilterLogEvents:   19,
			PolicyDenyDrops:   1,
			ScreenDropDrops:   4,
			FilterLogDrops:    9,
			UnknownFrameDrops: 6,
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
		"Event stream events:       policy_deny=13 screen_drop=17 filter_log=19 unknown_drops=6",
		"Event stream drops:        policy_deny=1 screen_drop=4 filter_log=9",
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

func TestFormatStatusSummaryWorkerRuntimeRolling60sColumn(t *testing.T) {
	// Three workers: w0 has a fully-populated window (45s CPU over 60s = 75%);
	// w1 has only cumulative data and no rotation yet (window_ns=0, show "-");
	// w2 is dead (windowed column suppressed by DEAD row).
	status := ProcessStatus{
		WorkerRuntime: []WorkerRuntimeStatus{
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
	status := ProcessStatus{
		ThreeColorPolicerCounters: []ThreeColorPolicerStatus{
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
	status := ProcessStatus{
		ForwardingArmed: true,
		HAGroups: []HAGroupStatus{
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
	status := ProcessStatus{
		Bindings: []BindingStatus{
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
	status := ProcessStatus{
		Bindings: []BindingStatus{
			{TXErrors: 100, DbgCoSQueueOverflow: 50},
		},
		CoSInterfaces: []CoSInterfaceStatus{
			{
				Queues: []CoSQueueStatus{
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
	status := ProcessStatus{
		Bindings: []BindingStatus{
			{TXErrors: 100, DbgCoSQueueOverflow: 80},
		},
		CoSInterfaces: []CoSInterfaceStatus{
			{
				Queues: []CoSQueueStatus{
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
	status := ProcessStatus{
		Bindings: []BindingStatus{
			{TXErrors: 1, DbgCoSQueueOverflow: 2},
		},
		CoSInterfaces: []CoSInterfaceStatus{
			{
				Queues: []CoSQueueStatus{
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
	status := ProcessStatus{
		CoSActiveFlowCountsTruncated: true,
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: 4, WorkerID: 1, ActiveFlowCount: 3},
			{Ifindex: 80, QueueID: 4, WorkerID: 2, ActiveFlowCount: 0},
			{Ifindex: 80, QueueID: 5, WorkerID: 0, ActiveFlowCount: 2},
			{Ifindex: 80, QueueID: 5, WorkerID: 1, ActiveFlowCount: 2},
		},
	}

	out := FormatFairnessRSS(status, []FairnessRSSExpectation{
		{Ifindex: 80, QueueID: 4, RSSExpectation: "balanced"},
		{Ifindex: 80, QueueID: 5, RSSExpectation: "max-worker-flow-share:50%"},
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
		"80       4       balanced                     false",
		"balanced: active_workers=2 expected",
		"80       5       max-worker-flow-share:0.5    true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("fairness output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatFairnessRSSShowsExpectationsWithoutRows(t *testing.T) {
	out := FormatFairnessRSS(ProcessStatus{Workers: 4}, []FairnessRSSExpectation{
		{Ifindex: 80, QueueID: 4, RSSExpectation: "cstruct-max:0.25"},
	})
	for _, want := range []string{
		"Userspace fairness RSS structure:",
		"  none",
		"RSS expectations:",
		"80       4       cstruct-max:0.25",
		"false",
		"cstruct-max: no active flows observed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("fairness output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatFlowWorkerMap(t *testing.T) {
	cosQueue := uint8(4)
	dscpRewrite := uint8(46)
	status := ProcessStatus{
		FlowWorkerMapTruncated: true,
		FlowWorkerMap: []FlowWorkerStatus{
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
				SessionKey: FlowTupleStatus{
					Protocol: 6,
					SrcIP:    "172.16.80.10",
					SrcPort:  40000,
					DstIP:    "172.16.80.200",
					DstPort:  5201,
				},
				ForwardWireKey: FlowTupleStatus{
					Protocol: 6,
					SrcIP:    "172.16.80.10",
					SrcPort:  40000,
					DstIP:    "172.16.80.200",
					DstPort:  5201,
				},
				ReverseCanonicalKey: FlowTupleStatus{
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
				SessionKey: FlowTupleStatus{
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
	status := ProcessStatus{
		Fabrics: []FabricSnapshot{
			{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7, OverlayLinux: "fab0", OverlayIfindex: 17, RXQueues: 4, PeerAddress: "10.99.1.2"},
		},
		Queues: []QueueStatus{
			{QueueID: 0, WorkerID: 0, Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Registered: true, Armed: false, Ready: false},
		},
		Bindings: []BindingStatus{
			{Slot: 0, QueueID: 0, WorkerID: 0, Registered: true, Armed: false, Ready: false, Bound: true, XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, Ifindex: 5, Interface: "ge-0-0-1", SharedUMEMMode: "cross-nic", SharedUMEMSocketRole: "owner", SharedUMEMGroup: "cross-nic:w0:ge-0-0-1,ge-0-0-2", RXPackets: 99, TXPackets: 7, DirectTXPackets: 5, CopyTXPackets: 1, InPlaceTXPackets: 1, ExceptionPackets: 3},
			{Slot: 1, QueueID: 0, WorkerID: 0, Registered: true, Armed: false, Ready: false, Bound: true, XSKRegistered: false, Ifindex: 6, Interface: "ge-0-0-2", ExceptionPackets: 1, LastError: "xsk map update failed"},
		},
		RecentExceptions: []ExceptionStatus{
			{Timestamp: time.Unix(0, 0).UTC(), Slot: 1, QueueID: 0, Interface: "ge-0-0-2", Reason: "fib_generation_mismatch", PacketLength: 512, AddrFamily: 10, Protocol: 6, ConfigGeneration: 11, FIBGeneration: 9},
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
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("bindings output missing %q:\n%s", want, out)
		}
	}
}
