package format

import (
	"testing"

	"github.com/psaab/xpf/internal/testgolden"
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// goldenSystemBuffersStatus builds a ProcessStatus that exercises every
// conditional block of FormatSystemBuffers so the golden pins the full,
// byte-for-byte rendered output across both render modes: the bounded
// utilization table (AF_XDP UMEM + TX aggregate/detail rows, CoS queue-bytes
// aggregate/detail, bounded session/flow-cache/neighbor rows), the WARNING /
// CRITICAL usage classification and the high-utilization warning count, and the
// unbounded status counters section (NAT reverse-key, pending-neighbor,
// flow-cache eviction, fill/TX-frame, and SYN-cookie counters) with its
// per-binding detail rows. It uses only deterministic fields — FormatSystemBuffers
// has no wall-clock dependence — so the golden is stable.
func goldenSystemBuffersStatus() userspace.ProcessStatus {
	owner := uint32(2)
	return userspace.ProcessStatus{
		SessionTableEntries:                   920,
		MaxSessions:                           1000,
		NeighborEntries:                       42,
		NeighborCacheCapacity:                 50,
		NatReverseKeyCollisions:               6,
		NatReverseKeySharedDisplacementsTotal: 3,
		NeighborPendingMaxDepth:               9,
		NeighborPendingTimeoutDropsTotal:      4,
		Bindings: []userspace.BindingStatus{
			{
				Slot: 0, WorkerID: 0, QueueID: 0, Ifindex: 7, Interface: "ge-0-0-1",
				UmemTotalFrames: 1000, UmemInflightFrames: 820,
				TxRingCapacity: 100, OutstandingTX: 90,
				ActiveFlowCount: 900, FlowCacheCapacity: 1000,
				FlowCacheCollisionEvictions: 5,
				DebugPendingFillFrames:      3, DebugSpareFillFrames: 5,
				DebugPendingTXPrepared: 7, DebugPendingTXLocal: 11,
				DbgTxRingFull: 13, DbgSendtoENOBUFS: 17,
				DbgBoundPendingOverflow: 19, DbgCoSQueueOverflow: 23,
				RxFillRingEmptyDescs: 37, RedirectInboxOverflowDrops: 41,
				PendingTXLocalOverflowDrops: 43, TxSubmitErrorDrops: 47,
				SYNCookieChallenges: 3, SYNCookieSecretUnavailable: 1,
				SYNCookieSynAckSent: 2, SYNCookieAckRstSent: 1,
				SYNCookieReplyBudgetDrops: 1, SYNCookieAckValid: 5,
				SYNCookieAckInvalid: 2, SYNCookieBypass: 4,
			},
			{
				Slot: 1, WorkerID: 1, QueueID: 0, Ifindex: 8, Interface: "ge-0-0-2",
				UmemTotalFrames: 1000, UmemInflightFrames: 100,
				TxRingCapacity: 100, OutstandingTX: 10,
				ActiveFlowCount: 100, FlowCacheCapacity: 1000,
				FlowCacheCollisionEvictions: 2,
				SYNCookieChallenges:         17, SYNCookieAckValid: 41,
			},
		},
		CoSInterfaces: []userspace.CoSInterfaceStatus{
			{
				Ifindex:       9,
				InterfaceName: "reth0.80",
				Queues: []userspace.CoSQueueStatus{
					{QueueID: 2, OwnerWorkerID: &owner, ForwardingClass: "ef", BufferBytes: 1000, QueuedBytes: 850},
					{QueueID: 3, ForwardingClass: "be", BufferBytes: 1000, QueuedBytes: 100},
				},
			},
		},
	}
}

// TestFormatSystemBuffersGolden pins the byte-for-byte output of both render
// modes and the "unavailable" branch. It is the byte-identity gate for the
// #4661 model/render split: the model (buffers_model.go) and renderers
// (buffers.go) may be reorganized freely so long as this output is unchanged.
// Run with `go test ... -update` after a deliberate, reviewed output change.
func TestFormatSystemBuffersGolden(t *testing.T) {
	status := goldenSystemBuffersStatus()
	got := "=== detail=false ===\n" + FormatSystemBuffers(status, false) +
		"=== detail=true ===\n" + FormatSystemBuffers(status, true) +
		"=== unavailable ===\n" + FormatSystemBuffers(userspace.ProcessStatus{
		PerBinding: []userspace.BindingCountersSnapshot{{WorkerID: 0, QueueID: 0, OutstandingTX: 10}},
	}, false)

	testgolden.String(t, "testdata/system_buffers.golden", got)
}
