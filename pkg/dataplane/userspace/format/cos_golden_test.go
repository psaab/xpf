package format

import (
	"testing"

	"github.com/psaab/xpf/internal/testgolden"
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// goldenCoSSummaryStatus builds a ProcessStatus that exercises every
// conditional block of FormatCoSInterfaceSummary so the golden pins the
// full, byte-for-byte rendered output: the config header (scheduler map,
// classifiers, shaping/burst), the output filter line, the runtime
// worker/queue/timer/waterfill header, the interface-level binding
// telemetry line, and — across two queues — the aligned queue table plus
// the interleaved Drops / Sojourn / Surplus sharing / Equal-flow /
// OwnerProfile / DrainShape / per-queue Waterfill detail rows. Paired with
// testCoSConfig() (queue 0 best-effort + queue 4 exact bandwidth-10mb).
func goldenCoSSummaryStatus() *userspace.ProcessStatus {
	owner := uint32(7)

	// Drain-latency histogram (DRAIN_HIST_BUCKETS layout): p50 in bucket 1
	// ("1us"), p99 in bucket 5 ("16us").
	drainHist := make([]uint64, 16)
	drainHist[1] = 50
	drainHist[2] = 48
	drainHist[5] = 2
	// Redirect-acquire histogram: p99 in bucket 2 ("2us").
	redirectHist := make([]uint64, 16)
	redirectHist[2] = 10

	return &userspace.ProcessStatus{
		CoSInterfaces: []userspace.CoSInterfaceStatus{
			{
				InterfaceName:               "reth0.80",
				OwnerWorkerID:               &owner,
				WorkerInstances:             2,
				NonemptyQueues:              1,
				RunnableQueues:              1,
				TimerLevel0Sleepers:         1,
				TimerLevel1Sleepers:         0,
				WaterfillEpochs:             12,
				WaterfillPhase1BudgetBreaks: 3,
				WaterfillMinEpochsPerWorker: 4,
				Queues: []userspace.CoSQueueStatus{
					{
						QueueID:                 0,
						ForwardingClass:         "best-effort",
						Priority:                0,
						Exact:                   false,
						TransmitRateBytes:       1_875_000,
						BufferBytes:             16 * 1024,
						QueuedPackets:           1,
						QueuedBytes:             1500,
						RunnableInstances:       1,
						ParkedInstances:         0,
						NextWakeupTick:          0,
						AdmissionFlowShareDrops: 0,
						AdmissionBufferDrops:    0,
						AdmissionEcnMarked:      0,
					},
					{
						QueueID:             4,
						OwnerWorkerID:       &owner,
						ForwardingClass:     "bandwidth-10mb",
						Priority:            1,
						Exact:               true,
						TransmitRateBytes:   1_250_000,
						BufferBytes:         32 * 1024,
						QueuedPackets:       3,
						QueuedBytes:         4096,
						RunnableInstances:   1,
						ParkedInstances:     1,
						NextWakeupTick:      77,
						SurplusDeficitBytes: 2048,

						AdmissionFlowShareDrops: 3,
						AdmissionBufferDrops:    2,
						AdmissionEcnMarked:      7,

						EqualFlowEnforcement:          true,
						EqualFlowEnforced:             true,
						EqualFlowTargetPerFlowBPS:     8_000_000,
						EqualFlowMaxWorkerCapBytes:    2 * 1024,
						EqualFlowCapHitEvents:         5,
						EqualFlowSuppressedGrantBytes: 900,
						EqualFlowTargetPolicy:         "strict",

						DrainLatencyHist:     drainHist,
						DrainInvocations:     100,
						DrainNoopInvocations: 30,
						RedirectAcquireHist:  redirectHist,
						OwnerPPS:             12345,
						PeerPPS:              6789,
						PostDrainBackupBytes: 4321,

						DrainSentBytes:                             10000,
						DrainGuaranteeSentBytes:                    6000,
						DrainSurplusSentBytes:                      4000,
						DrainNonExactSentBytesWhileExactBacklogged: 512,
						DrainParkRootTokens:                        2,
						DrainParkQueueTokens:                       1,

						SojournEwmaNS:        1500,
						SojournPeakNS:        2_000_000,
						SojournWindowedMinNS: 800,

						WaterfillPhase1Admissions:         40,
						WaterfillPhase2Admissions:         12,
						WaterfillEligibleVisits:           55,
						WaterfillPhase1SelectedNoProgress: 4,
					},
				},
			},
		},
	}
}

func TestFormatCoSInterfaceSummaryGolden(t *testing.T) {
	testgolden.String(t, "testdata/cos_summary.golden", FormatCoSInterfaceSummary(testCoSConfig(), goldenCoSSummaryStatus(), ""))
}
