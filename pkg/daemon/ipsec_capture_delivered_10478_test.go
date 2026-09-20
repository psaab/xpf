package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/nfqueue"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func newDeliveredPipeline10478(t *testing.T, reader func() (xnft.TransitFenceCounter, bool, error)) *IpsecCapturePipeline {
	t.Helper()
	supervisor := newIpsecSupervisor()
	supervisor.permit.Store(&permitRecord{state: ipsecPermitOpen, permitEpoch: 17})
	actor, err := NewIpsecCapturePipeline(IpsecCapturePipelineConfig{
		Supervisor:             supervisor,
		Registry:               new(nfqueue.OriginRegistry),
		RunID:                  "run-delivered-10478",
		DeliveredCounterReader: reader,
		Pipeline:               nfqueue.CapturePipelineConfig{Phase: nfqueue.PipelineQuarantine},
	})
	if err != nil {
		t.Fatalf("NewIpsecCapturePipeline: %v", err)
	}
	// A synthetic OPEN rotation gives Status the same authenticated join label
	// shape as a live generation without opening NFQUEUE handles in this cell.
	actor.rotation = &ipsecRotation{stateValue: ipsecRotationOpen, generation: 42}
	return actor
}

func TestIpsecCaptureDeliveredDeltaAndJoinLabels10478(t *testing.T) {
	samples := []xnft.TransitFenceCounter{{Packets: 41}, {Packets: 47}}
	index := 0
	actor := newDeliveredPipeline10478(t, func() (xnft.TransitFenceCounter, bool, error) {
		sample := samples[index]
		index++
		return sample, true, nil
	})
	if err := actor.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer actor.Stop()
	status := actor.Status()
	if !status.DeliveredAvailable || status.Delivered != 6 {
		t.Fatalf("delivered=(available=%v,count=%d), want (true,6)", status.DeliveredAvailable, status.Delivered)
	}
	if status.RunID != "run-delivered-10478" || status.Generation != 42 || status.PermitEpoch != 17 {
		t.Fatalf("join labels=(run=%q,generation=%d,permit_epoch=%d), want run-delivered-10478/42/17", status.RunID, status.Generation, status.PermitEpoch)
	}
}

func TestIpsecCaptureDeliveredNegativeDeltaLatchesUnavailable10478(t *testing.T) {
	samples := []xnft.TransitFenceCounter{{Packets: 10}, {Packets: 9}, {Packets: 100}}
	index := 0
	actor := newDeliveredPipeline10478(t, func() (xnft.TransitFenceCounter, bool, error) {
		sample := samples[index]
		index++
		return sample, true, nil
	})
	if err := actor.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer actor.Stop()
	if status := actor.Status(); status.DeliveredAvailable || status.Delivered != 0 {
		t.Fatalf("negative delta status=%+v, want unavailable and no count", status)
	}
	if status := actor.Status(); status.DeliveredAvailable || status.Delivered != 0 {
		t.Fatalf("latched reset status=%+v, want unavailable and no count", status)
	}
	if index != 2 {
		t.Fatalf("reader calls=%d, want baseline plus one post-baseline read; latch must stop polling", index)
	}
}

func TestIpsecCaptureDeliveredAbsentFenceLatchesUnavailable10478(t *testing.T) {
	calls := 0
	actor := newDeliveredPipeline10478(t, func() (xnft.TransitFenceCounter, bool, error) {
		calls++
		return xnft.TransitFenceCounter{}, false, nil
	})
	if err := actor.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer actor.Stop()
	status := actor.Status()
	if status.DeliveredAvailable || status.Delivered != 0 {
		t.Fatalf("absent fence status=%+v, want unavailable and no count", status)
	}
	if calls != 1 {
		t.Fatalf("absent fence reader calls=%d, want baseline only after latch", calls)
	}
}

func TestIpsecCaptureDeliveredReadErrorLatchesUnavailable10478(t *testing.T) {
	calls := 0
	actor := newDeliveredPipeline10478(t, func() (xnft.TransitFenceCounter, bool, error) {
		calls++
		if calls == 1 {
			return xnft.TransitFenceCounter{Packets: 10}, true, nil
		}
		return xnft.TransitFenceCounter{}, false, errors.New("synthetic netlink read error")
	})
	if err := actor.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer actor.Stop()
	if status := actor.Status(); status.DeliveredAvailable || status.Delivered != 0 {
		t.Fatalf("read error status=%+v, want unavailable and no count", status)
	}
	if status := actor.Status(); status.DeliveredAvailable || status.Delivered != 0 {
		t.Fatalf("latched error status=%+v, want unavailable and no count", status)
	}
	if calls != 2 {
		t.Fatalf("read-error reader calls=%d, want baseline plus one failed read", calls)
	}
}
