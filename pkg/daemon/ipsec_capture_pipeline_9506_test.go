package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/nfqueue"
)

func TestIpsecCapturePipelineDefaultInactive9506(t *testing.T) {
	registry := new(nfqueue.OriginRegistry)
	if err := registry.Register(1000, nfqueue.CaptureOrigin{Family: nfqueue.CaptureFamilyInet, Hook: nfqueue.CaptureHookForward, Owner: "owner-a", STN: "st0", OwnedIfindex: 7}); err != nil {
		t.Fatal(err)
	}
	actor, err := NewIpsecCapturePipeline(IpsecCapturePipelineConfig{
		Supervisor: newIpsecSupervisor(),
		Registry:   registry,
		Pipeline: nfqueue.CapturePipelineConfig{
			Phase:      nfqueue.PipelineQuarantine,
			HandoffCap: 2,
			BatchCap:   2,
		},
	})
	if err != nil {
		t.Fatalf("NewIpsecCapturePipeline: %v", err)
	}
	if actor.Status().Active {
		t.Fatal("new actor active before explicit Start")
	}
	if err := actor.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !actor.Status().Active {
		t.Fatal("actor inactive after Start")
	}
	if err := actor.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if actor.Status().Active {
		t.Fatal("actor active after Stop")
	}
}

func TestIpsecCapturePipelineRotationStageActivateRollback9506(t *testing.T) {
	actor, err := NewIpsecCapturePipeline(IpsecCapturePipelineConfig{Supervisor: newIpsecSupervisor(), Registry: new(nfqueue.OriginRegistry), Pipeline: nfqueue.CapturePipelineConfig{Phase: nfqueue.PipelineQuarantine}})
	if err != nil {
		t.Fatal(err)
	}
	old := []ipsecQueueHandle{{Number: 1000, Epoch: 1, Key: ipsecQueueKey{Generation: 1, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 7}}}
	staged := []ipsecQueueHandle{{Number: 1001, Epoch: 2, Key: ipsecQueueKey{Generation: 2, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 7}}}
	if err := actor.StageRotation(old, staged); err != nil {
		t.Fatalf("StageRotation: %v", err)
	}
	if got := actor.Status().Rotation; got != "QUARANTINE" {
		t.Fatalf("rotation after stage=%q, want QUARANTINE", got)
	}
	if err := actor.ActivateRotation(); err != nil {
		t.Fatalf("ActivateRotation: %v", err)
	}
	if got := actor.Status().Rotation; got != "OPEN" {
		t.Fatalf("rotation after activate=%q, want OPEN", got)
	}
	if err := actor.StageRotation(staged, []ipsecQueueHandle{{Number: 1002, Epoch: 3, Key: ipsecQueueKey{Generation: 3, Family: ipsecFamilyInet, Hook: ipsecHookForward, Owner: "owner-a", STN: "st0", Ifindex: 7}}}); err != nil {
		t.Fatalf("second StageRotation: %v", err)
	}
	actor.RollbackRotation()
	if got := actor.Status().Rotation; got != "CLOSED" {
		t.Fatalf("rotation after rollback=%q, want CLOSED", got)
	}
}
