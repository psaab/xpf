package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/nfqueue"
)

func wiringHandles9506() []ipsecQueueHandle {
	classes := []struct {
		family ipsecQueueFamily
		hook   ipsecQueueHook
		number uint16
	}{
		{ipsecFamilyInet, ipsecHookForward, 1001},
		{ipsecFamilyInet, ipsecHookInput, 1002},
		{ipsecFamilyBridge, ipsecHookForward, 1003},
		{ipsecFamilyBridge, ipsecHookInput, 1004},
	}
	handles := make([]ipsecQueueHandle, 0, len(classes))
	for _, class := range classes {
		handles = append(handles, ipsecQueueHandle{
			Number: class.number,
			Epoch:  9,
			Key: ipsecQueueKey{
				Generation: 4,
				Family:     class.family,
				Hook:       class.hook,
				Owner:      "vpn-a",
				STN:        "st1.0",
				Ifindex:    17,
			},
		})
	}
	return handles
}

func TestIpsecCaptureWiringBuildsFourClassSpecAndOrigins9506(t *testing.T) {
	handles := wiringHandles9506()
	spec, err := ipsecCaptureDivertSpec(handles)
	if err != nil {
		t.Fatalf("divert spec: %v", err)
	}
	if len(spec.InetForward) != 1 || len(spec.InetInput) != 1 || len(spec.BridgeForward) != 1 || len(spec.BridgeInput) != 1 {
		t.Fatalf("four-class spec = %+v", spec)
	}
	registry := new(nfqueue.OriginRegistry)
	if err := ipsecCaptureRegisterOrigins(registry, handles); err != nil {
		t.Fatalf("register origins: %v", err)
	}
	origin, ok := registry.Lookup(1004)
	if !ok || origin.Family != nfqueue.CaptureFamilyBridge || origin.Hook != nfqueue.CaptureHookInput || origin.Owner != "vpn-a" || origin.STN != "st1.0" || origin.OwnedIfindex != 17 {
		t.Fatalf("bridge input origin = %+v/%v", origin, ok)
	}
	if _, err := ipsecCaptureDivertSpec(handles[:3]); err == nil {
		t.Fatal("incomplete four-class generation was accepted")
	}
}

func TestIpsecCaptureRuntimeAnnounceSnapshotPreservesClosingEpoch9506(t *testing.T) {
	supervisor := newIpsecSupervisor()
	supervisor.permit.Store(&permitRecord{state: ipsecPermitOpen, permitEpoch: 17})
	runtime := &ipsecCaptureRuntime{supervisor: supervisor, handles: wiringHandles9506()}
	epoch, open, rows := runtime.authoritySnapshot()
	if epoch != 17 || !open || len(rows) != 4 {
		t.Fatalf("open authority=(%d,%v,%+v), want epoch 17/open/4 rows", epoch, open, rows)
	}
	supervisor.permit.Store(&permitRecord{state: ipsecPermitClosing, permitEpoch: 17})
	epoch, open, rows = runtime.authoritySnapshot()
	if epoch != 17 || open || len(rows) != 4 {
		t.Fatalf("closing authority=(%d,%v,%+v), want epoch 17/closed/4 rows", epoch, open, rows)
	}
	snapshotEpoch, snapshotRows := runtime.epochSnapshot()
	if snapshotEpoch != 0 || snapshotRows != nil {
		t.Fatalf("closed compile snapshot=(%d,%+v), want zero/nil", snapshotEpoch, snapshotRows)
	}
}

func TestRestoreIpsecCaptureRuntimeInvalidatesAuthorityAnnouncement9506(t *testing.T) {
	runtime := &ipsecCaptureRuntime{
		announced:       true,
		announcedPermit: 17,
		announcedOpen:   true,
		announcedRows:   []nfqueue.ReinjectQueueEpoch{{Queue: 1001, Epoch: 9}},
	}
	d := new(Daemon)
	d.restoreIpsecCaptureRuntime(runtime)
	runtime.authorityMu.Lock()
	announced := runtime.announced
	runtime.authorityMu.Unlock()
	if announced {
		t.Fatal("restored runtime retained stale authority announcement")
	}
	if d.ipsecCapture != runtime || d.ipsecCaptureStaged != nil || d.ipsecCaptureStagePending {
		t.Fatalf("restored daemon state = active=%p staged=%p pending=%v", d.ipsecCapture, d.ipsecCaptureStaged, d.ipsecCaptureStagePending)
	}
}
