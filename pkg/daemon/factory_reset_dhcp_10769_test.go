package daemon

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

type resetDHCPRecorder10769 struct {
	*recordingDHCPApplier9349
	applyNil  int
	leaseSync []bool
}

func (r *resetDHCPRecorder10769) Apply(cfg *config.DHCPServerConfig) error {
	if cfg == nil {
		r.applyNil++
	}
	return r.recordingDHCPApplier9349.Apply(cfg)
}

func (r *resetDHCPRecorder10769) SetLeaseSyncEnabled(enabled bool) {
	r.leaseSync = append(r.leaseSync, enabled)
}

func TestFactoryResetQuiescesAndRestoresDHCPAfterFailure10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	dhcp := &resetDHCPRecorder10769{recordingDHCPApplier9349: &recordingDHCPApplier9349{}}
	d := &Daemon{applySem: semaphore.NewWeighted(1), dhcpServer: dhcp}
	wantErr := errors.New("wipe failed")
	if err := d.factoryReset(context.Background(), func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("factoryReset error = %v, want %v", err, wantErr)
	}
	if dhcp.applyNil != 2 {
		t.Fatalf("DHCP clears = %d, want one reset quiesce and one failure restore", dhcp.applyNil)
	}
	if len(dhcp.leaseSync) != 2 || dhcp.leaseSync[0] || dhcp.leaseSync[1] {
		t.Fatalf("lease-sync states during quiesce/restore = %v, want [false false] for empty config", dhcp.leaseSync)
	}
	if d.isResetting() {
		t.Fatal("failed reset must leave the reset generation")
	}
}

func TestFactoryResetFencesDHCPEnqueueDuringGeneration10769(t *testing.T) {
	dhcp := &resetDHCPRecorder10769{recordingDHCPApplier9349: &recordingDHCPApplier9349{}}
	d := &Daemon{dhcpServer: dhcp}
	d.enterResetGeneration()
	defer d.exitResetGeneration()
	d.enqueueDHCPApplyWithAuthorityState(&config.DHCPServerConfig{}, "racing transition", nil, nil)
	if len(dhcp.authorityAsyncCfg) != 0 {
		t.Fatalf("async DHCP apply crossed the active reset generation: %v", dhcp.authorityAsyncCfg)
	}
}

func TestFactoryResetHoldsFenceAcrossWipe10769(t *testing.T) {
	isolateFactoryResetOwnershipPaths(t)
	isolateFactoryResetIdentityPaths(t)
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- d.factoryReset(context.Background(), func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	// The wipe runs only after factoryReset takes the fence, so a TryLock
	// here must fail deterministically — no sleep, no scheduling bet.
	if d.ddnsResetMu.TryLock() {
		d.ddnsResetMu.Unlock()
		close(release)
		t.Fatal("reset fence must be held across the wipe (a direct lease writer could land mid-wipe)")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("factoryReset: %v", err)
	}
	if !d.ddnsResetMu.TryLock() {
		t.Fatal("reset fence must be released after the wipe")
	}
	d.ddnsResetMu.Unlock()
}
