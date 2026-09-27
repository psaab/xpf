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
	dhcp := &resetDHCPRecorder10769{recordingDHCPApplier9349: &recordingDHCPApplier9349{}}
	d := &Daemon{applySem: semaphore.NewWeighted(1), dhcpServer: dhcp}
	wantErr := errors.New("wipe failed")
	if err := d.factoryReset(context.Background(), func() error {
		d.enqueueDHCPApplyWithAuthorityState(&config.DHCPServerConfig{}, "racing transition", nil, nil)
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("factoryReset error = %v, want %v", err, wantErr)
	}
	if dhcp.applyNil != 2 {
		t.Fatalf("DHCP clears = %d, want one reset quiesce and one failure restore", dhcp.applyNil)
	}
	if len(dhcp.leaseSync) != 2 || dhcp.leaseSync[0] || dhcp.leaseSync[1] {
		t.Fatalf("lease-sync states during quiesce/restore = %v, want [false false] for empty config", dhcp.leaseSync)
	}
	if len(dhcp.authorityAsyncCfg) != 0 {
		t.Fatalf("async DHCP apply crossed the active reset generation: %v", dhcp.authorityAsyncCfg)
	}
	if d.isResetting() {
		t.Fatal("failed reset must leave the reset generation")
	}
}
