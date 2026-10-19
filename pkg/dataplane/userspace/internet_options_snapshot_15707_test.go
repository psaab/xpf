package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15707: the snapshot builder must carry
// `system internet-options no-ipv6-reject-zero-hop-limit` onto the wire
// so the helper can suppress its ICMPv6 Time Exceeded for hop-limit=0.
func TestSnapshotCarriesNoIPv6RejectZeroHopLimit15707(t *testing.T) {
	cfg := &config.Config{System: config.SystemConfig{
		InternetOptions: &config.InternetOptionsConfig{NoIPv6RejectZeroHopLimit: true},
	}}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 7, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if !snap.NoIPv6RejectZeroHopLimit {
		t.Error("snapshot NoIPv6RejectZeroHopLimit = false, want true")
	}

	cfg2 := &config.Config{}
	snap2, err := buildSnapshot(cfg2, config.UserspaceConfig{}, 7, 0)
	if err != nil {
		t.Fatalf("buildSnapshot (control): %v", err)
	}
	if snap2.NoIPv6RejectZeroHopLimit {
		t.Error("control: snapshot NoIPv6RejectZeroHopLimit = true, want false")
	}
}
