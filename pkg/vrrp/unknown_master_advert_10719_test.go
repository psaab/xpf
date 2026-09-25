package vrrp

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
)

type warningCounter10719 struct {
	count atomic.Int64
}

func (h *warningCounter10719) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelWarn
}
func (h *warningCounter10719) Handle(_ context.Context, record slog.Record) error {
	if record.Message == "vrrp: priority-0/255 advert from source other than the learned master" {
		h.count.Add(1)
	}
	return nil
}
func (h *warningCounter10719) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *warningCounter10719) WithGroup(string) slog.Handler      { return h }

func installWarningCounter10719(t *testing.T) *warningCounter10719 {
	t.Helper()
	h := &warningCounter10719{}
	previous := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return h
}

// RED-on-revert for #10719: priority-0 and priority-255 adverts from a source
// other than the learned master must each increment the per-instance counter,
// while a burst emits only one warning. An advert from the learned master is
// not counted. Manager.RXDropStats exposes the per-instance counter.
func TestUnknownPriorityAdvertsWarnRateLimitedAndCount_10719(t *testing.T) {
	warnings := installWarningCounter10719(t)
	vi := newGateTestInstance(t, 100, true)
	peerIP := net.IPv4(10, 0, 0, 2)
	unknownIP := net.IPv4(10, 0, 0, 3)
	vi.recordMasterAdvert(&VRRPPacket{Priority: 100, SrcIP: peerIP})

	masterDown, _, preemptHold := longTimers(t)
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: peerIP}, masterDown, preemptHold)
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: unknownIP}, masterDown, preemptHold)
	vi.handleBackupRx(&VRRPPacket{Priority: 255, SrcIP: unknownIP}, masterDown, preemptHold)

	if got := vi.unrecognizedMasterAdverts.Load(); got != 2 {
		t.Fatalf("unrecognized master advert count = %d, want 2 (only unknown-source priority 0/255 adverts)", got)
	}
	if got := warnings.count.Load(); got != 1 {
		t.Fatalf("warning count = %d, want one rate-limited warning for the burst", got)
	}

	m := &Manager{instances: map[instanceKey]*vrrpInstance{
		{iface: "eth0", groupID: 101}: vi,
	}}
	stats := m.RXDropStats()
	if got := stats[vi.key()+"/unrecognized_master_adverts"]; got != 2 {
		t.Fatalf("RXDropStats unrecognized_master_adverts = %d, want 2; stats = %#v", got, stats)
	}
}

// An unknown priority-255 advert reaches the normal election handler and still
// causes the RFC priority transition, but must be detected before that source
// can replace the previously learned master identity.
func TestUnknownPriority255MasterAdvertDetectedBeforeDemotion_10719(t *testing.T) {
	warnings := installWarningCounter10719(t)
	vi := newGateTestInstance(t, 100, true)
	vi.setState(StateMaster)
	vi.recordMasterAdvert(&VRRPPacket{
		Priority: 100,
		SrcIP:    net.IPv4(10, 0, 0, 2),
	})
	masterDown, advert, _ := longTimers(t)

	vi.handleMasterRx(&VRRPPacket{
		Priority: 255,
		SrcIP:    net.IPv4(10, 0, 0, 3),
	}, masterDown, advert)

	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state = %s, want BACKUP: priority 255 remains an election input", got)
	}
	if got := vi.unrecognizedMasterAdverts.Load(); got != 1 {
		t.Fatalf("unrecognized master advert count = %d, want 1", got)
	}
	if got := warnings.count.Load(); got != 1 {
		t.Fatalf("warning count = %d, want 1", got)
	}
	vi.mu.RLock()
	lastMaster := append(net.IP(nil), vi.lastMasterIPv4[:]...)
	vi.mu.RUnlock()
	if !lastMaster.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("unknown priority-255 source replaced learned master IP: %v", lastMaster)
	}
}

// A priority-255 advert from the already-learned master is legitimate and
// still causes the RFC transition without raising the unknown-source signal.
func TestKnownPriority255AdvertIsNotReported_10719(t *testing.T) {
	warnings := installWarningCounter10719(t)
	vi := newGateTestInstance(t, 100, true)
	vi.setState(StateMaster)
	peerIP := net.IPv4(10, 0, 0, 2)
	vi.recordMasterAdvert(&VRRPPacket{Priority: 100, SrcIP: peerIP})
	masterDown, advert, _ := longTimers(t)

	vi.handleMasterRx(&VRRPPacket{Priority: 255, SrcIP: peerIP}, masterDown, advert)

	if got := vi.getState(); got != StateBackup {
		t.Fatalf("state = %s, want BACKUP: priority 255 remains an election input", got)
	}
	if got := vi.unrecognizedMasterAdverts.Load(); got != 0 {
		t.Fatalf("known-master priority-255 advert count = %d, want 0", got)
	}
	if got := warnings.count.Load(); got != 0 {
		t.Fatalf("warning count = %d, want 0 for the learned master", got)
	}
}

// Dual-stack RETH peers use unrelated IPv4 and IPv6 source addresses. Learning
// one family must not make the same peer look unknown on the other family.
func TestUnknownPriorityAdvertUsesFamilySpecificMasterIdentity_10719(t *testing.T) {
	warnings := installWarningCounter10719(t)
	vi := newGateTestInstance(t, 100, true)
	peerV4 := net.IPv4(10, 0, 0, 2)
	peerV6 := net.ParseIP("fe80::2")
	vi.recordMasterAdvert(&VRRPPacket{Priority: 100, SrcIP: peerV4})
	vi.recordMasterAdvert(&VRRPPacket{Priority: 100, SrcIP: peerV6})
	masterDown, _, preemptHold := longTimers(t)

	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: peerV4}, masterDown, preemptHold)
	vi.handleBackupRx(&VRRPPacket{Priority: 0, SrcIP: peerV6}, masterDown, preemptHold)
	if got := vi.unrecognizedMasterAdverts.Load(); got != 0 {
		t.Fatalf("known dual-stack peer source count = %d, want 0", got)
	}

	vi.handleBackupRx(&VRRPPacket{
		Priority: 0,
		SrcIP:    net.IPv4(10, 0, 0, 3),
	}, masterDown, preemptHold)
	if got := vi.unrecognizedMasterAdverts.Load(); got != 1 {
		t.Fatalf("unknown IPv4 source count = %d, want 1", got)
	}
	if got := warnings.count.Load(); got != 1 {
		t.Fatalf("warning count = %d, want 1", got)
	}
}
