package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// #16024: peer-loss takeover without confirmation must be an explicit alarm,
// not only a degraded status detail. Confirmed fencing and peer recovery must
// not leave that alarm active.
func TestUnconfirmedTakeoverAlarm16024_DefaultFencing(t *testing.T) {
	m := fenceInfoManager(t, "")
	if got := m.FormatStatus(); strings.Contains(got, "ALARM: dual-primary risk") {
		t.Fatalf("no takeover yet must raise no alarm:\n%s", got)
	}
	m.handlePeerTimeout()
	got := m.FormatStatus()
	if !strings.Contains(got, "ALARM: dual-primary risk") ||
		!strings.Contains(got, "peer fencing is disabled") {
		t.Fatalf("default-fencing takeover must raise a dual-primary-risk alarm naming the reason:\n%s", got)
	}
	if alarm := m.PeerLossTakeoverAlarm(); !strings.Contains(alarm, "peer fencing is disabled") {
		t.Fatalf("active takeover alarm = %q, want it to name the default-fencing reason", alarm)
	}
	if got := m.FormatInformation(); !strings.Contains(got, "ALARM: dual-primary risk") {
		t.Fatalf("information view omitted the takeover alarm:\n%s", got)
	}
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 1})
	if got := m.FormatStatus(); strings.Contains(got, "ALARM: dual-primary risk") {
		t.Fatalf("peer heartbeat return must clear the takeover alarm:\n%s", got)
	}
	if alarm := m.PeerLossTakeoverAlarm(); alarm != "" {
		t.Fatalf("peer heartbeat return left active takeover alarm %q", alarm)
	}
}

func TestUnconfirmedTakeoverAlarm16024_ConfirmedFenceSilent(t *testing.T) {
	m := confirmFenceManager(t)
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		return FenceAck{Status: FenceAckOK, RGsFenced: 1, RGsTotal: 1}, nil
	})
	m.handlePeerTimeout()
	if got := m.FormatStatus(); strings.Contains(got, "ALARM: dual-primary risk") {
		t.Fatalf("confirmed fence must raise no dual-primary alarm:\n%s", got)
	}
}

func TestUnconfirmedTakeoverAlarm16024_AbortedFenceIsSilent(t *testing.T) {
	m := confirmFenceManager(t)
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 1})
		return FenceAck{}, errors.New("fence failed")
	})
	m.handlePeerTimeout()
	if alarm := m.PeerLossTakeoverAlarm(); alarm != "" {
		t.Fatalf("aborted takeover with a recovered peer must not alarm, got %q", alarm)
	}
	if status := m.FormatStatus(); strings.Contains(status, "ALARM: dual-primary risk") {
		t.Fatalf("aborted takeover with a recovered peer raised a status alarm:\n%s", status)
	}
}

func TestUnconfirmedTakeoverAlarm16024_ColdStartIsNotDualPrimary(t *testing.T) {
	m := NewManager(0, 1)
	m.handlePeerNeverSeen()
	status := m.FormatStatus()
	if !strings.Contains(status, "Peer-loss takeover: DEGRADED") {
		t.Fatalf("cold-start takeover must retain its degraded status marker:\n%s", status)
	}
	if strings.Contains(status, "ALARM: dual-primary risk") {
		t.Fatalf("a peer never observed cannot create dual-primary risk:\n%s", status)
	}
	if alarm := m.PeerLossTakeoverAlarm(); alarm != "" {
		t.Fatalf("a peer never observed cannot create dual-primary risk, got %q", alarm)
	}
}
