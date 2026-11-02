package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// #16024: heartbeat-only loss with a live sync connection stays suppressed up
// to the cap, then takes over under default fencing and raises an explicit
// dual-primary-risk alarm. Confirmed fencing, peer recovery and aborted waits
// must not leave that alarm active.
func TestUnconfirmedTakeoverAlarm16024_DefaultFencing(t *testing.T) {
	m := fenceInfoManager(t, "")
	m.SetRGReady(0, true, nil)
	peerPrimary := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{{
			GroupID: 0, Priority: 100, Weight: 100, State: uint8(StatePrimary),
		}},
	}
	m.handlePeerHeartbeat(peerPrimary)
	m.mu.Lock()
	// Pin the observed peer-primary/local-secondary partition state. The local
	// node becomes primary only after the peer-loss election below.
	m.groups[0].State = StateSecondary
	m.mu.Unlock()
	if m.IsLocalPrimary(0) {
		t.Fatal("fixture must start secondary while the last peer heartbeat says primary")
	}
	if got := m.FormatStatus(); strings.Contains(got, "ALARM: dual-primary risk") {
		t.Fatalf("healthy peer must not raise an alarm before timeout:\n%s", got)
	}

	// Model lost UDP heartbeats while the connected session-sync path remains
	// fresh. The first timeout is suppressed; expiring its 5s cap permits the
	// real peer-loss path to take over.
	m.SetFakePeerSyncSourceForTesting(true, 100*time.Millisecond, true, true)
	m.handlePeerTimeout()
	if !m.PeerAlive() {
		t.Fatal("fresh connected sync must suppress the first heartbeat timeout")
	}
	if stamp := m.HBSuppressStartForTesting(); stamp == 0 {
		t.Fatal("fresh sync suppression must arm its 5s cap")
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("sync-suppressed heartbeat loss must not promote the local secondary")
	}
	if alarm := m.UnconfirmedTakeoverAlarm(); alarm != "" {
		t.Fatalf("suppressed timeout must not raise an alarm, got %q", alarm)
	}

	m.SetHBSuppressStartForTesting(MonotonicNanos() - (6 * time.Second).Nanoseconds())
	m.handlePeerTimeout()
	if m.PeerAlive() {
		t.Fatal("peer must be marked lost after the sync-recency suppression cap expires")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("eligible local secondary must take over after peer loss")
	}
	got := m.FormatStatus()
	if !strings.Contains(got, "ALARM: dual-primary risk") ||
		!strings.Contains(got, "peer fencing is disabled") {
		t.Fatalf("default-fencing takeover must raise a dual-primary-risk alarm naming the reason:\n%s", got)
	}
	if alarm := m.UnconfirmedTakeoverAlarm(); !strings.Contains(alarm, "peer fencing is disabled") {
		t.Fatalf("active takeover alarm = %q, want it to name the default-fencing reason", alarm)
	}
	if got := m.FormatInformation(); !strings.Contains(got, "ALARM: dual-primary risk") {
		t.Fatalf("information view omitted the takeover alarm:\n%s", got)
	}
	m.handlePeerHeartbeat(peerPrimary)
	if got := m.FormatStatus(); strings.Contains(got, "ALARM: dual-primary risk") {
		t.Fatalf("peer heartbeat return must clear the takeover alarm:\n%s", got)
	}
	if alarm := m.UnconfirmedTakeoverAlarm(); alarm != "" {
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
	if alarm := m.UnconfirmedTakeoverAlarm(); alarm != "" {
		t.Fatalf("aborted takeover with a recovered peer must not alarm, got %q", alarm)
	}
	if status := m.FormatStatus(); strings.Contains(status, "ALARM: dual-primary risk") {
		t.Fatalf("aborted takeover with a recovered peer raised a status alarm:\n%s", status)
	}
}

func TestUnconfirmedTakeoverAlarm16024_ColdStartIsAlarmed(t *testing.T) {
	m := coldBootManager(t)
	m.SetRGReady(0, true, nil)
	if m.IsLocalPrimary(0) {
		t.Fatal("cold-start non-preempt RG must remain secondary before absence is confirmed")
	}
	if status := m.FormatStatus(); strings.Contains(status, "ALARM: dual-primary risk") {
		t.Fatalf("cold-start RG must not alarm before peer absence is confirmed:\n%s", status)
	}
	if alarm := m.UnconfirmedTakeoverAlarm(); alarm != "" {
		t.Fatalf("unconfirmed-takeover alarm before absence confirmation = %q, want empty", alarm)
	}

	m.handlePeerNeverSeen()
	if !m.IsLocalPrimary(0) {
		t.Fatal("ready cold-start RG must promote after never-seen peer absence is confirmed")
	}
	status := m.FormatStatus()
	if !strings.Contains(status, "ALARM: dual-primary risk") ||
		!strings.Contains(status, "peer never seen; no fence possible") {
		t.Fatalf("cold-start promotion must report the split-brain risk:\n%s", status)
	}
	if alarm := m.UnconfirmedTakeoverAlarm(); !strings.Contains(alarm, "peer never seen; no fence possible") {
		t.Fatalf("cold-start takeover alarm = %q, want the no-fence reason", alarm)
	}
}
