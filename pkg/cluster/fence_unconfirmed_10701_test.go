package cluster

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func assertUnconfirmedTakeoverStatus10701(t *testing.T, m *Manager, reason string) {
	t.Helper()
	for name, render := range map[string]string{
		"status":      m.FormatStatus(),
		"information": m.FormatInformation(),
	} {
		if !strings.Contains(render, "Peer-loss takeover: DEGRADED") {
			t.Errorf("%s does not mark the takeover degraded after no peer fence confirmation:\n%s", name, render)
		}
		if !strings.Contains(render, reason) {
			t.Errorf("%s does not state why peer fencing was unconfirmed (%q):\n%s", name, reason, render)
		}
	}
	if !strings.Contains(m.FormatInformation(), "Local node: degraded") {
		t.Errorf("information render did not reflect the unconfirmed takeover in local node health:\n%s", m.FormatInformation())
	}
}

func TestUnconfiguredPeerFencingMarksTakeoverDegraded10701(t *testing.T) {
	m := fenceInfoManager(t, "")
	m.handlePeerTimeout()
	assertUnconfirmedTakeoverStatus10701(t, m, "peer fencing is disabled")
}

func TestBestEffortPeerFenceIsMarkedUnconfirmed10701(t *testing.T) {
	m := fenceInfoManager(t, PeerFencingDisableRG)
	var stateAtSend NodeState
	m.SetPeerFenceFunc(func() error {
		stateAtSend = rgState(t, m, 0)
		return nil
	})

	m.handlePeerTimeout()
	if stateAtSend != StatePrimary {
		t.Fatalf("best-effort fence was sent while local state was %s, want existing election-before-send behavior", stateAtSend)
	}
	assertUnconfirmedTakeoverStatus10701(t, m, "best-effort fence is unacknowledged")
}

func TestConfirmedPeerFenceFailureMarksTakeoverDegraded10701(t *testing.T) {
	m := confirmFenceManager(t)
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		return FenceAck{}, errors.New("peer ack timed out")
	})
	m.handlePeerTimeout()
	assertUnconfirmedTakeoverStatus10701(t, m, "peer ack timed out")
}

func TestConfirmedPeerFenceSuccessDoesNotMarkTakeoverDegraded10701(t *testing.T) {
	m := confirmFenceManager(t)
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		return FenceAck{Status: FenceAckOK, RGsFenced: 1, RGsTotal: 1}, nil
	})
	m.handlePeerTimeout()
	for name, render := range map[string]string{
		"status":      m.FormatStatus(),
		"information": m.FormatInformation(),
	} {
		if strings.Contains(render, "Peer-loss takeover: DEGRADED") {
			t.Errorf("%s marked a confirmed peer fence as degraded:\n%s", name, render)
		}
	}
}

func TestPeerHeartbeatClearsUnconfirmedTakeoverDegradation10701(t *testing.T) {
	m := fenceInfoManager(t, "")
	m.handlePeerTimeout()
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 1})
	for name, render := range map[string]string{
		"status":      m.FormatStatus(),
		"information": m.FormatInformation(),
	} {
		if strings.Contains(render, "Peer-loss takeover: DEGRADED") {
			t.Errorf("%s retained stale takeover degradation after the peer heartbeat returned:\n%s", name, render)
		}
	}
}

func TestIncompletePeerFenceMarksTakeoverDegraded10701(t *testing.T) {
	m := confirmFenceManager(t)
	m.SetPeerFenceConfirmFunc(func(time.Duration) (FenceAck, error) {
		return FenceAck{Status: FenceAckPartial, RGsFenced: 2, RGsTotal: 3}, nil
	})
	m.handlePeerTimeout()
	assertUnconfirmedTakeoverStatus10701(t, m, "peer disabled only 2/3")
}

func TestConfirmedPeerFenceWithoutSyncIsMarkedDegraded10701(t *testing.T) {
	m := confirmFenceManager(t)
	m.handlePeerTimeout()
	assertUnconfirmedTakeoverStatus10701(t, m, "sync not available")
}
