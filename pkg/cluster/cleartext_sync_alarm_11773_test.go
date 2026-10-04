package cluster

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestCleartextFallbackLatchesAlarmAndCounter11773 is the fail-on-revert gate
// for both #6629 cleartext sender arms: no negotiated key and seal failure.
// Each arm must still send the byte-identical legacy payload, then make the
// exposure sticky and observable on the sending node. Replacing that
// connection with a successfully encrypted one must not clear the historical
// alarm or counter: a capture from the earlier push remains useful.
func TestCleartextFallbackLatchesAlarmAndCounter11773(t *testing.T) {
	previousWait := syncConfigKeyWait
	syncConfigKeyWait = 5 * time.Millisecond
	t.Cleanup(func() { syncConfigKeyWait = previousWait })

	for _, tc := range []struct {
		name      string
		sealError bool
	}{
		{name: "peer did not negotiate"},
		{name: "sealing failed", sealError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
			senderConn, peerConn := net.Pipe()
			t.Cleanup(func() {
				_ = senderConn.Close()
				_ = peerConn.Close()
			})

			crypto := newConfigCryptoState()
			if crypto == nil {
				t.Fatal("could not generate config crypto state")
			}
			if tc.sealError {
				// A present, invalid-length derived key selects the seal-error
				// arm without changing the payload or error behavior.
				crypto.key = []byte{1}
			}
			sender.mu.Lock()
			sender.conn0 = senderConn
			sender.configCrypto0 = crypto
			sender.mu.Unlock()

			manager := NewManager(0, 22)
			manager.SetSyncStats(sender)
			if status := manager.FormatStatus(); strings.Contains(status, "config sync has sent or received cleartext") {
				t.Fatalf("a clean connection must not raise the cleartext alarm:\n%s", status)
			}
			if information := manager.FormatInformation(); strings.Contains(information, "WARNING: config sync cleartext fallback") {
				t.Fatalf("clean config sync must not render a latched cleartext warning:\n%s", information)
			}
			for name, statistics := range map[string]string{
				"cluster statistics": manager.FormatStatistics(),
				"data-plane statistics": manager.FormatDataPlaneStatistics(),
			} {
				if strings.Contains(statistics, "Config cleartext") {
					t.Fatalf("clean config sync must not render a cleartext counter in %s:\n%s", name, statistics)
				}
			}

			config := configWithPSK()
			sendDone := make(chan bool, 1)
			go func() { sendDone <- sender.queueConfigOnConn(senderConn, config, nil, 1, nil) }()
			if err := peerConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set peer read deadline: %v", err)
			}
			msgType, payload, _ := readOneFrame(t, peerConn)
			if msgType != syncMsgConfig {
				t.Fatalf("%s fallback message type = %d, want legacy cleartext type %d",
					tc.name, msgType, syncMsgConfig)
			}
			text, gen := decodeConfigPayload(payload)
			if text != config || gen != 1 {
				t.Fatalf("fallback changed config payload: text matches=%v gen=%d", text == config, gen)
			}
			if !<-sendDone {
				t.Fatal("cleartext fallback failed to send")
			}

			snapshot := sender.Stats()
			if snapshot.ConfigsSent != 1 || snapshot.ConfigsSentCleartext != 1 ||
				!snapshot.CleartextSyncAlarmLatched {
				t.Fatalf("successful cleartext fallback must increment and latch stats, got %+v", snapshot)
			}
			assertCleartextAlarmRendered11773(t, manager, 1, 0)

			// A later negotiated, sealed push proves that the alarm and the
			// cleartext counter describe historical exposure, not current link
			// state. Reconnect must not reset either value.
			sealedConn, sealedPeer := net.Pipe()
			t.Cleanup(func() {
				_ = sealedConn.Close()
				_ = sealedPeer.Close()
			})
			sender.installConn(0, sealedConn)
			peerCrypto := newConfigCryptoState()
			if peerCrypto == nil {
				t.Fatal("could not generate peer crypto state")
			}
			sender.handleConfigKeyExchange(sealedConn, keyExchangePayload(peerCrypto.pub))
			sealedDone := make(chan bool, 1)
			go func() { sealedDone <- sender.queueConfigOnConn(sealedConn, config, nil, 2, nil) }()
			if err := sealedPeer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("set sealed peer read deadline: %v", err)
			}
			sealedType, sealedPayload, _ := readOneFrame(t, sealedPeer)
			if sealedType != syncMsgConfigEncrypted {
				t.Fatalf("negotiated reconnection message type = %d, want encrypted %d",
					sealedType, syncMsgConfigEncrypted)
			}
			if !<-sealedDone {
				t.Fatal("sealed config push failed")
			}
			plain, err := openConfigPayload(sender.configKeyForConn(sealedConn), sealedPayload)
			if err != nil {
				t.Fatalf("open sealed config: %v", err)
			}
			gotConfig, gotGen := decodeConfigPayload(plain)
			if gotConfig != config || gotGen != 2 {
				t.Fatalf("sealed reconnection changed payload: text matches=%v gen=%d", gotConfig == config, gotGen)
			}
			afterReconnect := sender.Stats()
			if afterReconnect.ConfigsSent != 2 || afterReconnect.ConfigsSentCleartext != 1 ||
				!afterReconnect.CleartextSyncAlarmLatched {
				t.Fatalf("sealed reconnect cleared or recounted historical exposure: %+v", afterReconnect)
			}
			assertCleartextAlarmRendered11773(t, manager, 1, 0)
		})
	}
}

// TestCleartextReceiveLatchesAlarm11773 pins the receiving half: a legacy
// syncMsgConfig marks the same cluster-visible alarm even when this node never
// selected the fallback itself.
func TestCleartextReceiveLatchesAlarm11773(t *testing.T) {
	receiver := NewSessionSync(":0", "10.0.0.1:4785", &mockSweepDP{})
	local, peer := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	receiver.mu.Lock()
	receiver.conn0 = local
	receiver.mu.Unlock()

	receiver.handleMessage(local, syncMsgConfig, encodeConfigPayload(configWithPSK(), 9))
	snapshot := receiver.Stats()
	if snapshot.ConfigsReceived != 1 || snapshot.ConfigsReceivedCleartext != 1 ||
		!snapshot.CleartextSyncAlarmLatched {
		t.Fatalf("cleartext receive must increment and latch stats, got %+v", snapshot)
	}
	manager := NewManager(0, 22)
	manager.SetSyncStats(receiver)
	assertCleartextAlarmRendered11773(t, manager, 0, 1)
}

// TestFailedCleartextWriteDoesNotLatchAlarm11773 protects the event boundary:
// a fallback that never reaches the socket is not a cleartext exposure.
func TestFailedCleartextWriteDoesNotLatchAlarm11773(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	senderConn, peerConn := net.Pipe()
	_ = peerConn.Close()
	t.Cleanup(func() { _ = senderConn.Close() })
	crypto := newConfigCryptoState()
	if crypto == nil {
		t.Fatal("could not generate config crypto state")
	}
	crypto.key = []byte{1}
	sender.mu.Lock()
	sender.conn0 = senderConn
	sender.configCrypto0 = crypto
	sender.mu.Unlock()

	if sender.queueConfigOnConn(senderConn, configWithPSK(), nil, 1, nil) {
		t.Fatal("a write to the closed peer unexpectedly succeeded")
	}
	if snapshot := sender.Stats(); snapshot.ConfigsSentCleartext != 0 || snapshot.CleartextSyncAlarmLatched {
		t.Fatalf("failed write falsely reported an exposure: %+v", snapshot)
	}
}

func assertCleartextAlarmRendered11773(t *testing.T, manager *Manager, sent, received uint64) {
	t.Helper()
	status := manager.FormatStatus()
	if !strings.Contains(status, "Warning: config sync has sent or received cleartext payloads (#11773; alarm latched).") ||
		!strings.Contains(status, fmt.Sprintf("Cleartext config payloads: sent %d, received %d.", sent, received)) {
		t.Errorf("cluster status did not render the latched cleartext alarm and counters:\n%s", status)
	}
	information := manager.FormatInformation()
	if !strings.Contains(information, fmt.Sprintf("WARNING: config sync cleartext fallback has been used (alarm latched; sent %d, received %d)", sent, received)) {
		t.Errorf("cluster information did not render the latched cleartext alarm and counters:\n%s", information)
	}
	statistics := manager.FormatDataPlaneStatistics()
	if !strings.Contains(statistics, fmt.Sprintf("%-32s %-12d %d", "Config cleartext", sent, received)) {
		t.Errorf("cluster statistics did not render the cleartext counter:\n%s", statistics)
	}
	clusterStatistics := manager.FormatStatistics()
	if !strings.Contains(clusterStatistics, fmt.Sprintf("%-32s %-12d %d", "Config cleartext", sent, received)) {
		t.Errorf("cluster statistics did not render the cleartext counter:\n%s", clusterStatistics)
	}
}
