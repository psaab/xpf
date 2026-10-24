package cluster

import (
	"encoding/binary"
	"log/slog"
	"net"
)

// Receive handlers for config, heartbeat, and auth-upgrade frames,
// extracted verbatim from handleMessage (#16168). The *Frame suffix
// avoids colliding with the pre-existing handleConfigKeyExchange and
// handleAuthUpgrade* implementations these delegates call. Dispatch,
// counters, and lock choreography are unchanged.
func (s *SessionSync) handleConfigApplyNack(conn net.Conn, payload []byte) bool {
	// #7328: the peer did not apply a config generation this node pushed.
	// Length-gated: a short/absent payload is ignored rather than treated
	// as generation 0, which would be a valid-looking "legacy" value.
	if len(payload) < 8 {
		slog.Debug("cluster sync: short config-apply nack ignored", "len", len(payload))
		return false
	}
	nackedGen := binary.LittleEndian.Uint64(payload[:8])
	// Only a nack for the generation this node most recently sent can
	// re-arm the push marker. An older generation is a straggler for a
	// push already superseded by a newer one; acting on it would re-push
	// a config the peer may already have applied.
	if sent := s.lastSentConfigGen.Load(); nackedGen != sent {
		slog.Debug("cluster sync: ignoring stale config-apply nack",
			"nacked_gen", nackedGen, "last_sent_gen", sent)
		return false
	}
	s.stats.ConfigApplyNacksReceived.Add(1)
	// #9569: the peer did not apply the config generation. A handover onto it
	// remains refused until the peer positively acknowledges a successful apply.
	slog.Warn("cluster sync: peer did not apply the config generation we pushed — re-arming the push marker",
		"gen", nackedGen)
	if s.OnPeerConfigApplyFailed != nil {
		s.OnPeerConfigApplyFailed(nackedGen)
	}
	return true
}

func (s *SessionSync) handleConfigApplyAck(conn net.Conn, payload []byte) bool {
	if len(payload) < 8 {
		slog.Debug("cluster sync: short config-apply ack ignored", "len", len(payload))
		return false
	}
	appliedGen := binary.LittleEndian.Uint64(payload[:8])
	if appliedGen == 0 {
		return false
	}
	s.mu.Lock()
	if conn != nil && s.activeConnLocked() != conn {
		s.mu.Unlock()
		return false
	}
	lastSent := s.lastSentConfigGen.Load()
	if lastSent == 0 || appliedGen > lastSent {
		s.mu.Unlock()
		slog.Debug("cluster sync: ignoring config-apply ack for an unsent generation",
			"applied_gen", appliedGen, "last_sent_gen", lastSent)
		return false
	}
	advanced := false
	for {
		old := s.peerAppliedConfigGen.Load()
		if appliedGen <= old {
			break
		}
		if s.peerAppliedConfigGen.CompareAndSwap(old, appliedGen) {
			advanced = true
			break
		}
	}
	s.mu.Unlock()
	if advanced && s.OnPeerConfigApplyAck != nil {
		s.OnPeerConfigApplyAck(appliedGen)
	}
	slog.Debug("cluster sync: peer acknowledged applied config", "gen", appliedGen)
	return true
}

func (s *SessionSync) handleHeartbeat(conn net.Conn, payload []byte) bool {
	if conn == nil {
		return false
	}
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgHeartbeatAck, nil)
	s.writeMu.Unlock()
	if err != nil {
		slog.Debug("cluster sync: heartbeat ack send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
	}
	return true
}

func (s *SessionSync) handleHeartbeatAck(conn net.Conn, payload []byte) bool {
	// #5718 C01a (fold F1): bind the capability to the peer INCARNATION
	// that proved it — only a currently-installed fabric connection can
	// speak for the current one. See noteHeartbeatAck (sync_conn.go).
	if conn == nil {
		return true
	}
	return s.noteHeartbeatAck(conn)
}

func (s *SessionSync) handleConfig(conn net.Conn, payload []byte) bool {
	// This legacy message type is the cleartext #6629 fallback. Pass its
	// wire posture into the shared handler so receive totals and the
	// cleartext subtotal are recorded in one order (#11773).
	return s.handleConfigPayload(conn, payload, true)
}

func (s *SessionSync) handleConfigEncrypted(conn net.Conn, payload []byte) bool {
	// #6629: same payload, sealed under this connection's ephemeral key.
	// Decrypt, then hand the plaintext to the SAME handler — the two arms
	// must never diverge in ordering, generation accounting or apply
	// admission, and a divergence there would always be a bug, so there is
	// one implementation rather than two kept in agreement.
	// #15041: authenticated connections derive the key from the
	// handshake secret; unauthenticated ones use the ephemeral key.
	key := configKeyFromHandshake(conn)
	if key == nil {
		key = s.configKeyForConn(conn)
	}
	if key == nil {
		// A sealed payload arrived on a connection with no derived key:
		// either the exchange never completed or this is a stale
		// connection the slots no longer reference. Either way it cannot
		// be opened, and it must NOT be opened with another connection's
		// key. Drop it; the sender re-pushes on the next reconcile tick.
		//
		// NOT BOUND BY A TEST, and deliberately recorded as such: removing
		// this branch changes nothing observable, because
		// openConfigPayload fails closed on a nil key (aes.NewCipher(nil)
		// errors) and the decrypt-failure branch below drops the payload
		// anyway. It is kept for the DIAGNOSTIC — "we never negotiated"
		// and "it did not decrypt" send an operator to entirely different
		// places — and as defence in depth if openConfigPayload ever grows
		// a path that tolerates a short key. The safety property (an
		// unopenable payload never reaches the apply path) is bound by
		// TestConfigCryptoDropsUndecryptablePayload6629.
		s.stats.Errors.Add(1)
		slog.Error("cluster sync: encrypted config received but no key was negotiated on "+
			"this connection — dropping (#6629)", "remote", connRemoteAddrString(conn))
		return false
	}
	plaintext, err := openConfigPayload(key, payload)
	if err != nil {
		s.stats.Errors.Add(1)
		slog.Error("cluster sync: could not decrypt config payload — dropping (#6629)",
			"err", err, "remote", connRemoteAddrString(conn))
		return false
	}
	return s.handleConfigPayload(conn, plaintext, false)
}

func (s *SessionSync) handleConfigKeyExchangeFrame(conn net.Conn, payload []byte) bool {
	return s.handleConfigKeyExchange(conn, payload)
}

func (s *SessionSync) handleAuthUpgradeRequestFrame(conn net.Conn, payload []byte) bool {
	// #6628: the responder-role peer committed a key and is asking THIS
	// node (the initiator by node id) to start the exchange.
	return s.handleAuthUpgradeRequest(conn, payload)
}

func (s *SessionSync) handleAuthUpgradeHelloFrame(conn net.Conn, payload []byte) bool {
	// #6628: the peer committed a key and is offering to authenticate this
	// established connection in place. Never drops it.
	return s.handleAuthUpgradeHello(conn, payload)
}

func (s *SessionSync) handleAuthUpgradeProofFrame(conn net.Conn, payload []byte) bool {
	return s.handleAuthUpgradeProof(conn, payload)
}

func (s *SessionSync) handleAuthUpgradeConfirmFrame(conn net.Conn, payload []byte) bool {
	return s.handleAuthUpgradeConfirm(conn, payload)
}
