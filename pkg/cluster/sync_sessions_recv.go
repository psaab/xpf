package cluster

import (
	"log/slog"
	"net"
)

// Receive handlers for session install/delete frames, extracted verbatim
// from handleMessage (#16168). Dispatch, counters, and lock choreography
// are unchanged; handleMessage remains the sole switch.
func (s *SessionSync) handleSessionV4(conn net.Conn, payload []byte) {
	s.stats.SessionsReceived.Add(1)
	s.bulkReceiveProgress("v4", conn)
	if s.sessions != nil {
		key, val, ok := decodeSessionV4Payload(payload)
		if !ok {
			// #7175: a truncated record used to decode ok=true with PolicyID,
			// both zone ids and the NAT fields left at zero. It is now
			// rejected — and counted, because a silently skipped install is
			// how fabric corruption or a version-skewed peer hides.
			// #10724: count every occurrence; the log emits once per
			// family (detector above) so a malformed-record flood cannot
			// emit one Warn per record.
			n := s.stats.MalformedRecordsDropped.Add(1)
			s.malformedRecordWarn.observeV4(len(payload), n)
		} else {
			if val.IsReverse == 0 {
				s.bulkMu.Lock()
				if s.bulkInProgress {
					s.bulkRecvV4[key] = struct{}{}
				}
				s.bulkMu.Unlock()
			}
			offset := s.clockOffsetFor(conn)
			// #9915 F-118: count only installs that both saturate AND land:
			// the predicate decides the clamp, installClusterSyncedV4 decides
			// the guard outcome, and only a landed apply is counted.
			saturated := rebaseSaturates(val.Created, offset) || rebaseSaturates(val.LastSeen, offset)
			created, lastSeen := val.Created, val.LastSeen
			val.Created = rebaseTimestamp(val.Created, offset)
			val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
			landed := s.installClusterSyncedV4(key, val)
			if saturated && landed {
				n := s.stats.RebaseSaturations.Add(1)
				if n == 1 || n%64 == 0 {
					slog.Warn("cluster sync: saturating peer timestamp on rebase overflow; install clamped to far future",
						"created", created, "last_seen", lastSeen, "offset", offset,
						"saturated_total", n, "remote", connRemoteAddrString(conn))
				}
			}
		}
	}
}

func (s *SessionSync) handleSessionV6(conn net.Conn, payload []byte) {
	s.stats.SessionsReceived.Add(1)
	s.bulkReceiveProgress("v6", conn)
	if s.sessions != nil {
		key, val, ok := decodeSessionV6Payload(payload)
		if !ok {
			// #7175: a truncated record used to decode ok=true with PolicyID,
			// both zone ids and the NAT fields left at zero. It is now
			// rejected — and counted, because a silently skipped install is
			// how fabric corruption or a version-skewed peer hides.
			// #10724: see the v4 twin — count every occurrence, log once.
			n := s.stats.MalformedRecordsDropped.Add(1)
			s.malformedRecordWarn.observeV6(len(payload), n)
		} else {
			if val.IsReverse == 0 {
				s.bulkMu.Lock()
				if s.bulkInProgress {
					s.bulkRecvV6[key] = struct{}{}
				}
				s.bulkMu.Unlock()
			}
			offset := s.clockOffsetFor(conn)
			// #9915 F-118: see the v4 twin — count only landed saturations.
			saturated := rebaseSaturates(val.Created, offset) || rebaseSaturates(val.LastSeen, offset)
			created, lastSeen := val.Created, val.LastSeen
			val.Created = rebaseTimestamp(val.Created, offset)
			val.LastSeen = rebaseTimestamp(val.LastSeen, offset)
			landed := s.installClusterSyncedV6(key, val)
			if saturated && landed {
				n := s.stats.RebaseSaturations.Add(1)
				if n == 1 || n%64 == 0 {
					slog.Warn("cluster sync: saturating peer timestamp on rebase overflow; install clamped to far future",
						"created", created, "last_seen", lastSeen, "offset", offset,
						"saturated_total", n, "remote", connRemoteAddrString(conn))
				}
			}
		}
	}
}

func (s *SessionSync) handleDeleteV4(conn net.Conn, payload []byte) {
	s.stats.DeletesReceived.Add(1)
	if s.sessions != nil {
		key, gen, forwardOnly, domain, expectedID, scoped, ok := parseDeleteV4Wire(payload)
		if ok {
			if scoped {
				s.deleteClusterSyncedScopedV4(domain, key, gen, expectedID)
			} else {
				s.deleteClusterSyncedV4(key, gen, forwardOnly)
			}
		}
	}
}

func (s *SessionSync) handleDeleteV6(conn net.Conn, payload []byte) {
	s.stats.DeletesReceived.Add(1)
	if s.sessions != nil {
		key, gen, forwardOnly, domain, expectedID, scoped, ok := parseDeleteV6Wire(payload)
		if ok {
			if scoped {
				s.deleteClusterSyncedScopedV6(domain, key, gen, expectedID)
			} else {
				s.deleteClusterSyncedV6(key, gen, forwardOnly)
			}
		}
	}
}
