package api

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *Server) sessionsHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	limit := queryInt(r, "limit", 100)
	if limit > 10000 {
		limit = 10000
	}
	offset := queryInt(r, "offset", 0)
	zoneFilter := queryUint16(r, "zone", 0)
	protoFilter := r.URL.Query().Get("protocol")

	now := monotonicSeconds()
	all := make([]SessionEntry, 0)
	idx := 0

	// IPv4 sessions
	_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if zoneFilter != 0 && val.IngressZone != zoneFilter && val.EgressZone != zoneFilter {
			return true
		}
		proto := protoName(key.Protocol)
		if protoFilter != "" && proto != protoFilter {
			return true
		}

		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV4(key, val, now))
		}
		idx++
		return true
	})

	// IPv6 sessions
	_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if zoneFilter != 0 && val.IngressZone != zoneFilter && val.EgressZone != zoneFilter {
			return true
		}
		proto := protoName(key.Protocol)
		if protoFilter != "" && proto != protoFilter {
			return true
		}

		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV6(key, val, now))
		}
		idx++
		return true
	})

	writeOK(w, SessionListResponse{
		Total:    idx,
		Limit:    limit,
		Offset:   offset,
		Sessions: all,
	})
}

func (s *Server) sessionSummaryHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	var summary SessionSummary

	_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		summary.TotalEntries++
		if val.IsReverse == 0 {
			summary.ForwardOnly++
			summary.IPv4Sessions++
			if val.State == dataplane.SessStateEstablished {
				summary.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				summary.SNATSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				summary.DNATSessions++
			}
		}
		return true
	})

	_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		summary.TotalEntries++
		if val.IsReverse == 0 {
			summary.ForwardOnly++
			summary.IPv6Sessions++
			if val.State == dataplane.SessStateEstablished {
				summary.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				summary.SNATSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				summary.DNATSessions++
			}
		}
		return true
	})

	writeOK(w, summary)
}

func (s *Server) clearSessionsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}
	v4, v6, err := s.dp.ClearAllSessions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, ClearSessionsResult{IPv4Cleared: v4, IPv6Cleared: v6})
}

func (s *Server) sessionZonePairHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeOK(w, []ZonePairSessionSummary{})
		return
	}

	// Build zone ID -> name reverse map
	zoneNames := make(map[uint16]string)
	if cr := s.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
	}

	type zpKey struct{ from, to uint16 }
	counts := make(map[zpKey]*ZonePairSessionSummary)

	countSession := func(inZone, outZone uint16, proto uint8) {
		k := zpKey{inZone, outZone}
		zp, ok := counts[k]
		if !ok {
			zp = &ZonePairSessionSummary{
				FromZone: zoneNames[inZone],
				ToZone:   zoneNames[outZone],
			}
			if zp.FromZone == "" {
				zp.FromZone = fmt.Sprintf("zone-%d", inZone)
			}
			if zp.ToZone == "" {
				zp.ToZone = fmt.Sprintf("zone-%d", outZone)
			}
			counts[k] = zp
		}
		switch proto {
		case 6:
			zp.TCP++
		case 17:
			zp.UDP++
		case 1, dataplane.ProtoICMPv6:
			zp.ICMP++
		default:
			zp.Other++
		}
		zp.Total++
	}

	_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			countSession(val.IngressZone, val.EgressZone, key.Protocol)
		}
		return true
	})
	_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse == 0 {
			countSession(val.IngressZone, val.EgressZone, key.Protocol)
		}
		return true
	})

	result := make([]ZonePairSessionSummary, 0, len(counts))
	for _, zp := range counts {
		result = append(result, *zp)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FromZone != result[j].FromZone {
			return result[i].FromZone < result[j].FromZone
		}
		return result[i].ToZone < result[j].ToZone
	})
	writeOK(w, result)
}

// --- Session helper functions ---

func sessionStateName(state uint8) string {
	switch state {
	case dataplane.SessStateNone:
		return "None"
	case dataplane.SessStateNew:
		return "New"
	case dataplane.SessStateSynSent:
		return "SYN_SENT"
	case dataplane.SessStateSynRecv:
		return "SYN_RECV"
	case dataplane.SessStateEstablished:
		return "Established"
	case dataplane.SessStateFINWait:
		return "FIN_WAIT"
	case dataplane.SessStateCloseWait:
		return "CLOSE_WAIT"
	case dataplane.SessStateTimeWait:
		return "TIME_WAIT"
	case dataplane.SessStateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

func sessionEntryV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64) SessionEntry {
	se := SessionEntry{
		SrcAddr:    net.IP(key.SrcIP[:]).String(),
		DstAddr:    net.IP(key.DstIP[:]).String(),
		SrcPort:    ntohs(key.SrcPort),
		DstPort:    ntohs(key.DstPort),
		Protocol:   protoName(key.Protocol),
		State:      sessionStateName(val.State),
		PolicyID:   val.PolicyID,
		InZone:     val.IngressZone,
		OutZone:    val.EgressZone,
		FwdPackets: val.FwdPackets,
		FwdBytes:   val.FwdBytes,
		RevPackets: val.RevPackets,
		RevBytes:   val.RevBytes,
		Timeout:    val.Timeout,
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.Age = int64(now - val.LastSeen)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		se.NAT = fmt.Sprintf("SNAT %s:%d", uint32ToIP(val.NATSrcIP), ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		se.NAT = fmt.Sprintf("DNAT %s:%d", uint32ToIP(val.NATDstIP), ntohs(val.NATDstPort))
	}
	return se
}

func sessionEntryV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64) SessionEntry {
	se := SessionEntry{
		SrcAddr:    net.IP(key.SrcIP[:]).String(),
		DstAddr:    net.IP(key.DstIP[:]).String(),
		SrcPort:    ntohs(key.SrcPort),
		DstPort:    ntohs(key.DstPort),
		Protocol:   protoName(key.Protocol),
		State:      sessionStateName(val.State),
		PolicyID:   val.PolicyID,
		InZone:     val.IngressZone,
		OutZone:    val.EgressZone,
		FwdPackets: val.FwdPackets,
		FwdBytes:   val.FwdBytes,
		RevPackets: val.RevPackets,
		RevBytes:   val.RevBytes,
		Timeout:    val.Timeout,
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.Age = int64(now - val.LastSeen)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		se.NAT = fmt.Sprintf("SNAT [%s]:%d", net.IP(val.NATSrcIP[:]).String(), ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		se.NAT = fmt.Sprintf("DNAT [%s]:%d", net.IP(val.NATDstIP[:]).String(), ntohs(val.NATDstPort))
	}
	return se
}

// monotonicSeconds returns the current monotonic clock in seconds,
// matching BPF's bpf_ktime_get_ns() / 1e9.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}
