package cluster

import (
	"encoding/binary"
	"fmt"
)

// unmarshalHeartbeatPre19140 is a VERBATIM copy of UnmarshalHeartbeat at
// f9de73594b, the last revision before the #19140 readiness section: the
// decoder every deployed peer runs. It is the old-reader half of
// TestReadinessSectionInvisibleToPreSectionReaders19140.
func unmarshalHeartbeatPre19140(data []byte) (*HeartbeatPacket, error) {
	if len(data) < heartbeatHeaderSize {
		return nil, fmt.Errorf("heartbeat too short: %d bytes", len(data))
	}
	if string(data[0:4]) != heartbeatMagic {
		return nil, fmt.Errorf("invalid heartbeat magic: %q", string(data[0:4]))
	}
	if data[4] != heartbeatVersion {
		return nil, fmt.Errorf("unsupported heartbeat version: %d", data[4])
	}

	pkt := &HeartbeatPacket{
		NodeID:            data[5],
		ClusterID:         binary.LittleEndian.Uint16(data[6:8]),
		HAProtocolVersion: LegacyHAProtocolVersion,
	}

	numGroups := int(data[8])
	need := heartbeatHeaderSize + numGroups*heartbeatGroupSize
	if len(data) < need {
		return nil, fmt.Errorf("heartbeat truncated: have %d, need %d", len(data), need)
	}

	pkt.Groups = make([]HeartbeatGroup, numGroups)
	off := heartbeatHeaderSize
	for i := 0; i < numGroups; i++ {
		pkt.Groups[i] = HeartbeatGroup{
			GroupID:  data[off],
			Priority: binary.LittleEndian.Uint16(data[off+1 : off+3]),
			Weight:   data[off+3],
			State:    data[off+4],
		}
		off += heartbeatGroupSize
	}

	// Parse monitor section if present (backwards compatible — old packets
	// without monitors just have no remaining data). If the monitor section
	// is truncated (sender capped at maxHeartbeatSize), return whatever
	// monitors were successfully parsed rather than erroring — RG state
	// (already parsed above) is the critical data.
	monitorSectionComplete := true
	if off < len(data) {
		numMonitors := int(data[off])
		off++
		for i := 0; i < numMonitors; i++ {
			if off+4 > len(data) {
				monitorSectionComplete = false
				break // truncated — return what we have
			}
			rgID := data[off]
			up := data[off+1]&1 != 0
			weight := data[off+2]
			nameLen := int(data[off+3])
			off += 4
			if off+nameLen > len(data) {
				monitorSectionComplete = false
				break // truncated name — return what we have
			}
			name := string(data[off : off+nameLen])
			off += nameLen
			pkt.Monitors = append(pkt.Monitors, HeartbeatMonitor{
				RGID:      rgID,
				Weight:    weight,
				Up:        up,
				Interface: name,
			})
		}
	}
	versionSectionComplete := false
	if monitorSectionComplete && off < len(data) {
		versionLen := int(data[off])
		off++
		if off+versionLen <= len(data) {
			pkt.SoftwareVersion = string(data[off : off+versionLen])
			off += versionLen
			versionSectionComplete = true
		} else {
			return pkt, nil
		}
	}
	if monitorSectionComplete && versionSectionComplete && off+2 <= len(data) {
		pkt.HAProtocolVersion = normalizeHAProtocolVersion(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2
		if pkt.HAProtocolVersion >= heartbeatEchoProtocolVersion &&
			off+heartbeatEchoTrailerSize <= len(data) &&
			string(data[off:off+len(heartbeatEchoMagic)]) == heartbeatEchoMagic {
			off += len(heartbeatEchoMagic)
			pkt.HeartbeatSession = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
			pkt.HeartbeatSequence = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
			pkt.PeerHeartbeatSession = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
			pkt.PeerHeartbeatSequence = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
		}
		// #18585: the optional clock section, right after the echo (or the
		// HA version when there is no echo). Identified by its magic like the
		// echo; on a keyed frame from an older sender the bytes here are the
		// epoch marker, which matches the magic with probability 2^-32 per
		// key — the consumer's plausibility band discards such a reading.
		if off+heartbeatClockTrailerSize <= len(data) &&
			string(data[off:off+len(heartbeatClockMagic)]) == heartbeatClockMagic {
			off += len(heartbeatClockMagic)
			pkt.WallClockUnixNano = int64(binary.LittleEndian.Uint64(data[off : off+8]))
		}
	}

	return pkt, nil
}
