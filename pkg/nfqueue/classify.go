package nfqueue

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// CaptureClassification is the bounded L3 metadata extracted from an NFQUEUE
// payload. FlowKey is a stable datagram/transport key; fragment metadata is
// retained separately so fragment state cannot cross queue generations.
type CaptureClassification struct {
	Version    uint8
	Proto      uint8
	Src        [16]byte
	Dst        [16]byte
	HasPorts   bool
	SrcPort    uint16
	DstPort    uint16
	IsFragment bool
	FragMore   bool
	FragOffset uint32
	FragID     uint32
	FlowKey    string

	payloadOffset int
	payloadLength int
}

// FragmentKey derives the generation-scoped fragment identity. Whole packets
// intentionally cannot produce a fragment key.
func (c CaptureClassification) FragmentKey(tunnel, vrf uint32, generation uint64) (FragmentKey, bool) {
	if !c.IsFragment {
		return FragmentKey{}, false
	}
	return FragmentKey{
		Version:    c.Version,
		Tunnel:     tunnel,
		VRF:        vrf,
		Generation: generation,
		ID:         c.FragID,
		Src:        c.Src,
		Dst:        c.Dst,
	}, true
}

// FragmentPiece returns the L3 data carried by this fragment. It reparses the
// payload before slicing so malformed or mismatched packets are refused rather
// than being inserted under a caller-supplied key.
func (c CaptureClassification) FragmentPiece(payload []byte) (Fragment, bool) {
	parsed, err := ClassifyCapturePayload(payload)
	if err != nil || !parsed.IsFragment || parsed.FlowKey != c.FlowKey || parsed.FragOffset != c.FragOffset || parsed.FragID != c.FragID {
		return Fragment{}, false
	}
	end := parsed.payloadOffset + parsed.payloadLength
	if parsed.payloadOffset < 0 || parsed.payloadLength < 0 || end > len(payload) {
		return Fragment{}, false
	}
	data := append([]byte(nil), payload[parsed.payloadOffset:end]...)
	return Fragment{Offset: parsed.FragOffset, More: parsed.FragMore, Data: data}, true
}

// ClassifyCapturePayload parses an IPv4 or IPv6 packet from an NFQUEUE
// payload. It rejects truncation and unsupported/malformed headers; callers
// must drop or divert such packets instead of inventing a flow key.
func ClassifyCapturePayload(payload []byte) (CaptureClassification, error) {
	if len(payload) == 0 {
		return CaptureClassification{}, errors.New("nfqueue: empty capture payload")
	}
	switch payload[0] >> 4 {
	case 4:
		return classifyIPv4(payload)
	case 6:
		return classifyIPv6(payload)
	default:
		return CaptureClassification{}, fmt.Errorf("nfqueue: unsupported IP version %d", payload[0]>>4)
	}
}

func classifyIPv4(payload []byte) (CaptureClassification, error) {
	if len(payload) < 20 {
		return CaptureClassification{}, errors.New("nfqueue: truncated IPv4 header")
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || ihl > len(payload) {
		return CaptureClassification{}, errors.New("nfqueue: invalid IPv4 IHL")
	}
	total := int(binary.BigEndian.Uint16(payload[2:4]))
	if total < ihl || total > len(payload) {
		return CaptureClassification{}, errors.New("nfqueue: invalid IPv4 total length")
	}
	var c CaptureClassification
	c.Version = 4
	c.Proto = payload[9]
	copy(c.Src[12:], payload[12:16])
	copy(c.Dst[12:], payload[16:20])
	flagsFrag := binary.BigEndian.Uint16(payload[6:8])
	c.FragMore = flagsFrag&0x2000 != 0
	c.FragOffset = uint32(flagsFrag&0x1fff) * 8
	c.FragID = uint32(binary.BigEndian.Uint16(payload[4:6]))
	c.IsFragment = c.FragMore || c.FragOffset != 0
	c.payloadOffset = ihl
	c.payloadLength = total - ihl
	if c.IsFragment && c.FragOffset == 0 && c.payloadLength < 4 && isTransportProtocol(c.Proto) {
		return CaptureClassification{}, errors.New("nfqueue: truncated transport header in first IPv4 fragment")
	}
	if c.IsFragment && c.FragOffset == 0 && c.payloadLength >= 4 && isTransportProtocol(c.Proto) {
		c.SrcPort = binary.BigEndian.Uint16(payload[ihl : ihl+2])
		c.DstPort = binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])
		c.HasPorts = true
	} else if !c.IsFragment && c.payloadLength < 4 && isTransportProtocol(c.Proto) {
		return CaptureClassification{}, errors.New("nfqueue: truncated transport header in IPv4 packet")
	} else if !c.IsFragment && c.payloadLength >= 4 && isTransportProtocol(c.Proto) {
		c.SrcPort = binary.BigEndian.Uint16(payload[ihl : ihl+2])
		c.DstPort = binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])
		c.HasPorts = true
	}
	c.FlowKey = captureFlowKey(c)
	return c, nil
}

func classifyIPv6(payload []byte) (CaptureClassification, error) {
	if len(payload) < 40 {
		return CaptureClassification{}, errors.New("nfqueue: truncated IPv6 header")
	}
	payloadLength := int(binary.BigEndian.Uint16(payload[4:6]))
	end := 40 + payloadLength
	if end < 40 || end > len(payload) {
		return CaptureClassification{}, errors.New("nfqueue: invalid IPv6 payload length")
	}
	var c CaptureClassification
	c.Version = 6
	copy(c.Src[:], payload[8:24])
	copy(c.Dst[:], payload[24:40])
	next := payload[6]
	headerEnd := 40
	if next == 44 { // Fragment parsing is limited to an immediate Fragment header.
		if payloadLength < 8 {
			return CaptureClassification{}, errors.New("nfqueue: truncated IPv6 fragment header")
		}
		frag := payload[40:48]
		next = frag[0]
		word := binary.BigEndian.Uint16(frag[2:4])
		c.FragMore = word&1 != 0
		c.FragOffset = uint32(word>>3) * 8
		c.FragID = binary.BigEndian.Uint32(frag[4:8])
		c.IsFragment = true // atomic fragments (offset=0, M=0) remain fragments.
		headerEnd = 48
	}
	// IPv6 headers other than TCP and UDP have no ports to extract. Like the
	// IPv4 classifier, retain their protocol number and classify them by
	// endpoints so they can reach policy and reinjection (#10897).
	// Extension chains after an immediate Fragment header remain unparsed.
	c.Proto = next
	c.payloadOffset = headerEnd
	c.payloadLength = end - headerEnd
	if c.payloadLength < 0 {
		return CaptureClassification{}, errors.New("nfqueue: invalid IPv6 header length")
	}
	if c.IsFragment && c.FragOffset == 0 && c.payloadLength < 4 && isTransportProtocol(c.Proto) {
		return CaptureClassification{}, errors.New("nfqueue: truncated transport header in first IPv6 fragment")
	}
	if !c.IsFragment && c.payloadLength < 4 && isTransportProtocol(c.Proto) {
		return CaptureClassification{}, errors.New("nfqueue: truncated transport header in IPv6 packet")
	}
	if c.payloadLength >= 4 && isTransportProtocol(c.Proto) && (!c.IsFragment || c.FragOffset == 0) {
		c.SrcPort = binary.BigEndian.Uint16(payload[headerEnd : headerEnd+2])
		c.DstPort = binary.BigEndian.Uint16(payload[headerEnd+2 : headerEnd+4])
		c.HasPorts = true
	}
	c.FlowKey = captureFlowKey(c)
	return c, nil
}

func isTransportProtocol(proto uint8) bool {
	return proto == 6 || proto == 17
}

func captureFlowKey(c CaptureClassification) string {
	var src, dst [16]byte
	copy(src[:], c.Src[:])
	copy(dst[:], c.Dst[:])
	// Fragment keys are datagram keys and therefore include the IP ID while
	// whole transport packets include ports to preserve per-flow FIFO order.
	key := fmt.Sprintf("v%d/%d/%x/%x", c.Version, c.Proto, src, dst)
	if c.IsFragment {
		return fmt.Sprintf("%s/id=%08x", key, c.FragID)
	}
	if c.HasPorts {
		return fmt.Sprintf("%s/%d/%d", key, c.SrcPort, c.DstPort)
	}
	return key
}

// Keep hex imported in the source-level contract: callers that log FlowKey
// components can use the same canonical fixed-width encoding without net.IP
// formatting differences. This helper also avoids exposing mutable slices.
func captureAddressHex(address [16]byte) string { return hex.EncodeToString(address[:]) }
