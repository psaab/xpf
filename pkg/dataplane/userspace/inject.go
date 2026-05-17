package userspace

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
)

const InjectPacketUsage = "request chassis cluster data-plane userspace inject-packet slot <N> <valid|fib-mismatch|metadata-parse-error> [destination-ip <ip>] [emit-on-wire true source-ip <ip> [source-port <port>] [destination-port <port>] [protocol <icmp|icmpv6>]]"

func ParseInjectPacketCommand(args []string) (slot uint32, mode string, extra map[string]string, err error) {
	if len(args) < 4 || args[0] != "inject-packet" || args[1] != "slot" {
		return 0, "", nil, fmt.Errorf("usage: %s", InjectPacketUsage)
	}
	slotNum, err := strconv.Atoi(args[2])
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid slot: %s", args[2])
	}
	slot = uint32(slotNum)
	mode = args[3]
	extra = make(map[string]string)
	for i := 4; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return 0, "", nil, fmt.Errorf("missing value for %s", args[i])
		}
		key := strings.ToLower(args[i])
		extra[key] = args[i+1]
	}
	return slot, mode, extra, nil
}

func BuildInjectPacketRequest(slot uint32, mode string, extra map[string]string, status ProcessStatus) (InjectPacketRequest, error) {
	req := InjectPacketRequest{
		Slot:             slot,
		PacketLength:     128,
		AddrFamily:       uint8(syscall.AF_INET),
		Protocol:         6,
		ConfigGeneration: status.LastSnapshotGeneration,
		FIBGeneration:    status.LastFIBGeneration,
		MetadataValid:    true,
		DestinationIP:    extra["destination-ip"],
		EmitOnWire:       strings.EqualFold(extra["emit-on-wire"], "true"),
	}
	switch mode {
	case "valid":
	case "fib-mismatch":
		req.FIBGeneration++
	case "metadata-parse-error":
		req.MetadataValid = false
		req.PacketLength = 96
		req.AddrFamily = 0
		req.Protocol = 0
		req.ConfigGeneration = 0
		req.FIBGeneration = 0
	default:
		return InjectPacketRequest{}, fmt.Errorf("unknown inject mode %q", mode)
	}
	if req.EmitOnWire {
		if !req.MetadataValid {
			return InjectPacketRequest{}, fmt.Errorf("emit-on-wire requires valid metadata")
		}
		if err := populateInjectPacketTuple(&req, extra, status); err != nil {
			return InjectPacketRequest{}, err
		}
	}
	return req, nil
}

func populateInjectPacketTuple(req *InjectPacketRequest, extra map[string]string, status ProcessStatus) error {
	if status.InjectPacketTupleProtocolVersion < InjectPacketTupleProtocolVersion {
		return fmt.Errorf("emit-on-wire requires helper inject tuple protocol version %d (helper has %d)",
			InjectPacketTupleProtocolVersion, status.InjectPacketTupleProtocolVersion)
	}
	if req.DestinationIP == "" {
		return fmt.Errorf("emit-on-wire requires destination-ip")
	}
	sourceText := extra["source-ip"]
	if sourceText == "" {
		return fmt.Errorf("emit-on-wire requires source-ip")
	}
	sourceIP, err := netip.ParseAddr(sourceText)
	if err != nil {
		return fmt.Errorf("invalid source-ip %q: %w", sourceText, err)
	}
	destinationIP, err := netip.ParseAddr(req.DestinationIP)
	if err != nil {
		return fmt.Errorf("invalid destination-ip %q: %w", req.DestinationIP, err)
	}
	if sourceIP.Is4() != destinationIP.Is4() {
		return fmt.Errorf("emit-on-wire source-ip and destination-ip must use the same address family")
	}

	expectedProtocol := uint8(1)
	if sourceIP.Is4() {
		req.AddrFamily = uint8(syscall.AF_INET)
	} else {
		req.AddrFamily = uint8(syscall.AF_INET6)
		expectedProtocol = 58
	}
	protocol := expectedProtocol
	if text := extra["protocol"]; text != "" {
		protocol, err = parseInjectProtocol(text)
		if err != nil {
			return err
		}
	}
	if protocol != expectedProtocol {
		return fmt.Errorf("emit-on-wire supports only %s tuples for this address family", injectProtocolName(expectedProtocol))
	}

	sourcePort := uint16(req.Slot)
	if text := extra["source-port"]; text != "" {
		sourcePort, err = parseInjectPort("source-port", text)
		if err != nil {
			return err
		}
	}
	destinationPort := uint16(0)
	if text := extra["destination-port"]; text != "" {
		destinationPort, err = parseInjectPort("destination-port", text)
		if err != nil {
			return err
		}
	}

	req.TupleMetadataVersion = InjectPacketTupleProtocolVersion
	req.SourceIP = sourceIP.String()
	req.DestinationIP = destinationIP.String()
	req.Protocol = protocol
	req.SourcePort = &sourcePort
	req.DestinationPort = &destinationPort
	return nil
}

func parseInjectPort(name, value string) (uint16, error) {
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", name, value, err)
	}
	return uint16(n), nil
}

func parseInjectProtocol(value string) (uint8, error) {
	switch strings.ToLower(value) {
	case "icmp":
		return 1, nil
	case "icmpv6":
		return 58, nil
	}
	n, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid protocol %q: %w", value, err)
	}
	return uint8(n), nil
}

func injectProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("protocol %d", protocol)
	}
}
