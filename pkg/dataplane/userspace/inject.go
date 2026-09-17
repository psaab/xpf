package userspace

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"syscall"

	"github.com/psaab/xpf/pkg/dataplane"
)

const InjectPacketUsage = "request chassis cluster data-plane userspace inject-packet slot <N> <valid|fib-mismatch|metadata-parse-error> [packet-length <bytes>] [destination-ip <ip>] [emit-on-wire true source-ip <ip> [source-port <port>] [destination-port <port>] [protocol <icmp|icmpv6>]]"
const injectPacketTargetExtraPrefix = "xpf-inject-extra:"

func ParseInjectPacketCommand(args []string) (slot uint32, mode string, extra map[string]string, err error) {
	if len(args) < 4 || args[0] != "inject-packet" || args[1] != "slot" {
		return 0, "", nil, fmt.Errorf("usage: %s", InjectPacketUsage)
	}
	slot, err = parseBindingSlot(args[2])
	if err != nil {
		return 0, "", nil, err
	}
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

func EncodeInjectPacketTarget(extra map[string]string) string {
	if len(extra) == 0 {
		return ""
	}
	raw, err := json.Marshal(extra)
	if err != nil {
		return extra["destination-ip"]
	}
	return injectPacketTargetExtraPrefix + string(raw)
}

func DecodeInjectPacketTarget(target string) (map[string]string, error) {
	extra := make(map[string]string)
	if target == "" {
		return extra, nil
	}
	if !strings.HasPrefix(target, injectPacketTargetExtraPrefix) {
		extra["destination-ip"] = target
		return extra, nil
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(target, injectPacketTargetExtraPrefix)), &extra); err != nil {
		return nil, fmt.Errorf("invalid userspace inject target extras: %w", err)
	}
	return extra, nil
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
	// #2443: honor an optional operator-supplied packet-length override,
	// but bound it. An over-max value is REJECTED (not clamped) so an
	// API misuse / DoS attempt surfaces as an error rather than being
	// silently masked — clamping a malicious large value to the max
	// would still hide the misuse.
	if text := extra["packet-length"]; text != "" {
		n, err := strconv.ParseUint(text, 10, 32)
		if err != nil {
			return InjectPacketRequest{}, fmt.Errorf("invalid packet-length %q: %w", text, err)
		}
		req.PacketLength = uint32(n)
	}
	if req.PacketLength > MaxInjectPacketLength {
		return InjectPacketRequest{}, fmt.Errorf(
			"inject packet-length %d exceeds maximum %d", req.PacketLength, MaxInjectPacketLength)
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

func validateInjectPacketRequestForHelper(req InjectPacketRequest, status ProcessStatus) error {
	// Defense-in-depth (#5449): a request built directly via
	// BuildInjectPacketRequest can carry an out-of-range slot that never
	// passed parseBindingSlot. Reject it at the helper seam before it
	// selects an out-of-bounds binding-array slot.
	//
	// #8597: bounded on the SLOT dimension, not the composed-index one. This
	// compared against BindingArrayMaxEntries (MaxInterfaces *
	// BindingQueuesPerIface = 1048576), which bounds the composed index
	// `ifindex*BindingQueuesPerIface + queue` into userspace_bindings.
	// `req.Slot` is not that: the helper looks it up in maps keyed by the
	// planner's dense slot, which BindingSlotMapMaxEntries (4096) bounds —
	// and applyUserspaceHelperStatusLocked fail-closes on any binding whose
	// Slot reaches it. constants.go states the distinction and warns against
	// exactly this substitution: the two are "NOT interchangeable even though
	// both are 'the binding bound' in casual speech (#7497) ... a check
	// against the larger value admits slots these maps cannot address".
	//
	// DEFENSIVE, and currently unreachable — nothing today can exploit the
	// looser bound. The helper resolves an inject slot by map lookup and
	// returns "unknown binding slot" for anything not live, and a live slot
	// is always below 4096 by the fail-closed check above. The change buys an
	// earlier refusal with a truthful ceiling, not a fix for a live defect.
	//
	// #9915 F-124 OVERRIDES the #8597 conclusion recorded here: K79 claimed
	// `uint16(req.Slot)` truncates the default emit-on-wire source port for
	// "legal high binding slots", and the old reading held that narrowing the
	// operator grammar was unjustified because slots at that magnitude were
	// merely unaddressable. The cohort refiled the divergence itself as the
	// defect: a grammar 256x wider than the seam is wire-safe only by call
	// order, and the truncation runs pre-validation. The parse-side bound now
	// matches this seam (BindingSlotMapMaxEntries); slots 4096..1048575 were
	// never addressable, so earlier refusal is strictly more truthful.
	if req.Slot >= dataplane.BindingSlotMapMaxEntries {
		return fmt.Errorf("inject slot %d out of range [0, %d)", req.Slot, dataplane.BindingSlotMapMaxEntries)
	}
	if !req.EmitOnWire {
		return nil
	}
	if status.InjectPacketTupleProtocolVersion < InjectPacketTupleProtocolVersion {
		return fmt.Errorf("emit-on-wire requires helper inject tuple protocol version %d (helper has %d)",
			InjectPacketTupleProtocolVersion, status.InjectPacketTupleProtocolVersion)
	}
	if req.TupleMetadataVersion < InjectPacketTupleProtocolVersion {
		return fmt.Errorf("emit-on-wire request requires tuple metadata version %d (got %d)",
			InjectPacketTupleProtocolVersion, req.TupleMetadataVersion)
	}
	if req.SourceIP == "" {
		return fmt.Errorf("emit-on-wire requires source-ip")
	}
	if req.DestinationIP == "" {
		return fmt.Errorf("emit-on-wire requires destination-ip")
	}
	sourceIP, err := netip.ParseAddr(req.SourceIP)
	if err != nil {
		return fmt.Errorf("invalid source-ip %q: %w", req.SourceIP, err)
	}
	destinationIP, err := netip.ParseAddr(req.DestinationIP)
	if err != nil {
		return fmt.Errorf("invalid destination-ip %q: %w", req.DestinationIP, err)
	}
	if sourceIP.Is4() != destinationIP.Is4() {
		return fmt.Errorf("emit-on-wire source-ip and destination-ip must use the same address family")
	}
	expectedFamily := uint8(syscall.AF_INET6)
	expectedProtocol := uint8(58)
	if sourceIP.Is4() {
		expectedFamily = uint8(syscall.AF_INET)
		expectedProtocol = 1
	}
	if req.AddrFamily != expectedFamily {
		return fmt.Errorf("emit-on-wire tuple addr_family %d does not match packet family %d", req.AddrFamily, expectedFamily)
	}
	if req.Protocol != expectedProtocol {
		return fmt.Errorf("emit-on-wire supports only %s tuples for this address family", injectProtocolName(expectedProtocol))
	}
	if req.SourcePort == nil {
		return fmt.Errorf("emit-on-wire requires source-port tuple metadata")
	}
	if req.DestinationPort == nil {
		return fmt.Errorf("emit-on-wire requires destination-port tuple metadata")
	}
	return nil
}

func populateInjectPacketTuple(req *InjectPacketRequest, extra map[string]string, status ProcessStatus) error {
	// #9915 F-124: validate the slot BEFORE the uint16(req.Slot) source-port
	// derivation below. Deriving first would silently truncate an out-of-range
	// slot into a wrong port; the seam check runs later and cannot un-bake it.
	if req.Slot >= dataplane.BindingSlotMapMaxEntries {
		return fmt.Errorf("inject slot %d out of range [0, %d)", req.Slot, dataplane.BindingSlotMapMaxEntries)
	}
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
