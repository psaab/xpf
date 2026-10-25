package logging

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
)

// ResolveEventProtocol resolves an operator protocol token (name, alias,
// or numeric 0..255) to its IP protocol number through the appid SSOT
// (#16688). It is the event-log counterpart of the session surfaces'
// appid.ParseProtocolFilterToken: every name the event log renders
// (TCP/ICMPv6/ESP via protoName -> appid.ProtocolName) and every numeric
// form the outputs print (protocol-id="6") must parse back to the same
// number, so a scoped forensic query never silently narrows to nothing.
// ok=false means the token is neither a known name/alias nor a valid
// 0..255 numeric; callers fail closed with a usage error. The deliberate
// "0" (HOPOPT) resolves to (0, true).
func ResolveEventProtocol(token string) (uint8, bool) {
	return appid.ProtocolNumber(token)
}

// EventFilterArgsUsage is the canonical usage string for the
// `show security log` argument grammar, shared by the local CLI and the
// remote `cli` gRPC text path so a parse error reads identically on both.
const EventFilterArgsUsage = "usage: show security log [<count>] [zone <name>] " +
	"[protocol <proto>] [action <action>]"

// ParseEventFilterArgs parses the positional `show security log` arguments
// into an event count (default 50) and an EventFilter. It is the single
// source of truth for that grammar so the local CLI (pkg/cli) and the remote
// `cli` gRPC ShowText path (pkg/grpcapi) cannot drift — before #3547 the
// remote path dropped every non-numeric token and silently dumped all events,
// so a zone filter (including the unknown/none/0 zone-0 selector #3338) was a
// no-op there even though the local CLI honored it.
//
// zoneIDs maps a configured zone name to its dataplane ID, taken from the
// active apply result; haveApply reports whether that result exists at all
// (it is nil during early startup or after a failed apply). A NAMED zone
// filter requires haveApply — refusing rather than dropping the filter and
// widening to every zone's events (M02). The unknown/none/0 sentinels select
// zone 0 (the unassigned / pre-classification zone) without needing the apply
// result, because zone IDs are 1-based and 0 can never collide with a
// configured zone.
//
// Parsing fails CLOSED (#3347): an unknown token, a filter keyword with no
// value, a non-positive count, or an unresolvable named zone is an error, not
// a silently-ignored token that falls through to an unfiltered dump.
func ParseEventFilterArgs(args []string, zoneIDs map[string]uint16, haveApply bool) (int, EventFilter, error) {
	n := 50
	var filter EventFilter
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 >= len(args) {
				return 0, EventFilter{}, fmt.Errorf("missing value for %q\n%s", "zone", EventFilterArgsUsage)
			}
			i++
			zoneName := args[i]
			switch strings.ToLower(zoneName) {
			case "unknown", "none", "0":
				filter.Zone = 0
				filter.HasZone = true
				continue
			}
			if !haveApply {
				return 0, EventFilter{}, fmt.Errorf("cannot filter by zone %q: no active dataplane apply result "+
					"(zone IDs unavailable — retry after a successful commit)", zoneName)
			}
			zid, ok := zoneIDs[zoneName]
			if !ok {
				return 0, EventFilter{}, fmt.Errorf("zone %q not found", zoneName)
			}
			filter.Zone = zid
			filter.HasZone = true
		case "protocol":
			if i+1 >= len(args) {
				return 0, EventFilter{}, fmt.Errorf("missing value for %q\n%s", "protocol", EventFilterArgsUsage)
			}
			i++
			// #16688: resolve via the appid SSOT and fail closed on an
			// unknown token, instead of storing it raw where the matcher
			// compared it against the rendered name (TCP/ICMPv6/ESP) —
			// "6"/"58"/"50"/"icmp6" and typos like "tcpx" all silently
			// matched nothing. Store the number; keep the raw token for
			// diagnostics.
			num, ok := ResolveEventProtocol(args[i])
			if !ok {
				return 0, EventFilter{}, fmt.Errorf("unknown protocol %q\n%s", args[i], EventFilterArgsUsage)
			}
			filter.Protocol = args[i]
			filter.ProtocolNum = num
			filter.HasProtocol = true
		case "action":
			if i+1 >= len(args) {
				return 0, EventFilter{}, fmt.Errorf("missing value for %q\n%s", "action", EventFilterArgsUsage)
			}
			i++
			filter.Action = args[i]
		default:
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return 0, EventFilter{}, fmt.Errorf("unknown argument %q\n%s", args[i], EventFilterArgsUsage)
			}
			if v <= 0 {
				return 0, EventFilter{}, fmt.Errorf("event count must be a positive integer, got %d", v)
			}
			n = v
		}
	}
	return n, filter, nil
}
