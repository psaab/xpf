package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// flowSessionAction marks a parsed-args terminal subcommand of
// `show security flow session` (summary / sort-by top-talkers), as
// distinct from the default per-session listing.
type flowSessionAction int

const (
	flowSessionList flowSessionAction = iota
	flowSessionSummary
	flowSessionSortBy
)

func flowSessionActionName(a flowSessionAction) string {
	switch a {
	case flowSessionSummary:
		return "summary"
	case flowSessionSortBy:
		return "sort-by"
	default:
		return "list"
	}
}

// flowSessionParse is the strict parse result for the remote
// `show security flow session` argument vector.
type flowSessionParse struct {
	req       *pb.GetSessionsRequest
	brief     bool
	action    flowSessionAction
	sortKey   string
	hasFilter bool // a traffic-filter predicate token was supplied
	// zoneName is the `zone <v>` token EXACTLY as typed, unresolved.
	// Resolution needs a GetZones round trip, which a pure parse must not
	// make, so the caller resolves it — see resolveSessionZone (#9065).
	zoneName string
}

// parseFlowSessionArgs strictly parses the remote-CLI session filter
// tokens. Unlike the historical loop — which used `if ...; err == nil`
// with no else and had no default case — it surfaces operator-input
// errors instead of silently dropping the token: a dropped numeric
// value (e.g. `destination-port abc`) left the field zero (= wildcard)
// and silently WIDENED the inspected set, and an unknown token fell
// through and was ignored. This mirrors the strict local parser in
// pkg/cli/session_filter.go so the two CLI surfaces agree on identical
// command shapes (#3439 H5).
func parseFlowSessionArgs(args []string) (*flowSessionParse, error) {
	p := &flowSessionParse{req: &pb.GetSessionsRequest{Limit: 100, IncludePeer: true}}
	takeValue := func(i *int, kw string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("missing value for %q", kw)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			// #9065: this ran strconv.ParseUint on the value and answered
			// `invalid zone "trust"` for every real zone name. Three
			// independent contrasts said it was wrong: the local console
			// resolves the name through cr.ZoneIDs (pkg/cli/session_filter.go),
			// pkg/cmdtree offers zone NAMES as the completion set for this exact
			// path (tree.go:527) so the tree offered a completion this binary
			// then rejected, and the SAME binary's `clear security flow session
			// zone` takes a string (clear.go). The token is kept as typed and
			// resolved by the caller.
			v, err := takeValue(&i, "zone")
			if err != nil {
				return nil, err
			}
			p.zoneName = v
			p.hasFilter = true
		case "protocol":
			v, err := takeValue(&i, "protocol")
			if err != nil {
				return nil, err
			}
			if _, ok := appid.ParseProtocolFilterToken(v); !ok {
				return nil, fmt.Errorf("unknown protocol %q", v)
			}
			p.req.Protocol = strings.ToUpper(v)
			p.hasFilter = true
		case "source-prefix":
			v, err := takeValue(&i, "source-prefix")
			if err != nil {
				return nil, err
			}
			p.req.SourcePrefix = v
			p.hasFilter = true
		case "destination-prefix":
			v, err := takeValue(&i, "destination-prefix")
			if err != nil {
				return nil, err
			}
			p.req.DestinationPrefix = v
			p.hasFilter = true
		case "source-port":
			v, err := takeValue(&i, "source-port")
			if err != nil {
				return nil, err
			}
			n, err := strconv.ParseInt(v, 10, 32)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("invalid source-port %q", v)
			}
			p.req.SourcePort = uint32(n)
			p.hasFilter = true
		case "destination-port":
			v, err := takeValue(&i, "destination-port")
			if err != nil {
				return nil, err
			}
			n, err := strconv.ParseInt(v, 10, 32)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("invalid destination-port %q", v)
			}
			p.req.DestinationPort = uint32(n)
			p.hasFilter = true
		case "nat", "nat-only":
			p.req.NatOnly = true
			p.hasFilter = true
		case "limit":
			v, err := takeValue(&i, "limit")
			if err != nil {
				return nil, err
			}
			// C179-021: parse into a 32-bit range so an overflowing value
			// is rejected, not silently wrapped. strconv.Atoi returns a
			// 64-bit int, so a value like 3000000000 passed the `n < 1`
			// guard and then int32(n) wrapped NEGATIVE — the daemon clamps
			// <= 0 to the default limit, so an over-range request silently
			// became the default instead of erroring.
			n, err := strconv.ParseInt(v, 10, 32)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("invalid limit %q", v)
			}
			p.req.Limit = int32(n)
		case "application":
			v, err := takeValue(&i, "application")
			if err != nil {
				return nil, err
			}
			p.req.Application = v
			p.hasFilter = true
		case "summary":
			p.action = flowSessionSummary
		case "brief":
			p.brief = true
		case "interface":
			v, err := takeValue(&i, "interface")
			if err != nil {
				return nil, err
			}
			p.req.InterfaceFilter = v
			p.hasFilter = true
		case "source-nat-pool":
			v, err := takeValue(&i, "source-nat-pool")
			if err != nil {
				return nil, err
			}
			p.req.SourceNatPool = v
			p.hasFilter = true
		case "sort-by":
			v, err := takeValue(&i, "sort-by")
			if err != nil {
				return nil, err
			}
			p.action = flowSessionSortBy
			p.sortKey = v
		default:
			return nil, fmt.Errorf("unknown session filter %q", args[i])
		}
	}
	// `summary` and `sort-by` are global aggregations on this remote
	// surface: the summary RPC (GetSessionSummary) takes no filter, and
	// the top-talkers path walks the whole table. Earlier they parsed a
	// filter and then SILENTLY ignored it — the #3439 silent-drop bug in
	// a different sub-path. Reject the combination with a clear error
	// instead of returning an unfiltered result the operator did not ask
	// for (use the filtered per-session listing for a narrowed view).
	if p.hasFilter && p.action != flowSessionList {
		return nil, fmt.Errorf("session filters cannot be combined with %q", flowSessionActionName(p.action))
	}
	return p, nil
}

func (c *ctl) showFlowSession(args []string) error {
	p, err := parseFlowSessionArgs(args)
	if err != nil {
		return err
	}
	if p.action == flowSessionSummary {
		return c.showSessionSummary()
	}
	if p.action == flowSessionSortBy {
		return c.showText("sessions-top:" + p.sortKey)
	}
	req := p.req
	brief := p.brief
	if err := c.resolveSessionZone(p); err != nil {
		return err
	}

	resp, err := c.client.GetSessions(c.ctx(), req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	hasPeer := resp.Peer != nil

	if hasPeer {
		printNodeSessionHeader(int(resp.NodeId))
	}
	printSessionEntries(resp, brief)

	if hasPeer {
		fmt.Println()
		printNodeSessionHeader(int(resp.Peer.NodeId))
		printSessionEntries(resp.Peer, brief)
	}
	return nil
}

func printNodeSessionHeader(nodeID int) {
	fmt.Printf("node%d:\n", nodeID)
	fmt.Println("--------------------------------------------------------------------------")
}

func printSessionEntries(resp *pb.GetSessionsResponse, brief bool) {
	if brief {
		fmt.Printf("%-5s %-22s %-22s %-5s %-20s %-3s %-5s %5s %s\n",
			"ID", "Source", "Destination", "Proto", "Zone", "NAT", "State", "Age", "Pkts(f/r)")
		for i, se := range resp.Sessions {
			inZone := se.IngressZoneName
			if inZone == "" {
				inZone = fmt.Sprintf("%d", se.IngressZone)
			}
			outZone := se.EgressZoneName
			if outZone == "" {
				outZone = fmt.Sprintf("%d", se.EgressZone)
			}
			natFlag := " "
			if se.Nat != "" {
				if strings.Contains(se.Nat, "SNAT") {
					natFlag = "S"
				}
				if strings.Contains(se.Nat, "DNAT") || strings.HasPrefix(se.Nat, "dst") {
					natFlag = "D"
				}
			}
			st := se.State
			if len(st) > 5 {
				st = st[:5]
			}
			sid := se.SessionId
			if sid == 0 {
				sid = uint64(resp.Offset) + uint64(i) + 1
			}
			fmt.Printf("%-5d %-22s %-22s %-5s %-20s %-3s %-5s %5d %d/%d\n",
				sid,
				fmt.Sprintf("%s/%d", se.SrcAddr, se.SrcPort),
				fmt.Sprintf("%s/%d", se.DstAddr, se.DstPort),
				se.Protocol, inZone+"->"+outZone, natFlag,
				st, se.AgeSeconds,
				se.FwdPackets, se.RevPackets)
		}
		fmt.Printf("Total sessions: %d\n", resp.Total)
		return
	}

	for i, se := range resp.Sessions {
		polDisplay := se.PolicyName
		if polDisplay == "" {
			polDisplay = fmt.Sprintf("%d", se.PolicyId)
		}
		sid := se.SessionId
		if sid == 0 {
			sid = uint64(resp.Offset) + uint64(i) + 1
		}

		haStr := ""
		if se.HaActive {
			haStr = "Active"
		} else {
			haStr = "Backup"
		}
		fmt.Printf("Session ID: %d, Policy name: %s/%d, HA State: %s, Timeout: %d, Session State: Unknown (validity not tracked)\n",
			sid, polDisplay, se.PolicyId, haStr, se.TimeoutSeconds)

		inIf := se.IngressInterface
		if inIf == "" {
			inIf = se.IngressZoneName
		}
		inZone := se.IngressZoneName
		if inZone == "" {
			inZone = fmt.Sprintf("%d", se.IngressZone)
		}
		fmt.Printf("  In: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			se.SrcAddr, se.SrcPort, se.DstAddr, se.DstPort,
			se.Protocol, inIf, inZone, se.FwdPackets, se.FwdBytes)

		outSrcAddr := se.DstAddr
		outSrcPort := se.DstPort
		outDstAddr := se.SrcAddr
		outDstPort := se.SrcPort
		if se.NatSrcAddr != "" {
			outDstAddr = se.NatSrcAddr
			outDstPort = se.NatSrcPort
		}
		if se.NatDstAddr != "" {
			outSrcAddr = se.NatDstAddr
			outSrcPort = se.NatDstPort
		}
		outIf := se.EgressInterface
		if outIf == "" {
			outIf = se.EgressZoneName
		}
		outZone := se.EgressZoneName
		if outZone == "" {
			outZone = fmt.Sprintf("%d", se.EgressZone)
		}
		fmt.Printf("  Out: %s/%d --> %s/%d;%s, Conn Tag: 0x0, If: %s, Zone: %s, Pkts: %d, Bytes: %d,\n",
			outSrcAddr, outSrcPort, outDstAddr, outDstPort,
			se.Protocol, outIf, outZone, se.RevPackets, se.RevBytes)
		fmt.Println()
	}
	fmt.Printf("Total sessions: %d\n", resp.Total)
}

func (c *ctl) showSessionSummary() error {
	resp, err := c.client.GetSessionSummary(c.ctx(), &pb.GetSessionSummaryRequest{IncludePeer: true})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	if resp.Peer != nil {
		printNodeSessionSummary(int(resp.NodeId), resp)
		fmt.Println()
		printNodeSessionSummary(int(resp.Peer.NodeId), resp.Peer)
	} else {
		printSessionSummaryBlock(resp)
	}

	// #5320: when the cluster peer was requested but could not be reached the
	// totals above are LOCAL-ONLY. Surface that instead of letting a peer
	// partition masquerade as a healthy low session count.
	if resp.GetPeerStatus() == pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE {
		fmt.Printf("\nwarning: cluster peer unreachable; counts above are LOCAL-ONLY")
		if e := resp.GetPeerError(); e != "" {
			fmt.Printf(" (%s)", e)
		}
		fmt.Println()
	}
	return nil
}

func printNodeSessionSummary(nodeID int, resp *pb.GetSessionSummaryResponse) {
	fmt.Printf("node%d:\n", nodeID)
	fmt.Println("--------------------------------------------------------------------------")
	printSessionSummaryBlock(resp)
}

func printSessionSummaryBlock(resp *pb.GetSessionSummaryResponse) {
	unicast := resp.ForwardOnly
	fmt.Printf("Unicast-sessions: %d\n", unicast)
	fmt.Printf("Multicast-sessions: unknown\n")
	fmt.Printf("Services-offload-sessions: unknown\n")
	fmt.Printf("Failed-sessions: unknown\n")
	fmt.Printf("Sessions-in-drop-flow: unknown\n")
	fmt.Printf("Sessions-in-use: %d\n", unicast)
	fmt.Printf("  Valid sessions: unknown\n")
	fmt.Printf("  Pending sessions: unknown\n")
	fmt.Printf("  Invalidated sessions: unknown\n")
	fmt.Printf("  Sessions in other states: unknown\n")
	// #5323: render the dataplane's dynamic max (worker_count x per-worker
	// capacity) the live helper publishes, not the old hardcoded 10000000. A
	// dataplane with no userspace status attached reports 0 -> "unknown"
	// (render the truth rather than a fabricated authoritative bound).
	if max := resp.GetMaxSessions(); max > 0 {
		fmt.Printf("Maximum-sessions: %d\n", max)
	} else {
		fmt.Printf("Maximum-sessions: unknown\n")
	}
}

func (c *ctl) showFlowStatistics() error {
	resp, err := c.client.GetGlobalStats(c.ctx(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	fmt.Println("Flow statistics:")
	fmt.Printf("  %-30s %d\n", "Current sessions:", resp.SessionsCreated-resp.SessionsClosed)
	fmt.Printf("  %-30s %d\n", "Sessions created:", resp.SessionsCreated)
	fmt.Printf("  %-30s %d\n", "Sessions closed:", resp.SessionsClosed)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Packets received:", resp.RxPackets)
	fmt.Printf("  %-30s %d\n", "Packets transmitted:", resp.TxPackets)
	fmt.Printf("  %-30s %d\n", "Packets dropped:", resp.Drops)
	fmt.Printf("  %-30s %d\n", "TC egress packets:", resp.TcEgressPackets)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Policy deny:", resp.PolicyDenies)
	fmt.Printf("  %-30s %d\n", "NAT allocation failures:", resp.NatAllocFailures)
	fmt.Printf("  %-30s %d\n", "NAT64 translations:", resp.Nat64Translations)
	fmt.Println()
	fmt.Printf("  %-30s %d\n", "Host-inbound allowed:", resp.HostInboundAllowed)
	fmt.Printf("  %-30s %d\n", "Host-inbound denied:", resp.HostInboundDenies)

	if resp.ScreenDrops > 0 {
		fmt.Println()
		fmt.Printf("  %-30s %d\n", "Screen drops (total):", resp.ScreenDrops)
		for name, count := range resp.ScreenDropDetails {
			fmt.Printf("    %-28s %d\n", name+":", count)
		}
	}

	return nil
}

// resolveSessionZone binds `show security flow session zone <name>` to the zone
// id GetSessions filters on (#9065).
//
// THE WILDCARD IS THE TRAP. GetSessionsRequest.Zone == 0 means "every zone", so
// a resolve that failed soft would silently WIDEN the inspected set — the exact
// class of defect being fixed, and worse than the loud `invalid zone "trust"`
// it replaces. An unresolvable name is therefore an ERROR, mirroring the
// server's own `zone %q not found` (server_sessions.go).
//
// ZoneInfo.Id is populated from the same cr.ZoneIDs space GetSessions filters
// on, and config.StableZoneID is uint16-bounded to [1, 65533], so the
// server's `req.Zone > 65535` reject can never trip on a real zone id. An id of
// 0 in the response means the daemon has no apply result yet — indistinguishable
// on the wire from the wildcard, so it is refused rather than sent.
//
// A NUMERIC token is accepted only when no zone bears that NAME, so a zone
// literally named "5" keeps precedence over id 5 and existing numeric scripts
// still work.
func (c *ctl) resolveSessionZone(p *flowSessionParse) error {
	if p.zoneName == "" {
		return nil
	}
	resp, err := c.client.GetZones(c.ctx(), &pb.GetZonesRequest{})
	if err != nil {
		return fmt.Errorf("resolving zone %q: %v", p.zoneName, err)
	}
	for _, z := range resp.GetZones() {
		if z.GetName() != p.zoneName {
			continue
		}
		if z.GetId() == 0 {
			return fmt.Errorf("zone %q has no runtime id yet (no configuration has "+
				"been applied), so it cannot be used as a session filter; zone id 0 is "+
				"the request's WILDCARD and would silently match every zone",
				p.zoneName)
		}
		p.req.Zone = z.GetId()
		return nil
	}
	if n, cerr := strconv.ParseUint(p.zoneName, 10, 32); cerr == nil && n > 0 {
		p.req.Zone = uint32(n)
		return nil
	}
	return fmt.Errorf("zone %q not found", p.zoneName)
}
