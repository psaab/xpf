package upgrade

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// grpcCluster is the production RollingCluster backed by the xpfd gRPC API
// on the LOCAL node. It uses the NON-INTERACTIVE SystemAction RPC for
// mutations (the documented automation path — the interactive `cli -c
// "request ... in-service-upgrade"` hard-errors in non-TTY mode, #1563)
// and the `chassis-cluster-information` ShowText topic for the drain-
// predicate reads.
//
// The information topic renders cluster.Manager.FormatInformation(), which
// emits the fields the strong drain predicate needs:
//   - "Remote node: healthy (nodeN)" / "lost"
//   - per-RG "Local state: Primary|Secondary"
//   - per-RG "Takeover ready: yes|no (reasons)"
//   - per-RG "Effective priority: N"
//
// Parsing is defensive and conservative: an unrecognized / ambiguous state
// reads as not-drained / not-ready, so the rolling driver ABORTS without
// cutting rather than cutting unsafely. The exact field strings are
// asserted in cluster_cli_test.go against the live FormatInformation
// format so a status-format change is caught by a unit test, not in
// production.
type grpcCluster struct {
	addr        string
	dialTimeout time.Duration
}

// NewCLICluster returns a RollingCluster driving the SELECTED systemd unit's
// xpfd via gRPC. The name is retained for the cmd wiring; the implementation
// is the gRPC client (not the interactive `cli`).
//
// The cluster control RPCs (PeerAlive / SyncEstablished / DrainComplete /
// ForceSecondary / ResetFailover) target a single hard-coded local endpoint
// (127.0.0.1:50051). The systemd action side (stop/start/flip) honors the
// --unit selection, so a non-default --unit would cut one daemon while the
// drain predicate and ForceSecondary control ANOTHER — wrong-daemon control
// (#1983). Until a unit->endpoint mapping exists, only the default unit is
// supported; any other unit is REJECTED here at the single construction
// chokepoint so cluster RPCs can never silently target the wrong daemon
// while systemd actions hit a different one. Centralizing the guard in the
// constructor covers ALL callers (RunRolling + `xpfd upgrade kernel
// drain`/`rejoin`, which also pass --unit through) and any future caller
// automatically. --unit takes the BARE unit name (e.g. "xpfd"); the systemd
// layer appends ".service" itself (system_linux.go), so "xpfd.service" is a
// non-default spelling and is rejected.
func NewCLICluster(unit string) (RollingCluster, error) {
	if unit != "" && unit != DefaultUnit {
		return nil, fmt.Errorf("cluster control for systemd unit %q is "+
			"unsupported: the rolling/kernel upgrade control RPCs target the "+
			"default daemon at 127.0.0.1:50051, so a non-default --unit would "+
			"drive cluster failover against the WRONG daemon while systemd "+
			"actions hit %q (a per-unit control endpoint is not yet mapped; "+
			"use the default unit %q)", unit, unit, DefaultUnit)
	}
	return &grpcCluster{addr: "127.0.0.1:50051", dialTimeout: 5 * time.Second}, nil
}

func (g *grpcCluster) dial() (pb.BpfrxServiceClient, func(), error) {
	conn, err := grpc.NewClient(g.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("dial xpfd gRPC %s: %w", g.addr, err)
	}
	return pb.NewBpfrxServiceClient(conn), func() { _ = conn.Close() }, nil
}

const (
	rollingForceSecondaryBarrierTimeout = 60 * time.Second
	rollingForceSecondaryRetrySlack     = 5 * time.Second
	rollingForceSecondaryHandoffTimeout = 10 * time.Second
	rollingForceSecondaryDeadlineMargin = 15 * time.Second
)

// rollingForceSecondaryActionTimeoutForRGs covers ForceSecondary's sequential
// per-active-RG barrier waits, each RG's admission retry slack, and the
// observed peer-handoff wait. The production caller uses the maximum
// representable RG count: the daemon snapshots the active set only after the
// RPC begins, so a conservative bound here prevents a status read/ForceSecondary
// race from under-deadlining the action.
func rollingForceSecondaryActionTimeoutForRGs(activeRGCount int) time.Duration {
	if activeRGCount < 1 {
		activeRGCount = 1
	}
	return time.Duration(activeRGCount)*
		(rollingForceSecondaryBarrierTimeout+rollingForceSecondaryRetrySlack) +
		rollingForceSecondaryHandoffTimeout + rollingForceSecondaryDeadlineMargin
}

func (g *grpcCluster) actionCtx(action string, activeRGCount int) (context.Context, context.CancelFunc) {
	timeout := g.dialTimeout
	if action == "in-service-upgrade" {
		timeout = rollingForceSecondaryActionTimeoutForRGs(activeRGCount)
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (g *grpcCluster) systemAction(action string) error {
	cli, closeFn, err := g.dial()
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := g.actionCtx(action, config.MaxRedundancyGroups)
	defer cancel()
	_, err = cli.SystemAction(ctx, &pb.SystemActionRequest{Action: action})
	return err
}

func (g *grpcCluster) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), g.dialTimeout)
}

// information fetches the rendered `show chassis cluster information` text.
func (g *grpcCluster) information() (string, error) {
	cli, closeFn, err := g.dial()
	if err != nil {
		return "", err
	}
	defer closeFn()
	ctx, cancel := g.ctx()
	defer cancel()
	resp, err := cli.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-cluster-information"})
	if err != nil {
		return "", fmt.Errorf("show chassis cluster information: %w", err)
	}
	return resp.GetOutput(), nil
}

func (g *grpcCluster) PeerAlive() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	return parsePeerAlive(s), nil
}

func (g *grpcCluster) SyncEstablished() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	return parseSyncEstablished(s), nil
}

func (g *grpcCluster) SessionSyncBulkPrimed() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	return parseSessionSyncBulkPrimed(s), nil
}

func (g *grpcCluster) DrainComplete() (bool, error) {
	// DrainComplete needs BOTH the local node's RG states (Secondary) AND
	// the PEER node's RG states (Primary) — i.e. the peer has actually
	// taken ownership, not merely that the local node demoted itself. The
	// status topic (FormatStatus) renders both the local AND peer node
	// lines per RG; the information topic renders only the local view. So
	// drain-complete is evaluated against the STATUS topic.
	st, err := g.statusText()
	if err != nil {
		return false, err
	}
	// Also require the peer alive + sync up from the information topic.
	info, err := g.information()
	if err != nil {
		return false, err
	}
	return parseDrainComplete(st) && parsePeerAlive(info) && parseSyncEstablished(info), nil
}

func (g *grpcCluster) HAProtocolCompatible() (bool, error) {
	// The HA protocol version lines are in the STATUS topic
	// (FormatStatus), not information (FormatInformation).
	s, err := g.statusText()
	if err != nil {
		return false, err
	}
	return parseHAProtocolCompatible(s), nil
}

// SessionSyncWireCompatible reads the peer's advertised session-sync wire
// version from the STATUS topic and asks pkg/cluster for the verdict (#7990).
//
// The verdict lives in pkg/cluster rather than here so there is ONE definition
// of "compatible" shared with the runtime side, rather than a second copy in
// the upgrade driver that could drift from the wire it is judging.
func (g *grpcCluster) SessionSyncWireCompatible() (bool, string, error) {
	s, err := g.statusText()
	if err != nil {
		return false, "", err
	}
	return sessionSyncWireVerdictFromStatus(s)
}

// sessionSyncWireVerdictFromStatus is the DECISION half of
// SessionSyncWireCompatible, split from the gRPC fetch so it is drivable (#7990).
//
// The split is not cosmetic. The first version of this code inlined the decision
// next to the fetch, and the only test of the absent-line behaviour drove
// parsePeerSessionSyncWire and cluster.SessionSyncWireCompatible directly —
// both of which are UNCHANGED by the defect. Reverting the absent-line handling
// left the whole suite green. The collapse lives HERE, between the parser and
// the verdict, so this is the layer a test has to reach.
func sessionSyncWireVerdictFromStatus(status string) (bool, string, error) {
	peer, present := parsePeerSessionSyncWire(status)
	if !present {
		// The line is ABSENT, which is a statement about the INSTRUMENT, not
		// about the peer — and collapsing it into "peer advertises nothing"
		// (which permits) would be a gate that cannot fire, silently, exactly
		// the failure shape this change exists to remove.
		//
		// It is safe to refuse. FormatStatus renders the peer line
		// unconditionally when the peer is alive, this node is by definition
		// running THIS build (it is the node being upgraded), and
		// DrainAndConfirm's PeerAlive precheck runs FIRST and refuses a dead
		// peer. So by the time this runs the line must be present; its absence
		// means the status could not be rendered or parsed — a renamed line, a
		// truncated response, a peer that died between the two RPCs. Draining
		// on any of those is not something to do quietly.
		//
		// Reported as an ERROR rather than an incompatibility so the operator's
		// message says "the check could not run", not "the peer is
		// incompatible". Those are different facts and only one is about the peer.
		return false, "", fmt.Errorf("peer session-sync wire version not present in " +
			"`show chassis cluster status` — the check cannot run, and an unreadable " +
			"instrument is not evidence of compatibility")
	}
	okv, reason := cluster.SessionSyncWireCompatible(peer)
	return okv, reason, nil
}

// statusText fetches the rendered `show chassis cluster status` text.
func (g *grpcCluster) statusText() (string, error) {
	cli, closeFn, err := g.dial()
	if err != nil {
		return "", err
	}
	defer closeFn()
	ctx, cancel := g.ctx()
	defer cancel()
	resp, err := cli.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-cluster-status"})
	if err != nil {
		return "", fmt.Errorf("show chassis cluster status: %w", err)
	}
	return resp.GetOutput(), nil
}

func (g *grpcCluster) PeerTakeoverReady() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	return parsePeerTakeoverReady(s), nil
}

func (g *grpcCluster) ForceSecondary() error {
	// Non-interactive demote via the documented automation path.
	return g.systemAction("in-service-upgrade")
}

// --- pure parsers over `show chassis cluster information`
// (cluster.Manager.FormatInformation) text. Kept pure + exported-to-tests
// so a status-format drift is caught by cluster_cli_test.go (which feeds
// REAL FormatInformation output through them), not in production. ---

func parsePeerAlive(s string) bool {
	// "Remote node: healthy (nodeN)" => alive; "Remote node: lost" => not.
	return lineHasAll(s, "Remote node:", "healthy")
}

// parseSyncEstablished checks the session/fabric sync link is UP. The
// information topic (FormatInformation) renders a "Sync link statistics"
// (or "Fabric link statistics") block with a "Status: Up|Down" line
// (status.go). Require BOTH a healthy remote AND Status: Up. A missing
// Status line or "Status: Down" fails closed (Codex r2 High: a healthy
// heartbeat with session sync DOWN must NOT proceed to drain+cut).
func parseSyncEstablished(s string) bool {
	if strings.Contains(strings.ToLower(s), "unsynced") {
		return false
	}
	if !lineHasAll(s, "Remote node:", "healthy") {
		return false
	}
	// Find the sync-link "Status:" line, SCOPED to the sync/fabric link
	// section. FormatInformation renders the section under a "Fabric link
	// statistics:" or "Sync link statistics (control-link):" header and ends
	// it with a blank line (status.go). Scoping (vs the first "status:"
	// anywhere) means a future pre-sync section that also emits "Status:"
	// (e.g. IP-monitoring, FormatIPMonitoringStatus) can never be mis-read as
	// the sync link — which would wrongly green-light a drain (AGY review-011
	// Part I). Within the section, require the value to be EXACTLY "up", not a
	// substring, so a future "Status: startup" is not accepted as up.
	inSync := false
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(strings.TrimSpace(line))
		if !inSync {
			if strings.HasPrefix(ll, "sync link statistics") ||
				strings.HasPrefix(ll, "fabric link statistics") {
				inSync = true
			}
			continue
		}
		if ll == "" {
			// Reached the end of the sync section with no Status line (e.g.
			// "Not configured"): fail closed.
			break
		}
		if strings.HasPrefix(ll, "status:") {
			val := strings.TrimSpace(strings.TrimPrefix(ll, "status:"))
			return val == "up"
		}
	}
	// No sync-link Status line rendered: fail closed (do not assume sync is up).
	return false
}

// parseSessionSyncBulkPrimed reports whether the local daemon has completed
// receiving the inbound bulk session snapshot for the current sync epoch.
// The line is scoped to the sync/fabric section and fails closed when absent
// or malformed; a timeout-released startup readiness bit is intentionally not
// sufficient for rolling rejoin (#10261).
func parseSessionSyncBulkPrimed(s string) bool {
	inSync := false
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(strings.TrimSpace(line))
		if !inSync {
			if strings.HasPrefix(ll, "sync link statistics") ||
				strings.HasPrefix(ll, "fabric link statistics") {
				inSync = true
			}
			continue
		}
		if ll == "" {
			return false
		}
		if strings.HasPrefix(ll, "bulk sync primed:") {
			return strings.TrimSpace(strings.TrimPrefix(ll, "bulk sync primed:")) == "yes"
		}
	}
	return false
}

// parseHAProtocolCompatible compares the local and peer HA protocol
// version lines from `show chassis cluster status` (FormatStatus):
//
//	HA protocol version: N
//	Peer HA protocol version: M
//
// Compatible iff N == M (the rolling contract: mixed N/N+1 nodes only
// hand off RGs when CurrentHAProtocolVersion matches; a bump means the
// wire semantics changed and the release is NOT rolling-upgradable). If
// the peer line is ABSENT (peer not alive / version unknown) we return
// false so the driver does not proceed blind — PeerAlive already gates
// the happy path, and a missing peer-version here fails closed.
// parsePeerSessionSyncWire extracts the peer session-sync wire version from
// `show chassis cluster status` (FormatStatus):
//
//	Peer session-sync wire version: N        -> (N, true)
//	Peer session-sync wire version: unknown  -> (0, true)
//	line absent                              -> (0, false)
//
// "unknown" and a missing line are reported DIFFERENTLY even though both yield
// 0, because they are different facts about the instrument: "unknown" means this
// node rendered the line and the peer advertised nothing, while a missing line
// means this node never rendered it at all. The caller collapses them, but a
// future caller that must not may need to tell them apart, and a parser that
// erases the distinction cannot be asked later.
func parsePeerSessionSyncWire(s string) (uint16, bool) {
	const prefix = "peer session-sync wire version:"
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(l), prefix) {
			continue
		}
		val := strings.TrimSpace(l[len(prefix):])
		if strings.EqualFold(val, "unknown") {
			return 0, true
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			// A line we cannot parse is not a version. Report it as PRESENT
			// but 0 so the caller's permit-on-unknown path takes it, rather
			// than reporting absent and inviting a different branch.
			return 0, true
		}
		return uint16(n), true
	}
	return 0, false
}

func parseHAProtocolCompatible(s string) bool {
	var local, peer int
	haveLocal, havePeer := false, false
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		if strings.HasPrefix(ll, "peer ha protocol version:") {
			if n, ok := trailingInt(l); ok {
				peer, havePeer = n, true
			}
			continue
		}
		if strings.HasPrefix(ll, "ha protocol version:") {
			if n, ok := trailingInt(l); ok {
				local, haveLocal = n, true
			}
		}
	}
	if !haveLocal || !havePeer {
		return false
	}
	return local == peer
}

// trailingInt extracts the integer after the final ':' or space in a
// "key: N" line.
func trailingInt(line string) (int, bool) {
	idx := strings.LastIndex(line, ":")
	if idx < 0 || idx+1 >= len(line) {
		return 0, false
	}
	tok := strings.TrimSpace(line[idx+1:])
	n := 0
	if tok == "" {
		return 0, false
	}
	for _, r := range tok {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

func parsePeerTakeoverReady(s string) bool {
	// IMPORTANT (Codex): the information topic renders the LOCAL node's
	// view, so "Takeover ready" / "Transfer ready" / "Monitor failures"
	// reflect THIS node's readiness, not the peer's. We cannot directly see
	// the peer's takeover-readiness from the local control socket. This
	// precheck is therefore a BEST-EFFORT pre-demotion gate: it requires
	// the peer alive ("Remote node: healthy") and no LOCAL takeover blocker
	// (a local monitor/interface fault that would also affect the handoff).
	// The AUTHORITATIVE guard is DrainComplete, which AFTER demotion
	// confirms the peer ACTUALLY holds primary for every RG; if it does not
	// within the deadline the rolling driver fails back and ABORTS WITHOUT
	// cutting (rolling.go). So a peer that cannot take over cannot lead to a
	// cut — at worst the drain times out and the node is restored.
	//
	// The information topic (FormatInformation) emits "Takeover ready:
	// no (...)", "Transfer ready: no", and a "Monitor failures:" line when
	// an RG cannot take over (status.go). Conservative
	// — ANY of these blockers fails the precheck (Codex r4 High: the parser
	// must not be fail-open on the real not-ready tokens).
	if !lineHasAll(s, "Remote node:", "healthy") {
		return false
	}
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(strings.TrimSpace(line))
		// Check the STATE TOKEN (the first word after the colon), NOT a
		// substring of the whole line — a YES line whose reason text embeds
		// "no" (e.g. "Takeover ready: yes (no prior failures)") must not
		// trip the guard (Codex r5).
		if tok, ok := firstTokenAfterColon(ll, "takeover ready:"); ok && tok == "no" {
			return false
		}
		if tok, ok := firstTokenAfterColon(ll, "transfer ready:"); ok && tok == "no" {
			return false
		}
		if strings.HasPrefix(ll, "monitor failures:") {
			// A "Monitor failures:" line with any content after the colon
			// is a blocker; "none"/empty is fine.
			rest := strings.TrimSpace(ll[len("monitor failures:"):])
			if rest != "" && rest != "none" {
				return false
			}
		}
		if strings.Contains(ll, "monitor: fail") || strings.Contains(ll, "monitorfail") {
			return false
		}
	}
	return true
}

// firstTokenAfterColon returns the first whitespace-delimited token after
// the given "key:" prefix in line (lowercased), e.g. for
// "takeover ready: yes (no prior failures)" with prefix "takeover ready:"
// it returns ("yes", true).
func firstTokenAfterColon(line, prefix string) (string, bool) {
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := strings.TrimSpace(line[len(prefix):])
	f := strings.Fields(rest)
	if len(f) == 0 {
		return "", false
	}
	return f[0], true
}

// parseDrainComplete evaluates the `show chassis cluster status`
// (FormatStatus) text. It requires BOTH:
//   - every LOCAL node RG row is `secondary` (the local node demoted), AND
//   - every PEER node RG row is `primary` (the peer actually OWNS the RGs)
//
// Checking only the local side (Codex r2 Critical) is insufficient:
// ForceSecondary forcibly demotes the local node regardless of whether the
// peer became primary, so a healthy-but-stuck peer could leave BOTH nodes
// secondary with VIPs stranded. We confirm the peer has taken ownership.
//
// FormatStatus emits, per RG, a "Redundancy group: N , Failover count: M"
// header then a local row "nodeL  <prio>  <state> ..." and (if the peer is
// alive) a peer row "nodeP  <prio>  <state> ...". Drain is complete only
// when, for EVERY redundancy group, the local row is secondary AND the
// peer row is primary — a PER-RG pairing (Codex r3 High): a global
// "any peer primary" OR would wrongly pass an active-active cluster where
// the peer owns one RG but not the other the local node evacuated.
func parseDrainComplete(s string) bool {
	localID, ok := parseLocalNodeID(s)
	if !ok {
		return false // cannot identify the local node => fail closed
	}

	type rgPair struct {
		localState string
		peerState  string
		sawLocal   bool
		sawPeer    bool
	}
	groups := map[int]*rgPair{}
	curRG := -1
	sawAnyRG := false

	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		// RG header: "Redundancy group: N , Failover count: M".
		if strings.HasPrefix(ll, "redundancy group:") {
			// Reset curRG FIRST (Codex r4 Medium): a malformed header that
			// fails to parse a number must NOT leave curRG pointing at the
			// PREVIOUS RG, or the node rows after it would bleed into the
			// wrong group's state.
			curRG = -1
			rest := strings.TrimSpace(l[len("Redundancy group:"):])
			f := strings.Fields(rest)
			if len(f) > 0 {
				if n, nok := atoiSafe(f[0]); nok {
					curRG = n
					sawAnyRG = true
					if groups[curRG] == nil {
						groups[curRG] = &rgPair{}
					}
				}
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasPrefix(fields[0], "node") {
			continue
		}
		id, idOK := parseNodeToken(fields[0])
		if !idOK || curRG < 0 {
			continue
		}
		state := strings.ToLower(fields[2]) // "node prio state ..."
		g := groups[curRG]
		if g == nil {
			g = &rgPair{}
			groups[curRG] = g
		}
		if id == localID {
			g.localState, g.sawLocal = state, true
		} else {
			g.peerState, g.sawPeer = state, true
		}
	}

	if !sawAnyRG || len(groups) == 0 {
		return false // no RG rows => fail closed
	}
	for _, g := range groups {
		if !g.sawLocal || !g.sawPeer {
			return false // both rows required to confirm the handoff
		}
		if g.localState != "secondary" || g.peerState != "primary" {
			return false
		}
	}
	return true
}

// atoiSafe parses a base-10 non-negative integer, tolerating trailing
// non-digit cruft is NOT allowed (strict — the caller passes a clean
// field).
func atoiSafe(tok string) (int, bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return 0, false
	}
	n := 0
	for _, r := range tok {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// parseLocalNodeID reads the "Node name: nodeN" header line FormatStatus
// emits.
func parseLocalNodeID(s string) (int, bool) {
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "node name:") {
			fields := strings.Fields(l)
			return parseNodeToken(fields[len(fields)-1])
		}
	}
	return 0, false
}

// parseNodeToken parses "nodeN" -> N.
func parseNodeToken(tok string) (int, bool) {
	low := strings.ToLower(strings.TrimSpace(tok))
	if !strings.HasPrefix(low, "node") {
		return 0, false
	}
	num := low[len("node"):]
	if num == "" {
		return 0, false
	}
	n := 0
	for _, r := range num {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

func (g *grpcCluster) ResetFailover() error {
	// ForceSecondary demotes EVERY configured RG, so ResetFailover must
	// reset every configured RG — not a hardcoded set. Enumerate the live RG
	// IDs from the status output and FAIL CLOSED if enumeration fails (#5044):
	// the old {0,1,2} fallback silently left RG>=3 held ForceSecondary on a
	// transient status error, and RG IDs are not bounded to {0,1,2} (>15 is
	// possible). RejoinAndConfirm only checks PeerAlive/SyncEstablished — with
	// a guessed set it would return nil and advance to drain/recreate the peer
	// that still owns the un-reset groups, opening a no-primary window for
	// them. Returning the error stops the roll instead.
	rgs, err := g.configuredRGs()
	if err != nil {
		return err
	}
	var firstErr error
	for _, rg := range rgs {
		if err := g.systemAction(clusterfailover.ResetFailover(rg).Action()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// configuredRGs returns the redundancy-group IDs enumerated from the live
// status output. It FAILS CLOSED (#5044) rather than guessing a hardcoded set:
// see configuredRGsFromStatus.
func (g *grpcCluster) configuredRGs() ([]int, error) {
	s, err := g.statusText()
	return configuredRGsFromStatus(s, err)
}

// configuredRGsFromStatus derives the configured redundancy-group ID set from
// the rendered `show chassis cluster status` text (s) and the error from
// fetching it (statusErr). It FAILS CLOSED: a status-fetch error, or a parse
// that yields no RG IDs, returns an error rather than the pre-#5044 {0,1,2}
// guess. That guess stranded RG>=3 held ForceSecondary on a transient status
// failure — the caller (ResetFailover) reset only 0-2, returned nil, and the
// orchestrator advanced to touch the peer while the extra groups had no
// primary. Kept as a pure function so the fail-closed contract is unit-tested
// without a gRPC dial.
func configuredRGsFromStatus(s string, statusErr error) ([]int, error) {
	if statusErr != nil {
		return nil, fmt.Errorf("enumerate configured redundancy groups: %w", statusErr)
	}
	rgs := parseRGIDs(s)
	if len(rgs) == 0 {
		return nil, fmt.Errorf("enumerate configured redundancy groups: " +
			"no redundancy groups found in cluster status output")
	}
	return rgs, nil
}

// parseRGIDs extracts the redundancy-group IDs from "Redundancy group: N"
// header lines in FormatStatus output.
func parseRGIDs(s string) []int {
	seen := map[int]bool{}
	var out []int
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "redundancy group:") {
			rest := strings.TrimSpace(l[len("Redundancy group:"):])
			f := strings.Fields(rest)
			if len(f) > 0 {
				if n, ok := atoiSafe(f[0]); ok && !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
		}
	}
	return out
}

// LocalRejoinComplete reports whether the local node has left the
// ForceSecondary drain for EVERY configured redundancy group (#5138). The
// configured RG set is enumerated fail-closed from the STATUS topic (the same
// source ResetFailover resets over); per-RG eligibility is read from the
// INFORMATION topic, whose FormatInformation render carries a "Weight: W/255"
// line per RG. ForceSecondary sets weight 0 for every RG; ResetFailover
// restores it via re-election. So a configured RG that still shows weight 0 —
// or is absent from the local status entirely — is NOT yet rejoined. Both
// topics are dialed here and the decision is delegated to a pure function so
// the fail-closed contract is unit-tested without a gRPC dial.
func (g *grpcCluster) LocalRejoinComplete() (bool, error) {
	st, stErr := g.statusText()
	info, infoErr := g.information()
	return localRejoinCompleteFromStatus(st, stErr, info, infoErr)
}

// localRejoinCompleteFromStatus decides per-RG rejoin from the rendered STATUS
// text (s / statusErr — configured-RG enumeration) and INFORMATION text (info /
// infoErr — per-RG weight). It FAILS CLOSED: a status-enumeration error, an
// information-fetch error, a configured RG missing from the information render,
// or a configured RG whose local weight is still 0 (the ForceSecondary drain)
// all report not-rejoined. Kept pure so RejoinAndConfirm's per-RG gate is
// exercised over rendered fixtures rather than a live cluster.
func localRejoinCompleteFromStatus(s string, statusErr error, info string, infoErr error) (bool, error) {
	rgs, err := configuredRGsFromStatus(s, statusErr)
	if err != nil {
		return false, err
	}
	if infoErr != nil {
		return false, fmt.Errorf("read cluster information for per-RG rejoin: %w", infoErr)
	}
	weights := parseLocalRGWeights(info)
	for _, rg := range rgs {
		w, ok := weights[rg]
		if !ok {
			// Configured (per status) but not rendered in the local
			// information view — cannot confirm eligibility: fail closed.
			return false, nil
		}
		if w <= 0 {
			// Still held in the ForceSecondary drain (weight 0).
			return false, nil
		}
	}
	return true, nil
}

// parseLocalRGWeights extracts the LOCAL node's per-RG weight from the
// `show chassis cluster information` (FormatInformation) text. It returns a map
// rgID -> weight. FormatInformation renders, per group:
//
//	Redundancy group N:
//	  ...
//	  Weight: W/255 (threshold: 0)
//
// The header here is "Redundancy group N:" (a trailing ':' after the ID) —
// DISTINCT from the STATUS topic's "Redundancy group: N , Failover count: M"
// (a ':' immediately after "group"), so a status header can never be mistaken
// for an information header. A malformed/unparseable header resets the current
// group so a stray Weight line cannot bleed into the previous RG.
func parseLocalRGWeights(info string) map[int]int {
	out := map[int]int{}
	cur := -1
	for _, line := range strings.Split(info, "\n") {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		// Information-topic RG header: "redundancy group N:" — require the
		// space after "group" (the status header has "group:" with no space)
		// and a trailing ':'.
		if strings.HasPrefix(ll, "redundancy group ") && strings.HasSuffix(ll, ":") {
			cur = -1
			mid := strings.TrimSpace(l[len("redundancy group") : len(l)-1])
			if n, ok := atoiSafe(mid); ok {
				cur = n
			}
			continue
		}
		if cur >= 0 && strings.HasPrefix(ll, "weight:") {
			// "Weight: W/255 (threshold: 0)" -> W (the digits before '/').
			rest := strings.TrimSpace(l[len("weight:"):])
			numTok := rest
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				numTok = strings.TrimSpace(rest[:i])
			}
			if n, ok := atoiSafe(numTok); ok {
				out[cur] = n
			}
		}
	}
	return out
}

func (g *grpcCluster) LocalPrimary() (bool, error) {
	s, err := g.information()
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(ll, "local state:") && strings.Contains(ll, "primary") {
			return true, nil
		}
	}
	return false, nil
}

// lineHasAll reports whether any line of s contains all substrings
// (case-insensitive).
func lineHasAll(s string, subs ...string) bool {
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(line)
		all := true
		for _, sub := range subs {
			if !strings.Contains(ll, strings.ToLower(sub)) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
