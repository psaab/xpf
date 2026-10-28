package upgrade

// #17095 one-release text fallback. This file is the ONLY remaining
// ShowText scrape in pkg/upgrade: it runs solely when the local daemon
// does not implement GetClusterHAState (codes.Unimplemented — a
// pre-#17095 daemon in the skew window). Every parser below converts
// text into the SAME typed GetClusterHAStateResponse the RPC returns,
// so all verdicts have exactly one implementation (cluster_cli.go).
// Delete this file and its tests after the fallback window.

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// haStateFromTextFallback renders both text topics and converts them
// into the typed state. Conversion is fail-closed: absent peer lines
// leave the optional fields unset, exactly as a typed server that
// cannot carry them would.
func haStateFromTextFallback(cli haStateClient, ctxFn func() (context.Context, context.CancelFunc)) (*pb.GetClusterHAStateResponse, error) {
	show := func(topic string) (string, error) {
		ctx, cancel := ctxFn()
		defer cancel()
		resp, err := cli.ShowText(ctx, &pb.ShowTextRequest{Topic: topic})
		if err != nil {
			return "", fmt.Errorf("show %s: %w", topic, err)
		}
		return resp.GetOutput(), nil
	}
	info, err := show("chassis-cluster-information")
	if err != nil {
		return nil, err
	}
	st, err := show("chassis-cluster-status")
	if err != nil {
		return nil, err
	}
	return haStateFromText(info, st)
}

// haStateFromText converts the two text renders into typed state. It is
// the fallback equivalent of cluster.Manager.HAState + HAStateToProto.
// A malformed peer session-sync wire value fails the conversion
// (#18118 B2): the strict parser's error must not be dropped into
// present+nil, which the verdict permits as advertised-unknown
// (#14991 fail-open).
//
// Local-node identification fails closed too (#18118 F2). The status
// render's "Node name:" line is the ONLY source of the local node ID;
// when it is missing or unparseable the fallback must not default to
// node 0: with localID=0 a node1 render's rows invert (the real local
// node1 row reads as the peer and vice versa), drainCompleteFromState
// can report a not-drained cluster as drained, and the old text
// parseDrainComplete — which returned false when parseLocalNodeID
// failed — failed closed. So an unidentified local node leaves every
// RG's local/peer states UNKNOWN (never inverted) and marks every RG
// takeover-blocked, so no verdict built on this state can permit a
// drain while the partial facts (peer alive, sync, wire, HA versions)
// stay readable. Takeover blocking needs no local identity (it is
// scoped by the information render's RG headers), so a malformed RG
// header there resets cur=-1 and leaves that RG's blockers UNREAD —
// peerTakeoverBlockers therefore also reports whether every RG header
// parsed; an unreadable header marks every RG blocked for the same
// reason.
func haStateFromText(info, st string) (*pb.GetClusterHAStateResponse, error) {
	resp := &pb.GetClusterHAStateResponse{
		PeerAlive:       parsePeerAlive(info),
		SyncEstablished: parseSyncEstablished(info),
		BulkPrimed:      parseSessionSyncBulkPrimed(info),
	}
	// The status render carries the peer wire line exactly when the
	// peer is alive in its view; derive presence from the line itself
	// so a partial render (information says healthy, status lacks the
	// line) stays absent rather than fabricating presence.
	wire, wirePresent, werr := parsePeerSessionSyncWireStrict(st)
	if werr != nil {
		return nil, werr
	}
	if wirePresent {
		resp.SessionSyncWirePresent = true
		// "unknown" (predates #7990) leaves the value unset.
		if !isUnknownWireLine(st) {
			w := uint32(wire)
			resp.PeerSessionSyncWire = &w
		}
	}
	localID, localKnown := parseLocalNodeID(st)
	if localKnown {
		resp.LocalNodeId = int32(localID)
	}
	// HA versions carry presence independently, exactly as the typed
	// server does (HAStateToProto: local always, peer when known). A
	// peer line that parses while the local line is missing/garbled
	// therefore yields peer-present + local-absent; the verdicts refuse
	// that shape as an unreadable instrument (#18118 F1) instead of
	// dropping the peer fact or dereferencing the absent local.
	if local, present := parseLocalHAProtocol(st); present {
		l := uint32(local)
		resp.LocalHaProtocol = &l
	}
	if peer, present := parsePeerHAProtocol(st); present {
		pr := uint32(peer)
		resp.PeerHaProtocol = &pr
	}
	weights := parseLocalRGWeights(info)
	takeoverBlock, takeoverKnown := peerTakeoverBlockers(info)
	for _, id := range parseRGIDs(st) {
		localState := pb.RGNodeState_RG_NODE_STATE_UNKNOWN
		peerState := pb.RGNodeState_RG_NODE_STATE_UNKNOWN
		if localKnown {
			localState = rgLocalState(st, localID, id)
			peerState = rgPeerState(st, localID, id)
		}
		rg := &pb.ClusterRGState{
			Id:            int32(id),
			LocalState:    localState,
			PeerState:     peerState,
			TakeoverReady: localKnown && takeoverKnown && !takeoverBlock[id],
			TransferReady: localKnown && takeoverKnown && !takeoverBlock[id],
			FailoverCount: int32(rgFailoverCount(st, id)),
		}
		if w, ok := weights[id]; ok {
			rg.Weight = int32(w)
		}
		resp.RedundancyGroups = append(resp.RedundancyGroups, rg)
	}
	return resp, nil
}

func isUnknownWireLine(st string) bool {
	for _, line := range strings.Split(st, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(l, "peer session-sync wire version:") {
			return strings.EqualFold(strings.TrimSpace(l[len("peer session-sync wire version:"):]), "unknown")
		}
	}
	return false
}

// peerTakeoverBlockers marks RGs the information render blocks (mirrors
// parsePeerTakeoverReady's per-token checks, scoped per RG header).
// The second return reports whether every "Redundancy group N:" header
// parsed: a malformed header resets cur to -1, so that RG's blocker
// lines are silently dropped — the caller must treat an unreadable
// header as "blockers unknown" and fail closed (#18118 F2), never as
// "no blockers".
func peerTakeoverBlockers(info string) (map[int]bool, bool) {
	blocked := map[int]bool{}
	known := true
	cur := -1
	for _, line := range strings.Split(info, "\n") {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		if strings.HasPrefix(ll, "redundancy group ") && strings.HasSuffix(ll, ":") {
			cur = -1
			if n, ok := atoiSafe(strings.TrimSpace(l[len("redundancy group") : len(l)-1])); ok {
				cur = n
			} else {
				// Malformed header: this RG's blocker lines below are
				// unreadable, so no RG's readiness can be trusted.
				known = false
			}
			continue
		}
		if cur < 0 {
			continue
		}
		if tok, ok := firstTokenAfterColon(ll, "takeover ready:"); ok && tok == "no" {
			blocked[cur] = true
		}
		if tok, ok := firstTokenAfterColon(ll, "transfer ready:"); ok && tok == "no" {
			blocked[cur] = true
		}
		if strings.HasPrefix(ll, "monitor failures:") {
			if rest := strings.TrimSpace(ll[len("monitor failures:"):]); rest != "" && rest != "none" {
				blocked[cur] = true
			}
		}
	}
	return blocked, known
}

func rgStateFromStatus(st string, localID, rgID int, wantLocal bool) pb.RGNodeState {
	cur := -1
	for _, line := range strings.Split(st, "\n") {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		if strings.HasPrefix(ll, "redundancy group:") {
			cur = -1
			if f := strings.Fields(strings.TrimSpace(l[len("Redundancy group:"):])); len(f) > 0 {
				if n, ok := atoiSafe(f[0]); ok {
					cur = n
				}
			}
			continue
		}
		if cur != rgID {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		id, ok := parseNodeToken(f[0])
		if !ok || (id == localID) != wantLocal {
			continue
		}
		switch strings.ToLower(f[2]) {
		case "primary":
			return pb.RGNodeState_RG_NODE_STATE_PRIMARY
		case "secondary":
			return pb.RGNodeState_RG_NODE_STATE_SECONDARY
		case "secondary-hold":
			return pb.RGNodeState_RG_NODE_STATE_SECONDARY_HOLD
		case "lost":
			return pb.RGNodeState_RG_NODE_STATE_LOST
		case "disabled":
			return pb.RGNodeState_RG_NODE_STATE_DISABLED
		}
		return pb.RGNodeState_RG_NODE_STATE_UNKNOWN
	}
	return pb.RGNodeState_RG_NODE_STATE_UNKNOWN
}

func rgLocalState(st string, localID, rgID int) pb.RGNodeState {
	return rgStateFromStatus(st, localID, rgID, true)
}

func rgPeerState(st string, localID, rgID int) pb.RGNodeState {
	return rgStateFromStatus(st, localID, rgID, false)
}

func rgFailoverCount(st string, rgID int) int {
	for _, line := range strings.Split(st, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(l), "redundancy group:") {
			continue
		}
		f := strings.Fields(strings.TrimSpace(l[len("Redundancy group:"):]))
		if len(f) == 0 {
			continue
		}
		if n, ok := atoiSafe(f[0]); ok && n == rgID {
			// "... , Failover count: M"
			if i := strings.Index(strings.ToLower(l), "failover count:"); i >= 0 {
				if c, ok := atoiSafe(strings.Fields(l[i+len("failover count:"):])[0]); ok {
					return c
				}
			}
		}
	}
	return 0
}

// --- text parsers (fallback only; see file header) ---

func parsePeerAlive(s string) bool {
	return lineHasAll(s, "Remote node:", "healthy")
}

func parseSyncEstablished(s string) bool {
	if strings.Contains(strings.ToLower(s), "unsynced") {
		return false
	}
	if !lineHasAll(s, "Remote node:", "healthy") {
		return false
	}
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
			break
		}
		if strings.HasPrefix(ll, "status:") {
			return strings.TrimSpace(strings.TrimPrefix(ll, "status:")) == "up"
		}
	}
	return false
}

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

func parsePeerSessionSyncWireStrict(s string) (uint16, bool, error) {
	const prefix = "peer session-sync wire version:"
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(l), prefix) {
			continue
		}
		val := strings.TrimSpace(l[len(prefix):])
		if strings.EqualFold(val, "unknown") {
			return 0, true, nil
		}
		n, ok := strictVersionValue(val)
		if !ok {
			return 0, true, fmt.Errorf("peer session-sync wire version %q in `show chassis cluster status` is malformed — the compatibility check cannot run, and a garbled instrument is not evidence of compatibility", val)
		}
		return uint16(n), true, nil
	}
	return 0, false, nil
}

func parseLocalHAProtocol(s string) (int, bool) {
	return parseHAProtocolLine(s, "ha protocol version:")
}

func parsePeerHAProtocol(s string) (int, bool) {
	return parseHAProtocolLine(s, "peer ha protocol version:")
}

func parseHAProtocolLine(s, prefix string) (int, bool) {
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), prefix) {
			n, ok := strictVersionValue(l[len(prefix):])
			return n, ok
		}
	}
	return 0, false
}

func parseHAProtocolVersions(s string) (local, peer int, ok bool) {
	local, lok := parseLocalHAProtocol(s)
	peer, pok := parsePeerHAProtocol(s)
	if !lok || !pok {
		return 0, 0, false
	}
	return local, peer, true
}

func strictVersionValue(raw string) (int, bool) {
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return 0, false
	}
	for _, r := range tok {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(tok)
	if err != nil || n > 65535 {
		return 0, false
	}
	return n, true
}

func parsePeerTakeoverReady(s string) bool {
	if !lineHasAll(s, "Remote node:", "healthy") {
		return false
	}
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(strings.TrimSpace(line))
		if tok, ok := firstTokenAfterColon(ll, "takeover ready:"); ok && tok == "no" {
			return false
		}
		if tok, ok := firstTokenAfterColon(ll, "transfer ready:"); ok && tok == "no" {
			return false
		}
		if strings.HasPrefix(ll, "monitor failures:") {
			if rest := strings.TrimSpace(ll[len("monitor failures:"):]); rest != "" && rest != "none" {
				return false
			}
		}
		if strings.Contains(ll, "monitor: fail") || strings.Contains(ll, "monitorfail") {
			return false
		}
	}
	return true
}

func firstTokenAfterColon(line, prefix string) (string, bool) {
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	f := strings.Fields(strings.TrimSpace(line[len(prefix):]))
	if len(f) == 0 {
		return "", false
	}
	return f[0], true
}

// parseDrainComplete retains the original per-RG pairing over the
// STATUS text (local secondary + peer primary for every RG), so the
// fallback-era drain fixtures keep their exact fail-closed semantics.
func parseDrainComplete(s string) bool {
	localID, ok := parseLocalNodeID(s)
	if !ok {
		return false
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
		if strings.HasPrefix(ll, "redundancy group:") {
			curRG = -1
			rest := strings.TrimSpace(l[len("Redundancy group:"):])
			if f := strings.Fields(rest); len(f) > 0 {
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
		state := strings.ToLower(fields[2])
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
		return false
	}
	for _, g := range groups {
		if !g.sawLocal || !g.sawPeer {
			return false
		}
		if g.localState != "secondary" || g.peerState != "primary" {
			return false
		}
	}
	return true
}

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

func parseRGIDs(s string) []int {
	seen := map[int]bool{}
	var out []int
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "redundancy group:") {
			if f := strings.Fields(strings.TrimSpace(l[len("Redundancy group:"):])); len(f) > 0 {
				if n, ok := atoiSafe(f[0]); ok && !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
		}
	}
	return out
}

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
		if !ok || w <= 0 {
			return false, nil
		}
	}
	return true, nil
}

func parseLocalRGWeights(info string) map[int]int {
	out := map[int]int{}
	cur := -1
	for _, line := range strings.Split(info, "\n") {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		if strings.HasPrefix(ll, "redundancy group ") && strings.HasSuffix(ll, ":") {
			cur = -1
			if n, ok := atoiSafe(strings.TrimSpace(l[len("redundancy group") : len(l)-1])); ok {
				cur = n
			}
			continue
		}
		if cur >= 0 && strings.HasPrefix(ll, "weight:") {
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

// verdict helpers retained for the fallback-era tests that drive the
// text decision layer directly (#7990 / #14991 cells).
func haProtocolVerdictFromStatus(status string) (bool, uint16, uint16) {
	local, peer, ok := parseHAProtocolVersions(status)
	if !ok {
		return false, 0, 0
	}
	return local == peer, uint16(local), uint16(peer)
}

func peerProtocolVersionsFromStatus(status string) (uint16, uint16, uint16, bool, error) {
	st, err := haStateFromText("", status)
	if err != nil {
		return 0, 0, 0, false, err
	}
	return peerProtocolVersionsFromState(st)
}

func sessionSyncWireVerdictFromStatus(status string) (bool, string, error) {
	if _, _, err := parsePeerSessionSyncWireStrict(status); err != nil {
		return false, "", err
	}
	st, err := haStateFromText("", status)
	if err != nil {
		return false, "", err
	}
	return sessionSyncWireVerdictFromState(st)
}
