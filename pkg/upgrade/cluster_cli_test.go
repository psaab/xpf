package upgrade

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// TestParsers_AgainstRealFormatInformation feeds REAL
// cluster.Manager.FormatInformation() output through the drain-predicate
// parsers so a status-format change is caught here (Codex r1 Critical#7:
// the old parser keyed on "Remote node:" text that the WRONG command —
// FormatStatus — never emits; this asserts we parse the RIGHT command's
// output). A freshly-constructed Manager with a configured RG renders the
// "Remote node:" and per-RG "Local state:" lines the parsers depend on.
func TestParsers_AgainstRealFormatInformation(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ClusterID: 1,
		NodeID:    0,
		RedundancyGroups: []*config.RedundancyGroup{
			{
				ID:      0,
				Preempt: true,
				NodePriorities: map[int]int{
					0: 200,
					1: 100,
				},
			},
		},
	})

	info := m.FormatInformation()

	// The parsers depend on these exact field tokens — assert they exist in
	// real output so a format rename breaks this test, not production.
	if !strings.Contains(info, "Remote node:") {
		t.Fatalf("FormatInformation() lacks 'Remote node:' line the parsers key on:\n%s", info)
	}
	if !strings.Contains(info, "Local state:") {
		t.Fatalf("FormatInformation() lacks 'Local state:' line the parsers key on:\n%s", info)
	}

	// parseSyncEstablished scopes its Status match to the sync/fabric link
	// section. That scoping assumes FormatInformation never emits MORE than one
	// "Status:" line (here sync is unconfigured → "Not configured" → zero; with
	// sync configured it renders exactly one). Assert at-most-one so the day a
	// second "Status:" section (e.g. IP monitoring) is folded into
	// FormatInformation, THIS test fails loudly — forcing a re-check of the
	// drain gate (AGY review-011 Part I) rather than a silent mis-read.
	statusLines := 0
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "status:") {
			statusLines++
		}
	}
	if statusLines > 1 {
		t.Fatalf("FormatInformation() emits %d 'Status:' lines, want at most 1 (the sync "+
			"link); parseSyncEstablished's section scoping assumes a single Status — a "+
			"second breaks the drain gate:\n%s", statusLines, info)
	}

	// Real-format coverage of the drain gate: sync is unconfigured here, so
	// the sync link is not established and a drain must NOT be green-lit.
	if parseSyncEstablished(info) {
		t.Errorf("parseSyncEstablished true with sync unconfigured (no Status line):\n%s", info)
	}

	// No peer configured => remote lost => peer not alive.
	if parsePeerAlive(info) {
		t.Errorf("parsePeerAlive true with no peer (remote should be lost):\n%s", info)
	}

	// parseDrainComplete consumes the STATUS topic (node rows). A real
	// FormatStatus with no peer must NOT read as drained (no peer-primary).
	st := m.FormatStatus()
	if !strings.Contains(st, "Node name:") {
		t.Fatalf("FormatStatus lacks 'Node name:' header parseLocalNodeID keys on:\n%s", st)
	}
	if parseDrainComplete(st) {
		t.Errorf("parseDrainComplete true with no peer — would cut with no peer owning RGs:\n%s", st)
	}
}

// TestDrainParser_Fixtures exercises parseDrainComplete against
// FormatStatus-grammar fixtures (status.go node rows). Drain is complete
// ONLY when the LOCAL node row is secondary AND the PEER node row is
// primary (the peer actually took ownership).
func TestDrainParser_Fixtures(t *testing.T) {
	// FormatStatus row: "node<id>  <prio>  <state>  <preempt> <manual> <mon>".
	drained := strings.Join([]string{
		"Node name: node0",
		"",
		"Redundancy group: 0 , Failover count: 1",
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
		"",
	}, "\n")
	localStillPrimary := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   200      primary        yes      no       None",
		"node1   100      secondary      yes      no       None",
	}, "\n")
	bothSecondary := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   100      secondary      yes      no       None",
		"node1   100      secondary      yes      no       None",
	}, "\n")
	localSecondaryNoPeer := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   100      secondary      yes      no       None",
	}, "\n")
	// Multi-RG (Codex r3): RG0 fully handed off, RG1 peer still secondary —
	// NOT drained (per-RG pairing, not global any-peer-primary).
	multiRGPartial := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 1",
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
		"Redundancy group: 1 , Failover count: 0",
		"node0   100      secondary      yes      no       None",
		"node1   100      secondary      yes      no       None",
	}, "\n")
	multiRGDrained := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 1",
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
		"Redundancy group: 1 , Failover count: 1",
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
	}, "\n")

	if !parseDrainComplete(drained) {
		t.Error("local secondary + peer primary should be drain-complete")
	}
	if parseDrainComplete(localStillPrimary) {
		t.Error("local primary must NOT be drain-complete")
	}
	if parseDrainComplete(bothSecondary) {
		t.Error("both-secondary must NOT be drain-complete (peer has not taken ownership — VIP stranding)")
	}
	if parseDrainComplete(localSecondaryNoPeer) {
		t.Error("local secondary with no peer-primary row must NOT be drain-complete")
	}
	if parseDrainComplete(multiRGPartial) {
		t.Error("multi-RG with one RG peer-secondary must NOT be drain-complete (per-RG pairing)")
	}
	if !parseDrainComplete(multiRGDrained) {
		t.Error("multi-RG all-handed-off should be drain-complete")
	}
	if parseDrainComplete("garbage\nno node rows") {
		t.Error("garbled output read as drained")
	}
}

// TestPeerTakeoverReady_Fixtures covers the real not-ready tokens
// FormatInformation emits (Codex r4 High).
func TestPeerTakeoverReady_Fixtures(t *testing.T) {
	ready := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"  Takeover ready: yes (since 12:00:00)",
		"  Transfer ready: yes",
		"  Monitor failures: none",
	}, "\n")
	takeoverNo := strings.ReplaceAll(ready, "Takeover ready: yes (since 12:00:00)", "Takeover ready: no (interface ge-0-0-1 down)")
	transferNo := strings.ReplaceAll(ready, "Transfer ready: yes", "Transfer ready: no")
	monFail := strings.ReplaceAll(ready, "Monitor failures: none", "Monitor failures: ge-0-0-1")

	// A YES line whose reason text embeds the substring "no" must NOT trip
	// the "no" guard (Codex r5: hardens against future/localized reason
	// strings). The state token is "yes"; "no" only appears in the reason.
	readyReasonWithNo := strings.ReplaceAll(ready,
		"Takeover ready: yes (since 12:00:00)",
		"Takeover ready: yes (no prior failures)")

	if !parsePeerTakeoverReady(ready) {
		t.Error("all-green should be takeover-ready")
	}
	if !parsePeerTakeoverReady(readyReasonWithNo) {
		t.Error("a YES line whose reason embeds 'no' must NOT be treated as not-ready")
	}
	if parsePeerTakeoverReady(takeoverNo) {
		t.Error("'Takeover ready: no' must block (VIP stranding risk)")
	}
	if parsePeerTakeoverReady(transferNo) {
		t.Error("'Transfer ready: no' must block")
	}
	if parsePeerTakeoverReady(monFail) {
		t.Error("'Monitor failures: <iface>' must block")
	}
}

// TestDrainComplete_MalformedHeaderNoBleed proves a malformed RG header
// does not let following node rows bleed into the previous RG (Codex r4
// Medium): the rows after the bad header are dropped (curRG reset to -1),
// so the previous RG keeps only its own (incomplete) rows and the result
// is NOT drained.
func TestDrainComplete_MalformedHeaderNoBleed(t *testing.T) {
	// RG0 local-primary (not drained); then a MALFORMED header; then rows
	// that, if they bled into RG0, would look secondary/primary. The
	// malformed header must prevent the bleed so RG0 stays primary => not
	// drained.
	s := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   200      primary        yes      no       None",
		"node1   100      secondary      yes      no       None",
		"Redundancy group: XYZ , Failover count: 0", // malformed number
		"node0   100      secondary      yes      no       None",
		"node1   200      primary        yes      no       None",
	}, "\n")
	if parseDrainComplete(s) {
		t.Error("malformed header let node rows bleed into the previous RG — must NOT read drained")
	}
}

// TestSyncParser_Fixtures covers the Status: Up/Down sync gate.
func TestSyncParser_Fixtures(t *testing.T) {
	up := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"Sync link statistics (control-link):",
		"  Status: Up",
	}, "\n")
	down := strings.ReplaceAll(up, "Status: Up", "Status: Down")
	noStatus := "  Remote node: healthy (node1)\n"

	if !parseSyncEstablished(up) {
		t.Error("Status: Up should read as sync established")
	}
	if parseSyncEstablished(down) {
		t.Error("Status: Down must NOT read as sync established (would drop sessions on cut)")
	}
	if parseSyncEstablished(noStatus) {
		t.Error("missing Status line must fail closed")
	}
}

// TestSyncParser_ScopedAndExact covers the AGY review-011 Part I hardening:
// the Status match is scoped to the sync/fabric link section (so a pre-sync
// section that also emits "Status:" cannot be mis-read), and the value is
// matched EXACTLY as "up" (so "startup" is not accepted). Both are latent on
// today's FormatInformation (single sync "Status:" line) but guard against
// format drift that would otherwise wrongly green-light a drain.
func TestSyncParser_ScopedAndExact(t *testing.T) {
	// A pre-sync section emitting "Status: up" must NOT be read as the sync
	// link when the actual sync link is Down. The old first-"status:"-wins
	// parser would have returned true here and drained with sync down.
	preSyncUp := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"IP monitoring:",
		"  Status: up",
		"",
		"Sync link statistics (control-link):",
		"  Status: Down",
	}, "\n")
	if parseSyncEstablished(preSyncUp) {
		t.Error("a pre-sync 'Status: up' must not be read as the sync link when sync is Down")
	}

	// Exact-match: "startup" must not satisfy the up gate.
	startup := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"Sync link statistics (control-link):",
		"  Status: startup",
	}, "\n")
	if parseSyncEstablished(startup) {
		t.Error("'Status: startup' must not be read as up (exact match required)")
	}

	// Scoping still finds the sync Status when a benign pre-sync Status
	// precedes it and the sync link is genuinely Up.
	preSyncThenUp := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"IP monitoring:",
		"  Status: unreachable",
		"",
		"Sync link statistics (control-link):",
		"  Status: Up",
	}, "\n")
	if !parseSyncEstablished(preSyncThenUp) {
		t.Error("sync 'Status: Up' must be read as established despite a pre-sync Status line")
	}

	// The fabric-link header variant is honored too.
	fabricUp := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"Fabric link statistics:",
		"  Status: Up",
	}, "\n")
	if !parseSyncEstablished(fabricUp) {
		t.Error("'Fabric link statistics:' + 'Status: Up' must read as established")
	}

	// An UNCONFIGURED sync section ("Not configured", no Status) ends at its
	// blank line; a later out-of-section "Status: Up" must NOT be adopted as
	// the sync status (Codex r1). Sync is not established here → fail closed.
	notConfiguredThenLaterUp := strings.Join([]string{
		"  Remote node: healthy (node1)",
		"Fabric link statistics:",
		"  Not configured",
		"",
		"Some later section:",
		"  Status: Up",
	}, "\n")
	if parseSyncEstablished(notConfiguredThenLaterUp) {
		t.Error("unconfigured sync section must fail closed even if a later section says Status: Up")
	}
}

// TestParseRGIDs proves the configured-RG enumeration covers ALL
// configured RGs (Codex: shipped configs include RG 2; the per-RG rejoin
// readback must cover all of them, not a hardcoded {0,1}).
func TestParseRGIDs(t *testing.T) {
	s := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"node0   200      primary   yes no None",
		"Redundancy group: 1 , Failover count: 0",
		"node0   100      secondary yes no None",
		"Redundancy group: 2 , Failover count: 0",
		"node0   200      primary   yes no None",
	}, "\n")
	got := parseRGIDs(s)
	if len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
		t.Fatalf("parseRGIDs = %v, want [0 1 2]", got)
	}
}

// TestConfiguredRGsFromStatus_FailsClosed proves the #5044 fix: RG enumeration
// FAILS CLOSED on a transient status error or an unparseable status, instead of
// the old {0,1,2} guess. The guess stranded RG>=3 held ForceSecondary (a
// cluster can run >3 redundancy groups), letting a reset return nil and
// the orchestrator advance to drain/recreate the peer that still owned those
// groups — a no-primary window. RED if a fix-forward reintroduces any hardcoded
// fallback RG set. (Since #15239 the enumeration feeds the per-RG rejoin
// readback, LocalRejoinComplete; the reset itself is the single
// cluster-rejoin action.)
func TestConfiguredRGsFromStatus_FailsClosed(t *testing.T) {
	// A transient `show chassis cluster status` failure must NOT resolve to a
	// guessed set — it must return an error so the rejoin readback fails closed.
	if rgs, err := configuredRGsFromStatus("", errors.New("gRPC unavailable")); err == nil {
		t.Fatalf("transient status error: got rgs=%v err=nil, want an error "+
			"(no {0,1,2} fallback)", rgs)
	}
	// A status that parses to no RG headers (empty/garbled render) must also
	// fail closed rather than guess.
	if rgs, err := configuredRGsFromStatus("Node name: node0\n(no groups)\n", nil); err == nil {
		t.Fatalf("no-RG status: got rgs=%v err=nil, want an error "+
			"(no {0,1,2} fallback)", rgs)
	}

	// The happy path still enumerates every configured RG, including RG>=3,
	// which the old hardcoded {0,1,2} would have dropped.
	s := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"Redundancy group: 1 , Failover count: 0",
		"Redundancy group: 2 , Failover count: 0",
		"Redundancy group: 5 , Failover count: 0",
	}, "\n")
	rgs, err := configuredRGsFromStatus(s, nil)
	if err != nil {
		t.Fatalf("valid status: unexpected error: %v", err)
	}
	if len(rgs) != 4 || rgs[3] != 5 {
		t.Fatalf("valid status: rgs = %v, want [0 1 2 5] (RG>=3 must be kept)", rgs)
	}
}

// TestParseLocalRGWeights_AgainstRealFormatInformation feeds REAL
// cluster.Manager.FormatInformation() output through parseLocalRGWeights so a
// rename of the per-RG "Redundancy group N:" header or the "Weight: W/255" line
// breaks HERE (a unit test), not in production where it would silently make the
// #5138 per-RG rejoin gate read every RG as "not rendered" → fail-closed forever
// (a rejoin that can never confirm). It also proves the parser keys ID -> weight
// for more than one group, including RG>=3.
func TestParseLocalRGWeights_AgainstRealFormatInformation(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ClusterID: 1,
		NodeID:    0,
		RedundancyGroups: []*config.RedundancyGroup{
			{ID: 0, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100}},
			{ID: 3, Preempt: true, NodePriorities: map[int]int{0: 200, 1: 100}},
		},
	})

	info := m.FormatInformation()
	if !strings.Contains(info, "Weight:") {
		t.Fatalf("FormatInformation() lacks the 'Weight:' line parseLocalRGWeights keys on:\n%s", info)
	}

	weights := parseLocalRGWeights(info)
	if len(weights) != 2 {
		t.Fatalf("parseLocalRGWeights = %v, want 2 groups (0 and 3) from:\n%s", weights, info)
	}
	for _, rg := range []int{0, 3} {
		w, ok := weights[rg]
		if !ok {
			t.Fatalf("parseLocalRGWeights missing RG %d: %v\n%s", rg, weights, info)
		}
		// A freshly configured (undrained) RG must render a NON-ZERO weight, or
		// the rejoin gate would never confirm a healthy node.
		if w <= 0 {
			t.Errorf("parseLocalRGWeights[%d] = %d, want > 0 for an undrained RG", rg, w)
		}
	}
}

// TestLocalRejoinCompleteFromStatus proves the #5138 fix: rejoin is confirmed
// ONLY when EVERY configured RG (enumerated fail-closed from the status topic)
// has left the ForceSecondary drain (non-zero weight in the information topic).
// A configured RG still at weight 0 — or absent from the local information view
// — must read as NOT rejoined so RejoinAndConfirm cannot advance the orchestrator
// to drain the peer while that RG has no primary on either node. RED if the
// per-RG gate is dropped and rejoin confirms on peer-alive/sync alone.
func TestLocalRejoinCompleteFromStatus(t *testing.T) {
	// Status enumerates configured RGs 0, 1, 3 (RG>=3 must be honored).
	status := strings.Join([]string{
		"Node name: node0",
		"Redundancy group: 0 , Failover count: 0",
		"Redundancy group: 1 , Failover count: 0",
		"Redundancy group: 3 , Failover count: 0",
	}, "\n")

	// FormatInformation grammar: "Redundancy group N:" header + "Weight: W/255".
	infoAllEligible := strings.Join([]string{
		"Redundancy group 0:",
		"  Local state: Secondary",
		"  Weight: 255/255 (threshold: 0)",
		"Redundancy group 1:",
		"  Local state: Secondary",
		"  Weight: 128/255 (threshold: 0)",
		"Redundancy group 3:",
		"  Local state: Secondary",
		"  Weight: 255/255 (threshold: 0)",
	}, "\n")
	// RG3 still held in the ForceSecondary drain (weight 0) — the exact #5138
	// scenario the pre-#5044 {0,1,2} guess would have stranded.
	infoRG3Held := strings.ReplaceAll(infoAllEligible,
		"Redundancy group 3:\n  Local state: Secondary\n  Weight: 255/255 (threshold: 0)",
		"Redundancy group 3:\n  Local state: Secondary\n  Weight: 0/255 (threshold: 0)")
	// RG3 not rendered in the local information view at all.
	infoRG3Missing := strings.Join([]string{
		"Redundancy group 0:",
		"  Weight: 255/255 (threshold: 0)",
		"Redundancy group 1:",
		"  Weight: 255/255 (threshold: 0)",
	}, "\n")

	if ok, err := localRejoinCompleteFromStatus(status, nil, infoAllEligible, nil); err != nil || !ok {
		t.Fatalf("all RGs weight>0: got ok=%v err=%v, want ok=true err=nil", ok, err)
	}
	if ok, err := localRejoinCompleteFromStatus(status, nil, infoRG3Held, nil); err != nil || ok {
		t.Fatalf("RG3 held at weight 0: got ok=%v err=%v, want ok=false err=nil "+
			"(rejoin must NOT confirm while a configured RG is still drained)", ok, err)
	}
	if ok, err := localRejoinCompleteFromStatus(status, nil, infoRG3Missing, nil); err != nil || ok {
		t.Fatalf("RG3 missing from information: got ok=%v err=%v, want ok=false err=nil "+
			"(cannot confirm eligibility for an unrendered RG — fail closed)", ok, err)
	}
	// A status-enumeration failure fails closed with an error (propagated so the
	// deadline miss surfaces WHY), never a guessed RG set.
	if ok, err := localRejoinCompleteFromStatus("", errors.New("gRPC unavailable"), infoAllEligible, nil); err == nil || ok {
		t.Fatalf("status error: got ok=%v err=%v, want ok=false err!=nil", ok, err)
	}
	// An information-fetch failure likewise fails closed.
	if ok, err := localRejoinCompleteFromStatus(status, nil, "", errors.New("gRPC unavailable")); err == nil || ok {
		t.Fatalf("information error: got ok=%v err=%v, want ok=false err!=nil", ok, err)
	}
}

func TestParseHAProtocolCompatible(t *testing.T) {
	match := "HA protocol version: 1\nPeer HA protocol version: 1\n"
	mismatch := "HA protocol version: 1\nPeer HA protocol version: 2\n"
	noPeer := "HA protocol version: 1\n"

	if !parseHAProtocolCompatible(match) {
		t.Error("equal protocol versions should be compatible")
	}
	if parseHAProtocolCompatible(mismatch) {
		t.Error("mismatched protocol versions must be incompatible (not rolling-upgradable)")
	}
	if parseHAProtocolCompatible(noPeer) {
		t.Error("missing peer protocol line must fail closed")
	}
}

// TestStatusEmitsProtocolLines guards that FormatStatus still emits the HA
// protocol version lines parseHAProtocolCompatible keys on.
func TestStatusEmitsProtocolLines(t *testing.T) {
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		ClusterID:        1,
		NodeID:           0,
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0, NodePriorities: map[int]int{0: 200, 1: 100}}},
	})
	st := m.FormatStatus()
	if !strings.Contains(st, "HA protocol version:") {
		t.Fatalf("FormatStatus lacks 'HA protocol version:' the parser keys on:\n%s", st)
	}
}

// TestNewCLICluster_RejectsNonDefaultUnit is the #1983 regression: the
// rolling/kernel-drain cluster control RPCs target a hard-coded
// 127.0.0.1:50051, but the systemd action side honors --unit. A non-default
// --unit therefore would cut one daemon while driving cluster failover
// against ANOTHER (wrong-daemon control). NewCLICluster is the single
// construction chokepoint for all three callers (RunRolling + `upgrade
// kernel drain`/`rejoin`), so the guard lives here. The seam used by the
// rolling tests (runRollingWith) injects a fake cluster and bypasses
// construction, so this MUST be exercised at the constructor directly
// (Codex plan fold).
func TestNewCLICluster_RejectsNonDefaultUnit(t *testing.T) {
	// A non-default unit must be REJECTED — no cluster, an error, and the
	// error must NOT silently hand back a client pointed at the default
	// endpoint. This is the core invariant the bug violated.
	for _, unit := range []string{
		"xpfd-test",    // an alternate unit an integration test would pass
		"xpfd.service", // --unit takes the BARE name; ".service" is non-default
		"xpfd-staging",
	} {
		cl, err := NewCLICluster(unit)
		if err == nil {
			t.Fatalf("NewCLICluster(%q): want error, got nil (would silently "+
				"control the default daemon while systemd hits %q)", unit, unit)
		}
		if cl != nil {
			t.Fatalf("NewCLICluster(%q): want nil cluster on reject, got %#v "+
				"(a non-nil client could dial 127.0.0.1:50051)", unit, cl)
		}
		// The error must name the offending unit so the operator knows what
		// was rejected and why.
		if !strings.Contains(err.Error(), unit) {
			t.Errorf("NewCLICluster(%q) error must name the unit; got: %v", unit, err)
		}
		if !strings.Contains(err.Error(), "127.0.0.1:50051") {
			t.Errorf("NewCLICluster(%q) error must explain the hard-coded "+
				"control endpoint; got: %v", unit, err)
		}
	}
}

// TestNewCLICluster_AcceptsDefaultUnit confirms the default unit (and the
// empty-string shorthand the cmd layer normalizes to DefaultUnit) still
// constructs a working client pointed at the local control endpoint —
// default-unit rolling behavior is unchanged (#1983 invariant 8).
func TestNewCLICluster_AcceptsDefaultUnit(t *testing.T) {
	for _, unit := range []string{"", DefaultUnit} {
		cl, err := NewCLICluster(unit)
		if err != nil {
			t.Fatalf("NewCLICluster(%q): want a client, got error: %v", unit, err)
		}
		if cl == nil {
			t.Fatalf("NewCLICluster(%q): want a non-nil client, got nil", unit)
		}
		// The accepted client targets the local control endpoint. Inspect the
		// concrete type's addr WITHOUT dialing (no daemon runs under test).
		g, ok := cl.(*grpcCluster)
		if !ok {
			t.Fatalf("NewCLICluster(%q): want *grpcCluster, got %T", unit, cl)
		}
		if g.addr != "127.0.0.1:50051" {
			t.Errorf("NewCLICluster(%q): addr = %q, want 127.0.0.1:50051", unit, g.addr)
		}
	}
}
