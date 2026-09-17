package cluster

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"
)

// #7939: the degraded-promotion fallback must exist on the runElection path too,
// not only on electSingleNode.
//
// WHAT WENT WRONG, observed live rather than derived. #7161 added the fallback so
// "a readiness bug can never cost the cluster both nodes", and put it in
// electSingleNode. runElection — the path taken whenever `peerAlive` is true,
// which is where a cluster spends its life — kept a bare gate. After a routine
// cluster-deploy, RG1 sat SECONDARY ON BOTH NODES indefinitely with
// `userspace XSK liveness not proven`, logging twice a second for minutes, and
// could not self-heal: proving XSK liveness needs traffic, traffic needs a
// primary, and the gate was holding shut the only thing that could open it.
//
// Note what the split did to the fallback's own contract. #7161 required a
// fallback NOT gated on any peer condition, so that it would fire when the peer
// situation is what is wrong. Living only in electSingleNode gated it on a peer
// condition anyway — at the placement level rather than inside the timer. That is
// the #110 shape one layer up, and it is why this test drives the PEER-ALIVE
// path specifically: a fixture with no peer exercises electSingleNode, which
// already worked, and would pass against the shipped bug.

// notReadyWithPeerAlive builds a manager on the runElection path — peer seen and
// alive, local weight higher so the election wants us primary — with the RG NOT
// ready. That is the shape that hung.
func notReadyWithPeerAlive(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, true, map[int]int{0: 200}))
	cfg.ControlInterface = "em0" // cluster mode: the readiness gate applies
	m.UpdateConfig(cfg)
	// The readiness fallback tests exercise election readiness after the
	// dataplane is already serviceable; clear the new HA boot debt first.
	m.SetMonitorWeight(0, DataplaneArmMonitorIface, false, DataplaneArmMonitorCost)

	// Peer heartbeat at LOWER priority: peerAlive/peerEverSeen become true (so
	// electSingleNode is not the path) while the election still wants us
	// primary (so the gate is actually consulted).
	m.handlePeerHeartbeat(&HeartbeatPacket{
		NodeID:    1,
		ClusterID: 1,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 100, Weight: 100, State: uint8(StateSecondary)},
		},
	})

	m.mu.Lock()
	rg := m.groups[0]
	rg.State = StateSecondary
	rg.Ready = false
	rg.ReadySince = time.Time{}
	rg.ReadinessReasons = []string{"userspace XSK liveness not proven"}
	m.mu.Unlock()
	return m
}

func TestRunElectionHoldsSecondaryBeforeTheDegradedTimeout7939(t *testing.T) {
	m := notReadyWithPeerAlive(t)
	m.runElection()
	if m.IsLocalPrimary(0) {
		t.Fatal("a not-ready RG must stay secondary BEFORE the degraded timeout expires — " +
			"without this the fallback is indistinguishable from having no gate at all")
	}
}

func TestRunElectionPromotesAfterTheDegradedTimeout7939(t *testing.T) {
	m := notReadyWithPeerAlive(t)

	// First pass arms the fallback and holds secondary.
	m.runElection()
	if m.IsLocalPrimary(0) {
		t.Fatal("precondition: must hold secondary on the first pass")
	}

	// Age the arm point past the timeout. This is what the live cluster could
	// never reach, because nothing on this path armed or consulted it.
	m.mu.Lock()
	m.groups[0].NotReadySince = time.Now().Add(-2 * m.degradedPromoteTimeout)
	m.mu.Unlock()

	m.runElection()

	if !m.IsLocalPrimary(0) {
		t.Fatal("after the degraded timeout the RG must promote ANYWAY on the peer-alive " +
			"path. Holding secondary here is what left RG1 secondary on BOTH nodes with no " +
			"way out, since proving readiness required the traffic that only a primary " +
			"could carry (#7939)")
	}
	m.mu.RLock()
	degraded := m.groups[0].DegradedPromoted
	m.mu.RUnlock()
	if !degraded {
		t.Error("a promotion that only happened because the timeout expired must be MARKED " +
			"DegradedPromoted — it is forwarding while not ready, and must not read as a " +
			"normal promotion in the event stream or in show chassis cluster status")
	}
}

// Control. Without it, an implementation that ignored readiness entirely — or
// one that promoted on every pass — passes the timeout cell above for the wrong
// reason.
func TestRunElectionStillPromotesImmediatelyWhenReady7939(t *testing.T) {
	m := notReadyWithPeerAlive(t)
	m.mu.Lock()
	m.groups[0].Ready = true
	m.groups[0].ReadySince = time.Now().Add(-time.Hour) // satisfies the hold time
	m.groups[0].ReadinessReasons = nil
	m.mu.Unlock()

	m.runElection()
	if !m.IsLocalPrimary(0) {
		t.Fatal("a READY RG must promote immediately, with no degraded timeout involved")
	}
	m.mu.RLock()
	degraded := m.groups[0].DegradedPromoted
	m.mu.RUnlock()
	if degraded {
		t.Error("a normal ready promotion must NOT be marked degraded — if it is, the flag " +
			"stops meaning anything and the loud warning becomes noise")
	}
}

// The shared verdict's own behaviour. NOTE what this cell does NOT establish:
// reverting runElection to a bare gate leaves it GREEN, because the helper still
// exists and still works — only its CALLER changed. Measured, not assumed. The
// behavioural binding is TestRunElectionPromotesAfterTheDegradedTimeout7939,
// which reds on exactly that mutation, and the wiring binding is the source
// check below. This cell covers the third thing: that the verdict itself returns
// the right answers, which neither of the others isolates.
func TestBothElectionPathsShareOneReadinessVerdict7939(t *testing.T) {
	m := notReadyWithPeerAlive(t)

	// Not ready, timer not expired -> hold, from the shared verdict.
	m.mu.RLock()
	promote, reason := m.readinessGateVerdictLocked(m.groups[0])
	m.mu.RUnlock()
	if promote || reason != "" {
		t.Fatalf("shared verdict on a freshly not-ready RG: promote=%v reason=%q, want false/\"\"",
			promote, reason)
	}

	// Expired -> promote WITH a reason.
	m.mu.Lock()
	m.groups[0].NotReadySince = time.Now().Add(-2 * m.degradedPromoteTimeout)
	m.mu.Unlock()
	m.mu.RLock()
	promote, reason = m.readinessGateVerdictLocked(m.groups[0])
	m.mu.RUnlock()
	if !promote || reason == "" {
		t.Fatalf("shared verdict after the timeout: promote=%v reason=%q, want true and a "+
			"non-empty operator-facing reason", promote, reason)
	}
}

// Binds the WIRING, which is the claim the fix actually rests on: the two paths
// must CONSULT one rule rather than each carrying a copy. A behavioural test
// cannot distinguish "runElection calls the shared verdict" from "runElection
// reimplements it correctly today" — and it is the second state that decays into
// #7939 the next time a term is added to one copy and not the other.
//
// go/parser rather than grep: the comments in this file and on the function
// itself both name readinessGateVerdictLocked, so a textual scan is satisfied by
// the prose explaining the fix.
func TestBothElectionPathsCallTheSharedVerdict7939(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "election.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing election.go: %v", err)
	}

	callsVerdict := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Name.Name != "runElection" && fn.Name.Name != "electSingleNode" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "readinessGateVerdictLocked" {
				callsVerdict[fn.Name.Name] = true
			}
			return true
		})
		if _, seen := callsVerdict[fn.Name.Name]; !seen {
			callsVerdict[fn.Name.Name] = false
		}
	}

	for _, name := range []string{"runElection", "electSingleNode"} {
		called, found := callsVerdict[name]
		if !found {
			t.Fatalf("%s not found in election.go — if it was renamed, move this test with "+
				"it; a missing function must not read as a passing wiring check", name)
		}
		if !called {
			t.Errorf("%s does not call readinessGateVerdictLocked, so the two election paths "+
				"carry separate copies of the readiness rule again. That divergence IS #7939: "+
				"the fallback lived in one path and an RG sat secondary on BOTH nodes with no "+
				"way to self-heal", name)
		}
	}
}
