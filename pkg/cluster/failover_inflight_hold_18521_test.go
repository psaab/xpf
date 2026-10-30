package cluster

import (
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #18521 (secondary defect): the owner's manual-failover hold for a
// PEER-REQUESTED transfer was released by electRG's 2s dual-resign timer
// ("clearing manual failover (peer also yielded)") while the transfer was
// still in flight. The timer runs from the owner's demotion, but the
// requester is entitled to more than 2s before it commits: its own
// pre-request hold is released only after the owner's applied-ACK (which
// waits for the owner's demotion actuation), and it then spends up to
// localFailoverCommitTimeout (3s) in its local commit-ready settle. While the
// requester still advertises secondary-hold (or weight 0), an owner whose
// actuation or whose requester's commit window exceeded 2s cleared its own
// hold and could be re-promoted by ordinary election — so the commit then
// failed against an owner that was primary again.
//
// The invariant: while the reqID-bound remote transfer-out lease is LIVE, the
// hold belongs to the transfer protocol and is released only by the matching
// commit, the matching abort, the lease expiry, peer loss, or an operator
// reset — never by the 2s timer.

func inflightOwner18521(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(1, 1)
	// The owner OUTRANKS the requester, so a hold cleared mid-transfer is
	// observable: ordinary election hands RG 2 straight back to the owner.
	m.UpdateConfig(makeConfig(makeRG(2, false, map[int]int{0: 100, 1: 200})))
	// Session sync up: the channel the requester's commit/abort will use.
	m.SetFakePeerSyncSourceForTesting(true, 0, true, true)
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
		{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
	}})
	m.mu.Lock()
	m.groups[2].Ready = true
	m.groups[2].ReadySince = time.Now().Add(-time.Hour)
	m.groups[2].ReadinessReasons = nil
	m.mu.Unlock()
	m.runElection()
	if !m.IsLocalPrimary(2) {
		t.Fatal("fixture: owner must start primary")
	}
	// The peer's request, exactly as the daemon's OnRemoteFailover wiring does it.
	if _, err := m.ManualFailover(2); err != nil {
		t.Fatal(err)
	}
	m.ArmRemoteTransferOutLease([]int{2}, 18521)
	return m
}

func ageOwnerHold18521(m *Manager, by time.Duration) {
	m.mu.Lock()
	m.groups[2].ManualFailoverAt = m.groups[2].ManualFailoverAt.Add(-by)
	m.mu.Unlock()
}

func ownerHold18521(m *Manager) (held bool, state NodeState) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.groups[2].ManualFailover, m.groups[2].State
}

// RED before the fix: both rows log "clearing manual failover (peer also
// yielded)" and the owner re-promotes itself while the requester is mid-commit.
func TestInFlightRemoteTransferHoldOutlivesDualResignTimer18521(t *testing.T) {
	rows := []struct {
		name   string
		state  NodeState
		weight uint8
	}{
		// The requester's pre-request hold, still advertised until the
		// applied-ACK reaches it.
		{"requester still in its pre-request secondary-hold", StateSecondaryHold, 255},
		// A requester whose weight is momentarily 0 inside the window.
		{"requester advertising weight 0", StateSecondary, 0},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			m := inflightOwner18521(t)
			ageOwnerHold18521(m, 3*time.Second) // past the 2s timer, inside the lease
			m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
				{GroupID: 2, Priority: 100, Weight: row.weight, State: uint8(row.state)},
			}})
			held, state := ownerHold18521(m)
			if !held || state == StatePrimary {
				t.Fatalf("an in-flight peer-requested transfer lost the owner's hold to the 2s "+
					"dual-resign timer (held=%v state=%s): the requester has not committed or "+
					"aborted, and the lease that bounds its commit window is still live (#18521)",
					held, state)
			}
		})
	}
}

// The protocol paths still release the hold, each one promptly.
func TestInFlightRemoteTransferHoldReleasedByProtocol18521(t *testing.T) {
	t.Run("matching commit", func(t *testing.T) {
		m := inflightOwner18521(t)
		ageOwnerHold18521(m, 3*time.Second)
		if err := m.FinalizePeerTransferOut(2); err != nil {
			t.Fatal(err)
		}
		m.ClearRemoteTransferOutLease(2, 18521)
		if held, state := ownerHold18521(m); held || state != StateSecondary {
			t.Fatalf("commit must release the hold and leave the owner secondary: held=%v state=%s", held, state)
		}
	})
	t.Run("matching abort", func(t *testing.T) {
		m := inflightOwner18521(t)
		if err := m.AbortRemoteTransferOut(2, 18521); err != nil {
			t.Fatal(err)
		}
		if held, _ := ownerHold18521(m); held || !m.IsLocalPrimary(2) {
			t.Fatal("abort must release the hold and restore the owner")
		}
	})
	t.Run("lease expiry", func(t *testing.T) {
		m := inflightOwner18521(t)
		m.mu.Lock()
		m.remoteTransferOutLeaseUntil[2] = time.Now().Add(-time.Second)
		m.mu.Unlock()
		m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
			{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
		}})
		if held, _ := ownerHold18521(m); held || !m.IsLocalPrimary(2) {
			t.Fatal("an expired lease must still restore the owner")
		}
	})
}

// Control: an operator hold (no lease — `request chassis cluster failover
// redundancy-group N` on this node) keeps the pre-existing 2s dual-resign
// rescue. The fix is scoped to in-flight peer-requested transfers.
func TestOperatorHoldKeepsDualResignTimer18521(t *testing.T) {
	m := inflightOwner18521(t)
	m.mu.Lock()
	m.clearRemoteTransferOutLeaseLocked(2) // what a local operator hold looks like
	m.mu.Unlock()
	ageOwnerHold18521(m, 3*time.Second)
	m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
		{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
	}})
	if held, _ := ownerHold18521(m); held {
		t.Fatal("an operator hold against a yielded peer must still clear after 2s (dual-resign rescue)")
	}
}

// End to end through RequestPeerFailover: a requester that starts in its own
// secondary-hold asks a higher-priority owner for RG 2; the owner's demotion
// takes >2s to actuate, and the requester's local commit settle takes >2s.
// The transfer must commit with the owner secondary and the requester primary.
// RED before the fix: the owner clears its hold while the requester still
// advertises hold, re-promotes, and FinalizePeerTransferOut refuses the commit
// ("still primary locally").
func TestSlowTransferCommitsAgainstHigherPriorityOwner18521(t *testing.T) {
	requester, owner := ackWireManagers16592(t, []int{2}, false)
	owner.SetFakePeerSyncSourceForTesting(true, 0, true, true)
	// The requester carries a hold from an earlier push-away.
	requester.mu.Lock()
	rg := requester.groups[2]
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now().Add(-time.Minute)
	rg.State = StateSecondaryHold
	requester.mu.Unlock()
	owner.handlePeerHeartbeat(requester.buildHeartbeat())
	if !owner.IsLocalPrimary(2) {
		t.Fatal("fixture: owner must be primary")
	}

	const reqID = 18521
	ageOwner := func() {
		owner.mu.Lock()
		owner.groups[2].ManualFailoverAt = owner.groups[2].ManualFailoverAt.Add(-3 * time.Second)
		owner.mu.Unlock()
	}
	requester.SetPeerFailoverFunc(func(id int) (uint64, error) {
		if _, err := owner.ManualFailover(id); err != nil {
			return 0, err
		}
		owner.ArmRemoteTransferOutLease([]int{id}, reqID)
		// Demotion actuation (VRRP resign / rg_active / DHCP server) takes
		// >2s before the applied-ACK; the requester still advertises its
		// pre-request hold the whole time.
		ageOwner()
		owner.handlePeerHeartbeat(requester.buildHeartbeat())
		requester.handlePeerHeartbeat(owner.buildHeartbeat())
		return reqID, nil
	})
	requester.SetLocalTransferCommitReadyHook(func([]int) error {
		// The requester's local commit-ready settle (up to 3s) also passes
		// the 2s mark; heartbeats keep flowing in both directions.
		ageOwner()
		owner.handlePeerHeartbeat(requester.buildHeartbeat())
		requester.handlePeerHeartbeat(owner.buildHeartbeat())
		return nil
	})
	requester.SetPeerFailoverCommitFunc(func(id int, gotReqID uint64) error {
		if err := owner.FinalizePeerTransferOut(id); err != nil {
			return err
		}
		owner.ClearRemoteTransferOutLease(id, gotReqID)
		return nil
	})
	requester.SetPeerFailoverAbortFunc(func(id int, gotReqID uint64) error {
		return owner.AbortRemoteTransferOut(id, gotReqID)
	})

	if err := requester.RequestPeerFailover(2); err != nil {
		t.Fatalf("a slow but healthy transfer failed: %v — the owner's hold was released by "+
			"the 2s timer while the requester was still committing (#18521)", err)
	}
	owner.handlePeerHeartbeat(requester.buildHeartbeat())
	requester.handlePeerHeartbeat(owner.buildHeartbeat())
	if !requester.IsLocalPrimary(2) || owner.IsLocalPrimary(2) {
		t.Fatalf("after commit: requester primary=%v owner primary=%v, want true/false",
			requester.IsLocalPrimary(2), owner.IsLocalPrimary(2))
	}
}

// Review of #18525 (finding 1): commit AND abort both lost because session
// sync went down. The requester's commit write fails (disconnectConn leaves a
// single-fabric pair with no connection), so its abort has nothing to travel
// on; it restores its own pre-request hold and will not promote. Holding the
// owner for the rest of the lease then leaves the RG with NO primary for up to
// 26s. With sync down no commit or abort can arrive, so the pre-#18521 2s
// rescue must apply again. RED with the hold not gated on sync.
func TestLostCommitAndAbortWithSyncDownReelectsOwner18521(t *testing.T) {
	requester, owner := ackWireManagers16592(t, []int{2}, false)
	owner.SetFakePeerSyncSourceForTesting(true, 0, true, true)
	requester.mu.Lock()
	rg := requester.groups[2]
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now().Add(-time.Minute)
	rg.State = StateSecondaryHold
	requester.mu.Unlock()
	owner.handlePeerHeartbeat(requester.buildHeartbeat())

	const reqID = 18525
	requester.SetPeerFailoverFunc(func(id int) (uint64, error) {
		if _, err := owner.ManualFailover(id); err != nil {
			return 0, err
		}
		owner.ArmRemoteTransferOutLease([]int{id}, reqID)
		requester.handlePeerHeartbeat(owner.buildHeartbeat())
		return reqID, nil
	})
	requester.SetPeerFailoverCommitFunc(func(int, uint64) error {
		// The commit write fails; the sender tears the only connection down.
		owner.SetFakePeerSyncSourceForTesting(false, 0, false, false)
		return errors.New("failed to send failover commit: write: broken pipe")
	})
	requester.SetPeerFailoverAbortFunc(func(int, uint64) error {
		return errors.New("session sync not connected")
	})
	if err := requester.RequestPeerFailover(2); err == nil {
		t.Fatal("fixture: the request must fail when its commit is lost")
	}
	// The requester restored its pre-request hold and stays out.
	requester.handlePeerHeartbeat(owner.buildHeartbeat())
	if requester.IsLocalPrimary(2) {
		t.Fatal("fixture: the aborted requester must not promote")
	}

	// A few seconds later, with sync still down, the owner must be primary
	// again — not wait out the 26s lease.
	owner.mu.Lock()
	owner.groups[2].ManualFailoverAt = owner.groups[2].ManualFailoverAt.Add(-3 * time.Second)
	owner.mu.Unlock()
	owner.handlePeerHeartbeat(requester.buildHeartbeat())
	if !owner.IsLocalPrimary(2) {
		held, state := ownerHold18521(owner)
		t.Fatalf("commit and abort were both lost with session sync down, the requester is back in "+
			"its hold, and the owner is still held (held=%v state=%s): the RG has no primary until "+
			"the lease expires (review of #18525)", held, state)
	}
}

// Review of #18525 round 2 (finding 1, both seats): the leased hold was kept
// while ANY sync connection was up. Commit and abort frames lost with the
// request's connection are never re-sent, so a FRESH connection cannot carry
// them — yet it satisfied IsConnected, and the owner held for the rest of the
// lease while the requester sat in its restored hold: no primary for up to
// 26s. This is the shipped sync-down cell plus the one line the HA seat
// added: the dial side redials before the owner's next election. RED with
// the hold keyed on IsConnected.
func TestLostCommitAndAbortThenSyncReconnectsReelectsOwner18525(t *testing.T) {
	requester, owner := ackWireManagers16592(t, []int{2}, false)
	owner.SetFakePeerSyncSourceForTesting(true, 0, true, true)
	requester.mu.Lock()
	rg := requester.groups[2]
	rg.ManualFailover = true
	rg.ManualFailoverAt = time.Now().Add(-time.Minute)
	rg.State = StateSecondaryHold
	requester.mu.Unlock()
	owner.handlePeerHeartbeat(requester.buildHeartbeat())

	const reqID = 18525
	requester.SetPeerFailoverFunc(func(id int) (uint64, error) {
		if _, err := owner.ManualFailover(id); err != nil {
			return 0, err
		}
		owner.ArmRemoteTransferOutLease([]int{id}, reqID)
		requester.handlePeerHeartbeat(owner.buildHeartbeat())
		return reqID, nil
	})
	requester.SetPeerFailoverCommitFunc(func(int, uint64) error {
		owner.SetFakePeerSyncSourceForTesting(false, 0, false, false)
		return errors.New("failed to send failover commit: write: broken pipe")
	})
	requester.SetPeerFailoverAbortFunc(func(int, uint64) error {
		return errors.New("session sync not connected")
	})
	if err := requester.RequestPeerFailover(2); err == nil {
		t.Fatal("fixture: the request must fail when its commit is lost")
	}
	requester.handlePeerHeartbeat(owner.buildHeartbeat())
	if requester.IsLocalPrimary(2) {
		t.Fatal("fixture: the aborted requester must not promote")
	}

	// The reconnect: a NEW connection is up before the owner elects again.
	owner.SetFakePeerSyncSourceForTesting(true, 0, true, true)
	owner.mu.Lock()
	owner.groups[2].ManualFailoverAt = owner.groups[2].ManualFailoverAt.Add(-3 * time.Second)
	owner.mu.Unlock()
	owner.handlePeerHeartbeat(requester.buildHeartbeat())
	if !owner.IsLocalPrimary(2) {
		held, state := ownerHold18521(owner)
		t.Fatalf("commit and abort were lost with the request's connection and a fresh one came "+
			"up; the requester is back in its hold and the owner is still held (held=%v state=%s): "+
			"a fresh connection can never deliver the lost frames, so the RG has no primary until "+
			"the lease expires (review of #18525 round 2)", held, state)
	}
}

// The same invariant on a REAL SessionSync, so the binding is to the
// connection that existed when the lease was armed and not to a fake's
// identity: removing that connection from its slot (here a teardown and a
// redial into the same slot) returns the owner to the 2s rescue. Filling an
// EMPTY slot removes nothing, so the hold stays. RED with the hold keyed on
// IsConnected (first row) / with every install counted (second row).
func TestTransferHoldBoundToRequestConnection18525(t *testing.T) {
	newPipeConn := func(t *testing.T) *authConn {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		return &authConn{Conn: a}
	}
	rows := []struct {
		name     string
		mutate   func(t *testing.T, ss *SessionSync, carrier *authConn)
		wantHeld bool
	}{
		{"request connection torn down and redialled", func(t *testing.T, ss *SessionSync, carrier *authConn) {
			ss.disconnectConn(carrier, "test: queued frame write failed", nil)
			ss.installConn(0, newPipeConn(t))
		}, false},
		{"request connection superseded in its slot", func(t *testing.T, ss *SessionSync, _ *authConn) {
			ss.installConn(0, newPipeConn(t))
		}, false},
		{"other fabric connects, request connection intact", func(t *testing.T, ss *SessionSync, _ *authConn) {
			ss.installConn(1, newPipeConn(t))
		}, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
			carrier := newPipeConn(t)
			ss.installConn(0, carrier)
			m := NewManager(1, 1)
			m.UpdateConfig(makeConfig(makeRG(2, false, map[int]int{0: 100, 1: 200})))
			m.setPeerSyncSourceForTesting(ss)
			m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
				{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
			}})
			m.mu.Lock()
			m.groups[2].Ready = true
			m.groups[2].ReadySince = time.Now().Add(-time.Hour)
			m.groups[2].ReadinessReasons = nil
			m.mu.Unlock()
			m.runElection()
			if !m.IsLocalPrimary(2) {
				t.Fatal("fixture: owner must start primary")
			}
			if _, err := m.ManualFailover(2); err != nil {
				t.Fatal(err)
			}
			m.ArmRemoteTransferOutLease([]int{2}, 18525)

			row.mutate(t, ss, carrier)
			if !ss.IsConnected() {
				t.Fatal("fixture: a connection must be up when the owner elects")
			}
			ageOwnerHold18521(m, 3*time.Second)
			m.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
				{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
			}})
			held, state := ownerHold18521(m)
			if held != row.wantHeld {
				t.Fatalf("owner held=%v (state=%s), want held=%v: the hold must last exactly as long "+
					"as the connection the transfer request arrived on (review of #18525 round 2)",
					held, state, row.wantHeld)
			}
		})
	}
}

// The binding above is only as good as the removal generation, and the
// generation is only as good as its coverage of every slot write. Rather than
// enumerate today's removal sites (which is how a registry misses the next
// one), this pins the primitive: no production file assigns s.conn0 / s.conn1,
// or takes their address, anywhere except setConnSlotLocked. RED on any direct
// slot write, e.g. the pre-fold `s.conn0 = nil` in handleDisconnect, and on a
// `&s.conn1` alias outside the setter (review of #18525 round 3).
func TestConnSlotWritesGoThroughTheSetter18525(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned, setterWrites, setterAddrs := 0, 0, 0
	var offenders []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				// Review of #18525 round 3: a pointer to a slot taken outside
				// the setter (`p := &s.conn0; *p = c`) is a write the
				// assignment scan below cannot see.
				if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
					if sel, ok := u.X.(*ast.SelectorExpr); ok && (sel.Sel.Name == "conn0" || sel.Sel.Name == "conn1") {
						if fd.Name.Name == "setConnSlotLocked" {
							setterAddrs++
						} else {
							offenders = append(offenders, fmt.Sprintf("%s (%s: address of a slot)", fset.Position(u.Pos()), fd.Name.Name))
						}
					}
					return true
				}
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range as.Lhs {
					target := lhs
					if star, ok := lhs.(*ast.StarExpr); ok {
						target = star.X
					}
					switch e := target.(type) {
					case *ast.SelectorExpr:
						if e.Sel.Name == "conn0" || e.Sel.Name == "conn1" {
							offenders = append(offenders, fmt.Sprintf("%s (%s)", fset.Position(as.Pos()), fd.Name.Name))
						}
					case *ast.Ident:
						if fd.Name.Name == "setConnSlotLocked" && e.Name == "slot" {
							setterWrites++
						}
					}
				}
				return true
			})
		}
	}
	if scanned < 50 || setterWrites == 0 || setterAddrs == 0 {
		t.Fatalf("scan is broken: %d production files, %d setter writes, %d setter slot addresses",
			scanned, setterWrites, setterAddrs)
	}
	if len(offenders) > 0 {
		t.Fatalf("session-sync slots written outside setConnSlotLocked, so a removal there would "+
			"not advance the transfer-channel generation the owner hold is bound to (#18521):\n%s",
			strings.Join(offenders, "\n"))
	}
}

// Review of #18525 round 3 (finding 4, HA seat): the hold's binding can break
// while the owner's demotion is still actuating (a write timeout or a
// second-fabric flap removes a connection). The requester is legitimately
// still in its pre-request hold, so the 2s rescue re-promotes the owner — and
// the actuation barrier, which resolves on the queued demotion edge, then let
// "applied" go out anyway. The requester promoted beside the re-promoted
// owner until its commit was refused. The applied-ack is now sent only while
// the owner is still parked for that request. Driven through the real
// handleRemoteFailover against a real Manager. RED (applied) without the
// check.
func TestAppliedAckRefusedOnceTheHoldWasRescued18525(t *testing.T) {
	rows := []struct {
		name         string
		breakBinding bool
		newerRequest bool
		want         uint8
	}{
		{"binding intact through the actuation", false, false, failoverAckApplied},
		{"binding broke and the rescue re-promoted the owner", true, false, failoverAckFailed},
		// The hold still stands, but for a NEWER request: this one is stale.
		{"a newer request re-armed the lease", false, true, failoverAckFailed},
	}
	for _, batch := range []bool{false, true} {
		for _, row := range rows {
			name := "single/" + row.name
			if batch {
				name = "batch/" + row.name
			}
			t.Run(name, func(t *testing.T) {
				appliedAckCase18525(t, batch, row.breakBinding, row.newerRequest, row.want)
			})
		}
	}
}

func appliedAckCase18525(t *testing.T, batch, breakBinding, newerRequest bool, want uint8) {
	owner := NewManager(1, 1)
	owner.UpdateConfig(makeConfig(makeRG(2, false, map[int]int{0: 100, 1: 200})))
	owner.SetFakePeerSyncSourceForTesting(true, 0, true, true)
	owner.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
		{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondary)},
	}})
	owner.mu.Lock()
	owner.groups[2].Ready = true
	owner.groups[2].ReadySince = time.Now().Add(-time.Hour)
	owner.groups[2].ReadinessReasons = nil
	owner.mu.Unlock()
	owner.runElection()
	if !owner.IsLocalPrimary(2) {
		t.Fatal("fixture: owner must start primary")
	}

	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	cc := &captureConn{}
	ss.mu.Lock()
	ss.conn0 = cc
	ss.mu.Unlock()
	demote := func(rgs []int, reqID uint64) error {
		for _, rg := range rgs {
			if _, err := owner.ManualFailover(rg); err != nil {
				return err
			}
		}
		owner.ArmRemoteTransferOutLease(rgs, reqID)
		return nil
	}
	actuate := func() error {
		if breakBinding {
			// The slow actuation: a connection goes away and more than 2s
			// pass while the requester still advertises its hold.
			owner.SetFakePeerSyncSourceForTesting(true, 0, true, true)
			ageOwnerHold18521(owner, 3*time.Second)
			owner.handlePeerHeartbeat(&HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: []HeartbeatGroup{
				{GroupID: 2, Priority: 100, Weight: 255, State: uint8(StateSecondaryHold)},
			}})
			if !owner.IsLocalPrimary(2) {
				t.Fatal("fixture: the rescue must have re-promoted the owner")
			}
		}
		if newerRequest {
			owner.ArmRemoteTransferOutLease([]int{2}, 18526)
		}
		return nil // the demotion edge actuated
	}
	ss.OnRemoteFailover = func(rg int, reqID uint64) error { return demote([]int{rg}, reqID) }
	ss.OnRemoteFailoverBatch = demote
	ss.WaitFailoverApplied = func(int, uint64) error { return actuate() }
	ss.WaitFailoverAppliedBatch = func([]int, uint64) error { return actuate() }
	ss.OnRemoteFailoverAbort = owner.AbortRemoteTransferOut
	ss.OnRemoteFailoverAbortBatch = owner.AbortRemoteTransferOutBatch
	ss.TransferOutStillHeld = owner.RemoteTransferOutStillHeld

	var status []uint8
	if batch {
		ss.handleRemoteFailoverBatch(cc, []int{2}, 18525)
		for _, f := range cc.frames() {
			if f.msgType != syncMsgFailoverBatchAck {
				continue
			}
			if _, st, reqID, _, err := decodeFailoverBatchAckPayload(f.payload); err == nil && reqID == 18525 {
				status = append(status, st)
			}
		}
	} else {
		ss.handleRemoteFailover(cc, 2, 18525)
		for _, f := range cc.frames() {
			if f.msgType == syncMsgFailoverAck && len(f.payload) >= 10 &&
				binary.LittleEndian.Uint64(f.payload[2:10]) == 18525 {
				status = append(status, f.payload[1])
			}
		}
	}
	if len(status) != 1 || status[0] != want {
		t.Fatalf("failover ack statuses %v, want [%d]: an \"applied\" for a transfer whose owner "+
			"is primary again (or that a newer request replaced) promotes the requester beside it "+
			"(review of #18525 round 3)", status, want)
	}
	if breakBinding && !owner.IsLocalPrimary(2) {
		t.Fatal("the refused transfer must leave the rescued owner primary")
	}
}
