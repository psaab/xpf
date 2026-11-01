package userspace

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #18541 (raised from the #18540 restart lane): after a peer loss the survivor
// may still be draining the dead peer's queued session frames, each one a
// SetClusterSyncedSessionV4 round trip on the helper session socket. An RG
// activation (UpdateRGActive) must not queue behind that backlog. It shares
// only the brief m.mu -> sessionMu fence with the install path, and the install
// path holds sessionMu — not m.mu — across its socket round trip, so the
// activation waits for at most the ONE install already in flight.
//
// The cell holds install #1 inside the fake helper with more installs queued
// behind it, starts the activation, then releases exactly one install. The
// pass criterion is a COUNT (installs the helper served before the activation
// reached its fence), never a duration; the budget only bounds the wait.

type gatedSessionHelper18541 struct {
	ln      net.Listener
	arrived chan struct{}
	release chan struct{}
	served  atomic.Int64
}

func startGatedSessionHelper18541(t *testing.T, path string) *gatedSessionHelper18541 {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	h := &gatedSessionHelper18541{ln: ln, arrived: make(chan struct{}, 64), release: make(chan struct{}, 64)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = conn.Close()
				continue
			}
			h.arrived <- struct{}{}
			<-h.release
			h.served.Add(1)
			_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
			_ = conn.Close()
		}
	}()
	return h
}

func TestRGActivationWaitsForAtMostOneInFlightInstall18541(t *testing.T) {
	const budget = 30 * time.Second // liveness backstop for a loaded host
	dir, err := os.MkdirTemp("", "x18541")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	helper := startGatedSessionHelper18541(t, filepath.Join(dir, "userspace-dp-sessions.sock"))

	m := sessionTestManager9629(t, map[int]HAGroupStatus{1: {Active: false}})
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	m.haRGActiveMapWrite = func(int, bool) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.xskLivenessProven = true
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		*status = *readyHelperStatus()
		return nil
	}
	var servedAtFence atomic.Int64
	servedAtFence.Store(-1)
	m.haRGActiveSessionHoldHook = func() { servedAtFence.Store(helper.served.Load()) }

	// The dead peer's backlog: a stream of installs, issued back to back.
	const backlog = 8
	installsDone := make(chan struct{})
	go func() {
		defer close(installsDone)
		for i := 0; i < backlog; i++ {
			key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 61, 10}, DstIP: [4]byte{172, 16, 80, 200},
				Protocol: 6, SrcPort: uint16(20000 + i), DstPort: 5201}
			_ = m.SetClusterSyncedSessionV4(key, dataplane.SessionValue{State: dataplane.SessStateEstablished})
		}
	}()
	select {
	case <-helper.arrived:
	case <-time.After(budget):
		t.Fatal("fixture: the first install never reached the helper")
	}

	activated := make(chan error, 1)
	go func() { activated <- m.UpdateRGActive(1, true) }()
	// Release exactly the in-flight install; everything behind it stays held.
	helper.release <- struct{}{}
	select {
	case err := <-activated:
		if err != nil {
			t.Fatalf("UpdateRGActive: %v", err)
		}
	case <-time.After(budget):
		// Do not wait on the installer here: a lock held past its request
		// blocks it too, and an unbounded wait turns this red into a hang.
		t.Fatalf("RG activation did not complete within %v with one install released: it is queued "+
			"behind the session-install backlog (%d served)", budget, helper.served.Load())
	}
	switch got := servedAtFence.Load(); {
	case got > 1:
		t.Fatalf("RG activation reached its sessionMu fence after %d installs were served, want the 1 in "+
			"flight when it started: an activation must not wait out the install backlog", got)
	case got < 1:
		t.Fatalf("fixture: the activation reached its fence with %d installs served — it never contended "+
			"with the in-flight install, so this run measured nothing", got)
	}
	for i := 0; i < backlog; i++ {
		helper.release <- struct{}{}
	}
	select {
	case <-installsDone:
	case <-time.After(budget):
		t.Fatal("fixture: the install backlog never drained")
	}
}
