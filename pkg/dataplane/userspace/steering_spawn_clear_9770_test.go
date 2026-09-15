package userspace

// steering_spawn_clear_9770_test.go — #9770: the first ctrl-enable flush deleted steering
// rows the helper's live sessions still used. The clear moved to helper-spawn time (where
// no row can be live) plus a drain+fence closer after proven full stops (disarm,
// link-cycle stop_workers). These cells bind the move, the closer, and the call sites.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// Steering action values (userspace-xdp/src/lib.rs:421-422).
const (
	steeringRedirect9770     uint8 = 1
	steeringPassToKernel9770 uint8 = 2
)

// steeringMapKey9770 mirrors UserspaceSessionMapKey: the 40-byte bare 5-tuple.
type steeringMapKey9770 struct {
	AddrFamily uint8
	Protocol   uint8
	Pad        uint16
	SrcPort    uint16
	DstPort    uint16
	SrcAddr    [16]byte
	DstAddr    [16]byte
}

func steeringKey9770(proto uint8, srcPort, dstPort uint16, src0, dst0 byte) steeringMapKey9770 {
	var src, dst [16]byte
	src[0], dst[0] = src0, dst0
	return steeringMapKey9770{
		AddrFamily: 2, // AF_INET
		Protocol:   proto,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SrcAddr:    src,
		DstAddr:    dst,
	}
}

func seedSteeringRow9770(t *testing.T, usMap *ebpf.Map, key steeringMapKey9770, val uint8) {
	t.Helper()
	if err := usMap.Update(key, val, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed steering row: %v", err)
	}
}

func countSteeringRows9770(t *testing.T, usMap *ebpf.Map) int {
	t.Helper()
	var key, next [40]byte
	n := 0
	for {
		if err := usMap.NextKey(key, &next); err != nil {
			break
		}
		key = next
		n++
	}
	return n
}

func lookupSteering9770(t *testing.T, usMap *ebpf.Map, key steeringMapKey9770) (uint8, bool) {
	t.Helper()
	var val uint8
	if err := usMap.Lookup(key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false
		}
		t.Fatalf("lookup steering row: %v", err)
	}
	return val, true
}

func shortSockDir9770(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "u9770")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestClearStaleSteeringRowsDeletesEveryRow9770: the extracted clear is FULL, not
// value-selective — every seeded row goes regardless of value, with an exact count.
// RED on revert: restore a value predicate (or skip rows) and the count assertion reds.
func TestClearStaleSteeringRowsDeletesEveryRow9770(t *testing.T) {
	if got := unsafe.Sizeof(steeringMapKey9770{}); got != 40 {
		t.Fatalf("steeringMapKey9770 size = %d, want 40 (fixture must match the map ABI)", got)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := New()
	usMap := injectUserspaceSessionMap(t, m)
	seeds := []struct {
		key steeringMapKey9770
		val uint8
	}{
		{steeringKey9770(6, 1001, 80, 10, 20), 0},
		{steeringKey9770(6, 1002, 80, 10, 20), steeringRedirect9770},
		{steeringKey9770(6, 1003, 80, 10, 20), steeringPassToKernel9770},
		{steeringKey9770(17, 1004, 53, 10, 20), 3},
		{steeringKey9770(1, 0, 0, 10, 20), 255},
	}
	for _, s := range seeds {
		seedSteeringRow9770(t, usMap, s.key, s.val)
	}
	if got := clearStaleSteeringRows(usMap); got != len(seeds) {
		t.Fatalf("clearStaleSteeringRows deleted %d rows, want %d", got, len(seeds))
	}
	if n := countSteeringRows9770(t, usMap); n != 0 {
		t.Fatalf("%d steering rows survived the clear, want 0", n)
	}
	// Empty-map control: a clear over nothing reports zero, not an error.
	if got := clearStaleSteeringRows(usMap); got != 0 {
		t.Fatalf("clear over empty map deleted %d rows, want 0", got)
	}
}

// TestClearStaleSteeringRowsPopulatedTiming9770 reports the populated-map clear cost
// (§8 validation). The number is evidence; the bound catches pathology only.
func TestClearStaleSteeringRowsPopulatedTiming9770(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	const rows = 20000
	usMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    40,
		ValueSize:  1,
		MaxEntries: 32768,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new timing userspace_sessions map", err)
	}
	t.Cleanup(func() { usMap.Close() })
	for i := 0; i < rows; i++ {
		seedSteeringRow9770(t, usMap, steeringKey9770(6, uint16(1024+i%60000), 80, byte(i), byte(i>>8)), steeringRedirect9770)
	}
	start := time.Now()
	deleted := clearStaleSteeringRows(usMap)
	elapsed := time.Since(start)
	t.Logf("cleared %d/%d rows in %v", deleted, rows, elapsed)
	if deleted != rows {
		t.Fatalf("clear deleted %d rows, want %d", deleted, rows)
	}
	if elapsed > 120*time.Second {
		t.Fatalf("clear took %v, past the 120s pathology bound", elapsed)
	}
}

// TestClearStaleSteeringRowsNilMap9770: no handle (test-only synthetic manager) is a
// no-op, not a panic. Runs unprivileged: no BPF map involved.
func TestClearStaleSteeringRowsNilMap9770(t *testing.T) {
	if got := clearStaleSteeringRows(nil); got != 0 {
		t.Fatalf("clear over nil map deleted %d rows, want 0", got)
	}
}

// TestSpawnClearsSteeringRows9770 binds the SPAWN call site: the real ensureProcessLocked
// with a stand-in binary that exits immediately (cannot publish steering). Rows must be
// gone DESPITE the error return — the clear precedes cmd.Start. RED on revert: delete the
// call and the seeded rows survive.
// Controls: healthy-reuse (early return, live generation retained) and live-listener
// refusal both leave rows untouched — the clear runs exactly on spawn.
func TestSpawnClearsSteeringRows9770(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	t.Run("exiting child still clears", func(t *testing.T) {
		dir := shortSockDir9770(t)
		bin := filepath.Join(dir, "helper")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		m := New()
		m.restartTimerFn = (&restartRecorder{}).arm
		cfg := config.UserspaceConfig{
			Binary:        bin,
			ControlSocket: filepath.Join(dir, "c.sock"),
			StateFile:     filepath.Join(dir, "state.json"),
			EventSocket:   filepath.Join(dir, "e.sock"),
		}
		usMap := injectUserspaceSessionMap(t, m)
		k1 := steeringKey9770(6, 2001, 80, 30, 40)
		k2 := steeringKey9770(6, 2002, 80, 30, 40)
		seedSteeringRow9770(t, usMap, k1, steeringRedirect9770)
		seedSteeringRow9770(t, usMap, k2, steeringPassToKernel9770)

		m.mu.Lock()
		err := m.ensureProcessLocked(cfg)
		m.mu.Unlock()
		if err == nil {
			t.Fatal("ensureProcessLocked reported success for an exiting helper")
		}
		if n := countSteeringRows9770(t, usMap); n != 0 {
			t.Fatalf("%d steering rows survived the spawn clear, want 0", n)
		}
	})

	t.Run("healthy reuse keeps rows", func(t *testing.T) {
		dir := shortSockDir9770(t)
		controlSock := filepath.Join(dir, "c.sock")
		ln, err := net.Listen("unix", controlSock)
		if err != nil {
			t.Fatalf("listen control socket: %v", err)
		}
		defer ln.Close()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					var req ControlRequest
					if err := json.NewDecoder(conn).Decode(&req); err != nil {
						return
					}
					_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true, Status: &ProcessStatus{PID: 424242}})
				}()
			}
		}()
		cmd := exec.Command("sleep", "300")
		if err := cmd.Start(); err != nil {
			t.Fatalf("spawn sleep: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		m := New()
		m.proc = cmd
		m.cfg = config.UserspaceConfig{ControlSocket: controlSock}
		usMap := injectUserspaceSessionMap(t, m)
		k := steeringKey9770(6, 2003, 80, 30, 40)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)

		m.mu.Lock()
		err = m.ensureProcessLocked(m.cfg)
		m.mu.Unlock()
		if err != nil {
			t.Fatalf("healthy reuse returned error: %v", err)
		}
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("healthy reuse cleared a live generation's steering row")
		}
	})

	t.Run("refusal keeps rows", func(t *testing.T) {
		dir := shortSockDir9770(t)
		controlSock := filepath.Join(dir, "c.sock")
		ln, err := net.Listen("unix", controlSock)
		if err != nil {
			t.Fatalf("listen control socket: %v", err)
		}
		defer ln.Close() // held open: a live listener the spawn must refuse
		m := New()
		cfg := config.UserspaceConfig{
			Binary:        "/bin/true",
			ControlSocket: controlSock,
			StateFile:     filepath.Join(dir, "state.json"),
		}
		usMap := injectUserspaceSessionMap(t, m)
		k := steeringKey9770(6, 2004, 80, 30, 40)
		seedSteeringRow9770(t, usMap, k, steeringPassToKernel9770)

		m.mu.Lock()
		err = m.ensureProcessLocked(cfg)
		m.mu.Unlock()
		if err == nil {
			t.Fatal("ensureProcessLocked succeeded against a live listener, want refusal")
		}
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("refused spawn cleared steering rows it must not touch")
		}
	})
}

// requestLog9770 records session-socket request types across goroutines. Mutex-guarded:
// the fake appends on its handler goroutine while the test snapshots after the
// round trip, and a bare slice would race under -race (socket I/O is not a
// happens-before edge the detector understands).
type requestLog9770 struct {
	mu    sync.Mutex
	types []string
}

func (l *requestLog9770) add(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.types = append(l.types, t)
}

func (l *requestLog9770) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.types...)
}

// fakeSessionSocket9770 serves one canned reply per accepted connection on path,
// recording decoded request types into log (nil-able). The accept loop ends when the
// listener closes.
func fakeSessionSocket9770(t *testing.T, path string, reply ControlResponse, log *requestLog9770) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				if log != nil {
					log.add(req.Type)
				}
				_ = json.NewEncoder(conn).Encode(reply)
			}()
		}
	}()
	return ln
}

// TestDrainAndClearSteeringRows9770 binds the closer: an acked drain ping lets the clear
// run; a drain failure, an unconfigured socket, or a nil map skips it without failing.
// The sessionMu-held subtest proves the fence holds the lock across ping+clear: with the
// ping fake blocked mid-reply, a second session send cannot proceed until release.
func TestDrainAndClearSteeringRows9770(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	t.Run("ping ok clears", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		log := &requestLog9770{}
		fakeSessionSocket9770(t, m.sessionSocketPath(), ControlResponse{OK: true}, log)
		usMap := injectUserspaceSessionMap(t, m)
		k := steeringKey9770(6, 3001, 80, 50, 60)
		seedSteeringRow9770(t, usMap, k, steeringPassToKernel9770)

		m.mu.Lock()
		m.drainAndClearSteeringRowsLocked("test")
		m.mu.Unlock()

		if n := countSteeringRows9770(t, usMap); n != 0 {
			t.Fatalf("%d rows survived the closer, want 0", n)
		}
		if got := log.snapshot(); len(got) != 1 || got[0] != "ping" {
			t.Fatalf("session requests = %v, want exactly [ping] (the drain)", got)
		}
	})

	t.Run("drain failure keeps rows", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		// No session listener: the drain ping fails fast at dial.
		usMap := injectUserspaceSessionMap(t, m)
		k := steeringKey9770(6, 3002, 80, 50, 60)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)

		m.mu.Lock()
		m.drainAndClearSteeringRowsLocked("test")
		m.mu.Unlock()

		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("closer deleted rows after a failed drain (uncertain stop)")
		}
	})

	t.Run("unconfigured socket clears without drain", func(t *testing.T) {
		m := New()
		m.cfg.ControlSocket = ""
		usMap := injectUserspaceSessionMap(t, m)
		k := steeringKey9770(6, 3003, 80, 50, 60)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)

		m.mu.Lock()
		m.drainAndClearSteeringRowsLocked("test")
		m.mu.Unlock()

		if n := countSteeringRows9770(t, usMap); n != 0 {
			t.Fatalf("%d rows survived with no session socket configured, want 0", n)
		}
	})

	t.Run("nil map is a no-op", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		// A session listener that must never be contacted: proves the nil-map
		// short-circuit precedes the drain (no pointless dial + warn spam).
		ln, err := net.Listen("unix", m.sessionSocketPath())
		if err != nil {
			t.Fatalf("listen session socket: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
				t.Error("drain dialed the session socket despite a nil map")
			}
		}()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.drainAndClearSteeringRowsLocked("test") // must not panic, must not dial
	})

	t.Run("fence holds sessionMu across ping and clear", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		ln, err := net.Listen("unix", m.sessionSocketPath())
		if err != nil {
			t.Fatalf("listen session socket: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		pingArrived := make(chan struct{})
		releasePing := make(chan struct{})
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				return
			}
			close(pingArrived)
			<-releasePing
			_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
		}()
		usMap := injectUserspaceSessionMap(t, m)
		k := steeringKey9770(6, 3004, 80, 50, 60)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)

		done := make(chan struct{})
		go func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.drainAndClearSteeringRowsLocked("test")
			close(done)
		}()
		select {
		case <-pingArrived:
		case <-time.After(30 * time.Second):
			t.Fatal("closer never sent the drain ping (fence broken or gate mis-set)")
		}
		if m.sessionMu.TryLock() {
			m.sessionMu.Unlock()
			close(releasePing)
			<-done
			t.Fatal("sessionMu acquirable while the closer's drain is in flight: the fence does not hold the lock")
		}
		close(releasePing)
		<-done
		if n := countSteeringRows9770(t, usMap); n != 0 {
			t.Fatalf("%d rows survived after the fence released, want 0", n)
		}
	})

	t.Run("enabled generation skips without drain", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		m.initialCtrlCleanupDone = true
		// A session listener that must never be contacted: proves the
		// never-enabled gate precedes the drain (no pointless ping).
		ln, err := net.Listen("unix", m.sessionSocketPath())
		if err != nil {
			t.Fatalf("listen session socket: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				conn.Close()
				t.Error("drain pinged despite an enabled generation")
			}
		}()
		usMap := injectUserspaceSessionMap(t, m)
		k := steeringKey9770(6, 3005, 80, 50, 60)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)

		m.mu.Lock()
		defer m.mu.Unlock()
		m.drainAndClearSteeringRowsLocked("test")
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("closer deleted rows for an enabled generation (failback need)")
		}
	})
}

// TestDisarmReclaimsSteeringRows9770 binds the disarm call site: SetForwardingArmed(false)
// with an acked RPC reclaims seeded rows; transport failure, in-band rejection, and the
// arm path all leave rows untouched. RED on revert: delete the call and rows survive.
func TestDisarmReclaimsSteeringRows9770(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	setup := func(t *testing.T, reply ControlResponse) (*Manager, *ebpf.Map) {
		t.Helper()
		dir := shortSockDir9770(t)
		controlSock := filepath.Join(dir, "control.sock")
		ln, err := net.Listen("unix", controlSock)
		if err != nil {
			t.Fatalf("listen control socket: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					var req ControlRequest
					if err := json.NewDecoder(conn).Decode(&req); err != nil {
						return
					}
					_ = json.NewEncoder(conn).Encode(reply)
				}()
			}
		}()
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = controlSock
		fakeSessionSocket9770(t, m.sessionSocketPath(), ControlResponse{OK: true}, nil)
		injectCtrlAndBindingMaps(t, m)
		m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
		m.neighborsPrewarmed = true
		m.xskLivenessProven = true
		m.publishedSnapshot = 1
		return m, injectUserspaceSessionMap(t, m)
	}
	disarmed := ControlResponse{OK: true, Status: &ProcessStatus{Enabled: false}}

	t.Run("acked disarm clears", func(t *testing.T) {
		m, usMap := setup(t, disarmed)
		k := steeringKey9770(6, 4001, 80, 70, 80)
		seedSteeringRow9770(t, usMap, k, steeringPassToKernel9770)
		if _, err := m.SetForwardingArmed(false); err != nil {
			t.Fatalf("SetForwardingArmed(false): %v", err)
		}
		if n := countSteeringRows9770(t, usMap); n != 0 {
			t.Fatalf("%d rows survived an acked disarm, want 0", n)
		}
	})

	t.Run("disarm transport failure keeps rows", func(t *testing.T) {
		dir := shortSockDir9770(t)
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
		// No control listener: the disarm RPC fails at dial (stop uncertain).
		usMap := injectUserspaceSessionMap(t, m)
		k := steeringKey9770(6, 4002, 80, 70, 80)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)
		if _, err := m.SetForwardingArmed(false); err == nil {
			t.Fatal("SetForwardingArmed(false) succeeded with no helper listening")
		}
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("disarm failure cleared rows from an uncertain stop")
		}
	})

	t.Run("disarm rejection keeps rows", func(t *testing.T) {
		m, usMap := setup(t, ControlResponse{OK: false, Error: "forwarding reconcile failed: boom"})
		k := steeringKey9770(6, 4003, 80, 70, 80)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)
		if _, err := m.SetForwardingArmed(false); err == nil {
			t.Fatal("SetForwardingArmed(false) succeeded on an in-band rejection")
		} else if !errors.Is(err, errHelperRejected) {
			t.Fatalf("disarm rejection error = %v, want errHelperRejected", err)
		}
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("rejected disarm cleared rows (helper kept prior state)")
		}
	})

	t.Run("arm path keeps rows", func(t *testing.T) {
		m, usMap := setup(t, disarmed)
		m.lastStatus.Capabilities.ForwardingSupported = true
		k := steeringKey9770(6, 4004, 80, 70, 80)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)
		if _, err := m.SetForwardingArmed(true); err != nil {
			t.Fatalf("SetForwardingArmed(true): %v", err)
		}
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("arm path cleared rows (re-arm republishes live state)")
		}
	})

	t.Run("post-enable disarm keeps rows", func(t *testing.T) {
		m, usMap := setup(t, disarmed)
		m.initialCtrlCleanupDone = true
		k := steeringKey9770(6, 4005, 80, 70, 80)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)
		if _, err := m.SetForwardingArmed(false); err != nil {
			t.Fatalf("SetForwardingArmed(false): %v", err)
		}
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("post-enable disarm deleted rows needed for failback recovery")
		}
	})
}

// TestLinkCycleStopReclaimsSteeringRows9770 binds the link-cycle call site:
// PrepareLinkCycle with an acked stop_workers reclaims seeded rows; a failed join leaves
// rows untouched and keeps the existing error contract. RED on revert: delete the call and
// rows survive.
func TestLinkCycleStopReclaimsSteeringRows9770(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	setup := func(t *testing.T, reply ControlResponse) (*Manager, *ebpf.Map) {
		t.Helper()
		dir := shortSockDir9770(t)
		controlSock := filepath.Join(dir, "control.sock")
		ln, err := net.Listen("unix", controlSock)
		if err != nil {
			t.Fatalf("listen control socket: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					var req ControlRequest
					if err := json.NewDecoder(conn).Decode(&req); err != nil {
						return
					}
					_ = json.NewEncoder(conn).Encode(reply)
				}()
			}
		}()
		m := New()
		// #6871 round 10 (F1): PrepareLinkCycle below takes the link-cycle lease,
		// which starts a heartbeat goroutine; release it at cleanup so neither the
		// lease nor the goroutine leaks into later tests (same shape as
		// newLinkCycleProcessOnlyManager).
		t.Cleanup(m.releaseLinkCycleLease)
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = controlSock
		fakeSessionSocket9770(t, m.sessionSocketPath(), ControlResponse{OK: true}, nil)
		return m, injectUserspaceSessionMap(t, m)
	}

	t.Run("acked stop clears", func(t *testing.T) {
		m, usMap := setup(t, ControlResponse{OK: true, Status: &ProcessStatus{}})
		k := steeringKey9770(6, 5001, 80, 90, 100)
		seedSteeringRow9770(t, usMap, k, steeringPassToKernel9770)
		if err := m.PrepareLinkCycle(); err != nil {
			t.Fatalf("PrepareLinkCycle: %v", err)
		}
		if n := countSteeringRows9770(t, usMap); n != 0 {
			t.Fatalf("%d rows survived an acked link-cycle stop, want 0", n)
		}
	})

	t.Run("failed join keeps rows", func(t *testing.T) {
		m, usMap := setup(t, ControlResponse{OK: false, Error: "join exploded"})
		k := steeringKey9770(6, 5002, 80, 90, 100)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)
		err := m.PrepareLinkCycle()
		if err == nil {
			t.Fatal("PrepareLinkCycle succeeded on a failed join")
		}
		if got := err.Error(); !strings.Contains(got, "stop_workers") {
			t.Fatalf("error %q does not name stop_workers (#5103 contract)", got)
		}
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("failed join cleared rows from possibly-live workers")
		}
	})

	t.Run("post-enable stop keeps rows", func(t *testing.T) {
		m, usMap := setup(t, ControlResponse{OK: true, Status: &ProcessStatus{}})
		m.initialCtrlCleanupDone = true
		k := steeringKey9770(6, 5003, 80, 90, 100)
		seedSteeringRow9770(t, usMap, k, steeringRedirect9770)
		if err := m.PrepareLinkCycle(); err != nil {
			t.Fatalf("PrepareLinkCycle: %v", err)
		}
		if _, ok := lookupSteering9770(t, usMap, k); !ok {
			t.Fatal("post-enable link-cycle stop deleted rows needed for failback recovery")
		}
	})
}

// seedConntrack9770 writes a conntrack value with Created at the ABI offset the flush
// decodes (dataplane.SessionValueCreatedOffset, shared by both families).
func seedConntrack9770(t *testing.T, ctMap *ebpf.Map, key any, valueSize uint32, created uint64) {
	t.Helper()
	val := make([]byte, valueSize)
	binary.NativeEndian.PutUint64(val[dataplane.SessionValueCreatedOffset:], created)
	if err := ctMap.Update(key, val, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed conntrack row: %v", err)
	}
}

func assertConntrackAbsent9770(t *testing.T, ctMap *ebpf.Map, key any, valueSize uint32, what string) {
	t.Helper()
	val := make([]byte, valueSize)
	if err := ctMap.Lookup(key, &val); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("%s survived cleanup: err=%v", what, err)
	}
}

func assertConntrackPresent9770(t *testing.T, ctMap *ebpf.Map, key any, valueSize uint32, what string) {
	t.Helper()
	val := make([]byte, valueSize)
	if err := ctMap.Lookup(key, &val); err != nil {
		t.Fatalf("%s missing after cleanup: %v", what, err)
	}
}

// emitterFixture9770 is the shared harness for the three raw set_forwarding_state
// emitters (PR-review GPT-1): fake control + session sockets, status-apply fixtures,
// and a seeded steering map. controlArmed records the Armed flag of every request the
// fake control socket receives (asserted per emitter arm under test).
type emitterFixture9770 struct {
	m            *Manager
	usMap        *ebpf.Map
	controlArmed *requestLog9770
}

func setupEmitter9770(t *testing.T, reply ControlResponse) *emitterFixture9770 {
	t.Helper()
	dir := shortSockDir9770(t)
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	armed := &requestLog9770{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				if req.Forwarding != nil {
					if req.Forwarding.Armed {
						armed.add("arm")
					} else {
						armed.add("disarm")
					}
				}
				_ = json.NewEncoder(conn).Encode(reply)
			}()
		}
	}()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	fakeSessionSocket9770(t, m.sessionSocketPath(), ControlResponse{OK: true}, nil)
	injectCtrlAndBindingMaps(t, m)
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.neighborsPrewarmed = true
	m.xskLivenessProven = true
	m.publishedSnapshot = 1
	return &emitterFixture9770{m: m, usMap: injectUserspaceSessionMap(t, m), controlArmed: armed}
}

// enablingStatus9770 is a helper status that enables ctrl (reaches the gate).
func enablingStatus9770() ProcessStatus {
	return ProcessStatus{
		Enabled:                true,
		Workers:                1,
		LastSnapshotGeneration: 1,
		NeighborGeneration:     1,
		Capabilities:           UserspaceCapabilities{ForwardingSupported: true},
		Bindings: []BindingStatus{{
			Slot: 1, QueueID: 0, Ifindex: 5, Registered: true, Armed: true, Bound: true,
		}},
	}
}

// TestDisarmBeforeUnsupportedPublish9770 (emitter E1): a pre-publish disarm reclaims
// pre-enable orphans; post-enable it keeps rows for failback recovery; and re-arm
// publications after the clear are never deleted.
func TestDisarmBeforeUnsupportedPublish9770(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	snap := &ConfigSnapshot{
		Config:       &config.Config{},
		Capabilities: UserspaceCapabilities{ForwardingSupported: false},
	}
	disarmed := ControlResponse{OK: true, Status: &ProcessStatus{Enabled: false}}

	t.Run("pre-enable disarm reclaims", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		fx.m.lastStatus.ForwardingArmed = true
		k := steeringKey9770(6, 6001, 80, 110, 120)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
			t.Fatalf("disarmBeforeUnsupportedPublishLocked: %v", err)
		}
		if n := countSteeringRows9770(t, fx.usMap); n != 0 {
			t.Fatalf("%d rows survived a pre-enable unsupported-publish disarm, want 0", n)
		}
		if got := fx.controlArmed.snapshot(); len(got) != 1 || got[0] != "disarm" {
			t.Fatalf("control requests = %v, want exactly [disarm]", got)
		}
	})

	t.Run("post-enable disarm keeps rows", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		fx.m.lastStatus.ForwardingArmed = true
		fx.m.initialCtrlCleanupDone = true
		k := steeringKey9770(6, 6002, 80, 110, 120)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
			t.Fatalf("disarmBeforeUnsupportedPublishLocked: %v", err)
		}
		if _, ok := lookupSteering9770(t, fx.usMap, k); !ok {
			t.Fatal("post-enable disarm deleted rows needed for failback recovery")
		}
	})

	t.Run("rearm publications survive", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		fx.m.lastStatus.ForwardingArmed = true
		k := steeringKey9770(6, 6003, 80, 110, 120)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
			t.Fatalf("disarmBeforeUnsupportedPublishLocked: %v", err)
		}
		// Simulate the re-arm's republication, then run a status tick: nothing
		// downstream may delete what the re-arm published.
		r := steeringKey9770(6, 6004, 80, 110, 120)
		seedSteeringRow9770(t, fx.usMap, r, steeringPassToKernel9770)
		st := enablingStatus9770()
		if err := fx.m.applyHelperStatusLocked(&st); err != nil {
			t.Fatalf("post-rearm applyHelperStatusLocked: %v", err)
		}
		if _, ok := lookupSteering9770(t, fx.usMap, r); !ok {
			t.Fatal("re-arm publication deleted after an emitter disarm+clear")
		}
	})
}

// TestSyncDesiredForwardingState9770 (emitter E2): the desired-state disarm arm reclaims
// pre-enable orphans; post-enable it keeps rows; the arm half never clears.
func TestSyncDesiredForwardingState9770(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	disarmed := ControlResponse{OK: true, Status: &ProcessStatus{Enabled: false}}
	// desired=false via pure standby: clustered, no data RGs, no active group.
	standby := func(m *Manager) {
		m.clusterHA = true
		m.lastSnapshot = nil
		m.haGroups = nil
		m.lastStatus.Capabilities.ForwardingSupported = true
		m.lastStatus.ForwardingArmed = true
	}

	t.Run("pre-enable disarm reclaims", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		standby(fx.m)
		k := steeringKey9770(6, 6101, 80, 130, 140)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.syncDesiredForwardingStateLocked(); err != nil {
			t.Fatalf("syncDesiredForwardingStateLocked: %v", err)
		}
		if n := countSteeringRows9770(t, fx.usMap); n != 0 {
			t.Fatalf("%d rows survived a pre-enable desired-state disarm, want 0", n)
		}
		if got := fx.controlArmed.snapshot(); len(got) != 1 || got[0] != "disarm" {
			t.Fatalf("control requests = %v, want exactly [disarm]", got)
		}
	})

	t.Run("post-enable disarm keeps rows", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		standby(fx.m)
		fx.m.initialCtrlCleanupDone = true
		k := steeringKey9770(6, 6102, 80, 130, 140)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.syncDesiredForwardingStateLocked(); err != nil {
			t.Fatalf("syncDesiredForwardingStateLocked: %v", err)
		}
		if _, ok := lookupSteering9770(t, fx.usMap, k); !ok {
			t.Fatal("post-enable desired-state disarm deleted failback rows")
		}
	})

	t.Run("arm half never clears", func(t *testing.T) {
		fx := setupEmitter9770(t, ControlResponse{OK: true, Status: &ProcessStatus{Enabled: true}})
		fx.m.clusterHA = true
		fx.m.haGroups = map[int]HAGroupStatus{1: {RGID: 1, Active: true}}
		fx.m.helperHAStatePublished = true
		fx.m.lastStatus.Capabilities.ForwardingSupported = true
		fx.m.lastStatus.ForwardingArmed = false
		k := steeringKey9770(6, 6103, 80, 130, 140)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.syncDesiredForwardingStateLocked(); err != nil {
			t.Fatalf("syncDesiredForwardingStateLocked: %v", err)
		}
		if got := fx.controlArmed.snapshot(); len(got) != 1 || got[0] != "arm" {
			t.Fatalf("control requests = %v, want exactly [arm]", got)
		}
		if _, ok := lookupSteering9770(t, fx.usMap, k); !ok {
			t.Fatal("desired-state ARM deleted rows (re-arm republishes live state)")
		}
	})

	t.Run("rearm publications survive", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		standby(fx.m)
		k := steeringKey9770(6, 6104, 80, 130, 140)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.syncDesiredForwardingStateLocked(); err != nil {
			t.Fatalf("syncDesiredForwardingStateLocked: %v", err)
		}
		r := steeringKey9770(6, 6105, 80, 130, 140)
		seedSteeringRow9770(t, fx.usMap, r, steeringPassToKernel9770)
		st := enablingStatus9770()
		if err := fx.m.applyHelperStatusLocked(&st); err != nil {
			t.Fatalf("post-re-arm applyHelperStatusLocked: %v", err)
		}
		if _, ok := lookupSteering9770(t, fx.usMap, r); !ok {
			t.Fatal("re-arm publication deleted after a desired-state disarm+clear")
		}
	})
}

// TestDisarmSnapshotProtocolFailure9770 (emitter E3): a protocol-failure disarm reclaims
// pre-enable orphans and keeps rows post-enable; re-arm publications survive.
func TestDisarmSnapshotProtocolFailure9770(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	disarmed := ControlResponse{OK: true, Status: &ProcessStatus{Enabled: false}}
	protoErr := errors.New("snapshot protocol too old for persistent source NAT")

	t.Run("pre-enable disarm reclaims", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		k := steeringKey9770(6, 6201, 80, 150, 160)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.disarmSnapshotProtocolFailureLocked(protoErr); err != nil {
			t.Fatalf("disarmSnapshotProtocolFailureLocked: %v", err)
		}
		if n := countSteeringRows9770(t, fx.usMap); n != 0 {
			t.Fatalf("%d rows survived a pre-enable protocol-failure disarm, want 0", n)
		}
	})

	t.Run("post-enable disarm keeps rows", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		fx.m.initialCtrlCleanupDone = true
		k := steeringKey9770(6, 6202, 80, 150, 160)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.disarmSnapshotProtocolFailureLocked(protoErr); err != nil {
			t.Fatalf("disarmSnapshotProtocolFailureLocked: %v", err)
		}
		if _, ok := lookupSteering9770(t, fx.usMap, k); !ok {
			t.Fatal("post-enable protocol-failure disarm deleted failback rows")
		}
	})

	t.Run("rearm publications survive", func(t *testing.T) {
		fx := setupEmitter9770(t, disarmed)
		k := steeringKey9770(6, 6203, 80, 150, 160)
		seedSteeringRow9770(t, fx.usMap, k, steeringRedirect9770)
		if err := fx.m.disarmSnapshotProtocolFailureLocked(protoErr); err != nil {
			t.Fatalf("disarmSnapshotProtocolFailureLocked: %v", err)
		}
		r := steeringKey9770(6, 6204, 80, 150, 160)
		seedSteeringRow9770(t, fx.usMap, r, steeringPassToKernel9770)
		st := enablingStatus9770()
		if err := fx.m.applyHelperStatusLocked(&st); err != nil {
			t.Fatalf("post-re-arm applyHelperStatusLocked: %v", err)
		}
		if _, ok := lookupSteering9770(t, fx.usMap, r); !ok {
			t.Fatal("re-arm publication deleted after a protocol-failure disarm+clear")
		}
	})
}
