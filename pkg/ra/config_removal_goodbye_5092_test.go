package ra

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5092: removing RA config must GRACEFULLY withdraw the affected senders — a
// final lifetime-0 goodbye RA (RFC 4861 §6.2.5) — instead of a silent hard stop.
// Before the fix, Apply's removal loop and the empty-config path used modeHard
// (no goodbye), so hosts kept this firewall as their IPv6 default router until
// the previous Router Lifetime (default 1800s) expired — an avoidable outage.
//
// These tests pin both removal shapes and the non-regression of the changed-
// config restart (which correctly stays a hard replace: the router is not going
// away, the replacement re-advertises immediately). Each removal assertion is
// RED against the pre-#5092 hard stop, where goodbyeStats stays (0, 0).

// TestConfigRemovalAllInterfacesGoodbye_5092 drives the "operator removed ALL RA
// config" path: Apply with an empty desired set (the manager branch the daemon's
// standalone reconcile reaches via Withdraw()). Every sender must be retired with
// a final lifetime-0 goodbye, not a silent hard stop.
//
// RED on revert: the pre-#5092 empty-config branch called clearLocked (modeHard),
// so no goodbye was emitted and goodbyeStats("lo") == (0, 0) — the test fails.
func TestConfigRemovalAllInterfacesGoodbye_5092(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	loConn := waitConn(t, fl.getConn, "lo")
	waitWrites(t, loConn, 1)

	// Remove ALL RA config. releaseDrain joins the owner synchronously, so the
	// goodbye is on the wire by the time Apply returns.
	if err := m.Apply(nil); err != nil {
		t.Fatalf("empty-config Apply: %v", err)
	}

	total, conns := fl.goodbyeStats("lo")
	if conns != 1 || total == 0 {
		t.Fatalf("empty-config Apply emitted no goodbye (%d conns / %d writes); "+
			"removing all RA must gracefully withdraw with a final lifetime-0 RA (#5092)",
			conns, total)
	}
	assertGoodbyeIsLast(t, loConn.snapshot())

	m.mu.Lock()
	remaining := len(m.senders)
	m.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("senders remain after full removal: %d", remaining)
	}
}

// TestConfigRemovalOneInterfaceGoodbye_5092 drives the "operator removed RA from
// ONE interface while keeping another" path: Apply with a NON-empty desired set
// that no longer contains the removed interface. The removal loop must withdraw
// the dropped interface gracefully AND leave the kept interface untouched.
//
// The kept interface is a second sender injected directly into the manager
// (startFakeSender bypasses net.InterfaceByName, so no real NIC beyond "lo" is
// needed); a re-Apply that lists only the kept interface makes "lo" a true
// removal without any spurious start failure.
//
// RED on revert: the pre-#5092 removal loop used modeHard, so goodbyeStats("lo")
// == (0, 0) and the goodbye assertion fails.
func TestConfigRemovalOneInterfaceGoodbye_5092(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()

	// Sender on the real "lo" interface (conn faked).
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	loConn := waitConn(t, fl.getConn, "lo")
	waitWrites(t, loConn, 1)

	// A second, independently-started sender for a synthetic "kept" interface,
	// injected under m.mu. testCfg("keepif0") matches its config, so the re-Apply
	// below classifies it as unchanged (configEqual → left running, no RA gap).
	keep, keepConn := startFakeSender(t, fl.getConn, "keepif0")
	waitWrites(t, keepConn, 1)
	m.mu.Lock()
	m.senders["keepif0"] = keep
	m.mu.Unlock()

	// Re-apply with ONLY the kept interface → "lo" is a true removal.
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("keepif0")}); err != nil {
		t.Fatalf("removal Apply: %v", err)
	}

	// "lo" gracefully withdrawn: exactly one conn carries the lifetime-0 goodbye,
	// emitted as the LAST RA on that conn.
	total, conns := fl.goodbyeStats("lo")
	if conns != 1 || total == 0 {
		t.Fatalf("removed interface emitted no goodbye (%d conns / %d writes); a "+
			"config removal must gracefully withdraw with a final lifetime-0 RA (#5092)",
			conns, total)
	}
	assertGoodbyeIsLast(t, loConn.snapshot())

	// The removed sender is gone from the active set.
	for _, info := range m.Status() {
		if info.Interface == "lo" && info.State == "active" {
			t.Fatal("removed interface still reports active after withdrawal")
		}
	}

	// The KEPT interface is untouched: still a live sender, no goodbye emitted —
	// a partial removal must not disturb the interfaces that remain.
	m.mu.Lock()
	_, keptAlive := m.senders["keepif0"]
	m.mu.Unlock()
	if !keptAlive {
		t.Fatal("kept interface's sender was removed by a partial-removal Apply")
	}
	if total, conns := fl.goodbyeStats("keepif0"); conns != 0 || total != 0 {
		t.Fatalf("kept interface emitted a goodbye (%d conns / %d writes); a partial "+
			"removal must not withdraw the interfaces that remain", conns, total)
	}

	_ = m.Clear()
}

// TestConfigChangeEmitsNoGoodbye_5092 is the non-regression guard: a CHANGED (not
// removed) config is a hard replace — the router is not going away and the
// replacement re-advertises immediately — so NO goodbye is owed on either conn.
// The #5092 graceful-removal change must distinguish removal from replacement and
// must not turn a restart into a withdrawal.
func TestConfigChangeEmitsNoGoodbye_5092(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	old := waitConn(t, fl.getConn, "lo")
	waitWrites(t, old, 1)

	// Changed-config Apply → hard replace (stop old, start replacement). Apply
	// waits for the replacement conn (make-before-break) before returning.
	if err := m.Apply([]*config.RAInterfaceConfig{configChanged("lo")}); err != nil {
		t.Fatalf("changed-config Apply: %v", err)
	}

	// No goodbye on the old (hard-stopped) conn or the fresh replacement conn.
	if total, conns := fl.goodbyeStats("lo"); conns != 0 || total != 0 {
		t.Fatalf("changed-config restart emitted a goodbye (%d conns / %d writes); "+
			"a replace is not a withdrawal (#5092 must not regress the restart path)",
			conns, total)
	}

	_ = m.Clear()
}

func TestClearInterfacesWithoutGoodbye10779(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	loConn := waitConn(t, fl.getConn, "lo")
	waitWrites(t, loConn, 1)

	kept, keptConn := startFakeSender(t, fl.getConn, "keepif0")
	waitWrites(t, keptConn, 1)
	m.mu.Lock()
	m.senders["keepif0"] = kept
	m.mu.Unlock()

	if err := m.ClearInterfacesWithoutGoodbye([]string{"lo", "lo"}); err != nil {
		t.Fatalf("ClearInterfacesWithoutGoodbye: %v", err)
	}
	if total, conns := fl.goodbyeStats("lo"); total != 0 || conns != 0 {
		t.Fatalf("ownership clear emitted a goodbye (%d conns / %d writes); "+
			"shared router identity must remain advertised by the peer", conns, total)
	}
	if got := fl.liveCount(); got != 1 {
		t.Fatalf("live sender count after scoped clear = %d, want kept sender only", got)
	}
	m.mu.Lock()
	_, demotedRemains := m.senders["lo"]
	_, keptRemains := m.senders["keepif0"]
	m.mu.Unlock()
	if demotedRemains || !keptRemains {
		t.Fatalf("senders after scoped clear: demoted=%v kept=%v, want false/true",
			demotedRemains, keptRemains)
	}
	_ = m.Clear()
}
