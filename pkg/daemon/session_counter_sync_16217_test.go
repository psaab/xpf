package daemon

// #16217: live packet counters must cross delta -> SessionValue ->
// SessionSyncRequest, or the peer helper imports (0,0) and its
// scoped completion-evidence gate can never qualify (FZDiag19).

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestConvertCarriesPacketCounters16217(t *testing.T) {
	zoneIDs := map[string]uint32{"lan": 1, "wan": 2}
	d4 := closeClassDelta9412(t, "open", 0)
	d4.FwdPackets, d4.RevPackets = 12345, 6789
	_, v4, ok := userspaceSessionFromDeltaV4(d4, zoneIDs)
	if !ok {
		t.Fatal("FIXTURE: v4 delta did not convert")
	}
	if v4.FwdPackets != 12345 || v4.RevPackets != 6789 {
		t.Fatalf("#16217: v4 converted value carries fwd=%d rev=%d, want 12345/6789", v4.FwdPackets, v4.RevPackets)
	}
	d6 := closeClassDelta9412(t, "open", 0)
	d6.AddrFamily = dataplane.AFInet6
	d6.SrcIP, d6.DstIP = "2001:db8::1", "2001:db8::2"
	d6.FwdPackets, d6.RevPackets = 222, 111
	_, v6, ok := userspaceSessionFromDeltaV6(d6, zoneIDs)
	if !ok {
		t.Fatal("FIXTURE: v6 delta did not convert")
	}
	if v6.FwdPackets != 222 || v6.RevPackets != 111 {
		t.Fatalf("#16217: v6 converted value carries fwd=%d rev=%d, want 222/111", v6.FwdPackets, v6.RevPackets)
	}
	// Control: zero delta stays zero (no invented evidence).
	d0 := closeClassDelta9412(t, "open", 0)
	_, v0, ok := userspaceSessionFromDeltaV4(d0, zoneIDs)
	if !ok || v0.FwdPackets != 0 || v0.RevPackets != 0 {
		t.Fatalf("#16217: zero delta must stay zero, got fwd=%d rev=%d ok=%v", v0.FwdPackets, v0.RevPackets, ok)
	}
	_ = dpuserspace.SessionDeltaInfo{}
}

func TestConvertCarriesStatedZeroAppTimeoutLog17780(t *testing.T) {
	zoneIDs := map[string]uint32{"lan": 1, "wan": 2}
	d4 := closeClassDelta9412(t, "open", 0)
	d4.AppTimeoutLogStated = true
	_, v4, ok := userspaceSessionFromDeltaV4(d4, zoneIDs)
	if !ok || !v4.AppTimeoutLogStated || v4.AppTimeout != 0 || v4.LogFlags != 0 {
		t.Fatalf("v4 stated zero pair: ok=%v stated=%v pair=%d/%d", ok, v4.AppTimeoutLogStated, v4.AppTimeout, v4.LogFlags)
	}

	d6 := closeClassDelta9412(t, "open", 0)
	d6.AddrFamily = dataplane.AFInet6
	d6.SrcIP, d6.DstIP = "2001:db8::1", "2001:db8::2"
	d6.AppTimeoutLogStated = true
	_, v6, ok := userspaceSessionFromDeltaV6(d6, zoneIDs)
	if !ok || !v6.AppTimeoutLogStated || v6.AppTimeout != 0 || v6.LogFlags != 0 {
		t.Fatalf("v6 stated zero pair: ok=%v stated=%v pair=%d/%d", ok, v6.AppTimeoutLogStated, v6.AppTimeout, v6.LogFlags)
	}
}
