package flowexport

import (
	"testing"
	"time"
)

// TestNetflowSysUptimeWrapBoundary10726 pins #10726 A9-F5: the documented
// uint32-millisecond sysUptime wrap boundary. RED on revert — the constant IS
// the collector-facing note; deleting it breaks this reference.
func TestNetflowSysUptimeWrapBoundary10726(t *testing.T) {
	if NetflowSysUptimeWrapMs != 4294967296 {
		t.Fatalf("NetflowSysUptimeWrapMs = %d, want 2^32 ms", NetflowSysUptimeWrapMs)
	}
	days := float64(NetflowSysUptimeWrapMs) / 1000 / 86400
	if days < 49.7 || days > 49.8 {
		t.Fatalf("wrap period = %.3f days, want ~49.7", days)
	}
}

// TestUptimeMsWrapsPast49Days10726 characterizes the wrap the boundary note
// describes: a 50-day uptime wraps mod 2^32 instead of saturating, so a
// collector MUST NOT read a SysUptime decrease as a reboot.
func TestUptimeMsWrapsPast49Days10726(t *testing.T) {
	now := time.Now()
	boot50 := now.Add(-50 * 24 * time.Hour)
	if got, want := uptimeMs(boot50, now), uint32((50*24*time.Hour).Milliseconds()); got != want {
		t.Fatalf("uptimeMs(50d) = %d, want %d (wrapped mod 2^32)", got, want)
	}
	if got := uptimeMs(boot50, now); got >= uptimeMs(now.Add(-24*time.Hour), now) {
		t.Fatal("a 50-day uptime must wrap below a 1-day uptime")
	}
	// Sanity: inside the window the value is exact, not wrapped.
	boot48h := now.Add(-48 * time.Hour)
	if got, want := uptimeMs(boot48h, now), uint32((48*time.Hour).Milliseconds()); got != want {
		t.Fatalf("uptimeMs(48h) = %d, want %d", got, want)
	}
}
