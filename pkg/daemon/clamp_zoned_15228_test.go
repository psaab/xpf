package daemon

import "testing"

// #15228 A44-03: zoned link-local clamp must go to ::1, not duplicate 127.0.0.1.
func TestClampZonedLinkLocal15228(t *testing.T) {
	got, clamped := clampBindToLoopback("[fe80::1%ge-0-0-0]:80", false)
	if !clamped || got != "[::1]:80" {
		t.Fatalf("clamp zoned = (%q,%v) want ([::1]:80,true)", got, clamped)
	}
	// Dedup via clampBindsToLoopback: v4 + zoned v6 -> distinct loopbacks.
	out := clampBindsToLoopback([]string{"10.0.0.5:80", "[fe80::1%ge-0-0-0]:80"}, "", false, "HTTP")
	want := []string{"127.0.0.1:80", "[::1]:80"}
	if len(out) != 2 || out[0] != want[0] || out[1] != want[1] {
		t.Fatalf("clampBinds = %v want %v", out, want)
	}
	// Controls: global v6, loopback zoned? ::1 untouched, auth untouched.
	if got, c := clampBindToLoopback("[2001:db8::1]:443", false); !c || got != "[::1]:443" {
		t.Fatalf("global v6 clamp = (%q,%v)", got, c)
	}
	if got, c := clampBindToLoopback("[fe80::1%ge-0-0-0]:80", true); c || got != "[fe80::1%ge-0-0-0]:80" {
		t.Fatalf("auth zoned = (%q,%v) want unchanged", got, c)
	}
	if !hostIsLoopback("::1") || hostIsLoopback("fe80::1%ge-0-0-0") {
		t.Fatal("hostIsLoopback zoned classification wrong")
	}
}
