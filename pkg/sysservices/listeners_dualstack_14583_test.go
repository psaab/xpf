package sysservices

import "testing"

// TestListenersLinesDualStack14583 pins the #14583 plural rows: a dual-stack
// plane renders one row per bind address, and a failed family renders Failed
// while its sibling stays Listening — never collapsed into one row.
//
// FAIL-ON-REVERT: dropping the HTTPs/HTTPSs rows from Lines leaves a single
// row per plane and this test goes RED.
func TestListenersLinesDualStack14583(t *testing.T) {
	in := Listeners{
		GRPC: Listener{Addr: "127.0.0.1:50051", State: StateListening},
		HTTPs: []Listener{
			{Addr: "10.9.9.5:80", State: StateListening},
			{Addr: "[2001:db8::5]:80", State: StateListening},
		},
		HTTPSs: []Listener{
			{Addr: "10.9.9.5:443", State: StateListening},
			{Addr: "[fe80::1%ge-0-0-0]:443", State: StateFailed},
		},
	}
	want := []string{
		"  gRPC:           127.0.0.1:50051",
		"  HTTP REST:      10.9.9.5:80",
		"  HTTP REST:      [2001:db8::5]:80",
		"  HTTPS REST:     10.9.9.5:443",
		"  HTTPS REST:     [fe80::1%ge-0-0-0]:443 (bind failed)",
	}
	got := in.Lines()
	if len(got) != len(want) {
		t.Fatalf("Lines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Lines[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
}
