package logging

import "testing"

// #12890: a NAT64 record (v6 flow, left-aligned v4 NAT slot) must render
// the NAT address as IPv4, not as a bogus 16-byte IPv6 address.
func TestFormatNATAddr12890(t *testing.T) {
	var v4slot [16]byte
	copy(v4slot[:], []byte{203, 0, 113, 7})
	if got := formatNATAddr12890(v4slot, true, 8080); got != "203.0.113.7:8080" {
		t.Fatalf("NAT64 dst = %q, want 203.0.113.7:8080", got)
	}
	var v6slot [16]byte
	copy(v6slot[:], []byte{0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	if got := formatNATAddr12890(v6slot, true, 443); got != "[2001:db8::1]:443" {
		t.Fatalf("v6 NAT = %q, want [2001:db8::1]:443", got)
	}
	if got := formatNATAddr12890(v6slot, false, 443); got != "[2001:db8::1]:443" {
		t.Fatalf("NAT46 src = %q, want [2001:db8::1]:443", got)
	}
	var plain4 [16]byte
	copy(plain4[:], []byte{10, 0, 0, 1})
	if got := formatNATAddr12890(plain4, false, 53); got != "10.0.0.1:53" {
		t.Fatalf("plain v4 = %q, want 10.0.0.1:53", got)
	}
	var zero [16]byte
	if got := formatNATAddr12890(zero, true, 0); got != "[::]:0" {
		t.Fatalf("absent NAT = %q, want [::]:0", got)
	}
}
