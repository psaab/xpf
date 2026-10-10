package policymatch

import "testing"

// TestValidateProtocol asserts the #3108 contract for the simulator protocol
// token: an empty/whitespace token leaves the query protocol unspecified and is
// accepted; a known name/alias ("tcp", "udp", "icmp", "ospf") or a numeric
// value in 0-255 is accepted; an unknown name ("notaproto", "tcpp"), an
// out-of-range number ("999"), or other non-resolvable garbage is REJECTED.
// Without validation, constrained terms would never match an unknown protocol,
// but `application any` could still match and conceal invalid input.
//
// FAIL-ON-REVERT: replacing the body with `return nil` (dropping the
// appid.ProtocolNumber gate) flips every want-error case ("notaproto", "tcpp",
// "999", "256", "-1") to nil and turns them red.
func TestValidateProtocol(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"", false},         // absent -> unspecified, no constraint (unchanged)
		{"   ", false},      // whitespace -> unspecified
		{"tcp", false},      // known name
		{"udp", false},      // known name
		{"icmp", false},     // known name
		{"ospf", false},     // named, non-display protocol
		{"6", false},        // numeric tcp
		{"0", false},        // numeric HOPOPT (valid 0..255)
		{"255", false},      // numeric high bound
		{"notaproto", true}, // unknown name
		{"tcpp", true},      // operator typo
		{"999", true},       // out of range number
		{"256", true},       // one past the 8-bit top
		{"-1", true},        // negative number
		{"any", true},       // no "any" protocol keyword; omit for unspecified
	}
	for _, tc := range cases {
		err := ValidateProtocol(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ValidateProtocol(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
		}
	}
}
