package policymatch

import "testing"

// TestValidatePort asserts the #3116/#17081 contract for already-parsed
// present port values: 0 is a valid literal port, 1..65535 accepted, and a
// negative or >65535 value is REJECTED rather than becoming omitted.
//
// FAIL-ON-REVERT: dropping the range check flips (-1, 65536, 70000) red.
func TestValidatePort(t *testing.T) {
	cases := []struct {
		port    int
		wantErr bool
	}{
		{0, false},     // literal port 0 (#17081)
		{1, false},     // low bound
		{443, false},   // typical valid
		{65535, false}, // high bound
		{-1, true},     // negative
		{65536, true},  // one past the top
		{70000, true},  // far out of range
		{-1000, true},  // far negative
	}
	for _, tc := range cases {
		err := ValidatePort(tc.port)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ValidatePort(%d) err = %v, wantErr = %v", tc.port, err, tc.wantErr)
		}
	}
}

// TestParsePort asserts the #17081 contract: empty is omitted (nil), an
// explicit "0" is a PRESENT literal 0, and malformed/signed/out-of-range
// tokens are rejected rather than silently becoming omitted.
//
// FAIL-ON-REVERT: restoring the int/0-sentinel ParsePort makes "0" return
// the omitted value and flips the present-zero cases red.
func TestParsePort(t *testing.T) {
	cases := []struct {
		in      string
		want    int // -1 = omitted (nil)
		wantErr bool
	}{
		{"", -1, false},         // absent -> unspecified
		{"   ", -1, false},      // whitespace -> unspecified
		{"0", 0, false},         // explicit 0 -> PRESENT literal 0 (#17081)
		{"443", 443, false},     // valid
		{"65535", 65535, false}, // high bound
		{"abc", 0, true},        // malformed
		{"70000", 0, true},      // out of range
		{"65536", 0, true},      // one past the top
		{"-1", 0, true},         // negative
		{"44a", 0, true},        // partial-numeric garbage
		{"+80", 0, true},        // #3679 signed spelling
		{"+443", 0, true},       // #3679 signed spelling
		{"+0", 0, true},         // #3679 signed zero
	}
	for _, tc := range cases {
		got, err := ParsePort(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ParsePort(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
		}
		if tc.wantErr {
			if got != nil {
				t.Fatalf("ParsePort(%q) rejected but returned %v, want nil", tc.in, got)
			}
			continue
		}
		if tc.want < 0 {
			if got != nil {
				t.Fatalf("ParsePort(%q) = %v, want nil (omitted)", tc.in, *got)
			}
			continue
		}
		if got == nil || int(*got) != tc.want {
			t.Fatalf("ParsePort(%q) = %v, want %d", tc.in, got, tc.want)
		}
	}
}
