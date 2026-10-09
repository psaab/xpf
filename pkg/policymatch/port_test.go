package policymatch

import "testing"

// TestValidatePort asserts the #3116 contract for already-parsed port values
// (the gRPC int32 field and the REST query int): 0 means "unspecified"; a
// port-constrained term never matches without a port. 1..65535 is accepted,
// and a negative or >65535 value is REJECTED rather than becoming unspecified.
//
// FAIL-ON-REVERT: dropping the range check (return nil unconditionally) flips
// the want-error cases (-1, 65536, 70000) to nil and turns them red.
func TestValidatePort(t *testing.T) {
	cases := []struct {
		port    int
		wantErr bool
	}{
		{0, false},     // unspecified; constrained terms do not match
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

// TestParsePort asserts the #3116 contract for operator string tokens (the CLI
// surface): an empty/whitespace token is "unspecified" (0, nil), a valid token
// parses, and an explicit "0" is also unspecified. A constrained term does not
// match without a port, while an unconstrained term may still match. A malformed,
// negative, or out-of-range token is REJECTED rather than silently becoming 0.
// FAIL-ON-REVERT: restoring `dstPort, _ = strconv.Atoi(token)` (ignoring the
// error) makes "abc" and "" both become 0 with no error, flipping the want-error
// "abc"/"70000"/"-1" cases red.
//
// #3679 FAIL-ON-REVERT: restoring strconv.Atoi in place of
// config.ParseCanonicalUint makes the signed "+80"/"+0"/"+443" tokens parse as
// 80/0/443 with no error — Atoi accepts a leading '+' — flipping the want-error
// signed cases red. The CLI `show security match-policies` and `request security
// test policy` port surfaces both funnel through ParsePort, so this unit case is
// their RED-on-revert coverage.
func TestParsePort(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},          // absent -> unspecified, unchanged
		{"   ", 0, false},       // whitespace -> unspecified
		{"0", 0, false},         // explicit 0 -> unspecified (gRPC parity)
		{"443", 443, false},     // valid
		{"65535", 65535, false}, // high bound
		{"abc", 0, true},        // malformed
		{"70000", 0, true},      // out of range
		{"65536", 0, true},      // one past the top
		{"-1", 0, true},         // negative
		{"44a", 0, true},        // partial-numeric garbage
		{"+80", 0, true},        // #3679 signed spelling (Atoi accepted as 80)
		{"+443", 0, true},       // #3679 signed spelling
		{"+0", 0, true},         // #3679 signed zero (Atoi accepted as 0)
	}
	for _, tc := range cases {
		got, err := ParsePort(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("ParsePort(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Fatalf("ParsePort(%q) = %d, want %d", tc.in, got, tc.want)
		}
		if tc.wantErr && got != 0 {
			t.Fatalf("ParsePort(%q) rejected but returned %d, want 0", tc.in, got)
		}
	}
}
