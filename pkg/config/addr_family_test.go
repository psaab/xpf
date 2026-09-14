package config

import "testing"

// TestFRRAddrFamily is the rewritten #8597 pin (GLM-M3): the family
// discriminator the mismatch checks depend on, now shared by the commit
// gates and the render belts (#9820). The mapped rows expect "v6" — the
// explicit literal-classification rule (Rust parity + FRR X:X::X:X slot),
// opposite of the deleted frrOperandIsV6. Spellings cover compressed,
// fully expanded, uppercase, dotted and hexadecimal mapped forms plus a
// nonmapped v6 control, so a substring implementation cannot pass.
func TestFRRAddrFamily(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		note string
	}{
		{"192.168.50.1", "v4", "plain v4 address"},
		{"10.0.0.0/8", "v4", "plain v4 prefix"},
		{"0.0.0.0/0", "v4", "v4 default"},
		{"2001:db8::1", "v6", "plain v6 address"},
		{"2001:db8::/32", "v6", "plain v6 prefix"},
		{"::/0", "v6", "v6 default"},
		{"fe80::1", "v6", "nonmapped v6 control"},
		{"::ffff:192.168.50.1", "v6", "mapped, dotted"},
		{"::ffff:c000:201", "v6", "mapped, hex"},
		{"0:0:0:0:0:ffff:c000:0201", "v6", "mapped, fully expanded"},
		{"::FFFF:C000:201", "v6", "mapped, uppercase"},
		{"::ffff:10.0.0.0/104", "v6", "mapped prefix"},
		{"not-an-address", "", "unparseable reports empty"},
		{"", "", "empty reports empty"},
		{"10.0.0.0/99", "", "bad mask reports empty"},
	} {
		if got := FRRAddrFamily(c.in); got != c.want {
			t.Errorf("FRRAddrFamily(%q) = %q, want %q — %s", c.in, got, c.want, c.note)
		}
	}
}

// TestFRRAddrIsMapped pins the explicit mapped-literal check the
// backup-router and area gates refuse outright.
func TestFRRAddrIsMapped(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"::ffff:192.168.50.1", true},
		{"::ffff:c000:201", true},
		{"0:0:0:0:0:ffff:c000:0201", true},
		{"::FFFF:C000:201", true},
		{"::ffff:10.0.0.0/104", true},
		{"192.168.50.1", false},
		{"10.0.0.0/8", false},
		{"2001:db8::1", false},
		{"2001:db8::/32", false},
		{"fe80::1", false},
		{"not-an-address", false},
		{"", false},
	} {
		if got := FRRAddrIsMapped(c.in); got != c.want {
			t.Errorf("FRRAddrIsMapped(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
