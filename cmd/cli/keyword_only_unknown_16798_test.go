package main

// #16798: `cli -c` exited 0 having done nothing when a keyword-only
// node got an unknown or unimplemented subcommand. Handlers for such
// nodes printed tree help and returned nil (request.go software /
// chassis arms, clear.go security default, and their siblings), and
// main.go maps a nil dispatch error to exit 0. A scripted IKE flush,
// software add, config sync or failover therefore reported success
// for work that never happened.
//
// Fix: dispatchOperational consults cmdtree.ValidateOperationalLine
// (the operational SSOT) before routing and refuses
// `unknown <path> command: <token>` (exit 1 via the existing -c
// mapping). Bare keyword nodes keep help; value-slot and leaf
// failures fall through to the existing strict handlers.

import (
	"strings"
	"testing"
)

// Defect cells: every line must refuse, naming the offending token,
// with no RPC issued (nil client: any RPC nil-panics and fails the
// test, proving refusal happens before the wire).
func TestKeywordOnlyUnknownRefused16798(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		// Cited Junos-verb cells.
		{"clear security ike security-associations", "unknown clear security command: ike"},
		{"clear security ike", "unknown clear security command: ike"},
		{"request system software add", "unknown request system software command: add"},
		{"request system software add foo", "unknown request system software command: add"},
		{"request chassis cluster failoverx", "unknown request chassis cluster command: failoverx"},
		// Census siblings across every keyword-only umbrella.
		{"clear bogus", "unknown clear command: bogus"},
		{"clear security bogus", "unknown clear security command: bogus"},
		{"clear dhcp bogus", "unknown clear dhcp command: bogus"},
		{"clear system bogus", "unknown clear system command: bogus"},
		{"clear firewall bogus", "unknown clear firewall command: bogus"},
		{"clear ipv6 bogus", "unknown clear ipv6 command: bogus"},
		{"request zzqqbogus", "unknown request command: zzqqbogus"},
		{"request chassis bogus", "unknown request chassis command: bogus"},
		{"request chassis cluster bogus", "unknown request chassis cluster command: bogus"},
		{"request chassis cluster data-plane bogus", "unknown request chassis cluster data-plane command: bogus"},
		{"request system bogus", "unknown request system command: bogus"},
		{"request system software bogus", "unknown request system software command: bogus"},
		{"request system dynamic-dns bogus", "unknown request system dynamic-dns command: bogus"},
		{"request protocols bogus", "unknown request protocols command: bogus"},
		{"request protocols ospf bogus", "unknown request protocols ospf command: bogus"},
		{"request security bogus", "unknown request security command: bogus"},
		{"request security ipsec bogus", "unknown request security ipsec command: bogus"},
		{"request dhcp bogus", "unknown request dhcp command: bogus"},
		{"show bogus", "unknown show command: bogus"},
		{"show security bogus", "unknown show security command: bogus"},
		{"show security ike bogus", "unknown show security ike command: bogus"},
		{"show chassis cluster bogus", "unknown show chassis cluster command: bogus"},
		{"show dhcp bogus", "unknown show dhcp command: bogus"},
		{"show system bogus", "unknown show system command: bogus"},
		{"show services bogus", "unknown show services command: bogus"},
		{"show protocols bogus", "unknown show protocols command: bogus"},
		{"show class-of-service bogus", "unknown show class-of-service command: bogus"},
		{"show ipv6 bogus", "unknown show ipv6 command: bogus"},
		{"show security nat bogus", "unknown show security nat command: bogus"},
		{"show security flow bogus", "unknown show security flow command: bogus"},
		{"show monitor bogus", "unknown show monitor command: bogus"},
		{"monitor bogus", "unknown monitor command: bogus"},
		{"monitor security bogus", "unknown monitor security command: bogus"},
		{"test bogus", "unknown test command: bogus"},
		{"configure bogus", "unknown configure command: bogus"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			c := &ctl{client: nil}
			out := captureStdout(t, func() {
				err := c.dispatchOperational(tc.line)
				if err == nil {
					t.Fatalf("dispatchOperational(%q) = nil (silent success, would exit 0); want %q", tc.line, tc.want)
				}
				if err.Error() != tc.want {
					t.Fatalf("dispatchOperational(%q) error = %q, want %q", tc.line, err.Error(), tc.want)
				}
			})
			_ = out
		})
	}
}

// Ambiguous abbreviations under a keyword-only node refuse as
// ambiguous, not as a help listing.
func TestKeywordOnlyAmbiguousRefused16798(t *testing.T) {
	for _, line := range []string{"show s", "show se", "request s", "clear s"} {
		c := &ctl{client: nil}
		err := c.dispatchOperational(line)
		if err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("dispatchOperational(%q) = %v, want ambiguous refusal", line, err)
		}
		if !strings.Contains(err.Error(), strings.Fields(line)[1]) {
			t.Fatalf("dispatchOperational(%q) = %v, want token named", line, err)
		}
	}
}

// Positive/control cells unchanged: bare keyword nodes keep help
// (nil error), lawful commands still reach their handlers, and
// value-slot/leaf failures keep their existing handler errors
// rather than the new unknown-command gate.
func TestKeywordOnlyControlsUnchanged16798(t *testing.T) {
	// Bare nodes: help + nil (interactive `?` equivalent). These
	// canonicalize OK, so the gate must not fire.
	for _, line := range []string{
		"clear", "clear security", "clear dhcp", "clear system",
		"request", "request chassis", "request chassis cluster",
		"request system", "request system software",
		"request system dynamic-dns", "request protocols",
		"request security", "show", "show security", "monitor",
		"test", "?", "help",
	} {
		c := &ctl{client: nil}
		var err error
		captureStdout(t, func() { err = c.dispatchOperational(line) })
		if err != nil {
			t.Fatalf("bare node %q: got %v, want nil (help)", line, err)
		}
	}

	// Unknown top-level verb: pre-existing refusal preserved.
	{
		c := &ctl{client: nil}
		if err := c.dispatchOperational("zzqqbogus"); err == nil || err.Error() != "unknown command: zzqqbogus" {
			t.Fatalf("top-level unknown = %v, want `unknown command: zzqqbogus`", err)
		}
	}

	// Abbreviated lawful command still canonicalizes and is NOT
	// refused by the gate (it reaches the handler; with a nil
	// client that panics on RPC, so assert only that the gate's
	// wording is absent via a fake that records no gate error).
	// `show version` is the control: gate must pass it through.
	{
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		// show version goes through showCommand -> ShowText topic;
		// fake returns empty output without error.
		var err error
		captureStdout(t, func() { err = c.dispatchOperational("show version") })
		if err != nil && strings.Contains(err.Error(), "unknown") {
			t.Fatalf("show version gate-refused: %v", err)
		}
	}
}
