package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestRouteProtocolSSOTRoundTrip17029 proves every projection of the
// route-protocol vocabulary derives from the one config.RouteProtocols
// table (#17029): each rtproto byte maps to its row's Internal name, each
// Internal name yields its Junos name and (except redirect, whose tag is
// explicitly unassigned per the #17029 parent decision) a terse tag other
// than "?", and every Internal name plus every accept-only alias
// normalizes back to Internal. RED on revert: restoring any hand-maintained
// switch (or dropping a table row/alias) breaks a leg here.
func TestRouteProtocolSSOTRoundTrip17029(t *testing.T) {
	rows := config.RouteProtocols()
	if len(rows) == 0 {
		t.Fatal("RouteProtocols is empty")
	}
	seenInternal := make(map[string]bool)
	seenRTProto := make(map[int]string)
	for _, row := range rows {
		if row.Internal == "" {
			t.Fatalf("row with empty Internal: %+v", row)
		}
		if seenInternal[row.Internal] {
			t.Errorf("duplicate Internal %q", row.Internal)
		}
		seenInternal[row.Internal] = true
		if row.Junos == "" {
			t.Errorf("%s: Junos name is empty", row.Internal)
		}
		if len(row.RTProtos) == 0 {
			t.Errorf("%s: no RTProtos", row.Internal)
		}
		for _, rp := range row.RTProtos {
			if prev, dup := seenRTProto[rp]; dup {
				t.Errorf("rtproto %d claimed by both %s and %s", rp, prev, row.Internal)
			}
			seenRTProto[rp] = row.Internal
			if got := rtProtoName(netlink.RouteProtocol(rp)); got != row.Internal {
				t.Errorf("rtProtoName(%d) = %q, want SSOT Internal %q", rp, got, row.Internal)
			}
		}
		if got := junosProtoName(row.Internal); got != row.Junos {
			t.Errorf("junosProtoName(%q) = %q, want SSOT Junos %q", row.Internal, got, row.Junos)
		}
		// redirect is EXEMPT from the tag criterion (#17029 parent
		// decision): its tag is explicitly unassigned and protoTag
		// keeps rendering "?". Every other row must have a real tag.
		if row.Internal == "redirect" {
			if row.Tag != "" {
				t.Errorf("redirect Tag = %q, want explicitly unassigned (\"\")", row.Tag)
			}
			if got := protoTag(row.Internal); got != "?" {
				t.Errorf("protoTag(%q) = %q, want %q for the unassigned tag", row.Internal, got, "?")
			}
		} else {
			if row.Tag == "" || row.Tag == "?" {
				t.Errorf("%s: Tag = %q, want an assigned terse letter", row.Internal, row.Tag)
			}
			if got := protoTag(row.Internal); got != row.Tag {
				t.Errorf("protoTag(%q) = %q, want SSOT Tag %q", row.Internal, got, row.Tag)
			}
		}
		if got := NormalizeRouteProtocol(row.Internal); got != row.Internal {
			t.Errorf("NormalizeRouteProtocol(%q) = %q, want itself", row.Internal, got)
		}
		for _, alias := range row.Aliases {
			if got := NormalizeRouteProtocol(alias); got != row.Internal {
				t.Errorf("NormalizeRouteProtocol(alias %q) = %q, want %q", alias, got, row.Internal)
			}
		}
	}
	// Preservation spot-pins for spellings the pre-SSOT switches accepted:
	// case/whitespace tolerance and the is-is / access tolerances must keep
	// normalizing exactly as before.
	for token, want := range map[string]string{
		"Access-internal": "dhcp",
		"access_internal": "dhcp",
		"access internal": "dhcp",
		"IS-IS":           "isis",
		" Direct ":        "connected",
		"KERNEL":          "connected",
	} {
		if got := NormalizeRouteProtocol(token); got != want {
			t.Errorf("NormalizeRouteProtocol(%q) = %q, want %q", token, got, want)
		}
	}
	if got := NormalizeRouteProtocol("bogus"); got != "" {
		t.Errorf("NormalizeRouteProtocol(bogus) = %q, want \"\"", got)
	}
	if got := protoTag("bogus"); got != "?" {
		t.Errorf("protoTag(bogus) = %q, want %q", got, "?")
	}
	if got := junosProtoName("bogus"); got != "bogus" {
		t.Errorf("junosProtoName(bogus) = %q, want pass-through %q", got, "bogus")
	}
}

// TestRouteProtocolNamesAreCanonical17029 pins the completion vocabulary:
// canonical Internal tokens only, in table order. Junos spellings
// (access-internal, is-is) and tolerances (access_internal,
// "access internal", direct/local/kernel) are accept-only aliases and
// must never be offered (#17029 parent decision).
func TestRouteProtocolNamesAreCanonical17029(t *testing.T) {
	rows := config.RouteProtocols()
	names := config.RouteProtocolNames()
	if len(names) != len(rows) {
		t.Fatalf("RouteProtocolNames = %v, want one token per SSOT row %v", names, rows)
	}
	for i, row := range rows {
		if names[i] != row.Internal {
			t.Errorf("RouteProtocolNames[%d] = %q, want Internal %q", i, names[i], row.Internal)
		}
		for _, alias := range row.Aliases {
			for _, n := range names {
				if n == alias {
					t.Errorf("completion offers accept-only alias %q (row %s)", alias, row.Internal)
				}
			}
		}
	}
}

// TestRouteProtocolLiteralPins17029 (fold of Rev18085Opus F2): the
// Tag/Junos projections are pinned to LITERAL expectations, not to
// the table they derive from, so a table edit cannot drift both
// sides of the comparison at once.
func TestRouteProtocolLiteralPins17029(t *testing.T) {
	wantTag := map[string]string{
		"redirect": "?", "connected": "C", "dhcp": "D", "static": "S",
		"bgp": "B", "isis": "I", "ospf": "O", "rip": "R",
	}
	wantJunos := map[string]string{
		"redirect": "Redirect", "connected": "Direct", "dhcp": "Access-internal",
		"static": "Static", "bgp": "BGP", "isis": "IS-IS", "ospf": "OSPF", "rip": "RIP",
	}
	for internal, tag := range wantTag {
		if got := protoTag(internal); got != tag {
			t.Errorf("protoTag(%q) = %q, want literal %q", internal, got, tag)
		}
		if got := junosProtoName(internal); got != wantJunos[internal] {
			t.Errorf("junosProtoName(%q) = %q, want literal %q", internal, got, wantJunos[internal])
		}
	}
}
