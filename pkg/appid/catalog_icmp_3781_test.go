package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// u8 is a local pointer helper for the ICMP type/code fields (config uses u8p).
func u8(v uint8) *uint8 { return &v }

// icmpRefConfig builds a config whose single policy references every named
// application (predefined names included), so CatalogNames(cfg, false) returns
// exactly that referenced set. Predefined apps (junos-ping, junos-icmp-ping,
// junos-icmp-all) resolve via config.ResolveApplication even though they are not
// in the user Applications map.
func icmpRefConfig(userApps map[string]*config.Application, refs ...string) *config.Config {
	return &config.Config{
		Applications: config.ApplicationsConfig{Applications: userApps},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{Policies: []*config.Policy{{Match: config.PolicyMatch{Applications: refs}}}},
			},
		},
	}
}

// TestBuildCatalogTypeConstrainedICMPDropsOverMatchingRow is the #3781
// fail-on-revert guard for the catalog builder. An ICMP/ICMPv6 application that
// carries a type/code constraint (predefined junos-icmp-ping = icmp type 8, or a
// user-defined app with icmp-type set) MUST NOT ship a protocol-only
// CatalogEntry — that row would match EVERY ICMP type and falsely stamp a
// non-echo ICMP that fell to default-deny with the constrained app label. The
// interim fix drops the row while KEEPING the app_id->name row (AppNames parity
// with compileApplications). Protocol-only ICMP apps (junos-ping,
// junos-icmp-all, a user app with no type) and a non-ICMP app are unaffected.
// Reverting the icmpTypeConstrained guard re-emits junos-icmp-ping's
// over-matching ICMP row and turns this RED.
func TestBuildCatalogTypeConstrainedICMPDropsOverMatchingRow(t *testing.T) {
	cfg := icmpRefConfig(map[string]*config.Application{
		// user-defined type-constrained ICMP app (echo-request only)
		"my-echo": {Name: "my-echo", Protocol: "icmp", ICMPType: u8(8)},
		// user-defined type+code-constrained ICMPv6 app
		"my-na": {Name: "my-na", Protocol: "icmpv6", ICMPType: u8(136), ICMPCode: u8(0)},
		// user-defined protocol-only ICMP app — unaffected
		"my-icmp-any": {Name: "my-icmp-any", Protocol: "icmp"},
		// non-ICMP app — unaffected
		"my-web": {Name: "my-web", Protocol: "tcp", DestinationPort: "80"},
	},
		"junos-icmp-ping", "junos-ping", "junos-pingv6", "junos-icmp-all", "my-echo", "my-na", "my-icmp-any", "my-web")

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	// The type-constrained ICMP apps drop their over-matching row but KEEP the
	// AppNames id (parity contract with compileApplications).
	for _, name := range []string{"junos-icmp-ping", "my-echo", "my-na"} {
		if got := entriesForName(cat, name); len(got) != 0 {
			t.Fatalf("type-constrained ICMP app %q shipped %d catalog row(s) %+v; a protocol-only ICMP row over-matches every type and mislabels non-echo ICMP (#3781)", name, len(got), got)
		}
		if _, ok := appIDForName(cat, name); !ok {
			t.Fatalf("type-constrained ICMP app %q must keep its AppNames row so the app_id sequence stays in lock-step with compileApplications (parity)", name)
		}
	}

	// Protocol-only ICMP/ICMPv6 apps ship protocol-only rows (proto 1/58).
	for _, tc := range []struct {
		name     string
		protocol uint8
	}{
		{"junos-ping", 1},
		{"junos-pingv6", 58},
		{"junos-icmp-all", 1},
		{"my-icmp-any", 1},
	} {
		got := entriesForName(cat, tc.name)
		if len(got) != 1 {
			t.Fatalf("protocol-only ICMP app %q shipped %d rows, want 1", tc.name, len(got))
		}
		if got[0].Protocol != tc.protocol || got[0].DstPortLow != 0 || got[0].DstPortHigh != 0 {
			t.Fatalf("protocol-only ICMP app %q entry = %+v, want protocol=%d ports=0/0",
				tc.name, got[0], tc.protocol)
		}
	}

	// The non-ICMP app is untouched.
	web := entriesForName(cat, "my-web")
	if len(web) != 1 || web[0].Protocol != 6 || web[0].DstPortLow != 80 || web[0].DstPortHigh != 80 {
		t.Fatalf("my-web entry = %+v, want tcp(6) 80/80 (must be unaffected)", web)
	}

	// Every SHIPPED CatalogEntry still resolves to its AppNames row (no
	// stampable entry points at a wrong or missing name).
	for _, e := range cat.Entries {
		if cat.AppNames[e.AppID] != e.Name {
			t.Fatalf("catalog entry app_id=%d name=%q but AppNames[%d]=%q", e.AppID, e.Name, e.AppID, cat.AppNames[e.AppID])
		}
	}
}

// TestBuildCatalogTypeConstrainedICMPHonestUnknown proves the interim's
// guarantee: NO FALSE LABEL. Because the interim does NOT add the deferred
// type/code-aware catalog match, junos-icmp-ping's id is never stamped (its row
// is dropped), so a session carrying an app_id that no shipped entry stamps
// resolves to UNKNOWN via the show path — never to junos-icmp-ping. This is the
// "honest UNKNOWN over a false label" bar; positive echo classification is
// deferred with the wire work.
func TestBuildCatalogTypeConstrainedICMPHonestUnknown(t *testing.T) {
	cfg := icmpRefConfig(nil, "junos-icmp-ping", "junos-ping", "junos-pingv6", "junos-icmp-all")
	cfg.Services.ApplicationIdentification = false // catalog resolution, not fallback

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}

	echoID, ok := appIDForName(cat, "junos-icmp-ping")
	if !ok {
		t.Fatal("junos-icmp-ping must retain an AppNames row for parity")
	}
	// No shipped CatalogEntry carries junos-icmp-ping's id — the helper can
	// never stamp it, so the name is inert (resolves for no live session).
	for _, e := range cat.Entries {
		if e.AppID == echoID {
			t.Fatalf("junos-icmp-ping id=%d has a shipped catalog entry %+v; the interim must ship none so no session is stamped junos-icmp-ping (#3781)", echoID, e)
		}
	}
	// junos-ping is protocol-only in the bounded Junos definitions and therefore
	// keeps its stampable all-ICMP row.
	ping := entriesForName(cat, "junos-ping")
	if len(ping) != 1 || ping[0].Protocol != 1 {
		t.Fatalf("junos-ping entries = %+v, want one protocol-only ICMP row", ping)
	}
	// junos-icmp-all DOES have a stampable protocol-only row.
	icmpAllID, ok := appIDForName(cat, "junos-icmp-all")
	if !ok {
		t.Fatal("junos-icmp-all missing from AppNames")
	}
	stamped := false
	for _, e := range cat.Entries {
		if e.AppID == icmpAllID {
			stamped = true
		}
	}
	if !stamped {
		t.Fatal("junos-icmp-all must keep its protocol-only catalog row (unaffected by the interim)")
	}
}

// TestResolveTupleFallbackSkipsTypeConstrainedICMP is the #3781 fail-on-revert
// guard for the Go display/session-name tuple fallback (AppID-disabled path).
// matchTuple is protocol + port only, so a type-constrained ICMP app would
// otherwise match EVERY ICMP session and false-label it. A non-echo ICMP must
// resolve to a protocol-only ICMP app when one is referenced, or to empty
// (honest UNKNOWN), never to the type-constrained app. Reverting the
// icmpTypeConstrained skip in resolveTupleFallback turns this RED.
func TestResolveTupleFallbackSkipsTypeConstrainedICMP(t *testing.T) {
	// Case 1: only a type-constrained ICMP app is defined. An ICMP session must
	// NOT be labeled with it (no protocol-only fallback to fall back to).
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = false
	cfg.Applications.Applications = map[string]*config.Application{
		"my-echo": {Name: "my-echo", Protocol: "icmp", ICMPType: u8(8)},
	}
	// Non-echo ICMP (type 3 destination-unreachable). srcPort/dstPort are the
	// L4 tuple; ICMP has none, so both are 0. appID 0 (unstamped) forces the
	// tuple fallback.
	if got := ResolveSessionName(nil, cfg, 1, 0, 0, 0); got == "my-echo" {
		t.Fatalf("non-echo ICMP resolved to %q via the tuple fallback; a type-constrained ICMP app must not label arbitrary ICMP (#3781)", got)
	}
	// An echo (type 8) likewise gets no positive label from the interim (that
	// is the deferred type-aware match) — the guarantee is only NO FALSE LABEL.
	if got := ResolveSessionName(nil, cfg, 1, 0, 0, 0); got != "" && got != Unknown {
		t.Fatalf("type-constrained ICMP app produced label %q; the interim renders honest UNKNOWN/empty, not a false or positive label", got)
	}

	// Case 2: a protocol-only ICMP app is also defined. The honest label for any
	// ICMP session is the protocol-only app, NOT the type-constrained one — even
	// though "my-echo" sorts before "my-icmp-any" (the tie-break the revert would
	// otherwise win).
	cfg.Applications.Applications["my-icmp-any"] = &config.Application{Name: "my-icmp-any", Protocol: "icmp"}
	if got := ResolveSessionName(nil, cfg, 1, 0, 0, 0); got != "my-icmp-any" {
		t.Fatalf("ICMP session resolved to %q, want my-icmp-any (protocol-only); the type-constrained my-echo must be skipped (#3781)", got)
	}

	// Case 3: a non-ICMP tuple app is unaffected — tcp/80 still resolves.
	cfg.Applications.Applications["my-web"] = &config.Application{Name: "my-web", Protocol: "tcp", DestinationPort: "80"}
	if got := ResolveSessionName(nil, cfg, 6, 12345, 80, 0); got != "my-web" {
		t.Fatalf("tcp/80 session resolved to %q, want my-web (non-ICMP unaffected)", got)
	}
}
