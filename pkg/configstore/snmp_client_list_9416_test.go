package configstore

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9416: a named SNMP client-list source restriction FAILED OPEN.
//
//	snmp { client-list trusted { 10.0.0.0/8; }
//	       community public { authorization read-only; client-list-name trusted; } }
//
// committed clean on every channel, compiled to an EMPTY allowlist, and
// `AllowsSource` documents an empty allowlist as ALLOW-ALL. The operator
// authored an access restriction and got an agent answering every source.
//
// Every cell below is driven through `configstore.CheckText` — the channel the
// defect was measured on — and every one carries the two controls the issue's
// own table carries, in the SAME run:
//
//	CONTROL B  the inline `clients` spelling of the same intent, which is
//	           enforced (#4289). It proves the enforcement path works, so a
//	           failure in the named row is about the named row.
//	CONTROL C  no restriction authored at all, where allow-all is the CORRECT
//	           answer. Without it, "the named form denies" is satisfiable by
//	           denying everything.
//
// The middle row is the one that matters: A *asked* for a restriction, and
// before this change A and C were byte-identical at runtime.

func snmpText9416(body string) string {
	return "system { host-name fw; }\nsnmp {\n" + body + "\n}\n"
}

func snmpCommunity9416(t *testing.T, text string) *config.SNMPCommunity {
	t.Helper()
	cfg, err := CheckText(text, -1)
	if err != nil {
		t.Fatalf("CheckText: %v\nconfig:\n%s", err, text)
	}
	if cfg.System.SNMP == nil {
		t.Fatalf("no SNMP stanza compiled from:\n%s", text)
	}
	comm := cfg.System.SNMP.Communities["public"]
	if comm == nil {
		t.Fatalf("community not compiled from:\n%s", text)
	}
	return comm
}

func allows9416(t *testing.T, c *config.SNMPCommunity, ip string) bool {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("bad probe address %q", ip)
	}
	if !strings.Contains(ip, ":") {
		parsed = parsed.To4()
	}
	return c.AllowsSource(parsed)
}

// THE THREE-ROW TABLE from the issue, as a test.
func TestSNMPNamedClientListDeniesLikeTheInlineForm9416(t *testing.T) {
	const outsider = "203.0.113.9" // OUTSIDE the intended list
	const insider = "10.1.2.3"     // INSIDE the intended list

	// ROW A — the named spelling. This is the defect.
	a := snmpCommunity9416(t, snmpText9416(
		`    client-list trusted { 10.0.0.0/8; }
    community public { authorization read-only; client-list-name trusted; }`))
	if allows9416(t, a, outsider) {
		t.Errorf("#9416: a named client-list restriction FAILED OPEN — the community answers %s, "+
			"which is outside the list the operator named. Before this change `client-list` and "+
			"`client-list-name` appeared nowhere in pkg/config, so the stanza compiled to an empty "+
			"allowlist and AllowsSource reads an empty allowlist as allow-all", outsider)
	}
	if !allows9416(t, a, insider) {
		t.Errorf("#9416: the named list must still ADMIT %s, which it lists. A cell that only checked "+
			"the denial would pass on a community that denies everything", insider)
	}
	if got := a.ClientListNames; len(got) != 1 || got[0] != "trusted" {
		t.Errorf("the authored reference must be preserved for the reconcile hash and the API surface; got %v", got)
	}

	// CONTROL B — the inline spelling of the SAME intent (#4289, enforced).
	b := snmpCommunity9416(t, snmpText9416(
		`    community public { authorization read-only; clients 10.0.0.0/8; }`))
	if allows9416(t, b, outsider) {
		t.Fatalf("CONTROL B FAILED: the inline `clients` form no longer denies %s. The named-row "+
			"verdict above is uninterpretable without it — re-derive rather than re-run", outsider)
	}
	if !allows9416(t, b, insider) {
		t.Fatalf("CONTROL B FAILED: the inline form no longer admits %s", insider)
	}

	// CONTROL C — no restriction authored; allow-all is CORRECT here.
	c := snmpCommunity9416(t, snmpText9416(
		`    community public { authorization read-only; }`))
	if !allows9416(t, c, outsider) || !allows9416(t, c, insider) {
		t.Error("CONTROL C FAILED: with no restriction authored, allow-all is the correct Junos default. " +
			"If this denies, the fix has made an UNRESTRICTED community deny-all — a availability " +
			"regression wearing the shape of a security fix")
	}

	// A and C were byte-identical at runtime before #9416. They must not be now.
	if allows9416(t, a, outsider) == allows9416(t, c, outsider) {
		t.Error("#9416: the restricted community and the unrestricted one still answer identically for " +
			"an outside source — which is the defect, stated as an equality")
	}
}

// THE SIXTH SPELLING, found by censusing the family instead of fixing the
// fifth. `community <c> routing-instance <ri> { clients ... }` was measured
// fail-open in exactly the same way at the parent of this change.
//
// The verdict is split on purpose, because only half of it is enforceable: the
// SOURCE RESTRICTION is applied (leaving it out means allow-all), and the
// ROUTING-INSTANCE SCOPING is not (the agent binds one socket in the default
// instance) and must therefore be NAMED rather than silently ignored.
func TestSNMPRoutingInstanceScopedRestrictionIsApplied9416(t *testing.T) {
	const outsider = "203.0.113.9"
	const insider = "10.1.2.3"

	for _, body := range []string{
		// inline, inside the routing-instance block
		`    community public { authorization read-only; routing-instance ri1 { clients 10.0.0.0/8; } }`,
		// NAMED, inside the routing-instance block — both spellings of the
		// sixth, because fixing one and not the other is how this family got
		// to six in the first place
		`    client-list trusted { 10.0.0.0/8; }
    community public { authorization read-only; routing-instance ri1 { client-list-name trusted; } }`,
	} {
		text := snmpText9416(body)
		comm := snmpCommunity9416(t, text)
		if allows9416(t, comm, outsider) {
			t.Errorf("#9416 sixth spelling: a routing-instance-scoped restriction FAILED OPEN — the "+
				"community answers %s.\nconfig:\n%s", outsider, text)
		}
		if !allows9416(t, comm, insider) {
			t.Errorf("#9416 sixth spelling: %s is listed and must be admitted.\nconfig:\n%s", insider, text)
		}
		cfg, err := CheckText(text, -1)
		if err != nil {
			t.Fatalf("CheckText: %v", err)
		}
		if !warnsAbout9416(cfg.Warnings, "routing-instance") {
			t.Errorf("#9416: the routing-instance SCOPING is not enforced (one socket, default instance) "+
				"and must be NAMED at commit — silence about an unenforced security scope is the whole "+
				"defect class. warnings=%v", cfg.Warnings)
		}
	}
}

// An UNRESOLVABLE or EMPTY reference must never degrade to allow-all. Strict
// hard-rejects; the tolerant path warns and quarantines to deny-all.
//
// The two arms are asserted TOGETHER because either alone is satisfiable by the
// wrong fix: strict-only would be satisfied by hard-failing the tolerant path
// too (blacking out a booting node, the #1960 doctrine's explicit non-goal),
// and tolerant-only would be satisfied by never rejecting at all.
func TestSNMPUnresolvableClientListNeverAllowsAll9416(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"undefined list", `    community public { authorization read-only; client-list-name nope; }`},
		{"empty list", `    client-list trusted { }
    community public { authorization read-only; client-list-name trusted; }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// STRICT: reject, naming the list (the list name is not a secret;
			// the community string is, and must never appear).
			_, err := CheckText(snmpText9416(tc.body), -1)
			if err == nil {
				t.Fatal("#9416: an unresolvable client-list reference must be REJECTED at strict commit — " +
					"accepting it leaves an empty allowlist, which AllowsSource reads as allow-all, so the " +
					"operator's restriction becomes its exact opposite")
			}
			if !strings.Contains(err.Error(), "client-list-name") {
				t.Errorf("the rejection must name the leaf so the operator can find it: %v", err)
			}
			if strings.Contains(err.Error(), "public") {
				t.Errorf("the community NAME is the secret and must never be echoed: %v", err)
			}
		})
	}
}

// The TOLERANT ingress: a persisted config carrying an unresolvable reference
// must BOOT, and the affected community must be quarantined to deny-all rather
// than left allow-all.
func TestSNMPUnresolvableClientListQuarantinesOnLoad9416(t *testing.T) {
	cfgPath := t.TempDir() + "/config"
	writeStoredConfig(t, cfgPath,
		"set snmp community public authorization read-only",
		"set snmp community public client-list-name nope")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Store.Load must TOLERATE a persisted unresolvable reference — hard-failing here leaves "+
			"the daemon with no active config (operational blackout): %v", err)
	}
	cfg := s.ActiveConfig()
	if cfg == nil || cfg.System.SNMP == nil {
		t.Fatalf("the tolerated config must still compile its SNMP stanza; got %+v", cfg)
	}
	comm := cfg.System.SNMP.Communities["public"]
	if comm == nil {
		t.Fatal("the community must still exist after a tolerated load")
	}
	if comm.AllowsSource(net.ParseIP("203.0.113.9").To4()) || comm.AllowsSource(net.ParseIP("10.1.2.3").To4()) {
		t.Error("#9416: on the tolerant path an unresolvable client-list reference must QUARANTINE the " +
			"community to deny-all (the #5833 shape), not fall through to allow-all. A warning does not " +
			"make an open community safe")
	}

	// CONTROL: the tolerant path is not simply denying every community. One
	// with a RESOLVABLE reference is admitted through the same ingress.
	ctrlPath := t.TempDir() + "/config"
	writeStoredConfig(t, ctrlPath,
		"set snmp client-list trusted 10.0.0.0/8",
		"set snmp community public authorization read-only",
		"set snmp community public client-list-name trusted")
	c := newTestStoreAt(t, ctrlPath)
	if err := c.Load(); err != nil {
		t.Fatalf("CONTROL Store.Load: %v", err)
	}
	ctrl := c.ActiveConfig().System.SNMP.Communities["public"]
	if ctrl == nil {
		t.Fatal("CONTROL: community missing")
	}
	if !ctrl.AllowsSource(net.ParseIP("10.1.2.3").To4()) {
		t.Error("CONTROL: a resolvable reference must admit a listed source through the tolerant ingress")
	}
	if ctrl.AllowsSource(net.ParseIP("203.0.113.9").To4()) {
		t.Error("CONTROL: a resolvable reference must still deny an unlisted source through the tolerant ingress")
	}

	// The next STRICT commit must still reject the stale reference loudly.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := s.CommitCheck(); err == nil {
		t.Error("CommitCheck must stay strict after a tolerated Load")
	}
}

// Ordering must not decide whether the restriction applies: a community may
// reference a list defined AFTER it, and `show configuration` output order is
// not the order a persisted or peer-synced tree was built in.
func TestSNMPClientListResolvesRegardlessOfOrder9416(t *testing.T) {
	before := snmpCommunity9416(t, snmpText9416(
		`    client-list trusted { 10.0.0.0/8; }
    community public { authorization read-only; client-list-name trusted; }`))
	after := snmpCommunity9416(t, snmpText9416(
		`    community public { authorization read-only; client-list-name trusted; }
    client-list trusted { 10.0.0.0/8; }`))
	for _, tc := range []struct {
		name string
		comm *config.SNMPCommunity
	}{{"list first", before}, {"community first", after}} {
		if allows9416(t, tc.comm, "203.0.113.9") {
			t.Errorf("%s: the restriction must apply regardless of stanza order — an ordering the "+
				"operator cannot see must not decide whether a security control is enforced", tc.name)
		}
		if !allows9416(t, tc.comm, "10.1.2.3") {
			t.Errorf("%s: a listed source must be admitted", tc.name)
		}
	}
}

// `restrict` inside a NAMED list behaves exactly as it does inline, because the
// pairing is delegated to parseSNMPClients rather than reimplemented. A named
// list is where a mishandled `restrict` is MOST dangerous: one list backs every
// community that references it.
func TestSNMPNamedClientListHonoursRestrict9416(t *testing.T) {
	comm := snmpCommunity9416(t, snmpText9416(
		`    client-list trusted { 10.0.0.0/8; 10.1.0.0/16 restrict; }
    community public { authorization read-only; client-list-name trusted; }`))
	if !allows9416(t, comm, "10.2.3.4") {
		t.Error("10.2.3.4 is inside 10.0.0.0/8 and outside the restricted /16 — it must be admitted")
	}
	if allows9416(t, comm, "10.1.2.3") {
		t.Error("10.1.2.3 is inside the `restrict` /16, which is longer-prefix than the /8 allow — it must be denied")
	}
	if allows9416(t, comm, "203.0.113.9") {
		t.Error("an unlisted source must be denied")
	}

	// A malformed token in a NAMED list must not degrade to a plain allow.
	// Strict rejects, naming the token AND the list.
	_, err := CheckText(snmpText9416(
		`    client-list trusted { 10.0.0.0/8; 0.0.0.0/0 restric; }
    community public { authorization read-only; client-list-name trusted; }`), -1)
	if err == nil {
		t.Fatal("#9416: a mistyped `restrict` inside a named list must be rejected — it otherwise " +
			"detaches from its prefix and turns `0.0.0.0/0 restrict` into an unrestricted allow, for " +
			"EVERY community referencing the list")
	}
	if !strings.Contains(err.Error(), "client-list") {
		t.Errorf("the rejection must name the list so the operator knows which one: %v", err)
	}
}

// One list, two communities. The resolution is per-community, so a shared list
// must restrict BOTH — a bug that resolved only the first would be invisible in
// every single-community fixture.
func TestSNMPClientListSharedByTwoCommunities9416(t *testing.T) {
	cfg, err := CheckText(snmpText9416(
		`    client-list trusted { 10.0.0.0/8; }
    community public { authorization read-only; client-list-name trusted; }
    community other { authorization read-only; client-list-name trusted; }`), -1)
	if err != nil {
		t.Fatalf("CheckText: %v", err)
	}
	for _, name := range []string{"public", "other"} {
		comm := cfg.System.SNMP.Communities[name]
		if comm == nil {
			t.Fatalf("community %q missing", name)
		}
		if comm.AllowsSource(net.ParseIP("203.0.113.9").To4()) {
			t.Errorf("community %q: a shared client-list must restrict every community that references it", name)
		}
		if !comm.AllowsSource(net.ParseIP("10.1.2.3").To4()) {
			t.Errorf("community %q: a listed source must be admitted", name)
		}
	}
}

func warnsAbout9416(warnings []string, needle string) bool {
	for _, w := range warnings {
		if strings.Contains(w, needle) {
			return true
		}
	}
	return false
}

// FLAT-SET SPELLINGS. The #8939 census cannot probe `snmp community <c>
// routing-instance <ri>` — its synthetic fixture pairs `clients` with
// `client-list-name <synthetic-word>`, which #9416 REJECTS at strict commit as
// an unresolvable reference, so the census records the container as UNMEASURED.
// That is an honest state and not a pass, so the shapes it would have covered
// are driven here instead.
//
// `set` builds a CHAIN and packs its tail onto one node's Keys, so each row
// below is a distinct AST shape rather than a restatement of the braced test
// above: a leaf nested under the previous leaf, and a run of tokens on one node.
func TestSNMPClientListFlatSetSpellings9416(t *testing.T) {
	compile := func(t *testing.T, lines ...string) *config.SNMPCommunity {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, line := range lines {
			p, err := config.ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		if err := config.SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate: %v\nlines: %v", err, lines)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v\nlines: %v", err, lines)
		}
		comm := cfg.System.SNMP.Communities["public"]
		if comm == nil {
			t.Fatalf("community not compiled from %v", lines)
		}
		return comm
	}

	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"named list, separate lines", []string{
			"set snmp client-list trusted 10.0.0.0/8",
			"set snmp community public authorization read-only",
			"set snmp community public client-list-name trusted",
		}},
		{"reference BEFORE authorization on one line (a packed run)", []string{
			"set snmp client-list trusted 10.0.0.0/8",
			"set snmp community public client-list-name trusted authorization read-only",
		}},
		{"bracketed list body", []string{
			"set snmp client-list trusted [ 10.0.0.0/8 172.16.0.0/12 ]",
			"set snmp community public authorization read-only",
			"set snmp community public client-list-name trusted",
		}},
		{"list built by repeated set lines", []string{
			"set snmp client-list trusted 10.0.0.0/8",
			"set snmp client-list trusted 172.16.0.0/12",
			"set snmp community public authorization read-only",
			"set snmp community public client-list-name trusted",
		}},
		{"routing-instance scoped, inline", []string{
			"set snmp community public authorization read-only",
			"set snmp community public routing-instance ri1 clients 10.0.0.0/8",
		}},
		{"routing-instance scoped, named", []string{
			"set snmp client-list trusted 10.0.0.0/8",
			"set snmp community public authorization read-only",
			"set snmp community public routing-instance ri1 client-list-name trusted",
		}},
		{"routing-instance clients bracketed", []string{
			"set snmp community public authorization read-only",
			"set snmp community public routing-instance ri1 clients [ 10.0.0.0/8 172.16.0.0/12 ]",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			comm := compile(t, tc.lines...)
			if comm.AllowsSource(net.ParseIP("203.0.113.9").To4()) {
				t.Errorf("#9416: the restriction was lost in this spelling — 203.0.113.9 is outside "+
					"every prefix authored, and an empty allowlist reads as allow-all.\nlines: %v", tc.lines)
			}
			if !comm.AllowsSource(net.ParseIP("10.1.2.3").To4()) {
				t.Errorf("#9416: 10.1.2.3 is listed and must be admitted.\nlines: %v", tc.lines)
			}
		})
	}

	// The bracketed / repeated rows above must actually carry BOTH prefixes,
	// not just the first: `203.0.113.9 denied` is satisfied by an allowlist
	// holding only 10.0.0.0/8, so the second value needs its own probe. This is
	// the #2419 bracketed-list collapse, at a leaf that gates SNMP access.
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"bracketed", []string{
			"set snmp client-list trusted [ 10.0.0.0/8 172.16.0.0/12 ]",
			"set snmp community public authorization read-only",
			"set snmp community public client-list-name trusted",
		}},
		{"repeated set lines", []string{
			"set snmp client-list trusted 10.0.0.0/8",
			"set snmp client-list trusted 172.16.0.0/12",
			"set snmp community public authorization read-only",
			"set snmp community public client-list-name trusted",
		}},
		{"routing-instance bracketed", []string{
			"set snmp community public authorization read-only",
			"set snmp community public routing-instance ri1 clients [ 10.0.0.0/8 172.16.0.0/12 ]",
		}},
	} {
		t.Run(tc.name+" keeps EVERY value", func(t *testing.T) {
			comm := compile(t, tc.lines...)
			if !comm.AllowsSource(net.ParseIP("10.1.2.3").To4()) {
				t.Errorf("the FIRST prefix was lost.\nlines: %v", tc.lines)
			}
			if !comm.AllowsSource(net.ParseIP("172.16.5.5").To4()) {
				t.Errorf("#2419: the SECOND value of the list was dropped — reading only the first "+
					"value of a multi-value leaf is the collapse class, and here it narrows an SNMP "+
					"allowlist below what the operator authored.\nlines: %v", tc.lines)
			}
		})
	}
}
