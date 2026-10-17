package config

import (
	"strings"
	"testing"
)

// snmpv3_packed_protocols_14411_test.go — #14411 (DR13-H4).
//
// Three hierarchical-text placements compiled to a WEAKER SNMPv3 USM security
// level than written, with no commit error and no warning:
//
// (i) PACKED multi-protocol line — parseSNMPv3UserKeys switched on keys[0]
//     only and never looped, so the second (privacy) protocol on
//     `user alice authentication-sha256 authentication-password A
//     privacy-aes128 privacy-password P;` was dropped: the operator
//     configured authPriv and the agent served authNoPriv (cleartext).
// (ii) CASE-VARIANT keyword — `Authentication-SHA256` fails the #9155 gate's
//     exact-lowercase prefix test and the parser's exact-case switch, so the
//     whole stanza compiled to a bare noAuthNoPriv user.
// (iii) WRAPPED / ANCESTOR placement — `authentication { ... }` inside the
//     user, or a protocol block placed under local-engine beside the user:
//     the gate scanned only the user node's own Keys and its direct
//     children's Keys, so the keyword was never seen and the user compiled
//     bare.
//
// Every placement must now either compile the intended protocol(s) or be
// rejected at strict commit. No placement may compile weaker than written.

func compile14411(t *testing.T, src string) (*Config, error) {
	t.Helper()
	p := NewParser("snmp { v3 { usm { local-engine { " + src + " } } } }")
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfig(tree)
}

func user14411(t *testing.T, cfg *Config, name string) *SNMPv3User {
	t.Helper()
	if cfg == nil || cfg.System.SNMP == nil || cfg.System.SNMP.V3Users[name] == nil {
		t.Fatalf("user %q did not compile at all", name)
	}
	return cfg.System.SNMP.V3Users[name]
}

// (i) PACKED auth-first: both protocols must compile (authPriv).
func TestPackedAuthFirstCompilesAuthPriv14411(t *testing.T) {
	cfg, err := compile14411(t,
		`user alice authentication-sha256 authentication-password APASS privacy-aes128 privacy-password PPASS;`)
	if err != nil {
		t.Fatalf("packed authPriv user was rejected: %v", err)
	}
	u := user14411(t, cfg, "alice")
	if u.AuthProtocol != "sha256" || string(u.AuthPassword) != "APASS" {
		t.Fatalf("auth half wrong: auth=%q authpw set=%v", u.AuthProtocol, string(u.AuthPassword) != "")
	}
	if u.PrivProtocol != "aes128" || string(u.PrivPassword) != "PPASS" {
		t.Fatalf("packed second (privacy) protocol was dropped: priv=%q privpw set=%v — the user compiles authNoPriv while written authPriv",
			u.PrivProtocol, string(u.PrivPassword) != "")
	}
}

// (i) PACKED priv-first: privacy protocol must compile too. With both
// protocols and passwords present the user is a legitimate authPriv user and
// must commit (pre-fix the single-shot parser read only the privacy half and
// the #7530 privacy-without-auth arm rejected it; compiling both halves is
// the intended reading).
func TestPackedPrivFirstCompilesAuthPriv14411(t *testing.T) {
	cfg, err := compile14411(t,
		`user alice privacy-aes128 privacy-password PPASS authentication-sha256 authentication-password APASS;`)
	if err != nil {
		t.Fatalf("packed priv-first authPriv user was rejected: %v", err)
	}
	u := user14411(t, cfg, "alice")
	if u.AuthProtocol != "sha256" || string(u.AuthPassword) != "APASS" ||
		u.PrivProtocol != "aes128" || string(u.PrivPassword) != "PPASS" {
		t.Fatalf("packed priv-first user compiled weaker/differently than written: auth=%q priv=%q", u.AuthProtocol, u.PrivProtocol)
	}
}

// The packed run is also what the flat `set` line packs onto the v3 node's
// own Keys (compileSNMPv3's flat branch, node.Keys[5:]) and onto a hierarchical
// user's own instance line (child.Keys[2:]): both pass the whole remaining run
// to parseSNMPv3UserKeys, so both must compile both protocols.
func TestPackedRunOnFlatAndInstanceLines14411(t *testing.T) {
	t.Run("flat v3 line", func(t *testing.T) {
		p := NewParser(`snmp v3 usm local-engine user bob authentication-sha256 authentication-password APASS privacy-aes128 privacy-password PPASS;`)
		tree, perr := p.Parse()
		if perr != nil {
			t.Fatalf("parse: %v", perr)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("flat packed authPriv user was rejected: %v", err)
		}
		u := user14411(t, cfg, "bob")
		if u.PrivProtocol != "aes128" || string(u.PrivPassword) != "PPASS" {
			t.Fatalf("flat packed second protocol dropped: priv=%q", u.PrivProtocol)
		}
	})
	t.Run("hierarchical instance line", func(t *testing.T) {
		cfg, err := compile14411(t,
			`user carol authentication-sha authentication-password APASS privacy-des privacy-password PPASS;`)
		if err != nil {
			t.Fatalf("instance-line packed user was rejected: %v", err)
		}
		u := user14411(t, cfg, "carol")
		if u.AuthProtocol != "sha" || u.PrivProtocol != "des" || string(u.PrivPassword) != "PPASS" {
			t.Fatalf("instance-line packed user compiled weaker than written: auth=%q priv=%q", u.AuthProtocol, u.PrivProtocol)
		}
	})
}

// A password VALUE that happens to spell a protocol keyword must be consumed
// as a value, never re-parsed as a keyword (the parser steps over each whole
// protocol pair). If the trailing stray keyword were re-parsed it would name
// a protocol with no material and the #7530 gate would reject; a value must
// not have that effect.
func TestPackedPasswordValueSpellingAKeywordIsNotReparsed14411(t *testing.T) {
	cfg, err := compile14411(t,
		`user dave authentication-sha256 authentication-password privacy-aes128;`)
	if err != nil {
		t.Fatalf("password value spelling a keyword was rejected: %v", err)
	}
	u := user14411(t, cfg, "dave")
	if string(u.AuthPassword) != "privacy-aes128" || u.PrivProtocol != "" {
		t.Fatalf("password value was re-parsed as a protocol keyword: authpw=%q priv=%q", string(u.AuthPassword), u.PrivProtocol)
	}
}

// (ii) CASE-VARIANT: strict commit must reject, naming the token. Compiling
// it case-insensitively would also satisfy the criterion, but the gate is
// reject-only by design (#9155) — a case-variant is not a known keyword.
func TestCaseVariantProtocolRejected14411(t *testing.T) {
	_, err := compile14411(t,
		`user alice { Authentication-SHA256 { authentication-password APASS; } privacy-aes128 { privacy-password PPASS; } }`)
	if err == nil {
		t.Fatal("case-variant Authentication-SHA256 committed clean and compiled to a weaker level than written (bare noAuthNoPriv user)")
	}
	if !strings.Contains(err.Error(), "Authentication-SHA256") {
		t.Errorf("rejection does not name the case-variant token: %v", err)
	}
	// Privacy side, packed onto the user line: the case-variant token rides
	// the user node's own Keys, which the gate must also scan case-insensitively.
	_, err = compile14411(t,
		`user alice authentication-sha256 authentication-password APASS Privacy-AES128 privacy-password PPASS;`)
	if err == nil {
		t.Fatal("packed case-variant Privacy-AES128 committed clean")
	}
	if !strings.Contains(err.Error(), "Privacy-AES128") {
		t.Errorf("packed rejection does not name the case-variant token: %v", err)
	}
}

// (iii) WRAPPED: a protocol keyword inside a wrapper container under the user
// must be rejected at strict commit (the gate recurses the user subtree).
func TestWrappedProtocolKeywordRejected14411(t *testing.T) {
	_, err := compile14411(t,
		`user alice { authentication { authentication-sha256 { authentication-password APASS; } } }`)
	if err == nil {
		t.Fatal("wrapped authentication-sha256 committed clean and compiled to a bare noAuthNoPriv user")
	}
	if !strings.Contains(err.Error(), "authentication-sha256") {
		t.Errorf("rejection does not name the wrapped token: %v", err)
	}
}

// (iii) ANCESTOR: a protocol keyword placed under local-engine beside the
// user (outside any user node) must be rejected at strict commit.
func TestAncestorProtocolKeywordRejected14411(t *testing.T) {
	p := NewParser(`snmp { v3 { usm { local-engine { authentication-sha256 { authentication-password APASS; } user alice; } } } }`)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("ancestor-level authentication-sha256 committed clean; the user compiled bare")
	}
	if !strings.Contains(err.Error(), "authentication-sha256") {
		t.Errorf("rejection does not name the ancestor token: %v", err)
	}
	// Ancestor packed onto the local-engine line itself.
	p2 := NewParser(`snmp { v3 { usm { local-engine privacy-aes128 privacy-password PPASS; } } }`)
	tree2, perr2 := p2.Parse()
	if perr2 != nil {
		t.Fatalf("parse: %v", perr2)
	}
	if _, err := CompileConfig(tree2); err == nil {
		t.Fatal("protocol keyword packed onto the local-engine line committed clean")
	}
}

// The wrapped placement compiles at the WRITTEN level on the tolerant path:
// a persisted wrapped config must not silently serve a bare user while
// `show configuration` reads authenticated (#1960-safe direction).
func TestWrappedPlacementCompilesWrittenLevelLenient14411(t *testing.T) {
	p := NewParser(`snmp { v3 { usm { local-engine { user alice { authentication { authentication-sha256 { authentication-password APASS; } privacy-aes128 { privacy-password PPASS; } } } } } } }`)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path rejected the wrapped config: %v", err)
	}
	u := user14411(t, cfg, "alice")
	if u.AuthProtocol != "sha256" || string(u.AuthPassword) != "APASS" ||
		u.PrivProtocol != "aes128" || string(u.PrivPassword) != "PPASS" {
		t.Fatalf("wrapped user compiled weaker than written on the tolerant path: auth=%q priv=%q", u.AuthProtocol, u.PrivProtocol)
	}
}

// The packed flat `set` line — the run packed onto the v3 node's own Keys —
// is a legitimate placement the compiler reads via its flat branch; it must
// NOT be rejected as misplaced. (Regression cell for the gate's packed-run
// handling: a token-level scan that cannot tell a packed run from a braced
// misplaced block rejects every flat-set authPriv user.)
func TestFlatLinePackedRunIsNotMisplaced14411(t *testing.T) {
	p := NewParser(`snmp v3 usm local-engine user alice authentication-sha256 authentication-password APASS privacy-aes128 privacy-password PPASS;`)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("packed flat line rejected as misplaced: %v", err)
	}
	u := user14411(t, cfg, "alice")
	if u.PrivProtocol != "aes128" || string(u.PrivPassword) != "PPASS" {
		t.Fatalf("packed flat line compiled weaker than written: priv=%q", u.PrivProtocol)
	}
}

func TestProtocolKeywordUnderV3OrUsmRejected14411(t *testing.T) {
	for _, src := range []string{
		`snmp { v3 { authentication-sha256 { authentication-password APASS; } usm { local-engine { user alice; } } } }`,
		`snmp { v3 { usm privacy-aes128 privacy-password PPASS; } }`,
	} {
		p := NewParser(src)
		tree, perr := p.Parse()
		if perr != nil {
			t.Fatalf("parse %q: %v", src, perr)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("misplaced protocol keyword committed clean: %s", src)
		}
	}
}

// REFERENCE / CONTROL arms: shapes that compiled correctly before must keep
// compiling identically — braced, compact-braced, single-protocol packed, and
// a genuine no-protocol user.
func TestValidSNMPv3ShapesStillCompile14411(t *testing.T) {
	t.Run("braced authPriv", func(t *testing.T) {
		cfg, err := compile14411(t,
			`user alice { authentication-sha256 { authentication-password APASS; } privacy-aes128 { privacy-password PPASS; } }`)
		if err != nil {
			t.Fatalf("braced authPriv rejected: %v", err)
		}
		u := user14411(t, cfg, "alice")
		if u.AuthProtocol != "sha256" || u.PrivProtocol != "aes128" {
			t.Fatalf("braced authPriv compiled wrong: auth=%q priv=%q", u.AuthProtocol, u.PrivProtocol)
		}
	})
	t.Run("packed auth only stays authNoPriv", func(t *testing.T) {
		cfg, err := compile14411(t, `user alice authentication-md5 authentication-password APASS;`)
		if err != nil {
			t.Fatalf("packed auth-only rejected: %v", err)
		}
		u := user14411(t, cfg, "alice")
		if u.AuthProtocol != "md5" || u.PrivProtocol != "" {
			t.Fatalf("packed auth-only compiled wrong: auth=%q priv=%q", u.AuthProtocol, u.PrivProtocol)
		}
	})
	t.Run("no protocol is a legitimate bare user", func(t *testing.T) {
		cfg, err := compile14411(t, `user alice { }`)
		if err != nil {
			t.Fatalf("genuine noAuthNoPriv user rejected: %v", err)
		}
		u := user14411(t, cfg, "alice")
		if u.AuthProtocol != "" || u.PrivProtocol != "" {
			t.Fatalf("bare user gained a protocol: auth=%q priv=%q", u.AuthProtocol, u.PrivProtocol)
		}
	})
	// Matched-family control: no SNMP at all must not be rejected by the gate.
	t.Run("no snmp", func(t *testing.T) {
		p := NewParser(`system { host-name fw0; }`)
		tree, perr := p.Parse()
		if perr != nil {
			t.Fatalf("parse: %v", perr)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("config without snmp rejected: %v", err)
		}
	})
	// The tolerant path must still ACCEPT these placements with a warning
	// (#1960 no-brick); the strict verdicts above must not brick loading.
	t.Run("lenient still boots with warning", func(t *testing.T) {
		p := NewParser(`snmp { v3 { usm { local-engine { user alice { Authentication-SHA256 { authentication-password APASS; } } } } } }`)
		tree, perr := p.Parse()
		if perr != nil {
			t.Fatalf("parse: %v", perr)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant path rejected a persisted config: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "snmpv3 security keyword") {
				found = true
			}
		}
		if !found {
			t.Errorf("tolerant path accepted the case-variant with no warning; warnings: %v", cfg.Warnings)
		}
	})
}

// A bare password leaf directly under the user (`user alice { privacy-password
// P; }`) is #14401's shape, gated by its own gate on master. Retained here as
// a control that the #14411 gate does not let it through either path: strict
// must reject (via #14401) rather than sit silently beside a bare user.
func TestBarePasswordLeafUnderUserRejected14411(t *testing.T) {
	for _, body := range []string{
		`user alice { privacy-password PPASS; }`,
		`user alice { authentication-password APASS; }`,
	} {
		_, err := compile14411(t, body)
		if err == nil {
			t.Fatalf("bare password leaf committed clean: %s", body)
		}
		if !strings.Contains(err.Error(), "password") {
			t.Errorf("rejection does not name the password leaf: %v", err)
		}
	}
}

// The same user reached through a `system { snmp { … } }` wrapper (the
// compiler dispatches it via compileSystem's snmp child) must be gated
// exactly like the top-level `snmp { … }` spelling.
func TestSystemWrappedSNMPv3UserIsGated14411(t *testing.T) {
	p := NewParser(`system { snmp { v3 { usm { local-engine { user alice { Authentication-SHA256 { authentication-password APASS; } } } } } } }`)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("system-wrapped case-variant committed clean; the user compiled bare")
	}
	// Control: the valid spelling under system must still compile.
	p2 := NewParser(`system { snmp { v3 { usm { local-engine { user alice { authentication-sha256 { authentication-password APASS; } } } } } } }`)
	tree2, perr2 := p2.Parse()
	if perr2 != nil {
		t.Fatalf("parse: %v", perr2)
	}
	cfg, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("system-wrapped valid user rejected: %v", err)
	}
	if u := cfg.System.SNMP.V3Users["alice"]; u == nil || u.AuthProtocol != "sha256" {
		t.Fatalf("system-wrapped valid user compiled wrong: %+v", u)
	}
}

// compileSNMP iterates EVERY `v3` child of an snmp root; the gate must too.
// A case-variant user in the SECOND v3 block must reject, not slip past a
// first-block-only gate.
func TestSecondV3BlockIsGated14411(t *testing.T) {
	p := NewParser(`snmp { v3 { usm { local-engine { user alice { authentication-sha256 { authentication-password APASS; } } } } } v3 { usm { local-engine { user bob { Authentication-SHA256 { authentication-password BPASS; } } } } } }`)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("case-variant in second v3 block committed clean")
	}
}

// The brace-elided `system snmp …` form packs the path onto the system
// node's own Keys; compileSystem synthesises the snmp node from it, and
// the gate must see that synthesised root too.
func TestSystemElidedSNMPIsGated14411(t *testing.T) {
	p := NewParser(`system snmp v3 usm local-engine user alice Authentication-SHA256 authentication-password APASS;`)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("system-elided case-variant committed clean")
	}
}

// The top-level flat form (`snmp v3 usm local-engine user <name> <run>;`)
// packs the user onto the snmp node's own Keys, where compileSNMPv3's flat
// branch reads it. A case-variant there must reject, and an unknown
// protocol there must reject — neither may compile to a bare user.
func TestTopLevelFlatCaseVariantAndUnknownRejected14411(t *testing.T) {
	for _, src := range []string{
		`snmp v3 usm local-engine user alice Authentication-SHA256 authentication-password APASS;`,
		`snmp v3 usm local-engine user alice authentication-sha512 authentication-password APASS;`,
	} {
		p := NewParser(src)
		tree, perr := p.Parse()
		if perr != nil {
			t.Fatalf("parse %q: %v", src, perr)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("top-level flat bad protocol committed clean: %s", src)
		}
	}
}
