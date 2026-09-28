// #6692: four `system`-stanza leaves that setSchema declares `multi: true` were
// read with a single-value accessor, so a bracketed list — which the lexer
// collapses onto ONE node's Keys — compiled its first member and silently
// dropped the rest:
//
//	system archival configuration archive-sites      first site only
//	system services ssh key-exchange                 first (often WEAKER) method only
//	system services web-management api-auth api-key  first key only
//	system dataplane shared-umem interface           first interface only
//
// Three of the four share one defect shape and one repair (read both sides of
// the AST). `archive-sites` does NOT: its value tail interleaves a `password
// <secret>` MODIFIER with the site URLs, so accumulating the whole tail would
// PROMOTE the keyword and the secret into ArchiveSites and hand them to
// `scp <src> <dest>` as arguments (#6673's symmetric hazard, called out by name
// in the pre-fix comment at that site). It needs a grouping reader, which is
// what archiveSiteEntries is.
//
// These tests assert the compiled SLICE CONTENTS, in order, in every spelling —
// not the length, which a reader that installs the same value twice would also
// satisfy.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath, never NewParser.
package config

import (
	"reflect"
	"strings"
	"testing"
)

// sixNineTwoSpellings compiles the same two-value list authored at
// hierPath+leaf in every spelling the Junos grammar admits, and returns the
// compiled config per spelling name. A compiler that reads one side of the AST
// disagrees with itself across these; a correct one does not.
func sixNineTwoSpellings(t *testing.T, hierPath []string, leaf, v1, v2 string) map[string]*Config {
	t.Helper()

	brace := func(stmt string) string {
		var b strings.Builder
		for _, tok := range hierPath {
			b.WriteString(tok)
			b.WriteString(" { ")
		}
		b.WriteString(stmt)
		for range hierPath {
			b.WriteString(" }")
		}
		return b.String()
	}
	compileBrace := func(name, body string) *Config {
		t.Helper()
		p := NewParser(body)
		tree, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("%s: parse %q: %v", name, body, errs)
		}
		if err := addAPITestExpiry(tree, hierPath); err != nil {
			t.Fatal(err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("%s: CompileConfig(%q): %v", name, body, err)
		}
		return cfg
	}
	compileSet := func(name string, cmds ...string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			path, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("%s: ParseSetCommand(%q): %v", name, c, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("%s: SetPath(%q): %v", name, c, err)
			}
		}
		if err := addAPITestExpiry(tree, hierPath); err != nil {
			t.Fatal(err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("%s: CompileConfig(%v): %v", name, cmds, err)
		}
		return cfg
	}
	flat := "set " + strings.Join(hierPath, " ") + " " + leaf
	return map[string]*Config{
		"A-hier-bracket": compileBrace("A-hier-bracket", brace(leaf+" [ "+v1+" "+v2+" ];")),
		"B-hier-block":   compileBrace("B-hier-block", brace(leaf+" { "+v1+"; "+v2+"; }")),
		"C-hier-repeat":  compileBrace("C-hier-repeat", brace(leaf+" "+v1+"; "+leaf+" "+v2+";")),
		"D-set-bracket":  compileSet("D-set-bracket", flat+" [ "+v1+" "+v2+" ]"),
		"E-set-repeat":   compileSet("E-set-repeat", flat+" "+v1, flat+" "+v2),
	}
}
func addAPITestExpiry(tree *ConfigTree, hierPath []string) error {
	if strings.Join(hierPath, " ") != "system services web-management api-auth" {
		return nil
	}
	path := append(append([]string(nil), hierPath...), "expires", "2099-01-01")
	return tree.SetPath(path)
}

// assertSliceEverySpelling checks the extracted slice EQUALS want in every
// spelling. RED-on-revert: the single-value read returns want[:1] for the
// bracket spellings (and, for the leaves whose block shape was also unread,
// nothing at all).
func assertSliceEverySpelling(t *testing.T, cfgs map[string]*Config, want []string, get func(*Config) []string) {
	t.Helper()
	for name, cfg := range cfgs {
		got := get(cfg)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: compiled %v, want %v (RED-on-revert: the single-value read keeps slot 0 alone)",
				name, got, want)
		}
	}
}

func TestArchiveSitesMultiValue_6692(t *testing.T) {
	cfgs := sixNineTwoSpellings(t,
		[]string{"system", "archival", "configuration"}, "archive-sites",
		`"scp://backup-a/cfg"`, `"scp://backup-b/cfg"`)
	assertSliceEverySpelling(t, cfgs,
		[]string{"scp://backup-a/cfg", "scp://backup-b/cfg"},
		func(c *Config) []string {
			if c.System.Archival == nil {
				return nil
			}
			return c.System.Archival.ArchiveSites
		})
}

// TestArchiveSitesPasswordIsNotASite_6692 is the #6673 promotion guard: the
// widened read must separate the `password <secret>` MODIFIER from the site
// URLs. If the tail were accumulated wholesale, "password" and the secret
// itself would land in ArchiveSites and be passed to `scp` as arguments.
func TestArchiveSitesPasswordIsNotASite_6692(t *testing.T) {
	cases := []struct {
		name     string
		build    func(t *testing.T) *ConfigTree
		wantSite []string
		wantPw   []string
	}{
		{
			name: "flat-set-password-on-keys",
			build: func(t *testing.T) *ConfigTree {
				return buildTreeFromSet(t, []string{
					`set system archival configuration archive-sites "scp://a/cfg" password "$9$secret"`,
				})
			},
			wantSite: []string{"scp://a/cfg"},
			wantPw:   []string{"scp://a/cfg"},
		},
		{
			name: "flat-set-password-with-no-operand",
			build: func(t *testing.T) *ConfigTree {
				return buildTreeFromSet(t, []string{
					`set system archival configuration archive-sites "scp://a/cfg" password`,
				})
			},
			wantSite: []string{"scp://a/cfg"},
			wantPw:   []string{"scp://a/cfg"},
		},
		{
			name: "bracket-list-carries-no-password",
			build: func(t *testing.T) *ConfigTree {
				return buildTreeFromSet(t, []string{
					`set system archival configuration archive-sites [ "scp://a/cfg" "scp://b/cfg" ]`,
				})
			},
			wantSite: []string{"scp://a/cfg", "scp://b/cfg"},
			wantPw:   nil,
		},
		{
			name: "hier-block-per-site-password",
			build: func(t *testing.T) *ConfigTree {
				p := NewParser(`system { archival { configuration { archive-sites {` +
					` "scp://a/cfg" password "$9$secret"; "scp://b/cfg"; } } } }`)
				tree, errs := p.Parse()
				if len(errs) > 0 {
					t.Fatalf("parse: %v", errs)
				}
				return tree
			},
			wantSite: []string{"scp://a/cfg", "scp://b/cfg"},
			wantPw:   []string{"scp://a/cfg"},
		},
		{
			name: "hier-nested-password-block",
			build: func(t *testing.T) *ConfigTree {
				p := NewParser(`system { archival { configuration { archive-sites {` +
					` "scp://a/cfg" { password "$9$secret"; } } } } }`)
				tree, errs := p.Parse()
				if len(errs) > 0 {
					t.Fatalf("parse: %v", errs)
				}
				return tree
			},
			wantSite: []string{"scp://a/cfg"},
			wantPw:   []string{"scp://a/cfg"},
		},
		{
			name: "hier-value-on-keys-password-child",
			build: func(t *testing.T) *ConfigTree {
				p := NewParser(`system { archival { configuration { archive-sites "scp://a/cfg"` +
					` { password "$9$secret"; } } } }`)
				tree, errs := p.Parse()
				if len(errs) > 0 {
					t.Fatalf("parse: %v", errs)
				}
				return tree
			},
			wantSite: []string{"scp://a/cfg"},
			wantPw:   []string{"scp://a/cfg"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build(t))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			arch := cfg.System.Archival
			if arch == nil {
				t.Fatal("no archival config compiled")
			}
			if !reflect.DeepEqual(arch.ArchiveSites, tc.wantSite) {
				t.Errorf("ArchiveSites = %v, want %v — `password` and its secret "+
					"must never be promoted to a site (they reach scp as arguments)",
					arch.ArchiveSites, tc.wantSite)
			}
			if !reflect.DeepEqual(arch.ArchiveSitesWithPassword, tc.wantPw) {
				t.Errorf("ArchiveSitesWithPassword = %v, want %v",
					arch.ArchiveSitesWithPassword, tc.wantPw)
			}
		})
	}
}

// TestArchiveSitesLeadingDashGateCoversEverySite_6692 closes the gate ESCAPE the
// pre-fix comment documented: the #4589 leading-dash check ran on slot 1 alone,
// so a `-oProxyCommand=` member authored anywhere past the first was dropped
// AND unchecked — the bracket form ACCEPTED what the same token authored alone
// REJECTED. A widened read without a widened gate would have turned that inert
// escape into a live CWE-88 argv injection.
func TestArchiveSitesLeadingDashGateCoversEverySite_6692(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"bracket-second-slot", []string{
			`set system archival configuration archive-sites [ "scp://ok/cfg" "-oProxyCommand=id" ]`}},
		{"bracket-third-slot", []string{
			`set system archival configuration archive-sites [ "scp://ok/cfg" "scp://ok2/cfg" "-oProxyCommand=id" ]`}},
		{"repeated-second-line", []string{
			`set system archival configuration archive-sites "scp://ok/cfg"`,
			`set system archival configuration archive-sites "-oProxyCommand=id"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTreeFromSet(t, tc.cmds))
			if err == nil {
				t.Fatal("CompileConfig accepted a leading-dash archive-site past slot 0; " +
					"the #4589 gate must run over EVERY authored site")
			}
			if !strings.Contains(err.Error(), "must not begin with '-'") {
				t.Fatalf("error %q missing the leading-dash reason", err.Error())
			}
		})
	}
}

func TestSSHKeyExchangeMultiValue_6692(t *testing.T) {
	cfgs := sixNineTwoSpellings(t,
		[]string{"system", "services", "ssh"}, "key-exchange",
		"diffie-hellman-group14-sha1", "curve25519-sha256")
	assertSliceEverySpelling(t, cfgs,
		[]string{"diffie-hellman-group14-sha1", "curve25519-sha256"},
		func(c *Config) []string {
			if c.System.Services == nil || c.System.Services.SSH == nil {
				return nil
			}
			return c.System.Services.SSH.KeyExchange
		})
}

// TestSSHKeyExchangeValidatorCoversEverySlot_6692 is the widened-read/unwidened-
// validator guard the issue asks for. The key-exchange list is comma-joined into
// a sshd `KexAlgorithms` line (#4902), so a value carrying a space or a newline
// smuggles a second sshd directive. validateMultiValueLeaf must run
// ValidateSSHAlgorithm over EVERY authored slot, not slot 0 — otherwise widening
// the compiler's read turns a silent truncation into silent propagation.
func TestSSHKeyExchangeValidatorCoversEverySlot_6692(t *testing.T) {
	reject := [][]string{
		{`set system services ssh key-exchange [ curve25519-sha256 "curve25519 sha256" ]`},
		{`set system services ssh key-exchange [ curve25519-sha256 "kex\nPermitRootLogin yes" ]`},
		{`set system services ssh key-exchange curve25519-sha256`,
			`set system services ssh key-exchange "curve25519 sha256"`},
	}
	for _, cmds := range reject {
		tree := buildTreeFromSet(t, cmds)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Errorf("SchemaValidate accepted %v; a malformed algorithm name in a "+
				"non-zero slot must be rejected", cmds)
		}
	}
	// Over-reject control: a well-formed list in the same shape is accepted.
	ok := buildTreeFromSet(t, []string{
		`set system services ssh key-exchange [ curve25519-sha256 diffie-hellman-group-exchange-sha256 ]`,
	})
	if err := SchemaValidate(ok, nil); err != nil {
		t.Errorf("SchemaValidate rejected a well-formed key-exchange list: %v", err)
	}
}

func TestAPIKeyMultiValue_6692(t *testing.T) {
	const (
		keyA = "machine-generated-key-alpha"
		keyB = "machine-generated-key-bravo"
	)
	cfgs := sixNineTwoSpellings(t,
		[]string{"system", "services", "web-management", "api-auth"}, "api-key",
		keyA, keyB)
	for spelling, cfg := range cfgs {
		auth := cfg.System.Services.WebManagement.APIAuth
		if auth == nil || len(auth.APIKeys) != 2 {
			t.Errorf("%s: got APIAuth=%+v, want two keys", spelling, auth)
			continue
		}
		if !VerifyAPIAuthSecret(auth.APIKeys[0].Reveal(), keyA) ||
			!VerifyAPIAuthSecret(auth.APIKeys[1].Reveal(), keyB) {
			t.Errorf("%s: API-key list did not preserve both usable verifiers", spelling)
		}
	}
}

// TestAPIKeyEmptySecretGateSeesEverySlot_6692 pins WHY api-key uses
// multiLeafAuthoredValues and not firewallMatchValues: an EMPTY value is
// load-bearing on this leaf. A quoted-empty `api-key ""` authenticates any
// request presenting the empty token, so validateAPIAuthNoEmptySecretsStrict
// hard-rejects it (#5636). A reader that skipped empty tokens would make an
// empty key in a non-zero slot VANISH instead — silently withdrawing an
// operator-visible security rejection.
func TestAPIKeyEmptySecretGateSeesEverySlot_6692(t *testing.T) {
	// The BRACKET spelling is what discriminates the reader choice: it puts
	// both keys on ONE node's Keys, where multiLeafAuthoredValues yields
	// ["keyA",""] and firewallMatchValues yields ["keyA"] — so a
	// firewallMatchValues read would make the empty key vanish and the gate
	// stay silent. RED with either the pre-fix single-value read (the empty
	// slot is never reached) or an empty-skipping reader.
	for _, cmds := range [][]string{
		{`set system services web-management api-auth api-key [ keyA "" ]`},
		{`set system services web-management api-auth api-key keyA`,
			`set system services web-management api-auth api-key ""`},
	} {
		tree := buildTreeFromSet(t, cmds)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig accepted an EMPTY api-key in a non-zero slot (%v); "+
				"the #5636 empty-secret gate must see every authored key", cmds)
		}
		if !strings.Contains(err.Error(), "api-key") {
			t.Fatalf("error %q does not name the api-key leaf", err.Error())
		}
	}
	// The pre-fix behaviour for slot 0 is preserved bit-for-bit: an empty key
	// authored ALONE still reaches the gate (multiLeafAuthoredValues[0] ==
	// nodeVal, including for a valueless node).
	solo := buildTreeFromSet(t, []string{
		`set system services web-management api-auth api-key ""`,
	})
	if _, err := CompileConfig(solo); err == nil {
		t.Fatal("CompileConfig accepted a solo EMPTY api-key")
	}
}

func TestSharedUMEMInterfaceMultiValue_6692(t *testing.T) {
	cfgs := sixNineTwoSpellings(t,
		[]string{"system", "dataplane", "shared-umem"}, "interface",
		"eth1", "eth2")
	assertSliceEverySpelling(t, cfgs,
		[]string{"eth1", "eth2"},
		func(c *Config) []string {
			if c.System.UserspaceDataplane == nil || c.System.UserspaceDataplane.SharedUMEM == nil {
				return nil
			}
			var out []string
			for _, i := range c.System.UserspaceDataplane.SharedUMEM.Interfaces {
				out = append(out, string(i))
			}
			return out
		})
}
