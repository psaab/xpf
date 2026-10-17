package config

import (
	"strings"
	"testing"
)

// #14572 (residual of #14145): a token-INITIAL `[/*` (or `[//`) is not
// bracket-list sugar followed by a comment opener. The real lexer's skip
// loop tries tryBracketedEndpointLiteral first (lexer.go), and
// `[`+identrun+`]:`+identrun — `/` and `*` are identifier chars — is ONE
// identifier token (#5182), so no comment ever opens. ClassifyLoadContent
// left inToken=false on a token-initial `[`, so `/*` opened a fictitious
// block comment (and `//` a fictitious line comment) that blanked every
// following statement in the gate's view, while the store's hierarchical
// branch re-parsed the RAW body and applied them all.
//
// The decisive bodies below therefore put the denied subtree AFTER the
// endpoint-literal value on a leaf the restricted class may write, so the
// only thing between the gate and the denied path is the misclassification.

const probe14572 = "system {\n" +
	"    host-name [/*x]:1;\n" +
	"    root-authentication { plain-text-password-value hunter2; }\n" +
	"}\n" +
	"security { policies { default-policy { permit-all; } } }\n" +
	"# */\n"

func TestTokenInitialBracketEndpointDoesNotHideDeniedLoad14572(t *testing.T) {
	cfg := cfg9892(t)

	// Premise controls: the same denied path, without the trick, IS
	// refused, and an ordinary allowed load IS admitted. Without these a
	// refusal below could be a class refused everything (or a deny regex
	// that never fires) and the bypass cells would measure nothing.
	if err := AuthorizeConfigLoad(cfg, "limited", "merge",
		"system { root-authentication { plain-text-password-value hunter2; } }"); err == nil {
		t.Fatal("premise failed: bare denied hierarchical load was ALLOWED for limited")
	}
	if err := AuthorizeConfigLoad(cfg, "limited", "merge",
		"interfaces { ge-0/0/0 { description uplink14572; } }"); err != nil {
		t.Fatalf("premise failed: allowed description load was refused: %v", err)
	}

	bodies := map[string]string{
		// The decisive probe from the issue.
		"block-comment spelling on host-name": probe14572,
		// Same literal, `//` spelling: the fictitious comment is a line
		// comment, so the denied path rides the same line.
		"line-comment spelling on host-name": "system { host-name [//x]:1; " +
			"root-authentication { plain-text-password-value hunter2; } }\n",
		// The endpoint token on an ALLOWED description leaf: the leaf
		// itself is admissible, so refusal can only come from the denied
		// subtree the fake comment used to hide.
		"block-comment spelling on description": "interfaces {\n" +
			"    ge-0/0/0 { description [/*x]:1; }\n" +
			"}\n" +
			"system { root-authentication { plain-text-password-value hunter2; } }\n" +
			"# */\n",
		"line-comment spelling on description": "interfaces { ge-0/0/0 { description [//x]:1; } } " +
			"system { root-authentication { plain-text-password-value hunter2; } }\n",
	}
	for name, body := range bodies {
		if err := AuthorizeConfigLoad(cfg, "limited", "merge", body); err == nil {
			t.Errorf("%s: load merge carrying a denied path hidden behind a "+
				"token-initial bracketed endpoint literal was ALLOWED (#14572)\nbody: %q", name, body)
		}
	}
}

// The gate must SEE the denied line, not merely refuse: a fix that rejects
// every body containing `[` would pass the cells above by over-refusal.
func TestLoadMutationLinesSeesPastTokenInitialEndpoint14572(t *testing.T) {
	lines, err := LoadMutationLines(probe14572)
	if err != nil {
		t.Fatalf("LoadMutationLines error = %v; the classifier must agree with "+
			"the real lexer on a token-initial `[/*x]:1` endpoint literal (#14572)", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "root-authentication") {
		t.Errorf("LoadMutationLines(probe) = %q; the denied line never reached "+
			"adjudication (#14572)", lines)
	}
	if !strings.Contains(joined, "permit-all") {
		t.Errorf("LoadMutationLines(probe) = %q; the security leaf after the "+
			"endpoint literal never reached adjudication (#14572)", lines)
	}
}

// Narrowness controls: the endpoint-literal model must not swing to
// "brackets always swallow". A genuine comment after a bracket that does
// NOT form an endpoint literal is still a comment, a plain bracket list
// is still list sugar, and the endpoint literal itself still loads on an
// allowed leaf with its value intact.
func TestTokenInitialEndpointAllowedBodiesStillPass14572(t *testing.T) {
	cfg := cfg9892(t)

	// The endpoint literal alone, on an allowed leaf, loads: the value is
	// one token to the real lexer, so nothing about it is a comment.
	if err := AuthorizeConfigLoad(cfg, "limited", "merge",
		"interfaces { ge-0/0/0 { description [2001:db8::1]:51820; } }"); err != nil {
		t.Errorf("genuine bracketed endpoint literal on an allowed leaf was refused: %v", err)
	}

	// A bracketed token with no `:port` tail is list sugar, and a comment
	// after it is a genuine comment: denied prose inside it is not
	// adjudicated.
	flat, uncommented, err := ClassifyLoadContent(
		"set interfaces ge-0/0/0 description [ /* root-authentication */ x\n")
	if err != nil {
		t.Fatalf("ClassifyLoadContent error = %v", err)
	}
	if !flat {
		t.Errorf("flat = false, want true")
	}
	if strings.Contains(uncommented, "root-authentication") {
		t.Errorf("a genuine comment after non-endpoint bracket sugar survived "+
			"classification: %q (#14572 over-correction)", uncommented)
	}

	// A genuine hierarchical block comment still hides its prose.
	body := "interfaces {\n/* root-authentication { plain-text-password-value x; } */\n" +
		"ge-0/0/0 { description ok14572; }\n}\n"
	if err := AuthorizeConfigLoad(cfg, "limited", "merge", body); err != nil {
		t.Errorf("denied path inside a genuine hierarchical comment was adjudicated: %v", err)
	}
}
