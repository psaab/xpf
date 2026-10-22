package config

import (
	"sort"
	"strings"
	"testing"
)

// TestValueExamplesParseAsWritten8924 asserts that every `valueExamples` entry
// in setSchema PARSES as written in a `set` command value position.
//
// A valueExample is not documentation — it is the value the tool OFFERS the
// operator at `?` completion. An example the parser then rejects makes the tool
// contradict itself, and the operator's evidence is a completion suggesting a
// value and the parser refusing it. The natural conclusion is that the feature
// is broken, not that the value needs quoting (#8924).
//
// That is what happened to the OpenSSH algorithm names. `ValidateSSHAlgorithm`
// is built to accept `@`-bearing names and the schema offered
// `aes256-gcm@openssh.com` as an example, but the lexer rejects a bare `@`, so
// the `@` branch of the validator's own regex was unreachable for any unquoted
// input. The examples are now quoted, which parses and compiles to the
// unquoted name (asserted below).
//
// CENSUS, not a spot-check: this walks the whole schema. When the defect was
// found, exactly 3 examples repo-wide failed — the two `ciphers` and one of the
// `macs`. Guarding the invariant rather than the three sites is what stops the
// fourth from being written.
func TestValueExamplesParseAsWritten8924(t *testing.T) {
	var bad []string
	seen := map[*schemaNode]bool{}
	var walk func(n *schemaNode, path string, depth int)
	walk = func(n *schemaNode, path string, depth int) {
		if n == nil || depth > 8 || seen[n] {
			return
		}
		seen[n] = true
		for _, ex := range n.valueExamples {
			if _, err := ParseSetCommand("set " + strings.TrimSpace(path) + " " + ex); err != nil {
				bad = append(bad, "set "+strings.TrimSpace(path)+" "+ex+"   ("+err.Error()+")")
			}
		}
		for h, ch := range n.children {
			walk(ch, path+" "+h, depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, path+" <name>", depth+1)
		}
	}
	walk(setSchema, "", 0)
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("%d valueExamples do not parse as written:\n  %s\n\n"+
			"An example is the value `?` completion OFFERS. One the parser "+
			"rejects makes the tool contradict itself: the operator copies the "+
			"suggestion and gets a syntax error, and concludes the feature is "+
			"broken rather than that the value needs quoting. Quote the example "+
			"(a quoted value parses and compiles to the unquoted string) or "+
			"choose one that parses bare (#8924).",
			len(bad), strings.Join(bad, "\n  "))
	}
}

// TestQuotedExamplesCompileUnquoted8924 pins the property the fix RESTS on: a
// quoted example parses AND compiles to the bare name.
//
// Quoting the examples would be a fix in shape only if the quotes survived into
// the compiled value — the operator would get a cipher literally named
// `"aes256-gcm@openssh.com"`, which sshd would reject at reload. Asserting that
// the examples parse is not enough; the value has to be read back.
func TestQuotedExamplesCompileUnquoted8924(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		`set system services ssh ciphers "aes256-gcm@openssh.com"`,
		`set system services ssh macs "hmac-sha2-256-etm@openssh.com"`,
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit refused the quoted spelling: %v", err)
	}
	if cfg.System.Services == nil || cfg.System.Services.SSH == nil {
		t.Fatal("ssh config did not compile; the assertions below would be vacuous")
	}
	got := append(append([]string{}, cfg.System.Services.SSH.Ciphers...),
		cfg.System.Services.SSH.MACs...)
	if len(got) != 2 {
		t.Fatalf("expected 2 algorithms, got %d (%v)", len(got), got)
	}
	for _, v := range got {
		if strings.ContainsAny(v, `"`) {
			t.Errorf("%q still carries quote characters. The quoting fix only "+
				"works while the lexer strips them; if it stops, the operator "+
				"gets an algorithm name sshd cannot match and the completion is "+
				"offering a broken value again (#8924).", v)
		}
		if err := ValidateSSHAlgorithm(v); err != nil {
			t.Errorf("%q does not satisfy ValidateSSHAlgorithm (%v) — the "+
				"example the schema offers must be a value its own validator "+
				"accepts.", v, err)
		}
	}
}
