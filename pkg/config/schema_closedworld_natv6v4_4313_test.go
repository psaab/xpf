package config

import (
	"strings"
	"testing"
)

// #4313 — PRODUCTION closed-world subtree flip: `security nat natv6v4`.
//
// natv6v4 is an xpf-NATIVE options stanza whose entire grammar is the single
// flag `no-v6-frag-header` (modeled). The compiler (compiler_nat.go) reads ONLY
// that keyword and the struct (NATv6v4Config) holds ONLY NoV6FragHeader, so the
// subtree is leaf-complete by construction and closing it cannot false-reject a
// valid config. A typo (`no-v6-frag-heder`) previously committed clean and
// silently left the IPv6 fragment header in translated packets; it is now
// rejected at strict commit (lenient path warns, #1960).

func natv6v4Set(bodyLines ...string) []string {
	out := []string{}
	for _, l := range bodyLines {
		out = append(out, "set security nat natv6v4 "+l)
	}
	return out
}

// TestClosedWorldNATv6v4_RejectsUnknownKeyword is the RED-on-revert
// discriminator: an unmodeled keyword under natv6v4 is rejected at strict
// commit. On revert of closedWorld the same input is silently accepted.
func TestClosedWorldNATv6v4_RejectsUnknownKeyword(t *testing.T) {
	for _, typo := range []string{
		"no-v6-frag-heder",
		"bogus",
	} {
		tree := buildTree(t, natv6v4Set(typo))
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("a typo'd natv6v4 keyword %q must be rejected at commit, not silently dropped", typo)
		}
		if !strings.Contains(err.Error(), typo) || !strings.Contains(err.Error(), "closed-world") {
			t.Fatalf("error must name the typo %q and the closed-world subtree, got: %v", typo, err)
		}
	}
}

// TestClosedWorldNATv6v4_AcceptsValid proves no false-reject: the one modeled
// flag still commits clean under closed-world.
func TestClosedWorldNATv6v4_AcceptsValid(t *testing.T) {
	tree := buildTree(t, natv6v4Set("no-v6-frag-header"))
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("valid natv6v4 no-v6-frag-header must commit clean under closed-world, got: %v", err)
	}
}

// TestClosedWorldNATv6v4_LenientDoesNotBrick documents the #1960 no-brick
// contract.
func TestClosedWorldNATv6v4_LenientDoesNotBrick(t *testing.T) {
	typoTree := buildTree(t, natv6v4Set("no-v6-frag-heder"))
	if err := SchemaValidate(typoTree); err == nil {
		t.Fatal("precondition: strict SchemaValidate must reject the typo")
	}
	if _, err := CompileConfigLenient(typoTree); err != nil {
		t.Fatalf("the lenient load/peer-sync path must not brick on a closed-world typo (#1960); got: %v", err)
	}
}
