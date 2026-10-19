package config

import (
	"strings"
	"testing"
)

// #15000 A08-02: a NAT64 rule-set with an undefined or omitted source-pool
// passed strict commit, then compileNAT64 returned
// "NAT64 rule-set %q: source pool %q not found" from the #4960 pre-pass,
// aborting every dataplane compile. Fix: strict gate rejects empty/undefined
// source-pool (lenient warns); dataplane warn-skips instead of erroring
// (covered in pkg/dataplane).

func nat64WithPool15000(pool string) []string {
	cmds := []string{
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
	}
	if pool != "" {
		cmds = append(cmds, "set security nat nat64 rule-set rs1 source-pool "+pool)
	}
	return cmds
}

func TestNAT64UndefinedSourcePoolStrictRejected15000(t *testing.T) {
	tree := buildTree(t, nat64WithPool15000("missing-pool"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit must reject NAT64 rule-set with undefined source-pool")
	}
	if !strings.Contains(err.Error(), "rs1") || !strings.Contains(err.Error(), "missing-pool") {
		t.Fatalf("error must name rule-set and pool, got: %v", err)
	}
}

func TestNAT64OmittedSourcePoolStrictRejected15000(t *testing.T) {
	tree := buildTree(t, nat64WithPool15000(""))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit must reject NAT64 rule-set with omitted source-pool")
	}
	if !strings.Contains(err.Error(), "rs1") {
		t.Fatalf("error must name rule-set, got: %v", err)
	}
}

func TestNAT64UndefinedSourcePoolLenientWarns15000(t *testing.T) {
	for _, cmds := range [][]string{nat64WithPool15000("missing-pool"), nat64WithPool15000("")} {
		tree := buildTree(t, cmds)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile must not hard-fail: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "rs1") && strings.Contains(w, "source-pool") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient must warn naming rule-set/source-pool, warnings: %v", cfg.Warnings)
		}
	}
}

func TestNAT64DefinedSourcePoolControl15000(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("defined-pool control must compile strict, got: %v", err)
	}
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	}))
	if err != nil {
		t.Fatalf("defined-pool control lenient: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "rs1") && strings.Contains(w, "source-pool") {
			t.Fatalf("defined pool must not warn about source-pool: %q", w)
		}
	}
}
