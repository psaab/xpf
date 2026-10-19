package config

import (
	"strings"
	"testing"
)

// #15005 (A09-01): the same name defined as BOTH `firewall policer P` and
// `firewall three-color-policer P` committed cleanly. Both definitions ship
// to the userspace dataplane under the name P, where
// userspace-dp/src/filter/compiler.rs loads three-color templates first and
// skips a single-rate policer whose name already exists — so a filter term's
// `then policer P` silently enforces the three-color meter instead of the
// single-rate rate limit the operator authored, with no diagnostic.
//
// The fix hard-rejects the collision on the strict commit / commit-check
// path (validateFirewallPolicerNameCollisionStrict), naming both
// definitions. Tolerant load / peer-sync downgrades to a warning (#1960
// no-brick) so an already-persisted config still boots; on that boot the
// existing three-color precedence is unchanged, but no longer silent.
//
// FAIL-ON-REVERT: dropping the validateFirewallPolicerNameCollisionStrict
// dispatch in runUniformGatesFirewallNAT2 turns every strict-reject case
// below GREEN (CompileConfig accepts the collision) and drops the lenient
// warning — so TestPolicerNameCollision15005* go RED.

func policerCollisionLines15005() []string {
	return []string{
		"set firewall policer P if-exceeding bandwidth-limit 1m",
		"set firewall policer P if-exceeding burst-size-limit 15k",
		"set firewall policer P then discard",
		"set firewall three-color-policer P single-rate color-blind",
		"set firewall three-color-policer P single-rate committed-information-rate 2m",
		"set firewall three-color-policer P single-rate committed-burst-size 30k",
		"set firewall three-color-policer P single-rate excess-burst-size 60k",
		"set firewall three-color-policer P then discard",
		"set firewall family inet filter f1 term t1 then policer P",
		"set firewall family inet filter f1 term t1 then accept",
	}
}

func TestPolicerNameCollision15005RejectedAtCommit(t *testing.T) {
	_, err := CompileConfig(buildTree(t, policerCollisionLines15005()))
	if err == nil {
		t.Fatal("expected strict commit to reject a name defined as both " +
			"`firewall policer P` and `firewall three-color-policer P`")
	}
	msg := err.Error()
	for _, want := range []string{"P", "firewall policer", "three-color-policer"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("collision error %q does not mention %q", msg, want)
		}
	}
}

func TestPolicerNameCollision15005RejectedHierarchical(t *testing.T) {
	input := `firewall {
    policer P {
        if-exceeding {
            bandwidth-limit 1m;
            burst-size-limit 15k;
        }
        then discard;
    }
    three-color-policer P {
        single-rate {
            color-blind;
            committed-information-rate 2m;
            committed-burst-size 30k;
            excess-burst-size 60k;
        }
        then discard;
    }
    family inet {
        filter f1 {
            term t1 {
                then {
                    policer P;
                    accept;
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected strict commit to reject the hierarchical same-name policer collision")
	}
	if !strings.Contains(err.Error(), "three-color-policer") ||
		!strings.Contains(err.Error(), "\"P\"") {
		t.Fatalf("error = %v, want it to name both definitions of P", err)
	}
}

func TestPolicerNameCollision15005LenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, policerCollisionLines15005()))
	if err != nil {
		t.Fatalf("lenient compile must not brick on a pre-existing policer name collision: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policer name collision") && strings.Contains(w, "P") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a policer name collision warning; warnings = %v", cfg.Warnings)
	}
	// Both typed definitions survive on the tolerant path (no-brick); the
	// warning is what makes the dataplane's three-color precedence visible.
	if cfg.Firewall.Policers["P"] == nil || cfg.Firewall.ThreeColorPolicers["P"] == nil {
		t.Fatalf("lenient compile must retain both definitions, got policers=%v three-color=%v",
			cfg.Firewall.Policers, cfg.Firewall.ThreeColorPolicers)
	}
}

// Control: a single-rate policer alone (the surviving-leg reference shape)
// still commits and is referenced normally.
func TestPolicerNameCollision15005SingleRateOnlyCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall policer P if-exceeding bandwidth-limit 1m",
		"set firewall policer P if-exceeding burst-size-limit 15k",
		"set firewall policer P then discard",
		"set firewall family inet filter f1 term t1 then policer P",
		"set firewall family inet filter f1 term t1 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("single-rate-only policer P must commit cleanly, got: %v", err)
	}
}

// Control: a three-color policer alone still commits.
func TestPolicerNameCollision15005ThreeColorOnlyCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall three-color-policer P single-rate color-blind",
		"set firewall three-color-policer P single-rate committed-information-rate 2m",
		"set firewall three-color-policer P single-rate committed-burst-size 30k",
		"set firewall three-color-policer P single-rate excess-burst-size 60k",
		"set firewall three-color-policer P then discard",
		"set firewall family inet filter f1 term t1 then policer P",
		"set firewall family inet filter f1 term t1 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("three-color-only policer P must commit cleanly, got: %v", err)
	}
}

// Control: distinct names in the two namespaces do not collide — both
// definitions and references to each still commit.
func TestPolicerNameCollision15005DistinctNamesCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set firewall policer single1 if-exceeding bandwidth-limit 1m",
		"set firewall policer single1 if-exceeding burst-size-limit 15k",
		"set firewall policer single1 then discard",
		"set firewall three-color-policer three1 single-rate color-blind",
		"set firewall three-color-policer three1 single-rate committed-information-rate 2m",
		"set firewall three-color-policer three1 single-rate committed-burst-size 30k",
		"set firewall three-color-policer three1 single-rate excess-burst-size 60k",
		"set firewall three-color-policer three1 then discard",
		"set firewall family inet filter f1 term t1 then policer single1",
		"set firewall family inet filter f1 term t1 then accept",
		"set firewall family inet filter f1 term t2 then policer three1",
		"set firewall family inet filter f1 term t2 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("distinct policer / three-color-policer names must commit cleanly, got: %v", err)
	}
}
