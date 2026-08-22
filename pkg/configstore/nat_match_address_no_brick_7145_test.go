package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7145 no-brick, bound at the REAL ingress.
//
// The tolerant-path test in pkg/config drives CompileConfigLenient directly.
// That binds the compiler's behaviour, not the property: #1960 no-brick is a
// property of Store.Load / Store.SyncApply, and a change that routed either
// through the strict compile — or that registered the new gate outside
// lenientCompileOpts() — would leave every compiler-level test green while an
// already-persisted config stopped booting and HA config sync alarm-looped.
// Same argument, and same shape, as ipip_no_brick_4785_test.go.
//
// The widening in #7145 is exactly the kind that needs this: a `match
// source-address 999.1.1.1/24` COMMITTED CLEAN on every xpf build before this
// change, so the population of boxes whose persisted config carries one is
// non-empty by construction.

// natMatchBad7145 is the malformed value from the issue. It parses as neither a
// CIDR nor a bare host IP, so every Rust NAT consumer drops it.
const natMatchBad7145 = "999.1.1.1/24"

// natMatchPersisted7145 is the hierarchical form of a source-NAT rule whose
// `match source-address` list carries one good prefix and one malformed one —
// the shape an older binary persisted, and the shape a peer syncs.
//
// The good prefix is FIRST and the malformed one SECOND so the assertions below
// can tell "the list survived" apart from "the list was truncated at the bad
// entry".
const natMatchPersisted7145 = `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.2.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
    nat {
        source {
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match {
                        source-address [ 10.0.0.0/8 999.1.1.1/24 ];
                    }
                    then {
                        source-nat {
                            interface;
                        }
                    }
                }
            }
        }
    }
}`

// natMatchSourceList7145 returns the compiled source-NAT rule's match list.
func natMatchSourceList7145(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	if len(cfg.Security.NAT.Source) == 0 || len(cfg.Security.NAT.Source[0].Rules) == 0 {
		t.Fatalf("the tolerant ingress dropped the source-NAT rule entirely: %+v",
			cfg.Security.NAT.Source)
	}
	return cfg.Security.NAT.Source[0].Rules[0].Match.SourceAddresses
}

// assertNATMatch7145Tolerated checks the three things the tolerant ingress owes:
// it warned, it kept the GOOD prefix, and it kept the MALFORMED one.
//
// Keeping the malformed one is load-bearing, not laziness. The Rust
// `source_constrained` flag is keyed on the snapshot list being NON-EMPTY, not
// on how many entries parsed (userspace-dp/src/nat/source.rs). Dropping an
// all-malformed list Go-side would clear it and collapse the rule to MATCH-ANY
// — a fail-OPEN regression strictly worse than the silent narrowing #7145 is
// about. So: warn, keep, and let the dataplane drop.
func assertNATMatch7145Tolerated(t *testing.T, cfg *config.Config) {
	t.Helper()
	var warn string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, natMatchBad7145) && strings.Contains(w, "source-address") {
			warn = w
			break
		}
	}
	if warn == "" {
		t.Errorf("the tolerant ingress must WARN, naming the value and the leaf; a silent "+
			"tolerate is the pre-#7145 behaviour. warnings: %v", cfg.Warnings)
	}
	got := natMatchSourceList7145(t, cfg)
	if len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != natMatchBad7145 {
		t.Fatalf("tolerant-ingress match list = %q, want [10.0.0.0/8 %s]. The GOOD prefix must "+
			"survive (a boot that lost it forwards differently from the box that committed "+
			"it), and the MALFORMED one must survive too — the Rust source_constrained flag "+
			"is keyed on this list being non-empty, so dropping it here collapses an "+
			"all-malformed rule to MATCH-ANY", got, natMatchBad7145)
	}
}

// TestLoadToleratesNATMatchAddress7145 is the DISK-BOOT half: a node whose
// already-committed config carries a malformed NAT match prefix must still
// boot, and must still carry the rule.
//
// The tree is written straight to active.json with the committed marker set
// (DB.WriteActiveMarker), NOT through a commit. That models the real scenario —
// bytes an OLDER binary committed, before this gate existed — and it keeps the
// persistence step off the lenient compile path, so a mutation that makes the
// tolerant compile strict lands on THIS test's own Load assertion instead of
// tripping a borrowed precondition.
//
// RED-on-revert: drop lenientNATMatchAddressLiterals from lenientCompileOpts()
// and this fails at "Store.Load REFUSED a persisted config".
func TestLoadToleratesNATMatchAddress7145(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(natMatchPersisted7145).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}

	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying a malformed NAT match "+
			"prefix. That value COMMITTED CLEAN on every build before #7145, so this is a "+
			"config real boxes have: a compile failure here leaves ActiveConfig() nil, which "+
			"forces the daemon into the #1922 bootstrap/lifeline state — the box loses its "+
			"whole config over one narrowed NAT rule: %v", err)
	}
	cfg := booted.ActiveConfig()
	if cfg == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil; the daemon reads " +
			"that as an uncompiled config and refuses takeover, so a silent nil is the same " +
			"brick as an error")
	}
	assertNATMatch7145Tolerated(t, cfg)
}

// TestSyncApplyToleratesNATMatchAddress7145 is the HA peer-sync half. A standby
// that refuses the primary's config alarm-loops and diverges the cluster.
//
// RED-on-revert: same mutation, fails at "SyncApply REJECTED".
func TestSyncApplyToleratesNATMatchAddress7145(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(natMatchPersisted7145, nil)
	if err != nil {
		t.Fatalf("SyncApply REJECTED a config carrying a malformed NAT match prefix. The HA "+
			"config-sync ingress is TOLERANT by contract (#1960): a standby that refuses the "+
			"primary's config alarm-loops and diverges the cluster: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned a nil config on the tolerated path")
	}
	assertNATMatch7145Tolerated(t, cfg)
}

// TestCommitCheckRejectsNATMatchAddress7145 is the OVER-REACH guard on the
// other side: tolerating the value at ingress must NOT make the operator's next
// commit accept it. Tolerant ingest and a strict commit are the two halves of
// #1960, and a "fix" that satisfied the first by weakening the second would
// delete this change's whole point.
//
// It runs against the store's REAL commit-check entry point, not the compiler,
// because that is where an operator meets the gate.
//
// MUTATION NOTE, measured rather than assumed: reverting the TOLERANCE
// (lenientNATMatchAddressLiterals -> false) turns this test RED at its SyncApply
// PRECONDITION, not at its CommitCheck assertion. Read a failure here by WHICH
// line failed — a red at the precondition means the fixture could not be set
// up, not that a relaxed commit gate was caught.
func TestCommitCheckRejectsNATMatchAddress7145(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if _, err := s.SyncApply(natMatchPersisted7145, nil); err != nil {
		t.Fatalf("precondition: the ingress must tolerate the stanza: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck ACCEPTED a malformed NAT match prefix after a tolerated ingest " +
			"— the strict commit gate must stay strict; tolerating it at ingress is a " +
			"boot-safety concession, not a relaxation of the gate (#7145 / #1960)")
	}
	if !strings.Contains(err.Error(), natMatchBad7145) {
		t.Errorf("CommitCheck must reject for the #7145 reason and NAME the value, not fail "+
			"for some unrelated one: %v", err)
	}
}
