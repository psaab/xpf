package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9838 no-brick, bound at the REAL ingress (#1960, same shape as
// ipip_no_brick_4785 / nat_match_address_no_brick_7145).
//
// A bare `ge-0/0/0;` / `ri1;` COMMITTED CLEAN on every xpf build before this
// change, so the population of boxes whose persisted config carries one is
// non-empty by construction. Store.Load and Store.SyncApply must boot it
// with warnings, while the operator's next commit still refuses it.

// bareLeafPersisted9838 is the shape an older binary persisted and a peer
// syncs: bare leaves beside a valid interface.
const bareLeafPersisted9838 = `interfaces {
    ge-0/0/0;
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
routing-instances {
    ri1;
}`

func assertBareLeaf9838Tolerated(t *testing.T, cfg *config.Config) {
	t.Helper()
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "interfaces ge-0/0/0") || !strings.Contains(joined, "#9838") {
		t.Errorf("tolerant ingress: want a warning naming interfaces ge-0/0/0, got %q", joined)
	}
	if !strings.Contains(joined, "routing-instances ri1") {
		t.Errorf("tolerant ingress: want a warning naming routing-instances ri1, got %q", joined)
	}
	if cfg.Interfaces.Interfaces["ge-0/0/0"] != nil {
		t.Errorf("tolerant ingress: ge-0/0/0 compiled an interface it must not have")
	}
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			t.Errorf("tolerant ingress: ri1 compiled an instance it must not have")
		}
	}
	if cfg.Interfaces.Interfaces["ge-0/0/1"] == nil {
		t.Errorf("tolerant ingress: the valid ge-0/0/1 went missing")
	}
}

// TestLoadToleratesBareLeafInstances9838 is the DISK-BOOT half. The tree is
// written straight to active.json with the committed marker set, NOT through
// a commit, so a mutation that makes the tolerant compile strict lands here.
//
// RED-on-revert: drop lenientBareLeafInstance9838 from lenientCompileOpts()
// and this fails at "Store.Load REFUSED a persisted config".
func TestLoadToleratesBareLeafInstances9838(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(bareLeafPersisted9838).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}

	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying bare-leaf instances. Those "+
			"spellings COMMITTED CLEAN on every build before #9838, so this is a config real "+
			"boxes have: a compile failure here leaves ActiveConfig() nil, forcing the daemon "+
			"into the #1922 bootstrap/lifeline state over two inert spellings: %v", err)
	}
	cfg := booted.ActiveConfig()
	if cfg == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil; the daemon reads " +
			"that as an uncompiled config and refuses takeover, so a silent nil is the same " +
			"brick as an error")
	}
	assertBareLeaf9838Tolerated(t, cfg)
}

// TestSyncApplyToleratesBareLeafInstances9838 is the HA peer-sync half. A
// standby that refuses the primary's config alarm-loops and diverges the
// cluster.
//
// RED-on-revert: same mutation, fails at "SyncApply REJECTED".
func TestSyncApplyToleratesBareLeafInstances9838(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(bareLeafPersisted9838, nil)
	if err != nil {
		t.Fatalf("SyncApply REJECTED a config carrying bare-leaf instances. The HA "+
			"config-sync ingress is TOLERANT by contract (#1960): a standby that refuses the "+
			"primary's config alarm-loops and diverges the cluster: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned a nil config on the tolerated path")
	}
	assertBareLeaf9838Tolerated(t, cfg)
}

// TestCommitCheckRejectsAfterToleratedIngest9838 is the OVER-REACH guard:
// tolerating the spellings at ingress must NOT make the operator's next
// commit accept them.
func TestCommitCheckRejectsAfterToleratedIngest9838(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if _, err := s.SyncApply(bareLeafPersisted9838, nil); err != nil {
		t.Fatalf("precondition: the ingress must tolerate the stanza: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck ACCEPTED bare-leaf instances after a tolerated ingest — the " +
			"strict commit gate must stay strict; tolerating them at ingress is a boot-safety " +
			"concession, not a relaxation of the gate (#9838 / #1960)")
	}
	if !strings.Contains(err.Error(), "#9838") {
		t.Errorf("CommitCheck must reject for the #9838 reason, not for some unrelated one: %v", err)
	}
}
