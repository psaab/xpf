package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9878 — Store.Load must tolerate a persisted closed-world typo (#1960).
//
// A config an older binary committed green may carry `frum-zone` under
// `security policies`. The strict commit path rejects it (the #9878 fix),
// but the tolerant boot path must warn and continue: hard-failing would
// blackout-boot the node over a stanza that was already enforcing
// nothing. Paired precondition + tolerance on the same fixture, per the
// ipip_no_brick_4785 / tunnel_mode_no_brick_6924 argument: a pkg/config
// cell alone (CompileConfigLenient) leaves the Store.Load ingress
// unbound — a change that made Load schema-validate would keep it green
// while a booting node lost its config.
const typoPersistedConfig9878 = `security {
    policies {
        frum-zone trust to-zone untrust {
            policy p1 {
                then permit;
            }
        }
    }
}`

func TestLoadToleratesSecurityTypo_9878(t *testing.T) {
	tree, errs := config.NewParser(typoPersistedConfig9878).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := newTestStoreAt(t, path).schemaValidateExpandedTree(tree); err == nil {
		t.Fatal("precondition: the STRICT commit path accepted `frum-zone` — the #9878 arm is not in effect")
	} else if !strings.Contains(err.Error(), "frum-zone") {
		t.Fatalf("strict rejected, but not for the typo token: %v", err)
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}
	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying a closed-world typo: %v", err)
	}
	if booted.ActiveConfig() == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil — the same brick as an error")
	}
}
