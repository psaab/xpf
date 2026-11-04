package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Issue 8882 arms a new commit-time gate, so it makes configs that commit clean
// today start being rejected. The argument that this cannot blackout a boot is
// NOT "the load path does not validate" -- it does. It is:
//
//	compileTreeLenient schema-validates and DOWNGRADES the violation to a
//	warning (#1319 PR 2); only the operator-driven commit path is strict.
//
// The distinction matters because the safety rests entirely on that downgrade
// continuing to exist. A comment in schema_validators.go asserted the stronger,
// false version ("does not schema-validate at all"), was true when written,
// was hollowed by a later change with nothing re-checking it, and was then
// cited as authority by two agents in one day. So the premise is asserted here
// instead of described there.
const unknownTopLevelStanza8882 = `securty {
    zones {
        security-zone z1 {
        }
    }
}`

func TestUnknownTopLevelStanzaIsRejectedAtCommit_8882(t *testing.T) {
	tree, errs := config.NewParser(unknownTopLevelStanza8882).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	err := schemaValidateExpandedTreeForNode(tree, s.nodeID, false)
	if err == nil {
		t.Fatal("the STRICT commit path accepted a typo'd top-level stanza. Everything " +
			"under it is silently discarded, so the operator sees a clean commit and an " +
			"empty configuration")
	}
	if !strings.Contains(err.Error(), "securty") {
		t.Errorf("rejected, but not for the stanza keyword: %v", err)
	}
}

// THE PREMISE, asserted rather than remembered. If the lenient path ever stops
// downgrading, this cell reds -- and it reds BEFORE a node fails to boot on a
// config an older binary committed clean.
func TestLoadDowngradesUnknownTopLevelStanza8882(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(unknownTopLevelStanza8882).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}

	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying an unrecognised top-level "+
			"stanza. Such a config committed clean before this gate existed, so hard-failing "+
			"here leaves ActiveConfig() nil and drops the box into the bootstrap/lifeline "+
			"state. The whole safety argument for the #8882 gate is that the #1319 PR 2 "+
			"split keeps THIS path lenient: %v", err)
	}
	if booted.ActiveConfig() == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil — the daemon reads " +
			"ActiveConfig(), so a nil there is the same blackout as a load failure")
	}
}
