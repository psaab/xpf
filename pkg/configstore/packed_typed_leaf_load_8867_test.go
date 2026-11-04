package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Issue 8867 made SchemaValidate see the packed spelling, so a typed leaf
// authored packed is now validated instead of sailing through.
//
// That is a NEW rejection for values that previously committed clean, and the
// argument that it cannot blackout a boot rests on a STRUCTURE rather than on
// the change itself: #1319 PR 2 splits the gate, strict on the operator-driven
// commit path and downgraded to a warning on the tolerant Store.Load /
// SyncApply ingress. If that split were ever removed, this fix would start
// refusing to boot a node whose persisted config carries a packed invalid
// value -- committed clean by an older binary, and now un-loadable.
//
// The outcome follows from the structure, so the structure is what these cells
// pin. Nothing else in the tree asserts it for a PACKED value.
const packedInvalidTypedLeaf8867 = `class-of-service {
    schedulers be transmit-rate asd;
}`

func TestPackedTypedLeafIsRejectedAtCommit_8867(t *testing.T) {
	tree, errs := config.NewParser(packedInvalidTypedLeaf8867).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	err := schemaValidateExpandedTreeForNode(tree, s.nodeID, false)
	if err == nil {
		t.Fatal("the STRICT commit path accepted a packed `transmit-rate asd`. The compiler " +
			"COMPILES that packed tail, so the value reaches the dataplane while its " +
			"validator never ran — the whole of #8867")
	}
	if !strings.Contains(err.Error(), "asd") {
		t.Errorf("rejected, but not for the rate value — any other complaint would pass this "+
			"test while leaving the bypass open: %v", err)
	}
}

func TestLoadToleratesPackedInvalidTypedLeaf_8867(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(packedInvalidTypedLeaf8867).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}

	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying a packed invalid typed "+
			"leaf. Before #8867 that value was never validated, so an older binary "+
			"committed it clean; hard-failing here leaves ActiveConfig() nil and drops the "+
			"box into the bootstrap/lifeline state over one scheduler rate. The #1319 PR 2 "+
			"split must keep this path lenient: %v", err)
	}
	if booted.ActiveConfig() == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil — the daemon reads " +
			"ActiveConfig(), so a nil there is the same blackout as a load failure")
	}
}
