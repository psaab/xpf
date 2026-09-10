package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9546 — the BATCH sibling of TestDeleteSessionItselfNamesTheDomainOnTheWire9146,
// end to end through a REAL BPF session mirror.
//
// WHY THIS CELL IS THE ACCEPTANCE, not the unprivileged round-trip cells. The
// defect was never in any one function: #9364's batch plumbing and #9146's
// singular delete were each correct for a value that HAD a domain, and every
// unprivileged cell proved them correct that way. What was false was the premise
// that the value a production delete reads ever has one — the conntrack GC takes
// its entries from `store.ForEachV4`, a BatchLookup over the BPF mirror, and the
// on-map ABI had no slot for the domain. So this cell follows the GC's path
// exactly: seed a tenant row in a real map, read it back through ForEachV4, feed
// THAT to DeleteBatchKnownV4, and read the helper wire.
//
// It needs real BPF maps, so it SKIPS without CAP_BPF, like every mirror cell in
// this package (#9337). A skipping cell cannot score a mutation — stated here so
// nobody reads a "survived" off a run where this never executed. Run it with:
//
//	sudo -n env XPF_REQUIRE_MEMLOCK_GUARDS=1 PATH=/usr/bin:/bin HOME=/root \
//	  go test -count=1 ./pkg/dataplane/userspace/ -run 9546
//
// SCOPE, honestly: the row here is written by the GO mirror writer
// (bpfShim.SetSessionV4 -> toBPF). Rows the HELPER writes (publish_conntrack) are
// bound by the Rust row-builder cells plus the same field offset pinned in C,
// Rust (`offset_of!`) and Go (`TestRoutingDomainOffsets9546`) — a cross-language
// read cannot be driven from one test process.
func TestBatchDeleteNamesTheMirroredDomainOnTheWire9546(t *testing.T) {
	dir, err := os.MkdirTemp("", "x9546b")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m) // skips without BPF privileges
	rec := startSyncRec9146(t, filepath.Join(dir, "userspace-dp-sessions.sock"))

	const tenant = uint32(100007)
	k := key9146()
	rev := dataplane.SessionKey{
		SrcIP: k.DstIP, DstIP: k.SrcIP,
		SrcPort: k.DstPort, DstPort: k.SrcPort, Protocol: k.Protocol,
	}
	if err := m.bpfShim.SetSessionV4(k, dataplane.SessionValue{
		RoutingDomain: tenant,
		ReverseKey:    rev,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	store := m.Sessions()
	var entries []dataplane.SessionEntryV4
	if err := store.ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			entries = append(entries, dataplane.SessionEntryV4{Key: key, Value: val})
		}
		return true
	}); err != nil {
		t.Fatalf("ForEachV4: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("FIXTURE FAILED: ForEachV4 returned %d forward rows, want 1", len(entries))
	}

	// THE MECHANISM, observed at the exact read the conntrack GC performs. If this
	// fails, the delete below cannot name the domain however correct it is.
	if got := entries[0].Value.RoutingDomain; got != tenant {
		t.Fatalf("#9546: the row read back through ForEachV4 — the conntrack GC's own "+
			"source — carries routing_domain=%d, want %d. The BPF mirror is dropping the "+
			"domain again, so every batch delete goes out bare", got, tenant)
	}

	if _, err := store.DeleteBatchKnownV4(entries, dataplane.DeleteReasonGCExpired); err != nil {
		t.Fatalf("DeleteBatchKnownV4: %v", err)
	}

	var deletes []SessionSyncRequest
	for _, r := range rec.all() {
		if r.Operation == "delete" {
			deletes = append(deletes, r)
		}
	}
	if len(deletes) < 2 {
		t.Fatalf("recorded %d helper deletes, want the forward row AND its reverse "+
			"companion — the delete never reached the standby", len(deletes))
	}
	for i, r := range deletes {
		if r.RoutingDomain != tenant {
			t.Errorf("#9546: helper delete %d carried routing_domain=%d, want %d. A bare "+
				"delete makes the helper probe every routing instance and REFUSE when two "+
				"tenants share the tuple (#8636); on a standby that session leaks to idle "+
				"timeout and is promoted on failover", i, r.RoutingDomain, tenant)
		}
	}
}
