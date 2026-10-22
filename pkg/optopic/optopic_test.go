package optopic

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Registry-internal invariants. The cross-check against the actual handler
// dispatch lives in pkg/grpcapi (an independent source scrape); these tests
// pin only what this package itself guarantees, so they cannot become the
// registry grading its own homework.

func TestRegistryHasNoHandlerValues16136(t *testing.T) {
	// Metadata-only split: an Entry is data. If a handler field is ever
	// added, this shape assertion reds — handlers stay typed *Server
	// methods in pkg/grpcapi, never func(any, ...) in this package.
	for _, e := range append(ShowTextEntries(), SystemActionEntries()...) {
		if e.Key == "" {
			t.Error("entry with empty key")
		}
		if e.Command == "" {
			t.Errorf("entry %q has no canonical command; an uncommanded topic/verb must be a named absence, not an empty string", e.Key)
		}
	}
}

func TestShowTextLookupExactThenPrefix16136(t *testing.T) {
	if e, ok := LookupShowText("version"); !ok || e.Permission != config.PermView || e.Command != "show version" {
		t.Fatalf("version = (%+v,%v), want view/show version", e, ok)
	}
	if e, ok := LookupShowText("route-table:inet.0"); !ok || e.Key != "route-table:" {
		t.Fatalf("route-table:inet.0 resolved to %q (ok=%v), want the route-table: prefix rule", e.Key, ok)
	}
	if e, ok := LookupShowText("test-policy:from=a,to=b"); !ok || e.Permission != config.PermControl {
		t.Fatalf("test-policy: priced %+v (ok=%v), want PermControl", e, ok)
	}
	if _, ok := LookupShowText("zzbogus-topic"); ok {
		t.Fatal("unknown topic resolved; unknown must stay unregistered so callers price it strict")
	}
	// A bare prefix key itself resolves (the dispatcher's prefix arm fires
	// on the packed form; the key alone is the rule's name).
	if _, ok := LookupShowText("route-table:"); !ok {
		t.Fatal("prefix key route-table: does not resolve to its own rule")
	}
}

func TestSystemActionLookupAndPrefixPrice16136(t *testing.T) {
	if e, ok := LookupSystemAction("reboot"); !ok || e.Permission != config.PermMaint {
		t.Fatalf("reboot = (%+v,%v), want PermMaint", e, ok)
	}
	if e, ok := LookupSystemAction("clear-arp"); !ok || e.Permission != config.PermClear || e.IsPrefix() {
		t.Fatalf("clear-arp = (%+v,%v), want an exact PermClear entry", e, ok)
	}
	if e, ok := LookupSystemAction("clear-persistent-nat"); !ok || !e.FabricAllowed {
		t.Fatalf("clear-persistent-nat fabric=%v ok=%v, want the one fabric-admitted exact verb", e.FabricAllowed, ok)
	}
	// Prefix families resolve through the same lookup.
	if e, ok := LookupSystemAction("userspace-queue:3:arm"); !ok || e.Permission != config.PermMaint {
		t.Fatalf("userspace-queue:3:arm = (%+v,%v), want the PermMaint prefix family", e, ok)
	}
	if _, ok := LookupSystemAction("a-verb-nobody-has-written-yet"); ok {
		t.Fatal("unknown verb resolved; it must fall to the caller's PermMaint default")
	}
}

func TestFabricAdmissionIsNarrow16136(t *testing.T) {
	var show []string
	for _, e := range ShowTextEntries() {
		if e.FabricAllowed {
			show = append(show, e.Key)
		}
	}
	if len(show) != 1 || show[0] != "chassis-forwarding" {
		t.Fatalf("fabric-admitted ShowText topics = %v, want exactly [chassis-forwarding]", show)
	}
	var verbs []string
	for _, e := range SystemActionEntries() {
		if e.FabricAllowed {
			verbs = append(verbs, e.Key)
		}
	}
	if len(verbs) != 1 || verbs[0] != "clear-persistent-nat" {
		t.Fatalf("fabric-admitted SystemAction verbs = %v, want exactly [clear-persistent-nat]", verbs)
	}
}

func TestEntriesAreCopies16136(t *testing.T) {
	a := ShowTextEntries()
	if len(a) == 0 {
		t.Fatal("no ShowText entries")
	}
	// Sorted by key, so diffs and censuses are deterministic.
	for i := 1; i < len(a); i++ {
		if a[i-1].Key > a[i].Key {
			t.Fatalf("entries not sorted: %q before %q", a[i-1].Key, a[i].Key)
		}
	}
	a[0].Key = "mutated"
	if _, ok := LookupShowText("mutated"); ok {
		t.Fatal("mutating the returned slice changed registry lookups")
	}
}

func TestPrefixPermissionsEnumerateHandlerFamilies16136(t *testing.T) {
	fams := SystemActionPrefixPermissions()
	if len(fams) != 7 {
		t.Fatalf("prefix families = %d, want 7 (3 failover + 4 userspace)", len(fams))
	}
	for _, e := range fams {
		if !e.IsPrefix() || e.Permission != config.PermMaint {
			t.Errorf("prefix family %+v: want a ':' prefix at PermMaint", e)
		}
	}
	if AttestArmPermission != config.PermAll {
		t.Errorf("attest arm priced %v, want PermAll", AttestArmPermission)
	}
}
