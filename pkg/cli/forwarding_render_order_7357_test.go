package cli

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #7357: the pkg/cli `show forwarding-options` renderers must list instances
// in a STABLE order.
//
// pkg/cli holds its OWN copy of sortedInstanceNames — the two packages do not
// import each other — so the gRPC tests cannot bind these call sites. Four of
// the six affected renderers live here, and reverting any of them would escape
// a grpcapi-only suite entirely.
//
// EIGHT instances, not three: the subject is a randomised map iteration, so an
// unsorted render coincides with sorted order with probability 1/n!. At n=4
// that is 1/24 — a mutation cell would escape ~4% of the time and the test
// would be quietly flaky in the direction of passing. At n=8 it is 1/40320.
//
// The names are inserted in an order that is neither sorted nor reverse-sorted
// so neither a no-op nor an accidental reverse can satisfy the assertion.
func mirrorOrderStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	names := []string{
		"zulu", "delta", "november", "alpha", "kilo", "echo", "mike", "golf",
	}
	for i, name := range names {
		for _, line := range []string{
			// #16723: one ingress interface may be mirrored by only one
			// instance (later strict gate), so each instance mirrors a
			// distinct ingress interface; the ordering subject (instance
			// names from a map) is unchanged.
			"set forwarding-options port-mirroring instance " + name + " output interface ge-0/0/9",
			"set forwarding-options port-mirroring instance " + name + " input ingress interface ge-0/0/" + string(rune('1'+i)),
		} {
			if _, err := store.LoadSet(line); err != nil {
				t.Fatalf("LoadSet(%q) error = %v", line, err)
			}
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func assertRenderedSorted(t *testing.T, out, prefix, what string) {
	t.Helper()
	var got []string
	for _, line := range strings.Split(out, "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok {
			got = append(got, strings.TrimSpace(name))
		}
	}
	if len(got) == 0 {
		t.Fatalf("%s: rendered NO %q lines — the ordering assertion would pass "+
			"vacuously over an empty slice. Output was:\n%s", what, prefix, out)
	}
	want := append([]string(nil), got...)
	sort.Strings(want)
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: rendered order %v is not sorted (want %v) — a bare "+
				"`range` over a Go map is randomised per run (#7357)", what, got, want)
			return
		}
	}
}

func TestCLIShowPortMirroringOrderIsStable_7357(t *testing.T) {
	c := &CLI{store: mirrorOrderStore(t)}
	out := captureStdout(t, func() {
		if err := c.showPortMirroring(); err != nil {
			t.Fatalf("showPortMirroring() error = %v", err)
		}
	})
	assertRenderedSorted(t, out, "Instance:", "cli showPortMirroring")
}

func TestCLIShowForwardingOptionsOrderIsStable_7357(t *testing.T) {
	c := &CLI{store: mirrorOrderStore(t)}
	out := captureStdout(t, func() {
		if err := c.showForwardingOptions(); err != nil {
			t.Fatalf("showForwardingOptions() error = %v", err)
		}
	})
	assertRenderedSorted(t, out, "Instance:", "cli showForwardingOptions")
}
