package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #4422: `show firewall [filter <name>] effective` must render the COMPILED
// FirewallFilterSnapshot the dataplane actually receives — NOT the raw typed
// config. The sharpest differentiator is a `from source-prefix-list` reference:
// the raw `show firewall filter` prints the reference name verbatim, while the
// effective view resolves it to the literal prefixes the matcher enforces
// (#2506). This also pins multi-value list survival (bracketed destination-port
// collapse, #2419), DSCP code-point resolution (`ef` -> 46), and implicit
// accept (a modifier-only term renders `then accept`, #14632).
func newEffectiveFilterTestStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"policy-options prefix-list trusted 10.0.0.0/8",
		"policy-options prefix-list trusted 192.168.0.0/16",
		// term t1: scoped by a prefix-list reference + a multi-value port list +
		// a symbolic DSCP; modifier-only `then` (count + forwarding-class, no
		// terminating action) => fall-through.
		"firewall family inet filter demo term t1 from source-prefix-list trusted",
		"firewall family inet filter demo term t1 from protocol tcp",
		"firewall family inet filter demo term t1 from destination-port [ 22 80 ]",
		"firewall family inet filter demo term t1 from dscp ef",
		"firewall family inet filter demo term t1 then count c1",
		"firewall family inet filter demo term t1 then forwarding-class best-effort",
		// term t2: terminating accept.
		"firewall family inet filter demo term t2 then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestShowEffectiveFirewallFilterRendersCompiledSnapshot(t *testing.T) {
	c := &CLI{store: newEffectiveFilterTestStore(t)}

	var effErr error
	effOut := captureStdout(t, func() {
		effErr = c.handleShow([]string{"firewall", "effective"})
	})
	if effErr != nil {
		t.Fatalf("handleShow(firewall effective) error = %v", effErr)
	}

	// Heading is tagged [effective] to distinguish from the raw view.
	if !strings.Contains(effOut, "Filter: demo (family inet) [effective]") {
		t.Fatalf("effective output = %q, want [effective] heading", effOut)
	}
	// The prefix-list reference is RESOLVED to literal prefixes (the compiled
	// form) — and the raw reference name is NOT surfaced.
	if !strings.Contains(effOut, "from source-address 10.0.0.0/8, 192.168.0.0/16") {
		t.Fatalf("effective output = %q, want resolved source-address prefixes", effOut)
	}
	if strings.Contains(effOut, "source-prefix-list") {
		t.Fatalf("effective output = %q, unexpectedly shows the raw prefix-list reference", effOut)
	}
	// Multi-value destination-port list collapsed and survived (#2419).
	if !strings.Contains(effOut, "from destination-port 22, 80") {
		t.Fatalf("effective output = %q, want multi-value destination-port 22, 80", effOut)
	}
	// DSCP name resolved to its numeric code point (ef -> 46).
	if !strings.Contains(effOut, "from dscp 46") {
		t.Fatalf("effective output = %q, want DSCP resolved to code point 46", effOut)
	}
	// #14632: modifier-only t1 (count + forwarding-class, NO authored
	// `next term`) terminates as implicit accept — it must NOT render the
	// fall-through line; t2's explicit accept is indistinguishable in text,
	// so the fall-through absence is the discriminating assertion.
	if strings.Contains(effOut, "then next term (fall-through)") {
		t.Fatalf("effective output = %q, must not claim fall-through for modifier-only term t1 (#14632)", effOut)
	}
	if !strings.Contains(effOut, "then accept") {
		t.Fatalf("effective output = %q, want terminating accept (t1 implicit / t2 explicit)", effOut)
	}

	// Contrast: the RAW view prints the prefix-list reference verbatim and does
	// NOT resolve it — proving the effective view is a distinct, compiled surface.
	var rawErr error
	rawOut := captureStdout(t, func() {
		rawErr = c.handleShow([]string{"firewall", "filter", "demo"})
	})
	if rawErr != nil {
		t.Fatalf("handleShow(firewall filter demo) error = %v", rawErr)
	}
	if !strings.Contains(rawOut, "from source-prefix-list trusted") {
		t.Fatalf("raw output = %q, want the unresolved prefix-list reference", rawOut)
	}
	if strings.Contains(rawOut, "[effective]") {
		t.Fatalf("raw output = %q, unexpectedly tagged [effective]", rawOut)
	}
}

// The single-filter form honors the name and family selectors, and reports a
// clean miss for an unknown filter.
func TestShowEffectiveFirewallFilterByNameAndFamily(t *testing.T) {
	c := &CLI{store: newEffectiveFilterTestStore(t)}

	var err error
	out := captureStdout(t, func() {
		err = c.handleShow([]string{"firewall", "filter", "demo", "effective", "family", "inet"})
	})
	if err != nil {
		t.Fatalf("handleShow(firewall filter demo effective family inet) error = %v", err)
	}
	if !strings.Contains(out, "Filter: demo (family inet) [effective]") {
		t.Fatalf("output = %q, want inet effective heading", out)
	}

	// Wrong family: no inet6 filter named demo -> not found.
	missOut := captureStdout(t, func() {
		err = c.handleShow([]string{"firewall", "filter", "demo", "effective", "family", "inet6"})
	})
	if err != nil {
		t.Fatalf("handleShow(... family inet6) error = %v", err)
	}
	if !strings.Contains(missOut, "Filter not found: demo (family inet6)") {
		t.Fatalf("output = %q, want not-found for family inet6", missOut)
	}

	// Unknown filter name.
	unknownOut := captureStdout(t, func() {
		err = c.handleShow([]string{"firewall", "filter", "nope", "effective"})
	})
	if err != nil {
		t.Fatalf("handleShow(firewall filter nope effective) error = %v", err)
	}
	if !strings.Contains(unknownOut, "Filter not found: nope") {
		t.Fatalf("output = %q, want not-found for unknown filter", unknownOut)
	}
}
