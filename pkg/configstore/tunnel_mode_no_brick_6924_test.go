package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6924 — the `tunnel mode` allowlist rejects at COMMIT, and must not brick a
// box that already persisted an unrecognised mode (#1960).
//
// The two halves are one test each because they are two different call sites,
// the same argument ipip_no_brick_4785_test.go makes: the pkg/config tests
// drive SchemaValidate directly, which binds the validator and leaves the
// INGRESS unbound. A change that made Store.Load schema-validate would keep
// every pkg/config test green while a booting node lost its config over a
// tunnel that was already inert.
//
// PAIRED on the same fixture text, one axis:
//
//	strict commit-check -> REJECTED (the fix does something)
//	tolerant boot       -> ACCEPTED and PRESERVED (it does not brick)
//
// Without the first half a validator that accepted everything would satisfy the
// second; without the second, rejecting at the schema layer would be
// indistinguishable from rejecting everywhere, which is the #1960 brick.

// unknownModeConfig is a config an older binary would have committed green:
// `tunnel mode banana` was accepted by a schema leaf that had no validator.
const unknownModeConfig = `interfaces {
    gr-0/0/0 {
        tunnel {
            source 10.0.0.1;
            destination 10.0.0.2;
            mode banana;
        }
    }
}`

func TestUnknownTunnelModeIsRejectedAtCommit_6924(t *testing.T) {
	tree, errs := config.NewParser(unknownModeConfig).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := schemaValidateExpandedTreeForNode(tree, s.nodeID, false); err == nil {
		t.Fatal("the STRICT commit path accepted `tunnel mode banana`. It builds a kernel " +
			"GRE device that carries no traffic — an interface the operator can see with " +
			"nothing going through it, which is the #6924 defect")
	} else if !strings.Contains(err.Error(), "banana") {
		t.Errorf("rejected, but not for the mode value — any other complaint would pass "+
			"this test while leaving the defect open: %v", err)
	}
}

func TestLoadToleratesUnknownTunnelMode_6924(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(unknownModeConfig).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}

	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying an unrecognised tunnel "+
			"mode. A config an older binary committed must still BOOT (#1960): a compile "+
			"failure here leaves ActiveConfig() nil, which forces the daemon into the "+
			"bootstrap/lifeline state — the box loses its whole config over one tunnel "+
			"that was already carrying nothing: %v", err)
	}

	cfg := booted.ActiveConfig()
	if cfg == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil; the daemon reads " +
			"that as an uncompiled config and refuses takeover, so a silent nil is the " +
			"same brick as an error")
	}
	// TOLERATED, not dropped: a node that silently lost the stanza would
	// diverge from its peer on the next config comparison.
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != "banana" {
		t.Fatalf("the tolerant boot must PRESERVE the tunnel config verbatim, got %+v", ifc)
	}
}
