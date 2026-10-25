package configstore

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16577: a persisted (Store.Load) or peer-synced (Store.SyncApply) config
// carrying a Junos `from protocol` token FRR cannot emit must boot with a
// warning and the offending term forced to reject — not fail into the
// bootstrap/lifeline state (#1960 no-brick). Junos ospf3 strict-commits as
// OSPFv3 through the FRRRoutingProtocolKeyword alias.

const routingProtocolConfig16577 = `policy-options {
    policy-statement P {
        term T {
            from { protocol %s; }
            then accept;
        }
    }
}`

func TestStoreLoadToleratesUnknownRoutingProtocol16577(t *testing.T) {
	for _, proto := range []string{"aggregate", "local", "access-internal"} {
		t.Run(proto, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			tree, errs := config.NewParser(fmt.Sprintf(routingProtocolConfig16577, proto)).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse persisted input: %v", errs)
			}
			if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
				t.Fatalf("WriteActiveMarker: %v", err)
			}
			booted := newTestStoreAt(t, path)
			if err := booted.Load(); err != nil {
				t.Fatalf("Store.Load bricked on persisted `from protocol %s` (#1960): %v", proto, err)
			}
			cfg := booted.ActiveConfig()
			if cfg == nil {
				t.Fatal("Store.Load left ActiveConfig nil")
			}
			term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
			if term.Action != "reject" {
				t.Fatalf("loaded term Action = %q, want reject (poisoned)", term.Action)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), proto) {
				t.Fatalf("Store.Load warnings = %q, want downgrade warning naming %q", cfg.Warnings, proto)
			}
		})
	}
}

func TestSyncApplyToleratesUnknownRoutingProtocol16577(t *testing.T) {
	s := newTestStore(t)
	cfg, err := s.SyncApply(fmt.Sprintf(routingProtocolConfig16577, "aggregate"), nil)
	if err != nil {
		t.Fatalf("SyncApply bricked on peer-synced `from protocol aggregate` (#1960): %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if term.Action != "reject" {
		t.Fatalf("synced term Action = %q, want reject (poisoned)", term.Action)
	}
}

func TestSyncApplyOspf3CommitsAsOSPFv3_16577(t *testing.T) {
	s := newTestStore(t)
	cfg, err := s.SyncApply(fmt.Sprintf(routingProtocolConfig16577, "ospf3"), nil)
	if err != nil {
		t.Fatalf("SyncApply of `from protocol ospf3`: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if term.Action != "accept" {
		t.Fatalf("ospf3 term Action = %q, want accept (aliased, not poisoned)", term.Action)
	}
	if got := config.CanonicalSourceProtocol(term.FromProtocols[0]); got != "ospf6" {
		t.Fatalf("ospf3 canonicalizes to %q, want ospf6", got)
	}
}
