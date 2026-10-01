package configstore

import (
	"strings"
	"testing"
)

const unknownFilterThenAction11357 = `
firewall {
    family inet {
        filter f {
            term t {
                from {
                    source-address 10.0.0.0/8;
                }
                then {
                    next-ip 1.2.3.4;
                }
            }
        }
    }
}
`

func TestSyncApplyUnknownFilterThenActionFailsClosed11357(t *testing.T) {
	cfg, err := newTestStore(t).SyncApply(unknownFilterThenAction11357, nil)
	if err != nil {
		t.Fatalf("peer-synced unknown action must remain loadable: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["f"]
	if filter == nil || len(filter.Terms) != 1 {
		t.Fatalf("expected peer-synced filter f with one term, got %+v", filter)
	}
	term := filter.Terms[0]
	if term.Action != "discard" {
		t.Fatalf("peer-synced unknown action compiled as %q, want fail-closed discard", term.Action)
	}
	if len(term.UnknownActions) == 0 || term.UnknownActions[0] != "next-ip" {
		t.Fatalf("peer-sync must preserve the unknown token, got %v", term.UnknownActions)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "next-ip") {
		t.Fatalf("peer-sync must warn about the unknown action, got %v", cfg.Warnings)
	}
}

func TestCheckTextRejectsUnknownFilterThenAction11357(t *testing.T) {
	if _, err := CheckText(unknownFilterThenAction11357, -1); err == nil || !strings.Contains(err.Error(), "next-ip") {
		t.Fatalf("strict check-config must reject and name next-ip, got %v", err)
	}
}
