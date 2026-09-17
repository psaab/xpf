package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// routeExclusionSurfaceStore10000 reaches the tolerant peer-sync ingress: the
// destination compiler intentionally accepts the raw static-route key, while
// the userspace builder must reject values it cannot put on the Rust FIB wire.
// This is the path on which a committed legacy/peer-synced `default` keyword
// can be active even though a strict commit may reject it.
func routeExclusionSurfaceStore10000(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	_, err := store.SyncApply(`
routing-options {
    static {
        route default {
            discard;
        }
        route not-a-prefix {
            next-hop 10.0.0.1;
        }
        route 10.9.0.0/16 {
            discard;
        }
    }
    rib inet6.0 {
        static {
            route default {
                discard;
            }
            route not-a-prefix {
                next-hop 2001:db8::1;
            }
        }
    }
}
routing-instances {
    vrf-a {
        instance-type virtual-router;
        routing-options {
            static {
                route default {
                    discard;
                }
            }
        }
    }
}
`, nil)
	if err != nil {
		t.Fatalf("SyncApply() error = %v — the fixture's premise is that the tolerant "+
			"peer-sync path admits raw static destinations; if sync now rejects this, "+
			"the fixture must move to the relevant tolerant ingress", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("ActiveConfig() = nil after SyncApply")
	}
	return store
}

// TestCLIRendersOrdinaryStaticExclusions10000 asserts both global families.
// The discard arm and ordinary next-hop arm used to continue without
// printStaticRouteNotInstalled, so a reason map entry was not operator-visible.
//
// FAIL-ON-REVERT: remove either the ordinary verdict consults in
// cli_show_routing.go or restore the blanket NextTable=="" early return and
// the corresponding reason assertion goes RED.
func TestCLIRendersOrdinaryStaticExclusions10000(t *testing.T) {
	store := routeExclusionSurfaceStore10000(t)
	c := &CLI{store: store}

	out := captureStdout(t, func() {
		if err := c.showRoutingOptions(); err != nil {
			t.Fatalf("showRoutingOptions() error = %v", err)
		}
	})

	wantReason := "is neither a CIDR prefix nor a bare IP address"
	if got := strings.Count(out, wantReason); got != 4 {
		t.Fatalf("ordinary unusable routes were not each annotated in both global families: "+
			"reason count = %d, want 4 (two default-discard + two malformed next-hop)\n%s", got, out)
	}
	if !strings.Contains(out, `default`) || !strings.Contains(out, `discard`) {
		t.Fatalf("default-discard row is missing from show output:\n%s", out)
	}
	if !strings.Contains(out, `not-a-prefix`) || !strings.Contains(out, `10.0.0.1`) {
		t.Fatalf("malformed ordinary next-hop row is missing from show output:\n%s", out)
	}
	if strings.Contains(out, `destination "10.9.0.0/16"`) {
		t.Fatalf("a valid discard CIDR was annotated as unusable:\n%s", out)
	}
}

// TestCLIInstanceRendersOrdinaryStaticExclusions10000 covers the detail loop
// for routing-instances, whose discard arm likewise used to continue before
// consulting the shared verdict map.
//
// FAIL-ON-REVERT: remove the instance-loop consult and the reason disappears.
func TestCLIInstanceRendersOrdinaryStaticExclusions10000(t *testing.T) {
	store := routeExclusionSurfaceStore10000(t)
	c := &CLI{store: store}

	out := captureStdout(t, func() {
		if err := c.showRoutingInstances(true); err != nil {
			t.Fatalf("showRoutingInstances(true) error = %v", err)
		}
	})
	if !strings.Contains(out, "default -> discard") {
		t.Fatalf("routing-instance default-discard row is missing:\n%s", out)
	}
	if !strings.Contains(out, `destination "default" is neither a CIDR prefix nor a bare IP address`) {
		t.Fatalf("routing-instance ordinary exclusion is not operator-visible:\n%s", out)
	}
}
