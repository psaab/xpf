package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

type forwardingTableLister12076 struct {
	fakeRouteLister
	expectedTable int
}

func (f *forwardingTableLister12076) RouteListFiltered(family int, filter *netlink.Route, flags uint64) ([]netlink.Route, error) {
	if filter == nil || filter.Table != f.expectedTable {
		return nil, fmt.Errorf("route-table filter = %v; want table %d", filter, f.expectedTable)
	}
	return f.fakeRouteLister.RouteListFiltered(family, filter, flags)
}

func TestForwardingInstanceCLIUsesConfiguredTableID12076(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	_, err := store.SyncApply(`routing-instances {
    fbf-isp {
        instance-type forwarding;
        routing-options {
            static {
                route 10.9.0.0/24 {
                    next-hop 192.0.2.1;
                }
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply forwarding instance: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("SyncApply left no active configuration")
	}
	var tableID int
	for _, instance := range cfg.RoutingInstances {
		if instance != nil && instance.Name == "fbf-isp" {
			tableID = instance.TableID
			break
		}
	}
	if tableID <= 0 {
		t.Fatalf("active forwarding instance table ID = %d; want positive configured ID", tableID)
	}

	lister := &forwardingTableLister12076{
		fakeRouteLister: fakeRouteLister{
			vrfV4:      []netlink.Route{mkRoute("10.9.0.0/24", "192.0.2.1")},
			vrfLinkErr: fmt.Errorf("Link not found"),
		},
		expectedTable: tableID,
	}
	c := &CLI{store: store, routing: routing.NewManagerWithRouteListerForTest(lister)}

	showOutput := captureStdout(t, func() {
		if err := c.showRoutesForVRF("fbf-isp.inet.0"); err != nil {
			t.Fatalf("showRoutesForVRF: %v", err)
		}
	})
	if !strings.Contains(showOutput, "10.9.0.0/24") {
		t.Fatalf("show route table output = %q; want configured forwarding-instance route", showOutput)
	}

	testOutput := captureStdout(t, func() {
		if err := c.testRouting([]string{"destination", "10.9.0.5", "instance", "fbf-isp"}); err != nil {
			t.Fatalf("testRouting forwarding instance: %v", err)
		}
	})
	if !strings.Contains(testOutput, "Destination: 10.9.0.0/24") {
		t.Fatalf("test routing output = %q; want configured forwarding-instance route", testOutput)
	}
}
