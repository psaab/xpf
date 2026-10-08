package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// tableID12076Lister exposes routes only through their table ID and has no
// corresponding vrf-<name> device, as for an instance-type forwarding RI.
type tableID12076Lister struct {
	tableRoutes map[int][]netlink.Route
	linkErr     error
}

func (f tableID12076Lister) RouteListFilteredIter(family int, filter *netlink.Route, _ uint64, fn func(netlink.Route) bool) error {
	return nil
}
func (f tableID12076Lister) RouteListFiltered(family int, filter *netlink.Route, _ uint64) ([]netlink.Route, error) {
	var filtered []netlink.Route
	for _, route := range f.tableRoutes[filter.Table] {
		isV6 := route.Dst != nil && route.Dst.IP.To4() == nil
		if (family == netlink.FAMILY_V6) == isV6 {
			filtered = append(filtered, route)
		}
	}
	return filtered, nil
}
func (f tableID12076Lister) RouteList(_ netlink.Link, _ int) ([]netlink.Route, error) {
	return nil, nil
}
func (f tableID12076Lister) LinkByIndex(_ int) (netlink.Link, error) {
	return nil, errors.New("no such link")
}
func (f tableID12076Lister) LinkByName(_ string) (netlink.Link, error) { return nil, f.linkErr }

func TestForwardingInstanceTableNameUsesConfiguredTableID12076(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{
		Name:         "fbf-isp",
		InstanceType: "forwarding",
		TableID:      412001,
	}}
	lister := tableID12076Lister{
		tableRoutes: map[int][]netlink.Route{
			412001: []netlink.Route{{Dst: mustCIDR(t, "10.9.0.0/24")}},
		},
		linkErr: errors.New("Link not found"),
	}
	rr := &routeReader{ops: lister}

	entries, err := rr.GetTableRoutes("fbf-isp.inet.0", instances)
	if err != nil {
		t.Fatalf("GetTableRoutes(fbf-isp.inet.0) err = %v; want configured table routes", err)
	}
	if len(entries) != 1 || entries[0].Destination != "10.9.0.0/24" {
		t.Fatalf("GetTableRoutes entries = %+v; want exactly the configured table's route", entries)
	}

	entries, err = rr.GetInstanceRoutes("fbf-isp", instances)
	if err != nil {
		t.Fatalf("GetInstanceRoutes(fbf-isp) err = %v; want configured table routes", err)
	}
	if len(entries) != 1 || entries[0].Destination != "10.9.0.0/24" {
		t.Fatalf("GetInstanceRoutes entries = %+v; want exactly the configured table's route", entries)
	}
}
