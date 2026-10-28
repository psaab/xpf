package linkstate

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestUp17132 pins the single carrier predicate (#17132, #2070): admin-up
// alone never counts as up; only OperUp does, with OperUnknown falling back
// to the admin flag.
func TestUp17132(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs netlink.LinkAttrs
		want  bool
	}{
		{"oper up", netlink.LinkAttrs{OperState: netlink.OperUp}, true},
		{"oper up admin down", netlink.LinkAttrs{OperState: netlink.OperUp}, true},
		{"carrier down admin up", netlink.LinkAttrs{OperState: netlink.OperDown, Flags: net.FlagUp}, false},
		{"lower layer down admin up", netlink.LinkAttrs{OperState: netlink.OperLowerLayerDown, Flags: net.FlagUp}, false},
		{"unknown admin up", netlink.LinkAttrs{OperState: netlink.OperUnknown, Flags: net.FlagUp}, true},
		{"unknown admin down", netlink.LinkAttrs{OperState: netlink.OperUnknown}, false},
		{"not present admin up", netlink.LinkAttrs{OperState: netlink.OperNotPresent, Flags: net.FlagUp}, false},
		{"dormant admin up", netlink.LinkAttrs{OperState: netlink.OperDormant, Flags: net.FlagUp}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Up(&tc.attrs); got != tc.want {
				t.Errorf("Up(%+v) = %v, want %v", tc.attrs, got, tc.want)
			}
		})
	}
}
