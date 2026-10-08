package daemon

import (
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/vishvananda/netlink"
)

var errStep0NoLink = errors.New("no such link")

// TestRenameRethMemberSelectsIndexedSameRGMember_12157 models an old running
// system where both same-RG members still carry the legacy shared MAC. Even
// with the sibling visited first, recovery must exclude its configured name
// and rename the kernel-named target by the unique remaining match.
func TestRenameRethMemberSelectsIndexedSameRGMember_12157(t *testing.T) {
	legacyMAC := cluster.RethMAC(1, 1, 0, 0)
	memberMAC := cluster.RethMAC(1, 1, 1, 0)
	configuredNames := map[string]struct{}{
		"ge-0-0-0": {},
		"ge-0-0-1": {},
	}
	for _, reverse := range []bool{false, true} {
		name := "sibling-first"
		if reverse {
			name = "member-first"
		}
		t.Run(name, func(t *testing.T) {
			sibling := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "ge-0-0-0", HardwareAddr: legacyMAC}}
			member := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 8, Name: "enp8s1", HardwareAddr: legacyMAC}}
			ordered := []*fakeRethLink{sibling, member}
			if reverse {
				ordered = []*fakeRethLink{member, sibling}
			}
			orig := rethLinkOpsFn
			t.Cleanup(func() { rethLinkOpsFn = orig })
			var operations []string
			rethLinkOpsFn = rethLinkOps{
				interfaces: func() ([]net.Interface, error) {
					ifaces := make([]net.Interface, 0, len(ordered))
					for _, link := range ordered {
						ifaces = append(ifaces, net.Interface{Index: link.attrs.Index, Name: link.attrs.Name, HardwareAddr: link.attrs.HardwareAddr})
					}
					return ifaces, nil
				},
				byName: func(string) (netlink.Link, error) { return nil, errStep0NoLink },
				byIndex: func(index int) (netlink.Link, error) {
					for _, link := range ordered {
						if link.attrs.Index == index {
							return link, nil
						}
					}
					return nil, errStep0NoLink
				},
				setDown: func(link netlink.Link) error {
					operations = append(operations, "down:"+link.Attrs().Name)
					return nil
				},
				setUp: func(link netlink.Link) error {
					operations = append(operations, "up:"+link.Attrs().Name)
					return nil
				},
				setName: func(link netlink.Link, target string) error {
					operations = append(operations, "name:"+link.Attrs().Name+"->"+target)
					link.Attrs().Name = target
					return nil
				},
				setHardwareAddr: func(netlink.Link, net.HardwareAddr) error { return nil },
			}

			oldName, cycled, err := renameRethMember(
				"ge-0-0-1", memberMAC, legacyMAC, configuredNames, nil)
			if err != nil || !cycled || oldName != "enp8s1" || member.attrs.Name != "ge-0-0-1" {
				t.Errorf("recovery returned oldName=%q cycled=%v err=%v, member now=%q; want enp8s1 -> ge-0-0-1",
					oldName, cycled, err, member.attrs.Name)
			}
			if sibling.attrs.Name != "ge-0-0-0" {
				t.Errorf("healthy sibling was renamed to %q", sibling.attrs.Name)
			}
			wantOps := []string{"down:enp8s1", "name:enp8s1->ge-0-0-1", "up:ge-0-0-1"}
			if len(operations) != len(wantOps) {
				t.Errorf("link operations = %v, want %v", operations, wantOps)
			} else {
				for i := range wantOps {
					if operations[i] != wantOps[i] {
						t.Errorf("link operations = %v, want %v", operations, wantOps)
						break
					}
				}
			}
		})
	}
}

func TestRenameRethMemberRefusesAmbiguousLegacyMAC_12157(t *testing.T) {
	legacyMAC := cluster.RethMAC(1, 1, 0, 0)
	memberMAC := cluster.RethMAC(1, 1, 1, 0)
	first := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 7, Name: "enp8s0", HardwareAddr: legacyMAC}}
	second := &fakeRethLink{attrs: netlink.LinkAttrs{Index: 8, Name: "enp8s1", HardwareAddr: legacyMAC}}
	links := []*fakeRethLink{first, second}
	orig := rethLinkOpsFn
	t.Cleanup(func() { rethLinkOpsFn = orig })
	var operations []string
	rethLinkOpsFn = rethLinkOps{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{
				{Index: first.attrs.Index, Name: first.attrs.Name, HardwareAddr: first.attrs.HardwareAddr},
				{Index: second.attrs.Index, Name: second.attrs.Name, HardwareAddr: second.attrs.HardwareAddr},
			}, nil
		},
		byName: func(string) (netlink.Link, error) { return nil, errStep0NoLink },
		byIndex: func(index int) (netlink.Link, error) {
			for _, link := range links {
				if link.attrs.Index == index {
					return link, nil
				}
			}
			return nil, errStep0NoLink
		},
		setDown: func(link netlink.Link) error {
			operations = append(operations, "down:"+link.Attrs().Name)
			return nil
		},
		setUp: func(netlink.Link) error { return nil },
		setName: func(link netlink.Link, target string) error {
			operations = append(operations, "name:"+link.Attrs().Name+"->"+target)
			return nil
		},
		setHardwareAddr: func(netlink.Link, net.HardwareAddr) error { return nil },
	}
	oldName, cycled, err := renameRethMember(
		"ge-0-0-1", memberMAC, legacyMAC, nil, nil)
	if err != nil || cycled || oldName != "" || len(operations) != 0 {
		t.Fatalf("ambiguous legacy recovery mutated a link: oldName=%q cycled=%v err=%v ops=%v",
			oldName, cycled, err, operations)
	}
}
