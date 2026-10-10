package daemon

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestSameRGRETHRecoveryFullApply_12157(t *testing.T) {
	for _, missingOwner := range []string{"reth0", "reth1"} {
		t.Run(missingOwner, func(t *testing.T) {
			withTempLinkDir(t)
			cfg := sameRGRecoveryConfig12157()
			memberNames := map[string]string{
				"reth0": "p12157r0",
				"reth1": "p12157r1",
			}
			missingName := memberNames[missingOwner]
			siblingOwner := "reth0"
			if missingOwner == "reth0" {
				siblingOwner = "reth1"
			}
			siblingName := memberNames[siblingOwner]
			kernelName := "k12157"
			if missingOwner == "reth0" {
				kernelName += "0"
			} else {
				kernelName += "1"
			}
			legacyMAC := cluster.RethMAC(1, 1, 0, 0)
			sibling := &fakeRethLink{attrs: netlink.LinkAttrs{
				Index: 7, Name: siblingName, HardwareAddr: append(net.HardwareAddr(nil), legacyMAC...),
			}}
			recovering := &fakeRethLink{attrs: netlink.LinkAttrs{
				Index: 8, Name: kernelName, HardwareAddr: append(net.HardwareAddr(nil), legacyMAC...),
			}}
			links := []*fakeRethLink{sibling, recovering}
			var operations []string
			originalOps := rethLinkOpsFn
			t.Cleanup(func() { rethLinkOpsFn = originalOps })
			rethLinkOpsFn = rethLinkOps{
				interfaces: func() ([]net.Interface, error) {
					ifaces := make([]net.Interface, 0, len(links))
					for _, link := range links {
						ifaces = append(ifaces, net.Interface{
							Index: link.attrs.Index, Name: link.attrs.Name,
							HardwareAddr: append(net.HardwareAddr(nil), link.attrs.HardwareAddr...),
						})
					}
					return ifaces, nil
				},
				byName: func(name string) (netlink.Link, error) {
					for _, link := range links {
						if link.attrs.Name == name {
							return link, nil
						}
					}
					return nil, errStep0NoLink
				},
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
				setUp: func(link netlink.Link) error {
					operations = append(operations, "up:"+link.Attrs().Name)
					return nil
				},
				setName: func(link netlink.Link, name string) error {
					operations = append(operations, "name:"+link.Attrs().Name+"->"+name)
					link.Attrs().Name = name
					return nil
				},
				setHardwareAddr: func(link netlink.Link, mac net.HardwareAddr) error {
					operations = append(operations, "mac:"+link.Attrs().Name+":"+mac.String())
					link.Attrs().HardwareAddr = append(net.HardwareAddr(nil), mac...)
					return nil
				},
			}

			lc := &leaseTracingLinkController{}
			d := twoMemberRethDaemon(t, lc)
			originalRun := runCommandTimeout
			runCommandTimeout = func(name string, args ...string) ([]byte, error) {
				if name == "ethtool" && len(args) > 0 && args[0] == "-k" {
					return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: off\n"), nil
				}
				return nil, nil
			}
			t.Cleanup(func() { runCommandTimeout = originalRun })

			if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
				t.Fatalf("full config apply: %v", err)
			}

			recovered := links[1]
			if recovered.attrs.Name != missingName {
				t.Fatalf("recovery bound %s to %q, want %q", missingOwner, recovered.attrs.Name, missingName)
			}
			if sibling.attrs.Name != siblingName {
				t.Fatalf("healthy %s sibling renamed to %q, want %q", siblingOwner, sibling.attrs.Name, siblingName)
			}
			for _, event := range operations {
				if event == "down:"+siblingName || event == "up:"+siblingName {
					t.Fatalf("healthy sibling was cycled: operations=%v", operations)
				}
			}
			if !contains12157(operations, "down:"+kernelName) ||
				!contains12157(operations, "name:"+kernelName+"->"+missingName) ||
				!contains12157(operations, "up:"+missingName) {
				t.Fatalf("missing member did not complete its expected rename cycle: %v", operations)
			}

			for owner, memberName := range memberNames {
				index := 0
				if owner == "reth1" {
					index = 1
				}
				wantMAC := cluster.RethMAC(1, 1, index, 0)
				var link *fakeRethLink
				if memberName == missingName {
					link = recovered
				} else {
					link = sibling
				}
				if !bytes.Equal(link.attrs.HardwareAddr, wantMAC) {
					t.Errorf("%s member MAC = %s, want %s", owner, link.attrs.HardwareAddr, wantMAC)
				}
			}

			prepare, notify, keep, _, stillHeld, trace := lc.snapshot()
			if prepare != 1 || notify != 1 || keep != 0 || stillHeld {
				t.Fatalf("worker lease lifecycle = prepare:%d notify:%d keep:%d held:%v trace=%v",
					prepare, notify, keep, stillHeld, trace)
			}
			acquired, released := false, false
			for _, event := range trace {
				switch event {
				case "acquire":
					acquired = true
				case "notify(release)":
					if !acquired {
						t.Fatalf("worker lease released before the rename acquired it: %v", trace)
					}
					released = true
				}
				if released && event == "renew(NO-OP: lease already released)" {
					t.Fatalf("apply renewed an already-released worker lease: %v", trace)
				}
			}
			if !released {
				t.Fatalf("worker lease was never released after recovery: %v", trace)
			}
			if lc.deferredAbandonFoundLease(t) {
				t.Fatalf("apply backstop found an unreleased worker lease: %v", trace)
			}
		})
	}
}

func sameRGRecoveryConfig12157() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{ClusterID: 1, NodeID: 0},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"reth1":    {Name: "reth1", RedundancyGroup: 1},
				"p12157r0": {Name: "p12157r0", RedundantParent: "reth0"},
				"p12157r1": {Name: "p12157r1", RedundantParent: "reth1"},
			},
		},
	}
}

func contains12157(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
