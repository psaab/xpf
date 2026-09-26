package daemon

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

type stagOffloadCall10915 struct {
	name string
	args []string
}

func stubStagOffloadSeams10915(t *testing.T, iface string, kOut []byte, kErr, stagErr error) *[]stagOffloadCall10915 {
	t.Helper()
	calls := &[]stagOffloadCall10915{}
	origRun := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "ethtool" {
			*calls = append(*calls, stagOffloadCall10915{name: name, args: append([]string(nil), args...)})
			if len(args) >= 2 && args[0] == "-k" && args[1] == iface {
				return kOut, kErr
			}
			if len(args) >= 4 && args[0] == "-K" && args[1] == iface &&
				args[2] == "rx-vlan-stag-hw-parse" && args[3] == "off" {
				return []byte("not supported"), stagErr
			}
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = origRun })

	origByName, origList := rethParentLinkByName, rethLinkLister
	rethParentLinkByName = func(string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 10915, Name: iface}}, nil
	}
	rethLinkLister = func() ([]netlink.Link, error) { return nil, nil }
	t.Cleanup(func() { rethParentLinkByName, rethLinkLister = origByName, origList })
	return calls
}

func TestPostCycleStagFailureFailsPlainParent_10915(t *testing.T) {
	const iface = "xpf10915-member"
	cause := errors.New("ethtool refused S-tag disable")
	calls := stubStagOffloadSeams10915(t, iface,
		[]byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: on\n"), nil, cause)
	d := &Daemon{}
	err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, plainReth9946())
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "rx-vlan-stag-hw-parse") {
		t.Fatalf("post-cycle S-tag disable failure on a plain RETH must fail the apply with the S-tag error, got %v", err)
	}
	if len(*calls) != 2 || (*calls)[0].args[0] != "-k" ||
		(*calls)[1].args[2] != "rx-vlan-stag-hw-parse" || (*calls)[1].args[3] != "off" {
		t.Fatalf("post-cycle path must query then disable only S-tag offload, got %+v", *calls)
	}
}

func TestPostCycleStagSuccessAndAbsentDoNotFail_10915(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want int
	}{
		{name: "on disabled successfully", out: "rx-vlan-offload: off\nrx-vlan-stag-hw-parse: on\n", want: 2},
		{name: "feature absent", out: "rx-vlan-offload: off\nrx-checksumming: on\n", want: 1},
		{name: "off fixed", out: "rx-vlan-stag-hw-parse: off [fixed]\n", want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const iface = "xpf10915-member"
			calls := stubStagOffloadSeams10915(t, iface, []byte(tc.out), nil, nil)
			d := &Daemon{}
			if err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, plainReth9946()); err != nil {
				t.Fatalf("successful/absent S-tag offload must not fail apply: %v", err)
			}
			if len(*calls) != tc.want {
				t.Fatalf("ethtool calls = %+v, want %d", *calls, tc.want)
			}
		})
	}
}
