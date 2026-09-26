package daemon

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// stubRethLinkSeams6980 makes LinkByName succeed with a parent whose index is
// parentIdx, and LinkList return listErr.
//
// Both seams are needed: the LinkList call is only reached when LinkByName
// SUCCEEDS, and every pre-existing test in this area names an ABSENT interface
// so LinkByName fails and the whole block is skipped. That is why this path
// stayed unbound long enough for the discarded error to survive (#6980).
func stubRethLinkSeams6980(t *testing.T, parentIdx int, listErr error) {
	t.Helper()
	origRun := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "ethtool" && len(args) > 0 && args[0] == "-k" {
			return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: off\n"), nil
		}
		return origRun(name, args...)
	}
	t.Cleanup(func() { runCommandTimeout = origRun })
	origByName, origList := rethParentLinkByName, rethLinkLister
	rethParentLinkByName = func(string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: parentIdx, Name: "xpf6980-parent"}}, nil
	}
	rethLinkLister = func() ([]netlink.Link, error) { return nil, listErr }
	t.Cleanup(func() { rethParentLinkByName, rethLinkLister = origByName, origList })
}

// #6980: `links, _ := netlink.LinkList()`. On failure `links` is nil, the
// propagation loop never runs, the RETH virtual MAC never reaches ANY VLAN
// sub-interface — and there was no log line and no commit error. The apply
// reported success.
//
// On the reference topology the VLAN units carry the traffic (reth0.50
// transit, reth0.80 the data path), so the silent skip leaves them on the STALE
// MAC while the parent RETH has the new one: peers ARP to an address this node
// no longer answers on until the entry ages out. A blackhole whose only symptom
// is a successful commit.
func TestLinkListFailureIsReportedNotSwallowed_6980(t *testing.T) {
	d := &Daemon{}
	want := errors.New("xpf6980 netlink down")
	stubRethLinkSeams6980(t, 42, want)

	err := d.finishRethMemberLinkTail("xpf6980-parent", net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, &config.InterfaceConfig{})
	if err == nil {
		t.Fatal("finishRethMemberLinkTail returned nil after LinkList failed; the RETH MAC " +
			"reached no VLAN sub-interface and the apply reports success (#6980)")
	}
	if !errors.Is(err, want) {
		t.Errorf("returned error does not wrap the netlink failure: %v", err)
	}
	// The message must name the PARENT, because an operator reading a commit
	// failure needs to know which member did not propagate. An error that says
	// only "netlink down" sends them to the wrong layer.
	if !strings.Contains(err.Error(), "xpf6980-parent") {
		t.Errorf("returned error does not name the parent interface: %v", err)
	}
}

// The success path must NOT return an error — otherwise the fix would fail
// every commit rather than only the broken one, and the assertion above could
// not tell the two apart.
//
// Empty list, no error: the parent has no VLAN children, which is the ordinary
// case for a member that carries no tagged units.
func TestLinkListSuccessWithNoChildrenIsNotAnError_6980(t *testing.T) {
	d := &Daemon{}
	stubRethLinkSeams6980(t, 42, nil)
	if err := d.finishRethMemberLinkTail("xpf6980-parent", net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, &config.InterfaceConfig{}); err != nil {
		t.Fatalf("finishRethMemberLinkTail returned %v on a clean enumeration with no VLAN children", err)
	}
}
