package daemon

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// #9946. The link down/up cycle programRethMAC requires RESETS the member NIC's
// ethtool features, so `rx-vlan-offload` comes back ON. finishRethMemberLinkTail
// re-disables it — and when that re-disable FAILS it logs a warning and the
// apply reports success.
//
// The consequence is the one #5268 already fails the COMPILE closed for: XDP
// derives 802.1Q identity solely from the in-frame tag, so a NIC that strips
// tags into skb->vlan_tci makes every tagged frame parse as vlan_id=0 and fall
// back to the PHYSICAL parent ifindex — untrusted VLAN traffic classified into
// the parent's zone. #5268 made that an activation precondition at compile
// time; this path re-opens it AFTER activation and only warns.
//
// The window is unbounded. `ensureRxVlanOff` has exactly one production caller
// (pkg/dataplane/compiler_iface.go, inside the per-phys compile setup) and no
// ticker reaches applyConfigLocked — the daemon's periodic work is per-subsystem
// (DDNS, IPsec rebind, RA, HA reconcile) and none of it re-runs the config
// apply. So nothing re-asserts `rxvlan off` until the next apply EVENT: an
// operator commit, a reboot, or a peer's config sync. Measured, not assumed.

// rxvlanCall is one recorded external command from the member tail.
type rxvlanCall9946 struct {
	name string
	args []string
}

// stubRxVlanSeams9946 fails the ethtool -K rxvlan off call for iface and lets
// every other external command succeed, so the assertion is about THIS command
// and not about the rest of the tail.
//
// The netlink seams are stubbed to SUCCEED with no children: that is the #6980
// path's clean case, which returns nil on its own. Without that, a nil return
// would be ambiguous between "rxvlan was tolerated" and "the tail failed for an
// unrelated reason", and a non-nil return would not be attributable either.
func stubRxVlanSeams9946(t *testing.T, iface string, kOut []byte, kErr, dashKErr error) *[]rxvlanCall9946 {
	t.Helper()
	calls := &[]rxvlanCall9946{}

	origRun := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		*calls = append(*calls, rxvlanCall9946{name: name, args: args})
		if name == "ethtool" && len(args) >= 2 && args[0] == "-k" && args[1] == iface {
			return kOut, kErr
		}
		if name == "ethtool" && len(args) >= 4 && args[0] == "-K" && args[1] == iface &&
			args[2] == "rxvlan" && args[3] == "off" {
			return []byte("netlink error: Operation not supported"), dashKErr
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = origRun })

	origByName, origList := rethParentLinkByName, rethLinkLister
	rethParentLinkByName = func(string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 9946, Name: iface}}, nil
	}
	rethLinkLister = func() ([]netlink.Link, error) { return nil, nil }
	t.Cleanup(func() { rethParentLinkByName, rethLinkLister = origByName, origList })

	return calls
}

// vlanCarryingReth9946 is a RETH that classifies traffic by in-frame tag — the
// reference topology's shape (reth0.50 transit, reth0.80 the data path).
func vlanCarryingReth9946() *config.InterfaceConfig {
	return &config.InterfaceConfig{
		Units: map[int]*config.InterfaceUnit{
			50: {VlanID: 50},
			80: {VlanID: 180},
		},
	}
}

// plainReth9946 carries no 802.1Q units, so it does not classify by tag and the
// offload state is irrelevant to it.
func plainReth9946() *config.InterfaceConfig {
	return &config.InterfaceConfig{
		Units: map[int]*config.InterfaceUnit{0: {}},
	}
}

var errRxVlan9946 = errors.New("xpf9946 ethtool refused")

// THE REPRODUCTION. A VLAN-carrying RETH whose member NIC reports the offload
// ON and whose re-disable fails must fail the apply.
func TestPostCycleRxVlanFailureFailsTheApply_9946(t *testing.T) {
	const iface = "xpf9946-member"
	d := &Daemon{}
	stubRxVlanSeams9946(t, iface, []byte("rx-vlan-offload: on\n"), nil, errRxVlan9946)

	err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, vlanCarryingReth9946())
	if err == nil {
		t.Fatal("#9946: finishRethMemberLinkTail returned nil after the post-cycle " +
			"`ethtool -K rxvlan off` failed on a RETH carrying configured VLAN units. " +
			"The NIC keeps stripping 802.1Q tags, so every tagged frame parses as " +
			"vlan_id=0 and falls back to the parent ifindex — untrusted VLAN traffic " +
			"classified into the parent's zone, which is the cross-zone bypass #5268 " +
			"fails the COMPILE closed for. The apply reports success and nothing " +
			"re-asserts the knob until the next commit")
	}
	if !errors.Is(err, errRxVlan9946) {
		t.Errorf("returned error does not wrap the ethtool failure: %v", err)
	}
	// An operator reading a failed commit needs to know WHICH member, exactly as
	// #6980 requires for the LinkList failure.
	if !strings.Contains(err.Error(), iface) {
		t.Errorf("returned error does not name the member interface: %v", err)
	}
}

// POSITIVE CONTROL, same run, same failure: a RETH with no 802.1Q units does not
// classify by tag, so the identical ethtool failure must stay tolerated.
//
// Without this cell the fix is indistinguishable from "fail every commit whose
// ethtool call errors", which would red plain-parent deploys and every NIC that
// legitimately lacks the knob. This is the scope #5268's own gate uses
// (rxVlanOffloadActivationError returns nil unless the parent carries VLAN
// subinterfaces) and the post-cycle fault must not exceed it.
func TestPostCycleRxVlanFailureIsToleratedOnAPlainParent_9946(t *testing.T) {
	const iface = "xpf9946-plain"
	d := &Daemon{}
	stubRxVlanSeams9946(t, iface, []byte("rx-vlan-offload: on\n"), nil, errRxVlan9946)

	if err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, plainReth9946()); err != nil {
		t.Fatalf("#9946: a RETH with no configured VLAN units must tolerate the same "+
			"ethtool failure — it does not classify by in-frame tag, so the offload "+
			"state cannot misroute anything. Got: %v", err)
	}
}

// A NIC that does not have the feature at all (virtio) must not be probed with
// `-K`, which would fail "not supported" and trip the fail-closed gate on a
// parent that never strips a tag. This is the trap ensureRxVlanOff documents
// and the reason the post-cycle site cannot simply promote its warning.
func TestPostCycleRxVlanAbsentFeatureIsNotAFailure_9946(t *testing.T) {
	const iface = "xpf9946-virtio"
	d := &Daemon{}
	calls := stubRxVlanSeams9946(t, iface,
		[]byte("Features for xpf9946-virtio:\nrx-checksumming: on\ntx-checksumming: on\n"),
		nil, errRxVlan9946)

	if err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, vlanCarryingReth9946()); err != nil {
		t.Fatalf("#9946: a NIC whose ethtool -k lists no rx-vlan-offload feature never "+
			"strips tags, so there is nothing to fail closed about. Got: %v", err)
	}
	for _, c := range *calls {
		if c.name == "ethtool" && len(c.args) > 0 && c.args[0] == "-K" {
			t.Errorf("#9946: attempted `ethtool -K` on a NIC that has no rx-vlan-offload "+
				"feature. On virtio that fails \"not supported\" and would falsely trip "+
				"the fail-closed gate for a VLAN parent that never strips a tag. Calls: %v", *calls)
		}
	}
}

// Already off — including "off [fixed]" — is the ordinary post-cycle outcome on
// a NIC that does not reset the feature. No -K, no error.
func TestPostCycleRxVlanAlreadyOffIsNotAFailure_9946(t *testing.T) {
	for _, value := range []string{"off", "off [fixed]"} {
		t.Run(value, func(t *testing.T) {
			const iface = "xpf9946-alreadyoff"
			d := &Daemon{}
			calls := stubRxVlanSeams9946(t, iface,
				[]byte("rx-vlan-offload: "+value+"\n"), nil, errRxVlan9946)

			if err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, vlanCarryingReth9946()); err != nil {
				t.Fatalf("#9946: rx-vlan-offload is %q, so no tag is stripped. Got: %v", value, err)
			}
			for _, c := range *calls {
				if c.name == "ethtool" && len(c.args) > 0 && c.args[0] == "-K" {
					t.Errorf("#9946: ran `ethtool -K` though the feature already reads %q: %v", value, *calls)
				}
			}
		})
	}
}

// The query itself failing leaves the state UNKNOWN. `ensureRxVlanOff` attempts
// the disable in that case and lets the caller fail closed if it does not take.
// The post-cycle path must reach the same verdict: unknown-then-failed is a
// failure on a VLAN-carrying parent.
func TestPostCycleRxVlanUnknownStateThenFailedDisableFailsTheApply_9946(t *testing.T) {
	const iface = "xpf9946-unknown"
	d := &Daemon{}
	calls := stubRxVlanSeams9946(t, iface, nil, errors.New("xpf9946 query failed"), errRxVlan9946)

	err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, vlanCarryingReth9946())
	if err == nil {
		t.Fatal("#9946: the ethtool query failed (state unknown) AND the disable failed, " +
			"on a RETH carrying VLAN units. The knob cannot be shown off, so this must " +
			"fail closed exactly as the compile-time gate does")
	}
	sawDashK := false
	for _, c := range *calls {
		if c.name == "ethtool" && len(c.args) > 0 && c.args[0] == "-K" {
			sawDashK = true
		}
	}
	if !sawDashK {
		t.Error("#9946: an unknown state must still ATTEMPT the disable — otherwise a NIC " +
			"whose query is flaky would keep stripping tags with no attempt made")
	}
}

// The fail-closed verdict must NOT short-circuit the rest of the member tail.
//
// An early `return err` at the rxvlan step is the obvious way to write this fix
// and it is wrong: it skips the VLAN MAC propagation loop below, which is what
// #6980 made mandatory — every sub-interface keeps its STALE MAC while the
// parent has the new one, so peers ARP to an address the node no longer answers
// on until the entry ages out. That trades one silent misforwarding for another,
// and the commit failing does not undo it. The error belongs in the
// "fail-closed but complete" accumulator, like every other error on this path.
//
// The observable is the tail's FINAL lease renewal: it is the last statement of
// finishRethMemberLinkTail, so it runs if and only if the function did not
// return early. Two renewals means the tail completed — one from the split
// between the query and the disable, one at the end.
func TestPostCycleRxVlanFailureDoesNotSkipTheTail_9946(t *testing.T) {
	const iface = "xpf9946-notskipped"
	d, lc := newAbortRecoveryDaemon(nil)
	stubRxVlanSeams9946(t, iface, []byte("rx-vlan-offload: on\n"), nil, errRxVlan9946)

	err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, vlanCarryingReth9946())
	if err == nil {
		t.Fatal("premise: this cell needs the fail-closed verdict to fire, and it did not")
	}
	if lc.renewCalls != 2 {
		t.Errorf("#9946: RenewLinkCycle calls = %d, want 2. The tail returned EARLY on the "+
			"rxvlan failure instead of accumulating it, so the VLAN MAC propagation loop "+
			"never ran — reintroducing the #6980 stale-MAC blackhole on exactly the "+
			"VLAN-carrying parents this fix is about, and dropping the final lease renewal "+
			"with it", lc.renewCalls)
	}
}

// A successful disable on a VLAN-carrying parent is the common post-cycle case
// and must not fail the apply. This is what separates "the fix works" from "the
// fix fails every RETH commit"; without it every assertion above is also
// satisfied by returning an error unconditionally.
func TestPostCycleRxVlanSuccessfulDisableIsNotAFailure_9946(t *testing.T) {
	const iface = "xpf9946-recovers"
	d := &Daemon{}
	calls := stubRxVlanSeams9946(t, iface, []byte("rx-vlan-offload: on\n"), nil, nil)

	if err := d.finishRethMemberLinkTail(iface, net.HardwareAddr{2, 0xbf, 0x72, 1, 2, 3}, vlanCarryingReth9946()); err != nil {
		t.Fatalf("#9946: the re-disable SUCCEEDED; the apply must not fail. Got: %v", err)
	}
	sawDashK := false
	for _, c := range *calls {
		if c.name == "ethtool" && len(c.args) > 0 && c.args[0] == "-K" {
			sawDashK = true
		}
	}
	if !sawDashK {
		t.Error("premise: the offload read `on` and no `ethtool -K` was attempted, so this " +
			"cell is not exercising the re-disable at all")
	}
}
