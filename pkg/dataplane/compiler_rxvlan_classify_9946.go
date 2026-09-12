package dataplane

import "strings"

// RxVlanOffloadState is what an `ethtool -k <iface>` query says about
// `rx-vlan-offload`, reduced to the three cases a caller acts on.
//
// #9946 extracted this from ensureRxVlanOff so it could be shared. There are
// two places that must disable the offload and they are NOT the same code path:
//
//   - the COMPILE-time one (ensureRxVlanOff, driven from compiler_iface.go),
//     which is an activation precondition since #5268;
//   - the POST-LINK-CYCLE one (finishRethMemberLinkTail in pkg/daemon), which
//     runs after programRethMAC's down/up cycle RESETS the member NIC's ethtool
//     features — so the offload comes back on precisely where #5268 established
//     it must not be.
//
// The second one used to call `ethtool -K` blind and warn on failure. It is now
// the same decision as the first, and this type is what stops the two drifting:
// the classification is the part with a defect history, not the exec.
//
// The pre-#5268 bug the parse exists to prevent: `strings.Contains(line, "off")`
// matches the feature NAME "rx-vlan-offLOAD", so every line — "on" or "off" —
// read as "off" and an ACTIVE offload was never disabled. The value after the
// colon is the only sound thing to read.
type RxVlanOffloadState int

const (
	// RxVlanOffloadAbsent: the query SUCCEEDED and listed no `rx-vlan-offload`
	// feature at all, so the NIC has no such offload and never strips a tag.
	//
	// This case is why a caller cannot simply run `-K` and interpret its error.
	// On a NIC without the knob (virtio) `-K` fails "not supported", which is
	// indistinguishable from a real refusal — so probing it would make a
	// fail-closed gate red a VLAN parent that is not capable of the hazard.
	RxVlanOffloadAbsent RxVlanOffloadState = iota

	// RxVlanOffloadOff: reported "off", including "off [fixed]". No tags are
	// stripped; there is nothing to do and nothing to fail.
	RxVlanOffloadOff

	// RxVlanOffloadNeedsDisable: reported "on", OR the query itself failed so
	// the state is UNKNOWN. Both attempt the disable, and a failure is then a
	// genuine fail-closed candidate — "we could not establish that the NIC is
	// not stripping tags" is the same posture as "it is".
	RxVlanOffloadNeedsDisable
)

// ClassifyRxVlanOffload reduces an `ethtool -k <iface>` result to the state its
// caller acts on. queryErr is the error from running the query; a failed query
// is deliberately NOT treated as Absent — an unreadable NIC is unknown, not
// safe.
func ClassifyRxVlanOffload(out []byte, queryErr error) RxVlanOffloadState {
	if queryErr != nil {
		return RxVlanOffloadNeedsDisable
	}
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "rx-vlan-offload:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(l, "rx-vlan-offload:"))
		if strings.HasPrefix(value, "off") {
			return RxVlanOffloadOff
		}
		// Reported "on" (or anything else the tool prints): disable it.
		return RxVlanOffloadNeedsDisable
	}
	return RxVlanOffloadAbsent
}
