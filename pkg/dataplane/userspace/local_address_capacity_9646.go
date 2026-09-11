package userspace

import (
	"errors"
	"fmt"
	"log/slog"
)

// #9646: userspace_local_v4 and userspace_local_v6 are fixed-capacity shim hash
// maps. The local-address sync updated every desired key and returned the first
// kernel refusal, and the classifier-map callers turned ANY sync error into
// userspace_ctrl.Enabled=0, which drops all transit. So one local address past
// the capacity (interface addresses, VRRP VIPs and host addresses the netlink
// enumeration adds) took the dataplane from forwarding to dropping everything,
// with a map update error as the only hint.
//
// The set is now checked against the capacity before any classifier map is
// written. A refusal is a named error that leaves every map on the plan the
// helper enforces, so the fail-closed sync and the status poll keep ctrl as it
// is. Every other sync failure still fails closed.

// userspaceLocalAddressMapCapacity is max_entries of USERSPACE_LOCAL_V4 and
// USERSPACE_LOCAL_V6 in userspace-xdp/src/lib.rs.
// TestLocalAddressMapCapacityMatchesTheShim9646 binds the two, so a shim resize
// cannot leave this preflight checking a stale number.
const userspaceLocalAddressMapCapacity = 8192

// localAddressCapacityError reports a local-address set larger than its shim
// map. Nothing has been written when it is returned.
type localAddressCapacityError struct {
	Map      string
	Desired  int
	Capacity int
}

func (e *localAddressCapacityError) Error() string {
	return fmt.Sprintf("%d local addresses exceed the %s map capacity of %d (#9646); "+
		"the classifier maps and userspace_ctrl are left on the previous plan",
		e.Desired, e.Map, e.Capacity)
}

func isLocalAddressCapacityError(err error) bool {
	var capErr *localAddressCapacityError
	return errors.As(err, &capErr)
}

// checkLocalAddressCapacity refuses a set the shim maps cannot hold. A set of
// exactly the capacity fits.
func checkLocalAddressCapacity(v4, v6 int) error {
	if v4 > userspaceLocalAddressMapCapacity {
		return &localAddressCapacityError{Map: mapNameUserspaceLocalV4, Desired: v4, Capacity: userspaceLocalAddressMapCapacity}
	}
	if v6 > userspaceLocalAddressMapCapacity {
		return &localAddressCapacityError{Map: mapNameUserspaceLocalV6, Desired: v6, Capacity: userspaceLocalAddressMapCapacity}
	}
	return nil
}

// noteLocalAddressCapacityLocked raises the #9646 alarm when a capacity refusal
// starts or changes, and clears it when the set fits again. err nil means the
// last sync fit. Caller holds m.mu.
func (m *Manager) noteLocalAddressCapacityLocked(err error) {
	if err == nil {
		if m.localAddressCapacityAlarm != "" {
			slog.Info("userspace: local-address set fits the shim maps again; classifier maps refresh normally",
				"issue", "#9646")
			m.localAddressCapacityAlarm = ""
		}
		return
	}
	if msg := err.Error(); msg != m.localAddressCapacityAlarm {
		slog.Error("userspace: classifier maps not refreshed by the status poll; the local-address set exceeds the shim map capacity",
			"err", err, "issue", "#9646")
		m.localAddressCapacityAlarm = msg
	}
}
