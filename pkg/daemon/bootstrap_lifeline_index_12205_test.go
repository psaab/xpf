package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

// #12205 (C-016/U-024 <- D8-10): the idx != 0 refusal in setupBootstrapLifeline
// (bootstrap.go:1193-1215) was executed by NO test. Every fixture put the
// lifeline at enumeration index 0 — staticLifelineSeams enumerates one NIC
// named fxp0 (lifeline_snapshot_failclosed_6789_test.go:48-50) and the #7114
// wiring test enumerates one NIC named enp5s0
// (bootstrap_appliance_factory_7114_test.go:229-231) — so the branch that
// refuses to rename/cycle a management NIC which would not become fxp0 was
// covered by nothing.
//
// Production is correct as-is: the guard is explicit and returns before the
// .network write, the .link write, the rename and the reload. This file is
// TEST-ONLY. The two cells drive the REAL setupBootstrapLifeline through its
// existing seams with a SUCCESSFUL default-route observation, and assert the
// refusal contract: no fxp0 .network, no .link, no rename, no reload.
//
// Deliberately NOT asserted: the lifeline record. writeLifelineRecord runs at
// bootstrap.go:1180-1186, BEFORE the index refusal, so a "zero writes
// whatsoever" assertion would misstate the contract (reviewer consensus on
// C-016/U-024). The record may or may not exist; the naming/contract mutations
// must not.
//
// The tightening control already exists:
// TestCompleteObservationStillWritesAndRenames6789 proves index 0 with a
// complete observation still writes, renames and reloads, so a change that
// refuses everywhere cannot satisfy both files.

// lifelineIndexSeams12205 builds on staticLifelineSeams (#6789) with the
// fixture shape #12205 needs: the given enumeration, a SUCCESSFUL
// default-route observation naming lifeline, and observable (static)
// addressing. The addressing observation succeeds on purpose: under a weakened
// guard the snapshot completes and the .network/rename/reload all run, which
// is what makes the cells below fail on the mutant instead of passing
// vacuously through a later refusal.
func lifelineIndexSeams12205(t *testing.T, lifeline string, nics []pciNIC) lifelineSeamState {
	t.Helper()
	st := staticLifelineSeams(t)
	detectLifelineInterfaceFn = func() (string, bool, error) { return lifeline, true, nil }
	enumeratePCINICsFn = func() ([]pciNIC, error) { return nics, nil }
	lifelineLinkByName = func(string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: lifeline, Index: 7}}, nil
	}
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return nil, nil
	}
	return st
}

// assertLifelineIndexRefused12205 pins the idx != 0 refusal contract: the
// refusal precedes the .network write, the .link write, the rename and the
// reload, so none of them may happen. The pre-guard lifeline record is
// intentionally not examined (see the file comment).
func assertLifelineIndexRefused12205(t *testing.T, st lifelineSeamState, lifeline string, idx int) {
	t.Helper()
	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	if data, err := os.ReadFile(netPath); err == nil {
		t.Errorf("a bootstrap fxp0 .network was written for %s at enumeration index %d; "+
			"only index 0 becomes fxp0, so the lifeline must refuse before the .network "+
			"write (#12205). content:\n%s", lifeline, idx, data)
	}
	if got := filesIn(t, st.linkDir); len(got) != 0 {
		t.Errorf("files were written for %s at enumeration index %d, but the idx != 0 "+
			"refusal must precede the .network AND the .link writes: %v (#12205)",
			lifeline, idx, got)
	}
	if *st.renamed {
		t.Errorf("the management NIC %s at enumeration index %d was RENAMED; it would not "+
			"become fxp0, so renaming it breaks the mgmt naming contract on a box "+
			"reachable only over that NIC (#12205)", lifeline, idx)
	}
	if *st.reloaded {
		t.Errorf("networkctl reload ran for %s at enumeration index %d even though the index refusal "+
			"must precede the .network/.link writes and rename (#12205)", lifeline, idx)
	}
}

// TestSetupBootstrapLifelineRefusesIndex112205: the default route names
// enumeration index 1. That NIC would NOT become fxp0 (idx 0 -> fxp0), so the
// lifeline must refuse before the .network write, the .link write, the rename
// and the reload.
//
// FAIL-ON-REVERT / MUTANT: weakening the guard to `idx < 0` (or deleting it)
// lets index 1 through; the addressing observation succeeds, so the .network
// IS written, the NIC IS renamed and networkd IS reloaded, reddening every
// assertion above.
func TestSetupBootstrapLifelineRefusesIndex112205(t *testing.T) {
	const lifeline = "enp6s0"
	st := lifelineIndexSeams12205(t, lifeline, []pciNIC{
		{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"},
		{sortKey: 1, busAddr: "0000:06:00.0", name: lifeline},
	})

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	assertLifelineIndexRefused12205(t, st, lifeline, 1)
}

// TestSetupBootstrapLifelineRefusesAbsentIndex12205: the default route names a
// NIC that is NOT among the enumerated NICs, so the index lookup finds nothing
// and idx stays -1. Same refusal contract as the index-1 cell.
//
// FAIL-ON-REVERT / MUTANT: weakening the guard to `idx > 0` (or deleting it)
// lets idx -1 through; the addressing observation succeeds, so the .network IS
// written for a NIC that is not even present, the rename IS attempted and
// networkd IS reloaded, reddening every assertion above.
func TestSetupBootstrapLifelineRefusesAbsentIndex12205(t *testing.T) {
	const lifeline = "enp9s0"
	st := lifelineIndexSeams12205(t, lifeline, []pciNIC{
		{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"},
		{sortKey: 1, busAddr: "0000:06:00.0", name: "enp6s0"},
	})

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	assertLifelineIndexRefused12205(t, st, lifeline, -1)
}
