package dataplane

import (
	"strings"
	"testing"
)

// #19110 review (R23 P2-1): the stale-link reclaim DETACHES real links. Every
// test in this package therefore runs with a guard that panics if a reclaim, a
// sweep or a pin repair reaches the production pin directory. A test that
// reaches the attach path must redirect linkPinPath first
// (withTempPinDir9847 or SetLinkPinPathForTest).
func init() { GuardProductionPinDirForTest() }

func TestProductionPinDirGuardFires19110(t *testing.T) {
	if linkPinPath != productionLinkPinPath {
		t.Fatalf("fixture: linkPinPath = %q at test start, want the production default", linkPinPath)
	}
	for name, fn := range map[string]func(){
		"reclaim": func() { reclaimStaleXDPLinkPin(productionLinkPinPath + "/xdp_5") },
		"sweep":   func() { removeUserspaceShimXDPLinkPinsExcept(productionLinkPinPath, nil) },
		"repair":  func() { _ = ensureXDPLinkPinned(5, &pinTrackingLink9847{}) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil || !strings.Contains(r.(string), "PRODUCTION XDP link pin directory") {
					t.Fatalf("%s against the production pin directory did not panic (recovered %v)", name, r)
				}
			}()
			fn()
		})
	}
	restore := SetLinkPinPathForTest(t.TempDir())
	defer restore()
	removeUserspaceShimXDPLinkPinsExcept(linkPinPath, nil) // redirected: no panic
}

// The first line of defence: installing the #18740 transition seam moves the pin
// directory off the production default for as long as the seam is installed,
// and puts it back afterwards.
func TestTransitionSeamRedirectsTheProductionPinDir19110(t *testing.T) {
	if linkPinPath != productionLinkPinPath {
		t.Fatalf("fixture: linkPinPath = %q at test start, want the production default", linkPinPath)
	}
	restore := SetXDPTransitionSeamForTest(func(string, int, bool) (bool, error) { return true, nil })
	if linkPinPath == productionLinkPinPath {
		restore()
		t.Fatal("SetXDPTransitionSeamForTest left linkPinPath on the production directory; a seamed " +
			"attach pass would reclaim the live firewall's pins (#19110)")
	}
	restore()
	if linkPinPath != productionLinkPinPath {
		t.Errorf("restore left linkPinPath = %q, want the production default back", linkPinPath)
	}
}
