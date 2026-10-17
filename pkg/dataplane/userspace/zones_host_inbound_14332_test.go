// #14332: a lifeline slave enslaved to a VRF must not blanket-suppress
// co-VRF non-lifeline claims. The ambiguous fail-closed deny and the
// unambiguous flood-screen ingress are per-slave (meta sdifname) concerns;
// collapsing lifelines to their VRF master erased both for every sibling.
package userspace

import (
	"reflect"
	"testing"
)

func TestHostInboundIngressClaimsDoesNotBlanketSuppressSharedVRFWithLifeline(t *testing.T) {
	sigData := "data\x00ssh"
	sigOther := "other\x00ping"
	// One lifeline slave + one ambiguous non-lifeline slave + one
	// unambiguous non-lifeline slave, all enslaved to vrf-mgmt.
	claims := map[string]map[string]bool{
		"lifeline-slave":  {sigData: true},
		"ambiguous-slave": {sigData: true, sigOther: true},
		"data-slave":      {sigData: true},
	}
	lifelines := map[string]bool{"lifeline-slave": true}
	enslaved := map[string]bool{"lifeline-slave": true, "ambiguous-slave": true, "data-slave": true}
	masters := map[string]string{
		"lifeline-slave":  "vrf-mgmt",
		"ambiguous-slave": "vrf-mgmt",
		"data-slave":      "vrf-mgmt",
	}

	got := hostInboundIngressClaims(claims, lifelines, enslaved, masters)

	// The master target must retain BOTH non-lifeline signatures: the
	// ambiguous slave contributes two sigs and the data slave one. If the
	// lifeline blanket erased them, the target would be absent entirely.
	target, ok := got["vrf-mgmt"]
	if !ok {
		t.Fatalf("claims = %v, want vrf-mgmt target surviving from non-lifeline slaves (lifeline blanket suppressed it)", got)
	}
	if !target[sigData] || !target[sigOther] || len(target) != 2 {
		t.Fatalf("claims[vrf-mgmt] = %v, want {%q, %q}", target, sigData, sigOther)
	}
	// No raw slave name may appear as a target for VRF-enslaved netdevs.
	for name := range got {
		if name != "vrf-mgmt" {
			t.Fatalf("unexpected claim target %q in %v", name, got)
		}
	}

	// Ambiguous half (#10431): the master has >1 sig, so it must be in the
	// deny list — pre-fix it was empty.
	if deny := hostInboundViewIngressDenyNetdevs(claims, lifelines, enslaved, masters); !reflect.DeepEqual(deny, []string{"vrf-mgmt"}) {
		t.Fatalf("IngressDenyNetdevs = %v, want [vrf-mgmt] (ambiguous co-VRF slave must stay fail-closed)", deny)
	}

	// Unambiguous half: with only the data slave (plus lifeline), the view
	// for its sig must claim the master — pre-fix it claimed nothing.
	single := map[string]map[string]bool{
		"lifeline-slave": {sigData: true},
		"data-slave":     {sigData: true},
	}
	if got := hostInboundViewIngressNetdevsWithMasters(sigData, single, lifelines, enslaved, masters); !reflect.DeepEqual(got, []string{"vrf-mgmt"}) {
		t.Fatalf("IngressNetdevs for %q = %v, want [vrf-mgmt] (unambiguous co-VRF slave must stay flood-screen scoped)", sigData, got)
	}
	// And the other sig must claim nothing.
	if got := hostInboundViewIngressNetdevsWithMasters(sigOther, single, lifelines, enslaved, masters); len(got) != 0 {
		t.Fatalf("IngressNetdevs for %q = %v, want empty", sigOther, got)
	}
}
