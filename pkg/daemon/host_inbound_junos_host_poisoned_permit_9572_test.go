package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestJunosHostPoisonedPermitKeepsRenderedDrop9572 checks the #9572 fix at the
// layer the daemon installs: the nft payload built from BuildJunosHostPrograms.
// p0 is a permit with an EMPTY source dimension, which is what the tolerant
// compile leaves behind when it drops a source-address. The two rows differ
// ONLY in the #5575 LenientContentDropped flag. Unflagged, it is an authored
// permit-all and legitimately shadows the deny. Flagged, the helper refuses it,
// so the deny's DROP line must be in the payload as authored.
func TestJunosHostPoisonedPermitKeepsRenderedDrop9572(t *testing.T) {
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	drop := `iifname "ge-0-0-1" ip saddr 10.0.0.0/8 counter name "` + cn + `" drop`
	for _, poisoned := range []bool{false, true} {
		cfg := junosHostDenyTestConfig()
		p0 := permitPolicy("p0", "app:any")
		p0.LenientContentDropped = poisoned
		cfg.Security.Policies = []*config.ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
				p0,
				denyPolicy("p1", "src:bad-net", "app:any"),
			}},
		}
		payload, _ := junosHostPayload(t, cfg)
		got := strings.Contains(payload, drop)
		switch {
		case poisoned && !got:
			t.Errorf("poisoned p0 erased p1 from the installed program; want %q in:\n%s", drop, payload)
		case !poisoned && got:
			t.Errorf("control: an authored permit-all must shadow p1, yet the payload carries %q:\n%s", drop, payload)
		}
	}
}
