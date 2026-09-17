package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9993 — the tuple gate (:1100-1103) precedes the content-rejection gate
// (:1144-1145), so an unsupported (V4 src, V6 dst) tuple returned Deny + the
// dedicated tuple string while a whole-config retention problem went
// unreported — contradicting the in-file contract "every query for the config
// reports the runtime's retention" (#3727/#4394). The tuple verdict itself is
// true and conservative; no enforcement path reads it. Advisory precedence
// defect only.
//
// Fix: stamp the retention advisory onto the UnsupportedTuple result (the
// #4373 defer-stamp idiom: advisory rides the verdict without changing it),
// keeping UnsupportedTupleFamily=true and conservative Action=Deny while
// making ContentRejected win DisplayAction precedence. REST carries
// ContentRejected plus reasons; gRPC MatchPolicies has no dedicated fields
// and surfaces retention through Action=ContentRejectedActionString. The
// hand-rolled ShowText surfaces already check ContentRejected first.
//
// RED-ON-REVERT: drop the retention stamping in the tuple branch and
// ContentRejected is false / reasons empty for the mixed-tuple query below.
func TestUnsupportedTupleStillReportsRetention9993(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-undef-app",
				config.PolicyMatch{Applications: []string{"no-such-app"}})),
		},
	}, config.ApplicationsConfig{})

	// Same-family control: the config IS content-rejected for an ordinary
	// query, so the mixed-tuple query below must report it too.
	control := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if !control.ContentRejected {
		t.Fatalf("control: ContentRejected = false, want true for undefined-app config (res=%+v)", control)
	}

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("2001:db8::1"),
	})
	if !res.UnsupportedTupleFamily {
		t.Fatalf("UnsupportedTupleFamily = false, want true for (V4 src, V6 dst) (res=%+v)", res)
	}
	if !res.ContentRejected {
		t.Fatalf("ContentRejected = false, want true: unsupported-tuple query must still surface retention (res=%+v)", res)
	}
	if reason := strings.Join(res.ContentRejectionReasons, " | "); !strings.Contains(reason, "trust->untrust/permit-undef-app") {
		t.Fatalf("reasons %q do not name offending scope trust->untrust/permit-undef-app", reason)
	}
	if res.Matched || res.DefaultUsed || res.HostInboundUnmatched {
		t.Fatalf("Matched=%v DefaultUsed=%v HostInboundUnmatched=%v, want all false (res=%+v)",
			res.Matched, res.DefaultUsed, res.HostInboundUnmatched, res)
	}
	if res.Action != config.PolicyDeny {
		t.Fatalf("Action = %v, want conservative Deny", res.Action)
	}
	if got := res.DisplayAction(); got != ContentRejectedActionString {
		t.Fatalf("DisplayAction = %q, want retention-first ContentRejectedActionString", got)
	}
}

// TestUnsupportedTupleNoOverReport9993 is the non-regression control: a
// healthy config queried with an unsupported tuple reports the tuple verdict
// WITHOUT a retention advisory — the stamp fires ONLY when the config is
// actually content-rejected.
func TestUnsupportedTupleNoOverReport9993(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-all",
				config.PolicyMatch{Applications: []string{"junos-http"}})),
		},
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("2001:db8::1"),
	})
	if !res.UnsupportedTupleFamily {
		t.Fatalf("UnsupportedTupleFamily = false, want true (res=%+v)", res)
	}
	if res.ContentRejected || len(res.ContentRejectionReasons) != 0 {
		t.Fatalf("healthy config must not report retention: ContentRejected=%v reasons=%v",
			res.ContentRejected, res.ContentRejectionReasons)
	}
}
