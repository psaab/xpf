package api

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/argforms"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #17179 (R4-Q37-02): REST and gRPC must judge the SAME argument-bearing
// command for the same operator intent. Pre-fix the two surfaces carried
// hand-cloned reconstructors that disagreed in opposite directions:
//   - Divergence A: gRPC MatchPolicies{Protocol:"tcp"} with no zones/IPs
//     returned the bare charge (allowed under `protocol tcp`), while REST
//     match?protocol=tcp kept the selector (denied) — the on-box verdict.
//   - Divergence B: REST /security/events had no reconstruction arm, so
//     events?protocol=tcp judged the bare `show log` charge (allowed
//     under `^show security log protocol tcp$`), while
//     GetEvents{Protocol:"tcp"} was denied.
//   - Divergence C: the REST show-text decoder decoded packed/detail
//     topics showTextHandler 400s, manufacturing gate verdicts for
//     requests that never run, while every served (bare) topic fell
//     through to the bare return.
//
// The parity cells below run each {pattern, request} pair through BOTH
// real gates — authorizeRESTCommand (REST) and the shared argforms
// reconstruction judged with the same rules (the gRPC gate's exact
// EvaluateForms call, mirrored in grpcVerdict17179) — and require equal
// verdicts. The gRPC-side gate itself (authorizeRPCCommand) is exercised
// by TestMatchPoliciesNoZoneParityGRPC17179 in pkg/grpcapi, which pins
// the same cells through the real gRPC gate.

func cfg17179(t *testing.T, deny string) *config.Config {
	t.Helper()
	text := `
system {
    host-name authz-17179;
    login {
        class limited {
            permissions [ view clear maintenance ];
            deny-commands "` + deny + `";
        }
        user opsuser { class limited; }
    }
    security { zones { security-zone trust; security-zone secret-zone; security-zone untrust; } }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture does not compile: %v", err)
	}
	if _, ok, err := config.OperationalLoginRegexesFor(cfg, "limited"); err != nil || !ok {
		t.Fatalf("fixture premise: limited must carry operational regexes (ok=%v err=%v)", ok, err)
	}
	return cfg
}

// grpcVerdict17179 judges wire-request forms through the shared
// reconstruction exactly as authorizeRPCCommand does (EvaluateForms
// unanimity over forms[0] + forms[1:]). It exists because pkg/api must
// not import pkg/grpcapi's gate; the forms themselves come from the
// one shared implementation, so equality here is equality of the judged
// strings, not of two reconstructions.
func grpcVerdict17179(t *testing.T, cfg *config.Config, forms []string, named bool) bool {
	t.Helper()
	if !named {
		return false // unnameable denies for a restricted class
	}
	rules, ok, err := config.OperationalLoginRegexesFor(cfg, "limited")
	if err != nil || !ok {
		t.Fatalf("rules premise: ok=%v err=%v", ok, err)
	}
	return rules.EvaluateForms(forms[0], forms[0], forms[1:]...).Allowed
}

func TestRESTGRPCArgFormParity17179(t *testing.T) {
	trustID := config.StableZoneID("trust")
	zero := int32(0)
	tcp := "tcp"

	// Each cell: one operator intent expressed on both surfaces.
	// rest forms come from the REAL REST gate precursors
	// (restArgumentForms, the function authorizeRESTCommand judges);
	// grpc forms come from the shared reconstruction fed the wire
	// request the gRPC handler would receive.
	type cell struct {
		name    string
		pattern string
		// REST: route + path (charged cmd resolved by the test).
		route, path, restCmd string
		// gRPC: shared forms for the equivalent wire request.
		grpcForms func(cfg *config.Config) ([]string, bool)
		wantDeny  bool
	}
	cells := []cell{
		{
			name: "events protocol denied both", pattern: `^show security log protocol tcp$`,
			route: "GET /api/v1/security/events", path: "/api/v1/security/events?protocol=tcp", restCmd: "show log",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.EventsForms(cfg, &pb.GetEventsRequest{Protocol: tcp}, "show log")
			},
			wantDeny: true,
		},
		{
			name: "events protocol other allowed both", pattern: `^show security log protocol tcp$`,
			route: "GET /api/v1/security/events", path: "/api/v1/security/events?protocol=udp", restCmd: "show log",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.EventsForms(cfg, &pb.GetEventsRequest{Protocol: "udp"}, "show log")
			},
			wantDeny: false,
		},
		{
			name: "events zone denied both", pattern: `^show security log zone trust$`,
			route: "GET /api/v1/security/events", path: "/api/v1/security/events?zone=" + uitoa(uint(trustID)), restCmd: "show log",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.EventsForms(cfg, &pb.GetEventsRequest{Zone: uint32(trustID), HasZone: true}, "show log")
			},
			wantDeny: true,
		},
		{
			name: "events unfiltered allowed both", pattern: `^show security log zone trust$`,
			route: "GET /api/v1/security/events", path: "/api/v1/security/events", restCmd: "show log",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.EventsForms(cfg, &pb.GetEventsRequest{}, "show log")
			},
			wantDeny: false,
		},
		{
			name: "match protocol no zones denied both", pattern: `protocol tcp`,
			route: "GET /api/v1/security/match", path: "/api/v1/security/match?protocol=tcp", restCmd: "show security match-policies",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.MatchForms(&pb.MatchPoliciesRequest{Protocol: tcp}, "show security match-policies")
			},
			wantDeny: true,
		},
		{
			name: "match protocol no zones other allowed both", pattern: `protocol tcp`,
			route: "GET /api/v1/security/match", path: "/api/v1/security/match?protocol=udp", restCmd: "show security match-policies",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.MatchForms(&pb.MatchPoliciesRequest{Protocol: "udp"}, "show security match-policies")
			},
			wantDeny: false,
		},
		{
			name: "match no selectors bare both", pattern: `^show security match-policies$`,
			route: "GET /api/v1/security/match", path: "/api/v1/security/match", restCmd: "show security match-policies",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.MatchForms(&pb.MatchPoliciesRequest{}, "show security match-policies")
			},
			wantDeny: true,
		},
		{
			name: "match zones denied both", pattern: `^show security match-policies from-zone trust to-zone secret-zone$`,
			route: "GET /api/v1/security/match", path: "/api/v1/security/match?from_zone=trust&to_zone=secret-zone", restCmd: "show security match-policies",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.MatchForms(&pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "secret-zone"}, "show security match-policies")
			},
			wantDeny: true,
		},
		{
			name: "match dst port zero denied both", pattern: `destination-port 0`,
			route: "GET /api/v1/security/match", path: "/api/v1/security/match?from_zone=trust&to_zone=untrust&protocol=udp&dst_port=0", restCmd: "show security match-policies",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.MatchForms(&pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "untrust", Protocol: "udp", DestinationPort: &zero}, "show security match-policies")
			},
			wantDeny: true,
		},
		{
			name: "session zone denied both", pattern: `^show security flow session zone trust$`,
			route: "GET /api/v1/security/sessions", path: "/api/v1/security/sessions?zone=" + uitoa(uint(trustID)), restCmd: "show security flow session",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				return argforms.SessionForms(cfg, &pb.GetSessionsRequest{Zone: uint32(trustID)}, "show security flow session")
			},
			wantDeny: true,
		},
		{
			name: "show-text served topic allowed under packed deny both", pattern: `^show route table secret-vrf$`,
			route: "GET /api/v1/show-text", path: "/api/v1/show-text?topic=applications", restCmd: "show security applications",
			grpcForms: func(cfg *config.Config) ([]string, bool) {
				// gRPC ShowText with the bare topic: the registry charge.
				// (The REST charge for topic=applications is the same
				// string via cmdtree.ShowTextTopicCommands.)
				return argforms.ShowTextFormsFor("show security applications", "applications", "")
			},
			wantDeny: false,
		},
	}

	for _, tc := range cells {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfg17179(t, tc.pattern)

			// REST verdict through the real gate.
			restErr := call9952(t, cfg, "limited", "GET", tc.path, "")
			restAllowed := restErr == nil

			// gRPC verdict through the shared reconstruction + the
			// gate's EvaluateForms unanimity.
			forms, named := tc.grpcForms(cfg)
			grpcAllowed := grpcVerdict17179(t, cfg, forms, named)

			if restAllowed != grpcAllowed {
				t.Errorf("PARITY BREAK: pattern %q — REST allowed=%v (%v), gRPC allowed=%v (forms=%v named=%v); the two surfaces must judge the same command (#17179)", tc.pattern, restAllowed, restErr, grpcAllowed, forms, named)
			}
			if tc.wantDeny && restAllowed {
				t.Errorf("pattern %q over REST %s was ALLOWED; both surfaces must deny (#17179)", tc.pattern, tc.path)
			}
			if !tc.wantDeny && !restAllowed {
				t.Errorf("pattern %q over REST %s refused a command it does not name: %v", tc.pattern, tc.path, restErr)
			}
		})
	}
}

// TestRestShowTextTopicsCensus17179 re-derives the topics showTextHandler
// serves from its switch arms in show_text.go (an independent source
// scrape, not the gate map) and requires exact equality with
// restShowTextTopics17179 in both directions. A new handler arm without
// a gate entry would let a served topic be judged by a packed decoder;
// a gate entry without a handler arm manufactures verdicts for 400s.
func TestRestShowTextTopicsCensus17179(t *testing.T) {
	raw, err := os.ReadFile("show_text.go")
	if err != nil {
		t.Fatalf("read show_text.go: %v", err)
	}
	src := string(raw)
	start := strings.Index(src, "func (s *Server) showTextHandler")
	if start < 0 {
		t.Fatal("showTextHandler not found in show_text.go")
	}
	body := src[start:]
	served := map[string]bool{}
	caseRe := regexp.MustCompile(`case\s+((?:"[^"]+"\s*,?\s*)+):`)
	for _, m := range caseRe.FindAllStringSubmatch(body, -1) {
		for _, lit := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			served[lit[1]] = true
		}
	}
	if len(served) == 0 {
		t.Fatal("census scraped zero topics; the scrape is broken, not the handler")
	}
	// "version" is charged by the route (restRequestCommand9952) and
	// pinned as served by #15077/#14712, though showTextHandler 400s
	// it today; the gate set is arms + version (see
	// restShowTextTopics17179). Any OTHER gate entry without a handler
	// arm is a manufactured verdict and fails below.
	served["version"] = true
	var missing, extra []string
	for topic := range served {
		if !restShowTextTopics17179[topic] {
			missing = append(missing, topic)
		}
	}
	for topic := range restShowTextTopics17179 {
		if !served[topic] {
			extra = append(extra, topic)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("showTextHandler serves topics the REST gate does not decode: %v — add them to restShowTextTopics17179 (they are bare topics judged by their charge)", missing)
	}
	if len(extra) > 0 {
		t.Errorf("REST gate decodes topics showTextHandler 400s: %v — remove them from restShowTextTopics17179; no test may assert a gate verdict for an unserved topic (#17179)", extra)
	}
}

// TestRestShowTextUnservedTopicsDeny17179: a packed/detail topic the
// handler 400s is unnameable for a restricted class (denied, never
// judged as its packed spelling), and no cell asserts an ALLOW for one.
// The positive control: a served bare topic is allowed under a deny
// that names only the packed spelling.
func TestRestShowTextUnservedTopicsDeny17179(t *testing.T) {
	// Deny that names ONLY the packed spelling: the unserved topic must
	// still deny (unnameable), not slip through as allowed.
	cfg := cfg17179(t, `^show route table secret-vrf$`)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/show-text?topic=route-table:secret-vrf", ""); err == nil {
		t.Error("show-text?topic=route-table:secret-vrf ALLOWED for a restricted class; showTextHandler 400s this topic, so it is unnameable and must deny (#17179)")
	}
	// Fail-on-revert for the restriction itself: under a deny that does
	// NOT name the packed spelling, decoding it (the pre-fix clone)
	// ALLOWED the request; the restriction denies it as unnameable.
	cfg = cfg17179(t, `^show version$`)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/show-text?topic=route-table:secret-vrf", ""); err == nil {
		t.Error("show-text?topic=route-table:secret-vrf ALLOWED under ^show version$; decoding the packed spelling would allow it — the served-topic restriction must deny it as unnameable (#17179)")
	}
	// Same for a packed applications topic under a version-only deny:
	// pre-fix the REST decoder judged this topic; it happens to be
	// unnameable in the shared decoder too (the applications charge
	// takes no name argument), so this cell pins the outcome, while
	// the route-table cell above is the fail-on-revert.
	cfg = cfg17179(t, `^show version$`)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/show-text?topic=applications:secret-app", ""); err == nil {
		t.Error("show-text?topic=applications:secret-app ALLOWED; an unserved packed topic must deny for a restricted class (#17179)")
	}
	// Packed spelling that WOULD be denied if decoded must deny for the
	// unnameable reason too — asserted via the error text so a future
	// decoder-restoration that happens to deny cannot pass silently
	// for the wrong reason.
	cfg = cfg17179(t, `^show security applications secret-app$`)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/show-text?topic=applications:secret-app", ""); err == nil {
		t.Error("show-text?topic=applications:secret-app ALLOWED under its packed-spelling deny; unserved topics deny regardless (#17179)")
	} else if !strings.Contains(err.Error(), "cannot be named") && !strings.Contains(err.Error(), "arguments cannot be") {
		t.Errorf("unserved topic denial should name the unnameable-arguments cause, got: %v", err)
	}
	// Positive control: the served bare topic is judged by its charge
	// and allowed under a deny naming only the packed spelling.
	cfg = cfg17179(t, `^show route table secret-vrf$`)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/show-text?topic=applications", ""); err != nil {
		t.Errorf("served topic=applications refused by a packed-spelling deny it does not name: %v", err)
	}
	// And denied by a deny naming its own charge.
	cfg = cfg17179(t, `^show security applications$`)
	if err := call9952(t, cfg, "limited", "GET", "/api/v1/show-text?topic=applications", ""); err == nil {
		t.Error("served topic=applications ALLOWED under its own charge deny; the bare-topic charge must fire (#17179)")
	}
}
