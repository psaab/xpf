package grpcapi

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #18760: a streaming method declared request-INDEPENDENT in
// streamRequestSpec17175 is priced twice: once at open on its typed empty
// request (authorizeStreamOpenContext) and again on the decoded first message
// (authzRecvStream.RecvMsg). Both verdicts must pass, so for a method whose
// rpcArgumentForms depend on the request the open-time verdict can only be
// STRICTER than the true one. An argument-scoped deny is still applied on the
// first message; what breaks is an argument-scoped allow: the empty request's
// bare charge does not match it, so open refuses a request the class admits.
// MonitorPacketDrop was declared request-independent after #17184 gave it an
// argument-forms arm.
//
// Every row below is behavioural and runs the real interceptor. The allow
// rows are the ones a request-independent declaration breaks; the deny rows
// show the first-message gate still discriminates on arguments; the controls
// keep a fix that admits or refuses everything from passing.

const streamArgsConfig18760 = `
system {
    host-name authz-18760;
    login {
        class narrow-deny {
            permissions view;
            deny-commands "^(ping|traceroute) 10\.99\.|^monitor interface ge-0/0/9|^monitor security packet-drop source-prefix 10\.99\.";
        }
        class narrow-allow {
            permissions view;
            allow-commands "^(ping|traceroute) 10\.99\.|^monitor interface ge-0/0/9|^monitor security packet-drop source-prefix 10\.99\.";
        }
        user opsuser {
            class narrow-deny;
        }
        user allowuser {
            class narrow-allow;
        }
    }
}
`

const (
	uidNarrowDeny18760  = uidPingDeny17175  // opsuser
	uidNarrowAllow18760 = uidDiagAllow17175 // allowuser
)

// streamArgRows18760 has one entry per served stream: the typed empty
// request the generated handler would decode from an empty message, a
// request whose argument text the narrow classes name, and one they do not.
var streamArgRows18760 = map[string]struct{ empty, named, other func() any }{
	"Ping": {
		func() any { return &pb.PingRequest{} },
		func() any { return &pb.PingRequest{Target: "10.99.1.1"} },
		func() any { return &pb.PingRequest{Target: "10.98.1.1"} },
	},
	"Traceroute": {
		func() any { return &pb.TracerouteRequest{} },
		func() any { return &pb.TracerouteRequest{Target: "10.99.1.1"} },
		func() any { return &pb.TracerouteRequest{Target: "10.98.1.1"} },
	},
	"MonitorInterface": {
		func() any { return &pb.MonitorInterfaceRequest{} },
		func() any { return &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/9"} },
		func() any { return &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/8"} },
	},
	"MonitorPacketDrop": {
		func() any { return &pb.MonitorPacketDropRequest{} },
		func() any {
			return &pb.MonitorPacketDropRequest{SourcePrefix: "10.99.1.0/24", Protocol: "tcp", Count: 1}
		},
		func() any {
			return &pb.MonitorPacketDropRequest{SourcePrefix: "10.98.1.0/24", Protocol: "tcp", Count: 1}
		},
	},
}

// streamVerdict18760 runs one stream through the interceptor and reports
// whether the handler was entered (admitted) or the stream was refused with
// PermissionDenied. Any other outcome fails the test.
func streamVerdict18760(t *testing.T, uid uint32, method string, req any) (admitted bool) {
	t.Helper()
	s := streamServer17175(t, streamArgsConfig18760)
	errc, entered, cancel := runStream17175(t, s, uid, fullMethod17175(method), req)
	defer cancel()
	select {
	case <-entered:
		cancel()
		select {
		case <-errc:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: admitted stream did not end on hangup", method)
		}
		return true
	case err := <-errc:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: verdict = %v (code %v), want admission or PermissionDenied", method, err, status.Code(err))
		}
		return false
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: no verdict", method)
	}
	return false
}

func TestStreamArgumentScopedAllowAdmitsNamedRequest18760(t *testing.T) {
	shortenStreamReauth9051(t)
	for method, row := range streamArgRows18760 {
		t.Run(method, func(t *testing.T) {
			if !streamVerdict18760(t, uidNarrowAllow18760, method, row.named()) {
				t.Errorf("%s: a class whose allow-commands names this request's arguments was refused. "+
					"The stream was priced on its typed EMPTY request at open, whose bare charge the "+
					"argument-scoped allow cannot match (#18760)", method)
			}
			if streamVerdict18760(t, uidNarrowAllow18760, method, row.other()) {
				t.Errorf("%s: control: a request the allow-commands does not name was admitted, so the allow is not discriminating", method)
			}
		})
	}
}

func TestStreamArgumentScopedDenyRefusesNamedRequest18760(t *testing.T) {
	shortenStreamReauth9051(t)
	for method, row := range streamArgRows18760 {
		t.Run(method, func(t *testing.T) {
			if streamVerdict18760(t, uidNarrowDeny18760, method, row.named()) {
				t.Errorf("%s: a request whose arguments a deny-commands names was admitted (#18760)", method)
			}
			if !streamVerdict18760(t, uidNarrowDeny18760, method, row.other()) {
				t.Errorf("%s: control: a request the deny-commands does not name was refused, so the deny is not discriminating", method)
			}
		})
	}
}

// TestStreamWithArgumentFormsIsRequestDependent18760 keeps the behavioural
// rows above honest and complete: every served stream must have a row, and a
// row's named request must produce argument forms different from its TYPED
// EMPTY request (what open would price for a request-independent declaration),
// unless the method is argument-free (methodsWithoutArgumentForms). Where the
// forms differ, the stream must be declared request-dependent. That rule is
// the contrapositive of #17175's F3 census (needsRequest=false => no
// request-priced arm); stating it per row here is what ties the allow/deny
// cells to the spec, so a row that stops exercising an argument fails.
func TestStreamWithArgumentFormsIsRequestDependent18760(t *testing.T) {
	desc := pb.BpfrxService_ServiceDesc
	cfg := streamCensusCfg17175(t)
	for _, sd := range desc.Streams {
		row, ok := streamArgRows18760[sd.StreamName]
		if !ok {
			t.Errorf("stream %s has no argument row in streamArgRows18760; add one so its admit/deny behaviour is pinned (#18760)", sd.StreamName)
			continue
		}
		full := "/" + desc.ServiceName + "/" + sd.StreamName
		named := row.named()
		base, resolved := rpcCanonicalCommand(full, named)
		if !resolved {
			t.Errorf("%s: no canonical command for the named request", full)
			continue
		}
		namedForms, namedOK := rpcArgumentForms(cfg, full, named, base)
		emptyForms, emptyOK := rpcArgumentForms(cfg, full, row.empty(), base)
		dependent := namedOK != emptyOK || fmt.Sprint(namedForms) != fmt.Sprint(emptyForms)
		if dependent && !streamNeedsRequest17175(full) {
			t.Errorf("%s: rpcArgumentForms depends on the request (named=%v/%v typed-empty=%v/%v) but streamRequestSpec17175 declares it request-independent, so open prices the typed empty request (#18760)",
				full, namedForms, namedOK, emptyForms, emptyOK)
		}
		if _, argFree := methodsWithoutArgumentForms[sd.StreamName]; !dependent && !argFree {
			t.Errorf("%s: the named request produced the same argument forms as the typed empty request (%v); the row does not exercise an argument (#18760)", full, namedForms)
		}
	}
}
