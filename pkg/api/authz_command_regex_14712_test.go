package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #14712: a safe non-GET method (HEAD) bypassed command-regex route
// resolution in authorizeRESTCommand.
//
// readPermissionFor (#9134) canonicalizes any safe non-GET method to the
// GET table entry, so HEAD /api/v1/status passes the coarse PermView gate
// and reaches authorizeRESTRead -> authorizeRESTCommand. There the route
// was keyed on the raw r.Method, so "HEAD /api/v1/status" missed every
// GET-keyed table (restRouteCommand, restRoutesNoCommand, and the
// request-decoded switch) and hit the fail-closed !mapped denial.
// Every regex-restricted (non-superuser) class therefore got 403 on
// 100% of HEAD reads while GET succeeded — a fail-closed availability
// defect, not an authorization bypass.
//
// Only HEAD is reachable this way: Go's ServeMux aliases HEAD to GET
// patterns; OPTIONS/TRACE have no GET pattern and never reach the GET
// handler (the coarse gate's /api/v1 fail-closed arm or the mux 405
// stops them first). The fix therefore canonicalizes the route only for
// safe methods, mirroring readPermissionFor: the GET entry governs any
// safe method that can reach its handler.
//
// These cells call authorizeRESTCommand directly (the evaluator) and
// drive the real read middleware (the wiring). Both are needed: a test
// that only calls the gate proves the gate decides; only a test through
// readAuthz proves the decision is obeyed on HEAD requests.

const wiringConfig14712 = `
system {
    host-name authz-14712-wiring;
    login {
        class limited {
            permissions [ view clear maintenance ];
            allow-commands "^show ";
        }
        user opsuser {
            class limited;
        }
    }
}
`

func principalLimited14712() authz.Principal  { return authz.Principal{Class: "limited"} }
func principalWideopen14712() authz.Principal { return authz.Principal{Class: "wideopen"} }
func principalSuperuser14712() authz.Principal {
	return authz.Principal{Class: "limited", Superuser: true}
}

func runGuardedReadMethod14712(t *testing.T, s *Server, method, url string) *httptest.ResponseRecorder {
	t.Helper()
	connCtx := s.connContext(context.Background(), slotConn{
		client: tcpAddr6974("127.0.0.1", 40051),
		server: tcpAddr6974("127.0.0.1", 8080),
	})
	r := httptest.NewRequest(method, url, nil).WithContext(connCtx)
	rr := httptest.NewRecorder()
	ran := false
	s.readAuthz(rr, r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		writeOK(w, TextResponse{Output: "handler ran"})
	}))
	if ran && rr.Code != http.StatusOK {
		t.Fatalf("handler ran but status is %d", rr.Code)
	}
	return rr
}

// TestHeadFollowsGetCommandVerdict14712 is the defect itself, asserted
// as AGREEMENT between HEAD and GET rather than as a status for HEAD
// alone — "HEAD is 200" would also be satisfied by a gate that allows
// everything, and "HEAD is 403" by one that refuses everything. The
// decisive regression from the issue: restricted class
// (allow-commands "^show "), GET /api/v1/status allowed, HEAD currently
// 403 (fail-closed !mapped), and after the fix HEAD follows the GET
// verdict including deny cases.
func TestHeadFollowsGetCommandVerdict14712(t *testing.T) {
	// allow-commands "^show version$": /api/v1/show-text?topic=version
	// charges "show version" (allowed); /api/v1/status is a plumbing
	// probe (#15077) admitted by its coarse price on every spelling.
	allowCfg := cfg14146(t, "", "^show version$")
	s := &Server{}
	for _, path := range []string{"/api/v1/status", "/api/v1/show-text?topic=version"} {
		getErr := s.authorizeRESTCommand(httptest.NewRequest(http.MethodGet, path, nil), allowCfg, principalLimited14712())
		headErr := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, path, nil), allowCfg, principalLimited14712())
		if getErr != nil {
			t.Fatalf("control failed: GET %s refused under allow-commands \"^show version$\"; "+
				"the HEAD comparison would prove nothing: %v", path, getErr)
		}
		if headErr != nil {
			t.Errorf("HEAD %s refused (%v) while GET is allowed under allow-commands "+
				"\"^show version$\" — the HEAD route missed the GET-keyed command table (#14712)", path, headErr)
		}
	}

	// DENY direction: a class that denies the command must be refused
	// identically on HEAD and GET ("show version" via topic=version).
	// /api/v1/status is plumbing (#15077) and matches neither side's deny.
	denyCfg := cfg14146(t, "^show version$", "")
	for _, path := range []string{"/api/v1/show-text?topic=version"} {
		getErr := s.authorizeRESTCommand(httptest.NewRequest(http.MethodGet, path, nil), denyCfg, principalLimited14712())
		headErr := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, path, nil), denyCfg, principalLimited14712())
		if getErr == nil {
			t.Fatalf("control failed: GET %s allowed under deny-commands \"^show version$\"; "+
				"the HEAD comparison would prove nothing", path)
		}
		if headErr == nil {
			t.Errorf("HEAD %s ALLOWED under deny-commands \"^show version$\" while GET is "+
				"refused — HEAD bypassed the command regex (#14712)", path)
		} else if !strings.Contains(headErr.Error(), `denies "show version"`) {
			t.Errorf("HEAD %s refusal does not charge \"show version\": %v", path, headErr)
		}
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/config/status"} {
		if err := s.authorizeRESTCommand(httptest.NewRequest(http.MethodGet, path, nil), denyCfg, principalLimited14712()); err != nil {
			t.Errorf("GET %s is session plumbing and must stay admitted under a show-version deny (#15077): %v", path, err)
		}
		if err := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, path, nil), denyCfg, principalLimited14712()); err != nil {
			t.Errorf("HEAD %s is session plumbing and must stay admitted under a show-version deny (#15077): %v", path, err)
		}
	}
}

// TestHeadRequestDecodedFollowsGet14712: the request-decoded routes
// (show-text topic, system/info type) must resolve under HEAD exactly
// as under GET, including deny cases. Before the fix the HEAD route
// missed restRoutesNoCommand entirely, so even a topic the class is
// denied was irrelevant — HEAD hit the generic !mapped denial, and a
// topic the class allows was refused outright.
func TestHeadRequestDecodedFollowsGet14712(t *testing.T) {
	s := &Server{}

	// Topic "version" charges "show version": allowed under an
	// allow-list that permits it, denied under a deny that names it.
	allowCfg := cfg14146(t, "", "^show version$")
	// show-text?topic=version charges "show version".
	if headErr := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, "/api/v1/show-text?topic=version", nil), allowCfg, principalLimited14712()); headErr != nil {
		t.Errorf("HEAD /api/v1/show-text?topic=version refused (%v) under allow-commands \"^show version$\"; "+
			"GET resolves and allows this request-decoded command (#14712)", headErr)
	}
	// system/info?type=uptime charges "show system uptime" (#14146).
	allowUptimeCfg := cfg14146(t, "", "^show system uptime$")
	if headErr := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, "/api/v1/system/info?type=uptime", nil), allowUptimeCfg, principalLimited14712()); headErr != nil {
		t.Errorf("HEAD /api/v1/system/info?type=uptime refused (%v) under allow-commands \"^show system uptime$\"; "+
			"GET resolves and allows this request-decoded command (#14712)", headErr)
	}

	denyVersionCfg := cfg14146(t, "^show version$", "")
	headErr := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, "/api/v1/show-text?topic=version", nil), denyVersionCfg, principalLimited14712())
	if headErr == nil {
		t.Error("HEAD /api/v1/show-text?topic=version ALLOWED under deny-commands \"^show version$\"; " +
			"GET is refused — HEAD bypassed the topic's command regex (#14712)")
	} else if !strings.Contains(headErr.Error(), `denies "show version"`) {
		t.Errorf("HEAD show-text?topic=version refusal does not charge \"show version\": %v", headErr)
	}

	// Unknown topic still denies for a restricted class under HEAD,
	// exactly as under GET (unmapped means deny, #9952/#14146).
	anyCfg := cfg14146(t, "^show version$", "")
	if err := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, "/api/v1/show-text?topic=bogus", nil), anyCfg, principalLimited14712()); err == nil {
		t.Error("HEAD /api/v1/show-text?topic=bogus ALLOWED for a restricted class; an unnamed topic must fail closed (#14712)")
	}
}

// TestHeadNoCommandRoutesFollowGet14712: the six declared-no-command
// reads (#14146) deny for a restricted class on GET; HEAD must deny
// identically rather than via the generic unmapped-route message, and
// — the availability half — a class with NO operational regexes must
// be unaffected on HEAD exactly as on GET.
func TestHeadNoCommandRoutesFollowGet14712(t *testing.T) {
	denyAllCfg := cfg14146(t, ".*", "")
	s := &Server{}
	for _, path := range sixRoutes14146 {
		headErr := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, path, nil), denyAllCfg, principalLimited14712())
		if headErr == nil {
			t.Errorf("HEAD %s ALLOWED under deny-commands \".*\"; GET denies for a restricted class (#14146/#14712)", path)
		}
	}
	// No-regex control: HEAD on every affected shape is unaffected.
	for _, url := range append(append([]string{}, sixRoutes14146...),
		"/api/v1/status", "/api/v1/show-text?topic=version", "/api/v1/system/info?type=memory") {
		if err := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, url, nil), denyAllCfg, principalWideopen14712()); err != nil {
			t.Errorf("HEAD %s refused for a class with NO operational regexes: %v", url, err)
		}
	}
	// Superuser exemption is unchanged under HEAD.
	r := httptest.NewRequest(http.MethodHead, "/api/v1/statistics/interfaces", nil)
	if err := s.authorizeRESTCommand(r, denyAllCfg, principalSuperuser14712()); err != nil {
		t.Fatalf("superuser refused on a HEAD no-command route: %v", err)
	}
}

// TestHeadThroughReadMiddleware14712 drives the real readAuthz
// middleware with an allow-commands "^show " restricted class (the
// issue's decisive fixture): GET /api/v1/status serves, HEAD must
// serve identically, and HEAD on a show-text topic the allow-list
// does not permit must 403 exactly as GET does.
func TestHeadThroughReadMiddleware14712(t *testing.T) {
	usePasswdFixture(t)
	store := authzStore(t, wiringConfig14712)
	s, _ := authzServer(t, Config{
		Addr: "127.0.0.1:0", Store: store, PeerLookupFn: fixedPeerUID(4242), // opsuser -> class limited
	})
	if _, ok, err := config.OperationalLoginRegexesFor(store.ActiveConfig(), "limited"); err != nil || !ok {
		t.Fatalf("the server's active config has no operational regexes for `limited` (ok=%v err=%v); "+
			"this cell would prove nothing", ok, err)
	}

	// GET reference arms, same run, same middleware: the allow-list
	// permits "show version" and refuses a topic charging a command
	// outside "^show " is impossible (every show-text topic is a
	// show/request command), so the deny arm uses the no-command
	// routes, which an allow-list cannot permit (#14146).
	if rr := runGuardedReadMethod14712(t, s, http.MethodGet, "/api/v1/status"); rr.Code != http.StatusOK {
		t.Fatalf("control failed: GET /api/v1/status -> %d, want 200 under allow-commands \"^show \": %s",
			rr.Code, rr.Body.String())
	}
	if rr := runGuardedReadMethod14712(t, s, http.MethodGet, "/api/v1/statistics/interfaces"); rr.Code != http.StatusForbidden {
		t.Fatalf("control failed: GET /api/v1/statistics/interfaces -> %d, want 403 (allow-list cannot "+
			"permit a no-command route): %s", rr.Code, rr.Body.String())
	}

	// The defect: HEAD /api/v1/status was 403 pre-fix (raw-method
	// route missed the GET-keyed tables) while GET served.
	if rr := runGuardedReadMethod14712(t, s, http.MethodHead, "/api/v1/status"); rr.Code != http.StatusOK {
		t.Errorf("HEAD /api/v1/status -> %d, want 200: GET serves this restricted class but HEAD "+
			"was refused by the command gate (#14712): %s", rr.Code, rr.Body.String())
	}
	// HEAD follows the GET verdict on the request-decoded route too.
	if rr := runGuardedReadMethod14712(t, s, http.MethodHead, "/api/v1/show-text?topic=version"); rr.Code != http.StatusOK {
		t.Errorf("HEAD /api/v1/show-text?topic=version -> %d, want 200 under allow-commands \"^show \" (#14712): %s",
			rr.Code, rr.Body.String())
	}
	// Deny direction through the middleware: HEAD on a no-command
	// route 403s exactly as GET does.
	if rr := runGuardedReadMethod14712(t, s, http.MethodHead, "/api/v1/statistics/interfaces"); rr.Code != http.StatusForbidden {
		t.Errorf("HEAD /api/v1/statistics/interfaces -> %d, want 403: GET denies this restricted class (#14712)",
			rr.Code)
	}
}
