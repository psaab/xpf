package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #10306: the REST *-configuration gates used json.Unmarshal into wider,
// gate-only structs while the handlers used one json.Decoder.Decode into their
// actual request structs. json.Unmarshal rejects trailing bytes and wrong-typed
// unknown fields; the handler ignores unknown fields and accepts trailing data
// after the first JSON value. The old gate returned nil on those decode errors,
// so a restricted caller could reach the handler without an authorization
// verdict.
//
// These cells use the real active login model and invoke the middleware gate
// directly. Each denied row contains an allowed-to-decode body plus a
// gate-only field with the wrong type (or trailing garbage); the gate must
// decode the exact handler struct and still refuse the denied path. Each
// allowed row is a narrowness control: changing the fix to reject every body
// would satisfy the denial rows but break legitimate configuration.

func restGateFixture10306(t *testing.T) (*Server, authz.Principal, *config.Config) {
	t.Helper()
	store := authzStore(t, config9154)
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("fixture has no active config")
	}
	return &Server{}, authz.Principal{Class: "limited"}, cfg
}

func runRESTGate10306(t *testing.T, s *Server, cfg *config.Config, p authz.Principal, route, body string) error {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
	var err error
	if _, ok := restConfigMutationRoutes["POST "+route]; ok {
		err = s.authorizeRESTConfigMutation(r, cfg, p)
	} else {
		err = s.authorizeRESTConfigLoad(r, cfg, p)
	}
	got, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		t.Fatalf("gate did not restore request body: %v", readErr)
	}
	if string(got) != body {
		t.Fatalf("gate changed request body: got %q want %q", got, body)
	}
	return err
}

func TestRESTGateUsesExactHandlerStructs10306(t *testing.T) {
	cases := []struct {
		name       string
		route      string
		deniedBody string
		allowBody  string
	}{
		{
			name:       "set path is gate-only",
			route:      "/api/v1/config/set",
			deniedBody: `{"input":"system root-authentication","path":42}`,
			allowBody:  `{"input":"system host-name allowed10306","path":42}`,
		},
		{
			name:       "delete path is gate-only",
			route:      "/api/v1/config/delete",
			deniedBody: `{"input":"system root-authentication","path":42}`,
			allowBody:  `{"input":"system host-name","path":42}`,
		},
		{
			name:       "deactivate path is gate-only",
			route:      "/api/v1/config/deactivate",
			deniedBody: `{"input":"system root-authentication","path":42}`,
			allowBody:  `{"input":"system host-name","path":42}`,
		},
		{
			name:       "activate path is gate-only",
			route:      "/api/v1/config/activate",
			deniedBody: `{"input":"system root-authentication","path":42}`,
			allowBody:  `{"input":"system host-name","path":42}`,
		},
		{
			name:       "annotate input is gate-only",
			route:      "/api/v1/config/annotate",
			deniedBody: `{"path":"system root-authentication","comment":"reviewed","input":42}`,
			allowBody:  `{"path":"system host-name","comment":"reviewed","input":42}`,
		},
		{
			name:       "load n is gate-only",
			route:      "/api/v1/config/load",
			deniedBody: `{"mode":"merge","content":"system { root-authentication { plain-text-password hunter2; } }","n":"bad"}`,
			allowBody:  `{"mode":"merge","content":"system { host-name allowed10306; }","n":"bad"}`,
		},
		{
			name:       "rollback mode is gate-only",
			route:      "/api/v1/config/rollback",
			deniedBody: `{"n":1,"mode":42}`,
			allowBody:  `{"n":0,"mode":42}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+" denied", func(t *testing.T) {
			s, p, cfg := restGateFixture10306(t)
			if err := runRESTGate10306(t, s, cfg, p, tc.route, tc.deniedBody); err == nil {
				t.Fatalf("gate allowed denied path in %s with handler-ignored wrong-typed field", tc.route)
			}
		})
		t.Run(tc.name+" allowed control", func(t *testing.T) {
			s, p, cfg := restGateFixture10306(t)
			if err := runRESTGate10306(t, s, cfg, p, tc.route, tc.allowBody); err != nil {
				t.Fatalf("gate refused allowed path in %s: %v", tc.route, err)
			}
		})
	}
}

func TestRESTGateUsesHandlerDecoderForTrailingData10306(t *testing.T) {
	for _, tc := range []struct {
		name       string
		route      string
		deniedBody string
		allowBody  string
	}{
		{
			name:       "path mutation",
			route:      "/api/v1/config/set",
			deniedBody: `{"input":"system root-authentication"} trailing-garbage`,
			allowBody:  `{"input":"system host-name allowed10306"} trailing-garbage`,
		},
		{
			name:       "content load",
			route:      "/api/v1/config/load",
			deniedBody: `{"mode":"merge","content":"system { root-authentication { plain-text-password hunter2; } }"} trailing-garbage`,
			allowBody:  `{"mode":"merge","content":"system { host-name allowed10306; }"} trailing-garbage`,
		},
	} {
		t.Run(tc.name+" denied", func(t *testing.T) {
			s, p, cfg := restGateFixture10306(t)
			if err := runRESTGate10306(t, s, cfg, p, tc.route, tc.deniedBody); err == nil {
				t.Fatalf("gate allowed denied path with trailing data in %s", tc.route)
			}
		})
		t.Run(tc.name+" allowed control", func(t *testing.T) {
			s, p, cfg := restGateFixture10306(t)
			if err := runRESTGate10306(t, s, cfg, p, tc.route, tc.allowBody); err != nil {
				t.Fatalf("gate refused allowed path with handler-compatible trailing data in %s: %v", tc.route, err)
			}
		})
	}
}
