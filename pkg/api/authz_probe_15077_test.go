package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #15077 (REST leg): GET /api/v1/status and GET /api/v1/config/status were
// charged to `show version`, mirroring the gRPC plumbing probes. A class
// denying `show version` (or an allow-list naming anything else) was
// refused the liveness/config-mode facts, while `show version` itself —
// GET /api/v1/show-text?topic=version — stayed charged and denied. The
// probes are plumbing: exempt from the operational regex gate, governed
// by the coarse permission authorization alone.
//
// RED on pre-fix: both probes refused under the version deny / allow-list.

func TestStatusProbesArePlumbingNotShowVersion15077(t *testing.T) {
	s := &Server{}

	denyCfg := cfg14146(t, "^show version$", "")
	for _, path := range []string{"/api/v1/status", "/api/v1/config/status"} {
		if err := call9952(t, denyCfg, "limited", "GET", path, ""); err != nil {
			t.Errorf("GET %s denied under deny-commands \"^show version$\"; it is a plumbing probe, not `show version` (#15077): %v", path, err)
		}
		if err := s.authorizeRESTCommand(httptest.NewRequest(http.MethodHead, path, nil), denyCfg, principalLimited14712()); err != nil {
			t.Errorf("HEAD %s denied under a show-version deny; plumbing must follow GET (#15077): %v", path, err)
		}
	}
	// `show version` itself stays denied on the route that serves it.
	if err := call9952(t, denyCfg, "limited", "GET", "/api/v1/show-text?topic=version", ""); err == nil {
		t.Error("GET /api/v1/show-text?topic=version must stay denied under deny-commands \"^show version$\" (#15077)")
	} else if !strings.Contains(err.Error(), `denies "show version"`) {
		t.Errorf("show-text version refusal does not charge \"show version\": %v", err)
	}

	allowCfg := cfg14146(t, "", "^show interfaces$")
	for _, path := range []string{"/api/v1/status", "/api/v1/config/status"} {
		if err := call9952(t, allowCfg, "limited", "GET", path, ""); err != nil {
			t.Errorf("GET %s denied under an allow-list naming only `show interfaces`; plumbing must not require a listed command (#15077): %v", path, err)
		}
	}
	if err := call9952(t, allowCfg, "limited", "GET", "/api/v1/show-text?topic=version", ""); err == nil {
		t.Error("GET /api/v1/show-text?topic=version must stay denied under an allow-list that does not name it (#15077)")
	}
	// deny-everything still cannot refuse the probes (they carry no
	// command), while a real command route still fails closed.
	denyAllCfg := cfg14146(t, ".*", "")
	for _, path := range []string{"/api/v1/status", "/api/v1/config/status"} {
		if err := call9952(t, denyAllCfg, "limited", "GET", path, ""); err != nil {
			t.Errorf("GET %s denied under deny-commands \".*\"; plumbing carries no command to deny (#15077): %v", path, err)
		}
	}
	if err := call9952(t, denyAllCfg, "limited", "GET", "/api/v1/interfaces", ""); err == nil {
		t.Error("GET /api/v1/interfaces must stay denied under deny-commands \".*\" (control)")
	}
}
