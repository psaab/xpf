package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const matchPoliciesAuthzTestConfig11674 = `
system {
    host-name match-authz-test;
    login {
        user opsuser {
            class read-only;
        }
        user adminuser {
            class operator;
        }
    }
}
`

// The existing fixture account is assigned the operator class in this test
// config (rather than its usual super-user class).
const authzUIDOperator11674 = authzUIDSuperuser

// TestMatchPoliciesRESTCostsControl_11674 pins the REST route's class tier to
// the same PermControl floor as gRPC MatchPolicies (#11077). HEAD aliases the
// GET route, so it must resolve to the same class gate too. A PermView-only
// class must not be able to obtain a verdict; operator holds PermControl.
func TestMatchPoliciesRESTCostsControl_11674(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		permission, ok := readPermissionFor(method, "/api/v1/security/match")
		if !ok {
			t.Fatalf("%s /api/v1/security/match has no authorization policy", method)
		}
		if permission != config.PermControl {
			t.Errorf("%s /api/v1/security/match requires %v, want PermControl like gRPC MatchPolicies (#11674)", method, permission)
		}
		for _, class := range []string{"read-only", "config-viewer"} {
			if config.ClassHasPermission(nil, class, permission) {
				t.Errorf("%s /api/v1/security/match is reachable by PermView-only class %q", method, class)
			}
		}
		if !config.ClassHasPermission(nil, "operator", permission) {
			t.Errorf("%s /api/v1/security/match denies operator, which holds the gRPC MatchPolicies PermControl tier", method)
		}
	}
}

// TestMatchPoliciesRESTClassGate_11674 is an end-to-end pin through the real
// HTTP server and authz middleware: a read-only shell principal must be denied
// before the simulator can answer a policy verdict, while operator retains the
// same PermControl access the gRPC MatchPolicies method allows.
func TestMatchPoliciesRESTClassGate_11674(t *testing.T) {
	for _, tc := range []struct {
		name       string
		uid        uint32
		wantStatus int
	}{
		{name: "read-only denied", uid: authzUIDReadOnly, wantStatus: http.StatusForbidden},
		{name: "operator allowed", uid: authzUIDOperator11674, wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usePasswdFixture(t)
			store := authzStore(t, matchPoliciesAuthzTestConfig11674)
			_, base := authzServer(t, Config{
				Addr:         "127.0.0.1:8080",
				Store:        store,
				PeerLookupFn: fixedPeerUID(tc.uid),
			})

			path := "/api/v1/security/match?from_zone=trust&to_zone=untrust&protocol=tcp&dst_port=2121"
			status, body := get6660(t, base, path)
			if status != tc.wantStatus {
				t.Fatalf("GET /api/v1/security/match as %s returned %d, want %d: %s",
					tc.name, status, tc.wantStatus, body)
			}
			if tc.wantStatus == http.StatusForbidden && !strings.Contains(body, "permission denied") {
				t.Fatalf("read-only match denial does not identify an authorization refusal: %s", body)
			}
		})
	}
}
