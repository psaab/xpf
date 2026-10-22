package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// TestCompletionValuesSeam16160 pins the test-only context seam
// (export_test.go) to the real provider path: a nil-store server
// yields nil values, and the stamped superuser principal resolves to
// the unrestricted completion auth Complete uses.
func TestCompletionValuesSeam16160(t *testing.T) {
	s := &Server{}
	if got := s.valueProvider(config.ValueHintZoneName, nil); got != nil {
		t.Errorf("nil-store valueProvider = %v, want nil", got)
	}
	ctx := ContextWithAuthorizedPrincipalForTest(t.Context(), authz.Principal{
		Source: authz.SourcePeerUID, UID: 0, Username: "root", Superuser: true,
	})
	if auth := s.completionAuthFor(ctx); !auth.unrestricted {
		t.Errorf("superuser completionAuth = %+v, want unrestricted", auth)
	}
}
