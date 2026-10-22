package grpcapi

import (
	"context"

	"github.com/psaab/xpf/pkg/authz"
)

// ContextWithAuthorizedPrincipalForTest stamps an admitted principal
// onto ctx exactly as authorizeRPCContext does at the RPC boundary, so
// tests in this package's external test package (grpcapi_test,
// #16160) can drive the real Complete RPC as an identified
// principal. Test-only: this file is compiled only under `go test`
// for this package and is never linked into the production binary.
func ContextWithAuthorizedPrincipalForTest(ctx context.Context, p authz.Principal) context.Context {
	return context.WithValue(ctx, authorizedPrincipalKey{}, p)
}
