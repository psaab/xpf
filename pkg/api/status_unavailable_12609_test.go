package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

type unavailableStatusDP12609 struct {
	*dataplane.Manager
}

func (*unavailableStatusDP12609) IsLoaded() bool { return true }
func (*unavailableStatusDP12609) SessionCountContext(context.Context) (int, int, error) {
	return 0, 0, dataplane.ErrNotPublished
}

func TestRESTStatusUnpublishedCountMapsUnavailable12609(t *testing.T) {
	s := &Server{
		dp:    &unavailableStatusDP12609{Manager: dataplane.New()},
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
	rr := httptest.NewRecorder()
	s.statusHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code=%d, want 503; body=%s", rr.Code, rr.Body.String())
	}
}
