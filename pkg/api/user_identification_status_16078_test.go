package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// #16078: REST show-text must name configured user-identification stanzas
// INERT via the shared pkg/config renderer.
func TestShowTextUserIdentificationStatus16078(t *testing.T) {
	store := algAPIStore(t, "security {\n    user-identification {\n        active-directory-access {\n            domain-name corp.example;\n        }\n    }\n}\n")
	for _, topic := range []string{"user-identification-status", "security-user-identification-status"} {
		s := &Server{store: store}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/show/text?topic="+topic, nil)
		s.showTextHandler(rec, req)
		if rec.Code != 200 {
			t.Fatalf("topic %s status=%d body=%s", topic, rec.Code, rec.Body.String())
		}
		out := rec.Body.String()
		for _, want := range []string{"User identification status:", "INERT", "active-directory-access"} {
			if !strings.Contains(out, want) {
				t.Errorf("topic %s missing %q:\n%s", topic, want, out)
			}
		}
	}
}
