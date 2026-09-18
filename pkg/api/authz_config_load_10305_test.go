package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
)

// #10305 on REST: the content gate must classify the body exactly as the
// config-store load path does. The annotate-led trigger is not a flat replay
// command, so the following denied subtree must be rendered and adjudicated.
func TestRESTLoadDivergentTriggerIsRefused10305(t *testing.T) {
	store := authzStore(t, config9154)
	cfg := store.ActiveConfig()
	s := &Server{}
	p := authz.Principal{Class: "limited"}
	content := "annotate system host-name \"trigger10305\";\n" +
		"system { root-authentication { plain-text-password hunter2; } }\n"

	for _, mode := range []string{"merge", "override"} {
		t.Run(mode, func(t *testing.T) {
			raw := `{"mode":` + strconv.Quote(mode) + `,"content":` + strconv.Quote(content) + `}`
			r := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", strings.NewReader(raw))
			err := s.authorizeRESTConfigLoad(r, cfg, p)
			if err == nil {
				t.Fatalf("REST load %s allowed a denied hierarchical subtree (#10305)", mode)
			}
			got, readErr := io.ReadAll(r.Body)
			if readErr != nil || string(got) != raw {
				t.Fatalf("REST gate did not restore handler body: readErr=%v got=%q want=%q", readErr, got, raw)
			}
		})
	}
}

// Narrowness/control: the same REST content gate still allows a flat load set
// of an unrelated path. This pins that #10305 does not become blanket refusal.
func TestRESTLoadSetAllowedControl10305(t *testing.T) {
	store := authzStore(t, config9154)
	raw := `{"mode":"set","content":"set system host-name allowed10305"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", strings.NewReader(raw))
	if err := (&Server{}).authorizeRESTConfigLoad(r, store.ActiveConfig(), authz.Principal{Class: "limited"}); err != nil {
		t.Fatalf("REST load set of an allowed flat path was refused: %v", err)
	}
}
