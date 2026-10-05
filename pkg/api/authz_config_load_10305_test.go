package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestRESTLoadRescueIsRefusedForRestrictedClass10305(t *testing.T) {
	store := authzStore(t, config9154)
	raw := `{"mode":"rescue"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/config/load", strings.NewReader(raw))
	err := (&Server{}).authorizeRESTConfigLoad(
		r, store.ActiveConfig(), authz.Principal{Class: "limited"})
	if err == nil {
		t.Fatal("REST load rescue with empty content was allowed for a restricted class")
	}
	got, readErr := io.ReadAll(r.Body)
	if readErr != nil || string(got) != raw {
		t.Fatalf("REST gate did not restore handler body: readErr=%v got=%q want=%q", readErr, got, raw)
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

func TestRESTLoadRescueDeniedOverHTTPForRestrictedClass11802(t *testing.T) {
	usePasswd9154(t)
	store := authzStore(t, config9154)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:0",
		Store:        store,
		PeerLookupFn: fixedPeerUID(4247),
	})
	sessionID := enter9154(t, base)
	before := store.ShowCandidateSet()

	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/config/load",
		strings.NewReader(`{"mode":"rescue"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(restConfigSessionHeader, sessionID)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("REST load rescue: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read REST denial: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "permission denied") {
		t.Fatalf("restricted REST load rescue response = %d %q, want permission-denied 403",
			resp.StatusCode, body)
	}
	if got := store.ShowCandidateSet(); got != before {
		t.Fatalf("denied REST load rescue changed candidate: before=%q after=%q", before, got)
	}
}
