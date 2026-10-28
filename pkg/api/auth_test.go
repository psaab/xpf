package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestAuthMiddleware(t *testing.T) {
	cfg := AuthConfig{
		Users:   map[string]string{"admin": "secret123"},
		APIKeys: map[string]bool{"tok-abc-123": true},
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// metricsRequireAuth=false: the loopback-bind default, under which /metrics
	// stays exempt (the "metrics bypass" case below asserts 200).
	handler := productionAuthHandlerOnly(t, cfg, false, ok)

	tests := []struct {
		name   string
		path   string
		header map[string]string
		want   int
	}{
		{
			name: "health bypass",
			path: "/health",
			want: http.StatusOK,
		},
		{
			name: "metrics bypass",
			path: "/metrics",
			want: http.StatusOK,
		},
		{
			name: "no auth",
			path: "/api/v1/status",
			want: http.StatusUnauthorized,
		},
		{
			name:   "valid basic auth",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": basicAuth("admin", "secret123")},
			want:   http.StatusOK,
		},
		{
			name:   "invalid basic auth password",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": basicAuth("admin", "wrong")},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "invalid basic auth user",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": basicAuth("nobody", "secret123")},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "valid bearer token",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": "Bearer tok-abc-123"},
			want:   http.StatusOK,
		},
		{
			name:   "invalid bearer token",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": "Bearer bad-token"},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "valid X-API-Key",
			path:   "/api/v1/status",
			header: map[string]string{"X-API-Key": "tok-abc-123"},
			want:   http.StatusOK,
		},
		{
			name:   "invalid X-API-Key",
			path:   "/api/v1/status",
			header: map[string]string{"X-API-Key": "bad-key"},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "malformed basic auth",
			path:   "/api/v1/status",
			header: map[string]string{"Authorization": "Basic !!!notbase64"},
			want:   http.StatusUnauthorized,
		},
		{
			name: "www-authenticate header on 401",
			path: "/api/v1/security/sessions",
			want: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.want {
				t.Errorf("got status %d, want %d", w.Code, tt.want)
			}

			if tt.want == http.StatusUnauthorized {
				if wa := w.Header().Get("WWW-Authenticate"); wa == "" {
					t.Error("expected WWW-Authenticate header on 401")
				}
			}
		})
	}
}

func TestConfigExportHandler(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store}

	tests := []struct {
		format     string
		wantStatus int
		contains   string
	}{
		{"set", 200, "set interfaces"},
		{"text", 200, "interfaces"},
		{"json", 200, "{"},
		{"xml", 200, "<configuration>"},
		{"", 200, "set interfaces"}, // default is set
		{"yaml", 400, "unsupported format"},
	}

	for _, tt := range tests {
		t.Run("format="+tt.format, func(t *testing.T) {
			path := "/api/v1/config/export"
			if tt.format != "" {
				path += "?format=" + tt.format
			}
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			s.configExportHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			// Decode JSON response and check output field for success, raw body for errors
			var resp struct {
				Success bool `json:"success"`
				Data    struct {
					Output string `json:"output"`
				} `json:"data"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			checkStr := resp.Data.Output
			if tt.wantStatus != 200 {
				checkStr = resp.Error
			}
			if !strings.Contains(checkStr, tt.contains) {
				t.Errorf("response %q does not contain %q", checkStr, tt.contains)
			}
		})
	}
}
