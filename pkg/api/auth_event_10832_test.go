package api

import (
	"bytes"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/denyaudit"
)

func TestRESTAuthorizationAuditAtInfo10832(t *testing.T) {
	denyaudit.ResetWindowsForTest()
	beforeLogin := denyaudit.Total(denyaudit.SurfaceRESTLoginClass)
	beforeAPIAuth := denyaudit.Total(denyaudit.SurfaceRESTAPIAuthFail)

	previousLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	send := func(base, method, path, body string, headers map[string]string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		response, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(response)
	}
	oneRecord := func(t *testing.T, got string) {
		t.Helper()
		if strings.Count(got, "\n") != 1 {
			t.Fatalf("got %d log records, want exactly one: %q", strings.Count(got, "\n"), got)
		}
	}

	usePasswdFixture(t)
	_, deniedBase := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(authzUIDReadOnly),
	})
	status, _ := send(deniedBase, http.MethodPost, "/api/v1/config/set",
		`{"input":"set system host-name denied10832"}`, nil)
	if status != http.StatusForbidden {
		t.Fatalf("read-only configure denial returned %d, want 403", status)
	}
	if got := denyaudit.Total(denyaudit.SurfaceRESTLoginClass) - beforeLogin; got != 1 {
		t.Fatalf("REST login-class counter advanced by %d after one denied mutation, want 1", got)
	}
	denialLog := logs.String()
	oneRecord(t, denialLog)
	for _, field := range []string{
		"level=WARN", "api: REST request denied by authorization", "source=peer-uid",
		"required=configure", "denials_total=",
	} {
		if !strings.Contains(denialLog, field) {
			t.Errorf("denial record missing %q: %s", field, denialLog)
		}
	}
	logs.Reset()

	secret := "must-not-log-this-secret"
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:"+secret))
	store := authzStore(t, authzTestConfig)
	_, adminBase := authzServer(t, Config{
		Addr:           "127.0.0.1:8080",
		Store:          store,
		Auth:           &AuthConfig{Users: map[string]string{"webadmin": secret}},
		PeerLookupFn:   remotePeer(),
		PeerLocalityFn: remoteLocality(),
	})
	authHeader := map[string]string{"Authorization": credential}
	session := enterConfigure(t, adminBase, authHeader)
	logs.Reset()

	setRequest, err := http.NewRequest(http.MethodPost, adminBase+"/api/v1/config/set",
		strings.NewReader(`{"input":"set system host-name audited10832"}`))
	if err != nil {
		t.Fatal(err)
	}
	setRequest.Header.Set("Content-Type", "application/json")
	setRequest.Header.Set("Authorization", credential)
	setRequest.Header.Set(restConfigSessionHeader, session)
	setResponse, err := (&http.Client{Timeout: 10 * time.Second}).Do(setRequest)
	if err != nil {
		t.Fatal(err)
	}
	setBody, readErr := io.ReadAll(setResponse.Body)
	setResponse.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if setResponse.StatusCode != http.StatusOK {
		t.Fatalf("authorized config/set returned %d: %s", setResponse.StatusCode, setBody)
	}
	if candidate := store.ShowCandidate(); !strings.Contains(candidate, "audited10832") {
		t.Fatalf("successful config/set did not modify the candidate: %s", candidate)
	}
	configLog := logs.String()
	oneRecord(t, configLog)
	for _, field := range []string{
		"level=INFO", "api: authorized mutating request", `principal="api-auth credential"`,
		"source=api-auth-credential", "required=configure",
	} {
		if !strings.Contains(configLog, field) {
			t.Errorf("successful configure record missing %q: %s", field, configLog)
		}
	}
	if strings.Contains(configLog, secret) {
		t.Errorf("successful configure record disclosed api-auth secret: %s", configLog)
	}
	if got := denyaudit.Total(denyaudit.SurfaceRESTLoginClass) - beforeLogin; got != 1 {
		t.Errorf("successful mutation changed the denial counter: delta %d, want 1 from the earlier refusal", got)
	}
	logs.Reset()

	status, response := send(adminBase, http.MethodPost, "/api/v1/config/exit", "{}",
		map[string]string{"Authorization": credential, restConfigSessionHeader: session})
	if status != http.StatusOK {
		t.Fatalf("authorized config/exit returned %d: %s", status, response)
	}
	logs.Reset()
	status, response = send(adminBase, http.MethodPost, "/api/v1/system/action",
		`{"action":"clear-config-lock"}`, authHeader)
	if status != http.StatusOK {
		t.Fatalf("authorized maintenance mutation returned %d: %s", status, response)
	}
	maintLog := logs.String()
	oneRecord(t, maintLog)
	for _, field := range []string{
		"level=INFO", "api: authorized mutating request", `principal="api-auth credential"`,
		"source=api-auth-credential", "required=maintenance",
	} {
		if !strings.Contains(maintLog, field) {
			t.Errorf("successful maintenance record missing %q: %s", field, maintLog)
		}
	}
	if strings.Contains(maintLog, secret) {
		t.Errorf("successful maintenance record disclosed api-auth secret: %s", maintLog)
	}
	logs.Reset()

	status, _ = send(adminBase, http.MethodGet, "/api/v1/status", "", map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("webadmin:incorrect-guess")),
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("incorrect api-auth credential returned %d, want 401", status)
	}
	if got := denyaudit.Total(denyaudit.SurfaceRESTAPIAuthFail) - beforeAPIAuth; got != 1 {
		t.Fatalf("REST api-auth counter advanced by %d after one failed credential check, want 1", got)
	}
	authLog := logs.String()
	oneRecord(t, authLog)
	for _, field := range []string{
		"level=WARN", "api: REST authentication failed", "denials_total=",
	} {
		if !strings.Contains(authLog, field) {
			t.Errorf("api-auth failure record missing %q: %s", field, authLog)
		}
	}
	if strings.Contains(authLog, secret) {
		t.Errorf("api-auth failure record disclosed credential: %s", authLog)
	}
	if strings.Contains(authLog, "incorrect-guess") {
		t.Errorf("api-auth failure record disclosed attempted credential: %s", authLog)
	}
}
