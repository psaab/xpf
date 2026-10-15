package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/psaab/xpf/pkg/authz"
	"testing"
	"time"
)

// #2114 (Codex PR #6743 r4-F4): the REST half of the escape guards.
//
// api.Server keeps Config.DP for the daemon's lifetime exactly like
// grpcapi.Server does, so it needs its own end-to-end binder rather than
// an assumption that the one-line call site "is the same shape". These
// drive the PRODUCTION startup path (startHTTPServer →
// managementReconciler → api.NewServer), then issue a real HTTP request
// against the bound loopback listener.
//
// The binder and the over-reach guard are SEPARATE test functions on
// purpose: a guard sharing a body with a binder never executes on the
// runs where the binder fails, which is exactly when it is needed.

// startEscapeTestREST runs the production HTTP startup path on an
// ephemeral loopback port and returns the effective base URL.
// authorizeEscapeTestREST gives the test process an IDENTIFIED, authorized
// principal for the REST read surface (#6660).
//
// These cases assert what `/api/v1/status` REPORTS about the dataplane; they are
// not about authorization. Before #6660 the read surface was ungated so any
// caller reached the handler. Now a read requires PermView, and the test runner
// (an ordinary uid, not root) is not in the login model — so without this the
// cases fail at 403 having never exercised their subject.
//
// It maps the RUNNING uid to a name and grants that name super-user, rather than
// hardcoding a uid, so it is correct on any machine and in CI.
func authorizeEscapeTestREST(t *testing.T, d *Daemon) {
	t.Helper()
	const user = "xpf-escape-test"
	uid := os.Getuid()
	passwd := filepath.Join(t.TempDir(), "passwd")
	line := fmt.Sprintf("%s:x:%d:%d::/home/%s:/bin/bash\n", user, uid, uid, user)
	if err := os.WriteFile(passwd, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(passwd))

	text := fmt.Sprintf(
		"system {\n    login {\n        user %s {\n            class super-user;\n        }\n    }\n}\n",
		user)
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := d.store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	d.store.ExitConfigure()
}

func startEscapeTestREST(t *testing.T, d *Daemon) string {
	t.Helper()
	authorizeEscapeTestREST(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	d.opts.APIAddr = "127.0.0.1:0"
	d.startHTTPServer(ctx, &wg, nil, nil)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	mgmt := d.mgmt.Load()
	if mgmt == nil || mgmt.srv == nil {
		t.Fatal("startHTTPServer did not converge a management listener")
	}
	addr := mgmt.srv.EffectiveHTTPAddr()
	if addr == "" {
		t.Fatal("management listener reported no effective HTTP address")
	}
	return "http://" + addr
}

// restDataplaneLoaded reads DataplaneLoaded off the REST status document.
func restDataplaneLoaded(t *testing.T, base string) bool {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + "/api/v1/status")
	if err != nil {
		t.Fatalf("GET /api/v1/status: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /api/v1/status body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/status = %d: %s", resp.StatusCode, body)
	}
	var envelope struct {
		Data struct {
			DataplaneLoaded bool `json:"dataplane_loaded"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode /api/v1/status %s: %v", body, err)
	}
	return envelope.Data.DataplaneLoaded
}

// TestRESTServer_DisownedDataplaneIsNotReachable is the REST binder.
//
// Fail-on-revert: restore the capture-once wiring in
// daemon_run_servers.go's startHTTPServer —
//
//	var apiDP apiDataPlane
//	if rt := d.dataplane(); rt != nil {
//	        if probe, ok := rt.(apiDataPlane); ok { apiDP = probe }
//	}
//
// — and the REST server keeps reporting dataplane_loaded=true off a
// backend the daemon has already disowned.
func TestRESTServer_DisownedDataplaneIsNotReachable(t *testing.T) {
	d := newEscapeTestDaemon(t)
	d.setDataplane(newEscapeRecorderDP("A"))

	base := startEscapeTestREST(t, d)

	d.setDataplane(nil)
	if restDataplaneLoaded(t, base) {
		t.Fatal("REST still reports dataplane_loaded=true after setDataplane(nil); " +
			"api.Server is holding the backend handle instead of re-reading the #2114 cell")
	}
}

// TestRESTServer_PublishedDataplaneStillReachable is the REST over-reach
// guard: the fix must not sever REST from a dataplane that IS published.
// GREEN under the revert above.
func TestRESTServer_PublishedDataplaneStillReachable(t *testing.T) {
	d := newEscapeTestDaemon(t)
	d.setDataplane(newEscapeRecorderDP("A"))

	base := startEscapeTestREST(t, d)

	if !restDataplaneLoaded(t, base) {
		t.Fatal("REST reported dataplane_loaded=false while a loaded dataplane was published")
	}
}

// TestRESTServer_LateDataplanePublicationIsObserved pins the strict
// improvement the live indirection buys: a dataplane published AFTER the
// REST listener converged is visible without a daemon restart. The
// capture-once wiring froze apiDP=nil at startup, so this went RED on
// the pre-r4 code for the opposite reason to the binder above.
func TestRESTServer_LateDataplanePublicationIsObserved(t *testing.T) {
	d := newEscapeTestDaemon(t)

	base := startEscapeTestREST(t, d) // no dataplane published yet

	if restDataplaneLoaded(t, base) {
		t.Fatal("REST reported dataplane_loaded=true with an empty cell")
	}
	d.setDataplane(newEscapeRecorderDP("A"))
	if !restDataplaneLoaded(t, base) {
		t.Fatal("REST never observed the dataplane published after listener convergence")
	}
}
