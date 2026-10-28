package ddns

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// #16440: an rfc2136 update-server carrying URL userinfo
// ("user:s3cr3t@host") must never re-disclose the credential through
// LastError, journald, or a dial error — the residual of #15174, which
// redacted only the field renderers. RFC 2136 has no credential slot, so
// the value is rejected at construction and at strict commit; defence in
// depth redacts every rfc2136 error/log render and StatusViews.

const userinfoSecret16440 = "s3cr3t"

// TestRFC2136UpdateServerUserinfoRejected16440 pins the constructor gate:
// both userinfo shapes from the vf07 probe are refused, the refusal does
// not itself leak, and clean servers construct unchanged (positive
// control).
func TestRFC2136UpdateServerUserinfoRejected16440(t *testing.T) {
	for _, server := range []string{
		"user:" + userinfoSecret16440 + "@dns.example.com",
		"user:" + userinfoSecret16440 + "@dns.example.com:53",
	} {
		_, err := normalizeUpdateServer(server)
		if err == nil {
			t.Fatalf("normalizeUpdateServer(%q) accepted userinfo", server)
		}
		if strings.Contains(err.Error(), userinfoSecret16440) {
			t.Fatalf("rejection leaked the credential: %v", err)
		}
		if !strings.Contains(err.Error(), "<redacted>@dns.example.com") {
			t.Fatalf("rejection must name the redacted server, got: %v", err)
		}
		cfg := &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com", RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: server}}
		if _, err := newRFC2136Updater(policyFromConfig(cfg), cfg.RFC2136Endpoint, nil, nil, nil); err == nil {
			t.Fatalf("newRFC2136Updater accepted userinfo server %q", server)
		} else if strings.Contains(err.Error(), userinfoSecret16440) {
			t.Fatalf("constructor rejection leaked the credential: %v", err)
		}
		// Surface A path (the vf07 probe's route).
		p := &config.DDNSProvider{Name: "P", Backend: "rfc2136", RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: server}}
		if _, err := newSurfaceARFC2136(p, "wan.example.net"); err == nil {
			t.Fatalf("newSurfaceARFC2136 accepted userinfo server %q", server)
		} else if strings.Contains(err.Error(), userinfoSecret16440) {
			t.Fatalf("surface-a rejection leaked the credential: %v", err)
		}
	}
	// Positive control: a clean host:port is unchanged.
	got, err := normalizeUpdateServer("dns.example.com")
	if err != nil || got != "dns.example.com:53" {
		t.Fatalf("clean server changed: %q, %v", got, err)
	}
}

// TestRFC2136UserinfoLastErrorLeakFalse16440 is the vf07 acceptance probe
// re-run against production wiring: a provider whose update-server is a
// working fake DNS server publishes cleanly (positive control), while a
// userinfo provider never reaches StatusViews with the secret — its
// scope resolves to no backend / an error whose text is redacted.
func TestRFC2136UserinfoLastErrorLeakFalse16440(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m := newSurfaceAManagerRealBackend(t, srv)
	sc := realScope("wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("positive-control reconcile: %v", err)
	}
	views := m.StatusViews([]SurfaceAScope{sc})
	if len(views) != 1 || views[0].LastError != "" {
		t.Fatalf("positive control must have empty LastError, got %+v", views)
	}

	for _, server := range []string{
		"user:" + userinfoSecret16440 + "@dns.example.com",
		"user:" + userinfoSecret16440 + "@dns.example.com:53",
	} {
		p := &config.DDNSProvider{Name: "P", Backend: "rfc2136", RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: server}}
		if _, err := newSurfaceARFC2136(p, "wan.example.net"); err == nil {
			t.Fatalf("userinfo server %q must be refused before any dial", server)
		}
		// Defence in depth: even a directly-built updater (bypassing the
		// constructor) cannot leak through exchange / TSIG / warn paths.
		u := &rfc2136Updater{
			server:         server,
			conflictPolicy: "replace-owned",
			selfOwned:      true,
			timeout:        time.Second,
			client:         &failingExchanger16440{server: server},
		}
		unsignedUpdateWarned.Delete(server)
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		_, exchErr := u.exchange(context.Background(), new(dns.Msg))
		slog.SetDefault(prev)
		if exchErr == nil {
			t.Fatalf("exchange to %q must fail", server)
		}
		if strings.Contains(exchErr.Error(), userinfoSecret16440) {
			t.Fatalf("exchange error leaked the credential: %v", exchErr)
		}
		if strings.Contains(buf.String(), userinfoSecret16440) {
			t.Fatalf("journald warnUnsignedOnce leaked the credential: %s", buf.String())
		}
		if !strings.Contains(buf.String(), "<redacted>@dns.example.com") {
			t.Fatalf("warnUnsignedOnce must name the redacted server, log=%s", buf.String())
		}
		// TSIG validation errors format the server — redacted.
		u.tsigKeyName = "k1."
		u.tsigAlgo = dns.HmacSHA256
		if err := u.validateTSIGResponse(new(dns.Msg), "udp"); err == nil ||
			strings.Contains(err.Error(), userinfoSecret16440) {
			t.Fatalf("TSIG validation leaked or passed: %v", err)
		}
		// Status boundary: recordScopeError -> StatusViews.
		st2, _ := loadDDNSState(filepath.Join(t.TempDir(), "iface-ddns.json"))
		m2 := &SurfaceAManager{state: st2, runtime: map[string]*surfaceAState{}}
		rt := &surfaceAState{}
		m2.runtime[sc.scopeID()] = rt
		m2.recordScopeError(rt, sc.FQDN, 0, exchErr, time.Now(), false)
		if strings.Contains(rt.lastErr, userinfoSecret16440) {
			t.Fatalf("LastError leaked the credential: %q", rt.lastErr)
		}
		for _, v := range m2.StatusViews([]SurfaceAScope{sc}) {
			if strings.Contains(v.LastError, userinfoSecret16440) {
				t.Fatalf("StatusViews leaked the credential: %q", v.LastError)
			}
		}
	}
}

// failingExchanger16440 mimics a miekg dial error embedding the address.
type failingExchanger16440 struct{ server string }

func (f *failingExchanger16440) ExchangeContext(_ context.Context, _ *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	return nil, 0, errors.New("dial udp: lookup " + addr + ": no such host")
}

// TestScrubUserinfoInText16440 pins the status-boundary scrubber: dial
// phrasing is redacted, clean text is byte-identical.
func TestScrubUserinfoInText16440(t *testing.T) {
	leaky := "ddns surface-a: publish A wan.example.net=203.0.113.5: dial udp: lookup user:" +
		userinfoSecret16440 + "@dns.example.com:53: no such host"
	got := scrubLastErrorText(leaky)
	if strings.Contains(got, userinfoSecret16440) {
		t.Fatalf("scrubbed text still leaks: %q", got)
	}
	if !strings.Contains(got, "<redacted>@dns.example.com:53") {
		t.Fatalf("scrubbed text must keep the host diagnostic: %q", got)
	}
	clean := "ddns: update rejected (REFUSED)"
	if got := scrubLastErrorText(clean); got != clean {
		t.Fatalf("clean text changed: %q", got)
	}
	u := &rfc2136Updater{server: "dns.example.com:53"}
	cleanErr := errors.New("dial udp: lookup dns.example.com:53: no such host")
	if got := u.scrubServerError(cleanErr); got.Error() != cleanErr.Error() {
		t.Fatalf("clean updater scrub changed the error: %q", got)
	}
}
