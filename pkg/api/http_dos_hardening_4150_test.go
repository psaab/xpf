package api

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// #4150 M-6: the management HTTP/HTTPS servers must carry read/header/idle
// timeouts so a pre-auth slowloris (dribbled headers or body) cannot pin a
// goroutine/socket indefinitely. This asserts the constructed server fields
// directly — the RED-on-revert signal is that the original literals set only
// Addr/Handler(/TLSConfig), leaving every timeout field at its zero (no-limit)
// value.
func TestManagementServerTimeoutsSetM6(t *testing.T) {
	s := NewServer(Config{Addr: "127.0.0.1:0"})
	if s.httpServer() == nil {
		t.Fatal("httpServer was not constructed")
	}
	assertTimeouts(t, "http", s.httpServer().ReadHeaderTimeout, s.httpServer().ReadTimeout,
		s.httpServer().IdleTimeout, s.httpServer().MaxHeaderBytes, s.httpServer().WriteTimeout)

	// HTTPS server path: TLS on with an HTTPS listen address builds the second
	// literal, which must carry the SAME hardening.
	st := NewServer(Config{Addr: "127.0.0.1:0", TLS: true, HTTPSAddr: "127.0.0.1:0"})
	if st.httpsServer() == nil {
		t.Fatal("httpsServer was not constructed with TLS + HTTPSAddr set")
	}
	assertTimeouts(t, "https", st.httpsServer().ReadHeaderTimeout, st.httpsServer().ReadTimeout,
		st.httpsServer().IdleTimeout, st.httpsServer().MaxHeaderBytes, st.httpsServer().WriteTimeout)
}

func assertTimeouts(t *testing.T, which string, readHeader, read, idle time.Duration, maxHeaderBytes int, write time.Duration) {
	t.Helper()
	if readHeader != apiReadHeaderTimeout {
		t.Errorf("%s ReadHeaderTimeout = %v, want %v (slowloris-header defense)", which, readHeader, apiReadHeaderTimeout)
	}
	if read != apiReadTimeout {
		t.Errorf("%s ReadTimeout = %v, want %v (slow-body defense)", which, read, apiReadTimeout)
	}
	if idle != apiIdleTimeout {
		t.Errorf("%s IdleTimeout = %v, want %v", which, idle, apiIdleTimeout)
	}
	if maxHeaderBytes != apiMaxHeaderBytes {
		t.Errorf("%s MaxHeaderBytes = %d, want %d", which, maxHeaderBytes, apiMaxHeaderBytes)
	}
	// WriteTimeout MUST stay unlimited (0) so SSE event/log streams and large
	// metrics/session-table scrapes are not severed mid-response. A non-zero
	// WriteTimeout here would be a regression.
	if write != 0 {
		t.Errorf("%s WriteTimeout = %v, want 0 (unlimited — SSE streams + large scrapes must not be cut off)", which, write)
	}
}

// repeatReader streams `remaining` copies of byte b without materializing a
// giant buffer — used to build an over-cap request body cheaply.
type repeatReader struct {
	b         byte
	remaining int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = r.b
	}
	r.remaining -= n
	return int(n), nil
}

// #4150 M-7: a mutation-handler request body larger than maxRequestBodyBytes
// must be rejected with HTTP 413 rather than buffered whole (OOM). The body is
// valid JSON (`{"input":"AAAA..."}`) so on revert (no MaxBytesReader) the
// decoder reads the entire >16 MiB payload and returns 200/400 — never 413 —
// making the 413 assertion the RED-on-revert signal.
func TestConfigMutationBodyCappedM7(t *testing.T) {
	store := newAPIConfigStore(t)
	s := &Server{store: store}

	// prefix + (maxRequestBodyBytes + slack) filler bytes + suffix => the cap
	// fires inside the string value.
	body := io.MultiReader(
		strings.NewReader(`{"input":"`),
		&repeatReader{b: 'A', remaining: int64(maxRequestBodyBytes) + 4096},
		strings.NewReader(`"}`),
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/set", body)
	s.configSetHandler(rr, req)

	if rr.Code != 413 {
		t.Fatalf("oversized body status = %d, want 413 (request body too large); body: %s",
			rr.Code, rr.Body.String())
	}
}

// A normal-size mutation body must still succeed — the cap defends against
// abuse without breaking legitimate requests.
func TestConfigMutationNormalBodySucceedsM7(t *testing.T) {
	store := newAPIConfigStore(t)
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/set",
		strings.NewReader(`{"input":"system host-name capped-ok"}`))
	withRESTConfigSession(req, testRESTConfigSessionID)
	s.configSetHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("normal body status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
}

// A small malformed JSON body keeps returning HTTP 400 (not 413, not 500) — the
// cap must not change the error class for ordinary bad input.
func TestConfigMutationMalformedBodyStill400M7(t *testing.T) {
	store := newAPIConfigStore(t)
	s := &Server{store: store}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/set",
		strings.NewReader(`{not valid json`))
	s.configSetHandler(rr, req)

	if rr.Code != 400 {
		t.Fatalf("malformed body status = %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}
