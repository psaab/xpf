package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

type overrunSSEWriter struct {
	header       http.Header
	mu           sync.Mutex
	body         strings.Builder
	flushes      int
	headersSent  chan struct{}
	blockedFlush chan struct{}
	releaseFlush chan struct{}
}

func newOverrunSSEWriter() *overrunSSEWriter {
	return &overrunSSEWriter{
		header:       make(http.Header),
		headersSent:  make(chan struct{}),
		blockedFlush: make(chan struct{}),
		releaseFlush: make(chan struct{}),
	}
}

func (w *overrunSSEWriter) Header() http.Header { return w.header }
func (w *overrunSSEWriter) WriteHeader(int)     {}
func (w *overrunSSEWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(p)
}
func (w *overrunSSEWriter) Flush() {
	w.mu.Lock()
	w.flushes++
	n := w.flushes
	w.mu.Unlock()
	switch n {
	case 1:
		close(w.headersSent)
	case 2:
		close(w.blockedFlush)
		<-w.releaseFlush
	}
}
func (w *overrunSSEWriter) bodyString() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.String()
}

func TestSetSSEHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	setSSEHeaders(w)

	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	if cn := w.Header().Get("Connection"); cn != "keep-alive" {
		t.Errorf("Connection = %q, want keep-alive", cn)
	}
}

func TestWriteSSEEvent(t *testing.T) {
	w := httptest.NewRecorder()
	writeSSEEvent(w, "42", "test_event", `{"key":"value"}`)

	body := w.Body.String()
	if !strings.Contains(body, "id: 42\n") {
		t.Errorf("missing id line in %q", body)
	}
	if !strings.Contains(body, "event: test_event\n") {
		t.Errorf("missing event line in %q", body)
	}
	if !strings.Contains(body, "data: {\"key\":\"value\"}\n") {
		t.Errorf("missing data line in %q", body)
	}
	if !strings.HasSuffix(body, "\n\n") {
		t.Errorf("SSE event should end with double newline")
	}
}

func TestWriteSSEEventNoEventType(t *testing.T) {
	w := httptest.NewRecorder()
	writeSSEEvent(w, "1", "", "hello")

	body := w.Body.String()
	if strings.Contains(body, "event:") {
		t.Errorf("should not have event line when empty, got %q", body)
	}
	if !strings.Contains(body, "id: 1\n") {
		t.Errorf("missing id line")
	}
	if !strings.Contains(body, "data: hello\n") {
		t.Errorf("missing data line")
	}
}

func TestEventStreamHandler(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/events/stream", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Run handler in background
	done := make(chan struct{})
	go func() {
		s.eventStreamHandler(w, req)
		close(done)
	}()

	// Wait for subscription to be set up
	time.Sleep(50 * time.Millisecond)

	// Add events
	buf.Add(logging.EventRecord{
		Time:     time.Now(),
		Type:     "SESSION_OPEN",
		SrcAddr:  "10.0.1.5:12345",
		DstAddr:  "10.0.2.100:80",
		Protocol: "TCP",
		Action:   "permit",
		PolicyID: 1,
		InZone:   1,
		OutZone:  2,
	})

	time.Sleep(50 * time.Millisecond)

	// Cancel and wait for handler to exit
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "event: SESSION_OPEN") {
		t.Errorf("expected SESSION_OPEN event in response, got %q", body)
	}
	if !strings.Contains(body, "10.0.1.5:12345") {
		t.Errorf("expected source addr in event data, got %q", body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
}
func TestSSEStreamsReportSubscriberOverruns_10834(t *testing.T) {
	tests := []struct {
		name   string
		serve  func(*Server, http.ResponseWriter, *http.Request)
		target string
	}{
		{"events", (*Server).eventStreamHandler, "/api/v1/events/stream"},
		{"logs", (*Server).logStreamHandler, "/api/v1/logs/stream"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := logging.NewEventBuffer(512)
			s := &Server{eventBuf: buf}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest(http.MethodGet, tc.target, nil).WithContext(ctx)
			w := newOverrunSSEWriter()
			done := make(chan struct{})
			go func() {
				tc.serve(s, w, req)
				close(done)
			}()

			select {
			case <-w.headersSent:
			case <-time.After(2 * time.Second):
				t.Fatal("SSE handler did not establish its response")
			}
			buf.Add(logging.EventRecord{Time: time.Now(), Type: "POLICY_DENY", Action: "deny"})
			select {
			case <-w.blockedFlush:
			case <-time.After(2 * time.Second):
				t.Fatal("SSE handler did not block on the first event flush")
			}

			const storm = 300
			for range storm {
				buf.Add(logging.EventRecord{Time: time.Now(), Type: "POLICY_DENY", Action: "deny"})
			}
			dropped := buf.DroppedTotal()
			if dropped == 0 {
				t.Fatal("bounded event storm did not overrun the blocked subscriber")
			}
			close(w.releaseFlush)

			deadline := time.Now().Add(2 * time.Second)
			for !strings.Contains(w.bodyString(), "event: overrun") && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("SSE handler did not exit after cancellation")
			}

			body := w.bodyString()
			if !strings.Contains(body, "event: overrun") {
				t.Fatalf("stream omitted the overrun event: %q", body)
			}
			if marker := logging.OverrunLine(dropped); !strings.Contains(body, marker) {
				t.Errorf("stream gap marker does not report %d dropped records: %q", dropped, body)
			}
			if count := fmt.Sprintf(`"dropped":%d`, dropped); !strings.Contains(body, count) {
				t.Errorf("stream gap payload lacks cumulative dropped count %s: %q", count, body)
			}
		})
	}
}

func TestEventStreamCategoryFilter(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/events/stream?category=policy", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		s.eventStreamHandler(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Add session event (should be filtered out)
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "SESSION_OPEN", Action: "permit",
	})
	// Add policy deny event (should pass)
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "POLICY_DENY", Action: "deny",
		SrcAddr: "1.2.3.4:100", DstAddr: "5.6.7.8:80", Protocol: "TCP",
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if strings.Contains(body, "SESSION_OPEN") {
		t.Errorf("SESSION_OPEN should be filtered out, got %q", body)
	}
	if !strings.Contains(body, "POLICY_DENY") {
		t.Errorf("POLICY_DENY should pass filter, got %q", body)
	}
}

func TestLogStreamHandler(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/logs/stream", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		s.logStreamHandler(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "POLICY_DENY", Action: "deny",
		SrcAddr: "10.0.1.5:999", DstAddr: "10.0.2.1:22", Protocol: "TCP",
		PolicyID: 5, InZone: 1, OutZone: 2,
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if !strings.Contains(body, "event: log") {
		t.Errorf("expected 'event: log' in response, got %q", body)
	}
	if !strings.Contains(body, "RT_FLOW") {
		t.Errorf("expected RT_FLOW message in response, got %q", body)
	}

	// Parse the SSE data line
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			var entry LogStreamEntry
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &entry); err != nil {
				t.Fatalf("unmarshal log entry: %v", err)
			}
			if entry.Severity != "warning" {
				t.Errorf("severity = %q, want warning", entry.Severity)
			}
			if !strings.Contains(entry.Message, "POLICY_DENY") {
				t.Errorf("message missing POLICY_DENY: %q", entry.Message)
			}
			break
		}
	}
}

func TestLogStreamSeverityFilter(t *testing.T) {
	buf := logging.NewEventBuffer(100)
	s := &Server{eventBuf: buf}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Only error severity
	req := httptest.NewRequest("GET", "/api/v1/logs/stream?severity=error", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		s.logStreamHandler(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	// Info event (should be filtered)
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "SESSION_OPEN", Action: "permit",
	})
	// Error event (should pass)
	buf.Add(logging.EventRecord{
		Time: time.Now(), Type: "SCREEN_DROP", Action: "deny",
		SrcAddr: "1.2.3.4:1", DstAddr: "5.6.7.8:2", Protocol: "TCP",
		ScreenCheck: "syn-flood",
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	body := w.Body.String()
	if strings.Contains(body, "SESSION_OPEN") {
		t.Errorf("SESSION_OPEN (info) should be filtered with severity=error, got %q", body)
	}
	if !strings.Contains(body, "SCREEN_DROP") {
		t.Errorf("SCREEN_DROP (error) should pass severity=error filter, got %q", body)
	}
}

func TestEventStreamNoBuffer(t *testing.T) {
	s := &Server{eventBuf: nil}
	req := httptest.NewRequest("GET", "/api/v1/events/stream", nil)
	w := httptest.NewRecorder()
	s.eventStreamHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestParseCategories(t *testing.T) {
	tests := []struct {
		input string
		want  uint8
	}{
		{"", 0},
		{"session", logging.CategorySession},
		{"policy", logging.CategoryPolicy},
		{"screen", logging.CategoryScreen},
		{"firewall", logging.CategoryFirewall},
		{"session,policy", logging.CategorySession | logging.CategoryPolicy},
		{" session , screen ", logging.CategorySession | logging.CategoryScreen},
	}

	for _, tt := range tests {
		got, err := parseCategories(tt.input)
		if err != nil {
			t.Errorf("parseCategories(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseCategories(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}

	// #3383: a typo OR an empty token (leading/trailing/double comma) must
	// be rejected (fail-closed), not collapse to 0 = unfiltered. A
	// fully-absent param ("") stays match-all and is covered by the table
	// above.
	for _, bad := range []string{
		"polciy", "sesion", "session,polciy", "bogus",
		",", "policy,", ",policy", "session,,policy", " , ",
	} {
		if _, err := parseCategories(bad); err == nil {
			t.Errorf("parseCategories(%q) = nil error, want rejection", bad)
		}
	}
}

func TestMatchCategory(t *testing.T) {
	tests := []struct {
		eventType string
		mask      uint8
		want      bool
	}{
		{"SESSION_OPEN", logging.CategorySession, true},
		{"SESSION_CLOSE", logging.CategorySession, true},
		{"SESSION_OPEN", logging.CategoryPolicy, false},
		{"POLICY_DENY", logging.CategoryPolicy, true},
		{"SCREEN_DROP", logging.CategoryScreen, true},
		{"FILTER_LOG", logging.CategoryFirewall, true},
		{"UNKNOWN_TYPE", logging.CategorySession, false}, // #3383: unknown fails closed under a narrow mask
	}

	for _, tt := range tests {
		got := matchCategory(tt.eventType, tt.mask)
		if got != tt.want {
			t.Errorf("matchCategory(%q, %d) = %v, want %v", tt.eventType, tt.mask, got, tt.want)
		}
	}
}

func TestEventBufferSubscription(t *testing.T) {
	buf := logging.NewEventBuffer(10)
	sub := buf.Subscribe(16)
	defer sub.Close()

	rec := logging.EventRecord{
		Time: time.Now(), Type: "SESSION_OPEN", Action: "permit",
	}
	buf.Add(rec)

	select {
	case got := <-sub.C:
		if got.Type != "SESSION_OPEN" {
			t.Errorf("type = %q, want SESSION_OPEN", got.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscription event")
	}

	// Unsubscribe (#3384: Close also closes the channel). Verify the
	// channel is closed AND that no live record was delivered after
	// unsubscribe — a closed channel yields the zero value with ok==false,
	// so checking ok is what makes this a real assertion rather than a
	// vacuous read that any closed channel would satisfy.
	sub.Close()
	buf.Add(rec)
	got, ok := <-sub.C
	if ok {
		t.Fatalf("received a live record (%+v) after Close; want closed channel (ok==false)", got)
	}
}
