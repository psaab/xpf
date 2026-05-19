package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// setSSEHeaders configures the response for Server-Sent Events streaming.
func setSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
}

// writeSSEEvent writes a single SSE event to the response.
func writeSSEEvent(w http.ResponseWriter, id string, event string, data string) {
	fmt.Fprintf(w, "id: %s\n", id)
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// eventStreamHandler streams firewall events via SSE.
// Supports ?category= filter (comma-separated: session,policy,screen,firewall).
func (s *Server) eventStreamHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeError(w, http.StatusServiceUnavailable, "event buffer not available")
		return
	}

	// Parse category filter
	categoryFilter := parseCategories(r.URL.Query().Get("category"))

	setSSEHeaders(w)

	sub := s.eventBuf.Subscribe(128)
	defer sub.Close()

	var seq uint64
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-sub.C:
			if categoryFilter != 0 && !matchCategory(rec.Type, categoryFilter) {
				continue
			}
			seq++
			data, err := json.Marshal(eventEntryFromRecord(rec))
			if err != nil {
				continue
			}
			writeSSEEvent(w, fmt.Sprintf("%d", seq), rec.Type, string(data))
		}
	}
}

// logStreamHandler streams firewall events formatted as log messages via SSE.
// Supports ?severity= and ?category= filters.
func (s *Server) logStreamHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeError(w, http.StatusServiceUnavailable, "event buffer not available")
		return
	}

	severityFilter := logging.ParseSeverity(r.URL.Query().Get("severity"))
	categoryFilter := parseCategories(r.URL.Query().Get("category"))

	setSSEHeaders(w)

	sub := s.eventBuf.Subscribe(128)
	defer sub.Close()

	var seq uint64
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case rec := <-sub.C:
			severity := eventRecordSeverity(rec.Type)
			if severityFilter != 0 && severity > severityFilter {
				continue
			}
			if categoryFilter != 0 && !matchCategory(rec.Type, categoryFilter) {
				continue
			}
			seq++
			logEntry := LogStreamEntry{
				Time:     rec.Time.Format(time.RFC3339),
				Severity: severityName(severity),
				Message:  formatLogMessage(rec),
			}
			data, err := json.Marshal(logEntry)
			if err != nil {
				continue
			}
			writeSSEEvent(w, fmt.Sprintf("%d", seq), "log", string(data))
		}
	}
}

// LogStreamEntry is a log message sent via SSE.
type LogStreamEntry struct {
	Time     string `json:"time"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func eventEntryFromRecord(rec logging.EventRecord) EventEntry {
	return EventEntry{
		Time:         rec.Time.Format(time.RFC3339),
		Type:         rec.Type,
		SrcAddr:      rec.SrcAddr,
		DstAddr:      rec.DstAddr,
		Protocol:     rec.Protocol,
		Action:       rec.Action,
		PolicyID:     rec.PolicyID,
		InZone:       rec.InZone,
		OutZone:      rec.OutZone,
		ScreenCheck:  rec.ScreenCheck,
		SessionPkts:  rec.SessionPkts,
		SessionBytes: rec.SessionBytes,
	}
}

// parseCategories parses a comma-separated category string into a bitmask.
func parseCategories(s string) uint8 {
	if s == "" {
		return 0
	}
	var mask uint8
	for _, c := range strings.Split(s, ",") {
		mask |= logging.ParseCategory(strings.TrimSpace(c))
	}
	return mask
}

// matchCategory checks if an event type matches a category bitmask.
func matchCategory(eventType string, mask uint8) bool {
	var bit uint8
	switch eventType {
	case "SESSION_OPEN", "SESSION_CLOSE":
		bit = logging.CategorySession
	case "POLICY_DENY":
		bit = logging.CategoryPolicy
	case "SCREEN_DROP":
		bit = logging.CategoryScreen
	case "FILTER_LOG":
		bit = logging.CategoryFirewall
	default:
		return true // pass unknown types
	}
	return mask&bit != 0
}

// eventRecordSeverity maps event type names to syslog severity.
func eventRecordSeverity(eventType string) int {
	switch eventType {
	case "SCREEN_DROP":
		return logging.SyslogError
	case "POLICY_DENY":
		return logging.SyslogWarning
	default:
		return logging.SyslogInfo
	}
}

func severityName(s int) string {
	switch s {
	case logging.SyslogError:
		return "error"
	case logging.SyslogWarning:
		return "warning"
	default:
		return "info"
	}
}

func formatLogMessage(rec logging.EventRecord) string {
	if rec.Type == "SCREEN_DROP" {
		return fmt.Sprintf("RT_FLOW %s screen=%s src=%s dst=%s proto=%s action=%s zone=%d",
			rec.Type, rec.ScreenCheck, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action, rec.InZone)
	}
	if rec.Type == "SESSION_CLOSE" {
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%d->%d pkts=%d bytes=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			rec.PolicyID, rec.InZone, rec.OutZone, rec.SessionPkts, rec.SessionBytes)
	}
	if rec.Type == "FILTER_LOG" {
		source := rec.Reason
		if source == "" {
			source = "unknown"
		}
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s zone=%d->%d source=%s filter=%d term=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			rec.InZone, rec.OutZone, source, rec.RuleID, rec.TermID)
	}
	return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%d->%d",
		rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
		rec.PolicyID, rec.InZone, rec.OutZone)
}
