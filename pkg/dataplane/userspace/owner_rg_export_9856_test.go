package userspace

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// #9856 STEP-0: the owner-RG export's control response keeps only 4096 deltas
// per binding buffer, so a FullResync can ACK a partial export. These cells
// assert the fail-closed v2 contract from the revised design; all three are RED
// on base (the manager accepts whatever the helper returns).

// rawJSONHelper9856 serves scripted RAW JSON replies so a cell can send v2
// fields the base ControlResponse struct does not decode.
type rawJSONHelper9856 struct {
	t       *testing.T
	replies []string
	got     []ControlRequest
}

func startRawJSONHelper9856(t *testing.T, path string, replies []string) *rawJSONHelper9856 {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	h := &rawJSONHelper9856{t: t, replies: replies}
	idx := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				line, err := bufio.NewReader(c).ReadBytes('\n')
				if err != nil {
					return
				}
				var req ControlRequest
				if err := json.Unmarshal(line, &req); err != nil {
					return
				}
				h.got = append(h.got, req)
				body := `{"ok":true,"session_export_more":false}`
				if idx < len(h.replies) {
					body = h.replies[idx]
				}
				idx++
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				_, _ = c.Write(append([]byte(body), '\n'))
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return h
}

// M2: a helper that reports export drops must fail the export — the #9767
// transaction must not ACK a partial window. RED on base: the manager ignores
// the unknown dropped field and returns success.
func TestOwnerRGExportFailsWhenHelperReportsDrops9856(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	startRawJSONHelper9856(t, sock, []string{
		`{"ok":true,"session_deltas":[{"event":"open","src_ip":"10.0.0.1"},` +
			`{"event":"open","src_ip":"10.0.0.2"}],"session_export_more":false,` +
			`"session_export_dropped":1,"session_export_seq":9}`,
	})
	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if err == nil {
		t.Fatalf("#9856 RED: helper reported session_export_dropped=1 but the export returned %d deltas with no error — the FullResync would ACK a partial window", len(deltas))
	}
}

// M6 (new Go vs v1 helper): the authoritative export must REFUSE a v1 helper
// instead of accepting today's partial response. RED on base: the unpaged
// fallback returns whatever the helper sent with no error.
func TestOwnerRGExportRefusesV1Helper9856(t *testing.T) {
	m, _, sock := pagingManager9344(t, 0)
	startPagingHelper9344(t, sock, []pageReply9344{{deltas: 3, more: false}})
	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if err == nil {
		t.Fatalf("#9856 RED: authoritative export against a v1 helper returned %d deltas with no error — a partial export reads as success", len(deltas))
	}
}

// M6 (helper restart): the continuation token is opaque {helper_incarnation,
// sequence} and validated on every page, so a restarted helper cannot reuse a
// sequence and pass echo validation. RED on base: continuations carry no
// incarnation, so the page from the restarted helper is accepted.
func TestOwnerRGExportFailsWhenHelperRestartsMidWindow9856(t *testing.T) {
	m, _, sock := pagingManager9344(t, MinProtocolOwnerRGExportPaging)
	startRawJSONHelper9856(t, sock, []string{
		`{"ok":true,"session_deltas":[{"event":"open","src_ip":"10.0.0.1"},` +
			`{"event":"open","src_ip":"10.0.0.2"}],"session_export_more":true,` +
			`"session_export_incarnation":7,"session_export_seq":3}`,
		`{"ok":true,"session_deltas":[{"event":"open","src_ip":"10.0.0.3"}],` +
			`"session_export_more":false,` +
			`"session_export_incarnation":8,"session_export_seq":3}`,
	})
	deltas, _, err := m.ExportOwnerRGSessionsPaged([]int{1})
	if err == nil {
		t.Fatalf("#9856 RED: helper incarnation changed 7->8 mid-window but the export returned %d deltas with no error — a restarted helper's sequence reuse passes validation", len(deltas))
	}
}
