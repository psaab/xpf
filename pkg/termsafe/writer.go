package termsafe

import (
	"io"
	"sync"
	"unicode/utf8"
)

// maxBufferedLine bounds how much a SanitizingWriter will hold waiting for a
// newline before emitting anyway. At the bound, it may retain at most
// utf8.UTFMax-1 bytes when they are a valid but incomplete trailing rune.
//
// #7389: the motivating caller is `monitor traffic` (tcpdump), whose output is
// unbounded and interactive. A writer that buffered until a newline would grow
// without limit on a stream that never emits one -- a remote party choosing the
// packet bytes chooses whether a newline ever arrives, so "wait for the line to
// end" is an attacker-controlled allocation. Emitting a partial line is a
// cosmetic wrap; holding it is a memory defect.
const maxBufferedLine = 64 * 1024

// SanitizingWriter wraps an io.Writer and sanitizes everything passing through
// it with SanitizeBlockForDisplay, LINE AT A TIME.
//
// #7389: `handleMonitorTraffic` (tcpdump) and `handleTraceroute` wired
// `cmd.Stdout = os.Stdout` directly, so there was no string to sanitize and
// the #6584 sweep could not reach them. They are the two highest-taint sites
// in that class: tcpdump renders packet BYTES as ASCII, so the payload is
// chosen by whoever sends the packet, and traceroute resolves PTR records by
// default, so the displayed hostnames come from DNS an attacker may control.
// Both stream straight to the operator's terminal.
//
// Buffered capture was rejected: it is unbounded for tcpdump, and it breaks
// Ctrl-C and the incremental output that is the entire point of `monitor
// traffic`. A line-wise writer preserves the streaming UX.
//
// Line-at-a-time rather than chunk-at-a-time because a read boundary can fall
// mid-rune. Sanitizing a chunk that ends halfway through a multi-byte rune
// would escape the split bytes as invalid UTF-8 and corrupt legitimate output
// -- the sanitizer would be the thing mangling the text. Holding a partial
// line until its newline (or the bound) keeps runes intact.
type SanitizingWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
}

// NewSanitizingWriter returns a writer that sanitizes each line before passing
// it to w.
func NewSanitizingWriter(w io.Writer) *SanitizingWriter {
	return &SanitizingWriter{w: w}
}

// Write buffers p and emits every COMPLETE line, sanitized.
//
// It reports len(p) consumed on success. The sanitized form is a different
// length from the input -- escaping grows it -- so returning the underlying
// writer's count would make callers see a short write and retry, duplicating
// output. The contract this satisfies is io.Writer's: all of p was consumed.
func (s *SanitizingWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)

	for {
		i := indexByte(s.buf, '\n')
		if i < 0 {
			break
		}
		line := s.buf[:i+1]
		s.buf = s.buf[i+1:]
		if err := s.emit(line); err != nil {
			return 0, err
		}
	}

	if len(s.buf) >= maxBufferedLine {
		// #7389: bound the hold. Keep a valid but incomplete trailing rune
		// together for the next Write; escaping it here would make the render
		// depend on the upstream write boundary. Invalid trailing bytes are not
		// a prefix of any rune and remain in line for immediate escaping.
		suffixStart := incompleteUTF8Suffix(s.buf)
		line := s.buf[:suffixStart]
		s.buf = append([]byte(nil), s.buf[suffixStart:]...)
		if len(line) > 0 {
			if err := s.emit(line); err != nil {
				return 0, err
			}
		}
	}
	return len(p), nil
}

func (s *SanitizingWriter) emit(line []byte) error {
	_, err := io.WriteString(s.w, SanitizeBlockForDisplay(string(line)))
	return err
}

// incompleteUTF8Suffix returns the start of a trailing byte sequence that is
// a valid prefix of a UTF-8 rune but is missing one or more bytes. Invalid
// sequences return len(b), so they are emitted and escaped immediately.
//
// A UTF-8 rune is at most utf8.UTFMax bytes long, so only its final
// utf8.UTFMax-1 bytes can be an incomplete suffix. utf8.FullRune treats
// malformed encodings as complete invalid runes; combined with RuneStart that
// makes this distinguish a valid incomplete prefix from invalid input without
// retaining attacker-controlled data.
func incompleteUTF8Suffix(b []byte) int {
	start := len(b) - (utf8.UTFMax - 1)
	if start < 0 {
		start = 0
	}
	for i := start; i < len(b); i++ {
		if utf8.RuneStart(b[i]) && !utf8.FullRune(b[i:]) {
			return i
		}
	}
	return len(b)
}

// Flush emits any buffered partial line. Callers must call it once the command
// has exited, or a final line with no trailing newline is silently dropped --
// which for a diagnostic tool would mean losing the last line of output, the
// one most likely to say why it stopped.
func (s *SanitizingWriter) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf) == 0 {
		return nil
	}
	line := s.buf
	s.buf = nil
	return s.emit(line)
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
