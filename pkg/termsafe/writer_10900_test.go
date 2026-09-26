package termsafe

import (
	"bytes"
	"errors"
	"testing"
)

type failOnWriteCall struct {
	out    bytes.Buffer
	call   int
	failAt int
}

func (w *failOnWriteCall) Write(p []byte) (int, error) {
	w.call++
	if w.call == w.failAt {
		return 0, errors.New("injected write failure")
	}
	return w.out.Write(p)
}

func TestSanitizingWriterRetryAfterEmitFailureDoesNotDuplicate_10900(t *testing.T) {
	const input = "alpha\nbeta\n"
	const firstLine = "alpha\n"
	dst := &failOnWriteCall{failAt: 2}
	w := NewSanitizingWriter(dst)

	n, err := w.Write([]byte(input))
	if err == nil {
		t.Fatal("Write succeeded; expected the second line's emission to fail")
	}
	if n < 0 || n > len(input) {
		t.Fatalf("Write returned invalid count %d for %d input bytes", n, len(input))
	}
	if n != len(firstLine) {
		t.Errorf("Write consumed %d bytes, want %d bytes from the successfully emitted first line", n, len(firstLine))
	}

	// A retrying io.Writer caller retries only the unconsumed suffix. The
	// successful first line must not be buffered or emitted a second time.
	retry := []byte(input)[n:]
	n2, err := w.Write(retry)
	if err != nil {
		t.Fatalf("Write(retry): %v", err)
	}
	if n2 != len(retry) {
		t.Errorf("Write(retry) consumed %d bytes, want %d", n2, len(retry))
	}
	if got, want := dst.out.String(), input; got != want {
		t.Errorf("downstream output = %q, want exactly %q", got, want)
	}
}
