package proxy_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/proxy"
	"go.uber.org/zap"
)

// TestCaptureWrap_ConcurrentReadIsSafe reads the capture buffer while the wrapped
// body is still being tee'd from another goroutine -- the H2/H3 scenario where a
// plain bytes.Buffer would data-race. Run with -race to catch a regression; even
// without it the final length must equal the full payload.
func TestCaptureWrap_ConcurrentReadIsSafe(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 256*1024)
	req := httptest.NewRequest("POST", "http://example.com/", bytes.NewReader(payload))
	buf, wrapped := proxy.CaptureWrap(req)

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, wrapped.Body) // tees into buf as it reads
		close(done)
	}()

	for i := 0; i < 2000; i++ {
		_ = buf.Bytes() // concurrent read of the capture
	}
	<-done

	if got := buf.Bytes(); len(got) != len(payload) {
		t.Errorf("captured %d bytes, want %d", len(got), len(payload))
	}
}

// TestIngestionPipeline_ConcurrentCloseNoPanic exercises the shutdown TOCTOU:
// PersistCapture must never panic with "send on closed channel" when Close()
// races it, and a capture after Close must be a safe no-op. A >threshold body
// forces the slow temp-file offload path, widening the window between the
// closed-check and the send that the bug used to live in.
func TestIngestionPipeline_ConcurrentCloseNoPanic(t *testing.T) {
	p := proxy.NewIngestionPipeline(zap.NewNop())

	// Drain so the non-blocking send mostly succeeds; clean up offload files.
	drained := make(chan struct{})
	go func() {
		for c := range p.CaptureChan {
			if c.OffloadPath != "" {
				_ = os.Remove(c.OffloadPath)
			}
		}
		close(drained)
	}()

	req, _ := http.NewRequest("GET", "http://example.com/x", nil)
	body := make([]byte, 32*1024) // > config.BodyOffloadThreshold

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.PersistCapture(req, body) // must never panic, even racing Close()
		}()
	}

	p.Close() // races the in-flight captures
	wg.Wait()
	<-drained

	// A capture after Close must be a safe no-op (drop, not panic).
	p.PersistCapture(req, body)
}
