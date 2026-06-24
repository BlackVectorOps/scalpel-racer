// FILENAME: internal/engine/e2e_test.go
package engine_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// TestE2E_Workflow drives a real staged H1 race against a live local server
// through the production RealClientFactory + customhttp client, and asserts that
// every worker completes with a 200 AND that the server received the full,
// marker-stripped body intact (an end-to-end guard for the staged-framing fix).
func TestE2E_Workflow(t *testing.T) {
	var mu sync.Mutex
	var gotLens []int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotLens = append(gotLens, len(body))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "pong")
	}))
	defer srv.Close()

	racer := engine.NewRacer(&engine.RealClientFactory{}, zap.NewNop())
	// "p1{{SYNC}}p2" -> staged into two packets; the server must still see "p1p2".
	req := &models.CapturedRequest{Method: "POST", URL: srv.URL, Body: []byte("p1{{SYNC}}p2")}

	const concurrency = 5
	ch := make(chan models.ScanResult, concurrency+1)
	if err := racer.RunH1Race(context.Background(), req, concurrency, ch); err != nil {
		t.Fatalf("RunH1Race: %v", err)
	}

	results := drainResults(ch)
	if len(results) != concurrency {
		t.Fatalf("expected %d results, got %d", concurrency, len(results))
	}
	for i, r := range results {
		if r.Error != nil {
			t.Errorf("result[%d] error: %v", i, r.Error)
			continue
		}
		if r.StatusCode != http.StatusOK {
			t.Errorf("result[%d] status = %d, want 200", i, r.StatusCode)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotLens) != concurrency {
		t.Fatalf("server handled %d requests, want %d", len(gotLens), concurrency)
	}
	for _, n := range gotLens {
		if n != len("p1p2") {
			t.Errorf("server received body length %d, want %d (staged body corrupted?)", n, len("p1p2"))
		}
	}
}
