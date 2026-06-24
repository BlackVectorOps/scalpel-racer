// FILENAME: internal/engine/extra_test.go
package engine_test

import (
	"context"
	"testing"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// TestSequenceRace_Flow exercises the two-request synchronized sequence engine
// end-to-end through its real barrier/setup path (previously untested).
func TestSequenceRace_Flow(t *testing.T) {
	mockH2 := &MockH2Client{
		PreparedHandle:     &customhttp.H2StreamHandle{},
		ResponseStatusCode: 200,
		ResponseBody:       []byte("seq"),
	}
	racer := engine.NewRacer(&MockClientFactory{H2: mockH2}, zap.NewNop())
	reqA := &models.CapturedRequest{URL: "https://a.example", Body: []byte("a")}
	reqB := &models.CapturedRequest{URL: "https://b.example", Body: []byte("b")}

	results, err := racer.RunSequenceRace(context.Background(), reqA, reqB)
	if err != nil {
		t.Fatalf("RunSequenceRace: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Error != nil {
			t.Errorf("result[%d] error: %v", i, r.Error)
		}
		if r.StatusCode != 200 {
			t.Errorf("result[%d] status = %d, want 200", i, r.StatusCode)
		}
	}
}

// TestSequenceRace_SetupError verifies the setup-failure path returns an error
// (and does not deadlock) when a client cannot be created.
func TestSequenceRace_SetupError(t *testing.T) {
	racer := engine.NewRacer(&MockClientFactory{H2: nil}, zap.NewNop()) // factory fails
	reqA := &models.CapturedRequest{URL: "https://a.example"}
	reqB := &models.CapturedRequest{URL: "https://b.example"}

	if _, err := racer.RunSequenceRace(context.Background(), reqA, reqB); err == nil {
		t.Error("expected a setup error when the client factory fails")
	}
}
