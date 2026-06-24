// FILENAME: internal/models/models_test.go
package models_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

func TestScanResult_JSONIncludesErrorMessage(t *testing.T) {
	r := models.NewScanResult(1, 0, 0, nil, errors.New("boom"))
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	// The error interface marshals to {}; the message must be carried in a
	// string field instead so reports actually contain it.
	if !strings.Contains(string(b), `"error":"boom"`) {
		t.Errorf("JSON should carry the error message, got: %s", b)
	}
}

func TestCapturedRequest_Clone(t *testing.T) {
	original := &models.CapturedRequest{
		Method:   "POST",
		URL:      "http://example.com",
		Headers:  map[string]string{"Content-Type": "application/json", "X-ID": "123"},
		Body:     []byte(`{"key":"value"}`),
		Protocol: "h2",
	}

	clone := original.Clone()

	// 1. Verify Deep Equality
	if clone.Method != original.Method {
		t.Errorf("Method mismatch: %s", clone.Method)
	}
	if clone.Headers["Content-Type"] != "application/json" {
		t.Error("Header mismatch")
	}
	if string(clone.Body) != string(original.Body) {
		t.Error("Body mismatch")
	}

	// 2. Verify Independence (Deep Copy)
	clone.Headers["X-ID"] = "999" // Modify clone header
	clone.Body[2] = 'X'           // Modify clone body
	clone.Method = "GET"          // Modify clone method

	if original.Headers["X-ID"] == "999" {
		t.Error("Clone failed: Modifying clone header affected original")
	}
	if original.Body[2] == 'X' {
		t.Error("Clone failed: Modifying clone body affected original")
	}
	if original.Method == "GET" {
		t.Error("Clone failed: Modifying clone method affected original")
	}

	// 3. Nil check
	var nilReq *models.CapturedRequest
	if nilReq.Clone() != nil {
		t.Error("Cloning nil should return nil")
	}
}

func TestNewScanResult(t *testing.T) {
	t.Parallel()

	// 1. Valid Case
	body := []byte("test_payload")
	res := models.NewScanResult(1, 200, time.Second, body, nil)

	if res.StatusCode != 200 {
		t.Errorf("Status mismatch: got %d, want 200", res.StatusCode)
	}
	// BodyHash must be the hex-encoded sha256 of the body -- pin the algorithm
	// and encoding, not merely "non-empty".
	sum := sha256.Sum256(body)
	if want := hex.EncodeToString(sum[:]); res.BodyHash != want {
		t.Errorf("BodyHash = %s, want %s (hex sha256)", res.BodyHash, want)
	}
	if res.BodySnippet != "test_payload" {
		t.Errorf("Snippet mismatch: got %s", res.BodySnippet)
	}

	// 2. Error Case
	err := errors.New("fail")
	resErr := models.NewScanResult(2, 0, 0, nil, err)
	if resErr.Error != err {
		t.Error("Error not preserved in result")
	}
	if resErr.BodyHash != "empty" {
		t.Errorf("Hash should be 'empty' on error, got '%s'", resErr.BodyHash)
	}
	if !strings.Contains(resErr.String(), "ERR") {
		t.Errorf("String representation missing error indicator: %s", resErr.String())
	}

	// 3. Truncation
	longBody := make([]byte, 100)
	for i := range longBody {
		longBody[i] = 'A'
	}

	resLong := models.NewScanResult(3, 200, 0, longBody, nil)
	if resLong.BodySnippet != strings.Repeat("A", 50) {
		t.Errorf("Snippet not truncated to the 50-byte prefix: got %q (len %d)", resLong.BodySnippet, len(resLong.BodySnippet))
	}

	// 4. Empty-but-non-nil body (no error) hashes to the "empty" sentinel.
	resEmpty := models.NewScanResult(4, 200, 0, []byte{}, nil)
	if resEmpty.BodyHash != "empty" {
		t.Errorf("empty body should hash to \"empty\", got %q", resEmpty.BodyHash)
	}
}
