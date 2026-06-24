package engine_test

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// reassemble concatenates all wire stages and parses the result as a single
// HTTP/1.1 request. It returns the parsed request, its body, and any bytes left
// over after the body — leftover bytes mean the request was self-terminating and
// the rest of the payload would be smuggled as a second request (the C1 bug).
func reassemble(t *testing.T, stages [][]byte) (req *http.Request, body, leftover []byte) {
	t.Helper()
	var buf bytes.Buffer
	for _, s := range stages {
		buf.Write(s)
	}
	br := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	req, err := http.ReadRequest(br)
	if err != nil {
		t.Fatalf("reassembled wire stages did not parse as a valid HTTP request: %v", err)
	}
	body, err = io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading parsed body: %v", err)
	}
	leftover, _ = io.ReadAll(br)
	return req, body, leftover
}

// TestPlanH1Attack_Framing is the regression guard for C1: every H1 plan must
// reassemble into exactly one well-framed request whose declared length matches
// the marker-stripped body, with no orphaned (smuggle-able) trailing bytes.
func TestPlanH1Attack_Framing(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStages int
	}{
		{"unstaged", "username=admin&amount=100", 1},
		{"single_marker", "param=val&{{SYNC}}final=true", 2},
		{"multi_marker", "a{{SYNC}}b{{SYNC}}c", 3},
		{"marker_at_end", "payload=1{{SYNC}}", 2},
		{"marker_at_start", "{{SYNC}}payload=1", 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clean := bytes.ReplaceAll([]byte(tc.body), []byte(engine.SyncMarker), nil)

			plan, err := engine.PlanH1Attack(&models.CapturedRequest{
				Method:  "POST",
				URL:     "http://api.example.com/transfer",
				Body:    []byte(tc.body),
				Headers: map[string]string{"Host": "api.example.com"},
			})
			if err != nil {
				t.Fatalf("PlanH1Attack: %v", err)
			}

			if got := len(plan.WireStages); got != tc.wantStages {
				t.Errorf("stage count = %d, want %d", got, tc.wantStages)
			}

			req, gotBody, leftover := reassemble(t, plan.WireStages)

			// The declared length must equal the real body — not 0/chunked-empty.
			if req.ContentLength != int64(len(clean)) {
				t.Errorf("Content-Length = %d, want %d (self-terminating framing?)",
					req.ContentLength, len(clean))
			}
			if !bytes.Equal(gotBody, clean) {
				t.Errorf("parsed body = %q, want %q", gotBody, clean)
			}
			// The smoking gun for C1: any trailing bytes are a smuggled request.
			if len(leftover) != 0 {
				t.Errorf("found %d orphaned bytes after the request body (smuggling): %q",
					len(leftover), leftover)
			}
		})
	}
}
