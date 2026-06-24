// FILENAME: internal/engine/planner.go
package engine

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// SyncMarker denotes the boundary for synchronization barriers in the payload.
const SyncMarker = "{{SYNC}}"

// RacePlan encapsulates the calculated strategy for a staged attack.
type RacePlan struct {
	WireStages   [][]byte
	CleanRequest *http.Request
}

// PlanH1Attack performs the pure logic of analyzing a capture and calculating
// the wire-level split points.
func PlanH1Attack(reqSpec *models.CapturedRequest) (*RacePlan, error) {
	// 1. Logic: Split body by marker to get clean chunks
	rawBody := reqSpec.Body
	if rawBody == nil {
		rawBody = []byte{}
	}
	markerBytes := []byte(SyncMarker)
	bodyChunks := bytes.Split(rawBody, markerBytes)

	// 2. Logic: Reconstruct "clean" body and Request Object
	// OPTIMIZATION: We pass the body chunks to calculate length, but we do NOT
	// join them immediately into a massive buffer for serialization.
	req, cleanBody, err := constructCleanRequest(reqSpec, bodyChunks)
	if err != nil {
		return nil, err
	}

	// 3. Serialize the full request to wire format. SerializeRequest emits the
	// headers AND body framed with a correct Content-Length (= len(cleanBody)).
	serialized, err := customhttp.SerializeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("serialization failed: %w", err)
	}

	// 4. Map stages.
	var wireStages [][]byte
	if len(bodyChunks) <= 1 || len(cleanBody) == 0 {
		// No {{SYNC}} markers (or no body): send the whole, correctly-framed
		// request as a single stage. No intermediate barriers are created.
		wireStages = [][]byte{serialized}
	} else {
		// Staged attack: keep the serialized header block, then stream the real
		// body split at the markers. The chunks sum to cleanBody, so the
		// Content-Length declared in the headers stays correct. Splitting at the
		// first blank line is safe: header values cannot contain a blank line.
		sep := []byte("\r\n\r\n")
		hdrEnd := bytes.Index(serialized, sep)
		if hdrEnd < 0 {
			return nil, fmt.Errorf("serialized request missing header terminator")
		}
		headerBytes := serialized[:hdrEnd+len(sep)]

		wireStages = make([][]byte, len(bodyChunks))
		// Stage 0: Headers + Chunk 0 (copied so we don't alias the serialized buffer).
		wireStages[0] = append(append([]byte{}, headerBytes...), bodyChunks[0]...)
		// Subsequent Stages: Chunk N
		for i := 1; i < len(bodyChunks); i++ {
			wireStages[i] = bodyChunks[i]
		}
	}

	// Rebuild a fresh CleanRequest with a readable body for higher-level logic
	// (the request used for serialization had its body consumed during reads).
	req, _ = http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(cleanBody))
	req.ContentLength = int64(len(cleanBody))
	for k, v := range reqSpec.Headers {
		req.Header.Set(k, v)
	}

	// Explicitly set Host again on the reconstructed object.
	// This handles the case where the caller uses this object, ensuring the
	// Virtual Host is correct even if req.URL points to an IP address.
	if h, ok := reqSpec.Headers["Host"]; ok {
		req.Host = h
	}

	return &RacePlan{
		WireStages:   wireStages,
		CleanRequest: req,
	}, nil
}

// constructCleanRequest creates a standard http.Request without the sync markers.
// It returns the request (with NoBody but correct Content-Length) and the clean bytes.
func constructCleanRequest(reqSpec *models.CapturedRequest, bodyChunks [][]byte) (*http.Request, []byte, error) {
	method := reqSpec.Method
	if method == "" {
		method = "POST"
	}

	cleanBody := bytes.Join(bodyChunks, []byte{})
	totalLen := int64(len(cleanBody))

	// Build the request with the real (marker-stripped) body so SerializeRequest
	// frames it with a correct Content-Length. Passing http.NoBody here makes
	// SerializeRequest read an empty body and reset Content-Length to 0, which
	// yields a self-terminating request whose later-appended body is smuggled.
	req, err := http.NewRequest(method, reqSpec.URL, bytes.NewReader(cleanBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Scalpel-Racer/Go-H1")
	// Correctly set Content-Length for the stripped body.
	req.ContentLength = totalLen

	// Apply headers from capture with strict validation
	for k, v := range reqSpec.Headers {
		canonical := http.CanonicalHeaderKey(k)

		// BUG FIX: Strip connection-control headers that disrupt pipelining.
		if canonical == "Content-Length" || canonical == "Transfer-Encoding" || canonical == "Connection" {
			// Validate format if it's Content-Length, even if we ignore the value for the override.
			// This ensures we catch malformed input as expected by the tests.
			if canonical == "Content-Length" {
				if _, err := strconv.ParseInt(v, 10, 64); err != nil {
					return nil, nil, fmt.Errorf("invalid Content-Length header: %w", err)
				}
			}
			continue
		}
		req.Header.Set(k, v)
	}

	// Explicitly set Host from spec if present.
	// This ensures the Host header in the serialized request matches the original
	// capture, preserving Virtual Hosting even if the URL uses an IP address.
	if h, ok := reqSpec.Headers["Host"]; ok {
		req.Host = h
	}

	// BUG FIX: Enforce Keep-Alive to ensure the socket remains open for subsequent packet stages.
	req.Header.Set("Connection", "keep-alive")

	return req, cleanBody, nil
}
