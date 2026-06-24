// FILENAME: internal/models/models.go
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf8"
)

// CapturedRequest represents the attack configuration.
type CapturedRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        []byte            `json:"body,omitempty"`
	Protocol    string            `json:"protocol"`
	OffloadPath string            `json:"-"`
}

// Clone creates a deep copy of the request.
func (r *CapturedRequest) Clone() *CapturedRequest {
	if r == nil {
		return nil
	}
	c := &CapturedRequest{
		Method:      r.Method,
		URL:         r.URL,
		Protocol:    r.Protocol,
		OffloadPath: r.OffloadPath,
		Headers:     make(map[string]string, len(r.Headers)),
	}

	for k, v := range r.Headers {
		c.Headers[k] = v
	}

	if len(r.Body) > 0 {
		c.Body = make([]byte, len(r.Body))
		copy(c.Body, r.Body)
	}

	return c
}

// ScanResult represents the outcome of a single probe.
type ScanResult struct {
	Index       int               `json:"index"`
	StatusCode  int               `json:"status_code"`
	Duration    time.Duration     `json:"duration_ns"`
	BodyHash    string            `json:"body_hash"`
	BodySnippet string            `json:"body_snippet"`
	Body        []byte            `json:"-"` // Exclude raw body from JSON summary
	Error       error             `json:"-"` // interface; marshals to {}, so excluded -- see ErrorMsg
	ErrorMsg    string            `json:"error,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

func NewScanResult(index int, statusCode int, duration time.Duration, body []byte, err error) ScanResult {
	r := ScanResult{
		Index:      index,
		StatusCode: statusCode,
		Duration:   duration,
		Error:      err,
		Body:       body,
		Meta:       make(map[string]string),
	}
	if err != nil {
		r.ErrorMsg = err.Error()
	}

	if err == nil && len(body) > 0 {
		hash := sha256.Sum256(body)
		r.BodyHash = hex.EncodeToString(hash[:])

		limit := 50
		if len(body) < limit {
			limit = len(body)
		}
		snippet := body[:limit]
		// Back off a trailing partial UTF-8 rune so the snippet is always valid
		// UTF-8 (slicing at a fixed byte offset can split a multi-byte rune).
		for len(snippet) > 0 {
			if r, size := utf8.DecodeLastRune(snippet); r == utf8.RuneError && size == 1 {
				snippet = snippet[:len(snippet)-1]
			} else {
				break
			}
		}
		r.BodySnippet = string(snippet)
	} else {
		r.BodyHash = "empty"
	}

	return r
}

func (r ScanResult) String() string {
	if r.Error != nil {
		return fmt.Sprintf("[%02d] ERR: %v", r.Index, r.Error)
	}
	return fmt.Sprintf("[%02d] %d | %v | %s...", r.Index, r.StatusCode, r.Duration, r.BodySnippet)
}
