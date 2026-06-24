// FILENAME: internal/ui/fuzz_test.go
package ui

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// FuzzTextToRequest verifies that the manual text parser handles malformed input gracefully.
func FuzzTextToRequest(f *testing.F) {
	// 1. Seed Corpus
	f.Add("GET http://example.com HTTP/1.1\nHost: example.com\n\nBody")
	f.Add("POST / HTTP/2\nContent-Length: 5\n\n12345")
	f.Add("INVALID_LINE")
	f.Add("\n\n\n")

	f.Fuzz(func(t *testing.T, text string) {
		// Mock original request for host fallback logic
		original := &models.CapturedRequest{
			Headers: map[string]string{"Host": "fallback.com"},
		}

		// Execution
		parsed, err := textToRequest(text, original)

		// Errors on invalid input are fine; a successful parse must hold the
		// type's invariants (not merely "didn't panic").
		if err != nil {
			return
		}
		if parsed.Headers == nil {
			t.Fatal("parsed.Headers must be non-nil on success")
		}
		// TextToRequest normalizes Content-Length to the actual body length.
		if cl, ok := parsed.Headers["Content-Length"]; ok {
			n, perr := strconv.Atoi(cl)
			if perr != nil || n != len(parsed.Body) {
				t.Errorf("Content-Length %q != body length %d", cl, len(parsed.Body))
			}
		}
	})
}

// FuzzClean validates that the string cleaner/truncator handles all unicode inputs
// and width constraints without panicking.
func FuzzClean(f *testing.F) {
	f.Add("Standard String", 10)
	f.Add("With\tTabs", 5)
	f.Add("With\nNewlines", 10)
	f.Add("🚀 Emoji", 2)
	f.Add("🚀 Emoji", 1)
	f.Add("Long string that needs truncation", 5)
	f.Add("", 0)
	f.Add("Negative Width", -1)

	f.Fuzz(func(t *testing.T, s string, width int) {
		// 1. Execution
		res := clean(s, width)

		// 2. Invariants
		if width <= 0 {
			if res != "" {
				t.Errorf("Expected empty string for width %d, got %q", width, res)
			}
			return
		}

		// The resulting rune count must not exceed the requested width
		count := utf8.RuneCountInString(res)
		if count > width {
			t.Errorf("Result '%s' (len %d) exceeds width %d", res, count, width)
		}
	})
}

// FuzzResolveTarget ensures the URL and Host header parsing logic is robust against
// malformed inputs, verifying that we don't panic during IP/Port extraction.
func FuzzResolveTarget(f *testing.F) {
	f.Add("http://example.com", "example.com")
	f.Add("https://1.2.3.4:8080", "")
	f.Add("/path", "host.com")
	f.Add("http://[::1]:9090", "[::1]")
	f.Add("invalid-url", "invalid-host:port:garbage")

	f.Fuzz(func(t *testing.T, uStr string, hostHdr string) {
		req := &models.CapturedRequest{
			URL:     uStr,
			Headers: map[string]string{"Host": hostHdr},
		}

		// Use a safe mock resolver
		r := &fuzzResolver{}

		// Execution - Should not panic despite garbage input
		ip, port := resolveTargetIPAndPort(req, r)

		// Invariants: a returned IP must be a real IP, and the "no target"
		// result is exactly ("", 0).
		if ip != "" && net.ParseIP(ip) == nil {
			t.Errorf("returned non-empty but unparseable IP %q", ip)
		}
		if ip == "" && port != 0 {
			t.Errorf("empty IP must pair with port 0, got port %d", port)
		}
	})
}

// FuzzRequestRoundTrip tests the consistency of serialization and deserialization.
// It generates structured requests, converts them to text, and parses them back.
func FuzzRequestRoundTrip(f *testing.F) {
	f.Add("GET", "http://example.com", "HTTP/1.1", "Host", "example.com", []byte("body"))
	f.Add("POST", "/", "HTTP/2", "Content-Type", "application/json", []byte("{}"))

	f.Fuzz(func(t *testing.T, method, url, proto, hKey, hVal string, body []byte) {
		// Limit body size for performance during fuzzing
		if len(body) > 4096 {
			return
		}

		// 1. Construct Source
		req := &models.CapturedRequest{
			Method:   method,
			URL:      url,
			Protocol: proto,
			Headers:  map[string]string{hKey: hVal},
			Body:     body,
		}

		// 2. Serialize
		txt := requestToText(req)

		// 3. Deserialize (original passed as context, mimicking the editor).
		parsed, err := textToRequest(txt, req)
		if err != nil {
			return // malformed request lines are allowed to error
		}

		// The request line is whitespace-split on re-parse, and a newline in a
		// header would shift the header/body boundary, so the round-trip is only
		// well-defined for whitespace-clean request-line tokens and newline-free
		// headers. Within that domain method, protocol, and body survive verbatim.
		if method == "" || url == "" || proto == "" ||
			strings.ContainsAny(method, " \t\r\n") ||
			strings.ContainsAny(url, " \t\r\n") ||
			strings.ContainsAny(proto, " \t\r\n") ||
			strings.ContainsAny(hKey, "\r\n") || strings.ContainsAny(hVal, "\r\n") {
			return
		}
		if parsed.Method != req.Method {
			t.Errorf("method round-trip: got %q want %q", parsed.Method, req.Method)
		}
		if parsed.Protocol != req.Protocol {
			t.Errorf("protocol round-trip: got %q want %q", parsed.Protocol, req.Protocol)
		}
		if !bytes.Equal(parsed.Body, req.Body) {
			t.Errorf("body round-trip: got %q want %q", parsed.Body, req.Body)
		}
	})
}

// -- Mocks --

// fuzzResolver implements the Resolver interface for Fuzzing purposes.
type fuzzResolver struct{}

func (f *fuzzResolver) LookupIP(host string) ([]net.IP, error) {
	// Always return a valid IP to ensure we reach deeper logic branches in the target function.
	// This helps fuzz the logic that runs AFTER a successful DNS lookup.
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}
