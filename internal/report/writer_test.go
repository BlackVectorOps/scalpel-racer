package report_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"github.com/xkilldash9x/scalpel-racer/internal/report"
)

func TestWriteArtifacts(t *testing.T) {
	dir := t.TempDir()
	w := report.NewWriter(dir)

	results := []models.ScanResult{
		models.NewScanResult(0, 200, time.Second, []byte("ok"), nil),
		models.NewScanResult(1, 0, 0, nil, errors.New("boom")),
	}
	if err := w.WriteArtifacts(results, "race"); err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}

	var csvData, jsonData string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		switch {
		case strings.HasSuffix(e.Name(), ".csv"):
			csvData = string(b)
		case strings.HasSuffix(e.Name(), ".json"):
			jsonData = string(b)
		}
	}

	if !strings.Contains(csvData, "200") || !strings.Contains(csvData, "boom") {
		t.Errorf("CSV missing expected rows: %q", csvData)
	}
	// The error message must reach the JSON report (not "error":{}).
	if !strings.Contains(jsonData, `"boom"`) {
		t.Errorf("JSON missing error message: %q", jsonData)
	}
}
