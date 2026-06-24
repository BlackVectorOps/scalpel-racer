// FILENAME: cmd/scalpel-racer/main_test.go
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type MockRunner struct{}

func (r *MockRunner) Run(p *tea.Program) (tea.Model, error) {
	return nil, nil
}

func TestRun(t *testing.T) {
	// creates a context that cancels immediately to ensure Run exits without user input
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	args := []string{"-p", "0"}
	// Use an empty buffer for input to avoid racing on os.Stdin during test shutdown
	input := bytes.NewBuffer(nil)

	// calls Run with the injected context and safe I/O
	// note: we expect this to exit cleanly when the context times out
	if err := Run(ctx, args, input, io.Discard); err != nil {
		// If the context timed out, that's a successful test of the shutdown mechanism
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Errorf("Run failed: %v", err)
		}
	}
}

// TestRunCleanExitOnCancel locks in the H5 contract: a signal-driven shutdown
// (modelled here as an already-cancelled context) is a clean exit -- Run must
// return nil, not the ErrProgramKilled it gets back from bubbletea. It also
// exercises the graceful-shutdown path (cancel + bounded wait for races).
func TestRunCleanExitOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate SIGINT arriving at/just before startup

	if err := Run(ctx, []string{"-p", "0"}, bytes.NewBuffer(nil), io.Discard); err != nil {
		t.Errorf("Run should exit cleanly (nil) on a cancelled context, got: %v", err)
	}
}
