package barrier_test

import (
	"context"
	"testing"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/sync/barrier"
)

// TestReleaseUnblocksAllAwaiters is the happy path: every participant arrives,
// WaitReady unblocks, and Release lets them all proceed.
func TestReleaseUnblocksAllAwaiters(t *testing.T) {
	const n = 6
	b := barrier.NewSpinBarrier(n)
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { done <- b.Await(context.Background()) }()
	}

	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := b.WaitReady(wctx); err != nil {
		t.Fatalf("WaitReady with all participants present: %v", err)
	}

	b.Release()
	for i := 0; i < n; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Await returned %v, want nil after Release", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Await did not return after Release")
		}
	}
}

// TestArriveLetsWaitReadyReachTarget is the regression guard for the H1/H3
// hang: a participant that fails before it can spin-wait must still be able to
// "vote" via Arrive() so WaitReady reaches its target instead of blocking until
// the context times out.
func TestArriveLetsWaitReadyReachTarget(t *testing.T) {
	const n = 8
	b := barrier.NewSpinBarrier(n)

	done := make(chan error, n-1)
	for i := 0; i < n-1; i++ {
		go func() { done <- b.Await(context.Background()) }()
	}
	// The "failed" worker only votes; it never spins.
	b.Arrive()

	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := b.WaitReady(wctx); err != nil {
		t.Fatalf("WaitReady should reach target via the Arrive() vote, got: %v", err)
	}

	b.Release()
	for i := 0; i < n-1; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Await returned %v, want nil after Release", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Await did not return after Release")
		}
	}
}

// TestWaitReadyTimesOutWhenUndersubscribed: if the target is never reached and
// nobody votes, WaitReady must honor its context rather than hang forever.
func TestWaitReadyTimesOutWhenUndersubscribed(t *testing.T) {
	b := barrier.NewSpinBarrier(4)
	b.Arrive() // only 1 of 4 ever accounted for

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := b.WaitReady(ctx); err == nil {
		t.Fatal("WaitReady should return the context error when the target is never reached")
	}
}

// TestAwaitHonorsContext guards the spin loop's periodic safety check: a
// participant blocked in Await with the barrier never released must still fall
// out when its context is cancelled.
func TestAwaitHonorsContext(t *testing.T) {
	b := barrier.NewSpinBarrier(1)
	ctx, cancel := context.WithCancel(context.Background())

	errc := make(chan error, 1)
	go func() { errc <- b.Await(ctx) }()

	time.Sleep(20 * time.Millisecond) // let it enter the spin loop
	cancel()                          // never Release; only the ctx check can free it

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Await should return the context error after cancel, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Await did not honor context cancellation (spin safety-check broken?)")
	}
}
