// FILENAME: internal/sync/barrier/barrier.go
package barrier

import (
	"context"
	"runtime"
	"sync/atomic"

	"github.com/xkilldash9x/scalpel-racer/internal/config"
)

// SpinBarrier is a high-precision synchronization primitive.
// It uses busy-waiting (spinning) to achieve minimal latency jitter
// during the release phase of a packet synchronization attack.
type SpinBarrier struct {
	target int32
	count  int32
	flag   int32 // 0 = Hold, 1 = Release
	ready  chan struct{}
}

// NewSpinBarrier creates a barrier for the specified number of participants.
func NewSpinBarrier(concurrency int) *SpinBarrier {
	return &SpinBarrier{
		target: int32(concurrency),
		ready:  make(chan struct{}),
	}
}

// Arrive registers a participant without spinning. It exists so that a
// participant which will NOT wait for the release (for example a worker that
// failed during setup, or one that was cancelled before reaching the barrier)
// can still "vote", allowing WaitReady to reach the target instead of hanging
// until the context times out. The ready channel is closed exactly once, by
// the goroutine whose arrival makes the count equal the target; any further
// arrivals see count != target and do not close it.
func (b *SpinBarrier) Arrive() {
	if atomic.AddInt32(&b.count, 1) == b.target {
		close(b.ready)
	}
}

// Await registers a participant and spins until the barrier is released.
// It relies on the caller to lock the OS thread if extreme precision is required.
func (b *SpinBarrier) Await(ctx context.Context) error {
	// 1. Register arrival (also unblocks WaitReady once everyone is in).
	b.Arrive()

	// 2. Spin Loop
	// We avoid channels here to prevent scheduler preemption cost.
	spin := 0
	for atomic.LoadInt32(&b.flag) == 0 {
		spin++
		// Periodic safety check to prevent deadlock/starvation.
		// SpinBarrierCheck is the period (check every Nth iteration), so this
		// must be modulo, not a bitmask: `spin & 1024` is true for whole
		// 1024-iteration windows (~half of all spins), which would call
		// Gosched() far too often and destroy the spin precision.
		if spin%config.SpinBarrierCheck == 0 {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			runtime.Gosched()
		}
	}
	return nil
}

// WaitReady blocks until all participants have called Await.
// This is used by the orchestrator to ensure everyone is lined up before firing.
func (b *SpinBarrier) WaitReady(ctx context.Context) error {
	select {
	case <-b.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release drops the barrier, allowing all spinning goroutines to proceed simultaneously.
func (b *SpinBarrier) Release() {
	atomic.StoreInt32(&b.flag, 1)
}
