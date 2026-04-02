package retry

import (
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// SkippableBackOff wraps another BackOff and returns 0 (no delay) for the
// next interval when SkipNext has been called. This is useful, for example,
// when the previous operation already consumed time waiting for a timeout
// and adding additional backoff delay would be unnecessarily slow.
//
// Note: when SkipNext is set, the delegate's NextBackOff is not called, so
// wrappers like backoff.WithMaxRetries will not count the skipped interval.
type SkippableBackOff struct {
	delegate backoff.BackOff
	skip     bool
	mu       sync.Mutex
}

// NewSkippableBackOff creates a new SkippableBackOff wrapping delegate.
func NewSkippableBackOff(delegate backoff.BackOff) *SkippableBackOff {
	return &SkippableBackOff{delegate: delegate}
}

func (b *SkippableBackOff) NextBackOff() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skip {
		b.skip = false
		return 0
	}
	return b.delegate.NextBackOff()
}

func (b *SkippableBackOff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.skip = false
	b.delegate.Reset()
}

// SkipNext causes the next call to NextBackOff to return 0 (no delay).
// The flag stays set until NextBackOff consumes it, so multiple calls
// before a single NextBackOff are safe.
func (b *SkippableBackOff) SkipNext() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.skip = true
}
