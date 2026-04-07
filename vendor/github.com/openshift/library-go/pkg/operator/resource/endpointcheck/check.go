// Package endpointcheck provides a retry-with-backoff loop for endpoint
// health checks. It skips the backoff sleep after context.DeadlineExceeded
// errors (since the request timeout already provided sufficient delay) and
// stops immediately on backoff.Permanent errors.
package endpointcheck

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/openshift/library-go/pkg/operator/resource/retry"
)

const (
	DefaultRequestTimeout = 5 * time.Second
	DefaultRetryInterval  = 2 * time.Second
	DefaultAttemptCount   = 3
)

// CheckFunc is called on each attempt with the parent context and the
// per-request timeout. Return nil on success, a regular error to trigger
// a retry, or backoff.Permanent(err) to abort immediately.
type CheckFunc func(ctx context.Context, requestTimeout time.Duration) error

// Check runs checkFn up to attemptCount times, sleeping retryInterval between
// attempts. Zero-valued parameters fall back to their Default* constants.
// If checkFn returns context.DeadlineExceeded the next backoff sleep is
// skipped, since the request timeout already consumed enough wall-clock time.
func Check(ctx context.Context, requestTimeout time.Duration, retryInterval time.Duration, attemptCount uint64, checkFn CheckFunc) error {
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	if retryInterval == 0 {
		retryInterval = DefaultRetryInterval
	}
	if attemptCount == 0 {
		attemptCount = DefaultAttemptCount
	}

	// Run checkFn given number of times. Getting a timeout from checkFn causes an immediate retry,
	// we don't wait another retryInterval before performing the next check.
	skippableBoff := retry.NewSkippableBackOff(backoff.NewConstantBackOff(retryInterval))
	boff := backoff.WithContext(backoff.WithMaxRetries(skippableBoff, attemptCount-1), ctx)
	return backoff.Retry(func() error {
		err := checkFn(ctx, requestTimeout)
		if errors.Is(err, context.DeadlineExceeded) {
			skippableBoff.SkipNext()
		}
		return err
	}, boff)
}
