package window_settle

import (
	"testing"
	"time"
)

func TestWindowSettleDebounce(t *testing.T) {
	now := time.Now()

	t.Run("no deployed state applies immediately", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		d := s.Debounce(now, NewDeploymentSignature("a", 3, 1, 1, 0), NoDeploymentSignature())
		if d.WouldDefer || d.Reason != Fresh {
			t.Errorf("expected immediate apply on bootstrap, got %+v", d)
		}
	})

	t.Run("desired already deployed applies nothing", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		desired := NewDeploymentSignature("a", 3, 1, 1, 0)
		d := s.Debounce(now, desired, desired)
		if d.WouldDefer || d.Reason != Already {
			t.Errorf("expected no deferral when deployed equals desired, got %+v", d)
		}
	})

	t.Run("window starts on first sighting of a new desired state", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		d := s.Debounce(now, NewDeploymentSignature("a", 3, 1, 1, 0), NewDeploymentSignature("b", 3, 1, 1, 0))
		if !d.WouldDefer || d.Reason != QuiescenceStart {
			t.Errorf("expected deferral with window start, got %+v", d)
		}
		if d.Remaining != 10*time.Second {
			t.Errorf("expected a full window remaining, got %s", d.Remaining)
		}
	})

	t.Run("window resets when the desired state changes again", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		deployed := NewDeploymentSignature("b", 3, 1, 1, 0)
		s.Debounce(now, NewDeploymentSignature("a", 3, 1, 1, 0), deployed)
		// 9s later the fan-out delivers a further intermediate state.
		d := s.Debounce(now.Add(9*time.Second), NewDeploymentSignature("a2", 3, 2, 2, 0), deployed)
		if !d.WouldDefer || d.Reason != QuiescenceStart {
			t.Errorf("expected window reset on new desired state, got %+v", d)
		}
		if d.Pending != 9*time.Second {
			t.Errorf("expected pending to keep accumulating across resets, got %s", d.Pending)
		}
		// The reset must buy a full window, not the residue of the old one.
		d = s.Debounce(now.Add(9*time.Second+5*time.Second), NewDeploymentSignature("a2", 3, 2, 2, 0), deployed)
		if !d.WouldDefer || d.Reason != QuiescenceInProgress || d.Waited != 5*time.Second {
			t.Errorf("expected 5s waited after reset, got %+v", d)
		}
	})

	t.Run("apply once quiescent", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		desired := NewDeploymentSignature("a", 3, 1, 1, 0)
		deployed := NewDeploymentSignature("b", 3, 1, 1, 0)
		s.Debounce(now, desired, deployed)
		d := s.Debounce(now.Add(10*time.Second), desired, deployed)
		if d.WouldDefer || d.Reason != QuiescenceReached {
			t.Errorf("expected apply after window, got %+v", d)
		}
	})

	t.Run("max deferral degrades debounce to throttle", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		deployed := NewDeploymentSignature("b", 3, 1, 1, 0)
		s.Debounce(now, NewDeploymentSignature("a", 3, 1, 1, 0), deployed)
		// Input keeps changing, so the window keeps resetting.
		for elapsed := 5 * time.Second; elapsed <= 30*time.Second; elapsed += 5 * time.Second {
			s.Debounce(now.Add(elapsed), NewDeploymentSignature("a"+elapsed.String(), 3, 1, 1, 0), deployed)
		}
		d := s.Debounce(now.Add(30*time.Second), NewDeploymentSignature("a-final", 3, 1, 1, 0), deployed)
		if d.WouldDefer || d.Reason != MaxDeferredReached {
			t.Errorf("expected apply at max deferral under churn, got %+v", d)
		}
		if d.Pending < 30*time.Second {
			t.Errorf("expected pending to have reached the cap, got %s", d.Pending)
		}
	})

	t.Run("decision is re-derivable after restart", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		desired := NewDeploymentSignature("a", 3, 1, 1, 0)
		deployed := NewDeploymentSignature("b", 3, 1, 1, 0)
		s.Debounce(now, desired, deployed)
		// Operator restart: fresh observer, same signatures.
		s2 := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		d := s2.Debounce(now.Add(time.Minute), desired, deployed)
		if !d.WouldDefer || d.Reason != QuiescenceStart {
			t.Errorf("expected a fresh window after restart, got %+v", d)
		}
		// But an already deployed state is recognized without any warm-up.
		d = s2.Debounce(now.Add(time.Minute), deployed, deployed)
		if d.WouldDefer || d.Reason != Already {
			t.Errorf("expected no deferral for deployed state after restart, got %+v", d)
		}
	})

	t.Run("capacity changes are part of the signature", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		// Same hash and shape, different replica count: the desired state
		// differs, so the debounce tracks it like any other change.
		d := s.Debounce(now, NewDeploymentSignature("a", 5, 1, 1, 0), NewDeploymentSignature("a", 3, 1, 1, 0))
		if !d.WouldDefer || d.Reason != QuiescenceStart {
			t.Errorf("expected replica change to start a window, got %+v", d)
		}
	})

	// The invariant the MaxDeferral cap guarantees: the time between the
	// first divergence and the apply is bounded by MaxDeferral alone, never
	// by MaxDeferral plus a fresh window. Without the >= on the pending
	// check in the new-signature branch, an input landing exactly at the cap
	// would buy a full window and the apply would slip to MaxDeferral+Window.
	t.Run("input landing exactly at the cap applies immediately", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		deployed := NewDeploymentSignature("b", 3, 1, 1, 0)
		s.Debounce(now, NewDeploymentSignature("a", 3, 1, 1, 0), deployed)
		// A brand-new input arrives exactly when pending hits the cap.
		d := s.Debounce(now.Add(30*time.Second), NewDeploymentSignature("a-new", 3, 1, 1, 0), deployed)
		if d.WouldDefer || d.Reason != MaxDeferredReached {
			t.Errorf("expected immediate apply at the cap, got %+v", d)
		}
		if d.Pending != 30*time.Second {
			t.Errorf("expected pending of exactly the cap, got %s", d.Pending)
		}
	})

	// The oscillating-input churn mode: the signature keeps re-arriving, so
	// waited never reaches Window and only the pending cap can fire. This
	// exercises the MaxDeferral case in the unchanged-signature branch.
	// The cap is not a timer: it is evaluated at each sync, so the honest
	// invariant is that the apply fires on the first sync at or after
	// firstPendingSince+MaxDeferral, never a full window later.
	t.Run("oscillating inputs apply at the cap, never later", func(t *testing.T) {
		s := &WindowSettle{Window: 10 * time.Second, MaxDeferral: 30 * time.Second}
		deployed := NewDeploymentSignature("stable", 3, 1, 1, 0)
		a := NewDeploymentSignature("a", 3, 1, 1, 0)
		b := NewDeploymentSignature("b", 3, 1, 1, 0)

		// First divergence observed at t=0.
		s.Debounce(now, a, deployed)

		// Oscillate every 9s: each arrival resets lastInputChange, so waited
		// stays below the window for the whole cycle.
		const syncInterval = 9 * time.Second
		applied := false
		for elapsed := syncInterval; elapsed <= 60*time.Second; elapsed += syncInterval {
			var desired DeploymentSignature
			if (elapsed/syncInterval)%2 == 0 {
				desired = a
			} else {
				desired = b
			}
			d := s.Debounce(now.Add(elapsed), desired, deployed)
			if !d.WouldDefer {
				applied = true
				// The first sync at or after the cap is t=36s (30s cap rounded
				// up to the sync grid); one extra sync interval is the worst
				// admissible rounding, a full window is not.
				if elapsed > 30*time.Second+syncInterval {
					t.Errorf("apply happened at %s, later than the cap plus one sync interval", elapsed)
				}
				if d.Reason != MaxDeferredReached {
					t.Errorf("expected MaxDeferredReached at the cap, got %+v", d)
				}
				break
			}
			if elapsed == 27*time.Second {
				// Sanity: at 27s of churn the window is still resetting.
				if d.Reason != QuiescenceStart && d.Reason != QuiescenceInProgress {
					t.Errorf("expected the window to still be resetting at 27s, got %+v", d)
				}
			}
		}
		if !applied {
			t.Error("expected the oscillation to trigger an apply within the cap")
		}
	})
}

func TestDeploymentSignature(t *testing.T) {
	t.Run("signatures with equal fields are equal", func(t *testing.T) {
		a := NewDeploymentSignature("hash", 3, 2, 2, 1)
		b := NewDeploymentSignature("hash", 3, 2, 2, 1)
		if a != b {
			t.Errorf("expected equal signatures, got %q and %q", a, b)
		}
	})

	t.Run("signatures differ on any field", func(t *testing.T) {
		base := NewDeploymentSignature("hash", 3, 2, 2, 1)
		for _, variant := range []DeploymentSignature{
			NewDeploymentSignature("other", 3, 2, 2, 1),
			NewDeploymentSignature("hash", 5, 2, 2, 1),
			NewDeploymentSignature("hash", 3, 3, 2, 1),
			NewDeploymentSignature("hash", 3, 2, 3, 1),
			NewDeploymentSignature("hash", 3, 2, 2, 2),
			NoDeploymentSignature(),
		} {
			if base == variant {
				t.Errorf("expected signature to differ from %q", variant)
			}
		}
	})

	t.Run("string form is stable and readable", func(t *testing.T) {
		got := NewDeploymentSignature("abc123", 3, 12, 14, 3).String()
		want := "abc123/replicas=3/volumes=12/mounts=14/env=3"
		if got != want {
			t.Errorf("expected signature string %q, got %q", want, got)
		}
	})
}
