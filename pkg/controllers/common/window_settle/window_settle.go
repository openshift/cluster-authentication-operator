package window_settle

import (
	"fmt"
	"time"
)

type Reason uint8

const (
	Fresh Reason = iota + 1
	Already
	MaxDeferredReached
	QuiescenceStart
	QuiescenceInProgress
	QuiescenceReached
)

func (r Reason) String() string {
	switch r {
	case Fresh:
		return "no deployed state, apply immediately"
	case Already:
		return "desired state already deployed"
	case MaxDeferredReached:
		return "max deferral reached, apply"
	case QuiescenceStart:
		return "quiescence window started"
	case QuiescenceInProgress:
		return "quiescence window in progress"
	case QuiescenceReached:
		return "inputs quiescent, apply"
	default:
		return "unknown"
	}
}

// WindowSettle evaluates, without changing behavior, whether a
// defferral in deployment apply would happen in the current sync.
//
// Rationale: one logical configuration change fans out into several tracked
// input changes, each reaching the deployment controller in a separate sync.
// Each one triggers its own rollout today. A settle window would wait for
// the inputs to stop changing before applying, collapsing the fan-out into
// one rollout per logical change.
//
// At the moment we do not gate the apply. It only logs the decision
// it would have made.
//
// The comparing between desired and deployed deployments is done comparing:
// - resource counts (volumes, mounts, env), not their content;
// - replicas, so capacity changes are never deferred.
type WindowSettle struct {
	Window      time.Duration
	MaxDeferral time.Duration

	// lastDesiredSignature is the most recent desired signature observed
	// while it differed from the deployed one.
	lastDesiredSignature DeploymentSignature
	// lastInputChange is when the desired signature last changed while
	// pending. The quiescence window is measured from here and resets on
	// every change.
	lastInputChange time.Time
	// firstPendingSince is when the desired state first diverged from the
	// deployed one. It is NOT reset by input changes: MaxDeferral is
	// measured from here so that continuous churn can only delay, never
	// starve, the apply.
	firstPendingSince time.Time
}

// DebounceOutcome is the decision a real settle window would have made
// for this sync. WouldDefer is the decision; the other fields explain it.
type DebounceOutcome struct {
	WouldDefer bool
	Reason     Reason
	Waited     time.Duration
	Remaining  time.Duration
	Pending    time.Duration
}

func NewWindowSettle() *WindowSettle {
	settleWindow := WindowSettle{}
	settleWindow.Window = 10 * time.Second
	settleWindow.MaxDeferral = 3 * settleWindow.Window

	return &settleWindow
}

// Debounce runs the debounce state machine.
func (s *WindowSettle) Debounce(now time.Time, desiredSignature, deployedSignature DeploymentSignature) DebounceOutcome {
	if deployedSignature == NoDeploymentSignature() {
		// No deployed state (bootstrap or deletion path): must apply immediately.
		s.lastInputChange = time.Time{}
		s.firstPendingSince = time.Time{}
		s.lastDesiredSignature = NoDeploymentSignature()
		return DebounceOutcome{
			Reason: Fresh,
		}
	}

	if desiredSignature == deployedSignature {
		s.lastInputChange = time.Time{}
		s.firstPendingSince = time.Time{}
		s.lastDesiredSignature = desiredSignature
		return DebounceOutcome{
			Reason: Already,
		}
	}

	if s.lastDesiredSignature != desiredSignature || s.lastInputChange.IsZero() {
		if s.firstPendingSince.IsZero() {
			s.firstPendingSince = now
		}
		s.lastDesiredSignature = desiredSignature
		s.lastInputChange = now
		pending := now.Sub(s.firstPendingSince)
		if pending >= s.MaxDeferral { // also "=" because a brand new apply must apply instantly
			return DebounceOutcome{
				Reason:  MaxDeferredReached,
				Pending: pending,
			}
		}
		return DebounceOutcome{
			WouldDefer: true,
			Reason:     QuiescenceStart,
			Remaining:  s.Window,
			Pending:    pending,
		}
	}

	waited := now.Sub(s.lastInputChange)
	pending := now.Sub(s.firstPendingSince)
	switch {
	case pending >= s.MaxDeferral:
		// Under continuous churn or a stalled worker a real window must not
		// defer forever: after maxDeferral the debounce degrades to a
		// throttle and the current state is applied.
		return DebounceOutcome{
			Reason:  MaxDeferredReached,
			Waited:  waited,
			Pending: pending,
		}
	case waited >= s.Window:
		return DebounceOutcome{
			Reason:  QuiescenceReached,
			Waited:  waited,
			Pending: pending,
		}
	default:
		return DebounceOutcome{
			WouldDefer: true,
			Reason:     QuiescenceInProgress,
			Waited:     waited,
			Remaining:  s.Window - waited,
			Pending:    pending,
		}
	}
}

// DeploymentSignature summarizes the rollout-relevant shape of the desired
// or deployed oauth-server deployment. The rvs-hash covers every tracked
// configmap and secret content change plus the proxy settings; the counts
// cover template changes that are not hash-driven (IdP and proxy CA mounts,
// proxy env vars); replicas keep capacity changes out of the window.
type DeploymentSignature struct {
	rvsHash                    string
	replicas                   int32
	volumes, volumeMounts, env int
}

func NoDeploymentSignature() DeploymentSignature {
	return DeploymentSignature{}
}

func NewDeploymentSignature(rvsHash string, replicas int32, volumes, volumeMounts, env int) DeploymentSignature {
	return DeploymentSignature{
		rvsHash:      rvsHash,
		replicas:     replicas,
		volumes:      volumes,
		volumeMounts: volumeMounts,
		env:          env,
	}
}

func (ds DeploymentSignature) String() string {
	return fmt.Sprintf("%s/replicas=%d/volumes=%d/mounts=%d/env=%d", ds.rvsHash, ds.replicas, ds.volumes, ds.volumeMounts, ds.env)
}
