package scaling

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
)

func TestProcessDeployment(t *testing.T) {
	baseTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakeClock(baseTime)

	// Helper to create a basic deployment
	makeDeployment := func(replicas int32, annotations map[string]string) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-deployment",
				Namespace:   "test-ns",
				Annotations: annotations,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(replicas),
			},
		}
	}

	// Helper to create deployment status with Progressing condition
	makeStatus := func(progressing bool, reason string) appsv1.DeploymentStatus {
		status := corev1.ConditionFalse
		if progressing {
			status = corev1.ConditionTrue
		}
		return appsv1.DeploymentStatus{
			Conditions: []appsv1.DeploymentCondition{
				{
					Type:   appsv1.DeploymentProgressing,
					Status: status,
					Reason: reason,
				},
			},
		}
	}

	// Timestamps used in tests
	thirtySecondsAgo := baseTime.Add(-30 * time.Second).UTC().Format(time.RFC3339)
	justBeforeTimeout := baseTime.Add(-59 * time.Second).UTC().Format(time.RFC3339)
	justAfterTimeout := baseTime.Add(-61 * time.Second).UTC().Format(time.RFC3339)
	nowTimestamp := baseTime.UTC().Format(time.RFC3339)

	tests := []struct {
		name                   string
		existing               *appsv1.Deployment
		expected               *appsv1.Deployment
		wantAnnotations        map[string]string
		wantConditionOverwrite bool
		wantErr                bool
	}{
		// Edge cases: nil deployments and non-scaling changes
		{
			name:     "noop when existing is nil",
			existing: nil,
			expected: makeDeployment(3, nil),
		},
		{
			name:     "noop when expected is nil",
			existing: makeDeployment(3, nil),
			expected: nil,
		},
		{
			name: "noop when spec changed beyond replicas and discard tracking annotations",
			existing: func() *appsv1.Deployment {
				d := makeDeployment(3, map[string]string{
					replicasChangedAnnotation:      thirtySecondsAgo,
					deploymentProgressedAnnotation: "true",
				})
				d.Spec.Paused = true
				return d
			}(),
			expected: makeDeployment(3, nil),
		},
		{
			name:     "noop when replicas unchanged and no tracking annotation",
			existing: makeDeployment(3, nil),
			expected: makeDeployment(3, nil),
		},
		{
			name: "noop when existing has nil annotations map",
			existing: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-deployment",
					Namespace:   "test-ns",
					Annotations: nil,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
			},
			expected: makeDeployment(3, nil),
		},

		// Scaling start: replicas change detected
		{
			name:     "scaling start: cancel progressing when scaling up",
			existing: makeDeployment(3, nil),
			expected: makeDeployment(5, nil),
			wantAnnotations: map[string]string{
				replicasChangedAnnotation: nowTimestamp,
			},
			wantConditionOverwrite: true,
		},
		{
			name:     "scaling start: cancel progressing when scaling down",
			existing: makeDeployment(5, nil),
			expected: makeDeployment(3, nil),
			wantAnnotations: map[string]string{
				replicasChangedAnnotation: nowTimestamp,
			},
			wantConditionOverwrite: true,
		},
		{
			name: "scaling start: new timestamp when replicas change during active scaling",
			existing: func() *appsv1.Deployment {
				d := makeDeployment(5, map[string]string{
					replicasChangedAnnotation: thirtySecondsAgo,
				})
				d.Status = makeStatus(true, "ReplicaSetUpdated")
				return d
			}(),
			expected: makeDeployment(6, nil),
			wantAnnotations: map[string]string{
				replicasChangedAnnotation: nowTimestamp, // new timestamp, not the old one
			},
			wantConditionOverwrite: true,
		},

		// Scaling in progress: deployment is actively rolling out
		{
			name: "scaling in progress: keep canceling and mark as progressed",
			existing: func() *appsv1.Deployment {
				d := makeDeployment(3, map[string]string{
					replicasChangedAnnotation: thirtySecondsAgo,
				})
				d.Status = makeStatus(true, "ReplicaSetUpdated")
				return d
			}(),
			expected: makeDeployment(3, nil),
			wantAnnotations: map[string]string{
				replicasChangedAnnotation:      thirtySecondsAgo,
				deploymentProgressedAnnotation: "true",
			},
			wantConditionOverwrite: true,
		},
		{
			name: "scaling in progress: keep canceling when no deployment Progressing condition exists",
			existing: makeDeployment(3, map[string]string{
				replicasChangedAnnotation: thirtySecondsAgo,
			}),
			expected: makeDeployment(3, nil),
			wantAnnotations: map[string]string{
				replicasChangedAnnotation: thirtySecondsAgo,
			},
			wantConditionOverwrite: true,
		},

		// Scaling complete: deployment finished, clear tracking
		{
			name: "scaling complete: clear annotations after observing progression",
			existing: func() *appsv1.Deployment {
				d := makeDeployment(3, map[string]string{
					replicasChangedAnnotation:      thirtySecondsAgo,
					deploymentProgressedAnnotation: "true",
				})
				d.Status = makeStatus(true, "NewReplicaSetAvailable")
				return d
			}(),
			expected: makeDeployment(3, nil),
		},
		{
			name: "scaling complete: clear annotations after timeout even without observing progression",
			existing: func() *appsv1.Deployment {
				d := makeDeployment(3, map[string]string{
					replicasChangedAnnotation: justAfterTimeout,
				})
				d.Status = makeStatus(true, "NewReplicaSetAvailable")
				return d
			}(),
			expected: makeDeployment(3, nil),
		},

		// Scaling complete but waiting: finished quickly, never saw progression
		{
			name: "scaling finished early: keep canceling until timeout",
			existing: func() *appsv1.Deployment {
				d := makeDeployment(3, map[string]string{
					replicasChangedAnnotation: thirtySecondsAgo,
				})
				d.Status = makeStatus(true, "NewReplicaSetAvailable")
				return d
			}(),
			expected: makeDeployment(3, nil),
			wantAnnotations: map[string]string{
				replicasChangedAnnotation: thirtySecondsAgo,
			},
			wantConditionOverwrite: true,
		},

		// Timeout boundary tests
		{
			name: "timeout boundary: keep canceling at 59 seconds",
			existing: func() *appsv1.Deployment {
				d := makeDeployment(3, map[string]string{
					replicasChangedAnnotation: justBeforeTimeout,
				})
				d.Status = makeStatus(true, "NewReplicaSetAvailable")
				return d
			}(),
			expected: makeDeployment(3, nil),
			wantAnnotations: map[string]string{
				replicasChangedAnnotation: justBeforeTimeout,
			},
			wantConditionOverwrite: true,
		},
		{
			name: "timeout boundary: clear annotations at 61 seconds",
			existing: func() *appsv1.Deployment {
				d := makeDeployment(3, map[string]string{
					replicasChangedAnnotation: justAfterTimeout,
				})
				d.Status = makeStatus(true, "NewReplicaSetAvailable")
				return d
			}(),
			expected: makeDeployment(3, nil),
		},

		// Error cases
		{
			name: "error on malformed timestamp annotation",
			existing: makeDeployment(3, map[string]string{
				replicasChangedAnnotation: "not-a-timestamp",
			}),
			expected: makeDeployment(3, nil),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conditions, err := ProcessDeployment(tt.existing, tt.expected, fakeClock, "Test")

			if tt.wantErr != (err != nil) {
				t.Errorf("unexpected error returned: %v", err)
			}

			// Check conditions
			if tt.wantConditionOverwrite != (len(conditions) == 1) {
				var expectedCount int
				if tt.wantConditionOverwrite {
					expectedCount = 1
				}
				t.Errorf("expected %d condition overwrites, but got %d", expectedCount, len(conditions))
			} else if tt.wantConditionOverwrite {
				cond := conditions[0]
				if *cond.Type != "TestDeploymentProgressing" {
					t.Errorf("expected condition type %q, but got %q", "TestDeploymentProgressing", *cond.Type)
				}
				if *cond.Status != operatorv1.ConditionFalse {
					t.Errorf("expected condition status False, but got %v", *cond.Status)
				}
			}

			// Check scaling-related annotations on expected deployment
			if tt.expected != nil {
				gotAnnotations := tt.expected.Annotations
				if gotAnnotations == nil {
					gotAnnotations = make(map[string]string)
				}

				wantAnnotations := tt.wantAnnotations
				if wantAnnotations == nil {
					wantAnnotations = make(map[string]string)
				}

				if !cmp.Equal(wantAnnotations, gotAnnotations) {
					t.Errorf("annotations mismatch:\n%s", cmp.Diff(wantAnnotations, gotAnnotations))
				}
			}
		})
	}
}

func TestSpecsEqualIgnoringReplicas(t *testing.T) {
	tests := []struct {
		name     string
		existing *appsv1.Deployment
		expected *appsv1.Deployment
		want     bool
	}{
		{
			name:     "existing nil returns false",
			existing: nil,
			expected: &appsv1.Deployment{},
			want:     false,
		},
		{
			name:     "expected nil returns false",
			existing: &appsv1.Deployment{},
			expected: nil,
			want:     false,
		},
		{
			name:     "both nil returns false",
			existing: nil,
			expected: nil,
			want:     false,
		},
		{
			name: "identical specs returns true",
			existing: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas:        ptr.To[int32](3),
					MinReadySeconds: 5,
				},
			},
			expected: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas:        ptr.To[int32](3),
					MinReadySeconds: 5,
				},
			},
			want: true,
		},
		{
			name: "same specs except replicas returns true",
			existing: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas:        ptr.To[int32](3),
					MinReadySeconds: 5,
				},
			},
			expected: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas:        ptr.To[int32](5),
					MinReadySeconds: 5,
				},
			},
			want: true,
		},
		{
			name: "different specs returns false",
			existing: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas:        ptr.To[int32](3),
					MinReadySeconds: 5},
			},
			expected: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas:        ptr.To[int32](3),
					MinReadySeconds: 3,
				},
			},
			want: false,
		},
		{
			name: "nil replicas in existing handled correctly",
			existing: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas: nil,
				},
			},
			expected: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
			},
			want: true,
		},
		{
			name: "nil replicas in expected handled correctly",
			existing: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
			},
			expected: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas: nil,
				},
			},
			want: true,
		},
		{
			name: "both replicas nil handled correctly",
			existing: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas: nil,
				},
			},
			expected: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Replicas: nil,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := specsEqualIgnoringReplicas(tt.existing, tt.expected)
			if got != tt.want {
				t.Errorf("specsEqualIgnoringReplicas() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDeploymentProgressing(t *testing.T) {
	tests := []struct {
		name   string
		status appsv1.DeploymentStatus
		want   bool
	}{
		{
			name:   "return false on empty conditions",
			status: appsv1.DeploymentStatus{},
			want:   false,
		},
		{
			name: "Progressing condition with NewReplicaSetAvailable returns false",
			status: appsv1.DeploymentStatus{
				Conditions: []appsv1.DeploymentCondition{
					{
						Type:   appsv1.DeploymentProgressing,
						Status: corev1.ConditionTrue,
						Reason: "NewReplicaSetAvailable",
					},
				},
			},
			want: false,
		},
		{
			name: "Progressing condition with ReplicaSetUpdated returns true",
			status: appsv1.DeploymentStatus{
				Conditions: []appsv1.DeploymentCondition{
					{
						Type:   appsv1.DeploymentProgressing,
						Status: corev1.ConditionTrue,
						Reason: "ReplicaSetUpdated",
					},
				},
			},
			want: true,
		},
		{
			name: "Progressing condition with status False returns true",
			status: appsv1.DeploymentStatus{
				Conditions: []appsv1.DeploymentCondition{
					{
						Type:   appsv1.DeploymentProgressing,
						Status: corev1.ConditionFalse,
						Reason: "ProgressDeadlineExceeded",
					},
				},
			},
			want: true,
		},
		{
			name: "other condition type is ignored",
			status: appsv1.DeploymentStatus{
				Conditions: []appsv1.DeploymentCondition{
					{
						Type:   appsv1.DeploymentAvailable,
						Status: corev1.ConditionTrue,
					},
				},
			},
			want: false,
		},
		{
			name: "Progressing is found among multiple conditions",
			status: appsv1.DeploymentStatus{
				Conditions: []appsv1.DeploymentCondition{
					{
						Type:   appsv1.DeploymentAvailable,
						Status: corev1.ConditionTrue,
					},
					{
						Type:   appsv1.DeploymentProgressing,
						Status: corev1.ConditionTrue,
						Reason: "ReplicaSetUpdated",
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDeploymentProgressing(tt.status)
			if got != tt.want {
				t.Errorf("isDeploymentProgressing() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCancelProgressing(t *testing.T) {
	conditions := cancelProgressing("OAuth")

	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conditions))
	}

	cond := conditions[0]

	if *cond.Type != "OAuthDeploymentProgressing" {
		t.Errorf("expected type %q, got %q", "OAuthDeploymentProgressing", *cond.Type)
	}
	if *cond.Status != operatorv1.ConditionFalse {
		t.Errorf("expected status False, got %v", *cond.Status)
	}
	if *cond.Reason != "AsExpected" {
		t.Errorf("expected reason %q, got %q", "AsExpected", *cond.Reason)
	}
	if *cond.Message != "Scaling replicas only" {
		t.Errorf("expected message %q, got %q", "Scaling replicas only", *cond.Message)
	}
}
