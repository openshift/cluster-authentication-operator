package ingressnodesavailable

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1listers "github.com/openshift/client-go/operator/listers/operator/v1"

	operatorv1 "github.com/openshift/api/operator/v1"

	corev1 "k8s.io/api/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func Test_ingressNodesAvailableController_numberOfCustomIngressTargets(t *testing.T) {
	tests := []struct {
		name               string
		ingressControllers []*operatorv1.IngressController
		nodes              []*corev1.Node
		expected           int
		expectedErr        string
	}{
		{
			name: "no-ingress-controller",
		},
		{
			name: "no-custom-placement",
			ingressControllers: []*operatorv1.IngressController{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-ingress-operator", Name: "default"},
					Spec:       operatorv1.IngressControllerSpec{NodePlacement: nil},
				},
			},
		},
		{
			name: "no-custom-label",
			ingressControllers: []*operatorv1.IngressController{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-ingress-operator", Name: "default"},
					Spec:       operatorv1.IngressControllerSpec{NodePlacement: &operatorv1.NodePlacement{}},
				},
			},
		},
		{
			name: "no-node",
			ingressControllers: []*operatorv1.IngressController{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-ingress-operator", Name: "default"},
					Spec: operatorv1.IngressControllerSpec{NodePlacement: &operatorv1.NodePlacement{
						NodeSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}}},
				},
			},
		},
		{
			name: "match-node",
			ingressControllers: []*operatorv1.IngressController{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-ingress-operator", Name: "default"},
					Spec: operatorv1.IngressControllerSpec{NodePlacement: &operatorv1.NodePlacement{
						NodeSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}}},
				},
			},
			nodes: []*corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "a", Labels: map[string]string{"foo": "bar"}}},
			},
			expected: 1,
		},
		{
			name: "bad-ns",
			ingressControllers: []*operatorv1.IngressController{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "default"},
					Spec: operatorv1.IngressControllerSpec{NodePlacement: &operatorv1.NodePlacement{
						NodeSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}}},
				},
			},
			nodes: []*corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "a", Labels: map[string]string{"foo": "bar"}}},
			},
			expected: 0,
		},
		{
			name: "no-match-node",
			ingressControllers: []*operatorv1.IngressController{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-ingress-operator", Name: "default"},
					Spec: operatorv1.IngressControllerSpec{NodePlacement: &operatorv1.NodePlacement{
						NodeSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}}},
				},
			},
			nodes: []*corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "a", Labels: map[string]string{"foo": "not-bar"}}},
			},
			expected: 0,
		},
		{
			name: "illegal-selector",
			ingressControllers: []*operatorv1.IngressController{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-ingress-operator", Name: "default"},
					Spec: operatorv1.IngressControllerSpec{NodePlacement: &operatorv1.NodePlacement{
						NodeSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
							{Key: "first", Operator: "In", Values: []string{"one", "two"}},
						}}}},
				},
			},
			nodes: []*corev1.Node{
				{ObjectMeta: metav1.ObjectMeta{Name: "a", Labels: map[string]string{"foo": "not-bar"}}},
			},
			expected: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingressControllerIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, ingressController := range tt.ingressControllers {
				ingressControllerIndexer.Add(ingressController)
			}
			nodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, node := range tt.nodes {
				nodeIndexer.Add(node)
			}

			c := &ingressNodesAvailableController{
				ingressLister: operatorv1listers.NewIngressControllerLister(ingressControllerIndexer),
				nodeLister:    corev1listers.NewNodeLister(nodeIndexer),
			}
			actual, actualErr := c.numberOfCustomIngressTargets(context.TODO(), nil)
			switch {
			case len(tt.expectedErr) == 0 && actualErr == nil:
			case len(tt.expectedErr) == 0 && actualErr != nil:
				t.Fatal(actualErr)
			case len(tt.expectedErr) != 0 && actualErr == nil:
				t.Fatal(tt.expectedErr)
			case len(tt.expectedErr) != 0 && actualErr != nil && !strings.Contains(actualErr.Error(), tt.expectedErr):
				t.Fatal(actualErr)
			}
			if tt.expected != actual {
				t.Error(actual)
			}
		})
	}
}
