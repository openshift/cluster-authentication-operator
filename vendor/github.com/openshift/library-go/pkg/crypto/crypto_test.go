package crypto

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCurvePreferencesToGroups(t *testing.T) {
	tests := []struct {
		name                   string
		config                 map[string]interface{}
		sourcePath             []string
		targetPath             []string
		expectedGroups         []string
		expectedUnrecog        []tls.CurveID
		expectedTargetPathSet  bool
		expectError            bool
	}{
		{
			name: "all recognized curve IDs",
			config: map[string]interface{}{
				"servingInfo": map[string]interface{}{
					"curvePreferences": []interface{}{int64(tls.X25519), int64(tls.CurveP256), int64(tls.CurveP384)},
				},
			},
			sourcePath:            []string{"servingInfo", "curvePreferences"},
			targetPath:            []string{"tempGroups"},
			expectedGroups:        []string{"X25519", "secp256r1", "secp384r1"},
			expectedTargetPathSet: true,
		},
		{
			name: "some unrecognized curve IDs",
			config: map[string]interface{}{
				"servingInfo": map[string]interface{}{
					"curvePreferences": []interface{}{int64(tls.X25519), int64(9999), int64(tls.CurveP256)},
				},
			},
			sourcePath:            []string{"servingInfo", "curvePreferences"},
			targetPath:            []string{"tempGroups"},
			expectedGroups:        []string{"X25519", "secp256r1"},
			expectedUnrecog:       []tls.CurveID{9999},
			expectedTargetPathSet: true,
		},
		{
			name: "all unrecognized curve IDs - target path not set",
			config: map[string]interface{}{
				"servingInfo": map[string]interface{}{
					"curvePreferences": []interface{}{int64(9998), int64(9999)},
				},
			},
			sourcePath:      []string{"servingInfo", "curvePreferences"},
			targetPath:      []string{"tempGroups"},
			expectedUnrecog: []tls.CurveID{9998, 9999},
		},
		{
			name:       "source path doesn't exist",
			config:     map[string]interface{}{},
			sourcePath: []string{"servingInfo", "curvePreferences"},
			targetPath: []string{"tempGroups"},
		},
		{
			name: "invalid type in curve preferences",
			config: map[string]interface{}{
				"servingInfo": map[string]interface{}{
					"curvePreferences": []interface{}{"not-an-int"},
				},
			},
			sourcePath:  []string{"servingInfo", "curvePreferences"},
			targetPath:  []string{"tempGroups"},
			expectError: true,
		},
		{
			name: "empty curve preferences array - target path not set",
			config: map[string]interface{}{
				"servingInfo": map[string]interface{}{
					"curvePreferences": []interface{}{},
				},
			},
			sourcePath: []string{"servingInfo", "curvePreferences"},
			targetPath: []string{"tempGroups"},
		},
		{
			name: "string curve IDs (apiServerArguments format)",
			config: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"tls-curve-preferences": []interface{}{"29", "23", "24"},
				},
			},
			sourcePath:            []string{"apiServerArguments", "tls-curve-preferences"},
			targetPath:            []string{"tempGroups"},
			expectedGroups:        []string{"X25519", "secp256r1", "secp384r1"},
			expectedTargetPathSet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var unrecognized []tls.CurveID
			var err error

			// Infer type from the actual data in config
			curvePrefsRaw, found, _ := unstructured.NestedSlice(tt.config, tt.sourcePath...)
			if found && len(curvePrefsRaw) > 0 {
				switch curvePrefsRaw[0].(type) {
				case string:
					unrecognized, err = CurvePreferencesToGroups[string](tt.config, tt.sourcePath, tt.targetPath)
				case int64:
					unrecognized, err = CurvePreferencesToGroups[int64](tt.config, tt.sourcePath, tt.targetPath)
				default:
					t.Fatalf("unrecognized curve preference type in test data: %T", curvePrefsRaw[0])
				}
			} else {
				// For empty/missing data, use int64 (doesn't matter which since no data to process)
				unrecognized, err = CurvePreferencesToGroups[int64](tt.config, tt.sourcePath, tt.targetPath)
			}

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(unrecognized) != len(tt.expectedUnrecog) {
				t.Errorf("expected %d unrecognized curve IDs, got %d", len(tt.expectedUnrecog), len(unrecognized))
			}
			for i, curveID := range tt.expectedUnrecog {
				if i >= len(unrecognized) || unrecognized[i] != curveID {
					t.Errorf("unrecognized curve IDs mismatch: expected %v, got %v", tt.expectedUnrecog, unrecognized)
					break
				}
			}

			groups, found, err := unstructured.NestedStringSlice(tt.config, tt.targetPath...)
			if err != nil {
				t.Errorf("error reading target path: %v", err)
			}

			if found != tt.expectedTargetPathSet {
				t.Errorf("expected target path set=%v, got set=%v", tt.expectedTargetPathSet, found)
			}

			if found {
				if len(groups) != len(tt.expectedGroups) {
					t.Errorf("expected %d groups, got %d", len(tt.expectedGroups), len(groups))
				}
				for i, group := range tt.expectedGroups {
					if i >= len(groups) || groups[i] != group {
						t.Errorf("groups mismatch: expected %v, got %v", tt.expectedGroups, groups)
						break
					}
				}
			}
		})
	}
}

func TestGroupsToCurvePreferences(t *testing.T) {
	tests := []struct {
		name                   string
		config                 map[string]interface{}
		sourcePath             []string
		targetPath             []string
		expectedCurveIDs       []int64
		expectedUnrecog        []configv1.TLSGroup
		expectedTargetPathSet  bool
		expectError            bool
	}{
		{
			name: "all recognized groups",
			config: map[string]interface{}{
				"tempGroups": []interface{}{"X25519", "secp256r1", "secp384r1"},
			},
			sourcePath:            []string{"tempGroups"},
			targetPath:            []string{"servingInfo", "curvePreferences"},
			expectedCurveIDs:      []int64{int64(tls.X25519), int64(tls.CurveP256), int64(tls.CurveP384)},
			expectedTargetPathSet: true,
		},
		{
			name: "some unrecognized groups",
			config: map[string]interface{}{
				"tempGroups": []interface{}{"X25519", "invalid-group", "secp256r1"},
			},
			sourcePath:            []string{"tempGroups"},
			targetPath:            []string{"servingInfo", "curvePreferences"},
			expectedCurveIDs:      []int64{int64(tls.X25519), int64(tls.CurveP256)},
			expectedUnrecog:       []configv1.TLSGroup{"invalid-group"},
			expectedTargetPathSet: true,
		},
		{
			name: "all unrecognized groups - target path not set",
			config: map[string]interface{}{
				"tempGroups": []interface{}{"invalid1", "invalid2"},
			},
			sourcePath:      []string{"tempGroups"},
			targetPath:      []string{"servingInfo", "curvePreferences"},
			expectedUnrecog: []configv1.TLSGroup{"invalid1", "invalid2"},
		},
		{
			name:       "source path doesn't exist",
			config:     map[string]interface{}{},
			sourcePath: []string{"tempGroups"},
			targetPath: []string{"servingInfo", "curvePreferences"},
		},
		{
			name: "empty groups array - target path not set",
			config: map[string]interface{}{
				"tempGroups": []interface{}{},
			},
			sourcePath: []string{"tempGroups"},
			targetPath: []string{"servingInfo", "curvePreferences"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unrecognized, err := GroupsToCurvePreferences[int64](tt.config, tt.sourcePath, tt.targetPath)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(unrecognized) != len(tt.expectedUnrecog) {
				t.Errorf("expected %d unrecognized groups, got %d", len(tt.expectedUnrecog), len(unrecognized))
			}
			for i, group := range tt.expectedUnrecog {
				if i >= len(unrecognized) || unrecognized[i] != group {
					t.Errorf("unrecognized groups mismatch: expected %v, got %v", tt.expectedUnrecog, unrecognized)
					break
				}
			}

			curvePrefsRaw, found, err := unstructured.NestedSlice(tt.config, tt.targetPath...)
			if err != nil {
				t.Errorf("error reading target path: %v", err)
			}

			if found != tt.expectedTargetPathSet {
				t.Errorf("expected target path set=%v, got set=%v", tt.expectedTargetPathSet, found)
			}

			if found {
				if len(curvePrefsRaw) != len(tt.expectedCurveIDs) {
					t.Errorf("expected %d curve preferences, got %d", len(tt.expectedCurveIDs), len(curvePrefsRaw))
				}
				for i, expectedID := range tt.expectedCurveIDs {
					if i >= len(curvePrefsRaw) {
						break
					}
					actualID, ok := curvePrefsRaw[i].(int64)
					if !ok {
						t.Errorf("curve preference at index %d is not int64", i)
						continue
					}
					if actualID != expectedID {
						t.Errorf("curve IDs mismatch at index %d: expected %d, got %d", i, expectedID, actualID)
					}
				}
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	// Test that converting groups -> curves -> groups produces the same result
	config := map[string]interface{}{
		"originalGroups": []interface{}{"X25519", "secp256r1", "secp384r1", "secp521r1"},
	}

	unrecognizedGroups, err := GroupsToCurvePreferences[int64](config, []string{"originalGroups"}, []string{"curvePrefs"})
	if err != nil {
		t.Fatalf("GroupsToCurvePreferences failed: %v", err)
	}
	if len(unrecognizedGroups) > 0 {
		t.Errorf("unexpected unrecognized groups: %v", unrecognizedGroups)
	}

	unrecognizedCurves, err := CurvePreferencesToGroups[int64](config, []string{"curvePrefs"}, []string{"reconstructedGroups"})
	if err != nil {
		t.Fatalf("CurvePreferencesToGroups failed: %v", err)
	}
	if len(unrecognizedCurves) > 0 {
		t.Errorf("unexpected unrecognized curves: %v", unrecognizedCurves)
	}

	originalGroups, _, _ := unstructured.NestedStringSlice(config, "originalGroups")
	reconstructedGroups, _, _ := unstructured.NestedStringSlice(config, "reconstructedGroups")

	if len(originalGroups) != len(reconstructedGroups) {
		t.Errorf("round-trip failed: expected %d groups, got %d", len(originalGroups), len(reconstructedGroups))
	}

	for i := range originalGroups {
		if i >= len(reconstructedGroups) || originalGroups[i] != reconstructedGroups[i] {
			t.Errorf("round-trip failed: expected %v, got %v", originalGroups, reconstructedGroups)
			break
		}
	}
}
