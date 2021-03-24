package oauthendpoints

import (
	"reflect"
	"testing"
)

func Test_toHealthzURL(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "test urls",
			args: []string{"a", "b"},
			want: []string{"https://a/healthz", "https://b/healthz"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toHealthzURL(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toHealthzURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
