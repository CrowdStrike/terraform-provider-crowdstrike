package sensorupdatepolicy

import "testing"

func TestStripBuildPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "build number only",
			input: "17407",
			want:  "17407",
		},
		{
			name:  "full version string",
			input: "7.22.17407",
			want:  "17407",
		},
		{
			name:  "two part version",
			input: "22.17407",
			want:  "17407",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "pipe-delimited build tag",
			input: "20709|n|tagged|17",
			want:  "20709|n|tagged|17",
		},
		{
			name:  "pipe-delimited n-1 build tag",
			input: "20610|n-1|tagged|1",
			want:  "20610|n-1|tagged|1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := stripBuildPrefix(tt.input); got != tt.want {
				t.Errorf("stripBuildPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
