package fim_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/fim"
)

func TestFilterPoliciesByCID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []fim.PolicyRef
		cid      string
		want     []string
	}{
		{
			name: "keeps only matching cid preserving order",
			policies: []fim.PolicyRef{
				fim.NewPolicyRef("a", "010abf4b", ""),
				fim.NewPolicyRef("b", "2436580c", ""),
				fim.NewPolicyRef("c", "010abf4b", ""),
			},
			cid:  "010abf4b",
			want: []string{"a", "c"},
		},
		{
			name: "case insensitive cid match",
			policies: []fim.PolicyRef{
				fim.NewPolicyRef("a", "010ABF4B", ""),
			},
			cid:  "010abf4b",
			want: []string{"a"},
		},
		{
			name: "no matches returns empty",
			policies: []fim.PolicyRef{
				fim.NewPolicyRef("a", "2436580c", ""),
			},
			cid:  "010abf4b",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := fim.FilterPoliciesByCID(tt.policies, tt.cid)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestDistinctCIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []fim.PolicyRef
		want     []string
	}{
		{
			name: "single cid",
			policies: []fim.PolicyRef{
				fim.NewPolicyRef("a", "010abf4b", ""),
				fim.NewPolicyRef("b", "010abf4b", ""),
			},
			want: []string{"010abf4b"},
		},
		{
			name: "multiple distinct cids first-seen order",
			policies: []fim.PolicyRef{
				fim.NewPolicyRef("a", "2436580c", ""),
				fim.NewPolicyRef("b", "010abf4b", ""),
				fim.NewPolicyRef("c", "2436580c", ""),
			},
			want: []string{"2436580c", "010abf4b"},
		},
		{
			name: "empty cids skipped",
			policies: []fim.PolicyRef{
				fim.NewPolicyRef("a", "", ""),
				fim.NewPolicyRef("b", "010abf4b", ""),
			},
			want: []string{"010abf4b"},
		},
		{
			name:     "no policies",
			policies: []fim.PolicyRef{},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := fim.DistinctCIDs(tt.policies)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestStripChecksum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "uppercase ccid with checksum",
			in:   "010ABF4B1BA04B7DA3F240A4C56657AC-C1",
			want: "010abf4b1ba04b7da3f240a4c56657ac",
		},
		{
			name: "no checksum suffix",
			in:   "010ABF4B1BA04B7DA3F240A4C56657AC",
			want: "010abf4b1ba04b7da3f240a4c56657ac",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := fim.StripChecksum(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultPolicyName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		platform string
		want     string
	}{
		{platform: "Windows", want: "Default Policy (Windows)"},
		{platform: "Linux", want: "Default Policy (Linux)"},
		{platform: "Mac", want: "Default Policy (Mac)"},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			t.Parallel()
			if got := fim.DefaultPolicyName(tt.platform); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
