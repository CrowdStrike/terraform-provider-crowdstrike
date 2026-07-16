package preventionpolicy

import (
	"testing"
)

func TestFilterPoliciesByCID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []policyRef
		cid      string
		want     []string
	}{
		{
			name: "keeps only matching cid preserving order",
			policies: []policyRef{
				{id: "a", cid: "010abf4b"},
				{id: "b", cid: "2436580c"},
				{id: "c", cid: "010abf4b"},
			},
			cid:  "010abf4b",
			want: []string{"a", "c"},
		},
		{
			name: "case insensitive cid match",
			policies: []policyRef{
				{id: "a", cid: "010ABF4B"},
			},
			cid:  "010abf4b",
			want: []string{"a"},
		},
		{
			name: "no matches returns empty",
			policies: []policyRef{
				{id: "a", cid: "2436580c"},
			},
			cid:  "010abf4b",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := filterPoliciesByCID(tt.policies, tt.cid)
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
		policies []policyRef
		want     []string
	}{
		{
			name: "single cid",
			policies: []policyRef{
				{id: "a", cid: "010abf4b"},
				{id: "b", cid: "010abf4b"},
			},
			want: []string{"010abf4b"},
		},
		{
			name: "multiple distinct cids first-seen order",
			policies: []policyRef{
				{id: "a", cid: "2436580c"},
				{id: "b", cid: "010abf4b"},
				{id: "c", cid: "2436580c"},
			},
			want: []string{"2436580c", "010abf4b"},
		},
		{
			name: "empty cids skipped",
			policies: []policyRef{
				{id: "a", cid: ""},
				{id: "b", cid: "010abf4b"},
			},
			want: []string{"010abf4b"},
		},
		{
			name:     "no policies",
			policies: []policyRef{},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := distinctCIDs(tt.policies)
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
			if got := stripChecksum(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
