package acctest_test

import (
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/stretchr/testify/assert"
)

func TestConfigCompose(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config []string
		want   string
	}{
		{
			name:   "nil input returns empty string",
			config: nil,
			want:   "",
		},
		{
			name: "multiple strings",
			config: []string{
				"provider \"crowdstrike\" {}\n",
				"resource \"test\" {}\n",
				"data \"test\" {}\n",
			},
			want: "provider \"crowdstrike\" {}\nresource \"test\" {}\ndata \"test\" {}\n",
		},
		{
			name: "strings with newlines",
			config: []string{
				"resource \"test\" {\n  name = \"test\"\n}\n",
				"resource \"other\" {\n  name = \"other\"\n}\n",
			},
			want: "resource \"test\" {\n  name = \"test\"\n}\nresource \"other\" {\n  name = \"other\"\n}\n",
		},
		{
			name: "mix of empty and non-empty strings",
			config: []string{
				"",
				"resource \"test\" {}",
				"",
				"data \"test\" {}",
				"",
			},
			want: "resource \"test\" {}data \"test\" {}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := acctest.ConfigCompose(tt.config...)
			assert.Equal(t, tt.want, got)
		})
	}
}
