package iocindicator_test

import (
	"testing"
	"time"

	iocindicator "github.com/crowdstrike/terraform-provider-crowdstrike/internal/ioc_indicator"
	"github.com/go-openapi/strfmt"
)

func TestParseDateTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    strfmt.DateTime
		wantErr bool
	}{
		{
			name:  "valid RFC 3339 with timezone",
			input: "2025-12-31T23:59:59Z",
			want:  strfmt.DateTime(time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)),
		},
		{
			name:  "valid RFC 3339 with offset",
			input: "2025-06-15T10:30:00+05:00",
			want:  strfmt.DateTime(time.Date(2025, 6, 15, 10, 30, 0, 0, time.FixedZone("", 5*60*60))),
		},
		{
			name:  "valid date only",
			input: "2025-12-31",
			want:  strfmt.DateTime(time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)),
		},
		{
			name:    "invalid format",
			input:   "not-a-date",
			wantErr: true,
		},
		{
			name:    "partial date",
			input:   "2025-12",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := iocindicator.ParseDateTime(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseDateTime(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseDateTime(%q) unexpected error: %v", tt.input, err)
			}

			if got == nil {
				t.Fatalf("ParseDateTime(%q) returned nil, want non-nil", tt.input)
			}

			gotTime := time.Time(*got)
			wantTime := time.Time(tt.want)
			if !gotTime.Equal(wantTime) {
				t.Errorf("ParseDateTime(%q) = %v, want %v", tt.input, gotTime, wantTime)
			}
		})
	}
}
