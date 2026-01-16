package tferrors

import (
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/stretchr/testify/assert"
)

func TestGetPayloadErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		payload  interface{}
		expected string
	}{
		{
			name:     "nil payload",
			payload:  nil,
			expected: "API error response payload is nil",
		},
		{
			name:     "empty string payload",
			payload:  "",
			expected: "API error response format not recognized",
		},
		{
			name:     "unsupported payload type",
			payload:  123,
			expected: "API error response format not recognized",
		},
		{
			name: "MsaReplyMetaOnly with valid error message",
			payload: &models.MsaReplyMetaOnly{
				Errors: []*models.MsaAPIError{
					{
						Message: stringPtr("Test error message"),
					},
				},
			},
			expected: "Test error message",
		},
		{
			name: "MsaReplyMetaOnly with nil errors",
			payload: &models.MsaReplyMetaOnly{
				Errors: nil,
			},
			expected: "API error response contains no error messages",
		},
		{
			name: "MsaReplyMetaOnly with empty errors slice",
			payload: &models.MsaReplyMetaOnly{
				Errors: []*models.MsaAPIError{},
			},
			expected: "API error response contains no error messages",
		},
		{
			name: "MsaReplyMetaOnly with nil error element",
			payload: &models.MsaReplyMetaOnly{
				Errors: []*models.MsaAPIError{nil},
			},
			expected: "API error response contains no error messages",
		},
		{
			name: "MsaReplyMetaOnly with nil message",
			payload: &models.MsaReplyMetaOnly{
				Errors: []*models.MsaAPIError{
					{
						Message: nil,
					},
				},
			},
			expected: "API error response contains no error messages",
		},
		{
			name: "MsaspecResponseFields with valid error message",
			payload: &models.MsaspecResponseFields{
				Errors: []*models.MsaAPIError{
					{
						Message: stringPtr("Another test error"),
					},
				},
			},
			expected: "Another test error",
		},
		{
			name: "multiple errors returns first",
			payload: &models.MsaReplyMetaOnly{
				Errors: []*models.MsaAPIError{
					{Message: stringPtr("First error")},
					{Message: stringPtr("Second error")},
				},
			},
			expected: "First error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPayloadErrorMessage(tt.payload)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
