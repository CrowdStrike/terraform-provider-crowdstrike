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
			name: "MsaspecResponseFields with nil errors",
			payload: &models.MsaspecResponseFields{
				Errors: nil,
			},
			expected: "API error response contains no error messages",
		},
		{
			name: "MsaspecResponseFields with empty errors slice",
			payload: &models.MsaspecResponseFields{
				Errors: []*models.MsaAPIError{},
			},
			expected: "API error response contains no error messages",
		},
		{
			name: "MsaspecResponseFields with nil error element",
			payload: &models.MsaspecResponseFields{
				Errors: []*models.MsaAPIError{nil},
			},
			expected: "API error response contains no error messages",
		},
		{
			name: "MsaspecResponseFields with nil message",
			payload: &models.MsaspecResponseFields{
				Errors: []*models.MsaAPIError{
					{
						Message: nil,
					},
				},
			},
			expected: "API error response contains no error messages",
		},
		{
			name:     "nil MsaReplyMetaOnly pointer",
			payload:  (*models.MsaReplyMetaOnly)(nil),
			expected: "API error response payload is nil",
		},
		{
			name:     "nil MsaspecResponseFields pointer",
			payload:  (*models.MsaspecResponseFields)(nil),
			expected: "API error response payload is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPayloadErrorMessage(tt.payload)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPayloadErrorMessage_GenericPayloadStructure(t *testing.T) {
	type GenericErrorPayload struct {
		Errors []*models.MsaAPIError
	}

	tests := []struct {
		name     string
		payload  *GenericErrorPayload
		expected string
	}{
		{
			name: "generic payload with valid error",
			payload: &GenericErrorPayload{
				Errors: []*models.MsaAPIError{
					{Message: stringPtr("Generic error message")},
				},
			},
			expected: "Generic error message",
		},
		{
			name:     "generic payload with nil errors",
			payload:  &GenericErrorPayload{Errors: nil},
			expected: "API error response contains no error messages",
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

func TestGetPayloadErrorMessage_EdgeCases(t *testing.T) {
	t.Run("multiple errors returns first", func(t *testing.T) {
		payload := &models.MsaReplyMetaOnly{
			Errors: []*models.MsaAPIError{
				{Message: stringPtr("First error")},
				{Message: stringPtr("Second error")},
			},
		}
		result := GetPayloadErrorMessage(payload)
		assert.Equal(t, "First error", result)
	})

	t.Run("first error is nil but second is valid", func(t *testing.T) {
		payload := &models.MsaReplyMetaOnly{
			Errors: []*models.MsaAPIError{
				nil,
				{Message: stringPtr("Second error")},
			},
		}
		result := GetPayloadErrorMessage(payload)
		assert.Equal(t, "API error response contains no error messages", result)
	})

	t.Run("first error has nil message but second has valid message", func(t *testing.T) {
		payload := &models.MsaReplyMetaOnly{
			Errors: []*models.MsaAPIError{
				{Message: nil},
				{Message: stringPtr("Second error")},
			},
		}
		result := GetPayloadErrorMessage(payload)
		assert.Equal(t, "API error response contains no error messages", result)
	})

	t.Run("empty string message", func(t *testing.T) {
		payload := &models.MsaReplyMetaOnly{
			Errors: []*models.MsaAPIError{
				{Message: stringPtr("")},
			},
		}
		result := GetPayloadErrorMessage(payload)
		assert.Equal(t, "", result)
	})

	t.Run("whitespace-only message", func(t *testing.T) {
		payload := &models.MsaReplyMetaOnly{
			Errors: []*models.MsaAPIError{
				{Message: stringPtr("   \n\t  ")},
			},
		}
		result := GetPayloadErrorMessage(payload)
		assert.Equal(t, "   \n\t  ", result)
	})
}

// Benchmark tests to ensure the function is performant.
func BenchmarkGetPayloadErrorMessage_ValidMessage(b *testing.B) {
	payload := &models.MsaReplyMetaOnly{
		Errors: []*models.MsaAPIError{
			{Message: stringPtr("Benchmark error message")},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetPayloadErrorMessage(payload)
	}
}

func BenchmarkGetPayloadErrorMessage_NilPayload(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetPayloadErrorMessage(nil)
	}
}

func BenchmarkGetPayloadErrorMessage_UnknownType(b *testing.B) {
	payload := "unknown payload type"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetPayloadErrorMessage(payload)
	}
}
