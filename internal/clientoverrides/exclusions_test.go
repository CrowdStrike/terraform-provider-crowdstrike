package clientoverrides

import (
	"io"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExclusionsGroupsConsumer covers the groups shapes the API returns for an
// exclusions response, plus the fields alongside groups that must survive decoding.
func TestExclusionsGroupsConsumer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		body           string
		expectedGroups []string
	}{
		{
			name:           "host group objects",
			body:           `{"resources":[{"id":"exclusion-1","groups":[{"id":"group-1","name":"Group One"},{"id":"group-2"}]}]}`,
			expectedGroups: []string{"group-1", "group-2"},
		},
		{
			name:           "bare host group ids",
			body:           `{"resources":[{"id":"exclusion-1","groups":["group-1","group-2"]}]}`,
			expectedGroups: []string{"group-1", "group-2"},
		},
		{
			name:           "placeholder group with an empty id is dropped",
			body:           `{"resources":[{"id":"exclusion-1","groups":[{"id":"group-1"},{"id":""}]}]}`,
			expectedGroups: []string{"group-1"},
		},
		{
			name:           "empty groups",
			body:           `{"resources":[{"id":"exclusion-1","groups":[]}]}`,
			expectedGroups: []string{},
		},
		{
			name:           "null groups",
			body:           `{"resources":[{"id":"exclusion-1","groups":null}]}`,
			expectedGroups: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var payload models.ExclusionsRespV1
			err := exclusionsGroupsConsumer{inner: runtime.JSONConsumer()}.
				Consume(strings.NewReader(tt.body), &payload)
			require.NoError(t, err)

			require.Len(t, payload.Resources, 1)
			assert.Equal(t, "exclusion-1", *payload.Resources[0].ID)
			assert.Equal(t, tt.expectedGroups, payload.Resources[0].Groups)
		})
	}
}

// TestExclusionsGroupsConsumerKeepsSiblingFields guards the embedded-struct decoding:
// shadowing groups must not drop any other field of the response or the exclusion.
func TestExclusionsGroupsConsumerKeepsSiblingFields(t *testing.T) {
	t.Parallel()

	body := `{
		"meta": {"trace_id": "trace-1"},
		"errors": [{"code": 400, "message": "boom"}],
		"resources": [{
			"id": "exclusion-1",
			"value": "/tmp/*",
			"regexp_value": "regexp-1",
			"value_hash": "hash-1",
			"applied_globally": true,
			"is_descendant_process": true,
			"excluded_from": ["blocking"],
			"created_by": "creator",
			"created_on": "2026-01-01T00:00:00Z",
			"modified_by": "modifier",
			"last_modified": "2026-01-02T00:00:00Z",
			"groups": [{"id": "group-1"}]
		}]
	}`

	var payload models.ExclusionsRespV1
	err := exclusionsGroupsConsumer{inner: runtime.JSONConsumer()}.
		Consume(strings.NewReader(body), &payload)
	require.NoError(t, err)

	require.NotNil(t, payload.Meta)
	assert.Equal(t, "trace-1", *payload.Meta.TraceID)
	require.Len(t, payload.Errors, 1)
	assert.Equal(t, "boom", *payload.Errors[0].Message)

	require.Len(t, payload.Resources, 1)
	exclusion := payload.Resources[0]
	assert.Equal(t, "/tmp/*", *exclusion.Value)
	assert.Equal(t, "regexp-1", *exclusion.RegexpValue)
	assert.Equal(t, "hash-1", *exclusion.ValueHash)
	assert.True(t, *exclusion.AppliedGlobally)
	assert.True(t, *exclusion.IsDescendantProcess)
	assert.Equal(t, []string{"blocking"}, exclusion.ExcludedFrom)
	assert.Equal(t, "creator", *exclusion.CreatedBy)
	assert.Equal(t, "modifier", *exclusion.ModifiedBy)
	assert.Equal(t, "2026-01-01T00:00:00.000Z", exclusion.CreatedOn.String())
	assert.Equal(t, "2026-01-02T00:00:00.000Z", exclusion.LastModified.String())
	assert.Equal(t, []string{"group-1"}, exclusion.Groups)
}

// TestExclusionsGroupsConsumerDelegates checks that a target this override does not
// correct is handed to the consumer the runtime picked for the operation.
func TestExclusionsGroupsConsumerDelegates(t *testing.T) {
	t.Parallel()

	var payload models.SvExclusionsRespV1
	err := exclusionsGroupsConsumer{inner: runtime.JSONConsumer()}.Consume(
		strings.NewReader(`{"resources":[{"id":"exclusion-1","groups":[{"id":"group-1"}]}]}`),
		&payload,
	)
	require.NoError(t, err)

	require.Len(t, payload.Resources, 1)
	require.Len(t, payload.Resources[0].Groups, 1)
	assert.Equal(t, "group-1", *payload.Resources[0].Groups[0].ID)
}

// TestExclusionsGroupsConsumerEmptyBody documents that an empty body yields io.EOF,
// which the generated readers tolerate.
func TestExclusionsGroupsConsumerEmptyBody(t *testing.T) {
	t.Parallel()

	var payload models.ExclusionsRespV1
	err := exclusionsGroupsConsumer{inner: runtime.JSONConsumer()}.
		Consume(strings.NewReader(""), &payload)
	assert.ErrorIs(t, err, io.EOF)
}

// TestExclusionsGroupsConsumerRejectsUnknownGroupShape checks the error path, so a
// future third shape surfaces as a diagnostic instead of silently empty groups.
func TestExclusionsGroupsConsumerRejectsUnknownGroupShape(t *testing.T) {
	t.Parallel()

	var payload models.ExclusionsRespV1
	err := exclusionsGroupsConsumer{inner: runtime.JSONConsumer()}.Consume(
		strings.NewReader(`{"resources":[{"id":"exclusion-1","groups":[42]}]}`),
		&payload,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected host group objects or IDs")
}

// TestDecodeExclusionsGroupsWrapsReader checks the ClientOption swaps the reader in
// place rather than replacing the generated one.
func TestDecodeExclusionsGroupsWrapsReader(t *testing.T) {
	t.Parallel()

	original := runtime.ClientResponseReaderFunc(
		func(runtime.ClientResponse, runtime.Consumer) (any, error) { return nil, nil },
	)
	op := &runtime.ClientOperation{Reader: original}

	DecodeExclusionsGroups(op)

	wrapped, ok := op.Reader.(exclusionsGroupsReader)
	require.True(t, ok, "expected the reader to be wrapped, got %T", op.Reader)
	assert.NotNil(t, wrapped.inner)
}
