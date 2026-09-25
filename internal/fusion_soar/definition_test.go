package fusionsoar_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	fusionsoar "github.com/crowdstrike/terraform-provider-crowdstrike/internal/fusion_soar"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"gopkg.in/yaml.v3"
)

const configuredDefinition = `
name: example
description: example workflow
trigger:
  next:
    - Sleep
  name: On demand
  type: On demand
actions:
  Sleep:
    id: 4f1af1ae4c13dc1e3bcd725f8dc0f63b
    properties:
      sleep_time: 1m
    version_constraint: ~1
`

// exportedDefinition is configuredDefinition as the export endpoint returns it:
// a comment header, 4-space indentation, and default_name/name added to the action.
const exportedDefinition = `# This is an exported workflow. Editing this file is not recommended.

name: example
description: example workflow
trigger:
    next:
        - Sleep
    name: On demand
    type: On demand
actions:
    Sleep:
        id: 4f1af1ae4c13dc1e3bcd725f8dc0f63b
        default_name: Sleep
        name: Sleep
        properties:
            sleep_time: 1m
        version_constraint: ~1
`

func TestDefinitionDiff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
		got  string
		path string
	}{
		{
			name: "export with server-added keys matches",
			want: configuredDefinition,
			got:  exportedDefinition,
		},
		{
			name: "key order and formatting are ignored",
			want: "name: a\ntrigger: {type: On demand, name: On demand}\n",
			got:  "trigger:\n  name: On demand\n  type: On demand\nname: a\n",
		},
		{
			name: "changed scalar reports its path",
			want: configuredDefinition,
			got:  strings.Replace(exportedDefinition, "sleep_time: 1m", "sleep_time: 2m", 1),
			path: "actions.Sleep.properties.sleep_time",
		},
		{
			name: "key dropped by the API reports its path",
			want: "name: a\nbogus: value\n",
			got:  "name: a\n",
			path: "bogus",
		},
		{
			name: "list element change reports its index",
			want: "name: a\nlabels: [x, y]\n",
			got:  "name: a\nlabels: [x, z]\n",
			path: "labels[1]",
		},
		{
			name: "list length change reports the list",
			want: "name: a\nlabels: [x]\n",
			got:  "name: a\nlabels: [x, y]\n",
			path: "labels",
		},
		{
			name: "type change reports the path",
			want: "name: a\ntrigger: {type: On demand}\n",
			got:  "name: a\ntrigger: On demand\n",
			path: "trigger",
		},
		{
			name: "null configured value matches an omitted key",
			want: "name: a\ndescription:\n",
			got:  "name: a\n",
		},
		{
			name: "empty configured collections match an omitted key",
			want: "name: a\nlabels: []\nparameters: {}\n",
			got:  "name: a\n",
		},
		{
			name: "integer and float forms of a number match",
			want: "name: a\nlimit: 60\n",
			got:  "name: a\nlimit: 60.0\n",
		},
		{
			name: "integer beyond int64 matches its float form",
			want: "name: a\nlimit: 18446744073709551615\n",
			got:  "name: a\nlimit: 1.8446744073709551615e19\n",
		},
		{
			name: "number does not match its string form",
			want: "name: a\nlimit: 60\n",
			got:  "name: a\nlimit: \"60\"\n",
			path: "limit",
		},
		{
			name: "non-string keys are compared as strings",
			want: "name: a\nactions:\n  1: {id: x}\n",
			got:  "name: a\nactions:\n  \"1\": {id: x, default_name: X}\n",
		},
		{
			name: "trigger name is set by the API",
			want: "name: a\ntrigger: {name: Scheduled workflow, type: Scheduled}\n",
			got:  "name: a\ntrigger: {name: Scheduled, type: Scheduled}\n",
		},
		{
			name: "action default_name is set by the API",
			want: "name: a\nactions:\n  Sleep: {id: x, default_name: Old name}\n",
			got:  "name: a\nactions:\n  Sleep: {id: x, default_name: '[Missing Activity]'}\n",
		},
		{
			name: "default_name of an action inside a loop is set by the API",
			want: "name: a\nloops:\n  L:\n    actions:\n      Sleep: {id: x, default_name: Old name}\n",
			got:  "name: a\nloops:\n  L:\n    actions:\n      Sleep: {id: x, default_name: '[Missing Activity]'}\n",
		},
		{
			name: "action name is still compared",
			want: "name: a\nactions:\n  Sleep: {id: x, name: Mine}\n",
			got:  "name: a\nactions:\n  Sleep: {id: x, name: Sleep}\n",
			path: "actions.Sleep.name",
		},
		{
			name: "default_name outside an action is still compared",
			want: "name: a\ntrigger: {default_name: Mine}\n",
			got:  "name: a\ntrigger: {default_name: Other}\n",
			path: "trigger.default_name",
		},
		{
			name: "top-level name is still compared",
			want: "name: a\n",
			got:  "name: b\n",
			path: "name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, _, err := fusionsoar.DefinitionDiff(tt.want, tt.got)
			if err != nil {
				t.Fatalf("DefinitionDiff returned error: %s", err)
			}
			if got != tt.path {
				t.Errorf("DefinitionDiff() path = %q, want %q", got, tt.path)
			}
		})
	}
}

func TestDefinitionDiffInvalidYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
		got  string
	}{
		{name: "invalid configured YAML", want: "name: [unclosed", got: configuredDefinition},
		{name: "invalid stored YAML", want: configuredDefinition, got: "name: [unclosed"},
		{name: "configured top level is not a mapping", want: "- a\n", got: configuredDefinition},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := fusionsoar.DefinitionDiff(tt.want, tt.got); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestDefinitionDiffDetail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
		got  string
		// contains lists substrings the detail must include.
		contains []string
	}{
		{
			name:     "dropped key",
			want:     "name: a\nbogus: value\n",
			got:      "name: a\n",
			contains: []string{"did not store `bogus`", "spelled correctly"},
		},
		{
			name: "changed value shows both values",
			want: "name: a\nloops:\n  L: {display: a > b}\n",
			got:  "name: a\nloops:\n  L: {display: a &gt; b}\n",
			contains: []string{
				"different value at `loops.L.display`",
				"Configured:\na > b",
				"Stored:\na &gt; b",
			},
		},
		{
			name:     "value type change is visible",
			want:     "name: a\nlimit: 60\n",
			got:      "name: a\nlimit: \"60\"\n",
			contains: []string{"Configured:\n60", "Stored:\n\"60\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, detail, err := fusionsoar.DefinitionDiff(tt.want, tt.got)
			if err != nil {
				t.Fatalf("DefinitionDiff returned error: %s", err)
			}
			for _, s := range tt.contains {
				if !strings.Contains(detail, s) {
					t.Errorf("detail does not contain %q:\n%s", s, detail)
				}
			}
		})
	}
}

func TestDefinitionValueSemanticEquals(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// The framework calls StringSemanticEquals on the API's value with the
	// prior (configured) value as the argument.
	equal, diags := fusionsoar.NewDefinitionValue(exportedDefinition).StringSemanticEquals(ctx, fusionsoar.NewDefinitionValue(configuredDefinition))
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !equal {
		t.Error("expected the export to be semantically equal to the configured definition")
	}

	// The comparison is directional: the prior value must be contained in the new one.
	equal, diags = fusionsoar.NewDefinitionValue(configuredDefinition).StringSemanticEquals(ctx, fusionsoar.NewDefinitionValue(exportedDefinition))
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if equal {
		t.Error("expected a value missing default_name not to contain the export")
	}

	// A prior value that is not valid YAML is never equal.
	equal, diags = fusionsoar.NewDefinitionValue(exportedDefinition).StringSemanticEquals(ctx, fusionsoar.NewDefinitionValue("name: [unclosed"))
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if equal {
		t.Error("expected invalid YAML not to be semantically equal")
	}

	// A prior value of another type is reported as an error.
	_, diags = fusionsoar.NewDefinitionValue(exportedDefinition).StringSemanticEquals(ctx, basetypes.NewStringValue(configuredDefinition))
	if !diags.HasError() {
		t.Error("expected an error for a prior value of another type")
	}
}

func TestDefinitionWithID(t *testing.T) {
	t.Parallel()

	const id = "7fb858a949034a0cbca175f660f1e769"

	tests := []struct {
		name       string
		definition string
		// content is the definition without any top-level id.
		content string
		wantErr string
	}{
		{
			name:       "id is added",
			definition: configuredDefinition,
			content:    configuredDefinition,
		},
		{
			name:       "exported definition keeps its content",
			definition: exportedDefinition,
			content:    exportedDefinition,
		},
		{
			name:       "existing id is replaced",
			definition: "name: a\nid: other\n",
			content:    "name: a\n",
		},
		{
			name:       "invalid YAML",
			definition: "name: [unclosed",
			wantErr:    "not valid YAML",
		},
		{
			name:       "top level is a list",
			definition: "- name: a\n",
			wantErr:    "must be a YAML mapping",
		},
		{
			name:       "empty document",
			definition: "",
			wantErr:    "must be a YAML mapping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := fusionsoar.DefinitionWithID(tt.definition, id)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			var doc, want map[string]any
			if err := yaml.Unmarshal([]byte(got), &doc); err != nil {
				t.Fatalf("result is not valid YAML: %s\n%s", err, got)
			}
			if doc["id"] != id {
				t.Errorf("id = %v, want %s", doc["id"], id)
			}

			delete(doc, "id")
			if err := yaml.Unmarshal([]byte(tt.content), &want); err != nil {
				t.Fatalf("content is not valid YAML: %s", err)
			}
			if !reflect.DeepEqual(doc, want) {
				t.Errorf("content changed:\n%s", got)
			}
		})
	}
}
