//go:build testgen

package dataprotection

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"

const (
	transparentLogo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAXpeqz8AAAAASUVORK5CYII="
	redLogo         = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DQAAAEgQGALFXOsAAAAABJRU5ErkJggg=="
)

func init() {
	testgen.Register("crowdstrike_data_protection_content_pattern", testgen.Resource{
		Attributes: map[string]testgen.Attribute{
			"regex": {Values: []any{`\b\d{3}-\d{2}-\d{4}\b`, `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`}},
		},
		ImportIgnore: []string{"last_updated"},
	})

	testgen.Register("crowdstrike_data_protection_policy", testgen.Resource{
		Attributes: map[string]testgen.Attribute{
			"be_custom_splash_message":                {Values: []any{"Checking this file", "Still checking this file"}},
			"be_exclude_domains":                      {Values: []any{"*://*.alpha.example/*", "*://*.bravo.example/*", "*://*.charlie.example/*"}},
			"block_all_data_access":                   {Requires: map[string]any{"browsers_without_active_extension": "block_policy"}},
			"custom_allowed_action_notification":      {Values: []any{"This action was logged", "This action was recorded"}},
			"custom_blocked_action_notification":      {Values: []any{"This action was blocked", "This action was stopped"}},
			"enable_ocr":                              {Requires: map[string]any{"platform_name": "Mac"}},
			"end_user_encryption_activity":            {Requires: map[string]any{"evidence_storage": true}},
			"euj_business_purposes_enabled":           {Requires: map[string]any{"euj_custom_dropdown_options": []any{"Legal review", "Audit"}}},
			"euj_company_logo":                        {Values: []any{transparentLogo, redLogo}},
			"euj_custom_dropdown_options":             {Values: []any{"Legal review", "Customer request", "Audit"}},
			"euj_custom_header_text":                  {Values: []any{"Explain why you need this file.", "Tell us why you need this file."}},
			"euj_personal_use_enabled":                {Requires: map[string]any{"euj_custom_dropdown_options": []any{"Legal review", "Audit"}}},
			"evidence_storage_max_free_space_percent": {Requires: map[string]any{"evidence_storage": true}},
			"evidence_storage_max_size_gib":           {Requires: map[string]any{"evidence_storage": true}},
			"max_file_size_unit": {
				// MB is left out: max_file_size must be at least 512, and 512 MB
				// is over the 500 MiB inspection cap.
				Values:   []any{"Bytes", "KB"},
				Requires: map[string]any{"max_file_size": 512},
			},
			"minimum_similarity_threshold":                  {Requires: map[string]any{"similarity_detection": true}},
			"network_inspection_files_exceeding_size_limit": {Requires: map[string]any{"network_inspection": true}},
			"screen_capture":                                {Requires: map[string]any{"evidence_storage": true}},
			"screen_capture_post_event_seconds":             {Requires: map[string]any{"evidence_storage": true, "screen_capture": true}},
			"screen_capture_pre_event_seconds":              {Requires: map[string]any{"evidence_storage": true, "screen_capture": true}},
		},
		Skip: map[string]string{
			"classifications": "testgen: references to other resources are not supported yet",
			"hostGroups":      "testgen: references to other resources are not supported yet",
		},
	})
}
