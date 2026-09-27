//go:build testgen

package dataprotection

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/testgen"

const (
	transparentLogo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgAAIAAAUAAXpeqz8AAAAASUVORK5CYII="
	redLogo         = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DQAAAEgQGALFXOsAAAAABJRU5ErkJggg=="
)

func init() {
	testgen.Register("crowdstrike_data_protection_content_pattern", testgen.Resource{
		ImportIgnore: []string{"last_updated"},
	})

	testgen.Register("crowdstrike_data_protection_policy", testgen.Resource{
		Attributes: map[string]testgen.Attribute{
			"be_exclude_domains":                      {Values: []any{"*://*.alpha.example/*", "*://*.bravo.example/*", "*://*.charlie.example/*"}},
			"block_all_data_access":                   {Set: map[string]any{"browsers_without_active_extension": "block_policy"}},
			"enable_ocr":                              {Set: map[string]any{"platform_name": "Mac"}},
			"end_user_encryption_activity":            {Set: map[string]any{"evidence_storage": true}},
			"euj_business_purposes_enabled":           {Requires: []string{"euj_custom_dropdown_options"}},
			"euj_company_logo":                        {Values: []any{transparentLogo, redLogo}},
			"euj_personal_use_enabled":                {Requires: []string{"euj_custom_dropdown_options"}},
			"evidence_storage_max_free_space_percent": {Set: map[string]any{"evidence_storage": true}},
			"evidence_storage_max_size_gib":           {Set: map[string]any{"evidence_storage": true}},
			"max_file_size_unit": {
				// MB is left out: max_file_size must be at least 512, and 512 MB
				// is over the 500 MiB inspection cap.
				Values: []any{"Bytes", "KB"},
				Set:    map[string]any{"max_file_size": 512},
			},
			"minimum_similarity_threshold":                  {Set: map[string]any{"similarity_detection": true}},
			"network_inspection_files_exceeding_size_limit": {Set: map[string]any{"network_inspection": true}},
			"screen_capture":                                {Set: map[string]any{"evidence_storage": true}},
			"screen_capture_post_event_seconds":             {Set: map[string]any{"evidence_storage": true, "screen_capture": true}},
			"screen_capture_pre_event_seconds":              {Set: map[string]any{"evidence_storage": true, "screen_capture": true}},
		},
		Skip: map[string]string{
			"classifications": "testgen: references to other resources are not supported yet",
			"hostGroups":      "testgen: references to other resources are not supported yet",
		},
	})
}
