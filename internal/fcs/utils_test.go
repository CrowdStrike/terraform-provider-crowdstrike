package fcs

import (
	"testing"
)

func TestGetRoleNameFromArn(t *testing.T) {
	tests := []struct {
		name   string
		arn    string
		output string
	}{
		{
			name:   "Valid role arn",
			arn:    "arn:aws:iam::123456789012:role/role-name",
			output: "role-name",
		},
		{
			name:   "Invalid role arn",
			arn:    "arn:aws:iam::123456789013",
			output: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRoleNameFromArn(tt.arn); got != tt.output {
				t.Errorf("getRoleNameFromArn() = %v, want %v", got, tt.output)
			}
		})
	}
}
