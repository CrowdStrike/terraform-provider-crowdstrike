package user

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	recordReturnLimit int64 = 500
)

func getUserByUUID(
	ctx context.Context,
	r *client.CrowdStrikeAPISpecification,
	uuid string,
) (userResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	params := &user_management.RetrieveUsersGETV1Params{
		Context: ctx,
		Body: &models.MsaspecIdsRequest{
			Ids: []string{uuid},
		},
	}
	resp, err := r.UserManagement.RetrieveUsersGETV1(params)
	if err != nil {
		diags.AddError(
			"Failed to get existing Crowdstrike user by UUID",
			fmt.Sprintf("Failed to get existing Crowdstrike user by UUID: %s", handleErrors(err, userManagementScopes)),
		)
		return userResourceModel{}, diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to get existing Crowdstrike user by UUID",
			fmt.Sprintf("Failed to get existing Crowdstrike user by UUID: %s", err.Error()),
		)
		return userResourceModel{}, diags
	}

	resource := payload.Resources[0]
	model := userResourceModel{
		UID:       types.StringValue(resource.UID),
		UUID:      types.StringValue(resource.UUID),
		FirstName: types.StringValue(resource.FirstName),
		LastName:  types.StringValue(resource.LastName),
		CID:       types.StringValue(strings.ToUpper(resource.Cid)),
	}

	return model, diags
}

func getUserByUID(
	ctx context.Context,
	r *client.CrowdStrikeAPISpecification,
	uid string,
	cid string,
) (userResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	filter := fmt.Sprintf("uid:'%s'+cid:'%s'", uid, strings.ToLower(cid))
	params := &user_management.QueryUserV1Params{
		Context: ctx,
		Filter:  &filter,
	}

	resp, err := r.UserManagement.QueryUserV1(params)
	if err != nil {
		diags.AddError(
			"Failed to get existing Crowdstrike user by UID and CID",
			fmt.Sprintf("Failed to get existing Crowdstrike user by UID and CID: %s", handleErrors(err, userManagementScopes)),
		)
		return userResourceModel{}, diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to get existing Crowdstrike user by UID and CID",
			fmt.Sprintf("Failed to get existing Crowdstrike user by UID and CID: %s", err.Error()),
		)
		return userResourceModel{}, diags
	}

	resources := payload.Resources
	if len(resources) == 0 {
		diags.AddError(
			"User Not Found",
			"No user found for the UID and CID combination.\nIf you believe there is a bug in the provider or need help please let us know by opening a github issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
		)
		return userResourceModel{}, diags
	}

	return getUserByUUID(ctx, r, resources[0])
}

func validateCIDFormat(cid string) bool {
	if len(cid) != 32 {
		return false
	}
	for _, char := range cid {
		if !((char >= '0' && char <= '9') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	return true

}

func validateEmailFormat(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func getCIDFromCredentials(
	ctx context.Context,
	r *client.CrowdStrikeAPISpecification,
) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var cid string

	params := &sensor_download.GetSensorInstallersCCIDByQueryParams{
		Context: ctx,
	}

	resp, err := r.SensorDownload.GetSensorInstallersCCIDByQuery(params)

	if err != nil {
		if _, ok := err.(*sensor_download.GetSensorInstallersCCIDByQueryForbidden); ok {
			diags.AddError(
				"Failed to get CID from API credentials",
				fmt.Sprintf("Failed to get CID from API credentials: %s", handleErrors(err, getCidScopes)),
			)
			return "", diags
		}

		return "", diags
	}
	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to get CID from API credentials",
			fmt.Sprintf("Error reported when getting CCID from CrowdStrike Falcon API: %s", err.Error()),
		)
		return "", diags
	}
	if len(payload.Resources) != 1 {
		diags.AddError(
			"Failed to get CID from API credentials",
			fmt.Sprintf("Failed to get CCID: Unexpected API response %s", payload.Resources),
		)
		return "", diags
	}

	cid = strings.Split(payload.Resources[0], "-")[0]

	return cid, diags
}

func getUserRoles(
	ctx context.Context,
	r *client.CrowdStrikeAPISpecification,
	uuid string,
	cid string,
) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var grants []string

	params := user_management.CombinedUserRolesV2Params{
		Context:  ctx,
		UserUUID: strings.Trim(uuid, "\""),
		Limit:    &recordReturnLimit,
		Cid:      &cid,
	}

	resp, err := r.UserManagement.CombinedUserRolesV2(&params)
	if err != nil {
		if _, ok := err.(*user_management.CombinedUserRolesV2Forbidden); ok {
			diags.AddError(
				"Failed to read assigned role grants for individual user",
				fmt.Sprintf("Failed to read assigned role grants for individual user: %s", handleErrors(err, userManagementScopes)),
			)
			return nil, diags
		}
		diags.AddError(
			"Failed to read assigned role grants for user",
			fmt.Sprintf("Failed to read assigned role grants for user: %s", err.Error()),
		)
		return nil, diags
	}

	for _, resource := range resp.Payload.Resources {
		grants = append(grants, *resource.RoleID)
	}

	return grants, diags
}

func handleErrors(err error, apiScopes []scopes.Scope) (errorString string) {
	var code int
	parts := strings.Split(err.Error(), "Code:")
	if len(parts) > 1 {
		codePart := strings.Split(parts[1], " ")[0]
		if num, parseErr := strconv.Atoi(codePart); parseErr == nil {
			code = num
		} else {
			return err.Error()
		}
	}

	switch code {
	case 403:
		return fmt.Sprintf("403 Forbidden\n\n%s", scopes.GenerateScopeDescription(apiScopes))
	case 400:
		return "400 Bad Request"
	case 429:
		return "429 Too Many Requests"
	case 500:
		return "500 Internal Server Error"
	}
	return errorString
}

func convertStringSliceToTypesList(slice []string) types.List {
	elements := make([]attr.Value, len(slice))
	for i, s := range slice {
		elements[i] = types.StringValue(s)
	}
	return types.ListValueMust(types.StringType, elements)
}

func getUser(ctx context.Context,
	r *client.CrowdStrikeAPISpecification,
	uuid string,
	uid string,
	cid string,
) (userResourceModel, diag.Diagnostics) {
	var userResourceModel userResourceModel
	var diags diag.Diagnostics

	if uuid != "" {
		userResourceModel, diags = getUserByUUID(ctx, r, uuid)
	} else {
		userResourceModel, diags = getUserByUID(ctx, r, uid, cid)
	}

	return userResourceModel, diags
}
