package usergroup

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/mssp"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/sweep"
)

func RegisterSweepers() {
	sweep.Register("crowdstrike_user_group", sweepUserGroups)
}

func sweepUserGroups(ctx context.Context, client *client.CrowdStrikeAPISpecification) ([]sweep.Sweepable, error) {
	var sweepables []sweep.Sweepable

	queryParams := mssp.NewQueryUserGroupsParams()
	queryParams.WithContext(ctx)

	queryResp, err := client.Mssp.QueryUserGroups(queryParams)
	if sweep.SkipSweepError(err) {
		sweep.Warn("Skipping user group sweep: %s", err)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing user groups: %w", err)
	}

	if queryResp.Payload == nil || queryResp.Payload.Resources == nil {
		return sweepables, nil
	}

	getParams := mssp.NewGetUserGroupsByIDParams()
	getParams.WithContext(ctx)
	getParams.UserGroupIds = queryResp.Payload.Resources

	getResp, _, err := client.Mssp.GetUserGroupsByID(getParams)
	if err != nil {
		if sweep.SkipSweepError(err) {
			sweep.Warn("Skipping user group sweep: %s", err)
			return nil, nil
		}
		return nil, fmt.Errorf("error getting user groups: %w", err)
	}

	if getResp == nil || getResp.Payload == nil || getResp.Payload.Resources == nil {
		return sweepables, nil
	}

	for _, userGroup := range getResp.Payload.Resources {
		if userGroup.Name == nil {
			continue
		}
		name := *userGroup.Name

		if !strings.HasPrefix(name, sweep.ResourcePrefix) {
			sweep.Trace("Skipping user group %s (not a test resource)", name)
			continue
		}

		if userGroup.UserGroupID == "" {
			continue
		}

		sweepables = append(sweepables, sweep.NewSweepResource(
			userGroup.UserGroupID,
			name,
			deleteUserGroup,
		))
	}

	return sweepables, nil
}

func deleteUserGroup(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string) error {
	getMembersParams := mssp.NewGetUserGroupMembersByIDParams()
	getMembersParams.WithContext(ctx)
	getMembersParams.UserGroupIds = []string{id}

	membersResp, _, err := client.Mssp.GetUserGroupMembersByID(getMembersParams)
	if err != nil && !sweep.ShouldIgnoreError(err) {
		return fmt.Errorf("error getting user group members: %w", err)
	}

	if membersResp != nil && membersResp.Payload != nil && len(membersResp.Payload.Resources) > 0 {
		if membersResp.Payload.Resources[0] != nil && len(membersResp.Payload.Resources[0].UserUuids) > 0 {
			if err := deleteUserGroupMembers(ctx, client, id, membersResp.Payload.Resources[0].UserUuids); err != nil {
				return err
			}
		}
	}

	deleteParams := mssp.NewDeleteUserGroupsParams()
	deleteParams.WithContext(ctx)
	deleteParams.UserGroupIds = []string{id}

	_, _, err = client.Mssp.DeleteUserGroups(deleteParams)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error for user group %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}

func deleteUserGroupMembers(ctx context.Context, client *client.CrowdStrikeAPISpecification, id string, userUuids []string) error {
	deleteParams := mssp.NewDeleteUserGroupMembersParams()
	deleteParams.WithContext(ctx)
	deleteParams.Body = &models.DomainUserGroupMembersRequestV1{
		Resources: []*models.DomainUserGroupMembers{
			{
				UserGroupID: &id,
				UserUuids:   userUuids,
			},
		},
	}

	_, _, err := client.Mssp.DeleteUserGroupMembers(deleteParams)
	if err != nil {
		if sweep.ShouldIgnoreError(err) {
			sweep.Debug("Ignoring error deleting members for user group %s: %s", id, err)
			return nil
		}
		return err
	}

	return nil
}
