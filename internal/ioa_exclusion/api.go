package ioaexclusion

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ioa_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func getIOAExclusion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	id string,
) (*models.DomainSsIoaExclusionsV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := ioa_exclusions.NewSsIoaExclusionsGetV2ParamsWithContext(ctx)
	params.SetIds([]string{id})

	resp, err := client.IoaExclusions.SsIoaExclusionsGetV2(params)
	if err != nil {
		diags.Append(tferrors.NewDiagnosticFromAPIError(tferrors.Read, err, ioaExclusionRequiredScopes))
		return nil, diags
	}
	if resp == nil {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return nil, diags
	}

	exclusion, payloadDiags := extractIOAExclusionFromPayload(tferrors.Read, resp.GetPayload(), id)
	diags.Append(payloadDiags...)
	if diags.HasError() {
		return nil, diags
	}

	return exclusion, diags
}

func extractIOAExclusionFromPayload(
	operation tferrors.Operation,
	payload *models.DomainSsIoaExclusionsRespV2,
	id string,
) (*models.DomainSsIoaExclusionsV2, diag.Diagnostics) {
	var diags diag.Diagnostics

	if payload == nil {
		diags.Append(tferrors.NewEmptyResponseError(operation))
		return nil, diags
	}

	if diagErr := diagnosticFromIOAPayload(operation, payload.Errors); diagErr != nil {
		diags.Append(diagErr)
		return nil, diags
	}

	resource := findIOAExclusion(payload.Resources, id)
	if resource != nil {
		return resource, diags
	}

	if id != "" {
		diags.Append(tferrors.NewNotFoundError(fmt.Sprintf("IOA exclusion %q was not found", id)))
		return nil, diags
	}

	diags.Append(tferrors.NewEmptyResponseError(operation))
	return nil, diags
}

func findIOAExclusion(
	resources []*models.DomainSsIoaExclusionsV2,
	id string,
) *models.DomainSsIoaExclusionsV2 {
	for _, resource := range resources {
		if resource == nil || resource.ID == nil {
			continue
		}

		if id == "" || *resource.ID == id {
			return resource
		}
	}

	return nil
}

func diagnosticFromIOAPayload(
	operation tferrors.Operation,
	payloadErrors []*models.MsaAPIError,
) diag.Diagnostic {
	if len(payloadErrors) == 0 {
		return nil
	}

	if detail := notFoundDetail(payloadErrors); detail != "" {
		return tferrors.NewNotFoundError(detail)
	}

	return tferrors.NewDiagnosticFromPayloadErrors(operation, payloadErrors)
}

func diagnosticFromQueryPayload(
	operation tferrors.Operation,
	payload *models.MsaspecQueryResponse,
) diag.Diagnostic {
	if payload == nil {
		return tferrors.NewEmptyResponseError(operation)
	}

	if len(payload.Errors) == 0 {
		return nil
	}

	if detail := notFoundDetail(payload.Errors); detail != "" {
		return tferrors.NewNotFoundError(detail)
	}

	return tferrors.NewDiagnosticFromPayloadErrors(operation, payload.Errors)
}

func notFoundDetail(payloadErrors []*models.MsaAPIError) string {
	for _, apiErr := range payloadErrors {
		if apiErr == nil || apiErr.Code == nil || *apiErr.Code != 404 {
			continue
		}

		if apiErr.Message != nil && *apiErr.Message != "" {
			return *apiErr.Message
		}

		return "resource was not found"
	}

	return ""
}
