package cloudcompliance

import (
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// Error message constants.
const (
	apiOperationCreateFramework = "create_framework"
	apiOperationUpdateFramework = "update_framework"
	apiOperationReadFramework   = "read_framework"
	apiOperationDeleteFramework = "delete_framework"
	apiOperationCreateControl   = "create_control"
	apiOperationReadControls    = "read_controls"

	errorCreatingFramework = "Error Creating Custom Compliance Framework"
	errorUpdatingFramework = "Error Updating Custom Compliance Framework"
	errorReadingFramework  = "Error Reading Custom Compliance Framework"
	errorDeletingFramework = "Error Deleting Custom Compliance Framework"
	errorCreatingControl   = "Error Creating Compliance Control"
	errorUpdatingControl   = "Error Updating Compliance Control"
	errorAssigningRules    = "Error Assigning Compliance Rules"
	errorQueryingControls  = "Error Querying Compliance Controls"
	errorQueryingRules     = "Error Querying Compliance Rules"
	errorGettingControls   = "Error Getting Compliance Controls"

	// API response validation messages.
	emptyAPIResponse      = "The API returned an empty response"
	noResourcesReturned   = "No resources returned from API"
	noFrameworkReturned   = "No framework returned from API"
	noControlReturned     = "No control returned from API"
	noControlIdReturned   = "No control ID returned from API"
	failedToGetControls   = "Failed to get controls for control IDs %s: %s"
	failedToCreateControl = "Failed to create control %s in section %s: %s"
)

// Error handling utility functions.
func handleAPIError(err error, operation, id string) diag.Diagnostics {
	var diags diag.Diagnostics

	switch operation {
	case apiOperationCreateFramework:
		if badRequest, ok := err.(*cloud_policies.CreateComplianceFrameworkBadRequest); ok {
			diags.AddError(errorCreatingFramework,
				fmt.Sprintf("Failed to create custom compliance framework (%+v): %+v",
					*badRequest.Payload.Errors[0].Code,
					*badRequest.Payload.Errors[0].Message,
				))
			return diags
		}
	case apiOperationUpdateFramework:
		if badRequest, ok := err.(*cloud_policies.UpdateComplianceFrameworkBadRequest); ok {
			diags.AddError(errorUpdatingFramework,
				fmt.Sprintf("Failed to update custom compliance framework (%+v): %+v",
					badRequest.Payload.Errors[0].Code,
					*badRequest.Payload.Errors[0].Message,
				))
			return diags
		}
		if notFound, ok := err.(*cloud_policies.UpdateComplianceFrameworkNotFound); ok {
			diags.AddError(errorUpdatingFramework,
				fmt.Sprintf("Custom compliance framework with ID %s was not found (%+v): %+v",
					id,
					notFound.Payload.Errors[0],
					*notFound.Payload.Errors[0].Message,
				))
			return diags
		}
	case apiOperationReadFramework:
		if badRequest, ok := err.(*cloud_policies.GetComplianceFrameworksBadRequest); ok {
			diags.AddError(errorReadingFramework,
				fmt.Sprintf("Failed to read custom compliance framework (400): %+v",
					*badRequest.Payload.Errors[0].Message))
			return diags
		}
		if notFound, ok := err.(*cloud_policies.GetComplianceFrameworksNotFound); ok {
			diags.AddError(errorReadingFramework,
				fmt.Sprintf("Custom compliance framework with ID %s was not found (404): %+v",
					id, *notFound.Payload.Errors[0].Message))
			return diags
		}
		if internalServerError, ok := err.(*cloud_policies.GetComplianceFrameworksInternalServerError); ok {
			diags.AddError(errorReadingFramework,
				fmt.Sprintf("Failed to read custom compliance framework (500): %+v",
					*internalServerError.Payload.Errors[0].Message))
			return diags
		}
	case apiOperationDeleteFramework:
		if badRequest, ok := err.(*cloud_policies.DeleteComplianceFrameworkBadRequest); ok {
			diags.AddError(errorDeletingFramework,
				fmt.Sprintf("Failed to delete custom compliance framework (400): %+v",
					*badRequest.Payload.Errors[0].Message))
			return diags
		}
		if notFound, ok := err.(*cloud_policies.DeleteComplianceFrameworkNotFound); ok {
			diags.AddError(errorDeletingFramework,
				fmt.Sprintf("Custom compliance framework with ID %s was not found (404): %+v",
					id, *notFound.Payload.Errors[0].Message))
			return diags
		}
	case apiOperationCreateControl:
		if badRequest, ok := err.(*cloud_policies.CreateComplianceControlBadRequest); ok {
			diags.AddError(errorCreatingControl,
				fmt.Sprintf("Failed to create custom compliance framework (%+v): %+v",
					*badRequest.Payload.Errors[0].Code,
					*badRequest.Payload.Errors[0].Message,
				))
			return diags
		}
	case apiOperationReadControls:
		if badRequest, ok := err.(*cloud_policies.GetComplianceControlsBadRequest); ok {
			diags.AddError(errorGettingControls,
				fmt.Sprintf("Compliance framework controls with IDs %s were not found (%+v): %+v",
					id,
					*badRequest.Payload.Errors[0].Code,
					*badRequest.Payload.Errors[0].Message,
				))
			return diags
		}
	}

	// Generic error handling
	diags.AddError(operation, fmt.Sprintf("API error: %s", falcon.ErrorExplain(err)))
	return diags
}

func validateAPIResponse(payload interface{}, errSummary string) diag.Diagnostics {
	var diags diag.Diagnostics

	if payload == nil {
		diags.AddError(errSummary, emptyAPIResponse)
		return diags
	}

	// Check for API errors in payload
	switch p := payload.(type) {
	case *models.CommonCreateComplianceFrameworkResponse:
		if err := falcon.AssertNoError(p.Errors); err != nil {
			diags.AddError(errSummary, fmt.Sprintf("API returned error: %s", err.Error()))
		}

		if len(p.Resources) == 0 {
			diags.AddError(errSummary, noFrameworkReturned)
		}
	case *models.CommonGetComplianceFrameworksResponse:
		if err := falcon.AssertNoError(p.Errors); err != nil {
			diags.AddError(errSummary, fmt.Sprintf("API returned error: %s", err.Error()))
		}

		if len(p.Resources) == 0 {
			diags.AddError(errSummary, noFrameworkReturned)
		}
	case *models.CommonCreateComplianceControlResponse:
		if err := falcon.AssertNoError(p.Errors); err != nil {
			diags.AddError(errSummary, fmt.Sprintf("API returned error: %s", err.Error()))
		}

		if len(p.Resources) == 0 {
			diags.AddError(errSummary, noControlReturned)
		}

		if p.Resources[0].UUID == nil || *p.Resources[0].UUID == "" {
			diags.AddError(errSummary, noControlIdReturned)
		}
	case *models.CommonGetComplianceControlsResponse:
		if err := falcon.AssertNoError(p.Errors); err != nil {
			diags.AddError(errSummary, fmt.Sprintf("API returned error: %s", err.Error()))
		}

		if len(p.Resources) == 0 {
			diags.AddError(errSummary, noControlReturned)
		}
	}

	return diags
}
