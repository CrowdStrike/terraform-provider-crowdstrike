package cloudsecurity

import (
	"context"
	"errors"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/admission_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/config"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/tferrors"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &cloudSecurityKacPolicyPrecedenceResource{}
	_ resource.ResourceWithConfigure      = &cloudSecurityKacPolicyPrecedenceResource{}
	_ resource.ResourceWithValidateConfig = &cloudSecurityKacPolicyPrecedenceResource{}
)

var (
	kacPolicyPrecedenceDocumentationSection        string         = "Cloud Security"
	kacPolicyPrecedenceResourceMarkdownDescription string         = "This resource manages the precedence for Admission Control policies."
	kacPolicyPrecedenceRequiredScopes              []scopes.Scope = cloudSecurityKacPolicyScopes
)

func NewCloudSecurityKacPolicyPrecedenceResource() resource.Resource {
	return &cloudSecurityKacPolicyPrecedenceResource{}
}

type cloudSecurityKacPolicyPrecedenceResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudSecurityKacPolicyPrecedenceResourceModel struct {
	PolicyIds   types.List   `tfsdk:"ids"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

func (m *cloudSecurityKacPolicyPrecedenceResourceModel) wrap(
	ctx context.Context,
	policyIds []string,
) diag.Diagnostics {
	policyList, diags := types.ListValueFrom(ctx, types.StringType, policyIds)
	diags.Append(diags...)
	if diags.HasError() {
		return diags
	}

	m.PolicyIds = policyList

	return diags
}

func (r *cloudSecurityKacPolicyPrecedenceResource) Configure(
	_ context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	config, ok := req.ProviderData.(config.ProviderConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected config.ProviderConfig, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = config.Client
}

func (r *cloudSecurityKacPolicyPrecedenceResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_kac_policy_precedence"
}

func (r *cloudSecurityKacPolicyPrecedenceResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			kacPolicyPrecedenceDocumentationSection,
			kacPolicyPrecedenceResourceMarkdownDescription,
			kacPolicyPrecedenceRequiredScopes,
		),
		Attributes: map[string]schema.Attribute{
			"ids": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "The policy ids in order. The first ID specified will have the highest precedence and the last ID specified will have the lowest.",
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.UniqueValues(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
		},
	}
}

func (r *cloudSecurityKacPolicyPrecedenceResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecurityKacPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planPolicyIds := flex.ExpandListAs[string](ctx, plan.PolicyIds, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	updatedKacPolicyIdsOrderedByPrecedence, diags := r.setKACPolicyPrecedence(ctx, planPolicyIds)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updatedPolicyIds := updatedKacPolicyIdsOrderedByPrecedence[:len(plan.PolicyIds.Elements())]

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, updatedPolicyIds)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudSecurityKacPolicyPrecedenceResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecurityKacPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyIds, diags := r.getKACPoliciesByPrecedence(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyIds = policyIds[:len(state.PolicyIds.Elements())]

	resp.Diagnostics.Append(state.wrap(ctx, policyIds)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudSecurityKacPolicyPrecedenceResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecurityKacPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planPolicyIds := flex.ExpandListAs[string](ctx, plan.PolicyIds, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	updatedKacPolicyIdsOrderedByPrecedence, diags := r.setKACPolicyPrecedence(ctx, planPolicyIds)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updatedPolicyIds := updatedKacPolicyIdsOrderedByPrecedence[:len(plan.PolicyIds.Elements())]

	plan.LastUpdated = utils.GenerateUpdateTimestamp()
	resp.Diagnostics.Append(plan.wrap(ctx, updatedPolicyIds)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cloudSecurityKacPolicyPrecedenceResource) Delete(
	_ context.Context,
	_ resource.DeleteRequest,
	_ *resource.DeleteResponse,
) {
	// This is a no-op since this resource only updates precedence and does not actual create or delete resources.
}

func (r *cloudSecurityKacPolicyPrecedenceResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudSecurityKacPolicyPrecedenceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
}

func (r *cloudSecurityKacPolicyPrecedenceResource) getKACPoliciesByPrecedence(
	ctx context.Context,
) (policyIds []string, diags diag.Diagnostics) {
	limit := int64(500)
	sort := "precedence.asc"
	res, err := r.client.AdmissionControlPolicies.AdmissionControlQueryPolicies(
		&admission_control_policies.AdmissionControlQueryPoliciesParams{
			Context: ctx,
			Limit:   &limit,
			Sort:    &sort,
		},
	)
	if err != nil {
		var admissionControlQueryPoliciesForbidden *admission_control_policies.AdmissionControlQueryPoliciesForbidden
		if errors.As(err, &admissionControlQueryPoliciesForbidden) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Read, cloudSecurityKacPolicyScopes))
			return policyIds, diags
		}

		diags.Append(tferrors.NewOperationError(tferrors.Read, err))
		return policyIds, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.Append(tferrors.NewEmptyResponseError(tferrors.Read))
		return policyIds, diags
	}

	policyIds = res.Payload.Resources
	return policyIds, diags
}

func (r *cloudSecurityKacPolicyPrecedenceResource) setKACPolicyPrecedence(
	ctx context.Context,
	planPolicyIDs []string,
) (updatedPrecedence []string, diags diag.Diagnostics) {
	currentPolicyIDs, getDiags := r.getKACPoliciesByPrecedence(ctx)
	if getDiags.HasError() {
		diags.Append(getDiags...)
		return updatedPrecedence, diags
	}

	// Verify all plan IDs exist in current list (error if not found)
	currentSet := make(map[string]bool)
	for _, val := range currentPolicyIDs {
		currentSet[val] = true
	}

	// Build the desired final order: plan policies first, then remaining policies
	desiredOrder := make([]string, len(currentPolicyIDs))
	copy(desiredOrder, planPolicyIDs)

	planSet := make(map[string]bool)
	for _, planID := range planPolicyIDs {
		if !currentSet[planID] {
			diags.Append(
				tferrors.NewNotFoundError(fmt.Sprintf("Policy ID %s not found in existing policy IDs", planID)),
			)
		}

		planSet[planID] = true
	}

	if diags.HasError() {
		return nil, diags
	}

	idx := len(planPolicyIDs)
	for _, policyID := range currentPolicyIDs {
		if !planSet[policyID] {
			desiredOrder[idx] = policyID
			idx++
		}
	}

	planPrecedenceByPolicyId := make(map[string]int)
	for i, planID := range desiredOrder {
		planPrecedenceByPolicyId[planID] = i
	}

	// Use Longest Increasing Subsequence algorithm to minimize moves
	var policiesToMove []string
	if len(planPolicyIDs) == 1 && currentPolicyIDs[0] != planPolicyIDs[0] {
		policiesToMove = planPolicyIDs
	} else {
		policiesToMove = r.calculateMinimalMoves(currentPolicyIDs, desiredOrder)
		if diags.HasError() {
			return updatedPrecedence, diags
		}
	}

	// If no moves are needed, return the plan as-is
	if len(policiesToMove) == 0 {
		return currentPolicyIDs, diags
	}

	for _, policyToMove := range policiesToMove {
		// Calculate where this policy should be positioned relative to current state
		targetPosition := r.calculateRelativePrecedence(policyToMove, desiredOrder, currentPolicyIDs)

		// Move this policy to its calculated relative position (already 1-based)
		diags.Append(r.updateSinglePolicyPrecedence(ctx, policyToMove, targetPosition)...)
		if diags.HasError() {
			return updatedPrecedence, diags
		}

		// Get current state before next move to calculate relative position
		currentPolicyIDs, getDiags = r.getKACPoliciesByPrecedence(ctx)
		if getDiags.HasError() {
			diags.Append(getDiags...)
			return updatedPrecedence, diags
		}
	}

	return currentPolicyIDs, diags
}

// calculateMinimalMoves uses the Longest Increasing Subsequence algorithm
// to determine the minimum number of elements that need to be moved.
func (r *cloudSecurityKacPolicyPrecedenceResource) calculateMinimalMoves(
	currentOrder, targetOrder []string,
) (policyIdsToMove []string) {
	// Create a map of plan positions (desired final positions)
	planPos := make(map[string]int)
	for i, val := range targetOrder {
		planPos[val] = i
	}

	// Build the sequence that represents the desired positions of the policies
	// in the order they currently appear in the API
	var planIndices []int
	var currentPoliciesInPlan []string
	for _, policyID := range currentOrder {
		if targetPos, exists := planPos[policyID]; exists {
			planIndices = append(planIndices, targetPos)
			currentPoliciesInPlan = append(currentPoliciesInPlan, policyID)
		}
	}

	// Find which indices are in the LIS (already in correct relative order)
	lisIndices := r.findLISIndices(planIndices)
	lisSet := make(map[int]bool)
	for _, idx := range lisIndices {
		lisSet[idx] = true
	}

	// Collect elements not in LIS (these need to be moved)
	policiesToMoveSet := make(map[string]bool)
	for i, policyID := range currentPoliciesInPlan {
		if !lisSet[i] {
			policiesToMoveSet[policyID] = true
		}
	}

	// Return policies to move in plan order (not current order)
	for _, policyID := range targetOrder {
		if policiesToMoveSet[policyID] {
			policyIdsToMove = append(policyIdsToMove, policyID)
		}
	}

	return policyIdsToMove
}

// findLISIndices returns the indices of elements in the Longest Increasing Subsequence (LIS).
func (r *cloudSecurityKacPolicyPrecedenceResource) findLISIndices(targetIndices []int) []int {
	n := len(targetIndices)
	if n == 0 {
		return []int{}
	}

	lisLength := make([]int, n)
	parent := make([]int, n)

	// calculate the increasing subsequence for each index in the target
	// keep track of parent indices for reconstructing LIS
	for i := 0; i < n; i++ {
		lisLength[i] = 1
		parent[i] = -1
		for j := 0; j < i; j++ {
			if targetIndices[i] > targetIndices[j] && lisLength[j]+1 > lisLength[i] {
				lisLength[i] = lisLength[j] + 1
				parent[i] = j
			}
		}
	}

	// find the tail for the LIS
	maxIdx := 0
	for i := 1; i < n; i++ {
		if lisLength[i] > lisLength[maxIdx] {
			maxIdx = i
		}
	}

	// reconstruct LIS from tail to head
	var result []int
	for idx := maxIdx; idx != -1; idx = parent[idx] {
		result = append([]int{idx}, result...)
	}

	return result
}

// calculateRelativePosition determines where a policy should be inserted in the current precedence
// based on its relative position to other policies in the plan.
func (r *cloudSecurityKacPolicyPrecedenceResource) calculateRelativePrecedence(
	policyToMove string,
	targetOrder, currentOrder []string,
) (targetPrecedence int) {
	// Find the position of policyToMove in the plan
	var predecessorPlanIdx int
	for i, policyID := range targetOrder {
		if policyID == policyToMove {
			predecessorPlanIdx = i - 1
			break
		}
	}

	if predecessorPlanIdx == -1 {
		return 1
	}

	currentPrecedence := 0
	predecessorPolicyId := targetOrder[predecessorPlanIdx]
	for i, policyID := range currentOrder {
		if currentPrecedence == 0 && policyID == policyToMove {
			currentPrecedence = i + 1
		}
		if policyID == predecessorPolicyId {
			targetPrecedence = i + 1
			break
		}
	}

	// currentPrecedence 0 means the policy precedence is currently greater (lower priority) than the predecessor.
	// The target precedence in this case should be 1 lower than the target.
	// Otherwise, the currentPrecedence was found and is currently higher than the target,
	// which means the predecessor shifts up one and the new target is correct.
	if currentPrecedence == 0 {
		targetPrecedence++ // precedence is in ascending order, so lower precedence has a higher number
	}

	return targetPrecedence
}

func (r *cloudSecurityKacPolicyPrecedenceResource) updateSinglePolicyPrecedence(
	ctx context.Context,
	policyId string,
	precedence int,
) (diags diag.Diagnostics) {
	precedenceRequest := &models.ModelsUpdatePolicyPrecedenceRequest{
		ID:         &policyId,
		Precedence: int32(precedence),
	}

	precedenceParams := admission_control_policies.NewAdmissionControlUpdatePolicyPrecedenceParamsWithContext(ctx).
		WithBody(precedenceRequest)

	_, err := r.client.AdmissionControlPolicies.AdmissionControlUpdatePolicyPrecedence(precedenceParams)
	if err != nil {
		var admissionControlQueryPoliciesForbidden *admission_control_policies.AdmissionControlQueryPoliciesForbidden
		if errors.As(err, &admissionControlQueryPoliciesForbidden) {
			diags.Append(tferrors.NewForbiddenError(tferrors.Update, cloudSecurityKacPolicyScopes))
			return diags
		}

		diags.Append(tferrors.NewOperationError(tferrors.Update, err))
		return diags
	}

	return diags
}
