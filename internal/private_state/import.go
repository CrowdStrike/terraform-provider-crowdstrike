package privatestate

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ImportKey key used in private state
const importKey = "import"

type importPrivateState struct {
	IsImport bool `json:"isImport"`
}

func MarkPrivateStateForImport(
	ctx context.Context,
	resp *resource.ImportStateResponse,
) diag.Diagnostics {
	value := []byte(`{"isImport": true}`)
	return resp.Private.SetKey(ctx, importKey, value)
}

// IsImportRead checks if read is part of an import
func IsImportRead(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) (bool, diag.Diagnostics) {
	var respDiags diag.Diagnostics
	importRead, diags := req.Private.GetKey(ctx, importKey)
	respDiags.Append(diags...)

	resp.Private.SetKey(ctx, importKey, nil)

	isImport := false
	if importRead != nil {
		var i importPrivateState
		err := json.Unmarshal(importRead, &i)

		if err != nil {
			respDiags.AddError(
				"Internal provider error",
				"Failed to unmarshal private import state: "+err.Error(),
			)
		} else {
			isImport = i.IsImport
		}
	}

	return isImport, respDiags
}
