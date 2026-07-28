package user_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/testconfig"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/user"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	roleAssignmentResourceName = "crowdstrike_user_role_assignment.test"
	cidDataSourceName          = "data.crowdstrike_cid.current"
)

// Standard Falcon platform roles, used to build the role sets under test.
const (
	roleEventViewer    = "event_viewer"
	roleHostReadOnly   = "falconhost_read_only"
	roleHelpDesk       = "help_desk"
	roleDashboardAdmin = "dashboard_admin"
)

func TestAccUserRoleAssignmentResource_basic(t *testing.T) {
	email := testUserEmail()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				// Required attributes only: role_ids is omitted.
				Config:            testAccUserRoleAssignmentConfig(email, nil),
				ConfigStateChecks: roleAssignmentStateChecks(),
			},
			testAccUserRoleAssignmentImportStep(),
		},
	})
}

func TestAccUserRoleAssignmentResource_update(t *testing.T) {
	email := testUserEmail()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccUserRoleAssignmentConfig(email, []string{roleEventViewer, roleHostReadOnly}),
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer, roleHostReadOnly),
			},
			testAccUserRoleAssignmentImportStep(),
			{
				// Add a role: existing two must be retained (additive).
				Config:            testAccUserRoleAssignmentConfig(email, []string{roleEventViewer, roleHostReadOnly, roleHelpDesk}),
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer, roleHostReadOnly, roleHelpDesk),
			},
			testAccUserRoleAssignmentImportStep(),
			{
				// Remove a role: the removed role must be gone.
				Config:            testAccUserRoleAssignmentConfig(email, []string{roleEventViewer, roleHostReadOnly}),
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer, roleHostReadOnly),
			},
			testAccUserRoleAssignmentImportStep(),
			{
				// Swap roles in a single apply: remove one, add another.
				Config:            testAccUserRoleAssignmentConfig(email, []string{roleEventViewer, roleDashboardAdmin}),
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer, roleDashboardAdmin),
			},
			testAccUserRoleAssignmentImportStep(),
			{
				// Remove every role: role_ids is omitted entirely.
				Config:            testAccUserRoleAssignmentConfig(email, nil),
				ConfigStateChecks: roleAssignmentStateChecks(),
			},
			testAccUserRoleAssignmentImportStep(),
		},
	})
}

// TestAccUserRoleAssignmentResource_userUUIDReplace verifies that pointing the
// resource at a different user replaces it and carries the role set over to the
// new user.
func TestAccUserRoleAssignmentResource_userUUIDReplace(t *testing.T) {
	email := testUserEmail()
	secondEmail := testUserEmail()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccUserRoleAssignmentConfig_twoUsers(
					email,
					secondEmail,
					"crowdstrike_user.test.id",
					[]string{roleEventViewer},
				),
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer),
			},
			{
				Config: testAccUserRoleAssignmentConfig_twoUsers(
					email,
					secondEmail,
					"crowdstrike_user.second.id",
					[]string{roleEventViewer},
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(roleAssignmentResourceName, plancheck.ResourceActionReplace),
					},
				},
				ConfigStateChecks: append(
					roleAssignmentStateChecks(roleEventViewer),
					statecheck.CompareValuePairs(
						roleAssignmentResourceName,
						tfjsonpath.New("user_uuid"),
						"crowdstrike_user.second",
						tfjsonpath.New("id"),
						compare.ValuesSame(),
					),
				),
			},
			testAccUserRoleAssignmentImportStep(),
		},
	})
}

// TestAccUserRoleAssignmentResource_authoritativeOnCreate verifies that creating
// the resource revokes roles the user already holds in the CID that are absent
// from role_ids.
func TestAccUserRoleAssignmentResource_authoritativeOnCreate(t *testing.T) {
	email := testUserEmail()

	var userUUID, cid string

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				// Create the user on its own so a role can be granted outside
				// of Terraform before the assignment resource exists.
				Config: testAccUserRoleAssignmentConfig_user(email),
				ConfigStateChecks: []statecheck.StateCheck{
					captureAttr("crowdstrike_user.test", "id", &userUUID),
					captureAttr(cidDataSourceName, "cid", &cid),
				},
			},
			{
				PreConfig: func() {
					grantRoleOutOfBand(t, userUUID, cid, roleHelpDesk, "")
				},
				Config: testAccUserRoleAssignmentConfig(email, []string{roleEventViewer}),
				// role_ids holding only event_viewer proves help_desk was
				// revoked: the create waits for the API to report exactly the
				// configured set.
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer),
			},
			testAccUserRoleAssignmentImportStep(),
		},
	})
}

// TestAccUserRoleAssignmentResource_drift verifies that a role granted outside
// of Terraform is detected and revoked on the next apply.
func TestAccUserRoleAssignmentResource_drift(t *testing.T) {
	email := testUserEmail()

	var userUUID, cid string

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccUserRoleAssignmentConfig(email, []string{roleEventViewer}),
				ConfigStateChecks: append(
					roleAssignmentStateChecks(roleEventViewer),
					captureAttr(roleAssignmentResourceName, "user_uuid", &userUUID),
					captureAttr(roleAssignmentResourceName, "cid", &cid),
				),
			},
			{
				PreConfig: func() {
					grantRoleOutOfBand(t, userUUID, cid, roleHelpDesk, "")
				},
				// The configuration is unchanged, so an update in the plan is
				// the out-of-band grant being detected, and the state after
				// apply is it being revoked.
				Config: testAccUserRoleAssignmentConfig(email, []string{roleEventViewer}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(roleAssignmentResourceName, plancheck.ResourceActionUpdate),
					},
				},
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer),
			},
			testAccUserRoleAssignmentImportStep(),
		},
	})
}

// TestAccUserRoleAssignmentResource_temporaryRolesIgnored verifies that a role
// granted with an expiration is left out of state and does not produce a diff.
func TestAccUserRoleAssignmentResource_temporaryRolesIgnored(t *testing.T) {
	email := testUserEmail()

	var userUUID, cid string

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccUserRoleAssignmentConfig(email, []string{roleEventViewer}),
				ConfigStateChecks: append(
					roleAssignmentStateChecks(roleEventViewer),
					captureAttr(roleAssignmentResourceName, "user_uuid", &userUUID),
					captureAttr(roleAssignmentResourceName, "cid", &cid),
				),
			},
			{
				PreConfig: func() {
					expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
					grantRoleOutOfBand(t, userUUID, cid, roleHelpDesk, expiresAt)
				},
				// The temporary role is not owned by this resource, so it is
				// left out of state and the plan stays empty.
				Config: testAccUserRoleAssignmentConfig(email, []string{roleEventViewer}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer),
			},
		},
	})
}

// TestAccUserRoleAssignmentResource_import covers the import identifier parsing:
// a malformed identifier is rejected, and an uppercase CID is normalized to the
// lowercase form the schema requires.
func TestAccUserRoleAssignmentResource_import(t *testing.T) {
	email := testUserEmail()

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:            testAccUserRoleAssignmentConfig(email, []string{roleEventViewer}),
				ConfigStateChecks: roleAssignmentStateChecks(roleEventViewer),
			},
			{
				ResourceName:  roleAssignmentResourceName,
				ImportState:   true,
				ImportStateId: "missing-the-cid",
				ExpectError:   regexp.MustCompile("Unexpected Import Identifier"),
			},
			{
				// ImportStateVerify compares against the applied state, which
				// holds the lowercase CID. An import that kept the uppercase
				// CID would not match, and would replace the resource on the
				// next plan.
				ResourceName:                         roleAssignmentResourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    importStateIDByUserUUIDAndCID(roleAssignmentResourceName, strings.ToUpper),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "user_uuid",
			},
		},
	})
}

func TestChunkStrings(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in   []string
		size int
		want [][]string
	}{
		"nil":               {in: nil, size: 2, want: nil},
		"empty":             {in: []string{}, size: 2, want: nil},
		"smaller than size": {in: []string{"a"}, size: 2, want: [][]string{{"a"}}},
		"exact multiple":    {in: []string{"a", "b", "c", "d"}, size: 2, want: [][]string{{"a", "b"}, {"c", "d"}}},
		"with remainder":    {in: []string{"a", "b", "c"}, size: 2, want: [][]string{{"a", "b"}, {"c"}}},
		"size of one":       {in: []string{"a", "b"}, size: 1, want: [][]string{{"a"}, {"b"}}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := user.ChunkStrings(test.in, test.size)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("unexpected chunks (-want +got):\n%s", diff)
			}
		})
	}
}

// TestChunkStringsDoesNotShareBackingArray guards the full slice expression in
// chunkStrings: appending to one chunk must not overwrite the next one.
func TestChunkStringsDoesNotShareBackingArray(t *testing.T) {
	t.Parallel()

	chunks := user.ChunkStrings([]string{"a", "b", "c", "d"}, 2)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}

	chunks[0] = append(chunks[0], "clobber")

	if diff := cmp.Diff([]string{"c", "d"}, chunks[1]); diff != "" {
		t.Errorf("second chunk was modified by appending to the first (-want +got):\n%s", diff)
	}
}

func TestUnmanagedRoleIDs(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		assigned   []string
		configured []string
		want       []string
	}{
		"all configured":      {assigned: []string{"a", "b"}, configured: []string{"a", "b"}, want: nil},
		"none configured":     {assigned: []string{"b", "a"}, configured: nil, want: []string{"a", "b"}},
		"some configured":     {assigned: []string{"c", "a", "b"}, configured: []string{"b"}, want: []string{"a", "c"}},
		"configured not held": {assigned: []string{"a"}, configured: []string{"a", "z"}, want: nil},
		"nothing assigned":    {assigned: nil, configured: []string{"a"}, want: nil},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := user.UnmanagedRoleIDs(test.assigned, test.configured)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("unexpected unmanaged role ids (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRoleSetMismatch(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		actual   []string
		expected []string
		want     string
	}{
		"match":             {actual: []string{"a", "b"}, expected: []string{"b", "a"}, want: ""},
		"both empty":        {actual: nil, expected: nil, want: ""},
		"missing":           {actual: []string{"a"}, expected: []string{"a", "b"}, want: "roles not assigned: b"},
		"unexpected":        {actual: []string{"a", "b"}, expected: []string{"a"}, want: "roles assigned outside of the configuration: b"},
		"missing and extra": {actual: []string{"b"}, expected: []string{"a"}, want: "roles not assigned: a; roles assigned outside of the configuration: b"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := user.RoleSetMismatch(test.actual, test.expected)
			if got != test.want {
				t.Errorf("unexpected mismatch description\nwant: %q\ngot:  %q", test.want, got)
			}
		})
	}
}

func TestRoleIDs(t *testing.T) {
	t.Parallel()

	roleID := func(id string) *models.FlightcontrolapiCombinedUserRolesResourceV2 {
		return &models.FlightcontrolapiCombinedUserRolesResourceV2{RoleID: &id}
	}

	tests := map[string]struct {
		assigned []*models.FlightcontrolapiCombinedUserRolesResourceV2
		want     []string
	}{
		"empty": {assigned: nil, want: []string{}},
		"roles": {assigned: []*models.FlightcontrolapiCombinedUserRolesResourceV2{roleID("a"), roleID("b")}, want: []string{"a", "b"}},
		"skips nil role": {
			assigned: []*models.FlightcontrolapiCombinedUserRolesResourceV2{roleID("a"), nil},
			want:     []string{"a"},
		},
		"skips nil role id": {
			assigned: []*models.FlightcontrolapiCombinedUserRolesResourceV2{
				roleID("a"),
				{RoleID: nil},
			},
			want: []string{"a"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := user.RoleIDs(test.assigned)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("unexpected role ids (-want +got):\n%s", diff)
			}
		})
	}
}

// roleAssignmentStateChecks returns the checks made on every step: the user and
// CID the resource points at, and the role set it manages. No role IDs expects
// role_ids to be null.
func roleAssignmentStateChecks(roleIDs ...string) []statecheck.StateCheck {
	roles := knownvalue.Check(knownvalue.Null())
	if len(roleIDs) > 0 {
		checks := make([]knownvalue.Check, 0, len(roleIDs))
		for _, id := range roleIDs {
			checks = append(checks, knownvalue.StringExact(id))
		}
		roles = knownvalue.SetExact(checks)
	}

	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(roleAssignmentResourceName, tfjsonpath.New("user_uuid"), knownvalue.NotNull()),
		statecheck.CompareValuePairs(
			roleAssignmentResourceName,
			tfjsonpath.New("cid"),
			cidDataSourceName,
			tfjsonpath.New("cid"),
			compare.ValuesSame(),
		),
		statecheck.ExpectKnownValue(roleAssignmentResourceName, tfjsonpath.New("role_ids"), roles),
	}
}

// testAccUserRoleAssignmentImportStep returns an import step for the assignment
// resource. Run it after every state so each one is known to round-trip.
func testAccUserRoleAssignmentImportStep() resource.TestStep {
	return resource.TestStep{
		ResourceName:                         roleAssignmentResourceName,
		ImportState:                          true,
		ImportStateIdFunc:                    importStateIDByUserUUIDAndCID(roleAssignmentResourceName, nil),
		ImportStateVerify:                    true,
		ImportStateVerifyIdentifierAttribute: "user_uuid",
	}
}

// importStateIDByUserUUIDAndCID returns the "user_uuid,cid" import ID accepted
// by the resource, built from the named resource's state. transformCID rewrites
// the CID before it is joined, which is how the normalization done on import is
// exercised.
func importStateIDByUserUUIDAndCID(
	resourceName string,
	transformCID func(string) string,
) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("resource not found in state: %s", resourceName)
		}

		cid := rs.Primary.Attributes["cid"]
		if transformCID != nil {
			cid = transformCID(cid)
		}

		return fmt.Sprintf("%s,%s", rs.Primary.Attributes["user_uuid"], cid), nil
	}
}

// captureAttr records a string attribute so a later step can use it to call the
// API outside of Terraform.
func captureAttr(address, attribute string, dest *string) statecheck.StateCheck {
	return &attrCapture{address: address, attribute: attribute, dest: dest}
}

type attrCapture struct {
	address   string
	attribute string
	dest      *string
}

func (c *attrCapture) CheckState(
	_ context.Context,
	req statecheck.CheckStateRequest,
	resp *statecheck.CheckStateResponse,
) {
	if req.State == nil || req.State.Values == nil || req.State.Values.RootModule == nil {
		resp.Error = fmt.Errorf("state is empty, cannot capture %s.%s", c.address, c.attribute)
		return
	}

	for _, r := range req.State.Values.RootModule.Resources {
		if r.Address != c.address {
			continue
		}

		value, ok := r.AttributeValues[c.attribute].(string)
		if !ok {
			resp.Error = fmt.Errorf("%s: attribute %s is not a string", c.address, c.attribute)
			return
		}

		*c.dest = value

		return
	}

	resp.Error = fmt.Errorf("resource not found in state: %s", c.address)
}

// grantRoleOutOfBand grants a role through the API, bypassing Terraform, to set
// up drift. A non-empty expiresAt makes the grant temporary.
func grantRoleOutOfBand(t *testing.T, userUUID, cid, roleID, expiresAt string) {
	t.Helper()

	client := testconfig.GetTestClient()
	if client == nil {
		t.Fatal("falcon test client is not initialized")
	}

	if userUUID == "" || cid == "" {
		t.Fatalf("user uuid (%q) and cid (%q) must be captured from a previous step", userUUID, cid)
	}

	params := user_management.NewUserRolesActionV1ParamsWithContext(context.Background())
	params.Body = &models.FlightcontrolapiGrantInput{
		Action:    "grant",
		Cid:       cid,
		RoleIds:   []string{roleID},
		UUID:      userUUID,
		ExpiresAt: expiresAt,
	}

	res, err := client.UserManagement.UserRolesActionV1(params)
	if err != nil {
		t.Fatalf("granting role %s to user %s: %s", roleID, userUUID, err)
	}
	if res == nil || res.Payload == nil {
		t.Fatalf("granting role %s to user %s: empty response", roleID, userUUID)
	}
	for _, e := range res.Payload.Errors {
		if e == nil {
			continue
		}
		t.Fatalf("granting role %s to user %s: %s", roleID, userUUID, e.String())
	}
}

func testAccUserRoleAssignmentConfig_user(email string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
data "crowdstrike_cid" "current" {}

resource "crowdstrike_user" "test" {
  email      = %[1]q
  first_name = "John"
  last_name  = "Doe"
  cid        = data.crowdstrike_cid.current.cid
}
`, email)
}

// testAccUserRoleAssignmentConfig returns a config for a user and a role
// assignment. Empty roleIDs omits the role_ids attribute.
func testAccUserRoleAssignmentConfig(email string, roleIDs []string) string {
	return testAccUserRoleAssignmentConfig_user(email) +
		testAccUserRoleAssignmentConfig_assignment("crowdstrike_user.test.id", roleIDs)
}

// testAccUserRoleAssignmentConfig_twoUsers returns a config with two users and
// an assignment pointing at userRef, so the assignment can be moved between
// them.
func testAccUserRoleAssignmentConfig_twoUsers(email, secondEmail, userRef string, roleIDs []string) string {
	return testAccUserRoleAssignmentConfig_user(email) + fmt.Sprintf(`
resource "crowdstrike_user" "second" {
  email      = %[1]q
  first_name = "Jane"
  last_name  = "Roe"
  cid        = data.crowdstrike_cid.current.cid
}
`, secondEmail) + testAccUserRoleAssignmentConfig_assignment(userRef, roleIDs)
}

func testAccUserRoleAssignmentConfig_assignment(userRef string, roleIDs []string) string {
	roleIDsAttr := ""
	if len(roleIDs) > 0 {
		quoted := make([]string, 0, len(roleIDs))
		for _, id := range roleIDs {
			quoted = append(quoted, fmt.Sprintf("%q", id))
		}
		roleIDsAttr = fmt.Sprintf("\n  role_ids  = [%s]", strings.Join(quoted, ", "))
	}

	return fmt.Sprintf(`
resource "crowdstrike_user_role_assignment" "test" {
  user_uuid = %[1]s
  cid       = data.crowdstrike_cid.current.cid%[2]s
}
`, userRef, roleIDsAttr)
}
