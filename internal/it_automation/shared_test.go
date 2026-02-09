package itautomation_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/it_automation"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// namedReadCloser implements runtime.NamedReadCloser for file uploads.
type namedReadCloser struct {
	*strings.Reader
	name string
}

func (n *namedReadCloser) Close() error {
	return nil
}

func (n *namedReadCloser) Name() string {
	return n.name
}

func newNamedReadCloser(content, name string) *namedReadCloser {
	return &namedReadCloser{
		Reader: strings.NewReader(content),
		name:   name,
	}
}

// testFixtures contains shared terraform resource definitions used across it automation tests.
type testFixtures struct {
	HostGroups        map[string]string
	Policies          map[string]string
	VerificationTasks map[string]string
}

// sdkFixtures contains dynamically created SDK resources that need cleanup.
type sdkFixtures struct {
	ScriptFileIDs map[string]string
	FileIDs       map[string]string
	UserIDs       []string
	client        *client.CrowdStrikeAPISpecification
}

// createSDKFixtures creates RTR files and test users using the Falcon SDK.
func createSDKFixtures(t *testing.T) *sdkFixtures {
	t.Helper()

	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skip("Skipping acceptance test: TF_ACC not set")
	}

	clientID := os.Getenv("FALCON_CLIENT_ID")
	clientSecret := os.Getenv("FALCON_CLIENT_SECRET")
	cloud := os.Getenv("FALCON_CLOUD")

	if clientID == "" || clientSecret == "" {
		t.Fatal("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set")
	}

	if cloud == "" {
		cloud = "autodiscover"
	}

	falconClient, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     clientID,
		ClientSecret: clientSecret,
		Cloud:        falcon.Cloud(cloud),
		Context:      t.Context(),
	})
	if err != nil {
		t.Fatalf("failed to create falcon client: %v", err)
	}

	fixtures := &sdkFixtures{
		ScriptFileIDs: make(map[string]string),
		FileIDs:       make(map[string]string),
		UserIDs:       []string{},
		client:        falconClient,
	}

	randomSuffix := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	platforms := []string{"windows", "linux", "mac"}

	for _, platform := range platforms {
		scriptContent := fmt.Sprintf("echo 'test script for %s - %s'", platform, randomSuffix)
		scriptFileName := fmt.Sprintf("test-script-%s-%s.sh", platform, randomSuffix)
		scriptFileID, err := createRTRFile(
			t, falconClient, scriptFileName, scriptContent,
			"Test script file", platform,
		)
		if err != nil {
			fixtures.Cleanup(t)
			t.Fatalf("failed to create script file for %s: %v", platform, err)
		}

		fixtures.ScriptFileIDs[platform] = scriptFileID

		fileContent := fmt.Sprintf("test file content for %s - %s", platform, randomSuffix)
		fileName := fmt.Sprintf("test-file-%s-%s.txt", platform, randomSuffix)
		fileID, err := createRTRFile(
			t, falconClient, fileName, fileContent,
			"Test attachment file - terraform-provider-sdk acceptance tests", platform,
		)
		if err != nil {
			fixtures.Cleanup(t)
			t.Fatalf("failed to create attachment file for %s: %v", platform, err)
		}

		fixtures.FileIDs[platform] = fileID
	}

	for i := range 3 {
		email := fmt.Sprintf("%s-%d@crowdstrike.com", randomSuffix, i)
		userID, err := createUser(t, falconClient, email)
		if err != nil {
			fixtures.Cleanup(t)
			t.Fatalf("failed to create test user: %v", err)
		}

		fixtures.UserIDs = append(fixtures.UserIDs, userID)
	}

	return fixtures
}

// createRTRFile creates an RTR put file.
func createRTRFile(
	t *testing.T,
	falconClient *client.CrowdStrikeAPISpecification,
	fileName, content, description, platform string,
) (string, error) {
	t.Helper()

	params := &real_time_response_admin.RTRCreatePutFilesParams{
		Description: description,
		Name:        &fileName,
		File:        newNamedReadCloser(content, fileName),
		Context:     t.Context(),
	}

	platformComment := fmt.Sprintf("platform:%s", platform)
	params.CommentsForAuditLog = &platformComment

	_, err := falconClient.RealTimeResponseAdmin.RTRCreatePutFiles(params)
	if err != nil {
		return "", fmt.Errorf("RTRCreatePutFiles failed: %w", err)
	}

	fqlFilter := fmt.Sprintf("name:'%s'", fileName)
	listParams := &real_time_response_admin.RTRListPutFilesParams{
		Filter:  &fqlFilter,
		Context: t.Context(),
	}

	listResp, err := falconClient.RealTimeResponseAdmin.RTRListPutFiles(listParams)
	if err != nil {
		return "", fmt.Errorf("RTRListPutFiles failed: %w", err)
	}

	if listResp == nil || listResp.Payload == nil || len(listResp.Payload.Resources) == 0 {
		return "", fmt.Errorf("no file ID found after creation")
	}

	return listResp.Payload.Resources[0], nil
}

// createUser creates a test user with IT Administrator role.
func createUser(
	t *testing.T,
	falconClient *client.CrowdStrikeAPISpecification,
	email string,
) (string, error) {
	t.Helper()

	firstName := "Test"
	lastName := "User"

	params := &user_management.CreateUserV1Params{
		Body: &models.DomainCreateUserRequest{
			FirstName: firstName,
			LastName:  lastName,
			UID:       email,
		},
		Context: t.Context(),
	}

	resp, err := falconClient.UserManagement.CreateUserV1(params)
	if err != nil {
		return "", fmt.Errorf("CreateUserV1 failed: %w", err)
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		return "", fmt.Errorf("no user ID returned")
	}

	userUUID := resp.Payload.Resources[0].UUID

	grantParams := &user_management.GrantUserRoleIdsParams{
		UserUUID: userUUID,
		Body: &models.DomainRoleIDs{
			RoleIds: []string{"falcon_for_it_admin"},
		},
		Context: t.Context(),
	}

	_, err = falconClient.UserManagement.GrantUserRoleIds(grantParams)
	if err != nil {
		_ = deleteUser(t, falconClient, userUUID)
		return "", fmt.Errorf("GrantUserRoleIds failed: %w", err)
	}

	return userUUID, nil
}

// Cleanup deletes all SDK-created resources.
func (f *sdkFixtures) Cleanup(t *testing.T) {
	t.Helper()

	for platform, fileID := range f.ScriptFileIDs {
		if err := deleteRTRFile(t, f.client, fileID); err != nil {
			t.Logf("failed to delete script file for %s: %v", platform, err)
		}
	}

	for platform, fileID := range f.FileIDs {
		if err := deleteRTRFile(t, f.client, fileID); err != nil {
			t.Logf("failed to delete attachment file for %s: %v", platform, err)
		}
	}

	for _, userID := range f.UserIDs {
		if err := deleteUser(t, f.client, userID); err != nil {
			t.Logf("failed to delete user %s: %v", userID, err)
		}
	}
}

// deleteRTRFile deletes an RTR put file.
func deleteRTRFile(
	t *testing.T,
	falconClient *client.CrowdStrikeAPISpecification,
	fileID string,
) error {
	t.Helper()

	params := &real_time_response_admin.RTRDeletePutFilesParams{
		Ids:     fileID,
		Context: t.Context(),
	}

	_, err := falconClient.RealTimeResponseAdmin.RTRDeletePutFiles(params)
	if err != nil {
		if _, ok := err.(*real_time_response_admin.RTRDeletePutFilesNotFound); ok {
			return nil
		}
		return fmt.Errorf("RTRDeletePutFiles failed: %w", err)
	}

	return nil
}

// deleteUser deletes a test user.
func deleteUser(
	t *testing.T,
	falconClient *client.CrowdStrikeAPISpecification,
	userID string,
) error {
	t.Helper()

	params := &user_management.DeleteUserV1Params{
		UserUUID: userID,
		Context:  t.Context(),
	}

	_, err := falconClient.UserManagement.DeleteUserV1(params)
	if err != nil {
		if strings.Contains(err.Error(), "status 404") {
			return nil
		}
		return fmt.Errorf("DeleteUserV1 failed: %w", err)
	}

	return nil
}

// GetExistingPolicyIDs queries existing non-default policies for a platform.
func (f *sdkFixtures) GetExistingPolicyIDs(t *testing.T, platform string) []string {
	t.Helper()

	var allPolicyIDs []string
	limit := int64(100)
	offset := int64(0)

	for {
		queryParams := &it_automation.ITAutomationQueryPoliciesParams{
			Context:  t.Context(),
			Limit:    &limit,
			Offset:   &offset,
			Platform: platform,
		}

		ok, err := f.client.ItAutomation.ITAutomationQueryPolicies(queryParams)
		if err != nil {
			t.Fatalf("failed to query policies: %v", err)
		}

		if ok == nil || ok.Payload == nil {
			break
		}

		if len(ok.Payload.Resources) > 0 {
			allPolicyIDs = append(allPolicyIDs, ok.Payload.Resources...)
		}

		if len(ok.Payload.Resources) < int(limit) {
			break
		}

		offset += limit
	}

	if len(allPolicyIDs) == 0 {
		return []string{}
	}

	getParams := &it_automation.ITAutomationGetPoliciesParams{
		Context: t.Context(),
		Ids:     allPolicyIDs,
	}

	getResp, err := f.client.ItAutomation.ITAutomationGetPolicies(getParams)
	if err != nil {
		t.Fatalf("failed to get policies: %v", err)
	}

	if getResp == nil || getResp.Payload == nil || len(getResp.Payload.Resources) == 0 {
		return []string{}
	}

	var existingIDs []string
	for _, policy := range getResp.Payload.Resources {
		if policy != nil && policy.ID != nil && policy.Name != nil {
			if !isDefaultPolicy(*policy.Name) {
				existingIDs = append(existingIDs, *policy.ID)
			}
		}
	}

	return existingIDs
}

// isDefaultPolicy checks if a policy name matches the Default Policy pattern.
func isDefaultPolicy(name string) bool {
	return strings.HasPrefix(name, "Default Policy (") && strings.HasSuffix(name, ")")
}

// getTestFixtures creates a set of test fixtures with a unique random suffix to avoid naming conflicts when running tests in parallel.
func getTestFixtures() *testFixtures {
	randomSuffix := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	hostGroups := map[string]string{
		"windows": fmt.Sprintf(`
resource "crowdstrike_host_group" "windows" {
  name            = "%s-windows-hg"
  description     = "Test host group for Windows IT automation tests"
  type            = "dynamic"
  assignment_rule = "platform_name:'Windows'"
}`, randomSuffix),
		"linux": fmt.Sprintf(`
resource "crowdstrike_host_group" "linux" {
  name            = "%s-linux-hg"
  description     = "Test host group for Linux IT automation tests"
  type            = "dynamic"
  assignment_rule = "platform_name:'Linux'"
}`, randomSuffix),
		"mac": fmt.Sprintf(`
resource "crowdstrike_host_group" "mac" {
  name            = "%s-mac-hg"
  description     = "Test host group for Mac IT automation tests"
  type            = "dynamic"
  assignment_rule = "platform_name:'Mac'"
}`, randomSuffix),
	}

	policies := map[string]string{
		"windows_1": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "windows_1" {
  name        = "%s-windows-policy-1"
  description = "Test Windows policy 1 for precedence tests"
  platform_name    = "Windows"
  enabled  = true
  host_groups = [crowdstrike_host_group.windows.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}`, randomSuffix),
		"windows_2": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "windows_2" {
  name        = "%s-windows-policy-2"
  description = "Test Windows policy 2 for precedence tests"
  platform_name    = "Windows"
  enabled  = true
  host_groups = [crowdstrike_host_group.windows.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}`, randomSuffix),
		"windows_3": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "windows_3" {
  name        = "%s-windows-policy-3"
  description = "Test Windows policy 3 for precedence tests"
  platform_name    = "Windows"
  enabled  = true
  host_groups = [crowdstrike_host_group.windows.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}`, randomSuffix),
		"linux_1": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "linux_1" {
  name        = "%s-linux-policy-1"
  description = "Test Linux policy 1 for precedence tests"
  platform_name    = "Linux"
  enabled  = true
  host_groups = [crowdstrike_host_group.linux.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}`, randomSuffix),
		"linux_2": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "linux_2" {
  name        = "%s-linux-policy-2"
  description = "Test Linux policy 2 for precedence tests"
  platform_name    = "Linux"
  enabled  = true
  host_groups = [crowdstrike_host_group.linux.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}`, randomSuffix),
		"linux_3": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "linux_3" {
  name        = "%s-linux-policy-3"
  description = "Test Linux policy 3 for precedence tests"
  platform_name    = "Linux"
  enabled  = true
  host_groups = [crowdstrike_host_group.linux.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_throttle           = 15
  memory_allocation      = 1024
  memory_allocation_unit = "MB"
}`, randomSuffix),
		"mac_1": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "mac_1" {
  name        = "%s-mac-policy-1"
  description = "Test Mac policy 1 for precedence tests"
  platform_name    = "Mac"
  enabled  = true
  host_groups = [crowdstrike_host_group.mac.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_scheduling_priority = "Medium"
  memory_pressure_level   = "Medium"
}`, randomSuffix),
		"mac_2": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "mac_2" {
  name        = "%s-mac-policy-2"
  description = "Test Mac policy 2 for precedence tests"
  platform_name    = "Mac"
  enabled  = true
  host_groups = [crowdstrike_host_group.mac.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_scheduling_priority = "Medium"
  memory_pressure_level   = "Medium"
}`, randomSuffix),
		"mac_3": fmt.Sprintf(`
resource "crowdstrike_it_automation_policy" "mac_3" {
  name        = "%s-mac-policy-3"
  description = "Test Mac policy 3 for precedence tests"
  platform_name    = "Mac"
  enabled  = true
  host_groups = [crowdstrike_host_group.mac.id]

  concurrent_host_file_transfer_limit = 2500
  concurrent_host_limit               = 5000
  concurrent_task_limit               = 3

  enable_os_query         = true
  enable_python_execution = true
  enable_script_execution = true
  execution_timeout       = 30
  execution_timeout_unit  = "Minutes"

  cpu_scheduling_priority = "Medium"
  memory_pressure_level   = "Medium"
}`, randomSuffix),
	}

	verificationTasks := map[string]string{
		"windows": fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "verify_windows" {
  name        = "%s-windows-verification-task"
  access_type = "Public"
  type        = "query"
  os_query    = "SELECT * FROM system_info;"
}`, randomSuffix),
		"linux": fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "verify_linux" {
  name        = "%s-linux-verification-task"
  access_type = "Public"
  type        = "query"
  os_query    = "SELECT * FROM system_info;"
}`, randomSuffix),
		"mac": fmt.Sprintf(`
resource "crowdstrike_it_automation_task" "verify_mac" {
  name        = "%s-mac-verification-task"
  access_type = "Public"
  type        = "query"
  os_query    = "SELECT * FROM system_info;"
}`, randomSuffix),
	}

	return &testFixtures{
		HostGroups:        hostGroups,
		Policies:          policies,
		VerificationTasks: verificationTasks,
	}
}

// All returns all test fixtures combined (host groups, policies, and verification tasks).
func (f *testFixtures) All() string {
	var result strings.Builder

	for _, hg := range []string{"windows", "linux", "mac"} {
		result.WriteString(f.HostGroups[hg])
		result.WriteString("\n")
	}

	policies := []string{
		"windows_1", "windows_2", "windows_3",
		"linux_1", "linux_2", "linux_3",
		"mac_1", "mac_2", "mac_3",
	}
	for _, p := range policies {
		result.WriteString(f.Policies[p])
		result.WriteString("\n")
	}

	for _, vt := range []string{"windows", "linux", "mac"} {
		result.WriteString(f.VerificationTasks[vt])
		result.WriteString("\n")
	}

	return result.String()
}

// HostGroupsOnly returns only host group fixtures for all platforms.
func (f *testFixtures) HostGroupsOnly() string {
	var result strings.Builder
	for _, hg := range []string{"windows", "linux", "mac"} {
		result.WriteString(f.HostGroups[hg])
		result.WriteString("\n")
	}
	return result.String()
}

// PoliciesOnly returns only policy fixtures for all platforms (3 per platform).
func (f *testFixtures) PoliciesOnly() string {
	var result strings.Builder
	policies := []string{
		"windows_1", "windows_2", "windows_3",
		"linux_1", "linux_2", "linux_3",
		"mac_1", "mac_2", "mac_3",
	}
	for _, p := range policies {
		result.WriteString(f.Policies[p])
		result.WriteString("\n")
	}
	return result.String()
}

// WindowsHostGroupsOnly returns only the windows host group fixture.
func (f *testFixtures) WindowsHostGroupsOnly() string {
	return f.HostGroups["windows"] + "\n"
}

// LinuxHostGroupsOnly returns only the linux host group fixture.
func (f *testFixtures) LinuxHostGroupsOnly() string {
	return f.HostGroups["linux"] + "\n"
}

// MacHostGroupsOnly returns only the mac host group fixture.
func (f *testFixtures) MacHostGroupsOnly() string {
	return f.HostGroups["mac"] + "\n"
}

// WindowsPoliciesOnly returns only the windows policy fixtures.
func (f *testFixtures) WindowsPoliciesOnly() string {
	var result strings.Builder
	for _, p := range []string{"windows_1", "windows_2", "windows_3"} {
		result.WriteString(f.Policies[p])
		result.WriteString("\n")
	}
	return result.String()
}

// LinuxPoliciesOnly returns only the linux policy fixtures.
func (f *testFixtures) LinuxPoliciesOnly() string {
	var result strings.Builder
	for _, p := range []string{"linux_1", "linux_2", "linux_3"} {
		result.WriteString(f.Policies[p])
		result.WriteString("\n")
	}
	return result.String()
}

// MacPoliciesOnly returns only the mac policy fixtures.
func (f *testFixtures) MacPoliciesOnly() string {
	var result strings.Builder
	for _, p := range []string{"mac_1", "mac_2", "mac_3"} {
		result.WriteString(f.Policies[p])
		result.WriteString("\n")
	}
	return result.String()
}

// VerificationTasksOnly returns only verification task fixtures for all platforms.
func (f *testFixtures) VerificationTasksOnly() string {
	var result strings.Builder
	for _, vt := range []string{"windows", "linux", "mac"} {
		result.WriteString(f.VerificationTasks[vt])
		result.WriteString("\n")
	}
	return result.String()
}
