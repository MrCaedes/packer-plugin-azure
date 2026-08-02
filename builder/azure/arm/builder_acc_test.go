// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package arm

// Below are the requirements for running the acceptance tests for the Packer Azure plugin ARM Builder
//
// * An Azure subscription, with a resource group, app registration based credentials and a few image galleries
// You can use the Terraform config in the terraform folder at the base of the repository
// It is recommended to set the required environment variables and then run the acceptance_test_setup.sh script in the terraform directory
//
// * The Azure CLI installed and logged in for testing CLI based authentication
// * Env Variables for Auth
// ** ARM_CLIENT_ID
// ** ARM_CLIENT_SECRET
// ** ARM_SUBSCRIPTION_ID
// *
// * Env Variables Defining Azure Resources for Packer templates
// ** ARM_RESOURCE_GROUP_NAME - Resource group
// ** ARM_STORAGE_ACCOUNT - a storage account located in above resource group
// ** ARM_RESOURCE_PREFIX - String prefix for resources unique name constraints
// ** ARM_STORAGE_CONTAINER_NAME - storage container name for blob-based tests
// ** ARM_TEMP_RESOURCE_GROUP_NAME - temp resource group name for CLI-based tests
// ** For example SIG gallery names must be unique not just within the resource group, but within a subscription, and a user may not have access to all SIGs in a subscription.
// * As well as the following misc env variables
// ** ARM_SSH_PRIVATE_KEY_FILE - the file location of a PEM encoded RSA SSH Private Key (ed25519 is not supported by Azure),
// ** PACKER_ACC - set to any non 0 value
// * Env Variables for Existing VNet tests
// ** ARM_VIRTUAL_NETWORK_NAME - name of the pre-existing virtual network
// * Env Variables for Existing RBAC Key Vault tests
// ** ARM_RBAC_KEY_VAULT_NAME - name of the RBAC-enabled existing Key Vault in ARM_RESOURCE_GROUP_NAME
// ** AZURE_OBJECT_ID - object ID of the Packer build identity
//
// It is recommended to run the tests with the options "-v -timeout 90m"
// command, e.g.:
//   go test -v -timeout 90m -run TestBuilderAcc_.*
// This is to avoid hitting the default go test timeout, especially in the shared image gallery test

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/packer-plugin-azure/builder/azure/common"
	"github.com/hashicorp/packer-plugin-sdk/acctest"
)

const runnerIPPlaceholder = "RUNNER_IP_PLACEHOLDER"

func injectRunnerIP(t *testing.T, template string) string {
	t.Helper()

	runnerIP := common.DetectPackerPublicIP(t)
	quotedPlaceholder := strconv.Quote(runnerIPPlaceholder)
	if !strings.Contains(template, quotedPlaceholder) {
		t.Fatalf("template missing %q placeholder", runnerIPPlaceholder)
	}

	return strings.Replace(template, quotedPlaceholder, strconv.Quote(runnerIP), 1)
}

// This test builds two images,
// First a parent Specialized ARM 64 Linux VM to a Shared Image Gallery/Compute Gallery
// Then a second Specialized ARM64 Linux VM that uses the first as its source/parent image
func TestBuilderAcc_SharedImageGallery_ARM64SpecializedLinuxSIG_WithChildImage(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t,
		common.CheckAcceptanceTestEnvVarsParams{
			CheckAzureCLI:          true,
			CheckSSHPrivateKeyFile: true,
		},
	)
	subscriptionID := os.Getenv("ARM_SUBSCRIPTION_ID")
	resourcePrefix := os.Getenv("ARM_RESOURCE_PREFIX")
	resourceGroupName := os.Getenv("ARM_RESOURCE_GROUP_NAME")

	// After test finishes try and delete the created versions
	defer deleteGalleryVersions(t, subscriptionID, resourceGroupName, fmt.Sprintf("%s_acctestgallery", resourcePrefix), fmt.Sprintf("%s-arm-linux-specialized-sig", resourcePrefix), []string{"1.0.0", "1.0.1"})
	// Create parent specialized shared gallery image
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name: "test-specialized-linux-sig",
		Type: "azure-arm",
		// Run build with force to ignore previous test runs failed artifact deletions
		BuildExtraArgs: []string{"-force"},
		Template:       string(armLinuxSpecialziedSIGTemplate),
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})

	// Create child image from a specialized parent
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:           "test-specialized-linux-sig-child",
		Type:           "azure-arm",
		BuildExtraArgs: []string{"-force"},
		Template:       string(armLinuxChildFromSpecializedParent),
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})

}

func TestBuilderAcc_SharedImageGallery_WindowsSIG(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t,
		common.CheckAcceptanceTestEnvVarsParams{
			CheckAzureCLI: true,
		},
	)

	subscriptionID := os.Getenv("ARM_SUBSCRIPTION_ID")
	resourceGroupName := os.Getenv("ARM_RESOURCE_GROUP_NAME")
	resourcePrefix := os.Getenv("ARM_RESOURCE_PREFIX")
	defer deleteGalleryVersions(t, subscriptionID, resourceGroupName, fmt.Sprintf("%s_acctestgallery", resourcePrefix), fmt.Sprintf("%s-windows-sig", resourcePrefix), []string{"1.0.0"})

	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:           "test-windows-sig",
		Type:           "azure-arm",
		BuildExtraArgs: []string{"-force"},
		Template:       string(windowsSIGTemplate),
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func TestBuilderAcc_ManagedDisk_Windows(t *testing.T) {
	t.Parallel()
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-managedisk-windows",
		Type:     "azure-arm",
		Template: testBuilderAccManagedDiskWindows,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func TestBuilderAcc_ManagedDisk_Windows_TemporaryKeyVault_RBACDefaultRole(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{
		CheckAzureCLI: true,
	})

	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-managedisk-windows-temporary-key-vault-rbac-default-role",
		Type:     "azure-arm",
		Template: testBuilderAccManagedDiskWindowsTemporaryKeyVaultRBAC,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil && buildCommand.ProcessState.ExitCode() != 0 {
				return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
			}
			return nil
		},
	})
}

func TestBuilderAcc_ManagedDisk_Windows_ExistingBuildKeyVault_RBACDefaultRole(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{
		CheckAzureCLI: true,
	})

	keyVaultName := requiredAcceptanceEnvironment(t, "ARM_RBAC_KEY_VAULT_NAME")
	principalID := requiredAcceptanceEnvironment(t, "AZURE_OBJECT_ID")
	keyVaultScope := existingBuildKeyVaultScope(os.Getenv("ARM_SUBSCRIPTION_ID"), os.Getenv("ARM_RESOURCE_GROUP_NAME"), keyVaultName)
	roleAssignmentID := existingBuildKeyVaultRoleAssignmentID(keyVaultScope, principalID)
	assertNoDirectAcceptanceKeyVaultSecretsOfficerRoleAssignment(t, keyVaultScope, principalID)
	defer cleanupAcceptanceKeyVaultSecretsOfficerRoleAssignment(t, keyVaultScope, principalID, roleAssignmentID)

	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-managedisk-windows-existing-key-vault-rbac-default-role",
		Type:     "azure-arm",
		Template: testBuilderAccManagedDiskWindowsExistingKeyVaultRBAC,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil && buildCommand.ProcessState.ExitCode() != 0 {
				return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
			}
			return nil
		},
	})

	if actualRoleAssignmentID := waitForAcceptanceKeyVaultSecretsOfficerRoleAssignment(t, keyVaultScope, principalID); !strings.EqualFold(actualRoleAssignmentID, roleAssignmentID) {
		t.Fatalf("Expected Packer to create deterministic Key Vault role assignment %q, got %q", roleAssignmentID, actualRoleAssignmentID)
	}
	waitForNoActivePackerCertificateSecrets(t, keyVaultName)
}

func TestKeyVaultAcceptanceTemplatesUseDefaultRoleAssignment(t *testing.T) {
	testCases := []struct {
		name                 string
		template             string
		expectsExistingVault bool
	}{
		{
			name:     "temporary Key Vault",
			template: testBuilderAccManagedDiskWindowsTemporaryKeyVaultRBAC,
		},
		{
			name:                 "existing Key Vault in the build resource group",
			template:             testBuilderAccManagedDiskWindowsExistingKeyVaultRBAC,
			expectsExistingVault: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var document struct {
				Builders []map[string]interface{} `json:"builders"`
			}
			if err := json.Unmarshal([]byte(testCase.template), &document); err != nil {
				t.Fatalf("Expected valid acceptance template JSON: %v", err)
			}
			if len(document.Builders) != 1 {
				t.Fatalf("Expected one builder, got %d", len(document.Builders))
			}

			builder := document.Builders[0]
			if _, configured := builder["build_key_vault_assign_rbac_role"]; configured {
				t.Fatal("Acceptance template must omit build_key_vault_assign_rbac_role to cover the default assignment behaviour")
			}
			if enabled, ok := builder["build_key_vault_enable_rbac_authorization"].(bool); !ok || !enabled {
				t.Fatal("Acceptance template must enable Key Vault RBAC authorization")
			}
			if !testCase.expectsExistingVault {
				return
			}
			if _, ok := builder["build_key_vault_name"]; !ok {
				t.Fatal("Existing Key Vault acceptance template must configure build_key_vault_name")
			}
			if deleteSecret, ok := builder["build_key_vault_delete_secret"].(bool); !ok || !deleteSecret {
				t.Fatal("Existing Key Vault acceptance template must request certificate-secret cleanup")
			}
			if _, ok := builder["build_resource_group_name"]; !ok {
				t.Fatal("Existing Key Vault acceptance template must use the build resource group")
			}
		})
	}
}

func TestExistingBuildKeyVaultScope(t *testing.T) {
	actual := existingBuildKeyVaultScope("subscription-id", "key-vault-rg", "key-vault-name")
	expected := "/subscriptions/subscription-id/resourceGroups/key-vault-rg/providers/Microsoft.KeyVault/vaults/key-vault-name"
	if actual != expected {
		t.Fatalf("Expected Key Vault scope %q, got %q", expected, actual)
	}
}

func TestExistingBuildKeyVaultRoleAssignmentID(t *testing.T) {
	scope := existingBuildKeyVaultScope("subscription-id", "key-vault-rg", "key-vault-name")
	actual := existingBuildKeyVaultRoleAssignmentID(scope, "principal-id")
	expected := fmt.Sprintf("%s/providers/Microsoft.Authorization/roleAssignments/%s", scope, keyVaultRoleAssignmentName(scope, "principal-id"))
	if actual != expected {
		t.Fatalf("Expected deterministic Key Vault role assignment ID %q, got %q", expected, actual)
	}
}

// TODO Implement this test to validate client cert auth
func TestBuilderAcc_ClientCertificateAuth(t *testing.T) {
	t.Skip("Unimplemented Client Cert Auth Acceptance test")
}

func TestBuilderAcc_ManagedDisk_Windows_Build_Resource_Group(t *testing.T) {
	t.Parallel()
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-managedisk-windows-build-resource-group",
		Type:     "azure-arm",
		Template: testBuilderAccManagedDiskWindowsBuildResourceGroup,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func TestBuilderAcc_ManagedDisk_Windows_Build_Resource_Group_Additional_Disk(t *testing.T) {
	t.Parallel()
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-managedisk-windows-build-resource-group-additional-disk",
		Type:     "azure-arm",
		Template: testBuilderAccManagedDiskWindowsBuildResourceGroupAdditionalDisk,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func TestBuilderAcc_ManagedDisk_Linux(t *testing.T) {
	t.Parallel()
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-managedisk-linux",
		Type:     "azure-arm",
		Template: testBuilderAccManagedDiskLinux,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func TestBuilderAcc_ManagedDisk_Linux_AzureCLI(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{
		CheckAzureCLI: true,
	})
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-managedisk-linux-azurecli",
		Type:     "azure-arm",
		Template: testBuilderAccManagedDiskLinuxAzureCLI,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func TestBuilderAcc_Blob_Windows(t *testing.T) {
	t.Parallel()
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-blob-windows",
		Type:     "azure-arm",
		Template: testBuilderAccBlobWindows,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func TestBuilderAcc_Blob_Linux(t *testing.T) {
	t.Parallel()
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-blob-linux",
		Type:     "azure-arm",
		Template: testBuilderAccBlobLinux,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func TestBuilderUserData_Linux(t *testing.T) {
	t.Parallel()
	tmpfile, err := os.CreateTemp("", "userdata")
	if err != nil {
		t.Fatalf("failed creating tempfile: %s", err)
	}

	//nolint:errcheck
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(testBuilderCustomDataLinux); err != nil {
		t.Fatalf("failed writing userdata: %s", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("failed closing file: %s", err)
	}

	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-userdata-linux",
		Type:     "azure-arm",
		Template: testBuilderUserDataLinux(tmpfile.Name()),
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

//go:embed testdata/rsa_sha2_only_server.pkr.hcl
var rsaSHA2OnlyTemplate []byte

//go:embed testdata/windows_sig.pkr.hcl
var windowsSIGTemplate []byte

//go:embed testdata/arm_linux_specialized.pkr.hcl
var armLinuxSpecialziedSIGTemplate []byte

//go:embed testdata/child_from_specialized_parent.pkr.hcl
var armLinuxChildFromSpecializedParent []byte

func TestBuilderAcc_rsaSHA2OnlyServer(t *testing.T) {
	t.Parallel()
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-ubuntu-jammy-linux",
		Type:     "azure-arm",
		Template: string(rsaSHA2OnlyTemplate),
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			return nil
		},
	})
}

func deleteGalleryVersions(t *testing.T, subscriptionID string, resourceGroupName string, galleryName string, galleryImageName string, imageVersions []string) {
	for _, imageVersion := range imageVersions {
		// If we fail to delete a gallery version we should still try to delete other versions and the gallery
		// Its possible a build was canceled or failed mid test that would leave any of the builds incomplete
		// We still want to try and delete the Gallery to not leave behind orphaned resources to manually clean up
		deleteCommand := exec.Command(
			"az", "sig", "image-version", "delete",
			fmt.Sprintf("--gallery-image-definition=%s", galleryImageName),
			fmt.Sprintf("--gallery-image-version=%s", imageVersion),
			fmt.Sprintf("--gallery-name=%s", galleryName),
			fmt.Sprintf("-g=%s", resourceGroupName),
		)
		deleteStdout, err := deleteCommand.CombinedOutput()
		if err != nil {
			t.Logf("failed to delete Gallery Image Version %s:%s %s", galleryImageName, imageVersion, err)
			t.Logf("Failed command output \n%s", string(deleteStdout))
		}
	}
}

type acceptanceRoleAssignment struct {
	ID    string `json:"id"`
	Scope string `json:"scope"`
}

func requiredAcceptanceEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("Test %s requires environment variable %s to be set", t.Name(), name)
	}
	return value
}

func existingBuildKeyVaultScope(subscriptionID, resourceGroupName, keyVaultName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s", subscriptionID, resourceGroupName, keyVaultName)
}

func existingBuildKeyVaultRoleAssignmentID(keyVaultScope, principalID string) string {
	return fmt.Sprintf("%s/providers/Microsoft.Authorization/roleAssignments/%s", keyVaultScope, keyVaultRoleAssignmentName(keyVaultScope, principalID))
}

func waitForAcceptanceKeyVaultSecretsOfficerRoleAssignment(t *testing.T, keyVaultScope, principalID string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var lastErr error
	for {
		assignments, err := listAcceptanceKeyVaultSecretsOfficerRoleAssignments(keyVaultScope, principalID)
		if err == nil {
			for _, assignment := range assignments {
				if assignment.ID != "" && strings.EqualFold(assignment.Scope, keyVaultScope) {
					return assignment.ID
				}
			}
			lastErr = fmt.Errorf("no Key Vault Secrets Officer role assignment was returned at scope %q", keyVaultScope)
		} else {
			lastErr = err
		}

		if time.Now().After(deadline) {
			t.Fatalf("Timed out waiting for the Key Vault Secrets Officer role assignment at scope %q: %v", keyVaultScope, lastErr)
		}
		time.Sleep(5 * time.Second)
	}
}

func assertNoDirectAcceptanceKeyVaultSecretsOfficerRoleAssignment(t *testing.T, keyVaultScope, principalID string) {
	t.Helper()
	assignments, err := listAcceptanceKeyVaultSecretsOfficerRoleAssignments(keyVaultScope, principalID)
	if err != nil {
		t.Fatalf("Listing pre-existing Key Vault Secrets Officer role assignments: %v", err)
	}
	for _, assignment := range assignments {
		if assignment.ID != "" && strings.EqualFold(assignment.Scope, keyVaultScope) {
			t.Fatalf("Existing Key Vault fixture must not have a direct Key Vault Secrets Officer role assignment for the Packer identity at %q; remove stale fixture state before running this test", keyVaultScope)
		}
	}
}

func listAcceptanceKeyVaultSecretsOfficerRoleAssignments(keyVaultScope, principalID string) ([]acceptanceRoleAssignment, error) {
	command := exec.Command(
		"az", "role", "assignment", "list",
		"--scope", keyVaultScope,
		"--assignee-object-id", principalID,
		"--role", "Key Vault Secrets Officer",
		"--output", "json",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("listing Key Vault Secrets Officer role assignments: %w: %s", err, strings.TrimSpace(string(output)))
	}

	var assignments []acceptanceRoleAssignment
	if err := json.Unmarshal(output, &assignments); err != nil {
		return nil, fmt.Errorf("decoding Key Vault Secrets Officer role assignments: %w", err)
	}
	return assignments, nil
}

func waitForNoActivePackerCertificateSecrets(t *testing.T, keyVaultName string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var lastErr error
	for {
		secretNames, err := listActivePackerCertificateSecrets(keyVaultName)
		if err == nil && len(secretNames) == 0 {
			return
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("found %v", secretNames)
		}

		if time.Now().After(deadline) {
			t.Fatalf("Timed out waiting for Packer certificate cleanup in Key Vault %q: %v", keyVaultName, lastErr)
		}
		time.Sleep(5 * time.Second)
	}
}

func listActivePackerCertificateSecrets(keyVaultName string) ([]string, error) {
	query := fmt.Sprintf("[?starts_with(name, '%s')].name", DefaultSecretName+"-")
	command := exec.Command("az", "keyvault", "secret", "list", "--vault-name", keyVaultName, "--query", query, "--output", "json")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("listing active Packer certificate secrets: %w: %s", err, strings.TrimSpace(string(output)))
	}

	var secretNames []string
	if err := json.Unmarshal(output, &secretNames); err != nil {
		return nil, fmt.Errorf("decoding active Packer certificate secrets: %w", err)
	}
	return secretNames, nil
}

func cleanupAcceptanceKeyVaultSecretsOfficerRoleAssignment(t *testing.T, keyVaultScope, principalID, expectedRoleAssignmentID string) {
	t.Helper()
	assignments, err := listAcceptanceKeyVaultSecretsOfficerRoleAssignments(keyVaultScope, principalID)
	if err != nil {
		t.Errorf("Listing Key Vault Secrets Officer role assignments for cleanup: %v", err)
		return
	}
	for _, assignment := range assignments {
		if strings.EqualFold(assignment.ID, expectedRoleAssignmentID) {
			deleteAcceptanceRoleAssignment(t, expectedRoleAssignmentID)
			return
		}
	}
}

func deleteAcceptanceRoleAssignment(t *testing.T, roleAssignmentID string) {
	t.Helper()
	command := exec.Command("az", "role", "assignment", "delete", "--ids", roleAssignmentID)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Errorf("Failed to remove Key Vault role assignment %q: %v: %s", roleAssignmentID, err, strings.TrimSpace(string(output)))
	}
}

// TODO Move these templates to separate files inside the testdata directory rather than defined strings here
func testBuilderUserDataLinux(userdata string) string {
	return fmt.Sprintf(`
{
	"variables": {
	  "client_id": "{{env `+"`ARM_CLIENT_ID`"+`}}",
	  "client_secret": "{{env `+"`ARM_CLIENT_SECRET`"+`}}",
	  "subscription_id": "{{env `+"`ARM_SUBSCRIPTION_ID`"+`}}",
	  "storage_account": "{{env `+"`ARM_STORAGE_ACCOUNT`"+`}}",
	  "resource_group_name": "{{env `+"`ARM_RESOURCE_GROUP_NAME`"+`}}",
	  "capture_container_name": "{{env `+"`ARM_STORAGE_CONTAINER_NAME`"+`}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user `+"`client_id`"+`}}",
	  "client_secret": "{{user `+"`client_secret`"+`}}",
	  "subscription_id": "{{user `+"`subscription_id`"+`}}",

	  "storage_account": "{{user `+"`storage_account`"+`}}",
	  "resource_group_name": "{{user `+"`resource_group_name`"+`}}",
	  "capture_container_name": "{{user `+"`capture_container_name`"+`}}",
	  "capture_name_prefix": "testBuilderUserDataLinux",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",
	  "user_data_file": "%s",

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2"
	}]
}
`, userdata)
}

const testBuilderCustomDataLinux = `#cloud-config
growpart:
  mode: off
`

const testBuilderAccManagedDiskWindows = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccManagedDiskWindows-{{timestamp}}",

	  "os_type": "Windows",
	  "image_publisher": "MicrosoftWindowsServer",
	  "image_offer": "WindowsServer",
	  "image_sku": "2022-datacenter",

	  "communicator": "winrm",
	  "winrm_use_ssl": "true",
	  "winrm_insecure": "true",
	  "winrm_timeout": "3m",
	  "winrm_username": "packer",
	  "async_resourcegroup_delete": "true",

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2"
	}]
}
`

// build_key_vault_assign_rbac_role is intentionally omitted so this test covers
// the default Key Vault Secrets Officer assignment for a Packer-created vault.
const testBuilderAccManagedDiskWindowsTemporaryKeyVaultRBAC = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccManagedDiskWindowsTemporaryKeyVaultRBAC-{{timestamp}}",

	  "os_type": "Windows",
	  "image_publisher": "MicrosoftWindowsServer",
	  "image_offer": "WindowsServer",
	  "image_sku": "2022-datacenter",

	  "communicator": "winrm",
	  "winrm_use_ssl": "true",
	  "winrm_insecure": "true",
	  "winrm_timeout": "3m",
	  "winrm_username": "packer",

	  "build_key_vault_enable_rbac_authorization": true,
	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2"
	}]
}
`

// build_key_vault_assign_rbac_role is intentionally omitted so this test covers
// the default direct assignment on an existing Key Vault in the build resource group.
const testBuilderAccManagedDiskWindowsExistingKeyVaultRBAC = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}",
	  "key_vault_name": "{{env ` + "`ARM_RBAC_KEY_VAULT_NAME`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "build_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "build_key_vault_name": "{{user ` + "`key_vault_name`" + `}}",
	  "build_key_vault_enable_rbac_authorization": true,
	  "build_key_vault_delete_secret": true,
	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccManagedDiskWindowsExistingKeyVaultRBAC-{{timestamp}}",

	  "os_type": "Windows",
	  "image_publisher": "MicrosoftWindowsServer",
	  "image_offer": "WindowsServer",
	  "image_sku": "2022-datacenter",

	  "communicator": "winrm",
	  "winrm_use_ssl": "true",
	  "winrm_insecure": "true",
	  "winrm_timeout": "3m",
	  "winrm_username": "packer",
	  "vm_size": "Standard_DS2_v2"
	}]
}
`

const testBuilderAccManagedDiskWindowsBuildResourceGroup = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "build_resource_group_name" : "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccManagedDiskWindowsBuildResourceGroup-{{timestamp}}",

	  "os_type": "Windows",
	  "image_publisher": "MicrosoftWindowsServer",
	  "image_offer": "WindowsServer",
	  "image_sku": "2022-datacenter",

	  "communicator": "winrm",
	  "winrm_use_ssl": "true",
	  "winrm_insecure": "true",
	  "winrm_timeout": "3m",
	  "winrm_username": "packer",

	  "vm_size": "Standard_DS2_v2"
	}]
}
`

const testBuilderAccManagedDiskWindowsBuildResourceGroupAdditionalDisk = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "build_resource_group_name" : "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccManagedDiskWindowsBuildResourceGroupAdditionDisk-{{timestamp}}",

	  "os_type": "Windows",
	  "image_publisher": "MicrosoftWindowsServer",
	  "image_offer": "WindowsServer",
	  "image_sku": "2022-datacenter",

	  "communicator": "winrm",
	  "winrm_use_ssl": "true",
	  "winrm_insecure": "true",
	  "winrm_timeout": "3m",
	  "winrm_username": "packer",
	  "async_resourcegroup_delete": "true",

	  "vm_size": "Standard_DS2_v2",
	  "disk_additional_size": [10,15]
	}]
}
`

const testBuilderAccManagedDiskLinux = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccManagedDiskLinux-{{timestamp}}",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2",
	  "azure_tags": {
	    "env": "testing",
	    "builder": "packer"
	   }
	}]
}
`

const testBuilderAccBlobWindows = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "storage_account": "{{env ` + "`ARM_STORAGE_ACCOUNT`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}",
	  "capture_container_name": "{{env ` + "`ARM_STORAGE_CONTAINER_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "storage_account": "{{user ` + "`storage_account`" + `}}",
	  "resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "capture_container_name": "{{user ` + "`capture_container_name`" + `}}",
	  "capture_name_prefix": "testBuilderAccBlobWin",

	  "os_type": "Windows",
	  "image_publisher": "MicrosoftWindowsServer",
	  "image_offer": "WindowsServer",
	  "image_sku": "2022-datacenter",

	  "communicator": "winrm",
	  "winrm_use_ssl": "true",
	  "winrm_insecure": "true",
	  "winrm_timeout": "3m",
	  "winrm_username": "packer",

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2"
	}]
}
`

const testBuilderAccBlobLinux = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "storage_account": "{{env ` + "`ARM_STORAGE_ACCOUNT`" + `}}",
	  "capture_container_name": "{{env ` + "`ARM_STORAGE_CONTAINER_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "storage_account": "{{user ` + "`storage_account`" + `}}",
	  "resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "capture_container_name": "{{user ` + "`capture_container_name`" + `}}",
	  "capture_name_prefix": "testBuilderAccBlobLinux",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2"
	}]
}
`

const testBuilderAccManagedDiskLinuxAzureCLI = `
{
	"variables": {
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}",
	  "temp_resource_group_name": "{{env ` + "`ARM_TEMP_RESOURCE_GROUP_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "use_azure_cli_auth": true,

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccManagedDiskLinuxAzureCLI-{{timestamp}}",
	  "temp_resource_group_name": "{{user ` + "`temp_resource_group_name`" + `}}",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2",
	  "azure_tags": {
	    "env": "testing",
	    "builder": "packer"
	   }
	}]
}
`

const testBuilderAccAllowedInboundIpAddressesLiteral = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}",
	  "virtual_network_name": "{{env ` + "`ARM_VIRTUAL_NETWORK_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccAllowedInboundIpLiteral-{{timestamp}}",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",

	  "virtual_network_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "virtual_network_name": "{{user ` + "`virtual_network_name`" + `}}",
	  "virtual_network_subnet_name": "subnet",
	  "private_virtual_network_with_public_ip": true,
	  "allowed_inbound_ip_addresses": ["RUNNER_IP_PLACEHOLDER", "172.16.0.16/32"],

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2",
	  "azure_tags": {
	    "env": "testing",
	    "builder": "packer"
	   }
	}]
}
`

const testBuilderAccDenyOutboundIP = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccDenyOutboundIP-{{timestamp}}",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",
	  "deny_outbound_ip_addresses": ["198.51.100.10/32"],

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2",
	  "azure_tags": {
	    "env": "testing",
	    "builder": "packer"
	   }
	}]
}
`

const testBuilderAccBuildSucceedsWithoutDenyOutboundIpAddresses = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccBuildSucceedsWithoutDenyOutboundIpAddresses-{{timestamp}}",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",
	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2",
	  "azure_tags": {
	    "env": "testing",
	    "builder": "packer"
	   }
	}]
}
`

const testBuilderAccExistingVNetDenyOutboundIP = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}",
	  "virtual_network_name": "{{env ` + "`ARM_VIRTUAL_NETWORK_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccExistingVNetDenyOutboundIP-{{timestamp}}",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",

	  "virtual_network_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "virtual_network_name": "{{user ` + "`virtual_network_name`" + `}}",
	  "virtual_network_subnet_name": "subnet",
	  "private_virtual_network_with_public_ip": true,
	  "deny_outbound_ip_addresses": ["198.51.100.10/32"],

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2",
	  "azure_tags": {
	    "env": "testing",
	    "builder": "packer"
	   }
	}]
}
`
const testBuilderAccFqdnIngressAndOutboundRules = `
{
	"variables": {
	  "client_id": "{{env ` + "`ARM_CLIENT_ID`" + `}}",
	  "client_secret": "{{env ` + "`ARM_CLIENT_SECRET`" + `}}",
	  "subscription_id": "{{env ` + "`ARM_SUBSCRIPTION_ID`" + `}}",
	  "resource_group_name": "{{env ` + "`ARM_RESOURCE_GROUP_NAME`" + `}}"
	},
	"builders": [{
	  "type": "azure-arm",

	  "client_id": "{{user ` + "`client_id`" + `}}",
	  "client_secret": "{{user ` + "`client_secret`" + `}}",
	  "subscription_id": "{{user ` + "`subscription_id`" + `}}",

	  "managed_image_resource_group_name": "{{user ` + "`resource_group_name`" + `}}",
	  "managed_image_name": "testBuilderAccFqdnIngressAndOutboundRules-{{timestamp}}",

	  "os_type": "Linux",
	  "image_publisher": "Canonical",
	  "image_offer": "UbuntuServer",
	  "image_sku": "16.04-LTS",
	  "allowed_inbound_ip_addresses": ["RUNNER_IP_PLACEHOLDER", "example.com"],
	  "deny_outbound_ip_addresses": ["example.com"],

	  "location": "South Central US",
	  "vm_size": "Standard_DS2_v2",
	  "azure_tags": {
	    "env": "testing",
	    "builder": "packer"
	   }
	}],
	"provisioners": [{
	  "type": "shell",
	  "inline": [
	    "sudo apt-get update",
	    "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
	    "sudo DEBIAN_FRONTEND=noninteractive apt-get install curl -y",
	    "if ! getent hosts example.com >/dev/null 2>&1; then echo 'example.com did not resolve; cannot prove outbound deny'; exit 1; fi",
	    "if curl -fsS --connect-timeout 10 --max-time 20 https://example.com >/dev/null 2>&1; then echo 'example.com was reachable but should have been denied'; exit 1; fi",
	    "echo 'example.com resolved but HTTPS connection was blocked as expected'"
	  ]
	}]
}
`

func TestBuilderAcc_ExistingVNet_AllowedInboundIpAddresses(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{
		CheckVirtualNetworkName: true,
	})
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-existing-vnet-allowed-inbound-ip",
		Type:     "azure-arm",
		Template: injectRunnerIP(t, testBuilderAccAllowedInboundIpAddressesLiteral),
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil {
				if buildCommand.ProcessState.ExitCode() != 0 {
					return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
				}
			}
			logBytes, readErr := os.ReadFile(logfile)
			if readErr != nil {
				return fmt.Errorf("cannot read logfile %s: %w", logfile, readErr)
			}
			logStr := string(logBytes)
			if !strings.Contains(logStr, "Deleting Virtual Machine deployment") {
				return fmt.Errorf("cleanup-start marker missing in log. Logfile: %s", logfile)
			}
			if strings.Contains(logStr, "Error deleting resource. Please delete manually.") {
				return fmt.Errorf("cleanup-failure marker present in log. Logfile: %s", logfile)
			}
			return nil
		},
	})
}

func TestBuilderAcc_AllowedInboundAndDenyOutboundIpAddresses_Fqdn(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{})
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-fqdn-ingress-and-outbound-rules",
		Type:     "azure-arm",
		Template: injectRunnerIP(t, testBuilderAccFqdnIngressAndOutboundRules),
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil && buildCommand.ProcessState.ExitCode() != 0 {
				return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
			}
			logBytes, readErr := os.ReadFile(logfile)
			if readErr != nil {
				return fmt.Errorf("cannot read logfile %s: %w", logfile, readErr)
			}
			logStr := string(logBytes)
			if !strings.Contains(logStr, "Deleting Virtual Machine deployment") {
				return fmt.Errorf("cleanup-start marker missing in log. Logfile: %s", logfile)
			}
			if strings.Contains(logStr, "Error deleting resource. Please delete manually.") {
				return fmt.Errorf("cleanup-failure marker present in log. Logfile: %s", logfile)
			}
			return nil
		},
	})
}

func TestBuilderAcc_AllowedInboundIpAddresses_Literal(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{
		CheckVirtualNetworkName: true,
	})
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-allowed-inbound-ip-literal",
		Type:     "azure-arm",
		Template: injectRunnerIP(t, testBuilderAccAllowedInboundIpAddressesLiteral),
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil && buildCommand.ProcessState.ExitCode() != 0 {
				return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
			}
			logBytes, readErr := os.ReadFile(logfile)
			if readErr != nil {
				return fmt.Errorf("cannot read logfile %s: %w", logfile, readErr)
			}
			logStr := string(logBytes)
			if !strings.Contains(logStr, "Deleting Virtual Machine deployment") {
				return fmt.Errorf("cleanup-start marker missing in log. Logfile: %s", logfile)
			}
			if strings.Contains(logStr, "Error deleting resource. Please delete manually.") {
				return fmt.Errorf("cleanup-failure marker present in log. Logfile: %s", logfile)
			}
			return nil
		},
	})
}

func TestBuilderAcc_DenyOutboundIpAddresses(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{})
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-deny-outbound-ip",
		Type:     "azure-arm",
		Template: testBuilderAccDenyOutboundIP,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil && buildCommand.ProcessState.ExitCode() != 0 {
				return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
			}
			logBytes, readErr := os.ReadFile(logfile)
			if readErr != nil {
				return fmt.Errorf("cannot read logfile %s: %w", logfile, readErr)
			}
			logStr := string(logBytes)
			if !strings.Contains(logStr, "Deleting Virtual Machine deployment") {
				return fmt.Errorf("cleanup-start marker missing in log. Logfile: %s", logfile)
			}
			if strings.Contains(logStr, "Error deleting resource. Please delete manually.") {
				return fmt.Errorf("cleanup-failure marker present in log. Logfile: %s", logfile)
			}
			return nil
		},
	})
}

func TestBuilderAcc_DenyOutboundIpAddresses_ExistingVNet(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{
		CheckVirtualNetworkName: true,
	})
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-existing-vnet-deny-outbound-ip",
		Type:     "azure-arm",
		Template: testBuilderAccExistingVNetDenyOutboundIP,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil && buildCommand.ProcessState.ExitCode() != 0 {
				return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
			}
			logBytes, readErr := os.ReadFile(logfile)
			if readErr != nil {
				return fmt.Errorf("cannot read logfile %s: %w", logfile, readErr)
			}
			logStr := string(logBytes)
			if !strings.Contains(logStr, "Deleting Virtual Machine deployment") {
				return fmt.Errorf("cleanup-start marker missing in log. Logfile: %s", logfile)
			}
			if strings.Contains(logStr, "Error deleting resource. Please delete manually.") {
				return fmt.Errorf("cleanup-failure marker present in log. Logfile: %s", logfile)
			}
			return nil
		},
	})
}

func TestBuilderAcc_BuildSucceedsWithoutDenyOutboundIpAddresses(t *testing.T) {
	t.Parallel()
	common.CheckAcceptanceTestEnvVars(t, common.CheckAcceptanceTestEnvVarsParams{})
	acctest.TestPlugin(t, &acctest.PluginTestCase{
		Name:     "test-azure-build-succeeds-without-deny-outbound-ip-addresses",
		Type:     "azure-arm",
		Template: testBuilderAccBuildSucceedsWithoutDenyOutboundIpAddresses,
		Check: func(buildCommand *exec.Cmd, logfile string) error {
			if buildCommand.ProcessState != nil && buildCommand.ProcessState.ExitCode() != 0 {
				return fmt.Errorf("Bad exit code. Logfile: %s", logfile)
			}
			logBytes, readErr := os.ReadFile(logfile)
			if readErr != nil {
				return fmt.Errorf("cannot read logfile %s: %w", logfile, readErr)
			}
			logStr := string(logBytes)
			if !strings.Contains(logStr, "Deleting Virtual Machine deployment") {
				return fmt.Errorf("cleanup-start marker missing in log. Logfile: %s", logfile)
			}
			if strings.Contains(logStr, "Error deleting resource. Please delete manually.") {
				return fmt.Errorf("cleanup-failure marker present in log. Logfile: %s", logfile)
			}
			return nil
		},
	})
}
