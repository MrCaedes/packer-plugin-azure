// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package arm

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/commonids"
	"github.com/hashicorp/go-azure-sdk/resource-manager/authorization/2022-04-01/roleassignments"
	"github.com/hashicorp/packer-plugin-azure/builder/azure/common/constants"
	"github.com/hashicorp/packer-plugin-sdk/multistep"
	packersdk "github.com/hashicorp/packer-plugin-sdk/packer"
)

const keyVaultSecretsOfficerRoleDefinitionID = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"

type StepEnsureKeyVaultRBACRole struct {
	config *Config
	client *AzureClient
	create func(ctx context.Context, id roleassignments.ScopedRoleAssignmentId, input roleassignments.RoleAssignmentCreateParameters) error
	say    func(message string)
	error  func(error)
}

func NewStepEnsureKeyVaultRBACRole(client *AzureClient, ui packersdk.Ui, config *Config) *StepEnsureKeyVaultRBACRole {
	step := &StepEnsureKeyVaultRBACRole{
		config: config,
		client: client,
		say:    ui.Say,
		error:  func(err error) { ui.Error(err.Error()) },
	}
	step.create = step.createRoleAssignment
	return step
}

func (s *StepEnsureKeyVaultRBACRole) createRoleAssignment(ctx context.Context, id roleassignments.ScopedRoleAssignmentId, input roleassignments.RoleAssignmentCreateParameters) error {
	if s.client == nil || s.client.RoleAssignmentsClient.Client == nil {
		return fmt.Errorf("Azure role assignments client is not configured")
	}

	result, err := s.client.RoleAssignmentsClient.Create(ctx, id, input)
	if err == nil {
		return nil
	}

	if isRoleAssignmentAlreadyExists(result, err) {
		return nil
	}

	return err
}

func isRoleAssignmentAlreadyExists(result roleassignments.CreateOperationResponse, err error) bool {
	if err == nil {
		return false
	}

	if result.OData != nil && result.OData.Error != nil && result.OData.Error.Code != nil && strings.EqualFold(*result.OData.Error.Code, "RoleAssignmentExists") {
		return true
	}

	return strings.Contains(strings.ToLower(err.Error()), "roleassignmentexists")
}

func (s *StepEnsureKeyVaultRBACRole) Run(ctx context.Context, state multistep.StateBag) multistep.StepAction {
	if !s.config.shouldAssignBuildKeyVaultRBACRole() {
		return multistep.ActionContinue
	}

	keyVaultName := state.Get(constants.ArmKeyVaultName).(string)
	subscriptionID := state.Get(constants.ArmSubscription).(string)
	resourceGroupName := state.Get(constants.ArmResourceGroupName).(string)
	principalID := s.config.buildKeyVaultRBACPrincipalID()
	if principalID == "" {
		s.error(fmt.Errorf("cannot grant Key Vault Secrets Officer because the Packer build identity object ID is unavailable"))
		return multistep.ActionHalt
	}

	keyVaultID := commonids.NewKeyVaultID(subscriptionID, resourceGroupName, keyVaultName).ID()
	roleAssignmentID := roleassignments.NewScopedRoleAssignmentID(keyVaultID, keyVaultRoleAssignmentName(keyVaultID, principalID))
	input := roleassignments.RoleAssignmentCreateParameters{
		Properties: roleassignments.RoleAssignmentProperties{
			PrincipalId:      principalID,
			RoleDefinitionId: keyVaultRoleDefinitionID(subscriptionID),
		},
	}

	s.say("Ensuring Key Vault Secrets Officer role assignment on the existing build Key Vault...")
	if err := s.create(ctx, roleAssignmentID, input); err != nil {
		s.error(fmt.Errorf("failed to grant Key Vault Secrets Officer to the Packer build identity: %w. Set build_key_vault_assign_rbac_role=false only after granting Key Vault Secrets Officer, or equivalent secret data actions, at the vault scope or above; Packer also needs Microsoft.KeyVault/vaults/secrets/write to upload the certificate", err))
		return multistep.ActionHalt
	}

	return multistep.ActionContinue
}

func (s *StepEnsureKeyVaultRBACRole) Cleanup(multistep.StateBag) {}

func keyVaultRoleDefinitionID(subscriptionID string) string {
	return fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", subscriptionID, keyVaultSecretsOfficerRoleDefinitionID)
}

func keyVaultRoleAssignmentName(keyVaultID, principalID string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(keyVaultID)) + "\n" + strings.ToLower(strings.TrimSpace(principalID)) + "\n" + keyVaultSecretsOfficerRoleDefinitionID))
	digest[6] = digest[6]&0x0f | 0x50
	digest[8] = digest[8]&0x3f | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}
