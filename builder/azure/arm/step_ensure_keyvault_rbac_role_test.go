// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package arm

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/go-azure-sdk/resource-manager/authorization/2022-04-01/roleassignments"
	commonclient "github.com/hashicorp/packer-plugin-azure/builder/azure/common/client"
	"github.com/hashicorp/packer-plugin-azure/builder/azure/common/constants"
	"github.com/hashicorp/packer-plugin-sdk/multistep"
)

func newEnsureKeyVaultRBACRoleState() *multistep.BasicStateBag {
	state := new(multistep.BasicStateBag)
	state.Put(constants.ArmKeyVaultName, "test-key-vault")
	state.Put(constants.ArmSubscription, "00000000-0000-0000-0000-000000000001")
	state.Put(constants.ArmResourceGroupName, "test-key-vault-rg")
	return state
}

func TestStepEnsureKeyVaultRBACRoleCreatesVaultScopedSecretsOfficerAssignment(t *testing.T) {
	state := newEnsureKeyVaultRBACRoleState()
	var actualID roleassignments.ScopedRoleAssignmentId
	var actualInput roleassignments.RoleAssignmentCreateParameters
	step := &StepEnsureKeyVaultRBACRole{
		config: &Config{
			resolvedBuildPrincipalID: "00000000-0000-0000-0000-000000000002",
		},
		say:   func(string) {},
		error: func(error) {},
		create: func(_ context.Context, id roleassignments.ScopedRoleAssignmentId, input roleassignments.RoleAssignmentCreateParameters) error {
			actualID = id
			actualInput = input
			return nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected role assignment step to continue, got %v", action)
	}

	expectedScope := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test-key-vault-rg/providers/Microsoft.KeyVault/vaults/test-key-vault"
	if actualID.Scope != expectedScope {
		t.Fatalf("Expected vault-scoped role assignment %q, got %q", expectedScope, actualID.Scope)
	}
	if actualID.RoleAssignmentName != keyVaultRoleAssignmentName(expectedScope, "00000000-0000-0000-0000-000000000002") {
		t.Fatalf("Expected deterministic role assignment name, got %q", actualID.RoleAssignmentName)
	}
	if actualInput.Properties.PrincipalId != "00000000-0000-0000-0000-000000000002" {
		t.Fatalf("Expected token-derived build principal, got %q", actualInput.Properties.PrincipalId)
	}
	if actualInput.Properties.RoleDefinitionId != keyVaultRoleDefinitionID("00000000-0000-0000-0000-000000000001") {
		t.Fatalf("Expected Key Vault Secrets Officer role definition, got %q", actualInput.Properties.RoleDefinitionId)
	}
}

func TestStepEnsureKeyVaultRBACRoleUsesResolvedPrincipalOverConfiguredObjectID(t *testing.T) {
	state := newEnsureKeyVaultRBACRoleState()
	var actualPrincipalID string
	step := &StepEnsureKeyVaultRBACRole{
		config: &Config{
			ClientConfig:             commonclient.Config{ObjectID: "configured-but-not-token-principal"},
			resolvedBuildPrincipalID: "token-derived-principal",
		},
		say:   func(string) {},
		error: func(error) {},
		create: func(_ context.Context, _ roleassignments.ScopedRoleAssignmentId, input roleassignments.RoleAssignmentCreateParameters) error {
			actualPrincipalID = input.Properties.PrincipalId
			return nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected role assignment step to continue, got %v", action)
	}
	if actualPrincipalID != "token-derived-principal" {
		t.Fatalf("Expected token-derived principal, got %q", actualPrincipalID)
	}
}

func TestStepEnsureKeyVaultRBACRoleDoesNotAssignWhenDisabled(t *testing.T) {
	state := newEnsureKeyVaultRBACRoleState()
	assignRole := false
	createCalls := 0
	step := &StepEnsureKeyVaultRBACRole{
		config: &Config{BuildKeyVaultAssignRBACRole: &assignRole},
		say:    func(string) {},
		error:  func(error) {},
		create: func(context.Context, roleassignments.ScopedRoleAssignmentId, roleassignments.RoleAssignmentCreateParameters) error {
			createCalls++
			return nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected disabled role assignment step to continue, got %v", action)
	}
	if createCalls != 0 {
		t.Fatalf("Expected no role assignment when disabled, got %d calls", createCalls)
	}
}

func TestStepEnsureKeyVaultRBACRoleReportsAssignmentFailure(t *testing.T) {
	state := newEnsureKeyVaultRBACRoleState()
	var errors []string
	step := &StepEnsureKeyVaultRBACRole{
		config: &Config{resolvedBuildPrincipalID: "token-derived-principal"},
		say:    func(string) {},
		error: func(err error) {
			errors = append(errors, err.Error())
		},
		create: func(context.Context, roleassignments.ScopedRoleAssignmentId, roleassignments.RoleAssignmentCreateParameters) error {
			return fmt.Errorf("roleAssignments/write denied")
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionHalt {
		t.Fatalf("Expected role assignment failure to halt, got %v", action)
	}
	if len(errors) != 1 || !strings.Contains(errors[0], "build_key_vault_assign_rbac_role=false") {
		t.Fatalf("Expected actionable role assignment error, got %v", errors)
	}
}

func TestKeyVaultRoleAssignmentNameIsStableAndDistinctByPrincipal(t *testing.T) {
	vaultID := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test-key-vault-rg/providers/Microsoft.KeyVault/vaults/test-key-vault"
	first := keyVaultRoleAssignmentName(vaultID, "00000000-0000-0000-0000-000000000002")
	if first != keyVaultRoleAssignmentName(strings.ToUpper(vaultID), "00000000-0000-0000-0000-000000000002") {
		t.Fatal("Expected role assignment name to be case-insensitive")
	}
	if first == keyVaultRoleAssignmentName(vaultID, "00000000-0000-0000-0000-000000000003") {
		t.Fatal("Expected role assignment names for different principals to differ")
	}
	if !strings.Contains(first, "-") || len(first) != 36 {
		t.Fatalf("Expected a UUID-formatted role assignment name, got %q", first)
	}
}
