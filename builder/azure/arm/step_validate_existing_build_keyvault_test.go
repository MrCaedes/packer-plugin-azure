// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package arm

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-azure-sdk/resource-manager/keyvault/2023-07-01/vaults"
	"github.com/hashicorp/packer-plugin-azure/builder/azure/common/constants"
	"github.com/hashicorp/packer-plugin-sdk/multistep"
	packersdk "github.com/hashicorp/packer-plugin-sdk/packer"
)

func newExistingBuildKeyVaultValidationState() *multistep.BasicStateBag {
	state := new(multistep.BasicStateBag)
	state.Put(constants.ArmIsExistingKeyVault, true)
	state.Put(constants.ArmKeyVaultName, "test-key-vault")
	state.Put(constants.ArmSubscription, "00000000-0000-0000-0000-000000000001")
	state.Put(constants.ArmResourceGroupName, "test-key-vault-rg")
	state.Put(constants.ArmLocation, "West Europe")
	return state
}

func validExistingBuildKeyVault() *vaults.Vault {
	enabledForDeployment := true
	return &vaults.Vault{
		Location: stringPtr("westeurope"),
		Properties: vaults.VaultProperties{
			EnabledForDeployment: &enabledForDeployment,
			VaultUri:             stringPtr("https://test-key-vault.vault.azure.net/"),
		},
	}
}

func stringPtr(value string) *string {
	return &value
}

func TestStepValidateExistingBuildKeyVaultAcceptsCompatibleVault(t *testing.T) {
	state := newExistingBuildKeyVaultValidationState()
	var actualSubscriptionID, actualResourceGroupName, actualKeyVaultName string
	step := &StepValidateExistingBuildKeyVault{
		config: &Config{},
		client: &AzureClient{PollingDuration: time.Minute},
		say:    func(string) {},
		error:  func(error) {},
		getVault: func(ctx context.Context, subscriptionID, resourceGroupName, keyVaultName string) (*vaults.Vault, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("Expected Key Vault lookup context to have a deadline")
			}
			actualSubscriptionID = subscriptionID
			actualResourceGroupName = resourceGroupName
			actualKeyVaultName = keyVaultName
			return validExistingBuildKeyVault(), nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected compatible existing Key Vault to continue, got %v", action)
	}
	if actualSubscriptionID != "00000000-0000-0000-0000-000000000001" || actualResourceGroupName != "test-key-vault-rg" || actualKeyVaultName != "test-key-vault" {
		t.Fatalf("Unexpected Key Vault lookup target: %q/%q/%q", actualSubscriptionID, actualResourceGroupName, actualKeyVaultName)
	}
	if _, ok := state.GetOk(constants.ArmKeyVaultDataPlaneEndpoint); ok {
		t.Fatal("Expected no data-plane endpoint cache when secret cleanup is disabled")
	}
}

func TestStepValidateExistingBuildKeyVaultCachesEndpointForSecretCleanup(t *testing.T) {
	state := newExistingBuildKeyVaultValidationState()
	step := &StepValidateExistingBuildKeyVault{
		config: &Config{BuildKeyVaultDeleteSecret: true},
		say:    func(string) {},
		error:  func(error) {},
		getVault: func(context.Context, string, string, string) (*vaults.Vault, error) {
			return validExistingBuildKeyVault(), nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected compatible existing Key Vault to continue, got %v", action)
	}
	endpoint, ok := state.GetOk(constants.ArmKeyVaultDataPlaneEndpoint)
	if !ok || endpoint.(string) != "https://test-key-vault.vault.azure.net" {
		t.Fatalf("Expected cached Key Vault endpoint, got %v", endpoint)
	}
}

func TestStepValidateExistingBuildKeyVaultRejectsIneligibleVault(t *testing.T) {
	falseValue := false
	trueValue := true
	testCases := []struct {
		name     string
		config   *Config
		vault    *vaults.Vault
		expected string
	}{
		{
			name:     "missing vault model",
			config:   &Config{},
			vault:    nil,
			expected: "did not return",
		},
		{
			name:   "deployment disabled",
			config: &Config{},
			vault: &vaults.Vault{
				Location: stringPtr("West Europe"),
				Properties: vaults.VaultProperties{
					EnabledForDeployment: &falseValue,
				},
			},
			expected: "enabledForDeployment=true",
		},
		{
			name:   "different location",
			config: &Config{},
			vault: &vaults.Vault{
				Location: stringPtr("UK South"),
				Properties: vaults.VaultProperties{
					EnabledForDeployment: &trueValue,
				},
			},
			expected: "same location",
		},
		{
			name:   "RBAC requested for access-policy vault",
			config: &Config{BuildKeyVaultEnableRBACAuthorization: true},
			vault: &vaults.Vault{
				Location: stringPtr("West Europe"),
				Properties: vaults.VaultProperties{
					EnabledForDeployment:    &trueValue,
					EnableRbacAuthorization: &falseValue,
				},
			},
			expected: "does not use RBAC authorization",
		},
		{
			name:   "RBAC requested without property",
			config: &Config{BuildKeyVaultEnableRBACAuthorization: true},
			vault: &vaults.Vault{
				Location: stringPtr("West Europe"),
				Properties: vaults.VaultProperties{
					EnabledForDeployment: &trueValue,
				},
			},
			expected: "does not use RBAC authorization",
		},
		{
			name:   "cleanup requested without endpoint",
			config: &Config{BuildKeyVaultDeleteSecret: true},
			vault: &vaults.Vault{
				Location: stringPtr("West Europe"),
				Properties: vaults.VaultProperties{
					EnabledForDeployment: &trueValue,
				},
			},
			expected: "data-plane URI",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			state := newExistingBuildKeyVaultValidationState()
			var errors []string
			step := &StepValidateExistingBuildKeyVault{
				config: testCase.config,
				say:    func(string) {},
				error: func(err error) {
					errors = append(errors, err.Error())
				},
				getVault: func(context.Context, string, string, string) (*vaults.Vault, error) {
					return testCase.vault, nil
				},
			}

			if action := step.Run(context.Background(), state); action != multistep.ActionHalt {
				t.Fatalf("Expected ineligible existing Key Vault to halt, got %v", action)
			}
			if len(errors) != 1 || !strings.Contains(errors[0], testCase.expected) {
				t.Fatalf("Expected error containing %q, got %v", testCase.expected, errors)
			}
		})
	}
}

func TestStepValidateExistingBuildKeyVaultReportsReadFailure(t *testing.T) {
	state := newExistingBuildKeyVaultValidationState()
	var errors []string
	step := &StepValidateExistingBuildKeyVault{
		config: &Config{},
		say:    func(string) {},
		error: func(err error) {
			errors = append(errors, err.Error())
		},
		getVault: func(context.Context, string, string, string) (*vaults.Vault, error) {
			return nil, fmt.Errorf("not found")
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionHalt {
		t.Fatalf("Expected Key Vault read failure to halt, got %v", action)
	}
	if len(errors) != 1 || !strings.Contains(errors[0], "Microsoft.KeyVault/vaults/read") {
		t.Fatalf("Expected read-permission diagnostic, got %v", errors)
	}
}

func TestStepValidateExistingBuildKeyVaultRequiresExistingState(t *testing.T) {
	state := newExistingBuildKeyVaultValidationState()
	state.Put(constants.ArmIsExistingKeyVault, false)
	getCalls := 0
	step := &StepValidateExistingBuildKeyVault{
		config: &Config{},
		say:    func(string) {},
		error:  func(error) {},
		getVault: func(context.Context, string, string, string) (*vaults.Vault, error) {
			getCalls++
			return validExistingBuildKeyVault(), nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionHalt {
		t.Fatalf("Expected non-existing state to halt, got %v", action)
	}
	if getCalls != 0 {
		t.Fatalf("Expected no Key Vault lookup for non-existing state, got %d", getCalls)
	}
}

func TestExistingBuildKeyVaultPreflightStepsOrder(t *testing.T) {
	assignRole := false
	testCases := []struct {
		name     string
		config   *Config
		expected []string
	}{
		{
			name:     "RBAC with assignment",
			config:   &Config{BuildKeyVaultEnableRBACAuthorization: true, BuildKeyVaultDeleteSecret: true},
			expected: []string{"validate", "assign"},
		},
		{
			name:     "RBAC without assignment",
			config:   &Config{BuildKeyVaultEnableRBACAuthorization: true, BuildKeyVaultDeleteSecret: true, BuildKeyVaultAssignRBACRole: &assignRole},
			expected: []string{"validate"},
		},
		{
			name:     "RBAC without secret cleanup needs no data-plane role",
			config:   &Config{BuildKeyVaultEnableRBACAuthorization: true},
			expected: []string{"validate"},
		},
		{
			name:     "legacy access policy vault",
			config:   &Config{},
			expected: []string{"validate"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			steps := existingBuildKeyVaultPreflightSteps(nil, &packersdk.BasicUi{}, testCase.config)
			if len(steps) != len(testCase.expected) {
				t.Fatalf("Expected %d preflight steps, got %d", len(testCase.expected), len(steps))
			}
			for index, expected := range testCase.expected {
				switch expected {
				case "validate":
					if _, ok := steps[index].(*StepValidateExistingBuildKeyVault); !ok {
						t.Fatalf("Expected validation step at index %d, got %T", index, steps[index])
					}
				case "assign":
					if _, ok := steps[index].(*StepEnsureKeyVaultRBACRole); !ok {
						t.Fatalf("Expected role-assignment step at index %d, got %T", index, steps[index])
					}
				}
			}
		})
	}
}
