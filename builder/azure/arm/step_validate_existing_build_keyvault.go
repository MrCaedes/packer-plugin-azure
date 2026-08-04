// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package arm

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/commonids"
	"github.com/hashicorp/go-azure-sdk/resource-manager/keyvault/2023-07-01/vaults"
	"github.com/hashicorp/packer-plugin-azure/builder/azure/common/constants"
	"github.com/hashicorp/packer-plugin-sdk/multistep"
	packersdk "github.com/hashicorp/packer-plugin-sdk/packer"
)

type StepValidateExistingBuildKeyVault struct {
	config   *Config
	client   *AzureClient
	getVault func(ctx context.Context, subscriptionID, resourceGroupName, keyVaultName string) (*vaults.Vault, error)
	say      func(message string)
	error    func(error)
}

func NewStepValidateExistingBuildKeyVault(client *AzureClient, ui packersdk.Ui, config *Config) *StepValidateExistingBuildKeyVault {
	step := &StepValidateExistingBuildKeyVault{
		config: config,
		client: client,
		say:    ui.Say,
		error:  func(err error) { ui.Error(err.Error()) },
	}
	step.getVault = step.getExistingBuildKeyVault
	return step
}

func (s *StepValidateExistingBuildKeyVault) getExistingBuildKeyVault(ctx context.Context, subscriptionID, resourceGroupName, keyVaultName string) (*vaults.Vault, error) {
	if s.client == nil {
		return nil, fmt.Errorf("Azure Key Vault client is not configured")
	}

	result, err := s.client.VaultsClient.Get(ctx, commonids.NewKeyVaultID(subscriptionID, resourceGroupName, keyVaultName))
	if err != nil {
		return nil, err
	}
	return result.Model, nil
}

func (s *StepValidateExistingBuildKeyVault) halt(state multistep.StateBag, err error) multistep.StepAction {
	state.Put(constants.Error, err)
	s.error(err)
	return multistep.ActionHalt
}

func (s *StepValidateExistingBuildKeyVault) Run(ctx context.Context, state multistep.StateBag) multistep.StepAction {
	isExistingKeyVault, ok := state.GetOk(constants.ArmIsExistingKeyVault)
	if !ok || !isExistingKeyVault.(bool) {
		return s.halt(state, fmt.Errorf("refusing to validate build Key Vault because it is not marked as existing"))
	}

	keyVaultName := state.Get(constants.ArmKeyVaultName).(string)
	subscriptionID := state.Get(constants.ArmSubscription).(string)
	resourceGroupName := state.Get(constants.ArmResourceGroupName).(string)
	buildLocation := state.Get(constants.ArmLocation).(string)

	lookupTimeout := 15 * time.Minute
	if s.client != nil && s.client.PollingDuration > 0 {
		lookupTimeout = s.client.PollingDuration
	}
	lookupContext, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	s.say("Validating the existing build Key Vault...")
	vault, err := s.getVault(lookupContext, subscriptionID, resourceGroupName, keyVaultName)
	if err != nil {
		return s.halt(state, fmt.Errorf("failed to read existing build Key Vault %q in resource group %q: %w. Verify the vault name, resource group, and subscription are correct, and that the Packer identity has Microsoft.KeyVault/vaults/read at the vault scope or above", keyVaultName, resourceGroupName, err))
	}
	if vault == nil {
		return s.halt(state, fmt.Errorf("Azure did not return the existing build Key Vault %q in resource group %q", keyVaultName, resourceGroupName))
	}
	if vault.Properties.EnabledForDeployment == nil || !*vault.Properties.EnabledForDeployment {
		return s.halt(state, fmt.Errorf("existing build Key Vault %q must have enabledForDeployment=true so the build VM can retrieve its certificate", keyVaultName))
	}
	if vault.Location == nil || normalizeAzureRegion(*vault.Location) != normalizeAzureRegion(buildLocation) {
		vaultLocation := ""
		if vault.Location != nil {
			vaultLocation = *vault.Location
		}
		return s.halt(state, fmt.Errorf("existing build Key Vault %q is in location %q but the build VM is in %q; Azure requires them to use the same location", keyVaultName, vaultLocation, buildLocation))
	}
	if s.config.BuildKeyVaultEnableRBACAuthorization && (vault.Properties.EnableRbacAuthorization == nil || !*vault.Properties.EnableRbacAuthorization) {
		return s.halt(state, fmt.Errorf("build_key_vault_enable_rbac_authorization is true but existing build Key Vault %q does not use RBAC authorization. Packer will not change an existing vault's authorization model because doing so invalidates its access policies", keyVaultName))
	}
	if !s.config.BuildKeyVaultEnableRBACAuthorization && s.config.BuildKeyVaultDeleteSecret &&
		vault.Properties.EnableRbacAuthorization != nil && *vault.Properties.EnableRbacAuthorization {
		s.say(fmt.Sprintf("Warning: existing build Key Vault %q uses RBAC authorization but build_key_vault_enable_rbac_authorization is false. Certificate secret cleanup will fail with a 403 unless the Packer identity holds a data-plane role with the Microsoft.KeyVault/vaults/secrets/delete action on the vault", keyVaultName))
	}

	if s.config.BuildKeyVaultDeleteSecret {
		if vault.Properties.VaultUri == nil {
			return s.halt(state, fmt.Errorf("Azure did not return a data-plane URI for existing build Key Vault %q", keyVaultName))
		}
		endpoint, err := keyVaultEndpointFromURI(*vault.Properties.VaultUri)
		if err != nil {
			return s.halt(state, fmt.Errorf("existing build Key Vault %q has an invalid data-plane URI: %w", keyVaultName, err))
		}
		state.Put(constants.ArmKeyVaultDataPlaneEndpoint, endpoint)
	}

	return multistep.ActionContinue
}

func (s *StepValidateExistingBuildKeyVault) Cleanup(multistep.StateBag) {}
