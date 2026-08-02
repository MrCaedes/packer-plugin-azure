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

func (s *StepValidateExistingBuildKeyVault) Run(ctx context.Context, state multistep.StateBag) multistep.StepAction {
	isExistingKeyVault, ok := state.GetOk(constants.ArmIsExistingKeyVault)
	if !ok || !isExistingKeyVault.(bool) {
		s.error(fmt.Errorf("refusing to validate build Key Vault because it is not marked as existing"))
		return multistep.ActionHalt
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
		s.error(fmt.Errorf("failed to read existing build Key Vault %q in resource group %q: %w. The Packer identity requires Microsoft.KeyVault/vaults/read at the vault scope or above", keyVaultName, resourceGroupName, err))
		return multistep.ActionHalt
	}
	if vault == nil {
		s.error(fmt.Errorf("Azure did not return the existing build Key Vault %q in resource group %q", keyVaultName, resourceGroupName))
		return multistep.ActionHalt
	}
	if vault.Properties.EnabledForDeployment == nil || !*vault.Properties.EnabledForDeployment {
		s.error(fmt.Errorf("existing build Key Vault %q must have enabledForDeployment=true so the build VM can retrieve its certificate", keyVaultName))
		return multistep.ActionHalt
	}
	if vault.Location == nil || normalizeAzureRegion(*vault.Location) != normalizeAzureRegion(buildLocation) {
		vaultLocation := ""
		if vault.Location != nil {
			vaultLocation = *vault.Location
		}
		s.error(fmt.Errorf("existing build Key Vault %q is in location %q but the build VM is in %q; Azure requires them to use the same location", keyVaultName, vaultLocation, buildLocation))
		return multistep.ActionHalt
	}
	if s.config.BuildKeyVaultEnableRBACAuthorization && (vault.Properties.EnableRbacAuthorization == nil || !*vault.Properties.EnableRbacAuthorization) {
		s.error(fmt.Errorf("build_key_vault_enable_rbac_authorization is true but existing build Key Vault %q does not use RBAC authorization. Packer will not change an existing vault's authorization model because doing so invalidates its access policies", keyVaultName))
		return multistep.ActionHalt
	}

	if s.config.BuildKeyVaultDeleteSecret {
		if vault.Properties.VaultUri == nil {
			s.error(fmt.Errorf("Azure did not return a data-plane URI for existing build Key Vault %q", keyVaultName))
			return multistep.ActionHalt
		}
		endpoint, err := keyVaultEndpointFromURI(*vault.Properties.VaultUri)
		if err != nil {
			s.error(fmt.Errorf("existing build Key Vault %q has an invalid data-plane URI: %w", keyVaultName, err))
			return multistep.ActionHalt
		}
		state.Put(constants.ArmKeyVaultDataPlaneEndpoint, endpoint)
	}

	return multistep.ActionContinue
}

func (s *StepValidateExistingBuildKeyVault) Cleanup(multistep.StateBag) {}
