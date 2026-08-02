// Copyright IBM Corp. 2013, 2025
// SPDX-License-Identifier: MPL-2.0

package arm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/commonids"
	"github.com/hashicorp/go-azure-sdk/resource-manager/keyvault/2023-07-01/secrets"
	sdkclient "github.com/hashicorp/go-azure-sdk/sdk/client"
	"github.com/hashicorp/go-azure-sdk/sdk/client/dataplane"
	commonclient "github.com/hashicorp/packer-plugin-azure/builder/azure/common/client"
	"github.com/hashicorp/packer-plugin-azure/builder/azure/common/constants"
	"github.com/hashicorp/packer-plugin-sdk/multistep"
	packersdk "github.com/hashicorp/packer-plugin-sdk/packer"
)

const keyVaultSecretsAPIVersion = "7.5"

type StepCertificateInKeyVault struct {
	config               *Config
	client               *AzureClient
	set                  func(ctx context.Context, id secrets.SecretId) error
	deleteSecret         func(ctx context.Context, secretURI, secretName string) error
	getVaultURI          func(ctx context.Context, subscriptionID, resourceGroupName, keyVaultName string) (string, error)
	say                  func(message string)
	error                func(e error)
	certificate          string
	expirationTime       time.Duration
	secretWriteAttempted bool
	keyVaultEndpoint     string
}

func NewStepCertificateInKeyVault(client *AzureClient, ui packersdk.Ui, config *Config, certificate string, expirationTime time.Duration) *StepCertificateInKeyVault {
	var step = &StepCertificateInKeyVault{
		client:         client,
		config:         config,
		say:            func(message string) { ui.Say(message) },
		error:          func(e error) { ui.Error(e.Error()) },
		certificate:    certificate,
		expirationTime: expirationTime,
	}

	step.set = step.setCertificate
	step.deleteSecret = step.deleteCertificate
	step.getVaultURI = step.getKeyVaultURI
	return step
}

func (s *StepCertificateInKeyVault) setCertificate(ctx context.Context, id secrets.SecretId) error {
	secret := secrets.SecretCreateOrUpdateParameters{
		Properties: secrets.SecretProperties{
			Value: &s.certificate,
		},
	}
	if s.expirationTime != 0 {
		// Secrets API expects expiration time in seconds since the start of the unix epoch
		// https://learn.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets?pivots=deployment-language-bicep#secretattributes
		expirationTimeUnix := time.Now().Add(s.expirationTime).Unix()
		secret.Properties.Attributes = &secrets.Attributes{
			Exp: &expirationTimeUnix,
		}
	}
	pollingContext, cancel := context.WithTimeout(ctx, s.client.PollingDuration)
	defer cancel()

	_, err := s.client.SecretsClient.CreateOrUpdate(pollingContext, id, secret)
	if err != nil {
		return err
	}

	return nil
}

func (s *StepCertificateInKeyVault) getKeyVaultURI(ctx context.Context, subscriptionID, resourceGroupName, keyVaultName string) (string, error) {
	if s.client == nil {
		return "", fmt.Errorf("Azure client is not configured")
	}

	result, err := s.client.VaultsClient.Get(ctx, commonids.KeyVaultId{
		SubscriptionId:    subscriptionID,
		ResourceGroupName: resourceGroupName,
		VaultName:         keyVaultName,
	})
	if err != nil {
		return "", fmt.Errorf("getting Key Vault endpoint: %w", err)
	}
	if result.Model == nil || result.Model.Properties.VaultUri == nil || *result.Model.Properties.VaultUri == "" {
		return "", fmt.Errorf("Azure did not return a Key Vault data-plane URI")
	}

	return *result.Model.Properties.VaultUri, nil
}

func (s *StepCertificateInKeyVault) deleteCertificate(ctx context.Context, keyVaultURI, secretName string) error {
	vaultURI, err := keyVaultEndpointFromURI(keyVaultURI)
	if err != nil {
		return err
	}

	keyVaultClient, err := dataplane.NewClient(vaultURI, "secrets", keyVaultSecretsAPIVersion)
	if err != nil {
		return fmt.Errorf("creating Key Vault data-plane client: %w", err)
	}

	cloud := s.config.ClientConfig.CloudEnvironment()
	if cloud == nil {
		return fmt.Errorf("Azure cloud environment is not configured")
	}

	authOptions := commonclient.AzureAuthOptions{
		AuthType:           s.config.ClientConfig.AuthType(),
		ClientID:           s.config.ClientConfig.ClientID,
		ClientSecret:       s.config.ClientConfig.ClientSecret,
		ClientJWT:          s.config.ClientConfig.ClientJWT,
		ClientCertPath:     s.config.ClientConfig.ClientCertPath,
		ClientCertPassword: s.config.ClientConfig.ClientCertPassword,
		TenantID:           s.config.ClientConfig.TenantID,
		SubscriptionID:     s.config.ClientConfig.SubscriptionID,
		OidcRequestUrl:     s.config.ClientConfig.OidcRequestURL,
		OidcRequestToken:   s.config.ClientConfig.OidcRequestToken,
	}
	authorizer, err := commonclient.BuildKeyVaultAuthorizer(ctx, authOptions, *cloud)
	if err != nil {
		return fmt.Errorf("building Key Vault authorizer: %w", err)
	}
	keyVaultClient.SetAuthorizer(authorizer)

	return deleteKeyVaultSecret(ctx, keyVaultClient, secretName)
}

func deleteKeyVaultSecret(ctx context.Context, keyVaultClient sdkclient.BaseClient, secretName string) error {
	request, err := keyVaultClient.NewRequest(ctx, sdkclient.RequestOptions{
		ContentType:         "application/json; charset=utf-8",
		ExpectedStatusCodes: []int{http.StatusOK, http.StatusNotFound},
		HttpMethod:          http.MethodDelete,
		Path:                fmt.Sprintf("/secrets/%s", url.PathEscape(secretName)),
	})
	if err != nil {
		return fmt.Errorf("creating Key Vault secret delete request: %w", err)
	}

	response, err := request.Execute(ctx)
	if response != nil && response.Response != nil && response.Body != nil {
		defer func() {
			_ = response.Body.Close()
		}()
	}
	if err != nil {
		return fmt.Errorf("deleting Key Vault secret: %w", err)
	}

	return nil
}

func keyVaultEndpointFromURI(keyVaultURI string) (string, error) {
	parsedKeyVaultURI, err := url.Parse(keyVaultURI)
	if err != nil {
		return "", fmt.Errorf("parsing Key Vault URI: %w", err)
	}
	if parsedKeyVaultURI.Scheme != "https" || parsedKeyVaultURI.Host == "" {
		return "", fmt.Errorf("Key Vault URI must contain an HTTPS endpoint")
	}

	return (&url.URL{
		Scheme: parsedKeyVaultURI.Scheme,
		Host:   parsedKeyVaultURI.Host,
	}).String(), nil
}

func (s *StepCertificateInKeyVault) Run(ctx context.Context, state multistep.StateBag) multistep.StepAction {
	s.say("Setting the certificate in the KeyVault...")
	var keyVaultName = state.Get(constants.ArmKeyVaultName).(string)
	var subscriptionId = state.Get(constants.ArmSubscription).(string)
	var resourceGroupName = state.Get(constants.ArmResourceGroupName).(string)
	var keyVaultSecretName = state.Get(constants.ArmKeyVaultSecretName).(string)
	id := secrets.NewSecretID(subscriptionId, resourceGroupName, keyVaultName, keyVaultSecretName)
	s.secretWriteAttempted = false
	s.keyVaultEndpoint = ""
	if s.config.BuildKeyVaultDeleteSecret && s.config.BuildKeyVaultName != "" {
		isExistingKeyVault, ok := state.GetOk(constants.ArmIsExistingKeyVault)
		if !ok || !isExistingKeyVault.(bool) {
			s.error(fmt.Errorf("refusing to create Key Vault certificate secret because the configured build Key Vault is not marked as existing"))
			return multistep.ActionHalt
		}
		if s.config.tmpKeyVaultSecretName == "" || keyVaultSecretName != s.config.tmpKeyVaultSecretName {
			s.error(fmt.Errorf("refusing to create Key Vault secret %q because cleanup requires the generated run-scoped secret name", keyVaultSecretName))
			return multistep.ActionHalt
		}

		if endpoint, ok := state.GetOk(constants.ArmKeyVaultDataPlaneEndpoint); ok {
			s.keyVaultEndpoint = endpoint.(string)
		} else {
			getVaultURI := s.getVaultURI
			if getVaultURI == nil {
				getVaultURI = s.getKeyVaultURI
			}
			lookupTimeout := 15 * time.Minute
			if s.client != nil && s.client.PollingDuration > 0 {
				lookupTimeout = s.client.PollingDuration
			}
			lookupContext, cancel := context.WithTimeout(ctx, lookupTimeout)
			defer cancel()

			vaultURI, err := getVaultURI(lookupContext, subscriptionId, resourceGroupName, keyVaultName)
			if err != nil {
				s.error(fmt.Errorf("failed to resolve the Key Vault data-plane URI before creating certificate secret %q: %s", keyVaultSecretName, err))
				return multistep.ActionHalt
			}
			keyVaultEndpoint, err := keyVaultEndpointFromURI(vaultURI)
			if err != nil {
				s.error(fmt.Errorf("failed to validate the Key Vault data-plane URI before creating certificate secret %q: %s", keyVaultSecretName, err))
				return multistep.ActionHalt
			}
			s.keyVaultEndpoint = keyVaultEndpoint
		}
	}

	s.secretWriteAttempted = true
	err := s.set(ctx, id)
	if err != nil {
		s.error(fmt.Errorf("Error setting winrm cert in custom keyvault: %s", err))
		return multistep.ActionHalt
	}
	return multistep.ActionContinue
}

func (s *StepCertificateInKeyVault) Cleanup(state multistep.StateBag) {
	if !s.config.BuildKeyVaultDeleteSecret || !s.secretWriteAttempted || s.config.BuildKeyVaultName == "" {
		return
	}

	isExistingKeyVault, ok := state.GetOk(constants.ArmIsExistingKeyVault)
	if !ok || !isExistingKeyVault.(bool) {
		return
	}

	keyVaultSecretName := state.Get(constants.ArmKeyVaultSecretName).(string)
	cleanupTimeout := 15 * time.Minute
	if s.client != nil && s.client.PollingDuration > 0 {
		cleanupTimeout = s.client.PollingDuration
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	if s.keyVaultEndpoint == "" {
		s.reportCleanupFailure(state, fmt.Errorf("Packer could not delete Key Vault secret %q because its data-plane endpoint was not resolved before the write; delete it manually", keyVaultSecretName))
		return
	}

	s.say("Deleting the Packer certificate secret from the KeyVault...")
	if err := s.deleteSecret(ctx, s.keyVaultEndpoint, keyVaultSecretName); err != nil {
		s.reportCleanupFailure(state, fmt.Errorf("failed to delete Packer certificate secret %q from the Key Vault during cleanup: %w; delete it manually", keyVaultSecretName, err))
	}
}

func (s *StepCertificateInKeyVault) reportCleanupFailure(state multistep.StateBag, err error) {
	s.error(err)

	if _, hasBuildError := state.GetOk(constants.Error); hasBuildError {
		return
	}
	if _, cancelled := state.GetOk(multistep.StateCancelled); cancelled {
		return
	}
	if _, halted := state.GetOk(multistep.StateHalted); halted {
		return
	}

	state.Put(constants.Error, err)
}
