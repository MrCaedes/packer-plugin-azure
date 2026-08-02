// Copyright IBM Corp. 2013, 2025
// SPDX-License-Identifier: MPL-2.0

package arm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-azure-sdk/resource-manager/keyvault/2023-07-01/secrets"
	"github.com/hashicorp/go-azure-sdk/sdk/client/dataplane"
	"github.com/hashicorp/packer-plugin-azure/builder/azure/common/constants"
	"github.com/hashicorp/packer-plugin-sdk/multistep"
)

func newCertificateInKeyVaultState() *multistep.BasicStateBag {
	state := new(multistep.BasicStateBag)
	state.Put(constants.ArmKeyVaultName, "testKeyVaultName")
	state.Put(constants.ArmSubscription, "testSubscription")
	state.Put(constants.ArmResourceGroupName, "testResourceGroupName")
	state.Put(constants.ArmKeyVaultSecretName, "testKeyVaultSecretName")
	state.Put(constants.ArmIsExistingKeyVault, true)
	return state
}

func TestNewStepCertificateInKeyVault(t *testing.T) {
	state := newCertificateInKeyVaultState()

	config := &Config{
		winrmCertificate: "testCertificateString",
	}

	certKVStep := &StepCertificateInKeyVault{
		say:         func(message string) {},
		error:       func(e error) {},
		set:         func(ctx context.Context, id secrets.SecretId) error { return nil },
		config:      config,
		certificate: config.winrmCertificate}

	stepAction := certKVStep.Run(context.TODO(), state)

	if stepAction == multistep.ActionHalt {
		t.Fatalf("step should have succeeded.")
	}

}

func TestNewStepCertificateInKeyVault_error(t *testing.T) {
	state := newCertificateInKeyVaultState()

	config := &Config{
		winrmCertificate: "testCertificateString",
	}

	certKVStep := &StepCertificateInKeyVault{
		say:         func(message string) {},
		error:       func(e error) {},
		set:         func(ctx context.Context, id secrets.SecretId) error { return fmt.Errorf("Unit test fail") },
		config:      config,
		certificate: config.winrmCertificate}

	stepAction := certKVStep.Run(context.TODO(), state)

	if stepAction != multistep.ActionHalt {
		t.Fatalf("step should have failed.")
	}
}

func TestStepCertificateInKeyVaultCleanupDoesNotDeleteWithoutOptIn(t *testing.T) {
	state := newCertificateInKeyVaultState()
	deleteCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName: "testKeyVaultName",
		},
		say:   func(string) {},
		error: func(error) {},
		deleteSecret: func(context.Context, string, string) error {
			deleteCalls++
			return nil
		},
	}
	step.secretWriteAttempted = true
	step.keyVaultEndpoint = "https://test-key-vault.vault.azure.net"
	step.Cleanup(state)

	if deleteCalls != 0 {
		t.Fatalf("Expected no secret deletion without opt-in, got %d calls", deleteCalls)
	}
}

func TestStepCertificateInKeyVaultCleanupDeletesWrittenSecret(t *testing.T) {
	state := newCertificateInKeyVaultState()
	var actualSecretURI string
	var actualSecretName string
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:         "testKeyVaultName",
			BuildKeyVaultDeleteSecret: true,
			tmpKeyVaultSecretName:     "testKeyVaultSecretName",
		},
		say:   func(string) {},
		error: func(error) {},
		set: func(context.Context, secrets.SecretId) error {
			return nil
		},
		getVaultURI: func(context.Context, string, string, string) (string, error) {
			return "https://test-key-vault.vault.azure.net/", nil
		},
		deleteSecret: func(_ context.Context, secretURI, secretName string) error {
			actualSecretURI = secretURI
			actualSecretName = secretName
			return nil
		},
	}
	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected certificate step to succeed, got %v", action)
	}
	step.Cleanup(state)

	if actualSecretURI != "https://test-key-vault.vault.azure.net" {
		t.Fatalf("Expected cleanup to delete resolved Key Vault endpoint %q, got %q", "https://test-key-vault.vault.azure.net", actualSecretURI)
	}
	if actualSecretName != state.Get(constants.ArmKeyVaultSecretName).(string) {
		t.Fatalf("Expected cleanup to delete secret %q, got %q", state.Get(constants.ArmKeyVaultSecretName).(string), actualSecretName)
	}
}

func TestStepCertificateInKeyVaultCleanupRetriesForbiddenWhileDefaultRBACRolePropagates(t *testing.T) {
	state := newCertificateInKeyVaultState()
	deleteCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:                    "testKeyVaultName",
			BuildKeyVaultDeleteSecret:            true,
			BuildKeyVaultEnableRBACAuthorization: true,
			tmpKeyVaultSecretName:                "testKeyVaultSecretName",
		},
		waitForRolePropagation: func(context.Context, time.Duration) bool { return true },
		say:                    func(string) {},
		error:                  func(error) {},
		deleteSecret: func(context.Context, string, string) error {
			deleteCalls++
			if deleteCalls == 1 {
				return &keyVaultSecretDeleteError{statusCode: http.StatusForbidden, err: errors.New("forbidden while role assignment propagates")}
			}
			return nil
		},
	}
	step.secretWriteAttempted = true
	step.keyVaultEndpoint = "https://test-key-vault.vault.azure.net"
	step.Cleanup(state)

	if deleteCalls != 2 {
		t.Fatalf("Expected a retry after the initial RBAC propagation failure, got %d delete calls", deleteCalls)
	}
	if _, hasError := state.GetOk(constants.Error); hasError {
		t.Fatal("Expected successful retry not to report a cleanup error")
	}
}

func TestStepCertificateInKeyVaultCleanupDoesNotRetryNonRBACDeleteFailure(t *testing.T) {
	state := newCertificateInKeyVaultState()
	deleteCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:                    "testKeyVaultName",
			BuildKeyVaultDeleteSecret:            true,
			BuildKeyVaultEnableRBACAuthorization: true,
			tmpKeyVaultSecretName:                "testKeyVaultSecretName",
		},
		say:   func(string) {},
		error: func(error) {},
		deleteSecret: func(context.Context, string, string) error {
			deleteCalls++
			return errors.New("network unavailable")
		},
	}
	step.secretWriteAttempted = true
	step.keyVaultEndpoint = "https://test-key-vault.vault.azure.net"
	step.Cleanup(state)

	if deleteCalls != 1 {
		t.Fatalf("Expected one non-RBAC cleanup attempt, got %d", deleteCalls)
	}
	if _, hasError := state.GetOk(constants.Error); !hasError {
		t.Fatal("Expected the permanent cleanup failure to be reported")
	}
}

func TestStepCertificateInKeyVaultCleanupDoesNotRetryWhenRoleAssignmentIsDisabled(t *testing.T) {
	state := newCertificateInKeyVaultState()
	assignRole := false
	deleteCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:                    "testKeyVaultName",
			BuildKeyVaultDeleteSecret:            true,
			BuildKeyVaultEnableRBACAuthorization: true,
			BuildKeyVaultAssignRBACRole:          &assignRole,
			tmpKeyVaultSecretName:                "testKeyVaultSecretName",
		},
		say:   func(string) {},
		error: func(error) {},
		deleteSecret: func(context.Context, string, string) error {
			deleteCalls++
			return &keyVaultSecretDeleteError{statusCode: http.StatusForbidden, err: errors.New("forbidden")}
		},
	}
	step.secretWriteAttempted = true
	step.keyVaultEndpoint = "https://test-key-vault.vault.azure.net"
	step.Cleanup(state)

	if deleteCalls != 1 {
		t.Fatalf("Expected one cleanup attempt when role assignment is disabled, got %d", deleteCalls)
	}
}

func TestStepCertificateInKeyVaultCleanupBoundsRBACPropagationRetries(t *testing.T) {
	deleteCalls := 0
	waitCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:                    "testKeyVaultName",
			BuildKeyVaultDeleteSecret:            true,
			BuildKeyVaultEnableRBACAuthorization: true,
			tmpKeyVaultSecretName:                "testKeyVaultSecretName",
		},
		waitForRolePropagation: func(context.Context, time.Duration) bool {
			waitCalls++
			return true
		},
		say:   func(string) {},
		error: func(error) {},
		deleteSecret: func(context.Context, string, string) error {
			deleteCalls++
			return &keyVaultSecretDeleteError{statusCode: http.StatusForbidden, err: errors.New("forbidden")}
		},
	}
	if err := step.deleteCertificateDuringCleanup(context.Background(), "testKeyVaultSecretName"); err == nil {
		t.Fatal("Expected persistent RBAC propagation failure to be returned")
	}
	if deleteCalls != keyVaultRBACRolePropagationMaxRetries+1 {
		t.Fatalf("Expected %d bounded delete attempts, got %d", keyVaultRBACRolePropagationMaxRetries+1, deleteCalls)
	}
	if waitCalls != keyVaultRBACRolePropagationMaxRetries {
		t.Fatalf("Expected %d bounded propagation waits, got %d", keyVaultRBACRolePropagationMaxRetries, waitCalls)
	}
}

func TestStepCertificateInKeyVaultCleanupStopsWhenDefaultPropagationWaitIsCancelled(t *testing.T) {
	deleteCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultEnableRBACAuthorization: true,
		},
		say: func(string) {},
		deleteSecret: func(context.Context, string, string) error {
			deleteCalls++
			return &keyVaultSecretDeleteError{statusCode: http.StatusForbidden, err: errors.New("forbidden")}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := step.deleteCertificateDuringCleanup(ctx, "testKeyVaultSecretName"); err == nil {
		t.Fatal("Expected cancelled default propagation wait to return the delete failure")
	}
	if deleteCalls != 1 {
		t.Fatalf("Expected cancelled default propagation wait to stop after one attempt, got %d", deleteCalls)
	}
}

func TestWaitForKeyVaultRBACRolePropagationStopsForCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if waitForKeyVaultRBACRolePropagation(ctx, time.Hour) {
		t.Fatal("Expected a cancelled propagation context to stop waiting")
	}
}

func TestWaitForKeyVaultRBACRolePropagationCompletesAfterDelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if !waitForKeyVaultRBACRolePropagation(ctx, 0) {
		t.Fatal("Expected an elapsed propagation delay to permit a retry")
	}
}

func TestStepCertificateInKeyVaultCleanupDeletesAfterFailedWrite(t *testing.T) {
	state := newCertificateInKeyVaultState()
	var actualSecretURI string
	var actualSecretName string
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:         "testKeyVaultName",
			BuildKeyVaultDeleteSecret: true,
			tmpKeyVaultSecretName:     "testKeyVaultSecretName",
		},
		say:   func(string) {},
		error: func(error) {},
		set: func(context.Context, secrets.SecretId) error {
			return fmt.Errorf("set failed")
		},
		getVaultURI: func(ctx context.Context, subscriptionID, resourceGroupName, keyVaultName string) (string, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("Expected Key Vault URI lookup context to have a deadline")
			}
			if subscriptionID != "testSubscription" || resourceGroupName != "testResourceGroupName" || keyVaultName != "testKeyVaultName" {
				t.Fatalf("Unexpected Key Vault lookup target: %q/%q/%q", subscriptionID, resourceGroupName, keyVaultName)
			}
			return "https://test-key-vault.vault.azure.net/", nil
		},
		deleteSecret: func(_ context.Context, secretURI, secretName string) error {
			actualSecretURI = secretURI
			actualSecretName = secretName
			return nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionHalt {
		t.Fatalf("Expected certificate step to halt, got %v", action)
	}
	step.Cleanup(state)

	if actualSecretURI != "https://test-key-vault.vault.azure.net" {
		t.Fatalf("Expected cleanup to use the resolved Key Vault URI, got %q", actualSecretURI)
	}
	if actualSecretName != state.Get(constants.ArmKeyVaultSecretName).(string) {
		t.Fatalf("Expected cleanup to delete secret %q, got %q", state.Get(constants.ArmKeyVaultSecretName).(string), actualSecretName)
	}
}

func TestStepCertificateInKeyVaultCleanupDoesNotDeleteFromPackerOwnedVault(t *testing.T) {
	state := newCertificateInKeyVaultState()
	state.Put(constants.ArmIsExistingKeyVault, false)
	deleteCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:         "testKeyVaultName",
			BuildKeyVaultDeleteSecret: true,
		},
		say:   func(string) {},
		error: func(error) {},
		deleteSecret: func(context.Context, string, string) error {
			deleteCalls++
			return nil
		},
	}
	step.secretWriteAttempted = true
	step.keyVaultEndpoint = "https://test-key-vault.vault.azure.net"
	step.Cleanup(state)

	if deleteCalls != 0 {
		t.Fatalf("Expected no deletion from a Packer-owned Key Vault, got %d calls", deleteCalls)
	}
}

func TestStepCertificateInKeyVaultCleanupReportsDeletionFailure(t *testing.T) {
	state := newCertificateInKeyVaultState()
	var errors []string
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:         "testKeyVaultName",
			BuildKeyVaultDeleteSecret: true,
			tmpKeyVaultSecretName:     "testKeyVaultSecretName",
		},
		say: func(string) {},
		error: func(err error) {
			errors = append(errors, err.Error())
		},
		set: func(context.Context, secrets.SecretId) error {
			return nil
		},
		getVaultURI: func(context.Context, string, string, string) (string, error) {
			return "https://test-key-vault.vault.azure.net/", nil
		},
		deleteSecret: func(context.Context, string, string) error {
			return fmt.Errorf("delete failed")
		},
	}
	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected certificate step to succeed, got %v", action)
	}
	step.Cleanup(state)

	if len(errors) != 1 || !strings.Contains(errors[0], "delete it manually") {
		t.Fatalf("Expected a manual-remediation error, got %v", errors)
	}
	if _, ok := state.GetOk(constants.Error); !ok {
		t.Fatalf("Expected cleanup failure to set stateBag[%q]", constants.Error)
	}
}

func TestStepCertificateInKeyVaultCleanupUsesPreResolvedVaultURIWhenWriteHasNoSecretURI(t *testing.T) {
	state := newCertificateInKeyVaultState()
	var actualSecretURI string
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:         "testKeyVaultName",
			BuildKeyVaultDeleteSecret: true,
			tmpKeyVaultSecretName:     "testKeyVaultSecretName",
		},
		say:   func(string) {},
		error: func(error) {},
		set: func(context.Context, secrets.SecretId) error {
			return nil
		},
		getVaultURI: func(context.Context, string, string, string) (string, error) {
			return "https://test-key-vault.vault.azure.net/", nil
		},
		deleteSecret: func(_ context.Context, secretURI, _ string) error {
			actualSecretURI = secretURI
			return nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected certificate step to succeed, got %v", action)
	}
	step.Cleanup(state)

	if actualSecretURI != "https://test-key-vault.vault.azure.net" {
		t.Fatalf("Expected cleanup to use the resolved Key Vault URI, got %q", actualSecretURI)
	}
	if _, ok := state.GetOk(constants.Error); ok {
		t.Fatalf("Expected successful URI resolution not to set stateBag[%q]", constants.Error)
	}
}

func TestStepCertificateInKeyVaultUsesPreflightEndpointForSecretCleanup(t *testing.T) {
	state := newCertificateInKeyVaultState()
	state.Put(constants.ArmKeyVaultDataPlaneEndpoint, "https://test-key-vault.vault.azure.net")
	lookupCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:         "testKeyVaultName",
			BuildKeyVaultDeleteSecret: true,
			tmpKeyVaultSecretName:     "testKeyVaultSecretName",
		},
		say:   func(string) {},
		error: func(error) {},
		set: func(context.Context, secrets.SecretId) error {
			return nil
		},
		getVaultURI: func(context.Context, string, string, string) (string, error) {
			lookupCalls++
			return "", fmt.Errorf("preflight endpoint should have been used")
		},
		deleteSecret: func(_ context.Context, endpoint, _ string) error {
			if endpoint != "https://test-key-vault.vault.azure.net" {
				t.Fatalf("Expected cached endpoint, got %q", endpoint)
			}
			return nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionContinue {
		t.Fatalf("Expected certificate step to succeed with preflight endpoint, got %v", action)
	}
	if lookupCalls != 0 {
		t.Fatalf("Expected no Key Vault endpoint lookup after preflight, got %d calls", lookupCalls)
	}
	step.Cleanup(state)
}

func TestStepCertificateInKeyVaultRunStopsBeforeWriteWhenVaultURILookupFails(t *testing.T) {
	state := newCertificateInKeyVaultState()
	deleteCalls := 0
	setCalls := 0
	var errors []string
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:         "testKeyVaultName",
			BuildKeyVaultDeleteSecret: true,
			tmpKeyVaultSecretName:     "testKeyVaultSecretName",
		},
		say: func(string) {},
		error: func(err error) {
			errors = append(errors, err.Error())
		},
		set: func(context.Context, secrets.SecretId) error {
			setCalls++
			return nil
		},
		getVaultURI: func(context.Context, string, string, string) (string, error) {
			return "", fmt.Errorf("lookup failed")
		},
		deleteSecret: func(context.Context, string, string) error {
			deleteCalls++
			return nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionHalt {
		t.Fatalf("Expected certificate step to halt, got %v", action)
	}
	step.Cleanup(state)

	if setCalls != 0 {
		t.Fatalf("Expected no certificate write after a Key Vault URI lookup failure, got %d calls", setCalls)
	}
	if deleteCalls != 0 {
		t.Fatalf("Expected no delete after a Key Vault URI lookup failure, got %d calls", deleteCalls)
	}
	if len(errors) != 1 || !strings.Contains(errors[0], "before creating") {
		t.Fatalf("Expected a pre-write endpoint resolution error, got %v", errors)
	}
}

func TestStepCertificateInKeyVaultRunRefusesNonGeneratedCleanupSecretName(t *testing.T) {
	state := newCertificateInKeyVaultState()
	setCalls := 0
	step := &StepCertificateInKeyVault{
		config: &Config{
			BuildKeyVaultName:         "testKeyVaultName",
			BuildKeyVaultDeleteSecret: true,
			tmpKeyVaultSecretName:     "generated-testKeyVaultSecretName",
		},
		say:   func(string) {},
		error: func(error) {},
		set: func(context.Context, secrets.SecretId) error {
			setCalls++
			return nil
		},
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionHalt {
		t.Fatalf("Expected certificate step to halt, got %v", action)
	}
	if setCalls != 0 {
		t.Fatalf("Expected no certificate write for a non-generated cleanup name, got %d calls", setCalls)
	}
}

func TestDeleteKeyVaultSecretAcceptsNotFound(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete {
			t.Errorf("Expected DELETE request, got %q", request.Method)
		}
		if request.URL.Path != "/secrets/testKeyVaultSecretName" {
			t.Errorf("Expected secret path %q, got %q", "/secrets/testKeyVaultSecretName", request.URL.Path)
		}
		if apiVersion := request.URL.Query().Get("api-version"); apiVersion != keyVaultSecretsAPIVersion {
			t.Errorf("Expected API version %q, got %q", keyVaultSecretsAPIVersion, apiVersion)
		}
		responseWriter.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	keyVaultClient := dataplane.NewDataPlaneClient(server.URL, "secrets", keyVaultSecretsAPIVersion)
	keyVaultClient.SetTransport(server.Client().Transport)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := deleteKeyVaultSecret(ctx, keyVaultClient, "testKeyVaultSecretName"); err != nil {
		t.Fatalf("Expected a 404 delete response to succeed, got %v", err)
	}
}

func TestDeleteKeyVaultSecretReportsRequestConstructionFailure(t *testing.T) {
	keyVaultClient := dataplane.NewDataPlaneClient("https://test-key-vault.vault.azure.net", "secrets", keyVaultSecretsAPIVersion)
	err := deleteKeyVaultSecret(context.Background(), keyVaultClient, "testKeyVaultSecretName")
	if err == nil || !strings.Contains(err.Error(), "creating Key Vault secret delete request") {
		t.Fatalf("Expected request-construction error, got %v", err)
	}
}

func TestDeleteKeyVaultSecretIncludesForbiddenStatusForRBACRetry(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	keyVaultClient := dataplane.NewDataPlaneClient(server.URL, "secrets", keyVaultSecretsAPIVersion)
	keyVaultClient.SetTransport(server.Client().Transport)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := deleteKeyVaultSecret(ctx, keyVaultClient, "testKeyVaultSecretName")
	if err == nil {
		t.Fatal("Expected a 403 delete response to fail")
	}
	if !isKeyVaultRBACRolePropagationError(err) {
		t.Fatalf("Expected a 403 delete response to be eligible for a bounded RBAC propagation retry, got %v", err)
	}
}

func TestKeyVaultEndpointFromURI(t *testing.T) {
	endpoint, err := keyVaultEndpointFromURI("https://test-key-vault.vault.azure.net/secrets/testKeyVaultSecretName/version")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://test-key-vault.vault.azure.net" {
		t.Fatalf("Expected Key Vault endpoint %q, got %q", "https://test-key-vault.vault.azure.net", endpoint)
	}

	sovereignEndpoint, err := keyVaultEndpointFromURI("https://test-key-vault.vault.usgovcloudapi.net/")
	if err != nil {
		t.Fatal(err)
	}
	if sovereignEndpoint != "https://test-key-vault.vault.usgovcloudapi.net" {
		t.Fatalf("Expected sovereign Key Vault endpoint %q, got %q", "https://test-key-vault.vault.usgovcloudapi.net", sovereignEndpoint)
	}

	if _, err := keyVaultEndpointFromURI("http://test-key-vault.vault.azure.net/secrets/testKeyVaultSecretName"); err == nil {
		t.Fatal("Expected non-HTTPS Key Vault URI to be rejected")
	}
}
