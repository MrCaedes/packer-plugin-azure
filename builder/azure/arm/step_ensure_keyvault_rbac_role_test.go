// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package arm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-azure-sdk/resource-manager/authorization/2022-04-01/roleassignments"
	sdkEnvironments "github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/hashicorp/go-azure-sdk/sdk/odata"
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

func TestIsRoleAssignmentAlreadyExistsUsesCurrentCreateResponse(t *testing.T) {
	roleAssignmentExists := "RoleAssignmentExists"
	authorizationFailed := "AuthorizationFailed"

	testCases := []struct {
		name   string
		result roleassignments.CreateOperationResponse
		err    error
		want   bool
	}{
		{
			name: "current response reports existing assignment",
			result: roleassignments.CreateOperationResponse{
				OData: &odata.OData{Error: &odata.Error{Code: &roleAssignmentExists}},
			},
			err:  fmt.Errorf("unexpected status 409"),
			want: true,
		},
		{
			name: "unrelated current response is not treated as an existing assignment",
			result: roleassignments.CreateOperationResponse{
				OData: &odata.OData{Error: &odata.Error{Code: &authorizationFailed}},
			},
			err:  fmt.Errorf("unexpected status 403"),
			want: false,
		},
		{
			name: "SDK error text fallback",
			err:  fmt.Errorf("unexpected status 409 with RoleAssignmentExists"),
			want: true,
		},
		{
			name: "successful create is not a conflict",
			want: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := isRoleAssignmentAlreadyExists(testCase.result, testCase.err); got != testCase.want {
				t.Fatalf("Expected existing-assignment detection to be %t, got %t", testCase.want, got)
			}
		})
	}
}

func TestStepEnsureKeyVaultRBACRoleCreateRoleAssignmentUsesCurrentResponse(t *testing.T) {
	roleAssignmentExists := "RoleAssignmentExists"
	testCases := []struct {
		name         string
		responseCode int
		responseBody string
		wantErr      bool
	}{
		{
			name:         "existing assignment",
			responseCode: http.StatusConflict,
			responseBody: `{"error":{"code":"RoleAssignmentExists","message":"The role assignment already exists."}}`,
		},
		{
			name:         "successful assignment",
			responseCode: http.StatusCreated,
			responseBody: `{}`,
		},
		{
			name:         "unrelated failure despite stale prior error",
			responseCode: http.StatusForbidden,
			responseBody: `{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization."}}`,
			wantErr:      true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPut {
					t.Errorf("Expected PUT request, got %q", request.Method)
				}
				responseWriter.Header().Set("Content-Type", "application/json")
				responseWriter.WriteHeader(testCase.responseCode)
				_, _ = responseWriter.Write([]byte(testCase.responseBody))
			}))
			defer server.Close()

			roleAssignmentsClient, err := roleassignments.NewRoleAssignmentsClientWithBaseURI(sdkEnvironments.ResourceManagerAPI(server.URL))
			if err != nil {
				t.Fatalf("Creating test role assignments client: %v", err)
			}
			roleAssignmentsClient.Client.Transport = server.Client().Transport
			roleAssignmentsClient.Client.AuthorizeRequest = nil
			step := &StepEnsureKeyVaultRBACRole{
				client: &AzureClient{
					RoleAssignmentsClient: *roleAssignmentsClient,
					LastError:             azureErrorResponse{ErrorDetails: azureErrorDetails{Code: roleAssignmentExists}},
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = step.createRoleAssignment(
				ctx,
				roleassignments.NewScopedRoleAssignmentID("/subscriptions/test-subscription", "test-role-assignment"),
				roleassignments.RoleAssignmentCreateParameters{},
			)
			if testCase.wantErr && err == nil {
				t.Fatal("Expected the current authorization failure to be returned")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("Expected an existing assignment to be idempotent, got %v", err)
			}
		})
	}
}

func TestStepEnsureKeyVaultRBACRoleCreateRoleAssignmentRequiresConfiguredClient(t *testing.T) {
	step := &StepEnsureKeyVaultRBACRole{}
	err := step.createRoleAssignment(
		context.Background(),
		roleassignments.NewScopedRoleAssignmentID("/subscriptions/test-subscription", "test-role-assignment"),
		roleassignments.RoleAssignmentCreateParameters{},
	)
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("Expected an actionable unconfigured-client error, got %v", err)
	}
}

func TestStepEnsureKeyVaultRBACRoleRunBoundsRoleAssignmentContext(t *testing.T) {
	// The multistep runner context has no deadline, and the go-azure-sdk
	// resource manager client rejects deadline-less contexts before sending any
	// request. Run must therefore bound the context itself; this test drives Run
	// through the real createRoleAssignment path to pin that behaviour.
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut {
			t.Errorf("Expected PUT request, got %q", request.Method)
		}
		requests++
		responseWriter.Header().Set("Content-Type", "application/json")
		responseWriter.WriteHeader(http.StatusCreated)
		_, _ = responseWriter.Write([]byte(`{"properties":{}}`))
	}))
	defer server.Close()

	roleAssignmentsClient, err := roleassignments.NewRoleAssignmentsClientWithBaseURI(sdkEnvironments.ResourceManagerAPI(server.URL))
	if err != nil {
		t.Fatalf("Creating test role assignments client: %v", err)
	}
	roleAssignmentsClient.Client.Transport = server.Client().Transport
	roleAssignmentsClient.Client.AuthorizeRequest = nil
	step := &StepEnsureKeyVaultRBACRole{
		config: &Config{
			resolvedBuildPrincipalID: "00000000-0000-0000-0000-000000000002",
		},
		client: &AzureClient{
			RoleAssignmentsClient: *roleAssignmentsClient,
		},
		say:   func(string) {},
		error: func(error) {},
	}
	step.create = step.createRoleAssignment

	if action := step.Run(context.Background(), newEnsureKeyVaultRBACRoleState()); action != multistep.ActionContinue {
		t.Fatalf("Expected the role assignment step to continue with an undeadlined runner context, got %v", action)
	}
	if requests != 1 {
		t.Fatalf("Expected exactly one role assignment request, got %d", requests)
	}
}

func TestStepEnsureKeyVaultRBACRoleRetriesPrincipalNotFound(t *testing.T) {
	createCalls := 0
	waitCalls := 0
	step := &StepEnsureKeyVaultRBACRole{
		config: &Config{
			resolvedBuildPrincipalID: "00000000-0000-0000-0000-000000000002",
		},
		say:   func(string) {},
		error: func(error) {},
		create: func(context.Context, roleassignments.ScopedRoleAssignmentId, roleassignments.RoleAssignmentCreateParameters) error {
			createCalls++
			if createCalls < 3 {
				return fmt.Errorf(`unexpected status 400 (400 Bad Request) with error: PrincipalNotFound: Principal does not exist in the directory`)
			}
			return nil
		},
		wait: func(context.Context, time.Duration) bool {
			waitCalls++
			return true
		},
	}

	if action := step.Run(context.Background(), newEnsureKeyVaultRBACRoleState()); action != multistep.ActionContinue {
		t.Fatalf("Expected the role assignment to succeed after replication retries, got %v", action)
	}
	if createCalls != 3 || waitCalls != 2 {
		t.Fatalf("Expected 3 create attempts with 2 waits, got %d/%d", createCalls, waitCalls)
	}
}

func TestStepEnsureKeyVaultRBACRoleBoundsPrincipalNotFoundRetriesAndPutsBuildError(t *testing.T) {
	state := newEnsureKeyVaultRBACRoleState()
	createCalls := 0
	step := &StepEnsureKeyVaultRBACRole{
		config: &Config{
			resolvedBuildPrincipalID: "00000000-0000-0000-0000-000000000002",
		},
		say:   func(string) {},
		error: func(error) {},
		create: func(context.Context, roleassignments.ScopedRoleAssignmentId, roleassignments.RoleAssignmentCreateParameters) error {
			createCalls++
			return fmt.Errorf("PrincipalNotFound: Principal does not exist in the directory")
		},
		wait: func(context.Context, time.Duration) bool { return true },
	}

	if action := step.Run(context.Background(), state); action != multistep.ActionHalt {
		t.Fatalf("Expected a persistent PrincipalNotFound to halt, got %v", action)
	}
	if createCalls != keyVaultRBACRolePropagationMaxRetries+1 {
		t.Fatalf("Expected %d bounded create attempts, got %d", keyVaultRBACRolePropagationMaxRetries+1, createCalls)
	}
	rawErr, ok := state.GetOk(constants.Error)
	if !ok {
		t.Fatalf("Expected the halt to set stateBag[%q]", constants.Error)
	}
	if err, isError := rawErr.(error); !isError || !strings.Contains(err.Error(), "failed to grant Key Vault Secrets Officer") {
		t.Fatalf("Expected the grant failure in the state bag, got %v", rawErr)
	}
}

func TestStepEnsureKeyVaultRBACRoleDoesNotRetryNonReplicationFailures(t *testing.T) {
	createCalls := 0
	step := &StepEnsureKeyVaultRBACRole{
		config: &Config{
			resolvedBuildPrincipalID: "00000000-0000-0000-0000-000000000002",
		},
		say:   func(string) {},
		error: func(error) {},
		create: func(context.Context, roleassignments.ScopedRoleAssignmentId, roleassignments.RoleAssignmentCreateParameters) error {
			createCalls++
			return fmt.Errorf("AuthorizationFailed: The client does not have authorization")
		},
		wait: func(context.Context, time.Duration) bool {
			t.Fatal("Expected no replication wait for a non-replication failure")
			return true
		},
	}

	if action := step.Run(context.Background(), newEnsureKeyVaultRBACRoleState()); action != multistep.ActionHalt {
		t.Fatalf("Expected an authorization failure to halt immediately, got %v", action)
	}
	if createCalls != 1 {
		t.Fatalf("Expected a single create attempt, got %d", createCalls)
	}
}
