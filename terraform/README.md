# Terraform Acceptance Test Infrastructure

This repo's acceptance tests require a bit of setup to run, a subscription, and app registration, and several resources must be created. To make this process easier to manage in CI and easier for developers to quickly test changes, this directory contains terraform configuration to create the required resources.

## Creating Azure Resources

First you need an Azure Subscription, it is also recommended to also have an app registration created with client/secret authentication setup, as this is required for the acceptance tests themselves.

Authenticate to Azure using the Azure CLI for a service principal

The default resource group is named `packer-acceptance-test` with a storage account named `packeracctest`, however you can use variables TF `resource_group_name` and `storage_account_name` to change that to anything. Resource names are automatically suffixed to avoid conflicts between concurrent runs; you can supply `resource_suffix` to control the suffix.

For example
```
terraform apply -var "resource_group_name=cool-group" -var "storage_account_name=coolblobstore"
```

Note that Azure storage account names must not contain special characters.

## Terraform Outputs

The Terraform program exposes outputs for the resource names that the ARM acceptance tests reference through environment variables. These outputs are intended for debugging and local test setup.

They help with two common problems:
- confirming that the GitHub Actions workflow is computing the same names that Terraform actually created
- quickly exporting or inspecting the exact resource names when running acceptance tests locally

Current outputs:
- `resource_group_name`
- `storage_account_name`
- `storage_container_name`
- `resource_prefix`
- `resource_suffix`
- `virtual_network_name`
- `virtual_network_subnet_name`
- `key_vault_name`
- `rbac_key_vault_name`

You can inspect them with:
```
terraform output
```

Or fetch a single value with:
```
terraform output -raw virtual_network_name
```

These outputs only cover resources created by this Terraform program. For example, `ARM_TEMP_RESOURCE_GROUP_NAME` is still configured outside Terraform and is therefore not exposed as an output.

## RBAC Key Vault acceptance fixture

`rbac_key_vault_name` is a separate RBAC-enabled Key Vault in the acceptance
resource group. It intentionally has no direct Key Vault data-plane assignment
for the Packer identity so the ARM acceptance test can prove that Packer creates
a vault-scoped `Key Vault Secrets Officer` assignment itself.

The Packer acceptance identity needs `Microsoft.Authorization/roleAssignments/write`
at that vault scope or above. The acceptance-test runner needs
`Microsoft.Authorization/roleAssignments/delete` there to remove the test role
afterwards; CI uses the same service principal for both. `Contributor` alone is
insufficient. The Packer identity also needs
`Microsoft.KeyVault/vaults/read`, `Microsoft.KeyVault/vaults/secrets/write`,
and the usual permissions to create and delete the build resources. The test
checks that no direct assignment exists before the build, verifies Packer's
deterministic assignment afterwards, then removes only that assignment.

The temporary-Key-Vault RBAC acceptance test needs no
`Microsoft.Authorization/roleAssignments` permissions at all: a Packer-created
RBAC vault deploys without any data-plane role assignment.
