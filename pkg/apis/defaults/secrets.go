package defaults

import "fmt"

const (
	// BuildSecretPrefix All build secrets will be mounted with this prefix
	BuildSecretPrefix = "BUILD_SECRET_"

	// BuildSecretsName Name of the secret in the app namespace holding all build secrets
	BuildSecretsName = "build-secrets"

	// BuildSecretDefaultData When the build secrets hold radix_undefined, it means they have not been set yet
	BuildSecretDefaultData = "radix_undefined"

	// BlobFuseCredsAccountKeyPartSuffix Account key suffix of secret listed
	BlobFuseCredsAccountKeyPartSuffix = "-accountkey"

	// BlobFuseCredsAccountNamePartSuffix Account name suffix of secret listed
	BlobFuseCredsAccountNamePartSuffix = "-accountname"

	// BlobFuseCredsAccountKeyPart Account key part of secret data
	BlobFuseCredsAccountKeyPart = "accountkey"

	// BlobFuseCredsAccountNamePart Account name part of secret data
	BlobFuseCredsAccountNamePart = "accountname"

	blobFuseCreds = "%s-%s-blobfusecreds" // <componentname>-<radixvolumemountname>-blobfusecreds

	// CsiAzureCredsAccountKeyPartSuffix Account key suffix of secret listed
	CsiAzureCredsAccountKeyPartSuffix = "-accountkey"

	// CsiAzureCredsAccountNamePartSuffix Account name suffix of secret listed
	CsiAzureCredsAccountNamePartSuffix = "-accountname"

	// CsiAzureCredsAccountKeyPart Account key part of secret data
	CsiAzureCredsAccountKeyPart = "accountkey"

	// CsiAzureCredsAccountNamePart Account name part of secret data
	CsiAzureCredsAccountNamePart = "accountname"

	csiAzureCreds         = "%s-%s-csiazurecreds" // <componentname>-<radixvolumemountname>-csiazurecreds
	csiAzureKeyVaultCreds = "%s-%s-csiazkvcreds"  // <componentname>-<azure-keyvault-name>-csiazkvcreds

	// CsiAzureKeyVaultCredsClientIdSuffix Client ID suffix of secret listed
	CsiAzureKeyVaultCredsClientIdSuffix = "-azkv-clientid"

	// CsiAzureKeyVaultCredsClientSecretSuffix Client secret suffix of secret listed
	CsiAzureKeyVaultCredsClientSecretSuffix = "-azkv-clientsecret"

	// CsiAzureKeyVaultCredsClientIdPart Client ID part of secret data for Azure Key Vault
	CsiAzureKeyVaultCredsClientIdPart = "clientid"

	// CsiAzureKeyVaultCredsClientSecretPart Client secret part of secret data for Azure Key Vault
	CsiAzureKeyVaultCredsClientSecretPart = "clientsecret"
)

// GetBlobFuseCredsSecretName Helper method
func GetBlobFuseCredsSecretName(componentName string, volumeMountName string) string {
	return fmt.Sprintf(blobFuseCreds, componentName, volumeMountName)
}

// GetCsiAzureCredsSecretName Helper method
func GetCsiAzureCredsSecretName(componentName, radixVolumeMountName string) string {
	return fmt.Sprintf(csiAzureCreds, componentName, radixVolumeMountName)
}

// GetCsiAzureKeyVaultCredsSecretName Helper method
func GetCsiAzureKeyVaultCredsSecretName(componentName, azureKeyVaultName string) string {
	return fmt.Sprintf(csiAzureKeyVaultCreds, componentName, azureKeyVaultName)
}
