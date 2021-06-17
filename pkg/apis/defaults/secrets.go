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

	csiAzureCreds = "%s-%s-csiazurecreds" // <componentname>-<radixvolumemountname>-csiazurecreds
)

// GetBlobFuseCredsSecretName Helper method
func GetBlobFuseCredsSecretName(componentName string, volumeMountName string) string {
	return fmt.Sprintf(blobFuseCreds, componentName, volumeMountName)
}

// GetCsiAzureCredsSecretName Helper method
func GetCsiAzureCredsSecretName(componentName, radixVolumeMountName string) string {
	return fmt.Sprintf(csiAzureCreds, componentName, radixVolumeMountName)
}
