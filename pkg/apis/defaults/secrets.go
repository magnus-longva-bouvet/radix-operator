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

	// BlobFuseCredsAccountKeyPart Account key part of secret data
	BlobFuseCredsAccountKeyPart = "accountkey"

	// BlobFuseCredsAccountNamePart Account name part of secret data
	BlobFuseCredsAccountNamePart = "accountname"

	blobFuseCreds = "%s-blobfusecreds" // <componentname>-blobfusecreds
)

// GetBlobFuseCredsSecret Helper method
func GetBlobFuseCredsSecret(componentName string) string {
	return fmt.Sprintf(blobFuseCreds, componentName)
}
