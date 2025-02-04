package application

import (
	"github.com/equinor/radix-operator/pkg/apis/defaults"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ApplySecretsForPipelines creates secrets needed by pipeline to run
func (app Application) applySecretsForPipelines() error {
	radixRegistration := app.registration

	log.Debugf("Apply secrets for pipelines")
	buildNamespace := utils.GetAppNamespace(radixRegistration.Name)

	err := app.applyGitDeployKeyToBuildNamespace(buildNamespace)
	if err != nil {
		return err
	}
	err = app.applyServicePrincipalACRSecretToBuildNamespace(buildNamespace)
	if err != nil {
		log.Warnf("Failed to apply service principle acr secret (%s) to namespace %s", defaults.AzureACRServicePrincipleSecretName, buildNamespace)
	}
	return nil
}

func (app Application) applyGitDeployKeyToBuildNamespace(namespace string) error {
	radixRegistration := app.registration
	secret, err := app.createNewGitDeployKey(namespace, radixRegistration.Spec.DeployKey)
	if err != nil {
		return err
	}

	_, err = app.kubeutil.ApplySecret(namespace, secret)
	return err
}

func (app Application) applyServicePrincipalACRSecretToBuildNamespace(buildNamespace string) error {
	servicePrincipalSecretForBuild, err := app.createNewServicePrincipalACRSecret(buildNamespace)
	if err != nil {
		return err
	}

	_, err = app.kubeutil.ApplySecret(buildNamespace, servicePrincipalSecretForBuild)
	return err
}

func (app Application) createNewGitDeployKey(namespace, deployKey string) (*corev1.Secret, error) {
	knownHostsSecret, err := app.kubeutil.GetSecret(corev1.NamespaceDefault, "radix-known-hosts-git")
	if err != nil {
		log.Errorf("Failed to get known hosts secret. %v", err)
		return nil, err
	}

	secret := corev1.Secret{
		Type: "Opaque",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "git-ssh-keys",
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"id_rsa":      []byte(deployKey),
			"known_hosts": knownHostsSecret.Data["known_hosts"],
		},
	}
	return &secret, nil
}

func (app Application) createNewServicePrincipalACRSecret(namespace string) (*corev1.Secret, error) {
	servicePrincipalSecret, err := app.kubeutil.GetSecret(corev1.NamespaceDefault, defaults.AzureACRServicePrincipleSecretName)
	if err != nil {
		log.Errorf("Failed to get %s secret from default. %v", defaults.AzureACRServicePrincipleSecretName, err)
		return nil, err
	}
	secret := corev1.Secret{
		Type: "Opaque",
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaults.AzureACRServicePrincipleSecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"sp_credentials.json": servicePrincipalSecret.Data["sp_credentials.json"],
		},
	}
	return &secret, nil
}
