package deployment

import (
	"context"
	"fmt"
	"strconv"

	"github.com/equinor/radix-operator/pkg/apis/defaults"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	radixv1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	"github.com/equinor/radix-operator/pkg/apis/utils/slice"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const secretDefaultData = "xx"

func (deploy *Deployment) createOrUpdateSecrets(registration *radixv1.RadixRegistration, deployment *radixv1.RadixDeployment) error {
	envName := deployment.Spec.Environment
	namespace := utils.GetEnvironmentNamespace(registration.Name, envName)

	log.Debugf("Apply empty secrets based on radix deployment obj")
	for _, comp := range deployment.Spec.Components {
		err := deploy.createOrUpdateSecretsForComponent(registration, deployment, &comp, namespace)
		if err != nil {
			return err
		}
	}
	for _, comp := range deployment.Spec.Jobs {
		err := deploy.createOrUpdateSecretsForComponent(registration, deployment, &comp, namespace)
		if err != nil {
			return err
		}
	}
	return nil
}

func (deploy *Deployment) createOrUpdateSecretsForComponent(registration *radixv1.RadixRegistration, deployment *radixv1.RadixDeployment, component radixv1.RadixCommonDeployComponent, namespace string) error {
	secretsToManage := make([]string, 0)

	if len(component.GetSecrets()) > 0 {
		secretName := utils.GetComponentSecretName(component.GetName())
		if !deploy.kubeutil.SecretExists(namespace, secretName) {
			err := deploy.createOrUpdateSecret(namespace, registration.Name, component.GetName(), secretName, false)
			if err != nil {
				return err
			}
		} else {
			err := deploy.removeOrphanedSecrets(namespace, secretName, component.GetSecrets())
			if err != nil {
				return err
			}
		}

		secretsToManage = append(secretsToManage, secretName)
	}

	dnsExternalAlias := component.GetDNSExternalAlias()
	if dnsExternalAlias != nil && len(dnsExternalAlias) > 0 {
		err := deploy.garbageCollectSecretsNoLongerInSpecForComponentAndExternalAlias(component)
		if err != nil {
			return err
		}

		// Create secrets to hold TLS certificates
		for _, externalAlias := range dnsExternalAlias {
			secretsToManage = append(secretsToManage, externalAlias)

			if deploy.kubeutil.SecretExists(namespace, externalAlias) {
				continue
			}

			err := deploy.createOrUpdateSecret(namespace, registration.Name, component.GetName(), externalAlias, true)
			if err != nil {
				return err
			}
		}
	} else {
		err := deploy.garbageCollectAllSecretsForComponentAndExternalAlias(component)
		if err != nil {
			return err
		}
	}

	for _, radixVolumeMount := range component.GetVolumeMounts() {
		switch radixVolumeMount.Type {
		case radixv1.MountTypeBlob:
			{
				secretName, accountKey, accountName := deploy.getBlobFuseCredsSecrets(namespace, component.GetName(), radixVolumeMount.Name)
				secretsToManage = append(secretsToManage, secretName)
				err := deploy.createOrUpdateVolumeMountsSecrets(namespace, component.GetName(), secretName, accountName, accountKey)
				if err != nil {
					return err
				}
			}
		case radixv1.MountTypeBlobCsiAzure, radixv1.MountTypeFileCsiAzure:
			{
				secretName, accountKey, accountName := deploy.getCsiAzureCredsSecrets(namespace, component.GetName(), radixVolumeMount.Name)
				secretsToManage = append(secretsToManage, secretName)
				err := deploy.createOrUpdateCsiAzureVolumeMountsSecrets(namespace, component.GetName(), radixVolumeMount.Name, radixVolumeMount.Type, secretName, accountName, accountKey)
				if err != nil {
					return err
				}
			}
		}
	}
	err := deploy.garbageCollectVolumeMountsSecretsNoLongerInSpecForComponent(component, secretsToManage)
	if err != nil {
		return err
	}

	err = deploy.grantAppAdminAccessToRuntimeSecrets(deployment.Namespace, registration, component, secretsToManage)
	clientCertificateSecretName := utils.GetComponentClientCertificateSecretName(component.GetName())
	if auth := component.GetAuthentication(); auth != nil && component.GetPublicPort() != "" && IsSecretRequiredForClientCertificate(auth.ClientCertificate) {
		if !deploy.kubeutil.SecretExists(namespace, clientCertificateSecretName) {
			if err := deploy.createClientCertificateSecret(namespace, registration.Name, component.GetName(), clientCertificateSecretName); err != nil {
				return err
			}
		}
		secretsToManage = append(secretsToManage, clientCertificateSecretName)
	} else if deploy.kubeutil.SecretExists(namespace, clientCertificateSecretName) {
		deploy.kubeutil.DeleteSecret(namespace, clientCertificateSecretName)
	}

	err = deploy.grantAppAdminAccessToRuntimeSecrets(deployment.Namespace, registration, component, secretsToManage)
	if err != nil {
		return fmt.Errorf("failed to grant app admin access to own secrets. %v", err)
	}

	if len(secretsToManage) == 0 {
		err := deploy.garbageCollectSecretsNoLongerInSpecForComponent(component)
		if err != nil {
			return err
		}
	}
	return nil
}

func (deploy *Deployment) getBlobFuseCredsSecrets(ns, componentName, volumeMountName string) (string, []byte, []byte) {
	secretName := defaults.GetBlobFuseCredsSecretName(componentName, volumeMountName)
	accountKey := []byte(secretDefaultData)
	accountName := []byte(secretDefaultData)
	if deploy.kubeutil.SecretExists(ns, secretName) {
		oldSecret, _ := deploy.kubeutil.GetSecret(ns, secretName)
		accountKey = oldSecret.Data[defaults.BlobFuseCredsAccountKeyPart]
		accountName = oldSecret.Data[defaults.BlobFuseCredsAccountNamePart]
	}
	return secretName, accountKey, accountName
}

func (deploy *Deployment) getCsiAzureCredsSecrets(namespace, componentName, volumeMountName string) (string, []byte, []byte) {
	secretName := defaults.GetCsiAzureCredsSecretName(componentName, volumeMountName)
	accountKey := []byte(secretDefaultData)
	accountName := []byte(secretDefaultData)
	if deploy.kubeutil.SecretExists(namespace, secretName) {
		oldSecret, _ := deploy.kubeutil.GetSecret(namespace, secretName)
		accountKey = oldSecret.Data[defaults.CsiAzureCredsAccountKeyPart]
		accountName = oldSecret.Data[defaults.CsiAzureCredsAccountNamePart]
	}
	return secretName, accountKey, accountName
}

func (deploy *Deployment) garbageCollectSecretsNoLongerInSpec() error {
	secrets, err := deploy.kubeutil.ListSecrets(deploy.radixDeployment.GetNamespace())
	if err != nil {
		return err
	}

	for _, existingSecret := range secrets {
		if existingSecret.ObjectMeta.Labels[kube.RadixExternalAliasLabel] != "" {
			// Not handled here
			continue
		}

		componentName, ok := NewRadixComponentNameFromLabels(existingSecret)
		if !ok {
			continue
		}

		// Garbage collect if secret is labelled radix-job-type=job-scheduler and not defined in RD jobs
		garbageCollect := false
		if jobType, ok := NewRadixJobTypeFromObjectLabels(existingSecret); ok && jobType.IsJobScheduler() {
			garbageCollect = !componentName.ExistInDeploymentSpecJobList(deploy.radixDeployment)
		} else {
			// Garbage collect secret if not defined in RD components or jobs
			garbageCollect = !componentName.ExistInDeploymentSpec(deploy.radixDeployment)
		}

		if garbageCollect {
			deploy.deleteSecret(existingSecret)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (deploy *Deployment) garbageCollectSecretsNoLongerInSpecForComponent(component radixv1.RadixCommonDeployComponent) error {
	secrets, err := deploy.listSecretsForComponent(component)
	if err != nil {
		return err
	}

	for _, secret := range secrets {
		// External alias not handled here
		if secret.ObjectMeta.Labels[kube.RadixExternalAliasLabel] != "" {
			continue
		}

		// Secrets for jobs not handled here
		if _, ok := NewRadixJobTypeFromObjectLabels(secret); ok {
			continue
		}

		log.Debugf("Delete secret %s no longer in spec for component %s", secret.Name, component.GetName())
		err = deploy.deleteSecret(secret)
		if err != nil {
			return err
		}
	}

	return nil
}

func (deploy *Deployment) garbageCollectAllSecretsForComponentAndExternalAlias(component radixv1.RadixCommonDeployComponent) error {
	return deploy.garbageCollectSecretsForComponentAndExternalAlias(component, true)
}

func (deploy *Deployment) garbageCollectSecretsNoLongerInSpecForComponentAndExternalAlias(component radixv1.RadixCommonDeployComponent) error {
	return deploy.garbageCollectSecretsForComponentAndExternalAlias(component, false)
}

func (deploy *Deployment) garbageCollectSecretsForComponentAndExternalAlias(component radixv1.RadixCommonDeployComponent, all bool) error {
	secrets, err := deploy.listSecretsForComponentExternalAlias(component)
	if err != nil {
		return err
	}

	for _, secret := range secrets {
		garbageCollectSecret := true

		dnsExternalAlias := component.GetDNSExternalAlias()
		if !all && dnsExternalAlias != nil {
			externalAliasForSecret := secret.Name
			for _, externalAlias := range dnsExternalAlias {
				if externalAlias == externalAliasForSecret {
					garbageCollectSecret = false
				}
			}
		}

		if garbageCollectSecret {
			log.Debugf("Delete secret %s for component %s and external alias %s", secret.Name, component.GetName(), dnsExternalAlias)
			err = deploy.deleteSecret(secret)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (deploy *Deployment) listSecretsForComponent(component radixv1.RadixCommonDeployComponent) ([]*v1.Secret, error) {
	return deploy.listSecrets(getLabelSelectorForComponent(component))
}

func (deploy *Deployment) listSecretsForComponentExternalAlias(component radixv1.RadixCommonDeployComponent) ([]*v1.Secret, error) {
	return deploy.listSecrets(getLabelSelectorForExternalAlias(component))
}

func (deploy *Deployment) listSecretsForVolumeMounts(component radixv1.RadixCommonDeployComponent) ([]*v1.Secret, error) {
	blobVolumeMountSecret := getLabelSelectorForBlobVolumeMountSecret(component)
	secrets, err := deploy.listSecrets(blobVolumeMountSecret)
	if err != nil {
		return nil, err
	}
	csiAzureVolumeMountSecret := getLabelSelectorForCsiAzureVolumeMountSecret(component)
	csiSecrets, err := deploy.listSecrets(csiAzureVolumeMountSecret)
	if err != nil {
		return nil, err
	}
	secrets = append(secrets, csiSecrets...)
	return secrets, err
}

func (deploy *Deployment) listSecrets(labelSelector string) ([]*v1.Secret, error) {
	secrets, err := deploy.kubeutil.ListSecretsWithSelector(deploy.radixDeployment.GetNamespace(), &labelSelector)

	if err != nil {
		return nil, err
	}

	return secrets, err
}

func (deploy *Deployment) createOrUpdateSecret(ns, app, component, secretName string, isExternalAlias bool) error {
	secretType := v1.SecretType("Opaque")
	if isExternalAlias {
		secretType = v1.SecretType("kubernetes.io/tls")
	}

	secret := v1.Secret{
		Type: secretType,
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
			Labels: map[string]string{
				kube.RadixAppLabel:           app,
				kube.RadixComponentLabel:     component,
				kube.RadixExternalAliasLabel: strconv.FormatBool(isExternalAlias),
			},
		},
	}

	if isExternalAlias {
		defaultValue := []byte(secretDefaultData)

		// Will need to set fake data in order to apply the secret. The user then need to set data to real values
		data := make(map[string][]byte)
		data["tls.crt"] = defaultValue
		data["tls.key"] = defaultValue

		secret.Data = data
	}

	_, err := deploy.kubeutil.ApplySecret(ns, &secret)
	if err != nil {
		return err
	}

	return nil
}

func (deploy *Deployment) createClientCertificateSecret(ns, app, component, secretName string) error {
	secret := v1.Secret{
		Type: v1.SecretType("Opaque"),
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
			Labels: map[string]string{
				kube.RadixAppLabel:       app,
				kube.RadixComponentLabel: component,
			},
		},
	}

	defaultValue := []byte(secretDefaultData)

	// Will need to set fake data in order to apply the secret. The user then need to set data to real values
	data := make(map[string][]byte)
	data["ca.crt"] = defaultValue
	secret.Data = data

	_, err := deploy.kubeutil.ApplySecret(ns, &secret)
	return err
}

func (deploy *Deployment) removeOrphanedSecrets(ns, secretName string, secrets []string) error {
	secret, err := deploy.kubeutil.GetSecret(ns, secretName)
	if err != nil {
		return err
	}

	orphanRemoved := false
	for secretName := range secret.Data {
		if !slice.ContainsString(secrets, secretName) {
			delete(secret.Data, secretName)
			orphanRemoved = true
		}
	}

	if orphanRemoved {
		_, err = deploy.kubeutil.ApplySecret(ns, secret)
		if err != nil {
			return err
		}
	}

	return nil
}

func IsSecretRequiredForClientCertificate(clientCertificate *radixv1.ClientCertificate) bool {
	if clientCertificate != nil {
		certificateConfig := parseClientCertificateConfiguration(*clientCertificate)
		if *certificateConfig.PassCertificateToUpstream || *certificateConfig.Verification != radixv1.VerificationTypeOff {
			return true
		}
	}

	return false
}

//GarbageCollectSecrets delete secrets, excluding with names in the excludeSecretNames
func (deploy *Deployment) GarbageCollectSecrets(secrets []*v1.Secret, excludeSecretNames []string) error {
	for _, secret := range secrets {
		if slice.ContainsString(excludeSecretNames, secret.Name) {
			continue
		}
		err := deploy.deleteSecret(secret)
		if err != nil {
			return err
		}
	}
	return nil
}

func (deploy *Deployment) deleteSecret(secret *v1.Secret) error {
	log.Debugf("Delete secret %s", secret.Name)
	return deploy.kubeclient.CoreV1().Secrets(deploy.radixDeployment.GetNamespace()).Delete(context.TODO(), secret.Name, metav1.DeleteOptions{})
}
