package onpush

import (
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/statoil/radix-operator/pkg/apis/radix/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (cli *RadixOnPushHandler) deploy(radixRegistration *v1.RadixRegistration, radixApplication *v1.RadixApplication, imageTag string, targetEnvs map[string]bool) error {
	appName := radixRegistration.Name
	log.Infof("Deploying app %s", appName)

	radixDeployments, err := createRadixDeployments(radixApplication, imageTag, targetEnvs)
	if err != nil {
		return fmt.Errorf("Failed to create radix deployments objects for app %s. %v", appName, err)
	}

	err = cli.applyRadixDeployments(radixRegistration, radixDeployments)
	if err != nil {
		return fmt.Errorf("Failed to apply radix deployments for app %s. %v", appName, err)
	}
	log.Infof("App deployed %s", appName)

	return nil
}

func (cli *RadixOnPushHandler) applyRadixDeployments(radixRegistration *v1.RadixRegistration, radixDeployments []v1.RadixDeployment) error {
	for _, rd := range radixDeployments {
		err := cli.applyEnvNamespace(radixRegistration, rd)
		if err != nil {
			log.Errorf("Failed to create namespace %s. %v", rd.ObjectMeta.Namespace, err)
			return err
		}

		log.Infof("Apply radix deployment %s on env %s", rd.ObjectMeta.Name, rd.ObjectMeta.Namespace)
		_, err = cli.radixclient.RadixV1().RadixDeployments(rd.ObjectMeta.Namespace).Create(&rd)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cli *RadixOnPushHandler) applyEnvNamespace(radixRegistration *v1.RadixRegistration, rd v1.RadixDeployment) error {
	namespaceName := rd.ObjectMeta.Namespace
	ownerRef := getOwnerRef(radixRegistration)
	labels := map[string]string{
		"sync": "cluster-wildcard-tls-cert",
	}

	return cli.kubeutil.ApplyNamespace(namespaceName, labels, ownerRef)
}

func createRadixDeployments(radixApplication *v1.RadixApplication, imageTag string, targetEnvs map[string]bool) ([]v1.RadixDeployment, error) {
	radixDeployments := []v1.RadixDeployment{}
	for _, env := range radixApplication.Spec.Environments {
		if _, contains := targetEnvs[env.Name]; !contains {
			continue
		}
		radixComponents := getRadixComponentsForEnv(radixApplication, env.Name, imageTag)
		radixDeployment := createRadixDeployment(radixApplication.Name, env.Name, imageTag, radixComponents)
		radixDeployments = append(radixDeployments, radixDeployment)
	}

	return radixDeployments, nil
}

func createRadixDeployment(appName, env, imageTag string, components []v1.RadixDeployComponent) v1.RadixDeployment {
	radixDeployment := v1.RadixDeployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", appName, imageTag),
			Namespace: fmt.Sprintf("%s-%s", appName, env),
			Labels: map[string]string{
				"radixApp": appName,
				"env":      env,
			},
		},
		Spec: v1.RadixDeploymentSpec{
			AppName:     appName,
			Environment: env,
			Components:  components,
		},
	}
	return radixDeployment
}

func getRadixComponentsForEnv(radixApplication *v1.RadixApplication, env, imageTag string) []v1.RadixDeployComponent {
	appName := radixApplication.Name
	components := []v1.RadixDeployComponent{}
	for _, appComponent := range radixApplication.Spec.Components {
		componentName := appComponent.Name
		variables := getEnvironmentVariables(appComponent, env)

		deployComponent := v1.RadixDeployComponent{
			Name:                 componentName,
			Image:                getImagePath(appName, componentName, imageTag),
			Replicas:             appComponent.Replicas,
			Public:               appComponent.Public,
			Ports:                appComponent.Ports,
			Secrets:              appComponent.Secrets,
			EnvironmentVariables: variables, // todo: use single EnvVars instead
		}
		components = append(components, deployComponent)
	}
	return components
}

func getEnvironmentVariables(component v1.RadixComponent, env string) v1.EnvVarsMap {
	if component.EnvironmentVariables == nil {
		return v1.EnvVarsMap{}
	}

	for _, variables := range component.EnvironmentVariables {
		if variables.Environment == env {
			return variables.Variables
		}
	}
	return v1.EnvVarsMap{}
}

func getOwnerRef(radixRegistration *v1.RadixRegistration) []metav1.OwnerReference {
	trueVar := true
	return []metav1.OwnerReference{
		metav1.OwnerReference{
			APIVersion: "radix.equinor.com/v1",
			Kind:       "RadixRegistration",
			Name:       radixRegistration.Name,
			UID:        radixRegistration.UID,
			Controller: &trueVar,
		},
	}
}
