package deployment

import (
	"strings"

	"github.com/equinor/radix-operator/pkg/apis/defaults"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (deploy *Deployment) createDeployment(deployComponent v1.RadixDeployComponent) error {
	namespace := deploy.radixDeployment.Namespace
	appName := deploy.radixDeployment.Spec.AppName
	deployment, err := deploy.getDeploymentConfig(deployComponent)
	if err != nil {
		return err
	}

	// If Replicas == 0 or HorizontalScaling is nil then delete hpa if exists before updating deployment
	deployReplicas := deployment.Spec.Replicas
	if deployReplicas != nil && *deployReplicas == 0 || deployComponent.HorizontalScaling == nil {
		err = deploy.deleteHPAIfExists(deployComponent)
		if err != nil {
			return err
		}
	}

	deploy.customSecuritySettings(appName, namespace, deployment)
	return deploy.kubeutil.ApplyDeployment(namespace, deployment)
}

func (deploy *Deployment) getDeploymentConfig(deployComponent v1.RadixDeployComponent) (*appsv1.Deployment, error) {
	appName := deploy.radixDeployment.Spec.AppName
	environment := deploy.radixDeployment.Spec.Environment
	componentName := deployComponent.Name
	componentPorts := deployComponent.Ports
	replicas := deployComponent.Replicas
	automountServiceAccountToken := false

	const branchKey, commitIDKey = "radix-branch", "radix-commit"
	rdLabels := deploy.radixDeployment.Labels
	var branch, commitID string
	if branchVal, exists := rdLabels[branchKey]; exists {
		branch = branchVal
	}
	if commitIDVal, exists := rdLabels[commitIDKey]; exists {
		commitID = commitIDVal
	}

	ownerReference := getOwnerReferenceOfDeployment(deploy.radixDeployment)
	securityContext := getSecurityContextForContainer()

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: componentName,
			Labels: map[string]string{
				kube.RadixAppLabel:       appName,
				kube.RadixComponentLabel: componentName,
				kube.RadixCommitLabel:    commitID,
			},
			Annotations: map[string]string{
				kube.RadixBranchAnnotation: branch,
			},
			OwnerReferences: ownerReference,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(DefaultReplicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					kube.RadixComponentLabel: componentName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						kube.RadixAppLabel:       appName,
						kube.RadixComponentLabel: componentName,
						kube.RadixCommitLabel:    commitID,
					},
					Annotations: map[string]string{
						"apparmor.security.beta.kubernetes.io/pod": "runtime/default",
						"seccomp.security.alpha.kubernetes.io/pod": "docker/default",
						kube.RadixBranchAnnotation:                 branch,
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &automountServiceAccountToken,
					Containers: []corev1.Container{
						{
							Name:            componentName,
							Image:           deployComponent.Image,
							ImagePullPolicy: corev1.PullAlways,
							SecurityContext: securityContext,
						},
					},
					ImagePullSecrets: deploy.radixDeployment.Spec.ImagePullSecrets,
				},
			},
		},
	}

	var ports []corev1.ContainerPort
	for _, v := range componentPorts {
		containerPort := corev1.ContainerPort{
			Name:          v.Name,
			ContainerPort: int32(v.Port),
		}
		ports = append(ports, containerPort)
	}
	deployment.Spec.Template.Spec.Containers[0].Ports = ports

	if len(ports) > 0 {
		readinessProbe, err := getReadinessProbe(ports[0].ContainerPort)
		if err != nil {
			return nil, err
		}
		deployment.Spec.Template.Spec.Containers[0].ReadinessProbe = readinessProbe
	}

	deploymentStrategy, err := getDeploymentStrategy()
	if err != nil {
		return nil, err
	}
	deployment.Spec.Strategy = deploymentStrategy

	if replicas != nil && *replicas >= 0 {
		deployment.Spec.Replicas = int32Ptr(int32(*replicas))
	}

	// Override Replicas with horizontalScaling.minReplicas if exists
	if replicas != nil && *replicas != 0 && deployComponent.HorizontalScaling != nil {
		deployment.Spec.Replicas = deployComponent.HorizontalScaling.MinReplicas
	}

	// For backwards compatibility
	isDeployComponentPublic := deployComponent.PublicPort != "" || deployComponent.Public
	environmentVariables := deploy.getEnvironmentVariables(deployComponent.EnvironmentVariables, deployComponent.Secrets, isDeployComponentPublic, deployComponent.Ports, deploy.radixDeployment.Name, deploy.radixDeployment.Namespace, environment, appName, componentName)

	if environmentVariables != nil {
		deployment.Spec.Template.Spec.Containers[0].Env = environmentVariables
	}

	resourceRequirements := deployComponent.GetResourceRequirements()

	if resourceRequirements != nil {
		deployment.Spec.Template.Spec.Containers[0].Resources = *resourceRequirements
	}

	return deployment, nil
}

func (deploy *Deployment) garbageCollectDeploymentsNoLongerInSpec() error {
	deployments, err := deploy.kubeutil.ListDeployments(deploy.radixDeployment.GetNamespace())
	if err != nil {
		return err
	}

	for _, exisitingComponent := range deployments {
		garbageCollect := true
		exisitingComponentName := exisitingComponent.ObjectMeta.Labels[kube.RadixComponentLabel]

		for _, component := range deploy.radixDeployment.Spec.Components {
			if strings.EqualFold(component.Name, exisitingComponentName) {
				garbageCollect = false
				break
			}
		}

		if garbageCollect {
			propagationPolicy := metav1.DeletePropagationForeground
			err = deploy.kubeclient.AppsV1().Deployments(deploy.radixDeployment.GetNamespace()).Delete(exisitingComponent.Name, &metav1.DeleteOptions{PropagationPolicy: &propagationPolicy})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getReadinessProbe(componentPort int32) (*corev1.Probe, error) {
	initialDelaySeconds, err := defaults.GetDefaultReadinessProbeInitialDelaySeconds()
	if err != nil {
		return nil, err
	}

	periodSeconds, err := defaults.GetDefaultReadinessProbePeriodSeconds()
	if err != nil {
		return nil, err
	}

	probe := corev1.Probe{
		Handler: corev1.Handler{
			TCPSocket: &corev1.TCPSocketAction{
				Port: intstr.IntOrString{
					IntVal: componentPort,
				},
			},
		},
		InitialDelaySeconds: initialDelaySeconds,
		PeriodSeconds:       periodSeconds,
	}

	return &probe, nil
}

func getDeploymentStrategy() (appsv1.DeploymentStrategy, error) {
	rollingUpdateMaxUnavailable, err := defaults.GetDefaultRollingUpdateMaxUnavailable()
	if err != nil {
		return appsv1.DeploymentStrategy{}, err
	}

	rollingUpdateMaxSurge, err := defaults.GetDefaultRollingUpdateMaxSurge()
	if err != nil {
		return appsv1.DeploymentStrategy{}, err
	}

	deploymentStrategy := appsv1.DeploymentStrategy{
		RollingUpdate: &appsv1.RollingUpdateDeployment{
			MaxUnavailable: &intstr.IntOrString{
				Type:   intstr.String,
				StrVal: rollingUpdateMaxUnavailable,
			},
			MaxSurge: &intstr.IntOrString{
				Type:   intstr.String,
				StrVal: rollingUpdateMaxSurge,
			},
		},
	}

	return deploymentStrategy, nil
}

func getSecurityContextForContainer() *corev1.SecurityContext {
	allowPrivilegeEscalation := false
	// runAsNonRoot := true
	// runAsUser := int64(1000)

	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		// RunAsNonRoot:             &runAsNonRoot,
		// RunAsUser:                &runAsUser,
	}
}
func int32Ptr(i int32) *int32 {
	return &i
}
