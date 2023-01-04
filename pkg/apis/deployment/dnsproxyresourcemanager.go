package deployment

import (
	"fmt"
	"github.com/equinor/radix-operator/pkg/apis/defaults"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NewDnsProxyResourceManager creates a new NewDnsProxyResourceManager
func NewDnsProxyResourceManager(rd *v1.RadixDeployment, rr *v1.RadixRegistration, re *v1.RadixEnvironment, kubeutil *kube.Kube, dnsProxyContainerImage string) AuxiliaryResourceManager {
	return &dnsProxyResourceManager{
		rd:                     rd,
		rr:                     rr,
		kubeutil:               kubeutil,
		dnsProxyContainerImage: dnsProxyContainerImage,
	}
}

type dnsProxyResourceManager struct {
	rd                     *v1.RadixDeployment
	rr                     *v1.RadixRegistration
	kubeutil               *kube.Kube
	dnsProxyContainerImage string
}

func (o *dnsProxyResourceManager) Sync() error {
	allowedDnsZones := o.rd.Spec.AllowedDnsZones
	if err := o.createOrUpdateService(allowedDnsZones); err != nil {
		return err
	}

	for _, component := range o.rd.Spec.Components {
		if err := o.syncComponent(&component, allowedDnsZones); err != nil {
			return fmt.Errorf("failed to sync dns proxy: %v", err)
		}
	}
	return nil
}

func (o *dnsProxyResourceManager) syncComponent(component *v1.RadixDeployComponent, allowedDnsZones []string) error {
	newComponent := component.DeepCopy()
	newComponent.AllowedDnsZones = allowedDnsZones
	return o.createOrUpdateDeployment(component)
}

func (o *dnsProxyResourceManager) createOrUpdateDeployment(component v1.RadixCommonDeployComponent) error {
	current, desired, err := o.getCurrentAndDesiredDeployment(component)
	if err != nil {
		return err
	}

	if err := o.kubeutil.ApplyDeployment(o.rd.Namespace, current, desired); err != nil {
		return err
	}
	return nil
}

func (o *dnsProxyResourceManager) getCurrentAndDesiredDeployment(component v1.RadixCommonDeployComponent) (*appsv1.Deployment, *appsv1.Deployment, error) {
	deploymentName := utils.GetAuxiliaryComponentDeploymentName(component.GetName(), defaults.OAuthProxyAuxiliaryComponentSuffix)

	currentDeployment, err := o.kubeutil.GetDeployment(o.rd.Namespace, deploymentName)
	if err != nil && !errors.IsNotFound(err) {
		return nil, nil, err
	}
	desiredDeployment, err := o.getDesiredDeployment(component)
	if err != nil {
		return nil, nil, err
	}

	return currentDeployment, desiredDeployment, nil
}

func (o *dnsProxyResourceManager) getDesiredDeployment(component v1.RadixCommonDeployComponent) (*appsv1.Deployment, error) {
	deploymentName := utils.GetAuxiliaryComponentDeploymentName(component.GetName(), defaults.OAuthProxyAuxiliaryComponentSuffix)
	readinessProbe, err := getReadinessProbeWithDefaultsFromEnv(oauthProxyPortNumber)
	if err != nil {
		return nil, err
	}

	// Spec.Strategy defaults to RollingUpdate, ref https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy
	desiredDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            deploymentName,
			Annotations:     make(map[string]string),
			OwnerReferences: []metav1.OwnerReference{getOwnerReferenceOfDeployment(o.rd)},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(DefaultReplicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: o.getLabelsForAuxComponent(component),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: o.getLabelsForAuxComponent(component),
					Annotations: map[string]string{
						"apparmor.security.beta.kubernetes.io/pod": "runtime/default",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            component.GetName(),
							Image:           o.oauth2ProxyDockerImage,
							ImagePullPolicy: corev1.PullAlways,
							Env:             o.getEnvVars(component),
							Ports: []corev1.ContainerPort{
								{
									Name:          oauthProxyPortName,
									ContainerPort: oauthProxyPortNumber,
								},
							},
							ReadinessProbe: readinessProbe,
						},
					},
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type: "RuntimeDefault",
						},
					},
				},
			},
		},
	}

	o.mergeAuxComponentResourceLabels(desiredDeployment, component)
	return desiredDeployment, nil
}

func (o *dnsProxyResourceManager) createOrUpdateService(component []string) error {
	service := o.buildServiceSpec(component)
	return o.kubeutil.ApplyService(o.rd.Namespace, service)
}

func (o *dnsProxyResourceManager) GarbageCollect() error {
	if err := o.garbageCollect(); err != nil {
		return fmt.Errorf("failed to garbage collect oauth proxy: %v", err)
	}
	return nil
}

if allowedDnsZones := component.GetAllowedDnsZones(); allowedDnsZones != nil {
dnsPolicy := "None"
dnsConfig := corev1.PodDNSConfig{
Nameservers: nil,
}
}