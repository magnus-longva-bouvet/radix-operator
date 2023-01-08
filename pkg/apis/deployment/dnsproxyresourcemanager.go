package deployment

import (
	"context"
	"fmt"
	"github.com/equinor/radix-operator/pkg/apis/defaults"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"strings"
)

const (
	// dnsmasqConfKey is the key inside the configMap which holds the data for the /etc/dnsmasq.conf file
	dnsmasqConfKey           = "dnsmasqConf"
	dnsProxyPortName         = "dns"
	dnsProxyPortNumber int32 = 53
)

// NewDnsProxyResourceManager creates a new NewDnsProxyResourceManager
func NewDnsProxyResourceManager(rd *v1.RadixDeployment, rr *v1.RadixRegistration, kubeutil *kube.Kube, dnsProxyContainerImage string) AuxiliaryResourceManager {
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
	if allowedDnsZones == nil {
		log.Debugf("RadixDeployment %s/%s has empty allowedDnsZones, skipping dns-aux sync", o.rd.Namespace, o.rd.Name)
		return nil
	}
	kubeDnsIp, err := o.getKubeDnsIp()
	if err != nil {
		return err
	}
	_, err = o.createOrUpdateService()
	if err != nil {
		return err
	}
	if err := o.createOrUpdateConfigMap(kubeDnsIp, allowedDnsZones); err != nil {
		return err
	}
	return o.createOrUpdateDeployment(allowedDnsZones)
}

func (o *dnsProxyResourceManager) createOrUpdateDeployment(allowedDnsZones []string) error {
	current, desired, err := o.getCurrentAndDesiredDeployment(allowedDnsZones)
	if err != nil {
		return err
	}

	if err := o.kubeutil.ApplyDeployment(o.rd.Namespace, current, desired); err != nil {
		return err
	}
	return nil
}

func (o *dnsProxyResourceManager) getCurrentAndDesiredDeployment(allowedDnsZones []string) (*appsv1.Deployment, *appsv1.Deployment, error) {
	deploymentName := utils.GetAuxiliaryComponentDeploymentName(o.rd.Spec.AppName, defaults.OAuthProxyAuxiliaryComponentSuffix)

	currentDeployment, err := o.kubeutil.GetDeployment(o.rd.Namespace, deploymentName)
	if err != nil && !errors.IsNotFound(err) {
		return nil, nil, err
	}
	desiredDeployment, err := o.getDesiredDeployment(allowedDnsZones)
	if err != nil {
		return nil, nil, err
	}

	return currentDeployment, desiredDeployment, nil
}

func (o *dnsProxyResourceManager) getDesiredDeployment(allowedDnsZones []string) (*appsv1.Deployment, error) {
	deploymentName := utils.GetAuxiliaryComponentDeploymentName(o.rd.Spec.AppName, defaults.OAuthProxyAuxiliaryComponentSuffix)
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
				MatchLabels: o.getLabelsForAuxComponent(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: o.getLabelsForAuxComponent(),
					Annotations: map[string]string{
						"apparmor.security.beta.kubernetes.io/pod": "runtime/default",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            o.rd.Spec.AppName,
							Image:           o.dnsProxyContainerImage,
							ImagePullPolicy: corev1.PullAlways,
							// Env:             o.getEnvVars(component),
							Ports: []corev1.ContainerPort{
								{
									Name:          dnsProxyPortName,
									ContainerPort: dnsProxyPortNumber,
								},
							},
							ReadinessProbe: readinessProbe,
							VolumeMounts: []corev1.VolumeMount{{
								Name:             "",
								ReadOnly:         false,
								MountPath:        "",
								SubPath:          "",
								MountPropagation: nil,
								SubPathExpr:      "",
							}},
						},
					},
					Volumes: []corev1.Volume{{
						Name: "",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "",
								},
								Items: []corev1.KeyToPath{{
									Key:  dnsmasqConfKey,
									Path: "/etc/dnsmasq.conf",
									Mode: int32Ptr(644),
								}},
								Optional: utils.BoolPtr(false),
							},
						},
					}},
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type: "RuntimeDefault",
						},
					},
				},
			},
		},
	}

	o.mergeAuxComponentResourceLabels(desiredDeployment)
	return desiredDeployment, nil
}

func (o *dnsProxyResourceManager) createOrUpdateService() (*corev1.Service, error) {
	service := o.buildServiceSpec()
	service, err := o.kubeutil.ApplyService(o.rd.Namespace, service)
	if err != nil {
		return nil, err
	}
	return service, nil
}

func (o *dnsProxyResourceManager) GarbageCollect() error {
	if err := o.garbageCollect(); err != nil {
		return fmt.Errorf("failed to garbage collect dns proxy: %v", err)
	}
	return nil
}

func (o *dnsProxyResourceManager) getLabelsForAuxComponent() map[string]string {
	return map[string]string{
		kube.RadixAppLabel:                    o.rd.Spec.AppName,
		kube.RadixAuxiliaryComponentTypeLabel: defaults.DnsProxyAuxiliaryComponentType,
	}
}

func (o *dnsProxyResourceManager) mergeAuxComponentResourceLabels(object metav1.Object) {
	object.SetLabels(labels.Merge(object.GetLabels(), o.getLabelsForAuxComponent()))
}

func (o *dnsProxyResourceManager) buildServiceSpec() *corev1.Service {
	serviceName := utils.GetAuxiliaryComponentServiceName(o.rd.Spec.AppName, defaults.DnsProxyAuxiliaryComponentSuffix)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            serviceName,
			OwnerReferences: []metav1.OwnerReference{getOwnerReferenceOfDeployment(o.rd)},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: o.getLabelsForAuxComponent(),
			Ports: []corev1.ServicePort{
				{
					Port:       dnsProxyPortNumber,
					TargetPort: intstr.FromInt(int(dnsProxyPortNumber)),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Port:       dnsProxyPortNumber,
					TargetPort: intstr.FromInt(int(dnsProxyPortNumber)),
					Protocol:   corev1.ProtocolUDP,
				},
			},
		},
	}
	o.mergeAuxComponentResourceLabels(service)
	return service
}

func (o *dnsProxyResourceManager) garbageCollect() error {
	allowedDnsZones := o.rd.Spec.AllowedDnsZones
	if allowedDnsZones == nil {
		log.Debugf("RadixDeployment %s/%s has empty allowedDnsZones, garbage collecting dns-aux proxy", o.rd.Namespace, o.rd.Name)
		if err := o.garbageCollectDeployment(); err != nil {
			return err
		}
		if err := o.garbageCollectConfigMap(); err != nil {
			return err
		}
		return o.garbageCollectServices()
	}
	log.Debugf("RadixDeployment %s has non-empty allowedDnsZones field, skipping dns-aux garbage collection", o.rd.Name)
	return nil
}

func (o *dnsProxyResourceManager) garbageCollectDeployment() error {
	deployments, err := o.kubeutil.ListDeployments(o.rd.Namespace)
	if err != nil {
		return err
	}

	for _, deployment := range deployments {
		if o.isEligibleForGarbageCollection(deployment) {
			err := o.kubeutil.KubeClient().AppsV1().Deployments(deployment.Namespace).Delete(context.TODO(), deployment.Name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}

func (o *dnsProxyResourceManager) garbageCollectServices() error {
	services, err := o.kubeutil.ListServices(o.rd.Namespace)
	if err != nil {
		return err
	}

	for _, service := range services {
		if o.isEligibleForGarbageCollection(service) {
			err := o.kubeutil.KubeClient().CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}

func (o *dnsProxyResourceManager) isEligibleForGarbageCollection(object metav1.Object) bool {
	if appName := object.GetLabels()[kube.RadixAppLabel]; appName != o.rd.Spec.AppName {
		return false
	}
	if auxType := object.GetLabels()[kube.RadixAuxiliaryComponentTypeLabel]; auxType != defaults.DnsProxyAuxiliaryComponentType {
		return false
	}
	auxTargetComponentName, nameExist := RadixComponentNameFromAuxComponentLabel(object)
	if !nameExist {
		return false
	}
	return !auxTargetComponentName.ExistInDeploymentSpec(o.rd)
}

func (o *dnsProxyResourceManager) createOrUpdateConfigMap(kubeDnsIp string, allowedDnsZones []string) error {
	configMapName := getDnsProxyConfigMapName(o.rd.Spec.AppName)
	currentConfigMap, err := o.kubeutil.GetConfigMap(o.rd.Namespace, configMapName)
	if err != nil {
		if errors.IsNotFound(err) {
			newConfigMap, err := o.buildConfigMapSpec(configMapName, kubeDnsIp, allowedDnsZones)
			if err != nil {
				return err
			}
			_, err = o.kubeutil.CreateConfigMap(o.rd.Namespace, newConfigMap)
			return err
		} else {
			return err
		}
	}
	newConfigMap, err := o.buildConfigMapSpec(configMapName, kubeDnsIp, allowedDnsZones)
	if err != nil {
		return err
	}
	return o.kubeutil.ApplyConfigMap(o.rd.Namespace, currentConfigMap, newConfigMap)
}

func (o *dnsProxyResourceManager) buildConfigMapSpec(name, kubeDnsIp string, allowedDnsZones []string) (*corev1.ConfigMap, error) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Data: map[string]string{
			dnsmasqConfKey: createDnsMasqConfFile(kubeDnsIp, allowedDnsZones),
		},
	}
	o.mergeAuxComponentResourceLabels(configMap)
	return configMap, nil
}

func (o *dnsProxyResourceManager) getKubeDnsIp() (string, error) {
	// TODO: Test_Controller_Calls_Handler doesn't work when fake kubeclient can't retrieve kube-dns IP
	return "10.0.2.10", nil
	//kubeDnsService, err := o.kubeutil.GetService("kube-system", "kube-dns")
	//if err != nil {
	//	return "", fmt.Errorf("failed to get kube-dns service: %v", err)
	//}
	//clusterIp := kubeDnsService.Spec.ClusterIP
	//if clusterIp == "" {
	//	return "", fmt.Errorf("kube-dns service has empty clusterIp")
	//}
	//return clusterIp, nil
}

func (o *dnsProxyResourceManager) garbageCollectConfigMap() error {
	configMaps, err := o.kubeutil.ListConfigMaps(o.rd.Namespace)
	if err != nil {
		return err
	}

	for _, configMap := range configMaps {
		if o.isEligibleForGarbageCollection(configMap) {
			err := o.kubeutil.KubeClient().CoreV1().ConfigMaps(configMap.Namespace).Delete(context.TODO(), configMap.Name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func createDnsMasqConfFile(kubeDnsIp string, allowedDnsZones []string) string {
	lines := []string{"address=\"/#/\"", "conf-dir=/etc/dnsmasq.d/,*.conf", "bogus-priv", "no-hosts", "no-resolv"}
	for _, allowedDnsZone := range allowedDnsZones {
		lines = append(lines, fmt.Sprintf("server=/%s/%s", allowedDnsZone, kubeDnsIp))
	}
	return strings.Join(lines, "\n")
}

func getDnsProxyConfigMapName(appName string) string {
	return fmt.Sprintf("%s-%s-config", appName, defaults.DnsProxyAuxiliaryComponentSuffix)
}
